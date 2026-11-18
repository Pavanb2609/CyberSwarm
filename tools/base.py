"""
Every tool wrapper implements this same interface, so the Recon Engine
never needs to know anything tool-specific -- it just calls .run(target)
and gets back a standardized ToolResult, regardless of which tool ran.
"""

import os
import pwd
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


def _extra_search_dirs() -> List[str]:
    """
    Directories to check beyond PATH. Needed because tools installed via
    `go install` or `pip install --user` land in the invoking user's home
    (e.g. ~/go/bin), but running via sudo drops that PATH entry since
    root's PATH doesn't include the original user's ~/go/bin.
    """
    homes = [Path.home()]
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            homes.append(Path(pwd.getpwnam(sudo_user).pw_dir))
        except KeyError:
            pass

    dirs = []
    for home in homes:
        dirs += [str(home / "go" / "bin"), str(home / ".local" / "bin")]
    dirs += ["/usr/local/go/bin", "/usr/local/bin", "/root/go/bin"]
    return dirs


@dataclass
class ToolResult:
    tool: str
    status: str            # "success" | "error" | "not_installed" | "timeout"
    capability: str
    results: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    raw_stdout: Optional[str] = None
    raw_stderr: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status,
            "capability": self.capability,
            "results": self.results,
            "error": self.error,
        }


class Tool(ABC):
    """Base class every tool wrapper must inherit from."""

    name: str = "base"
    capability: str = ""
    binary: str = ""            # the executable name to look for on PATH
    allow_nonzero_exit: bool = False   # some tools (e.g. nmap) can exit non-zero on partial results

    def __post_init_resolved_path(self):
        if not hasattr(self, "_resolved_path"):
            self._resolved_path = None

    def is_available(self) -> bool:
        self.__post_init_resolved_path()
        found = shutil.which(self.binary)
        if found:
            self._resolved_path = found
            return True
        for extra_dir in _extra_search_dirs():
            candidate = Path(extra_dir) / self.binary
            if candidate.exists() and os.access(candidate, os.X_OK):
                self._resolved_path = str(candidate)
                return True
        return False

    def _binary_path(self) -> str:
        self.__post_init_resolved_path()
        return self._resolved_path or self.binary

    @abstractmethod
    def build_command(self, target: str, **kwargs) -> List[str]:
        """Return the argv list to execute for this target."""
        raise NotImplementedError

    @abstractmethod
    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Turn raw tool output into a small structured dict of findings."""
        raise NotImplementedError

    def validate(self) -> Optional[str]:
        """Return None if the tool is ready to run, else a reason string."""
        if not self.is_available():
            return (f"'{self.binary}' not found on PATH or in common install dirs "
                     "(~/go/bin, ~/.local/bin, /usr/local/bin). Install it or skip this tool.")
        return None

    def run(self, target: str, timeout: int = 180, **kwargs) -> ToolResult:
        problem = self.validate()
        if problem:
            return ToolResult(tool=self.name, status="not_installed", capability=self.capability, error=problem)

        try:
            timeout = float(timeout)
        except (TypeError, ValueError):
            timeout = 180

        try:
            cmd = self.build_command(target, **kwargs)
        except FileNotFoundError as e:
            # A tool's build_command() can raise this for a missing
            # required input file (e.g. ffuf.py checking a caller-supplied
            # wordlist path exists) -- a clean, explicit convention any
            # Tool subclass can use instead of letting the underlying
            # binary fail later with its own cryptic subprocess error.
            return ToolResult(tool=self.name, status="not_installed", capability=self.capability, error=str(e))
        if cmd and cmd[0] == self.binary:
            cmd[0] = self._binary_path()  # use resolved full path in case it's outside the current PATH
        if os.environ.get("CS_TRACE_TOOLS"):
            print(f"[tool] {self.name}: {' '.join(cmd)}", file=sys.stderr, flush=True)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        except subprocess.TimeoutExpired:
            return ToolResult(tool=self.name, status="timeout", capability=self.capability,
                               error=f"Timed out after {timeout}s running: {' '.join(cmd)}")
        except FileNotFoundError as e:
            return ToolResult(tool=self.name, status="not_installed", capability=self.capability, error=str(e))

        if proc.returncode != 0 and not self.allow_nonzero_exit:
            return ToolResult(
                tool=self.name, status="error", capability=self.capability,
                error=f"exit code {proc.returncode}: {proc.stderr[:500]}",
                raw_stdout=proc.stdout, raw_stderr=proc.stderr,
            )

        try:
            parsed = self.parse(proc.stdout, proc.stderr)
        except Exception as e:  # noqa: BLE001
            return ToolResult(
                tool=self.name, status="error", capability=self.capability,
                error=f"parse failure: {e}", raw_stdout=proc.stdout, raw_stderr=proc.stderr,
            )

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results=parsed, raw_stdout=proc.stdout, raw_stderr=proc.stderr,
        )
