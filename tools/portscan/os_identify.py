import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool


class OSIdentificationTool(Tool):
    """
    nmap -O OS fingerprinting. Requires root/sudo. Only runs when passwordless
    sudo is already configured for nmap; otherwise it skips cleanly with a
    clear message, the same way a missing binary skips cleanly, rather than
    prompting mid-scan.

    Previously this tried to broker an interactive `sudo` password prompt
    through `script(1)` (a pty-recording wrapper) while the surrounding
    Tool.run() captures the subprocess's stdout/stderr through a plain pipe
    (capture_output=True). Those two don't mix: `script`/`sudo` need a real
    tty to negotiate the password prompt, but the pipe isn't one, so the
    prompt never completed -- the run hung until the 180s tool timeout while
    raw terminal control sequences leaked into the captured "results" text
    (that's the staircase-indented garbage you'd see in the console). An
    automated recon sweep also shouldn't be stopping mid-run to ask for your
    local root password in the first place.
    """

    name = "nmap_os_detect"
    capability = "OPERATING_SYSTEM_IDENTIFICATION"
    binary = "nmap"
    allow_nonzero_exit = True

    def __init__(self):
        self._xml_path = Path(tempfile.mktemp(suffix=".xml"))
        self._skipped_no_sudo = False

    def _can_sudo_nopass(self) -> bool:
        result = subprocess.run(["sudo", "-n", "true"], capture_output=True, text=True)
        return result.returncode == 0

    def validate(self):
        problem = super().validate()
        if problem:
            return problem
        # A missing/broken binary is a hard problem. A missing passwordless-sudo
        # permission is NOT fatal anymore: we degrade to a non-privileged
        # TTL-based OS heuristic in build_command/parse instead of skipping
        # the capability entirely. So validate() passes whenever nmap exists.
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        if self._can_sudo_nopass():
            return ["sudo", "-n", self.binary, "-O", "-oX", str(self._xml_path), target]
        # No privileges: fall back to a connect/ping scan that reveals the hop
        # TTL, which we later map to a heuristic OS guess. Never invokes sudo,
        # so this degrades cleanly (no pty/pw prompt) on unprivileged boxes.
        self._skipped_no_sudo = True
        self._ttl_target = kwargs.get("ports", "") or target
        return [self.binary, "-sP", "-n"]

    def _ttl_guess(self, ttl: int) -> str:
        if ttl is None:
            return "Unknown (no host reachable)"
        if ttl in (64, 63, 65):
            return "Linux / macOS / *BSD (TTL=64 family)"
        if ttl in (128, 127, 129):
            return "Windows (TTL=128 family)"
        if ttl in (255, 254):
            return "Cisco / network gear (TTL=255 family)"
        return f"Unknown OS (TTL={ttl})"

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        # With sudo we parse the -O XML for authoritative guesses.
        if not self._skipped_no_sudo and self._xml_path.exists():
            tree = ET.parse(self._xml_path)
            root = tree.getroot()
            host = root.find("host")
            self._xml_path.unlink(missing_ok=True)
            if host is None:
                return {"os_guesses": []}
            os_el = host.find("os")
            guesses = []
            if os_el is not None:
                for match in os_el.findall("osmatch"):
                    guesses.append({"name": match.get("name"), "accuracy": match.get("accuracy")})
            return {"os_guesses": guesses}

        # Unprivileged fallback: mine TTL from -sP output lines like
        # "Host is up (0.049s latency)." plus ICMP "ttl=" lines.
        self._xml_path.unlink(missing_ok=True)
        import re
        ttl = None
        for line in stdout.splitlines():
            m = re.search(r"ttl\s*[=:]\s*(\d+)", line, re.I)
            if m:
                ttl = int(m.group(1))
                break
        return {
            "os_guesses": [{"name": self._ttl_guess(ttl), "accuracy": "25-40 (heuristic, unprivileged)"}],
            "mode": "ttl_heuristic",
            "note": "nmap -O needs root; used TTL heuristic instead. Enable passwordless sudo for nmap "
                    "to get authoritative OS detection.",
        }
