"""
Nikto wrapper for WEB_VULN_SCAN capability.

Runs nikto with JSON output and parses the findings into a
normalised list. Nikto is slow — default timeout is 300s.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool, ToolResult


class NiktoTool(Tool):
    name = "nikto"
    capability = "WEB_VULN_SCAN"
    binary = "nikto"
    allow_nonzero_exit = True

    def __init__(self):
        self._json_path = Path(tempfile.mktemp(suffix=".json"))
        self._perl5lib = os.path.expanduser("~/perl5/lib/perl5")

    def build_command(self, target: str, **kwargs) -> List[str]:
        host = target if target.startswith("http") else f"https://{target}"
        return [
            self.binary,
            "-h", host,
            "-o", str(self._json_path),
            "-Format", "json",
            "-nointeractive",
            "-maxtime", "240",   # nikto can hang on slow targets
            "-Tuning", "x6",     # skip DoS (x) and run misconfig (6) checks
        ]

    def run(self, target: str, timeout: int = 180, **kwargs) -> ToolResult:
        problem = self.validate()
        if problem:
            return ToolResult(tool=self.name, status="not_installed", capability=self.capability, error=problem)
        cmd = self.build_command(target, **kwargs)
        if cmd and cmd[0] == self.binary:
            cmd[0] = self._binary_path()
        env = os.environ.copy()
        env["PERL5LIB"] = f"{self._perl5lib}:{env.get('PERL5LIB', '')}"
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace", env=env)
        except subprocess.TimeoutExpired:
            return ToolResult(tool=self.name, status="timeout", capability=self.capability,
                              error=f"Timed out after {timeout}s running: {' '.join(cmd)}")
        except FileNotFoundError as e:
            return ToolResult(tool=self.name, status="not_installed", capability=self.capability, error=str(e))
        if proc.returncode != 0 and not self.allow_nonzero_exit:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error=f"exit code {proc.returncode}: {proc.stderr[:500]}",
                              raw_stdout=proc.stdout, raw_stderr=proc.stderr)
        try:
            parsed = self.parse(proc.stdout, proc.stderr)
        except Exception as e:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error=f"parse failure: {e}", raw_stdout=proc.stdout, raw_stderr=proc.stderr)
        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results=parsed, raw_stdout=proc.stdout, raw_stderr=proc.stderr)

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        # Nikto writes JSON to the -o file, stdout is progress noise
        if self._json_path.exists():
            raw = self._json_path.read_text(encoding="utf-8", errors="replace")
            self._json_path.unlink(missing_ok=True)
        else:
            # Fallback: some nikto versions dump JSON to stdout too
            raw = stdout

        findings = []
        try:
            data = json.loads(raw)
            # Nikto JSON wraps everything under "vulnerabilities"
            vulns = data.get("vulnerabilities", [])
            if not vulns and isinstance(data, list):
                vulns = data
            for v in vulns:
                findings.append({
                    "id":      v.get("id", ""),
                    "osvdbid": v.get("OSVDB", ""),
                    "method":  v.get("method", "GET"),
                    "url":     v.get("url", ""),
                    "msg":     v.get("msg", v.get("message", ""))[:300],
                })
        except (json.JSONDecodeError, AttributeError):
            # Parse plain-text output as fallback
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("+ ") and len(line) > 10:
                    findings.append({
                        "id": "",
                        "osvdbid": "",
                        "method": "GET",
                        "url": "",
                        "msg": line[2:300],
                    })

        return {
            "nikto_findings": findings,
            "count": len(findings),
        }
