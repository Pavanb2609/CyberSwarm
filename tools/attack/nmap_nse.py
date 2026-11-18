"""
Nmap NSE vuln-category scripts wrapper for SERVICE_VULN_SCAN capability.

Runs `nmap --script vuln` against discovered open ports and parses
the script output blocks into normalised findings.
"""

import re
import shlex
from typing import Any, Dict, List

from tools.base import Tool


def _clean_truncate(text: str, limit: int) -> str:
    """Truncate to at most `limit` chars without cutting a token in the
    middle. A hard character-count cap landed mid-URL in a real report
    (nmap's vulners NSE script lists several "CVE\\tscore\\turl" entries on
    one line; a plain [:400] slice cut the 5th entry's URL down to
    "https://vulners.com/c", which reads as corrupted data rather than an
    obvious truncation). Backtracking to the last whitespace boundary and
    marking the cut explicitly avoids both problems."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    last_space = cut.rfind(" ")
    if last_space > limit * 0.5:  # don't backtrack drastically for one long unbroken token
        cut = cut[:last_space]
    return cut.rstrip() + " …[truncated]"


class NmapNSETool(Tool):
    name = "nmap_nse"
    capability = "SERVICE_VULN_SCAN"
    binary = "nmap"
    allow_nonzero_exit = True

    def build_command(self, target: str, **kwargs) -> List[str]:
        ports = kwargs.get("ports", "")
        port_arg = ["-p", ports] if ports else ["-p", "80,443,8080,8443,22,21,25,3306,5432"]

        return [
            self.binary,
            "-sV",              # service version detection (required by many NSE scripts)
            "--script", "vuln",
            "--script-timeout", "60s",
            "-T4",
            "--open",           # only show open ports
            *port_arg,
            target,
        ]

    def _save_block(self, findings: List[Dict[str, Any]], port: str, script: str,
                    lines: List[str], severity_hints: Dict[str, str]) -> None:
        if not (script and lines):
            return
        output = " ".join(lines).strip()
        sev = "INFO"
        for hint, level in severity_hints.items():
            if hint in output.upper():
                sev = level
                break
        cve = re.findall(r"CVE-\d{4}-\d+", output)
        findings.append({
            "port":     port or "",
            "script":   script,
            "output":   _clean_truncate(output, 400),
            "severity": sev,
            "cve":      cve[:3],
        })

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        findings = []
        current_port = None
        current_script = None
        current_lines = []

        SEVERITY_HINTS = {
            # More specific phrases MUST come before the generic "VULNERABLE"
            # check below, since "NOT VULNERABLE" and "LIKELY VULNERABLE"
            # both contain "VULNERABLE" as a substring -- with the generic
            # one checked first, first-match-wins meant a "LIKELY VULNERABLE"
            # finding was always misclassified as HIGH instead of MEDIUM.
            "NOT VULNERABLE": "INFO",
            "LIKELY VULNERABLE": "MEDIUM",
            "VULNERABLE": "HIGH",
            "CVE-": "HIGH",
            "EXPLOIT": "HIGH",
        }

        for line in stdout.splitlines():
            # Detect port line: "80/tcp open  http"
            port_match = re.match(r"^(\d+/\w+)\s+open\s+(.+)", line.strip())
            if port_match:
                # A new port section starts here -- save whatever script
                # block was still pending from the previous port first.
                # (Previously this reset current_script/current_lines
                # without saving, silently dropping the last NSE finding
                # for every port except the very last one in the scan.)
                self._save_block(findings, current_port, current_script,
                                 current_lines, SEVERITY_HINTS)
                current_port = port_match.group(1)
                current_script = None
                current_lines = []
                continue

            # Detect NSE script block start: "|_scriptname:" or "| scriptname:"
            script_match = re.match(r"^\|[_\s](\S+):\s*(.*)", line.strip())
            if script_match:
                # Save previous script block
                self._save_block(findings, current_port, current_script,
                                 current_lines, SEVERITY_HINTS)
                current_script = script_match.group(1)
                current_lines = [script_match.group(2)]
                continue

            # Continuation of current script output
            if current_script and (line.startswith("|") or line.startswith("  ")):
                current_lines.append(line.strip().lstrip("|").strip())

        # Save last block
        self._save_block(findings, current_port, current_script,
                         current_lines, SEVERITY_HINTS)

        # Filter out "NOT VULNERABLE" results — no value in storing them
        findings = [f for f in findings if "NOT VULNERABLE" not in f["output"].upper()]

        return {
            "nmap_vuln_findings": findings,
            "count": len(findings),
        }
