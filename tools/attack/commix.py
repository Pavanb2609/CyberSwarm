"""
Commix wrapper — automated command injection detection (non-destructive).
"""

from typing import Any, Dict, List

from tools.base import Tool


class CommixTool(Tool):
    name = "commix"
    capability = "CMD_INJECTION_SCAN"
    binary = "commix"

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = target if target.startswith("http") else f"https://{target}"
        cmd = [self.binary, "--url", url, "--level", "1", "--batch"]
        if kwargs.get("injectable"):
            cmd += ["--inject", kwargs["injectable"]]
        return cmd

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        findings = []
        low = (stdout or "").lower()
        if "injectable" in low or "is vulnerable" in low or "identified" in low:
            findings.append({"issue": "Potential command injection", "detail": (stdout or "")[:300]})
        return {"commix_findings": findings, "count": len(findings)}
