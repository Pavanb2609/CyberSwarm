"""
Dalfox wrapper — reflected XSS / parameter scanning.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool


class DalfoxTool(Tool):
    name = "dalfox"
    capability = "XSS_SCAN"
    binary = "dalfox"
    allow_nonzero_exit = True

    def build_command(self, target: str, **kwargs) -> List[str]:
        return [self.binary, "url", target, "--silence", "--no-spinner",
                "--skip-bav", "-o", "/dev/stdout"]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            try:
                obj = json.loads(line)
                findings.append({
                    "url": obj.get("data", obj.get("url", "")),
                    "type": obj.get("type", "XSS"),
                    "severity": "HIGH",
                    "description": str(obj.get("data", ""))[:300],
                })
            except json.JSONDecodeError:
                if "=--" in line or "vuln" in line.lower():
                    findings.append({"url": line, "type": "XSS", "severity": "HIGH",
                                     "description": line[:300]})
        return {"xss_findings": findings, "count": len(findings)}
