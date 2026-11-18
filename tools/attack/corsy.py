"""
Corsy wrapper — CORS misconfiguration detection (passive, HTTP only).
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool


class CorsyTool(Tool):
    name = "corsy"
    capability = "CORS_SCAN"
    binary = "corsy"
    allow_nonzero_exit = True

    def build_command(self, target: str, **kwargs) -> List[str]:
        out = tempfile.mktemp(suffix=".json")
        self._out = out
        return [self.binary, "-u", target, "-o", out, "-q"]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        findings = []
        path = getattr(self, "_out", None)
        data = ""
        if path and Path(path).exists():
            data = Path(path).read_text(encoding="utf-8", errors="replace")
            Path(path).unlink(missing_ok=True)
        if data.strip():
            try:
                for item in json.loads(data):
                    findings.append({
                        "url": item.get("url", ""),
                        "cors_vulnerable": True,
                        "reason": item.get("reason", item.get("httpcode", ""))[:200],
                    })
            except json.JSONDecodeError:
                for line in data.splitlines():
                    line = line.strip()
                    if "vulnerable" in line.lower():
                        findings.append({"url": line.split()[0], "cors_vulnerable": True,
                                         "reason": line[:200]})
        return {"cors_findings": findings, "count": len(findings)}
