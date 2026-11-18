"""
Subjack wrapper — subdomain takeover detection via CNAME fingerprinting.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool


class SubjackTool(Tool):
    name = "subjack"
    capability = "SUBDOMAIN_TAKEOVER_SCAN"
    binary = "subjack"

    def build_command(self, target: str, **kwargs) -> List[str]:
        out = tempfile.mktemp(suffix=".txt")
        self._out = out
        domain = str(kwargs.get("domain", "") or target).strip()
        if not domain:
            domain = target
        cmd = [self.binary, "-d", domain, "-o", out, "-a"]
        if kwargs.get("timeout"):
            cmd += ["-t", str(kwargs["timeout"])]
        return cmd

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        findings = []
        path = getattr(self, "_out", None)
        data = ""
        if path and Path(path).exists():
            data = Path(path).read_text(encoding="utf-8", errors="replace")
            Path(path).unlink(missing_ok=True)
        for line in (data or stdout).splitlines():
            parts = line.split(",")
            if len(parts) >= 2:
                domain, status = parts[0].strip(), parts[1].strip()
                findings.append({"domain": domain, "status": status})
        return {"takeover_candidates": findings, "count": len(findings)}
