"""
SSLyze wrapper — deep TLS protocol/certificate scan (supplement to testssl).
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.base import Tool


class SSLyzeTool(Tool):
    name = "sslyze"
    capability = "TLS_VULN_SCAN"
    binary = "sslyze"

    def build_command(self, target: str, **kwargs) -> List[str]:
        host = target
        if "://" in host:
            from urllib.parse import urlparse
            host = urlparse(host).netloc or host
        out = tempfile.mktemp(suffix=".json")
        self._out = out
        return [self.binary, "--json_out", out, "--quiet", "--heartbleed",
                "--robot", "--compression", "--reneg", "--resum", host]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        findings = []
        path = getattr(self, "_out", None)
        data = ""
        if path and Path(path).exists():
            data = Path(path).read_text(encoding="utf-8", errors="replace")
            Path(path).unlink(missing_ok=True)
        try:
            obj = json.loads(data) if data.strip() else {}
        except json.JSONDecodeError:
            obj = {}
        results = obj.get("server_scan_results", {})
        for server, sdata in (results or {}).items():
            for scan, sres in (sdata.get("scan_commands_results") or {}).items():
                if isinstance(sres, dict):
                    vuln = None
                    if scan == "heartbleed" and sres.get("is_vulnerable_to_heartbleed"):
                        vuln = "Heartbleed"
                    elif scan == "compression" and sres.get("supports_compression"):
                        vuln = "CRIME / TLS compression"
                    elif scan == "robot" and sres.get("robot_result") in ("VULNERABLE", "PARTIALLY_VULNERABLE"):
                        vuln = f"ROBOT ({sres.get('robot_result')})"
                    elif scan == "reneg" and sres.get("supports_client_renegotiation"):
                        vuln = "Insecure client renegotiation"
                    if vuln:
                        findings.append({"host": server, "issue": vuln})
        return {"tls_findings": findings, "count": len(findings)}
