"""
CERT_INFO -- lightweight TLS certificate information extraction.

Pure Python (ssl + socket).  No external tools needed.
"""

import socket
import ssl
from typing import Any

from tools.base import Tool, ToolResult


class CertInfoTool(Tool):
    """Lightweight TLS certificate info extraction."""

    name = "cert_info"
    capability = "CERT_INFO"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["python-cert-info", target]

    def parse(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 10, **kwargs) -> ToolResult:
        host = kwargs.get("host") or target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        port = kwargs.get("port", 443)

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                cert = s.getpeercert()

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            sans = [d[1] for d in cert.get("subjectAltName", [])]
            version = cert.get("version", "unknown")
            serial = cert.get("serialNumber", "unknown")
            not_before = cert.get("notBefore", "unknown")
            not_after = cert.get("notAfter", "unknown")

            # Calculate days until expiry
            from datetime import datetime, timezone
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
            except (ValueError, TypeError):
                days_left = -1

            # Check for weak indicators
            issues = []
            if days_left < 0:
                issues.append("Certificate EXPIRED")
            elif days_left < 30:
                issues.append(f"Certificate expires in {days_left} days")

            cipher_info = s.cipher()
            protocol = s.version() if hasattr(s, "version") else "unknown"

            return ToolResult(tool=self.name, status="success", capability=self.capability,
                              results={
                                  "subject": subject,
                                  "issuer": issuer,
                                  "sans": sans,
                                  "san_count": len(sans),
                                  "not_before": not_before,
                                  "not_after": not_after,
                                  "days_until_expiry": days_left,
                                  "protocol": protocol,
                                  "cipher": cipher_info[0] if cipher_info else None,
                                  "cipher_bits": cipher_info[2] if cipher_info else None,
                                  "version": version,
                                  "serial": serial,
                                  "issues": issues,
                                  "severity": "HIGH" if issues else "INFO",
                              })
        except Exception as e:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error=f"TLS connection failed: {e}")
