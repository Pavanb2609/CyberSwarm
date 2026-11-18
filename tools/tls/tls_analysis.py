"""
TLS_ANALYSIS -- inspects the TLS handshake and leaf certificate on a
target's HTTPS port using the system `openssl` binary. No extra install
required (openssl ships on virtually every Linux box already used for
naabu/nmap/etc.).

Two openssl invocations:
  1. `openssl s_client -connect host:port -servername host` (stdin closed
     immediately via input="", same effect as `</dev/null`) -- captures the
     negotiated protocol/cipher, verify return code, and the leaf cert PEM.
  2. `openssl x509 -noout -dates -subject -issuer` fed that PEM on stdin --
     pulls out notBefore/notAfter/subject/issuer without needing to write
     a temp file.

Flags weak/deprecated protocols, failed verification, and expired or
soon-to-expire certificates as `tls_findings`.
"""

import re
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List

from tools.base import Tool, ToolResult

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
CERT_EXPIRY_WARNING_DAYS = 14


class TLSAnalysisTool(Tool):
    name = "tls_analysis"
    capability = "TLS_ANALYSIS"
    binary = "openssl"

    def _pick_port(self, kwargs) -> int:
        """Prefer a known HTTPS-ish port out of what PORT_DISCOVERY found;
        default to 443 if nothing more specific is available."""
        ports_arg = kwargs.get("ports")
        if ports_arg:
            candidates = [int(p) for p in str(ports_arg).split(",") if p.strip().isdigit()]
            for preferred in (443, 8443):
                if preferred in candidates:
                    return preferred
            if candidates:
                return candidates[0]
        return 443

    def build_command(self, target: str, **kwargs) -> List[str]:
        # Kept for interface compliance / validate(); run() below performs
        # the actual (two-step) execution.
        port = self._pick_port(kwargs)
        return [self.binary, "s_client", "-connect", f"{target}:{port}", "-servername", target]

    def run(self, target: str, timeout: int = 180, **kwargs) -> ToolResult:
        problem = self.validate()
        if problem:
            return ToolResult(tool=self.name, status="not_installed", capability=self.capability, error=problem)

        port = self._pick_port(kwargs)
        handshake_cmd = [self._binary_path(), "s_client", "-connect", f"{target}:{port}",
                          "-servername", target]

        try:
            handshake = subprocess.run(handshake_cmd, input="", capture_output=True,
                                        text=True, timeout=timeout, errors="replace")
        except subprocess.TimeoutExpired:
            return ToolResult(tool=self.name, status="timeout", capability=self.capability,
                               error=f"Timed out after {timeout}s connecting to {target}:{port}")
        except FileNotFoundError as e:
            return ToolResult(tool=self.name, status="not_installed", capability=self.capability, error=str(e))

        stdout, stderr = handshake.stdout or "", handshake.stderr or ""

        if "CONNECTED" not in stdout:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                               error=f"No TLS handshake established with {target}:{port}: {stderr[:300]}",
                               raw_stdout=stdout, raw_stderr=stderr)

        try:
            parsed = self.parse(stdout, stderr)
        except Exception as e:  # noqa: BLE001
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                               error=f"parse failure: {e}", raw_stdout=stdout, raw_stderr=stderr)

        cert_match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", stdout, re.S)
        if cert_match:
            try:
                x509 = subprocess.run(
                    [self._binary_path(), "x509", "-noout", "-dates", "-subject", "-issuer"],
                    input=cert_match.group(0), capture_output=True, text=True,
                    timeout=timeout, errors="replace",
                )
                cert_fields = self._parse_cert_fields(x509.stdout)
                extra_findings = cert_fields.pop("tls_findings", [])
                parsed["tls_findings"] = parsed.get("tls_findings", []) + extra_findings
                parsed.update(cert_fields)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass  # cert dates just won't be present; handshake info still returned

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                           results=parsed, raw_stdout=stdout, raw_stderr=stderr)

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        protocol = None
        cipher = None
        verify_code = None

        m = re.search(r"Protocol\s*:\s*(\S+)", stdout) or re.search(r"New,\s*(\S+),\s*Cipher is", stdout)
        if m:
            protocol = m.group(1)
        m = re.search(r"Cipher\s*:\s*(\S+)", stdout) or re.search(r"Cipher is (\S+)", stdout)
        if m:
            cipher = m.group(1)
        m = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)", stdout)
        if m:
            verify_code = {"code": int(m.group(1)), "message": m.group(2)}

        findings: List[str] = []
        if protocol in WEAK_PROTOCOLS:
            findings.append(f"Negotiated weak/deprecated protocol: {protocol}")
        if verify_code and verify_code["code"] != 0:
            findings.append(f"Certificate verification failed: {verify_code['message']}")

        return {
            "tls_reachable": True,
            "protocol": protocol,
            "cipher": cipher,
            "verify_return_code": verify_code,
            "tls_findings": findings,
        }

    @staticmethod
    def _parse_cert_fields(x509_out: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        findings: List[str] = []

        m = re.search(r"notBefore=(.+)", x509_out)
        if m:
            out["cert_not_before"] = m.group(1).strip()

        m = re.search(r"notAfter=(.+)", x509_out)
        if m:
            not_after_str = m.group(1).strip()
            out["cert_not_after"] = not_after_str
            try:
                expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                out["cert_days_until_expiry"] = days_left
                if days_left < 0:
                    findings.append("Certificate is EXPIRED")
                elif days_left < CERT_EXPIRY_WARNING_DAYS:
                    findings.append(f"Certificate expires soon ({days_left} days)")
            except ValueError:
                pass

        m = re.search(r"subject=(.+)", x509_out)
        if m:
            out["cert_subject"] = m.group(1).strip()
        m = re.search(r"issuer=(.+)", x509_out)
        if m:
            out["cert_issuer"] = m.group(1).strip()

        if findings:
            out["tls_findings"] = findings
        return out
