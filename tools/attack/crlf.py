"""
CRLF_INJECTION_SCAN -- tests for HTTP header injection via \\r\\n in parameters
and paths.  Uses curl to inject CRLF sequences and checks whether the server
reflects them as separate HTTP headers.

Non-destructive: only reads responses, never writes.
"""

import subprocess
from typing import Any, Dict, List
from urllib.parse import urlparse

from tools.attack.verdict import confidence_from_criteria, criteria_label
from tools.base import Tool, ToolResult


# Payloads that inject CRLF sequences into parameters/paths
CRLF_PAYLOADS = [
    ("%0d%0aX-Injected:%20true", "param"),
    ("%0d%0aSet-Cookie:%20crlf_test=1", "param"),
    ("%0D%0ALocation:%20https://evil.com", "param"),
    ("/%0d%0aX-Injected:%20true", "path"),
    ("/%0d%0aSet-Cookie:%20crlf_test=1", "path"),
]

# Injection evidence markers: each is a *unique value* WE injected, so its
# presence in the response means an actual new header line was added.  A bare
# "Location:" is NOT a marker (redirects legitimately contain it).
INJECTED_HEADER_MARKERS = [
    "x-injected: true",
    "set-cookie: crlf_test=1",
    "location: https://evil.com",
]

# Proof criteria -- a marker only counts when it is literally injected by the
# payload AND was absent from a clean baseline request to the same URL.
CRITERIA_WEIGHTS = {
    "marker_injected": 30,
    "absent_in_baseline": 15,
    "header_line_present": 5,
}
CRITERIA_HINTS = {
    "marker_injected": "unique injection marker present in response headers",
    "absent_in_baseline": "marker absent from the clean baseline response",
    "header_line_present": "marker appears on its own header line (not in body/URL)",
}


class CRLFInjectionTool(Tool):
    """CRLF header injection scanner (curl-based)."""

    name = "crlf"
    capability = "CRLF_INJECTION_SCAN"
    binary = "curl"

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["echo", "crlf-tool-placeholder"]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 60, **kwargs) -> "ToolResult":
        from tools.base import ToolResult
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        endpoints = kwargs.get("endpoints") or []

        # Build test URLs: base URL params + discovered endpoints
        test_targets = []
        parsed = urlparse(base)
        if parsed.query:
            # Inject into existing params
            test_targets.append(("param", base))
        else:
            # Add a dummy param to inject into
            test_targets.append(("param", f"{base}?q=test"))

        for ep in endpoints[:8]:
            ep_url = ep if ep.startswith("http") else f"{base.rstrip('/')}/{ep.lstrip('/')}"
            test_targets.append(("path", ep_url))

        findings = []
        for inject_type, url in test_targets:
            for payload, ptype in CRLF_PAYLOADS:
                if ptype != inject_type:
                    continue
                finding = self._test_crlf(url, payload, timeout)
                if finding:
                    findings.append(finding)
                    break  # one confirmed per URL is enough

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={"crlf_findings": findings, "count": len(findings),
                     "tested_urls": [u for _, u in test_targets]},
        )

    @staticmethod
    def _test_crlf(url: str, payload: str, timeout: int) -> Dict[str, Any] | None:
        """Test a single URL+CRLF payload; a marker counts only if the clean
        baseline request to the same URL did not already contain it."""
        if payload.startswith("/"):
            test_url = url.rstrip("/") + payload
        else:
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{payload}"

        clean_headers = CRLFInjectionTool._fetch_headers(url, timeout)
        injected_headers = CRLFInjectionTool._fetch_headers(test_url, timeout)
        if clean_headers is None or injected_headers is None:
            return None

        clean_lower = clean_headers.lower()
        for marker in INJECTED_HEADER_MARKERS:
            marker_injected = marker in injected_headers.lower()
            absent_in_baseline = marker not in clean_lower
            line = next((ln for ln in injected_headers.splitlines()
                         if marker in ln.lower()), "")
            header_line_present = bool(line.strip())
            if marker_injected and absent_in_baseline and header_line_present:
                met = ["marker_injected", "absent_in_baseline", "header_line_present"]
                conf = confidence_from_criteria(met, CRITERIA_WEIGHTS)
                return {
                    "url": url,
                    "payload": payload,
                    "injected_header": line.strip()[:200],
                    "severity": "HIGH",
                    "confidence": conf,
                    "description": f"CRLF injection at {url} — injected: {line.strip()[:100]}; "
                                   f"proof: {criteria_label(met, CRITERIA_HINTS)}",
                    "proof_criteria": met,
                }
        return None

    @staticmethod
    def _fetch_headers(url: str, timeout: int) -> str | None:
        cmd = [
            "curl", "-s", "-D", "-", "-o", "/dev/null",
            "-m", str(min(timeout, 15)),
            "-A", "Mozilla/5.0 (compatible; CyberSwarm-crlf/1.0)",
            url,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, errors="replace")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
        return proc.stdout
