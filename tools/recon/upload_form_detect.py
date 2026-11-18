"""
UPLOAD_FORM_DETECTION -- passive detection of file upload forms in HTML pages.

Scans discovered endpoints for <input type="file"> elements and reports:
  - Upload form URLs and input field names
  - Accept attribute restrictions (or lack thereof)
  - enctype settings

Pure Python (urllib + HTMLParser), no external binary.
"""

import ssl
import urllib.request
from html.parser import HTMLParser
from typing import Any

from tools.base import Tool, ToolResult


class _UploadFormDetector(HTMLParser):
    """Detect <input type="file"> in HTML pages."""

    def __init__(self):
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._in_form = False
        self._current: dict[str, Any] = {}

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): v for k, v in attrs}
        if tag == "form":
            self._in_form = True
            self._current = {
                "action": a.get("action", ""),
                "method": a.get("method", "post").upper(),
                "enctype": a.get("enctype", ""),
                "has_file_input": False,
                "file_input_name": "",
                "file_input_accept": "",
            }
        elif tag == "input" and self._in_form and a.get("type", "").lower() == "file":
            self._current["has_file_input"] = True
            self._current["file_input_name"] = a.get("name", "")
            self._current["file_input_accept"] = a.get("accept", "")

    def handle_endtag(self, tag):
        if tag == "form" and self._in_form:
            if self._current.get("has_file_input"):
                self.forms.append(self._current)
            self._in_form = False
            self._current = {}


class UploadFormDetectionTool(Tool):
    """Passive detection of file upload forms."""

    name = "upload_form_detect"
    capability = "UPLOAD_FORM_DETECTION"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["python-urllib-upload-detect", target]

    def parse(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 30, **kwargs) -> ToolResult:
        full_url = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        endpoints = kwargs.get("endpoints") or []

        test_urls = [full_url]
        for ep in endpoints[:10]:
            ep_url = ep if ep.startswith("http") else f"{full_url.rstrip('/')}/{ep.lstrip('/')}"
            if ep_url not in test_urls:
                test_urls.append(ep_url)

        all_forms = []
        for url in test_urls[:15]:
            forms = self._scan_page(url, timeout)
            all_forms.extend(forms)

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={"upload_forms": all_forms, "count": len(all_forms),
                     "tested_urls": test_urls[:15]},
        )

    @staticmethod
    def _scan_page(url: str, timeout: int) -> list[dict[str, Any]]:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url, method="GET",
            headers={"User-Agent": "Mozilla/5.0 (compatible; CyberSwarm-recon/1.0)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(50000).decode("utf-8", errors="replace")
        except Exception:
            return []

        parser = _UploadFormDetector()
        try:
            parser.feed(body)
        except Exception:
            return []

        results = []
        for form in parser.forms:
            action = form.get("action", "")
            action_url = action if action.startswith("http") else f"{url.rstrip('/')}/{action.lstrip('/')}"
            accept = form.get("file_input_accept", "")
            results.append({
                "page_url": url,
                "action_url": action_url,
                "method": form.get("method", "POST"),
                "input_name": form.get("file_input_name", ""),
                "accept": accept,
                "has_type_restriction": bool(accept),
                "enctype": form.get("enctype", ""),
            })
        return results
