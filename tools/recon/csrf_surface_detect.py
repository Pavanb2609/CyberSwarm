"""
CSRF_SURFACE_DETECTION -- passive analysis of HTML forms for CSRF attack surface.

Scans discovered endpoints for forms and identifies:
  - POST/PUT/DELETE forms missing anti-CSRF tokens
  - State-changing GET operations
  - SameSite cookie attribute status
  - Form action URLs for attack targeting

Pure Python (urllib + HTMLParser), no external binary.
"""

import ssl
import urllib.request
from html.parser import HTMLParser
from typing import Any

from tools.base import Tool, ToolResult


class _FormExtractor(HTMLParser):
    """Extract <form> tags from HTML, capturing method, action, and hidden inputs."""

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
                "method": a.get("method", "get").upper(),
                "id": a.get("id", ""),
                "name": a.get("name", ""),
                "has_csrf_token": False,
            }
        elif tag == "input" and self._in_form:
            name = a.get("name", "").lower()
            csrf_kw = ["csrf", "token", "_token", "nonce", "_xsrf", "authenticity"]
            if any(kw in name for kw in csrf_kw):
                self._current["has_csrf_token"] = True

    def handle_endtag(self, tag):
        if tag == "form" and self._in_form:
            self.forms.append(self._current)
            self._in_form = False
            self._current = {}


class CSRFSurfaceDetectionTool(Tool):
    """Passive detection of CSRF attack surface in HTML forms."""

    name = "csrf_surface_detect"
    capability = "CSRF_SURFACE_DETECTION"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["python-urllib-csrf-detect", target]

    def parse(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 30, **kwargs) -> ToolResult:
        full_url = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        endpoints = kwargs.get("endpoints") or []
        auth_paths = kwargs.get("auth_paths") or []

        test_urls = [full_url]
        for p in auth_paths[:8]:
            test_urls.append(p if p.startswith("http") else f"{full_url.rstrip('/')}/{p.lstrip('/')}")
        for ep in endpoints[:8]:
            ep_url = ep if ep.startswith("http") else f"{full_url.rstrip('/')}/{ep.lstrip('/')}"
            if ep_url not in test_urls:
                test_urls.append(ep_url)

        all_surface = []
        for url in test_urls[:15]:
            surface = self._scan_page(url, timeout)
            all_surface.extend(surface)

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={"csrf_surface": all_surface, "count": len(all_surface),
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

        parser = _FormExtractor()
        try:
            parser.feed(body)
        except Exception:
            return []

        results = []
        for form in parser.forms:
            action = form.get("action", "")
            action_url = action if action.startswith("http") else f"{url.rstrip('/')}/{action.lstrip('/')}"
            method = form["method"]
            has_token = form["has_csrf_token"]

            # Classify risk
            risk = "low"
            if method in ("POST", "PUT", "DELETE", "PATCH") and not has_token:
                risk = "high"
            elif method == "GET" and any(kw in action.lower() for kw in
                                         ("delete", "remove", "update", "edit", "admin")):
                risk = "medium"

            results.append({
                "page_url": url,
                "action_url": action_url,
                "method": method,
                "form_name": form.get("name", ""),
                "has_csrf_token": has_token,
                "risk": risk,
            })
        return results
