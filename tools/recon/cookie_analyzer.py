"""
COOKIE_ANALYZER -- passive analysis of Set-Cookie headers for security flags.

Checks Secure, HttpOnly, SameSite attributes on all cookies.  Pure Python + requests.
"""

from typing import Any

import requests

from tools.base import Tool, ToolResult


class CookieAnalyzerTool(Tool):
    """Passive cookie security analysis."""

    name = "cookie_analyzer"
    capability = "COOKIE_ANALYSIS"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["python-cookie-analyzer", target]

    def parse(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 15, **kwargs) -> ToolResult:
        full_url = kwargs.get("full_url")
        url = full_url or (target if target.startswith("http") else f"https://{target}")

        set_cookie_headers: list[str] = []
        try:
            r = requests.get(url, timeout=timeout, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"
            }, allow_redirects=True)
            # Iterate raw headers to capture all Set-Cookie values
            # (CaseInsensitiveDict merges them into one string with ", " separator)
            raw_cookie = r.headers.get("Set-Cookie", "")
            if raw_cookie:
                # Split on ", " but be careful with cookie values that contain commas
                # Use a simpler approach: split on "; " boundaries that look like cookie names
                for part in raw_cookie.split("\r\n"):
                    part = part.strip()
                    if part:
                        set_cookie_headers.append(part)
                # Also try comma-split for single-header case
                if len(set_cookie_headers) <= 1 and "," in raw_cookie:
                    # re-split
                    set_cookie_headers = []
                    for part in raw_cookie.split(","):
                        part = part.strip()
                        if "=" in part:
                            set_cookie_headers.append(part)
        except Exception as e:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error=str(e))

        if not set_cookie_headers:
            return ToolResult(tool=self.name, status="success", capability=self.capability,
                              results={"cookies": [], "count": 0, "insecure_count": 0,
                                       "message": "No Set-Cookie headers found"})

        cookies = []
        insecure_count = 0

        for raw in set_cookie_headers:
            name = raw.split("=")[0].strip() if "=" in raw else raw.strip()
            raw_lower = raw.lower()
            flags = {}
            flags["secure"] = "secure" in raw_lower
            flags["httponly"] = "httponly" in raw_lower
            flags["samesite"] = "samesite" in raw_lower

            issues = []
            if not flags["secure"]:
                issues.append("missing Secure flag")
            if not flags["httponly"]:
                issues.append("missing HttpOnly flag")
            if not flags["samesite"]:
                issues.append("missing SameSite attribute")

            if issues:
                insecure_count += 1

            cookies.append({
                "name": name,
                "flags": flags,
                "issues": issues,
                "severity": "MEDIUM" if len(issues) >= 2 else ("LOW" if issues else "INFO"),
            })

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={
                              "cookies": cookies,
                              "count": len(cookies),
                              "insecure_count": insecure_count,
                              "insecure_cookies": [c["name"] for c in cookies if c["issues"]],
                          })
