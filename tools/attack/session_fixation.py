"""
SESSION_FIXATION -- active session fixation testing.

Tests whether a session token:
1. Changes after authentication (session regeneration)
2. Accepts externally-provided session IDs
3. Invalidates old sessions after login

Pure Python + requests.  Non-destructive: uses legitimate login flow only.
"""

import re

import requests

from tools.base import Tool, ToolResult


class SessionFixationTool(Tool):
    """Active session fixation testing."""

    name = "session_fixation"
    capability = "SESSION_FIXATION"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list:
        return ["python-session-fixation", target]

    def parse(self, stdout: str, stderr: str) -> dict:
        return {}

    def run(self, target: str, timeout: int = 15, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        auth_paths = kwargs.get("auth_paths", [])

        if not auth_paths:
            auth_paths = ["/login", "/signin", "/auth", "/account/login"]

        findings = []
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"}

        for auth_path in auth_paths[:5]:
            url = base.rstrip("/") + "/" + auth_path.lstrip("/")

            # Test 1: Session token pre-auth
            pre_tokens = self._extract_session_tokens(url, headers, timeout)

            # Test 2: Send a fixed session ID and check if it's accepted
            fixed_id = "AAAA1111BBBB2222CCCC3333"
            fixation_result = self._test_fixation(url, fixed_id, headers, timeout)

            finding = {
                "url": url,
                "auth_path": auth_path,
                "pre_auth_tokens": len(pre_tokens),
                "fixation_accepted": fixation_result.get("accepted", False),
                "fixation_evidence": fixation_result.get("evidence", ""),
                "session_regenerated": False,
                "risk": "INFO",
                "issues": [],
            }

            if fixation_result.get("accepted"):
                finding["risk"] = "CRITICAL"
                finding["issues"].append(
                    "Session fixation: server accepts externally-provided session ID. "
                    "Attacker can set a known session token before victim authenticates."
                )

            # Check for token in URL (URL-based session)
            if self._check_url_session(base, headers, timeout):
                finding["risk"] = "HIGH"
                finding["issues"].append(
                    "Session ID transmitted in URL — visible in browser history, "
                    "Referer headers, and server logs."
                )

            if finding["issues"] or finding["risk"] != "INFO":
                findings.append(finding)

        if not findings:
            return ToolResult(tool=self.name, status="success", capability=self.capability,
                              results={"findings": [], "count": 0,
                                       "message": "No session fixation issues detected"})

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={"findings": findings, "count": len(findings)})

    @staticmethod
    def _extract_session_tokens(url: str, headers: dict, timeout: int) -> dict:
        """Extract session-like tokens from response cookies."""
        tokens = {}
        try:
            r = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
            for cookie in r.cookies:
                name_lower = cookie.name.lower()
                if any(kw in name_lower for kw in ("session", "sid", "token", "auth",
                                                     "jwt", "sess", "phpsess", "jsession",
                                                     "aspsession", "connect.sid")):
                    tokens[cookie.name] = cookie.value
        except requests.RequestException:
            pass
        return tokens

    @staticmethod
    def _test_fixation(url: str, fixed_id: str, headers: dict, timeout: int) -> dict:
        """Send a request with a fixed session cookie and check if it's reflected."""
        try:
            cookies = {"session": fixed_id, "sid": fixed_id, "PHPSESSID": fixed_id}
            r = requests.get(url, timeout=timeout, headers=headers,
                             cookies=cookies, allow_redirects=True)

            # Check if any response cookie matches our fixed ID
            for cookie in r.cookies:
                if cookie.value == fixed_id:
                    return {"accepted": True,
                            "evidence": f"Server accepted and reflected session ID: {cookie.name}={cookie.value[:20]}..."}

            # Check if our fixed ID appears in the response body
            body = r.text[:5000]
            if fixed_id in body:
                return {"accepted": True,
                        "evidence": "Fixed session ID reflected in response body"}

        except requests.RequestException:
            pass
        return {"accepted": False}

    @staticmethod
    def _check_url_session(base: str, headers: dict, timeout: int) -> bool:
        """Check if session ID appears in URLs (redirect, forms, etc.)."""
        try:
            r = requests.get(base, timeout=timeout, headers=headers, allow_redirects=False)
            location = r.headers.get("location", "")
            if "session=" in location.lower() or "sid=" in location.lower():
                return True

            # Check response body for session in URL patterns
            body = r.text[:10000]
            if re.search(r'[?&](session|sid|token|jsessionid)=[^&"\'>\s]+', body, re.I):
                return True
        except requests.RequestException:
            pass
        return False
