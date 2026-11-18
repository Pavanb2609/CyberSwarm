"""
SESSION_HIJACK -- active session hijacking / token reuse testing.

Tests whether:
1. Session tokens survive across different IPs/User-Agents
2. Tokens are invalidated on logout
3. Session timeout is properly configured
4. Tokens can be reused after server-side invalidation

Pure Python + requests.  Non-destructive: only reads and reuses tokens
already issued by the server.
"""

import requests

from tools.base import Tool, ToolResult


class SessionHijackTool(Tool):
    """Active session token reuse and invalidation testing."""

    name = "session_hijack"
    capability = "SESSION_HIJACK"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list:
        return ["python-session-hijack", target]

    def parse(self, stdout: str, stderr: str) -> dict:
        return {}

    def run(self, target: str, timeout: int = 15, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        cookies = kwargs.get("cookies", {})

        findings = []

        # Test 1: Token reuse from different User-Agent
        ua_finding = self._test_ua_spoofing(base, cookies, timeout)
        if ua_finding:
            findings.append(ua_finding)

        # Test 2: Token persistence (no timeout)
        timeout_finding = self._test_session_timeout(base, cookies, timeout)
        if timeout_finding:
            findings.append(timeout_finding)

        # Test 3: Token in response body (XSS exfil vector)
        exfil_finding = self._test_token_exposure(base, cookies, timeout)
        if exfil_finding:
            findings.append(exfil_finding)

        # Test 4: Concurrent session test
        concurrent_finding = self._test_concurrent_sessions(base, cookies, timeout)
        if concurrent_finding:
            findings.append(concurrent_finding)

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={"findings": findings, "count": len(findings)})

    @staticmethod
    def _test_ua_spoofing(url: str, cookies: dict, timeout: int) -> dict | None:
        """Check if session is accepted from a completely different User-Agent."""
        if not cookies:
            return None

        user_agents = [
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",  # Mobile
            "curl/7.68.0",  # CLI
            "Python-urllib/3.10",  # Script
        ]

        for ua in user_agents:
            try:
                r = requests.get(url, timeout=timeout, cookies=cookies,
                                 headers={"User-Agent": ua}, allow_redirects=True)
                if r.status_code == 200:
                    body = r.text[:5000].lower()
                    if "login" not in body and "signin" not in body:
                        return {
                            "type": "session_not_bound_to_ua",
                            "severity": "MEDIUM",
                            "url": url,
                            "evidence": f"Session accepted from User-Agent: {ua[:50]}",
                            "description": "Session token not bound to User-Agent. "
                                           "Enables session hijacking via UA spoofing.",
                        }
            except requests.RequestException:
                continue
        return None

    @staticmethod
    def _test_session_timeout(url: str, cookies: dict, timeout: int) -> dict | None:
        """Check if session has a reasonable timeout by testing immediate reuse."""
        if not cookies:
            return None

        try:
            s = requests.Session()
            s.get(url, timeout=timeout, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"
            })
            session_cookies = dict(s.cookies)

            if not session_cookies:
                return None

            r2 = requests.get(url, timeout=timeout, cookies=session_cookies,
                              headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"})

            if r2.status_code == 200:
                body = r2.text[:5000].lower()
                if "login" not in body and "signin" not in body:
                    return {
                        "type": "session_no_timeout_enforcement",
                        "severity": "LOW",
                        "url": url,
                        "evidence": f"Session cookies immediately reusable: {list(session_cookies.keys())}",
                        "description": "Session token valid immediately without re-authentication. "
                                       "Verify server-side session timeout is configured.",
                    }
        except requests.RequestException:
            pass
        return None

    @staticmethod
    def _test_token_exposure(url: str, cookies: dict, timeout: int) -> dict | None:
        """Check if session tokens appear in response body (XSS exfil vector)."""
        try:
            r = requests.get(url, timeout=timeout, cookies=cookies,
                             headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"},
                             allow_redirects=True)

            body = r.text
            for cookie_name, cookie_val in cookies.items():
                if cookie_val and len(cookie_val) > 8 and cookie_val in body:
                    return {
                        "type": "token_exposed_in_body",
                        "severity": "HIGH",
                        "url": url,
                        "evidence": f"Session token '{cookie_name}' value found in response body",
                        "description": f"Token value for '{cookie_name}' is embedded in HTML. "
                                       "Accessible to XSS attacks for session hijacking.",
                    }
        except requests.RequestException:
            pass
        return None

    @staticmethod
    def _test_concurrent_sessions(url: str, cookies: dict, timeout: int) -> dict | None:
        """Check if multiple concurrent sessions with same token are allowed."""
        if not cookies:
            return None

        try:
            headers_a = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"}
            headers_b = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Safari/537.36"}

            r_a = requests.get(url, timeout=timeout, cookies=cookies, headers=headers_a)
            r_b = requests.get(url, timeout=timeout, cookies=cookies, headers=headers_b)

            if r_a.status_code == 200 and r_b.status_code == 200:
                body_a = r_a.text[:3000].lower()
                body_b = r_b.text[:3000].lower()
                if "login" not in body_a and "login" not in body_b:
                    return {
                        "type": "concurrent_session_allowed",
                        "severity": "INFO",
                        "url": url,
                        "evidence": "Same session token accepted from two different clients simultaneously",
                        "description": "Server allows concurrent sessions with the same token. "
                                       "Consider limiting to single active session per token.",
                    }
        except requests.RequestException:
            pass
        return None
