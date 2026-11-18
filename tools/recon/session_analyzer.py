"""
SESSION_ANALYZER -- passive session token and cookie security analysis.

Analyzes session tokens for:
- Entropy (token length, randomness, predictability)
- Transmission security (URL leakage, Secure flag, HttpOnly)
- Token format (Base64, JWT, sequential IDs)
- Session configuration (timeout, SameSite, domain scope)

Pure Python + requests.  No destructive actions.
"""

import math
import re
import string
from collections import Counter

import requests

from tools.base import Tool, ToolResult


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _charset_size(token: str) -> int:
    """Estimate the character set size used in the token."""
    chars = set(token)
    if all(c in string.digits for c in chars):
        return 10
    if all(c in string.hexdigits.lower() for c in chars):
        return 16
    if all(c in string.hexdigits for c in chars):
        return 36
    if all(c in string.ascii_letters + string.digits for c in chars):
        return 62
    if all(c in string.ascii_letters + string.digits + "-_" for c in chars):
        return 64
    if all(c in string.printable for c in chars):
        return 95
    return 128


def _estimate_bit_strength(token: str) -> float:
    """Estimate cryptographic bit strength of a token."""
    cs = _charset_size(token)
    if cs <= 1:
        return 0.0
    return len(token) * math.log2(cs)


def _detect_format(token: str) -> str:
    """Detect the token format."""
    # Sequential/numeric
    if token.isdigit():
        return "sequential_numeric"
    # JWT
    if token.count(".") == 2 and len(token.split(".")[0]) > 10:
        return "jwt"
    # Base64
    try:
        import base64
        decoded = base64.b64decode(token)
        if len(decoded) > 4:
            return "base64_encoded"
    except Exception:
        pass
    # Hex
    if re.match(r'^[0-9a-fA-F]+$', token) and len(token) >= 16:
        return "hex"
    # UUID
    if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', token):
        return "uuid"
    # Alphanumeric
    if re.match(r'^[a-zA-Z0-9]+$', token):
        return "alphanumeric"
    return "unknown"


class SessionAnalyzerTool(Tool):
    """Passive session token and cookie security analysis."""

    name = "session_analyzer"
    capability = "SESSION_ANALYSIS"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> list:
        return ["python-session-analyzer", target]

    def parse(self, stdout: str, stderr: str) -> dict:
        return {}

    def run(self, target: str, timeout: int = 15, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        auth_paths = kwargs.get("auth_paths", [])

        urls_to_check = [base]
        for p in auth_paths[:5]:
            url = base.rstrip("/") + "/" if not p.startswith("/") else base.rstrip("/")
            urls_to_check.append(base.rstrip("/") + p)

        all_sessions = []
        for url in urls_to_check:
            try:
                r = requests.get(url, timeout=timeout, headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0"
                }, allow_redirects=True)
                cookies = r.cookies
                set_cookie_headers = []
                for h in r.headers.items():
                    if h[0].lower() == "set-cookie":
                        set_cookie_headers.append(h[1])

                for cookie in cookies:
                    token = cookie.value
                    if not token or len(token) < 4:
                        continue

                    analysis = self._analyze_token(token, cookie.name, set_cookie_headers)
                    all_sessions.append(analysis)

            except requests.RequestException:
                continue

        if not all_sessions:
            return ToolResult(tool=self.name, status="success", capability=self.capability,
                              results={"sessions": [], "count": 0,
                                       "message": "No session tokens found"})

        risky = [s for s in all_sessions if s["risk"] in ("HIGH", "CRITICAL")]
        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={
                              "sessions": all_sessions,
                              "count": len(all_sessions),
                              "risky_count": len(risky),
                              "high_risk_tokens": [s["token_name"] for s in risky],
                          })

    @staticmethod
    def _analyze_token(token: str, name: str, set_cookie_headers: list) -> dict:
        entropy = _shannon_entropy(token)
        bit_strength = _estimate_bit_strength(token)
        fmt = _detect_format(token)

        # Check flags from Set-Cookie headers
        cookie_flags = {"secure": False, "httponly": False, "samesite": False, "domain_restricted": False}
        for raw in set_cookie_headers:
            if name in raw.split("=")[0]:
                raw_lower = raw.lower()
                cookie_flags["secure"] = "secure" in raw_lower
                cookie_flags["httponly"] = "httponly" in raw_lower
                cookie_flags["samesite"] = "samesite=" in raw_lower
                cookie_flags["domain_restricted"] = "domain=" in raw_lower
                break

        issues = []
        if not cookie_flags["secure"]:
            issues.append("Missing Secure flag — token transmittable over HTTP")
        if not cookie_flags["httponly"]:
            issues.append("Missing HttpOnly — token accessible via JavaScript (XSS -> session theft)")
        if not cookie_flags["samesite"]:
            issues.append("Missing SameSite — vulnerable to CSRF-based session fixation")
        if fmt == "sequential_numeric":
            issues.append("Sequential numeric token — trivially predictable")
        if bit_strength < 40:
            issues.append(f"Low entropy ({bit_strength:.0f} bits) — brute-force feasible")
        if fmt == "jwt" and token.split(".")[1]:
            issues.append("JWT detected — verify algorithm/claims server-side")
        if entropy < 3.0:
            issues.append(f"Low Shannon entropy ({entropy:.2f}) — limited randomness")
        if len(token) < 16:
            issues.append(f"Short token ({len(token)} chars) — may be brute-forceable")

        # Determine risk
        if not cookie_flags["httponly"] and not cookie_flags["secure"]:
            risk = "CRITICAL"
        elif not cookie_flags["httponly"] or fmt == "sequential_numeric" or bit_strength < 40:
            risk = "HIGH"
        elif not cookie_flags["samesite"] or entropy < 3.0:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return {
            "token_name": name,
            "token_length": len(token),
            "token_format": fmt,
            "entropy": round(entropy, 3),
            "bit_strength": round(bit_strength, 1),
            "flags": cookie_flags,
            "issues": issues,
            "risk": risk,
            "sample_token": token[:16] + "..." if len(token) > 16 else token,
        }
