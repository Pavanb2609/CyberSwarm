"""
AUTH_FLOW_ANALYSIS -- enumerate and fingerprint the target's authentication
flow without submitting credentials (passive-ish, single GET/POST-less probes).

For each candidate login/auth endpoint it records: presence of a login form,
form action + input fields, the token mechanism hint (cookie / JWT / OAuth /
CSRF), rate-limit signals, and MFA hints. Seeds the engagement metadata that
LOGIN_FILL / LOGIN_BRUTE / IDOR_TEST consume. Pure Python + requests.
"""

from typing import Any, Dict, List

from tools.base import Tool, ToolResult

DEFAULT_TIMEOUT = 25

LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/admin", "/admin/login",
    "/auth", "/auth/login", "/api/auth/login", "/user/login",
    "/account/login", "/portal", "/wp-login.php",
]

FORM_FIELDS = ("name", "id", "autocomplete", "class")
LOGIN_FIELD_WORDS = ("user", "email", "login", "username", "account")
PASSWORD_FIELD_WORDS = ("pass", "pwd")
CSRF_WORDS = ("csrf", "_token", "authenticity_token", "xsrf", "__requestverificationtoken")
MFA_WORDS = ("2fa", "otp", "two-factor", "twofactor", "totp", "authy", "app code")
JWT_WORDS = ("jwt", "bearer", "authorization")
OAUTH_WORDS = ("oauth", "google.com/o/oauth2", "github.com/login/oauth", "sso")


def _suffixes_for(path: str) -> List[str]:
    return [path, path.rstrip("/") + "/", path.lower()]


class AuthFlowAnalysisTool(Tool):
    name = "auth_flow_analysis"
    capability = "AUTH_FLOW_ANALYSIS"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = DEFAULT_TIMEOUT, **kwargs) -> ToolResult:
        if not hasattr(self, "_http"):
            try:
                import requests
            except ImportError as e:
                return ToolResult(tool=self.name, status="error", capability=self.capability,
                                  error=f"'requests' package not available: {e}")
            self._http = requests

        base = kwargs.get("full_url") or (target if target.startswith("http")
                                          else f"https://{target}")
        base = str(base).rstrip("/")
        paths = [p for p in (kwargs.get("paths") or LOGIN_PATHS) if p]
        if kwargs.get("paths"):
            paths = [p if p.startswith("http") else f"{base}/{p.lstrip('/')}" for p in paths]

        headers = {"User-Agent": "Mozilla/5.0 (compatible; CyberSwarm-auth-flow/1.0)"}
        results = []
        for path in paths:
            url = path if path.startswith("http") else f"{base}{path}"
            found = self._probe_login_url(url, headers, timeout)
            if found is not None and found["status"] in (200, 201, 301, 302, 303, 401, 403):
                results.append(found)

        if not results:
            return ToolResult(tool=self.name, status="success", capability=self.capability,
                              results={"auth_results": [], "login_url": ""})

        mechanisms = sorted({m for r in results for m in r["mechanisms"]})
        login_url = max(results, key=lambda r: r["login_form"]).get("url", "")
        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={
                "auth_results": results,
                "login_url": login_url if any(r["login_form"] for r in results) else "",
                "mechanisms": mechanisms,
                "mfa_detected": any(r["mfa_hint"] for r in results),
                "rate_limited": any(r["rate_limited"] for r in results),
                "csrf_protected": any(r["csrf_field"] for r in results),
            })

    def _probe_login_url(self, url: str, headers: Dict[str, str],
                         timeout: int) -> Dict[str, Any]:
        try:
            resp = self._http.get(url, headers=headers, timeout=timeout,
                                  allow_redirects=True, verify=True)
        except Exception:  # noqa: BLE001 -- TLS/DNS/conn errors
            return None
        blob = resp.text[:200000].lower()
        has_password = 'type="password"' in blob or "type='password'" in blob
        form = "<form" in blob
        login_form = has_password or (form and any(w in blob for w in
                                                   ("login", "signin", "authenticate")))

        mechanisms: List[str] = []
        if any(w in blob for w in JWT_WORDS):
            mechanisms.append("jwt")
        if any(w in blob for w in OAUTH_WORDS):
            mechanisms.append("oauth")
        if resp.headers.get("set-cookie"):
            mechanisms.append("cookie")
        if not mechanisms:
            mechanisms.append("unknown")

        csrf_field = ""
        for name, attrs in self._extract_inputs(resp.text or ""):
            if any(w in attrs for w in CSRF_WORDS):
                csrf_field = name or "hidden_csrf"
                break

        mfa_hint = any(w in blob for w in MFA_WORDS)
        rate_limited = resp.status_code == 429 or bool(resp.headers.get("retry-after"))
        return {
            "url": url,
            "status": resp.status_code,
            "login_form": login_form,
            "has_password_field": has_password,
            "mechanisms": mechanisms,
            "csrf_field": csrf_field,
            "mfa_hint": mfa_hint,
            "rate_limited": rate_limited,
            "set_cookie": resp.headers.get("set-cookie", "")[:200],
            "redirects_to": resp.url if resp.url and resp.url != url else "",
        }

    @staticmethod
    def _extract_inputs(html: str) -> List[str]:
        """Return (name_or_id, attrs_str) for <input ...> tags (rough parse)."""
        out = []
        i = 0
        while True:
            marker = html.find("<input", i)
            if marker < 0:
                break
            end = html.find(">", marker)
            if end < 0:
                break
            tag = html[marker:end]
            i = end + 1
            if "type" in tag and "password" in tag:
                continue
            attrs = tag.lower()
            name = ""
            for key in ("name=", "id="):
                pos = attrs.find(key)
                if pos >= 0:
                    rest = attrs[pos + len(key):].lstrip("\"'")
                    name = rest.split("\"")[0].split("'")[0].split(" ")[0]
                    if name:
                        break
            out.append((name, attrs))
        return out