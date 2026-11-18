"""
LOGIN_FILL -- authenticate as identity A/B using the engagement's credentials
and persist the session cookies into EngagementContext so every later tool is
credentialed. Pure Python + requests.

Non-destructive login: it performs the login handshake the app expects
(CSRF token fetch, form POST, redirect following) and records the outcome as
evidence. On success it updates ctx.cookies in place -- the same mutable
object the Controller passes to all tools -- so subsequent capabilities
(idor_test, api_probe, ...) automatically run authenticated.
"""

from typing import Any, Dict, List, Optional

from tools.base import Tool, ToolResult

DEFAULT_TIMEOUT = 30

LOGIN_CANDIDATES = [
    "/login", "/signin", "/sign-in", "/admin/login", "/auth/login",
    "/api/auth/login", "/user/login", "/wp-login.php",
]


class LoginFillTool(Tool):
    name = "login_fill"
    capability = "LOGIN_FILL"
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
        ctx = kwargs.get("context")
        if ctx is None or not ctx.credentials:
            return ToolResult(
                tool=self.name, status="error", capability=self.capability,
                error="LOGIN_FILL needs credentials: pass --creds-file, or supply "
                      "context.credentials")

        cred = ctx.credential_for()
        if cred is None:
            return ToolResult(
                tool=self.name, status="error", capability=self.capability,
                error="multiple anonymous credentials; tag identities in the creds "
                      "file and set --identity")

        try:
            if not hasattr(self, "_http"):
                import requests
                self._http = requests
        except ImportError as e:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error=f"'requests' package not available: {e}")

        base = ctx.base_url or (target if target.startswith("http")
                                else f"https://{target}")
        base = str(base).rstrip("/")
        login_url = kwargs.get("login_url")
        if not login_url:
            for path in LOGIN_CANDIDATES:
                maybe = self._find_login_page(f"{base}{path}", timeout)
                if maybe:
                    login_url = maybe
                    break
        if not login_url:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error="no login form found at the usual paths; pass --login-url")

        outcome = self._submit(login_url, cred.username, cred.password, ctx, timeout)
        if outcome["authenticated"]:
            ctx.identity = cred.identity if cred.identity and cred.identity != "anonymous" \
                else ctx.identity
            return ToolResult(tool=self.name, status="success", capability=self.capability,
                              results={
                                  "authenticated": True,
                                  "mechanism": outcome["mechanism"],
                                  "username": cred.username,
                                  "final_url": outcome["final_url"],
                                  "status_code": outcome["status_code"],
                                  "session_cookie": outcome.get("session_cookie", ""),
                                  "session_assets": [f"{cred.username}@{target}"],
                              })

        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={"authenticated": False, "reason": outcome.get("reason"),
                                   "login_url": login_url, "username": cred.username})

    # ── internals ─────────────────────────────────────────────────────────

    def _find_login_page(self, url: str, timeout: int) -> Optional[str]:
        try:
            resp = self._http.get(url, timeout=timeout, allow_redirects=True, verify=True,
                                  headers={"User-Agent": self._ua()})
        except Exception:  # noqa: BLE001
            return None
        if resp.status_code != 200:
            return None
        blob = resp.text[:200000]
        if 'type="password"' in blob.lower():
            return resp.url or url
        return None

    def _submit(self, login_url: str, username: str, password: str, ctx,
                timeout: int) -> Dict[str, Any]:
        session = self._http.Session()
        session.headers["User-Agent"] = self._ua()
        if ctx.cookies:
            session.cookies.update(ctx.cookies)
        try:
            page = session.get(login_url, timeout=timeout, verify=True)
        except Exception as e:  # noqa: BLE001
            return {"authenticated": False, "reason": f"GET failed: {e}"}

        csrf = self._csrf_value(page.text or "")
        fields = {"username": username, "password": password,
                  "email": username, "login": username, "user_login": username}
        if csrf:
            fields.setdefault(csrf["name"], csrf["value"])

        post_url = self._form_action(login_url, page.text or "")
        try:
            resp = session.post(post_url, data=fields, timeout=timeout, verify=True,
                                allow_redirects=True)
        except Exception as e:  # noqa: BLE001
            return {"authenticated": False, "reason": f"POST failed: {e}"}

        body = resp.text[:200000].lower() if resp.text else ""
        # Heuristic: a successful form login redirects off login / drops a
        # session cookie / no longer shows a password field.
        authenticated = False
        if resp.url and "login" not in resp.url.rstrip("/").split("/")[-1]:
            authenticated = True
        if "session" in {c.name.lower() for c in session.cookies}:
            authenticated = authenticated or len(session.cookies) > 0
        if 'type="password"' in body and "login" in body:
            authenticated = False
        if authenticated:
            new_cookies = {c.name: c.value for c in session.cookies}
            ctx.update_cookies(new_cookies)
        redir = resp.url if resp.url and resp.url != post_url else ""
        return {
            "authenticated": authenticated,
            "mechanism": "cookie",
            "final_url": redir,
            "status_code": resp.status_code,
            "reason": "" if authenticated else "no redirect / no session cookie / login form re-rendered",
            "session_cookie": next((n for n in {c.name for c in session.cookies}
                                    if "session" in n.lower() or "sess" in n.lower()), ""),
        }

    @staticmethod
    def _ua() -> str:
        return "Mozilla/5.0 (compatible; CyberSwarm-login-fill/1.0)"

    @staticmethod
    def _csrf_value(html: str) -> Optional[Dict[str, str]]:
        i = 0
        while True:
            marker = html.find("<input", i)
            if marker < 0:
                return None
            end = html.find(">", marker)
            if end < 0:
                return None
            tag = html[marker:end].lower()
            i = end + 1
            if any(w in tag for w in ("csrf", "_token", "authenticity_token",
                                      "xsrf", "__requestverificationtoken")):
                name = LoginFillTool._attr(tag, "name") or "_csrf"
                value = LoginFillTool._attr(tag, "value") or ""
                return {"name": name, "value": value}
        return None

    @staticmethod
    def _attr(tag: str, key: str) -> str:
        needle = f"{key}="
        pos = tag.find(needle)
        if pos < 0:
            return ""
        rest = tag[pos + len(needle):].lstrip("\"'")
        return rest.split("\"")[0].split("'")[0].split(" ")[0]

    @staticmethod
    def _form_action(login_url: str, html: str) -> str:
        marker = html.lower().find("<form")
        base = login_url.rsplit("/", 1)[0]
        if marker < 0:
            return login_url
        end = html.find(">", marker)
        if end < 0:
            return login_url
        tag = html[marker:end]
        action = LoginFillTool._attr(tag, "action")
        if not action:
            return login_url
        if action.startswith("http"):
            return action
        return f"{base.rstrip('/')}/{action.lstrip('/')}"