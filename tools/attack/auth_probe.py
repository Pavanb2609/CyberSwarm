"""
AUTH_PROBE -- live-probes authentication / admin / login paths with plain HTTP
GETs and records evidence: status code, redirect target, login-form presence,
and Set-Cookie flags (Secure / HttpOnly / SameSite). Pure Python, no binary.
Non-destructive: single GET per path, no submissions.
"""

import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List

from tools.base import Tool, ToolResult

DEFAULT_TIMEOUT = 30


class AuthProbeTool(Tool):
    name = "auth_probe"
    capability = "AUTH_PROBE"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["python-urllib-auth-probe", target]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = DEFAULT_TIMEOUT, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or f"https://{target}"
        paths = [p for p in (kwargs.get("paths") or []) if p][:12]
        if not paths:
            paths = [f"{base}/login", f"{base}/admin"]
        else:
            paths = [p if p.startswith("http") else f"{base.rstrip('/')}/{p.lstrip('/')}"
                     for p in paths]

        checks = []
        for url in paths:
            probe = self._probe_one(url, timeout)
            if probe is not None:
                checks.append(probe)

        if not checks:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error="No auth paths responded over HTTPS/HTTP.")
        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={"auth_checks": checks, "target": target})

    @staticmethod
    def _probe_one(url: str, timeout: int) -> Dict[str, Any]:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url, method="GET",
            headers={"User-Agent": "Mozilla/5.0 (compatible; CyberSwarm-auth-probe/1.0)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                final_url = resp.geturl()
                status = resp.status
                headers = {k.lower(): v for k, v in resp.getheaders()}
                body = resp.read(30000).decode("utf-8", errors="replace")
                return AuthProbeTool._analyze(url, final_url, status, headers, body)
        except urllib.error.HTTPError as e:
            final_url = e.geturl() if hasattr(e, "geturl") else url
            headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            return AuthProbeTool._analyze(url, final_url, e.code, headers, "")
        except Exception:  # noqa: BLE001 -- DNS/TLS/conn refused/timeout
            return None

    @staticmethod
    def _analyze(url: str, final_url: str, status: int,
                 headers: Dict[str, str], body: str) -> Dict[str, Any]:
        login_form = False
        blob = body.lower()
        if 'type="password"' in blob:
            login_form = True
        elif "<form" in blob and any(w in blob for w in ("login", "signin", "authenticate")):
            login_form = True

        set_cookie = headers.get("set-cookie", "")
        cookie_flags = {
            "secure": "secure" in set_cookie.lower(),
            "httponly": "httponly" in set_cookie.lower(),
            "samesite": "samesite=" in set_cookie.lower(),
        }

        return {
            "url": url,
            "status": status,
            "final_url": final_url,
            "redirected": final_url != url,
            "login_form": login_form,
            "set_cookie": set_cookie[:200],
            "cookie_flags": cookie_flags,
            "server": headers.get("server", ""),
            "auth_required": status in (401, 403),
        }
