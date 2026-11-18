"""
IDOR_TEST -- cross-identity horizontal/vertical access-control checks.

Compares access to the same object URL as identity A (the authenticated
context) versus an anonymous/secondary context. A difference where A sees the
object (200 + meaningful body) and the other side is denied (401/403/redirect)
is an IDOR / broken-object-authorization candidate -> HIGH finding.

For object discovery it probes a small, safe set of object-shaped paths
(/user/1, /api/users/1, ...) on hosts/APIs already known in the engagement.
Pure Python + requests. Requires credentials or pre-seeded session cookies
(see LOGIN_FILL) -- without an authenticated context it reports "no session".
"""

from typing import Any, Dict, List, Optional, Tuple

from tools.base import Tool, ToolResult

DEFAULT_TIMEOUT = 8

OBJECT_PATTERNS = [
    "/user/{n}", "/users/{n}", "/api/user/{n}", "/api/users/{n}",
    "/account/{n}", "/profile/{n}", "/profile?id={n}",
    "/api/account/{n}", "/api/profile/{n}", "/v1/users/{n}",
    "/api/orders/{n}", "/order/{n}", "/api/invoices/{n}",
    "/members/{n}", "/api/members/{n}",
]
DEFAULT_OBJECT_IDS = [1, 2, 100, 1000, 10001]


class IDORTestTool(Tool):
    name = "idor_test"
    capability = "IDOR_TEST"
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
        if not hasattr(self, "_http"):
            try:
                import requests
            except ImportError as e:
                return ToolResult(tool=self.name, status="error", capability=self.capability,
                                  error=f"'requests' package not available: {e}")
            self._http = requests

        if ctx is None:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error="no engagement context (IDOR needs current identity A)")
        if not ctx.cookies and not any(
                c.identity == "A" or c.identity != "anonymous" for c in ctx.credentials):
            if not ctx.cookies:
                return ToolResult(tool=self.name, status="success",
                                  capability=self.capability,
                                  results={"tested": 0, "idor_results": [],
                                           "vulnerable": [], "note": "no authenticated session; "
                                            "run LOGIN_FILL first"})

        authed_ctx = ctx
        anon_ctx = ctx.anonymized()
        second_ctx = None
        if ctx.credential_for("B") is not None and not ctx.cookies:
            # If a second identity is supplied but A is anonymous-only, swap:
            # treat supplied identity as the privileged side.
            authed_ctx = ctx
        else:
            second_ctx = anon_ctx

        base_origins, api_origins = self._origins(target, ctx, kwargs)
        results: List[Dict[str, Any]] = []
        vulnerable: List[Dict[str, Any]] = []
        tested = 0

        for origin in list(base_origins) + list(api_origins):
            for pattern in OBJECT_PATTERNS:
                for n in self._object_ids(kwargs):
                    url = origin + pattern.format(n=n)
                    a_status, a_body = self._fetch(url, authed_ctx, timeout)
                    tested += 1
                    if a_status is None or a_body is None:
                        continue
                    if a_status in (401, 403) or a_body == b"unauthorized":
                        continue  # not accessible even to A - not an IDOR
                    b_status, b_body = self._fetch(url, second_ctx, timeout)
                    denied = b_status in (401, 403) or (b_status is None)
                    if denied:
                        record = {
                            "url": url,
                            "authed_status": a_status,
                            "other_status": b_status,
                            "identity_a": "A",
                            "identity_b": second_ctx.identity if second_ctx else "anonymous",
                        }
                        results.append(record)
                        vulnerable.append(record)

        if not tested:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error="no object URLs to test (no base_url/API origins)")

        out: Dict[str, Any] = {
            "tested": tested, "idor_results": results, "vulnerable": vulnerable,
        }
        if vulnerable:
            out["vulnerabilities"] = [
                {"name": "IDOR - cross-identity object access",
                 "severity": "HIGH", "url": v["url"],
                 "kind": "idor"} for v in vulnerable]
        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results=out)

    # ── internals ─────────────────────────────────────────────────────────

    def _origins(self, target: str, ctx, kwargs) -> Tuple[List[str], List[str]]:
        base = []
        if ctx.base_url:
            base.append(str(ctx.base_url).rstrip("/"))
        if not base:
            t = target if target.startswith("http") else f"https://{target}"
            base.append(t.rstrip("/"))
        for extra in (kwargs.get("base_urls") or []):
            base.append(str(extra).rstrip("/"))
        api = [f"{b}{p}" for b in base
               for p in ("/api", "/v1", "/api/v1", "/graphql") if b]
        return base, api

    @staticmethod
    def _object_ids(kwargs) -> List[int]:
        ids = [int(x) for x in (kwargs.get("object_ids") or []) if str(x).isdigit()]
        return ids or DEFAULT_OBJECT_IDS[:3]

    def _fetch(self, url: str, ctx, timeout: int) -> Tuple[Optional[int], Optional[bytes]]:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; CyberSwarm-idor/1.0)"}
        for k, v in ctx.headers.items():
            headers.setdefault(k, str(v))
        cookie_str = ctx.cookie_str()
        if cookie_str:
            headers["Cookie"] = cookie_str
        try:
            resp = self._http.get(url, headers=headers, timeout=timeout,
                                  allow_redirects=True, verify=True)
        except Exception:  # noqa: BLE001
            return None, None
        body = resp.content[:4000] if resp.content else b""
        return resp.status_code, body