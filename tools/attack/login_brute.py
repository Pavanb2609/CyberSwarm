"""
LOGIN_BRUTE -- credential brute-force / stuffing.

Two paths, both designed around the engagement context:
  1. hydra (external binary, ACTIVE_HIGH): a full http-post-form/http-get-form
     run. Only used when the user supplies `brute_spec` via --assess kwargs
     (login_url, form field names, failure string); otherwise skipped.
  2. Pure-Python fallback (always available): basic-auth brute from the creds
     file, plus a bundled top-N default list for form logins when a login
     page is found. No external dependencies.

On a hit it returns finding-shaped results (weak-credentials, HIGH) so the
Controller records a finding automatically.
"""

from typing import Any, Dict, List, Optional

from tools.base import Tool, ToolResult

DEFAULT_TIMEOUT = 45

# Small top-N default credential list (same spirit as the classic
# admin/password lists; expand via `defaults_file` kwarg for real runs).
DEFAULT_CREDENTIALS: List[tuple] = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "changeme"), ("root", "toor"),
    ("root", "root"), ("root", "password"), ("user", "user"),
    ("test", "test"), ("guest", "guest"), ("administrator", "admin"),
    ("administrator", "password"), ("admin", "letmein"), ("admin", "welcome"),
    ("admin", "qwerty"), ("oracle", "oracle"), ("postgres", "postgres"),
    ("tomcat", "tomcat"), ("admin", "1234"), ("admin", "0000"),
    ("admin", "P@ssw0rd"), ("demo", "demo"), ("ftp", "ftp"),
]


class LoginBruteTool(Tool):
    name = "login_brute"
    capability = "LOGIN_BRUTE"
    binary = "hydra"

    def is_available(self) -> bool:
        return super().is_available()

    def build_command(self, target: str, **kwargs) -> List[str]:
        spec = kwargs.get("brute_spec") or {}
        hosts = [t for t in (spec.get("host") or target or "").split(",") if t]
        host = hosts[0] if hosts else target
        scheme = spec.get("scheme", "https")
        login_url = str(spec.get("login_url", "/login"))
        users = spec.get("userlist") or kwargs.get("userlist")
        passes = spec.get("passwordlist") or kwargs.get("passwordlist")
        cmd = ["hydra", "-L", users, "-P", passes, "-s",
               str(spec.get("port", "443" if scheme == "https" else "80"))]
        if spec.get("http_method") == "get":
            cmd += [f"{host}", "http-get-form", f"{login_url}:{spec.get('failure', '')}=S:302"]
        else:
            cmd += ["-f", host, "http-post-form",
                    f"{login_url}:{spec.get('user_field', 'username')}={{^USER^}}&"
                    f"{spec.get('pass_field', 'password')}={{^PASS^}}"
                    f":{spec.get('failure', 'login')}=F"]
        return cmd

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse hydra text output into structured findings."""
        hits = []
        for line in (stdout or "").splitlines():
            if "[80]" in line or "[443]" in line:
                parts = line.split()
                user = passw = ""
                for p in parts:
                    if p.startswith("login:"):
                        user = p.split(":", 1)[1].strip('"')
                    if p.startswith("password:"):
                        passw = p.split(":", 1)[1].strip('"')
                if user:
                    hits.append({"username": user, "password": passw})
        return {"brute_results": hits, "source": "hydra"}

    def run(self, target: str, timeout: int = DEFAULT_TIMEOUT, **kwargs) -> ToolResult:
        ctx = kwargs.get("context")
        brute_spec = kwargs.get("brute_spec")
        if brute_spec and self.is_available():
            return super().run(target, timeout=timeout, **kwargs)
        # Pure-Python fallback
        if not hasattr(self, "_http"):
            try:
                import requests
            except ImportError as e:
                return ToolResult(tool=self.name, status="error", capability=self.capability,
                                  error=f"'requests' package not available: {e}")
            self._http = requests
        return self._python_brute(target, ctx, kwargs, timeout)

    # ── pure-python fallback ──────────────────────────────────────────────

    def _python_brute(self, target: str, ctx, kwargs, timeout: int) -> ToolResult:
        base = ctx.base_url if ctx and ctx.base_url else (
            target if target.startswith("http") else f"https://{target}")
        base = str(base).rstrip("/")

        creds: List[tuple] = []
        if ctx and ctx.credentials:
            creds = [(c.username, c.password) for c in ctx.credentials]
        extras = kwargs.get("extra_creds") or []
        for e in extras:
            if isinstance(e, (list, tuple)) and len(e) >= 2:
                creds.append((str(e[0]), str(e[1])))
        if not extras:
            extras_source = kwargs.get("defaults_file")
            if extras_source:
                try:
                    from pathlib import Path
                    for line in Path(extras_source).read_text().splitlines():
                        if ":" in line and not line.startswith("#"):
                            creds.append(tuple(line.strip().split(":", 1)))
                except OSError:
                    pass
            else:
                creds = creds + DEFAULT_CREDENTIALS

        seen, unique = set(), []
        for c in creds:
            if c not in seen and c[0] and c[1]:
                seen.add(c)
                unique.append(c)

        checks, hits = [], []
        tried = self._probe_basic(base, unique, timeout)
        for url, username, password, status, hit in tried:
            checks.append({"url": url, "username": username, "status": status,
                           "hit": bool(hit)})
            if hit:
                hits.append({"url": url, "username": username, "password": password})

        # If no basic-auth barrier was present, try default creds against a
        # discovered login form (form POST).
        if not any(c["status"] == 401 for c in checks):
            login_url = kwargs.get("login_url")
            if not login_url:
                login_url = self._find_login_form(base, timeout)
            if login_url:
                for username, password in unique[: len(unique)]:
                    r = self._post_once(login_url, username, password, timeout)
                    if r is None:
                        continue
                    status, ok, body = r
                    checks.append({"url": login_url, "username": username,
                                   "status": status, "hit": ok})
                    if ok:
                        hits.append({"url": login_url, "username": username,
                                     "password": password})
                        break  # stop guessing once a working credential is confirmed --
                               # every further attempt is a live login POST against the
                               # real target with zero additional benefit and real
                               # lockout/alerting risk

        if not checks:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error="no auth barrier found (no 401 basic-auth, no login form)")

        results: Dict[str, Any] = {"brute_results": checks, "attempts": len(checks),
                                   "hits": len(hits), "hits_detail": hits,
                                   "source": "python-fallback"}
        if hits:
            results["vulnerabilities"] = [
                {"name": f"weak-credentials for {h['username']}",
                 "severity": "HIGH", "url": h["url"], "kind": "weak-credentials",
                 "credential": f"{h['username']}@{target}"} for h in hits]
        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results=results)

    def _probe_basic(self, base: str, creds: List[tuple],
                     timeout: int) -> List[tuple]:
        """Return (url, username, password, status, hit) for basic-auth."""
        out = []
        try:
            head = self._http.get(base, timeout=timeout, allow_redirects=True, verify=True)
            challenged = head.status_code == 401 and "basic" in (head.headers.get(
                "www-authenticate", "") or "").lower()
        except Exception:  # noqa: BLE001
            return out
        if not challenged:
            for path in ("/", "/admin", "/console"):
                try:
                    r = self._http.get(f"{base}{path}", timeout=timeout, verify=True)
                except Exception:  # noqa: BLE001
                    continue
                if r.status_code == 401 and "basic" in (
                        r.headers.get("www-authenticate", "") or "").lower():
                    challenged = True
                    break
        if not challenged:
            out.append((base, "", "", head.status_code, False))
            return out

        HTTPBasicAuth = getattr(self._http, "HTTPBasicAuth", None)
        if HTTPBasicAuth is None:
            from requests.auth import HTTPBasicAuth
        session = self._http.Session()
        for username, password in creds:
            try:
                r = session.get(base, auth=HTTPBasicAuth(username, password),
                                timeout=timeout, allow_redirects=True, verify=True)
            except Exception:  # noqa: BLE001
                continue
            hit = r.status_code == 200
            out.append((base, username, password, r.status_code, hit))
            if hit:
                break
        return out

    def _find_login_form(self, base: str, timeout: int) -> Optional[str]:
        for path in ("/login", "/admin/login", "/wp-login.php"):
            try:
                r = self._http.get(f"{base}{path}", timeout=timeout, verify=True)
            except Exception:  # noqa: BLE001
                continue
            if r.status_code == 200 and 'type="password"' in (r.text or "").lower():
                return f"{base}{path}"
        return None

    def _post_once(self, login_url: str, username: str, password: str,
                   timeout: int) -> Optional[tuple]:
        try:
            s = self._http.Session()
            page = s.get(login_url, timeout=timeout, verify=True)
            data = {"username": username, "password": password,
                    "login": username, "user_login": username, "email": username}
            resp = s.post(login_url, data=data, timeout=timeout,
                          allow_redirects=True, verify=True)
        except Exception:  # noqa: BLE001
            return None
        body = (resp.text or "").lower()
        ok = (resp.status_code == 200 and "login" not in body
              and 'type="password"' not in body) or \
             (resp.status_code in (301, 302, 303) and "login" not in resp.url.lower())
        return (resp.status_code, ok, resp.url)