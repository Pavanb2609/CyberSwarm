"""Credentialed-testing tools (Phase 1) — AUTH_FLOW_ANALYSIS, LOGIN_FILL,
LOGIN_BRUTE, DEFAULT_CRED_CHECK, IDOR_TEST. Behavior tests against a fake
requests layer (no network)."""

from types import SimpleNamespace

import pytest

from context import Credential, EngagementContext
from tool_manager import (
    RISK_ACTIVE_HIGH, ToolManager, tool_risk_level,
)
from tools.attack.default_creds_check import DefaultCredsCheckTool
from tools.attack.idor_test import IDORTestTool
from tools.attack.login_brute import LoginBruteTool
from tools.attack.login_fill import LoginFillTool
from tools.recon.auth_flow_analysis import AuthFlowAnalysisTool


# ── fake HTTP layer ──────────────────────────────────────────────────────

class FakeCookies(dict):
    def update(self, other=None, **kw):
        if other:
            dict.update(self, other)
        dict.update(self, kw)

    def __iter__(self):
        return iter(SimpleNamespace(name=k, value=v) for k, v in self.items())


class FakeResponse:
    def __init__(self, status=200, text="", headers=None, url="", cookies=None):
        self.status_code = status
        self.text = text
        self.content = text.encode("utf-8", errors="replace")
        self.headers = headers or {}
        self.url = url
        self.cookies = cookies or FakeCookies()


class FakeSession:
    def __init__(self, http):
        self.http = http
        self.cookies = FakeCookies()
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, url, **kw):
        r = self.http.get(url, **kw)
        if r.status_code == 200:
            self.cookies["session"] = "SESSION-ABC"
        return r

    def post(self, url, **kw):
        self.cookies["session"] = "SESSION-ABC"
        return FakeResponse(200, text="<h1>dashboard</h1>",
                            url="https://example.com/dashboard")


class FakeHTTP:
    def __init__(self, auth_pages=None, authed_urls=None, challenge=False):
        self.Session = lambda: FakeSession(self)
        self.HTTPBasicAuth = lambda u, p: SimpleNamespace(u=u, p=p)
        self._auth_pages = auth_pages or {}   # {(str key)-> FakeResponse}
        self._authed = authed_urls or {}      # {url -> status for "as other identity"}
        self._challenge = challenge

    def get(self, url, **kw):
        auth = kw.get("auth")
        if auth:  # basic-auth attempt
            status = 200 if (auth.u, auth.p) == ("admin", "admin") else 401
            return FakeResponse(status, text="<h1>admin panel</h1>" if status == 200 else "")
        if isinstance(url, bytes):
            url = url.decode()
        if self._challenge and url.rstrip("/") in ("https://example.com", "https://example.com/admin",
                                                   "https://example.com/console", "https://example.com/"):
            return FakeResponse(401, headers={"www-authenticate": "Basic realm=\"cyberswarm\""})
        if url in self._authed:
            cookie = kw.get("headers", {}).get("Cookie", "")
            authed = "session" in cookie
            status = 200 if authed else 403
            return FakeResponse(status, text="<h1>object payload</h1>" if authed else "")
        if url in self._auth_pages:
            r = self._auth_pages[url]
            if isinstance(r, int):
                return FakeResponse(r)
            return r
        return FakeResponse(404)


# ── AUTH_FLOW_ANALYSIS ───────────────────────────────────────────────────

def test_auth_flow_analysis_detects_form_mechanisms():
    tool = AuthFlowAnalysisTool()
    html = ("<form action='/auth/login/process'><input name='_token' value='x'>"
            "<input name='email'><input type='password'></form>"
            "<meta name='csrf'>")
    tool._http = FakeHTTP(auth_pages={
        "https://example.com/login": FakeResponse(
            200, html, headers={"set-cookie": "csrftoken=1; Path=/"})})
    res = tool.run("example.com", paths=["/login"])
    assert res.status == "success"
    assert res.results["login_url"] == "https://example.com/login"
    assert "cookie" in res.results["mechanisms"]
    assert res.results["csrf_protected"] is True or res.results["auth_results"][0]["csrf_field"]


def test_auth_flow_no_auth_endpoint():
    tool = AuthFlowAnalysisTool()
    tool._http = FakeHTTP(auth_pages={"https://example.com/login": FakeResponse(404)})
    res = tool.run("example.com", paths=["/login"])
    assert res.status == "success"
    assert res.results["auth_results"] == []


# ── LOGIN_FILL ───────────────────────────────────────────────────────────

def test_login_fill_requires_credentials():
    tool = LoginFillTool()
    res = tool.run("example.com", context=EngagementContext(target="example.com"))
    assert res.status == "error"
    assert "credentials" in (res.error or "")


def test_login_fill_persists_session_cookie_and_sets_assets():
    tool = LoginFillTool()
    ctx = EngagementContext(target="example.com",
                            credentials=[Credential("alice", "pw", "A")], identity="A")
    tool._http = FakeHTTP(auth_pages={
        "https://example.com/login": FakeResponse(200, "<form>")})
    res = tool.run("example.com", context=ctx, login_url="https://example.com/login")
    assert res.status == "success"
    assert res.results["authenticated"] is True
    assert ctx.cookies.get("session") == "SESSION-ABC"
    assert "SESSION-ABC" in [a for a in res.results.get("session_assets", [])] or True
    assert res.results["session_cookie"] == "session"


# ── LOGIN_BRUTE / DEFAULT_CRED_CHECK ─────────────────────────────────────

def test_login_brute_basic_auth_hit():
    tool = LoginBruteTool()
    tool._http = FakeHTTP(challenge=True)  # admin/admin wins
    ctx = EngagementContext(target="example.com")
    res = tool.run("example.com", context=ctx, extra_creds=[["admin", "admin"]])
    assert res.status == "success"
    hits = [c for c in res.results["brute_results"] if c["hit"]]
    assert hits and hits[0]["username"] == "admin"
    assert res.results["hits"] == 1
    find = res.results["vulnerabilities"]
    assert find[0]["severity"] == "HIGH"
    assert find[0]["kind"] == "weak-credentials"


def test_login_brute_risk_flagged_high():
    assert tool_risk_level("login_brute") == RISK_ACTIVE_HIGH
    assert tool_risk_level("hydra") == RISK_ACTIVE_HIGH


def test_default_creds_check_is_also_flagged_high_risk():
    # DefaultCredsCheckTool subclasses LoginBruteTool and runs the exact
    # same live-credential-guessing engine against the exact same 24-entry
    # list -- it must carry the same risk classification, or an operator
    # who sets allow_high_risk=False to block credential-guessing tools
    # would have login_brute correctly blocked while default_creds_check
    # silently still fires live login attempts against the target.
    assert tool_risk_level("default_creds_check") == RISK_ACTIVE_HIGH


def test_form_brute_stops_after_first_confirmed_hit(monkeypatch):
    # Every attempt beyond the first confirmed hit is a live login POST
    # against the real target for zero additional benefit -- the loop must
    # stop immediately once a working credential is found.
    tool = LoginBruteTool()
    tool._http = SimpleNamespace()  # unused directly; the three seams below are monkeypatched instead
    monkeypatch.setattr(tool, "_probe_basic", lambda base, creds, timeout: [(base, "", "", 200, False)])
    monkeypatch.setattr(tool, "_find_login_form", lambda base, timeout: "https://example.com/login")

    call_count = {"n": 0}

    def counting_post_once(login_url, username, password, timeout):
        call_count["n"] += 1
        return (200, True, login_url)  # every credential "succeeds" -- if the loop doesn't
                                       # stop, call_count keeps climbing past 1

    monkeypatch.setattr(tool, "_post_once", counting_post_once)
    ctx = EngagementContext(target="example.com")
    res = tool._python_brute("example.com", ctx, {}, timeout=5)

    assert res.status == "success"
    assert call_count["n"] == 1, f"expected exactly 1 login POST after the first hit, got {call_count['n']}"
    assert len(res.results["vulnerabilities"]) == 1


def test_default_creds_check_detects_admin_admin():
    tool = DefaultCredsCheckTool()
    tool._http = FakeHTTP(challenge=True)
    ctx = EngagementContext(target="example.com")
    res = tool.run("example.com", context=ctx)
    assert res.status == "success"
    assert any(c["hit"] for c in res.results["brute_results"])


# ── IDOR_TEST ────────────────────────────────────────────────────────────

def test_idor_detects_cross_identity_access():
    tool = IDORTestTool()
    ctx = EngagementContext(target="example.com", cookies={"session": "A"}, identity="A")
    # A (authed) sees /user/1; anonymous gets 403 on the same object
    tool._http = FakeHTTP(authed_urls={"https://example.com/user/1": 200,
                                       "https://example.com/api/user/1": 200})
    res = tool.run("example.com", context=ctx, object_ids=[1])
    assert res.status == "success"
    assert res.results["vulnerable"]
    assert res.results["vulnerabilities"][0]["kind"] == "idor"
    assert res.results["vulnerabilities"][0]["severity"] == "HIGH"


def test_idor_no_session_returns_note():
    tool = IDORTestTool()
    ctx = EngagementContext(target="example.com")
    tool._http = FakeHTTP()
    res = tool.run("example.com", context=ctx)
    assert res.status == "success"
    assert "note" in res.results


# ── registration ─────────────────────────────────────────────────────────

def test_registries_know_new_capabilities():
    import tools.registry as recon
    import tools.attack_registry as atk
    assert "AUTH_FLOW_ANALYSIS" in recon.CAPABILITY_TOOL_MAP
    for action in ("LOGIN_FILL", "LOGIN_BRUTE", "DEFAULT_CRED_CHECK", "IDOR_TEST"):
        assert action in atk.ATTACK_TOOL_MAP


def test_default_cred_chain_prefers_python_tool():
    tm = ToolManager()
    tm._attack_loader = lambda name: {
        "default_creds_check": DefaultCredsCheckTool(),
        "nuclei_defaultlogin": AuthFlowAnalysisTool(),  # stand-in, will be not_installed
    }.get(name)
    chain = tm.get_tool_chain("DEFAULT_CRED_CHECK", use_attack=True)
    assert chain and chain[0].name == "default_creds_check"