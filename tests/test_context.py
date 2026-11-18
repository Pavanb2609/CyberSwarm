"""EngagementContext (Phase 0) — auth state, loaders, tool kwargs threading,
and Controller persistence."""

import json

import pytest

import state as state_mod
import evidence_store as ev_store
import authorization as auth
from agents import memory_agent

from context import (
    ANONYMOUS, Credential, EngagementContext, load_engagement,
)
from controller import Controller
from memory_store import MemoryStore
from tool_manager import ToolManager
from tools.base import Tool, ToolResult


@pytest.fixture(autouse=True)
def _isolate_stores(tmp_path, monkeypatch):
    monkeypatch.setattr(state_mod, "STORE_DIR", tmp_path / "state")
    monkeypatch.setattr(ev_store, "STORE_DIR", tmp_path / "evidence")
    monkeypatch.setattr(ev_store, "DECISION_LOG_PATH", tmp_path / "decision_log.jsonl")
    monkeypatch.setattr(memory_agent, "STORE_DIR", tmp_path / "attack_evidence")
    monkeypatch.setattr(auth, "CONFIG_PATH", tmp_path / "auth.json")
    yield


# ── parsing / accessors ──────────────────────────────────────────────────

def _json_file(data):
    import tempfile, os
    fd, name = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return name


def test_parse_identities_shape():
    ctx = load_engagement("127.0.0.1", creds_file=_json_file({
        "identities": {
            "A": {"username": "alice", "password": "pw-a",
                  "source_url": "https://127.0.0.1/login"},
            "B": {"username": "bob", "password": "pw-b"},
        }
    }))
    assert [(c.username, c.identity) for c in ctx.credentials] == \
        [("alice", "A"), ("bob", "B")]
    assert ctx.identity_labels() == ["A", "B"]
    assert ctx.credential_for("A").password == "pw-a"
    assert ctx.credential_for("B").username == "bob"


def test_parse_flat_users_and_pairs():
    ctx = load_engagement("x", creds_file=_json_file([["u1", "p1"], ["u2", "p2"]]))
    assert [c.username for c in ctx.credentials] == ["u1", "u2"]
    assert ctx.credential_for() is None  # ambiguous: two anonymous creds
    assert ctx.credentials[0].username == "u1"

    ctx = load_engagement("x", creds_file=_json_file({
        "users": [{"username": "u", "password": "p", "identity": "A"},
                  {"username": "v", "password": "q"}]}))
    assert ctx.identity_labels() == ["A"]
    assert ctx.credential_for("A").username == "u"


def test_cookies_from_dict_and_header_and_har():
    ctx = load_engagement("x", cookies_file=_json_file({"sid": "abc"}))
    assert ctx.cookies == {"sid": "abc"}

    import tempfile, os
    fd, n2 = tempfile.mkstemp(suffix=".hdr")
    with os.fdopen(fd, "w") as fh:
        fh.write("Cookie: a=1; b=2")
    ctx = load_engagement("x", cookies_file=n2)
    assert ctx.cookies == {"a": "1", "b": "2"}

    ctx = load_engagement("x", cookies_file=_json_file({
        "log": {"entries": [{"request": {"cookies": [
            {"name": "PHPSESSID", "value": "xyz"}]}}]}}))
    assert ctx.cookies == {"PHPSESSID": "xyz"}


def test_roundtrip_and_anonymized():
    ctx = EngagementContext(target="t", cookies={"sid": "1"},
                            credentials=[Credential("u", "p", "A")], identity="A")
    back = EngagementContext.from_dict(ctx.to_dict())
    assert back.cookies == {"sid": "1"}
    assert back.credential_for("A").password == "p"

    anon = ctx.anonymized()
    assert anon.cookies == {}
    assert anon.identity == ANONYMOUS
    assert anon.credentials == ctx.credentials


def test_bad_creds_file_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json{")
    with pytest.raises(ValueError):
        load_engagement("x", creds_file=str(bad))


# ── kwargs threading through ToolManager ─────────────────────────────────

class CapturingTool(Tool):
    name = "capture"
    capability = "CAPTURE"
    binary = ""

    def __init__(self):
        self.last_kwargs = None

    def is_available(self):
        return True

    def build_command(self, target, **kwargs):
        return []

    def parse(self, stdout, stderr):
        return {}

    def run(self, target, timeout=180, **kwargs):
        self.last_kwargs = kwargs
        return ToolResult(tool=self.name, status="success",
                          capability=self.capability, results={"ok": True})


def test_tool_manager_forwards_kwargs_to_tools(tmp_path):
    from tools import registry as recon_registry
    from tools import attack_registry as atk

    tool = CapturingTool()
    contingency = CapturingTool()

    def loader(name):
        return tool if name == "capture" else contingency

    recon_registry.CAPABILITY_TOOL_MAP["CAPTURE"] = ["capture"]
    atk.ATTACK_TOOL_MAP["ATK"] = ["capture"]

    tm = ToolManager(recon_loader=loader, attack_loader=loader,
                     memory_path=tmp_path / "tm.json")
    ctx = EngagementContext(target="127.0.0.1", cookies={"sid": "z"})
    try:
        tm.execute_capability("CAPTURE", "127.0.0.1", context=ctx)
        assert tool.last_kwargs.get("context") is ctx
        tm.execute_action("ATK", "127.0.0.1", context=ctx)
        assert tool.last_kwargs.get("context") is ctx
    finally:
        recon_registry.CAPABILITY_TOOL_MAP.pop("CAPTURE", None)
        atk.ATTACK_TOOL_MAP.pop("ATK", None)


# ── Controller persistence + shared mutable context ──────────────────────

class LoginTool(Tool):
    name = "login_fill"
    capability = "LOGIN_FILL"
    binary = ""

    def __init__(self):
        self.seen_contexts = []

    def is_available(self):
        return True

    def build_command(self, target, **kwargs):
        return []

    def parse(self, stdout, stderr):
        return {}

    def run(self, target, timeout=180, **kwargs):
        ctx = kwargs.get("context")
        self.seen_contexts.append(ctx)
        if ctx is not None and ctx.credential_for("A"):
            ctx.update_cookies({"session": "SESSION-ABC"})
        return ToolResult(tool=self.name, status="success",
                          capability=self.capability, results={
                              "authenticated": True,
                              "mechanism": "cookie",
                              "session_cookie": "session"})


def test_controller_persists_context_and_tools_share_cookies(tmp_path, monkeypatch):
    from tools import registry as recon_registry

    login = LoginTool()
    probe_tool = LoginTool()

    recon_registry.CAPABILITY_TOOL_MAP["LOGIN_FILL"] = ["login_fill"]
    import controller as controller_mod
    monkeypatch.setattr(controller_mod, "RECON_CAPABILITIES", ("LOGIN_FILL",))

    def loader(name):
        return login if name == "login_fill" else probe_tool

    tm = ToolManager(recon_loader=loader, attack_loader=loader,
                     memory_path=tmp_path / "tm.json")
    mem = MemoryStore("127.0.0.1", tool_manager=tm)

    ctx = EngagementContext(target="127.0.0.1",
                            credentials=[Credential("alice", "pw", "A")],
                            identity="A")
    c = Controller("127.0.0.1", tool_manager=tm, memory_store=mem,
                   max_actions=3, max_time_s=60, context=ctx)
    try:
        out = c.assess()
        assert out["actions_run"] > 0
        st = state_mod.load_state("127.0.0.1")
        assert st.metadata.get("engagement", {}).get("cookies", {}).get("session") == "SESSION-ABC"
    finally:
        recon_registry.CAPABILITY_TOOL_MAP.pop("LOGIN_FILL", None)
    # the shared context object means a later tool sees what LOGIN_FILL set
    assert all(t.seen_contexts[0].cookies.get("session") == "SESSION-ABC"
               for t in (login, probe_tool) if t.seen_contexts)