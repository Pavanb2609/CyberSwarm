"""Tests for ask.py — resolving plain English to a capability, and refusing to.

The interesting cases are the refusals. A layer that turns free text into tool
execution is the easiest place to widen scope by accident, so most of this file
asserts that bad resolutions do not reach the executor.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ask  # noqa: E402


class StubModel:
    """Returns a canned reply and records what it was asked."""

    def __init__(self, reply):
        self.reply = reply if isinstance(reply, str) else json.dumps(reply)
        self.prompts = []

    def chat(self, system, user, temperature=None):
        self.prompts.append((system, user))
        return self.reply


CAPS = ["SUBDOMAIN_DISCOVERY", "PORT_DISCOVERY", "CONTENT_DISCOVERY"]
AGENTS = ["web_attack", "network"]


def _resolve(reply, request="find the subdomains of example.com"):
    return ask.resolve(request, StubModel(reply), capabilities=CAPS, agents=AGENTS)


# ── Target extraction ────────────────────────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("find the subdomains of example.com", "example.com"),
    ("scan https://shop.example.co.uk/cart?a=1", "shop.example.co.uk"),
    ("look at http://EXAMPLE.COM/", "example.com"),
    ("check 192.168.1.10 please", "192.168.1.10"),
    ("no target at all here", ""),
    ("look at e.g. the login page", ""),
    ("read report.json for details", ""),
])
def test_extract_target(text, expected):
    assert ask.extract_target(text) == expected


def test_url_wins_over_bare_host():
    assert ask.extract_target("compare a.example.com with https://b.example.org/x") \
        == "b.example.org"


def test_invalid_ip_is_not_a_target():
    assert ask.extract_target("check 999.1.1.1") != "999.1.1.1"


# ── Successful resolution ────────────────────────────────────────────────────

def test_resolves_a_plain_request():
    res = _resolve({"kind": "capability", "name": "SUBDOMAIN_DISCOVERY",
                    "target": "example.com", "confidence": 90, "reason": "asks for subdomains"})
    assert res.ok
    assert res.name == "SUBDOMAIN_DISCOVERY"
    assert res.target == "example.com"
    assert res.confidence == 90


def test_name_matching_is_case_insensitive_but_exact():
    res = _resolve({"kind": "capability", "name": "subdomain_discovery",
                    "target": "example.com", "confidence": 80})
    assert res.ok
    assert res.name == "SUBDOMAIN_DISCOVERY", "should normalise to the registered name"


def test_agents_resolve_too():
    res = _resolve({"kind": "agent", "name": "web_attack",
                    "target": "example.com", "confidence": 70},
                   request="attack the web app at example.com")
    assert res.ok
    assert res.kind == "agent"
    assert "cli.py attack" in res.command()


def test_json_in_a_code_fence_is_parsed():
    res = _resolve('```json\n{"kind":"capability","name":"PORT_DISCOVERY",'
                   '"target":"example.com","confidence":80}\n```',
                   request="port scan example.com")
    assert res.ok


def test_prose_around_the_json_is_tolerated():
    res = _resolve('Sure! {"kind":"capability","name":"PORT_DISCOVERY",'
                   '"target":"example.com","confidence":80} Hope that helps.',
                   request="port scan example.com")
    assert res.ok


def test_the_allowed_list_is_given_to_the_model():
    model = StubModel({"kind": "none", "name": "", "target": ""})
    ask.resolve("anything", model, capabilities=CAPS, agents=AGENTS)
    _, user = model.prompts[0]
    for name in CAPS + AGENTS:
        assert name in user


# ── Refusals ─────────────────────────────────────────────────────────────────

def test_unregistered_capability_is_refused():
    """A hallucinated or injected action must not reach the executor."""
    res = _resolve({"kind": "capability", "name": "NUKE_EVERYTHING",
                    "target": "example.com", "confidence": 99})
    assert not res.ok
    assert any("not a registered" in e for e in res.errors)


def test_unregistered_agent_is_refused():
    res = _resolve({"kind": "agent", "name": "ransomware",
                    "target": "example.com", "confidence": 99})
    assert not res.ok


def test_target_substitution_is_refused():
    """The model must not point the run at a host the user did not name."""
    res = _resolve({"kind": "capability", "name": "PORT_DISCOVERY",
                    "target": "other-company.com", "confidence": 95},
                   request="port scan example.com")
    assert not res.ok
    assert any("other-company.com" in e for e in res.errors)


def test_target_not_present_in_the_request_is_refused():
    res = _resolve({"kind": "capability", "name": "PORT_DISCOVERY",
                    "target": "internal.corp", "confidence": 95},
                   request="port scan the internal box")
    assert not res.ok
    assert any("not written out" in e for e in res.errors)


def test_missing_target_is_refused():
    res = _resolve({"kind": "capability", "name": "PORT_DISCOVERY",
                    "target": "", "confidence": 95})
    assert not res.ok


def test_kind_none_is_refused():
    res = _resolve({"kind": "none", "name": "", "target": "",
                    "reason": "request is not an action"})
    assert not res.ok
    assert "no matching capability" in " ".join(res.errors)


def test_unknown_kind_is_refused():
    res = _resolve({"kind": "shell", "name": "rm -rf /",
                    "target": "example.com", "confidence": 99})
    assert not res.ok


def test_unparseable_reply_is_refused():
    assert not _resolve("I'm sorry, I can't do that").ok


def test_empty_request_is_refused():
    assert not ask.resolve("", StubModel({}), capabilities=CAPS, agents=AGENTS).ok


def test_model_failure_is_reported_not_raised():
    class Broken:
        def chat(self, *a, **kw):
            raise RuntimeError("no model server")

    res = ask.resolve("find subdomains of example.com", Broken(),
                      capabilities=CAPS, agents=AGENTS)
    assert not res.ok
    assert any("model call failed" in e for e in res.errors)


def test_no_registered_actions_is_refused():
    assert not ask.resolve("anything", StubModel({}), capabilities=[], agents=[]).ok


def test_bad_confidence_defaults_to_zero():
    res = _resolve({"kind": "capability", "name": "SUBDOMAIN_DISCOVERY",
                    "target": "example.com", "confidence": "very high"})
    assert res.confidence == 0


# ── Gates ────────────────────────────────────────────────────────────────────

def test_gates_run_authorization(monkeypatch):
    import authorization

    monkeypatch.setattr(authorization, "is_authorized",
                        lambda t: (False, "outside scope"))
    res = _resolve({"kind": "capability", "name": "SUBDOMAIN_DISCOVERY",
                    "target": "example.com", "confidence": 90})
    allowed, messages = ask.check_gates(res)
    assert allowed is False
    assert any("outside scope" in m for m in messages)


def test_gates_pass_when_authorized(monkeypatch):
    import authorization

    monkeypatch.setattr(authorization, "is_authorized", lambda t: (True, "in scope"))
    res = _resolve({"kind": "capability", "name": "SUBDOMAIN_DISCOVERY",
                    "target": "example.com", "confidence": 90})
    allowed, messages = ask.check_gates(res)
    assert allowed is True
    assert any("in scope" in m for m in messages)


def test_unresolved_never_passes_gates():
    allowed, _ = ask.check_gates(ask.Resolution())
    assert allowed is False


def test_authorization_failure_refuses_rather_than_allows(monkeypatch):
    """If the scope check itself breaks, refuse — do not fall open."""
    import authorization

    def explode(_t):
        raise RuntimeError("scope file unreadable")

    monkeypatch.setattr(authorization, "is_authorized", explode)
    res = _resolve({"kind": "capability", "name": "SUBDOMAIN_DISCOVERY",
                    "target": "example.com", "confidence": 90})
    allowed, messages = ask.check_gates(res)
    assert allowed is False
    assert any("refusing" in m for m in messages)


# ── Execution ────────────────────────────────────────────────────────────────

def test_execute_refuses_an_unresolved_request():
    with pytest.raises(ValueError):
        ask.execute(ask.Resolution())


def test_execute_refuses_an_agent():
    res = _resolve({"kind": "agent", "name": "web_attack",
                    "target": "example.com", "confidence": 80},
                   request="attack example.com")
    assert res.ok
    with pytest.raises(ValueError, match="agent"):
        ask.execute(res)


def test_execute_delegates_to_the_normal_executor(monkeypatch):
    """There must be no second execution path for the gates to miss."""
    calls = {}

    import recon_engine

    def fake(capability, target, timeout=180, **kwargs):
        calls["args"] = (capability, target, timeout)
        return "result"

    monkeypatch.setattr(recon_engine, "execute_capability", fake)
    res = _resolve({"kind": "capability", "name": "SUBDOMAIN_DISCOVERY",
                    "target": "example.com", "confidence": 90})
    assert ask.execute(res, timeout=42) == "result"
    assert calls["args"] == ("SUBDOMAIN_DISCOVERY", "example.com", 42)


# ── Registry wiring ──────────────────────────────────────────────────────────

def test_known_lists_come_from_the_real_registries():
    assert "SUBDOMAIN_DISCOVERY" in ask.known_capabilities()
    assert "web_attack" in ask.known_agents()
    assert ask.tools_for("SUBDOMAIN_DISCOVERY")


def test_describe_is_readable_both_ways():
    good = _resolve({"kind": "capability", "name": "SUBDOMAIN_DISCOVERY",
                     "target": "example.com", "confidence": 90})
    assert "SUBDOMAIN_DISCOVERY" in good.describe()
    assert "subfinder" in good.describe()
    assert "Could not resolve" in ask.Resolution().describe()
