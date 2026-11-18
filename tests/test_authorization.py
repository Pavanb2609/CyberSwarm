"""Tests for the hardened authorization gate.

The key behavioral change: strict mode (the new default) blocks targets
when no scope file is configured, rather than silently allowing everything.
Lab/private targets are always permitted regardless of the scope file.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import authorization as auth


@pytest.fixture
def no_scope(monkeypatch, tmp_path):
    """Simulate: no authorized_targets.json exists."""
    monkeypatch.setattr(auth, "CONFIG_PATH", tmp_path / "no_such_file.json")


@pytest.fixture
def with_scope(monkeypatch, tmp_path):
    """Scope file containing only example.com."""
    p = tmp_path / "authorized_targets.json"
    p.write_text(json.dumps({"targets": ["example.com"]}), encoding="utf-8")
    monkeypatch.setattr(auth, "CONFIG_PATH", p)


# ── Lab targets always permitted ─────────────────────────────────────────────

@pytest.mark.parametrize("target", [
    "127.0.0.1", "localhost", "192.168.1.50", "10.10.10.5",
    "172.16.0.1", "dvwa", "juiceshop",
])
def test_lab_targets_always_allowed(target, no_scope):
    ok, reason = auth.is_authorized(target, mode="strict")
    assert ok is True
    assert "lab" in reason.lower() or "private" in reason.lower()


# ── Strict mode (new default) ─────────────────────────────────────────────────

def test_strict_no_scope_blocks_live_target(no_scope):
    """The core change: no scope file = DENIED in strict mode."""
    ok, reason = auth.is_authorized("meesho.com", mode="strict")
    assert ok is False
    assert "authorize" in reason.lower()


def test_strict_with_scope_allows_matching(with_scope):
    ok, reason = auth.is_authorized("example.com", mode="strict")
    assert ok is True


def test_strict_with_scope_blocks_non_matching(with_scope):
    ok, _ = auth.is_authorized("evil.com", mode="strict")
    assert ok is False


def test_strict_wildcard_scope(monkeypatch, tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"targets": [".example.com"]}), encoding="utf-8")
    monkeypatch.setattr(auth, "CONFIG_PATH", p)
    assert auth.is_authorized("sub.example.com", mode="strict")[0] is True
    assert auth.is_authorized("example.com",     mode="strict")[0] is True
    assert auth.is_authorized("notexample.com",  mode="strict")[0] is False


# ── Legacy mode (backward compat) ────────────────────────────────────────────

def test_legacy_mode_allows_with_no_scope(no_scope):
    """Old behaviour preserved for tests that relied on it."""
    ok, reason = auth.is_authorized("anything.com", mode="legacy")
    assert ok is True
    assert "legacy" in reason.lower()


# ── Regression: the meesho and amazon runs ───────────────────────────────────

@pytest.mark.parametrize("target", ["meesho.com", "amazon.in", "amazon.com"])
def test_live_production_targets_blocked_without_scope(target, no_scope):
    """These ran without authorization. They must not be able to again."""
    ok, _ = auth.is_authorized(target, mode="strict")
    assert ok is False


def test_authorize_target_adds_to_scope(tmp_path, monkeypatch):
    p = tmp_path / "targets.json"
    monkeypatch.setattr(auth, "CONFIG_PATH", p)
    auth.authorize_target("testlab.local")
    assert auth.is_authorized("testlab.local", mode="strict")[0] is True


def test_is_lab_target_detection():
    assert auth.is_lab_target("127.0.0.1") is True
    assert auth.is_lab_target("10.0.0.1") is True
    assert auth.is_lab_target("192.168.100.1") is True
    assert auth.is_lab_target("dvwa") is True
    assert auth.is_lab_target("google.com") is False
    assert auth.is_lab_target("8.8.8.8") is False


# ── User-friendly scope management (remove / describe / offer) ───────────────

def test_remove_target_removes_from_scope(tmp_path, monkeypatch):
    p = tmp_path / "targets.json"
    p.write_text(json.dumps({"targets": ["a.com", "b.com"]}), encoding="utf-8")
    monkeypatch.setattr(auth, "CONFIG_PATH", p)
    auth.remove_target("https://b.com/")          # URL form must normalize
    assert auth.is_authorized("a.com", mode="strict")[0] is True
    assert auth.is_authorized("b.com", mode="strict")[0] is False


def test_remove_target_missing_file_is_noop(tmp_path, monkeypatch):
    p = tmp_path / "targets.json"
    monkeypatch.setattr(auth, "CONFIG_PATH", p)
    auth.remove_target("nonexistent.invalid")
    assert not p.exists()


def test_describe_scope_empty(no_scope):
    s = auth.describe_scope()
    assert "No authorized targets" in s
    assert "cyberswarm authorize <target>" in s


def test_describe_scope_lists_entries(with_scope):
    s = auth.describe_scope()
    assert "- example.com" in s
    assert "always permitted" in s


def test_offer_authorize_returns_true_when_already_allowed(with_scope):
    assert auth.offer_authorize("example.com") is True


def test_offer_authorize_non_tty_never_prompts(monkeypatch):
    """Unattended/CI runs must stay a hard block and never prompt."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert auth.offer_authorize("cyberswarm-new.invalid") is False


def test_offer_authorize_tty_decline(monkeypatch, tmp_path):
    p = tmp_path / "targets.json"
    monkeypatch.setattr(auth, "CONFIG_PATH", p)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    assert auth.offer_authorize(
        "cyberswarm-new.invalid", input_func=lambda _: "n") is False
    assert not p.exists()


def test_offer_authorize_tty_accept_writes_scope(monkeypatch, tmp_path):
    p = tmp_path / "targets.json"
    monkeypatch.setattr(auth, "CONFIG_PATH", p)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    assert auth.offer_authorize(
        "cyberswarm-new.invalid", action="test run", input_func=lambda _: "y") is True
    assert auth.is_authorized("cyberswarm-new.invalid", mode="strict")[0] is True


# ── scope entries with authorization metadata / expiry ──────────────────────

def test_scope_entries_accept_metadata_and_drop_expired(tmp_path, monkeypatch):
    import json as _json

    import authorization as auth_mod
    cfg = tmp_path / "authorized_targets.json"
    cfg.write_text(_json.dumps({"targets": [
        "plain.example",
        {"target": "current.example", "authorized_by": "client CISO",
         "scope": "SOW-1", "authorized_until": "2999-12-31"},
        {"target": "old.example", "authorized_by": "client CISO",
         "authorized_until": "2020-01-01"},
        {"target": "bad-date.example", "authorized_until": "next tuesday"},
    ]}))
    monkeypatch.setattr(auth_mod, "CONFIG_PATH", cfg)
    scope = auth_mod.load_scope()
    assert "plain.example" in scope and "current.example" in scope
    assert "old.example" not in scope          # expired
    assert "bad-date.example" not in scope     # unreadable expiry fails closed
    assert "authorized_by=client CISO" in auth_mod.describe_scope(cfg)


def test_authorize_and_remove_handle_dict_entries(tmp_path, monkeypatch):
    import json as _json

    import authorization as auth_mod
    cfg = tmp_path / "authorized_targets.json"
    cfg.write_text(_json.dumps({"targets": [{"target": "meta.example", "authorized_by": "x"}]}))
    auth_mod.authorize_target("meta.example", cfg)          # no duplicate added
    assert len(_json.loads(cfg.read_text())["targets"]) == 1
    auth_mod.remove_target("meta.example", cfg)
    assert _json.loads(cfg.read_text())["targets"] == []
