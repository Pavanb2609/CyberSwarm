"""Authorization gate behavior (Stage 11). These tests verify the scope gate
replaces the earlier no-op stub: lenient when unconfigured, enforced when an
operator defines a scope, and never interactive inside confirm()."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import authorization


def _empty_scope(tmp_path, monkeypatch):
    p = tmp_path / "auth.json"
    p.write_text(json.dumps({"targets": []}))
    monkeypatch.setattr(authorization, "CONFIG_PATH", p)
    return p


def test_strict_when_scope_is_empty(tmp_path, monkeypatch):
    """New default: no scope = DENIED. Prevents accidental live-target runs."""
    _empty_scope(tmp_path, monkeypatch)
    authorized, reason = authorization.is_authorized("any-target.example",
                                                     mode="strict")
    assert authorized is False
    assert "authorize" in reason.lower()


def test_lenient_when_scope_is_empty_legacy_mode(tmp_path, monkeypatch):
    """Legacy mode preserves the old allow-all behaviour for existing tests."""
    _empty_scope(tmp_path, monkeypatch)
    authorized, reason = authorization.is_authorized("any-target.example",
                                                     mode="legacy")
    assert authorized is True
    assert "no authorization scope" in reason


def test_enforced_when_scope_configured(tmp_path, monkeypatch):
    p = tmp_path / "auth.json"
    p.write_text(json.dumps({"targets": ["example.com"]}))
    monkeypatch.setattr(authorization, "CONFIG_PATH", p)
    assert authorization.is_authorized("example.com")[0] is True
    assert authorization.is_authorized("evil.example")[0] is False


def test_confirm_never_prompts(monkeypatch, tmp_path):
    p = tmp_path / "auth.json"
    p.write_text(json.dumps({"targets": ["example.com"]}))
    monkeypatch.setattr(authorization, "CONFIG_PATH", p)
    called = {"input": False}

    def intercept_input(*a, **kw):
        called["input"] = True
        raise AssertionError("confirm() must not prompt")
    monkeypatch.setattr("builtins.input", intercept_input)

    authorization.confirm("example.com")
    with pytest.raises(PermissionError):
        authorization.confirm("evil.example")
    assert not called["input"]