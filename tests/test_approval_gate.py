"""Tests for approval_gate.py: the human approval gate for Phase-1 recon
planner decisions. Covers the yes/no/override input paths and the
append-only audit log's shape/content.
"""

import json

import approval_gate as ag

DECISION = {
    "target_profile": "WEB_APPLICATION",
    "next_capability": "PORT_DISCOVERY",
    "confidence": 0.9,
    "reason": "Fresh domain, no ports scanned yet",
    "requires_human_approval": True,
}


def _log_lines(path):
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def test_review_yes_approves_and_logs(isolated_stores, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    entry = ag.review(DECISION, "example.com", {"open_ports": []})

    assert entry["approved"] is True
    assert entry["override_capability"] is None
    lines = _log_lines(ag.LOG_PATH)
    assert len(lines) == 1
    assert lines[0]["target"] == "example.com"
    assert lines[0]["approved"] is True
    assert lines[0]["model_decision"] == DECISION


def test_review_no_rejects_and_records_reason(isolated_stores, monkeypatch):
    responses = iter(["n", "not in scope"])
    monkeypatch.setattr("builtins.input", lambda *_: next(responses))
    entry = ag.review(DECISION, "example.com", {})

    assert entry["approved"] is False
    assert entry["override_capability"] is None
    assert entry["human_note"] == "not in scope"


def test_review_override_records_new_capability_and_reason(isolated_stores, monkeypatch):
    responses = iter(["o", "DNS_RESOLUTION", "want DNS first"])
    monkeypatch.setattr("builtins.input", lambda *_: next(responses))
    entry = ag.review(DECISION, "example.com", {})

    assert entry["approved"] is False
    assert entry["override_capability"] == "DNS_RESOLUTION"
    assert entry["human_note"] == "want DNS first"


def test_review_anything_else_is_treated_as_rejection(isolated_stores, monkeypatch):
    responses = iter(["garbage", ""])
    monkeypatch.setattr("builtins.input", lambda *_: next(responses))
    entry = ag.review(DECISION, "example.com", {})
    assert entry["approved"] is False


def test_review_appends_to_log_across_multiple_calls(isolated_stores, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    ag.review(DECISION, "a.com", {})
    ag.review(DECISION, "b.com", {})
    lines = _log_lines(ag.LOG_PATH)
    assert len(lines) == 2
    assert [l["target"] for l in lines] == ["a.com", "b.com"]


def test_review_entry_includes_timestamp_and_full_evidence(isolated_stores, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    evidence = {"open_ports": [80, 443], "technologies": ["nginx"]}
    entry = ag.review(DECISION, "example.com", evidence)
    assert "timestamp" in entry
    assert entry["evidence"] == evidence


def test_auto_log_always_approves_without_prompting(isolated_stores, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: (_ for _ in ()).throw(
        AssertionError("auto_log must never call input()")))
    entry = ag.auto_log(DECISION, "example.com", {})
    assert entry["approved"] is True
    assert entry["human_note"] == "auto-approved (--auto-approve mode)"
    lines = _log_lines(ag.LOG_PATH)
    assert len(lines) == 1
    assert lines[0]["approved"] is True
