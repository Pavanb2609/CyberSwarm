"""Tests for modes.py — run modes, pause policy, and approval routing."""

import argparse
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import approval_gate  # noqa: E402
import modes  # noqa: E402
from modes import Mode, Pause, SessionPolicy  # noqa: E402


class _Finding:
    def __init__(self, severity, name="x"):
        self.severity = severity
        self.name = name


# ── Parsing ──────────────────────────────────────────────────────────────────

def test_mode_and_pause_parse_case_insensitively():
    assert Mode.parse("GUIDED") is Mode.GUIDED
    assert Mode.parse(" free ") is Mode.FREE
    assert Pause.parse("CheckPoint") is Pause.CHECKPOINT


def test_bad_values_fall_back_to_default():
    assert Mode.parse("nonsense") is Mode.AUTO
    assert Mode.parse(None, Mode.GUIDED) is Mode.GUIDED
    assert Pause.parse(object()) is Pause.NEVER


def test_parse_is_idempotent_on_enum_members():
    assert Mode.parse(Mode.FREE) is Mode.FREE
    assert Pause.parse(Pause.ALWAYS) is Pause.ALWAYS


# ── Mode behaviour ───────────────────────────────────────────────────────────

def test_guided_asks_before_acting():
    assert SessionPolicy(Mode.GUIDED).requires_approval_before_action() is True
    assert SessionPolicy(Mode.AUTO).requires_approval_before_action() is False
    assert SessionPolicy(Mode.FREE).requires_approval_before_action() is False


def test_only_free_drops_phase_structure():
    assert SessionPolicy(Mode.FREE).enforces_phases is False
    assert SessionPolicy(Mode.AUTO).enforces_phases is True
    assert SessionPolicy(Mode.GUIDED).enforces_phases is True


# ── Pause behaviour ──────────────────────────────────────────────────────────

def test_never_pauses_even_on_critical():
    policy = SessionPolicy(Mode.AUTO, Pause.NEVER)
    assert policy.should_pause_after_result([_Finding("CRITICAL")]) is False
    assert policy.should_pause_after_result(phase_changed=True) is False


def test_always_pauses_on_nothing_at_all():
    assert SessionPolicy(Mode.AUTO, Pause.ALWAYS).should_pause_after_result([]) is True


def test_checkpoint_pauses_on_threshold_severity():
    policy = SessionPolicy(Mode.AUTO, Pause.CHECKPOINT)
    assert policy.should_pause_after_result([_Finding("LOW")]) is False
    assert policy.should_pause_after_result([_Finding("MEDIUM")]) is False
    assert policy.should_pause_after_result([_Finding("HIGH")]) is True
    assert policy.should_pause_after_result([_Finding("CRITICAL")]) is True


def test_checkpoint_pauses_at_phase_boundaries():
    policy = SessionPolicy(Mode.AUTO, Pause.CHECKPOINT)
    assert policy.should_pause_after_result([], phase_changed=True) is True


def test_checkpoint_threshold_is_tunable():
    policy = SessionPolicy(Mode.AUTO, Pause.CHECKPOINT, checkpoint_severity="LOW")
    assert policy.should_pause_after_result([_Finding("LOW")]) is True


def test_findings_may_be_dicts_or_objects():
    policy = SessionPolicy(Mode.AUTO, Pause.CHECKPOINT)
    assert policy.should_pause_after_result([{"severity": "HIGH"}]) is True
    assert policy.should_pause_after_result([{"name": "no severity"}]) is False


def test_unknown_severity_never_triggers():
    policy = SessionPolicy(Mode.AUTO, Pause.CHECKPOINT)
    assert policy.should_pause_after_result([_Finding("BANANA")]) is False


def test_auto_plus_always_is_the_watch_it_work_combination():
    """The combination called out in the design: autonomous but reviewable."""
    policy = SessionPolicy(Mode.AUTO, Pause.ALWAYS)
    assert policy.requires_approval_before_action() is False
    assert policy.should_pause_after_result([]) is True


# ── Construction ─────────────────────────────────────────────────────────────

def test_from_config_reads_session_block():
    policy = modes.from_config({"session": {"mode": "guided", "pause": "checkpoint",
                                            "checkpoint_severity": "medium"}})
    assert policy.mode is Mode.GUIDED
    assert policy.pause is Pause.CHECKPOINT
    assert policy.checkpoint_severity == "MEDIUM"


def test_from_config_defaults_and_bad_types():
    assert modes.from_config({}).mode is Mode.AUTO
    assert modes.from_config({"session": "nope"}).pause is Pause.NEVER


def test_cli_flags_override_config():
    args = argparse.Namespace(mode="free", pause="always", auto_approve=False,
                              checkpoint_severity=None)
    policy = modes.from_args(args, {"session": {"mode": "guided"}})
    assert policy.mode is Mode.FREE
    assert policy.pause is Pause.ALWAYS


def test_auto_approve_still_means_auto_never():
    """Existing scripts and CI invocations must keep working unchanged."""
    args = argparse.Namespace(auto_approve=True, mode=None, pause=None,
                              checkpoint_severity=None)
    policy = modes.from_args(args, {})
    assert policy.mode is Mode.AUTO
    assert policy.pause is Pause.NEVER


def test_explicit_flags_beat_auto_approve():
    args = argparse.Namespace(auto_approve=True, mode=None, pause="always",
                              checkpoint_severity=None)
    assert modes.from_args(args, {}).pause is Pause.ALWAYS


def test_from_args_tolerates_a_bare_namespace():
    assert modes.from_args(argparse.Namespace(), {}).mode is Mode.AUTO


def test_add_cli_arguments_registers_the_flags():
    parser = argparse.ArgumentParser()
    modes.add_cli_arguments(parser)
    parsed = parser.parse_args(["--mode", "guided", "--pause", "checkpoint"])
    assert parsed.mode == "guided"
    assert parsed.pause == "checkpoint"


def test_describe_is_human_readable():
    text = SessionPolicy(Mode.AUTO, Pause.CHECKPOINT).describe()
    assert "auto" in text and "checkpoint" in text


# ── Approval routing ─────────────────────────────────────────────────────────

def test_guided_routes_to_the_interactive_review(monkeypatch):
    called = {}

    def fake_review(decision, target, evidence):
        called["review"] = True
        return {"approved": True}

    monkeypatch.setattr(approval_gate, "review", fake_review)
    approval_gate.gate({"next_capability": "PORT_DISCOVERY"}, "t", {},
                       policy=SessionPolicy(Mode.GUIDED))
    assert called.get("review") is True


def test_auto_routes_to_the_logger(monkeypatch, tmp_path):
    monkeypatch.setattr(approval_gate, "LOG_PATH", tmp_path / "decision_log.jsonl")
    entry = approval_gate.gate({"next_capability": "PORT_DISCOVERY"}, "t", {},
                               policy=SessionPolicy(Mode.AUTO))
    assert entry["approved"] is True
    assert "auto" in entry["human_note"]


def test_no_policy_keeps_the_old_prompting_behaviour(monkeypatch):
    called = {}
    monkeypatch.setattr(approval_gate, "review",
                        lambda d, target, evidence: called.setdefault("r", True))
    approval_gate.gate({}, "t", {}, policy=None)
    assert called.get("r") is True


def test_pause_for_review_is_silent_when_never(capsys):
    assert approval_gate.pause_for_review(
        "agent x", [_Finding("CRITICAL")], SessionPolicy(Mode.AUTO, Pause.NEVER)) is True
    assert capsys.readouterr().out == ""


def test_pause_for_review_stops_when_operator_declines(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_a: "n")
    assert approval_gate.pause_for_review(
        "agent x", [_Finding("HIGH")], SessionPolicy(Mode.AUTO, Pause.CHECKPOINT)) is False


def test_pause_for_review_continues_on_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_a: "")
    assert approval_gate.pause_for_review(
        "agent x", [_Finding("HIGH")], SessionPolicy(Mode.AUTO, Pause.CHECKPOINT)) is True


def test_pause_for_review_survives_no_stdin(monkeypatch):
    """Non-interactive CI must not crash on a checkpoint."""
    def no_stdin(*_a):
        raise EOFError

    monkeypatch.setattr("builtins.input", no_stdin)
    assert approval_gate.pause_for_review(
        "agent x", [_Finding("HIGH")], SessionPolicy(Mode.AUTO, Pause.CHECKPOINT)) is True
