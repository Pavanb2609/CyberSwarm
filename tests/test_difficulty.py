"""Tests for difficulty.py — real-time task difficulty assessment.

The behaviour that matters is not the arithmetic; it is the refusal to act on
thin data. A mechanism that abandons branches confidently from one measured
dimension is worse than no mechanism, so most of this file checks that missing
inputs degrade to neutral and that low-information verdicts stay CONTINUE.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import difficulty as d  # noqa: E402


# ── Horizon ──────────────────────────────────────────────────────────────────

def test_shorter_horizon_scores_higher():
    assert d.horizon_score(1) > d.horizon_score(5) > d.horizon_score(11)


def test_horizon_saturates_at_the_ceiling():
    assert d.horizon_score(d.HORIZON_CEILING) == 0.0
    assert d.horizon_score(d.HORIZON_CEILING * 5) == 0.0


def test_competing_branches_make_a_horizon_worse():
    """Eight steps alone is discouraging; eight with rivals is worse."""
    assert d.horizon_score(6, active_branches=1) > d.horizon_score(6, active_branches=5)


def test_horizon_unmeasured_returns_none():
    assert d.horizon_score(None) is None
    assert d.horizon_score("soon") is None
    assert d.horizon_score(-1) is None


# ── Evidence ─────────────────────────────────────────────────────────────────

def test_verified_evidence_beats_speculative():
    assert d.evidence_score([0.95, 0.9]) > d.evidence_score([0.3, 0.35])


def test_evidence_is_floored_at_speculative():
    """Unproven is not disproven — a hypothesis still scores above zero."""
    assert d.evidence_score([0.0, 0.0]) == d.SPECULATIVE


def test_evidence_accepts_percentages_and_units():
    assert d.evidence_score([80, 90]) == pytest.approx(d.evidence_score([0.8, 0.9]))


def test_evidence_ignores_junk_values():
    assert d.evidence_score([0.9, None, "high", 0.9]) == pytest.approx(0.9)


def test_evidence_unmeasured_returns_none():
    assert d.evidence_score(None) is None
    assert d.evidence_score([]) is None
    assert d.evidence_score(["nonsense"]) is None


# ── Context ──────────────────────────────────────────────────────────────────

def test_context_score_is_headroom_not_usage():
    assert d.context_score(0, 1000) == 1.0
    assert d.context_score(1000, 1000) == 0.0
    assert d.context_score(250, 1000) == pytest.approx(0.75)


def test_context_overflow_clamps():
    assert d.context_score(5000, 1000) == 0.0


def test_context_unmeasured_returns_none():
    assert d.context_score(None, 1000) is None
    assert d.context_score(100, None) is None
    assert d.context_score(100, 0) is None


# ── Historical ───────────────────────────────────────────────────────────────

def test_history_is_smoothed():
    """One failure on a first attempt must not read as hopeless."""
    assert d.historical_score(successes=0, attempts=1) > 0.25


def test_more_successes_score_higher():
    assert (d.historical_score(successes=9, attempts=10)
            > d.historical_score(successes=1, attempts=10))


def test_explicit_reliability_wins():
    assert d.historical_score(reliability=0.9) == 0.9


def test_history_unmeasured_returns_none():
    assert d.historical_score() is None
    assert d.historical_score(attempts=0) is None


# ── Composition ──────────────────────────────────────────────────────────────

def _full(**over):
    args = dict(remaining_steps=2, active_branches=1, confidences=[0.9],
                used_tokens=1000, window_tokens=32768, successes=9, attempts=10)
    args.update(over)
    return d.assess(**args)


def test_a_healthy_branch_continues():
    result = _full()
    assert result.verdict == d.CONTINUE
    assert result.score > 0.7
    assert set(result.measured) == {"horizon", "evidence", "context", "historical"}


def test_a_hopeless_branch_is_abandoned():
    result = _full(remaining_steps=12, confidences=[0.0], successes=0, attempts=10)
    assert result.verdict == d.ABANDON


def test_a_middling_branch_is_deprioritised():
    result = _full(remaining_steps=7, confidences=[0.45], successes=2, attempts=8)
    assert result.verdict == d.DEPRIORITISE


def test_exhausted_context_abandons_an_otherwise_healthy_branch():
    """The failure this mechanism exists for: a good branch with no room left."""
    result = _full(used_tokens=31500, window_tokens=32768)
    assert result.verdict == d.ABANDON
    assert any("exhausted" in r for r in result.reasons)
    assert result.score > 0.4, "score stays healthy; the hard stop is what fires"


def test_missing_dimensions_go_neutral_not_zero():
    """A branch with nothing measured must look ordinary, not doomed."""
    result = d.assess(branch="fresh")
    assert result.horizon == result.evidence == d.NEUTRAL
    assert result.measured == []
    # Neutral value (0.5) scaled by the neutral context factor.
    expected = d.NEUTRAL * (d.CONTEXT_FLOOR + (1 - d.CONTEXT_FLOOR) * d.NEUTRAL)
    assert result.score == pytest.approx(expected)
    assert result.verdict == d.CONTINUE


def test_thin_data_never_abandons():
    """One measured dimension is a guess wearing a number."""
    result = d.assess(branch="new", remaining_steps=12)
    assert result.confident is False
    assert result.verdict == d.CONTINUE
    assert any("too few dimensions" in r for r in result.reasons)


def test_two_dimensions_are_enough_to_act():
    result = d.assess(branch="x", remaining_steps=12, confidences=[0.0],
                      successes=0, attempts=20)
    assert result.confident is True
    assert result.verdict == d.ABANDON


def test_reasons_are_attached_for_each_weak_dimension():
    result = _full(remaining_steps=11, confidences=[0.0], successes=0, attempts=20)
    joined = " ".join(result.reasons)
    assert "long" in joined and "speculative" in joined and "rarely worked" in joined


def test_weights_are_normalised():
    w = d.Weights(horizon=2, evidence=2, historical=1).normalised()
    assert sum([w.horizon, w.evidence, w.historical]) == pytest.approx(1.0)


def test_zero_weights_fall_back_to_defaults():
    assert d.Weights(0, 0, 0).normalised().horizon > 0


def test_context_headroom_cannot_rescue_a_hopeless_branch():
    """An empty context window is not a reason to pursue a dead path."""
    hopeless = dict(remaining_steps=12, confidences=[0.0], successes=0, attempts=20)
    roomy = d.assess(used_tokens=10, window_tokens=32768, **hopeless)
    tight = d.assess(used_tokens=20000, window_tokens=32768, **hopeless)
    assert roomy.verdict == d.ABANDON
    assert tight.verdict == d.ABANDON
    assert roomy.score < 0.25, "headroom must not inflate a worthless branch"


def test_tight_context_demotes_a_promising_branch():
    good = dict(remaining_steps=2, confidences=[0.9], successes=9, attempts=10)
    roomy = d.assess(used_tokens=10, window_tokens=32768, **good)
    tight = d.assess(used_tokens=28000, window_tokens=32768, **good)
    assert tight.score < roomy.score


def test_weighting_changes_the_verdict():
    args = dict(remaining_steps=11, confidences=[0.95], used_tokens=100,
                window_tokens=32768, successes=9, attempts=10)
    horizon_heavy = d.assess(weights=d.Weights(horizon=0.9, evidence=0.05,
                                               historical=0.05), **args)
    evidence_heavy = d.assess(weights=d.Weights(horizon=0.05, evidence=0.9,
                                                historical=0.05), **args)
    assert evidence_heavy.score > horizon_heavy.score


def test_assessment_serialises():
    payload = _full().to_dict()
    assert set(payload["dimensions"]) == {"horizon", "evidence", "context", "historical"}
    assert payload["verdict"] in (d.CONTINUE, d.DEPRIORITISE, d.ABANDON)


# ── Graph integration ────────────────────────────────────────────────────────

GRAPH = [
    {"agent": "web_attack", "priority": 5, "reason": "web surface",
     "estimated_remaining_steps": 2, "skip": False},
    {"agent": "deserialization", "priority": 1, "reason": "maybe java",
     "estimated_remaining_steps": 12, "skip": False},
    {"agent": "cloud", "priority": 9, "reason": "no cloud", "skip": True},
]

HISTORY = {"web_attack": {"successes": 9, "attempts": 10},
           "deserialization": {"successes": 0, "attempts": 12}}


def test_assess_graph_skips_skipped_nodes():
    out = d.assess_graph(GRAPH, context_used=1000, context_window=32768,
                         history=HISTORY)
    assert set(out) == {"web_attack", "deserialization"}


def test_reprioritise_promotes_the_tractable_branch():
    """The whole point: a low-value branch must stop being priority 1."""
    out = d.assess_graph(GRAPH, context_used=1000, context_window=32768,
                         history=HISTORY)
    ordered = d.reprioritise(GRAPH, out)
    active = [n for n in ordered if not n.get("skip")]
    assert active[0]["agent"] == "web_attack"
    assert active[0]["priority"] == 1


def test_reprioritise_marks_abandoned_branches_skipped_with_a_reason():
    out = d.assess_graph(GRAPH, context_used=1000, context_window=32768,
                         history=HISTORY)
    ordered = d.reprioritise(GRAPH, out)
    node = next(n for n in ordered if n["agent"] == "deserialization")
    if out["deserialization"].verdict == d.ABANDON:
        assert node["skip"] is True
        assert "TDA:" in node["reason"]


def test_reprioritise_does_not_mutate_the_input():
    before = [dict(n) for n in GRAPH]
    out = d.assess_graph(GRAPH, context_used=1000, context_window=32768, history=HISTORY)
    d.reprioritise(GRAPH, out)
    assert GRAPH == before


def test_reprioritise_annotates_every_node():
    out = d.assess_graph(GRAPH, context_used=1000, context_window=32768, history=HISTORY)
    for node in d.reprioritise(GRAPH, out):
        if node["agent"] in out:
            assert "tractability" in node and "tda_verdict" in node


def test_graph_without_horizon_estimates_still_works():
    """An older planner, or a model that omits the field, must not break it."""
    bare = [{"agent": "web_attack", "priority": 1, "skip": False}]
    out = d.assess_graph(bare, context_used=1000, context_window=32768)
    assert out["web_attack"].verdict == d.CONTINUE


def test_malformed_nodes_are_ignored():
    messy = [{"agent": "", "priority": 1}, "not a dict", {"priority": 2}]
    assert d.assess_graph(messy) == {}


# ── Config ───────────────────────────────────────────────────────────────────

def test_config_defaults():
    cfg = d.tda_config({})
    assert cfg["enabled"] is True
    assert cfg["thresholds"].abandon_below == 0.25


def test_config_overrides():
    cfg = d.tda_config({"difficulty": {
        "enabled": False,
        "weights": {"horizon": 0.5},
        "thresholds": {"abandon_below": 0.1}}})
    assert cfg["enabled"] is False
    assert cfg["weights"].horizon == 0.5
    assert cfg["thresholds"].abandon_below == 0.1


def test_config_tolerates_wrong_types():
    assert d.tda_config({"difficulty": "nope"})["enabled"] is True
    assert d.tda_config({"difficulty": {"weights": "nope"}})["weights"].horizon == 0.35
    assert d.tda_config({"difficulty": {"thresholds": {"abandon_below": "low"}}})[
        "thresholds"].abandon_below == 0.25


# ── Planner integration ──────────────────────────────────────────────────────

def test_planner_apply_difficulty_reorders():
    from agents.planner_agent import PlannerAgent

    graph = {"attack_graph": [dict(n) for n in GRAPH]}
    out = PlannerAgent(None).apply_difficulty(
        graph, history=HISTORY, config={"difficulty": {"enabled": True}})
    active = [n for n in out["attack_graph"] if not n.get("skip")]
    assert active[0]["agent"] == "web_attack"
    assert "difficulty" in out


def test_planner_apply_difficulty_is_a_noop_when_disabled():
    from agents.planner_agent import PlannerAgent

    graph = {"attack_graph": [dict(n) for n in GRAPH]}
    out = PlannerAgent(None).apply_difficulty(
        graph, history=HISTORY, config={"difficulty": {"enabled": False}})
    assert out == graph


def test_planner_survives_a_broken_assessment(monkeypatch):
    from agents.planner_agent import PlannerAgent

    monkeypatch.setattr(d, "assess_graph",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    graph = {"attack_graph": [dict(n) for n in GRAPH]}
    assert PlannerAgent(None).apply_difficulty(graph, history=HISTORY) == graph


def test_planner_prompt_asks_for_a_horizon_estimate():
    from agents.planner_agent import PLANNER_SYSTEM

    assert "estimated_remaining_steps" in PLANNER_SYSTEM


# ── Context instrumentation ──────────────────────────────────────────────────

def test_model_client_records_prompt_size():
    from model_client import ModelClient

    client = ModelClient(context_window=1000)
    client._record_prompt("a" * 400, "b" * 400)
    assert client.last_prompt_tokens == 200
    assert client.context_load() == pytest.approx(0.2)


def test_model_client_tracks_the_peak():
    from model_client import ModelClient

    client = ModelClient(context_window=10000)
    client._record_prompt("a" * 4000, "")
    client._record_prompt("a" * 40, "")
    assert client.peak_prompt_tokens == 1000
    assert client.last_prompt_tokens == 10


def test_context_load_clamps_past_the_window():
    from model_client import ModelClient

    client = ModelClient(context_window=100)
    client._record_prompt("a" * 10000, "")
    assert client.context_load() == 1.0
