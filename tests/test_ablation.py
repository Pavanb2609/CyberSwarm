"""Ablation benchmark (Stage 9) — strategy comparison harness tests."""

import pytest

from ablation import (
    DECOY_TARGET, LAYERED_TARGET, CapabilityProfile, Scorebox, SimulationEnv,
    benchmark_strategies, run_strategy,
)


def _layered(max_actions=8):
    return benchmark_strategies(SimulationEnv(LAYERED_TARGET), max_actions=max_actions, seed=7)


def test_all_strategies_return_scoreboxes():
    box = _layered()
    assert set(box) == {"evidence", "registry", "random"}
    for name, sb in box.items():
        assert isinstance(sb, Scorebox)
        assert sb.actions_run >= 1
        assert sb.assets_found >= 1


def test_determinism():
    a = _layered()
    b = _layered()
    for name in a:
        assert a[name].area_under_curve == b[name].area_under_curve
        assert a[name].plan == b[name].plan


def test_evidence_beats_random_on_layered_target():
    box = _layered()
    assert box["evidence"].area_under_curve > box["random"].area_under_curve
    assert box["evidence"].assets_found >= box["random"].assets_found


def test_evidence_never_wastes_repeats_before_full_coverage():
    box = _layered(max_actions=12)
    plan = box["evidence"].plan
    seen = set()
    full = False
    for cap in plan:
        if full:
            break
        assert cap not in seen, f"evidence repeated {cap} while gaps remained"
        seen.add(cap)
        if len(seen) == len(LAYERED_TARGET):
            full = True


def test_coverage_ratio_matches_explored_set():
    env = SimulationEnv(LAYERED_TARGET, seed=7)
    sb = run_strategy("registry", env, max_actions=8, seed=7)
    assert sb.coverage_ratio == 1.0  # 8 capabilities, 8 steps, no repeats
    sb2 = run_strategy("random", env, max_actions=8, seed=7)
    assert sb2.coverage_ratio == 1.0  # draws without replacement until budget


def test_stops_when_untried_exhausted_registry():
    env = SimulationEnv(LAYERED_TARGET, seed=1)
    sb = run_strategy("registry", env, max_actions=100, seed=1)
    assert sb.actions_run == len(LAYERED_TARGET)
    assert sb.coverage_ratio == 1.0


def test_metrics_are_higher_with_more_budget():
    env = SimulationEnv(LAYERED_TARGET, seed=3)
    short = run_strategy("evidence", env, max_actions=4, seed=3)
    long = run_strategy("evidence", env, max_actions=12, seed=3)
    assert long.assets_found >= short.assets_found
    assert long.evidence_items >= short.evidence_items


def test_decoy_and_layered_targets_constructible():
    for profiles in (LAYERED_TARGET, DECOY_TARGET):
        env = SimulationEnv(profiles, seed=5)
        assert env.execute(env.candidates()[0])[0].status == "success"
        assert env.candidates()