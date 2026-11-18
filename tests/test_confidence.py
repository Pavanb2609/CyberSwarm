"""Tests for the centralized confidence engine."""

import pytest

from confidence import (
    CEILING,
    CONFIRM_FLOOR,
    ConfidenceEngine,
    base_confidence,
    blend_agent_critic,
    clamp_unit,
    combine_scores,
    confidence_label,
    corroboration_adjustment,
    llm_fallback_confidence,
    recency_adjustment,
    reliability_adjustment,
    to_percent,
    to_unit,
)


def test_to_unit_detects_scale():
    assert to_unit(0.7) == pytest.approx(0.7)
    assert to_unit(70) == pytest.approx(0.7)
    assert to_unit("80") == pytest.approx(0.8)
    assert to_unit(True) == 1.0
    assert to_unit(False) == 0.0
    assert to_unit(None) == 0.0
    assert to_unit("junk") == 0.0
    assert to_unit(None, default=0.5) == 0.5


def test_to_percent_round_trip():
    assert to_percent(0.7) == 70.0
    assert to_percent(70) == 70.0
    assert to_percent(0.333) == pytest.approx(33.3)


def test_base_confidence_groups_and_default():
    assert base_confidence("nmap") == pytest.approx(0.75)
    assert base_confidence("subfinder") == pytest.approx(0.75)
    assert base_confidence("whatweb") == pytest.approx(0.6)
    assert base_confidence("file_upload") == pytest.approx(0.5)
    assert base_confidence("totally_unknown") == pytest.approx(0.6)
    assert base_confidence("") == pytest.approx(0.6)


def test_reliability_neutral_is_noop():
    assert reliability_adjustment(0.6, 0.5) == pytest.approx(0.6)


def test_reliability_scales_around_neutral():
    assert reliability_adjustment(0.6, 0.9) == pytest.approx(0.6 * (0.5 + 0.9))
    assert reliability_adjustment(0.6, 0.1) == pytest.approx(0.6 * (0.5 + 0.1))
    assert reliability_adjustment(0.6, 0.0) == pytest.approx(0.6 * 0.5)


def test_reliability_output_capped_at_ceiling():
    assert reliability_adjustment(0.99, 1.0) <= CEILING
    assert reliability_adjustment(0.9, 1.0) == CEILING


def test_corroboration_single_source_discounted():
    assert corroboration_adjustment(0.7, 1) == pytest.approx(0.7 * 0.9)
    assert corroboration_adjustment(0.7, 0) == pytest.approx(0.7 * 0.85)


def test_corroboration_multi_source_raises_and_caps():
    assert corroboration_adjustment(0.7, 2) == pytest.approx(0.7 * 0.97)
    assert corroboration_adjustment(0.7, 3) > corroboration_adjustment(0.7, 2)
    assert corroboration_adjustment(0.7, 100) <= CEILING


def test_recency_decay():
    assert recency_adjustment(0.8, None) == pytest.approx(0.8)
    assert recency_adjustment(0.8, 0) == pytest.approx(0.8)
    assert recency_adjustment(0.8, 72) == pytest.approx(0.4)
    assert recency_adjustment(0.8, 144) == pytest.approx(0.2)


def test_combine_scores_noiseless_or():
    assert combine_scores([]) == 0.0
    assert combine_scores([0.5]) == pytest.approx(0.5)
    assert combine_scores([0.5, 0.5]) == pytest.approx(0.75)
    assert combine_scores([0.9, 0.9]) == pytest.approx(0.99)


def test_blend_agent_critic_forty_sixty():
    assert blend_agent_critic(40, 90) == pytest.approx(0.7)
    assert blend_agent_critic(0.4, 0.9) == pytest.approx(0.7)


def test_confidence_label_thresholds():
    assert confidence_label(0.2) == "LOW"
    assert confidence_label(0.4) == "MEDIUM"
    assert confidence_label(0.7) == "HIGH"
    assert confidence_label(0.9) == "CONFIRMED"


def test_llm_fallback_is_deterministic_and_low():
    assert llm_fallback_confidence() == pytest.approx(0.35)
    assert llm_fallback_confidence() < CONFIRM_FLOOR


def test_engine_score_tool_result_non_success_is_zero():
    engine = ConfidenceEngine()
    assert engine.score_tool_result("nmap", "error") == 0.0
    assert engine.score_tool_result("nmap", "timeout") == 0.0
    assert engine.score_tool_result("nmap", "not_installed") == 0.0


def test_engine_score_tool_result_uses_reliability_provider():
    def provider(name):
        return 0.9 if name == "nmap" else 0.1

    engine = ConfidenceEngine(reliability_provider=provider)
    base = base_confidence("nmap")
    assert engine.score_tool_result("nmap", "success") == pytest.approx(
        reliability_adjustment(base, 0.9) * 0.9)  # single-source discount


def test_engine_score_tool_result_quality_boosts():
    engine = ConfidenceEngine()
    low = engine.score_tool_result("whatweb", "success", quality=0.9)
    high = engine.score_tool_result("whatweb", "success", quality=0.1)
    assert low > high


def test_engine_wires_from_tool_manager():
    class FakeTM:
        def reliability(self, name):
            return 0.9

    engine = ConfidenceEngine(tool_manager=FakeTM())
    s = engine.adjusted_confidence(0.6, tool_name="nmap")
    assert s > 0.6


def test_engine_adjusted_confidence_pipeline():
    engine = ConfidenceEngine(reliability_provider=lambda n: 0.5)
    s = engine.adjusted_confidence(0.6, n_sources=3, age_hours=72)
    expected = corroboration_adjustment(recency_adjustment(0.6, 72), 3)
    assert s == pytest.approx(expected)


def test_engine_verdict_and_floor():
    engine = ConfidenceEngine()
    assert engine.confirm_floor() == CONFIRM_FLOOR
    assert engine.decided_verdict(0.8) == "CONFIRMED"
    assert engine.decided_verdict(0.4) == "NEEDS_PROOF"
    assert engine.decided_verdict(0.1) == "REJECTED"


def test_clamp_unit_bounds():
    assert clamp_unit(1.5) == CEILING
    assert clamp_unit(-1) == 0.0