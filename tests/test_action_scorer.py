"""Tests for ActionScorer: evidence-gap selection, success priors, novelty
decay, risk gating, and planner attack-graph rescoring."""

import pytest

from action_scorer import (
    AGENT_CAPABILITY,
    ActionScorer,
    information_gap,
    novelty_ratio,
    risk_penalty_for,
    success_prior,
)
from agents.planner_agent import PlannerAgent
from tool_manager import RISK_ACTIVE_HIGH, RISK_ACTIVE_LOW, RISK_PASSIVE


def test_information_gap_strong_when_untouched():
    assert information_gap({}, "PORT_DISCOVERY") == 1.0
    assert information_gap({"PORT_DISCOVERY": 0}, "PORT_DISCOVERY") == 1.0
    assert information_gap({"PORT_DISCOVERY": 3}, "PORT_DISCOVERY") == pytest.approx(0.25)


def test_novelty_ratio_decays():
    assert novelty_ratio([], "X") == 1.0
    assert novelty_ratio(["X"], "X") == pytest.approx(0.4)
    assert novelty_ratio(["X", "X"], "X") == pytest.approx(0.2)
    assert novelty_ratio(["other", "X", "other"], "X") == pytest.approx(0.4)


def test_risk_penalty_levels():
    assert risk_penalty_for(RISK_PASSIVE) == 0.0
    assert risk_penalty_for(RISK_ACTIVE_LOW) == pytest.approx(0.1)
    assert risk_penalty_for(RISK_ACTIVE_HIGH) == pytest.approx(0.3)
    assert risk_penalty_for(RISK_ACTIVE_HIGH, allow_high_risk=False) == 1.0


def test_success_prior_surface_hints():
    assert success_prior("PORT_DISCOVERY", {"reachable": True}) == pytest.approx(0.9)
    assert success_prior("WEB_TECHNOLOGY_DISCOVERY", {"web": True}) == pytest.approx(0.85)
    assert success_prior("SQLI_SCAN", {"web": True, "params_found": True}) == pytest.approx(1.0)
    assert success_prior("SQLI_SCAN", {}) == pytest.approx(0.5)


def test_score_action_prioritizes_unexplored_passive():
    scorer = ActionScorer()
    score = scorer.score_action("PORT_DISCOVERY", coverage={}, surface={"reachable": True})
    assert score.info_gain == 1.0
    assert score.risk_level == RISK_ACTIVE_LOW
    assert score.total > 0.8


def test_score_action_high_risk_disallowed_is_zero():
    scorer = ActionScorer(allow_high_risk=False)
    score = scorer.score_action("SQLI_SCAN", coverage={}, surface={"web": True})
    assert score.total == 0.0


def test_score_action_high_risk_allowed_is_sizable():
    scorer = ActionScorer(allow_high_risk=True)
    score = scorer.score_action("SQLI_SCAN", coverage={}, surface={"web": True})
    assert score.risk_level == RISK_ACTIVE_HIGH
    assert score.total > 0.0


def test_score_action_penalizes_repeat_attempts():
    scorer = ActionScorer()
    first = scorer.score_action("PORT_DISCOVERY", coverage={}, attempted=[])
    repeat = scorer.score_action("PORT_DISCOVERY", coverage={}, attempted=["PORT_DISCOVERY"])
    assert repeat.total < first.total


def test_rank_orders_descending():
    scorer = ActionScorer()
    coverage = {"PORT_DISCOVERY": 5}
    capabilities = ["PORT_DISCOVERY", "SUBDOMAIN_DISCOVERY", "TLS_ANALYSIS"]
    ranked = scorer.rank(capabilities, coverage, surface={"reachable": True})
    assert ranked[0].capability != "PORT_DISCOVERY"
    totals = [s.total for s in ranked]
    assert totals == sorted(totals, reverse=True)


def test_next_action_returns_top():
    scorer = ActionScorer()
    action = scorer.next_action(["PORT_DISCOVERY", "DNS_RESOLUTION"],
                                {"PORT_DISCOVERY": 9}, surface={"reachable": True})
    assert action.capability == "DNS_RESOLUTION"


def test_score_action_uses_tool_manager_risk():
    class FakeTM:
        def risk_level_for_capability(self, capability, use_attack=False):
            return RISK_ACTIVE_HIGH if capability == "SQLI_SCAN" else RISK_ACTIVE_LOW

    scorer = ActionScorer(tool_manager=FakeTM())
    assert scorer.risk_level("SQLI_SCAN") == RISK_ACTIVE_HIGH
    assert scorer.risk_level("PORT_DISCOVERY") == RISK_ACTIVE_LOW


def test_score_plan_rescores_and_preserves_skip():
    scorer = ActionScorer()
    nodes = [
        {"agent": "network", "priority": 1, "reason": "r", "skip": False},
        {"agent": "headers_attack", "priority": 3, "reason": "r", "skip": True},
        {"agent": "intelligence", "priority": 10, "reason": "r", "skip": False},
    ]
    plan = scorer.score_plan(nodes, coverage={}, surface={"reachable": True})
    by_agent = {n["agent"]: n for n in plan["attack_graph"]}
    assert by_agent["network"]["evidence_score"]["total"] > 0
    assert by_agent["network"]["capability"] == "PORT_DISCOVERY"
    assert by_agent["headers_attack"]["skip"] is True
    assert "headers_attack" in plan["skip_agents"]
    assert plan["reasoning"].startswith("evidence-driven")


def test_score_plan_unknown_agent_keeps_own_priority():
    scorer = ActionScorer()
    nodes = [{"agent": "mystery_agent", "priority": 7, "reason": "r", "skip": False}]
    plan = scorer.score_plan(nodes, coverage={})
    assert plan["attack_graph"][0]["evidence_priority"] == 7
    assert "capability" not in plan["attack_graph"][0]


def test_agent_capability_map_covers_planner_agents():
    required = {"web_attack", "network", "api", "auth", "infra", "cloud",
                "web_fuzz", "headers_attack", "subdomain_takeover", "waf_bypass",
                "jwt", "xxe", "csrf", "deserialization", "session_hijack",
                "ssti_exploit", "lfi_exploit", "ssrf_exploit", "jwt_exploit",
                "exploitation", "intelligence"}
    assert required <= set(AGENT_CAPABILITY)


def test_planner_rescore_with_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr("agents.memory_agent.STORE_DIR", tmp_path)
    p = PlannerAgent(None)
    nodes = [
        {"agent": "network", "priority": 1, "reason": "r1", "skip": False},
        {"agent": "auth", "priority": 5, "reason": "r2", "skip": True},
    ]
    graph = {"target_profile": "WEB_APPLICATION", "attack_graph": nodes,
             "skip_agents": ["auth"], "reasoning": "original"}
    out = p.rescore_with_evidence(graph, coverage={}, surface={"reachable": True})
    assert out["evidence_scored"] is True
    assert out["target_profile"] == "WEB_APPLICATION"
    assert out["skip_agents"] == ["auth"]
    assert out["reasoning"].startswith("evidence-driven")
    agent_names = [n["agent"] for n in out["attack_graph"]]
    assert agent_names == ["network", "auth"]


def test_planner_rescore_without_evidence_is_safe():
    p = PlannerAgent(None)
    graph = {"attack_graph": [], "skip_agents": [], "reasoning": ""}
    out = p.rescore_with_evidence(graph)
    assert out["evidence_scored"] is True
    assert out["attack_graph"] == []