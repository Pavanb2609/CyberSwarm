"""Tests for dashboard_data.py: the read-only aggregation layer behind the
CyberSwarm dashboard (spec §20). Deterministic throughout -- builds small
fixture states/logs on disk and asserts the snapshot shape, never touches
the real results/ directory."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import approval_gate
import attack_evidence_store
import dashboard_data
import evidence_store
import state as state_mod
from state import ActionRecord, Asset, AssessmentState, Decision, EvidenceItem


@pytest.fixture
def dashboard_stores(isolated_stores, monkeypatch, tmp_path):
    """isolated_stores already redirects evidence_store/attack_evidence_store/
    approval_gate/run_agent_loop's logs; this adds state.py's store, since
    the dashboard reads from it directly and it isn't in the shared fixture."""
    monkeypatch.setattr(state_mod, "STORE_DIR", tmp_path / "state")
    return tmp_path


def _memory_path(tmp_path: Path) -> Path:
    return tmp_path / "tool_memory.json"


def test_list_targets_empty_when_nothing_recorded(dashboard_stores):
    assert dashboard_data.list_targets() == []


def test_list_targets_includes_state_graph_target(dashboard_stores):
    st = AssessmentState(target="new.example")
    state_mod.save_state(st)
    assert dashboard_data.list_targets() == ["new.example"]


def test_list_targets_includes_legacy_only_target(dashboard_stores):
    ev = evidence_store.load("legacy.example")
    ev["subdomains"] = ["api.legacy.example"]
    evidence_store.save(ev)
    assert dashboard_data.list_targets() == ["legacy.example"]


def test_list_targets_dedupes_across_sources(dashboard_stores):
    st = AssessmentState(target="both.example")
    state_mod.save_state(st)
    ev = evidence_store.load("both.example")
    evidence_store.save(ev)
    assert dashboard_data.list_targets() == ["both.example"]


def test_build_snapshot_for_unknown_target_is_empty_but_valid(dashboard_stores, tmp_path):
    snap = dashboard_data.build_snapshot("nothing-here.example", memory_path=_memory_path(tmp_path))
    assert snap["target"] == "nothing-here.example"
    assert snap["asset_counts"] == {}
    assert snap["findings"] == []
    assert snap["data_source"] == "state_graph"  # no legacy data either -- default label
    json.dumps(snap)  # must always be JSON-serializable


def test_build_snapshot_uses_state_graph_when_state_file_exists(dashboard_stores, tmp_path):
    st = AssessmentState(target="graph.example")
    st.upsert_asset(Asset(type="subdomain", value="api.graph.example", source="subfinder", confidence=0.8))
    st.add_action(ActionRecord(action="SUBDOMAIN_DISCOVERY", tool="subfinder",
                               target="graph.example", status="success"))
    st.add_decision(Decision(target="graph.example", selected_action="SUBDOMAIN_DISCOVERY",
                             selected_tool="subfinder", result_status="success",
                             knowledge_gaps=["PORT_DISCOVERY"]))
    state_mod.save_state(st)

    snap = dashboard_data.build_snapshot("graph.example", memory_path=_memory_path(tmp_path))
    assert snap["data_source"] == "state_graph"
    assert snap["asset_counts"] == {"subdomain": 1}
    assert snap["assets"]["subdomain"][0]["value"] == "api.graph.example"
    assert len(snap["completed_actions"]) == 1
    assert snap["decision_timeline"][0]["selected_action"] == "SUBDOMAIN_DISCOVERY"
    assert snap["open_knowledge_gaps"] == ["PORT_DISCOVERY"]


def test_build_snapshot_falls_back_to_legacy_stores_when_no_state_file(dashboard_stores, tmp_path):
    ev = evidence_store.load("legacyonly.example")
    ev["subdomains"] = ["a.legacyonly.example"]
    ev["open_ports"] = [80, 443]
    ev["completed_actions"] = ["SUBDOMAIN_DISCOVERY", "PORT_DISCOVERY"]
    ev["failed_actions"] = ["CMS_ASSESSMENT"]
    evidence_store.save(ev)

    attack_ev = attack_evidence_store.load("legacyonly.example", recon_evidence=ev)
    attack_ev["vulnerabilities"] = [{"title": "missing header", "severity": "LOW"}]
    attack_ev["risk_rating"] = "LOW"
    attack_evidence_store.save(attack_ev)

    snap = dashboard_data.build_snapshot("legacyonly.example", memory_path=_memory_path(tmp_path))
    assert snap["data_source"] == "legacy"
    assert snap["asset_counts"]["subdomain"] == 1
    assert snap["asset_counts"]["port"] == 2
    assert len(snap["completed_actions"]) == 2
    assert len(snap["failed_actions"]) == 1
    assert snap["findings"][0]["title"] == "missing header"
    assert snap["risk_rating"] == "LOW"
    json.dumps(snap)


def test_build_snapshot_prefers_state_graph_over_legacy_when_both_exist(dashboard_stores, tmp_path):
    ev = evidence_store.load("preferred.example")
    ev["subdomains"] = ["legacy-only-sub.preferred.example"]
    evidence_store.save(ev)

    st = AssessmentState(target="preferred.example")
    st.upsert_asset(Asset(type="url", value="https://preferred.example/", source="httpx"))
    state_mod.save_state(st)

    snap = dashboard_data.build_snapshot("preferred.example", memory_path=_memory_path(tmp_path))
    assert snap["data_source"] == "state_graph"
    assert "url" in snap["asset_counts"]
    assert "subdomain" not in snap["asset_counts"]  # legacy-only field must not leak in


def test_confidence_breakdown_reflects_asset_labels(dashboard_stores, tmp_path):
    st = AssessmentState(target="conf.example")
    st.upsert_asset(Asset(type="port", value="80", source="naabu", confidence=0.9))
    st.upsert_asset(Asset(type="port", value="443", source="naabu", confidence=0.2))
    state_mod.save_state(st)

    snap = dashboard_data.build_snapshot("conf.example", memory_path=_memory_path(tmp_path))
    assert snap["confidence"]["average"] == pytest.approx(0.55)
    assert sum(snap["confidence"]["by_label"].values()) == 2


def test_approval_history_merges_recon_and_attack_logs_for_the_target(dashboard_stores):
    approval_gate.auto_log(
        {"next_capability": "PORT_DISCOVERY", "requires_human_approval": False},
        target="approve.example", evidence={})

    import run_agent_loop
    run_agent_loop.log_entry({
        "timestamp": "2026-01-01T00:00:00+00:00", "target": "approve.example",
        "approved": False, "phase_marker": "attack-native-entry",
    })

    history = dashboard_data._approval_history("approve.example")
    phases = {h["phase"] for h in history}
    assert phases == {"recon", "attack"}


def test_approval_history_excludes_other_targets(dashboard_stores):
    approval_gate.auto_log({"next_capability": "X"}, target="mine.example", evidence={})
    approval_gate.auto_log({"next_capability": "Y"}, target="someone-elses.example", evidence={})

    history = dashboard_data._approval_history("mine.example")
    assert len(history) == 1
    assert history[0]["target"] == "mine.example"


def test_agent_status_always_includes_the_four_fixed_roles(dashboard_stores, tmp_path):
    snap = dashboard_data.build_snapshot("roles.example", memory_path=_memory_path(tmp_path))
    names = {a["name"] for a in snap["agents"]}
    assert {"Controller", "Planner", "Critic", "Intelligence"}.issubset(names)


def test_snapshot_enriches_findings_with_cvss_and_detects_chains(dashboard_stores, tmp_path):
    st = AssessmentState(target="dashchain.example")
    st.findings.append({"name": "Clickjacking - missing X-Frame-Options", "severity": "LOW",
                        "url": "https://dashchain.example/"})
    st.findings.append({"name": "Missing CSRF token on account settings", "severity": "MEDIUM",
                        "url": "https://dashchain.example/"})
    state_mod.save_state(st)

    snap = dashboard_data.build_snapshot("dashchain.example", memory_path=_memory_path(tmp_path))
    assert all("finding_type" in f for f in snap["findings"])
    assert "attack_chains" in snap
    ids = {c["chain_rule_id"] for c in snap["attack_chains"]}
    assert "clickjacking_csrf" in ids
    json.dumps(snap)


def test_snapshot_is_always_json_serializable_even_with_evidence_and_gaps(dashboard_stores, tmp_path):
    st = AssessmentState(target="full.example")
    st.upsert_asset(Asset(type="technology", value="nginx", source="whatweb", confidence=0.6))
    st.add_evidence(EvidenceItem(target="full.example", source_tool="whatweb",
                                 capability="WEB_TECHNOLOGY_DISCOVERY", status="success",
                                 parsed_result={"technologies": ["nginx"]}))
    st.add_decision(Decision(target="full.example", selected_action="WEB_TECHNOLOGY_DISCOVERY",
                             knowledge_gaps=["CONTENT_DISCOVERY", "PARAMETER_DISCOVERY"]))
    state_mod.save_state(st)

    snap = dashboard_data.build_snapshot("full.example", memory_path=_memory_path(tmp_path))
    json.dumps(snap)
    assert snap["evidence_count"] == 1
    assert snap["open_knowledge_gaps"] == ["CONTENT_DISCOVERY", "PARAMETER_DISCOVERY"]
