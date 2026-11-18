"""Decision trace (Stage 8) — reproducibility layer tests."""

import json

import pytest

import evidence_store as ev_store
import state as state_mod
from agents import memory_agent
import decision_trace
from decision_trace import DecisionTrace
from state import AssessmentState, Decision


@pytest.fixture(autouse=True)
def _isolate_stores(tmp_path, monkeypatch):
    monkeypatch.setattr(state_mod, "STORE_DIR", tmp_path / "state")
    monkeypatch.setattr(ev_store, "STORE_DIR", tmp_path / "evidence")
    monkeypatch.setattr(ev_store, "DECISION_LOG_PATH", tmp_path / "decision_log.jsonl")
    monkeypatch.setattr(memory_agent, "STORE_DIR", tmp_path / "attack_evidence")
    yield


def _state_with_decisions():
    st = AssessmentState(target="example.com")
    st.add_decision(Decision(
        target="example.com", selected_action="SUBDOMAIN_DISCOVERY",
        reasoning="unexplored passive asset discovery",
        knowledge_gaps=["SUBDOMAIN_DISCOVERY", "PORT_DISCOVERY"],
        candidate_actions=[{"capability": "SUBDOMAIN_DISCOVERY", "total": 0.75}],
        selected_tool="subfinder", result_status="success"))
    st.add_decision(Decision(
        target="example.com", selected_action="PORT_DISCOVERY",
        reasoning="subdomains mapped; ports now highest gap",
        knowledge_gaps=["PORT_DISCOVERY", "TLS_ANALYSIS"],
        candidate_actions=[{"capability": "PORT_DISCOVERY", "total": 0.74}],
        selected_tool="naabu", result_status="success"))
    return st


def test_selections_order_matches_log():
    tr = DecisionTrace.from_state(_state_with_decisions())
    plan = tr.selections()
    assert [s["selected_action"] for s in plan] == [
        "SUBDOMAIN_DISCOVERY", "PORT_DISCOVERY"]
    assert plan[0]["selected_tool"] == "subfinder"
    assert plan[0]["result_status"] == "success"


def test_gap_chronology_and_closed_gaps():
    tr = DecisionTrace.from_state(_state_with_decisions())
    chrono = tr.gap_chronology()
    assert chrono[0]["gaps_before"] == ["SUBDOMAIN_DISCOVERY", "PORT_DISCOVERY"]
    # SUBDOMAIN_DISCOVERY is no longer a gap in the decision after it ran
    assert "SUBDOMAIN_DISCOVERY" in tr.closed_gaps()
    assert tr.open_gaps() == ["PORT_DISCOVERY", "TLS_ANALYSIS"] or \
        tr.open_gaps()[0] in ("PORT_DISCOVERY", "TLS_ANALYSIS")


def test_candidate_rankings_captured_per_step():
    tr = DecisionTrace.from_state(_state_with_decisions())
    cands = tr.candidate_actions()
    assert len(cands) == 2
    assert cands[0][0]["capability"] == "SUBDOMAIN_DISCOVERY"


def test_empty_trace_returns_clean_summary():
    tr = DecisionTrace("example.com")
    s = tr.summary()
    assert s["steps"] == 0
    assert s["plan"] == []
    assert s["open_gaps"] == []
    assert "No decisions" in tr.to_markdown()


def test_markdown_includes_steps_and_gaps():
    tr = DecisionTrace.from_state(_state_with_decisions())
    md = tr.to_markdown()
    assert "SUBDOMAIN_DISCOVERY" in md
    assert "PORT_DISCOVERY" in md
    assert "Open gaps:" in md


def test_export_trace_round_trips(tmp_path):
    tr = DecisionTrace.from_state(_state_with_decisions())
    out = tmp_path / "trace.json"
    tr.export_trace(str(out))
    data = json.loads(out.read_text())
    assert data["target"] == "example.com"
    assert data["steps"] == 2
    assert data["plan"][0]["selected_action"] == "SUBDOMAIN_DISCOVERY"


def test_load_trace_from_saved_state(tmp_path):
    st = _state_with_decisions()
    st.mark_updated()
    state_mod.save_state(st, "example.com")
    tr = DecisionTrace.load("example.com")
    assert tr.target == "example.com"
    assert tr.summary()["steps"] == 2


def test_from_dict_round_trip(tmp_path):
    st = _state_with_decisions()
    as_dicts = [d.to_dict() for d in st.decisions]
    tr = DecisionTrace.from_decisions("example.com", as_dicts)
    plan = tr.selections()
    assert plan[1]["selected_action"] == "PORT_DISCOVERY"