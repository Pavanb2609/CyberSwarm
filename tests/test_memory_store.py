"""Tests for the unified MemoryStore facade and finding dedup."""

import pytest

import evidence_store as ev_store
import state as state_mod
from agents import memory_agent
from memory_store import MemoryStore, merge_findings
from state import (
    ASSET_API,
    ASSET_ENDPOINT,
    ASSET_PARAMETER,
    ASSET_PORT,
    ASSET_SUBDOMAIN,
    ASSET_TECHNOLOGY,
    ASSET_URL,
    ActionRecord,
    Asset,
    EvidenceItem,
    AssessmentState,
)


def _legacy_evidence(target="example.com"):
    return {
        "target": target,
        "resolved_ip": "1.2.3.4",
        "reachable": True,
        "open_ports": [80, 443],
        "services": [{"port": 443, "service": "https"}],
        "port_details": [{"port": 443, "service": "https", "state": "open"}],
        "technologies": ["nginx"],
        "discovered_urls": ["https://example.com/"],
        "discovered_paths": ["/admin"],
        "subdomains": ["www.example.com"],
        "discovered_parameters": ["id"],
        "cms_detected": None,
        "detected_api_types": [],
        "completed_actions": ["SUBDOMAIN_DISCOVERY", "PORT_DISCOVERY"],
        "failed_actions": ["WPS_SCAN"],
        "zero_findings_actions": [],
        "previous_observations": [],
    }


@pytest.fixture(autouse=True)
def _isolate_stores(tmp_path, monkeypatch):
    monkeypatch.setattr(state_mod, "STORE_DIR", tmp_path / "state")
    monkeypatch.setattr(ev_store, "STORE_DIR", tmp_path / "evidence")
    monkeypatch.setattr(ev_store, "DECISION_LOG_PATH", tmp_path / "decision_log.jsonl")
    monkeypatch.setattr(memory_agent, "STORE_DIR", tmp_path / "attack_evidence")
    yield


# ── dedup ───────────────────────────────────────────────────────────────────

def test_merge_findings_dedupes_same_issue():
    a = {"name": "Missing Header: HSTS", "url": "https://x.test", "severity": "MEDIUM"}
    b = {"name": "missing header: hsts", "url": "http://x.test", "severity": "HIGH"}
    merged = merge_findings([], [a, b])
    assert len(merged) == 1
    assert merged[0]["severity"] == "HIGH"


def test_merge_findings_keeps_both_distinct_issues():
    a = {"name": "HSTS missing", "url": "https://x.test", "severity": "MEDIUM"}
    b = {"name": "S3 bucket public", "url": "https://s3.amazonaws.com/x", "severity": "HIGH"}
    assert len(merge_findings([], [a, b])) == 2


def test_merge_findings_raises_confidence_on_duplicate():
    a = {"name": "XSS", "url": "https://x.test", "severity": "MEDIUM", "confidence": 60}
    b = {"name": "x-ss", "url": "https://x.test", "severity": "MEDIUM", "confidence": 90}
    merged = merge_findings([a], [b])
    assert len(merged) == 1
    assert merged[0]["confidence"] == 90


def test_merge_findings_ignores_non_dicts():
    assert merge_findings([], [None, {"name": "a", "url": "https://x.test", "severity": "LOW"}]) \
        == [{"name": "a", "url": "https://x.test", "severity": "LOW"}]


# ── load and hydrate ────────────────────────────────────────────────────────

def test_load_empty_returns_state_for_target():
    store = MemoryStore("example.com")
    st = store.load()
    assert isinstance(st, AssessmentState)
    assert st.target == "example.com"
    assert st.assets == []


def test_hydrate_from_evidence_maps_assets(tmp_path):
    ev_store.STORE_DIR.mkdir(parents=True, exist_ok=True)
    ev_store.save(_legacy_evidence())
    store = MemoryStore("example.com")
    st = store.load()  # no state file -> hydrate from evidence
    assert st.has_asset(ASSET_SUBDOMAIN, "www.example.com")
    assert st.has_asset(ASSET_PORT, "443")
    assert st.has_asset(ASSET_TECHNOLOGY, "nginx")
    assert st.has_asset(ASSET_URL, "https://example.com/")
    assert st.has_asset(ASSET_ENDPOINT, "example.com/admin")
    assert st.has_asset(ASSET_PARAMETER, "id")
    assert st.metadata.get("reachable") is True


def test_hydrate_records_coverage_from_legacy_actions():
    ev_store.save(_legacy_evidence())
    store = MemoryStore("example.com")
    st = store.load()
    cov = store.coverage_map(st)
    assert cov.get("SUBDOMAIN_DISCOVERY", 0) >= 1
    assert cov.get("PORT_DISCOVERY", 0) >= 1
    assert "WPS_SCAN" in store.attempted_capabilities(st)


def test_state_file_wins_over_legacy(tmp_path):
    ev_store.save(_legacy_evidence())
    store = MemoryStore("example.com")
    st = store.load()
    st.assets.append(Asset(type=ASSET_PORT, value="8080", source="test"))
    st.add_action(ActionRecord(action="CUSTOM_ACTION", tool="t", target="example.com"))
    state_mod.save_state(st, "example.com")
    st2 = store.load()
    assert st2.has_asset(ASSET_PORT, "8080")
    assert "CUSTOM_ACTION" in store.attempted_capabilities(st2)
    cov = store.coverage_map(st2)
    assert "CUSTOM_ACTION" not in cov  # action recorded, no evidence item


# ── queries ─────────────────────────────────────────────────────────────────

def test_coverage_map_counts_evidence_capabilities():
    store = MemoryStore("example.com")
    st = AssessmentState(target="example.com")
    st.add_evidence(EvidenceItem(target="example.com", source_tool="naabu",
                                 capability="PORT_DISCOVERY", parsed_result={"p": [80]}))
    st.add_evidence(EvidenceItem(target="example.com", source_tool="nmap",
                                 capability="PORT_DISCOVERY", parsed_result={"p": [443]}))
    assert store.coverage_map(st) == {"PORT_DISCOVERY": 2}


def test_surface_hints_derived_from_state():
    store = MemoryStore("example.com")
    st = AssessmentState(target="example.com")
    st.upsert_asset(Asset(type=ASSET_PORT, value="443", source="naabu"))
    st.upsert_asset(Asset(type=ASSET_URL, value="https://example.com/", source="httpx"))
    st.upsert_asset(Asset(type=ASSET_API, value="graphql", source="api_discover"))
    st.upsert_asset(Asset(type=ASSET_PARAMETER, value="id", source="arjun"))
    hints = store.surface_hints(st)
    assert hints["reachable"] is True
    assert hints["web"] is True
    assert hints["ssl"] is True
    assert hints["api"] is True
    assert hints["params_found"] is True


def test_overview_includes_everything(tmp_path):
    store = MemoryStore("example.com")
    mem = store.memory_agent.load()
    mem["vulnerabilities"] = [{"name": "x", "url": "https://example.com/", "severity": "HIGH"}]
    mem["completed_agents"] = ["web_attack"]
    store.memory_agent.save(mem)
    ov = store.overview()
    assert ov["target"] == "example.com"
    assert ov["vulnerabilities"] == 1
    assert ov["completed_agents"] == ["web_attack"]
    assert "tool_reliability" in ov
    assert "state" in ov


# ── exports and persistence ─────────────────────────────────────────────────

def test_state_to_evidence_populates_legacy_fields():
    store = MemoryStore("example.com")
    st = AssessmentState(target="example.com")
    st.upsert_asset(Asset(type=ASSET_PORT, value="443", source="naabu"))
    st.upsert_asset(Asset(type=ASSET_URL, value="https://example.com/", source="httpx"))
    st.upsert_asset(Asset(type=ASSET_SUBDOMAIN, value="www.example.com", source="subfinder"))
    st.add_action(ActionRecord(action="PORT_DISCOVERY", tool="naabu", target="example.com"))
    ev = store.state_to_evidence(st)
    assert 443 in ev["open_ports"]
    assert "www.example.com" in ev["subdomains"]
    assert "https://example.com/" in ev["discovered_urls"]
    assert "PORT_DISCOVERY" in ev["completed_actions"]
    assert ev["target"] == "example.com"


def test_save_persists_state_and_evidence(tmp_path):
    store = MemoryStore("example.com")
    st = store.load()
    st.upsert_asset(Asset(type=ASSET_PORT, value="80", source="naabu"))
    store.save(st)
    assert (state_mod.STORE_DIR / "example.com.json").exists()
    assert (ev_store.STORE_DIR / "example.com.json").exists()
    loaded = store.load()
    assert loaded.has_asset(ASSET_PORT, "80")


def test_export_attack_memory_preserves_target():
    store = MemoryStore("example.com")
    st = store.load()
    st.findings = [{"name": "x", "url": "https://example.com/", "severity": "HIGH"}]
    mem = store.export_attack_memory(st)
    assert mem["target"] == "example.com"
    assert len(mem["vulnerabilities"]) == 1


def test_import_attack_memory_pulls_vulnerabilities(tmp_path):
    store = MemoryStore("example.com")
    st = store.load()
    mem = store.memory_agent.load()
    mem["vulnerabilities"] = [{"name": "CVE", "url": "https://example.com/", "severity": "CRITICAL"}]
    store.memory_agent.save(mem)
    store.import_attack_memory(st)
    assert len(st.findings) == 1
    assert st.findings[0]["name"] == "CVE"

# ── persist must keep evidence linkage ─────────────────────────────────────
# _finding_to_vuln previously dropped evidence_chain/final_confidence/
# independent_sources/raw_output_excerpt, so CONFIRM vulns exported without
# the tool artifacts that justified them.

from agents.base_agent import AgentFinding, AgentResult


def _persist_test_finding():
    f = AgentFinding(agent="web_attack", tool="dalfox", name="Reflected XSS",
                     severity="HIGH", confidence=80,
                     evidence_chain=["[dalfox] reflected q -> <script>"],
                     raw_output_excerpt="[dalfox] reflected q -> <script>alert(1)</script> status 200")
    f.final_confidence = 90
    f.independent_sources = 2
    return f


def test_store_agent_result_persists_evidence_linkage():
    from agents.memory_agent import MemoryAgent
    f = _persist_test_finding()
    res = AgentResult(agent="web_attack", target="web.test", status="success",
                      findings=[f], attack_paths_discovered=["EXPLOIT:1"],
                      tools_run=["dalfox"])
    agent = MemoryAgent("web.test")
    mem = agent.store_agent_result(agent.load(), res,
                                   {"confirmed": [f], "disputed": [], "needs_proof": []},
                                   system_map={})
    agent.save(mem)
    vulns = agent.load()["vulnerabilities"]
    assert vulns
    v = vulns[0]
    assert v["evidence_chain"] == ["[dalfox] reflected q -> <script>"]
    assert "alert(1)" in v["raw_output_excerpt"]
    assert v["final_confidence"] == 90
    assert v["independent_sources"] == 2


def test_run_agent_loop_finding_to_dict_keeps_evidence():
    from run_agent_loop import _finding_to_dict
    d = _finding_to_dict(_persist_test_finding())
    assert d["evidence_chain"] == ["[dalfox] reflected q -> <script>"]
    assert "alert(1)" in d["raw_output_excerpt"]
    assert d["final_confidence"] == 90
    assert d["independent_sources"] == 2
