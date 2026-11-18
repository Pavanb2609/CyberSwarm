"""Controller (Stage 7) — evidence-driven assessment loop tests."""

from pathlib import Path

import evidence_store as ev_store
import pytest
import state as state_mod
import authorization as auth
from agents import memory_agent

from tools.base import Tool, ToolResult
from tool_manager import ToolManager, RISK_ACTIVE_HIGH

from controller import Controller, absorb_tool_result
from memory_store import MemoryStore
from state import (
    ASSET_API, ASSET_CMS, ASSET_ENDPOINT, ASSET_IP, ASSET_PARAMETER,
    ASSET_PORT, ASSET_SERVICE, ASSET_SUBDOMAIN, ASSET_TECHNOLOGY, ASSET_URL,
    AssessmentState,
)
from tool_manager import tool_risk_level


@pytest.fixture(autouse=True)
def _isolate_stores(tmp_path, monkeypatch):
    monkeypatch.setattr(state_mod, "STORE_DIR", tmp_path / "state")
    monkeypatch.setattr(ev_store, "STORE_DIR", tmp_path / "evidence")
    monkeypatch.setattr(ev_store, "DECISION_LOG_PATH", tmp_path / "decision_log.jsonl")
    monkeypatch.setattr(memory_agent, "STORE_DIR", tmp_path / "attack_evidence")
    monkeypatch.setattr(auth, "CONFIG_PATH", tmp_path / "auth.json")
    yield


class FakeTool(Tool):
    def __init__(self, name, results=None):
        self.name = name
        self.capability = name
        self._results = results or {}

    def build_command(self, target, **kwargs):
        return []

    def parse(self, stdout, stderr):
        return {}

    def run(self, target, timeout=120, **kwargs):
        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results=self._results)


FAKE_RECON_RESULTS = {
    "subfinder": {"subdomains": ["www.example.com", "api.example.com"]},
    "amass": {"subdomains": ["dev.example.com"]},
    "naabu": {"open_ports": ["80", "443", "8080"]},
    "whatweb": {"technologies": ["nginx"], "cms_detected": "WordPress"},
    "httpx": {"discovered_urls": ["https://example.com/"],
              "resolved_ip": "93.184.216.34"},
    "nuclei": {"vulnerabilities": [{"name": "MySQL unauth", "severity": "HIGH",
                                    "url": "https://example.com/"}]},
    "nmap": {"port_details": [{"port": 443, "service": "https"}]},
    "arjun": {"discovered_parameters": ["id"]},
    "ffuf": {"discovered_endpoints": ["/wp-login.php"], "discovered_paths": ["/admin"]},
}


def fake_loader(name):
    return FakeTool(name, FAKE_RECON_RESULTS.get(name) or {})


def fake_attack_loader(name):
    return FakeTool(name, {})


def make_controller(tmp_path, target="127.0.0.1", **kwargs):
    tm = ToolManager(recon_loader=fake_loader, attack_loader=fake_attack_loader,
                     memory_path=tmp_path / "tool_memory.json")
    mem = MemoryStore(target, tool_manager=tm)
    return Controller(target, tool_manager=tm, memory_store=mem, **kwargs)


def test_absorb_tool_result_registers_assets():
    st = AssessmentState(target="127.0.0.1")
    result = ToolResult(
        tool="nmap", status="success", capability="PORT_DISCOVERY",
        results={
            "open_ports": ["22", "443"],
            "port_details": [{"port": 443, "service": "https"}],
            "subdomains": ["www.example.com"],
            "technologies": ["nginx"],
            "discovered_urls": ["https://example.com/"],
            "discovered_endpoints": ["/login"], "discovered_paths": ["/admin"],
            "discovered_parameters": ["token"], "detected_api_types": ["REST"],
            "resolved_ip": "93.184.216.34", "cms_detected": "WordPress",
        },
    )
    absorb_tool_result(st, result, "127.0.0.1")
    assert st.has_asset(ASSET_PORT, "22")
    assert st.has_asset(ASSET_SERVICE, "443/https")
    assert st.has_asset(ASSET_SUBDOMAIN, "www.example.com")
    assert st.has_asset(ASSET_TECHNOLOGY, "nginx")
    assert st.has_asset(ASSET_URL, "https://example.com/")
    assert st.has_asset(ASSET_ENDPOINT, "127.0.0.1/login")
    assert st.has_asset(ASSET_ENDPOINT, "127.0.0.1/admin")
    assert st.has_asset(ASSET_PARAMETER, "token")
    assert st.assets_of_type(ASSET_API), "api detections stored as api assets"
    assert st.has_asset(ASSET_IP, "93.184.216.34")
    assert st.has_asset(ASSET_CMS, "WordPress")


def test_absorb_tool_result_absorbs_findings():
    st = AssessmentState(target="127.0.0.1")
    result = ToolResult(tool="nuclei", status="success", capability="WEB_VULN_SCAN",
                        results={"vulnerabilities": [
                            {"name": "MySQL unauth", "url": "x", "severity": "HIGH"}]})
    absorb_tool_result(st, result, "127.0.0.1")
    assert len(st.findings) == 1
    absorb_tool_result(st, result, "127.0.0.1")
    assert len(st.findings) == 1, "repeat findings must dedupe"


def test_absorb_tool_result_enriches_findings_with_cvss():
    st = AssessmentState(target="127.0.0.1")
    result = ToolResult(tool="sqlmap", status="success", capability="WEB_VULN_SCAN",
                        results={"vulnerabilities": [
                            {"name": "SQL Injection in login form", "url": "https://example.com/login",
                             "severity": "UNKNOWN"}]})
    absorb_tool_result(st, result, "127.0.0.1")
    finding = st.findings[0]
    assert finding["finding_type"] == "sql_injection"
    assert finding["cvss_vector"].startswith("CVSS:3.1/")
    assert finding["cvss_severity"] == "CRITICAL"


def test_capability_retry_cap_prevents_hogging():
    """Evidence-less capabilities stop being re-selected after max_cap_attempts."""
    c = make_controller(Path("/tmp/x"), max_cap_attempts=2)
    flags = c.candidates_for_step(
        {}, attempted=[], surface={"reachable": True, "web": True},
        session_attempts={"S3_LIST": 2})
    assert all(cap != "S3_LIST" for cap, _ in flags)
    flags1 = c.candidates_for_step(
        {}, attempted=[], surface={"reachable": True, "web": True},
        session_attempts={"S3_LIST": 1})
    assert any(cap == "S3_LIST" for cap, _ in flags1), "under the cap stays eligible"


def test_assess_runs_plan_records_decisions_and_evidence(tmp_path):
    c = make_controller(tmp_path)
    out = c.assess()
    assert out["actions_run"] >= 3
    assert out["target"] == "127.0.0.1"
    assert out["decisions"], "a decision trace must be recorded"
    first = out["decisions"][0]
    assert first["knowledge_gaps"], "gaps should be enumerated"
    assert first["candidate_actions"], "candidate ranking must be captured"
    snap = out["snapshot"]
    total_assets = sum(snap.get("asset_counts", {}).values())
    assert total_assets >= 3, "assets discovered by fake tools"
    assert snap["evidence_count"] >= 3
    assert len(snap["actions_taken"]) >= 3
    st = state_mod.load_state("127.0.0.1")
    assert any(a.action == first["selected_action"] and a.tool != "(dry-run)"
               for a in st.actions)


def test_assess_recon_first_phase_gate(tmp_path):
    c = make_controller(tmp_path, allow_high_risk=True)
    flags = c.candidates_for_step({}, [])
    assert all(not flag for _, flag in flags), "attack must wait for recon"
    assert c.candidate_flags(), "candidates never empty"


def test_attack_unlocks_after_core_recon(tmp_path):
    c = make_controller(tmp_path, allow_high_risk=True)
    assert all(not flag for _, flag in c.candidates_for_step({}, []))
    core = {"reachable": True, "web": True}
    flags = c.candidates_for_step({}, [], surface=core)
    assert any(flag for _, flag in flags), \
        "attack actions must unlock once the target is reachable/web"

    c2 = make_controller(tmp_path, allow_high_risk=True)
    recon_flags = [f for f in c2.candidates_for_step({}, []) if not f[1]]
    attempted_all = [cap for cap, _ in recon_flags]
    assert any(flag for _, flag in
               c2.candidates_for_step({}, attempted_all, surface={})), \
        "attack actions must unlock after every recon cap is attempted"


def test_high_risk_gated_until_allowed(tmp_path):
    c = make_controller(tmp_path, allow_high_risk=False)
    for cap, flag in c.candidate_flags():
        if flag:
            assert tool_risk_level(cap) != RISK_ACTIVE_HIGH, \
                f"high-risk action {cap} leaked into a gated plan"
    c2 = make_controller(tmp_path, allow_high_risk=True)
    assert c2.candidate_flags(), "high-risk plan keeps all candidates"


def test_assess_min_score_stops_immediately(tmp_path):
    c = make_controller(tmp_path, min_action_score=0.99)
    out = c.assess()
    assert out["actions_run"] == 0
    assert "minimum score" in out["stop_reason"]


def test_dry_run_never_touches_tools(tmp_path):
    c = make_controller(tmp_path, dry_run=True)
    out = c.assess()
    assert out["dry_run"] is True
    assert out["actions_run"] >= 3
    st = state_mod.load_state("127.0.0.1")
    assert all(a.tool == "(dry-run)" for a in st.actions)


def test_saves_state_across_runs(tmp_path):
    c = make_controller(tmp_path)
    first = c.assess()
    path = state_mod.STORE_DIR / "127.0.0.1.json"
    assert path.exists()
    second_ctrl = make_controller(tmp_path)
    out = second_ctrl.assess()
    st = state_mod.load_state("127.0.0.1")
    assert st.actions, "actions persist across runs"
    assert len(st.decisions) >= len(first["decisions"])


def test_memory_persists_full_pipeline(tmp_path):
    c = make_controller(tmp_path)
    out = c.assess()
    mem = MemoryStore("127.0.0.1", tool_manager=c.tool_manager)
    assert mem.attack_memory()["target"] == "127.0.0.1"
    st = mem.load()
    assert len(st.evidence) == out["snapshot"]["evidence_count"]
    assert mem.overview(st)["target"] == "127.0.0.1"