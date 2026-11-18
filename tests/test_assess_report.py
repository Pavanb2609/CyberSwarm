"""Assess report generator (Stage 10) — test_report_assess-style tests."""

import pytest

import evidence_store as ev_store
import state as state_mod
from agents import memory_agent

from generate_assess_report import build_report, render_markdown
from state import ASSET_PORT, ASSET_TECHNOLOGY, Asset, EvidenceItem, AssessmentState


@pytest.fixture(autouse=True)
def _isolate_stores(tmp_path, monkeypatch):
    monkeypatch.setattr(state_mod, "STORE_DIR", tmp_path / "state")
    monkeypatch.setattr(ev_store, "STORE_DIR", tmp_path / "evidence")
    monkeypatch.setattr(ev_store, "DECISION_LOG_PATH", tmp_path / "decision_log.jsonl")
    monkeypatch.setattr(memory_agent, "STORE_DIR", tmp_path / "attack_evidence")
    yield


def _seed_target(target="r.example.com"):
    st = AssessmentState(target=target)
    st.upsert_asset(Asset(type=ASSET_PORT, value="443", source="sim"))
    st.upsert_asset(Asset(type=ASSET_TECHNOLOGY, value="nginx", source="sim"))
    st.add_evidence(EvidenceItem(target=target, source_tool="sim",
                                 capability="PORT_DISCOVERY",
                                 parsed_result={"open_ports": ["443"]}))
    st.findings.append({"name": "Open admin", "severity": "HIGH",
                        "url": f"https://{target}/admin"})
    st.risk_rating = "HIGH"
    state_mod.save_state(st, target)
    mem = memory_agent.MemoryAgent(target)
    mem.save({"target": target, "risk_rating": "HIGH",
              "vulnerabilities": [{"name": "Old dep", "severity": "MEDIUM",
                                   "url": "https://x"}]})
    return st


def test_build_report_aggregates_state_memory_and_findings():
    _seed_target()
    data = build_report("r.example.com")
    assert data["target"] == "r.example.com"
    assert data["risk_rating"] == "HIGH"
    assert data["evidence_count"] == 1
    assert data["asset_counts"].get("port") == 1
    assert data["asset_counts"].get("technology") == 1
    names = {f["name"] for f in data["findings"]}
    assert names == {"Open admin", "Old dep"}
    for f in data["findings"]:
        assert "_verdict" in f


def test_render_markdown_includes_sections():
    _seed_target()
    data = build_report("r.example.com")
    md = render_markdown(data)
    assert "Assessment Report" in md
    assert "Risk rating" in md
    assert "Target profile" in md
    assert "Coverage" in md
    assert "Open admin" in md
    assert "Old dep" in md


def test_cli_writes_markdown_and_json(tmp_path):
    _seed_target(target="cli.example.com")
    out = tmp_path / "cli_report.md"
    from generate_assess_report import main
    assert main(["cli.example.com", "--out", str(out)]) == 0
    assert out.exists()
    assert out.with_suffix(".json").exists()
    assert "cli.example.com" in out.read_text()
# ── CVSS scoring + cross-finding attack chains ──────────────────────────────

def _seed_chainable_target(target="chain.example.com"):
    st = AssessmentState(target=target)
    st.findings.append({"name": "Clickjacking - missing X-Frame-Options", "severity": "LOW",
                        "url": f"https://{target}/"})
    st.findings.append({"name": "Missing CSRF token on account settings", "severity": "MEDIUM",
                        "url": f"https://{target}/"})
    st.risk_rating = "MEDIUM"
    state_mod.save_state(st, target)
    return st


def test_build_report_enriches_findings_with_cvss():
    _seed_target()  # findings: "Open admin" (unclassifiable) + "Old dep" (unclassifiable)
    data = build_report("r.example.com")
    for f in data["findings"]:
        assert "finding_type" in f
        assert "cvss_source" in f


def test_build_report_classifies_a_recognizable_finding():
    st = AssessmentState(target="sqli.example.com")
    st.findings.append({"name": "SQL Injection in search", "severity": "UNKNOWN",
                        "url": "https://sqli.example.com/search"})
    state_mod.save_state(st, "sqli.example.com")
    data = build_report("sqli.example.com")
    finding = next(f for f in data["findings"] if f["name"] == "SQL Injection in search")
    assert finding["finding_type"] == "sql_injection"
    assert finding["cvss_source"] == "finding_type_default"
    assert finding["cvss_severity"] == "CRITICAL"


def test_build_report_includes_attack_chains_key():
    _seed_chainable_target()
    data = build_report("chain.example.com")
    assert "attack_chains" in data
    ids = {c["chain_rule_id"] for c in data["attack_chains"]}
    assert "clickjacking_csrf" in ids


def test_render_markdown_includes_cvss_and_chains_section():
    _seed_chainable_target()
    data = build_report("chain.example.com")
    md = render_markdown(data)
    assert "CVSS" in md
    assert "Cross-Finding Attack Chains" in md
    assert "requires manual verification" in md


def test_render_markdown_omits_chains_section_when_none_found():
    _seed_target()  # "Open admin" + "Old dep" alone don't satisfy any chain rule
    data = build_report("r.example.com")
    md = render_markdown(data)
    assert "Cross-Finding Attack Chains" not in md


def test_build_report_lists_failed_actions_without_fabricating_an_error_message():
    from state import ActionRecord
    st = AssessmentState(target="dqcheck.example.com")
    st.add_action(ActionRecord(action="WEB_PROBING", tool="httpx", target="dqcheck.example.com",
                               status="timeout"))
    st.add_action(ActionRecord(action="PORT_DISCOVERY", tool="naabu", target="dqcheck.example.com",
                               status="success"))
    state_mod.save_state(st, "dqcheck.example.com")

    data = build_report("dqcheck.example.com")
    assert data["failed_actions"] == [{"action": "WEB_PROBING", "tool": "httpx", "status": "timeout"}]

    md = render_markdown(data)
    assert "Data Quality" in md
    assert "WEB_PROBING" in md
    assert "httpx" in md
    assert "PORT_DISCOVERY" not in md.split("Data Quality")[1].split("##")[0]  # the successful action isn't listed


def test_render_markdown_omits_data_quality_section_when_nothing_failed():
    _seed_target()
    data = build_report("r.example.com")
    md = render_markdown(data)
    assert "Data Quality" not in md


def test_build_report_sorts_by_cvss_severity_not_raw_tool_label():
    st = AssessmentState(target="sortcheck.example.com")
    st.findings.append({"name": "Clickjacking - missing X-Frame-Options", "severity": "LOW",
                        "url": "https://sortcheck.example.com/a"})
    st.findings.append({"name": "SQL Injection in login form", "severity": "UNKNOWN",
                        "url": "https://sortcheck.example.com/login"})
    state_mod.save_state(st, "sortcheck.example.com")

    data = build_report("sortcheck.example.com")
    names_in_order = [f["name"] for f in data["findings"]]
    assert names_in_order.index("SQL Injection in login form") < \
        names_in_order.index("Clickjacking - missing X-Frame-Options")

    md = render_markdown(data)
    assert "CRITICAL] SQL Injection in login form" in md
    assert "tool reported: UNKNOWN" in md
