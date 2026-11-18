"""Tests for evidence_store.py: load/save round-trip, merge_tool_result
branch coverage (ports/services/tech/dedup/zero-findings/failure-patterns),
and the self-healing fallback that reconstructs from decision_log.jsonl
when the evidence file is corrupt, empty, or thinner than what's on record.
"""

import json

import pytest

import evidence_store as es
from tools.base import ToolResult


# ── load()/save() ───────────────────────────────────────────────────────────

def test_load_creates_fresh_evidence_when_none_exists(isolated_stores):
    ev = es.load("fresh.test", warn_on_regression=False)
    assert ev["target"] == "fresh.test"
    assert ev["completed_actions"] == []
    assert ev["open_ports"] == []
    assert ev["authorized_scope"] is True


def test_save_load_roundtrip(isolated_stores):
    ev = es.load("roundtrip.test", warn_on_regression=False)
    ev["open_ports"] = [80, 443]
    ev["completed_actions"] = ["PORT_DISCOVERY"]
    es.save(ev)

    reloaded = es.load("roundtrip.test", warn_on_regression=False)
    assert reloaded["open_ports"] == [80, 443]
    assert reloaded["completed_actions"] == ["PORT_DISCOVERY"]


def test_load_slashes_and_colons_in_target_dont_break_path(isolated_stores):
    # Path-scoped / URL-ish targets must not create nested directories.
    ev = es.load("example.com:8443/admin", warn_on_regression=False)
    es.save(ev)
    reloaded = es.load("example.com:8443/admin", warn_on_regression=False)
    assert reloaded["target"] == "example.com:8443/admin"


# ── self-healing fallback ───────────────────────────────────────────────────

def _log_entry(target: str, completed_actions: list) -> dict:
    return {
        "target": target,
        "evidence": {"target": target, "completed_actions": completed_actions,
                     "open_ports": [], "services": [], "technologies": [],
                     "failed_actions": [], "zero_findings_actions": [],
                     "previous_observations": [], "subdomains": [],
                     "subdomain_resolutions": {}, "failure_patterns": {},
                     "authorized_scope": True},
    }


def test_load_warns_and_restores_richer_decision_log_snapshot(isolated_stores, monkeypatch):
    # Evidence file on disk is thin (1 completed action)...
    ev = es.load("richtest.com", warn_on_regression=False)
    ev["completed_actions"] = ["DNS_RESOLUTION"]
    es.save(ev)

    # ...but decision_log.jsonl remembers a richer prior session (3 actions).
    es.DECISION_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(es.DECISION_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(_log_entry(
            "richtest.com", ["DNS_RESOLUTION", "PORT_DISCOVERY", "WEB_PROBING"])) + "\n")

    monkeypatch.setattr("builtins.input", lambda *_: "y")
    restored = es.load("richtest.com", warn_on_regression=True)
    assert restored["completed_actions"] == ["DNS_RESOLUTION", "PORT_DISCOVERY", "WEB_PROBING"]


def test_load_keeps_current_evidence_if_user_declines_restore(isolated_stores, monkeypatch):
    ev = es.load("declinetest.com", warn_on_regression=False)
    ev["completed_actions"] = ["DNS_RESOLUTION"]
    es.save(ev)

    es.DECISION_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(es.DECISION_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(_log_entry(
            "declinetest.com", ["DNS_RESOLUTION", "PORT_DISCOVERY"])) + "\n")

    monkeypatch.setattr("builtins.input", lambda *_: "n")
    kept = es.load("declinetest.com", warn_on_regression=True)
    assert kept["completed_actions"] == ["DNS_RESOLUTION"]  # unchanged


def test_richest_logged_evidence_picks_the_best_of_multiple_sessions(isolated_stores):
    es.DECISION_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(es.DECISION_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(_log_entry("multi.test", ["A"])) + "\n")
        f.write(json.dumps(_log_entry("multi.test", ["A", "B", "C"])) + "\n")  # richest
        f.write(json.dumps(_log_entry("multi.test", ["A", "B"])) + "\n")
        f.write(json.dumps(_log_entry("other.test", ["X", "Y", "Z", "W"])) + "\n")  # different target

    richest = es._richest_logged_evidence("multi.test")
    assert richest["completed_actions"] == ["A", "B", "C"]


def test_richest_logged_evidence_skips_corrupt_lines(isolated_stores):
    es.DECISION_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(es.DECISION_LOG_PATH, "a", encoding="utf-8") as f:
        f.write("{not valid json\n")
        f.write(json.dumps(_log_entry("corrupttest.com", ["A", "B"])) + "\n")
        f.write("\n")  # blank line

    richest = es._richest_logged_evidence("corrupttest.com")
    assert richest["completed_actions"] == ["A", "B"]


def test_richest_logged_evidence_returns_none_when_no_log(isolated_stores):
    assert es._richest_logged_evidence("nolog.test") is None


# ── merge_tool_result: recon fields ─────────────────────────────────────────

def _base_evidence():
    return es.load("merge.test", warn_on_regression=False)


def test_merge_open_ports_dedupes_and_sorts(isolated_stores):
    ev = _base_evidence()
    ev["open_ports"] = [443]
    r = ToolResult(tool="naabu", status="success", capability="PORT_DISCOVERY",
                   results={"open_ports": [80, 443, 8080]})
    ev = es.merge_tool_result(ev, r)
    assert ev["open_ports"] == [80, 443, 8080]


def test_merge_subdomains_dedupes_preserving_order(isolated_stores):
    ev = _base_evidence()
    ev["subdomains"] = ["api.example.com"]
    r = ToolResult(tool="subfinder", status="success", capability="SUBDOMAIN_DISCOVERY",
                   results={"subdomains": ["api.example.com", "www.example.com"]})
    ev = es.merge_tool_result(ev, r)
    assert ev["subdomains"] == ["api.example.com", "www.example.com"]


def test_merge_port_details_updates_by_port_number(isolated_stores):
    ev = _base_evidence()
    ev["port_details"] = [{"port": 80, "service": "http", "product": None, "version": None}]
    r = ToolResult(tool="nmap", status="success", capability="SERVICE_DETECTION",
                   results={"port_details": [{"port": 80, "service": "http",
                                              "product": "nginx", "version": "1.22"},
                                             {"port": 443, "service": "https",
                                              "product": "nginx", "version": "1.22"}]})
    ev = es.merge_tool_result(ev, r)
    by_port = {d["port"]: d for d in ev["port_details"]}
    assert by_port[80]["product"] == "nginx"  # updated, not duplicated
    assert 443 in by_port
    assert [d["port"] for d in ev["port_details"]] == [80, 443]  # sorted


def test_merge_marks_capability_completed_on_success(isolated_stores):
    ev = _base_evidence()
    r = ToolResult(tool="httpx", status="success", capability="WEB_PROBING",
                   results={"probes": [{"url": "https://merge.test", "status_code": 200}],
                            "reachable": True})
    ev = es.merge_tool_result(ev, r)
    assert "WEB_PROBING" in ev["completed_actions"]


def test_merge_marks_zero_findings_when_success_but_nothing_found(isolated_stores):
    ev = _base_evidence()
    r = ToolResult(tool="subfinder", status="success", capability="SUBDOMAIN_DISCOVERY",
                   results={"subdomains": [], "count": 0})
    ev = es.merge_tool_result(ev, r)
    assert "SUBDOMAIN_DISCOVERY" in ev["completed_actions"]
    assert "SUBDOMAIN_DISCOVERY" in ev["zero_findings_actions"]


def test_merge_does_not_mark_zero_findings_when_something_found(isolated_stores):
    ev = _base_evidence()
    r = ToolResult(tool="naabu", status="success", capability="PORT_DISCOVERY",
                   results={"open_ports": [443], "count": 1})
    ev = es.merge_tool_result(ev, r)
    assert "PORT_DISCOVERY" not in ev["zero_findings_actions"]


def test_merge_tracks_failed_actions_and_failure_patterns(isolated_stores):
    ev = _base_evidence()
    r = ToolResult(tool="naabu", status="error", capability="PORT_DISCOVERY",
                   error="connection refused")
    ev = es.merge_tool_result(ev, r)
    assert "PORT_DISCOVERY" in ev["failed_actions"]
    assert ev["failure_patterns"]["PORT_DISCOVERY"]["count"] == 1
    assert "connection refused" in ev["failure_patterns"]["PORT_DISCOVERY"]["errors"]

    # A second failure for the same capability increments the count, doesn't duplicate the error
    r2 = ToolResult(tool="naabu", status="error", capability="PORT_DISCOVERY",
                    error="connection refused")
    ev = es.merge_tool_result(ev, r2)
    assert ev["failure_patterns"]["PORT_DISCOVERY"]["count"] == 2
    assert ev["failure_patterns"]["PORT_DISCOVERY"]["errors"] == ["connection refused"]


def test_merge_testssl_removes_capability_from_zero_findings_when_vulns_present(isolated_stores):
    ev = _base_evidence()
    ev["zero_findings_actions"] = ["TLS_ANALYSIS"]
    r = ToolResult(tool="testssl", status="success", capability="TLS_ANALYSIS",
                   results={"tls_findings": ["CIPHER: RC4 [MEDIUM]"], "protocols": {}})
    ev = es.merge_tool_result(ev, r)
    assert "TLS_ANALYSIS" not in ev["zero_findings_actions"]
    assert ev["testssl_results"] == r.results


def test_merge_header_findings_dedupe(isolated_stores):
    ev = _base_evidence()
    ev["header_findings"] = ["HSTS missing"]
    r = ToolResult(tool="header_analysis", status="success", capability="HEADER_ANALYSIS",
                   results={"header_findings": ["HSTS missing", "CSP missing"]})
    ev = es.merge_tool_result(ev, r)
    assert ev["header_findings"] == ["HSTS missing", "CSP missing"]


# ── staleness (living-target freshness guard) ──────────────────────────────
# A weeks-old evidence file describes a previous incarnation of a live host
# (stale services/technologies AND completed_actions that make capabilities
# skip). is_stale/fresh exist so recon can discard and rebuild instead of
# poisoning a live engagement.

def test_fresh_returns_clean_evidence_with_no_history(isolated_stores):
    ev = es.fresh("fresh.test")
    assert ev["completed_actions"] == []
    assert ev["open_ports"] == []
    assert ev["previous_observations"] == []


def test_is_stale_false_when_no_file(isolated_stores):
    assert es.is_stale("does.not.exist") is False


def test_is_stale_true_when_older_than_max_age(isolated_stores):
    ev = es.fresh("old.test")
    es.save(ev)
    old = 30 * 86400
    import os
    os.utime(es.path_for("old.test"), (old, old))
    assert es.is_stale("old.test", max_age_days=7) is True


def test_is_stale_false_when_fresh(isolated_stores):
    ev = es.fresh("new.test")
    es.save(ev)
    assert es.is_stale("new.test", max_age_days=7) is False


def test_save_stamps_saved_at(isolated_stores):
    ev = es.fresh("stamped.test")
    es.save(ev)
    reloaded = es.load("stamped.test", warn_on_regression=False)
    assert reloaded.get("saved_at"), "save() must stamp saved_at timestamps"
    assert es.path_for("stamped.test").exists()
