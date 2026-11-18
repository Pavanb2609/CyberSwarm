"""Tests for generate_attack_report.py: report rendering, finding dedup
(including the severity-merge fix applied alongside these tests), the
Manual Verification Checklist, and risk-rating display.
"""

import json

import pytest

import generate_attack_report as gar


def _evidence(**overrides):
    base = {
        "target": "example.com",
        "risk_rating": "HIGH",
        "completed_agents": ["web_attack", "auth"],
        "vulnerabilities": [],
        "disputed_findings": [],
        "proof_requests": [],
        "new_attack_paths": [],
    }
    base.update(overrides)
    return base


# ── _dedup / _finding_key ────────────────────────────────────────────────────

def test_dedup_collapses_same_name_and_host_regardless_of_severity():
    items = [
        {"name": "Missing Security Header: HSTS", "severity": "MEDIUM", "url": "https://example.com"},
        {"name": "missing security header: hsts", "severity": "HIGH", "url": "https://example.com"},
    ]
    out = gar._dedup(items)
    assert len(out) == 1
    assert out[0]["severity"] == "HIGH"  # keeps the higher severity, not whichever came first


def test_dedup_keeps_distinct_issues_on_same_host():
    items = [
        {"name": "Issue A", "severity": "LOW", "url": "https://example.com"},
        {"name": "Issue B", "severity": "LOW", "url": "https://example.com"},
    ]
    assert len(gar._dedup(items)) == 2


def test_dedup_keeps_same_name_on_different_hosts():
    items = [
        {"name": "Same Issue", "severity": "LOW", "url": "https://a.example.com"},
        {"name": "Same Issue", "severity": "LOW", "url": "https://b.example.com"},
    ]
    assert len(gar._dedup(items)) == 2


def test_dedup_preserves_first_seen_order():
    items = [
        {"name": "Z-issue", "severity": "LOW", "url": "https://example.com"},
        {"name": "A-issue", "severity": "LOW", "url": "https://example.com"},
    ]
    out = gar._dedup(items)
    assert [i["name"] for i in out] == ["Z-issue", "A-issue"]


# ── OWASP findings mapping for the new exploitation surface ──────────────────

def test_owasp_for_new_exploitation_finding_types():
    assert gar.owasp_for({"finding_type": "asrep_roastable",
                          "name": "AS-REP roast — capture", "severity": "CRITICAL"}) == "A07"
    assert gar.owasp_for({"finding_type": "kerberoastable",
                          "name": "Kerberoast — capture", "severity": "HIGH"}) == "A07"
    assert gar.owasp_for({"finding_type": "smb_null_session",
                          "name": "SMB null session", "severity": "HIGH"}) == "A01"
    assert gar.owasp_for({"finding_type": "nosql_injection",
                          "name": "NoSQL operator payload", "severity": "HIGH"}) == "A03"
    assert gar.owasp_for({"finding_type": "ldap_injection",
                          "name": "LDAP filter wildcard", "severity": "HIGH"}) == "A03"


def test_owasp_keyword_fallback_covers_the_surface():
    # If a store entry somehow drops its finding_type, the keyword fallback must
    # still land on the right category.
    assert gar.owasp_for({"name": "Kerberoastable service account found",
                          "severity": "MEDIUM"}) == "A07"
    assert gar.owasp_for({"name": "AS-REP roastable account, no pre-auth",
                          "severity": "MEDIUM"}) == "A07"
    assert gar.owasp_for({"name": "SMB null session anonymous share enum",
                          "severity": "HIGH"}) == "A01"


# ── render_report: basic shape ───────────────────────────────────────────────

def test_render_report_includes_target_and_risk_rating():
    report = gar.render_report(_evidence())
    assert "example.com" in report
    assert "HIGH" in report


def test_render_report_no_vulnerabilities():
    report = gar.render_report(_evidence(vulnerabilities=[]))
    assert "No vulnerabilities confirmed" in report


def test_render_report_sorts_vulnerabilities_by_severity():
    ev = _evidence(vulnerabilities=[
        {"name": "Low issue", "severity": "LOW", "url": "https://example.com/l"},
        {"name": "Critical issue", "severity": "CRITICAL", "url": "https://example.com/c"},
        {"name": "Medium issue", "severity": "MEDIUM", "url": "https://example.com/m"},
    ])
    report = gar.render_report(ev)
    pos_crit = report.index("Critical issue")
    pos_med = report.index("Medium issue")
    pos_low = report.index("Low issue")
    assert pos_crit < pos_med < pos_low


def test_render_report_includes_cve_and_cwe_when_present():
    ev = _evidence(vulnerabilities=[
        {"name": "Vulnerable component", "severity": "HIGH", "url": "https://example.com",
         "cve_id": ["CVE-2024-1234"], "cwe_id": ["CWE-79"], "description": "XSS in search"}])
    report = gar.render_report(ev)
    assert "CVE-2024-1234" in report
    assert "CWE-79" in report


def test_render_report_exploit_candidates_section():
    ev = _evidence(exploit_candidates=[
        {"edb_id": "50000", "title": "WordPress RCE", "type": "webapps",
         "cve": ["CVE-2024-9999"], "url": "https://exploit-db.com/50000"}])
    report = gar.render_report(ev)
    assert "WordPress RCE" in report
    assert "CVE-2024-9999" in report


def test_render_report_derives_searchsploit_exploit_candidates_from_vulns_when_absent():
    ev = _evidence(vulnerabilities=[
        {"name": "nginx 1.18 known exploit", "severity": "HIGH", "tool": "searchsploit",
         "url": "https://example.com"}])
    report = gar.render_report(ev)
    assert "## Exploit Candidates (1)" in report


# ── risk rating display ──────────────────────────────────────────────────────

@pytest.mark.parametrize("risk,emoji", [
    ("CRITICAL", "🔴"), ("HIGH", "🟠"), ("MEDIUM", "🟡"),
    ("LOW", "🔵"), ("INFO", "⚪"), ("UNKNOWN", "⚫"),
])
def test_render_report_risk_emoji_matches_severity(risk, emoji):
    report = gar.render_report(_evidence(risk_rating=risk))
    assert f"{emoji} **{risk}**" in report


# ── recommended next steps ───────────────────────────────────────────────────

def test_render_report_recommends_immediate_remediation_for_high_critical():
    ev = _evidence(vulnerabilities=[
        {"name": "SQLi", "severity": "CRITICAL", "url": "https://example.com"}])
    report = gar.render_report(ev)
    assert "Immediate remediation required" in report


def test_render_report_no_findings_recommends_manual_testing():
    report = gar.render_report(_evidence(vulnerabilities=[]))
    assert "No critical findings" in report


# ── Manual Verification Checklist ────────────────────────────────────────────

def test_checklist_includes_confirmed_finding_urls():
    ev = _evidence(vulnerabilities=[
        {"name": "Exposed admin panel", "severity": "HIGH", "url": "https://example.com/admin"}])
    report = gar.render_report(ev)
    assert "CONFIRMED" in report
    assert "https://example.com/admin" in report


def test_checklist_includes_disputed_findings():
    ev = _evidence(disputed_findings=[
        {"name": "Possible IDOR", "severity": "MEDIUM", "url": "https://example.com/api/1"}])
    report = gar.render_report(ev)
    assert "CRITIC-DISPUTED" in report


def test_checklist_includes_proof_requests_with_urls():
    ev = _evidence(proof_requests=["check https://example.com/reset-password for token leakage"])
    report = gar.render_report(ev)
    assert "NEEDS-PROOF" in report
    assert "https://example.com/reset-password" in report


def test_checklist_proof_request_without_url_uses_manual_step_placeholder():
    ev = _evidence(proof_requests=["verify rate limiting manually"])
    report = gar.render_report(ev)
    assert "manual step" in report


def test_checklist_empty_when_nothing_to_verify():
    report = gar.render_report(_evidence())
    assert "No URLs to verify" in report


def test_checklist_dedupes_when_url_appears_in_both_field_and_description():
    # The checklist adds a vuln's `url` field AND any target-owned URLs it
    # finds inside `description` -- when they're the same URL it must only
    # appear once in the checklist table, not twice.
    ev = _evidence(vulnerabilities=[
        {"name": "Issue A", "severity": "HIGH", "url": "https://example.com/x",
         "description": "Confirmed at https://example.com/x during testing."},
    ])
    report = gar.render_report(ev)
    checklist_section = report.split("Manual Verification Checklist", 1)[1]
    assert checklist_section.count("https://example.com/x") == 1


def test_checklist_masked_or_truncated_recon_urls_are_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(gar, "ROOT", tmp_path)
    smap_dir = tmp_path / "results" / "system_map"
    smap_dir.mkdir(parents=True)
    (smap_dir / "example.com.json").write_text(json.dumps({
        "technologies": [], "services": [],
        "endpoints": [],
        "auth_paths": ["/login****", "/admin\u2026"],
        "api_paths": ["/api/v1"],
    }))
    report = gar.render_report(_evidence())
    assert "/api/v1" in report
    assert "****" not in report
    assert "\u2026" not in report


# ── load_evidence ─────────────────────────────────────────────────────────

def test_load_evidence_reads_from_store(tmp_path, monkeypatch):
    monkeypatch.setattr(gar, "STORE_DIR", tmp_path)
    (tmp_path / "example.com.json").write_text(json.dumps(_evidence()))
    ev = gar.load_evidence("example.com")
    assert ev["target"] == "example.com"


def test_load_evidence_missing_target_exits(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(gar, "STORE_DIR", tmp_path)
    with pytest.raises(SystemExit):
        gar.load_evidence("nonexistent.test")
    assert "No attack evidence found" in capsys.readouterr().out

# ── CVSS scoring + cross-finding attack chains ──────────────────────────────

def test_render_report_shows_cvss_for_a_classifiable_finding():
    ev = _evidence(vulnerabilities=[
        {"name": "SQL Injection in login form", "severity": "UNKNOWN", "url": "https://example.com/login"},
    ])
    report = gar.render_report(ev)
    assert "**CVSS:**" in report
    assert "CVSS:3.1/AV:N" in report


def test_render_report_labels_unclassified_findings_as_not_a_scored_assessment():
    ev = _evidence(vulnerabilities=[
        {"name": "Something the classifier will never recognize", "severity": "MEDIUM",
         "url": "https://example.com/x"},
    ])
    report = gar.render_report(ev)
    assert "not a scored CVSS assessment" in report


def test_render_report_includes_attack_chains_section_when_a_chain_is_detected():
    ev = _evidence(vulnerabilities=[
        {"name": "Clickjacking - missing X-Frame-Options", "severity": "LOW", "url": "https://example.com/"},
        {"name": "Missing CSRF token on account settings", "severity": "MEDIUM", "url": "https://example.com/"},
    ])
    report = gar.render_report(ev)
    assert "Cross-Finding Attack Chains" in report
    assert "requires manual verification" in report
    assert "UI-redress" in report or "clickjacking_csrf" in report.lower() or \
        "UI-redressing" in report


def test_render_report_omits_attack_chains_section_when_none_detected():
    ev = _evidence(vulnerabilities=[
        {"name": "Missing security header", "severity": "LOW", "url": "https://example.com/"},
    ])
    report = gar.render_report(ev)
    assert "Cross-Finding Attack Chains" not in report


def test_render_report_shows_no_data_quality_warning_when_recon_evidence_absent():
    ev = _evidence()
    report = gar.render_report(ev)
    assert "Data Quality" not in report
    assert "UNREACHABLE" not in report


def test_render_report_surfaces_unreachable_warning_and_failure_detail(isolated_stores):
    import evidence_store
    recon_ev = evidence_store.load("dataquality.example")
    recon_ev["reachable"] = False
    recon_ev["failure_patterns"] = {
        "WEB_PROBING": {"errors": ["Timed out after 10.0s running: httpx -u dataquality.example"]},
    }
    recon_ev["zero_findings_actions"] = ["WEB_TECHNOLOGY_DISCOVERY"]
    evidence_store.save(recon_ev)

    ev = _evidence(target="dataquality.example")
    report = gar.render_report(ev)
    assert "UNREACHABLE" in report
    assert "Data Quality" in report
    assert "WEB_PROBING" in report
    assert "Timed out after 10.0s" in report
    assert "WEB_TECHNOLOGY_DISCOVERY" in report


def test_render_report_no_unreachable_banner_when_target_was_reachable(isolated_stores):
    import evidence_store
    recon_ev = evidence_store.load("reachable.example")
    recon_ev["reachable"] = True
    evidence_store.save(recon_ev)

    ev = _evidence(target="reachable.example")
    report = gar.render_report(ev)
    assert "UNREACHABLE" not in report


def test_render_report_sorts_and_badges_by_cvss_severity_not_raw_tool_label():
    # A finding the tool couldn't score (UNKNOWN) but that classifies as
    # SQL injection (CRITICAL via CVSS) must outrank a genuinely LOW finding
    # and must NOT display the misleading "UNKNOWN" badge.
    ev = _evidence(vulnerabilities=[
        {"name": "Clickjacking - missing X-Frame-Options", "severity": "LOW", "url": "https://example.com/a"},
        {"name": "SQL Injection in login form", "severity": "UNKNOWN", "url": "https://example.com/login"},
    ])
    report = gar.render_report(ev)
    sqli_pos = report.find("SQL Injection in login form")
    clickjacking_pos = report.find("Clickjacking - missing X-Frame-Options")
    assert 0 < sqli_pos < clickjacking_pos, "CRITICAL (via CVSS) finding must sort above a LOW finding"
    assert "[CRITICAL] SQL Injection" in report
    assert "[UNKNOWN] SQL Injection" not in report
    assert "tool reported severity: UNKNOWN" in report
