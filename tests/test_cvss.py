"""Tests for cvss.py: CVSS 3.1 base-score math and finding-type
classification/enrichment. The score-math tests pin the implementation
against well-known, widely-published CVSS 3.1 reference vectors so a
future refactor can't silently drift from the spec."""

import pytest

import cvss
from cvss import CVSSVector, base_score, classify_finding_type, enrich_finding, enrich_findings, severity_from_score


# ── Base score formula, pinned against published reference vectors ─────────

@pytest.mark.parametrize("vector,expected", [
    (CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"), 9.8),   # unauthenticated RCE, scope unchanged
    (CVSSVector("N", "L", "N", "N", "C", "H", "H", "H"), 10.0),  # scope changed -> ceiling
    (CVSSVector("N", "L", "N", "R", "C", "L", "L", "N"), 6.1),   # classic reflected-XSS reference vector
    (CVSSVector("N", "L", "L", "N", "U", "L", "N", "N"), 4.3),   # low-privilege info-disclosure reference
    (CVSSVector("N", "H", "N", "N", "U", "N", "N", "N"), 0.0),   # no impact metrics set -> 0
])
def test_base_score_matches_published_reference_vectors(vector, expected):
    assert base_score(vector) == pytest.approx(expected, abs=0.05)


def test_base_score_never_exceeds_ten():
    vector = CVSSVector("N", "L", "N", "N", "C", "H", "H", "H")
    assert base_score(vector) <= 10.0


@pytest.mark.parametrize("score,label", [
    (0.0, "NONE"), (2.0, "LOW"), (5.5, "MEDIUM"), (8.0, "HIGH"), (9.9, "CRITICAL"), (None, "UNKNOWN"),
])
def test_severity_from_score_bands(score, label):
    assert severity_from_score(score) == label


def test_every_finding_type_default_computes_a_valid_score():
    # Every curated vector must actually compute to something in [0, 10] --
    # catches a typo'd metric letter before it ships.
    for finding_type, vector in cvss.FINDING_TYPE_CVSS_DEFAULTS.items():
        score = base_score(vector)
        assert 0.0 <= score <= 10.0, f"{finding_type} produced an out-of-range score: {score}"


# ── Finding-type classification ─────────────────────────────────────────────

@pytest.mark.parametrize("name,expected_type", [
    ("SQL Injection in login form", "sql_injection"),
    ("Reflected Cross-Site Scripting", "cross_site_scripting_reflected"),
    ("Stored XSS in comment field", "cross_site_scripting_stored"),
    ("Server-Side Request Forgery via webhook", "server_side_request_forgery"),
    ("XML External Entity (XXE) Injection", "xml_external_entity"),
    ("Remote Code Execution via deserialization gadget", "remote_code_execution"),
    ("Insecure Direct Object Reference on /api/users/{id}", "idor"),
    ("Missing CSRF token on password change", "csrf"),
    ("Subdomain takeover on old.example.com (subjack)", "subdomain_takeover"),
    ("JWT accepts alg:none", "jwt_weak_algorithm"),
    ("Permissive CORS policy with credentials", "cors_misconfiguration"),
    ("Clickjacking - missing X-Frame-Options", "clickjacking"),
    ("Directory listing enabled at /backups/", "directory_listing"),
    ("Default credentials admin/admin", "default_credentials"),
])
def test_classify_finding_type_recognizes_common_names(name, expected_type):
    assert classify_finding_type({"name": name}) == expected_type


def test_classify_prefers_stored_xss_over_generic_xss():
    # "stored xss" must not fall through to the generic reflected-XSS bucket
    # just because "xss" also matches -- ordering in _CLASSIFIERS matters.
    assert classify_finding_type({"name": "Stored XSS via profile bio"}) == "cross_site_scripting_stored"


def test_classify_ad_exploitation_findings():
    assert classify_finding_type(
        {"name": "AS-REP roast — offline-crackable hashes captured"}) == "asrep_roastable"
    assert classify_finding_type(
        {"name": "Kerberoast — service account TGS hashes captured"}) == "kerberoastable"
    assert classify_finding_type(
        {"name": "SMB null session — anonymous share enumeration"}) == "smb_null_session"
    assert classify_finding_type(
        {"name": "NoSQL injection anomaly via operator payload"}) == "nosql_injection"
    assert classify_finding_type(
        {"name": "LDAP injection anomaly in filter parameter"}) == "ldap_injection"


def test_enrich_scores_new_exploitation_types():
    for name, finding_type in (
            ("AS-REP roast — hashes captured", "asrep_roastable"),
            ("Kerberoast found", "kerberoastable"),
            ("SMB null session", "smb_null_session"),
            ("NoSQL injection detected", "nosql_injection"),
            ("LDAP injection detected", "ldap_injection")):
        v = enrich_finding({"name": name, "severity": "HIGH"})
        assert v["finding_type"] == finding_type
        assert v["cvss_vector"]  # scored, not just labelled
        assert isinstance(v.get("cvss_score"), (int, float))


def test_classify_returns_none_for_unrecognized_text():
    assert classify_finding_type({"name": "Some completely novel thing nothing matches"}) is None


def test_classify_is_case_insensitive():
    assert classify_finding_type({"name": "SQL INJECTION"}) == "sql_injection"


def test_classify_checks_template_id_and_description_too():
    assert classify_finding_type({"name": "", "template_id": "sqli-detect"}) == "sql_injection"
    assert classify_finding_type({"name": "Finding", "description": "possible ssrf via url param"}) == \
        "server_side_request_forgery"


# ── enrich_finding ────────────────────────────────────────────────────────

def test_enrich_finding_scores_a_recognized_type():
    v = enrich_finding({"name": "SQL Injection in search", "severity": "UNKNOWN", "url": "https://x/search"})
    assert v["finding_type"] == "sql_injection"
    assert v["cvss_source"] == "finding_type_default"
    assert v["cvss_vector"].startswith("CVSS:3.1/")
    assert v["cvss_severity"] == "CRITICAL"
    assert v["cvss_score"] > 9.0


def test_enrich_finding_falls_back_to_severity_label_when_unclassified():
    v = enrich_finding({"name": "Something obscure the classifier won't recognize", "severity": "HIGH"})
    assert v["finding_type"] == "unclassified"
    assert v["cvss_vector"] is None
    assert v["cvss_source"] == "tool_severity_label"
    assert v["cvss_score"] == 8.0
    assert v["cvss_severity"] == "HIGH"


def test_enrich_finding_handles_missing_severity_gracefully():
    v = enrich_finding({"name": "Unrecognized finding with no severity at all"})
    assert v["cvss_score"] is None
    assert v["cvss_severity"] == "UNKNOWN"


def test_enrich_finding_does_not_mutate_the_input():
    original = {"name": "SQL Injection", "severity": "UNKNOWN"}
    snapshot = dict(original)
    enrich_finding(original)
    assert original == snapshot


def test_enrich_finding_is_idempotent_and_never_overwrites_an_existing_assessment():
    already_scored = {"name": "SQL Injection", "finding_type": "custom_type_a_human_set",
                      "cvss_vector": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}
    v = enrich_finding(already_scored)
    assert v["finding_type"] == "custom_type_a_human_set"
    assert v["cvss_vector"] == "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"


def test_enrich_findings_applies_to_every_item_in_a_list():
    out = enrich_findings([{"name": "SQL Injection"}, {"name": "Reflected XSS"}])
    assert [f["finding_type"] for f in out] == ["sql_injection", "cross_site_scripting_reflected"]


# ── effective_severity ──────────────────────────────────────────────────────

def test_effective_severity_prefers_cvss_classification_over_tool_unknown():
    v = enrich_finding({"name": "SQL Injection in login form", "severity": "UNKNOWN"})
    assert cvss.effective_severity(v) == "CRITICAL"


def test_effective_severity_falls_back_to_tool_label_when_unclassified():
    v = enrich_finding({"name": "Something the classifier will never recognize", "severity": "HIGH"})
    assert cvss.effective_severity(v) == "HIGH"


def test_effective_severity_handles_a_raw_unenriched_finding():
    # Called on something that never went through enrich_finding() at all --
    # must not crash, just fall back to the raw severity field.
    assert cvss.effective_severity({"severity": "LOW"}) == "LOW"
    assert cvss.effective_severity({}) == "UNKNOWN"
