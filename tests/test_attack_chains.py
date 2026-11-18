"""Tests for attack_chains.py: deterministic cross-finding correlation.
Every chain is a hypothesis for a human to verify (requires_manual_verification
must always be True), never an auto-confirmed finding."""

import pytest

from attack_chains import CHAIN_RULES, ChainRule, detect_chains, detect_chains_as_dicts
from cvss import enrich_finding


def _finding(name, url="https://target.example/"):
    return enrich_finding({"name": name, "severity": "MEDIUM", "url": url})


def test_no_chains_when_no_findings():
    assert detect_chains([]) == []


def test_no_chain_when_only_one_of_two_required_types_present():
    findings = [_finding("Clickjacking - missing X-Frame-Options")]
    assert detect_chains(findings) == []


def test_chain_fires_when_both_required_types_present_on_same_host():
    findings = [
        _finding("Clickjacking - missing X-Frame-Options"),
        _finding("Missing CSRF token on account settings"),
    ]
    chains = detect_chains(findings)
    ids = {c.rule_id for c in chains}
    assert "clickjacking_csrf" in ids


def test_chain_does_not_fire_across_different_hosts():
    findings = [
        _finding("Clickjacking - missing X-Frame-Options", url="https://a.example/"),
        _finding("Missing CSRF token on account settings", url="https://b.example/"),
    ]
    assert detect_chains(findings) == []


def test_chain_requires_all_prerequisite_types_not_just_any_one():
    rule = ChainRule(id="test_three", name="test", requires=("a", "b", "c"), narrative="{host}")
    findings = [
        {"finding_type": "a", "url": "https://x/"},
        {"finding_type": "b", "url": "https://x/"},
    ]
    assert detect_chains(findings, rules=(rule,)) == []
    findings.append({"finding_type": "c", "url": "https://x/"})
    assert len(detect_chains(findings, rules=(rule,))) == 1


def test_every_curated_chain_rule_is_internally_consistent():
    # Every rule must require at least 2 distinct finding types (a "chain"
    # of one finding isn't cross-finding correlation) and its
    # resulting_impact, if set, must be a real scoreable finding_type.
    from cvss import FINDING_TYPE_CVSS_DEFAULTS
    for rule in CHAIN_RULES:
        assert len(rule.requires) >= 2, f"{rule.id}: chain rules must require 2+ finding types"
        assert len(set(rule.requires)) == len(rule.requires), f"{rule.id}: duplicate requirement"
        if rule.resulting_impact is not None:
            assert rule.resulting_impact in FINDING_TYPE_CVSS_DEFAULTS, \
                f"{rule.id}: resulting_impact '{rule.resulting_impact}' has no CVSS default"
        assert "{host}" in rule.narrative, f"{rule.id}: narrative should reference {{host}}"


def test_chained_finding_always_requires_manual_verification():
    findings = [
        _finding("Clickjacking - missing X-Frame-Options"),
        _finding("Missing CSRF token on account settings"),
    ]
    for chain in detect_chains(findings):
        assert chain.requires_manual_verification is True


def test_chained_finding_carries_an_assessed_cvss_score_when_rule_defines_one():
    findings = [
        _finding("Reflected Cross-Site Scripting"),
        _finding("Missing security header: Content-Security-Policy"),
    ]
    chains = detect_chains(findings)
    xss_chain = next(c for c in chains if c.rule_id == "xss_session_hijack")
    assert xss_chain.cvss_score is not None
    assert xss_chain.cvss_vector.startswith("CVSS:3.1/")


def test_to_dict_shape_and_contributing_findings():
    findings = [
        _finding("Clickjacking - missing X-Frame-Options"),
        _finding("Missing CSRF token on account settings"),
    ]
    chain = detect_chains(findings)[0]
    d = chain.to_dict()
    assert d["finding_type"] == "attack_chain"
    assert d["requires_manual_verification"] is True
    assert d["host"] == "target.example"
    assert len(d["contributing_findings"]) == 2
    assert set(d["contributing_finding_types"]) == {"clickjacking", "csrf"}


def test_detect_chains_as_dicts_matches_detect_chains():
    findings = [
        _finding("Clickjacking - missing X-Frame-Options"),
        _finding("Missing CSRF token on account settings"),
    ]
    assert len(detect_chains_as_dicts(findings)) == len(detect_chains(findings))


def test_multiple_hosts_each_get_their_own_independent_chain():
    findings = [
        _finding("Clickjacking - missing X-Frame-Options", url="https://a.example/"),
        _finding("Missing CSRF token on account settings", url="https://a.example/"),
        _finding("Clickjacking - missing X-Frame-Options", url="https://b.example/"),
        _finding("Missing CSRF token on account settings", url="https://b.example/"),
    ]
    chains = detect_chains(findings)
    hosts = {c.host for c in chains if c.rule_id == "clickjacking_csrf"}
    assert hosts == {"a.example", "b.example"}


def test_findings_without_a_url_are_grouped_together_not_dropped():
    findings = [
        {"finding_type": "clickjacking", "url": ""},
        {"finding_type": "csrf", "url": ""},
    ]
    chains = detect_chains(findings)
    assert any(c.rule_id == "clickjacking_csrf" for c in chains)


@pytest.mark.parametrize("rule_id,names", [
    ("directory_listing_disclosure", ["Directory listing enabled at /backups/",
                                      "Information disclosure: backup file exposed"]),
    ("takeover_cors_trust", ["Subdomain takeover on old.example.com (subjack)",
                             "Permissive CORS policy with credentials"]),
    ("jwt_idor_takeover", ["JWT accepts alg:none", "IDOR on /api/orders/{id}"]),
    ("creds_upload_webshell", ["Default credentials admin/admin",
                               "Unrestricted file upload on /media/upload"]),
    ("lfi_upload_rce", ["Local file inclusion via ?page=", "Unrestricted file upload on /media/upload"]),
    ("tls_session_fixation", ["Weak TLS cipher suite supported", "Session fixation on login"]),
    ("host_header_open_redirect", ["Host header injection in password reset link",
                                   "Open redirect via ?next="]),
])
def test_each_remaining_curated_chain_rule_fires_on_matching_findings(rule_id, names):
    findings = [_finding(n) for n in names]
    ids = {c.rule_id for c in detect_chains(findings)}
    assert rule_id in ids
