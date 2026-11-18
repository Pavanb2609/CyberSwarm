"""Tests for finding_extractor — the deterministic filter that stops RUN-ALL
recording false positives as confirmed vulnerabilities.

Every case here is drawn from the real amazon.in run that produced 27
"vulnerabilities" of which 26 were noise or false positives.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import finding_extractor as fx  # noqa: E402


# ── The amazon.in false positives, verbatim ──────────────────────────────────

def test_brute_hit_false_is_dropped_entirely():
    """The fake CRITICAL: raw record said hit=false, tool reported a credential."""
    findings = fx.extract_findings("LOGIN_BRUTE", {
        "brute_results": [{"url": "https://amazon.in", "username": "",
                           "status": 200, "hit": False}]}, "login_brute")
    assert findings == [], "a brute result that did not hit is not a finding"


def test_brute_real_hit_is_kept_but_needs_proof():
    findings = fx.extract_findings("LOGIN_BRUTE", {
        "brute_results": [{"url": "https://x", "username": "admin",
                           "password": "admin", "hit": True, "confidence": 90}]},
        "login_brute")
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].verdict == fx.NEEDS_PROOF, "even a hit needs critic proof"


def test_crlf_encoded_payload_is_disputed():
    """The response Location had %0d%0a still encoded -- it never split."""
    findings = fx.extract_findings("CRLF_INJECTION_SCAN", {
        "crlf_findings": [{"url": "https://amazon.in?q=test",
                           "injected_header": "Location: https://www.amazon.in/?q=test&%0d%0aX-Injected:%20true",
                           "severity": "HIGH", "confidence": 85}]}, "crlf")
    assert len(findings) == 1
    assert findings[0].verdict == fx.DISPUTE
    assert findings[0].severity == "LOW"


def test_crlf_real_split_is_confirmed():
    findings = fx.extract_findings("CRLF_INJECTION_SCAN", {
        "crlf_findings": [{"url": "https://x",
                           "injected_header": "Set-Cookie: a=b\r\nX-Injected: true",
                           "confidence": 85}]}, "crlf")
    assert findings[0].verdict == fx.CONFIRM
    assert findings[0].severity == "HIGH"


def test_ssrf_html_evidence_is_disputed():
    """gopher->Redis returning an HTML page is the site, not Redis."""
    findings = fx.extract_findings("SSRF_EXPLOIT", {
        "ssrf_findings": [{"type": "protocol_smuggling", "variant": "gopher_redis",
                           "evidence": "<html>\r\n<head><title>", "confidence": 70,
                           "severity": "HIGH"}]}, "ssrf_exploit")
    assert findings[0].verdict == fx.DISPUTE


def test_ssrf_redirect_evidence_is_disputed():
    """Every 'internal port' returned the same 301 -- that is the redirect."""
    findings = fx.extract_findings("SSRF_EXPLOIT", {
        "ssrf_findings": [{"type": "internal_port_scan",
                           "evidence": "HTTP 301, 163 bytes response",
                           "description": "SSRF: internal port 21 (FTP)"}]},
        "ssrf_exploit")
    assert findings[0].verdict == fx.DISPUTE


def test_ssrf_real_service_response_is_confirmed():
    findings = fx.extract_findings("SSRF_EXPLOIT", {
        "ssrf_findings": [{"type": "protocol_smuggling", "variant": "gopher_redis",
                           "evidence": "redis_version:6.2.1\r\nused_memory:1024",
                           "confidence": 70, "severity": "HIGH"}]}, "ssrf_exploit")
    assert findings[0].verdict == fx.CONFIRM
    assert findings[0].severity == "HIGH"


# ── Nikto noise ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("line", [
    "Target IP:          3.253.176.101",
    "Start Time:         2026-09-22 09:36:21 (GMT0)",
    "Your Nikto installation is out of date.",
    "1 host(s) tested",
    "Server: Server",
    "No CGI Directories found",
    "Scan terminated: 1 error and 7 items reported",
])
def test_nikto_metadata_is_dropped(line):
    findings = fx.extract_findings("WEB_VULN_SCAN",
                                   {"nikto_findings": [line]}, "nikto")
    assert findings == [], f"{line!r} is scan metadata, not a finding"


@pytest.mark.parametrize("line", [
    "/: Suggested security header missing: x-content-type-options",
    "Server is using a wildcard certificate: *.cy.peg.a2z.com",
    "/: Uncommon header 'x-amz-rid' found",
])
def test_nikto_real_findings_are_kept(line):
    findings = fx.extract_findings("WEB_VULN_SCAN",
                                   {"nikto_findings": [line]}, "nikto")
    assert len(findings) == 1


def test_missing_header_is_confirmed_but_low():
    findings = fx.extract_findings("WEB_VULN_SCAN", {
        "nikto_findings": ["/: Suggested security header missing: strict-transport-security"]},
        "nikto")
    assert findings[0].verdict == fx.CONFIRM
    assert findings[0].severity == "INFO"


# ── The whole amazon.in payload ──────────────────────────────────────────────

def test_full_amazon_sweep_collapses_to_signal():
    """27 confirmed 'vulnerabilities' -> a handful, none falsely CRITICAL."""
    amazon = {
        "crlf_findings": [{"url": "https://amazon.in?q=test",
                           "injected_header": "Location: https://www.amazon.in/?q=test&%0d%0aX-Injected:%20true",
                           "confidence": 85}],
        "ssrf_findings": [
            {"type": "protocol_smuggling", "variant": "gopher_redis",
             "evidence": "<html>\r\n<head>", "confidence": 70},
            {"type": "internal_port_scan", "evidence": "HTTP 301, 163 bytes",
             "description": "internal port 22 (SSH)"}],
        "brute_results": [{"username": "", "status": 200, "hit": False}],
        "nikto_findings": [
            "Target IP: 3.253.176.101", "Start Time: 2026", "1 host(s) tested",
            "Your Nikto installation is out of date",
            "/: Suggested security header missing: x-content-type-options",
            "Server is using a wildcard certificate: *.cy.peg.a2z.com"],
    }
    findings = fx.extract_findings("RUN_ALL", amazon, "mixed")
    summary = fx.summarise(findings)

    # No confirmed CRITICAL or HIGH survives -- every high-severity claim was
    # a false positive.
    confirmed = [f for f in findings if f.verdict == fx.CONFIRM]
    assert all(f.severity in ("INFO", "LOW") for f in confirmed), \
        "no high-severity finding should be confirmed from this benign data"
    assert not any(f.name.startswith("Valid credentials") for f in findings), \
        "the fake CRITICAL must be gone"
    assert summary[fx.DISPUTE] >= 3


def test_non_dict_results_are_safe():
    assert fx.extract_findings("X", None, "t") == []
    assert fx.extract_findings("X", "nope", "t") == []


def test_summarise_counts_verdicts():
    findings = fx.extract_findings("WEB_VULN_SCAN", {
        "nikto_findings": ["/: security header missing: x-frame-options"]}, "nikto")
    assert fx.summarise(findings)[fx.CONFIRM] == 1
