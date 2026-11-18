"""Tests for evidence_trail — the per-target, per-vulnerability proof folder."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import evidence_trail as et  # noqa: E402


# ── Classification ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,expected", [
    ("Reflected XSS via q", "xss"),
    ("SQL Injection in id", "sqli"),
    ("Blind SQL injection", "sqli"),
    ("Server-Side Template Injection", "ssti"),
    ("SSRF protocol smuggling", "ssrf"),
    ("Local File Inclusion", "lfi"),
    ("Path traversal", "lfi"),
    ("OS Command Injection", "rce"),
    ("Default credentials accepted", "auth"),
    ("JWT alg confusion", "jwt"),
    ("CRLF Injection", "crlf"),
    ("Kerberoastable accounts", "ad"),
    ("Missing security header", "headers"),
    ("Something unrecognised", "other"),
])
def test_classify(name, expected):
    assert et.classify(name) == expected


# ── Target folder naming ──────────────────────────────────────────────────────

@pytest.mark.parametrize("target,expected", [
    ("http://localhost:8001", "localhost"),
    ("https://amazon.in/path", "amazon.in"),
    ("192.168.1.5:8080", "192.168.1.5"),
    ("EXAMPLE.com", "example.com"),
])
def test_safe_target(target, expected):
    assert et.safe_target(target) == expected


# ── Folder structure ──────────────────────────────────────────────────────────

def test_creates_folder_named_after_target(tmp_path):
    trail = et.EvidenceTrail("http://localhost:8001", base_dir=tmp_path)
    trail.record(et.Attempt(technique="Reflected XSS", tool="xss_proof"),
                 vuln_class="xss")
    folder = trail.write()
    assert folder.name == "localhost"
    assert (folder / "xss.md").exists()
    assert (folder / "00_SUMMARY.md").exists()
    assert (folder / "raw" / "xss.json").exists()


def test_one_file_per_class(tmp_path):
    trail = et.EvidenceTrail("t.local", base_dir=tmp_path)
    trail.record(et.Attempt(technique="XSS"), vuln_class="xss")
    trail.record(et.Attempt(technique="SQLi"), vuln_class="sqli")
    trail.record(et.Attempt(technique="SSRF"), vuln_class="ssrf")
    folder = trail.write()
    assert (folder / "xss.md").exists()
    assert (folder / "sqli.md").exists()
    assert (folder / "ssrf.md").exists()


def test_class_file_shows_payload_request_response(tmp_path):
    trail = et.EvidenceTrail("t.local", base_dir=tmp_path)
    trail.record(et.Attempt(
        technique="Reflected XSS via q",
        payload='<img src=x onerror=alert(1)>',
        request="GET /search?q=<img...>",
        response="proof variable set — executed",
        verdict="CONFIRM", proven=True, proof="ran in headless browser",
        tool="xss_proof"), vuln_class="xss")
    content = (trail.write() / "xss.md").read_text()
    assert "<img src=x onerror=alert(1)>" in content
    assert "GET /search?q=" in content
    assert "proof variable set" in content
    assert "PROVEN" in content
    assert "ran in headless browser" in content


def test_disputed_attempts_are_recorded_not_hidden(tmp_path):
    """The trail must show what was TRIED and rejected, not only what passed."""
    trail = et.EvidenceTrail("t.local", base_dir=tmp_path)
    trail.record(et.Attempt(
        technique="XSS reflected not executed",
        payload="<script>alert(1)</script>",
        response="reflected in attribute, did not execute",
        verdict="DISPUTE"), vuln_class="xss")
    content = (trail.write() / "xss.md").read_text()
    assert "DISPUTE" in content
    assert "<script>alert(1)</script>" in content


# ── Proof honesty ─────────────────────────────────────────────────────────────

def test_summary_counts_proven_separately_from_confirmed(tmp_path):
    trail = et.EvidenceTrail("t.local", base_dir=tmp_path)
    trail.record(et.Attempt(technique="A", verdict="CONFIRM", proven=True,
                            response="evidence"), vuln_class="xss")
    trail.record(et.Attempt(technique="B", verdict="CONFIRM", proven=False),
                 vuln_class="xss")
    summary = (trail.write() / "00_SUMMARY.md").read_text()
    assert "Confirmed: 2" in summary
    assert "Proven (with execution evidence): 1" in summary


def test_amazon_data_yields_zero_proven(tmp_path):
    """The real amazon.in run: nothing was actually proven. The trail must
    say so rather than inheriting the flat JSON's '27 vulnerabilities'."""
    evidence = {
        "vulnerabilities": [
            {"name": "Valid credentials disclosed", "severity": "CRITICAL",
             "verdict": "CONFIRM", "confidence": 90, "tool": "login_brute",
             "raw_output_excerpt": ""},   # no evidence
            {"name": "CRLF Injection", "severity": "HIGH", "verdict": "CONFIRM",
             "tool": "crlf", "raw_output_excerpt": ""},
        ]
    }
    folder = et.build_trail_from_evidence("amazon.in", evidence, base_dir=tmp_path)
    summary = (folder / "00_SUMMARY.md").read_text()
    assert "Proven (with execution evidence): 0" in summary


# ── Sessions ──────────────────────────────────────────────────────────────────

def test_sessions_recorded_as_proof(tmp_path):
    trail = et.EvidenceTrail("t.local", base_dir=tmp_path)
    trail.record(et.Attempt(technique="RCE"), vuln_class="rce")
    trail.record_session(
        {"session_id": "a1", "user": "www-data", "hostname": "box",
         "os_hint": "linux", "elevated": False},
        [{"command": "id", "output": "uid=33(www-data)"}])
    folder = trail.write()
    assert (folder / "sessions.md").exists()
    content = (folder / "sessions.md").read_text()
    assert "www-data" in content
    assert "uid=33" in content


# ── Raw JSON ──────────────────────────────────────────────────────────────────

def test_raw_json_is_machine_readable(tmp_path):
    trail = et.EvidenceTrail("t.local", base_dir=tmp_path)
    trail.record(et.Attempt(technique="XSS", payload="<x>", verdict="CONFIRM"),
                 vuln_class="xss")
    folder = trail.write()
    data = json.loads((folder / "raw" / "xss.json").read_text())
    assert data[0]["technique"] == "XSS"
    assert data[0]["payload"] == "<x>"


def test_finding_object_is_recorded(tmp_path):
    """Accepts AgentFinding-like objects, not just Attempt."""
    class FakeFinding:
        name = "Reflected XSS"
        severity = "HIGH"
        confidence = 80
        verdict = "CONFIRM"
        url = "http://t/search"
        tool = "xss_proof"
        raw_output_excerpt = "executed"
        owasp_category = "A03"
        evidence_chain = None

    trail = et.EvidenceTrail("t.local", base_dir=tmp_path)
    trail.record_finding(FakeFinding())
    folder = trail.write()
    assert (folder / "xss.md").exists()


def test_empty_trail_still_writes_summary(tmp_path):
    folder = et.EvidenceTrail("t.local", base_dir=tmp_path).write()
    assert (folder / "00_SUMMARY.md").exists()


def test_trail_counts_disputed_and_proof_requests(tmp_path):
    """A run with zero confirmed vulns must still report what was attempted."""
    evidence = {
        "vulnerabilities": [],
        "disputed_findings": [
            {"name": "Missing security header: permissions-policy",
             "tool": "header_analysis", "verdict": "DISPUTE",
             "url": "https://t.local", "raw_output_excerpt": "hdrs"},
        ],
        "proof_requests": [
            {"name": "Possible open redirect", "tool": "payload_probe",
             "url": "https://t.local/?next=x"},
        ],
    }
    folder = et.build_trail_from_evidence("t.local", evidence, base_dir=tmp_path)
    summary = (folder / "00_SUMMARY.md").read_text()
    assert "Total attempts recorded: 2" in summary
    assert "Confirmed: 0" in summary
    assert "Proven (with execution evidence): 0" in summary


def test_text_proof_requests_are_parsed_and_classified(tmp_path):
    evidence = {"proof_requests": [
        "[headers_attack] Missing X-XSS-Protection: header missing, may allow XSS.\n[EVIDENCE GATE]: none",
        "[cloud] Publicly Listable S3 Bucket: bucket 'x' may be listable.",
        "free text with no structure",
    ]}
    folder = et.build_trail_from_evidence("t.local", evidence, base_dir=tmp_path)
    summary = (folder / "00_SUMMARY.md").read_text()
    assert "Total attempts recorded: 3" in summary
    assert "[headers.md]" in summary and "[cloud.md]" in summary
    assert "[xss.md]" not in summary  # a missing header is not an XSS attempt


def test_classify_uses_tool_when_name_is_generic():
    assert et.classify("Possible issue", tool="sqlmap") == "sqli"
    assert et.classify("Finding", agent="headers_attack") == "headers"
    assert et.classify("Missing X-XSS-Protection") == "headers"
    assert et.classify("Reflected XSS (Dalfox)", tool="dalfox") == "xss"


def test_text_finding_never_counts_as_proven(tmp_path):
    trail = et.EvidenceTrail("t.local", base_dir=tmp_path)
    trail.record_finding({"name": "Reflected XSS", "verdict": "CONFIRM",
                          "description": "the model says it works"})
    summary = (trail.write() / "00_SUMMARY.md").read_text()
    assert "Proven (with execution evidence): 0" in summary
