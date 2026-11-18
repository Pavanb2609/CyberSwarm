"""Tests for the confidence-aware CriticAgent upgrades: centralized gate
math, deterministic offline fallback, self-consistency flags, and
corroboration context passed to the reviewing LLM."""

import json

import pytest
import system_map as sm

from agents.base_agent import AgentFinding
from agents.critic_agent import (
    MIN_CONFIRM_CONFIDENCE, MIN_EVIDENCE_LEN, CriticAgent,
)
from confidence import llm_fallback_confidence


class FakeModelClient:
    def __init__(self, response=""):
        self._resp = response
        self.calls = 0
        self.last_user = ""

    def chat(self, system_prompt, user_prompt, temperature=None):
        self.calls += 1
        self.last_user = user_prompt
        return self._resp


def _finding(name="x", confidence=70, tool="nuclei", independent_sources=1,
             evidence_chain=None):
    return AgentFinding(agent="web_attack", tool=tool, name=name,
                        severity="HIGH", confidence=confidence,
                        independent_sources=independent_sources,
                        evidence_chain=evidence_chain)


def _web_map():
    return sm.build_from_evidence("web.test", {
        "resolved_ip": "1.2.3.4",
        "reachable": True,
        "port_details": [{"port": 443, "service": "https", "state": "open"}],
        "open_ports": [443],
        "technologies": ["nginx"],
        "discovered_urls": ["https://web.test/"],
        "subdomains": [],
        "completed_actions": ["portscan"],
        "failed_actions": [],
        "zero_findings_actions": [],
        "discovered_parameters": [],
    })


def test_gate_verdict_downgrades_low_confidence_confirm():
    c = CriticAgent(FakeModelClient())
    final_conf, verdict = c.gate_verdict("CONFIRM", agent_conf=30, critic_score=15)
    assert verdict == "NEEDS_PROOF"
    assert final_conf == 21  # 0.4*30 + 0.6*15


def test_gate_verdict_keeps_high_confidence_confirm():
    c = CriticAgent(FakeModelClient())
    final_conf, verdict = c.gate_verdict("CONFIRM", agent_conf=90, critic_score=95)
    assert verdict == "CONFIRM"
    assert final_conf == 93  # 0.4*90 + 0.6*95


def test_gate_verdict_passes_dispute_through():
    c = CriticAgent(FakeModelClient())
    final_conf, verdict = c.gate_verdict("DISPUTE", agent_conf=40, critic_score=10)
    assert verdict == "DISPUTE"


def test_gate_floor_constant_matches_confidence_module():
    assert MIN_CONFIRM_CONFIDENCE == 50


def test_apply_review_downgrade_keeps_message():
    client = FakeModelClient(json.dumps({
        "reviews": [{"index": 0, "verdict": "CONFIRM", "adjusted_confidence": 15,
                     "critique": "weak", "false_positive_reasons": [], "proof_needed": ""}]
    }))
    c = CriticAgent(client)
    f = _finding(confidence=30, evidence_chain=["nuclei matched template x"])
    buckets = c.review_batch([f], _web_map())
    assert f.verdict == "NEEDS_PROOF"
    assert f in buckets["needs_proof"]
    assert "downgraded CONFIRM -> NEEDS_PROOF" in f.description


def test_apply_review_uses_engine_blend():
    client = FakeModelClient(json.dumps({
        "reviews": [{"index": 0, "verdict": "CONFIRM", "adjusted_confidence": 90,
                     "critique": "strong", "false_positive_reasons": [], "proof_needed": ""}]
    }))
    c = CriticAgent(client)
    f = _finding(confidence=70, evidence_chain=[
        "GET /?id=1' AND 1=1 -> 200, error 'MySQL syntax' in response"])
    c.review_batch([f], _web_map())
    assert f.critic_score == 90
    assert f.final_confidence == int(70 * 0.4 + 90 * 0.6)


def test_offline_fallback_is_deterministic_and_low():
    c = CriticAgent(FakeModelClient(""))
    f = _finding(confidence=90)
    c.review_batch([f], _web_map())
    assert f.verdict == "NEEDS_PROOF"
    assert f.final_confidence == int(llm_fallback_confidence() * 100)
    assert f.final_confidence < MIN_CONFIRM_CONFIDENCE


def test_self_consistency_flags():
    c = CriticAgent(FakeModelClient())
    assert c.self_consistency_flags("CONFIRM", 20) == ["CONFIRM contradicts low confidence"]
    assert c.self_consistency_flags("DISPUTE", 90) == [
        "DISPUTE at high confidence warrants proof of the false positive"]
    assert c.self_consistency_flags("NEEDS_PROOF", 95) == [
        "NEEDS_PROOF at high confidence warrants an active proof step"]
    assert c.self_consistency_flags("CONFIRM", 95) == []
    assert c.self_consistency_flags("DISPUTE", 30) == []
    assert c.self_consistency_flags("garbage", "junk") == []


def test_self_consistency_flags_are_low_confirm_aligned():
    c = CriticAgent(FakeModelClient())
    flags = c.self_consistency_flags("CONFIRM", 49)
    assert "CONFIRM contradicts low confidence" in flags


def test_independent_sources_in_finding_serialization():
    f = _finding(independent_sources=3)
    assert f.to_dict()["independent_sources"] == 3
    assert _finding().to_dict()["independent_sources"] == 1


def test_batch_prompt_includes_corroboration_context():
    client = FakeModelClient(json.dumps({
        "reviews": [{"index": 0, "verdict": "CONFIRM", "adjusted_confidence": 90,
                     "critique": "ok", "false_positive_reasons": [], "proof_needed": ""}]
    }))
    c = CriticAgent(client)
    f = _finding(independent_sources=4)
    c.review_batch([f], _web_map())
    assert "independent_sources" in client.last_user
    assert '"independent_sources": 4' in client.last_user


def test_finding_default_independent_sources_is_one():
    assert AgentFinding(agent="a", tool="t", name="n").independent_sources == 1


# ── deterministic evidence gate ────────────────────────────────────────────

def test_evidence_gate_rejects_pure_llm_finding_without_evidence():
    c = CriticAgent(FakeModelClient())
    f = _finding(tool="analysis", confidence=95)
    f.evidence_chain = []
    f.raw_output_excerpt = ""
    assert c.evidence_gate(f) == "NEEDS_PROOF"


def test_evidence_gate_accepts_tool_finding_with_real_excerpt():
    c = CriticAgent(FakeModelClient())
    f = _finding(tool="nuclei", confidence=95)
    f.raw_output_excerpt = "curl --output x http://target 200 OK SQLi payload matched"
    assert c.evidence_gate(f) is None


def test_evidence_gate_accepts_finding_with_evidence_chain():
    c = CriticAgent(FakeModelClient())
    f = _finding(tool="sqlmap", confidence=95)
    f.evidence_chain = ["GET /?id=1' -> 200, error 'MySQL syntax' in response"]
    assert c.evidence_gate(f) is None


def test_evidence_gate_rejects_noisy_excerpt():
    c = CriticAgent(FakeModelClient())
    f = _finding(tool="nuclei", confidence=95)
    f.raw_output_excerpt = "{}"
    assert len(f.raw_output_excerpt) < MIN_EVIDENCE_LEN
    assert c.evidence_gate(f) == "NEEDS_PROOF"


def test_gate_blocks_confirm_when_llm_insists_without_evidence():
    client = FakeModelClient(json.dumps({
        "reviews": [{"index": 0, "verdict": "CONFIRM", "adjusted_confidence": 95,
                     "critique": "sounds real", "false_positive_reasons": [], "proof_needed": ""}]
    }))
    c = CriticAgent(client)
    f = _finding(tool="analysis", confidence=90)
    buckets = c.review_batch([f], _web_map())
    assert f.verdict == "NEEDS_PROOF"
    assert f not in buckets["confirmed"]
    assert "[EVIDENCE GATE]" in f.description
    assert f.final_confidence == int(llm_fallback_confidence() * 100)


def test_gate_runs_before_llm_saving_calls():
    client = FakeModelClient(json.dumps({
        "reviews": [{"index": 0, "verdict": "CONFIRM", "adjusted_confidence": 95,
                     "critique": "", "false_positive_reasons": [], "proof_needed": ""}]
    }))

    def counting_chat(system, user, temperature=None):
        counting_chat.calls += 1
        return client._resp
    counting_chat.calls = 0

    c = CriticAgent(FakeModelClient(""))
    c.model.chat = counting_chat
    f = _finding(tool="analysis", confidence=90)
    c.review_batch([f], _web_map())
    assert counting_chat.calls == 0, "never pay the LLM to bless un-evidenced claims"
    assert f.verdict == "NEEDS_PROOF"

# ── evidence QUALITY gate (artifact vs LLM narration) ──────────────────────
# The certifiedhacker.com run confirmed prose: the evidence gate previously
# accepted any >=MIN_EVIDENCE_LEN string, so LLM-authored sentences like
# "Missing security headers: strict-transport-security, ..." counted as
# evidence. Real evidence is a tool artifact: an HTTP response, structured
# JSON, a quoted payload, a status row, a [tool]-backed chain line. LLM
# narration of what the tool "found" is not evidence.

from agents.critic_agent import _substantive_excerpt

PROSE_EXCERPTS = [
    "Missing security headers: strict-transport-security, content-security-policy, x-content-type-options, x-frame-options, referrer-policy, permissions-policy.",
    "TLS vulnerabilities detected: heartbleed, CCS, ticketbleed, opossum, ROBOT, secure_renego, secure_client_renego, CRIME_TLS.",
    "Authentication paths identified: /admin.php, /login, /admin.html.",
    "Missing security headers: content-security-policy, x-content-type-options, x-frame-options, referrer-policy, permissions-policy.",
    "Weak cipher suites detected.",
]

ARTIFACT_EXCERPTS = [
    "HTTP/2 200\ndate: Fri, 25 Sep 2026 05:17:36 GMT\nserver: nginx/1.29.8\ncontent-type: text/html",
    '{"status": 200, "url": "https://t.com/login", "set_cookie": "s=abc; Secure; HttpOnly"}',
    "GET /?q=1',` GET /?q=<script>alert(1)</script> -> 200 len 1234 reflected",
    "secp256k1\\x41\\x42 ok",
    "[dalfox] param q reflected: <script>alert(1)</script> -> status 200, matched",
]


def test_all_flipkart_prose_narration_rejected_as_evidence():
    for p in PROSE_EXCERPTS:
        assert _substantive_excerpt(p) is False, f"LLM prose wrongly counted: {p[:40]}"


def test_real_tool_artifacts_accepted_as_evidence():
    for r in ARTIFACT_EXCERPTS:
        assert _substantive_excerpt(r) is True, f"real artifact wrongly rejected: {r[:40]}"


def test_evidence_gate_rejects_confirmed_prose_excerpt_even_when_llm_confirms():
    client = FakeModelClient(json.dumps({
        "reviews": [{"index": 0, "verdict": "CONFIRM", "adjusted_confidence": 95,
                     "critique": "", "false_positive_reasons": [], "proof_needed": ""}]
    }))
    c = CriticAgent(client)
    f = _finding(tool="web_attack", confidence=90)
    f.evidence_chain = []
    f.raw_output_excerpt = PROSE_EXCERPTS[0]
    buckets = c.review_batch([f], _web_map())
    assert f in buckets["needs_proof"]
    assert f not in buckets["confirmed"]
    assert "[EVIDENCE GATE]" in f.description


def test_evidence_gate_keeps_real_artifact_confirm():
    client = FakeModelClient(json.dumps({
        "reviews": [{"index": 0, "verdict": "CONFIRM", "adjusted_confidence": 95,
                     "critique": "", "false_positive_reasons": [], "proof_needed": ""}]
    }))
    c = CriticAgent(client)
    f = _finding(tool="dalfox", confidence=90)
    f.evidence_chain = []
    f.raw_output_excerpt = ARTIFACT_EXCERPTS[4]
    buckets = c.review_batch([f], _web_map())
    assert f in buckets["confirmed"]


# ── deterministic severity calibration ─────────────────────────────────────
# Missing security headers / cookie flags / clickjack / server disclosure were
# venue-adjusted to LOW; fuzzed paths / exposed-login / admin.html artifacts to
# INFO. Real exploitable classes (SQLi, XSS, SSRF, RCE...) are untouched.

def _cal(name, sev):
    return CriticAgent.calibrate_severity(name, sev)


def test_missing_security_headers_capped_to_low():
    assert _cal("Missing Security Headers", "HIGH") == "LOW"
    assert _cal("Missing security header: strict-transport-security", "MEDIUM") == "LOW"


def test_clickjack_and_cookie_flags_capped_to_low():
    assert _cal("Clickjacking possible — missing X-Frame-Options", "MEDIUM") == "LOW"
    assert _cal("Session cookies missing security flags", "MEDIUM") == "LOW"


def test_exposed_auth_paths_capped_to_info():
    assert _cal("Exposed Authentication Endpoints", "MEDIUM") == "INFO"
    assert _cal("Admin panel exposed", "MEDIUM") == "INFO"
    assert _cal("Fuzzed path: /admin.html", "INFO") == "INFO"


def test_real_exploits_untouched():
    assert _cal("SQL Injection", "CRITICAL") == "CRITICAL"
    assert _cal("Reflected XSS", "HIGH") == "HIGH"
    assert _cal("Server-Side Request Forgery", "HIGH") == "HIGH"
    assert _cal("Remote Code Execution", "CRITICAL") == "CRITICAL"
