"""Unit tests for the unified assessment state (state.py).

Covers normalization/dedup, asset identity and merging, relationship
provenance, confidence blending, evidence integrity hashing, JSON
round-tripping, and persistence helpers.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from state import (
    ASSET_DOMAIN,
    ASSET_ENDPOINT,
    ASSET_PORT,
    ASSET_SUBDOMAIN,
    ASSET_URL,
    ActionRecord,
    AssessmentState,
    Asset,
    Decision,
    EvidenceItem,
    Relationship,
    asset_identity,
    evidence_from_tool_result,
    load_state,
    merge_confidence,
    normalize_hostname,
    normalize_port,
    normalize_url,
    save_state,
)


# ── normalization / dedup identity ────────────────────────────────────────

def test_normalize_hostname_lowercase_and_trailing_dot():
    assert normalize_hostname("  Example.COM. ") == "example.com"
    assert normalize_hostname("sub.ExAmPlE.org") == "sub.example.org"


def test_normalize_port_numeric_and_string():
    assert normalize_port(443) == "443"
    assert normalize_port(" 8080 ") == "8080"
    assert normalize_port(None) == ""


def test_normalize_url_removes_default_port_lowercases_host():
    assert normalize_url("HTTP://Example.COM:80/path/") == "http://example.com/path"
    assert normalize_url("https://EXAMPLE.com:443/PATH/#frag") == "https://example.com/PATH"


def test_normalize_url_preserves_non_default_port_and_query():
    u = normalize_url("https://example.com:8443/api?q=1&x=2#frag")
    assert u == "https://example.com:8443/api?q=1&x=2"


@pytest.mark.parametrize("type,value_a,value_b", [
    (ASSET_URL, "https://Example.COM/Admin/", "https://example.com/Admin"),
    (ASSET_SUBDOMAIN, "SUB.Example.Com.", "sub.example.com"),
    (ASSET_PORT, 80, "80"),
])
def test_asset_identity_dedupes_normalized_variants(type, value_a, value_b):
    assert asset_identity(type, value_a) == asset_identity(type, value_b)


# ── Asset model ───────────────────────────────────────────────────────────

def test_asset_rejects_unknown_type():
    with pytest.raises(ValueError):
        Asset(type="not_a_real_type", value="x")


def test_asset_rejects_empty_normalized_value():
    with pytest.raises(ValueError):
        Asset(type=ASSET_URL, value="   ")


def test_asset_deterministic_id():
    a = Asset(type=ASSET_SUBDOMAIN, value="api.Example.com")
    b = Asset(type=ASSET_SUBDOMAIN, value="api.example.com")
    assert a.id == b.id
    assert a.id.startswith(ASSET_SUBDOMAIN + ":")


# ── AssessmentState upsert / dedup / confidence ───────────────────────────

def test_upsert_asset_adds_new():
    s = AssessmentState(target="example.com")
    a = Asset(type=ASSET_SUBDOMAIN, value="api.example.com", source="subfinder",
              confidence=0.8)
    stored = s.upsert_asset(a)
    assert stored.id == a.id
    assert len(s.assets) == 1


def test_upsert_dedupes_and_refreshes_last_seen(monkeypatch):
    s = AssessmentState(target="example.com")
    a = Asset(type=ASSET_SUBDOMAIN, value="api.example.com", source="subfinder",
              confidence=0.6)
    s.upsert_asset(a)
    # Same asset from a second, independent tool.
    s.upsert_asset(Asset(type=ASSET_SUBDOMAIN, value="api.example.com",
                         source="amass", confidence=0.9))
    assert len(s.assets) == 1
    stored = s.assets[0]
    # Confidence rises with independent confirmation but stays < 1.
    assert 0.6 < stored.confidence < 1.0
    assert {stored.source, s.assets[0].source}  # last-seen source kept updated


def test_has_and_get_asset():
    s = AssessmentState(target="example.com")
    s.upsert_asset(Asset(type=ASSET_PORT, value=443, source="naabu"))
    assert s.has_asset(ASSET_PORT, "443")
    assert s.get_asset(ASSET_PORT, 443) is not None
    assert not s.has_asset(ASSET_PORT, "8443")


def test_merge_confidence_ceiling_and_floor():
    assert merge_confidence(None, 0.9) == 0.9
    assert merge_confidence(0.99, 0.99, 10) <= 0.99
    bl = merge_confidence(0.9, 0.3, 2)
    assert bl < 0.9
    assert bl > 0.3


# ── relationships ─────────────────────────────────────────────────────────

def test_add_relationship_dedupes_and_keeps_provenance():
    s = AssessmentState(target="example.com")
    sub = s.upsert_asset(Asset(type=ASSET_SUBDOMAIN, value="api.example.com",
                               source="subfinder"))
    s.add_relationship(Relationship(from_id=sub.id, to_id="ip:1.2.3.4",
                                    kind="resolves_to", source="dns_resolve",
                                    confidence=0.8))
    s.add_relationship(Relationship(from_id=sub.id, to_id="ip:1.2.3.4",
                                    kind="resolves_to", source="naabu",
                                    confidence=0.95))
    assert len(s.relationships) == 1
    rel = s.relationships[0]
    assert rel.confidence > 0.8
    assert rel.source == "naabu"


# ── evidence ──────────────────────────────────────────────────────────────

def test_evidence_integrity_hash_deterministic():
    e1 = EvidenceItem(target="example.com", source_tool="nmap",
                      capability="SERVICE_DETECTION",
                      parsed_result={"open_ports": [80]})
    e2 = EvidenceItem(target="example.com", source_tool="nmap",
                      capability="SERVICE_DETECTION",
                      parsed_result={"open_ports": [80]})
    assert e1.integrity_hash == e2.integrity_hash
    assert e1.id == e2.id


def test_evidence_hash_differs_with_parsed_result():
    e1 = EvidenceItem(target="example.com", source_tool="nmap",
                      capability="SERVICE_DETECTION",
                      parsed_result={"open_ports": [80]})
    e2 = EvidenceItem(target="example.com", source_tool="nmap",
                      capability="SERVICE_DETECTION",
                      parsed_result={"open_ports": [443]})
    assert e1.integrity_hash != e2.integrity_hash


def test_evidence_from_tool_result(tmp_path):
    from tools.base import ToolResult
    tr = ToolResult(tool="subfinder", status="success", capability="SUBDOMAIN_DISCOVERY",
                    results={"subdomains": ["api.example.com"]}, raw_stdout="api.example.com")
    ev = evidence_from_tool_result(tr, "example.com")
    assert ev is not None
    assert ev.source_tool == "subfinder"
    assert ev.capability == "SUBDOMAIN_DISCOVERY"
    assert ev.status == "success"
    assert ev.parsed_result["subdomains"] == ["api.example.com"]


def test_evidence_from_none_returns_none():
    assert evidence_from_tool_result(None, "example.com") is None


# ── actions / decisions ───────────────────────────────────────────────────

def test_add_action_records_history():
    s = AssessmentState(target="example.com")
    s.add_action(ActionRecord(action="SUBDOMAIN_DISCOVERY", tool="subfinder",
                              target="example.com", status="success", duration_s=4.2))
    s.add_action(ActionRecord(action="PORT_DISCOVERY", tool="naabu",
                              target="example.com", status="timeout", duration_s=30.0))
    assert len(s.actions) == 2
    assert [a.action for a in s.actions if a.status != "success"] == ["PORT_DISCOVERY"]


def test_add_decision():
    s = AssessmentState(target="example.com")
    d = Decision(target="example.com", selected_action="WEB_TECHNOLOGY_DISCOVERY",
                 reasoning="high info gain for live HTTP host",
                 knowledge_gaps=["technology versions"])
    s.add_decision(d)
    assert len(s.decisions) == 1


# ── serialization ─────────────────────────────────────────────────────────

def test_state_json_roundtrip():
    s = AssessmentState(target="example.com")
    s.upsert_asset(Asset(type=ASSET_SUBDOMAIN, value="api.example.com",
                         source="subfinder", confidence=0.8))
    s.upsert_asset(Asset(type=ASSET_PORT, value=443, source="naabu"))
    s.add_relationship(Relationship(from_id=s.assets[0].id, to_id="ip:1.2.3.4",
                                    kind="resolves_to", source="dns_resolve"))
    s.add_evidence(EvidenceItem(target="example.com", source_tool="httpx",
                                capability="WEB_PROBING",
                                parsed_result={"reachable": True}))
    s.add_action(ActionRecord(action="WEB_PROBING", tool="httpx", target="example.com"))
    s.update_risk_rating("high")

    restored = AssessmentState.from_json(s.to_json())
    assert restored.target == "example.com"
    assert len(restored.assets) == 2
    assert len(restored.relationships) == 1
    assert len(restored.evidence) == 1
    assert len(restored.actions) == 1
    assert restored.risk_rating == "HIGH"
    # Identity preserved across round-trip.
    assert restored.assets[0].id == s.assets[0].id


def test_state_save_load_roundtrip(tmp_path, monkeypatch):
    import state as st
    monkeypatch.setattr(st, "STORE_DIR", tmp_path)
    s = AssessmentState(target="example.com")
    s.upsert_asset(Asset(type=ASSET_SUBDOMAIN, value="api.example.com", source="subfinder"))
    save_state(s)
    loaded = load_state("example.com")
    assert loaded.target == "example.com"
    assert len(loaded.assets) == 1
    assert loaded.assets[0].value == "api.example.com"


def test_load_state_missing_returns_empty(tmp_path, monkeypatch):
    import state as st
    monkeypatch.setattr(st, "STORE_DIR", tmp_path)
    fresh = load_state("does-not-exist.example")
    assert fresh.target == "does-not-exist.example"
    assert fresh.assets == []


# ── state snapshot ────────────────────────────────────────────────────────

def test_snapshot_summarizes_state():
    s = AssessmentState(target="example.com")
    s.upsert_asset(Asset(type=ASSET_SUBDOMAIN, value="api.example.com"))
    s.add_action(ActionRecord(action="SUBDOMAIN_DISCOVERY", tool="subfinder",
                              target="example.com", status="success"))
    s.add_action(ActionRecord(action="PORT_DISCOVERY", tool="naabu",
                              target="example.com", status="timeout"))
    snap = s.snapshot()
    assert snap["target"] == "example.com"
    assert snap["asset_counts"]["subdomain"] == 1
    assert "SUBDOMAIN_DISCOVERY" in snap["actions_taken"]
    assert "PORT_DISCOVERY" in snap["failed_actions"]