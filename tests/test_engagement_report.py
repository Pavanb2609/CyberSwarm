"""Tests for the folder-wise engagement report generator
(engagement_report.py).

The generator must emit per-confirmed-vulnerability folders and, when no
vulnerability is confirmed, a PROOF_OF_TESTING deliverable that records the
testing that actually ran.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import engagement_report as er


@pytest.fixture
def stores(monkeypatch, tmp_path):
    atk = tmp_path / "attack_evidence"
    rec = tmp_path / "evidence"
    shots = tmp_path / "screenshots"
    out = tmp_path / "engagements"
    for p in (atk, rec, shots, out):
        p.mkdir(parents=True, exist_ok=True)
    attack = tmp_path / "attack_decision_log.jsonl"
    recon_log = tmp_path / "decision_log.jsonl"
    attack.write_text("", encoding="utf-8")
    recon_log.write_text("", encoding="utf-8")

    monkeypatch.setattr(er, "ATTACK_EVIDENCE_DIR", atk)
    monkeypatch.setattr(er, "RECON_EVIDENCE_DIR", rec)
    monkeypatch.setattr(er, "SCREENSHOT_DIR", shots)
    monkeypatch.setattr(er, "OUT_ROOT", out)
    monkeypatch.setattr(er, "ATTACK_LOG", attack)
    monkeypatch.setattr(er, "RECON_LOG", recon_log)
    monkeypatch.setattr(er, "SYSTEM_MAP_DIR", tmp_path / "system_map")

    def write_attack(evidence: dict):
        (atk / "app.test.json").write_text(json.dumps(evidence), encoding="utf-8")

    def write_recon(evidence: dict):
        (rec / "app.test.json").write_text(json.dumps(evidence), encoding="utf-8")

    def write_log(path: Path, rows: list):
        path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    return dict(tmp=tmp_path, out=out, write_attack=write_attack,
                write_recon=write_recon, write_log=write_log)


def _base_attack():
    return {
        "target": "app.test",
        "risk_rating": "LOW",
        "agent_runs": [],
        "completed_agents": [],
        "vulnerabilities": [],
        "disputed_findings": [],
        "proof_requests": [],
    }


def _recon_done():
    return {
        "target": "app.test", "authorized_scope": True, "target_type": "domain",
        "resolved_ip": "10.0.0.2", "reachable": True,
        "completed_actions": ["PORT_DISCOVERY", "WEB_PROBING"],
        "zero_findings_actions": ["PORT_DISCOVERY"],
        "failed_actions": [],
        "subdomains": ["api.app.test"],
        "open_ports": [],
        "services": [],
        "technologies": ["nginx"],
    }


# ── vulnerability case: one folder per confirmed finding ────────────────────

def test_confirmed_finding_gets_vulnerability_folder(stores):
    atk = _base_attack()
    atk["vulnerabilities"] = [{
        "name": "Missing X-Content-Type-Options header",
        "severity": "LOW", "confidence": 71, "final_confidence": 88,
        "independent_sources": 2, "false_positive_risk": 0.1,
        "tool": "headerex", "url": "https://app.test/",
        "description": "Header absent on responses.",
        "evidence_chain": ['[headerex] GET / -> 200, header "x-content-type-options" absent'],
        "raw_output_excerpt": "HTTP/1.1 200 OK ... x-content-type-options: MISSING",
    }]
    stores["write_attack"](atk)
    stores["write_recon"](_recon_done())

    er.build("app.test")
    vuln_dir = stores["out"] / "app.test" / "vulnerabilities"
    folders = sorted(p.name for p in vuln_dir.iterdir() if p.is_dir())
    assert len(folders) == 1, folders
    assert folders[0].startswith("01__LOW__missing-x-content-type-options-header")
    finding = (vuln_dir / folders[0] / "finding.md").read_text(encoding="utf-8")
    assert "[headerex] GET /" in finding
    assert "x-content-type-options: MISSING" in finding
    meta = json.loads((vuln_dir / folders[0] / "meta.json").read_text(encoding="utf-8"))
    assert meta["severity"] == "LOW"
    assert meta["final_confidence"] == 88


# ── no-vulnerability case: auditable proof of testing ───────────────────────

def test_no_vulnerability_writes_proof_of_testing(stores):
    stores["write_attack"](_base_attack())
    stores["write_recon"](_recon_done())
    stores["write_log"](stores["tmp"] / "attack_decision_log.jsonl", [
        {"target": "app.test", "event": "attack_graph"},
        {"target": "app.test", "agent": "web_attack"},
    ])

    er.build("app.test")
    out = stores["out"] / "app.test"
    proof = out / "proof_of_testing" / "PROOF_OF_TESTING.md"
    assert proof.exists()
    md = proof.read_text(encoding="utf-8")
    assert "No vulnerabilities were confirmed" in md
    assert "PORT_DISCOVERY" in md          # tool matrix shows what ran
    assert "WEB_PROBING" in md
    assert "subdomains" in md              # recon evidence recorded
    assert "attack_graph" in md            # decision log timeline included
    assert not (out / "vulnerabilities").exists() or \
        not any((out / "vulnerabilities").iterdir())
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["confirmed_vulnerabilities"] == 0
    assert "integrity" in summary


# ── fallback: confirmed finding nested in agent_runs ─────────────────────────

def test_confirmed_finding_via_agent_runs_fallback(stores):
    atk = _base_attack()
    atk["agent_runs"] = [{
        "agent": "infra", "status": "success", "duration_s": 12.3,
        "tools_run": ["testssl"], "reasoning": None,
        "findings": [{
            "status": "confirmed", "name": "Weak TLS cipher suite",
            "severity": "MEDIUM", "tool": "testssl",
            "description": "DES-CBC3-SHA offered.",
            "evidence_chain": ["[testssl] cipher DES-CBC3-SHA accepted by server"],
        }],
    }]
    stores["write_attack"](atk)
    er.build("app.test")
    vuln_dir = stores["out"] / "app.test" / "vulnerabilities"
    folders = list(p.name for p in vuln_dir.iterdir() if p.is_dir())
    assert folders and folders[0].startswith("01__MEDIUM__weak-tls-cipher-suite")