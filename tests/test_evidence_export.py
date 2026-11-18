"""Tests for the evidence-backed export (export_to_evidence_manager.py).

The export is CONFIRM-only by default and re-attaches the full-fidelity
evidence (evidence_chain / raw_output_excerpt / final_confidence) that the
top-level `vulnerabilities` list drops on persist. It must degrade to the
self-contained local deliverable when the external evidence_manager package
is absent (which it is on this machine).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from export_to_evidence_manager import (  # noqa: E402
    _evidence_items,
    render_markdown,
    select_evidence_backed,
    write_local_export,
    export_assessment,
)

CONFIRMED = {
    "source_agent": "xss_exploit", "tool": "xss_proof",
    "name": "Reflected XSS proven to execute", "severity": "HIGH",
    "confidence": 93, "url": "http://127.0.0.1:8686/?q=probe", "port": "",
    "description": "Payload executed in a headless browser",
    "evidence_chain": ["[xss_proof] http://.../?q=... -> script executed"],
    "raw_output_excerpt": '{"proven": true, "nonce": "abc"}',
    "final_confidence": 93, "false_positive_risk": "LOW", "verdict": "CONFIRM",
}
NO_EVIDENCE_CONF = {
    "source_agent": "web_attack", "tool": "dalfox",
    "name": "Reflected XSS (Dalfox)", "severity": "HIGH",
    "confidence": 65, "url": "", "port": "",
    "description": "tool ran",
    "evidence_chain": [], "raw_output_excerpt": "{}",
    "final_confidence": 26, "false_positive_risk": "HIGH", "verdict": "DISPUTE",
}


def _evidence_payload():
    return {
        "target": "example.com",
        "risk_rating": "CRITICAL",
        "vulnerabilities": [
            {k: v for k, v in CONFIRMED.items() if k != "evidence_chain"},
            {k: v for k, v in NO_EVIDENCE_CONF.items() if k != "evidence_chain"},
        ],
        "disputed_findings": [
            {k: v for k, v in NO_EVIDENCE_CONF.items() if k != "evidence_chain"},
        ],
        "proof_requests": ["[auth] Exposure of multiple authentication endpoints"],
        "agent_runs": [
            {"agent": "xss_exploit", "findings": [CONFIRMED]},
            {"agent": "web_attack", "findings": [NO_EVIDENCE_CONF]},
        ],
    }


def test_evidence_items_ignore_noise():
    f = {"evidence_chain": ["real output here"], "raw_output_excerpt": "{}"}
    assert _evidence_items(f) == ["real output here"]
    f2 = {"evidence_chain": [], "raw_output_excerpt": "{}"}
    assert _evidence_items(f2) == []


def test_select_confirmed_only_skips_disputed_and_no_proof():
    sel = select_evidence_backed(_evidence_payload())
    assert [e["title"] for e in sel["confirmed"]] == ["Reflected XSS proven to execute"]
    assert sel["unconfirmed"] == []


def test_select_with_unconfirmed_includes_dispute_and_proof_requests():
    sel = select_evidence_backed(_evidence_payload(), include_unconfirmed=True)
    verdicts = sorted(e["verdict"] for e in sel["unconfirmed"])
    assert verdicts == ["DISPUTE", "NEEDS_PROOF"]


def test_confirmed_entries_carry_reattached_evidence():
    sel = select_evidence_backed(_evidence_payload())
    entry = sel["confirmed"][0]
    assert entry["evidence"] == [
        "[xss_proof] http://.../?q=... -> script executed",
        '{"proven": true, "nonce": "abc"}',
    ]
    assert entry["confidence"] == 93
    assert entry["false_positive_risk"] == "LOW"


def test_confirmed_without_evidence_is_flagged_for_manual_review():
    # A CONFIRM that somehow lost its evidence must not silently look proven.
    payload = _evidence_payload()
    payload["vulnerabilities"] = [{
        "source_agent": "intelligence", "tool": "intelligence",
        "name": "Flask", "severity": "HIGH", "confidence": 75, "url": "",
        "description": "CVE", "verdict": "CONFIRM",
        "evidence_chain": [], "raw_output_excerpt": "",
        "final_confidence": 75, "false_positive_risk": "LOW",
    }]
    sel = select_evidence_backed(payload)
    assert sel["confirmed"][0]["evidence"] == []


def test_render_markdown_contains_evidence_blocks():
    sel = select_evidence_backed(_evidence_payload())
    md = render_markdown("ENG-1", "dem", [sel])
    assert "Evidence:" in md
    assert "script executed" in md
    assert "CONFIRM-only" in md


def test_write_local_export_roundtrip(tmp_path):
    sel = select_evidence_backed(_evidence_payload())
    paths = write_local_export("ENG-1", "dem", [sel], root=tmp_path)
    data = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert data["assessment_id"] == "ENG-1"
    assert data["targets"][0]["confirmed"][0]["evidence"]
    assert Path(paths["markdown"]).exists()


def test_export_assessment_falls_back_without_evidence_manager(tmp_path, monkeypatch):
    # evidence_manager is absent on this machine: must not crash, must write
    # the self-contained deliverable, and must say so.
    calls = []
    monkeypatch.setattr("export_to_evidence_manager.DEFAULT_EVIDENCE_DIR",
                        Path(__file__).parent)  # no json files at all
    ev_dir = tmp_path / "ev"
    ev_dir.mkdir()
    (ev_dir / "example.com.json").write_text(
        json.dumps(_evidence_payload()), encoding="utf-8")
    export_assessment(
        evidence_dir=str(ev_dir), assessment_id="ENG-2",
        assessment_name="demo", evidence_manager_path=str(tmp_path / "missing"),
        print_fn=lambda *a: calls.append(a),
    )
    assert any("evidence_manager not found" in c[0] for c in calls)
    from export_to_evidence_manager import LOCAL_REPORT_ROOT
    out = LOCAL_REPORT_ROOT / "ENG-2.md"
    assert out.exists()
    md = out.read_text(encoding="utf-8")
    assert "Reflected XSS proven to execute" in md
    assert "script executed" in md