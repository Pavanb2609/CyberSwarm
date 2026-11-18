"""Integration tests for build_system_map.build_for().

Regression coverage for a bug where derive_attack_surface() was computed
AFTER save_map(), so the persisted SystemMap's "attack_surface" field was
always {} on disk even though the console output showed it correctly.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import build_system_map
import evidence_store
import system_map as sm


def _write_evidence(evidence_dir: Path, target: str, evidence: dict) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    safe = target.replace("/", "_").replace(":", "_")
    (evidence_dir / f"{safe}.json").write_text(json.dumps(evidence), encoding="utf-8")


def test_build_for_persists_attack_surface(tmp_path, monkeypatch):
    evidence_dir = tmp_path / "evidence"
    map_dir = tmp_path / "system_map"
    monkeypatch.setattr(evidence_store, "STORE_DIR", evidence_dir)
    monkeypatch.setattr(sm, "STORE_DIR", map_dir)

    target = "example.com"
    _write_evidence(evidence_dir, target, {
        "target": target,
        "resolved_ip": "93.184.216.34",
        "reachable": True,
        "open_ports": [80, 443],
        "port_details": [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}],
        "technologies": ["nginx"],
        "completed_actions": ["portscan"],
        "discovered_urls": ["https://example.com/api/v1/users"],
    })

    m = build_system_map.build_for(target, verbose=False)

    # In-memory result must be populated (this passed even before the fix).
    assert m["attack_surface"].get("mapped") is True
    assert "web_attack" in m["attack_surface"]["agents"]

    # The bug: the file on disk kept "attack_surface": {} because save_map()
    # ran before derive_attack_surface(). Reload from disk and confirm the
    # persisted copy matches what was computed, not an empty placeholder.
    reloaded = sm.load_map(target)
    assert reloaded["attack_surface"].get("mapped") is True
    assert "web_attack" in reloaded["attack_surface"]["agents"]
    assert reloaded["attack_surface"]["agents"]["api"]["skip"] is False
