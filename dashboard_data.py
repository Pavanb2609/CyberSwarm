"""
dashboard_data.py — read-only aggregation layer for the CyberSwarm
dashboard (spec §20).

Every function here only READS from stores that already exist: state.py's
AssessmentState, decision_trace.py, tool_manager.py's persisted tool
memory, approval_gate.py's + run_agent_loop.py's decision logs, and
system_map.py. Nothing in this module executes a tool, calls a model, or
writes anything back -- the dashboard must never be able to interfere
with an in-progress assessment ("do not let dashboard development
interfere with the core framework").

build_snapshot(target) returns one JSON-safe dict covering everything
spec §20 asks for: assets, agents, current/completed/failed actions,
confidence, findings, evidence, approval history, decision timeline, and
a system-map summary.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import approval_gate
import attack_evidence_store
import confidence as confidence_mod
import decision_trace
import evidence_store
import state as state_mod
import system_map as sm
import tool_manager as tool_manager_mod
from agents.registry import AGENT_REGISTRY
from cvss import enrich_findings, effective_severity
from attack_chains import detect_chains


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _newest_targets_in(store_dir: Path, seen: Dict[str, float]) -> None:
    if not store_dir.exists():
        return
    for path in store_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        target = data.get("target")
        if target:
            seen[target] = max(seen.get(target, 0.0), path.stat().st_mtime)


def list_targets() -> List[str]:
    """Every target we have any record of, newest activity first.

    state.py (results/state/) is the preferred, richest source, but a
    target run through the older recon/attack loops before state.py
    existed only has evidence_store/attack_evidence_store files -- those
    are included too so historical runs aren't invisible in the picker."""
    seen: Dict[str, float] = {}
    _newest_targets_in(state_mod.STORE_DIR, seen)
    _newest_targets_in(evidence_store.STORE_DIR, seen)
    _newest_targets_in(attack_evidence_store.STORE_DIR, seen)
    return [t for t, _ in sorted(seen.items(), key=lambda kv: kv[1], reverse=True)]


def _has_state_file(target: str) -> bool:
    return state_mod._safe_path(target).exists()


def _legacy_fallback(target: str) -> Dict[str, Any]:
    """For a target that predates state.py: pull what we can out of the
    old evidence_store / attack_evidence_store dicts so it isn't shown as
    completely empty just because it was run before the Controller/state
    pipeline existed."""
    ev = evidence_store.load(target, warn_on_regression=False)
    attack_ev = attack_evidence_store.load(target, recon_evidence=ev)

    assets_by_type: Dict[str, List[Dict[str, Any]]] = {}

    def _add(asset_type: str, values: List[str]) -> None:
        if not values:
            return
        assets_by_type[asset_type] = [
            {"value": v, "confidence": None, "source": "legacy evidence_store", "last_seen": None}
            for v in values
        ]

    _add("subdomain", ev.get("subdomains", []))
    _add("port", [str(p) for p in ev.get("open_ports", [])])
    _add("technology", ev.get("technologies", []))
    _add("url", ev.get("discovered_urls", []))

    def _action(name: str, status: str) -> Dict[str, Any]:
        return {"action": name, "tool": "(legacy)", "target": target, "timestamp": "",
                "status": status, "duration_s": 0.0, "output_quality": 0.5, "cost": 0.0}

    completed = [_action(a, "success") for a in ev.get("completed_actions", [])]
    completed += [_action(a, "success") for a in attack_ev.get("attack_actions_completed", [])]
    failed = [_action(a, "error") for a in ev.get("failed_actions", [])]
    failed += [_action(a, "error") for a in attack_ev.get("attack_actions_failed", [])]

    return {
        "assets": assets_by_type,
        "completed_actions": completed,
        "failed_actions": failed,
        "findings": attack_ev.get("vulnerabilities", []),
        "risk_rating": attack_ev.get("risk_rating", "UNKNOWN"),
    }


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _approval_history(target: str) -> List[Dict[str, Any]]:
    """Every logged human-approval decision for this target, recon + attack
    phase combined, newest first.

    approval_gate.review() / run_agent_loop.human_approval_gate() are both
    synchronous -- they block on stdin at the moment a decision needs a
    human -- so there is no "pending" queue anywhere in the codebase to
    surface here. This is a history of what was asked and how it was
    resolved, not a live inbox. A true pending-request panel would need a
    non-blocking approval mechanism (e.g. a queue the CLI polls instead of
    calling input() directly), which is a bigger architectural change than
    the dashboard itself.
    """
    entries = []
    for entry in _read_jsonl(approval_gate.LOG_PATH):
        if entry.get("target") == target:
            entries.append({**entry, "phase": "recon"})
    try:
        import run_agent_loop
        for entry in _read_jsonl(run_agent_loop.LOG_PATH):
            if entry.get("target") == target:
                entries.append({**entry, "phase": "attack"})
    except ImportError:
        pass
    entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return entries


def _agent_status(st: state_mod.AssessmentState) -> List[Dict[str, Any]]:
    """Best-effort role labeling, not a live process list. CyberSwarm's
    agents run to completion synchronously within one Controller step --
    there is no persistent agent process to poll for "current" status, so
    this reflects what the recorded decisions/actions imply has run."""
    roles = [
        {"name": "Controller", "role": "orchestrator", "status": "active" if st.actions else "idle"},
        {"name": "Planner", "role": "action selection", "status": "active" if st.decisions else "idle"},
        {"name": "Critic", "role": "validator",
         "status": "active" if any(d.critic_verdict for d in st.decisions) else "idle"},
        {"name": "Intelligence", "role": "CVE / EPSS / KEV enrichment",
         "status": "active" if any("intel" in (f.get("source") or "").lower() for f in st.findings) else "idle"},
    ]
    seen = set()
    for d in st.decisions:
        cap = (d.selected_action or "").lower()
        for name in AGENT_REGISTRY:
            if name in cap:
                seen.add(name)
    for name in sorted(seen):
        roles.append({"name": name, "role": "specialist agent", "status": "ran"})
    return roles


def _confidence_breakdown(st: state_mod.AssessmentState) -> Dict[str, Any]:
    if not st.assets:
        return {"average": None, "by_label": {}}
    counts: Dict[str, int] = {}
    for a in st.assets:
        label = confidence_mod.confidence_label(a.confidence)
        counts[label] = counts.get(label, 0) + 1
    avg = round(sum(a.confidence for a in st.assets) / len(st.assets), 3)
    return {"average": avg, "by_label": counts}


def build_snapshot(target: str, memory_path: Optional[Path] = None) -> Dict[str, Any]:
    """Everything the dashboard needs for one target, in one JSON-safe dict."""
    has_state = _has_state_file(target)
    st = state_mod.load_state(target)
    trace = decision_trace.DecisionTrace.from_state(st)
    smap = sm.load_map(target)
    tm = tool_manager_mod.ToolManager(memory_path=memory_path) if memory_path else tool_manager_mod.ToolManager()

    assets_by_type: Dict[str, List[Dict[str, Any]]] = {}
    for a in st.assets:
        assets_by_type.setdefault(a.type, []).append({
            "value": a.value, "confidence": round(a.confidence, 3),
            "source": a.source, "last_seen": a.last_seen,
        })
    for bucket in assets_by_type.values():
        bucket.sort(key=lambda x: x["last_seen"], reverse=True)

    completed = [a.to_dict() for a in st.actions if a.status == "success"]
    failed = [a.to_dict() for a in st.actions if a.status != "success"]
    findings = st.findings
    risk_rating = st.risk_rating

    # A target run before state.py existed (recon/attack loops only) has no
    # results/state/<target>.json at all -- fall back to the legacy stores
    # rather than showing it as empty just because it predates this schema.
    data_source = "state_graph"
    if not has_state:
        legacy = _legacy_fallback(target)
        if legacy["assets"] or legacy["completed_actions"] or legacy["findings"]:
            data_source = "legacy"
            assets_by_type = legacy["assets"]
            completed = legacy["completed_actions"]
            failed = legacy["failed_actions"]
            findings = legacy["findings"]
            risk_rating = legacy["risk_rating"]

    # Enrich (idempotent -- a finding already scored at ingestion time is
    # left untouched) so older persisted findings from before cvss.py
    # existed still get finding_type/cvss_* on the way out, and so
    # detect_chains() below always has finding_type to key on.
    findings = enrich_findings(findings)
    chains = [c.to_dict() for c in detect_chains(findings)]

    return {
        "target": target,
        "generated_at": _now(),
        "data_source": data_source,
        "risk_rating": risk_rating,
        "state_updated": st.updated,
        "assets": assets_by_type,
        "asset_counts": {k: len(v) for k, v in assets_by_type.items()},
        "relationships": [r.to_dict() for r in st.relationships],
        "agents": _agent_status(st),
        "current_action": (completed + failed)[-1] if (completed + failed) and data_source == "legacy"
                          else (st.actions[-1].to_dict() if st.actions else None),
        "completed_actions": completed,
        "failed_actions": failed,
        "confidence": _confidence_breakdown(st),
        "findings": findings,
        "attack_chains": chains,
        "evidence_count": len(st.evidence),
        "evidence_sample": [e.to_dict() for e in st.evidence[-20:]],
        "approval_history": _approval_history(target),
        "decision_timeline": trace.selections(),
        "open_knowledge_gaps": trace.open_gaps(),
        "tool_reliability": tm.all_tool_stats(),
        "system_map_summary": {
            "web_surfaces": len(smap.get("web_surfaces", [])),
            "technologies": len(smap.get("technologies", [])),
            "endpoints": len(smap.get("endpoints", [])),
            "links": len(smap.get("links", [])),
            "signals": smap.get("signals", {}),
        },
    }
