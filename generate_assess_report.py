#!/usr/bin/env python3
"""
generate_assess_report.py — assessment report for the evidence-driven flow.

Reads the unified MemoryStore + decision trace for one target and renders a
markdown report covering: target profile (assets), evidence & confidence,
capability coverage, the decision trace, tool reliability, and findings
(risk-rated, deduplicated).

Usage:
    python generate_assess_report.py example.com
    python generate_assess_report.py example.com --out report.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from confidence import ConfidenceEngine
from decision_trace import DecisionTrace
from memory_store import MemoryStore
from tool_manager import ToolManager
from utils import ROOT, finding_key, severity_rank
from cvss import enrich_findings, effective_severity
from attack_chains import detect_chains

REPORT_DIR = ROOT / "results" / "reports"

SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534", "HIGH": "\U0001f7e0", "MEDIUM": "\U0001f7e1",
    "LOW": "\U0001f535", "INFO": "\u26aa", "UNKNOWN": "\u26ab",
}


def build_report(target: str) -> Dict[str, Any]:
    """Assemble the full report payload for a target."""
    store = MemoryStore(target, tool_manager=ToolManager())
    st = store.load()
    overview = store.overview(st)
    coverage = store.coverage_map(st)
    surface = store.surface_hints(st)
    trace = DecisionTrace.load(target)

    findings: Dict[str, Any] = {}
    for f in st.findings:
        key = finding_key(f)
        findings[key] = f
    mem = store.attack_memory()
    for f in (mem.get("vulnerabilities", []) or []):
        key = finding_key(f)
        if key not in findings or severity_rank(f.get("severity", "UNKNOWN")) > \
                severity_rank(findings[key].get("severity", "UNKNOWN")):
            findings[key] = f

    conf = ConfidenceEngine(tool_manager=store.tool_manager)
    enriched = enrich_findings(list(findings.values()))  # adds finding_type + cvss_vector/score/severity
    ordered = sorted(enriched, key=lambda f: severity_rank(effective_severity(f)), reverse=True)
    scored = []
    for f in ordered:
        base = conf.adjusted_confidence(
            conf.base_confidence(str(f.get("name", "finding"))))
        scored.append({**f, "_verdict": conf.decided_verdict(base)})

    chains = detect_chains(ordered)  # cross-finding correlation; advisory, never auto-confirmed

    # Data quality: which actions failed, so a reader can tell "genuinely
    # nothing found" apart from "the tool failed to run". Note: ActionRecord
    # only carries a status code, not an error message (unlike the older
    # evidence_store.py's failure_patterns dict) -- so unlike the legacy
    # report, this can only say WHICH actions failed, not WHY. Closing that
    # gap would mean adding an error field to ActionRecord and threading
    # ToolResult.error through absorb_tool_result() -- a real, separate
    # follow-up, not attempted here.
    failed_actions = [{"action": a.action, "tool": a.tool, "status": a.status}
                      for a in st.actions if a.status != "success"]

    return {
        "target": target,
        "overview": overview,
        "assets_by_type": st.snapshot().get("assets_by_type", {}),
        "asset_counts": st.snapshot().get("asset_counts", {}),
        "evidence_count": st.snapshot().get("evidence_count", 0),
        "actions": st.snapshot().get("actions_taken", []),
        "failed_actions": failed_actions,
        "coverage": coverage,
        "surface": surface,
        "risk_rating": overview.get("risk_rating", st.risk_rating),
        "tool_reliability": overview.get("tool_reliability", {}),
        "decisions": trace.summary(),
        "findings": scored,
        "attack_chains": [c.to_dict() for c in chains],
    }


def render_markdown(data: Dict[str, Any]) -> str:
    t = data["target"]
    L: List[str] = [f"# Assessment Report — {t}", ""]

    risk = data["risk_rating"] or "UNKNOWN"
    L.append(f"**Risk rating:** {SEVERITY_EMOJI.get(risk, '')} {risk}")
    L.append(f"**Evidence items:** {data['evidence_count']} | "
             f"**Findings:** {len(data['findings'])} | "
             f"**Actions:** {len(data['actions'])}")
    L.append("")

    failed = data.get("failed_actions", [])
    if failed:
        L.append(f"## ⚠️ Data Quality — {len(failed)} action(s) did not succeed")
        L.append("_Results above may be incomplete because of this, not because the target "
                 "genuinely has none of these findings. (Only the failure status is available "
                 "here, not the underlying error -- see the legacy attack report for detailed "
                 "error text on a shared target.)_")
        for a in failed:
            L.append(f"- **{a['action']}** ({a['tool']}) — {a['status']}")
        L.append("")

    counts = data.get("asset_counts", {}) or {}
    if counts:
        L.append("## Target profile")
        for atype, total in sorted(counts.items()):
            L.append(f"- **{atype}**: {total}")
        L.append("")

    surf = data.get("surface", {}) or {}
    if surf:
        L.append("## Surface hints")
        L.append(", ".join(f"{k}={v}" for k, v in sorted(surf.items())))
        L.append("")

    cov = data.get("coverage", {}) or {}
    if cov:
        covered = sum(1 for v in cov.values() if v > 0)
        L.append(f"## Coverage ({covered}/{len(cov)} capabilities explored)")
        for cap in sorted(cov, key=lambda c: -cov[c])[:15]:
            L.append(f"- {cap}: {cov[cap]}")
        L.append("")

    rel = data.get("tool_reliability", {}) or {}
    if rel:
        L.append("## Tool reliability")
        for name in sorted(rel):
            L.append(f"- {name}: {rel[name]}")
        L.append("")

    tr = data.get("decisions", {}) or {}
    if tr.get("steps"):
        L.append(f"## Decision trace ({tr['steps']} steps)")
        for i, step in enumerate(tr.get("plan", [])):
            L.append(f"{i}. {step['selected_action']} "
                     f"(tool={step.get('selected_tool') or '—'}, "
                     f"status={step.get('result_status') or '—'})")
        L.append(f"\nOpen gaps: {', '.join(tr.get('open_gaps', [])) or 'none'}")
        L.append("")

    findings = data.get("findings", [])
    L.append("## Findings" + ("" if findings else " (none recorded)"))
    for f in findings:
        sev = effective_severity(f)
        raw_sev = str(f.get("severity", "UNKNOWN")).upper()
        cvss_note = ""
        if f.get("cvss_score") is not None:
            src_note = "" if f.get("cvss_source") == "finding_type_default" else " *(from tool severity label, not a scored CVSS assessment)*"
            cvss_note = f" — CVSS {f['cvss_score']} ({f.get('cvss_severity', sev)}){src_note}"
        sev_note = f" _(tool reported: {raw_sev})_" if raw_sev != sev else ""
        L.append(f"- [{SEVERITY_EMOJI.get(sev, '')} {sev}] {f.get('name', '?')} "
                 f"({f.get('url', '')}) — {f.get('_verdict', '')}{cvss_note}{sev_note}")
    L.append("")

    chains = data.get("attack_chains", [])
    if chains:
        L.append(f"## Cross-Finding Attack Chains ({len(chains)}) \u26a0\ufe0f requires manual verification")
        L.append("_These correlate two or more individually-lower-severity findings into a higher-impact "
                 "scenario using documented attack patterns. They are hypotheses for a reviewer to verify, "
                 "not confirmed exploitation._")
        L.append("")
        for c in chains:
            L.append(f"### {c['name']} — {c['host']}")
            L.append(c["description"])
            if c.get("cvss_score") is not None:
                L.append(f"\n**Assessed impact if verified:** CVSS {c['cvss_score']} ({c['cvss_severity']})")
            contributors = ", ".join(f"{cf['name']} ({cf['finding_type']})" for cf in c.get("contributing_findings", []))
            L.append(f"\n**Contributing findings:** {contributors}")
            L.append("")
    return "\n".join(L)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="cyberswarm report-assess",
                                description="Render an assessment report from the "
                                            "unified evidence/state store")
    p.add_argument("target")
    p.add_argument("--out", default="", help="output path (default: results/reports/<target>.md)")
    args = p.parse_args(argv)

    data = build_report(args.target)
    md = render_markdown(data)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = Path(args.out) if args.out else REPORT_DIR / f"{args.target}.md"
    out.write_text(md, encoding="utf-8")
    (out.with_suffix(".json")).write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    print(md)
    print(f"\n[report-assess] wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())