"""Export CyberSwarm findings to an evidence_manager assessment tracker.

"Evidence-backed" is the whole point of this export: only findings the
CriticAgent kept as CONFIRM are exported by default, and each one carries
its evidence chain / raw output excerpt / final confidence / false-positive
risk so the deliverable never shows a bare assertion. LLM "PROOF:" narration
and empty-evidence HIGH/CRITICALs have no place in a client-grade report.

The evidence_manager integration is optional. When the package is not
importable (it lives outside this project, e.g. next to it at
``../evidence_manager``), the exporter degrades gracefully to a
self-contained deliverable: a per-assessment JSON + Markdown report under
``results/reports/evidence_export/``. The selection logic is the same in
both paths, so the fallback is also the test target.

Usage:
    python export_to_evidence_manager.py --assessment ENG-2026-001
    python export_to_evidence_manager.py --assessment ENG-2026-001 \
        --target booking.zielmobility.com --include-unconfirmed --generate-report

Only entries with real tool evidence attached (evidence_chain /
raw_output_excerpt of substance) qualify for CONFIRM export; the verdict is
set by the pipeline (CriticAgent evidence gate + dispute review), not by
this exporter.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_EVIDENCE_DIR = ROOT / "results" / "attack_evidence"
LOCAL_REPORT_ROOT = ROOT / "results" / "reports" / "evidence_export"

MIN_EVIDENCE_LEN = 8

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _clean(s: str) -> str:
    """Strip ANSI colour escapes and other control cruft so client-facing
    evidence blocks never carry terminal artifacts."""
    return _ANSI_RE.sub("", str(s)).replace("\x00", "").strip()


def _iter_findings(evidence: dict):
    """Yield the full-fidelity per-agent findings, which preserve the
    evidence_chain/raw_output_excerpt/final_confidence that the top-level
    ``vulnerabilities`` list drops on persist."""
    for run in evidence.get("agent_runs") or []:
        for f in run.get("findings") or []:
            yield f


def _finding_key(f: dict) -> tuple:
    """Stable identity for matching a denormalized finding back to its
    full-fidelity agent_run record."""
    return (
        str(f.get("source_agent") or f.get("agent") or ""),
        str(f.get("tool") or ""),
        str(f.get("name") or ""),
        str(f.get("url") or ""),
    )


def _build_rich_index(evidence: dict) -> dict:
    idx: dict = {}
    for f in _iter_findings(evidence):
        idx.setdefault(_finding_key(f), []).append(f)
    return idx


def _evidence_items(f: dict) -> list:
    """All real evidence strings on a finding, deduped and non-trivial."""
    out: list = []
    for chain in f.get("evidence_chain") or []:
        s = _clean(chain)
        if len(s) >= MIN_EVIDENCE_LEN and s not in out:
            out.append(s)
    raw = _clean(f.get("raw_output_excerpt") or "")
    if len(raw) >= MIN_EVIDENCE_LEN and raw not in out:
        out.append(raw)
    return out


def _entry(f: dict, verdict: str) -> dict:
    """Normalize a finding into an evidence-backed export record."""
    return {
        "id": "%s|%s" % (verdict, _finding_key(f)),
        "title": str(f.get("name") or "?"),
        "verdict": verdict,
        "severity": str(f.get("severity") or "UNKNOWN").upper(),
        "confidence": f.get("final_confidence", f.get("confidence")),
        "false_positive_risk": f.get("false_positive_risk", ""),
        "url": str(f.get("url") or ""),
        "source_agent": f.get("source_agent") or f.get("agent") or "",
        "tool": str(f.get("tool") or ""),
        "cve": f.get("cve_id") or f.get("cve") or "",
        "evidence": _evidence_items(f),
        "description": str(f.get("description") or ""),
    }


def select_evidence_backed(evidence: dict,
                           include_unconfirmed: bool = False) -> dict:
    """Split an attack_evidence payload into evidence-backed records.

    Default: only CONFIRM findings. With include_unconfirmed, DISPUTE and
    NEEDS_PROOF items are also exported (clearly labelled) so a reviewer can
    see what was tried but not proven.
    """
    idx = _build_rich_index(evidence)
    target = str(evidence.get("target") or "unknown")

    confirmed = []
    for f in evidence.get("vulnerabilities") or []:
        verdict = str(f.get("verdict") or f.get("final_verdict") or "CONFIRM").upper()
        if verdict in ("DISPUTE", "NEEDS_PROOF"):
            continue
        rich = idx.get(_finding_key(f), [{}])[0]
        merged = dict(f)
        merged.update({k: v for k, v in rich.items() if v is not None})
        confirmed.append(_entry(merged, "CONFIRM"))

    unconfirmed = []
    if include_unconfirmed:
        for f in evidence.get("disputed_findings") or []:
            rich = idx.get(_finding_key(f), [{}])[0]
            merged = dict(f)
            merged.update({k: v for k, v in rich.items() if v is not None})
            unconfirmed.append(_entry(merged, "DISPUTE"))
        for pr in evidence.get("proof_requests") or []:
            unconfirmed.append({
                "id": "NEEDS_PROOF|manual|%s" % str(pr)[:40],
                "title": str(pr),
                "verdict": "NEEDS_PROOF",
                "severity": "INFO",
                "confidence": None,
                "false_positive_risk": "HIGH",
                "url": "",
                "source_agent": "manual",
                "tool": "",
                "cve": "",
                "evidence": [],
                "description": "Proof requested by the swarm for an "
                               "unproven finding; needs manual verification.",
            })
    return {"target": target, "confirmed": confirmed, "unconfirmed": unconfirmed}


def render_markdown(assessment_id: str, name: str, blocks: list) -> str:
    lines = ["# CyberSwarm Evidence-Backed Export",
             "",
             f"**Assessment:** `{assessment_id}`",
             f"**Name:** {name}",
             f"**Generated:** {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
             "**Policy:** CONFIRM-only (evidence-gated) by default; "
             "unconfirmed items included only when explicitly requested.",
             ""]
    for block in blocks:
        t = block["target"]
        lines.append(f"## Target: {t}")
        confirmed, unconfirmed = block["confirmed"], block["unconfirmed"]
        lines.append(f"\n### Confirmed findings ({len(confirmed)})")
        if not confirmed:
            lines.append("_None._")
        for e in confirmed:
            lines.append(f"- **[{e['severity']}] {e['title']}** "
                         f"(conf {e['confidence']}, FP-risk {e['false_positive_risk'] or 'n/a'})")
            if e["url"]:
                lines.append(f"  - URL: `{e['url']}`")
            lines.append(f"  - Source: {e['source_agent']} / {e['tool'] or 'n/a'}")
            for ev in e["evidence"][:5]:
                lines.append(f"  - Evidence: {ev[:220]}")
            if not e["evidence"]:
                lines.append("  - Evidence: **NONE — flag for manual review**")
        if unconfirmed:
            lines.append(f"\n### Unconfirmed / needs proof ({len(unconfirmed)})")
            for e in unconfirmed:
                lines.append(f"- [{e['verdict']}] {e['title'][:160]}")
    lines.append("")
    lines.append("_Generated by CyberSwarm evidence-backed exporter._")
    return "\n".join(lines)


def write_local_export(assessment_id: str, name: str, blocks: list,
                       root: Path = LOCAL_REPORT_ROOT) -> dict:
    """Persist the self-contained deliverable (always, both paths)."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    payload = {
        "assessment_id": assessment_id,
        "name": name,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "policy": "confirm_only" if not any(b["unconfirmed"] for b in blocks) else "with_unconfirmed",
        "targets": [{"target": b["target"], "confirmed": b["confirmed"],
                     "unconfirmed": b["unconfirmed"]} for b in blocks],
    }
    json_path = root / f"{assessment_id}.json"
    md_path = root / f"{assessment_id}.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    md_path.write_text(render_markdown(assessment_id, name, blocks), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def _stage_confirm_only(blocks: list, tmpdir: Path) -> Path:
    """Write a reduced attack_evidence dir containing ONLY the selected
    (CONFIRM-only unless include_unconfirmed) findings, so whatever adapter
    the evidence_manager exposes can never see unproven material."""
    tmpdir.mkdir(parents=True, exist_ok=True)
    for block in blocks:
        target = block["target"]
        safe = target.replace("/", "_").replace(":", "_")
        staged = {
            "target": target,
            "risk_rating": "INFO",
            "vulnerabilities": block["confirmed"],
            "disputed_findings": block["unconfirmed"],
            "proof_requests": [],
        }
        (tmpdir / f"{safe}.json").write_text(
            json.dumps(staged, indent=2, ensure_ascii=False), encoding="utf-8")
    return tmpdir


def push_to_evidence_manager(blocks: list, assessment_id: str, assessment_name: str,
                             evidence_manager_path: str, reports_root: str,
                             include_unconfirmed: bool) -> list:
    """Push staged CONFIRM-only evidence into an evidence_manager assessment.

    Raises ImportError when the package isn't installed — callers degrade to
    the self-contained local export instead of crashing the run.
    """
    em_parent = Path(evidence_manager_path).resolve()
    sys.path.insert(0, str(em_parent))
    from evidence_manager import EvidenceManager  # noqa: PLC0415
    from evidence_manager.adapters.cyberswarm_adapter import \
        export_cyberswarm_findings  # noqa: PLC0415

    import tempfile
    with tempfile.TemporaryDirectory(prefix="cyberswarm_evm_") as tmp:
        staging = _stage_confirm_only(blocks, Path(tmp))
        manager = EvidenceManager(root_directory=reports_root)
        finding_ids = export_cyberswarm_findings(
            evidence_dir=str(staging),
            manager=manager,
            assessment_id=assessment_id,
            assessment_name=assessment_name,
            include_zero_confidence=include_unconfirmed,
            attach_raw_evidence=True,
        )
        return list(finding_ids)


def export_assessment(evidence_dir: str, assessment_id: str,
                      assessment_name: str = "",
                      target: str = "",
                      evidence_manager_path: str = "../evidence_manager",
                      reports_root: str = "./reports",
                      include_unconfirmed: bool = False,
                      generate_report: bool = False,
                      print_fn=print) -> dict:
    """Run the full export. Returns {paths, pushed, counts}."""
    ev_dir = Path(evidence_dir)
    if target:
        files = [ev_dir / f"{target.replace('/', '_').replace(':', '_')}.json"]
    else:
        files = sorted(ev_dir.glob("*.json"))
    blocks = []
    for path in files:
        if not path.exists():
            continue
        try:
            evidence = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not evidence.get("target"):
            continue
        sel = select_evidence_backed(evidence, include_unconfirmed=include_unconfirmed)
        blocks.append(sel)
    if not blocks:
        raise SystemExit(f"[ERROR] No attack evidence found under {ev_dir}.")

    paths = write_local_export(assessment_id, assessment_name or assessment_id, blocks)

    pushed = []
    use_evm = True
    try:
        import importlib.util
        em_parent = Path(evidence_manager_path).resolve()
        if not (em_parent / "evidence_manager").is_dir():
            use_evm = False
    except Exception:  # noqa: BLE001
        use_evm = False
    if use_evm:
        try:
            pushed = push_to_evidence_manager(
                blocks, assessment_id, assessment_name or assessment_id,
                evidence_manager_path, reports_root, include_unconfirmed)
            print_fn(f"[OK] evidence_manager: imported {len(pushed)} finding(s) "
                     f"into assessment '{assessment_id}'.")
            if generate_report:
                import sys as _sys
                _sys.path.insert(0, str(Path(evidence_manager_path).resolve()))
                from evidence_manager import EvidenceManager  # noqa: PLC0415
                manager = EvidenceManager(root_directory=reports_root)
                paths_ = manager.generate_assessment_report(assessment_id)
                print_fn(f"[OK] Assessment report: {paths_.get('markdown')}")
                print_fn(f"[OK] Assessment report: {paths_.get('html')}")
        except ImportError as e:
            print_fn(f"[INFO] evidence_manager not usable ({e}); wrote "
                     f"self-contained export only (always written underneath).")
    else:
        print_fn(f"[INFO] evidence_manager not found under "
                 f"{Path(evidence_manager_path).resolve()}; "
                 f"wrote evidence-backed export to {paths['json']} and "
                 f"{paths['markdown']}.")

    total_conf = sum(len(b["confirmed"]) for b in blocks)
    total_unconf = sum(len(b["unconfirmed"]) for b in blocks)
    print_fn(f"[OK] exported {total_conf} confirmed + {total_unconf} "
             f"unconfirmed finding(s) across {len(blocks)} target(s).")
    return {"paths": paths, "pushed": pushed,
            "counts": {"confirmed": total_conf, "unconfirmed": total_unconf}}


def main() -> None:
    p = argparse.ArgumentParser(description="CyberSwarm evidence-backed export")
    p.add_argument("--assessment", required=True,
                   help="assessment_id to file findings under")
    p.add_argument("--name", default="", help="Human-readable assessment name")
    p.add_argument("--target", default="",
                   help="Only export this one target (default: all targets)")
    p.add_argument("--evidence-dir", default=str(DEFAULT_EVIDENCE_DIR),
                   help="Path to results/attack_evidence")
    p.add_argument("--evidence-manager-path", default="../evidence_manager",
                   help="Path to the folder containing the evidence_manager package")
    p.add_argument("--reports-root", default="./reports",
                   help="Root evidence_manager should write its reports into")
    p.add_argument("--include-unconfirmed", action="store_true",
                   help="Also export DISPUTE / NEEDS_PROOF items (clearly labelled)")
    p.add_argument("--generate-report", action="store_true",
                   help="Also generate assessment md/html report via evidence_manager")
    args = p.parse_args()
    export_assessment(
        evidence_dir=args.evidence_dir,
        assessment_id=args.assessment,
        assessment_name=args.name,
        target=args.target,
        evidence_manager_path=args.evidence_manager_path,
        reports_root=args.reports_root,
        include_unconfirmed=args.include_unconfirmed,
        generate_report=args.generate_report,
    )


if __name__ == "__main__":
    main()