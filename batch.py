"""
batch.py — multi-target assessment (serial, deterministic).

`cyberswarm assess --targets-file targets.txt` runs the same evidence-driven
Controller loop per target, one at a time:

  - each target gets a fresh AssessmentState + MemoryStore + decision trace
  - per-target tool-memory file (results/tool_memory.<target>.json) so the
    reliability ledger never has concurrent-writer races
  - unauthorized targets are skipped (or auto-authorized with --auto-approve)
  - a rolled-up summary lands in results/reports/_batch.<timestamp>.{md,json}

Serial by default: deterministic ordering, no shared-state races. Use the
single-target CLI when you need credentialed context per target (--creds-file
still applies to every target in the batch).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

from context import load_engagement
from controller import Controller, RECON_CAPABILITIES, ATTACK_ACTIONS
from decision_trace import DecisionTrace
from memory_store import MemoryStore
from tool_manager import ToolManager
from utils import ROOT

REPORT_DIR = ROOT / "results" / "reports"


def read_targets_file(path: str) -> List[str]:
    """One host per line; '#' comments and blank lines ignored."""
    with open(path, encoding="utf-8") as fh:
        lines = (ln.split("#", 1)[0].strip() for ln in fh)
        return [ln for ln in lines if ln]


def _safe(target: str) -> str:
    return "".join("_" if c in "/:." else c for c in target)


def run_one(target: str, args) -> Dict[str, Any]:
    """Run the Controller for a single target; returns a compact summary."""
    t = _normalize(target)
    tm = ToolManager(memory_path=ROOT / "results" / f"tool_memory.{_safe(t)}.json")
    mem = MemoryStore(t, tool_manager=tm)
    ctx = load_engagement(t,
                          creds_file=getattr(args, "creds_file", None),
                          cookies_file=getattr(args, "cookies_file", None),
                          identity=getattr(args, "identity", None))
    c = Controller(
        t,
        tool_manager=tm,
        memory_store=mem,
        allow_high_risk=not getattr(args, "no_high_risk", False),
        max_actions=getattr(args, "max_actions", 100),
        max_time_s=getattr(args, "max_time", 1800.0),
        dry_run=getattr(args, "dry_run", False),
        context=ctx,
        tool_timeout=getattr(args, "tool_timeout", 120),
    )
    res = c.assess()
    snap = res.get("snapshot", {})
    assets_by_type = snap.get("assets_by_type", {})
    asset_total = sum(len(v) for v in assets_by_type.values())

    total_caps = len(_capability_count(res))
    covered = sum(1 for v in res.get("coverage", {}).values() if v >= 1)
    pct = round(100.0 * covered / total_caps) if total_caps else 0

    sum_row = {
        "target": res["target"],
        "actions_run": res["actions_run"],
        "elapsed_s": round(res["elapsed_s"], 1),
        "stop_reason": res.get("stop_reason", ""),
        "asset_total": int(asset_total),
        "assets": {k: len(v) for k, v in assets_by_type.items()},
        "evidence_count": int(snap.get("evidence_count", 0)),
        "findings": int(snap.get("findings", 0)),
        "coverage_pct": pct,
        "dry_run": bool(res.get("dry_run", False)),
    }

    traces_dir = ROOT / "results" / "traces"
    traces_dir.mkdir(parents=True, exist_ok=True)
    trace_path = traces_dir / f"{res['target']}.json"
    DecisionTrace.from_decisions(res["target"], res.get("decisions", [])).export_trace(
        str(trace_path))
    sum_row["trace"] = str(trace_path)
    print(f"  [{res['target']}] {res['actions_run']} actions in {res['elapsed_s']}s | "
          f"assets={asset_total} evidence={snap.get('evidence_count', 0)} "
          f"findings={snap.get('findings', 0)} | {pct}% coverage | {res.get('stop_reason', '')}")
    return sum_row


def _normalize(target: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(target or "")
    if parsed.scheme in ("http", "https") and parsed.hostname:
        return parsed.hostname
    return target


def _capability_count(res: Dict[str, Any]) -> List[str]:
    """Number of registered capabilities (recon + attack) for coverage pct."""
    return list(RECON_CAPABILITIES) + list(ATTACK_ACTIONS)


def _authz_targets(targets: List[str], args, authorize_all: bool = False) -> List[str]:
    import authorization as auth
    out = []
    for t in (_normalize(t) for t in targets):
        ok, _ = auth.is_authorized(t)
        if ok:
            out.append(t)
        elif authorize_all or getattr(args, "auto_approve", False) \
                or getattr(args, "force", False):
            auth.authorize_target(t)
            out.append(t)
        else:
            print(f"  [skip] {t}: not authorized (run 'cyberswarm authorize {t}' "
                  f"or --auto-approve)")
    return out


def run_assess_batch(args) -> int:
    """CLI entry: assess --targets-file. Returns process exit code."""
    start = time.monotonic()
    targets = [_normalize(t) for t in read_targets_file(args.targets_file)]
    if not targets:
        print(f"error: no targets in {args.targets_file}", file=__import__("sys").stderr)
        return 2

    print(f"[batch] {len(targets)} targets from {args.targets_file} (serial, "
          f"{'dry-run' if args.dry_run else 'live'}):")
    authorized = _authz_targets(targets, args)
    if not authorized:
        print("[batch] no authorized targets to assess")
        return 1

    rows = [run_one(t, args) for t in authorized]
    return _write_summary(rows, start)


def authorize_batch(args) -> int:
    """CLI entry: authorize --targets-file."""
    import authorization as auth
    targets = read_targets_file(args.targets_file)
    for t in (_normalize(t) for t in targets):
        auth.authorize_target(t)
        print(f"[authorize] added '{t}' to {auth.CONFIG_PATH}")
    print(f"[authorize] scope: {', '.join(auth.scope())}")
    return 0


def _write_summary(rows: List[Dict[str, Any]], start: float) -> int:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    md_path = REPORT_DIR / f"_batch.{stamp}.md"
    json_path = REPORT_DIR / f"_batch.{stamp}.json"

    walls = (n for n in ("asset_total", "evidence_count", "findings"))
    totals = {n: sum(r[n] for r in rows) for n in walls}
    ok = sum(1 for r in rows if "target not authorized" not in r["stop_reason"])

    md = [
        "# CyberSwarm batch assessment",
        "",
        f"- targets: {len(rows)} | ran: {ok} | total assets: {totals['asset_total']}"
        f" | evidence: {totals['evidence_count']} | findings: {totals['findings']}"
        f" | elapsed: {round(time.monotonic() - start, 1)}s",
        "",
        "| target | actions | assets | evidence | findings | coverage% | elapsed(s) | result |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        md.append(
            f"| {r['target']} | {r['actions_run']} | {r['asset_total']} | "
            f"{r['evidence_count']} | {r['findings']} | {r['coverage_pct']} | "
            f"{r['elapsed_s']} | {r['stop_reason']} |")
    md += ["", "## Traces", ""]
    for r in rows:
        md.append(f"- [`{r['target']}`]({r['trace']}) — {r['stop_reason']}")

    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")
    json_path.write_text(
        __import__("json").dumps({"rows": rows, "totals": totals}, indent=2),
        encoding="utf-8")
    print(f"\n[batch] summary: {md_path}")
    return 0