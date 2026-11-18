#!/usr/bin/env python3
"""e2e_repeats.py -- repeated end-to-end runs of the full pipeline on the
local lab application, for the paper's end-to-end performance section.

Each repeat = one vulnerable-app run + one clean-control run through
lab_bench.run_e2e (full `recon --run-all` + `attack` pipeline, model backend
required). Per repeat we record:

  * duration (wall clock), run error ("" if none)
  * detected classes vs LAB_TRUTH, misses, extra classes
  * confirmed findings (post-critic) on the vulnerable app
  * false positives on the clean control
  * tool-call accounting from the archived attack evidence:
      agent_runs, tools invoked (unique + total), tool errors,
      disputed findings, critic verdict mix

Output: results/paper/e2e_repeats/<ts>/e2e_repeats.{md,json} with mean +/- sd
runtime across repeats and the full per-run records. Honest basis for the
"case study -> measured across N independent lab runs" upgrade.

Usage: python benchmarks/e2e_repeats.py --repeats 3 [--timeout 1800]
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TARGET = "localhost"  # lab_bench.TARGET


def _evidence_stats(stamp: str, label: str) -> Dict[str, Any]:
    """Tool-call accounting from the per-run archived evidence file."""
    base = ROOT / "results" / "benchmarks" / "archive" / f"{stamp}_{label}"
    info: Dict[str, Any] = {"agent_runs": 0, "tool_calls_total": 0,
                            "tools_unique": [], "tool_status_mix": {},
                            "critic_verdicts": {}, "disputed": 0, "confirmed": 0}
    p = base / "attack_evidence.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return info
    runs = data.get("agent_runs") or []
    info["agent_runs"] = len(runs)
    tools: set[str] = set()
    for r in runs:
        for rc in (r.get("tools_run") or []):
            name = str(rc).split("(", 1)[0]
            tools.add(name)
            info["tool_calls_total"] += 1
        st = r.get("status") or "unknown"
        info["tool_status_mix"][st] = info["tool_status_mix"].get(st, 0) + 1
        for f in (r.get("findings") or []):
            v = f.get("verdict") or "none"
            info["critic_verdicts"][v] = info["critic_verdicts"].get(v, 0) + 1
    info["tools_unique"] = sorted(tools)
    info["disputed"] = len(data.get("disputed_findings") or [])
    info["confirmed"] = len(data.get("vulnerabilities") or [])
    return info


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=1800,
                    help="per-stage CLI timeout in seconds")
    ap.add_argument("--out", default="results/paper/e2e_repeats")
    ap.add_argument("--app", default="v1", choices=["v1", "v3"],
                    help="v1 = simulated SQL (frozen runs); v3 = real SQLite backend so sqli is confirmable")
    args = ap.parse_args()

    from benchmarks import lab_bench as lab  # noqa: E402

    # The vulnerable lab server is spawned with sys.executable and needs
    # Flask; fail fast and loudly instead of producing six 0-second no-op
    # runs when launched under an interpreter without it.
    try:
        import flask  # noqa: F401
    except ModuleNotFoundError:
        print("error: Flask is not available under this interpreter; the "
              "vulnerable lab server cannot start. Run with "
              "./venv/bin/python benchmarks/e2e_repeats.py", file=sys.stderr)
        return 2

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(args.out) / ts
    out.mkdir(parents=True, exist_ok=True)

    runs: List[Dict[str, Any]] = []
    for i in range(1, args.repeats + 1):
        print(f"[e2e] repeat {i}/{args.repeats} vulnerable", flush=True)
        stamp = f"e2e{ts}_{i}"
        vuln = lab.run_e2e("vulnerable", args.timeout, stamp, app_version=args.app)
        ev_v = _evidence_stats(stamp, "after_vulnerable")
        print(f"[e2e] repeat {i}/{args.repeats} control", flush=True)
        ctrl = lab.run_e2e("control", args.timeout, stamp, app_version=args.app)
        runs.append({
            "repeat": i,
            "vulnerable": {
                "detected": sorted(vuln.detected), "missed": sorted(vuln.misses),
                "hits": sorted(vuln.hits), "extra": sorted(vuln.false_positives),
                "findings": vuln.findings,
                "confirmed": vuln.confirmed_findings,
                "duration_s": round(vuln.duration_s, 1), "error": vuln.error,
                "evidence": ev_v,
            },
            "control": {
                "false_positive_classes": sorted(ctrl.detected),
                "false_positives": ctrl.findings,
                "duration_s": round(ctrl.duration_s, 1), "error": ctrl.error,
            },
        })
        print(f"  -> vuln {sorted(vuln.hits)} missed {sorted(vuln.misses)} "
              f"{vuln.duration_s:.0f}s | ctrl FPs {ctrl.findings}", flush=True)
        # checkpoint after each repeat so a restart costs one repeat, not all
        (out / f"checkpoint_repeat_{i}.json").write_text(
            json.dumps({"ts": ts, "completed": i, "runs": runs}, indent=2),
            encoding="utf-8")

    # aggregate
    durs = [r["vulnerable"]["duration_s"] for r in runs]
    tps = [len(r["vulnerable"]["hits"]) for r in runs]
    fps = [r["control"]["false_positives"] for r in runs]
    def mean(x): return round(statistics.fmean(x), 1) if x else 0.0
    def sd(x): return round(statistics.stdev(x), 2) if len(x) > 1 else 0.0

    # per-class hit counts across repeats
    per_class: Dict[str, int] = {}
    for r in runs:
        for c in r["vulnerable"]["hits"]:
            per_class[c] = per_class.get(c, 0) + 1

    summary = {
        "generated": ts, "repeats": args.repeats, "target": TARGET,
        "runtime_mean_s": mean(durs), "runtime_sd_s": sd(durs),
        "tp_classes_mean": mean(tps), "tp_classes_sd": sd(tps),
        "fp_control_mean": mean(fps), "fp_control_sd": sd(fps),
        "fp_total": int(sum(fps)),
        "per_class_hit_counts": per_class,
        "per_class_hit_rate": {c: n / args.repeats for c, n in per_class.items()},
        "tool_calls_total_mean": mean([r["vulnerable"]["evidence"]["tool_calls_total"]
                                       for r in runs]),
        "agent_runs_mean": mean([r["vulnerable"]["evidence"]["agent_runs"]
                                 for r in runs]),
        "tools_unique_union": sorted({t for r in runs
                                      for t in r["vulnerable"]["evidence"]["tools_unique"]}),
        "run_errors": [r["vulnerable"]["error"] or r["control"]["error"]
                       for r in runs if (r["vulnerable"]["error"] or r["control"]["error"])],
    }

    (out / "e2e_repeats.json").write_text(
        json.dumps({"summary": summary, "runs": runs}, indent=2),
        encoding="utf-8")

    L = [f"# End-to-end performance: {args.repeats} repeats on lab_app",
         "",
         f"Generated {ts}; full recon --run-all + attack pipeline, "
         "vulnerable app + clean control per repeat.",
         "",
         f"- runtime: **{summary['runtime_mean_s']} s +/- "
         f"{summary['runtime_sd_s']}" f"** (sd across {args.repeats} runs)",
         f"- true-positive classes per run: {summary['tp_classes_mean']} +/- "
         f"{summary['tp_classes_sd']} of {len(lab.LAB_TRUTH)}",
         f"- control false positives: {summary['fp_control_mean']} +/- "
         f"{summary['fp_control_sd']} (total {summary['fp_total']})",
         f"- tool calls per run (attack phase): {summary['tool_calls_total_mean']}",
         f"- agent runs per run (attack phase): {summary['agent_runs_mean']}",
         f"- per-class hit rate over repeats: "
         + ", ".join(f"{c} {rate:.0%}"
                     for c, rate in sorted(summary["per_class_hit_rate"].items())),
         "",
         "| repeat | detected | missed | findings | duration s | control FPs |",
         "|---|---|---|---|---|---|"]
    for r in runs:
        v, c = r["vulnerable"], r["control"]
        L.append(f"| {r['repeat']} | {', '.join(v['hits'])} | "
                 f"{', '.join(v['missed']) or '-'} | {v['findings']} | "
                 f"{v['duration_s']} | {c['false_positives']} |")
    if summary["run_errors"]:
        L += ["", f"run errors: {summary['run_errors']}"]
    (out / "e2e_repeats.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"\n[done] {out / 'e2e_repeats.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
