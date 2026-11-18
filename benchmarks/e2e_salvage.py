#!/usr/bin/env python3
"""e2e_salvage.py -- recover e2e_repeats.py results after a mid-run restart.

A harness restart kills the e2e_repeats process, but every completed
vulnerable/control run has already been archived to
results/benchmarks/archive/<stamp>_<i>_{after_vulnerable,after_control}/.
This script replays those archives into the standard run records:

  * findings / classes / confirmed counts come from the archived
    attack_evidence.json (the same JSON the live run scored), via
    scoring.score_benchmark -- identical values, not approximations
  * tool-call accounting via e2e_repeats._evidence_stats, unchanged
  * per-run duration is reconstructed from archive file mtimes (recon
    evidence mtime -> attack evidence mtime and start-to-end wall time);
    runs missing an archive are executed live with the true duration
  * aggregation and output files are byte-compatible with e2e_repeats.py

Usage:
  python benchmarks/e2e_salvage.py --stamp e2e20261104_031744 \
      --repeats 3 --out results/paper/e2e_repeats/20261104_031744
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TARGET = "localhost"


def run_stats(attack_ev: dict) -> dict:
    runs = attack_ev.get("agent_runs") or []
    tools: set[str] = set()
    total = 0
    status_mix: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    for r in runs:
        for rc in (r.get("tools_run") or []):
            tools.add(str(rc).split("(", 1)[0])
            total += 1
        st = r.get("status") or "unknown"
        status_mix[st] = status_mix.get(st, 0) + 1
        for f in (r.get("findings") or []):
            v = f.get("verdict") or "none"
            verdicts[v] = verdicts.get(v, 0) + 1
    return {"agent_runs": len(runs), "tool_calls_total": total,
            "tools_unique": sorted(tools), "tool_status_mix": status_mix,
            "critic_verdicts": verdicts,
            "disputed": len(attack_ev.get("disputed_findings") or []),
            "confirmed": len(attack_ev.get("vulnerabilities") or []),
            }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stamp", required=True,
                    help="archive stamp, e.g. e2e20261104_031744")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=1800,
                    help="per-stage CLI timeout for live missing runs")
    ap.add_argument("--out", default=None,
                    help="output dir (default results/paper/e2e_repeats/<ts of stamp>)")
    args = ap.parse_args()

    archive = ROOT / "results" / "benchmarks" / "archive"
    start_ts = datetime.strptime(args.stamp.removeprefix("e2e"), "%Y%m%d_%H%M%S").timestamp()

    out = Path(args.out or f"results/paper/e2e_repeats/{args.stamp.removeprefix('e2e')}")
    out.mkdir(parents=True, exist_ok=True)

    from benchmarks import lab_bench as lab  # noqa: E402
    from benchmarks.e2e_repeats import _evidence_stats  # noqa: E402

    cursor = start_ts
    runs: list[dict] = []
    for i in range(1, args.repeats + 1):
        sub = [f"{args.stamp}_{i}_after_control",
               f"{args.stamp}_{i}_after_vulnerable"]
        missing = [lab for lab in sub if not (archive / lab).is_dir()]
        live: dict[str, dict] = {}
        for miss in missing:
            label = "control" if miss.endswith("after_control") else "vulnerable"
            print(f"[salvage] repeat {i}/{args.repeats} {label} missing -> live run", flush=True)
            stamp = f"{args.stamp}_{i}"
            res = lab.run_e2e(label, args.timeout, stamp)
            live[label] = {"duration_s": round(res.duration_s, 1),
                           "end_ts": datetime.now().isoformat()}
            # remember the true duration so a later replay doesn't
            # inflate it with mtime math (live runs are not sequential
            # with the ones before them)
            after_dir = archive / f"{args.stamp}_{i}_after_{label}"
            (after_dir / "live_run.json").write_text(
                json.dumps(live[label], indent=2), encoding="utf-8")
            print(f"  -> live {label}: hits {sorted(res.hits)} "
                  f"FPs {res.findings} {res.duration_s:.0f}s "
                  f"error={res.error!r}", flush=True)

        dirs = {"vulnerable": archive / sub[1], "control": archive / sub[0]}

        tmp_cursor = cursor
        rec: dict = {"repeat": i}
        for label in ("vulnerable", "control"):
            d = dirs[label]
            attack_ev = json.loads((d / "attack_evidence.json").read_text(encoding="utf-8"))
            findings = list(attack_ev.get("vulnerabilities") or [])
            # For a run executed live during a previous salvage pass, the
            # sidecar records the exact duration and end time; otherwise
            # derive from archive mtimes (runs were strictly sequential).
            live_info = d / "live_run.json"
            if live_info.is_file():
                lr = json.loads(live_info.read_text(encoding="utf-8"))
                duration = round(lr["duration_s"], 1)
                tmp_cursor = datetime.fromisoformat(lr["end_ts"]).timestamp()
            else:
                duration = round(max((d / "attack_evidence.json").stat().st_mtime
                                     - tmp_cursor, 0.0), 1)
                tmp_cursor = (d / "attack_evidence.json").stat().st_mtime

            if label == "vulnerable":
                from benchmarks import scoring
                scored = scoring.score_benchmark("vulnerable", lab.LAB_TRUTH, findings,
                                                 duration_s=duration)
                rec["vulnerable"] = {
                    "detected": sorted(scored.detected), "missed": sorted(scored.misses),
                    "hits": sorted(scored.hits), "extra": sorted(scored.false_positives),
                    "findings": scored.findings, "confirmed": scored.confirmed_findings,
                    "duration_s": duration, "error": "",
                    "evidence": _evidence_stats(f"{args.stamp}_{i}", "after_vulnerable"),
                }
            else:
                found = len(findings)
                rec["control"] = {
                    "false_positive_classes": sorted({str(v.get("name", ""))
                                                      for v in findings}),
                    "false_positives": found,
                    "duration_s": duration, "error": "",
                }
        cursor = tmp_cursor
        runs.append(rec)
        v, c = rec["vulnerable"], rec["control"]
        print(f"  -> repeat {i}: vuln hits {v['hits']} missed {v['missed']} "
              f"{v['duration_s']}s | ctrl FPs {c['false_positives']} {c['duration_s']}s",
              flush=True)

    # aggregate -- mirrors e2e_repeats.py
    durs = [r["vulnerable"]["duration_s"] for r in runs]
    tps = [len(r["vulnerable"]["hits"]) for r in runs]
    fps = [r["control"]["false_positives"] for r in runs]

    def mean(x): return round(statistics.fmean(x), 1) if x else 0.0
    def sd(x): return round(statistics.stdev(x), 2) if len(x) > 1 else 0.0

    per_class: dict[str, int] = {}
    for r in runs:
        for c_ in r["vulnerable"]["hits"]:
            per_class[c_] = per_class.get(c_, 0) + 1

    ts = args.stamp.removeprefix("e2e")
    summary = {
        "generated": ts, "repeats": args.repeats, "target": TARGET,
        "salvaged": True,
        "runtime_mean_s": mean(durs), "runtime_sd_s": sd(durs),
        "tp_classes_mean": mean(tps), "tp_classes_sd": sd(tps),
        "fp_control_mean": mean(fps), "fp_control_sd": sd(fps),
        "fp_total": int(sum(fps)),
        "per_class_hit_counts": per_class,
        "per_class_hit_rate": {c_: n / args.repeats for c_, n in per_class.items()},
        "tool_calls_total_mean": mean([r["vulnerable"]["evidence"]["tool_calls_total"]
                                       for r in runs]),
        "agent_runs_mean": mean([r["vulnerable"]["evidence"]["agent_runs"]
                                 for r in runs]),
        "tools_unique_union": sorted({t for r in runs
                                      for t in r["vulnerable"]["evidence"]["tools_unique"]}),
    }

    (out / "e2e_repeats.json").write_text(
        json.dumps({"summary": summary, "runs": runs}, indent=2),
        encoding="utf-8")

    L = [f"# End-to-end performance: {args.repeats} repeats on lab_app", "",
         f"Generated {ts}; full recon --run-all + attack pipeline, "
         "vulnerable app + clean control per repeat.",
         "**NOTE: recovered from archives after a mid-run restart "
         "(e2e_salvage.py). Findings/classes/accounting are exact; "
         "durations reconstructed from archive timestamps.**", "",
         f"- runtime: **{summary['runtime_mean_s']} s +/- {summary['runtime_sd_s']}** "
         f"(sd across {args.repeats} runs)",
         f"- true-positive classes per run: {summary['tp_classes_mean']} +/- "
         f"{summary['tp_classes_sd']} of {len(lab.LAB_TRUTH)}",
         f"- control false positives: {summary['fp_control_mean']} +/- "
         f"{summary['fp_control_sd']} (total {summary['fp_total']})",
         f"- tool calls per run (attack phase): {summary['tool_calls_total_mean']}",
         f"- agent runs per run (attack phase): {summary['agent_runs_mean']}",
         f"- per-class hit rate over repeats: "
         + ", ".join(f"{c_} {rate:.0%}"
                     for c_, rate in sorted(summary["per_class_hit_rate"].items())),
         "",
         "| repeat | detected | missed | findings | duration s | control FPs |",
         "|---|---|---|---|---|---|"]
    for r in runs:
        v, c = r["vulnerable"], r["control"]
        L.append(f"| {r['repeat']} | {', '.join(v['hits'])} | "
                 f"{', '.join(v['missed']) or '-'} | {v['findings']} | "
                 f"{v['duration_s']} | {c['false_positives']} |")
    (out / "e2e_repeats.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"\n[done] {out / 'e2e_repeats.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
