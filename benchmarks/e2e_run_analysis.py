#!/usr/bin/env python3
"""e2e_run_analysis.py -- per-stage timing and tool-resolution accounting
for archived e2e runs (Section 5.5).

For each archived vulnerable/control run it reports:
  * recon stage duration   (recon evidence mtime - run start)
  * attack stage duration  (attack evidence mtime - recon evidence mtime)
  * tool calls: total, unique, status mix
  * critic verdict mix, disputed / confirmed counts

Run start times are inferred sequentially from the run's archive chain
(within a repeat, runs are strictly sequential), which is exact to the
second for runs produced by one process.

Usage:
  python benchmarks/e2e_run_analysis.py --stamp e2e20261104_031744 \
      --repeats 3 [--out results/paper/e2e_repeats/20261104_031744]
"""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARCHIVE = ROOT / "results" / "benchmarks" / "archive"


def stage_stats(d: Path, start: float) -> tuple[dict, float]:
    ev = d / "evidence.json"
    atk = d / "attack_evidence.json"
    recon_s = ev.stat().st_mtime - start
    attack_s = atk.stat().st_mtime - ev.stat().st_mtime
    data = json.loads(atk.read_text(encoding="utf-8"))
    runs = data.get("agent_runs") or []
    tools, total, status_mix, verdicts = set(), 0, {}, {}
    for r in runs:
        for rc in (r.get("tools_run") or []):
            tools.add(str(rc).split("(", 1)[0])
            total += 1
        st = r.get("status") or "unknown"
        status_mix[st] = status_mix.get(st, 0) + 1
        for f in (r.get("findings") or []):
            v = f.get("verdict") or "none"
            verdicts[v] = verdicts.get(v, 0) + 1
    return ({"recon_s": round(recon_s, 1), "attack_s": round(attack_s, 1),
             "total_s": round(recon_s + attack_s, 1),
             "agent_runs": len(runs), "tool_calls_total": total,
             "tools_unique": len(tools),
             "tool_status_mix": status_mix,
             "critic_verdicts": verdicts,
             "disputed": len(data.get("disputed_findings") or []),
             "confirmed": len(data.get("vulnerabilities") or [])},
            atk.stat().st_mtime)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stamp", required=True, help="e.g. e2e20261104_031744")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    start = datetime.strptime(args.stamp.removeprefix("e2e"),
                              "%Y%m%d_%H%M%S").timestamp()
    cursor = start
    rows = []
    for i in range(1, args.repeats + 1):
        rec = {"repeat": i}
        for label in ("vulnerable", "control"):
            d = ARCHIVE / f"{args.stamp}_{i}_after_{label}"
            if not d.is_dir():
                rec[label] = {"missing": True}
                continue
            live = d / "live_run.json"
            if live.is_file():
                lr = json.loads(live.read_text(encoding="utf-8"))
                st, end = None, datetime.fromisoformat(lr["end_ts"]).timestamp()
                stats, _ = stage_stats(d, end - lr["duration_s"])
            else:
                stats, end = stage_stats(d, cursor)
            stats["stage"] = label
            rec[label] = stats
            cursor = end
        rows.append(rec)
        v, c = rec["vulnerable"], rec["control"]
        print(f"repeat {i}: vuln recon {v['recon_s']}s + attack {v['attack_s']}s "
              f"= {v['total_s']}s | tools {v['tools_unique']} uniq/"
              f"{v['tool_calls_total']} calls | critic {v['critic_verdicts']} "
              f"| ctrl {c['total_s']}s FPs {c['confirmed']}")

    out = Path(args.out or ROOT / "results" / "paper" / "e2e_repeats"
               / args.stamp.removeprefix("e2e"))
    out.mkdir(parents=True, exist_ok=True)
    (out / "e2e_stage_analysis.json").write_text(
        json.dumps({"stamp": args.stamp, "runs": rows}, indent=2),
        encoding="utf-8")

    def mean(x):
        return round(statistics.fmean(x), 1) if x else 0

    L = ["# e2e per-stage analysis", "",
         f"Stamp {args.stamp}, {args.repeats} repeats.", "",
         "| repeat | stage | recon s | attack s | total s | agent runs | "
         "tool calls | unique tools | critic verdicts | confirmed |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    for rec in rows:
        for label in ("vulnerable", "control"):
            s = rec[label]
            if s.get("missing"):
                continue
            L.append(f"| {rec['repeat']} | {label} | {s['recon_s']} | "
                     f"{s['attack_s']} | {s['total_s']} | {s['agent_runs']} | "
                     f"{s['tool_calls_total']} | {s['tools_unique']} | "
                     f"{json.dumps(s['critic_verdicts'])} | {s['confirmed']} |")
    vuln = [r["vulnerable"] for r in rows if not r["vulnerable"].get("missing")]
    L += ["", f"- mean total (vulnerable): **{mean([v['total_s'] for v in vuln])} s**",
          f"- mean recon: {mean([v['recon_s'] for v in vuln])} s, "
          f"mean attack: {mean([v['attack_s'] for v in vuln])} s",
          f"- mean tool calls (attack): {mean([v['tool_calls_total'] for v in vuln])}, "
          f"unique tools/run: {mean([v['tools_unique'] for v in vuln])}"]
    (out / "e2e_stage_analysis.md").write_text("\n".join(L) + "\n",
                                               encoding="utf-8")
    print(f"\n[done] {out / 'e2e_stage_analysis.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
