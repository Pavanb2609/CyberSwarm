#!/usr/bin/env python3
"""xbow_rescore.py — recompute XBOW variant results from persisted raw findings.

The runner (xbow_bench.py) stores per-run raw findings as
``evidence_{variant}_{benchmark}.json`` in the matrix output directory exactly
so that taxonomy/mapping fixes can be applied by rescoring instead of rerunning
the whole matrix. This tool loads each variant's runs, reclassifies the raw
findings under the current ``benchmarks/taxonomy.py``, and writes
``{variant}.rescored.json`` plus a comparison table (old vs new).

Usage: python benchmarks/xbow_rescore.py --repo ../validation-benchmarks \
           --out results/xbow/matrix
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmarks import scoring  # noqa: E402

VARIANTS = ["baseline", "no-difficulty", "no-rag", "no-llm-planner", "no-guardrails"]


def load_tags(repo: Path) -> dict:
    """benchmark id -> tags, from the benchmark repo metadata."""
    tags = {}
    root = repo / "benchmarks"
    if not root.is_dir():
        root = repo
    for meta_path in sorted(root.glob("*/benchmark.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        bid = meta.get("id") or meta_path.parent.name
        tags[bid] = meta.get("tags") or []
    return tags


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="../validation-benchmarks")
    ap.add_argument("--out", default="results/xbow/matrix")
    args = ap.parse_args()
    repo = Path(args.repo)
    out = Path(args.out)

    tags = load_tags(repo)
    for variant in VARIANTS:
        p = out / f"{variant}.json"
        if not p.exists():
            continue
        runs = json.loads(p.read_text())
        rescored = []
        changed = 0
        for r in runs:
            ev_path = out / f"evidence_{variant}_{r['benchmark']}.json"
            if ev_path.exists():
                findings = json.loads(ev_path.read_text())
                bench_tags = tags.get(r["benchmark"], r.get("expected", []))
                nr = scoring.score_benchmark(r["benchmark"], bench_tags, findings,
                                             r.get("level", ""),
                                             r.get("duration_s", 0.0),
                                             error=r.get("error", ""))
                new = dict(r)
                new.update({
                    "expected": sorted(nr.expected), "skipped": sorted(nr.skipped),
                    "detected": sorted(nr.detected), "hits": sorted(nr.hits),
                    "misses": sorted(nr.misses),
                    "false_positives": sorted(nr.false_positives),
                    "solved": nr.solved, "findings": nr.findings,
                    "confirmed_findings": nr.confirmed_findings})
                if (new["detected"] != r.get("detected")
                        or new["false_positives"] != r.get("false_positives")
                        or new["solved"] != r.get("solved")):
                    changed += 1
                rescored.append(new)
            else:
                rescored.append(r)  # raw evidence not persisted; keep as-is
        (out / f"{variant}.rescored.json").write_text(json.dumps(rescored, indent=1))
        old_solved = sum(1 for r in runs if r.get("solved"))
        new_solved = sum(1 for r in rescored if r.get("solved"))
        old_fp = sum(len(r.get("false_positives") or []) for r in runs)
        new_fp = sum(len(r.get("false_positives") or []) for r in rescored)
        print(f"{variant:<16} solved {old_solved}->{new_solved} | "
              f"FP tags {old_fp}->{new_fp} | runs changed {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
