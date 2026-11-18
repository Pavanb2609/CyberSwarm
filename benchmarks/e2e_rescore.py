#!/usr/bin/env python3
"""e2e_rescore.py — recompute e2e run aggregates from archived attack evidence.

The taxonomy fix of 2026-11-14 (the ``ssh`` ClassSpec accepted ANY
network-scanner finding via the weak-evidence producer path, so nmap_nse's
CUPS http-server-header INFO on localhost:631 was manufactured into a
phantom "ssh" class) changes the class labels of already-collected runs.
This tool re-scores each archived e2e run from its persisted
``attack_evidence.json`` (the exact findings the live scorer saw) under the
current taxonomy and writes ``e2e_repeats_rescored.{json,md}`` next to the
original aggregate. Originals are left untouched for provenance.

Usage: python benchmarks/e2e_rescore.py results/paper/e2e_repeats_freeze3/<stamp> ...
"""

from __future__ import annotations

import argparse
import glob
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmarks.scoring import detections_from_findings  # noqa: E402
from benchmarks.lab_bench import LAB_TRUTH, LAB_COMPANIONS  # noqa: E402

ARCHIVE = ROOT / "results/benchmarks/archive"


def load_findings(stamp: str, repeat: int, label: str) -> tuple[list, str]:
    p = ARCHIVE / f"e2e{stamp}_{repeat}_after_{label}" / "attack_evidence.json"
    if not p.exists():
        return [], f"missing archive: {p.relative_to(ROOT)}"
    data = json.loads(p.read_text(encoding="utf-8"))
    return list(data.get("vulnerabilities") or []), ""


def rescore_stamp(stamp_dir: Path) -> dict:
    agg = json.loads((stamp_dir / "e2e_repeats.json").read_text(encoding="utf-8"))
    stamp = agg["summary"]["generated"]
    out_runs = []
    for run in agg["runs"]:
        rep = run["repeat"]
        vuln_f, err_v = load_findings(stamp, rep, "vulnerable")
        ctrl_f, err_c = load_findings(stamp, rep, "control")
        det = detections_from_findings(vuln_f)
        cdet = detections_from_findings(ctrl_f)
        out_runs.append({
            "repeat": rep,
            "vulnerable": {
                "expected": sorted(LAB_TRUTH),
                "detected": sorted(det),
                "missed": sorted(set(LAB_TRUTH) - det),
                "extra": sorted(det - set(LAB_TRUTH) - LAB_COMPANIONS),
                "recall": round(len(det & set(LAB_TRUTH)) / len(LAB_TRUTH), 3),
                "findings": len(vuln_f), "error": err_v},
            "control": {
                "false_positive_classes": sorted(cdet),
                "false_positives": len(ctrl_f), "error": err_c},
            "duration_s": run.get("duration_s"),
        })
    n = len(out_runs)
    hits = {c: sum(1 for r in out_runs if c in r["vulnerable"]["detected"])
            for c in LAB_TRUTH}
    fp_total = sum(r["control"]["false_positives"] for r in out_runs)
    return {
        "stamp": stamp, "runs": out_runs,
        "summary": {
            "repeats": n,
            "per_class_hit_counts": hits,
            "per_class_hit_rate": {c: v / n for c, v in hits.items()},
            "fp_total": fp_total,
            "fp_mean": round(fp_total / n, 2),
            "runtime_mean_s": (round(statistics.mean(
                r["duration_s"] for r in out_runs if r["duration_s"]), 1)
                if any(r["duration_s"] for r in out_runs) else None),
        },
    }


def render(res: dict, orig: dict) -> str:
    s = res["summary"]
    lines = [
        f"# e2e rescored: {res['stamp']} (taxonomy fix 2026-11-14)",
        "",
        "Recomputed from archived attack_evidence.json under the current",
        "taxonomy (ssh ClassSpec no longer accepts network-scanner findings",
        "without ssh text evidence). Original aggregate kept untouched.",
        "",
        f"- per-class hits: " + ", ".join(
            f"{c} {v}/{s['repeats']}" for c, v in s["per_class_hit_counts"].items()),
        f"- control FPs: {s['fp_mean']} per run (total {s['fp_total']})",
        "",
        "| repeat | detected | missed | extra | control FP classes | ctrl findings |",
        "|---|---|---|---|---|---|",
    ]
    for r in res["runs"]:
        v, c = r["vulnerable"], r["control"]
        lines.append(
            f"| {r['repeat']} | {', '.join(v['detected']) or '-'} "
            f"| {', '.join(v['missed']) or '-'} "
            f"| {', '.join(v['extra']) or '-'} "
            f"| {', '.join(c['false_positive_classes']) or '-'} "
            f"| {c['false_positives']} |")
    lines += ["", "Original aggregate per-class hits: " + json.dumps(
        orig["summary"].get("per_class_hit_counts", {}))]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("stamp_dirs", nargs="+")
    args = ap.parse_args()
    for sd in args.stamp_dirs:
        d = Path(sd)
        orig = json.loads((d / "e2e_repeats.json").read_text(encoding="utf-8"))
        res = rescore_stamp(d)
        (d / "e2e_repeats_rescored.json").write_text(json.dumps(res, indent=1))
        (d / "e2e_repeats_rescored.md").write_text(render(res, orig))
        s = res["summary"]
        print(f"{d.name}: hits " +
              ", ".join(f"{c}{v}" for c, v in s['per_class_hit_counts'].items()) +
              f" | ctrl FPs {s['fp_mean']}/run (was {orig['summary'].get('fp_control_mean')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
