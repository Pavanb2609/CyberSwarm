#!/usr/bin/env python3
"""scanner_equiv_rescore.py — re-score persisted scanner-arm detections under
the 2026-11-16 equivalence rule (lfi ≡ path_traversal at lfi ground-truth
endpoints), applied uniformly to every arm.

Why: the original scoring required exact class equality. CyberSwarm's
findings are labelled by the paper taxonomy, which maps a "path traversal /
file disclosure" finding to {lfi, path_traversal} — so /download was
credited. ZAP's tool-native alerts at the same three lab lfi endpoints were
labelled path_traversal only and went uncredited. Review flagged this as an
asymmetry. The rule is now in `scanner_bench.score()` itself (all future
runs), and this script re-scores the already-collected arms — detections are
persisted per arm in each stamp's run.json, so no re-execution is needed.
Originals are kept; this writes `run_equiv_rescored.json` beside each.

Usage: python benchmarks/scanner_equiv_rescore.py [stamp ...]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmarks import scanner_bench as sb  # noqa: E402  (updated score())

STAMPS = {
    "20261111_064739": ["sqlmap", "nuclei-serial", "nuclei-concurrent"],
    "20261112_050320": ["zap"],
    "20261114_174628": ["cyberswarm"],
}


def main() -> int:
    base = ROOT / "results/scanner_benchmark"
    stamps = sys.argv[1:] or list(STAMPS)
    for stamp in stamps:
        d = base / stamp
        run = json.loads((d / "run.json").read_text(encoding="utf-8"))
        out = {"stamp": stamp, "rule": "lfi ~= path_traversal (uniform)", "tools": {}}
        for tool, arm in run["tools"].items():
            old = arm["score"]
            new = sb.score(tool, arm.get("detections") or [], d)
            out["tools"][tool] = {"original": old, "rescored": new}
            print(f"{stamp} {tool:18s} TP {old['tp']} -> {new['tp']}"
                  f" | param {len(old['param_hits'])} -> {len(new['param_hits'])}"
                  f" | ctrl {len(old['control_hits'])} -> {len(new['control_hits'])}"
                  f" | FH {len(old['false_high_severity'])} -> {len(new['false_high_severity'])}")
            if new["hits"] != old["hits"]:
                print(f"    new hits: {sorted(set(new['hits']) - set(old['hits']))}")
        (d / "run_equiv_rescored.json").write_text(json.dumps(out, indent=1))
    print("wrote run_equiv_rescored.json next to each run.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
