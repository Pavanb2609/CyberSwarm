#!/usr/bin/env python3
"""validate_candidates.py -- Section 5.4 candidate validation from real runs.

Collects EVERY finding produced by the attack agents in the archived e2e
runs (pre-critic), labels each candidate against the lab ground truth
(vulnerable app: xss/sqli/ssti/lfi true; companions path_traversal and
information_disclosure counted as true-but-not-truth; clean control: every
finding is a false positive by construction), and crosses the labels with
the critic's actual verdict. This turns the archived runs into a
real-input-labelled validation set for the finding-validation section --
no hand-set confidences, no synthetic candidates.

Usage:
  python benchmarks/validate_candidates.py --stamp e2e20261104_031744 \
      --repeats 3
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
ARCHIVE = ROOT / "results" / "benchmarks" / "archive"
from benchmarks import taxonomy  # noqa: E402

TRUTH = {"xss", "sqli", "ssti", "lfi"}
COMPANIONS = {"path_traversal", "information_disclosure"}


def label(classes: set[str], stage: str) -> str:
    hit = classes & TRUTH
    if stage == "vulnerable":
        if hit:
            return "true"
        if classes & COMPANIONS:
            return "companion"      # real, but not counted as lab truth
        return "false"
    return "false"                  # clean control: everything is a FP


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stamp", required=True)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    candidates = []
    for i in range(1, args.repeats + 1):
        for lbl in ("vulnerable", "control"):
            d = ARCHIVE / f"{args.stamp}_{i}_after_{lbl}"
            p = d / "attack_evidence.json"
            if not p.is_file():
                continue
            data = json.loads(p.read_text(encoding="utf-8"))
            for r in (data.get("agent_runs") or []):
                for f in (r.get("findings") or []):
                    classes = taxonomy.classify_finding(
                        f.get("name", ""), f.get("description", ""),
                        f.get("tool", ""), f.get("source_agent", ""))
                    candidates.append({
                        "repeat": i, "stage": lbl,
                        "name": f.get("name", "")[:90],
                        "url": f.get("url", ""),
                        "severity": f.get("severity"),
                        "classes": sorted(classes),
                        "label": label(classes, lbl),
                        "verdict": (f.get("verdict") or "none"),
                    })

    out = Path(args.out or ROOT / "results" / "paper" / "e2e_repeats"
               / args.stamp.removeprefix("e2e"))
    out.mkdir(parents=True, exist_ok=True)

    # label x verdict confusion (deployed pipeline, real inputs)
    confusion: Counter = Counter((c["label"], c["verdict"]) for c in candidates)
    n = len(candidates)
    L = ["# Candidate validation from real e2e runs", "",
         f"Stamp {args.stamp}; {args.repeats} repeats; **{n} candidate findings** "
         "collected from archived attack evidence, labelled against the lab "
         "ground truth (vulnerable) / by construction (control).", "",
         "## Label x critic-verdict confusion (deployed pipeline)", "",
         "| label \\ verdict | CONFIRM | DISPUTE | NEEDS_PROOF | none |",
         "|---|---:|---:|---:|---:|"]
    for lbl in ("true", "companion", "false"):
        row = [confusion.get((lbl, v), 0) for v in
               ("CONFIRM", "DISPUTE", "NEEDS_PROOF", "none")]
        L.append(f"| **{lbl}** | " + " | ".join(str(x) for x in row) + " |")

    by_label = Counter(c["label"] for c in candidates)
    tp = confusion.get(("true", "CONFIRM"), 0)
    fp = confusion.get(("false", "CONFIRM"), 0)
    fn = sum(confusion.get(("true", v), 0) for v in ("DISPUTE", "NEEDS_PROOF", "none"))
    tn = by_label.get("false", 0) - fp
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    L += ["",
          f"- true candidates: {by_label.get('true', 0)}, companions: "
          f"{by_label.get('companion', 0)}, false candidates: {by_label.get('false', 0)}",
          f"- critic precision on true/false candidates: "
          f"**{prec:.0%}** ({tp}/{tp + fp})" if prec is not None else "- no confirms",
          f"- critic recall on true candidates: **{rec:.0%}** ({tp}/{tp + fn})"
          if rec is not None else "- no true candidates"]
    # per-repeat consistency
    per_rep = []
    for i in range(1, args.repeats + 1):
        cs = [c for c in candidates if c["repeat"] == i]
        per_rep.append(len(cs))
    L.append(f"- candidates per repeat: {per_rep}")

    (out / "candidate_validation.md").write_text("\n".join(L) + "\n",
                                                 encoding="utf-8")
    (out / "candidate_validation.json").write_text(
        json.dumps({"stamp": args.stamp, "n": n,
                    "confusion": {f"{k[0]}|{k[1]}": v for k, v in confusion.items()},
                    "candidates": candidates}, indent=2), encoding="utf-8")
    print("\n".join(L))
    print(f"\n[done] {out / 'candidate_validation.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
