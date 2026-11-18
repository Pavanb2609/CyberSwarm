#!/usr/bin/env python3
"""
ci_analysis.py -- error bars + paired significance tests for the recon
planner benchmark dumps produced by run_benchmark.py (per-scenario rows).

Given one or more benchmark dump files (each {summary, results: per-scenario
rows with rules/llm/guarded outcomes and "score" bools}), this computes:

  * pass/total and exact Wilson 95% confidence intervals per mode, per dump
    and pooled across dumps (bounded-Bernoulli interval, no normal approx);
  * exact McNemar tests (binomial, two-sided) for the paired comparisons the
    paper draws:
        raw LLM planner  vs  guardrailed planner
        rules planner    vs  raw LLM planner
      Pooled across all scenarios of the given dumps, plus per dump.

No third-party stats library needed; scipy/statsmodels are not required.
"""

from __future__ import annotations

import argparse
import glob
import json
import math
from pathlib import Path
from typing import Any, Dict, List

Z = 1.959963984540054  # two-sided 95%


def wilson(x: int, n: int, z: float = Z) -> tuple:
    """(lo, hi) of the Wilson score interval at level z."""
    if n == 0:
        return (0.0, 0.0)
    center = (x + z * z / 2) / (n + z * z)
    half = z * math.sqrt(x * (n - x) / n + z * z / 4) / (n + z * z)
    return (max(0.0, center - half), min(1.0, center + half))


def mcnemar_exact(b: int, c: int) -> tuple:
    """Two-sided exact McNemar p-value for discordant counts b, c."""
    n = b + c
    if n == 0:
        return (b, c, 1.0)
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) * (0.5 ** n)
    p = min(1.0, 2.0 * tail)
    return (b, c, p)


def _load(paths: List[str]) -> List[Dict[str, Any]]:
    dumps = []
    for path in paths:
        for f in sorted(glob.glob(path)):
            d = json.loads(Path(f).read_text(encoding="utf-8"))
            rows = d.get("results") or []
            if rows:
                dumps.append({"path": f, "rows": rows})
    return dumps


def _mode_outcome(row: Dict[str, Any], mode: str) -> bool:
    res = row.get(mode)
    return bool(res and res.get("score", {}).get("pass"))


def analyse(dumps: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"n_dumps": len(dumps), "pooled": {}, "per_dump": [],
                           "mcnemar": {}}
    modes = ("rules", "llm", "guarded")

    # pooled
    rows = [r for d in dumps for r in d["rows"]]
    pooled = {"rows": 0, "pass": {}, "wilson": {}}
    for m in modes:
        n = len(rows)
        x = sum(_mode_outcome(r, m) for r in rows)
        lo, hi = wilson(x, n)
        pooled["pass"][m] = {"x": x, "n": n,
                            "rate": round(x / n, 4) if n else 0.0,
                            "wilson95": [round(lo, 4), round(hi, 4)]}
        pooled["rows"] = n
    out["pooled"] = pooled

    # per dump
    for d in dumps:
        rows_d = d["rows"]
        entry = {m: {"x": sum(_mode_outcome(r, m) for r in rows_d),
                     "n": len(rows_d)} for m in modes}
        try:
            entry["model"] = d["rows"][0].get("guarded", {}).get("decision") is not None and (
                json.loads(Path(d["path"]).read_text(encoding="utf-8"))
                .get("summary", {}).get("model", "?"))
        except Exception:  # noqa: BLE001
            entry["model"] = "?"
        out["per_dump"].append(entry)

    # McNemar: llm vs guarded, rules vs llm (pooled)
    b_rg = sum(1 for r in rows                      # raw fail -> guarded pass
               if not _mode_outcome(r, "llm") and _mode_outcome(r, "guarded"))
    c_rg = sum(1 for r in rows                      # raw pass -> guarded fail
               if _mode_outcome(r, "llm") and not _mode_outcome(r, "guarded"))
    b_rl = sum(1 for r in rows                      # rules fail -> llm pass
               if not _mode_outcome(r, "rules") and _mode_outcome(r, "llm"))
    c_rl = sum(1 for r in rows                      # rules pass -> llm fail
               if _mode_outcome(r, "rules") and not _mode_outcome(r, "llm"))
    p_rg = mcnemar_exact(b_rg, c_rg)
    p_rl = mcnemar_exact(b_rl, c_rl)
    out["mcnemar"] = {
        "llm_vs_guarded": {"discordant_raw_fail_guarded_pass": b_rg,
                           "discordant_raw_pass_guarded_fail": c_rg,
                           "p_value": p_rg[2]},
        "rules_vs_llm": {"discordant_rules_fail_llm_pass": b_rl,
                         "discordant_rules_pass_llm_fail": c_rl,
                         "p_value": p_rl[2]},
    }
    return out


def to_markdown(res: Dict[str, Any]) -> str:
    lines: List[str] = []
    p = res["pooled"]
    lines.append(f"### Pooled across {res['n_dumps']} dumps "
                 f"({p['rows']} scenario decisions)\n")
    lines.append("| mode | pass | rate | Wilson 95% CI |")
    lines.append("|---|---:|---:|---|")
    for m in ("rules", "llm", "guarded"):
        s = p["pass"][m]
        lo, hi = s["wilson95"]
        lines.append(f"| {m} | {s['x']}/{s['n']} | {s['rate']:.1%} "
                     f"| [{lo:.1%}, {hi:.1%}] |")
    mc = res["mcnemar"]
    a = mc["llm_vs_guarded"]
    b = mc["rules_vs_llm"]
    lines.append(f"\n**McNemar (exact, two-sided), raw LLM vs guarded:** "
                 f"discordant {a['discordant_raw_fail_guarded_pass']}/"
                 f"{a['discordant_raw_pass_guarded_fail']} → p = {a['p_value']:.2g}")
    lines.append(f"\n**McNemar (exact, two-sided), rules vs raw LLM:** "
                 f"discordant {b['discordant_rules_fail_llm_pass']}/"
                 f"{b['discordant_rules_pass_llm_fail']} → p = {b['p_value']:.2g}")
    lines.append("\n### Per dump\n")
    lines.append("| model | n | rules | llm | guarded |")
    lines.append("|---|---:|---:|---:|---:|")
    for e in res["per_dump"]:
        r_, l_, g_ = e["rules"], e["llm"], e["guarded"]
        lines.append(f"| {e.get('model', '?')} | {r_['n']} | {r_['x']} | {l_['x']} | {g_['x']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dumps", nargs="+",
                    help="run_benchmark results JSON paths/globs")
    ap.add_argument("--out", default=None,
                    help="write markdown here (default: print)")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    dumps = _load(args.dumps)
    if not dumps:
        print("no dumps with rows found", file=sys.stderr)
        return 1
    res = analyse(dumps)
    md = to_markdown(res)
    print(md)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(res, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    import sys  # noqa: E402
    raise SystemExit(main())
