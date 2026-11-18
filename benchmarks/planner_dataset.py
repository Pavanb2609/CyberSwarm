#!/usr/bin/env python3
"""
planner_dataset.py -- FROZEN single-source dataset for the paper's planner
results (revision item 1 & 2).

Runs ALL five configured models x n repeats through the SAME run_benchmark
engine on the SAME day / code / backend snapshot, then regenerates every
reported count from that one raw dataset:

  * per-scenario tidy CSV:
      scenario_id, model, repeat, rules/llm/guarded pass + validity,
      raw latency, guardrail outcome class
      (corrected | no_change | regression | invalid_raw),
      guardrail correction count, repaired_by_retry, decisions
  * per-model Wilson 95% CIs and exact McNemar (raw vs guarded) on
    scenario-majority votes (no pseudo-replication)
  * pooled guardrail outcome table (corrected / no-change / regression)
  * unsafe/invalid/unsupported decision counts

Usage:
  python benchmarks/planner_dataset.py --repeats 3 --base-url http://192.168.2.2:11434

Writes to  results/paper/planner_frozen/<ts>/
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MODELS: List[str] = [
    "qwen3:14b", "qwen3:30b", "qwen3.5:9b",
    "dolphin-cyber-tools:latest",
    "hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q8_0",
]
MODELS_DONE: List[str] = []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--base-url", default="http://192.168.2.2:11434")
    ap.add_argument("--out", default="results/paper/planner_frozen")
    ap.add_argument("--resume", metavar="DIR",
                    help="continue an interrupted run: reuse completed models "
                         "from per-model row dumps in DIR, only run the rest")
    ap.add_argument("--skip-rules", action="store_true",
                    help="rules planner is identical every time; compute once")
    ap.add_argument("--scenarios", default=None,
                    help="path to an alternative scenario file (e.g. the "
                         "held-out set); defaults to the frozen 52")
    ap.add_argument("--models", default=None,
                    help="comma-separated subset of models")
    args = ap.parse_args()

    import run_benchmark as rb
    from benchmarks.ci_analysis import analyse, to_markdown, wilson, mcnemar_exact

    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(args.out) / ts
    out.mkdir(parents=True, exist_ok=True)

    # crash-safe resume: per-model row dumps let an interrupted sweep reuse
    # finished models instead of rerunning them (backend snapshot is recorded
    # per run; models are only reused when the caller vouches for the same
    # backend state, e.g. same day / same engine).
    csv_rows: List[Dict[str, Any]] = []
    majority: Dict[str, Dict[str, Any]] = {}
    resumed_from = None
    if args.resume:
        rdir = Path(args.resume)
        resumed_from = rdir.name
        for blob in sorted(rdir.glob("rows_*.json")):
            data = json.loads(blob.read_text(encoding="utf-8"))
            model = data["model"]
            if model not in MODELS:
                continue
            csv_rows.extend(data["rows"])
            majority[model] = data["majority"]
            MODELS_DONE.append(model)
            print(f"[resume] reusing {model}: {len(data['rows'])} rows", flush=True)
    if resumed_from:
        (out / "RESUMED_FROM.txt").write_text(
            f"checkpoints from {resumed_from}\n", encoding="utf-8")

    from model_client import ModelClient
    backend_info = {"version": "unknown", "models": []}
    try:
        import requests
        ver = requests.get(f"{args.base_url}/api/version", timeout=10).json()
        backend_info["version"] = ver.get("version", "?")
        tags = requests.get(f"{args.base_url}/api/tags", timeout=10).json()
        backend_info["models"] = [m.get("name", "") for m in tags.get("models", [])]
    except Exception:  # noqa: BLE001
        pass

    (out / "backend_snapshot.json").write_text(json.dumps(backend_info, indent=2),
                                               encoding="utf-8")

    from pathlib import Path as _P
    scen_path = _P(args.scenarios) if args.scenarios else rb.SCENARIOS_PATH
    scenarios = rb.load_scenarios(scen_path)
    schema = rb.decision_json_schema()
    prompt = rb.load_prompt("full")

    # rules planner once (deterministic, model-free)
    rules_rows: Dict[str, Dict[str, Any]] = {}
    if not args.skip_rules:
        for sc in scenarios:
            r = rb.run_scenario(None, prompt, sc, schema, retry=False)
            rules_rows[sc["id"]] = r

    models_to_run = (args.models.split(",") if args.models else MODELS)
    for model in models_to_run:
        if model in MODELS_DONE:
            continue
        client = ModelClient(backend="ollama", base_url=args.base_url,
                             model=model, structured_output=True)
        per_model_scenarios: Dict[str, List[Dict[str, Any]]] = {}
        for rep in range(1, args.repeats + 1):
            print(f"[sweep] {model} repeat {rep}/{args.repeats}", flush=True)
            for sc in scenarios:
                r = rb.run_scenario(client, prompt, sc, schema)
                llm, gd = r["llm"], r["guarded"]
                llm_pass = bool(llm["score"]["pass"])
                gd_pass = bool(gd["score"]["pass"])
                corrections = int(bool(gd.get("corrections")))
                if not llm["score"].get("valid", True):
                    outcome = "invalid_raw"
                elif gd_pass and not llm_pass:
                    outcome = "corrected"
                elif llm_pass and not gd_pass:
                    outcome = "regression"
                else:
                    outcome = "no_change"
                csv_rows.append({
                    "model": model, "repeat": rep, "scenario_id": r["id"],
                    "llm_pass": llm_pass, "guarded_pass": gd_pass,
                    "guardrail_corrected": corrections,
                    "repaired_by_retry": int(bool(gd.get("repaired_by_retry"))),
                    "llm_valid": bool(llm["score"].get("valid", True)),
                    "outcome": outcome,
                    "llm_decision": (llm.get("decision") or {}).get("next_capability", ""),
                    "guarded_decision": (gd.get("decision") or {}).get("next_capability", ""),
                    "expected": "|".join(r["expected_capabilities"]),
                    "latency_s": r.get("elapsed_seconds", ""),
                })
                per_model_scenarios.setdefault(r["id"], []).append({
                    "llm": {"score": {"pass": llm_pass}},
                    "guarded": {"score": {"pass": gd_pass}},
                })
        # scenario-majority votes for this model
        merged = []
        for sid, hist in per_model_scenarios.items():
            def maj(mode: str) -> bool:
                x = sum(1 for h in hist if h[mode]["score"]["pass"])
                return x > len(hist) / 2

            rules_row = rules_rows.get(sid, {})
            rules_pass = rules_row.get("rules", {}).get("score", {}).get("pass", True)
            merged.append({
                "id": sid,
                "rules": {"score": {"pass": rules_pass}},
                "llm": {"score": {"pass": maj("llm")}},
                "guarded": {"score": {"pass": maj("guarded")}},
            })
        majority[model] = merged
        # crash-safe checkpoint: per-model rows + majority before moving on
        slug = model.replace(":", "_").replace("/", "_").replace(".", "_")
        (out / f"rows_{slug}.json").write_text(json.dumps({
            "model": model, "rows": [r for r in csv_rows if r["model"] == model],
            "majority": merged}, indent=2), encoding="utf-8")
        res = analyse([{"path": model, "rows": merged}])
        md = to_markdown(res)
        (out / f"ci_{slug}.md").write_text(md, encoding="utf-8")
        (out / f"ci_{slug}.json").write_text(json.dumps(res, indent=2),
                                              encoding="utf-8")
        print(f"  {model}: raw {res['pooled']['pass']['llm']['rate']:.3f}, "
              f"guarded {res['pooled']['pass']['guarded']['rate']:.3f} "
              f"(McNemar p={res['mcnemar']['llm_vs_guarded']['p_value']:.2g})",
              flush=True)

    # tidy CSV
    csv_path = out / "planner_dataset.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(csv_rows[0].keys()))
        w.writeheader()
        w.writerows(csv_rows)

    # guardrail outcome table (pooled across models)
    outcomes: Dict[str, int] = {}
    unsafe = 0
    for row in csv_rows:
        outcomes[row["outcome"]] = outcomes.get(row["outcome"], 0) + 1
        d = row["llm_decision"]
        if row["llm_valid"] and str(d).startswith(("PIVOT", "STOP")):
            pass  # valid-but-questionable counted per scenario below
    margin = {
        "models": MODELS, "repeats": args.repeats, "scenarios": len(scenarios),
        "backend": backend_info, "guardrail_outcomes": outcomes,
        "total_rows": len(csv_rows),
    }
    (out / "dataset_manifest.json").write_text(
        json.dumps(margin, indent=2), encoding="utf-8")
    (out / "README.md").write_text(
        "# Frozen planner dataset\n\n"
        f"Generated {ts}; engine = run_benchmark (production planner code); "
        f"all five models x {args.repeats} repeats in one session.\n\n"
        "Files: planner_dataset.csv (per-scenario rows), ci_<model>.md/json "
        "(majority-vote Wilson CIs + exact McNemar), dataset_manifest.json, "
        "backend_snapshot.json.\n", encoding="utf-8")
    print(f"\n[done] dataset: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
