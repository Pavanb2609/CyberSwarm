#!/usr/bin/env python3
"""profile_capture.py -- per-model profile/capability accuracy, latency and
prompt-token counts with FULL decisions persisted (Section 5.1 regeneration).

The frozen planner CSV persisted only the capability string, so profile
accuracy and prompt_eval_count were not recoverable offline. This rerun (one
pass per model, 52 scenarios, temperature 0, num_ctx 4096 -- the Ollama
default the frozen runs used) talks to the Ollama API directly so the complete
decision dict -- including target_profile -- plus prompt/eval token counts are
captured per decision.

Freeze: produced under freeze-2 code but with num_ctx pinned to the frozen
4096 default, so decoding conditions match freeze-1. Disclose as a rerun.

Usage: python benchmarks/profile_capture.py [--models m1,m2] [--base-url URL]
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import run_benchmark as rb  # noqa: E402

MODELS = ["qwen3:14b", "qwen3:30b", "qwen3.5:9b",
          "dolphin-cyber-tools:latest",
          "hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q8_0"]


def one_call(base_url: str, model: str, system_prompt: str, user: str,
             schema: dict) -> tuple[str | None, float, int | None, int | None]:
    """One deterministic structured call; returns (raw, latency, prompt_eval, eval)."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "think": False,
        "format": schema,
        "options": {"temperature": 0.0, "num_ctx": 4096},
    }
    t0 = time.time()
    resp = requests.post(f"{base_url}/api/chat", json=payload, timeout=600)
    resp.raise_for_status()
    data = resp.json()
    latency = time.time() - t0
    raw = data.get("message", {}).get("content")
    usage = {k: data.get(k) for k in ("prompt_eval_count", "eval_count")}
    return raw, latency, usage["prompt_eval_count"], usage["eval_count"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://192.168.2.2:11434")
    ap.add_argument("--models", default=None, help="comma-separated subset")
    ap.add_argument("--out", default="results/paper/profile_capture")
    args = ap.parse_args()

    models = args.models.split(",") if args.models else MODELS
    scenarios = rb.load_scenarios(rb.SCENARIOS_PATH)
    schema = rb.decision_json_schema()
    system_prompt = rb.load_prompt("full")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(args.out) / ts
    out.mkdir(parents=True, exist_ok=True)

    for model in models:
        rows = []
        for sc in scenarios:
            user = json.dumps(sc["evidence"], indent=2)
            raw, lat, pe, ec = one_call(args.base_url, model, system_prompt,
                                        user, schema)
            ok, parsed, errs = rb.validate_decision(raw)
            dec = parsed if ok else {}
            prof = dec.get("target_profile")
            cap = dec.get("next_capability")
            rows.append({
                "scenario_id": sc["id"],
                "expected_profiles": sc["expected_profiles"],
                "expected_capabilities": sc["expected_capabilities"],
                "target_profile": prof,
                "next_capability": cap,
                "profile_match": bool(prof in sc["expected_profiles"]),
                "capability_match": bool(cap in sc["expected_capabilities"]),
                "valid": ok,
                "latency_s": round(lat, 3),
                "prompt_eval_count": pe,
                "eval_count": ec,
            })
            print(f"[{model}] {sc['id']}: profile={rows[-1]['profile_match']} "
                  f"cap={rows[-1]['capability_match']} valid={ok} "
                  f"prompt_eval={pe}", flush=True)
        n = len(rows)
        summary = {
            "model": model, "n": n,
            "profile_acc": round(sum(r["profile_match"] for r in rows) / n, 3),
            "capability_acc": round(sum(r["capability_match"] for r in rows) / n, 3),
            "valid_json": round(sum(r["valid"] for r in rows) / n, 3),
            "latency_mean_s": round(statistics.fmean(r["latency_s"] for r in rows), 2),
            "latency_sd_s": round(statistics.stdev(r["latency_s"] for r in rows), 2),
            "prompt_eval_max": max((r["prompt_eval_count"] for r in rows
                                    if isinstance(r["prompt_eval_count"], int)),
                                   default=None),
            "prompt_eval_mean": round(statistics.fmean(
                r["prompt_eval_count"] for r in rows
                if isinstance(r["prompt_eval_count"], int)), 1),
        }
        safe = model.replace("/", "_").replace(":", "_")
        (out / f"decisions_{safe}.json").write_text(
            json.dumps({"model": model, "summary": summary, "rows": rows},
                       indent=2), encoding="utf-8")
        print(f"[done] {model}: profile {summary['profile_acc']}, "
              f"capability {summary['capability_acc']}, "
              f"valid {summary['valid_json']}, latency "
              f"{summary['latency_mean_s']}s, max prompt_eval "
              f"{summary['prompt_eval_max']}", flush=True)
    print(f"[all done] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
