#!/usr/bin/env python3
"""
validation_ablation.py -- controlled, deterministic ablation of the validation
layer (critic confidence floor + evidence gate).

Figure 4 / the critic rows of the ablation table ask: how many findings each
configuration reports as confirmed, and how many of those are false confirms?
Measuring this on live targets would require a model and the critic/gate
toggles wired through the whole pipeline. Instead this module exercises the
*real* validation functions (the 40/60 blend and CONFIRM floor from
`confidence.py`, and the captured-evidence predicate) over a fixed, documented
set of candidate findings with known ground truth. It is a mechanism ablation
with stated inputs, not a measurement on real targets, and it needs no model,
no network, and no external tools, so it reproduces exactly on any machine.

The candidate set (see CANDIDATES) mixes:
  * true findings backed by captured tool output (should be confirmed/proven);
  * plausible but unproven model-written assertions with no captured output
    (should NOT be confirmed) -- the classic autonomous-pentest false positive.

Configurations compared:
  producer_only   accept on the producing agent's confidence alone
  critic_only     apply the 40/60 critic blend + CONFIRM floor
  evidence_only   confirm only when captured evidence is present
  full            both (the deployed CyberSwarm behaviour)

Reported per configuration: confirmed, true_confirms, false_confirms,
missed (true findings not confirmed), precision, recall.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from confidence import CONFIRM_FLOOR, blend_agent_critic, to_unit  # noqa: E402

# A fixed, documented candidate set. `truth` is the ground truth (is this a
# real vulnerability?); `evidence` is whether captured tool output backs it;
# `agent`/`critic` are confidences on 0-1. The unproven rows model what an
# over-eager generator emits: high agent confidence, low critic score, no
# captured evidence.
CANDIDATES: List[Dict[str, Any]] = [
    {"name": "Reflected XSS proven to execute", "truth": True, "evidence": True,
     "agent": 0.90, "critic": 0.92},
    {"name": "SQL injection (error-based) confirmed", "truth": True, "evidence": True,
     "agent": 0.85, "critic": 0.88},
    {"name": "SSTI truth marker evaluated", "truth": True, "evidence": True,
     "agent": 0.80, "critic": 0.85},
    {"name": "LFI: /etc/passwd contents returned", "truth": True, "evidence": True,
     "agent": 0.88, "critic": 0.90},
    {"name": "Publicly listable storage bucket (listing captured)", "truth": True,
     "evidence": True, "agent": 0.80, "critic": 0.78},
    {"name": "Reflected XSS (scanner claim, no proof)", "truth": False, "evidence": False,
     "agent": 0.75, "critic": 0.20},
    {"name": "SQL injection (tool found no vulnerability)", "truth": False, "evidence": False,
     "agent": 0.70, "critic": 0.15},
    {"name": "Missing security header -> clickjacking (301 redirect only)", "truth": False,
     "evidence": False, "agent": 0.65, "critic": 0.25},
    {"name": "No obvious insecure-design flaws (model note)", "truth": False, "evidence": False,
     "agent": 0.60, "critic": 0.30},
    {"name": "Publicly listable bucket (asserted, no listing)", "truth": False,
     "evidence": False, "agent": 0.75, "critic": 0.35},
]

CONFIGS = ("producer_only", "critic_only", "evidence_only", "full")
_PRODUCER_THRESHOLD = 0.5  # a naive generator confirms above this


def _confirms(cand: Dict[str, Any], config: str) -> bool:
    """Does this configuration report the candidate as confirmed?"""
    blended = blend_agent_critic(cand["agent"], cand["critic"])
    agent_ok = to_unit(cand["agent"]) >= _PRODUCER_THRESHOLD
    critic_ok = blended >= CONFIRM_FLOOR
    evidence_ok = bool(cand["evidence"])
    if config == "producer_only":
        return agent_ok
    if config == "critic_only":
        return critic_ok
    if config == "evidence_only":
        return evidence_ok
    if config == "full":
        return critic_ok and evidence_ok
    raise ValueError(config)


def score_config(config: str, candidates: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    cands = candidates if candidates is not None else CANDIDATES
    n_true = sum(1 for c in cands if c["truth"])
    confirmed = [c for c in cands if _confirms(c, config)]
    true_confirms = sum(1 for c in confirmed if c["truth"])
    false_confirms = sum(1 for c in confirmed if not c["truth"])
    missed = n_true - true_confirms
    precision = round(true_confirms / len(confirmed), 3) if confirmed else 1.0
    recall = round(true_confirms / n_true, 3) if n_true else 0.0
    return {"config": config, "confirmed": len(confirmed),
            "true_confirms": true_confirms, "false_confirms": false_confirms,
            "missed": missed, "precision": precision, "recall": recall}


def run(candidates: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    cands = candidates if candidates is not None else CANDIDATES
    rows = [score_config(cfg, cands) for cfg in CONFIGS]
    return {"n_candidates": len(cands),
            "n_true": sum(1 for c in cands if c["truth"]),
            "n_false": sum(1 for c in cands if not c["truth"]),
            "producer_threshold": _PRODUCER_THRESHOLD,
            "confirm_floor": CONFIRM_FLOOR,
            "configs": rows}


def to_markdown(result: Dict[str, Any]) -> str:
    L = ["# Validation-layer ablation (controlled candidate set)", "",
         f"Fixed candidate set: {result['n_true']} true findings "
         f"(evidence-backed) + {result['n_false']} unproven assertions. "
         f"Confirm floor {result['confirm_floor']}; producer threshold "
         f"{result['producer_threshold']}.", "",
         "| Configuration | Confirmed | True | False confirms | Missed | Precision | Recall |",
         "| --- | --- | --- | --- | --- | --- | --- |"]
    label = {"producer_only": "Producer confidence only", "critic_only": "+ Critic blend/floor",
             "evidence_only": "+ Evidence gate", "full": "Full (critic + evidence)"}
    for r in result["configs"]:
        L.append(f"| {label[r['config']]} | {r['confirmed']} | {r['true_confirms']} | "
                 f"{r['false_confirms']} | {r['missed']} | {r['precision']:.0%} | {r['recall']:.0%} |")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    import json
    res = run()
    print(to_markdown(res))
    print(json.dumps(res))
