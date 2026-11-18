#!/usr/bin/env python3
"""
Recon Planner benchmark runner.

Pipeline per scenario:
    evidence -> planner prompt -> model (structured JSON) -> validator
             -> [repair retry] -> guardrails -> compare vs expected labels

Three numbers are reported for every run, from the SAME model responses:

    llm        the model's own answer, no help        (what the old benchmark measured)
    guarded    model answer after planner_policy guardrails + rules fallback
               (what run_recon_loop.py actually executes)
    rules      the deterministic planner alone, no model (baseline / CI check)

Examples:
    python run_benchmark.py --backend ollama --model qwen3:8b
    python run_benchmark.py --backend ollama --model qwen3:30b --think
    python run_benchmark.py --prompt compact            # benchmark the 4 KB prompt
    python run_benchmark.py --rules-only                # no model needed
    python run_benchmark.py --only fresh_domain_no_assets --verbose
"""

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

import planner_policy
from model_client import ModelClient, chat_structured
from schema.validator import decision_json_schema, validate_decision

ROOT = Path(__file__).parent
PROMPTS = {"full": ROOT / "prompts" / "recon_planner.txt",
           "compact": ROOT / "prompts" / "recon_planner_compact.txt"}
SCENARIOS_PATH = ROOT / "scenarios" / "scenarios.json"
RESULTS_DIR = ROOT / "results" / "benchmarks"


def load_prompt(name: str = "full") -> str:
    return PROMPTS[name].read_text(encoding="utf-8")


def load_scenarios(path: Path = SCENARIOS_PATH) -> list:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _score(decision, sc) -> dict:
    if not decision:
        return {"profile": False, "capability": False, "pass": False}
    p = decision.get("target_profile") in sc["expected_profiles"]
    c = decision.get("next_capability") in sc["expected_capabilities"]
    return {"profile": p, "capability": c, "pass": p and c}


def _rate(n, total):
    return round(n / total, 3) if total else 0.0


def summarize(rows: list, key: str) -> dict:
    total = len(rows)
    valid = sum(1 for r in rows if r.get(key) and r[key].get("valid", True))
    return {
        "schema_valid_rate": _rate(valid, total),
        "profile_accuracy": _rate(sum(r[key]["score"]["profile"] for r in rows if r.get(key)), total),
        "capability_accuracy": _rate(sum(r[key]["score"]["capability"] for r in rows if r.get(key)), total),
        "full_pass_rate": _rate(sum(r[key]["score"]["pass"] for r in rows if r.get(key)), total),
    }


def confusion(rows: list, key: str) -> list:
    """(expected, got) capability pairs for failures, most common first."""
    c = Counter()
    for r in rows:
        res = r.get(key)
        if res and not res["score"]["capability"]:
            got = (res.get("decision") or {}).get("next_capability", "<invalid>")
            c[("|".join(r["expected_capabilities"]), got)] += 1
    return [{"expected": e, "got": g, "count": n} for (e, g), n in c.most_common()]


def run_scenario(client, system_prompt, sc, schema, retry=True):
    """One scenario through the full pipeline. Returns per-mode results."""
    evidence = sc["evidence"]
    user = json.dumps(evidence, indent=2)
    out = {"id": sc["id"], "description": sc.get("description", ""),
           "rule": sc.get("rule", ""),
           "expected_profiles": sc["expected_profiles"],
           "expected_capabilities": sc["expected_capabilities"]}

    rules = planner_policy.rules_decision(evidence)
    out["rules"] = {"decision": rules, "score": _score(rules, sc)}
    if client is None:
        return out

    raws, errors, llm, t0 = [], [], None, time.time()
    prompt = user
    for _attempt in range(2 if retry else 1):
        try:
            raw = chat_structured(client, system_prompt, prompt, json_schema=schema)
        except Exception as e:
            errors.append(f"model call failed: {e}")
            break
        raws.append(raw)
        ok, parsed, errs = validate_decision(raw)
        if ok:
            llm = parsed
            break
        errors.append(errs)
        prompt = (user + "\n\nYour previous reply was rejected: " + "; ".join(errs)
                  + "\nReturn ONLY the JSON object, using only the supported names.")
    elapsed = round(time.time() - t0, 2)

    first_ok = bool(raws) and validate_decision(raws[0])[0]
    # Record the decision the pipeline actually consumed (possibly the
    # repaired retry), with first-shot validity kept separately. Previously
    # repaired rows were recorded as decision=None/valid=False even though
    # the repaired decision drove the guardrails (llm_valid bug).
    out["llm"] = {"decision": llm, "valid": llm is not None,
                  "first_shot_valid": first_ok,
                  "score": _score(llm, sc)}
    if llm is None:
        guarded, corrections, fallback = rules, [], True
    else:
        guarded, corrections = planner_policy.apply_guardrails(evidence, llm)
        fallback = False
    out["guarded"] = {"decision": guarded, "valid": True, "score": _score(guarded, sc),
                      "corrections": corrections, "rules_fallback": fallback,
                      "repaired_by_retry": (not first_ok) and llm is not None}
    out["raw_responses"] = raws
    out["errors"] = errors
    out["elapsed_seconds"] = elapsed
    return out


def run(args):
    scenarios = load_scenarios(args.scenarios)
    if args.only:
        scenarios = [s for s in scenarios if s["id"] == args.only]
        if not scenarios:
            print(f"No scenario found with id={args.only}", file=sys.stderr)
            sys.exit(1)

    client = None
    if not args.rules_only:
        client = ModelClient(backend=args.backend, base_url=args.base_url, model=args.model,
                             api_key=args.api_key, temperature=args.temperature,
                             timeout=args.timeout, think=args.think,
                             structured_output=not args.no_structured)
    system_prompt = load_prompt(args.prompt)
    schema = decision_json_schema()

    rows = []
    for sc in scenarios:
        r = run_scenario(client, system_prompt, sc, schema, retry=not args.no_retry)
        rows.append(r)
        modes = ["rules"] if client is None else ["llm", "guarded"]
        marks = "  ".join(f"{m}={'PASS' if r[m]['score']['pass'] else 'FAIL'}" for m in modes)
        print(f"[{sc['id']}] {marks}" + (f"  ({r['elapsed_seconds']}s)" if client else ""))
        if args.verbose or not r[modes[-1]]["score"]["pass"]:
            for m in modes:
                d = r[m].get("decision") or {}
                print(f"    {m:8s} profile={d.get('target_profile')} cap={d.get('next_capability')}")
            print(f"    expected profile in {sc['expected_profiles']} cap in {sc['expected_capabilities']}")
            if client and r["guarded"]["corrections"]:
                print(f"    guardrail: {r['guarded']['corrections']}")
            if client and r.get("errors"):
                print(f"    errors: {r['errors']}")

    modes = ["rules"] if client is None else ["llm", "guarded", "rules"]
    summary = {"total_scenarios": len(rows), "prompt": args.prompt,
               "backend": None if client is None else args.backend,
               "model": None if client is None else args.model,
               "structured_output": None if client is None else not args.no_structured}
    for m in modes:
        summary[m] = summarize(rows, m)
    if client is not None:
        summary["guardrail_corrections"] = sum(bool(r["guarded"]["corrections"]) for r in rows)
        summary["rules_fallbacks"] = sum(r["guarded"]["rules_fallback"] for r in rows)
        summary["repaired_by_retry"] = sum(r["guarded"]["repaired_by_retry"] for r in rows)
        summary["avg_seconds"] = round(sum(r["elapsed_seconds"] for r in rows) / max(len(rows), 1), 2)

    print("\n" + "=" * 60 + "\nSUMMARY\n" + "=" * 60)
    print(f"  scenarios: {len(rows)}   prompt: {args.prompt}")
    print(f"  {'mode':10s}{'valid':>8s}{'profile':>10s}{'capab.':>9s}{'PASS':>8s}")
    for m in modes:
        s = summary[m]
        print(f"  {m:10s}{s['schema_valid_rate']:>8.1%}{s['profile_accuracy']:>10.1%}"
              f"{s['capability_accuracy']:>9.1%}{s['full_pass_rate']:>8.1%}")
    if client is not None:
        print(f"  guardrail corrections: {summary['guardrail_corrections']}   "
              f"rules fallbacks: {summary['rules_fallbacks']}   "
              f"fixed by retry: {summary['repaired_by_retry']}   avg {summary['avg_seconds']}s/scenario")
        conf = confusion(rows, "llm")
        if conf:
            print("\n  Most common LLM mistakes (expected -> got):")
            for c in conf[:8]:
                print(f"    {c['count']}x  {c['expected']}  ->  {c['got']}")
        summary["llm_confusion"] = conf
        summary["guarded_confusion"] = confusion(rows, "guarded")

    if not args.no_save:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        tag = "rules" if client is None else str(args.model).replace(":", "_").replace("/", "_")
        out_path = RESULTS_DIR / f"bench_{tag}_{args.prompt}_{int(time.time())}.json"
        out_path.write_text(json.dumps({"summary": summary, "results": rows}, indent=2),
                            encoding="utf-8")
        print(f"\nFull results written to: {out_path}")
    if args.min_pass is not None:
        key = "rules" if client is None else "guarded"
        if summary[key]["full_pass_rate"] < args.min_pass:
            print(f"FAIL: {key} pass rate {summary[key]['full_pass_rate']:.1%} < {args.min_pass:.0%}")
            sys.exit(2)
    return summary


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Run the Recon Planner benchmark")
    p.add_argument("--backend", choices=["ollama", "openai_compat"], default="ollama")
    p.add_argument("--base-url", default="http://localhost:11434")
    p.add_argument("--model", default="qwen3:8b")
    p.add_argument("--api-key", default=None)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--think", action="store_true", help="enable Qwen3 extended thinking")
    p.add_argument("--prompt", choices=sorted(PROMPTS), default="full",
                   help="which planner prompt to benchmark")
    p.add_argument("--scenarios", default=str(SCENARIOS_PATH))
    p.add_argument("--rules-only", action="store_true",
                   help="score the deterministic planner only (no model needed)")
    p.add_argument("--no-structured", action="store_true",
                   help="disable constrained JSON decoding (to measure its effect)")
    p.add_argument("--no-retry", action="store_true", help="disable the repair retry")
    p.add_argument("--no-save", action="store_true")
    p.add_argument("--min-pass", type=float, default=None,
                   help="exit 2 if the guarded (or rules) pass rate is below this, e.g. 0.75")
    p.add_argument("--only", default=None, help="run a single scenario by id")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args(argv)


if __name__ == "__main__":
    run(parse_args())
