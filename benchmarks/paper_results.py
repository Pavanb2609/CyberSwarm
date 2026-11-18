#!/usr/bin/env python3
"""
paper_results.py -- one command that produces every benchmark number the paper
needs, writes them to a single JSON, and renders the paper's tables (Table 3,
Table 4) and figure data (Figures 3-6) from whatever actually ran.

It is honest by construction: an experiment it cannot run on this machine
(no model backend, no Docker, missing tools) is recorded as
``{"status": "skipped", "reason": ...}`` rather than fabricated. The
deterministic experiments (lab detection, rule-planner accuracy) always run.

What it runs
------------
1. Lab detection     deterministic -- recall on the ground-truth lab (4 classes)
                     and false positives on the clean control. Needs only Flask.
2. Recon planning    the 52-scenario decision benchmark: rule planner (always),
                     and the LLM-only + guarded pipeline (if a model backend is
                     reachable), repeated for a mean +/- sd.
3. XBOW suite        detection recall/precision/F1 per ablation variant
                     (if --xbow-repo is given and Docker is present).
4. Efficiency        historical reference figures, plus a measured end-to-end
                     lab run when --time-e2e is set (needs backend + tools).

Usage
-----
    # deterministic only (no model, no Docker) -- reproducible anywhere
    python benchmarks/paper_results.py

    # full planner + lab, model reachable, 5 repeats for variance
    python benchmarks/paper_results.py --model qwen3:8b --repeats 5

    # add the XBOW detection + ablation study (needs Docker + the repo)
    python benchmarks/paper_results.py --model qwen3:8b --repeats 5 \\
        --xbow-repo ../validation-benchmarks

    # also time a real end-to-end lab engagement
    python benchmarks/paper_results.py --model qwen3:8b --time-e2e

Outputs (under results/paper/<timestamp>/)
    paper_results.json     every number, with status/reason per experiment
    table3_main.md         Table 3 (main benchmark results)
    table4_ablation.md     Table 4 (ablation + uncertainty)
    fig3_benchmark.csv     Figure 3 data (overall performance)
    fig4_critic.csv        Figure 4 data (critic/gate effectiveness)
    fig5_ablation.csv      Figure 5 data (ablation)
    fig6_efficiency.csv    Figure 6 data (performance vs runtime)
    SUMMARY.md             which cell each number fills; what is still to run
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Historical reference efficiency figures (reference host; re-confirm locally).
HISTORICAL_EFFICIENCY = [
    {"config": "full engagement", "metric": "wall-clock", "before_s": 12600, "after_s": 1020,
     "note": "approx 3.5 h -> 17 min on the reference host"},
    {"config": "web-attack stage", "metric": "wall-clock", "before_s": 3405, "after_s": 103,
     "note": "CDN-swallowed scanners skipped, remainder concurrent"},
    {"config": "cloud enumeration", "metric": "wall-clock", "before_s": 605, "after_s": 20,
     "note": "concurrent probing (approx 5-34 s observed)"},
]


def _skip(reason: str) -> dict[str, Any]:
    return {"status": "skipped", "reason": reason}


def _mean_sd(xs: list[float]) -> dict[str, float | None]:
    xs = [float(x) for x in xs if x is not None]
    if not xs:
        return {"mean": None, "sd": None, "n": 0, "values": []}
    return {"mean": round(statistics.fmean(xs), 4),
            "sd": round(statistics.stdev(xs), 4) if len(xs) > 1 else 0.0,
            "n": len(xs), "values": [round(x, 4) for x in xs]}


# ── environment probe ────────────────────────────────────────────────────────

def probe_env(backend: str, base_url: str | None) -> dict[str, Any]:
    info: dict[str, Any] = {}
    # model backend reachability
    try:
        import requests

        from model_client import resolve_backend_url
        url = resolve_backend_url(base_url, backend)
        health = "/v1/models" if backend == "openai_compat" else "/api/tags"
        requests.get(url.rstrip("/") + health, timeout=3)
        info["model_backend"] = {"reachable": True, "url": url, "backend": backend}
    except Exception as exc:
        info["model_backend"] = {"reachable": False, "error": str(exc)[:200]}
    # docker
    import shutil
    info["docker"] = shutil.which("docker") is not None
    # flask (needed for the lab)
    try:
        import flask  # noqa: F401
        info["flask"] = True
    except ImportError:
        info["flask"] = False
    # installed security tools
    try:
        from tools.preflight import run_preflight
        rep = run_preflight()
        info["tools"] = {"resolved": len(rep.resolved), "missing": len(rep.missing)}
    except Exception as exc:
        info["tools"] = {"error": str(exc)[:200]}
    return info


# ── 1. lab detection (deterministic) ──────────────────────────────────────────

def bench_lab(repeats: int, env: dict[str, Any]) -> dict[str, Any]:
    if not env.get("flask"):
        return _skip("flask not installed (pip install flask)")
    from benchmarks import lab_bench
    recalls, fps, detected_sets = [], [], []
    for _ in range(max(1, repeats)):
        vuln = lab_bench.run_detection("vulnerable")
        ctrl = lab_bench.run_detection("control")
        if vuln.error:
            return _skip(f"lab run error: {vuln.error}")
        hit = vuln.expected & vuln.detected
        recalls.append(len(hit) / max(len(vuln.expected), 1))
        fps.append(ctrl.findings)
        detected_sets.append(sorted(vuln.detected))
    truth = sorted(lab_bench.LAB_TRUTH)
    return {"status": "ok", "truth_classes": truth,
            "recall": _mean_sd(recalls), "false_positives": _mean_sd(fps),
            "detected_last": detected_sets[-1],
            "missed_last": sorted(set(truth) - set(detected_sets[-1]))}


# ── 2. recon planner ───────────────────────────────────────────────────────────

def _recon_once(argv: list[str]) -> dict[str, Any]:
    import run_benchmark
    return run_benchmark.run(run_benchmark.parse_args(argv))


def bench_recon(model: str, backend: str, base_url: str | None,
                repeats: int, structured: bool, env: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    # rule planner -- deterministic, always
    rules = _recon_once(["--rules-only", "--no-save"])
    out["rules"] = {"status": "ok", "full_pass": rules["rules"]["full_pass_rate"],
                    "profile_acc": rules["rules"]["profile_accuracy"],
                    "capability_acc": rules["rules"]["capability_accuracy"],
                    "scenarios": rules["total_scenarios"]}
    # model-dependent -- llm + guarded
    if not env.get("model_backend", {}).get("reachable"):
        out["llm"] = out["guarded"] = _skip("model backend not reachable")
        return out
    base = ["--model", model, "--backend", backend, "--no-save"]
    if base_url:
        base += ["--base-url", base_url]
    if not structured:
        base += ["--no-structured"]
    llm_fp, guarded_fp, valid, corrections, fallbacks, repaired, secs = ([] for _ in range(7))
    last = None
    for _ in range(max(1, repeats)):
        s = _recon_once(base)
        last = s
        llm_fp.append(s["llm"]["full_pass_rate"])
        guarded_fp.append(s["guarded"]["full_pass_rate"])
        valid.append(s["llm"]["schema_valid_rate"])
        corrections.append(s.get("guardrail_corrections"))
        fallbacks.append(s.get("rules_fallbacks"))
        repaired.append(s.get("repaired_by_retry"))
        secs.append(s.get("avg_seconds"))
    out["llm"] = {"status": "ok", "full_pass": _mean_sd(llm_fp),
                  "valid_json": _mean_sd(valid),
                  "profile_acc": last["llm"]["profile_accuracy"],
                  "capability_acc": last["llm"]["capability_accuracy"]}
    out["guarded"] = {"status": "ok", "full_pass": _mean_sd(guarded_fp),
                      "guardrail_corrections": _mean_sd([c for c in corrections if c is not None]),
                      "rules_fallbacks": _mean_sd([f for f in fallbacks if f is not None]),
                      "repaired_by_retry": _mean_sd([r for r in repaired if r is not None]),
                      "avg_seconds": _mean_sd([x for x in secs if x is not None])}
    out["model"] = model
    out["structured_output"] = structured
    out["llm_confusion"] = last.get("llm_confusion", [])[:8]
    return out


# ── 3. XBOW detection + ablation ───────────────────────────────────────────────

DEFAULT_XBOW_VARIANTS = ["baseline", "no-llm-planner", "no-rag", "minimal"]


def bench_xbow(repo: str | None, variants: list[str], timeout: int,
               limit: int, env: dict[str, Any]) -> dict[str, Any]:
    if not repo:
        return _skip("no --xbow-repo given")
    if not env.get("docker"):
        return _skip("docker not installed")
    from benchmarks import scoring, xbow_bench
    repo_path = Path(repo).expanduser()
    benches = xbow_bench.load_benchmarks(repo_path)
    if not benches:
        return _skip(f"no benchmarks under {repo}")
    if limit:
        benches = benches[:limit]
    docker = xbow_bench.DockerRunner()
    if not docker.available():
        return _skip("docker not available to compose")
    out: dict[str, Any] = {"status": "ok", "benchmarks": len(benches), "variants": {}}
    for variant in variants:
        results = []
        for bench in benches:
            try:
                results.append(xbow_bench.run_one(bench, ROOT, docker, timeout, variant))
            except Exception as exc:
                results.append(scoring.score_benchmark(bench["id"], bench["tags"], [],
                                                        bench.get("level", ""), error=str(exc)[:200]))
        out["variants"][variant] = scoring.aggregate(results).to_dict()
    return out


# ── 4. efficiency ──────────────────────────────────────────────────────────────

def bench_efficiency(time_e2e: bool, env: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"historical": HISTORICAL_EFFICIENCY}
    if not time_e2e:
        out["measured_e2e"] = _skip("--time-e2e not set")
        return out
    if not (env.get("flask") and env.get("model_backend", {}).get("reachable")):
        out["measured_e2e"] = _skip("need flask + a reachable model backend")
        return out
    from benchmarks import lab_bench
    stamp = time.strftime("%Y%m%d_%H%M%S")
    t0 = time.time()
    res = lab_bench.run_e2e("vulnerable", timeout=3600, stamp=stamp)
    out["measured_e2e"] = {"status": "ok", "seconds": round(time.time() - t0, 1),
                           "error": res.error or "", "detected": sorted(res.detected)}
    return out


# ── rendering: tables, figures, summary ────────────────────────────────────────

def _fp_cell(ms: dict[str, Any]) -> str:
    if not ms or ms.get("mean") is None:
        return "_[to run]_"
    return f"{ms['mean']:.0%}" + (f" ± {ms['sd']:.0%}" if ms.get("n", 0) > 1 else "")


def render_table3(data: dict[str, Any]) -> str:
    lab, recon, xbow = data["lab"], data["recon"], data["xbow"]
    rows = [("Vulnerability-class recall", "Ground-truth lab (4 classes)",
             _fp_cell(lab.get("recall")) if lab.get("status") == "ok" else "_[skipped]_",
             "lab_bench.py (deterministic)"),
            ("False positives", "Clean control",
             (f"{lab['false_positives']['mean']:.1f}" if lab.get("status") == "ok" else "_[skipped]_"),
             "lab_bench.py (deterministic)"),
            ("Recon full-pass (rules)", "52 scenarios",
             (f"{recon['rules']['full_pass']:.0%}" if recon.get("rules", {}).get("status") == "ok" else "_[skipped]_"),
             "run_benchmark.py --rules-only"),
            ("Recon full-pass (LLM only)", "52 scenarios",
             _fp_cell(recon.get("llm", {}).get("full_pass")) if recon.get("llm", {}).get("status") == "ok" else "_[to run]_",
             "run_benchmark.py --model"),
            ("Recon full-pass (guarded)", "52 scenarios",
             _fp_cell(recon.get("guarded", {}).get("full_pass")) if recon.get("guarded", {}).get("status") == "ok" else "_[to run]_",
             "run_benchmark.py --model"),
            ("Valid-JSON rate (constrained)", "52 scenarios",
             _fp_cell(recon.get("llm", {}).get("valid_json")) if recon.get("llm", {}).get("status") == "ok" else "_[to run]_",
             "run_benchmark.py --model")]
    if xbow.get("status") == "ok":
        base = xbow["variants"].get("baseline", {})
        rows.append(("XBOW detection recall", f"XBOW ({xbow['benchmarks']})",
                     f"{base.get('recall', 0):.0%}", "xbow_bench.py"))
    else:
        rows.append(("XBOW detection recall", "XBOW suite", "_[to run]_",
                     f"xbow_bench.py ({xbow.get('reason', 'not run')})"))
    lines = ["| Metric | Setting | Result | Source |", "| --- | --- | --- | --- |"]
    lines += [f"| {m} | {s} | {r} | {src} |" for m, s, r, src in rows]
    return "# Table 3. Main benchmark results\n\n" + "\n".join(lines) + "\n"


def render_table4(data: dict[str, Any]) -> str:
    xbow = data["xbow"]
    lines = ["| Configuration | Recall | Precision | FP/bench | Solved | Notes |",
             "| --- | --- | --- | --- | --- | --- |"]
    if xbow.get("status") == "ok":
        for variant, agg in xbow["variants"].items():
            lines.append(f"| {variant} | {agg['recall']:.0%} | {agg['precision']:.0%} | "
                         f"{agg['false_positives_per_benchmark']} | "
                         f"{agg['solved']}/{agg['scored']} | {agg['errored']} errored |")
    else:
        for variant in DEFAULT_XBOW_VARIANTS:
            lines.append(f"| {variant} | _[to run]_ | _[to run]_ | _[to run]_ | _[to run]_ | "
                         f"{xbow.get('reason', 'not run')} |")
    return "# Table 4. Ablation results and uncertainty\n\n" + "\n".join(lines) + "\n"


def _write_csv(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def render_figures(data: dict[str, Any], out: Path) -> None:
    lab, recon, xbow, eff = data["lab"], data["recon"], data["xbow"], data["efficiency"]

    def mean_or(ms, default="NA"):
        return ms["mean"] if ms and ms.get("mean") is not None else default

    # Figure 3 -- overall benchmark performance
    f3 = [["lab_recall", "lab",
           mean_or(lab.get("recall")) if lab.get("status") == "ok" else "NA", "verified"],
          ["control_false_positives", "control",
           mean_or(lab.get("false_positives")) if lab.get("status") == "ok" else "NA", "verified"],
          ["recon_full_pass", "rules",
           recon.get("rules", {}).get("full_pass", "NA"), "verified"],
          ["recon_full_pass", "llm",
           mean_or(recon.get("llm", {}).get("full_pass")) if recon.get("llm", {}).get("status") == "ok" else "NA", "measured"],
          ["recon_full_pass", "guarded",
           mean_or(recon.get("guarded", {}).get("full_pass")) if recon.get("guarded", {}).get("status") == "ok" else "NA", "measured"]]
    if xbow.get("status") == "ok":
        f3.append(["xbow_recall", "baseline", xbow["variants"].get("baseline", {}).get("recall", "NA"), "measured"])
    _write_csv(out / "fig3_benchmark.csv", ["metric", "setting", "value", "status"], f3)

    # Figure 4 -- critic/gate effectiveness (from xbow baseline vs minimal, proxy for mechanisms off)
    f4 = []
    if xbow.get("status") == "ok":
        for variant in ("baseline", "minimal"):
            agg = xbow["variants"].get(variant)
            if agg:
                f4.append([variant, agg["precision"], agg["false_positives_per_benchmark"], agg["recall"]])
    else:
        f4.append(["baseline", "NA", "NA", "NA"])
        f4.append(["mechanisms-off", "NA", "NA", "NA"])
    _write_csv(out / "fig4_critic.csv", ["configuration", "precision", "fp_per_bench", "recall"], f4)

    # Figure 5 -- ablation
    f5 = []
    if xbow.get("status") == "ok":
        for variant, agg in xbow["variants"].items():
            f5.append([variant, agg["recall"], agg["precision"], agg["false_positives_per_benchmark"], agg["solve_rate"]])
    else:
        for variant in DEFAULT_XBOW_VARIANTS:
            f5.append([variant, "NA", "NA", "NA", "NA"])
    _write_csv(out / "fig5_ablation.csv", ["variant", "recall", "precision", "fp_per_bench", "solve_rate"], f5)

    # Figure 6 -- efficiency
    f6 = [[e["config"], e["before_s"], e["after_s"],
           round(e["before_s"] / e["after_s"], 1), "historical"] for e in eff["historical"]]
    m = eff.get("measured_e2e", {})
    if m.get("status") == "ok":
        f6.append(["measured e2e lab", "NA", m["seconds"], "NA", "measured"])
    _write_csv(out / "fig6_efficiency.csv", ["config", "before_s", "after_s", "speedup_x", "status"], f6)


def render_summary(data: dict[str, Any]) -> str:
    L = ["# Paper results -- what ran and where each number goes", "",
         f"Generated: {data['generated_at']}", "",
         "## Environment", "```json", json.dumps(data["env"], indent=2), "```", "",
         "## Status", ""]
    status = [("Lab detection (Fig 3, Table 3)", data["lab"].get("status", "?")),
              ("Recon rules (Table 3)", data["recon"].get("rules", {}).get("status", "?")),
              ("Recon LLM/guarded (Table 3, Fig 3)", data["recon"].get("llm", {}).get("status", "?")),
              ("XBOW + ablation (Tables 3-4, Figs 4-5)", data["xbow"].get("status", "?")),
              ("Efficiency measured (Fig 6)", data["efficiency"].get("measured_e2e", {}).get("status", "?"))]
    for name, st in status:
        mark = "done" if st == "ok" else st
        L.append(f"- {name}: **{mark}**")
    L += ["", "## To complete the remaining cells, run:", "",
          "```bash",
          "# model-dependent recon rates (Table 3, Fig 3)",
          "python benchmarks/paper_results.py --model qwen3:8b --repeats 5",
          "# XBOW detection + ablation (Tables 3-4, Figs 4-5) -- needs Docker + repo",
          "python benchmarks/paper_results.py --model qwen3:8b --xbow-repo ../validation-benchmarks",
          "# measured end-to-end efficiency (Fig 6)",
          "python benchmarks/paper_results.py --model qwen3:8b --time-e2e",
          "```"]
    return "\n".join(L) + "\n"


# ── driver ─────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Produce all paper benchmark results")
    p.add_argument("--model", default="qwen3:8b")
    p.add_argument("--backend", default="ollama", choices=["ollama", "openai_compat"])
    p.add_argument("--base-url", default=None)
    p.add_argument("--repeats", type=int, default=1, help="repeats for variance (recon/lab)")
    p.add_argument("--no-structured", action="store_true", help="disable constrained JSON decoding")
    p.add_argument("--skip-model", action="store_true", help="force-skip model-dependent recon")
    p.add_argument("--xbow-repo", default=None, help="path to validation-benchmarks checkout")
    p.add_argument("--xbow-variant", action="append", default=None,
                   help="xbow ablation variant (repeatable); default: a standard set")
    p.add_argument("--xbow-timeout", type=int, default=1800)
    p.add_argument("--xbow-limit", type=int, default=0, help="first N benchmarks only")
    p.add_argument("--time-e2e", action="store_true", help="time a real end-to-end lab run")
    p.add_argument("--out", default="results/paper")
    a = p.parse_args(argv)

    env = probe_env(a.backend, a.base_url)
    if a.skip_model:
        env["model_backend"] = {"reachable": False, "error": "skipped by --skip-model"}

    print("[paper] environment:", json.dumps(env))
    print("[paper] 1/4 lab detection ...")
    lab = bench_lab(a.repeats, env)
    print("[paper] 2/4 recon planner ...")
    recon = bench_recon(a.model, a.backend, a.base_url, a.repeats, not a.no_structured, env)
    print("[paper] 3/4 XBOW + ablation ...")
    xbow = bench_xbow(a.xbow_repo, a.xbow_variant or DEFAULT_XBOW_VARIANTS,
                      a.xbow_timeout, a.xbow_limit, env)
    print("[paper] 4/4 efficiency ...")
    eff = bench_efficiency(a.time_e2e, env)

    data = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "env": env,
            "lab": lab, "recon": recon, "xbow": xbow, "efficiency": eff}

    stamp = time.strftime("%Y%m%d_%H%M%S")
    out = ROOT / a.out / stamp
    out.mkdir(parents=True, exist_ok=True)
    (out / "paper_results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    (out / "table3_main.md").write_text(render_table3(data), encoding="utf-8")
    (out / "table4_ablation.md").write_text(render_table4(data), encoding="utf-8")
    render_figures(data, out)
    (out / "SUMMARY.md").write_text(render_summary(data), encoding="utf-8")

    print("\n" + render_summary(data))
    print(f"[paper] wrote tables, figure CSVs and JSON to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
