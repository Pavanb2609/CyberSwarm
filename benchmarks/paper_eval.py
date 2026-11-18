#!/usr/bin/env python3
"""
paper_eval.py -- one command to produce every benchmark detail the paper needs.

It orchestrates the existing benchmarks, runs what the current machine supports,
and assembles paper-ready outputs under results/paper/:

  paper_results.json   everything, machine-readable
  summary.md           human summary + exactly what was skipped and why
  table3.md            Main benchmark results (manuscript Table 3)
  table4.md            Ablation results (manuscript Table 4)
  fig3.csv .. fig6.csv  tidy data for Figures 3-6

Design rule: never fabricate. A measurement that needs a resource this machine
lacks (an LLM backend, Docker, installed tools) is written as `SKIPPED` with the
reason and the exact command to run it later. Deterministic measurements (the
ground-truth lab, the rule planner, and the validation-layer ablation) run
offline and populate immediately.

Usage:
  python benchmarks/paper_eval.py                       # run everything available now
  python benchmarks/paper_eval.py --model qwen3:8b --base-url http://localhost:11434
  python benchmarks/paper_eval.py --xbow-repo ../validation-benchmarks
  python benchmarks/paper_eval.py --timing-target localhost   # time a lab e2e run
  python benchmarks/paper_eval.py --no-model                  # deterministic only
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OUT = ROOT / "results" / "paper"


def _skip(reason: str, command: str) -> Dict[str, Any]:
    return {"status": "SKIPPED", "reason": reason, "command": command}


def _ok(value: Any, source: str) -> Dict[str, Any]:
    return {"status": "ok", "value": value, "source": source}


# ── environment probes ───────────────────────────────────────────────────────

def _have_flask() -> bool:
    try:
        import flask  # noqa: F401
        return True
    except ImportError:
        return False


def _have_docker() -> bool:
    from shutil import which
    if not which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=10).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _model_reachable(backend: str, base_url: str, timeout: float = 3.0) -> bool:
    try:
        import requests
        from model_client import resolve_backend_url
        url = resolve_backend_url(base_url, backend, probe_timeout=timeout).rstrip("/")
        health = "/api/tags" if backend == "ollama" else "/v1/models"
        requests.get(url + health, timeout=timeout)
        return True
    except Exception:  # noqa: BLE001
        return False


# ── individual benchmarks ─────────────────────────────────────────────────────

def run_lab(have_flask: bool) -> Dict[str, Any]:
    cmd = "python benchmarks/lab_bench.py"
    if not have_flask:
        return _skip("flask not installed (pip install flask)", cmd)
    from benchmarks import lab_bench
    vuln = lab_bench.run_detection("vulnerable")
    ctrl = lab_bench.run_detection("control")
    truth = set(lab_bench.LAB_TRUTH)
    return _ok({
        "recall": round(len(truth & vuln.detected) / max(len(truth), 1), 3),
        "classes_detected": sorted(truth & vuln.detected),
        "classes_missed": sorted(truth - vuln.detected),
        "control_false_positives": ctrl.findings,
        "control_classes": sorted(ctrl.detected),
    }, cmd + " (detection mode, deterministic)")


def run_recon(model: Optional[str], backend: str, base_url: str,
              model_ok: bool) -> Dict[str, Any]:
    """Rule planner always; LLM/guarded + structured/prompt variants if a
    backend is reachable. run_benchmark returns llm/guarded/rules in one run."""
    import run_benchmark as rb
    out: Dict[str, Any] = {}
    rules = rb.run(rb.parse_args(["--rules-only", "--no-save"]))
    out["rules_full_pass"] = _ok(rules["rules"]["full_pass_rate"],
                                 "run_benchmark.py --rules-only (deterministic)")
    out["n_scenarios"] = rules["total_scenarios"]
    model_cmd = f"python run_benchmark.py --model {model} --base-url {base_url}"
    if not model_ok:
        for k in ("llm_full_pass", "guarded_full_pass", "valid_json_rate",
                  "no_structured_valid_json", "compact_full_pass"):
            out[k] = _skip("no LLM backend reachable", model_cmd)
        return out
    full = rb.run(rb.parse_args(["--model", model, "--backend", backend,
                                 "--base-url", base_url, "--no-save"]))
    out["llm_full_pass"] = _ok(full["llm"]["full_pass_rate"], model_cmd)
    out["guarded_full_pass"] = _ok(full["guarded"]["full_pass_rate"], model_cmd)
    out["valid_json_rate"] = _ok(full["llm"]["schema_valid_rate"], model_cmd)
    out["llm_confusion"] = full.get("llm_confusion", [])[:8]
    nostruct = rb.run(rb.parse_args(["--model", model, "--backend", backend,
                                     "--base-url", base_url, "--no-structured", "--no-save"]))
    out["no_structured_valid_json"] = _ok(nostruct["llm"]["schema_valid_rate"],
                                          model_cmd + " --no-structured")
    compact = rb.run(rb.parse_args(["--model", model, "--backend", backend,
                                    "--base-url", base_url, "--prompt", "compact", "--no-save"]))
    out["compact_full_pass"] = _ok(compact["guarded"]["full_pass_rate"],
                                   model_cmd + " --prompt compact")
    return out


def run_validation() -> Dict[str, Any]:
    from benchmarks import validation_ablation
    return _ok(validation_ablation.run(),
               "python benchmarks/validation_ablation.py (deterministic)")


def run_xbow(repo: Optional[str], have_docker: bool) -> Dict[str, Any]:
    cmd = "python benchmarks/xbow_bench.py --repo <xbow> --variant baseline --variant no-rag --variant no-difficulty"
    if not repo:
        return _skip("no --xbow-repo given", cmd)
    if not have_docker:
        return _skip("Docker not available", cmd)
    try:
        proc = subprocess.run([sys.executable, "benchmarks/xbow_bench.py", "--repo", repo],
                              cwd=str(ROOT), capture_output=True, text=True,
                              timeout=7200, errors="replace")
    except Exception as exc:  # noqa: BLE001
        return _skip(f"xbow run failed: {exc}", cmd)
    return _ok({"stdout_tail": (proc.stdout or "")[-2000:], "returncode": proc.returncode}, cmd)


def run_timing(target: Optional[str], model_ok: bool, have_flask: bool) -> Dict[str, Any]:
    cmd = "python benchmarks/lab_bench.py --mode e2e"
    if not target:
        return _skip("no --timing-target given", cmd)
    if not (model_ok and have_flask):
        return _skip("needs model backend + flask (+ installed tools)", cmd)
    from benchmarks import lab_bench
    t0 = time.time()
    res = lab_bench.run_e2e("vulnerable", timeout=3600, stamp=time.strftime("%Y%m%d_%H%M%S"))
    return _ok({"seconds": round(time.time() - t0, 1), "error": res.error}, cmd)


# ── assembly ──────────────────────────────────────────────────────────────────

def _cell(entry: Dict[str, Any]) -> str:
    if not isinstance(entry, dict):
        return str(entry)
    if entry.get("status") == "ok":
        return str(entry["value"])
    return "SKIPPED"


def build_tables(r: Dict[str, Any]) -> Dict[str, str]:
    lab, recon, val = r["lab"], r["recon"], r["validation"]
    lab_v = lab.get("value", {}) if lab.get("status") == "ok" else {}

    def pct(entry):
        return f"{entry['value']:.0%}" if isinstance(entry, dict) and entry.get("status") == "ok" \
            and isinstance(entry.get("value"), (int, float)) else "_[to run]_"

    t3 = ["## Table 3 — Main benchmark results", "",
          "| Metric | Setting | Result | Source |",
          "| --- | --- | --- | --- |",
          f"| Vulnerability-class recall | Ground-truth lab | {pct(lab) if lab.get('status')=='ok' else '_[to run]_'}"
          f"{(' ('+str(lab_v.get('recall'))+')') if False else ''} | lab_bench.py |"]
    if lab.get("status") == "ok":
        t3[-1] = (f"| Vulnerability-class recall | Ground-truth lab (4 classes) | "
                  f"**{lab_v['recall']:.0%}** | verified — lab_bench.py |")
        t3.append(f"| False positives | Clean control | **{lab_v['control_false_positives']}** "
                  f"| verified — lab_bench.py |")
    rules = recon.get("rules_full_pass", {})
    t3.append(f"| Recon full-pass (rules) | {recon.get('n_scenarios','?')} scenarios | "
              f"**{pct(rules)}** | verified — --rules-only |")
    for key, lbl in (("llm_full_pass", "Recon full-pass (LLM only)"),
                     ("guarded_full_pass", "Recon full-pass (guarded)"),
                     ("valid_json_rate", "Valid-JSON rate (constrained)")):
        e = recon.get(key, {})
        t3.append(f"| {lbl} | scenarios, model | {pct(e) if e.get('status')=='ok' else 'SKIPPED'} "
                  f"| {e.get('command','') if e.get('status')!='ok' else e.get('source','')} |")
    xb = r["xbow"]
    t3.append(f"| XBOW detection recall | XBOW suite | "
              f"{'see summary' if xb.get('status')=='ok' else 'SKIPPED'} | {xb.get('command', xb.get('source',''))} |")
    tm = r["timing"]
    t3.append(f"| Full-engagement time | reference host | "
              f"{tm['value']['seconds'] if tm.get('status')=='ok' else 'SKIPPED'}"
              f"{'s' if tm.get('status')=='ok' else ''} | {tm.get('command', tm.get('source',''))} |")

    t4 = ["## Table 4 — Ablation results", "",
          "### 4a. Validation layer (controlled candidate set, deterministic)", ""]
    if val.get("status") == "ok":
        from benchmarks import validation_ablation
        t4.append(validation_ablation.to_markdown(val["value"]).split("\n", 2)[2])
    t4 += ["", "### 4b. Planner mechanisms (from run_benchmark modes)", "",
           "| Configuration | Recon full-pass | Source |",
           "| --- | --- | --- |",
           f"| Full (LLM + guardrails + fallback) | {pct(recon.get('guarded_full_pass', {}))} | guarded mode |",
           f"| − Guardrails/fallback (LLM only) | {pct(recon.get('llm_full_pass', {}))} | llm mode |",
           f"| − LLM (rules only) | {pct(rules)} | rules mode |",
           f"| − Constrained decoding (valid-JSON) | {pct(recon.get('no_structured_valid_json', {}))} | --no-structured |",
           f"| Compact prompt (guarded) | {pct(recon.get('compact_full_pass', {}))} | --prompt compact |",
           "", "### 4c. Pipeline mechanisms (critic / evidence gate / RAG / difficulty)", "",
           "Run on the XBOW suite with the variant flags; requires Docker + model:",
           "`python benchmarks/xbow_bench.py --repo <xbow> --variant baseline --variant no-rag --variant no-difficulty`"]
    return {"table3.md": "\n".join(t3) + "\n", "table4.md": "\n".join(t4) + "\n"}


def build_figures(r: Dict[str, Any]) -> Dict[str, str]:
    lab = r["lab"].get("value", {}) if r["lab"].get("status") == "ok" else {}
    recon = r["recon"]

    def val(entry):
        return entry["value"] if isinstance(entry, dict) and entry.get("status") == "ok" else ""

    fig3 = ["setting,recall,false_positives,recon_full_pass",
            f"lab,{lab.get('recall','')},{lab.get('control_false_positives','')},",
            f"recon_rules,,,{val(recon.get('rules_full_pass', {}))}",
            f"recon_llm,,,{val(recon.get('llm_full_pass', {}))}",
            f"recon_guarded,,,{val(recon.get('guarded_full_pass', {}))}"]

    fig4 = ["config,precision,false_confirms,recall"]
    if r["validation"].get("status") == "ok":
        for row in r["validation"]["value"]["configs"]:
            fig4.append(f"{row['config']},{row['precision']},{row['false_confirms']},{row['recall']}")

    fig5 = ["variant,recon_full_pass,valid_json",
            f"full_guarded,{val(recon.get('guarded_full_pass', {}))},{val(recon.get('valid_json_rate', {}))}",
            f"no_guardrails_llm,{val(recon.get('llm_full_pass', {}))},{val(recon.get('valid_json_rate', {}))}",
            f"rules_only,{val(recon.get('rules_full_pass', {}))},1.0",
            f"no_constrained_decoding,,{val(recon.get('no_structured_valid_json', {}))}"]

    fig6 = ["configuration,runtime_seconds,quality_note"]
    if r["timing"].get("status") == "ok":
        fig6.append(f"lab_e2e,{r['timing']['value']['seconds']},see lab recall")

    return {"fig3.csv": "\n".join(fig3) + "\n", "fig4.csv": "\n".join(fig4) + "\n",
            "fig5.csv": "\n".join(fig5) + "\n", "fig6.csv": "\n".join(fig6) + "\n"}


def build_summary(r: Dict[str, Any]) -> str:
    done, skipped = [], []
    def walk(name, entry):
        if isinstance(entry, dict) and entry.get("status") == "ok":
            done.append(name)
        elif isinstance(entry, dict) and entry.get("status") == "SKIPPED":
            skipped.append((name, entry.get("reason", ""), entry.get("command", "")))
    walk("lab", r["lab"]); walk("validation", r["validation"])
    walk("xbow", r["xbow"]); walk("timing", r["timing"])
    for k, v in r["recon"].items():
        if isinstance(v, dict) and "status" in v:
            walk(f"recon.{k}", v)
    L = ["# Paper benchmark run — summary", "",
         f"Generated: {r['generated']}", "",
         f"**Produced now ({len(done)}):** " + ", ".join(done), ""]
    if skipped:
        L += ["**Still to run (need model / Docker / tools):**", ""]
        for name, reason, cmd in skipped:
            L.append(f"- `{name}` — {reason}: `{cmd}`")
    L += ["", "Numbers land in table3.md / table4.md and fig3-6.csv in this folder; "
          "re-run this script after the skipped resources are available to fill them."]
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Assemble all paper benchmark details")
    p.add_argument("--model", default="qwen3:8b")
    p.add_argument("--backend", default="ollama", choices=["ollama", "openai_compat"])
    p.add_argument("--base-url", default="http://localhost:11434")
    p.add_argument("--xbow-repo", default=None)
    p.add_argument("--timing-target", default=None)
    p.add_argument("--no-model", action="store_true", help="deterministic benchmarks only")
    p.add_argument("--out", default=str(OUT))
    a = p.parse_args(argv)

    have_flask, have_docker = _have_flask(), _have_docker()
    model_ok = (not a.no_model) and _model_reachable(a.backend, a.base_url)
    print(f"[paper_eval] flask={have_flask} docker={have_docker} model_reachable={model_ok}")

    r: Dict[str, Any] = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                         "environment": {"flask": have_flask, "docker": have_docker,
                                         "model_reachable": model_ok, "model": a.model}}
    print("[paper_eval] lab detection ..."); r["lab"] = run_lab(have_flask)
    print("[paper_eval] reconnaissance benchmark ..."); r["recon"] = run_recon(
        a.model, a.backend, a.base_url, model_ok)
    print("[paper_eval] validation ablation ..."); r["validation"] = run_validation()
    print("[paper_eval] xbow ..."); r["xbow"] = run_xbow(a.xbow_repo, have_docker)
    print("[paper_eval] timing ..."); r["timing"] = run_timing(a.timing_target, model_ok, have_flask)

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "paper_results.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
    for name, text in {**build_tables(r), **build_figures(r)}.items():
        (out / name).write_text(text, encoding="utf-8")
    (out / "summary.md").write_text(build_summary(r), encoding="utf-8")
    print(build_summary(r))
    print(f"[paper_eval] wrote -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
