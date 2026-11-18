#!/usr/bin/env python3
"""paper_figures.py — generate the Section 5 figures from frozen datasets.

Outputs PDF + PNG into results/paper/figures/, plus tidy CSVs (the paper
draft's figure sources). Re-run after new data lands (e.g. the XBOW matrix
rerun) to refresh F6/S1.

  F1  planner accuracy per model, raw vs guarded, majority level + Wilson CIs
  F2  guardrail correction rule breakdown (117 firings)
  F3  lab v2 per-class detection recall (+ hardened control = 0)
  F4  e2e per-class hit rate across repeats (+ per-run duration)
  F5  critic three-arm probe: false confirms / true confirmed
  F6  XBOW per-variant solved + false-positive tags (regenerate post-rerun)
  S1  per-model planner latency distributions (supplementary)
"""

from __future__ import annotations

import csv
import glob
import json
import math
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results/paper/figures"
OUT.mkdir(parents=True, exist_ok=True)

MODELS = ["qwen3:14b", "qwen3:30b", "qwen3.5:9b",
          "hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q8_0",
          "dolphin-cyber-tools:latest"]
SHORT = {"qwen3:14b": "qwen3:14b", "qwen3:30b": "qwen3:30b",
         "qwen3.5:9b": "qwen3.5:9b",
         "hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q8_0": "Dolphin-8B\nGGUF",
         "dolphin-cyber-tools:latest": "dolphin-cyber\ntools"}
C_RAW, C_GUARDED = "#bbbbbb", "#2b6cb0"


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def save(fig, name):
    fig.savefig(OUT / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(OUT / f"{name}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("wrote", name)


def f1_planner_accuracy():
    labels, raw, guarded, raw_ci, gua_ci = [], [], [], [], []
    for m in MODELS:
        safe = m.replace("/", "_").replace(":", "_").replace(".", "_")
        d = json.load(open(ROOT / f"results/paper/planner_frozen/20261103_035619/rows_{safe}.json"))
        maj = {x["id"]: x for x in d["majority"]}
        r = sum(1 for x in maj.values() if x["llm"]["score"]["pass"])
        g = sum(1 for x in maj.values() if x["guarded"]["score"]["pass"])
        labels.append(SHORT[m]); raw.append(r / 52); guarded.append(g / 52)
        raw_ci.append(wilson(r, 52)); gua_ci.append(wilson(g, 52))
    rows = [("model", "raw_rate", "raw_lo", "raw_hi", "guarded_rate", "guarded_lo", "guarded_hi")]
    for lb, r, g, rc, gc in zip(labels, raw, guarded, raw_ci, gua_ci):
        rows.append((lb.replace("\n", " "), f"{r:.3f}", f"{rc[0]:.3f}", f"{rc[1]:.3f}",
                     f"{g:.3f}", f"{gc[0]:.3f}", f"{gc[1]:.3f}"))
    with open(OUT / "fig1_planner_accuracy.csv", "w", newline="") as f:
        csv.writer(f).writerows(rows)

    x = range(len(labels))
    fig, ax = plt.subplots(figsize=(7, 3.6))
    ax.bar([i - 0.2 for i in x], raw, 0.38, yerr=[[r - c[0] for r, c in zip(raw, raw_ci)],
           [c[1] - r for r, c in zip(raw, raw_ci)]], label="raw LLM", color=C_RAW)
    ax.bar([i + 0.2 for i in x], guarded, 0.38,
           yerr=[[g - c[0] for g, c in zip(guarded, gua_ci)],
                 [c[1] - g for g, c in zip(guarded, gua_ci)]],
           label="guarded", color=C_GUARDED)
    ax.set_xticks(list(x), labels); ax.set_ylim(0, 1)
    ax.set_ylabel("scenario-majority pass rate")
    ax.legend(frameon=False)
    save(fig, "fig1_planner_accuracy")


def f2_correction_rules():
    rules = [("no-repeat", 46), ("scope-unknown", 18), ("profile-sanity", 18),
             ("mandatory-before-STOP", 15), ("out-of-scope", 11),
             ("arch-evidence", 6), ("pivot-exhausted", 3)]
    labels = [r[0] for r in rules][::-1]
    vals = [r[1] for r in rules][::-1]
    with open(OUT / "fig2_correction_rules.csv", "w", newline="") as f:
        csv.writer(f).writerows([("rule", "firings")] + list(rules))
    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.barh(labels, vals, color=C_GUARDED)
    ax.set_xlabel("guardrail firings (117 corrections over 780 decisions)")
    save(fig, "fig2_correction_rules")


def f3_lab_detection():
    d = json.load(open(ROOT / "results/benchmarks/lab_20261105_043904.json"))
    per = d["detail"]["vulnerable"]["per_endpoint"]
    cls = {}
    for e in per:
        cls[e["expected"]] = cls.get(e["expected"], [0, 0])
        cls[e["expected"]][0] += 1 if e["hit"] else 0
        cls[e["expected"]][1] += 1
    labels = sorted(cls) + ["control\n(hardened)"]
    hits = [cls[k][0] for k in sorted(cls)] + [0]
    totals = [cls[k][1] for k in sorted(cls)] + [3]
    with open(OUT / "fig3_lab_detection.csv", "w", newline="") as f:
        csv.writer(f).writerows(
            [("class", "hit", "total")] + [(k, cls[k][0], cls[k][1]) for k in sorted(cls)]
            + [("control", 0, 0)])
    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    bars = ax.bar(labels, hits, color=C_GUARDED)
    for b, h, t in zip(bars, hits, totals):
        ax.text(b.get_x() + b.get_width() / 2, 0.08, f"{h}/{t}", ha="center",
                color="white", fontweight="bold")
    ax.set_ylabel("instances detected"); ax.set_ylim(0, 3.6)
    save(fig, "fig3_lab_detection")


def f4_e2e():
    agg = json.load(open(ROOT / "results/paper/e2e_repeats/20261104_031744/e2e_repeats.json"))
    runs = agg["runs"]
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.2))
    classes = ["lfi", "xss", "sqli", "ssti"]
    hits = [sum(1 for r in runs if c in (r.get("detected_classes") or []))
            for c in classes]
    with open(OUT / "fig4_e2e.csv", "w", newline="") as f:
        csv.writer(f).writerows([("class", "hits", "repeats")] + list(zip(classes, hits, [len(runs)] * 4)))
    axes[0].bar(classes, hits, color=C_GUARDED)
    axes[0].set_ylim(0, len(runs) + 0.4)
    axes[0].set_ylabel("repeats with class detected")
    durs = [r.get("duration_s") for r in runs if r.get("duration_s")]
    axes[1].bar([str(i + 1) for i in range(len(durs))], durs, color=C_RAW)
    axes[1].set_ylabel("vulnerable-run duration (s)")
    axes[1].set_xlabel("repeat")
    save(fig, "fig4_e2e")


def f5_probe():
    d = json.load(open(sorted(glob.glob(str(ROOT / "results/paper/critic_false_confirm/*/false_confirm.json")))[-1]))
    arms = [a for a in d["arms"]]
    labels = {"deployed": "deployed\n(gate + batch)",
              "batch_no_gate": "batch,\ngate off",
              "critic_only": "critic-only\n(different prompt)"}
    names = [labels.get(a.get("arm"), a.get("arm")) for a in arms]
    false_cf = [a["false_confirms"] for a in arms]
    true_cf = [a["true_confirmed"] for a in arms]
    with open(OUT / "fig5_probe.csv", "w", newline="") as f:
        csv.writer(f).writerows([("arm", "false_confirms", "true_confirmed")]
                                + [(a.get("arm"), a["false_confirms"], a["true_confirmed"]) for a in arms])
    x = range(len(arms))
    fig, ax = plt.subplots(figsize=(6, 3.4))
    ax.bar([i - 0.2 for i in x], false_cf, 0.38, label="false confirms (/12)", color="#c53030")
    ax.bar([i + 0.2 for i in x], true_cf, 0.38, label="true confirmed (/8)", color=C_GUARDED)
    ax.set_xticks(list(x), names); ax.legend(frameon=False)
    ax.set_ylim(0, 13)
    save(fig, "fig5_critic_probe")


def f6_xbow():
    rows = [("variant", "solved", "fp_tags")]
    labels, solved, fps = [], [], []
    for v in ["baseline", "no-difficulty", "no-rag", "no-llm-planner", "no-guardrails"]:
        p = ROOT / f"results/xbow/matrix/{v}.rescored.json"
        if not p.exists():
            p = ROOT / f"results/xbow/matrix/{v}.json"
        if not p.exists():
            continue
        runs = json.load(open(p))
        s = sum(1 for r in runs if r.get("solved"))
        fp = sum(len(r.get("false_positives") or []) for r in runs)
        labels.append(v); solved.append(s); fps.append(fp)
        rows.append((v, s, fp))
    if not labels:
        print("F6 skipped: no matrix data"); return
    with open(OUT / "fig6_xbow.csv", "w", newline="") as f:
        csv.writer(f).writerows(rows)
    x = range(len(labels))
    fig, ax = plt.subplots(figsize=(7, 3.4))
    ax.bar([i - 0.2 for i in x], solved, 0.38, label="benchmarks solved (/27)", color=C_GUARDED)
    ax.bar([i + 0.2 for i in x], fps, 0.38, label="false-positive class tags", color="#c53030")
    ax.set_xticks(list(x), [l.replace("-", "\n") for l in labels])
    ax.legend(frameon=False)
    save(fig, "fig6_xbow_variants")


def s1_latency():
    lat = {}
    for r in csv.DictReader(open(ROOT / "results/paper/planner_frozen/20261103_035619/planner_dataset.csv")):
        lat.setdefault(r["model"], []).append(float(r["latency_s"]))
    order = [m for m in MODELS if m in lat]
    data = [lat[m] for m in order]
    with open(OUT / "s1_latency.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["model", "latency_s"])
        for m, vals in zip(order, data):
            for v in vals:
                w.writerow((m, v))
    fig, ax = plt.subplots(figsize=(7, 3.2))
    ax.boxplot(data, tick_labels=[SHORT[m] for m in order], showfliers=False)
    ax.set_ylabel("planner decision latency (s)")
    save(fig, "s1_latency")


if __name__ == "__main__":
    f1_planner_accuracy()
    f2_correction_rules()
    f3_lab_detection()
    f4_e2e()
    f5_probe()
    f6_xbow()
    s1_latency()
    print("figures in", OUT)
