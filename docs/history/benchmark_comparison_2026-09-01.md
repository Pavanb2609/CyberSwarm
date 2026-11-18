# CyberSwarm Model Benchmark Comparison

**Date:** 2026-09-01
**Test:** Phase 1 Recon Planner benchmark (15 scenarios, strict JSON validation)

## Setup

| Server | IP | Models |
|--------|-----|--------|
| Host (laptop) | 192.168.0.66 | qwen3:8b, qwen3:14b |
| GPU box | 192.168.1.223 | qwen3:30b |

## Result Summary

| Metric | qwen3:8b | qwen3:30b (no think) | qwen3:30b (--think) |
|--------|---------|----------------------|---------------------|
| Avg time per call | **13.4s** | 18.0s | 21.0s |
| Valid JSON rate | **100%** | 46.7% | 86.7% |
| Profile accuracy | 73.3% | 40.0% | **86.7%** |
| Capability accuracy | **53.3%** | 13.3% | 26.7% |
| Full pass rate | **53.3%** | 13.3% | 26.7% |

## Speed: qwen3:8b wins
The 8B is the fastest (13.4s/call). The 30B without think is ~34% slower
(18s); with --think it's ~57% slower (21s), because it generates reason
tokens. If raw speed is the priority, 8b is the clear choice.

## Reliability (valid JSON): 8b wins, but --think fixes the 30B
The 30B without think only produced valid JSON 47% of the time. With
`--think` that jumps to **86.7%** -- so the output-formatting problem is
largely fixed by extended thinking. The 8B still leads at 100%.

## Accuracy: --think makes the 30B smarter on profiles
With --think, the 30B's **profile accuracy hits 86.7%**, beating the 8B's
73.3%. So on correctly classifying the target, the bigger model now wins.

**However:** the 30B (with or without think) keeps forcing `TLS_ANALYSIS`
on any scenario with an open 443 port, ignoring the expected capability.
That's why its capability accuracy stays low (26.7% vs the 8B's 53.3%).
So even when it parses fine, it makes the *wrong procedural choice*.

---

## The Problem (from my side, in plain terms)

Common sense says: bigger model = better, so my instinct was to move
you up to the 30B. But the benchmark completely flipped that.

The 30B is a **MoE (Mixture-of-Experts)** model -- a different
architecture from the dense 8B. And it's clearly struggling with one
specific thing: **following the strict JSON output format**. Most of the
time it doesn't return parseable JSON at all, so all that extra brainpower
is wasted. Size doesn't matter if the model can't hand back its answer in
the exact box we require.

So this isn't really "8B is smarter than 30B." It's that the 30B, as it
stands right now, fails at the *formatting* the pipeline depends on. If we
fixed that, the 30B would very likely give better reasoning quality.

## Verdict

| Goal | Best model |
|------|-----------|
| **Fastest results** | qwen3:8b (host, 192.168.0.66) |
| Best reliability (valid JSON) | qwen3:8b |
| Best target classification | qwen3:30b with --think (86.7% profiles) |
| Best full pass rate | qwen3:8b (53.3%) |

**For speed now:** stick with **qwen3:8b** at `http://192.168.0.66:11434`.
It's the fastest and most reliable end-to-end.

**If you want the 30B's sharper classification:** run it with `--think`.
It fixes the JSON parsing (47% -> 87%) and lifts profile accuracy above the
8B. The remaining blocker is its forced-`TLS_ANALYSIS` behavior lowering
capability score -- that's a prompt/logic issue, not a model-size one.

**Bottom line:** speed = 8b. Smarter classification = 30b with --think
(if you can tolerate the slower 21s/call and the TLS_ANALYSIS quirk).
