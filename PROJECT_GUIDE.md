# CyberSwarm — Complete Project Guide

A self-hosted, multi-agent offensive security framework. **Phase 1** (recon)
discovers a target's attack surface, **Phase 2** (attack) uses a team of LLM
agents to test that surface, and every finding is reviewed by a skeptical
"Critic" agent before it becomes a confirmed vulnerability.

> This guide explains: (1) everything we have done so far, (2) how the whole
> pipeline works, and (3) what every file in the project does.
>
> Sections 1 and 9 describe the August 2026 state. For what changed since, see
> [CHANGELOG.md](CHANGELOG.md); for current commands, see [README.md](README.md).
> The recon planner is now wrapped by `planner_policy.py` (guardrails + rules
> fallback) -- see the README's "Measuring it" section.

---

## Table of Contents

1. [What we have done so far](#1-what-we-have-done-so-far)
2. [Setup: model backend (Ollama on Windows + GPU)](#2-setup-model-backend)
3. [How the whole pipeline works](#3-how-the-whole-pipeline-works)
4. [Phase 1 — Recon loop](#4-phase-1--recon-loop)
5. [SystemMap — the shared target model](#5-systemmap--the-shared-target-model)
6. [Phase 2 — Multi-agent attack loop](#6-phase-2--multi-agent-attack-loop)
7. [File-by-file reference](#7-file-by-file-reference)
8. [Key improvements & why they matter](#8-key-improvements--why-they-matter)
9. [Validation results on the test target](#9-validation-results)
10. [How to run everything](#10-how-to-run-everything)
11. [Testing](#11-testing)
12. [Extending: add a tool or an agent](#12-extending-add-a-tool-or-an-agent)
13. [Cross-engagement RAG memory](#13-cross-engagement-rag-memory)
14. [Engagement phases & quality gates](#14-engagement-phases--quality-gates)
15. [Run modes & pause policy](#15-run-modes--pause-policy)
16. [Prompts](#16-prompts)
17. [Built-in help](#17-built-in-help)
18. [Asking in plain English](#18-asking-in-plain-english)

---

## 1. What we have done so far

This project started as two separate "phase" codebases and was merged into one
working pipeline. Then, in this session, we optimized it for the user's actual
hardware and made the results dramatically faster and more trustworthy:

| # | Change | Result |
|---|--------|--------|
| 1 | **Switched the default model to `qwen3:8b`** (fits the 6 GB GPU). The 14b model ran CPU-only at ~4–5 tok/s. | ~4.5× faster inference (18.7 tok/s), full run dropped from **3.5 hours → ~17 minutes** |
| 2 | **Split models per role** in `config.yaml` (`model`, `model_critic`, `model_planner`, `model_deep`). | The critic (bulk of LLM calls) and planner stay fast; you can keep the deep analysis model heavier |
| 3 | **Batched CriticAgent** (`review_batch`) — the critic reviews **all** of an agent's findings in **one LLM call** instead of one call per finding. | Critic LLM calls dropped from ~30 per run to ~6 |
| 4 | **Critic confirms on evidence.** The review prompt now treats live response evidence (HTTP 401/403, a publicly listable bucket, an explicit header/status) as sufficient proof. | Went from **0 confirmed vulnerabilities to real confirmed counts** |
| 5 | **Aggregated repeated findings** in the Auth and API agents (e.g. 18 auth findings → 6 grouped findings, each carrying the full path list + raw evidence). | Fewer, higher-quality findings; the critic can CONFIRM each one |
| 6 | **WAF/CDN-aware `web_attack` agent.** It detects Cloudflare/Akamai/etc. in the SystemMap and **skips nikto + feroxbuster** (a CDN swallows their results), keeping nuclei + corsy. Tools run **concurrently** (4 workers). | web_attack dropped from **3405s → 103s** |
| 7 | **Planner attack graph built once** and reused on the first loop iteration. | Saves one full planner LLM call per target |
| 8 | **S3 bucket enumeration** — a new read-only `s3_enum` tool that lists a publicly-listable bucket over the REST API (max-keys=1000, pure Python). | Produced a concrete, critic-`CONFIRM`ed **HIGH** finding with real object counts |
| 9 | **Fixed a `cloud_enum` regression** (a bad kwarg silently made it produce zero cloud assets). | Cloud agent now runs `cloud_enum` → `s3_enum` and surfaces the bucket |
| 10 | **`run.sh` rewritten** as an explicit 4-phase pipeline (recon → map → attack → report), reads the model/backend from `config.yaml`, checks backend reachability, and **saves the report** to `results/reports/`. | One command runs the entire engagement end-to-end |
| 11 | **Manual Verification Checklist** added to the report — a table of exact URLs/endpoints (confirmed, critic-disputed, needs-proof, recon surfaces). | A human knows exactly where to check every finding |
| 12 | **All model references updated to `qwen3:8b`** across every script, docstring, README, and skill file. | No part of the system silently tries to load the 14b model |
| 13 | **Cross-agent finding dedup** (`MemoryAgent` + report). Same issue from two agents (e.g. "Missing Security Header: Referrer-Policy" reported by both `web_attack` and `infra`) is now stored/rendered once. | No inflated vulnerability counts or risk ratings |
| 14 | **`cloud_enum` made concurrent** (8 workers, 3s/request instead of 6s sequential). | cloud agent: 605 s → ~5 s of probing |
| 15 | **S3 proof of exposure.** `s3_enum` now does read-only HEAD on up to 2 sample keys; if downloadable, the finding becomes "Publicly listable + downloadable S3 bucket" with content-type/size evidence. | Stronger HIGH finding, easier critic CONFIRM |
| 16 | **Replan on more triggers.** Besides HIGH/CRITICAL confirmed findings, any newly surfaced `API:`/`AUTH:` path re-prioritizes the api/auth agents mid-run (capped at 4 replans). | Deeper follow-on probing without a full restart |

---

## 2. Setup: model backend

The system is split across two machines:

```
┌─────────────────────────┐        ┌──────────────────────────┐
│  Ubuntu VM (this repo)  │  HTTP  │  Windows host (model)    │
│  runs the whole pipeline│ ─────► │  Ollama + NVIDIA 6GB GPU │
│                         │ 11434  │  serves qwen3:8b         │
└─────────────────────────┘        └──────────────────────────┘
```

On the Windows host, we ran (PowerShell):

```powershell
ollama pull qwen3:8b
setx OLLAMA_NUM_GPU 999    # push all layers to the GPU
setx OLLAMA_HOST "0.0.0.0:11434"   # listen on the LAN
# restart Ollama afterwards
```

The VM talks to it at `http://192.168.0.66:11434`. Everything is configured in
`config.yaml`:

```yaml
model:
  backend: ollama
  model: qwen3:8b            # default model (fits 6GB GPU)
  model_critic: qwen3:8b     # fast model for verdict batching
  model_planner: qwen3:8b    # fast model for attack-graph planning
  model_deep: qwen3:8b       # set qwen3:14b to trade speed for depth
  base_url: http://192.168.0.66:11434
```

Because the 14b model does not fit in 6 GB VRAM it fell back to CPU and ran at
~4–5 tok/s. `qwen3:8b` fits the GPU and runs at ~18.7 tok/s — about **4.5×
faster** for a small quality trade-off.

---

## 3. How the whole pipeline works

`run.sh` runs four stages (`bin/cyberswarm` commands):

```
run.sh <target>
 │
 ├─[1/4]  recon   → Phase 1: all 26 recon capabilities run by run_recon_loop.py
 │                    (evidence → planner → capability → engine → tool → evidence)
 │
 ├─[2/4]  map     → build_system_map.py turns flat evidence into a SystemMap
 │                    (structured model: services, tech, paths, signals, links)
 │
 ├─[3/4]  attack  → run_agent_loop.py: the multi-agent Phase 2
 │                    PlannerAgent builds an AttackGraph (built once)
 │                    → specialist agents run (web_attack/api/auth/infra/cloud)
 │                    → WAF/CDN-aware skipping + concurrent tools
 │                    → batched CriticAgent (1 LLM call per agent)
 │                    → MemoryAgent (only CONFIRMED findings = vulnerabilities)
 │                    → replan on significant findings → intelligence enrichment
 │
 └─[4/4]  report  → generate_attack_report.py renders results/reports/<target>.md
                     (vulns + risk rating + Manual Verification Checklist)
```

### The two "evidence" files
- `results/evidence/<target>.json` — Phase 1 recon evidence (from `evidence_store.py`)
- `results/system_map/<target>.json` — the SystemMap built from that evidence
- `results/attack_evidence/<target>.json` — Phase 2 attack memory (vulnerabilities,
  disputed findings, proof requests, agent runs)

---

## 4. Phase 1 — Recon loop

`run_recon_loop.py` implements the loop:

```
evidence → PlannerAgent (LLM) → capability (e.g. "PORT_DISCOVERY")
        → [human approval gate] → recon_engine runs the tool
        → results merged into evidence → repeat
```

- The planner outputs a *capability*, never a tool name. `tools/registry.py`
  maps each capability to the best installed tool (preference order).
- `--run-all` runs all **26 capabilities** in a fixed logical order
  (passive asset discovery → subdomain discovery → DNS → ports → services →
  web probing → tech → crawling → content → params → API → CMS → TLS …).
- It stops when the planner returns a terminal capability
  (`STOP_NO_RELEVANT_ACTION`, `BLOCK_EXECUTION`), requests evidence the engine
  can't provide, a human rejects a step, or `max_iterations` is hit.
- All LLM decisions are validated against `schema/` enums/validators before use.

---

## 5. SystemMap — the shared target model

**Central idea: one model, many agents.** Phase 1 produces flat evidence; the
SystemMap turns it into a structured, relational model every later phase reads
and extends.

Key fields:
- `assets` — resolved IP, reachability, subdomains + resolutions
- `services` — `[{port, proto, service, version, ssl}]`
- `technologies` — `[{name, version, source}]`
- `web_surfaces` — `[{url, host, ports, tech, title, status, headers}]`
- `endpoints` / `parameters` / `auth_paths` / `api_paths` / `js_endpoints` / `historical_urls`
- `signals` — CMS, cloud, AD, container, IoT, API types (used by planner rules)
- `posture` — TLS findings, weak ciphers, missing security headers, response headers
- `links` — a graph of relationships between assets (recon ↔ finding ↔ vulnerability)

Helpers: `compress_for_llm()` (small JSON for prompt budgets),
`derive_attack_surface()` (which agents should run, in what priority),
`add_link()` (agents annotate the map as they confirm findings).

---

## 6. Phase 2 — Multi-agent attack loop

`run_agent_loop.py` is the product core. Per target:

### 6.1 PlannerAgent (hybrid)
1. **Rules first** — `derive_attack_surface()` produces a valid deterministic
   graph (which agents apply, with priority + skip flags, from recon signals).
2. **LLM refines** — one call to reorder/justify/skip nodes; output is
   sanitized (only known agent names, priorities clamped 1–10).
3. Graph is **built once** and reused for the first loop iteration (saves a
   planner call). IntelligenceAgent is always queued last.
4. **Replan** — if a confirmed finding is HIGH/CRITICAL, the planner injects
   and re-prioritizes (e.g. new API endpoints un-skip the api agent).

### 6.2 The agents
| Agent | File | Owned tools | Runs when |
|-------|------|-------------|-----------|
| `web_attack` | `web_attack_agent.py` | nuclei, nikto, dalfox, sqlmap, feroxbuster, corsy | web surface present |
| `network` | `specialists.py` | nmap_nse, smb_enum, ldap_enum | non-web ports open |
| `api` | `specialists.py` | api_probe, api_discover, arjun | API paths discovered |
| `auth` | `specialists.py` | auth_probe | auth paths discovered |
| `infra` | `specialists.py` | testssl, tls_analysis, header_analysis, dns_enum | web surface / TLS issues |
| `cloud` | `specialists.py` | cloud_enum, container_probe, **s3_enum** | cloud/container signals |
| `intelligence` | `intelligence_agent.py` | (HTTP APIs) | always last |
| `exploitation` | `exploitation_agent.py` | nuclei, sqlmap, dalfox | validates HIGH/CRITICAL findings |

Each agent: reasons over the SystemMap (LLM call, optional) → selects targets →
runs ≥1 tool → analyzes output (LLM call) → emits `AgentResult` with
confidence-scored `AgentFinding`s. **Every agent has a deterministic fallback**
so it still works if the LLM is down.

### 6.3 WAF/CDN-aware `web_attack` (what we added)
`detect_waf_cdn()` matches `CDN_WAF_MARKERS` (Cloudflare `cf-ray`, Akamai,
CloudFront, Fastly, Varnish, …) against SystemMap tech + web surface tech +
response headers. When found:

```
[waf] CDN/WAF detected (Cloudflare) — skipping nikto + feroxbuster (CDN swallows
      them) for time saving; keeping nuclei + corsy.
```

Tools are then run in a `ThreadPoolExecutor(max_workers=4)` — a 3405 s agent
became **103 s**.

### 6.4 CriticAgent — the adversarial reviewer
- **Before (slow):** one LLM call per finding → ~30 calls/run.
- **After (batch):** `review_batch()` sends all of an agent's findings in
  **one call**, each with an `index` the model must echo back. On a malformed
  or partial batch, missing findings fall back to per-finding review — no
  finding is ever lost to a JSON parse failure.
- Verdict protocol: `CONFIRM` / `DISPUTE` / `NEEDS_PROOF`.
- **CONFIRM rules (added):** live response evidence directly proves the claim —
  an HTTP 401/403 (auth IS enforced), a publicly listable bucket
  (`publicly_listable: true`), an explicit header/status that *is* the finding.
  This is what changed "0 confirmed" into real confirmed counts.
- `final_confidence = agent_confidence × 0.4 + critic_score × 0.6`.
- If the model backend is unreachable → conservative `NEEDS_PROOF` fallback.

### 6.5 Aggregated findings (Auth/API agents)
Instead of 18 near-identical findings, the Auth agent now emits **grouped**
findings with the full path list and raw probe evidence:

```
name = "Session cookies missing security flags (4 paths)"
description = "Live Set-Cookie on 4 auth path(s) lacks: secure, samesite. Paths: ..."
evidence_chain = ["https://.../login -> missing secure, samesite", ...]
raw_output_excerpt = "<the actual HTTP probe JSON>"
```

The critic reviews ~4–6 findings per agent instead of ~30 total, and the raw
evidence lets it say `CONFIRM` with confidence.

### 6.6 MemoryAgent
Pure logic, no LLM:
- **Only Critic-confirmed findings** become `vulnerabilities`.
- Disputed findings are kept in `disputed_findings` for audit.
- `NEEDS_PROOF` becomes a human `proof_requests` entry.
- Computes `risk_rating` (highest severity present).
- Updates the SystemMap links (`sm.add_link`) for confirmed findings.

### 6.7 Human approval gate
After each agent, unless `--auto-approve`, the console shows the result and
asks: send to Critic? reject? skip? (Also an authorization prompt for unknown
targets — type `YES` or pass `--force`/`--auto-approve`.)

---

## 7. File-by-file reference

### Entry points
| File | Purpose |
|------|---------|
| `bin/cyberswarm` | Console entry point — just imports `cli.main()`. |
| `cli.py` | The `cyberswarm` CLI: subcommands `recon`, `map`, `attack`, `full`, `report`, `tools`. Merges `config.yaml` defaults (`_merge`) so CLI flags win over config. `cmd_attack` passes the loaded config into `run_attack`. |
| `run.sh` | One-command end-to-end launcher: [1/4] recon `--run-all`, [2/4] `map`, [3/4] `attack --auto-approve --reset-memory`, [4/4] `report --out results/reports/<target>.md`. Reads `model`/`base_url` from `config.yaml`, curls the backend for a reachability warning. |
| `run_all_target.sh` | Helper that writes a ready-to-run recon command into `results/<target>/run.txt`. |

### Model layer
| File | Purpose |
|------|---------|
| `config.yaml` | All defaults: `model` (backend/model/base_url + per-role models), `pipeline` (max_agents, pivots, llm_planner), `recon`, `attack`, `report`, `rag`. |
| `rag_memory.py` | Cross-engagement lesson store (SQLite + FTS5/BM25). Indexes `results/`, retrieves top-k lessons for the planner. Degrades to a no-op when disabled or unbuilt. |
| `scripts/rag_index.py` | CLI for the RAG index: rebuild, `--list`, `--stats`, `--query`, `--smap`. |
| `phases.py` | Engagement phase model (DISCOVERY -> REPORTING) with entry gates over collected evidence. |
| `scripts/phase_ctl.py` | CLI for phase status, `--advance`, `--set`, `--force`, `--history`. |
| `modes.py` | Run modes (auto/guided/free) and pause policy (never/always/checkpoint). |
| `prompt_library.py` | Loads reusable prompts from `prompts/` (markdown + YAML frontmatter). |
| `scripts/prompt.py` | CLI to list, render and run prompts. |
| `help_text.py` | Built-in help, generated from the live registries. |
| `ask.py` | Resolves a plain-English request to one registered capability or agent. |
| `skills/pentestcode/` | Imported MIT skill pack (see its `ATTRIBUTION.md`). |
| `model_client.py` | `ModelClient` dataclass — the single HTTP client for the LLM. Supports `ollama` (`POST /api/chat`, sends `think: false`, `num_predict`, temperature) and `openai_compat` (`/v1/chat/completions`). Retries, timeout, default `model="qwen3:8b"`. |

### Phase 1 (recon)
| File | Purpose |
|------|---------|
| `run_recon_loop.py` | The Phase-1 loop (evidence → planner → capability → gate → engine → tool). `--run-all` executes all 26 capabilities in `CAPABILITY_EXECUTION_ORDER`. |
| `recon_engine.py` | Executes capabilities via the tool registry, merges structured results into evidence. |
| `evidence_store.py` | Persists accumulated recon evidence to `results/evidence/<target>.json`. Has a self-healing fallback: if the file is corrupt/empty it reconstructs the richest snapshot from `results/decision_log.jsonl`. |
| `approval_gate.py` | Human approval for each recon capability (or auto-approve). |
| `schema/enums.py`, `schema/validator.py` | Validators for planner decisions (capability enums, JSON shapes). |

### SystemMap
| File | Purpose |
|------|---------|
| `system_map.py` | The shared target model + helpers: `build_from_evidence`, `save_map`/`load_map`, `compress_for_llm`, `derive_attack_surface`, `add_link`, signal heuristics (cloud/AD/container/IoT/API/auth path hints). |
| `build_system_map.py` | CLI + `build_for()` that turns evidence into a map and prints the derived attack surface. |

### Phase 2 (attack)
| File | Purpose |
|------|---------|
| `run_agent_loop.py` | The orchestrator: loads config, builds role clients, planner/critic/memory, runs agents from the (reused) attack graph, approval gate, batch critic, memory store, replan on significant findings, pivot queue, intelligence post-processing, summary. |
| `agents/base_agent.py` | `AgentFinding` and `AgentResult` dataclasses, `extract_json()` (strips `<think>` blocks + fences), `BaseAgent` (LLM helpers `_llm`/`_llm_json`, tool runner `_run_tool`, finding factory with confidence coercion), `run_with_timing`. |
| `agents/registry.py` | Maps agent name → class path (`load_agent`). |
| `agents/planner_agent.py` | Hybrid graph builder: rules → LLM refine → sanitize → apply completed. `replan()` injects changes after significant findings. |
| `agents/critic_agent.py` | `review_batch` (one LLM call per agent, index echo-back, per-finding fallback), `review_finding`, `_apply_review`, `_bucket_of`. Protocol CONFIRM/DISPUTE/NEEDS_PROOF, final confidence 40/60 blend. |
| `agents/memory_agent.py` | `store_agent_result` (only confirmed → vulnerabilities), cross-agent **dedup** via `finding_key`, `_compute_risk`, SystemMap link updates, `agent_debate_log`. |
| `agents/web_attack_agent.py` | WebAttackAgent + `detect_waf_cdn()` + `CDN_WAF_MARKERS`. Reason → (WAF-skip) → concurrent tools → analyze → findings. Deterministic `_deterministic_findings` fallback. |
| `agents/specialists.py` | Network, API, Auth, Infra, Cloud agents. Each reasons over the map, runs owned tools, aggregates findings with `evidence_chain` + `raw_output_excerpt`. CloudAgent chains `cloud_enum` → `s3_enum` for a HIGH confirmed bucket finding. |
| `agents/exploitation_agent.py` | Validates critic-confirmed HIGH/CRITICAL findings with targeted PoC checks. |
| `agents/intelligence_agent.py` | Enriches technologies/findings with CVE / EPSS / CISA KEV / PoC from free public APIs, cached under `results/cache/`. |

### Tools layer
| File | Purpose |
|------|---------|
| `tools/base.py` | `Tool` ABC + `ToolResult`. Uniform interface: `build_command` / `parse` / `run`. Handles PATH search (incl. `~/go/bin`, `~/.local/bin`), timeouts, non-zero exits, parse errors. |
| `tools/registry.py` | Phase-1: capability → tool name preference order + `TOOL_MODULES` (name → module/class) + `load_tool`/`get_tools_for_capability`. |
| `tools/attack_registry.py` | Phase-2: attack action → tool mapping (`ATTACK_TOOL_MAP`, `ATTACK_TOOL_MODULES`), `load_attack_tool`. |
| `tools/cloud/s3_enum.py` | **New.** `S3EnumTool` — read-only `ListObjectsV2` GET (`?list-type=2&max-keys=1000`) via urllib against a bucket recon already confirmed publicly listable. Returns object_count / is_truncated / sample_keys, plus **read-only HEAD verification of 2 sample keys** (`downloadable_objects`, `public_downloads`). |
| `tools/cloud/cloud_enum.py` | Probes `<name>.s3.amazonaws.com` / Azure / GCS candidates for publicly-resolvable assets (HEAD, status 200) — now **concurrent** (8 workers, 3 s/request). |
| `tools/attack/api_probe.py`, `tools/attack/auth_probe.py` | Live HTTP probes: return real status codes, cookie flags, login forms, graphql detection — the evidence the critic CONFIRMs on. |
| `tools/attack/nuclei.py`, `nikto.py`, `dalfox.py`, `sqlmap.py`, `feroxbuster.py`, `corsy.py`, `nmap_nse.py`, `searchsploit.py`, `testssl.py` | Wrappers for the external scanning tools used by attack agents. |

### Report & misc
| File | Purpose |
|------|---------|
| `generate_attack_report.py` | Renders `results/attack_evidence/<target>.json` → markdown report: risk rating, vulnerabilities, exploit candidates, raw summaries, next steps, and the **Manual Verification Checklist** (confirmed URLs, critic-disputed incl. external redirect targets, needs-proof, recon auth/api surfaces; deduped + target-owned filter + masked/truncated URL cleanup). |
| `run_benchmark.py` | Measures model speed/quality across benchmark scenarios (`--model qwen3:8b`). This is what produced the 18.7 vs 4.2 tok/s numbers. |
| `tests/test_agents.py` | 22 tests: planner rules/skips, extract_json, critic offline fallback, memory round-trip, **critic batch (one call + partial fallback)**, **WAF detect + nikto-skip + full battery**, **auth/api aggregation**. |
| `tests/test_registry.py`, `tests/test_system_map.py` | Registry and SystemMap unit tests. |

---

## 8. Key improvements & why they matter

### Speed
- **14b → 8b on GPU**: ~4.5× faster inference.
- **Batched critic**: 1 LLM call per agent instead of per finding.
- **WAF/CDN-aware skipping**: nikto + feroxbuster are pointless behind a CDN.
- **Concurrent tools**: web tools run in parallel (4 workers).
- **Planner graph built once**: no duplicate first-iteration planner call.

### Correctness / trust
- **Critic CONFIRMs on live evidence** — confirmed counts are now real (the
  S3 bucket finding is backed by an actual `ListObjectsV2` response).
- **Aggregated findings** carry `evidence_chain` + `raw_output_excerpt`, so a
  human (and the critic) can verify them in one place.
- **Manual Verification Checklist** — exact URLs/endpoints to check, including
  critic-disputed redirect targets a human should eyeball.

### Reliability
- Deterministic fallbacks everywhere (planner, agents, critic offline → NEEDS_PROOF).
- Partial-batch critic fallback — a malformed JSON reply can't lose findings.
- `run.sh` reads the model from `config.yaml`, so scripts never drift from config.

---

## 9. Validation results

### Run 3 (Tier-1 fixes, 2026-08-07) — final

Real run against the user's Shopify test target (`your-store.myshopify.com`), **`--reset-memory`**:

```
  Risk rating      : HIGH
  Vulnerabilities  : 6            (all unique — no duplicate entries)
  Disputed         : 14
  Proof requests   : 1
  Agents completed : web_attack, api, auth, infra, intelligence, cloud
```

Tier-1 fixes observed live in this run:

| Fix | Observed |
|-----|----------|
| S3 download proof | finding = **"Publicly listable + downloadable S3 bucket: your-store"** (HIGH, confidence 95); evidence_chain: `downloadable: https://your-store.s3.amazonaws.com/1-10-rc-car-accessories.html`, `…/1-16-brass-strips.html` |
| Replan on significant finding | `[Replan] significant finding: Publicly listable + downloadable S3 bucket: your-store` fired mid-run |
| cloud_enum concurrency | cloud agent **33.9 s** (was ~605 s) |
| Memory dedup | 6 confirmed vulns, each a distinct name — same issue never stored twice |
| Report dedup | report renders 6 vulns with no duplicate rows |

Note: `web_attack`'s generic "Missing Security Headers" (nuclei bundle) and `infra`'s specific "Missing security header: referrer-policy" (testssl) remain separate — dedup keys on normalized name, and the two names differ in granularity.

### Run 1/2 — before Tier-1 fixes

```
  Risk rating      : HIGH
  Vulnerabilities  : 6            (was 0 confirmed before the critic changes)
  Disputed         : 12
  Proof requests   : 2            (was 30)
  Agents completed : web_attack, api, auth, infra, cloud, intelligence
```

| Agent | Before | After |
|-------|--------|-------|
| web_attack | 3405 s, nikto/feroxbuster swallowed by Cloudflare | **103 s**, `[waf]` skip message, nuclei+corsy only |
| api | 9 findings, ungrouped | 2 grouped findings, critic confirmed both |
| auth | 18 findings | 6 grouped findings |
| infra | — | 130 s (testssl + headers) |
| cloud | tools=`[]` (regression) | `cloud_enum` + `s3_enum(1 buckets)` → **HIGH "Publicly listable S3 bucket" confirmed** |

Top confirmed finding:

```
### 🟠 [HIGH] Publicly listable + downloadable S3 bucket: your-store
- **Source:** cloud
- **URL:** https://your-store.s3.amazonaws.com/?list-type=2&max-keys=1000
- **Detail:** Anonymous S3 ListObjectsV2 returned 1000 object(s)
  (truncated=True). Anonymous HEAD confirmed 2 sample object(s) publicly
  downloadable: 1-10-rc-car-accessories.html (text/html, 37018 bytes); ...
```

Full report: `results/reports/your-store.myshopify.com.md`

> Timing note: on this target the web_attack nuclei pass dominates wall time
> (~40 min when nuclei tags explode, ~4.5 min when lean). Budget ~50 min for a
> full `./run.sh` cycle and use a generous timeout / `nohup`.

---

## 10. How to run everything

```bash
# Full end-to-end (recon → map → attack → report)
./run.sh your-store.myshopify.com

# Attack only (if recon already done)
python3 bin/cyberswarm attack your-store.myshopify.com --auto-approve --reset-memory

# Regenerate the report only
python3 generate_attack_report.py your-store.myshopify.com --out results/reports/your-store.myshopify.com.md

# Check which tools are installed
python3 bin/cyberswarm tools

# Dry-run the planner/agent selection without running tools
./run.sh example.com --dry-run
```

The model/backend come from `config.yaml` by default; override with
`--model qwen3:8b --base-url http://192.168.0.66:11434`.

---

## 11. Testing

```bash
python3 -m pytest tests/ -q        # ~1,350 tests, ~30 s, fully offline
```

The suite grew from 22 tests (August) to cover every agent, tool parser,
report writer, the planner policy/guardrails, validator, model client
(structured output), scope gate and benchmarks. Anything a test writes into
`results/` is reverted at session end. Three tests need locally installed
tools (nmap, impacket, the full preflight set); CI deselects them.

---

## 12. Extending: add a tool or an agent

**Add a tool** (e.g. a new scanner):
1. Write a wrapper subclassing `tools/base.py:Tool` (`build_command` + `parse`).
2. Add one line to `tools/registry.py:TOOL_MODULES` (and a capability in
   `CAPABILITY_TOOL_MAP` if it's a recon tool, or `tools/attack_registry.py` if
   it's an attack tool).
3. Done — no other pipeline code changes. (Pure-Python example:
   `tools/cloud/s3_enum.py`.)

**Add an agent**:
1. Subclass `BaseAgent`, set `agent_name` + `owned_tools`, implement
   `run()`/`should_run()`.
2. Register in `agents/registry.py`.
3. Add a priority/skip rule in `system_map.derive_attack_surface` (or the
   planner's `_rules_to_graph`) so the graph knows when to run it.

---

## 13. Cross-engagement RAG memory

Persistent memory across engagements. Every run's evidence is normalized into
short one-line "lessons", indexed with SQLite FTS5, and the top-5 matches are
injected into the planner prompt so a later scan benefits from what earlier
scans observed.

Keyword retrieval (BM25), not embeddings — Ollama embeddings are disabled on
the server and no vector libraries are installed, so this adds zero new
dependencies. FTS5 ships with CPython's bundled SQLite.

### What gets indexed

| Source | Lessons produced |
|--------|------------------|
| `results/attack_evidence/<target>.json` | One per confirmed finding (severity, tool, critic verdict); one per attack-graph node (why an agent was queued or skipped); agent coverage. |
| `results/evidence/<target>.json` | Target profile (technologies, ports, CMS, API types); per-capability failures with their failure pattern; zero-finding capabilities; missing security headers. |
| `results/tool_memory.json` | Per-tool success/failure/timeout ratios. |
| `results/attack_decision_log.jsonl` | Per-agent outcomes aggregated across runs: run count, dominant status, findings, average duration, tools used. |

### How retrieval works

`build_query(smap)` derives a search string from the SystemMap — technologies,
service names, non-web ports, CMS/cloud/AD/API signals, and coarse surface
flags. Standard web ports are dropped (they carry no signal); port 3306 is
kept.

Every document also carries a **context** field: the technology fingerprint of
the engagement it came from. It is indexed but never displayed. Without it,
technology-derived queries only ever matched the recon-profile documents,
because a lesson like `capability CONTENT_DISCOVERY FAILED` never mentions
Apache. With it, a new Apache/MySQL target retrieves the operational lessons
from a prior Apache/MySQL engagement.

Retrieval prefers spreading lessons across engagements (`max_per_target`), but
backfills in rank order rather than trading a strong match for a weak one — if
only one prior engagement is relevant, all five lessons may come from it.

### Configuration

```yaml
rag:
  enabled: true
  db_path: results/idx/cyberswarm_memory.sqlite   # relative paths resolve under the project root
  top_k: 5                   # lessons per planner call (keep small for qwen3:8b)
  auto_reindex: true         # rebuild after each recon/attack run
```

`enabled: false` restores the exact pre-RAG planner prompt.

### CLI

```bash
python scripts/rag_index.py                     # incremental reindex
python scripts/rag_index.py --full              # wipe + rebuild
python scripts/rag_index.py --stats             # counts by kind and target
python scripts/rag_index.py --list --kind tool  # dump documents
python scripts/rag_index.py --query "wordpress php mysql" -k 5
python scripts/rag_index.py --smap results/system_map/example.com.json
```

`--smap` runs the exact query the planner would build from a stored SystemMap
and prints the block as it would be injected — the fastest way to check why a
run retrieved a surprising lesson.

### Safety properties

- **Backward compatible.** A missing index, a disabled feature, a SQLite build
  without FTS5, an empty result, or an exception anywhere in the RAG layer all
  return `""` and planning proceeds exactly as before. `use_llm=False` never
  touches the index.
- **Idempotent.** Documents are keyed and content-hashed; re-indexing unchanged
  results is a no-op, and an edited finding updates in place instead of
  duplicating.
- **Additive.** RAG supplements `load_recon_lessons()`; it does not replace it.
- **Bounded.** Lesson bodies are capped at 240 characters and the block at
  `top_k` lines, so the injection costs roughly 500 characters on a ~9.5k
  prompt.
- **Auto-reindex is best-effort.** A failed reindex logs a warning; it never
  turns a completed assessment into a non-zero exit.

### Skill packs

With `rag.index_skills` on, the markdown under `cyberswarm-phase2-agent-skill/`
is chunked by heading and indexed alongside engagement lessons, so the planner
receives the playbook sections relevant to the current target's technology
rather than the whole pack. Skill sections are retrieved separately from
lessons and cannot crowd them out, and they get a larger body budget (700 chars
vs 240) because a truncated playbook step is worse than none.

```yaml
rag:
  index_skills: true
  skills_dir: cyberswarm-phase2-agent-skill
  skill_top_k: 2       # playbook excerpts injected per planner call
```

Together the two blocks add roughly 1.4k characters to a ~9.5k planner prompt.

### Imported skill pack

`skills/pentestcode/` holds 22 skills imported from the PentestCode project
(MIT, itself an OpenCode fork) — web vulnerability classes, service notes, and
playbooks. See `skills/pentestcode/ATTRIBUTION.md`; the files are unmodified.

Their YAML frontmatter carries trigger keywords:

```yaml
description: SQL injection detection→exploitation→proof. Triggers - sql syntax
  error, ' or 1=1, order by, sleep-based delay, login bypass, id/search param.
```

That description is indexed as retrieval context on every section of the file,
so a target showing a boolean differential reaches the SQLi playbook even
though no individual section mentions those words. It is never printed into the
prompt.

Four categories are excluded by default because CyberSwarm has no agent for
them — `playbooks/ad`, `services/pivoting`, `services/mobile-android` and
`phases/post-exploit`. Injecting advice the toolkit cannot act on spends
context and can push the planner toward actions it has no tool for. Enable them
by editing `rag.skill_excludes`.

### Scope caveat

Retrieval is global across all targets in `results/`, so lessons from any
indexed engagement can reach the planner for any future target. If
`config/authorized_targets.json` is meant to be authoritative, note that
`authorization.py` is lenient by default and `results/` may contain targets
outside that scope. Filtering `collect_documents()` by the authorized scope
would be a small addition if that matters for your workflow.

---

## 14. Engagement phases & quality gates

    DISCOVERY -> ENUMERATION -> SURFACE_MAPPING -> EXPLOITATION -> REPORTING

Each phase owns a slice of the recon capability list and declares **entry
gates** — cheap predicates over the evidence already collected. The gate that
matters most refuses to start exploitation against a host that was barely
enumerated.

Gates are **advisory, not authorization.** They are a quality mechanism; target
authorization stays entirely in `authorization.py` and is unchanged by this
feature.

### Gates

| Phase | Entry gates |
|-------|-------------|
| `DISCOVERY` | none — always enterable |
| `ENUMERATION` | target resolved/reachable; discovery coverage |
| `SURFACE_MAPPING` | enumeration coverage; a service or technology identified |
| `EXPLOITATION` | attack surface present; enumeration coverage; surface coverage |
| `REPORTING` | something actually ran |

A failing gate reports the numbers it compared, so a blocked run is
diagnosable without reading source:

```
[FAIL] enumeration_coverage: enumeration coverage 0/8 (0% vs 50% required)
```

### Behaviour

* **Recon loop** — a capability belonging to a later phase is skipped until
  that phase's gates pass. Capabilities from earlier phases are always allowed,
  since backfilling recon you skipped is normal.
* **Attack loop** — `run_attack` refuses to start and returns
  `status="blocked_by_phase_gate"` when EXPLOITATION gates fail. `--force`
  bypasses it.
* **Overrides are recorded.** A forced transition is written to the phase
  history with the gates that were failing at the time.
* Phase state is per-target and persisted under `results/phase_state/`, so a
  resumed run picks up where it left off.

### CLI

```bash
python scripts/phase_ctl.py example.com                    # status + gate report
python scripts/phase_ctl.py example.com --advance
python scripts/phase_ctl.py example.com --set EXPLOITATION --force --note "lab box"
python scripts/phase_ctl.py example.com --history
```

### Configuration

```yaml
phases:
  enabled: true          # false restores the pre-phase behaviour exactly
  gates:
    min_discovery_coverage: 0.4
    min_enumeration_coverage: 0.5
    min_surface_coverage: 0.25
    require_open_port_for_exploitation: true
```

A gate that raises is treated as passing — a bug in a gate must never block a
run. An unrecognised capability is never phase-mapped and never blocked.

---

## 15. Run modes & pause policy

Two independent axes replace the single `--auto-approve` boolean:

| `--mode` | Behaviour |
|----------|-----------|
| `auto` | runs the phases autonomously, approving planner decisions |
| `guided` | proposes each action and waits for approval |
| `free` | no phase structure; runs exactly what you asked |

| `--pause` | Behaviour |
|-----------|-----------|
| `never` | never stops |
| `always` | stops after every agent/capability result |
| `checkpoint` | stops at phase boundaries and on `HIGH`+ findings |

They combine: `--mode auto --pause always` is autonomous execution that still
stops at every result for review.

```bash
python run_recon_loop.py example.com --mode auto --pause checkpoint
python run_agent_loop.py example.com --mode guided
python run_recon_loop.py example.com --auto-approve      # still works: auto + never
```

`--auto-approve` is preserved and means exactly `--mode auto --pause never`, so
existing scripts and CI invocations keep working unchanged.

**Free mode drops phase structure only.** There is deliberately no mode that
bypasses the scope check — `authorization.py` is consulted identically in every
mode.

### Configuration

```yaml
session:
  mode: auto            # auto | guided | free
  pause: never          # never | always | checkpoint
  checkpoint_severity: HIGH
```

---

## 16. Prompts

Reusable prompts live in `prompts/` as markdown with YAML frontmatter:

```markdown
---
description: Rank the findings by real-world exploitability, not raw CVSS
tags: [reporting, triage]
variables: [target]
---
Review the confirmed findings for {{target}} ...
```

Drop a file in and it is available immediately — no registration step, no code
change. Both `{{name}}` and `$NAME` are substituted at render time.

```bash
python cli.py prompt                                   # list
python cli.py prompt triage-findings --target example.com
python cli.py prompt report-exec-summary --target example.com -v client=Acme
python scripts/prompt.py triage-findings --target example.com --run
```

Without `--run` the rendered text is printed, so you can pipe it elsewhere.
With `--run` it is sent to the configured model and the target's stored
evidence is attached as context (`--no-context` to suppress that).

Rendering is deliberately dumb: only the declared placeholders are replaced and
nothing else is interpreted, so a stray brace in a payload example inside a
prompt cannot break a run. Missing variables are refused up front rather than
sent half-filled.

Four prompts ship by default: `triage-findings`, `explain-target`,
`next-steps`, `report-exec-summary`.

### Configuration

```yaml
prompts:
  dir: prompts
```

---

## 17. Built-in help

```bash
python cli.py help                # overview and topic list
python cli.py help phases         # one topic
python cli.py help capabilities
```

Topics: `agents`, `capabilities`, `phases`, `modes`, `prompts`, `skills`,
`memory`, `config`, `scripts`, `safety`.

Every topic is **generated from the live registries**, not written out by hand.
Adding an agent to `agents/registry.py` or a capability to `tools/registry.py`
makes it appear in `help` on the next run with no edit to `help_text.py`, so
the help cannot drift from the code. A test asserts the overview lists every
registered topic, and another asserts a topic whose backing module raises
degrades to a short note rather than taking the whole help command down.

`help safety` is the one worth reading before a first run: it states plainly
that `authorization.py` is lenient by default, and where the audit trails live.

---

## 18. Asking in plain English

```bash
python cli.py ask "find the subdomains of example.com"
```

```
SUBDOMAIN_DISCOVERY  on  example.com
  kind       : capability
  confidence : 90
  tools      : subfinder, amass

  authorization: target matches scope entry 'example.com'
  phase: SUBDOMAIN_DISCOVERY belongs to DISCOVERY (at or before current phase)

Nothing was run. Equivalent command:
  python cli.py recon example.com    # capability: SUBDOMAIN_DISCOVERY

Re-run with --execute to run it now.
```

The layer is deliberately thin: it resolves free text to
`(capability_or_agent, target)` and nothing more. Execution goes through the
same `recon_engine.execute_capability` the recon loop uses, behind the same
authorization check and phase gate — there is no second execution path,
because a second path is a second place for the gates to be missed.

### What it refuses

Free text is the easiest place to widen scope by accident, so the resolver is
built to fail closed:

| Situation | Result |
|-----------|--------|
| Model returns a name not in the registry | refused — no fuzzy matching |
| Model returns a target you did not write | refused, naming both |
| Request has no target in it | refused |
| Model emits a shell command or unknown `kind` | refused |
| Reply is not parseable JSON | refused |
| `authorization.is_authorized()` itself errors | refused — it does not fall open |
| Confidence below `--min-confidence` (default 50) | refused for `--execute` |

The model is never asked for a command, only for a name from a fixed list, so
a hallucinated or prompt-injected action cannot reach the executor.

Printing is the default. `--execute` runs the capability; agents are resolved
but never executed here, since they need the planner (`cli.py attack`).
