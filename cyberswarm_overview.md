 # CyberSwarm — Overview & File Reference

## What It Is

**CyberSwarm** is a **self-hosted, multi-agent offensive security (penetration testing) platform** that runs entirely against a **local LLM** (Ollama / OpenAI-compatible). It has evolved through several "phases" (benchmark planner → recon engine → full attack agent framework). The LLM acts as the brain that **decides** what to do; humans approve each step; real security tools *execute*.

## Core Concept: Agent Architecture

A swarm of LLM-driven **agents**, each a specialist, reason about a shared `SystemMap` (target model) and drive real tools. Flow through `run_agent_loop.py`:

1. **PlannerAgent** builds an attack plan (rules first, LLM refines it)
2. **Agents** run tools, produce **findings** (with confidence + evidence chain)
3. **CriticAgent** reviews each finding (confirm/dispute/needs_proof)
4. **IntelligenceAgent** enriches with CVE/EPSS/KEV data
5. Human approval gate + audit log throughout

---

## Top-Level Files (& what each does)

### Entry / Orchestration

| File | Lines | Purpose |
|------|-------|---------|
| `cli.py` | 370 | The `cyberswarm` command-line entry point; subcommands: `attack`, `recon`, `status`, audit/log viewing. Parses `config.yaml`, builds the model client, kicks off the agent loop. |
| `run_agent_loop.py` | 450 | The **attack orchestrator**: runs the swarm loop (`run_attack`), the planner, critic, deep analysis, replanning on new API/AUTH/pivot findings, and cross-agent pivot queue. |
| `run_recon_loop.py` | 887 | The **recon loop**: plan → approve → execute recon tools → merge evidence → repeat until terminal capability. |
| `run_benchmark.py` | 161 | Benchmarks the recon planner LLM across `scenarios/scenarios.json`, scoring JSON validity/accuracy. |
| `ablation.py` | 352 | Ablation testing: turn features on/off to measure their contribution (e.g. disable LLM planner, critic, etc.). |

### Model / Brain

| File | Lines | Purpose |
|------|-------|---------|
| `model_client.py` | 94 | Thin wrapper to talk to Ollama (`/api/chat`) or any OpenAI-compatible server. Configurable model, temp, max tokens, API key, retries. Defines "which model you're using". |

### Target Model & State

| File | Lines | Purpose |
|------|-------|---------|
| `system_map.py` | 507 | Builds the **"one model, many agents"** relational view of the target: assets, open ports, services, endpoints, API paths, auth paths, signals, attack-surface derivation, LLM compression. |
| `build_system_map.py` | 77 | Assembles a SystemMap from evidence/batch data. |
| `state.py` | 571 | Persistent agent state store (assets, findings, completed agents, risk). |
| `memory_store.py` | 294 | Shared swarm "memory": new attack paths, cross-agent state. |
| `context.py` | 236 | Target/recon/attack context + credentials tagged by identity. |
| `target.py` | 134 | Target parsing. |
| `target_utils.py` | 27 | Target/URL normalization and scope helpers. |
| `evidence_store.py` | 277 | Per-target evidence persistence and merging of tool findings (recon). |
| `attack_evidence_store.py` | 302 | Per-target attack evidence persistence and merging. |

### Planning & Scoring

| File | Lines | Purpose |
|------|-------|---------|
| `action_scorer.py` | 246 | Evidence-driven ranking of which capability to run next. |
| `attack_chains.py` | 221 | Chains/sequences of attacks. |

### Safety & Authorization

| File | Lines | Purpose |
|------|-------|---------|
| `authorization.py` | 113 | Target scope/authorization checks against `config/authorized_targets.json`. |
| `approval_gate.py` | 96 | Mandatory human-in-the-loop: every decision is approved/rejected/overridden, logged to `results/decision_log.jsonl`. |
| `decision_trace.py` | 134 | Records why each decision was made (audit/traceability). |

### Findings Quality

| File | Lines | Purpose |
|------|-------|---------|
| `confidence.py` | 250 | Normalizes/coerces confidence values (0–100, 0–1, words). |
| `cvss.py` | 263 | CVSS scoring for severity. |

### Execution Engine

| File | Lines | Purpose |
|------|-------|---------|
| `controller.py` | 319 | The Controller (Stage 7): decides which capability runs, resolves to a tool, merges evidence back. |
| `recon_engine.py` | 44 | Resolves capability → available tool → executes → standard JSON. |
| `tool_manager.py` | 296 | Dynamic tool loading/dispatch layer. |
| `attack_engine.py` | 68 | Attack-phase tool execution. |
| `utils.py` | 149 | Shared helpers (logging, YAML config loading). |

### Dashboard & Reporting

| File | Lines | Purpose |
|------|-------|---------|
| `dashboard_data.py` | 266 | Local web dashboard data aggregation. |
| `dashboard_server.py` | 462 | Serves the live dashboard UI/stats. |
| `generate_attack_report.py` | 422 | Produces the final attack/finding report. |
| `generate_assess_report.py` | 210 | Assessment report generator. |

### Other

| File | Lines | Purpose |
|------|-------|---------|
| `batch.py` | 191 | Batch/parallel processing of evidence or decisions. |

---

## `agents/` — The Swarm's Specialists

Each extends `BaseAgent`:

| File | Purpose |
|------|---------|
| `base_agent.py` | Parent: LLM helpers, robust JSON extraction, tool running, finding factory, confidence coercion. Defines `AgentFinding` (severity, confidence, evidence_chain) and `AgentResult`. |
| `planner_agent.py` | Builds/refines the attack graph (rules first, LLM refinement second). |
| `web_attack_agent.py` | Web app attacks (XSS/SSRF/etc. via tools). |
| `attack_specialists.py` | Directory/param fuzzing (ffuf, arjun). |
| `specialists.py` | API/auth/cloud/subdomain-takeover/discovery specialists (emits `API:`/`AUTH:`/`PIVOT:` signals). |
| `exploitation_agent.py` | Exploitation + pivot handling (`PIVOT:` signals). |
| `critic_agent.py` | Independent review of findings. |
| `intelligence_agent.py` | CVE/EPSS/KEV enrichment. |
| `memory_agent.py` | Maintains cross-agent memory. |
| `registry.py` | Maps agent names to classes. |

---

## `tools/` — The Real Tool Plugins (grouped by category)

All wrappers expose `run()/parse()/validate()` (in `tools/base.py`), returning uniform JSON. Registration: `tools/registry.py` (recon) and `tools/attack_registry.py` (attack).

| Category | Tools |
|---|---|
| **api** | `api_discover` (probe OpenAPI/Swagger/GraphQL/SOAP signatures) |
| **attack** | 37 tools — `api_probe`, `auth_probe`, `clickjacking`, `commix`, `corsy`, `crlf`, `csrf`, `dalfox` (XSS), `default_creds_check`, `deserialization`, `feroxbuster`, `file_upload`, `host_header`, `http_methods`, `idor_test`, `jwt_exploit`, `jwt_tool`, `lfi`, `login_brute`, `login_fill`, `nikto`, `nmap_nse`, `nuclei`, `nuclei_tags`, `searchsploit`, `session_fixation`, `session_hijack`, `sqlmap`, `sslyze`, `ssrf`, `ssti`, `subjack`, `waf_bypass_payloads`, `wafw00f`, `xxe` |
| **cloud** | `cloud_enum`, `s3_enum` (bucket enumeration) |
| **cms** | `cms_identify`, `wpscan` (WordPress) |
| **container** | `container_probe` |
| **content** | `ffuf` (content/directory fuzz) |
| **directory** | `ldap_enum`, `smb_enum` |
| **dns** | `dns_enum`, `dns_resolve` |
| **iot** | `iot_probe` |
| **javascript** | `linkfinder` (JS endpoint mining) |
| **params** | `arjun` (parameter discovery) |
| **passive** | `amass`, `subfinder` (subdomain discovery) |
| **portscan** | `host_discovery`, `naabu`, `nmap`, `os_identify` |
| **recon** | 10 recon-detectors — `auth_flow_analysis`, `cert_info`, `cookie_analyzer`, `csrf_surface_detect`, `deserialization_detect`, `graphql_introspection`, `robots_txt_parser`, `sensitive_endpoint_detect`, `session_analyzer`, `upload_form_detect` |
| **screenshots** | `gowitness` |
| **tls** | `testssl`, `tls_analysis` |
| **web** | `gau`, `header_analysis`, `httpx`, `katana`, `waybackurls`, `whatweb` |
| **validation** | (empty — future) |

---

## Other Layout

| Path | Purpose |
|------|---------|
| `schema/` | Canonical enums (`enums.py`, `attack_enums.py`) and strict validators (`validator.py`, `attack_validator.py`) for LLM output. |
| `prompts/` | `recon_planner.txt`, `recon_planner_compact.txt`, `attack_planner.txt`. |
| `scenarios/` | 15 benchmark test cases. |
| `results/` | Reports, evidence, decision logs, benchmark JSON. |
| `config.yaml` | Model backend/URL, pipeline, recon, attack, report settings. |
| `config/authorized_targets.json` | Authorized scope list. |
| `tests/` | 650 passing tests. |
| `docs/skill`, `cyberswarm-phase2-agent-skill/`, `bin/cyberswarm` | Docs & installed entry script. |

---

## Key Features

1. **Multi-agent swarm** — planner → specialists → critic → intelligence, sharing one SystemMap.
2. **LLM-driven, human-gated** — the model only *recommends*; humans approve each action (audit-logged).
3. **Plugin tool architecture** — add a tool = 1 wrapper + 1 registry line.
4. **Hybrid rules+LLM planning** (deterministic safety fallback if LLM fails).
5. **Evidence chain & confidence scoring** with independent-source checks.
6. **Cross-agent pivoting** (`PIVOT:` signals), API/AUTH surface discovery (`API:`/`AUTH:`) and replanning.
7. **Resumable state** + evidence persistence, live dashboard.
8. **Extensive coverage**: web, API, network, cloud, directory services, TLS, CMS, containers, IoT, and recon detection.
