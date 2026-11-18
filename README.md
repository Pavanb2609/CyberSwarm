# CyberSwarm

**Self-hosted, multi-agent penetration-testing framework for authorized security assessments.**

CyberSwarm uses a local LLM (Ollama or any OpenAI-compatible server) as the decision engine while real security tools do the actual work. A human approval gate, a scope file, and an evidence-honesty layer keep every engagement accountable and transparent.

---

## Table of Contents

1. [What the Project Does](#what-the-project-does)
2. [Why the Project Is Useful](#why-the-project-is-useful)
3. [Requirements](#requirements)
4. [Quick Start](#quick-start)
5. [Shell Scripts & Launchers](#shell-scripts--launchers)
6. [Advanced Usage](#advanced-usage)
7. [Architecture](#architecture)
8. [File Structure](#file-structure)
9. [Agents](#agents)
10. [Tools & Capabilities](#tools--capabilities)
11. [Key Modules Explained](#key-modules-explained)
12. [Configuration Reference](#configuration-reference)
13. [Benchmarking & Validation](#benchmarking--validation)
14. [Testing](#testing)
15. [Packaging & Distribution](#packaging--distribution)
16. [FAQ](#faq)

---

## What the Project Does

CyberSwarm automates the full penetration-testing lifecycle through a four-phase pipeline:

1. **Recon** — An LLM planner picks the next reconnaissance capability (37 capabilities, 39 tool wrappers). A deterministic policy layer (`planner_policy.py`) enforces hard rules and takes over if the model's output is unusable. Every step passes through a human approval gate.

2. **Map** — Flat recon evidence is compiled into a structured **SystemMap**: a shared model of the target's assets, ports, services, endpoints, authentication paths, API surfaces, and attack surface signals.

3. **Attack** — Specialist LLM agents (web, API, auth, infra, cloud, AD, XSS, payload, Burp/ZAP, exploitation) test the mapped surface. A **CriticAgent** reviews every finding, and an **IntelligenceAgent** enriches confirmed vulnerabilities with CVE/EPSS/KEV data. A **MemoryAgent** deduplicates findings across agents.

4. **Report** — Confirmed vulnerabilities are rendered into a Markdown attack report with:
   - OWASP Top-10 mapping
   - Per-vulnerability proof trails with captured evidence
   - A manual verification checklist with exact URLs and endpoints
   - Risk rating and engagement summary

**Evidence honesty** is enforced throughout: confidence scores come from the proof checks that actually matched. A CONFIRM below 50 is downgraded to NEEDS_PROOF, and "proven" requires captured execution evidence.

---

## Why the Project Is Useful

- **Fully self-hosted** — No data leaves your network. The LLM runs locally via Ollama or any OpenAI-compatible server.
- **Human-in-the-loop** — Every recon step and attack action passes through an approval gate with an audit log. No autonomous exploitation without consent.
- **Scope enforcement** — An authorization file (`config/authorized_targets.json`) with expiry dates prevents testing unauthorized targets. Loopback and lab targets are always allowed.
- **Evidence-based confidence** — Findings are confirmed only when real proof (HTTP responses, exposed data, TLS vulnerabilities) is captured. No guessing, no hallucinated vulnerabilities.
- **Multi-agent architecture** — Specialist agents focus on their domain (web, API, cloud, AD, etc.), reviewed by an independent CriticAgent for quality control.
- **WAF/CDN-aware** — Automatically detects Cloudflare/Akamai/etc. and skips tools whose results a CDN would absorb (nikto, feroxbuster), keeping the scan efficient.
- **Benchmarked** — A 52-scenario planner benchmark, a local lab detection bench, and XBOW benchmark integration provide measurable validation of detection quality.

---

## Requirements

### System Requirements

- **OS:** Ubuntu Linux (tested on Ubuntu 22.04+)
- **Python:** 3.10 or higher
- **GPU (recommended):** NVIDIA GPU with 6+ GB VRAM for running the LLM locally

### Software Dependencies

#### Python packages (installed via pip)

| Package | Purpose |
|---------|---------|
| `requests>=2.31` | HTTP client for tool wrappers and model API |
| `PyYAML>=6.0` | Configuration file loading |
| `dnspython>=2.4` | DNS enumeration (pure Python, no external binary) |
| `ldap3>=2.9` | LDAP/Active Directory enumeration |

#### LLM Backend (one of the following)

| Backend | Description |
|---------|-------------|
| **Ollama** (recommended) | Local LLM server. Install from [ollama.com](https://ollama.com). Default model: `qwen3:14b` (fits 8+ GB GPU) or `qwen3:8b` (fits 6 GB GPU) |
| **OpenAI-compatible** | vLLM, LM Studio, or llama.cpp server, usually on port `:8000` |

#### External Security Tools

These tools are optional — CyberSwarm runs the preflight check to report what is installed and what is missing. Missing tools are skipped gracefully.

**Passive Recon:**
`subfinder`, `amass`

**DNS:**
`dnspython` (Python library, no binary needed)

**Port Scanning:**
`nmap`, `naabu`

**Web Probing:**
`httpx`, `whatweb`

**TLS Analysis:**
`testssl.sh` (preferred), `openssl` (fallback)

**Web Crawling & Discovery:**
`katana`, `ffuf`, `gau`, `waybackurls`

**JavaScript & Parameters:**
`linkfinder`, `arjun`

**Vulnerability Scanning:**
`nuclei`, `nikto`, `sqlmap`, `dalfox`, `commix`, `feroxbuster`

**CMS:**
`wpscan`

**Cloud:**
Built-in S3 enumeration (pure Python)

**Screenshots:**
`gowitness`

**Active Scanners (optional):**
Burp Suite Professional (REST API), OWASP ZAP

**Active Directory:**
`impacket` (GetNPUsers.py, GetUserSPNs.py)

**Automated installation:** Run `./install_cyberswarm_tools.sh` to install all external tools on Ubuntu automatically.

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/AmritaCSN/CyberSwarm.git
cd CyberSwarm
```

### 2. Set up the Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Set up the LLM backend

```bash
# Install Ollama (https://ollama.com)
ollama pull qwen3:8b    # for 6 GB GPU
# or
ollama pull qwen3:14b   # for 8+ GB GPU (better accuracy)
```

Edit `config.yaml` to point `base_url` at your Ollama instance:

```yaml
model:
  backend: ollama
  model: qwen3:8b
  base_url: http://localhost:11434
```

### 4. Run the preflight check

```bash
python -m tools.preflight
```

This reports which external security tools are installed and which are missing.

### 5. Run the full pipeline

```bash
./run.sh scanme.nmap.org
```

This runs all four phases end to end: recon → map → attack → report. The report is saved to `results/reports/<target>.md`.

---

## Shell Scripts & Launchers

CyberSwarm provides several shell scripts for different workflows:

### `run.sh` — Full End-to-End Pipeline

The main launcher. Runs all four phases (recon → map → attack → report) on a single target.

```bash
./run.sh <target>                        # full pipeline
./run.sh <target> --dry-run              # plan only, no live tools
./run.sh --help                          # show help
TARGET=example.com ./run.sh              # target via env var
```

**What it does internally:**
1. Reads the model name and backend URL from `config.yaml`
2. Auto-detects the LLM backend if the configured host is unreachable (probes localhost, local IPs, gateway/NAT hosts on port 11434)
3. Adds Go binaries (`~/go/bin`), Python venv, and ZAP to `$PATH`
4. Sets the `FFUF_WORDLIST` to `common.txt` if present in the repo
5. Runs Phase 1 recon with `--run-all --auto-approve` (all 37 capabilities)
6. Builds the SystemMap
7. Runs Phase 3 multi-agent attack with `--auto-approve --reset-memory`
8. Generates the report to `results/reports/<target>.md`

You can pass extra arguments after the target — they are forwarded to each `cyberswarm` subcommand (e.g. `--base-url`, `--model`).

### `run_assess.sh` — Evidence-Driven Assessment (Controller Flow)

An alternative pipeline that uses the **Controller** (`controller.py`) — a deterministic, evidence-scored capability ranker that does not require an LLM for action selection.

```bash
./run_assess.sh <target>                           # full assessment
./run_assess.sh <target> --max-actions 200         # increase budget
./run_assess.sh <target> --no-high-risk            # skip high-risk probes
```

**Pipeline:** authorize → Controller loop (evidence-driven) → assess report  
**Defaults:** full-aggressive, up to 100 capability probes, 30-minute budget.

The Controller uses the `ActionScorer` to rank every candidate capability on four axes: information gain, success likelihood, novelty, and risk. No LLM is needed — it is fully deterministic.

### `run_all_target.sh` — Controller Assessment with Flags

A convenience wrapper around `cyberswarm assess` for single-target runs:

```bash
./run_all_target.sh example.com                    # full assessment
./run_all_target.sh example.com --dry-run          # plan without executing
./run_all_target.sh example.com --no-llm           # no LLM (fallback planner)
./run_all_target.sh example.com --fast             # 60s per-tool cap
```

### `run_xbow_matrix.sh` — XBOW Benchmark Matrix

Runs a stratified ~30-benchmark subset across 5 pipeline variants (baseline, no-difficulty, no-rag, no-llm-planner, no-guardrails) for paper results.

```bash
bash run_xbow_matrix.sh                  # run or resume the whole matrix
bash run_xbow_matrix.sh --status         # show progress and ETA
bash run_xbow_matrix.sh --finalize       # rebuild reports + comparison table
```

- **Resumable:** safe to Ctrl+C; re-run continues where it stopped
- **Logged:** all output is tee'd to `results/xbow/matrix/run_*.log`
- Runs approximately 108 total runs (~20 hours)

### `install_cyberswarm_tools.sh` — External Tool Installer

Automated installer for all external security tools on Ubuntu:

```bash
./install_cyberswarm_tools.sh
```

Installs in 7 stages:
1. Ubuntu system packages (nmap, hydra, nikto, sqlmap, whatweb, testssl.sh, etc.)
2. Python packages (dnspython, impacket, arjun, sslyze, wafw00f, etc.)
3. Go-based tools (subfinder, httpx, naabu, nuclei, katana, ffuf, gau, dalfox, gowitness, etc.)
4. Rust-based tools (feroxbuster via cargo)
5. Standalone Python tools (jwt_tool, LinkFinder, Corsy, commix — cloned into `tools/`)
6. Ruby tools (wpscan via gem)
7. PATH update + CyberSwarm preflight check

### `install_remaining.sh` — Supplementary Tool Installer

Installs tools that `install_cyberswarm_tools.sh` may have missed (arjun, sslyze, wafw00f, impacket, gowitness, httpx, waybackurls, wpscan) and runs the preflight check.

---

## Advanced Usage

### Common Commands

```bash
# Full pipeline (recon → map → attack → report)
./run.sh <target>

# Individual phases
python cli.py recon  <target>       # Phase 1: recon loop (approval gate on every step)
python cli.py map    <target>       # Phase 2: build SystemMap from evidence
python cli.py attack <target>       # Phase 3: multi-agent attack loop
python cli.py report <target>       # Phase 4: regenerate the attack report

# Utilities
python cli.py evidence  <target>    # per-vulnerability proof trail
python cli.py status    <target>    # resume/status view
python cli.py dashboard             # read-only live dashboard
python cli.py tools                 # list all available tools
python cli.py help [topic]          # agents, phases, modes, prompts, safety ...

# Natural language queries
python cli.py ask "find the subdomains of example.com"
```

### Run Modes

Control how much autonomy the system has:

| Mode | Behavior |
|------|----------|
| `--mode auto` | LLM decides what to do next; approval gate still active |
| `--mode guided` | LLM suggests, but waits for explicit confirmation on each action |
| `--mode free` | LLM runs without the planner policy guardrails (advanced users only) |

Pause policy: `--pause never | always | checkpoint`

Example:

```bash
python cli.py recon example.com --mode guided --pause checkpoint
```

### Scope & Authorization

Before scanning any non-lab target, create `config/authorized_targets.json`:

```json
{
  "targets": [
    "lab.example",
    {
      "target": "app.client.com",
      "authorized_by": "J. Smith (client CISO)",
      "scope": "SOW-2026-14, web app only",
      "authorized_until": "2026-12-31"
    }
  ]
}
```

- Plain hostnames or objects with authorization metadata are supported.
- `.example.com` matches the host and all subdomains.
- Entries past their `authorized_until` date are ignored. Unreadable dates fail closed.
- Loopback and private-range targets (localhost, 127.x, 10.x, 192.168.x) are always allowed.

Manage the scope file:

```bash
cyberswarm authorize <host>       # add a target
cyberswarm authorize --list       # view authorized targets
cyberswarm authorize --remove     # remove a target
```

### Authenticated Testing

When the target has a login wall, supply credentials or a session cookie:

```bash
# Browser session cookie (easiest for SPA / OAuth sites)
python cli.py attack <target> --cookies-file session.txt

# Credential file for one or more identities
python cli.py attack <target> --creds-file creds.json --identity A
```

Credential file format:

```json
{
  "users": [
    {
      "identity": "A",
      "username": "testuser",
      "password": "testpass"
    }
  ]
}
```

When running interactively, `./run.sh <target>` prompts for login credentials up front before recon begins. You can enter a username/password, paste a session cookie, point at a file, continue anonymously, or abort.

Without a session, the authenticated surface (OWASP A01 Broken Access Control, A07 Authentication Failures) is reported as **not tested** rather than assumed secure. CyberSwarm never guesses or brute-forces credentials.

### Pipeline Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--max-agents` | 24 | Maximum agent runs per full attack sweep |
| `--max-iterations` | 26 | Maximum recon loop iterations |
| `--auto-approve` | false | Skip the human approval gate (unattended runs) |
| `--force` | false | Skip authorization prompt for unknown targets |
| `--backend` | ollama | Model backend: `ollama`, `openai_compat`, `local` |
| `--model` | qwen3:14b | Model name for inference |
| `--base-url` | (from config) | URL of the LLM server |

---

## Architecture

### Pipeline Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        cli.py / run.sh                           │
│                      (Entry Point)                               │
└──────────────────────────┬───────────────────────────────────────┘
                           │
         ┌─────────────────▼──────────────────┐
         │      Phase 1 — RECON               │
         │   run_recon_loop.py                 │
         │                                    │
         │  planner_policy.py (LLM + rules)   │
         │  → approval_gate.py (human check)  │
         │  → recon_engine.py (dispatch)      │
         │  → tools/* (39 tool wrappers)      │
         │  → evidence_store.py (persist)     │
         └─────────────────┬──────────────────┘
                           │
         ┌─────────────────▼──────────────────┐
         │      Phase 2 — MAP                 │
         │   build_system_map.py              │
         │   → system_map.py (SystemMap)      │
         └─────────────────┬──────────────────┘
                           │
         ┌─────────────────▼──────────────────┐
         │      Phase 3 — ATTACK              │
         │   run_agent_loop.py                │
         │                                    │
         │  PlannerAgent → AttackGraph        │
         │  → Specialist Agents (11+ agents)  │
         │  → CriticAgent (batch review)      │
         │  → IntelligenceAgent (CVE/EPSS)    │
         │  → MemoryAgent (dedup + confirm)   │
         └─────────────────┬──────────────────┘
                           │
         ┌─────────────────▼──────────────────┐
         │      Phase 4 — REPORT              │
         │   generate_attack_report.py        │
         │                                    │
         │  → Attack Report (.md)             │
         │  → Evidence Trail (per-vuln)       │
         │  → OWASP Top-10 Map               │
         │  → Dashboard (live, read-only)     │
         │  → Engagement Report (folders)     │
         └────────────────────────────────────┘
```

### Data Flow

| Artifact | File | Purpose |
|----------|------|---------|
| Recon evidence | `results/evidence/<target>.json` | Raw Phase 1 recon data |
| SystemMap | `results/system_map/<target>.json` | Structured target model |
| Attack evidence | `results/attack_evidence/<target>.json` | Phase 2 findings, proofs, agent runs |
| Attack report | `results/reports/<target>.md` | Final vulnerability report |
| Decision log | `results/attack_decision_log.jsonl` | Full agent decision audit trail |

### Model Configuration

CyberSwarm supports split models per role for performance tuning:

```yaml
model:
  model: qwen3:14b           # default model
  model_critic: qwen3:14b    # critic reviews (switch to a different model for independent review)
  model_planner: qwen3:14b   # attack-graph planning
  model_deep: qwen3:14b      # deep analysis (trade speed for depth)
```

If `model_critic` and `model_deep` are the same model, the system prints a warning — a genuinely independent critic review benefits from a different model family or size.

---

## File Structure

```
CyberSwarm/
├── cli.py                        # Entry point (all commands)
├── run.sh                        # Full pipeline script (recon → map → attack → report)
├── config.yaml                   # Configuration (model, pipeline, recon, attack, report settings)
│
├── run_recon_loop.py             # Phase 1: LLM-guided recon loop
├── planner_policy.py             # Deterministic rules planner + LLM guardrails
├── recon_engine.py               # Recon tool dispatch engine
├── approval_gate.py              # Human approval gate with audit log
├── evidence_store.py             # Phase 1 evidence persistence
│
├── build_system_map.py           # Phase 2: build SystemMap from evidence
├── system_map.py                 # SystemMap data model
│
├── run_agent_loop.py             # Phase 3: multi-agent attack loop
├── attack_engine.py              # Attack tool execution engine
├── attack_evidence_store.py      # Phase 2 findings + proof persistence
├── attack_chains.py              # Attack chain construction
│
├── generate_attack_report.py     # Phase 4: render vulnerability report
├── engagement_report.py          # Per-vulnerability engagement folders
├── evidence_trail.py             # Per-class proof trail (00_SUMMARY.md)
│
├── model_client.py               # Ollama / OpenAI-compatible LLM client (structured output)
├── authorization.py              # Scope gate (authorized_targets.json)
├── auth_handling.py              # Authenticated testing (cookies, creds)
├── confidence.py                 # Evidence-based confidence scoring
├── cvss.py                       # CVSS score computation
├── owasp_registry.py             # OWASP Top-10 category mapping
├── target.py / target_utils.py   # Target normalization and utilities
├── context.py                    # Shared execution context
├── state.py                      # Pipeline state management
├── modes.py                      # Run mode definitions (auto, guided, free)
├── phases.py                     # Engagement phase model with quality gates
├── difficulty.py                 # Real-time task difficulty assessment
├── decision_trace.py             # Decision audit trail
├── rag_memory.py                 # Cross-engagement RAG lesson memory (SQLite + FTS5)
├── memory_store.py               # Finding deduplication store
├── utils.py                      # Shared utilities
│
├── agents/                       # Specialist attack agents
│   ├── base_agent.py             # Base agent class
│   ├── planner_agent.py          # Attack graph planner
│   ├── critic_agent.py           # Batched finding reviewer
│   ├── intelligence_agent.py     # CVE/EPSS/KEV enrichment
│   ├── memory_agent.py           # Cross-agent deduplication
│   ├── web_attack_agent.py       # Web vulnerability testing
│   ├── xss_agent.py              # XSS-specific testing
│   ├── payload_agent.py          # Payload generation
│   ├── exploitation_agent.py     # Exploitation verification
│   ├── burp_agent.py             # Burp Suite Professional integration
│   ├── ad_agent.py               # Active Directory testing
│   ├── specialists.py            # Domain-specific agents (API, auth, infra, cloud)
│   ├── attack_specialists.py     # Extended specialist registry
│   └── registry.py               # Agent registration
│
├── tools/                        # Recon & attack tool wrappers (17 categories)
│   ├── passive/                  # subfinder, amass
│   ├── dns/                      # DNS resolution, zone transfer
│   ├── portscan/                 # nmap, naabu
│   ├── web/                      # httpx, whatweb, katana, gau, waybackurls, header_analysis
│   ├── tls/                      # testssl.sh, openssl
│   ├── content/                  # ffuf (content discovery)
│   ├── javascript/               # linkfinder (JS endpoint extraction)
│   ├── params/                   # arjun (parameter discovery)
│   ├── screenshots/              # gowitness
│   ├── api/                      # API endpoint detection
│   ├── attack/                   # nuclei, nikto, sqlmap, dalfox
│   ├── cloud/                    # S3 enumeration, cloud_enum
│   ├── cms/                      # wpscan
│   ├── container/                # Container/Docker detection
│   ├── directory/                # LDAP enumeration
│   ├── iot/                      # IoT-specific probes
│   ├── recon/                    # cert_info, cookie_analyzer, CSRF, GraphQL, robots.txt, etc.
│   ├── commix/                   # Command injection tool (vendored)
│   ├── jwt_tool/                 # JWT analysis tool (vendored)
│   ├── Corsy/                    # CORS misconfiguration tool (vendored)
│   ├── LinkFinder/               # JavaScript link extraction (vendored)
│   ├── registry.py               # Tool registration and lookup
│   ├── wordlists.py              # Wordlist management
│   └── preflight.py              # Tool availability checker
│
├── schema/                       # JSON schema validation
│   ├── enums.py                  # Recon capability enums
│   ├── attack_enums.py           # Attack profile enums
│   ├── validator.py              # Recon decision validator
│   └── attack_validator.py       # Attack decision validator
│
├── prompts/                      # LLM prompt templates (Markdown + YAML frontmatter)
├── scenarios/                    # Planner benchmark scenarios (52 scenarios)
├── benchmarks/                   # Validation benchmarks (lab, XBOW, paper results)
├── skills/                       # Penetration testing playbooks
│   └── pentestcode/
│       ├── web/                  # SQLi, XSS, SSRF, SSTI, XXE, LFI, deserialization, upload-RCE
│       ├── playbooks/            # AD, cloud, webapp playbooks
│       ├── services/             # SSH, SMB, FTP, Docker/K8s, database, CICD
│       └── phases/               # Post-exploitation, reporting
│
├── tests/                        # Pytest suite (offline, faked model calls, loopback HTTP)
├── scripts/                      # Packaging, decision-to-scenario converter
├── config/                       # authorized_targets.json
├── docs/                         # Design history and notes
├── bin/                          # CLI entry point wrappers
│
├── requirements.txt              # Python dependencies
├── pyproject.toml                # Build config, Ruff linting rules
├── install_cyberswarm_tools.sh   # Automated external tool installer (Ubuntu)
├── .gitignore                    # Git ignore rules
├── PROJECT_GUIDE.md              # Complete project design guide
├── TOOLS_REFERENCE.md            # All tools, commands, install instructions
├── CHANGELOG.md                  # Version history
└── README.md                     # This file
```

---

## Agents

CyberSwarm uses specialist agents, each focused on a domain:

| Agent | File | Role |
|-------|------|------|
| **PlannerAgent** | `planner_agent.py` | Builds and maintains the attack graph; decides which agent runs next |
| **WebAttackAgent** | `web_attack_agent.py` | Web vulnerability scanning (nuclei, nikto, corsy, feroxbuster); WAF/CDN-aware |
| **XSSAgent** | `xss_agent.py` | Targeted XSS testing (dalfox) |
| **PayloadAgent** | `payload_agent.py` | Payload crafting and injection testing |
| **ExploitationAgent** | `exploitation_agent.py` | Exploitation verification with captured evidence |
| **BurpAgent** | `burp_agent.py` | Burp Suite Professional active scanner integration (REST API) |
| **ADAgent** | `ad_agent.py` | Active Directory: AS-REP roast, Kerberoast, SMB null session, BloodHound analysis |
| **CriticAgent** | `critic_agent.py` | Skeptical reviewer — batch-reviews all findings per agent in one LLM call |
| **IntelligenceAgent** | `intelligence_agent.py` | Enriches confirmed findings with CVE, EPSS scores, KEV status |
| **MemoryAgent** | `memory_agent.py` | Cross-agent finding deduplication; only CONFIRMED findings become vulnerabilities |
| **API/Auth/Infra/Cloud Specialists** | `specialists.py` | Domain-specific testing for APIs, authentication, infrastructure, and cloud services |

---

## Tools & Capabilities

### Phase 1 — Recon (37 capabilities)

| Category | Capability | Tool |
|----------|-----------|------|
| Passive Recon | SUBDOMAIN_DISCOVERY | subfinder |
| Passive Recon | PASSIVE_ASSET_DISCOVERY | amass |
| DNS | DNS_RESOLUTION | dnspython (Python) |
| DNS | DNS_ENUMERATION | dnspython (Python) |
| Port Scanning | HOST_DISCOVERY | nmap |
| Port Scanning | PORT_DISCOVERY | naabu |
| Port Scanning | SERVICE_DETECTION | nmap |
| Port Scanning | OS_IDENTIFICATION | nmap |
| Web Probing | WEB_PROBING | httpx |
| Web Probing | WEB_TECHNOLOGY_DISCOVERY | whatweb |
| Web Probing | HEADER_ANALYSIS | Built-in (Python) |
| TLS | TLS_ANALYSIS | testssl.sh / openssl |
| Web Crawling | WEB_CRAWLING | katana |
| Content Discovery | CONTENT_DISCOVERY | ffuf |
| Historical | HISTORICAL_URL_DISCOVERY | gau / waybackurls |
| JavaScript | JAVASCRIPT_ANALYSIS | linkfinder |
| Parameters | PARAMETER_DISCOVERY | arjun |
| Screenshots | SCREENSHOT_CAPTURE | gowitness |
| Recon (built-in) | CERT_INFO, COOKIE_ANALYSIS, CSRF_DETECTION, DESERIALIZATION_DETECTION, GRAPHQL_INTROSPECTION, ROBOTS_TXT, SENSITIVE_ENDPOINT_DETECTION, SESSION_ANALYSIS, UPLOAD_FORM_DETECTION | Python modules |

### Phase 3 — Attack Tools

| Tool | Purpose |
|------|---------|
| nuclei | Template-based vulnerability scanning |
| nikto | Web server misconfiguration scanning |
| sqlmap | SQL injection testing |
| dalfox | XSS testing |
| commix | Command injection testing |
| feroxbuster | Content discovery / forced browsing |
| Corsy | CORS misconfiguration detection |
| jwt_tool | JWT token analysis and attack |
| Burp Suite Pro | Active scanning (optional, REST API) |
| OWASP ZAP | Active scanning (free alternative to Burp) |
| impacket | AD: AS-REP roast, Kerberoast |
| s3_enum | S3 bucket enumeration (built-in, read-only) |

---

## Key Modules Explained

Beyond the main pipeline scripts (`cli.py`, `run_recon_loop.py`), several standalone modules handle specific responsibilities:

### `controller.py` — Evidence-Driven Assessment Controller

An autonomous assessment loop that **does not need an LLM** for action selection. Instead, it uses the `ActionScorer` to deterministically rank every available capability by expected information gain, then executes the top pick.

**Loop:** score all capabilities → pick highest → execute via `ToolManager` → fold results into `AssessmentState` → record a `Decision` object → repeat until action budget or time limit is exhausted.

Key parameters (via CLI or config):
- `--max-actions` — total capability executions allowed (default 100)
- `--max-time` — wall-clock time limit in seconds (default 1800)
- `--no-high-risk` — skip capabilities flagged `active_high`

### `action_scorer.py` — Deterministic Action Ranker

Scores every candidate action on four weighted axes:

| Axis | Weight | What It Measures |
|------|--------|-----------------|
| Information Gain | 0.4 | How much new data the action is expected to produce |
| Success Likelihood | 0.3 | Probability the tool will return useful output |
| Novelty | 0.2 | Whether this action has been tried before on this target |
| Risk | 0.1 | Penalty based on intrusiveness: passive = 0, active_low = 0.1, active_high = 0.3 |

No LLM is involved — scoring is pure arithmetic on the current `AssessmentState`.

### `scan_router.py` — Active-Scan Engine Selector

Decides which scanner to use for active vulnerability scanning:

- **Burp Pro** → preferred (full scanner capabilities)
- **Burp Community** → skipped (no scanner in Community Edition)
- **OWASP ZAP** → free fallback

Returns a decision dict (`{tool, reason}`) but **never launches anything** — the caller is responsible for execution.

### `batch.py` — Multi-Target Serial Assessor

Runs the Controller assessment loop across multiple targets in sequence. Each target gets a fresh `AssessmentState`, memory, and trace. Unauthorized targets are skipped automatically. At the end, a batch summary is written to `results/reports/_batch.<timestamp>.{md,json}`.

### `ablation.py` — Strategy Benchmark (No Network Required)

Compares three action-selection strategies on **simulated** targets with known dependency structures:

| Strategy | Description |
|----------|------------|
| `evidence` | Uses `ActionScorer` (the production strategy) |
| `registry` | Fixed registration order |
| `random` | Random capability selection |

Metrics: `assets_found`, `evidence_items`, `coverage_ratio`, `area_under_curve`. Fully deterministic — no network or LLM calls.

### `dashboard_server.py` — Read-Only Status Server

A lightweight HTTP server (stdlib only, no Flask) for monitoring running assessments:

```
GET /                              → index page
GET /cyberswarm/targets            → list of assessed targets
GET /cyberswarm/state/<target>     → current AssessmentState as JSON
```

Uses the `/cyberswarm/` prefix to avoid collisions with reverse-proxy routes. Launch it with `cyberswarm dashboard`.

### `generate_assess_report.py` — Assessment Report Generator

Produces the final Markdown report after a Controller assessment:

- Target profile and scope summary
- Evidence table with confidence scores
- Capability coverage heat-map
- Complete decision trace (every action + outcome)
- Tool reliability statistics
- Risk-rated findings sorted by severity

### `export_to_evidence_manager.py` — Evidence Exporter

Exports all `CONFIRM`-confidence findings to the `evidence_manager` module. If `evidence_manager` is not importable (e.g., packaged builds), falls back to self-contained JSON + Markdown export files.

---

## Packaging & Distribution

CyberSwarm can be packaged into a distributable archive:

```bash
python scripts/package.py
```

This produces a `.zip` containing the full project (source, tools directory, config, README) ready for deployment on a new machine. After extracting, run `install_cyberswarm_tools.sh` on the target host to install external dependencies.

---

## Configuration Reference

All settings are in `config.yaml`. CLI flags override config values.

### Key Sections

```yaml
model:
  backend: ollama                    # ollama | openai_compat | local
  model: qwen3:14b                   # default LLM model
  model_critic: qwen3:14b            # model for critic reviews
  model_planner: qwen3:14b           # model for attack planning
  model_deep: qwen3:14b              # model for deep analysis
  base_url: http://localhost:11434   # LLM server URL

pipeline:
  max_agents: 24           # agent runs per full sweep
  max_pivot_depth: 3       # pivot cascade depth
  auto_approve: false      # human approval gate on/off

recon:
  max_iterations: 26       # recon loop iterations (26 = all capabilities)

attack:
  tool_timeout: 900        # per-tool subprocess timeout (seconds)
  waf_skip: false          # auto-skip tools when WAF/CDN detected
  owasp: true              # force OWASP Top-10 coverage

session:
  mode: auto               # auto | guided | free
  pause: never             # never | always | checkpoint

rag:
  enabled: true            # cross-engagement lesson memory
  top_k: 5                 # lessons per planner call
```

See `config.yaml` for the full reference with comments on every option, including Burp Suite, ZAP, Active Directory, difficulty assessment, and engagement phase gates.

---

## Benchmarking & Validation

### All Paper Results in One Command

```bash
python benchmarks/paper_results.py                                # deterministic only
python benchmarks/paper_results.py --model qwen3:8b --repeats 5   # + model recon rates
python benchmarks/paper_results.py --model qwen3:8b --repeats 5 \
    --xbow-repo ../validation-benchmarks                          # + XBOW detection
```

### Individual Benchmarks

| Benchmark | Command | Requirements |
|-----------|---------|-------------|
| Planner decision quality (52 scenarios) | `python run_benchmark.py --model qwen3:8b` | Model |
| Compact prompt variant | `python run_benchmark.py --prompt compact` | Model |
| Deterministic planner baseline | `python run_benchmark.py --rules-only` | None |
| Local lab detection + false-positive control | `python benchmarks/lab_bench.py` | Flask |
| XBOW benchmark detection | `python benchmarks/xbow_bench.py --repo ../validation-benchmarks` | Docker |

### Benchmark Scores

`run_benchmark.py` prints three scores from the same model replies:

- **llm**: the model on its own
- **guarded**: after `planner_policy.py` guardrails + rules fallback (what the recon loop actually executes)
- **rules**: the deterministic planner with no model

It also lists the model's most common mistakes as expected → got pairs. Results are saved to `results/benchmarks/`.

### Growing the Scenario Set

Every `[o]verride` in the approval gate is a labelled example:

```bash
python scripts/decisions_to_scenarios.py          # preview
python scripts/decisions_to_scenarios.py --write  # append to scenarios/scenarios.json
```

---

## Testing

```bash
python -m pytest tests/ -q
```

- The suite runs **offline** — model calls are faked, HTTP tests use local loopback servers.
- Files written to `results/` are reverted after each test session (`tests/conftest.py`).
- Three tests require locally installed tools (nmap, impacket, full tool set for preflight) and fail without them. CI deselects them.
- CI (`.github/workflows/ci.yml`) runs lint on new modules, the test suite, and the rules-only planner benchmark.

---

## FAQ

**Q: My code takes a very long time to run. I cannot run it in 5 minutes.**
A: Run it ahead of time and demonstrate the output your code produces. Use `python cli.py status <target>` to show the saved results.

**Q: Which model should I use?**
A: `qwen3:8b` fits a 6 GB GPU and runs at ~18.7 tokens/sec. `qwen3:14b` is more accurate (84.6% guarded pass rate) but needs 8+ GB VRAM. On CPU, expect 4–5 tokens/sec.

**Q: Can I use a different LLM?**
A: Yes. Any Ollama model or OpenAI-compatible API works. Set the model name and backend URL in `config.yaml`.

**Q: How do I add a new tool?**
A: See Section 12 ("Extending: add a tool or an agent") in [PROJECT_GUIDE.md](PROJECT_GUIDE.md). Create a wrapper in the appropriate `tools/` subdirectory, register its capability in the enum, and add a scenario to the benchmark.

**Q: How do I add a new agent?**
A: Subclass `BaseAgent` in `agents/`, register it in `agents/registry.py`, and add it to the planner's attack graph options. See [PROJECT_GUIDE.md](PROJECT_GUIDE.md) Section 12 for the full walkthrough.

**Q: What if I do not have code in my project?**
A: If your project uses any computing software (simulation tools, testbeds, etc.), show those tools and how you use them. If purely theoretical, speak with the Project Coordinator.

---

## References

- [PROJECT_GUIDE.md](PROJECT_GUIDE.md) — Complete architecture guide, design decisions, and file-by-file reference
- [TOOLS_REFERENCE.md](TOOLS_REFERENCE.md) — All tools with exact commands, install instructions, and known issues
- [CHANGELOG.md](CHANGELOG.md) — Version history and what changed when
- [README_LIVE_PROOFS.md](README_LIVE_PROOFS.md) — Live proof capture documentation

---

## License

This project is developed at Amrita School of Engineering for academic and authorized security research purposes only. Use only on systems you own or have explicit written authorization to test.
