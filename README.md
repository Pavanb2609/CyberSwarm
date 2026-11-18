# CyberSwarm

Self-hosted, multi-agent penetration-testing framework for **authorized**
assessments. A local LLM (Ollama or any OpenAI-compatible server) decides what
to do next; real security tools do the work; a human approval gate, a scope
file and an evidence-honesty layer keep it accountable.

- **Recon loop:** an LLM planner picks the next recon capability (37
  capabilities, 39 tool wrappers). A deterministic policy layer enforces the
  hard rules and takes over if the model's output is unusable.
- **SystemMap:** one shared model of the target (assets, ports, services,
  endpoints, auth/API paths, attack surface).
- **Attack loop:** specialist agents (web, API, auth, infra, cloud, AD,
  payload, XSS, Burp/ZAP, exploitation), plus a Critic that reviews every
  finding and an Intelligence agent that adds CVE/EPSS/KEV data.
- **Evidence honesty:** confidence comes from the proof checks that actually
  matched. A CONFIRM below 50 is downgraded to NEEDS_PROOF, and "proven"
  requires captured execution evidence.
- **Reports:** attack report, a per-vulnerability engagement folder, a proof
  trail, an OWASP Top-10 map, an evidence-manager export and a read-only
  dashboard.

Full architecture and design notes: [PROJECT_GUIDE.md](PROJECT_GUIDE.md).
What changed and when: [CHANGELOG.md](CHANGELOG.md).

---

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m tools.preflight          # which external tools are installed / missing
```

Model backend (`config.yaml` → `model:`):

- **Ollama:** `ollama serve`, then `ollama pull qwen3:8b`. The default model fits a 6 GB GPU.
- **OpenAI-compatible:** vLLM, LM Studio or the llama.cpp server, usually on `:8000`.

Structured output (constrained JSON decoding) is used automatically when the
server supports it: Ollama ≥ 0.5 `format`, or OpenAI-compatible
`response_format`. Older servers fall back to plain calls without error.

## Scope (required before any non-lab target)

`config/authorized_targets.json`:

```json
{"targets": [
  "lab.example",
  {"target": "app.client.com", "authorized_by": "J. Smith (client CISO)",
   "scope": "SOW-2026-14, web app only", "authorized_until": "2026-12-31"}
]}
```

- Entries are plain hosts or objects with authorization metadata.
  `.example.com` matches the host and all of its subdomains.
- An entry past its `authorized_until` date is ignored. An unreadable date
  fails closed.
- Loopback and lab targets (localhost, 127.x and the private ranges) are
  always allowed.
- Manage the file with `cyberswarm authorize <host>`, `--list` and `--remove`.

## Common commands

```bash
./run.sh <target>                         # recon -> map -> attack -> report, end to end
python cli.py recon  <target>             # recon loop (approval gate on every step)
python cli.py attack <target>             # multi-agent attack loop
python cli.py report <target>             # regenerate the attack report
python cli.py evidence <target>           # per-vulnerability proof trail
python cli.py status <target>             # resume view
python cli.py dashboard                   # read-only live dashboard
python cli.py ask "find the subdomains of example.com"
python cli.py help [topic]                # agents, phases, modes, prompts, safety ...
```

Run modes: `--mode auto | guided | free` and `--pause never | ...`. See
`python cli.py help modes`.

## Targets with a login (authenticated testing)

When recon detects a login (a password form, OAuth/SSO, or a login path), the
attack run says so with an `[auth]` notice and the report gains an
**Authentication** section. To test the surface *behind* the login, supply a
session or credentials for an account you are authorized to use:

```bash
# a browser session cookie (easiest): a 'Cookie: a=b; c=d' line, JSON map, or HAR
python cli.py attack <target> --cookies-file session.txt

# or credentials for one or more identities
python cli.py attack <target> --creds-file creds.json --identity A
#   creds.json: {"users":[{"identity":"A","username":"...","password":"..."}]}
```

`./run.sh <target>` and `cyberswarm full <target>` ask about a login **up
front, before recon**, so you provide access once for the whole engagement.

If you don't pass anything and you're at a terminal, the run asks. You
can **enter a username and password right there** (you're prompted; the
password is hidden), **paste a session cookie** (the easy path for SPA / OAuth
/ login-wall sites — log in with your browser, copy the `Cookie:` header, paste
it), point at a file, continue anonymously, or abort. Either path turns the run
authenticated on the spot, so you don't have to hand-write a creds file.
Automated runs (`--auto-approve`, scheduled, CI) never block and just print the
guidance.

**Login-wall sites** (the root *is* the login, e.g. a SPA or portal) are
flagged as a LOGIN WALL: the anonymous surface is tiny, so a near-empty result
means "supply a session to go further", not "nothing found".

Without a session, the authenticated surface (OWASP A01 Broken Access Control,
A07 Authentication Failures) is reported as **not tested** rather than assumed
secure. CyberSwarm never guesses or brute-forces credentials; authenticated
testing uses only what you provide.

## Measuring it

**All paper results in one command.** `benchmarks/paper_results.py` runs every
benchmark your machine supports, writes one `paper_results.json`, and renders
the paper's Table 3, Table 4 and Figure 3–6 CSVs under `results/paper/<ts>/`.
Experiments it cannot run (no model, no Docker, missing tools) are recorded as
`skipped` with a reason — never fabricated.

```bash
python benchmarks/paper_results.py                               # deterministic only
python benchmarks/paper_results.py --model qwen3:8b --repeats 5  # + model recon rates
python benchmarks/paper_results.py --model qwen3:8b --repeats 5 \
    --xbow-repo ../validation-benchmarks                         # + XBOW detection/ablation
python benchmarks/paper_results.py --model qwen3:8b --time-e2e   # + measured efficiency
```

The individual benchmarks it orchestrates can also be run directly:

| What | Command | Needs |
|---|---|---|
| Planner decision quality (52 scenarios) | `python run_benchmark.py --model qwen3:8b` | model |
| Same, compact prompt | `python run_benchmark.py --prompt compact` | model |
| Deterministic planner baseline | `python run_benchmark.py --rules-only` | nothing |
| Detection on the local lab + false-positive control | `python benchmarks/lab_bench.py` | Flask |
| Detection on XBOW benchmarks | `python benchmarks/xbow_bench.py --repo ../validation-benchmarks` | Docker |

`run_benchmark.py` prints three scores computed from the **same** model replies:

- `llm`: the model on its own
- `guarded`: after `planner_policy.py` guardrails and the rules fallback. This
  is what the recon loop actually executes.
- `rules`: the deterministic planner with no model

It also lists the model's most common mistakes as expected → got pairs.
Results are saved to `results/benchmarks/`.

Grow the scenario set from real runs: every `[o]verride` in the approval gate
is a labelled example.

```bash
python scripts/decisions_to_scenarios.py          # preview
python scripts/decisions_to_scenarios.py --write  # append to scenarios/scenarios.json
```

## Tests

```bash
python -m pytest tests/ -q
```

- The suite runs offline. Model calls are faked, and the HTTP tests use local
  loopback servers.
- Anything a test writes into `results/` is reverted at the end of the session
  (see `tests/conftest.py`).
- Three tests need locally installed tools (nmap, impacket and the full tool
  set for preflight) and fail without them. CI deselects them.
- CI (`.github/workflows/ci.yml`) runs lint on the new modules, the test suite
  and the rules-only planner benchmark.

## Packaging

```bash
python scripts/package.py            # dist/CyberSwarm_merged_31_<date>.zip, source only
```

The package leaves out `node_modules`, caches and `results/`, since engagement
results can contain real target data. Use `--with-results` to include them on
purpose.

## Layout

```
cli.py                    entry point (all commands)
run_recon_loop.py         recon loop: plan -> approve -> execute -> merge -> repeat
planner_policy.py         deterministic rules planner + guardrails around the LLM planner
run_agent_loop.py         multi-agent attack loop
model_client.py           Ollama / OpenAI-compatible client (structured output)
schema/                   capability/profile enums + strict decision validator
prompts/                  planner prompts (full + compact) and reusable prompts
scenarios/scenarios.json  planner benchmark scenarios (each cites the rule it tests)
system_map.py             shared target model
agents/                   specialist agents, critic, intelligence, memory, planner
tools/                    recon + attack tool wrappers, registries, preflight
benchmarks/               lab_bench, xbow_bench, scoring, taxonomy
evidence_trail.py         per-class attempt/proof trail (00_SUMMARY.md)
engagement_report.py      per-vulnerability engagement folders
authorization.py          scope gate
approval_gate.py          human approval + audit log
tests/                    pytest suite
```
