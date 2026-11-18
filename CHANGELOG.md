# Changelog

Newest first. Older detailed write-ups are in [docs/history/](docs/history/).

## 2026-10-26: one-command paper-results harness

- New `benchmarks/paper_results.py` runs every benchmark the host supports —
  lab detection, the 52-scenario recon planner (rules always; LLM + guarded
  when a backend is reachable, with repeats for mean ± sd), the XBOW detection
  and ablation variants (when `--xbow-repo` and Docker are present), and
  efficiency (historical + a measured end-to-end run with `--time-e2e`). It
  writes one `paper_results.json` plus the paper's Table 3, Table 4 and the
  Figure 3–6 CSVs under `results/paper/<timestamp>/`, and records any
  experiment it cannot run as `skipped` with a reason rather than fabricating a
  number. A SUMMARY.md maps each value to its paper cell and lists the commands
  for the cells still to run.

## 2026-10-26: ask about login up front

- `cyberswarm full` (and `run.sh`) now asks about authentication **before
  recon**, so you supply credentials once and the whole engagement uses them,
  instead of only being asked when the attack phase starts. The up-front prompt
  offers: enter a username/password, paste a session cookie, or continue (a
  login found during recon still prompts). Skipped when credentials were passed
  as flags, in `--dry-run`, and in non-interactive / `--auto-approve` runs.

## 2026-10-26: friendlier login handling + login-wall sites

- When a login is detected and no session was supplied, an interactive run (a
  real terminal, not `--auto-approve`/CI) now offers a short menu instead of
  only printing guidance: **enter a username and password** (prompted, password
  hidden via getpass), **paste a session cookie** (the easy path for SPA /
  OAuth / login-wall sites), point at a `--cookies-file`/`--creds-file`,
  continue anonymously, or abort. Entering credentials or pasting a `Cookie:`
  header turns the run authenticated on the spot — no file to hand-write.
  Non-interactive runs never block.
- **Login-wall detection:** targets whose root is essentially the login (little
  or no anonymous surface — common for SPAs and portals) are now called out as
  a LOGIN WALL in the console, the report and the menu, so a near-empty
  anonymous result reads as "you need a session here", not "nothing found".

## 2026-10-26: login handling ("what to do when the target has a login")

- New `auth_handling.py`: detects whether the target has a login (password
  form, OAuth/SSO/SAML, or a login-ish auth path) and reports one of three
  states — no login, authenticated (a session/credentials were supplied), or
  login detected but nothing supplied. In the last case it prints exactly how
  to supply a session cookie or credentials and marks the authenticated surface
  (OWASP A01/A07) as **not tested** rather than assumed secure.
- Wired `--creds-file` / `--cookies-file` / `--identity` into `cyberswarm
  attack` and `full` (previously only `assess` used them). When supplied for an
  authorized target, the engagement context is loaded and the run reports
  authenticated mode; the authenticated surface is tested only with
  operator-supplied credentials/cookies — never guessed or brute-forced.
- The attack run prints an `[auth]` notice at start, and the report gains an
  **Authentication** section. Shown on the real wolt.com map, which uses OAuth:
  the login is now correctly detected and flagged as untested without creds.

## 2026-10-26: attack phase no longer crashes on a malformed planner graph

- Fixed a crash that aborted the entire attack phase: when the LLM returned the
  attack graph as a list of bare agent names (or other non-object shapes)
  instead of the documented list of objects, `PlannerAgent._sanitize` did
  `node.get("agent")` on a string and raised
  `'str' object has no attribute 'get'`. This took down `cli.py attack`,
  `full`, `run.sh` and the `--mode e2e` lab benchmark (which read 0% recall
  purely because the run crashed before any tool executed — not a detection
  failure). `_sanitize` now coerces string nodes (`"web_attack"` ->
  `{"agent": "web_attack"}`), reads alternate keys (`name`/`id`), and rejects
  non-list / non-dict graphs; refinement is additionally wrapped so any
  malformed LLM output falls back to the deterministic rule graph. Regression
  tests cover list-of-strings, non-list, top-level-list and non-JSON replies.

## 2026-10-26: lab benchmark fixed, SQL-error detection reliability

Investigating a 0% lab recall report, the root causes were in the test setup
and a drifted marker, not the detection engine:

- **Lab discovery gap:** `scripts/lab_app.py` linked none of its vulnerable
  endpoints from the index, so recon discovered no parameters and the attack
  phase had no surface to test. The index now links `/greet`, `/search`,
  `/calc` and `/page` the way a real app exposes its surface.
- **Lab SQLi was non-differential:** the simulated query matched `SELECT` in
  the static SQL, so it errored on every request including the benign
  baseline, which a baseline-comparing scanner correctly ignores. It now
  errors only when the user input breaks the quoting.
- **SQL-error fingerprint had drifted:** `payload_probe` kept a private copy of
  the SQL-error regex that was narrower than the canonical one in
  `tools/attack/verdict.py` (no "unclosed quotation", only empty-quote
  `near "": syntax error`), so it under-reported SQL injection. The probe now
  reuses the one canonical marker, which was also broadened to match non-empty
  `near "X": syntax error` and common Postgres/SQLite error strings.
- **`benchmarks/lab_bench.py` rebuilt** with a deterministic default
  `--mode detection`: it seeds the known lab endpoints into a SystemMap and
  runs the PayloadAgent directly, needing no model backend and no external
  tools, so the recall number is reproducible on any machine. `--mode e2e`
  keeps the full `recon`+`attack` pipeline run (adds discovery, needs the
  backend + tools). Measured: **100% recall (4/4: xss, sqli, ssti, lfi), 0
  false positives on the clean control.** A CI-friendly test pins this.

## 2026-10-26: per-target OWASP coverage

- New per-target OWASP Top-10 coverage report: for each category A01–A10 it
  shows the status (tested / attempted with no tool output / not tested / no
  tooling), which tools actually ran, finding counts by verdict (proven /
  confirmed / disputed / unproven) and the reason each finding did not hold up.
  It appears in `cyberswarm report <target>` and in `cyberswarm owasp <target>`,
  and is shown even when nothing was confirmed, so an empty engagement reads as
  "here is what was tested" instead of looking broken.
  (`owasp_registry.per_target_coverage` / `render_target_coverage`.)
- Coverage is honest about generic tools: a plain `nuclei` run no longer counts
  as having tested every `nuclei_*` template family (SSRF, SQLi, …). Only the
  categories whose specific tools actually ran are marked tested.
- Fixed swapped A09/A10 labels in the report module: A09 is Security Logging &
  Monitoring Failures and A10 is SSRF, per OWASP 2021 (the registry was already
  correct, so the two now agree and SSRF findings label correctly).

## 2026-10-24: planner reliability, honest summaries, cleanup

**LLM decision quality**
- Fixed a policy contradiction. The prompt's "mandatory TLS" rule said it
  overrode every other rule, but 8 of the 15 benchmark scenarios had port 443
  open and expected a different step. Models that obeyed the prompt (qwen3:30b)
  were scored wrong. TLS analysis is now required **before stopping** on an
  HTTPS target, which matches the prompt's own priority list. Both prompts are
  updated.
- New `planner_policy.py`:
  - a deterministic rules planner
  - guardrails that correct LLM decisions only when they break a hard rule:
    scope, repeats, dead ends, architecture-specific capabilities without
    evidence, STOP while a mandatory step is pending, OS profiles without OS
    evidence, pivoting to internal IPs
  - one repair retry with the validation errors fed back, then the rules
    fallback

  The recon loop no longer stops on the first invalid model reply.
- `model_client.py` sends a JSON schema for constrained decoding (Ollama
  `format`, OpenAI `response_format`), with an automatic fallback for servers
  that reject it.
- The validator no longer auto-registers hallucinated capability names, and no
  longer turns a missing capability into a silent STOP. It repairs common slips:
  confidence given as `85`, booleans as strings, a single string where a list
  belongs, `<think>` blocks.
- Benchmark: 15 → 52 scenarios. Each cites the prompt rule it tests, and 3
  contradictory labels are fixed. `run_benchmark.py` reports `llm`, `guarded`
  and `rules` scores from the same replies, a table of the model's common
  mistakes, `--prompt compact`, `--rules-only` and `--min-pass`.
  `scripts/decisions_to_scenarios.py` turns approval-gate overrides into
  scenarios.

**Results / reporting**
- The engagement summary showed "0 attempts" whenever nothing was confirmed:
  `build_trail_from_evidence` ignored disputed findings and proof requests.
  wolt.com now shows 11 attempts across 5 classes.
- Proof requests stored as `"[agent] Name: detail"` text are parsed. The
  classifier uses the tool or agent when the name is generic, and missing-header
  findings (for example `X-XSS-Protection`) are no longer filed as XSS.
- New `benchmarks/lab_bench.py`: recall on `scripts/lab_app.py` plus
  false positives on a clean control page. No Docker needed.

**Safety / cleanliness**
- Scope entries can carry `authorized_by`, `scope` and `authorized_until`, and
  expired entries are ignored (an unreadable date fails closed). Plain-string
  entries still work.
- Tests no longer leave changes in `results/`: a session fixture reverts them.
- `scripts/package.py` builds a source-only zip (318 files, about 0.8 MB, versus
  4,318 files and 15.5 MB). Added the CI workflow, rewrote the README and moved
  the dated docs to `docs/history/`.

## 2026-10-15: live proofs
- `cli.py proofs` / `scripts/generate_live_proofs.py`: browser-executed XSS
  proof, payload bundles and probe classification, written to
  `results/proofs/` and the dashboard store.

## 2026-10-14: wolt.com engagement (authorized)
- Full recon → map → attack → report. All quality gates passed (enumeration
  88%, surface 91%), 11 attack modules ran, 0 confirmed vulnerabilities behind
  CloudFront.

## 2026-10-06: evidence-honesty pass + preflight
- `tools/attack/verdict.py`: confidence derived from the proof criteria that
  matched. csrf, crlf, file_upload, jwt_exploit, ssrf, ssti, deserialization
  and waf_bypass_payloads were moved onto it.
- `tools/preflight.py` + `config/tool_reference.json`. Added fixed-sample
  output tests for the attack tool parsers.

## 2026-09-22 → 09-28: PayloadAgent, engagement reports, Burp/ZAP
- PayloadAgent (payload generation + probing) with a 16-case scenario suite.
- `engagement_report.py`, `evidence_trail.py`, evidence-manager export.
- Burp and ZAP integration, browser-based XSS proof, scan router, finding
  extractor, CVSS, AD graph.

## 2026-09-01: model benchmark
- qwen3:8b scored 100% valid JSON and a 53.3% full pass rate. qwen3:30b with
  `--think` scored best on target profiles (86.7%). Default: qwen3:8b. The
  30b's TLS behaviour turned out to be the prompt contradiction fixed on
  2026-10-24.

## 2026-08-17: review fix pass
- Attack surface is now saved to disk, requirements are complete, the scope
  file is externalized, the CONFIRM confidence floor was added and a warning
  for same-model critic review. Details:
  [docs/history/CHANGELOG_2026-08-17.md](docs/history/CHANGELOG_2026-08-17.md).

## 2026-08-07: speed + trust (Tier-1)
- 14b → 8b on GPU (3.5 h → about 17 min per run), batched critic, WAF/CDN-aware
  web attack (3,405 s → 103 s), concurrent cloud enumeration, finding
  aggregation and dedup, S3 exposure proof.
