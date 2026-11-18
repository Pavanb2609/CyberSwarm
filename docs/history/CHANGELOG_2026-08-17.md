# CyberSwarm — Fix Pass, 2026-08-17

All 5 issues from the review are fixed and covered by tests. Full suite:
**309/309 passing** (baseline was 296/298 — the 2 pre-existing failures
were a missing dependency, fixed as part of this pass).

See `CyberSwarm_fixes.patch` for the exact unified diff against the
version you uploaded.

---

## 1. `attack_surface` was never persisted to disk

**File:** `build_system_map.py`

`derive_attack_surface()` was called *after* `save_map()`, purely to power
console output. The field written to `results/system_map/<target>.json`
was always `{}`, even though every downstream consumer worked around it by
recomputing the surface fresh (so nothing was functionally broken — but
the saved JSON was misleading to anyone inspecting it directly, and any
future code trusting the persisted field would have silently gotten
nothing).

**Fix:** compute the surface first, store it on the map, *then* save.

**Test:** `tests/test_build_system_map.py` — builds a map, reloads it from
disk, and asserts the surface round-tripped.

---

## 2. `requirements.txt` was missing real dependencies

**File:** `requirements.txt`

Only `requests` was listed, but the codebase imports `yaml` (`cli.py`,
`run_agent_loop.py`), `dns` (`tools/dns/dns_enum.py`), and `ldap3`
(`tools/directory/ldap_enum.py`). A fresh `pip install -r requirements.txt`
would fail the moment DNS enum, LDAP enum, or config loading ran. This is
also what caused the 2 pre-existing test failures.

**Fix:** added `PyYAML`, `dnspython`, `ldap3` with comments on what each is for.

---

## 3. Hardcoded authorization allowlist, no scope/expiry metadata

**Files:** new `authorization.py`, new `config/authorized_targets.json`;
updated `run_recon_loop.py`, `run_agent_loop.py`

Both entry points had their own hardcoded Python `set()` of pre-authorized
hostnames — including real-looking production domains
(`app.syfe.com`, `1win.com`, `app.codacy.com`, etc.) — with no record of
who authorized them, under what scope, or until when. Anyone with repo
write access could add a hostname and it would be silently trusted forever.

**Fix:** externalized into `config/authorized_targets.json`. An entry only
bypasses the "type YES" confirmation prompt if it has a **real,
non-placeholder `scope` and `authorized_by`**, and (if set) hasn't hit its
`authorized_until` expiry. Both `run_recon_loop.py` and `run_agent_loop.py`
now call the same shared `authorization.confirm()` so the two phases can't
drift into different allowlists again.

**⚠️ Action needed on your end:** I migrated your existing domains into the
registry, but I don't have your actual authorization details, so I left
`TODO` placeholders in their `scope`/`authorized_by` fields. **Those
targets will now prompt for interactive confirmation again** until you
fill in real values in `config/authorized_targets.json`. `scanme.nmap.org`
is filled in for real (it's a public test target) and will continue to
bypass the prompt as before.

Also removed an `auto_approve` parameter on `run_agent_loop.py`'s
`confirm_authorization()` that was passed through but never actually used
in the function body — dead parameter, now gone.

**Tests:** `tests/test_authorization_gate.py` — updated + 5 new tests
covering placeholder rejection, expiry, and case-insensitive lookup.

---

## 4. No confidence floor on CONFIRM verdicts

**File:** `agents/critic_agent.py`

A `CONFIRM` verdict with `adjusted_confidence=15` was stored in
`vulnerabilities[]` exactly like a `CONFIRM` at confidence 95 — the
verdict alone gated storage, confidence was just along for the ride.

**Fix:** `MIN_CONFIRM_CONFIDENCE = 50`. Any `CONFIRM` whose blended
`final_confidence` (the existing `agent*0.4 + critic*0.6` formula) falls
below this is downgraded to `NEEDS_PROOF` instead, with a note appended to
the finding's description explaining why.

**Tests:** 2 new tests in `tests/test_agents.py` — one confirms the
downgrade fires, one confirms a genuinely high-confidence CONFIRM is left
alone.

---

## 5. Same-model critic self-review was silent

**Files:** `run_agent_loop.py`, `config.yaml`

`config.yaml` ships with every `model_*` key set to the same model
(`qwen3:8b`), meaning the "adversarial" CriticAgent reviews findings using
the same model that produced them — a second pass with a different
prompt, not genuine independent review. This isn't necessarily wrong to
run, but it was never surfaced anywhere.

**Fix:** `run_agent_loop.py` now prints a `[WARNING]` at startup whenever
`model_critic == model_deep`, explaining the limitation and how to fix it.
`config.yaml` comments updated to match.

---

## Bonus fixes (same review, low-risk)

- **`docs/skill/references/critic_agent.md` had drifted** from the real
  `critic_agent.py`/`memory_agent.py` (missing the batch index-remap fix,
  confidence coercion, and the new confidence floor). Rewrote it to
  describe behavior and link to source instead of embedding a second copy
  of the code that can drift again.
- **Auth/API path detection used raw substring matching** — `/login`
  would match inside unrelated text like `/how-to-login-safely`, and
  `/rest` inside `/restaurant-finder`. Now requires a path-segment
  boundary (`system_map.py::_hint_matches()`). 3 new tests.
- Removed a dead unused variable (`all_paths_str`) in `system_map.py`
  while touching that function.

## Not changed (judgment calls, flagging for awareness)

- `human_approval_gate()` rejecting an agent still marks it
  `completed_agents`, so a rejected agent can't be individually re-run
  without `--reset-memory` wiping everything. Left as-is since I wasn't
  sure if that's intentional (prevents re-litigating a human's "no").
- `schema_version` in `system_map.py` is set but still unread/unmigrated
  anywhere. Low risk today since every reader uses `.get()` with defaults;
  worth a real migration path if the map shape changes later.
