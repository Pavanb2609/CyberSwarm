#!/usr/bin/env python3
"""
The full Phase 1.2 loop:

    evidence -> Planner -> capability -> [human approval] -> Recon Engine
    -> tool executes -> results merged into evidence -> repeat

Stops when the planner returns a terminal capability (STOP_NO_RELEVANT_ACTION,
BLOCK_EXECUTION), asks for evidence the engine can't supply
(REQUEST_ADDITIONAL_EVIDENCE / REQUEST_AUTHORIZED_CREDENTIALS), a human
rejects a step, or max_iterations is hit.

Usage:
    python run_recon_loop.py scanme.nmap.org \
        --backend ollama --model qwen3:8b --base-url http://192.168.0.66:11434
"""

import argparse
import json
import re
import socket
import sys
from pathlib import Path
from typing import Any, Dict

from model_client import ModelClient, chat_structured
from agents.base_agent import extract_json
import approval_gate
import planner_policy
import modes
import phases
import evidence_store
import recon_engine
from tools import registry

ROOT = Path(__file__).parent
PROMPT_PATH = ROOT / "prompts" / "recon_planner.txt"
PROMPT_COMPACT_PATH = ROOT / "prompts" / "recon_planner_compact.txt"

TERMINAL_CAPABILITIES = {"STOP_NO_RELEVANT_ACTION", "STOP", "BLOCK_EXECUTION"}
PAUSE_CAPABILITIES = {"REQUEST_ADDITIONAL_EVIDENCE", "REQUEST_AUTHORIZED_CREDENTIALS", "VERIFY_SCOPE"}
PIVOT_CAPABILITIES = {"PIVOT_TO_SUBDOMAIN", "RETURN_FROM_SUBDOMAIN"}
DECISION_LOG_PATH = ROOT / "results" / "decision_log.jsonl"

# Logical execution order for --run-all mode
CAPABILITY_EXECUTION_ORDER = [
    "PASSIVE_ASSET_DISCOVERY",
    "SUBDOMAIN_DISCOVERY",
    "DNS_RESOLUTION",
    "DNS_ENUMERATION",
    "HOST_DISCOVERY",
    "PORT_DISCOVERY",
    "SERVICE_DETECTION",
    "OPERATING_SYSTEM_IDENTIFICATION",
    "WEB_PROBING",
    "WEB_TECHNOLOGY_DISCOVERY",
    "TLS_ANALYSIS",
    "HEADER_ANALYSIS",
    "CERT_INFO",
    "WEB_CRAWLING",
    "HISTORICAL_URL_DISCOVERY",
    "CONTENT_DISCOVERY",
    "PARAMETER_DISCOVERY",
    "JAVASCRIPT_ANALYSIS",
    "API_ENDPOINT_DISCOVERY",
    "GRAPHQL_INTROSPECTION",
    "CMS_IDENTIFICATION",
    "CMS_ASSESSMENT",
    "SCREENSHOT_CAPTURE",
    "DIRECTORY_SERVICE_ENUMERATION",
    "WINDOWS_SERVICE_ENUMERATION",
    "CLOUD_ASSET_DISCOVERY",
    "S3_LIST",
    "CONTAINER_DISCOVERY",
    "IOT_SERVICE_IDENTIFICATION",
    "ROBOTS_TXT_ANALYSIS",
    "SENSITIVE_ENDPOINT_DETECTION",
    "UPLOAD_FORM_DETECTION",
    "CSRF_SURFACE_DETECTION",
    "COOKIE_ANALYSIS",
    "SESSION_ANALYSIS",
    "AUTH_FLOW_ANALYSIS",
    "DESERIALIZATION_DETECTION",
]

# System prompt for the LLM-guided planning pass used by --run-all mode.
RUNALL_PLAN_PROMPT = """You are the recon planner for an authorized penetration test of {target}.

We must run a FULL sweep: every capability in the supplied list will eventually execute.
Your job is to OPTIMIZE the order (and optionally provide parameter hints), not to cut
anything.

Guidance:
- Use every capability in the list exactly once; reorder freely.
- Group by phase for efficiency: passive/DNS discovery -> network scanning ->
  web fingerprinting -> web fuzzing/enrichment.
- Prefer cheap, high-signal steps before expensive fuzzers (e.g. do
  WEB_TECHNOLOGY_DISCOVERY before CONTENT_DISCOVERY so fuzzers can use real techs).
- param_hints is optional per-capability free-form guidance passed to the tool
  wrappers, e.g. {{"ports": "443,8443"}}, {{"focus_subdomains": ["a.example.com"]}},
  {{"paths": ["/admin", "/api"]}}.

Current evidence:
{evidence}

Remaining capabilities:
{capabilities}

Return ONLY JSON:
{{"order": ["CAP_A", ...], "rationale": "...", "param_hints": {{"CAP_B": {{"ports": "443"}}}}}}
"""


def confirm_authorization(target: str, force: bool = False) -> None:
    """Scope gate for the recon loop: hard block un-authorized live targets.

    Offers an interactive `y/N` step-up when a human is at the terminal;
    in unattended/CI runs it stays a hard block. `--force` bypasses (lab
    and explicitly overridden scripted runs).
    """
    if force:
        return
    import authorization as _authz
    if not _authz.offer_authorize(target, action="reconnaissance against the target"):
        raise SystemExit("[authorization] aborted: target not authorized. "
                         "Run `cyberswarm authorize <target>` (or --yes) first, "
                         "or re-run with --force.")


def load_recon_lessons() -> str:
    """Parse decision_log.jsonl to extract patterns from past sessions.
    Returns a text block the planner can use for cross-session intelligence."""
    if not DECISION_LOG_PATH.exists():
        return ""

    tool_stats = {}
    target_profiles_seen = {}

    with open(DECISION_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            evidence = entry.get("evidence", {})
            decision = entry.get("model_decision", {})
            cap = decision.get("next_capability", "")

            if cap in ("STOP_NO_RELEVANT_ACTION", "BLOCK_EXECUTION",
                       "VERIFY_SCOPE", "REQUEST_ADDITIONAL_EVIDENCE",
                       "PIVOT_TO_SUBDOMAIN", "RETURN_FROM_SUBDOMAIN"):
                continue

            profile = decision.get("target_profile", "UNKNOWN")
            target_profiles_seen[profile] = target_profiles_seen.get(profile, 0) + 1

            if cap not in tool_stats:
                tool_stats[cap] = {"successes": 0, "failures": 0, "timeout_failures": 0}

            completed = evidence.get("completed_actions", [])
            failed = evidence.get("failed_actions", [])

            if cap in completed:
                tool_stats[cap]["successes"] += 1
            if cap in failed:
                tool_stats[cap]["failures"] += 1
                prev = evidence.get("previous_observations", [])
                for obs in prev:
                    if cap in obs and "timeout" in obs.lower():
                        tool_stats[cap]["timeout_failures"] += 1
                        break

    if not tool_stats:
        return ""

    lines = ["CROSS-SESSION INTELLIGENCE (from prior scans):"]
    for cap, stats in sorted(tool_stats.items()):
        total = stats["successes"] + stats["failures"]
        if total > 1:
            fail_rate = stats["failures"] / total
            if fail_rate > 0.7:
                lines.append(f"- {cap} failed {stats['failures']}/{total} times in past sessions "
                             f"(fail rate {fail_rate:.0%})")
            if stats["timeout_failures"] > 0:
                lines.append(f"- {cap} timed out {stats['timeout_failures']} time(s) in past sessions")

    if target_profiles_seen:
        lines.append(f"- Target profiles seen: {dict(target_profiles_seen)}")

    return "\n".join(lines) if len(lines) > 1 else ""


def auto_resolve_subdomains(ev):
    """Batch-resolve all discovered subdomains and store IPs in evidence."""
    subs = ev.get("subdomains", [])
    if not subs:
        return
    sr = ev.get("subdomain_resolutions", {})
    unresolved = [s for s in subs if s not in sr]
    if not unresolved:
        return
    print(f"\n[auto-resolve] Resolving {len(unresolved)} new subdomain(s)...")
    for sub in unresolved:
        try:
            socket.setdefaulttimeout(5)
            ip = socket.gethostbyname(sub)
            sr[sub] = ip
            print(f"  {sub} -> {ip}")
        except (socket.gaierror, socket.timeout, OSError):
            sr[sub] = None
            print(f"  {sub} -> (unresolvable)")
    ev["subdomain_resolutions"] = sr
    evidence_store.save(ev)


def compress_evidence(evidence):
    """Aggressively compress evidence to fit within small context windows.
    The model only needs: target, what's been done, what was found, what's next."""
    c = {}
    c["target"] = evidence.get("target", "")

    # Core state
    if evidence.get("resolved_ip"):
        c["resolved_ip"] = evidence["resolved_ip"]
    if evidence.get("reachable") is not None:
        c["reachable"] = evidence["reachable"]
    if not evidence.get("resolved_ip") and evidence.get("subdomains"):
        c["hint"] = "No main IP resolved yet. Run DNS_RESOLUTION or PORT_DISCOVERY on main target first."

    # What we know
    if evidence.get("open_ports"):
        c["open_ports"] = evidence["open_ports"]
    elif "PORT_DISCOVERY" in evidence.get("completed_actions", []) or \
         "HOST_DISCOVERY" in evidence.get("completed_actions", []):
        # Explicitly tell the LLM ports were scanned but nothing was found.
        # Without this, open_ports=[] is falsy and compress_evidence drops it,
        # so the LLM thinks PORT_DISCOVERY was never run and re-selects it every iteration.
        c["open_ports_scanned"] = "PORT_DISCOVERY ran but found no open ports (host may filter/block probes). Do NOT re-run PORT_DISCOVERY. Target is reachable via HTTP — proceed with web recon capabilities."
    if evidence.get("technologies"):
        c["technologies"] = evidence["technologies"][:10]
    if evidence.get("services"):
        c["services"] = evidence["services"][:5]
    if evidence.get("cms_detected"):
        c["cms_detected"] = evidence["cms_detected"]

    # Subdomains - separate internal vs external
    subs = evidence.get("subdomains", [])
    if subs:
        res = evidence.get("subdomain_resolutions", {})
        resolved = [s for s in subs if res.get(s)]
        unresolvable = [s for s in subs if res.get(s) is None and s in res]
        internal = [s for s in subs if (res.get(s) or "").startswith("10.") or (res.get(s) or "").startswith("192.168.") or (res.get(s) or "").startswith("172.16.")]
        external = [s for s in subs if res.get(s) and not ((res.get(s) or "").startswith("10.") or (res.get(s) or "").startswith("192.168.") or (res.get(s) or "").startswith("172.16."))]
        c["subdomains"] = f"{len(subs)} total, {len(external)} external, {len(internal)} internal, {len(unresolvable)} dead"
        if external:
            c["external_subs"] = {s: res[s] for s in external[:15]}
        if internal:
            c["internal_subs_note"] = f"{len(internal)} internal IPs (10.x/192.168.x) - unreachable from outside, skip PIVOT"
        if resolved:
            c["resolved_count"] = len(resolved)

    # What's been done - compact format
    done = list(evidence.get("completed_actions", []))
    failed = evidence.get("failed_actions", [])
    zero = evidence.get("zero_findings_actions", [])

    # BUG FIX: httpx (WEB_PROBING) often surfaces technologies, which means
    # WEB_TECHNOLOGY_DISCOVERY has effectively been done — but it never appears
    # in completed_actions because whatweb wasn't explicitly run. Without this
    # the LLM sees technologies in evidence AND WEB_TECHNOLOGY_DISCOVERY absent
    # from done[] and keeps picking it, wasting an iteration.
    if evidence.get("technologies") and "WEB_TECHNOLOGY_DISCOVERY" not in done:
        done = done + ["WEB_TECHNOLOGY_DISCOVERY (inferred: technologies detected via WEB_PROBING)"]

    if done:
        c["done"] = done
    if failed:
        c["failed"] = failed
    if zero:
        c["zero_findings"] = zero

    # Subdomain pivot status
    if evidence.get("active_subtarget"):
        c["active_subtarget"] = evidence["active_subtarget"]
    if evidence.get("subdomains_exhausted"):
        c["subdomains_exhausted"] = True
    results = evidence.get("subtarget_results", {})
    if results:
        c["pivoted_to"] = list(results.keys())

    # Last 3 observations only, max 80 chars each
    obs = evidence.get("previous_observations", [])[-3:]
    if obs:
        c["last_observations"] = [o[:80] for o in obs]

    # BUG FIX: When open_ports=[] AND target is reachable via web,
    # the LLM stalls because it sees no ports and gets confused about
    # what to do next. Inject an explicit hint listing remaining web
    # capabilities so the loop continues rather than stopping early.
    done_set = set(evidence.get("completed_actions", []))
    if (evidence.get("reachable") and not evidence.get("open_ports")):
        web_remaining = [cap for cap in [
            "TLS_ANALYSIS", "WEB_CRAWLING", "CONTENT_DISCOVERY",
            "JAVASCRIPT_ANALYSIS", "HISTORICAL_URL_DISCOVERY",
            "API_ENDPOINT_DISCOVERY", "PARAMETER_DISCOVERY",
            "CMS_IDENTIFICATION", "SCREENSHOT_CAPTURE",
        ] if cap not in done_set]
        if web_remaining:
            c["web_recon_hint"] = (
                f"Target is reachable via HTTP/HTTPS. No raw TCP ports were found "
                f"(common behind load balancers/CDN). Continue web recon. "
                f"Remaining web capabilities: {web_remaining}"
            )

    return c


def _llm_plan_todo(client, target: str, evidence, todo: list):
    """Ask the LLM to order/prioritize the remaining capabilities for --run-all.
    Returns (ordered_todo, param_hints). On any failure (model unreachable, bad
    JSON, empty order) falls back to the deterministic order with no hints."""
    hints = {}
    caps_json = json.dumps(list(todo))
    evidence_json = json.dumps(compress_evidence(evidence))
    # Build the filled prompt FIRST and split it into (system, user) only after
    # formatting. Splitting the raw template put the literal "{target}"
    # placeholder in the system message and dumped the whole instruction body
    # into the user turn — dolphin-family models respond to that shape by
    # echoing the prompt back verbatim instead of answering, which was the
    # "model returned no parseable JSON" failure.
    prompt = RUNALL_PLAN_PROMPT.format(target=target, evidence=evidence_json,
                                       capabilities=caps_json)
    system, user = prompt.split("\n\n", 1)
    # Constrained decoding: Ollama's "format" field forces valid JSON matching
    # this schema (see model_client.py structured_output notes). Removes the
    # prose/echo failure mode entirely; servers that reject it are retried
    # without the schema transparently by ModelClient.
    schema = {
        "type": "object",
        "properties": {
            "order": {"type": "array", "items": {"type": "string"}},
            "rationale": {"type": "string"},
            "param_hints": {"type": "object"},
        },
        "required": ["order"],
    }
    try:
        raw = chat_structured(client, system, user, json_schema=schema, temperature=0.0)
        data = extract_json(raw)
        # Retry once: 8b models sometimes truncate/corrupt long JSON on the
        # first attempt. Only helps if it wasn't a hard 700-token cutoff, so
        # the client must be built with a higher max_tokens for this call.
        if data is None and todo:
            raw = chat_structured(client, system, user, json_schema=schema, temperature=0.0)
            data = extract_json(raw)
        if data is None:
            raise ValueError("model returned no parseable JSON (twice)")
        order = data.get("order") or []
        rationale = data.get("rationale", "")
        hints = data.get("param_hints") or {}
        planned = [c for c in order if c in set(todo)]
        seen = set()
        deduped = []
        for c in planned:
            if c not in seen:
                seen.add(c)
                deduped.append(c)
        final = deduped + [c for c in todo if c not in seen]
        print(f"[recon-llm] Planner ordered {len(final)} capabilities. Rationale: {rationale}")
        return final, hints
    except Exception as e:
        print(f"[recon-llm] LLM planning failed ({e}); using deterministic order.")
        return list(todo), hints


# Parameters execute_capability() takes explicitly (see recon_engine.py). An
# LLM param_hint using one of these names would otherwise collide with the
# explicit call below -- this happened in practice: a 'timeout' hint on
# WEB_PROBING crashed run-all with "got multiple values for keyword argument
# 'timeout'". 'timeout' is still honored (popped out and used to override
# the per-call timeout, since that's a reasonable planner suggestion);
# 'capability'/'target' are dropped outright since those must only ever
# come from the loop itself, never from the LLM.
_RESERVED_EXECUTE_CAPABILITY_KWARGS = {"capability", "target"}


def build_capability_kwargs(evidence: dict, cap_hints: dict, default_timeout: int,
                            full_url: str = None) -> tuple:
    """Build the kwargs dict + resolved timeout for one execute_capability()
    call, merging evidence-derived defaults with LLM param_hints safely.
    Returns (kwargs, timeout)."""
    kwargs = {}
    if evidence.get("open_ports"):
        kwargs["ports"] = ",".join(str(p) for p in evidence["open_ports"])
    if evidence.get("cms_detected"):
        kwargs["cms"] = evidence["cms_detected"]
    if evidence.get("discovered_paths"):
        kwargs["discovered_paths"] = evidence["discovered_paths"]
    if evidence.get("technologies"):
        kwargs["technologies"] = evidence["technologies"]
    # discovered_urls holds plain URL strings, but discovered_paths holds dicts
    # like {"url": ..., "status": 403, "length": 358}. Concatenating them and
    # calling dict.fromkeys() crashed because a dict is unhashable. Normalise
    # every entry to its URL string first.
    def _as_url(item):
        if isinstance(item, dict):
            return str(item.get("url") or item.get("path") or "")
        return str(item or "")

    raw_endpoints = (evidence.get("discovered_urls", []) or []) \
        + (evidence.get("discovered_paths", []) or [])
    endpoints = list(dict.fromkeys(
        u for u in (_as_url(e) for e in raw_endpoints) if u))
    if endpoints:
        kwargs["endpoints"] = endpoints[:15]
    auth_hint_segments = ("login", "admin", "auth", "signin", "oauth", "signup", "register",
                          "forgot", "reset", "session", "account", "profile", "logout", "password")
    auth_paths = [str(p) for p in endpoints
                  if str(p).lstrip("/").split("?")[0].split("/")[0].lower() in auth_hint_segments]
    if auth_paths:
        kwargs["auth_paths"] = auth_paths[:8]
    for k, v in (cap_hints or {}).items():
        if v not in (None, "") and k not in _RESERVED_EXECUTE_CAPABILITY_KWARGS:
            kwargs[k] = v
    if full_url:
        kwargs["full_url"] = full_url
    timeout = kwargs.pop("timeout", default_timeout)
    if isinstance(timeout, str):
        match = re.search(r"\d+(\.\d+)?", timeout)
        timeout = float(match.group()) if match else default_timeout
    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        timeout = default_timeout
    return kwargs, timeout


def _stale_reset(args, evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Discard recon evidence older than --stale-days for LIVE targets.

    A months-old evidence file describes a past incarnation of the host
    (stale services/technologies/endpoints AND completed_actions that make
    capabilities skip). Rebuilding fresh is cheap; poisoning a live run with
    ghost endpoints (e.g. admin.php on a rebuilt SPA) is expensive.
    """
    stale_days = getattr(args, "stale_days", None)
    if stale_days is None or stale_days <= 0:
        return evidence
    import evidence_store as es
    age = es.file_age_days(es.path_for(args.target))
    if age is not None and age > stale_days:
        print(f"[recon] stored evidence for {args.target} is {age:.0f} days old "
              f"(> {stale_days}); discarding stale facts — rebuilding from a "
              f"fresh pass against the live host.")
        return es.fresh(args.target)
    return evidence


def _harvest_root_surface(full_url: str) -> tuple:
    """Deterministic one-page harvest of links, form actions and form params.

    Katana follows hrefs but ignores <form action> as a navigable target, and
    many benchmark apps (XBEN-076 '/greet?name=') expose their whole attack
    surface in the landing page's form. Returns (urls, params): urls are
    absolute endpoint URLs, params are injectable "action?name=1" strings.
    """
    from urllib.parse import urljoin, urlsplit, urlunsplit

    try:
        import requests
        resp = requests.get(full_url, timeout=15, verify=False,
                            headers={"User-Agent": "Mozilla/5.0 (compatible; CyberSwarm)"})
        html = resp.text or ""
    except Exception:  # noqa: BLE001
        return [], []

    urls: list[str] = []
    forms: list[dict] = []   # {"action", "method", "inputs"}

    import html.parser as _hp

    class _P(_hp.HTMLParser):
        cur: dict | None = None

        def handle_starttag(self, tag, attrs):
            a = {k: v for k, v in attrs}
            if tag == "a" and a.get("href"):
                link = urljoin(full_url, str(a["href"]).split("#", 1)[0])
                if link.startswith("http") and link not in urls:
                    urls.append(link)
            elif tag == "form":
                action = a.get("action") or ""
                act = urljoin(full_url, action) if action else full_url
                self.cur = {"action": act,
                            "method": (a.get("method") or "get").lower(),
                            "inputs": []}
                forms.append(self.cur)
            elif tag in ("input", "textarea", "select") and self.cur is not None:
                n = a.get("name")
                if n and n not in self.cur["inputs"]:
                    self.cur["inputs"].append(n)

    p = _P()
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001
        pass

    params: list[str] = []
    for form in forms[:10]:
        act, inputs = form["action"], form["inputs"][:4]
        if not inputs:
            continue
        for name in inputs:
            sep = "&" if "?" in act else "?"
            cand = f"{act}{sep}{name}=1"
            if cand not in params:
                params.append(cand)
        if form["method"] == "get" and act not in urls:
            urls.append(act)
    # relative -> absolute already handled; drop fragments/queries from urls
    urls = [u for u in urls if isinstance(u, str) and u.startswith("http")]
    return urls[:60], params[:60]


def run_all_mode(args):
    """Run every registered capability in logical order, bypassing the planner."""
    pass

    evidence = evidence_store.load(args.target, warn_on_regression=False)
    evidence = _stale_reset(args, evidence)
    if getattr(args, "fresh", False):
        import evidence_store as es
        print(f"[recon] --fresh: discarding ALL stored evidence for {args.target} "
              f"(completed/failed/zero-findings) — rebuilding from scratch.")
        evidence = es.fresh(args.target)
        evidence_store.save(evidence)
    if args.retry_failed and evidence.get("failed_actions"):
        cleared = evidence["failed_actions"]
        evidence["failed_actions"] = []
        evidence_store.save(evidence)
        print(f"Cleared failed_actions (will retry): {cleared}")

    completed = set(evidence.get("completed_actions", []))
    failed = set(evidence.get("failed_actions", []))
    zero = set(evidence.get("zero_findings_actions", []))
    skip = completed | failed | zero

    todo = [cap for cap in CAPABILITY_EXECUTION_ORDER if cap not in skip]
    print(f"\n=== RUN-ALL MODE ===")
    print(f"Target: {args.target}")
    print(f"Already done ({len(completed)}): {sorted(completed)}")
    print(f"Skipping ({len(skip)}): {sorted(skip)}")
    print(f"To run ({len(todo)}): {todo}")
    print()

    param_hints = {}
    if todo and not args.dry_run:
        try:
            # LLM-guided planning pass: optimizes order + tool hints. Uses a short
            # timeout so a hung/unreachable model degrades to deterministic quickly.
            client = ModelClient(backend=args.backend, base_url=args.base_url,
                                 model=args.model, api_key=args.api_key,
                                 temperature=args.temperature, timeout=min(args.timeout, 90),
                                 think=args.think,
                                 max_tokens=1500)  # ordering JSON for 26 caps overflows 700
            todo, param_hints = _llm_plan_todo(client, args.target, evidence, todo)
            if todo != [c for c in CAPABILITY_EXECUTION_ORDER if c not in skip]:
                print(f"[recon-llm] Optimized execution order: {todo}")
        except Exception as e:
            print(f"[recon-llm] LLM planning unavailable ({e}); using deterministic order.")

    for i, cap in enumerate(todo, 1):
        if cap not in registry.CAPABILITY_TOOL_MAP:
            print(f"[{i}/{len(todo)}] {cap} -- no tool registered, skipping")
            continue

        tools = registry.CAPABILITY_TOOL_MAP[cap]
        tool_status = []
        for t in tools:
            try:
                tool = registry.load_tool(t)
                problem = tool.validate()
                tool_status.append(f"{t}:{'OK' if not problem else 'MISSING'}")
            except Exception as e:
                tool_status.append(f"{t}:ERROR")
        print(f"[{i}/{len(todo)}] {cap} -> {', '.join(tool_status)}")

        if args.dry_run:
            print("  [dry-run] not executing tools")
            continue

        cap_hints = param_hints.get(cap) or {}
        kwargs, timeout = build_capability_kwargs(
            evidence, cap_hints, args.tool_timeout,
            full_url=getattr(args, "full_url", None))
        # A ~4.6k-entry wordlist at modest request rates needs >5 min; the
        # generic 180s tool timeout killed ffuf mid-run so CONTENT_DISCOVERY
        # produced nothing (and downstream agents starved). Floor the known
        # slow, high-value capabilities instead of raising every tool's cap.
        if cap in ("CONTENT_DISCOVERY", "PARAMETER_DISCOVERY",
                   "SCREENSHOT_CAPTURE", "JAVASCRIPT_ANALYSIS"):
            timeout = max(timeout, 600)

        result = recon_engine.execute_capability(cap, args.target,
                                                 timeout=timeout, **kwargs)
        print(f"  Tool: {result.tool} | Status: {result.status}")
        if result.status != "success":
            print(f"  Error: {result.error}")
        else:
            res_str = json.dumps(result.results, indent=2)
            print(f"  Results: {res_str[:500]}{'...' if len(res_str) > 500 else ''}")

        evidence = evidence_store.merge_tool_result(evidence, result)
        obs = evidence.get("previous_observations", [])
        if len(obs) > 50:
            evidence["previous_observations"] = obs[-50:]
        evidence_store.save(evidence)
        auto_resolve_subdomains(evidence)
        print()

    # ── Late surface enrichment ──────────────────────────────────────────
    # (a) Content discovery can miss form-action endpoints entirely (katana
    #     follows hrefs but not <form action>), so harvest the landing page
    #     deterministically. (b) PARAMETER_DISCOVERY can be ordered before
    #     CONTENT_DISCOVERY, leaving no params at discovery time; if we now
    #     have endpoint paths but zero params, give arjun one second pass.
    if getattr(args, "full_url", None) or str(args.target).startswith("http"):
        harvest_url = args.full_url or args.target
        hu, hp = _harvest_root_surface(harvest_url)
        if hu or hp:
            from tools.base import ToolResult
            tr = ToolResult(tool="root_surface_harvest", status="success",
                            capability="WEB_CRAWLING",
                            results={"discovered_urls": hu,
                                     "discovered_parameters": hp,
                                     "count": len(hu) + len(hp)})
            evidence = evidence_store.merge_tool_result(evidence, tr)
            evidence_store.save(evidence)
            print(f"[ENRICH] root surface harvest: {len(hu)} urls, {len(hp)} param targets")
    if (evidence.get("discovered_paths")
            and not evidence.get("discovered_parameters")):
        print("[ENRICH] re-running PARAMETER_DISCOVERY against discovered endpoints")
        kwargs, timeout = build_capability_kwargs(
            evidence, {}, args.tool_timeout,
            full_url=getattr(args, "full_url", None))
        result = recon_engine.execute_capability(
            "PARAMETER_DISCOVERY", args.target, timeout=max(timeout, 300), **kwargs)
        print(f"  Tool: {result.tool} | Status: {result.status}")
        evidence = evidence_store.merge_tool_result(evidence, result)
        obs = evidence.get("previous_observations", [])
        evidence["previous_observations"] = (obs + [
            f"param_enrich_after_content_discovery: {json.dumps(result.results or {})[:100]}"
        ])[-50:]
        evidence_store.save(evidence)
        print()

    print_summary(evidence, args.target)

    # Fold this run's evidence into the cross-engagement RAG memory so the next
    # planner call can retrieve it. No-op when rag.auto_reindex is false.
    try:
        import rag_memory as rag
        rag.maybe_auto_reindex()
    except ImportError:
        pass


def main():
    p = argparse.ArgumentParser(description="Run the full plan -> approve -> execute -> evidence loop")
    p.add_argument("target")
    p.add_argument("--backend", choices=["ollama", "openai_compat"], default="ollama")
    p.add_argument("--base-url", default="http://localhost:11434")
    p.add_argument("--model", default="qwen3:8b")
    p.add_argument("--api-key", default=None)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--tool-timeout", type=int, default=180)
    p.add_argument("--think", action="store_true")
    p.add_argument("--max-iterations", type=int, default=None,
                   help="Cap on planner iterations (default from config.yaml recon.max_iterations)")
    p.add_argument("--retry-failed", action="store_true",
                   help="Clear failed_actions from saved evidence before starting, so capabilities "
                        "that failed last time (e.g. due to a missing wordlist you've since fixed) "
                        "get retried instead of being skipped forever.")
    p.add_argument("--fresh", action="store_true",
                   help="Discard ALL stored recon evidence for the target (completed, failed and "
                        "zero-findings actions) and rebuild from scratch. Use when the last run "
                        "was interrupted or the target changed since (e.g. an unreachable host "
                        "during the previous pass poisoned the store with empty results).")
    p.add_argument("--stale-days", type=int, default=7,
                   help="Discard stored recon evidence older than this many days and rebuild "
                        "fresh against the live host (default 7; 0/negative disables).")
    p.add_argument("--auto-approve", action="store_true",
                   help="Skip human approval gate -- auto-approve every decision.")
    modes.add_cli_arguments(p)
    p.add_argument("--force", action="store_true",
                   help="Skip authorization confirmation prompt.")
    p.add_argument("--run-all", action="store_true",
                   help="Run every registered capability in sequence, bypassing the planner.")
    p.add_argument("--compact-prompt", action="store_true",
                   help="Use the compact system prompt (~950 tokens) instead of the full one (~3200 tokens).")
    p.add_argument("--dry-run", action="store_true",
                   help="Plan only -- print the capability plan and tool availability without executing anything.")
    args = p.parse_args()

    # Auto-detect a reachable model backend when the configured/base_url is dead.
    try:
        from model_client import resolve_backend_url
        args.base_url = resolve_backend_url(args.base_url, args.backend)
    except Exception:  # noqa: BLE001
        pass

    # ── URL → hostname extraction ──────────────────────────────────
    # If the user passes a full URL (e.g. https://host/path), extract the
    # hostname for DNS/port tools and store the full URL for web tools.
    from urllib.parse import urlparse
    _parsed = urlparse(args.target)
    if _parsed.scheme in ("http", "https") and _parsed.hostname:
        args.full_url = args.target          # preserve for httpx / gowitness
        args.target = _parsed.hostname       # bare hostname for dns / nmap
        if _parsed.port:
            args.target_port = _parsed.port  # explicit port if given
        print(f"[info] Parsed URL — hostname: {args.target}"
              f"{f', port: {args.target_port}' if hasattr(args, 'target_port') else ''}"
              f", full URL: {args.full_url}")

    confirm_authorization(args.target, force=args.force)

    if args.run_all:
        run_all_mode(args)
        return

    from pathlib import Path as _P
    import yaml as _yaml
    try:
        _rcfg = (_yaml.safe_load((_P(__file__).parent / "config.yaml").read_text(encoding="utf-8")) or {})
        _max_iter = _rcfg.get("recon", {}).get("max_iterations", 8)
    except Exception:  # noqa: BLE001
        _max_iter = 8
    if args.max_iterations is None:
        args.max_iterations = _max_iter

    system_prompt = (PROMPT_COMPACT_PATH if args.compact_prompt else PROMPT_PATH).read_text(encoding="utf-8")
    client = ModelClient(
        backend=args.backend, base_url=args.base_url, model=args.model,
        api_key=args.api_key, temperature=args.temperature,
        timeout=min(args.timeout, 90) if args.dry_run else args.timeout, think=args.think,
    )

    evidence = evidence_store.load(args.target, warn_on_regression=not args.auto_approve)
    evidence = _stale_reset(args, evidence)
    if getattr(args, "fresh", False):
        import evidence_store as es
        print(f"[recon] --fresh: discarding ALL stored evidence for {args.target} "
              f"(completed/failed/zero-findings) — rebuilding from scratch.")
        evidence = es.fresh(args.target)
        evidence_store.save(evidence)
    if args.retry_failed and evidence.get("failed_actions"):
        cleared = evidence["failed_actions"]
        evidence["failed_actions"] = []
        evidence_store.save(evidence)
        print(f"Cleared failed_actions (will retry): {cleared}")

    # Target stack for subdomain pivoting: list of (target_str, evidence_dict) tuples
    target_stack = []
    original_target = args.target

    # Load cross-session intelligence from past decision logs
    recon_lessons = load_recon_lessons()
    if recon_lessons:
        print(f"[lessons] Loaded cross-session intelligence from {DECISION_LOG_PATH}")

    duplicate_streak = 0
    pivot_skip_streak = 0

    for i in range(1, args.max_iterations + 1):
        print(f"\n{'#' * 60}\nITERATION {i}/{args.max_iterations}\n{'#' * 60}")
        current_target = evidence.get("active_subtarget") or original_target
        print(f"Current target: {current_target}")
        print("Current evidence (compressed):")
        print(json.dumps(compress_evidence(evidence), indent=2))

        evidence_json = json.dumps(compress_evidence(evidence))
        if recon_lessons:
            evidence_json += f"\n\n{recon_lessons}"

        if evidence.get("subdomains_exhausted"):
            evidence_json = ("!!! CRITICAL: subdomains_exhausted=true. ALL reachable different-IP "
                             "subdomains have been investigated. Do NOT select PIVOT_TO_SUBDOMAIN. "
                             "Choose a different capability or STOP_NO_RELEVANT_ACTION. !!!\n\n"
                             + evidence_json)

        # Structured-output call + one repair retry + deterministic fallback +
        # guardrails (planner_policy.py). An invalid model reply used to end
        # the whole run here; now the rules planner takes that step instead.
        decision, plan_info = planner_policy.plan(client, system_prompt, evidence, evidence_json)
        if plan_info["fallback"]:
            print(f"[planner] model output unusable ({plan_info['errors']}); "
                  f"using the deterministic rules planner for this step.")
        for correction in plan_info["corrections"]:
            print(f"[guardrail] {correction}")

        print(f"\nPlanner decision: {decision['next_capability']} "
              f"(profile={decision['target_profile']}, confidence={decision['confidence']})")

        policy = getattr(args, "_policy", None) or modes.from_args(args)
        entry = approval_gate.gate(decision, target=current_target,
                                   evidence=evidence, policy=policy)
        capability = entry.get("override_capability") or decision["next_capability"]

        # Phase gate: refuse a capability that belongs to a phase whose entry
        # conditions are not met yet. Advisory -- free mode and phases.enabled
        # false both disable it, and it never blocks terminal capabilities.
        if policy.enforces_phases and capability not in TERMINAL_CAPABILITIES:
            controller = phases.get_controller(current_target)
            ctx = phases.PhaseContext.from_evidence(evidence, target=current_target)
            allowed, why = controller.allows_capability(capability, ctx)
            if not allowed:
                print(f"[phase] {why}")
                print(f"[phase] currently in {controller.current}; "
                      f"skipping {capability} this round.")
                evidence.setdefault("failed_actions", [])
                if capability not in evidence["failed_actions"]:
                    evidence["failed_actions"].append(capability)
                continue
            moved, message, _ = controller.advance(ctx)
            if moved:
                print(f"[phase] {message}")

        if not entry["approved"] and not entry.get("override_capability"):
            print("Rejected by human. Stopping loop.")
            break

        # --- Handle terminal capabilities with subdomain return logic ---
        if capability in TERMINAL_CAPABILITIES:
            if capability in ("STOP_NO_RELEVANT_ACTION", "STOP") and evidence.get("active_subtarget"):
                # We're in a subdomain -- return to parent instead of stopping
                sub_target = evidence["active_subtarget"]
                parent_target = evidence["subtarget_parent"]

                # Save subdomain summary to parent
                summary = {
                    "target": sub_target,
                    "completed_actions": evidence.get("completed_actions", []),
                    "open_ports": evidence.get("open_ports", []),
                    "technologies": evidence.get("technologies", []),
                    "resolved_ip": evidence.get("resolved_ip"),
                    "services": evidence.get("services", []),
                }
                if target_stack:
                    parent_evidence = target_stack[-1][1]
                    parent_evidence.setdefault("subtarget_results", {})[sub_target] = summary

                # Pop back to parent
                if target_stack:
                    parent_target_str, parent_evidence = target_stack.pop()
                    parent_evidence["active_subtarget"] = None
                    parent_evidence["subtarget_parent"] = None
                    evidence = parent_evidence
                    original_target = parent_target_str
                    evidence_store.save(evidence)
                    print(f"\n[subdomain-return] Returning to parent target: {parent_target_str}")
                    continue

            print(f"\nPlanner reached a terminal capability ({capability}). Stopping loop.")
            break

        # --- Handle pivot/return capabilities ---
        if capability == "PIVOT_TO_SUBDOMAIN":
            # Guardrail: don't pivot if main target IP hasn't been resolved yet
            if not evidence.get("resolved_ip") and not evidence.get("active_subtarget"):
                print("\n[guardrail] Cannot pivot: main target IP not resolved yet. "
                      "Run DNS_RESOLUTION or PORT_DISCOVERY first.")
                evidence.setdefault("previous_observations", []).append(
                    "PIVOT blocked: no resolved_ip on main target. Run DNS_RESOLUTION or PORT_DISCOVERY first.")
                evidence_store.save(evidence)
                continue

            next_sub = decision.get("next_subdomain")
            if not next_sub:
                print("\nPIVOT_TO_SUBDOMAIN selected but no next_subdomain provided. Skipping.")
                pivot_skip_streak += 1
                continue

            # Auto-resolve subdomains before pivoting
            auto_resolve_subdomains(evidence)

            # Check if all subdomains are exhausted FIRST (sets flag for planner)
            sub_res = evidence.get("subdomain_resolutions", {})
            sub_results = evidence.get("subtarget_results", {})
            main_ip = evidence.get("resolved_ip", "")
            all_exhausted = True
            for sub, ip in sub_res.items():
                if ip is not None and ip != main_ip and sub not in sub_results:
                    all_exhausted = False
                    break
            if all_exhausted and sub_res:
                print(f"\n[subdomain-pivot] All reachable different-IP subdomains exhausted. "
                      f"No more pivots available.")
                evidence["subdomains_exhausted"] = True
                evidence.setdefault("previous_observations", []).append(
                    "PIVOT_TO_SUBDOMAIN skipped: all reachable different-IP subdomains exhausted. "
                    "Do NOT select PIVOT_TO_SUBDOMAIN again.")
                evidence_store.save(evidence)
                pivot_skip_streak += 1
                if pivot_skip_streak >= 3:
                    print("Planner re-selected PIVOT_TO_SUBDOMAIN 3 times after exhaustion. "
                          "Stopping loop.")
                    break
                continue

            # Check if already investigated
            if next_sub in evidence.get("subtarget_results", {}):
                print(f"\n[subdomain-pivot] {next_sub} already investigated. Skipping.")
                evidence.setdefault("previous_observations", []).append(
                    f"PIVOT_TO_SUBDOMAIN skipped: {next_sub} already in subtarget_results")
                evidence_store.save(evidence)
                pivot_skip_streak += 1
                if pivot_skip_streak >= 3:
                    print("Planner re-selected PIVOT_TO_SUBDOMAIN 3 times with no valid target. "
                          "Stopping loop.")
                    break
                continue

            # Verify subdomain is reachable
            sub_ip = evidence.get("subdomain_resolutions", {}).get(next_sub)
            if sub_ip is None:
                print(f"\n[subdomain-pivot] {next_sub} does not resolve. Skipping.")
                evidence.setdefault("previous_observations", []).append(
                    f"PIVOT_TO_SUBDOMAIN skipped: {next_sub} does not resolve")
                evidence_store.save(evidence)
                pivot_skip_streak += 1
                if pivot_skip_streak >= 3:
                    print("Planner re-selected PIVOT_TO_SUBDOMAIN 3 times with no valid target. "
                          "Stopping loop.")
                    break
                continue

            # Check if same IP as main domain (likely same CDN)
            main_ip = evidence.get("resolved_ip")
            if main_ip and sub_ip == main_ip:
                print(f"\n[subdomain-pivot] {next_sub} resolves to same IP as main domain ({sub_ip}). "
                      f"Likely same CDN/WAF. Skipping.")
                evidence.setdefault("previous_observations", []).append(
                    f"PIVOT_TO_SUBDOMAIN skipped: {next_sub} resolves to same IP as main domain")
                evidence_store.save(evidence)
                pivot_skip_streak += 1
                if pivot_skip_streak >= 3:
                    print("Planner re-selected PIVOT_TO_SUBDOMAIN 3 times with no valid target. "
                          "Stopping loop.")
                    break
                continue

            # Save current state and pivot
            pivot_skip_streak = 0  # reset on successful pivot
            evidence["subtarget_results"] = evidence.get("subtarget_results", {})
            target_stack.append((original_target, evidence))

            # Load or create subdomain evidence
            original_target = next_sub
            sub_evidence = evidence_store.load(next_sub)
            sub_evidence["active_subtarget"] = next_sub
            sub_evidence["subtarget_parent"] = target_stack[-1][0]
            sub_evidence["authorized_scope"] = evidence.get("authorized_scope", True)
            evidence = sub_evidence
            evidence_store.save(evidence)

            print(f"\n[subdomain-pivot] Pivoting to: {next_sub} (IP: {sub_ip})")
            continue

        if capability == "RETURN_FROM_SUBDOMAIN":
            if not target_stack:
                print("\nRETURN_FROM_SUBDOMAIN but no parent in stack. Stopping.")
                break

            parent_target_str, parent_evidence = target_stack.pop()
            parent_evidence["active_subtarget"] = None
            parent_evidence["subtarget_parent"] = None
            original_target = parent_target_str
            evidence = parent_evidence
            evidence_store.save(evidence)

            print(f"\n[subdomain-return] Returned to parent: {parent_target_str}")
            continue

        if capability in PAUSE_CAPABILITIES:
            if args.auto_approve:
                # In auto-approve mode, don't stop - add a hint and pick the next logical capability
                missing = decision.get("missing_evidence", [])
                hint = (f"NOTE: '{capability}' requested but auto-approved mode cannot supply manual input. "
                        f"Missing: {', '.join(missing) if missing else 'unknown'}. "
                        f"Select a different uncompleted capability instead.")
                print(f"[auto-approve] {hint}")
                if hint not in evidence["previous_observations"]:
                    evidence["previous_observations"].append(hint)
                evidence_store.save(evidence)
                continue
            print(f"Planner requested '{capability}' -- this needs manual input, not automated execution.")
            print("Supply the needed evidence yourself (e.g. edit the evidence file) and re-run to continue.")
            break

        # Guardrail: the prompt tells the planner not to repeat a completed
        # action, and zero_findings_actions flags dead ends -- but a small
        # local model doesn't always obey that (it re-picked
        # PASSIVE_ASSET_DISCOVERY a second time in one run). Enforce both in
        # code instead of trusting the model to self-correct. A human
        # override via [o] always bypasses this.
        already_done = capability in evidence.get("completed_actions", [])
        dead_end = capability in evidence.get("zero_findings_actions", [])
        if (already_done or dead_end) and not entry.get("override_capability"):
            duplicate_streak += 1
            why = "already completed" if already_done else "returned zero findings last time"
            print(f"Planner re-selected '{capability}', which {why}. "
                  f"Skipping re-execution (guardrail) instead of wasting a tool run on it.")
            note = (f"NOTE: '{capability}' {why} and has no new evidence to justify rerunning it. "
                    f"Do not select it again -- choose a different, uncompleted capability, "
                    f"or STOP_NO_RELEVANT_ACTION if none remain.")
            if note not in evidence["previous_observations"]:
                evidence["previous_observations"].append(note)
            evidence_store.save(evidence)
            if duplicate_streak >= 2:
                print("Planner repeated a dead-end capability twice in a row -- stopping rather than "
                      "burning the rest of the iteration budget. Consider overriding manually with [o].")
                break
            continue
        duplicate_streak = 0

        if capability not in registry.CAPABILITY_TOOL_MAP:
            print(f"No tool registered yet for capability '{capability}'.")
            print(f"Currently supported: {registry.supported_capabilities()}")
            print("Stopping loop -- add a wrapper for this capability to continue automatically.")
            break

        print(f"\nExecuting capability '{capability}' via tool registry...")
        # pass along ports if we have them, useful for nmap targeted scans
        kwargs = {}
        if evidence.get("open_ports"):
            kwargs["ports"] = ",".join(str(p) for p in evidence["open_ports"])
        if evidence.get("cms_detected"):
            kwargs["cms"] = evidence["cms_detected"]
        if evidence.get("discovered_paths"):
            kwargs["discovered_paths"] = evidence["discovered_paths"]
        if evidence.get("technologies"):
            kwargs["technologies"] = evidence["technologies"]
        # Pass full URL for web tools when target was parsed from a URL
        if hasattr(args, "full_url"):
            kwargs["full_url"] = args.full_url

        if args.dry_run:
            tools = registry.CAPABILITY_TOOL_MAP.get(capability, [])
            status = []
            for t in tools:
                try:
                    tool = registry.load_tool(t)
                    status.append(f"{t}:{'OK' if not tool.validate() else 'MISSING'}")
                except Exception:
                    status.append(f"{t}:ERROR")
            print(f"  [dry-run] would run {', '.join(status)} (no tools executed)")
            print(f"  [dry-run] planner dry-run complete after first planned action.")
            break

        result = recon_engine.execute_capability(capability, current_target,
                                                 timeout=args.tool_timeout, **kwargs)
        print(f"Tool result: tool={result.tool} status={result.status}")
        if result.status != "success":
            print(f"  error: {result.error}")
        else:
            print(f"  results: {json.dumps(result.results, indent=2)}")

        evidence = evidence_store.merge_tool_result(evidence, result)

        # Cap previous_observations to prevent evidence bloat
        obs = evidence.get("previous_observations", [])
        if len(obs) > 10:
            evidence["previous_observations"] = obs[-10:]

        evidence_store.save(evidence)

        # Auto-resolve any newly discovered subdomains
        auto_resolve_subdomains(evidence)

        if result.status == "not_installed":
            print(f"\n'{result.tool}' isn't installed on this machine. "
                  f"Install it (or another tool for '{capability}') to continue automatically.")
            break

    print(f"\n{'#' * 60}\nLoop finished. Final evidence saved to results/evidence/\n{'#' * 60}")
    parent_evidence = evidence_store.load(args.target, warn_on_regression=False)
    print_summary(parent_evidence, args.target)

    # Fold this run's evidence into the cross-engagement RAG memory so the next
    # planner call can retrieve it. No-op when rag.auto_reindex is false.
    try:
        import rag_memory as rag
        rag.maybe_auto_reindex()
    except ImportError:
        pass


def print_summary(evidence, target):
    """Print the full recon breakdown at the end of every run."""
    completed = evidence.get("completed_actions", [])
    failed = evidence.get("failed_actions", [])
    zero = evidence.get("zero_findings_actions", [])

    print(f"\n{'=' * 60}")
    print(f"RECON SUMMARY: {target}")
    print(f"{'=' * 60}")

    print(f"\n--- Target Info ---")
    print(f"  Resolved IP:   {evidence.get('resolved_ip', 'N/A')}")
    print(f"  Reachable:     {evidence.get('reachable', 'N/A')}")
    print(f"  Open ports:    {evidence.get('open_ports', [])}")
    print(f"  Services:      {evidence.get('services', [])}")
    print(f"  Technologies:  {evidence.get('technologies', [])}")
    print(f"  CMS:           {evidence.get('cms_detected', 'none')}")
    print(f"  Screenshot:    {evidence.get('screenshot_captured', False)}")
    print(f"  Subdomains:    {len(evidence.get('subdomains', []))}")

    if evidence.get("subdomains"):
        print(f"\n--- Subdomains ({len(evidence['subdomains'])}) ---")
        for sub, ip in evidence.get("subdomain_resolutions", {}).items():
            status = ip if ip else "unresolvable"
            print(f"  {sub:35s} -> {status}")

    if evidence.get("subtarget_results"):
        print(f"\n--- Subdomain Pivots ---")
        for sub, data in evidence.get("subtarget_results", {}).items():
            print(f"  {sub}:")
            print(f"    IP:          {data.get('resolved_ip')}")
            print(f"    Ports:       {data.get('open_ports', [])}")
            print(f"    Tech:        {data.get('technologies', [])}")
            print(f"    Completed:   {data.get('completed_actions', [])}")

    print(f"\n--- Capabilities Breakdown ---")
    denom = len(CAPABILITY_EXECUTION_ORDER)
    print(f"  Completed:     {len(completed)}/{denom}")
    for c in sorted(completed):
        print(f"    [x] {c}")
    print(f"  Failed:        {len(failed)}/{denom}")
    for f in sorted(failed):
        print(f"    [!] {f}")
    print(f"  Zero findings: {len(zero)}/{denom}")
    for z in sorted(zero):
        print(f"    [-] {z}")

    # A capability that finished with no findings is BOTH "completed" and
    # "zero findings" -- zero is a subset of completed, not a separate bucket.
    # Summing all three double-counted it and produced the impossible 154%.
    ran = len(set(completed) | set(failed))
    not_run = max(0, denom - ran)
    if not_run > 0:
        print(f"  Not run:       {not_run}/{denom}")

    pct = lambda n: f"{n * 100 // denom}%" if denom else "n/a"
    print(f"\n--- Pass Rate ---")
    print(f"  Ran:           {ran}/{denom} ({pct(ran)})")
    print(f"  Success:       {len(completed)}/{denom} ({pct(len(completed))})")
    print(f"  Failed:        {len(failed)}/{denom} ({pct(len(failed))})")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
