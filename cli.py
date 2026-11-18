#!/usr/bin/env python3
"""
CyberSwarm CLI — one command to drive the full offensive pipeline.

    cyberswarm full scanme.nmap.org --auto-approve
    cyberswarm recon example.com
    cyberswarm map example.com
    cyberswarm attack scanme.nmap.org --max-agents 4
    cyberswarm assess scanme.nmap.org --max-actions 20 --high-risk
    cyberswarm ablate --iterations 10
    cyberswarm report scanme.nmap.org
    cyberswarm report-assess example.com --out report.md
    cyberswarm authorize example.com
    cyberswarm tools
    cyberswarm bench --only fresh_domain_no_assets
"""

import argparse
import logging
import subprocess
import sys
from urllib.parse import urlparse

import modes
from utils import ROOT, load_config, validate_target


def _merge(args, cfg) -> None:
    """Default argparse values from config.yaml (CLI flags still win)."""
    m = cfg.get("model", {})
    p = cfg.get("pipeline", {})
    args.backend = args.backend or m.get("backend", "ollama")
    args.model = args.model or m.get("model", "qwen3:8b")
    from model_client import resolve_backend_url
    configured = args.base_url or m.get("base_url", "http://localhost:11434")
    resolved = resolve_backend_url(configured, args.backend)
    if resolved != configured:
        print(f"[model] configured backend {configured} unreachable — "
              f"auto-detected {resolved}")
    args.base_url = resolved
    if args.max_agents is None:
        args.max_agents = p.get("max_agents", 6)


def norm_target(target: str) -> str:
    """Reduce a full URL (https://host/path) to its bare hostname.

    Mirrors the normalization in run_recon_loop.py so that recon, map,
    attack and report all key their evidence/stores on the same string.
    """
    try:
        parsed = urlparse(target or "")
        if parsed.scheme in ("http", "https") and parsed.hostname:
            return parsed.hostname
    except Exception:
        pass
    return target


def cmd_recon(target: str, args) -> int:
    cmd = [sys.executable, str(ROOT / "run_recon_loop.py"), target,
           "--backend", args.backend, "--model", args.model, "--base-url", args.base_url]
    if args.run_all:
        cmd.append("--run-all")
    if args.auto_approve:
        cmd.append("--auto-approve")
    if args.force:
        cmd.append("--force")
    if getattr(args, "fresh", False):
        cmd.append("--fresh")
    if args.dry_run:
        cmd.append("--dry-run")
    return subprocess.call(cmd)


def cmd_map(target: str, args) -> int:
    target = norm_target(target)
    import build_system_map
    import system_map as sm
    m = build_system_map.build_for(target)
    sm.save_map(target, m)
    print(f"[map] saved SystemMap: results/system_map/{target}.json")
    return 0


def _context_from_choice(host: str, full_url, choice: dict):
    """Build an EngagementContext from an auth_handling resolver result."""
    from context import Credential, EngagementContext
    context = EngagementContext(target=host, base_url=full_url or f"https://{host}")
    if choice.get("cookies"):
        context.update_cookies(choice["cookies"])
    if choice.get("credentials"):
        context.credentials = [
            Credential(username=c.get("username", ""), password=c.get("password", ""),
                       identity=c.get("identity", "A"), source_url=c.get("source_url", ""))
            for c in choice["credentials"]]
        context.identity = choice.get("identity", context.identity)
    return context


def cmd_attack(target: str, args) -> int:
    import run_agent_loop
    from model_client import ModelClient
    from target_utils import parse_target_url
    host, full_url, _ = parse_target_url(target)
    cfg = load_config()
    client = ModelClient(backend=args.backend, model=args.model, base_url=args.base_url)

    # Authenticated testing: if the operator supplied credentials or a session
    # cookie for this (authorized) target, load them so the attack can test the
    # surface behind the login. If a login is detected and none were supplied,
    # run_attack prints exactly how to supply them and marks that surface as
    # not tested rather than skipping it silently.
    context = None
    creds_file = getattr(args, "creds_file", None)
    cookies_file = getattr(args, "cookies_file", None)
    if creds_file or cookies_file or getattr(args, "identity", None):
        from context import load_engagement
        try:
            context = load_engagement(host, creds_file=creds_file,
                                      cookies_file=cookies_file,
                                      base_url=full_url, identity=getattr(args, "identity", None))
        except ValueError as exc:
            print(f"[auth] {exc}")
            return 2
    elif getattr(args, "_auth_context", None) is not None:
        # Credentials were already supplied up front (e.g. at the start of
        # `full`); reuse them and do not ask again.
        context = args._auth_context
    elif not getattr(args, "dry_run", False):
        # No credentials passed: if the saved recon shows a login and a human is
        # at the terminal, offer a friendly way to supply a session right now
        # (enter credentials / paste a cookie), instead of only printing
        # guidance. Non-interactive or --auto-approve runs never block.
        try:
            import auth_handling
            import system_map as sm
            smap = sm.load_map(host)
            status = auth_handling.auth_status(smap, None, target=host)
            choice = auth_handling.interactive_resolve(
                status, host, auto=not _auth_prompt_enabled(args))
            if choice["action"] == "abort":
                if choice["message"]:
                    print(f"[auth] {choice['message']}")
                return 0
            if choice["action"] == "authenticated" and (choice.get("cookies")
                                                         or choice.get("credentials")):
                context = _context_from_choice(host, full_url, choice)
                print(f"[auth] {choice['message']}")
        except Exception as exc:  # auth prompt must never break the run
            print(f"[auth] interactive login check skipped: {exc}")

    run_agent_loop.run_attack(
        target=host, full_url=full_url, model_client=client, max_agents=args.max_agents,
        auto_approve=args.auto_approve, force=args.force,
        use_llm_planner=not args.no_llm_planner,
        max_pivot_depth=args.max_pivot_depth, dry_run=args.dry_run,
        reset_memory=getattr(args, "reset_memory", False), config=cfg,
        run_all=getattr(args, "run_all", False), context=context)
    return 0


def _auth_prompt_enabled(args) -> bool:
    """Whether the interactive auth menu may block for input.

    run.sh passes --auto-approve unconditionally (it exists to auto-approve the
    per-agent gates), which used to silence the auth menu too — a human at a
    real terminal then never got asked for credentials/cookies. Decouple the
    two: the one-time auth menu asks whenever stdin is a TTY and the
    CYBERSWARM_NO_AUTH_PROMPT env var is not set; piped/CI runs (no TTY)
    never block.
    """
    import os
    import sys
    if os.environ.get("CYBERSWARM_NO_AUTH_PROMPT"):
        return False
    return sys.stdin.isatty()


def cmd_full(target: str, args) -> int:
    # Ask about a login UP FRONT, before recon, so credentials are supplied once
    # and the whole engagement can use them. Skipped when the operator already
    # passed --creds-file/--cookies-file/--identity, in --dry-run, and in
    # non-interactive / --auto-approve runs (which never block).
    if not (getattr(args, "creds_file", None) or getattr(args, "cookies_file", None)
            or getattr(args, "identity", None)) and not getattr(args, "dry_run", False):
        try:
            import auth_handling
            from target_utils import parse_target_url
            host, full_url, _ = parse_target_url(target)
            choice = auth_handling.prelaunch_auth(host, auto=not _auth_prompt_enabled(args))
            if choice["action"] == "authenticated":
                args._auth_context = _context_from_choice(host, full_url, choice)
                print(f"[auth] {choice['message']} — will be used for the whole run.")
        except Exception as exc:  # must never block the engagement
            print(f"[auth] up-front login prompt skipped: {exc}")

    rc = cmd_recon(target, args)
    if rc != 0:
        return rc
    cmd_map(target, args)
    return cmd_attack(target, args)


def cmd_ablate(args) -> int:
    import ablation
    return ablation.run(args.max_actions, args.seed, args.iterations)


def cmd_bench(args) -> int:
    cmd = [sys.executable, str(ROOT / "run_benchmark.py"),
           "--backend", args.backend, "--model", args.model, "--base-url", args.base_url]
    if getattr(args, "only", None):
        cmd += ["--only", args.only]
    if getattr(args, "bench_prompt", None):
        cmd += ["--prompt", args.bench_prompt]
    if getattr(args, "rules_only", False):
        cmd += ["--rules-only"]
    if getattr(args, "think", False):
        cmd += ["--think"]
    if getattr(args, "min_pass", None) is not None:
        cmd += ["--min-pass", str(args.min_pass)]
    return subprocess.call(cmd)


def cmd_evidence(target: str, args) -> int:
    """Write the per-target, per-vulnerability proof trail from stored evidence."""
    import evidence_trail
    from agents.memory_agent import MemoryAgent

    if not target:
        print("Usage: python cli.py evidence <target>")
        return 1
    mem = MemoryAgent(target).load()
    vulns = mem.get("vulnerabilities", [])
    if not vulns:
        print(f"No stored findings for {target!r}. Run an attack first: "
              f"python cli.py attack {target}")
        return 1
    folder = evidence_trail.build_trail_from_evidence(target, mem)
    print(f"[evidence] proof trail written to {folder}")
    print(f"[evidence] {len(vulns)} finding(s) organised by vulnerability class")
    print(f"[evidence] open {folder}/00_SUMMARY.md")
    return 0


def cmd_report(target: str, args) -> int:
    cmd = [sys.executable, str(ROOT / "generate_attack_report.py")]
    if target:
        cmd.append(norm_target(target))
    if args.all:
        cmd.append("--all")
    if args.out:
        cmd += ["--out", args.out]
    return subprocess.call(cmd)


def cmd_assess(target: str, args) -> int:
    """Deterministic evidence-driven assessment (Controller)."""
    from context import load_engagement
    from controller import Controller
    ctx = load_engagement(norm_target(target),
                          creds_file=getattr(args, "creds_file", None),
                          cookies_file=getattr(args, "cookies_file", None),
                          identity=getattr(args, "identity", None))
    c = Controller(
        norm_target(target),
        allow_high_risk=not args.no_high_risk,
        max_actions=args.max_actions,
        max_time_s=args.max_time,
        dry_run=args.dry_run,
        context=ctx,
        tool_timeout=getattr(args, "tool_timeout", 120),
    )
    res = c.assess()
    snap = res["snapshot"]
    print(f"\n[assess] {res['target']}: {res['actions_run']} actions run "
          f"in {res['elapsed_s']}s — {res['stop_reason']}"
          + (" (dry run)" if res["dry_run"] else ""))
    print("  assets     : " + ", ".join(f"{k}={len(v)}" for k, v
                                         in snap.get("assets_by_type", {}).items()) or "none")
    print(f"  evidence   : {snap.get('evidence_count', 0)} items | "
          f"findings: {snap.get('findings', 0)}")
    print("  coverage   : " + ", ".join(f"{k}->{v}" for k, v
                                         in sorted(res["coverage"].items(), key=lambda kv: -kv[1])[:8]))
    print(f"  decisions  : {len(res['decisions'])} trace entries "
          f"(last: {res['decisions'][-1]['selected_action']})" if res["decisions"] else "")
    from decision_trace import DecisionTrace
    traces_dir = ROOT / "results" / "traces"
    traces_dir.mkdir(parents=True, exist_ok=True)
    trace_path = traces_dir / f"{res['target']}.json"
    DecisionTrace.from_decisions(res["target"], res["decisions"]).export_trace(str(trace_path))
    print(f"  trace      : {trace_path}")
    return 0


def cmd_report_assess(target: str, args) -> int:
    import generate_assess_report
    argv = [target]
    if getattr(args, "out", ""):
        argv += ["--out", args.out]
    return generate_assess_report.main(argv)


def cmd_status(target: str, args) -> int:
    from target import Target
    from target_utils import parse_target_url
    host, full_url, _ = parse_target_url(target)
    t = Target(host, full_url=full_url)
    c = t.to_context()
    print(f"\n[Target] {c['target']}  ({'mapped' if c['provenance'] else 'no recon map yet'})")
    if c["full_url"]:
        print(f"  path scope : {c['full_url']}")
    print(f"  assets     : {c['subdomains']} subdomains")
    print(f"  services   : {c['services']} on ports={c['ports'] or '—'}")
    print(f"  tech       : {', '.join(c['technologies']) or '—'}")
    print(f"  cms        : {c['cms'] or '—'}")
    print(f"  web        : {c['endpoints']} endpoints, {c['auth_paths']} auth, {c['api_paths']} api")
    print(f"  links      : {c['links']}")
    print(f"  recon      : {c['recon_actions']} capabilities completed")
    m = c["attack_memory"]
    print(f"  attack     : risk={m['risk_rating'] or '—'} | {m['vulnerabilities']} findings | "
          f"agents={', '.join(m['completed_agents']) or '—'}")
    print()
    return 0


def cmd_authorize(target: str, args) -> int:
    import authorization as auth

    if getattr(args, "auth_list", False):
        print(auth.describe_scope())
        return 0

    if getattr(args, "auth_remove", False):
        if not target:
            print("error: --remove requires a target", file=sys.stderr)
            return 2
        host = auth._munge(target)
        auth.remove_target(target)
        if host not in auth.load_scope():
            print(f"[authorize] '{host}' was not in scope")
        else:
            print(f"[authorize] removed '{host}' from authorization scope")
        print(f"            scope: {', '.join(auth.scope()) or '(empty)'}")
        return 0

    host = auth._munge(target)
    if not host:
        print("error: target required (or use `cyberswarm authorize --list`)",
              file=sys.stderr)
        return 2
    if host in auth.load_scope():
        print(f"[authorize] '{host}' is already in scope")
        return 0
    if getattr(args, "auth_yes", False):
        auth.authorize_target(target)
        print(f"[authorize] added '{host}' to {auth.CONFIG_PATH}")
        print(f"            scope: {', '.join(auth.scope())}")
        return 0
    if auth.offer_authorize(target, action="direct authorization"):
        print(f"[authorize] done — '{host}' is now authorised.")
        return 0
    return 1


def cmd_dashboard(args) -> int:
    """Serve the read-only, real-time assessment dashboard (spec §20).

    Never touches a store, runs a tool, or calls a model -- it only reads
    results/state/*.json (+ decision logs, tool memory, system map) and
    serves them over a stdlib-only local HTTP server.
    """
    import dashboard_server
    dashboard_server.run(host=args.host, port=args.port, open_browser=not args.no_browser)
    return 0


def cmd_tools() -> int:
    from tools.attack_registry import ATTACK_TOOL_MAP, load_attack_tool
    print("Installed attack tools:")
    ok = 0
    total = 0
    for action, names in ATTACK_TOOL_MAP.items():
        for n in names:
            total += 1
            try:
                t = load_attack_tool(n)
                err = t.validate()
                status = "OK" if not err else f"MISSING ({err})"
                if not err:
                    ok += 1
            except Exception as e:
                status = f"ERROR ({e})"
            print(f"  [{status}] {n:16s} -> {action}")
    print(f"\n{ok}/{total} attack tools available.")
    return 0


def cmd_owasp(args) -> int:
    """Show the OWASP Top-10 coverage map (agents / tools / exploits).

    Prints what the platform *can* exercise for each category. Per-target
    OWASP labelling of findings lives in the attack report (OWASP section).
    """
    import owasp_registry

    rows = owasp_registry.coverage_report()
    print("OWASP Top 10 (2021) coverage:")
    print(f"{'':6s}{'Category':48s}{'Exploit':10s}{'#Tools':8s}{'Agents'}")
    print("-" * 90)
    for r in rows:
        code = r["code"]
        entry = r["title"]
        ex = "yes" if r["exploitable"] else "—"
        tools = r["tools"]
        agents = ", ".join(r["agents"])
        print(f"{code:6s}{entry[:47]:48s}{ex:10s}{tools:<8d}{agents}")
    print(f"\n{len(rows)} categories; "
          f"{sum(1 for r in rows if r['exploitable'])} have exploit tooling.")

    if getattr(args, "target", ""):
        # Per-target coverage: what each category actually ran against THIS
        # target, from the stored attack evidence (agent runs + findings).
        target = norm_target(args.target)
        from generate_attack_report import owasp_for
        try:
            import attack_evidence_store as aes
            evidence = aes.load(target)
        except Exception:
            evidence = {}
        if not evidence.get("agent_runs") and not evidence.get("vulnerabilities"):
            print(f"\nNo attack evidence stored for '{target}'. "
                  f"Run `cyberswarm attack {target}` first.")
            return 0

        cov = owasp_registry.per_target_coverage(evidence, classify=owasp_for)
        status_label = {"tested": "tested", "attempted": "attempted (no tool output)",
                        "not_tested": "NOT TESTED", "no_tooling": "no tooling"}
        print(f"\nPer-target OWASP coverage ({target}):")
        print(f"{'OWASP':6s}{'Status':26s}{'Prov':5s}{'Conf':5s}{'Disp':5s}{'Unpr':5s}Tools run")
        print("-" * 100)
        for r in cov:
            tools = ", ".join(r["tools_ran"]) or "—"
            print(f"{r['code']:6s}{status_label[r['status']]:26s}"
                  f"{r['proven']:<5d}{r['confirmed']:<5d}{r['disputed']:<5d}{r['unproven']:<5d}{tools[:40]}")
        tested = sum(1 for r in cov if r["status"] == "tested")
        proven = sum(r["proven"] for r in cov)
        print(f"\n{tested}/10 categories had a real tool run; {proven} proven with execution evidence.")
        print("Proven = execution evidence captured. Confirmed = critic accepted, no exec proof.")
        print("Disputed = critic rejected. Unproven = no real tool output behind it.")
        reasons = [r for r in cov if r["reasons"]]
        if reasons:
            print("\nWhy findings did not hold up:")
            for r in reasons:
                print(f"  {r['code']} {r['title']}")
                for reason in r["reasons"]:
                    print(f"    - {reason}")
        print(f"\nFull write-up: `cyberswarm report {target}` "
              f"(OWASP Top 10 — Per-Target Coverage section).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cyberswarm",
                                description="Self-hosted multi-agent offensive security platform")
    p.add_argument("--backend", help="model backend")
    p.add_argument("--model", help="model name")
    p.add_argument("--base-url", help="model server URL")
    sub = p.add_subparsers(dest="command", required=True)

    for name, help_txt in (("recon", "Phase-1 recon loop"),
                           ("map", "Build SystemMap from existing evidence"),
                           ("attack", "Run the multi-agent attack loop"),
                           ("assess", "Evidence-driven autonomous assessment (Controller)"),
                           ("full", "recon + map + attack"),
                           ("status", "Show a target's model summary (resume view)"),
                           ("report", "Generate attack report"),
                           ("evidence", "Write the per-vulnerability proof trail for a target"),
                           ("report-assess", "Generate unified assessment report (evidence-driven)"),
                           ("tools", "Show tool availability"),
                           ("bench", "Run the recon-planner benchmark"),
                           ("ablate", "Benchmark Controller strategies on simulated targets"),
                           ("authorize", "Add a target to the authorized assessment scope"),
                           ("dashboard", "Serve the read-only real-time assessment dashboard"),
                           ("proofs", "Run live proof capture and log it to the dashboard store"),
                           ("owasp", "Show OWASP Top-10 coverage (agents/tools/exploits)"),
                           ("help", "Explain commands, phases, modes, prompts and config"),
                           ("prompt", "List, render or run a reusable prompt"),
                           ("ask", "Resolve a plain-English request to a capability to run")):
        sp = sub.add_parser(name, help=help_txt)
        if name == "help":
            sp.add_argument("topic", nargs="?", default="",
                            help="agents, capabilities, phases, modes, prompts, "
                                 "skills, memory, config, scripts, safety")
            continue
        if name == "ask":
            sp.add_argument("request", nargs="+",
                            help='e.g. "find the subdomains of example.com"')
            sp.add_argument("--execute", action="store_true",
                            help="run the resolved capability (default: print only)")
            sp.add_argument("--timeout", type=int, default=180)
            sp.add_argument("--min-confidence", type=int, default=50,
                            help="refuse to execute below this confidence")
            continue
        if name == "prompt":
            sp.add_argument("prompt_name", nargs="?", default="",
                            help="prompt to render (omit to list)")
            sp.add_argument("--target", default=None)
            sp.add_argument("-v", "--var", action="append", dest="variables",
                            metavar="KEY=VALUE")
            sp.add_argument("--run", action="store_true",
                            help="send the rendered prompt to the model")
            continue
        if name in ("recon", "map", "attack", "full", "assess", "report", "status",
                "report-assess", "authorize", "evidence", "proofs"):
            sp.add_argument("target", nargs="?" if name in ("report", "status",
                                                            "assess", "authorize", "evidence",
                                                            "proofs") else None)
        if name == "owasp":
            sp.add_argument("target", nargs="?", default=None,
                            help="optionally map one target's stored findings to OWASP")
        if name == "authorize":
            sp.add_argument("--list", action="store_true", dest="auth_list",
                            help="print the current assessment scope (no target needed)")
            sp.add_argument("--remove", action="store_true", dest="auth_remove",
                            help="de-authorize the given target")
            sp.add_argument("--yes", action="store_true", dest="auth_yes",
                            help="skip the interactive consent prompt")
        if name == "assess":
            sp.add_argument("--max-actions", type=int, default=100,
                            help="(assess) max capabilities to probe this run")
            sp.add_argument("--max-time", type=float, default=1800.0,
                            help="(assess) time budget in seconds")
            sp.add_argument("--high-risk", action="store_true", help=argparse.SUPPRESS)
            sp.add_argument("--no-high-risk", action="store_true",
                            help="(assess) disable ACTIVE_HIGH exploit/testing actions")
            sp.add_argument("--tool-timeout", type=int, default=120,
                            help="(assess) per-tool subprocess timeout in seconds")
        elif name == "ablate":
            sp.add_argument("--max-actions", type=int, default=12)
            sp.add_argument("--seed", type=int, default=7)
            sp.add_argument("--iterations", type=int, default=1)
        elif name == "dashboard":
            sp.add_argument("--host", default="127.0.0.1")
            sp.add_argument("--port", type=int, default=8765)
            sp.add_argument("--no-browser", action="store_true",
                            help="don't auto-open a browser tab")
        sp.add_argument("--auto-approve", action="store_true")
        modes.add_cli_arguments(sp)
        sp.add_argument("--force", action="store_true")
        sp.add_argument("--fresh", action="store_true",
                        help="(recon/full) discard ALL stored recon evidence for the target "
                             "(completed/failed/zero-findings) and rebuild from scratch — "
                             "use when the last run was interrupted or the host changed")
        sp.add_argument("--run-all", action="store_true",
                        help="(recon/attack/full) bypass the planner; recon: run all "
                             "registered recon capabilities, attack: run all registered "
                             "attack actions")
        sp.add_argument("--max-agents", type=int, default=None)
        sp.add_argument("--max-pivot-depth", type=int, default=1)
        sp.add_argument("--no-llm-planner", action="store_true")
        sp.add_argument("--dry-run", action="store_true")
        sp.add_argument("--targets-file", default=None,
                        help="(assess/authorize) batch: file with one target per line (# = comment)")
        sp.add_argument("--creds-file", default=None,
                        help="(attack/full/assess) JSON credential file (identities/users shapes) "
                             "for authenticated testing of a login-protected target")
        sp.add_argument("--cookies-file", default=None,
                        help="(attack/full/assess) session cookies: JSON dict / HAR export / "
                             "raw 'Cookie: a=b; c=d' header")
        sp.add_argument("--identity", default=None,
                        help="(attack/full/assess) active credential identity label (default first cred)")
        if name == "bench":
            sp.add_argument("--only", default=None, help="(bench) run a single scenario by id")
            sp.add_argument("--prompt", dest="bench_prompt", choices=["full", "compact"],
                            default=None, help="(bench) planner prompt to benchmark")
            sp.add_argument("--rules-only", action="store_true",
                            help="(bench) score the deterministic planner, no model")
            sp.add_argument("--think", action="store_true",
                            help="(bench) enable Qwen3 extended thinking")
            sp.add_argument("--min-pass", type=float, default=None,
                            help="(bench) fail if pass rate is below this (e.g. 0.75)")
        sp.add_argument("--reset-memory", action="store_true",
                        help="(attack/full) clear prior attack memory so every agent re-runs")
        sp.add_argument("--all", action="store_true", help="(report) all targets")
        sp.add_argument("--out", default="", help="(report) output file")
    return p


def cmd_ask(args, config) -> int:
    """Resolve a plain-English request; print it, or run it with --execute."""
    import ask as ask_module
    from model_client import ModelClient

    request = " ".join(getattr(args, "request", []) or [])
    model_cfg = (config or {}).get("model") or {}
    client = ModelClient(**{k: v for k, v in model_cfg.items()
                            if k in ModelClient.__dataclass_fields__}) \
        if hasattr(ModelClient, "__dataclass_fields__") else ModelClient()

    resolution = ask_module.resolve(request, client)
    print(resolution.describe())

    if not resolution.ok:
        print("\nTry naming the target explicitly, or see "
              "`python cli.py help capabilities`.")
        return 1

    allowed, messages = ask_module.check_gates(resolution, config)
    print()
    for message in messages:
        print(f"  {message}")

    if not args.execute:
        print("\nNothing was run. Equivalent command:")
        print(f"  {resolution.command()}")
        print("\nRe-run with --execute to run it now.")
        return 0

    if not allowed:
        print("\nRefusing to execute: the checks above did not pass.")
        return 1
    if resolution.confidence < args.min_confidence:
        print(f"\nRefusing to execute: confidence {resolution.confidence} is "
              f"below --min-confidence {args.min_confidence}.")
        return 1
    if resolution.kind != "capability":
        print(f"\n{resolution.name} is an agent, not a single capability. Run:")
        print(f"  python cli.py attack {resolution.target}")
        return 1

    print(f"\nRunning {resolution.name} on {resolution.target} ...")
    result = ask_module.execute(resolution, timeout=args.timeout)
    print(f"  status : {result.status}")
    if getattr(result, "tool", ""):
        print(f"  tool   : {result.tool}")
    if getattr(result, "error", ""):
        print(f"  error  : {result.error}")
    if getattr(result, "results", None):
        import json as _json
        print(_json.dumps(result.results, indent=2)[:2000])
    return 0 if result.status in ("success", "partial") else 1


def cmd_prompt(args, config) -> int:
    """List, render or run a prompt from prompts/."""
    import prompt_library

    prompts = prompt_library.load_prompts(
        prompt_library.prompts_dir_from_config(config))
    name = getattr(args, "prompt_name", "")

    if not name:
        if not prompts:
            print("No prompts found. Add a .md file to prompts/ — "
                  "see `cli.py help prompts`.")
            return 0
        for prompt in sorted(prompts.values(), key=lambda p: p.name):
            print(prompt.summary())
        return 0

    prompt = prompts.get(name)
    if prompt is None:
        print(f"No prompt named {name!r}. Run `cli.py prompt` to list them.")
        return 1

    values = {}
    for item in getattr(args, "variables", None) or []:
        key, sep, value = str(item).partition("=")
        if sep:
            values[key.strip().lower()] = value.strip()
    if getattr(args, "target", None):
        values.setdefault("target", args.target)

    try:
        rendered = prompt.render(values, strict=True)
    except KeyError as exc:
        print(f"{exc}\nSupply them with --target or -v key=value.")
        return 1

    if not getattr(args, "run", False):
        print(rendered)
        return 0

    from model_client import ModelClient
    client = ModelClient()
    print(client.chat("You are assisting with an authorized security assessment. "
                      "Answer only from the evidence provided.", rendered))
    return 0


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    args = build_parser().parse_args()
    cfg = load_config()

    # These two do not run a pipeline, so they are dispatched before _merge --
    # which expects the run-flags the other subcommands define.
    if args.command == "help":
        import help_text
        print(help_text.render(getattr(args, "topic", "")))
        return 0
    if args.command == "prompt":
        return cmd_prompt(args, cfg)
    if args.command == "ask":
        return cmd_ask(args, cfg)

    _merge(args, cfg)
    if args.command == "tools":
        return cmd_tools()
    if args.command == "owasp":
        return cmd_owasp(args)
    if args.command == "dashboard":
        return cmd_dashboard(args)
    if args.command == "proofs":
        from scripts.generate_live_proofs import main as proofs_main
        return proofs_main(["--target", getattr(args, "target", None) or "localhost"])
    if args.command == "ablate":
        return cmd_ablate(args)
    if args.command == "bench":
        return cmd_bench(args)
    if args.command == "report":
        return cmd_report(args.target, args)
    if args.command == "evidence":
        return cmd_evidence(args.target, args)
    if args.command == "report-assess":
        if not args.target:
            print("error: target required", file=sys.stderr)
            return 2
        return cmd_report_assess(args.target, args)
    if args.command == "authorize":
        if getattr(args, "targets_file", None):
            import batch
            return batch.authorize_batch(args)
        if not args.target and not getattr(args, "auth_list", False):
            print("error: target required (or use `cyberswarm authorize --list`)",
                  file=sys.stderr)
            return 2
        return cmd_authorize(args.target, args)
    if args.command == "status":
        return cmd_status(args.target or "", args)
    if args.command == "assess" and getattr(args, "targets_file", None):
        import batch
        return batch.run_assess_batch(args)
    if not args.target:
        print("error: target required", file=sys.stderr)
        return 2

    if args.target:
        valid, reason = validate_target(args.target)
        if not valid:
            print(f"error: invalid target '{args.target}': {reason}", file=sys.stderr)
            return 2

    if args.command == "recon":
        return cmd_recon(args.target, args)
    if args.command == "map":
        return cmd_map(args.target, args)
    if args.command == "assess":
        return cmd_assess(args.target, args)
    if args.command == "attack":
        return cmd_attack(args.target, args)
    if args.command == "full":
        return cmd_full(args.target, args)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Piping into head/less closes stdout early; not an error.
        try:
            sys.stdout.close()
        finally:
            sys.exit(0)
