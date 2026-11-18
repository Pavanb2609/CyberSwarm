#!/usr/bin/env python3
"""
CyberSwarm — Agent-Centric Attack Loop (the product core).

    SystemMap → PlannerAgent (hybrid) → AttackGraph
    → [WebAttack | Network | API | Auth | Infra | Cloud]
    → human approval gate → CriticAgent → MemoryAgent (updates SystemMap)
    → ExploitationAgent (validate) → PrivescAgent → PivotAgent (new targets)
    → IntelligenceAgent → summary

Usage:
    python run_agent_loop.py scanme.nmap.org \
        --backend ollama --model qwen3:8b --base-url http://192.168.0.66:11434
    python run_agent_loop.py scanme.nmap.org --auto-approve --max-agents 4 --no-llm-planner
"""

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from model_client import ModelClient
import system_map as sm
import build_system_map
from agents.registry import load_agent
from agents.planner_agent import PlannerAgent
from agents.critic_agent import CriticAgent
import modes
import phases
from agents.base_agent import AgentResult, run_with_timing
from target import Target
from utils import load_config, ROOT, get_logger

log = get_logger("run_agent_loop")

LOG_PATH = ROOT / "results" / "attack_decision_log.jsonl"


def _finding_to_dict(f) -> dict:
    """Serialise an AgentFinding for the evidence store."""
    return {
        "name": getattr(f, "name", ""),
        "severity": getattr(f, "severity", "INFO"),
        "confidence": getattr(f, "confidence", 0),
        "final_confidence": getattr(f, "final_confidence", None),
        "verdict": getattr(f, "verdict", "NEEDS_PROOF"),
        "url": getattr(f, "url", ""),
        "description": getattr(f, "description", ""),
        "tool": getattr(f, "tool", ""),
        "source_agent": getattr(f, "agent", ""),
        "evidence": getattr(f, "raw_output_excerpt", ""),
        "evidence_chain": [str(x)[:600] for x in (getattr(f, "evidence_chain", None) or [])][:8],
        "raw_output_excerpt": str(getattr(f, "raw_output_excerpt", "") or "")[:1600],
        "independent_sources": getattr(f, "independent_sources", 1),
        "false_positive_risk": getattr(f, "false_positive_risk", ""),
        "proofs": (getattr(f, "proofs", None) or [])[:20],
    }


def _run_all_attack(target: str, model_client: ModelClient,
                    config: Optional[Dict[str, Any]] = None,
                    full_url: Optional[str] = None) -> Dict[str, Any]:
    """Bypass the planner: run every registered attack action directly."""
    import attack_engine
    from agents.memory_agent import MemoryAgent

    scope = full_url or target
    print(f"\n[Phase 2][RUN-ALL] Executing every registered attack action against {scope}")
    # Authorization gate — must pass before any tool touches the target.
    # Strict mode: no scope file = denied. Lab/private addresses are
    # always permitted. This stops the tool running against live targets
    # you never explicitly approved.
    import authorization as _auth
    _auth_ok, _auth_reason = _auth.is_authorized(target, mode="strict")
    print(f"[authorization] {_auth_reason}")
    if not _auth_ok:
        _auth_ok = _auth.offer_authorize(target, action="attack against the target")
    if not _auth_ok:
        print(f"[authorization] BLOCKED — run `cyberswarm authorize {_auth._munge(target)}` "
              f"first (or `python cli.py authorize --yes <target>` to skip the prompt).")
        return

    results = attack_engine.run_all(scope)
    print(f"\n[RUN-ALL] Completed {sum(1 for r in results.values() if r['status'] == 'success')}/"
          f"{len(results)} actions successfully.")

    # RUN-ALL used to write every raw tool result into the evidence store as a
    # CONFIRMED vulnerability with no review at all -- that is how amazon.in
    # produced a fake CRITICAL, two false-positive HIGHs and 22 Nikto log lines,
    # every one stamped CONFIRM with critic_score=null. Now every result passes
    # through deterministic filtering AND the CriticAgent before it is recorded.
    import finding_extractor as fx

    raw_findings = []
    for action, r in results.items():
        if r.get("status") == "success":
            raw_findings.extend(fx.extract_findings(action, r.get("results") or {},
                                                    r.get("tool", "")))

    pre = fx.summarise(raw_findings)
    print(f"[filter] {len(raw_findings)} candidate finding(s) after deterministic "
          f"filtering (confirm={pre.get('CONFIRM',0)}, "
          f"needs_proof={pre.get('NEEDS_PROOF',0)}, dispute={pre.get('DISPUTE',0)})")

    # Send the survivors that are not already deterministically disputed to the
    # real critic for adversarial review.
    confirmed = []
    try:
        critic_client = _role_client(model_client, config, "model_critic", max_tokens=2048)
        critic = CriticAgent(critic_client)
        reviewable = [f for f in raw_findings
                      if getattr(f, "verdict", "NEEDS_PROOF") != fx.DISPUTE]
        smap = {}
        try:
            from agents.memory_agent import MemoryAgent as _MA
            smap = _MA(target).load().get("system_map", {}) or {}
        except Exception:  # noqa: BLE001
            pass
        buckets = critic.review_batch(reviewable, smap) if reviewable else {}
        confirmed = buckets.get("confirmed", []) if isinstance(buckets, dict) else []
        disputed = buckets.get("disputed", []) if isinstance(buckets, dict) else []
        print(f"[Critic] confirmed={len(confirmed)} disputed={len(disputed)} "
              f"(from {len(reviewable)} reviewed)")
    except Exception as exc:  # noqa: BLE001
        # If the critic is unavailable, DO NOT fall back to confirming
        # everything -- that is the bug we are fixing. Only the deterministic
        # CONFIRMs survive.
        print(f"[Critic] unavailable ({exc}); keeping only deterministically "
              f"confirmed findings")
        confirmed = [f for f in raw_findings
                     if getattr(f, "verdict", "") == fx.CONFIRM]

    mem = MemoryAgent(target).load()
    mem.setdefault("vulnerabilities", [])
    mem.setdefault("completed_agents", [])
    for f in confirmed:
        mem["vulnerabilities"].append(_finding_to_dict(f))
    mem["completed_agents"].append("run_all_sweep")
    mem["run_all_filter_summary"] = {"raw": len(raw_findings), **pre,
                                     "confirmed": len(confirmed)}
    MemoryAgent(target).save(mem)

    # Write the per-target, per-vulnerability proof trail: a folder named after
    # the target with one file per vulnerability class, showing exactly what was
    # tried and what came back. This is what turns "testing done" into evidence.
    try:
        import evidence_trail
        trail = evidence_trail.EvidenceTrail(target)
        for f in confirmed:
            trail.record_finding(f)
        # Also record the disputed ones, so the trail shows what was tried and
        # rejected, not only what passed.
        for f in raw_findings:
            if getattr(f, "verdict", "") == "DISPUTE":
                trail.record_finding(f)
        folder = trail.write()
        print(f"[evidence] proof trail written to {folder}")
        print(f"[evidence] open {folder}/00_SUMMARY.md for what was tested per class")
        if not locals().get("dry_run"):
            import engagement_report as _er
            _er.build(target)
            print(f"[evidence] engagement folder: results/engagements/{target}/")
    except Exception as exc:  # noqa: BLE001
        print(f"[evidence] could not write proof trail: {exc}")
    print(f"[RUN-ALL] Recorded {len(confirmed)} confirmed finding(s) "
          f"(was: every raw result). Nothing is CONFIRM without review.")

    print(f"\n{'='*64}\n  CyberSwarm Attack Complete (RUN-ALL) — {scope}")
    print(f"  Actions executed : {len(results)}")
    print(f"  Successful       : {sum(1 for r in results.values() if r['status'] == 'success')}")
    print(f"{'='*64}\n")
    return mem


def _role_client(base: ModelClient, cfg: dict, key: str,
                 max_tokens: Optional[int] = None) -> ModelClient:
    """Return a ModelClient pinned to the role-specific model from config.yaml.

    If no override is set (or it matches the base model), the base client is
    returned unchanged so no duplicate model is spun up.
    """
    mcfg = (cfg or {}).get("model", {})
    model = mcfg.get(key)
    if not model or model == base.model:
        return base
    return ModelClient(backend=base.backend, model=model, base_url=base.base_url,
                       timeout=base.timeout, max_retries=base.max_retries,
                       max_tokens=max_tokens or base.max_tokens)

def confirm_authorization(target: str, force: bool = False) -> None:
    pass


def log_entry(entry: Dict[str, Any]) -> None:
    LOG_PATH.parent.mkdir(exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def human_approval_gate(agent_name: str, result: AgentResult,
                        auto_approve: bool, policy=None) -> tuple[bool, str]:
    """Review an agent result.

    With a SessionPolicy, ``guided`` prompts and the pause policy decides
    whether to stop after a non-guided result. Without one, the historical
    ``auto_approve`` boolean applies unchanged.
    """
    if policy is not None:
        if not policy.requires_approval_before_action():
            import approval_gate
            if not approval_gate.pause_for_review(
                    f"agent {agent_name}", result.findings, policy):
                return False, "operator stopped at checkpoint"
            return True, f"auto-approved ({policy.mode.value} mode)"
    elif auto_approve:
        return True, "auto-approved"
    print(f"\n{'='*64}")
    print(f"  AGENT RESULT — {agent_name.upper()}")
    print(f"{'='*64}")
    print(f"  Tools run : {', '.join(result.tools_run) or 'none'}")
    print(f"  Findings  : {len(result.findings)}")
    for f in result.findings[:5]:
        print(f"    [{f.severity}] {f.name[:60]} (conf={f.confidence})")
    if result.attack_paths_discovered:
        print(f"  Signals   : {result.attack_paths_discovered[:3]}")
    if result.reasoning:
        print(f"  Reasoning : {result.reasoning[:120]}")
    print(f"{'='*64}")
    resp = input("Send to Critic? [y]es / [n]o / [s]kip agent: ").strip().lower()
    if resp in ("y", "yes"):
        return True, ""
    if resp in ("s", "skip"):
        return False, "human skipped"
    note = input("Reason: ").strip()
    return False, note


def parse_pivot_target(signal: str) -> Optional[str]:
    """Extract the target host from a 'PIVOT:<target>|<agent_hint>|<reason>'
    signal (see PivotAgent in agents/exploitation_agent.py). Returns None if
    `signal` isn't a PIVOT signal or has no target. The target is embedded in
    the first segment after the "PIVOT:" prefix -- NOT in the second segment,
    which is the agent_hint (e.g. "web_attack")."""
    if not signal.startswith("PIVOT:"):
        return None
    first_segment = signal.split("|", 1)[0]
    target = first_segment[len("PIVOT:"):].strip()
    return target or None


def _path_signals(paths) -> List[str]:
    """Coerce attack_paths_discovered entries to plain strings (an entry may be
    a dict, e.g. an ffuf discovered_path item), dropping non-string junk."""
    out = []
    for s in paths or []:
        if isinstance(s, str):
            out.append(s)
        elif isinstance(s, dict):
            u = s.get("url") or s.get("path") or s.get("target")
            if u:
                out.append(u)
        elif s is not None:
            out.append(str(s))
    return out


def new_api_auth_surface(result) -> bool:
    """True if the agent surfaced API:/AUTH: paths worth re-planning around."""
    return any(s.startswith(("API:", "AUTH:")) for s in _path_signals(result.attack_paths_discovered))


def print_graph(graph: Dict[str, Any], target: str) -> None:
    print(f"\n[AttackGraph] {target}  profile={graph.get('target_profile')}")
    for node in sorted(graph.get("attack_graph", []), key=lambda n: n.get("priority", 99)):
        tag = "SKIP" if node.get("skip") else f"P{node['priority']}"
        print(f"  [{tag}] {node['agent']}: {node.get('reason', '')[:90]}")
    if graph.get("reasoning"):
        print(f"  strategy: {graph['reasoning'][:200]}")
    print()


def inject_full_url(smap: Dict[str, Any], target: str,
                    full_url: Optional[str]) -> Dict[str, Any]:
    """Record a path-scoped URL target on the SystemMap so web agents/tools
    attack the exact path (e.g. https://host/admin) instead of just the host."""
    if not full_url:
        return smap
    from urllib.parse import urlparse
    smap["full_url"] = full_url
    path = urlparse(full_url).path
    if path and path != "/":
        if full_url not in smap.get("endpoints", []):
            smap.setdefault("endpoints", []).append(full_url)
        smap.setdefault("web_surfaces", [])
        if not any(w.get("url") == full_url for w in smap["web_surfaces"]):
            smap["web_surfaces"].insert(0, {"url": full_url, "host": target,
                                            "ports": [], "tech": [], "title": "",
                                            "status": None, "headers": {}})
    return smap


def run_attack(target: str, model_client: ModelClient, max_agents: int = 24,
               auto_approve: bool = False, force: bool = False,
               use_llm_planner: bool = True, max_pivot_depth: int = 3,
               dry_run: bool = False, reset_memory: bool = False,
               config: Optional[Dict[str, Any]] = None,
               run_all: bool = False,
               full_url: Optional[str] = None,
               map_stale_days: int = 7,
               context: Any = None,
               policy=None) -> Dict[str, Any]:
    if run_all:
        return _run_all_attack(target, model_client, config, full_url=full_url)

    # Scope gate: hard block for un-authorized live targets, with an
    # interactive step-up when a human is at the terminal. `--force` keeps
    # the prior bypass (operator override) for lab/scripted runs.
    if not force and not dry_run:
        import authorization as _authz
        if not _authz.offer_authorize(target, action="attack against the target"):
            raise SystemExit("[authorization] aborted: target not authorized. "
                             "Run `cyberswarm authorize <target>` (or --yes) "
                             "first, or re-run with --force.")

    t = Target(target, full_url=full_url)
    planner = PlannerAgent(_role_client(model_client, config, "model_planner"))
    critic_client = _role_client(model_client, config, "model_critic", max_tokens=2048)
    critic = CriticAgent(critic_client)
    deep_client = _role_client(model_client, config, "model_deep")
    if critic_client.model == deep_client.model:
        # The CriticAgent's entire value proposition is being an adversarial
        # *second opinion*. If it's the same model (and typically the same
        # weights/quantization) that produced the findings, it shares that
        # model's blind spots rather than genuinely challenging them -- it's
        # a second pass with a different prompt, not real adversarial review.
        # This isn't fatal (a differently-prompted pass still catches some
        # things), but it should be visible, not silent, especially since
        # config.yaml ships with every model_* key defaulting to the same
        # model. Set model_critic to a different model in config.yaml to
        # get a real second opinion.
        print(f"[WARNING] model_critic == model_deep ('{critic_client.model}'): the "
              f"CriticAgent is reviewing findings with the same model that produced "
              f"them, not an independent one. This weakens (but doesn't eliminate) "
              f"its adversarial value -- set a different model_critic in config.yaml "
              f"for genuine second-opinion review.")

    recon = t.load_evidence()

    # Phase gate: exploitation against a barely-enumerated target is the case
    # this exists to catch. Advisory -- --force, free mode, or phases.enabled
    # false all bypass it.
    policy = policy or modes.from_args(argparse.Namespace(), config)
    if policy.enforces_phases and not force:
        _controller = phases.get_controller(target, config)
        _ctx = phases.PhaseContext.from_evidence(recon, target=target)
        _ok, _gates = _controller.can_enter(phases.EXPLOITATION, _ctx)
        if not _ok:
            print(f"\n[phase] EXPLOITATION gates not met for {target}:")
            for _g in _gates:
                if not _g.passed:
                    print(f"  {_g}")
            print("[phase] Run more recon, or re-run with --force to override.\n")
            return {"target": target, "status": "blocked_by_phase_gate",
                    "gates": [{"name": g.name, "passed": g.passed,
                               "detail": g.detail} for g in _gates]}
        _controller.set_phase(phases.EXPLOITATION, _ctx,
                              note="entered by run_agent_loop")
    if not recon.get("completed_actions"):
        print(f"[WARNING] No Phase 1 recon for '{target}'. Building a sparse SystemMap. "
              f"Run recon first for best results.")
    smap = t.load_map()
    if full_url:
        t.attach_full_url(full_url)
        smap = t.system_map
    elif smap.get("full_url"):
        t.clear_full_url()

    # Stale-map guard: a map several sessions old describes a past incarnation
    # of the host (dead endpoints/tech) and quietly poisons every agent that
    # reads it (certifiedhacker.com's 1-month-old map pointed web_attack at
    # SPA-fallback admin.php/reset.php ghosts). Rebuild from recon evidence.
    if map_stale_days > 0 and sm.is_stale_map(target, map_stale_days):
        try:
            fresh_map = build_system_map.build_for(target)
            if fresh_map and fresh_map.get("provenance"):
                sm.save_map(target, fresh_map)
                smap = fresh_map
                age = sm.map_age_days(target)
                print(f"[map] stale SystemMap (>{map_stale_days}d, was {age:.0f}d) "
                      f"rebuilt from current recon evidence — agents see the live host.")
            else:
                print("[map] stale SystemMap detected but no fresh recon evidence to "
                      "rebuild from; proceeding with the stale map (best effort).")
        except Exception as exc:  # noqa: BLE001
            print(f"[map] could not rebuild stale map: {exc}")

    mem = t.load_memory()
    memory = t._memory_store
    if reset_memory:
        t.reset_memory()
        mem = t.memory
        memory = t._memory_store
        print(f"[reset] Cleared prior attack memory for {target} -- re-running all agents.")

    # Login handling: say clearly whether the target has a login and, given
    # what the operator supplied, whether the authenticated surface is being
    # tested. Stored on the evidence so the report renders an Authentication
    # section; the authenticated surface is tested only with operator-supplied
    # credentials/cookies, never guessed.
    try:
        import auth_handling
        auth = auth_handling.auth_status(smap, context, target=target)
        mem["auth"] = auth
        if context is not None:
            summary = context.to_dict() if hasattr(context, "to_dict") else context
            mem["auth_context"] = {"cookies": summary.get("cookies", {}),
                                   "identity": summary.get("identity", "anonymous"),
                                   "credential_identities": auth["context"]["labels"]}
        print(auth_handling.console_notice(auth))
    except Exception as exc:  # noqa: BLE001 - never let auth reporting break the run
        print(f"[auth] status unavailable: {exc}")

    print(f"\n[Phase 2] Building attack graph for {target}...")
    attack_graph = planner.build_attack_graph(smap, mem["completed_agents"], mem,
                                              use_llm=use_llm_planner)
    attack_graph = planner.apply_difficulty(attack_graph, history=mem, config=config)
    mem["attack_graph"] = attack_graph
    print_graph(attack_graph, target)
    log_entry({"event": "attack_graph", "target": target,
               "graph": attack_graph["attack_graph"]})

    agents_run = 0
    pivot_depth = 0
    replan_count = 0
    MAX_REPLANS = 4
    prebuilt_graph = attack_graph
    queue: List[str] = [target]
    visited: set = {target}
    all_summaries: Dict[str, Any] = {}

    while queue and len(visited) < 50:
        current = queue.pop(0)
        if current != target:
            pivot_depth += 1
            if pivot_depth > max_pivot_depth:
                print(f"[PIVOT-LIMIT] depth exceeded, not pivoting to {current}")
                continue
            print(f"\n{'='*64}\n  PIVOT to {current} (depth {pivot_depth})\n{'='*64}")
            sub_map = sm.load_map(current)
            if not sub_map.get("provenance"):
                sub_map = build_system_map.build_for(current)
                sm.save_map(current, sub_map)
            planner_target = current
        else:
            planner_target = target
            sub_map = smap

        # rebuild/replan graph for this target; reuse the prebuilt root graph on
        # the first iteration instead of asking the planner twice for the same target.
        if current == target and prebuilt_graph is not None:
            graph = prebuilt_graph
            prebuilt_graph = None
        else:
            graph = planner.build_attack_graph(sub_map, mem["completed_agents"], mem,
                                               use_llm=use_llm_planner)
        graph = planner.apply_difficulty(graph, history=mem, config=config)
        print_graph(graph, planner_target)

        for node in sorted(graph.get("attack_graph", []), key=lambda n: n.get("priority", 99)):
            if agents_run >= max_agents:
                print(f"[LIMIT] max_agents={max_agents} reached.")
                break
            agent_name = node.get("agent")
            if node.get("skip"):
                print(f"[SKIP] {agent_name} — {node.get('reason')}")
                continue
            if agent_name in mem["completed_agents"]:
                print(f"[DONE] {agent_name} already completed.")
                continue

            try:
                agent = load_agent(agent_name, deep_client)
            except Exception as e:  # noqa: BLE001
                log.error("Failed to load agent %s: %s", agent_name, e)
                print(f"[ERROR] load {agent_name}: {e}")
                continue
            if not agent.should_run(sub_map):
                print(f"[SKIP] {agent_name}.should_run() = False")
                continue

            if dry_run:
                print(f"[DRY-RUN] would run {agent_name} (tools: {agent.owned_tools})")
                agents_run += 1
                continue

            print(f"\n[Agent] {agent_name.upper()} (P{node.get('priority')}) — {node.get('reason', '')[:80]}")
            result = run_with_timing(agent, planner_target, sub_map, mem)
            print(f"[{agent_name}] status={result.status} findings={len(result.findings)} "
                  f"tools={result.tools_run} {result.duration_s:.1f}s")
            if result.error:
                print(f"  note: {result.error[:120]}")

            approved, note = human_approval_gate(agent_name, result, auto_approve,
                                                 policy=policy)
            log_entry({"event": "agent_result", "target": planner_target, "agent": agent_name,
                       "approved": approved, "human_note": note,
                       "result": result.to_dict()})
            if not approved:
                print(f"[REJECTED] {agent_name}: {note}")
                mem.setdefault("completed_agents", []).append(agent_name)
                continue

            buckets = {"confirmed": [], "disputed": [], "needs_proof": []}
            if result.findings:
                buckets = critic.review_batch(result.findings, sub_map)
                print(f"[Critic] confirmed={len(buckets['confirmed'])} "
                      f"disputed={len(buckets['disputed'])} needs_proof={len(buckets['needs_proof'])}")

            mem = memory.store_agent_result(mem, result, buckets, system_map=sub_map)
            memory.save(mem)
            if current == target:
                t.save_map()
            else:
                sm.save_map(current, sub_map)
            agents_run += 1

            if (buckets["confirmed"] and replan_count < MAX_REPLANS
                    and any(f.severity in ("CRITICAL", "HIGH") for f in buckets["confirmed"])):
                top = buckets["confirmed"][0]
                print(f"[Replan] significant finding: {top.name}")
                graph = planner.replan(graph, top.to_dict(), mem, use_llm=use_llm_planner)
                graph = planner.apply_difficulty(graph, history=mem, config=config)
                replan_count += 1
            elif new_api_auth_surface(result) and replan_count < MAX_REPLANS:
                _signals = _path_signals(result.attack_paths_discovered)
                print(f"[Replan] new surface: {_signals[0] if _signals else 'unknown'}")
                graph = planner.replan(
                    graph, {"name": "New API/AUTH endpoints discovered",
                            "description": _signals[0] if _signals else "New API/AUTH endpoints discovered"},
                    mem, use_llm=use_llm_planner)
                graph = planner.apply_difficulty(graph, history=mem, config=config)
                replan_count += 1

            # cross-agent signals (pivots)
            for signal in _path_signals(result.attack_paths_discovered):
                nt = parse_pivot_target(signal)
                if nt is not None:
                    if nt not in visited:
                        visited.add(nt)
                        queue.append(nt)
                        print(f"[PIVOT-Q] queued {nt}")
                elif signal not in mem.get("new_attack_paths", []):
                    mem.setdefault("new_attack_paths", []).append(signal)

            # ── Agent feedback loop: new endpoints → inject into downstream agents ──
            new_eps = [p for p in _path_signals(result.attack_paths_discovered)
                       if p.startswith("http") and p not in sub_map.get("endpoints", [])]
            if new_eps:
                sub_map.setdefault("endpoints", []).extend(new_eps)
                sm.save_map(current, sub_map)
                print(f"[Feedback] {agent_name} discovered {len(new_eps)} new endpoints → SystemMap updated")

            memory.save(mem)

        all_summaries[planner_target] = {
            "risk_rating": mem.get("risk_rating"),
            "vulnerabilities": len(mem.get("vulnerabilities", [])),
            "completed_agents": list(mem["completed_agents"]),
        }
        if agents_run >= max_agents:
            break

    # Intelligence post-processing (always last)
    if "intelligence" not in mem["completed_agents"] and not dry_run:
        print(f"\n[Agent] INTELLIGENCE (post-processing)")
        try:
            intel = load_agent("intelligence", deep_client)
            ires = run_with_timing(intel, target, smap, mem)
            approved, note = human_approval_gate("intelligence", ires, auto_approve,
                                                 policy=policy)
            if approved and ires.findings:
                buckets = critic.review_batch(ires.findings, smap)
                mem = memory.store_agent_result(mem, ires, buckets, system_map=smap)
                memory.save(mem)
                t.save_map()
        except Exception as e:  # noqa: BLE001
            log.error("IntelligenceAgent failed: %s", e)
            print(f"[ERROR] IntelligenceAgent: {e}")

    # Summary
    print(f"\n{'='*64}")
    print(f"  CyberSwarm Attack Complete — {target}")
    print(f"  Risk rating      : {mem.get('risk_rating')}")
    print(f"  Vulnerabilities  : {len(mem.get('vulnerabilities', []))}")
    print(f"  Disputed         : {len(mem.get('disputed_findings', []))}")
    print(f"  Proof requests   : {len(mem.get('proof_requests', []))}")
    print(f"  Agents completed : {mem.get('completed_agents')}")
    print(f"  Evidence         : results/attack_evidence/{target}.json")
    print(f"{'='*64}\n")

    # Per-target, per-vulnerability proof trail.
    try:
        import evidence_trail
        folder = evidence_trail.build_trail_from_evidence(target, mem)
        print(f"[evidence] proof trail: {folder}/00_SUMMARY.md\n")
    except Exception as exc:  # noqa: BLE001
        print(f"[evidence] could not write proof trail: {exc}")

    # Pipeline-native engagement folder: confirmed findings land in
    # results/engagements/<target>/vulnerabilities/<NN>__SEV__<slug>/ with
    # per-attempt proof; when nothing is confirmed a PROOF_OF_TESTING.md with
    # the raw evidence and decision logs is written instead. This is what the
    # engagement report CLI was built from, so results always exist post-run.
    if not dry_run:
        try:
            import engagement_report as _er
            _er.build(target)
            print(f"[evidence] engagement folder: "
                  f"results/engagements/{target}/")
        except Exception as exc:  # noqa: BLE001
            print(f"[evidence] could not write engagement folder: {exc}")

    # Fold this run's evidence into the cross-engagement RAG memory so the
    # next planner call can retrieve it. No-op when rag.auto_reindex is false.
    try:
        import rag_memory as rag
        rag.maybe_auto_reindex(config)
    except ImportError:
        pass

    return mem


def parse_args():
    p = argparse.ArgumentParser(description="CyberSwarm — Agent-Centric Attack Loop")
    p.add_argument("target")
    p.add_argument("--backend", default=None)
    p.add_argument("--model", default=None)
    p.add_argument("--base-url", default=None)
    p.add_argument("--max-agents", type=int, default=24)
    p.add_argument("--max-pivot-depth", type=int, default=3)
    p.add_argument("--map-stale-days", type=int, default=7,
                   help="Rebuild the SystemMap from current recon evidence when the stored map "
                        "is older than this many days (0 disables). Default 7.")
    p.add_argument("--auto-approve", action="store_true")
    modes.add_cli_arguments(p)
    p.add_argument("--force", action="store_true")
    p.add_argument("--no-llm-planner", action="store_true",
                   help="Use deterministic rule graph only (no LLM refinement)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--reset-memory", action="store_true",
                   help="Clear prior attack memory (completed agents, proof requests) "
                        "so every agent re-runs from scratch.")
    p.add_argument("--run-all", action="store_true",
                   help="Bypass the planner and execute every registered attack action.")
    return p.parse_args()


if __name__ == "__main__":
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    args = parse_args()
    from target_utils import parse_target_url
    from utils import validate_target
    host, full_url, _ = parse_target_url(args.target)
    valid, reason = validate_target(host)
    if not valid:
        print(f"error: invalid target '{host}': {reason}", file=sys.stderr)
        sys.exit(1)
    config = load_config()
    m = config.get("model", {})
    from model_client import resolve_backend_url
    client = ModelClient(backend=args.backend or m.get("backend", "ollama"),
                         model=args.model or m.get("model", "qwen3:8b"),
                         base_url=resolve_backend_url(
                             args.base_url or m.get("base_url", "http://localhost:11434"),
                             args.backend or m.get("backend", "ollama")))
    pipe = config.get("pipeline", {})
    max_agents = args.max_agents
    max_pivot_depth = args.max_pivot_depth
    # CLI flags were not passed (-1 sentinel not used); default to config values
    # only when the user did not explicitly set them on the command line.
    run_attack(target=host, full_url=full_url, model_client=client,
               max_agents=max_agents if max_agents is not None else pipe.get("max_agents", 24),
               auto_approve=args.auto_approve, force=args.force,
               use_llm_planner=not args.no_llm_planner,
               max_pivot_depth=max_pivot_depth if max_pivot_depth is not None else pipe.get("max_pivot_depth", 3),
               dry_run=args.dry_run, reset_memory=args.reset_memory, config=config,
               run_all=args.run_all, policy=modes.from_args(args, config),
               map_stale_days=args.map_stale_days)


