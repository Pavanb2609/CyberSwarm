"""
controller.py — evidence-driven Assessment Controller.

Implements the autonomous assessment loop behind `cyberswarm assess`:

  1. choose the capability with the highest information-gain score
     (ActionScorer, deterministic, no LLM required)
  2. execute it through the reliability-aware ToolManager (with fallback)
  3. fold every result into the unified AssessmentState (assets, evidence,
     action history, findings) with confidence scored by the ConfidenceEngine
  4. record a Decision (reasoning + candidate ranking) so the run is
     reproducible and auditable
  5. repeat until the plan is exhausted, a budget is spent, or nothing
     worthwhile remains

The Controller deliberately reuses the existing recon/attack registries and
tool wrappers -- it is a new orchestration layer, not a rewrite.
"""

from __future__ import annotations

import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import authorization as auth
import tools.registry as _recon_registry
import tools.attack_registry as _attack_registry
from action_scorer import ActionScorer, information_gap
from confidence import ConfidenceEngine
from context import ANONYMOUS, EngagementContext
from memory_store import MemoryStore
from state import (
    ASSET_API,
    ASSET_CMS,
    ASSET_ENDPOINT,
    ASSET_IP,
    ASSET_PARAMETER,
    ASSET_PORT,
    ASSET_SERVICE,
    ASSET_SUBDOMAIN,
    ASSET_TECHNOLOGY,
    ASSET_URL,
    ActionRecord,
    Asset,
    Decision,
    EvidenceItem,
    AssessmentState,
    evidence_from_tool_result,
)
from tool_manager import RISK_ACTIVE_HIGH, ToolManager, output_quality, tool_risk_level
from utils import finding_key
from cvss import enrich_finding

RECON_CAPABILITIES = tuple(_recon_registry.CAPABILITY_TOOL_MAP.keys())
ATTACK_ACTIONS = tuple(_attack_registry.ATTACK_TOOL_MAP.keys())


def absorb_tool_result(state: AssessmentState, result, target: str) -> AssessmentState:
    """Fold a ToolResult's structured findings into an AssessmentState.

    Registering assets here means the same observation deduplicates across
    tools and sessions (via Asset.id), and coverage/planner queries stay
    correct without a separate merge step.
    """
    r = (result.results or {}) if result is not None else {}
    tool = getattr(result, "tool", "unknown")

    for p in r.get("open_ports", []) or []:
        state.upsert_asset(Asset(type=ASSET_PORT, value=p, source=tool))
    for sub in r.get("subdomains", []) or []:
        state.upsert_asset(Asset(type=ASSET_SUBDOMAIN, value=sub, source=tool))
    for tech in r.get("technologies", []) or []:
        state.upsert_asset(Asset(type=ASSET_TECHNOLOGY, value=tech, source=tool))
    for u in r.get("discovered_urls", []) or []:
        state.upsert_asset(Asset(type=ASSET_URL, value=u, source=tool))
    for ep in (r.get("discovered_endpoints", []) or []) + (r.get("discovered_paths", []) or []):
        url = ep if str(ep).startswith("http") else f"{target}{ep}"
        state.upsert_asset(Asset(type=ASSET_ENDPOINT, value=url, source=tool))
    for par in r.get("discovered_parameters", []) or []:
        state.upsert_asset(Asset(type=ASSET_PARAMETER, value=par, source=tool))
    for at in r.get("detected_api_types", []) or []:
        state.upsert_asset(Asset(type=ASSET_API, value=at, source=tool))
    if r.get("resolved_ip"):
        state.upsert_asset(Asset(type=ASSET_IP, value=r["resolved_ip"], source=tool))
    if r.get("cms_detected"):
        state.upsert_asset(Asset(type=ASSET_CMS, value=r["cms_detected"], source=tool))

    details = r.get("port_details", []) or []
    for d in details:
        port = d.get("port") if isinstance(d, dict) else None
        if not port:
            continue
        state.upsert_asset(Asset(
            type=ASSET_SERVICE, value=f"{port}/{d.get('service', '') or 'unknown'}",
            source=tool, properties={"port": port, "service": d.get("service", "")}))
    for s in r.get("services", []) or []:
        if isinstance(s, dict) and s.get("port"):
            state.upsert_asset(Asset(
                type=ASSET_SERVICE,
                value=f"{s['port']}/{str(s.get('service', '') or 'unknown')}",
                source=tool, properties=dict(s)))

    for v in r.get("vulnerabilities", []) or []:
        if isinstance(v, dict) and v.get("name"):
            v = dict(v)
            v.setdefault("url", "")
            v.setdefault("severity", str(v.get("severity", "UNKNOWN")).upper())
            v = enrich_finding(v)  # adds finding_type + cvss_vector/score/severity (see cvss.py)
            if finding_key(v) not in {finding_key(f) for f in state.findings}:
                state.findings.append(v)

    if r.get("reachable") is not None:
        state.metadata["reachable"] = r["reachable"]
    return state


class Controller:
    """Autonomous assessment controller for one target."""

    def __init__(
        self,
        target: str,
        tool_manager: Optional[ToolManager] = None,
        memory_store: Optional[MemoryStore] = None,
        scorer: Optional[ActionScorer] = None,
        confidence_engine: Optional[ConfidenceEngine] = None,
        allow_high_risk: bool = True,
        max_actions: int = 60,
        max_time_s: float = 600.0,
        min_action_score: float = 0.35,
        dry_run: bool = False,
        context: Optional[EngagementContext] = None,
        tool_timeout: int = 120,
        max_cap_attempts: int = 3,
    ) -> None:
        self.target = target
        self.tool_manager = tool_manager or ToolManager()
        self.memory = memory_store or MemoryStore(target, tool_manager=self.tool_manager)
        self.context = context or EngagementContext(target=target, base_url=f"https://{target}")
        self.allow_high_risk = bool(allow_high_risk)
        self.scorer = scorer or ActionScorer(
            tool_manager=self.tool_manager, allow_high_risk=self.allow_high_risk)
        self.confidence = confidence_engine or ConfidenceEngine(tool_manager=self.tool_manager)
        self.max_actions = max(1, int(max_actions))
        self.max_time_s = float(max_time_s)
        self.min_action_score = float(min_action_score)
        self.dry_run = bool(dry_run)
        self.tool_timeout = int(tool_timeout)
        self.max_cap_attempts = max(1, int(max_cap_attempts))

    def recon_candidates(self) -> List[str]:
        return list(RECON_CAPABILITIES)

    def attack_candidates(self) -> List[str]:
        return list(ATTACK_ACTIONS)

    def candidate_flags(self) -> List[Tuple[str, bool]]:
        """(capability, use_attack) pairs. Attack actions are gated by the
        high-risk policy unless allowed."""
        caps: List[Tuple[str, bool]] = [(c, False) for c in self.recon_candidates()]
        for action in self.attack_candidates():
            if self.allow_high_risk or tool_risk_level(action) != RISK_ACTIVE_HIGH:
                caps.append((action, True))
        seen, out = set(), []
        for cap, flag in caps:
            if cap in seen:
                continue
            seen.add(cap)
            out.append((cap, flag))
        return out

    def candidates_for_step(self, coverage: Dict[str, int],
                            attempted: List[str],
                            surface: Optional[Dict[str, Any]] = None,
                            session_attempts: Optional[Dict[str, int]] = None
                            ) -> List[Tuple[str, bool]]:
        """Phased candidate selection: reconnaissance first, attack after.

        Attack/testing actions enter the ranking once EITHER every recon
        capability has been attempted once, OR fundamental recon is complete
        (the target is reachable and has a web/network/API surface to test) --
        so a live target progresses to active testing after a few recon steps
        instead of stalling while exotic capabilities stay unexplored.
        """
        flags = self.candidate_flags()
        seen = Counter(session_attempts or {})
        flags = [f for f in flags if seen[f[0]] < self.max_cap_attempts]
        recon_flags = [f for f in flags if not f[1]]
        if not recon_flags:
            return flags
        surface = surface or {}
        recon_done = all(cap in (attempted or []) for cap, _ in recon_flags)
        core_done = bool(surface.get("reachable")) and bool(
            surface.get("web") or surface.get("network") or surface.get("api"))
        if recon_done or core_done:
            return flags
        return recon_flags

    def assess(self) -> Dict[str, Any]:
        """Run the assessment loop. Returns a summary + the decision trace."""
        if not self.dry_run:
            ok, reason = auth.is_authorized(self.target)
            if not ok:
                return {
                    "target": self.target, "actions_run": 0, "elapsed_s": 0.0,
                    "stop_reason": f"target not authorized: {reason}",
                    "dry_run": self.dry_run,
                    "coverage": {}, "surface": {}, "snapshot": {},
                    "decisions": [],
                }
        st = self.memory.load()
        attempted = self.memory.attempted_capabilities(st)
        coverage = self.memory.coverage_map(st)
        surface = self.memory.surface_hints(st)
        self.context.target = self.target
        if not self.context.base_url:
            self.context.base_url = f"https://{self.target}"
        st.metadata["engagement"] = self.context.to_dict()
        st.mark_updated()

        decisions: List[Decision] = list(st.decisions)
        started = time.monotonic()
        stop_reason = ""
        actions_run = 0
        session_attempts: Dict[str, int] = Counter()

        for _ in range(self.max_actions):
            if self.max_time_s and (time.monotonic() - started) >= self.max_time_s:
                stop_reason = "time budget exhausted"
                break
            ranked = self.scorer.rank_flagged(
                self.candidates_for_step(coverage, attempted, surface, session_attempts),
                coverage, attempted, surface)
            actionable = [s for s in ranked if s.total >= self.min_action_score]
            if not actionable:
                stop_reason = "no remaining action exceeds the minimum score"
                break

            top = actionable[0]
            decision = self._decide(st, top, ranked[:5], coverage)
            st.add_decision(decision)
            decisions.append(decision)
            actions_run += 1
            session_attempts[top.capability] += 1

            if self.dry_run:
                st.add_action(ActionRecord(
                    action=top.capability, tool="(dry-run)", target=self.target,
                    status="success", duration_s=0.0, output_quality=0.5))
                print(f"  [{actions_run}/{self.max_actions}] {top.capability} "
                      f"-> (dry-run)", flush=True)
            else:
                result, duration = self._run(top)
                self._absorb(st, top, result, duration)
                print(f"  [{actions_run}/{self.max_actions}] {top.capability} "
                      f"-> {result.status} ({duration:.1f}s)", flush=True)
            attempted.append(top.capability)
            coverage = self.memory.coverage_map(st)
            surface = self.memory.surface_hints(st)
            st.mark_updated()

        if not stop_reason:
            stop_reason = f"completed {actions_run} actions within budget"

        st.metadata["engagement"] = self.context.to_dict()
        self.memory.save(st)
        self.memory.import_attack_memory(st)
        self.memory.save(st)

        elapsed = time.monotonic() - started
        return {
            "target": self.target,
            "actions_run": actions_run,
            "elapsed_s": round(elapsed, 2),
            "stop_reason": stop_reason,
            "dry_run": self.dry_run,
            "coverage": coverage,
            "surface": surface,
            "snapshot": st.snapshot(),
            "decisions": [d.to_dict() for d in decisions],
        }

    # ── internals ───────────────────────────────────────────────────────────

    def _run(self, top) -> Tuple[Any, float]:
        t0 = time.monotonic()
        kw = {"context": self.context, "timeout": self.tool_timeout}
        if top.use_attack:
            result = self.tool_manager.execute_action(top.capability, self.target, **kw)
        else:
            result = self.tool_manager.execute_capability(top.capability, self.target, **kw)
        return result, time.monotonic() - t0

    def _absorb(self, st: AssessmentState, top, result, duration: float) -> None:
        st.add_action(ActionRecord(
            action=top.capability, tool=result.tool, target=self.target,
            status=result.status, duration_s=duration,
            output_quality=output_quality(result)))
        ev = evidence_from_tool_result(result, self.target)
        if ev is not None:
            ev.confidence = self.confidence.score_tool_result(
                ev.source_tool, ev.status, quality=output_quality(result))
            st.add_evidence(ev)
        absorb_tool_result(st, result, self.target)

    def _decide(self, st: AssessmentState, top, top_five: List[Any],
                coverage: Dict[str, int]) -> Decision:
        gaps = [cap for cap, _ in self.candidate_flags() if information_gap(coverage, cap) >= 1.0]
        return Decision(
            target=self.target, selected_action=top.capability,
            reasoning=(f"evidence-driven selection: {top.capability} "
                       f"(info_gain={top.info_gain:.2f}, success={top.success:.2f}, "
                       f"novelty={top.novelty:.2f}, risk={top.risk_level}, "
                       f"score={top.total:.2f})"),
            context_snapshot=st.snapshot(),
            knowledge_gaps=gaps[:5],
            candidate_actions=[s.to_dict() for s in top_five],
            selected_tool="",
        )