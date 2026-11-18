"""
PlannerAgent — hybrid: deterministic rules first, LLM refinement second.

Reads the SystemMap and produces a prioritized AttackGraph:
    [{agent, priority, reason, skip}]

Rules always produce a valid graph (deterministic, safe, fast).
If the LLM is available it may reorder/skip/justify nodes.
If the LLM fails, the rule graph stands (fallback).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import system_map as sm
from agents.base_agent import BaseAgent, extract_json
from utils import get_logger

try:
    import difficulty
except ImportError:  # TDA is optional; planning works without it
    difficulty = None  # type: ignore[assignment]

try:
    import rag_memory as rag
except ImportError:  # RAG memory is optional; planning works without it
    rag = None  # type: ignore[assignment]

log = get_logger("planner_agent")

AGENTS = ["web_attack", "burp", "ad", "network", "api", "auth", "infra", "cloud",
          "web_fuzz", "headers_attack", "subdomain_takeover", "waf_bypass", "jwt",
          "xxe", "csrf", "deserialization", "session_hijack",
          "ssti_exploit", "lfi_exploit", "ssrf_exploit", "xss_exploit", "jwt_exploit",
          "payload",
          "insecure_design", "exploitation", "privesc", "pivot", "intelligence"]

PLANNER_SYSTEM = """You are the PlannerAgent for CyberSwarm, an offensive security framework.

A deterministic rule engine already produced a candidate attack graph from the
target's SystemMap. Your job is to REFINE it: keep relevant nodes, set correct
priority (lower = higher priority), write a one-sentence reason per agent, and
skip agents with no attack surface. IntelligenceAgent must always run AFTER the
specialists. Do NOT invent agents. Do NOT run any tools.

Return ONLY JSON:
{
  "target_profile": "WEB_APPLICATION|REST_API|CMS|NETWORK|LINUX_HOST|WINDOWS_HOST|MIXED|UNKNOWN",
  "attack_graph": [
    {"agent": "<agent_name>", "priority": 1, "reason": "...", "skip": false,
     "estimated_remaining_steps": 3}
  ],
  "skip_agents": ["..."],
  "reasoning": "2-3 sentences on strategy"
}

"estimated_remaining_steps" is your honest estimate of how many more tool runs
that agent needs before it either proves or disproves something on this target.
1-2 means a quick check; 8+ means a long chain that may not finish. Estimate it
from the evidence, not from how interesting the agent sounds."""


class PlannerAgent(BaseAgent):
    agent_name = "planner"

    def build_attack_graph(self, system_map: Dict[str, Any],
                           completed_agents: List[str],
                           memory: Dict[str, Any],
                           use_llm: bool = True) -> Dict[str, Any]:
        # 1. Deterministic rule graph
        surface = sm.derive_attack_surface(system_map)
        rule_graph = self._rules_to_graph(surface, system_map, completed_agents)

        # 2. LLM refinement (optional), optionally seeded with prior-engagement
        #    lessons retrieved from the cross-engagement RAG store.
        graph = rule_graph
        if use_llm:
            lessons = self._rag_lessons(system_map)
            skills = self._rag_skills(system_map)
            # A malformed LLM refinement must never crash the attack phase; on
            # any parsing/shape error we fall back to the deterministic rule
            # graph (which is always well-formed).
            graph = rule_graph
            try:
                refined = self._llm_refine(system_map, rule_graph, completed_agents,
                                           lessons=lessons, skills=skills)
                sanitized = self._sanitize(refined, completed_agents) if refined else {}
                if sanitized:
                    # Never let the LLM silently drop agents that the
                    # deterministic rules confirmed have attack surface (it
                    # over-trims on small models). Rule-active nodes are always
                    # preserved; the LLM keeps its priority/reason for the rest.
                    graph = self._restore_rule_active(sanitized, rule_graph)
            except Exception as exc:
                import logging
                logging.getLogger("cyberswarm.planner").warning(
                    "LLM attack-graph refinement failed (%s); using the "
                    "deterministic rule graph for this target.", exc)
                graph = rule_graph

        graph = self._apply_completed(graph, completed_agents)
        graph["target_profile"] = self._profile(system_map)
        graph["reasoning"] = graph.get("reasoning") or self._default_reasoning(graph)
        return graph

    # ── Rules half ───────────────────────────────────────────────────────────

    def _rules_to_graph(self, surface: Dict[str, Any], smap: Dict[str, Any],
                        completed: List[str]) -> Dict[str, Any]:
        agents = surface.get("agents", {})
        nodes = []
        for name, info in sorted(agents.items(), key=lambda kv: kv[1].get("priority", 9)):
            if name in completed:
                continue
            nodes.append({
                "agent": name,
                "priority": int(info.get("priority", 9)),
                "reason": info.get("reason", ""),
                "skip": bool(info.get("skip")),
            })
        # intelligence always queued last (post-processing)
        if "intelligence" not in completed and "intelligence" not in [n["agent"] for n in nodes]:
            nodes.append({"agent": "intelligence", "priority": 10,
                          "reason": "Enrich confirmed findings with CVE/EPSS/KEV intelligence",
                          "skip": False})
        return {
            "target_profile": "UNKNOWN",
            "attack_graph": nodes,
            "skip_agents": [n["agent"] for n in nodes if n["skip"]],
            "reasoning": "",
        }

    def _default_reasoning(self, graph: Dict[str, Any]) -> str:
        active = [n["agent"] for n in graph.get("attack_graph", []) if not n.get("skip")]
        skipped = graph.get("skip_agents", [])
        txt = f"Rule-mapped attack plan: {', '.join(active) or 'none'}."
        if skipped:
            txt += f" Skipped (no surface): {', '.join(skipped)}."
        return txt

    def apply_difficulty(self, graph: Dict[str, Any],
                         history: Optional[Dict[str, Any]] = None,
                         findings_by_agent: Optional[Dict[str, Any]] = None,
                         model_client: Any = None,
                         config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Reorder the attack graph by assessed tractability.

        Branches assessed ABANDON are marked skipped with the reason attached,
        so a later reader can see why. Strictly advisory and fail-open: if TDA
        is unavailable, disabled, or raises, the graph is returned untouched.
        """
        if difficulty is None:
            return graph
        try:
            cfg = difficulty.tda_config(config)
            if not cfg["enabled"]:
                return graph

            nodes = list(graph.get("attack_graph", []))
            if not nodes:
                return graph

            used = getattr(model_client, "last_prompt_tokens", None)
            window = getattr(model_client, "context_window", None)

            assessments = difficulty.assess_graph(
                nodes, context_used=used, context_window=window,
                history=history or self._agent_history(),
                findings_by_agent=findings_by_agent,
                weights=cfg["weights"], thresholds=cfg["thresholds"])

            out = dict(graph)
            out["attack_graph"] = difficulty.reprioritise(nodes, assessments)
            out["difficulty"] = {a: v.to_dict() for a, v in assessments.items()}

            dropped = [a for a, v in assessments.items()
                       if v.verdict == difficulty.ABANDON]
            if dropped:
                log.info("TDA abandoned %d branch(es): %s",
                         len(dropped), ", ".join(sorted(dropped)))
            return out
        except Exception as exc:  # noqa: BLE001 - never break planning
            log.debug("Difficulty assessment skipped: %s", exc)
            return graph

    @staticmethod
    def _agent_history() -> Dict[str, Dict[str, Any]]:
        """Per-agent success counts from the tool reliability store."""
        try:
            from tool_manager import ToolManager
            return ToolManager().all_tool_stats()
        except Exception:  # noqa: BLE001
            return {}

    def rescore_with_evidence(self, graph: Dict[str, Any],
                              coverage: Optional[Dict[str, int]] = None,
                              attempted: Optional[List[str]] = None,
                              surface: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Deterministically re-prioritize an attack graph from evidence gaps.

        Merges the ActionScorer's evidence-driven ordering back into the graph
        while preserving any LLM-driven priority/skip decisions as tie-breakers.
        No-op-safe: with no evidence, the graph is returned with extra scoring.
        """
        from action_scorer import ActionScorer
        nodes = list(graph.get("attack_graph", []))
        scorer = ActionScorer()
        evidence_plan = scorer.score_plan(
            nodes, coverage or {}, attempted or [], surface or {})
        out = dict(graph)
        out["attack_graph"] = evidence_plan["attack_graph"]
        out["skip_agents"] = evidence_plan["skip_agents"]
        out["reasoning"] = evidence_plan["reasoning"]
        out["evidence_scored"] = True
        return out

    # ── LLM half ─────────────────────────────────────────────────────────────

    def _rag_lessons(self, smap: Dict[str, Any]) -> str:
        """Top-k lessons from prior engagements, as a prompt block.

        Strictly additive: returns "" when the module is absent, the feature is
        disabled, the index has not been built, or retrieval finds nothing. In
        every one of those cases planning proceeds exactly as it did before.
        """
        if rag is None:
            return ""
        try:
            cfg = rag.rag_config()
            if not cfg["enabled"]:
                return ""
            block = rag.lessons_for_smap(smap, k=cfg["top_k"])
            if block:
                log.debug("Planner injected %d RAG lesson(s)",
                          block.count("\n- "))
            else:
                log.debug("No RAG lessons available; planning without them")
            return block
        except Exception as exc:  # noqa: BLE001 - never break planning
            log.debug("RAG lesson lookup skipped: %s", exc)
            return ""

    def _rag_skills(self, smap: Dict[str, Any]) -> str:
        """Playbook excerpts matching this target's technology profile.

        Same contract as _rag_lessons: any failure yields "" and planning is
        unchanged. Kept separate so a noisy skill pack can be switched off
        (rag.index_skills) without losing engagement lessons.
        """
        if rag is None:
            return ""
        try:
            cfg = rag.rag_config()
            if not cfg.get("enabled") or not cfg.get("index_skills", True):
                return ""
            return rag.skills_for_smap(smap, k=cfg.get("skill_top_k"))
        except Exception as exc:  # noqa: BLE001 - never break planning
            log.debug("RAG skill lookup skipped: %s", exc)
            return ""

    def _llm_refine(self, smap: Dict[str, Any], rule_graph: Dict[str, Any],
                    completed: List[str],
                    lessons: str = "", skills: str = "") -> Optional[Dict[str, Any]]:
        compressed = sm.compress_for_llm(smap)
        user = (
            "Candidate rule graph:\n```json\n"
            f"{json.dumps(rule_graph, indent=2)}\n```\n\n"
            "SystemMap:\n```json\n"
            f"{json.dumps(compressed, indent=2)}\n```\n\n"
            f"Completed agents: {completed}\n\n"
        )
        if skills:
            user += f"{skills}\n\n"
        if lessons:
            user += f"{lessons}\n\n"
        user += "Return the refined attack graph JSON."
        return self._llm_json(PLANNER_SYSTEM, user, temperature=0.2)

    # ── Sanitization ─────────────────────────────────────────────────────────

    def _sanitize(self, graph: Dict[str, Any], completed: List[str]) -> Dict[str, Any]:
        if not isinstance(graph, dict):
            return {}
        raw_nodes = graph.get("attack_graph")
        if not isinstance(raw_nodes, list):
            return {}
        nodes = []
        seen = set()
        for n in raw_nodes:
            # Small models sometimes return the graph as a list of bare agent
            # names ("attack_graph": ["web_attack", "api"]) or put the name
            # under a different key, instead of the documented list of objects.
            # Coerce each shape rather than crashing the whole attack phase.
            if isinstance(n, str):
                n = {"agent": n}
            elif isinstance(n, dict):
                if "agent" not in n:
                    for alt in ("name", "agent_name", "id"):
                        if alt in n:
                            n = {**n, "agent": n[alt]}
                            break
            else:
                continue
            agent = n.get("agent")
            if agent not in AGENTS or agent in seen:
                continue
            seen.add(agent)
            try:
                priority = max(1, min(10, int(n.get("priority", 5))))
            except (TypeError, ValueError):
                priority = 5
            nodes.append({
                "agent": agent,
                "priority": priority,
                "estimated_remaining_steps": n.get("estimated_remaining_steps"),
                "reason": str(n.get("reason", ""))[:200],
                "skip": bool(n.get("skip")),
            })
        if not nodes:
            return {}
        return {
            "target_profile": str(graph.get("target_profile", "UNKNOWN")),
            "attack_graph": nodes,
            "skip_agents": [n["agent"] for n in nodes if n["skip"]],
            "reasoning": str(graph.get("reasoning", ""))[:500],
        }

    def _apply_completed(self, graph: Dict[str, Any],
                         completed: List[str]) -> Dict[str, Any]:
        nodes = [n for n in graph.get("attack_graph", []) if n["agent"] not in completed]
        graph["attack_graph"] = nodes
        graph["skip_agents"] = [n["agent"] for n in nodes if n.get("skip")]
        return graph

    def _restore_rule_active(self, graph: Dict[str, Any],
                             rule_graph: Dict[str, Any]) -> Dict[str, Any]:
        """Re-merge any agent the LLM dropped that the deterministic rules
        deemed active (not skipped). Prevents plan over-trimming on small
        models. LLM agents already present keep their LLM priority/reason;
        restored agents keep the rule priority/reason."""
        llm_nodes = {n["agent"]: n for n in graph.get("attack_graph", [])}
        for rn in rule_graph.get("attack_graph", []):
            agent = rn["agent"]
            if rn.get("skip"):
                continue
            if agent not in llm_nodes and agent not in graph.get("skip_agents", []):
                graph["attack_graph"].append(rn)
        return graph

    def _profile(self, smap: Dict[str, Any]) -> str:
        sig = smap.get("signals", {})
        if sig.get("cms"):
            return "CMS"
        if sig.get("ad") or sig.get("ldap_naming_contexts"):
            return "WINDOWS_HOST"
        if smap.get("api_paths") or sig.get("api_types"):
            return "REST_API"
        if any(s.get("port") not in (80, 443, 8080, 8443) for s in smap.get("services", [])):
            return "NETWORK"
        if smap.get("web_surfaces"):
            return "WEB_APPLICATION"
        return "UNKNOWN"

    # ── Replan ───────────────────────────────────────────────────────────────

    def replan(self, current_graph: Dict[str, Any], new_finding: Dict[str, Any],
               memory: Dict[str, Any], use_llm: bool = True) -> Dict[str, Any]:
        """Inject/reprioritize after a significant finding (creds, new paths...)."""
        completed = memory.get("completed_agents", [])
        # Rule-driven adjustments from the finding
        graph = dict(current_graph)
        nodes = list(graph.get("attack_graph", []))
        fp = str(new_finding.get("name", "")).lower() + " " + str(new_finding.get("description", "")).lower()
        if "credential" in fp or "session" in fp or "auth:" in fp or "admin" in fp:
            for n in nodes:
                if n["agent"] == "auth" and n.get("skip"):
                    n["skip"] = False
                    n["priority"] = 1
                    n["reason"] = "Credentials/session/auth surface obtained — escalate auth testing"
                if n["agent"] == "exploitation":
                    n["priority"] = 2
        if "/api/" in fp or "endpoint" in fp or "api:" in fp:
            for n in nodes:
                if n["agent"] == "api" and n.get("skip"):
                    n["skip"] = False
                    n["priority"] = 1
                    n["reason"] = "New API endpoints discovered"
        if use_llm and self.model:
            try:
                REPLAN = ("You are the PlannerAgent. A significant finding arrived mid-attack.\n"
                          "Update the graph. Return the same JSON schema. Only include agents "
                          "not already completed.")
                msg = (f"Current graph:\n{json.dumps(graph, indent=2)}\n\nNew finding:\n"
                       f"{json.dumps(new_finding, indent=2)}\n\nCompleted: {completed}\nUpdate the graph.")
                raw = self._llm(REPLAN, msg, temperature=0.2)
                refined = extract_json(raw)
                if refined and refined.get("attack_graph"):
                    graph = self._sanitize(refined, completed)
            except Exception:  # noqa: BLE001
                pass
        graph["attack_graph"] = self._apply_completed(graph, completed)["attack_graph"]
        return graph
