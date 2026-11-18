"""
MemoryAgent — durable, confidence-scored store and keeper of the SystemMap.

Only Critic-confirmed findings become vulnerabilities. Disputed findings are
kept for audit. Findings also update the SystemMap links so the model of the
target evolves across the whole engagement.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from agents.base_agent import AgentFinding, AgentResult
from utils import finding_key, SEVERITY_ORDER

STORE_DIR = Path(__file__).parent.parent / "results" / "attack_evidence"


def _path_for(target: str) -> Path:
    safe = target.replace("/", "_").replace(":", "_")
    return STORE_DIR / f"{safe}.json"


class MemoryAgent:
    """Not an LLM agent — pure logic. Owns writes to attack evidence."""

    def __init__(self, target: str):
        self.target = target
        self._path = _path_for(target)

    def load(self) -> Dict[str, Any]:
        if self._path.exists():
            return json.loads(self._path.read_text(encoding="utf-8"))
        return self._empty()

    def save(self, memory: Dict[str, Any]) -> None:
        STORE_DIR.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(memory, indent=2), encoding="utf-8")

    def store_agent_result(self, memory: Dict[str, Any], result: AgentResult,
                           critic_buckets: Dict[str, List[AgentFinding]],
                           system_map: Dict[str, Any] = None) -> Dict[str, Any]:
        vulns = memory.setdefault("vulnerabilities", [])
        by_key = {finding_key(v): v for v in vulns}
        for f in critic_buckets.get("confirmed", []):
            vuln = self._finding_to_vuln(f)
            key = finding_key(vuln)
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = vuln
                vulns.append(vuln)
            else:
                # Same issue already recorded (possibly by another agent) --
                # merge rather than duplicate: keep whichever severity is higher.
                old_idx = SEVERITY_ORDER.index(str(existing.get("severity", "UNKNOWN")).upper()) \
                    if str(existing.get("severity", "UNKNOWN")).upper() in SEVERITY_ORDER else 0
                new_idx = SEVERITY_ORDER.index(vuln["severity"]) if vuln["severity"] in SEVERITY_ORDER else 0
                if new_idx > old_idx:
                    idx = vulns.index(existing)
                    vulns[idx] = vuln
                    by_key[key] = vuln
        seen_disputed = {finding_key(v) for v in memory.get("disputed_findings", [])}
        for f in critic_buckets.get("disputed", []):
            vuln = self._finding_to_vuln(f)
            key = finding_key(vuln)
            if key not in seen_disputed:
                seen_disputed.add(key)
                memory.setdefault("disputed_findings", []).append(vuln)
        for f in critic_buckets.get("needs_proof", []):
            req = f"[{f.agent}] {f.name}: {f.description[:200]}"
            if req not in memory.get("proof_requests", []):
                memory.setdefault("proof_requests", []).append(req)

        agent = result.agent
        if agent not in memory.get("completed_agents", []):
            memory.setdefault("completed_agents", []).append(agent)

        for path in result.attack_paths_discovered:
            if path not in memory.get("new_attack_paths", []):
                memory.setdefault("new_attack_paths", []).append(path)

        memory["risk_rating"] = self._compute_risk(memory)

        for f in (critic_buckets.get("confirmed", []) + critic_buckets.get("disputed", [])
                  + critic_buckets.get("needs_proof", [])):
            memory.setdefault("agent_debate_log", []).append({
                "agent": f.agent,
                "finding": f.name,
                "agent_confidence": f.confidence,
                "critic_score": f.critic_score,
                "final_confidence": f.final_confidence,
                "verdict": f.verdict,
            })

        memory.setdefault("agent_runs", []).append(result.to_dict())

        if system_map is not None:
            self._update_system_map(system_map, critic_buckets)
        return memory

    def _update_system_map(self, system_map: Dict[str, Any],
                           buckets: Dict[str, List[AgentFinding]]) -> None:
        import system_map as sm
        for f in buckets.get("confirmed", []):
            sm.add_link(system_map, f"finding:{f.name}", "vulnerability",
                        kind=f"confirmed_by_{f.agent}", confidence=f.final_confidence or f.confidence,
                        source=f.agent)
        sm.save_map(self.target, system_map)

    def _finding_to_vuln(self, f: AgentFinding) -> Dict[str, Any]:
        return {
            "source_agent": f.agent,
            "tool": f.tool,
            "name": f.name,
            "severity": f.severity,
            "confidence": f.final_confidence or f.confidence,
            "final_confidence": f.final_confidence,
            "url": f.url,
            "port": f.port,
            "description": f.description[:500],
            "false_positive_risk": f.false_positive_risk,
            "verdict": f.verdict,
            "independent_sources": f.independent_sources,
            "evidence_chain": [str(x)[:600] for x in (f.evidence_chain or [])][:8],
            "raw_output_excerpt": str(f.raw_output_excerpt or "")[:1600],
            "proofs": (f.proofs or [])[:20],
        }

    def _compute_risk(self, memory: Dict[str, Any]) -> str:
        idx = 0
        for v in memory.get("vulnerabilities", []):
            sev = str(v.get("severity", "UNKNOWN")).upper()
            if sev in SEVERITY_ORDER:
                idx = max(idx, SEVERITY_ORDER.index(sev))
        return SEVERITY_ORDER[idx]

    def _empty(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "vulnerabilities": [],
            "disputed_findings": [],
            "proof_requests": [],
            "completed_agents": [],
            "attack_graph": {},
            "agent_debate_log": [],
            "new_attack_paths": [],
            "agent_runs": [],
            "risk_rating": "UNKNOWN",
        }
