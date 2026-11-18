"""
BaseAgent — parent for all CyberSwarm attack agents.

Every agent:
  1. Receives the SystemMap + memory snapshot
  2. Reasons about the attack surface (LLM call, optional)
  3. Selects targets / params / payloads
  4. Runs >= 1 tool
  5. Analyzes output (LLM call)
  6. Emits AgentResult with confidence-scored findings

Subclass this. Override run().
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from model_client import ModelClient
from utils import get_logger

log = get_logger("base_agent")

_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}


@dataclass
class AgentFinding:
    agent: str
    tool: str
    name: str
    severity: str = "INFO"                 # CRITICAL/HIGH/MEDIUM/LOW/INFO
    confidence: int = 50                   # 0-100
    url: str = ""
    port: str = ""
    description: str = ""
    evidence_chain: List[str] = field(default_factory=list)
    critic_score: Optional[int] = None
    final_confidence: Optional[int] = None
    false_positive_risk: str = "UNKNOWN"   # LOW/MEDIUM/HIGH
    verdict: str = "PENDING"               # CONFIRM/DISPUTE/NEEDS_PROOF
    raw_output_excerpt: str = ""
    independent_sources: int = 1          # independent tool outputs behind this finding
    proofs: List[Dict[str, Any]] = field(default_factory=list)
    # Continuous, per-attempt evidence (XSStrike-style): each entry is
    # {"payload", "category", "request": {...}, "response": {...}, "matched",
    #  "match_criteria"}. The payload agent fills this so a finding is never
    # a bare claim -- you can replay the exact request that triggered it.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent,
            "tool": self.tool,
            "name": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "port": self.port,
            "description": self.description[:500],
            "evidence_chain": self.evidence_chain,
            "critic_score": self.critic_score,
            "final_confidence": self.final_confidence,
            "false_positive_risk": self.false_positive_risk,
            "verdict": self.verdict,
            "raw_output_excerpt": self.raw_output_excerpt[:500],
            "independent_sources": self.independent_sources,
            "proofs": self.proofs,
        }


@dataclass
class AgentResult:
    agent: str
    target: str
    status: str                            # success / partial / failed / skipped
    findings: List[AgentFinding] = field(default_factory=list)
    attack_paths_discovered: List[str] = field(default_factory=list)
    proof_requests: List[str] = field(default_factory=list)
    reasoning: str = ""
    tools_run: List[str] = field(default_factory=list)
    duration_s: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent,
            "target": self.target,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "attack_paths_discovered": self.attack_paths_discovered,
            "proof_requests": self.proof_requests,
            "reasoning": self.reasoning,
            "tools_run": self.tools_run,
            "duration_s": round(self.duration_s, 1),
            "error": self.error,
        }


def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Robust JSON extraction from an LLM response (think tags + fences)."""
    raw = text or ""
    if "<think>" in raw:
        end_idx = raw.rfind("</think>")
        if end_idx == -1:
            # <think> was opened but the response got truncated before it
            # closed (e.g. hit num_predict/max_tokens mid-thought) -- there's
            # no reliable JSON after an unclosed think block, so bail out
            # cleanly instead of slicing from a bogus -1+8=7 offset.
            return None
        raw = raw[end_idx + len("</think>"):].strip()
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    blob = raw[start:end + 1]
    try:
        parsed = json.loads(blob)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


class BaseAgent:
    """Subclass and override run(). agent_name and owned_tools are required."""

    agent_name: str = "base"
    owned_tools: List[str] = []
    system_prompt: str = ""

    def __init__(self, model_client: ModelClient):
        self.model = model_client
        # tool_name -> real evidence excerpt captured from the last successful
        # ToolResult for that tool. Findings produced from a tool run get this
        # spliced into their evidence_chain automatically (see _make_finding),
        # so the CriticAgent's deterministic evidence gate has concrete tool
        # output to verify against instead of LLM narration.
        self._tool_outputs: Dict[str, str] = {}

    # ── LLM helpers ──────────────────────────────────────────────────────────

    def _llm(self, system: str, user: str, temperature: float = 0.2) -> str:
        try:
            return self.model.chat(system, user, temperature=temperature)
        except Exception as e:  # noqa: BLE001
            log.error("LLM call failed for %s: %s", self.agent_name, e)
            return f"__LLM_ERROR__: {e}"

    def _llm_json(self, system: str, user: str, temperature: float = 0.2) -> Optional[Dict]:
        raw = self._llm(system, user, temperature)
        if raw.startswith("__LLM_ERROR__"):
            return None
        return extract_json(raw)

    # ── Tool running ─────────────────────────────────────────────────────────

    def _run_tool(self, tool_name: str, target: str, timeout: int = 300, **kwargs):
        """Dynamically load and run a tool. Returns ToolResult or None."""
        try:
            from tools.attack_registry import load_attack_tool
            tool = load_attack_tool(tool_name)
        except Exception:  # noqa: BLE001
            try:
                from tools.registry import load_tool
                tool = load_tool(tool_name)
            except Exception:  # noqa: BLE001
                log.warning("Tool %s not loadable (attack or recon registry)", tool_name)
                return None
        err = tool.validate()
        if err:
            log.info("Tool %s not available: %s", tool_name, err)
            return None
        result = tool.run(target, timeout=timeout, **kwargs)
        # Capture real evidence from the ToolResult so findings can cite it.
        if result is not None and getattr(result, "status", "") == "success":
            self._tool_outputs[tool_name] = self._excerpt_from_toolresult(result)
        return result

    @staticmethod
    def _excerpt_from_toolresult(result) -> str:
        """Build a compact evidence excerpt from a ToolResult (raw stdout or
        structured results). Returns raw stdout when present, else a bounded
        json dump of the parsed results."""
        raw = getattr(result, "raw_stdout", None) or ""
        raw = str(raw).strip()
        if len(raw) >= 8:
            return raw[:1200]
        try:
            results = getattr(result, "results", None)
            if results:
                blob = json.dumps(results, ensure_ascii=False)[:1200]
                if len(blob) >= 8:
                    return blob
        except (TypeError, ValueError):
            pass
        return ""

    def evidence_for_tool(self, tool_name: str) -> str:
        """Most recent real tool-output excerpt for `tool_name`. Empty if the
        tool never ran successfully in this agent instance."""
        return self._tool_outputs.get(tool_name, "") or ""

    def _append_tool_evidence(self, finding: "AgentFinding") -> None:
        """If a real tool produced this finding, and no evidence is attached,
        splice the captured tool output into evidence_chain + raw_output_excerpt.
        Pure-LLM findings (tool='analysis'/'recon') never get tool evidence
        injected, so the evidence gate can reject them deterministically."""
        if finding.tool in ("", "analysis", "recon"):
            return
        excerpt = self.evidence_for_tool(finding.tool)
        if not excerpt:
            return
        if not finding.evidence_chain:
            finding.evidence_chain = [f"[{finding.tool}] {excerpt}"]
        if not (finding.raw_output_excerpt or "").strip():
            finding.raw_output_excerpt = excerpt[:500]

    # ── Finding factory ──────────────────────────────────────────────────────

    def _make_finding(self, tool: str, name: str, severity: str, confidence: int,
                      **kwargs) -> AgentFinding:
        sev = str(severity).upper()
        if sev not in _SEVERITIES:
            sev = "INFO"
        conf = self._coerce_confidence(confidence)
        finding = AgentFinding(
            agent=self.agent_name, tool=tool, name=name, severity=sev,
            confidence=conf, **kwargs,
        )
        self._append_tool_evidence(finding)
        return finding

    @staticmethod
    def _coerce_confidence(confidence: Any) -> int:
        """LLMs sometimes return 'HIGH' / '70%' / '' instead of an int."""
        if isinstance(confidence, bool):
            return 100 if confidence else 0
        if isinstance(confidence, int):
            return max(0, min(100, confidence))
        if isinstance(confidence, float):
            return max(0, min(100, int(confidence)))
        s = str(confidence or "").strip().lower().rstrip("%")
        word_map = {"high": 75, "medium": 55, "low": 35, "info": 15,
                    "confirmed": 90, "critical": 90, "none": 0, "unknown": 50}
        if s in word_map:
            return word_map[s]
        try:
            val = float(s)
        except (TypeError, ValueError):
            return 50
        if 0 < val <= 1:  # 0-1 scale from LLM -> percent
            val *= 100
        return max(0, min(100, int(round(val))))

    # ── Main entry point ─────────────────────────────────────────────────────

    def run(self, target: str, system_map: Dict[str, Any],
            memory: Dict[str, Any]) -> AgentResult:
        raise NotImplementedError(f"{self.__class__.__name__} must implement run()")

    def should_run(self, system_map: Dict[str, Any]) -> bool:
        return True


def run_with_timing(agent: BaseAgent, target: str, smap: Dict[str, Any],
                    memory: Dict[str, Any]) -> AgentResult:
    t0 = time.time()
    result = AgentResult(agent=agent.agent_name, target=target, status="failed")
    try:
        result = agent.run(target, smap, memory)
    except Exception as e:  # noqa: BLE001
        result.status = "failed"
        result.error = str(e)
    result.duration_s = time.time() - t0
    if not result.status:
        result.status = "success" if result.findings else "partial"
    return result
