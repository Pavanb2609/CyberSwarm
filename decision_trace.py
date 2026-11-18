"""
decision_trace.py — reproducibility layer over the Controller decision log.

Every Controller step emits a `state.Decision` with the selected action, the
reasoning snapshot, the ranked candidate list and the open knowledge gaps.
This module turns that log into an auditable artifact:

  - gap_chronology(): which knowledge gaps existed when each step ran and
    which ones got closed by the following evidence
  - open_gaps(): capabilities still unexplored at the end of a run
  - selections(): the exact ordered capability plan + tool used
  - to_markdown()/export_trace(): render/download a human/JSON artifact

It is a pure query layer over `AssessmentState` -- no tools, no network,
so it is fully testable.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from state import AssessmentState, Decision, load_state


class DecisionTrace:
    """A read-only, deterministic view over one target's decision log."""

    def __init__(self, target: str, decisions: Optional[List[Decision]] = None) -> None:
        self.target = target
        self.decisions = list(decisions or [])

    # ── construction helpers ────────────────────────────────────────────────

    @classmethod
    def from_state(cls, st: AssessmentState) -> "DecisionTrace":
        return cls(st.target, list(st.decisions))

    @classmethod
    def load(cls, target: str) -> "DecisionTrace":
        st = load_state(target)
        return cls.from_state(st)

    @classmethod
    def from_decisions(cls, target: str,
                       decisions: List[Dict[str, Any]]) -> "DecisionTrace":
        return cls(target, [Decision.from_dict(d) for d in decisions])

    # ── queries ─────────────────────────────────────────────────────────────

    def selections(self) -> List[Dict[str, Any]]:
        """The exact ordered plan: (timestamp, action, tool, status)."""
        out = []
        for d in self.decisions:
            out.append({
                "timestamp": d.timestamp,
                "selected_action": d.selected_action,
                "selected_tool": d.selected_tool or None,
                "result_status": d.result_status or None,
            })
        # fall back to knowledge_gaps presence ordering when no decisions exist
        return out

    def gap_chronology(self) -> List[Dict[str, Any]]:
        """knowledge_gaps at each step (before the step's evidence landed)."""
        return [{"idx": i, "action": d.selected_action,
                 "gaps_before": list(d.knowledge_gaps)}
                for i, d in enumerate(self.decisions)]

    def open_gaps(self) -> List[str]:
        """Gaps recorded in the last decision -- i.e. still unexplored."""
        if not self.decisions:
            return []
        last = self.decisions[-1]
        return list(last.knowledge_gaps)

    def candidate_actions(self) -> List[List[Dict[str, Any]]]:
        """The ranked candidate list captured at each step."""
        return [list(d.candidate_actions) for d in self.decisions]

    def closed_gaps(self) -> Dict[str, Any]:
        """Map from a selected action to the successor decision that no longer
        lists it as a gap.  Order-insensitive, based on set change."""
        closed: Dict[str, List[int]] = {}
        gap_sets = [set(d.knowledge_gaps) for d in self.decisions]
        for i in range(len(gap_sets) - 1):
            current, nxt = gap_sets[i], gap_sets[i + 1]
            for gap in sorted(current - nxt):
                closed.setdefault(gap, []).append(i + 1)
        return closed

    def summary(self) -> Dict[str, Any]:
        """Pack everything into one stable dict for reports/CLI."""
        return {
            "target": self.target,
            "steps": len(self.decisions),
            "plan": self.selections(),
            "gap_chronology": self.gap_chronology(),
            "open_gaps": self.open_gaps(),
            "closed_gaps": self.closed_gaps(),
        }

    # ── rendering ───────────────────────────────────────────────────────────

    def to_markdown(self) -> str:
        lines = [f"# Decision Trace — {self.target}", ""]
        if not self.decisions:
            lines.append("_No decisions recorded yet._")
            return "\n".join(lines)
        for i, d in enumerate(self.decisions):
            lines.append(f"## step {i}: {d.selected_action}")
            lines.append("")
            if d.reasoning:
                lines.append(f"  - reason: {d.reasoning}")
            if d.selected_tool:
                lines.append(f"  - tool: {d.selected_tool}")
            if d.result_status:
                lines.append(f"  - outcome: {d.result_status}")
            if d.knowledge_gaps:
                lines.append("  - gaps: " + ", ".join(d.knowledge_gaps))
            lines.append("")
        lines.append(f"Open gaps: {', '.join(self.open_gaps()) or 'none'}")
        return "\n".join(lines)

    def export_trace(self, path: str) -> None:
        """Write the full trace as JSON to `path`."""
        from pathlib import Path
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.summary(), indent=2, sort_keys=True))


def collect_trace(target: str) -> DecisionTrace:
    """Convenience: build a trace from the saved State file."""
    return DecisionTrace.load(target)