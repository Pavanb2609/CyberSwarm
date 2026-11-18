"""
difficulty.py — real-time task difficulty assessment (TDA).

CyberSwarm could always tell you *what* it had found; it could never tell you
whether the branch it was working on was worth continuing. So it over-committed
to dead ends, kept going after the evidence had gone cold, and ran out of
context mid-chain. Those are the failures a human tester avoids by intuition —
"this isn't going anywhere, try something else."

This module supplies that judgement as a number, from four dimensions that are
each measurable from data the pipeline already produces:

    H  horizon           estimated steps still needed on this branch
    E  evidence          mean confidence of the findings along the path
    C  context           fraction of the model's context window consumed
    S  historical        how often this agent/tool has worked before

They compose into a tractability score in [0, 1] and one of three verdicts:

    CONTINUE      the branch is worth more effort
    DEPRIORITISE  push it below other branches, come back if they fail
    ABANDON       stop spending on it

Design notes
------------
* **Nothing here calls a model.** Horizon is read from a field the planner
  already returns; everything else is arithmetic over stored state. TDA must be
  cheap enough to run after every step, and a mechanism that costs an LLM call
  to decide whether to make an LLM call is self-defeating.
* **Missing dimensions degrade to neutral, not to zero.** An unmeasured
  dimension must not look like a failing one, or a fresh branch with no history
  would be abandoned before it started.
* **Verdicts are advisory.** Like the phase gates, this reorders and warns; it
  does not silently delete work. The caller decides what to do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:
    from utils import get_logger
except ImportError:  # standalone import
    import logging

    def get_logger(name: str):  # type: ignore[misc]
        return logging.getLogger(name)

log = get_logger("difficulty")

CONTINUE = "CONTINUE"
DEPRIORITISE = "DEPRIORITISE"
ABANDON = "ABANDON"

NEUTRAL = 0.5

# Evidence confidence floor. A branch resting on nothing but an untested
# hypothesis still scores above zero, because "unproven" is not "disproven".
SPECULATIVE = 0.3

# Beyond this many remaining steps a branch is treated as effectively
# unbounded. Chains longer than this have essentially never completed.
HORIZON_CEILING = 12


@dataclass
class Weights:
    """How much each dimension counts. Must be tuned against real runs.

    Note that ``context`` is not among them. Horizon, evidence and history are
    *value* signals -- they say whether a branch is worth pursuing. Context is a
    *constraint*: having plenty of room to think is not a reason to continue a
    hopeless path, though having none is a reason to stop a promising one. So
    context multiplies the weighted value rather than averaging into it.
    Averaging it in let a branch with zero evidence and no track record score
    respectably purely because the context window was empty.
    """

    horizon: float = 0.35
    evidence: float = 0.40
    historical: float = 0.25

    def normalised(self) -> "Weights":
        total = self.horizon + self.evidence + self.historical
        if total <= 0:
            return Weights()
        return Weights(self.horizon / total, self.evidence / total,
                       self.historical / total)


# How much an exhausted context can drag a score down. At full headroom the
# multiplier is 1.0; with the window full it is this value.
CONTEXT_FLOOR = 0.65


@dataclass
class Thresholds:
    abandon_below: float = 0.25
    deprioritise_below: float = 0.45
    # Context is a hard stop rather than a weighted term past this point:
    # a branch cannot finish a chain it has no room left to think about.
    context_hard_stop: float = 0.90


@dataclass
class Assessment:
    """One branch's tractability, with the reasoning kept attached."""

    branch: str = ""
    horizon: float = NEUTRAL
    evidence: float = NEUTRAL
    context: float = NEUTRAL
    historical: float = NEUTRAL
    score: float = NEUTRAL
    verdict: str = CONTINUE
    reasons: List[str] = field(default_factory=list)
    measured: List[str] = field(default_factory=list)

    @property
    def confident(self) -> bool:
        """True when enough dimensions were actually measured to be worth acting on.

        A verdict resting on one measured dimension and three neutral defaults
        is a guess wearing a number, and should not abandon anything.
        """
        return len(self.measured) >= 2

    def describe(self) -> str:
        lines = [f"{self.branch or 'branch'}: {self.verdict} (tractability {self.score:.2f})",
                 f"  horizon    {self.horizon:.2f}"
                 + ("" if "horizon" in self.measured else "   (not measured)"),
                 f"  evidence   {self.evidence:.2f}"
                 + ("" if "evidence" in self.measured else "   (not measured)"),
                 f"  context    {self.context:.2f}"
                 + ("" if "context" in self.measured else "   (not measured)"),
                 f"  historical {self.historical:.2f}"
                 + ("" if "historical" in self.measured else "   (not measured)")]
        lines += [f"  - {r}" for r in self.reasons]
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {"branch": self.branch, "score": round(self.score, 3),
                "verdict": self.verdict,
                "dimensions": {"horizon": round(self.horizon, 3),
                               "evidence": round(self.evidence, 3),
                               "context": round(self.context, 3),
                               "historical": round(self.historical, 3)},
                "measured": list(self.measured), "reasons": list(self.reasons)}


# ── Dimensions ───────────────────────────────────────────────────────────────

def _clamp(value: Any, default: float = NEUTRAL) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


def horizon_score(remaining_steps: Optional[Any],
                  active_branches: int = 1) -> Optional[float]:
    """Fewer remaining steps → higher score. None when unmeasured.

    Normalised across active branches: eight steps is discouraging on its own,
    but far worse when seven other branches are competing for the same budget.
    """
    if remaining_steps is None:
        return None
    try:
        steps = float(remaining_steps)
    except (TypeError, ValueError):
        return None
    if steps < 0:
        return None
    branches = max(1, int(active_branches or 1))
    # Each competing branch inflates the effective distance somewhat.
    effective = steps * (1.0 + 0.15 * (branches - 1))
    return _clamp(1.0 - min(effective, HORIZON_CEILING) / HORIZON_CEILING)


def evidence_score(confidences: Optional[Iterable[Any]]) -> Optional[float]:
    """Mean confidence along the path, floored at the speculative baseline.

    Accepts 0-1 or 0-100 values, since findings carry both conventions.
    """
    if confidences is None:
        return None
    values: List[float] = []
    for item in confidences:
        if item is None:
            continue
        try:
            value = float(item)
        except (TypeError, ValueError):
            continue
        if value > 1.0:
            value /= 100.0
        values.append(max(0.0, min(1.0, value)))
    if not values:
        return None
    return _clamp(max(SPECULATIVE, sum(values) / len(values)))


def context_score(used_tokens: Optional[Any],
                  window_tokens: Optional[Any]) -> Optional[float]:
    """Headroom left in the context window. 1.0 = empty, 0.0 = full."""
    if used_tokens is None or not window_tokens:
        return None
    try:
        used = float(used_tokens)
        window = float(window_tokens)
    except (TypeError, ValueError):
        return None
    if window <= 0:
        return None
    return _clamp(1.0 - (used / window))


def historical_score(successes: Optional[Any] = None,
                     attempts: Optional[Any] = None,
                     reliability: Optional[Any] = None) -> Optional[float]:
    """Prior probability this kind of work pays off.

    Accepts a precomputed reliability, or raw counts which are smoothed
    (Laplace) so a single failure on a first attempt does not read as
    hopeless.
    """
    if reliability is not None:
        return _clamp(reliability)
    if attempts is None:
        return None
    try:
        n = float(attempts)
        k = float(successes or 0)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    return _clamp((k + 1.0) / (n + 2.0))


# ── Composition ──────────────────────────────────────────────────────────────

def assess(branch: str = "",
           remaining_steps: Optional[Any] = None,
           active_branches: int = 1,
           confidences: Optional[Iterable[Any]] = None,
           used_tokens: Optional[Any] = None,
           window_tokens: Optional[Any] = None,
           successes: Optional[Any] = None,
           attempts: Optional[Any] = None,
           reliability: Optional[Any] = None,
           weights: Optional[Weights] = None,
           thresholds: Optional[Thresholds] = None) -> Assessment:
    """Score one branch. Every argument is optional; missing ones go neutral."""
    weights = (weights or Weights()).normalised()
    thresholds = thresholds or Thresholds()

    result = Assessment(branch=branch)

    dimensions = {
        "horizon": horizon_score(remaining_steps, active_branches),
        "evidence": evidence_score(confidences),
        "context": context_score(used_tokens, window_tokens),
        "historical": historical_score(successes, attempts, reliability),
    }
    for name, value in dimensions.items():
        if value is not None:
            setattr(result, name, value)
            result.measured.append(name)

    value = (result.horizon * weights.horizon
             + result.evidence * weights.evidence
             + result.historical * weights.historical)
    context_factor = CONTEXT_FLOOR + (1.0 - CONTEXT_FLOOR) * result.context
    result.score = _clamp(value * context_factor)

    # Explain the weak dimensions, so a verdict is auditable after the fact.
    if "horizon" in result.measured and result.horizon < 0.35:
        result.reasons.append(
            f"branch looks long: ~{remaining_steps} step(s) remaining"
            + (f" across {active_branches} active branches" if active_branches > 1 else ""))
    if "evidence" in result.measured and result.evidence <= SPECULATIVE + 0.01:
        result.reasons.append("evidence on this path is speculative, not verified")
    if "context" in result.measured and result.context < 0.25:
        result.reasons.append(
            f"context {100 * (1 - result.context):.0f}% consumed; "
            "a long chain will not fit")
    if "historical" in result.measured and result.historical < 0.35:
        result.reasons.append("this has rarely worked on past engagements")

    result.verdict = _verdict(result, thresholds)
    return result


def _verdict(result: Assessment, thresholds: Thresholds) -> str:
    # Context exhaustion is a hard stop: no weighting saves a branch that has
    # no room left to reason in. This is the 18%-of-failures case.
    if "context" in result.measured and result.context <= (1.0 - thresholds.context_hard_stop):
        result.reasons.append("context effectively exhausted — hard stop")
        return ABANDON

    if not result.confident:
        # One measured dimension is not grounds for demoting work, let alone
        # abandoning it.
        if result.score < thresholds.deprioritise_below:
            result.reasons.append(
                "score is low but too few dimensions were measured to act on it")
        return CONTINUE

    if result.score < thresholds.abandon_below:
        return ABANDON
    if result.score < thresholds.deprioritise_below:
        return DEPRIORITISE
    return CONTINUE


# ── Attack-graph integration ─────────────────────────────────────────────────

def assess_graph(nodes: Sequence[Dict[str, Any]],
                 context_used: Optional[Any] = None,
                 context_window: Optional[Any] = None,
                 history: Optional[Dict[str, Dict[str, Any]]] = None,
                 findings_by_agent: Optional[Dict[str, List[Any]]] = None,
                 weights: Optional[Weights] = None,
                 thresholds: Optional[Thresholds] = None) -> Dict[str, Assessment]:
    """Assess every non-skipped node of an attack graph.

    ``history`` maps agent name -> {"successes", "attempts"} (the shape
    ToolManager already stores). ``findings_by_agent`` maps agent name -> the
    findings produced so far on that branch.
    """
    active = [n for n in nodes if isinstance(n, dict) and not n.get("skip")]
    out: Dict[str, Assessment] = {}

    for node in active:
        agent = str(node.get("agent", "")).strip()
        if not agent:
            continue
        stats = (history or {}).get(agent) or {}
        findings = (findings_by_agent or {}).get(agent)
        confidences = ([getattr(f, "confidence", None)
                        if not isinstance(f, dict) else f.get("confidence")
                        for f in findings] if findings else None)

        out[agent] = assess(
            branch=agent,
            remaining_steps=node.get("estimated_remaining_steps"),
            active_branches=len(active),
            confidences=confidences,
            used_tokens=context_used, window_tokens=context_window,
            successes=stats.get("successes"), attempts=stats.get("attempts"),
            weights=weights, thresholds=thresholds)
    return out


def reprioritise(nodes: Sequence[Dict[str, Any]],
                 assessments: Dict[str, Assessment]) -> List[Dict[str, Any]]:
    """Reorder a graph by tractability, marking abandoned branches skipped.

    Returns a new list; the input is not mutated. Priorities are rewritten so
    downstream code that sorts on ``priority`` needs no changes.
    """
    ordered = sorted(
        (dict(n) for n in nodes if isinstance(n, dict)),
        key=lambda n: (
            bool(n.get("skip")),
            -(assessments.get(str(n.get("agent", "")), Assessment()).score),
            n.get("priority", 99),
        ))

    for index, node in enumerate(ordered, start=1):
        agent = str(node.get("agent", ""))
        verdict = assessments.get(agent)
        node["priority"] = index
        if verdict is None:
            continue
        node["tractability"] = round(verdict.score, 3)
        node["tda_verdict"] = verdict.verdict
        if verdict.verdict == ABANDON and not node.get("skip"):
            node["skip"] = True
            reason = "; ".join(verdict.reasons) or "assessed intractable"
            node["reason"] = f"{node.get('reason', '')} [TDA: {reason}]".strip()
    return ordered


# ── Config ───────────────────────────────────────────────────────────────────

def tda_config(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if config is None:
        try:
            from utils import load_config
            config = load_config()
        except Exception:  # noqa: BLE001
            config = {}
    section = (config or {}).get("difficulty") or {}
    if not isinstance(section, dict):
        section = {}
    raw_weights = section.get("weights") or {}
    if not isinstance(raw_weights, dict):
        raw_weights = {}
    raw_thresholds = section.get("thresholds") or {}
    if not isinstance(raw_thresholds, dict):
        raw_thresholds = {}

    def _f(source, key, default):
        try:
            return float(source.get(key, default))
        except (TypeError, ValueError):
            return default

    return {
        "enabled": bool(section.get("enabled", True)),
        "weights": Weights(
            horizon=_f(raw_weights, "horizon", 0.35),
            evidence=_f(raw_weights, "evidence", 0.40),
            historical=_f(raw_weights, "historical", 0.25)),
        "thresholds": Thresholds(
            abandon_below=_f(raw_thresholds, "abandon_below", 0.25),
            deprioritise_below=_f(raw_thresholds, "deprioritise_below", 0.45),
            context_hard_stop=_f(raw_thresholds, "context_hard_stop", 0.90)),
    }
