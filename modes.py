"""
modes.py — run modes and pause policy.

Replaces the single ``--auto-approve`` boolean with two independent axes, so
"run it all but stop and show me anything interesting" becomes expressible:

    mode   auto    run phases autonomously, approving planner decisions
           guided  propose every action and wait for approval
           free    no phase structure; run exactly what was asked

    pause  never       never stop
           always      stop after every agent/capability result
           checkpoint  stop at phase boundaries and on notable findings

The two combine: ``auto`` + ``always`` is autonomous execution that still
stops at every result for review, which is the common "watch it work" setup.

Scope note
----------
Free mode drops *phase* structure only. Target authorization is unaffected —
``authorization.py`` is consulted the same way in every mode. There is
deliberately no mode that bypasses the scope check.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, Optional, Sequence

try:
    from utils import get_logger
except ImportError:  # standalone import
    import logging

    def get_logger(name: str):  # type: ignore[misc]
        return logging.getLogger(name)

log = get_logger("modes")

_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class Mode(str, Enum):
    AUTO = "auto"
    GUIDED = "guided"
    FREE = "free"

    @classmethod
    def parse(cls, value: Any, default: "Mode" = None) -> "Mode":
        default = default or cls.AUTO
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except (ValueError, AttributeError):
            return default


class Pause(str, Enum):
    NEVER = "never"
    ALWAYS = "always"
    CHECKPOINT = "checkpoint"

    @classmethod
    def parse(cls, value: Any, default: "Pause" = None) -> "Pause":
        default = default or cls.NEVER
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except (ValueError, AttributeError):
            return default


def severity_rank(severity: Any) -> int:
    return _SEVERITY_RANK.get(str(severity).strip().upper(), 0)


@dataclass
class SessionPolicy:
    """How much rope the run gets, and when it stops to check in."""

    mode: Mode = Mode.AUTO
    pause: Pause = Pause.NEVER
    checkpoint_severity: str = "HIGH"

    # ── behaviour ────────────────────────────────────────────────────────────

    @property
    def enforces_phases(self) -> bool:
        """Free mode runs what it was asked, without phase structure."""
        return self.mode is not Mode.FREE

    @property
    def approves_automatically(self) -> bool:
        """True when planner decisions proceed without asking a human first."""
        return self.mode is not Mode.GUIDED

    def requires_approval_before_action(self) -> bool:
        """Guided mode proposes each action and waits."""
        return self.mode is Mode.GUIDED

    def should_pause_after_result(self, findings: Optional[Sequence[Any]] = None,
                                  phase_changed: bool = False) -> bool:
        """Whether to stop for review after a capability/agent result.

        ``always`` stops unconditionally. ``checkpoint`` stops at a phase
        boundary or when a finding reaches ``checkpoint_severity``.
        """
        if self.pause is Pause.NEVER:
            return False
        if self.pause is Pause.ALWAYS:
            return True
        if phase_changed:
            return True
        return self.has_notable_finding(findings)

    def has_notable_finding(self, findings: Optional[Iterable[Any]]) -> bool:
        threshold = severity_rank(self.checkpoint_severity)
        for finding in findings or []:
            severity = getattr(finding, "severity", None)
            if severity is None and isinstance(finding, dict):
                severity = finding.get("severity")
            if severity_rank(severity) >= threshold:
                return True
        return False

    # ── presentation ─────────────────────────────────────────────────────────

    def describe(self) -> str:
        bits = {
            Mode.AUTO: "autonomous through the phases",
            Mode.GUIDED: "proposes each action and waits for approval",
            Mode.FREE: "no phase structure; runs what you ask",
        }[self.mode]
        stops = {
            Pause.NEVER: "never stops",
            Pause.ALWAYS: "stops after every result",
            Pause.CHECKPOINT: (f"stops at phase boundaries and "
                               f"{self.checkpoint_severity}+ findings"),
        }[self.pause]
        return f"mode={self.mode.value} ({bits}); pause={self.pause.value} ({stops})"

    def to_dict(self) -> Dict[str, Any]:
        return {"mode": self.mode.value, "pause": self.pause.value,
                "checkpoint_severity": self.checkpoint_severity}


# ── Construction ─────────────────────────────────────────────────────────────

def from_config(config: Optional[Dict[str, Any]] = None) -> SessionPolicy:
    if config is None:
        try:
            from utils import load_config
            config = load_config()
        except Exception:  # noqa: BLE001
            config = {}
    section = (config or {}).get("session") or {}
    if not isinstance(section, dict):
        section = {}
    return SessionPolicy(
        mode=Mode.parse(section.get("mode"), Mode.AUTO),
        pause=Pause.parse(section.get("pause"), Pause.NEVER),
        checkpoint_severity=str(section.get("checkpoint_severity", "HIGH")).upper(),
    )


def from_args(args: Any, config: Optional[Dict[str, Any]] = None) -> SessionPolicy:
    """Build a policy from CLI args, falling back to config then defaults.

    ``--auto-approve`` remains supported: it is exactly ``auto`` + ``never``,
    so existing scripts and CI invocations keep working unchanged.
    """
    policy = from_config(config)

    mode = getattr(args, "mode", None)
    if mode:
        policy.mode = Mode.parse(mode, policy.mode)
    pause = getattr(args, "pause", None)
    if pause:
        policy.pause = Pause.parse(pause, policy.pause)

    if getattr(args, "auto_approve", False) and not mode and not pause:
        policy.mode = Mode.AUTO
        policy.pause = Pause.NEVER

    severity = getattr(args, "checkpoint_severity", None)
    if severity:
        policy.checkpoint_severity = str(severity).upper()
    return policy


def add_cli_arguments(parser: Any) -> None:
    """Attach --mode / --pause / --checkpoint-severity to an argparse parser."""
    parser.add_argument("--mode", choices=[m.value for m in Mode], default=None,
                        help="auto (autonomous), guided (approve each action), "
                             "free (no phase structure)")
    parser.add_argument("--pause", choices=[p.value for p in Pause], default=None,
                        help="never, always, or checkpoint (phase boundaries "
                             "and notable findings)")
    parser.add_argument("--checkpoint-severity", default=None,
                        help="severity that triggers a checkpoint pause "
                             "(default: HIGH)")
