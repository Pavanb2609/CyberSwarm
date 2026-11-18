"""
phases.py — engagement phase model with quality gates.

CyberSwarm already runs recon and attack as two scripts, but nothing stops a
run from entering exploitation against a target it barely enumerated. This
module makes the progression explicit and gated:

    DISCOVERY -> ENUMERATION -> SURFACE_MAPPING -> EXPLOITATION -> REPORTING

Each phase declares the capabilities/agents that belong to it and a set of
*entry gates* — cheap predicates over the evidence already collected. A gate
answers one question: "is there enough signal to make this phase worth
running?" Advancing with a failing gate is allowed, but only explicitly
(``force=True``), and the override is recorded in the phase history.

Gates read evidence dicts (the shape both run loops already pass around), so
this module has no dependency on the agent or tool layers and stays cheap to
test.

Design notes
------------
* Gates are advisory-by-default. This is a quality mechanism ("you're about to
  exploit a host you never port-scanned"), not an authorization mechanism.
  Target authorization remains entirely in ``authorization.py``.
* Phase state is per-target and persisted, so a resumed run picks up where it
  left off rather than silently restarting at DISCOVERY.
* Unknown/legacy capabilities never block anything: a capability this module
  has never heard of is simply not counted toward coverage.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:
    from utils import ROOT, get_logger
except ImportError:  # standalone import
    ROOT = Path(__file__).resolve().parent
    import logging

    def get_logger(name: str):  # type: ignore[misc]
        return logging.getLogger(name)

log = get_logger("phases")

STATE_DIR = ROOT / "results" / "phase_state"


# ── Phase definitions ────────────────────────────────────────────────────────

DISCOVERY = "DISCOVERY"
ENUMERATION = "ENUMERATION"
SURFACE_MAPPING = "SURFACE_MAPPING"
EXPLOITATION = "EXPLOITATION"
REPORTING = "REPORTING"

PHASE_ORDER: List[str] = [DISCOVERY, ENUMERATION, SURFACE_MAPPING,
                          EXPLOITATION, REPORTING]

# Recon capabilities that belong to each phase. Drawn from
# CAPABILITY_EXECUTION_ORDER in run_recon_loop.py.
PHASE_CAPABILITIES: Dict[str, List[str]] = {
    DISCOVERY: [
        "PASSIVE_ASSET_DISCOVERY", "SUBDOMAIN_DISCOVERY", "DNS_RESOLUTION",
        "DNS_ENUMERATION", "HOST_DISCOVERY",
    ],
    ENUMERATION: [
        "PORT_DISCOVERY", "SERVICE_DETECTION", "OPERATING_SYSTEM_IDENTIFICATION",
        "WEB_PROBING", "WEB_TECHNOLOGY_DISCOVERY", "TLS_ANALYSIS",
        "HEADER_ANALYSIS", "CERT_INFO",
    ],
    SURFACE_MAPPING: [
        "WEB_CRAWLING", "HISTORICAL_URL_DISCOVERY", "CONTENT_DISCOVERY",
        "PARAMETER_DISCOVERY", "JAVASCRIPT_ANALYSIS", "API_ENDPOINT_DISCOVERY",
        "GRAPHQL_INTROSPECTION", "CMS_IDENTIFICATION", "CMS_ASSESSMENT",
        "ROBOTS_TXT_ANALYSIS", "SENSITIVE_ENDPOINT_DETECTION",
        "UPLOAD_FORM_DETECTION", "CSRF_SURFACE_DETECTION", "COOKIE_ANALYSIS",
        "SESSION_ANALYSIS", "AUTH_FLOW_ANALYSIS", "DESERIALIZATION_DETECTION",
        "SCREENSHOT_CAPTURE", "DIRECTORY_SERVICE_ENUMERATION",
        "WINDOWS_SERVICE_ENUMERATION", "CLOUD_ASSET_DISCOVERY",
        "CONTAINER_DISCOVERY", "IOT_SERVICE_IDENTIFICATION",
    ],
    EXPLOITATION: [],   # driven by agents, not recon capabilities
    REPORTING: [],
}

# Which recon phase a capability belongs to (reverse index).
CAPABILITY_PHASE: Dict[str, str] = {
    cap: phase
    for phase, caps in PHASE_CAPABILITIES.items()
    for cap in caps
}


# ── Context ──────────────────────────────────────────────────────────────────

@dataclass
class PhaseContext:
    """Everything the gates need, derived from evidence the loops already hold."""

    target: str = ""
    completed_actions: List[str] = field(default_factory=list)
    failed_actions: List[str] = field(default_factory=list)
    open_ports: List[Any] = field(default_factory=list)
    technologies: List[Any] = field(default_factory=list)
    web_surfaces: List[Any] = field(default_factory=list)
    endpoints: List[Any] = field(default_factory=list)
    resolved: bool = False
    reachable: bool = False
    findings: int = 0
    completed_agents: List[str] = field(default_factory=list)

    @classmethod
    def from_evidence(cls, evidence: Optional[Dict[str, Any]],
                      attack_evidence: Optional[Dict[str, Any]] = None,
                      target: str = "") -> "PhaseContext":
        ev = evidence if isinstance(evidence, dict) else {}
        att = attack_evidence if isinstance(attack_evidence, dict) else {}

        urls = list(ev.get("discovered_urls") or [])
        urls += list(ev.get("web_surfaces") or [])
        endpoints = list(ev.get("endpoints") or []) + list(ev.get("api_paths") or [])

        return cls(
            target=str(target or ev.get("target") or att.get("target") or ""),
            completed_actions=[str(a) for a in (ev.get("completed_actions") or [])],
            failed_actions=[str(a) for a in (ev.get("failed_actions") or [])],
            open_ports=list(ev.get("open_ports") or ev.get("port_details") or []),
            technologies=list(ev.get("technologies") or []),
            web_surfaces=urls,
            endpoints=endpoints,
            resolved=bool(ev.get("resolved_ip") or ev.get("resolved_ips")
                          or ev.get("subdomains")),
            reachable=bool(ev.get("reachable")),
            findings=len(att.get("vulnerabilities") or []),
            completed_agents=[str(a) for a in (att.get("completed_agents") or [])],
        )

    def coverage(self, phase: str) -> Tuple[int, int]:
        """(completed, total) recon capabilities for ``phase``."""
        caps = PHASE_CAPABILITIES.get(phase, [])
        if not caps:
            return (0, 0)
        done = sum(1 for c in caps if c in set(self.completed_actions))
        return (done, len(caps))

    def coverage_ratio(self, phase: str) -> float:
        done, total = self.coverage(phase)
        return (done / total) if total else 1.0


# ── Gates ────────────────────────────────────────────────────────────────────

@dataclass
class GateResult:
    name: str
    passed: bool
    detail: str

    def __str__(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        return f"[{mark}] {self.name}: {self.detail}"


@dataclass
class Gate:
    """One entry condition for a phase."""

    name: str
    check: Callable[[PhaseContext, "GateConfig"], Tuple[bool, str]]

    def evaluate(self, ctx: PhaseContext, cfg: "GateConfig") -> GateResult:
        try:
            passed, detail = self.check(ctx, cfg)
        except Exception as exc:  # noqa: BLE001 - a broken gate must not block a run
            log.debug("Gate %s raised (%s); treating as passed", self.name, exc)
            return GateResult(self.name, True, f"gate error, not enforced: {exc}")
        return GateResult(self.name, bool(passed), str(detail))


@dataclass
class GateConfig:
    """Thresholds, so gates are tunable without editing code."""

    min_discovery_coverage: float = 0.4
    min_enumeration_coverage: float = 0.5
    min_surface_coverage: float = 0.25
    require_open_port_for_exploitation: bool = True


def _gate_resolved(ctx: PhaseContext, cfg: GateConfig) -> Tuple[bool, str]:
    if ctx.resolved or ctx.reachable or ctx.open_ports:
        return True, "target resolved or reachable"
    return False, "no resolved address, subdomain or open port yet"


def _gate_discovery_coverage(ctx: PhaseContext, cfg: GateConfig) -> Tuple[bool, str]:
    done, total = ctx.coverage(DISCOVERY)
    ratio = ctx.coverage_ratio(DISCOVERY)
    ok = ratio >= cfg.min_discovery_coverage
    return ok, (f"discovery coverage {done}/{total} "
                f"({ratio:.0%} vs {cfg.min_discovery_coverage:.0%} required)")


def _gate_enumeration_coverage(ctx: PhaseContext, cfg: GateConfig) -> Tuple[bool, str]:
    done, total = ctx.coverage(ENUMERATION)
    ratio = ctx.coverage_ratio(ENUMERATION)
    ok = ratio >= cfg.min_enumeration_coverage
    return ok, (f"enumeration coverage {done}/{total} "
                f"({ratio:.0%} vs {cfg.min_enumeration_coverage:.0%} required)")


def _gate_surface_coverage(ctx: PhaseContext, cfg: GateConfig) -> Tuple[bool, str]:
    done, total = ctx.coverage(SURFACE_MAPPING)
    ratio = ctx.coverage_ratio(SURFACE_MAPPING)
    ok = ratio >= cfg.min_surface_coverage
    return ok, (f"surface coverage {done}/{total} "
                f"({ratio:.0%} vs {cfg.min_surface_coverage:.0%} required)")


def _gate_has_attack_surface(ctx: PhaseContext, cfg: GateConfig) -> Tuple[bool, str]:
    if ctx.web_surfaces or ctx.endpoints:
        return True, f"{len(ctx.web_surfaces)} web surface(s), {len(ctx.endpoints)} endpoint(s)"
    if ctx.open_ports and not cfg.require_open_port_for_exploitation:
        return True, "open ports present"
    if ctx.open_ports:
        return True, f"{len(ctx.open_ports)} open port(s)"
    return False, "nothing to attack: no web surface, endpoint or open port"


def _gate_service_identified(ctx: PhaseContext, cfg: GateConfig) -> Tuple[bool, str]:
    if ctx.technologies or ctx.open_ports:
        return True, (f"{len(ctx.technologies)} technolog(ies), "
                      f"{len(ctx.open_ports)} port(s) identified")
    return False, "no service or technology identified; exploitation would be blind"


def _gate_any_work_done(ctx: PhaseContext, cfg: GateConfig) -> Tuple[bool, str]:
    if ctx.completed_actions or ctx.completed_agents:
        return True, (f"{len(ctx.completed_actions)} capabilit(ies), "
                      f"{len(ctx.completed_agents)} agent(s) completed")
    return False, "nothing has run; a report would be empty"


PHASE_GATES: Dict[str, List[Gate]] = {
    DISCOVERY: [],
    ENUMERATION: [
        Gate("target_resolved", _gate_resolved),
        Gate("discovery_coverage", _gate_discovery_coverage),
    ],
    SURFACE_MAPPING: [
        Gate("enumeration_coverage", _gate_enumeration_coverage),
        Gate("service_identified", _gate_service_identified),
    ],
    EXPLOITATION: [
        Gate("attack_surface_present", _gate_has_attack_surface),
        Gate("enumeration_coverage", _gate_enumeration_coverage),
        Gate("surface_coverage", _gate_surface_coverage),
    ],
    REPORTING: [
        Gate("any_work_done", _gate_any_work_done),
    ],
}


# ── Controller ───────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_name(target: str) -> str:
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in str(target))[:120] or "unknown"


@dataclass
class PhaseState:
    target: str
    phase: str = DISCOVERY
    history: List[Dict[str, Any]] = field(default_factory=list)
    updated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"target": self.target, "phase": self.phase,
                "history": self.history, "updated_at": self.updated_at}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PhaseState":
        phase = str(data.get("phase") or DISCOVERY)
        if phase not in PHASE_ORDER:
            phase = DISCOVERY
        return cls(target=str(data.get("target", "")), phase=phase,
                   history=list(data.get("history") or []),
                   updated_at=str(data.get("updated_at", "")))


class PhaseController:
    """Tracks and gates the current phase for one target."""

    def __init__(self, target: str, state_dir: Optional[Path] = None,
                 gate_config: Optional[GateConfig] = None,
                 enabled: bool = True):
        self.target = str(target)
        self.state_dir = Path(state_dir) if state_dir else STATE_DIR
        self.gate_config = gate_config or GateConfig()
        self.enabled = bool(enabled)
        self._state: Optional[PhaseState] = None

    # ── persistence ──────────────────────────────────────────────────────────

    @property
    def path(self) -> Path:
        return self.state_dir / f"{_safe_name(self.target)}.json"

    def load(self) -> PhaseState:
        if self._state is not None:
            return self._state
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._state = PhaseState.from_dict(data)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            self._state = PhaseState(target=self.target)
        return self._state

    def save(self) -> None:
        state = self.load()
        state.updated_at = _now()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(state.to_dict(), indent=2),
                                 encoding="utf-8")
        except OSError as exc:
            log.warning("Could not persist phase state for %s: %s", self.target, exc)

    def reset(self) -> None:
        self._state = PhaseState(target=self.target)
        self.save()

    # ── queries ──────────────────────────────────────────────────────────────

    @property
    def current(self) -> str:
        return self.load().phase

    def index(self, phase: Optional[str] = None) -> int:
        try:
            return PHASE_ORDER.index(phase or self.current)
        except ValueError:
            return 0

    def next_phase(self) -> Optional[str]:
        idx = self.index()
        return PHASE_ORDER[idx + 1] if idx + 1 < len(PHASE_ORDER) else None

    def phase_for_capability(self, capability: str) -> Optional[str]:
        return CAPABILITY_PHASE.get(str(capability).upper())

    def evaluate(self, phase: str, ctx: PhaseContext) -> List[GateResult]:
        return [g.evaluate(ctx, self.gate_config) for g in PHASE_GATES.get(phase, [])]

    def can_enter(self, phase: str, ctx: PhaseContext) -> Tuple[bool, List[GateResult]]:
        """Whether ``phase``'s entry gates pass. Disabled controller always allows."""
        results = self.evaluate(phase, ctx)
        if not self.enabled:
            return True, results
        return all(r.passed for r in results), results

    def allows_capability(self, capability: str, ctx: PhaseContext) -> Tuple[bool, str]:
        """Whether a recon capability is in-phase right now.

        Capabilities from earlier phases are always allowed (backfilling is
        normal); capabilities from a later phase are only allowed once that
        phase's gates pass.
        """
        if not self.enabled:
            return True, "phase control disabled"
        phase = self.phase_for_capability(capability)
        if phase is None:
            return True, "capability not phase-mapped"
        if self.index(phase) <= self.index():
            return True, f"{capability} belongs to {phase} (at or before current phase)"
        ok, results = self.can_enter(phase, ctx)
        if ok:
            return True, f"{phase} gates pass; capability available"
        blockers = "; ".join(r.detail for r in results if not r.passed)
        return False, f"{capability} needs phase {phase}, blocked by: {blockers}"

    # ── transitions ──────────────────────────────────────────────────────────

    def advance(self, ctx: PhaseContext, force: bool = False,
                note: str = "") -> Tuple[bool, str, List[GateResult]]:
        """Move to the next phase if its gates pass (or ``force``).

        Returns (moved, message, gate_results).
        """
        target_phase = self.next_phase()
        if target_phase is None:
            return False, f"already at final phase {self.current}", []
        return self.set_phase(target_phase, ctx, force=force, note=note)

    def set_phase(self, phase: str, ctx: PhaseContext, force: bool = False,
                  note: str = "") -> Tuple[bool, str, List[GateResult]]:
        """Jump to an explicit phase, subject to that phase's gates."""
        if phase not in PHASE_ORDER:
            return False, f"unknown phase {phase!r}", []

        state = self.load()
        previous = state.phase
        ok, results = self.can_enter(phase, ctx)

        if not ok and not force:
            blockers = "; ".join(r.detail for r in results if not r.passed)
            return False, f"gates block entry to {phase}: {blockers}", results

        state.phase = phase
        state.history.append({
            "at": _now(), "from": previous, "to": phase,
            "forced": bool(force and not ok),
            "note": note,
            "gates": [{"name": r.name, "passed": r.passed, "detail": r.detail}
                      for r in results],
        })
        self.save()

        if force and not ok:
            log.warning("Phase %s entered with failing gates (forced): %s",
                        phase, "; ".join(r.detail for r in results if not r.passed))
            return True, f"entered {phase} with failing gates (forced)", results
        return True, f"entered {phase}", results

    # ── presentation ─────────────────────────────────────────────────────────

    def summary(self, ctx: PhaseContext) -> str:
        lines = [f"Target: {self.target}",
                 f"Phase:  {self.current}"
                 + ("" if self.enabled else "   (phase control disabled)")]
        for phase in PHASE_ORDER:
            done, total = ctx.coverage(phase)
            marker = ">" if phase == self.current else " "
            cov = f"{done}/{total}" if total else "n/a"
            lines.append(f" {marker} {phase:<16} coverage {cov}")
        nxt = self.next_phase()
        if nxt:
            ok, results = self.can_enter(nxt, ctx)
            lines.append(f"\nNext phase: {nxt} — {'READY' if ok else 'BLOCKED'}")
            for r in results:
                lines.append(f"  {r}")
        return "\n".join(lines)


# ── Config plumbing ──────────────────────────────────────────────────────────

def phase_config(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if config is None:
        try:
            from utils import load_config
            config = load_config()
        except Exception:  # noqa: BLE001
            config = {}
    section = (config or {}).get("phases") or {}
    if not isinstance(section, dict):
        section = {}
    gates = section.get("gates") or {}
    if not isinstance(gates, dict):
        gates = {}
    return {
        "enabled": bool(section.get("enabled", True)),
        "gate_config": GateConfig(
            min_discovery_coverage=float(gates.get("min_discovery_coverage", 0.4)),
            min_enumeration_coverage=float(gates.get("min_enumeration_coverage", 0.5)),
            min_surface_coverage=float(gates.get("min_surface_coverage", 0.25)),
            require_open_port_for_exploitation=bool(
                gates.get("require_open_port_for_exploitation", True)),
        ),
    }


def get_controller(target: str, config: Optional[Dict[str, Any]] = None,
                   state_dir: Optional[Path] = None) -> PhaseController:
    cfg = phase_config(config)
    return PhaseController(target, state_dir=state_dir,
                           gate_config=cfg["gate_config"], enabled=cfg["enabled"])
