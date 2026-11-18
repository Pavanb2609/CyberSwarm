"""Tests for phases.py — the engagement phase model and its quality gates."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import phases  # noqa: E402


@pytest.fixture
def state_dir(tmp_path):
    return tmp_path / "phase_state"


@pytest.fixture
def controller(state_dir):
    return phases.PhaseController("example.com", state_dir=state_dir)


def _evidence(**overrides):
    base = {
        "target": "example.com",
        "resolved_ip": "203.0.113.5",
        "reachable": True,
        "completed_actions": [],
        "failed_actions": [],
        "open_ports": [],
        "technologies": [],
        "discovered_urls": [],
    }
    base.update(overrides)
    return base


def _full_recon():
    """Evidence for a target that has been discovered, enumerated and mapped."""
    return _evidence(
        completed_actions=(phases.PHASE_CAPABILITIES[phases.DISCOVERY]
                           + phases.PHASE_CAPABILITIES[phases.ENUMERATION]
                           + phases.PHASE_CAPABILITIES[phases.SURFACE_MAPPING][:10]),
        open_ports=[80, 443],
        technologies=["nginx", "PHP"],
        discovered_urls=["https://example.com/"],
    )


# ── Context ──────────────────────────────────────────────────────────────────

def test_context_from_evidence_reads_the_loop_shape():
    ctx = phases.PhaseContext.from_evidence(_full_recon(), target="example.com")
    assert ctx.target == "example.com"
    assert ctx.resolved is True
    assert ctx.open_ports == [80, 443]
    assert ctx.web_surfaces


def test_context_tolerates_missing_and_wrong_types():
    assert phases.PhaseContext.from_evidence(None).completed_actions == []
    assert phases.PhaseContext.from_evidence({}).open_ports == []
    assert phases.PhaseContext.from_evidence("not a dict").resolved is False


def test_coverage_counts_only_phase_capabilities():
    ctx = phases.PhaseContext.from_evidence(_evidence(
        completed_actions=["PORT_DISCOVERY", "SERVICE_DETECTION", "NOT_A_REAL_CAPABILITY"]))
    done, total = ctx.coverage(phases.ENUMERATION)
    assert done == 2
    assert total == len(phases.PHASE_CAPABILITIES[phases.ENUMERATION])


def test_unknown_capability_never_blocks(controller):
    ctx = phases.PhaseContext.from_evidence(_evidence())
    allowed, why = controller.allows_capability("SOME_FUTURE_CAPABILITY", ctx)
    assert allowed is True
    assert "not phase-mapped" in why


def test_phases_with_no_capabilities_report_full_coverage():
    ctx = phases.PhaseContext.from_evidence(_evidence())
    assert ctx.coverage(phases.EXPLOITATION) == (0, 0)
    assert ctx.coverage_ratio(phases.EXPLOITATION) == 1.0


# ── Gates ────────────────────────────────────────────────────────────────────

def test_enumeration_blocked_without_discovery(controller):
    ctx = phases.PhaseContext.from_evidence(_evidence(reachable=False, resolved_ip=""))
    ok, results = controller.can_enter(phases.ENUMERATION, ctx)
    assert ok is False
    failed = {r.name for r in results if not r.passed}
    assert "target_resolved" in failed
    assert "discovery_coverage" in failed


def test_enumeration_allowed_once_discovered(controller):
    ctx = phases.PhaseContext.from_evidence(_evidence(
        completed_actions=phases.PHASE_CAPABILITIES[phases.DISCOVERY]))
    ok, _ = controller.can_enter(phases.ENUMERATION, ctx)
    assert ok is True


def test_exploitation_blocked_on_bare_target(controller):
    """The case this whole module exists to catch."""
    ctx = phases.PhaseContext.from_evidence(_evidence())
    ok, results = controller.can_enter(phases.EXPLOITATION, ctx)
    assert ok is False
    failed = {r.name for r in results if not r.passed}
    assert "attack_surface_present" in failed
    assert "enumeration_coverage" in failed


def test_exploitation_allowed_after_real_recon(controller):
    ctx = phases.PhaseContext.from_evidence(_full_recon())
    ok, results = controller.can_enter(phases.EXPLOITATION, ctx)
    assert ok is True, [str(r) for r in results if not r.passed]


def test_gate_detail_shows_the_numbers(controller):
    """A blocked run must be diagnosable without reading source."""
    ctx = phases.PhaseContext.from_evidence(_evidence())
    _, results = controller.can_enter(phases.EXPLOITATION, ctx)
    detail = next(r.detail for r in results if r.name == "enumeration_coverage")
    assert "0/" in detail and "%" in detail


def test_reporting_blocked_when_nothing_ran(controller):
    ctx = phases.PhaseContext.from_evidence(_evidence())
    ok, _ = controller.can_enter(phases.REPORTING, ctx)
    assert ok is False


def test_a_raising_gate_does_not_block(controller, monkeypatch):
    def explode(ctx, cfg):
        raise RuntimeError("bad gate")

    monkeypatch.setitem(phases.PHASE_GATES, phases.ENUMERATION,
                        [phases.Gate("boom", explode)])
    ok, results = controller.can_enter(phases.ENUMERATION,
                                       phases.PhaseContext.from_evidence(_evidence()))
    assert ok is True
    assert "not enforced" in results[0].detail


def test_thresholds_are_configurable(state_dir):
    strict = phases.PhaseController(
        "example.com", state_dir=state_dir,
        gate_config=phases.GateConfig(min_discovery_coverage=1.0))
    ctx = phases.PhaseContext.from_evidence(_evidence(
        completed_actions=phases.PHASE_CAPABILITIES[phases.DISCOVERY][:2]))
    assert strict.can_enter(phases.ENUMERATION, ctx)[0] is False


def test_disabled_controller_allows_everything(state_dir):
    off = phases.PhaseController("example.com", state_dir=state_dir, enabled=False)
    ctx = phases.PhaseContext.from_evidence(_evidence())
    assert off.can_enter(phases.EXPLOITATION, ctx)[0] is True
    assert off.allows_capability("CONTENT_DISCOVERY", ctx)[0] is True


# ── Capability gating ────────────────────────────────────────────────────────

def test_earlier_phase_capabilities_always_allowed(controller):
    """Backfilling recon you skipped is normal and must not be blocked."""
    ctx = phases.PhaseContext.from_evidence(_full_recon())
    controller.set_phase(phases.SURFACE_MAPPING, ctx)
    allowed, _ = controller.allows_capability("PORT_DISCOVERY", ctx)
    assert allowed is True


def test_later_phase_capability_blocked_until_gates_pass(controller):
    ctx = phases.PhaseContext.from_evidence(_evidence())
    allowed, why = controller.allows_capability("CONTENT_DISCOVERY", ctx)
    assert allowed is False
    assert "SURFACE_MAPPING" in why


def test_later_phase_capability_allowed_when_gates_pass(controller):
    ctx = phases.PhaseContext.from_evidence(_full_recon())
    allowed, _ = controller.allows_capability("CONTENT_DISCOVERY", ctx)
    assert allowed is True


# ── Transitions & persistence ────────────────────────────────────────────────

def test_advance_walks_the_order(controller):
    ctx = phases.PhaseContext.from_evidence(_full_recon())
    assert controller.current == phases.DISCOVERY
    assert controller.advance(ctx)[0] is True
    assert controller.current == phases.ENUMERATION
    assert controller.advance(ctx)[0] is True
    assert controller.current == phases.SURFACE_MAPPING


def test_advance_refuses_when_gates_fail(controller):
    ctx = phases.PhaseContext.from_evidence(_evidence(reachable=False, resolved_ip=""))
    moved, message, _ = controller.advance(ctx)
    assert moved is False
    assert "gates block" in message
    assert controller.current == phases.DISCOVERY


def test_force_overrides_and_is_recorded(controller):
    ctx = phases.PhaseContext.from_evidence(_evidence())
    moved, message, _ = controller.set_phase(phases.EXPLOITATION, ctx,
                                             force=True, note="lab target")
    assert moved is True
    assert "forced" in message
    entry = controller.load().history[-1]
    assert entry["forced"] is True
    assert entry["note"] == "lab target"
    assert any(not g["passed"] for g in entry["gates"])


def test_state_persists_across_controllers(state_dir):
    ctx = phases.PhaseContext.from_evidence(_full_recon())
    first = phases.PhaseController("example.com", state_dir=state_dir)
    first.advance(ctx)
    second = phases.PhaseController("example.com", state_dir=state_dir)
    assert second.current == phases.ENUMERATION


def test_per_target_isolation(state_dir):
    ctx = phases.PhaseContext.from_evidence(_full_recon())
    a = phases.PhaseController("a.example.com", state_dir=state_dir)
    a.advance(ctx)
    b = phases.PhaseController("b.example.com", state_dir=state_dir)
    assert b.current == phases.DISCOVERY


def test_corrupt_state_falls_back_to_discovery(state_dir):
    state_dir.mkdir(parents=True)
    (state_dir / "example.com.json").write_text("{ not json", encoding="utf-8")
    assert phases.PhaseController("example.com", state_dir=state_dir).current \
        == phases.DISCOVERY


def test_unknown_persisted_phase_falls_back(state_dir):
    state_dir.mkdir(parents=True)
    (state_dir / "example.com.json").write_text(
        json.dumps({"target": "example.com", "phase": "MOON"}), encoding="utf-8")
    assert phases.PhaseController("example.com", state_dir=state_dir).current \
        == phases.DISCOVERY


def test_target_name_is_path_safe(state_dir):
    controller = phases.PhaseController("../../etc/passwd", state_dir=state_dir)
    controller.reset()
    assert controller.path.parent == state_dir
    assert "/" not in controller.path.name


def test_advance_at_final_phase_is_a_noop(controller):
    ctx = phases.PhaseContext.from_evidence(_full_recon())
    controller.set_phase(phases.REPORTING, ctx, force=True)
    moved, message, _ = controller.advance(ctx)
    assert moved is False
    assert "final phase" in message


def test_set_unknown_phase_rejected(controller):
    ctx = phases.PhaseContext.from_evidence(_full_recon())
    moved, message, _ = controller.set_phase("NOPE", ctx)
    assert moved is False
    assert "unknown phase" in message


# ── Config & presentation ────────────────────────────────────────────────────

def test_config_reads_thresholds():
    cfg = phases.phase_config({"phases": {"enabled": False, "gates": {
        "min_enumeration_coverage": 0.9}}})
    assert cfg["enabled"] is False
    assert cfg["gate_config"].min_enumeration_coverage == 0.9


def test_config_defaults_and_bad_types():
    assert phases.phase_config({})["enabled"] is True
    assert phases.phase_config({"phases": "nope"})["enabled"] is True
    assert phases.phase_config({"phases": {"gates": "nope"}})[
        "gate_config"].min_discovery_coverage == 0.4


def test_summary_mentions_every_phase(controller):
    text = controller.summary(phases.PhaseContext.from_evidence(_full_recon()))
    for phase in phases.PHASE_ORDER:
        assert phase in text


def test_capability_phase_index_is_complete():
    """Every capability in the phase map is reverse-indexed exactly once."""
    total = sum(len(caps) for caps in phases.PHASE_CAPABILITIES.values())
    assert len(phases.CAPABILITY_PHASE) == total
