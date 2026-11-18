"""
ablation.py — repeatable strategy benchmark for the assessment Controller.

Compares selection strategies over *simulated* targets that expose realistic
dependency structure (e.g. a service can't be fingerprinted before ports are
known; parameters can't be enumerated before a web surface exists). Because
the environment is a pure function of the capability executed, runs are
deterministic (seeded) and cheap — no binaries, no LLM, no network.

Strategies:
    evidence   ActionScorer / Controller ranking (info-gain + surface priors)
    registry   run capabilities in fixed registry order (baseline)
    random     seeded shuffled order

Metrics per strategy over `max_actions` steps:
    assets_found      unique assets accumulated
    evidence_items    recorded evidence items
    coverage_ratio    fraction of the capability set with >=1 evidence item
    final_surface     derived surface hints reached
    area_under_curve  mean assets-per-step (a reward for early efficient wins)
"""

from __future__ import annotations

import random
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from action_scorer import ActionScorer, information_gap
from state import (
    ASSET_ENDPOINT, ASSET_PARAMETER, ASSET_PORT, ASSET_SERVICE,
    ASSET_SUBDOMAIN, ASSET_TECHNOLOGY, ASSET_URL, ActionRecord, Asset,
    AssessmentState, evidence_from_tool_result,
)
from tools.base import ToolResult

SURFACE_KEYS = ("reachable", "web", "api", "params_found", "ssl", "cms", "cloud", "network")


def _hints_for(results: Dict[str, Any]) -> Dict[str, bool]:
    """Derive the standard surface hint booleans from a result's structured
    fields, mirroring MemoryStore.surface_hints."""
    ports = {str(p) for p in results.get("open_ports", []) or []}
    urls = results.get("discovered_urls", []) or []
    endpoints = results.get("discovered_endpoints", []) or []
    return {
        "reachable": bool(ports) or bool(urls) or bool(results.get("resolved_ip")),
        "web": bool(urls) or bool(endpoints) or bool(ports & {"80", "443"}),
        "api": False,
        "params_found": bool(results.get("discovered_parameters", [])),
        "ssl": bool(ports & {"443", "8443"}),
        "cms": bool(results.get("cms_detected")),
        "cloud": False,
        "network": bool(ports) and not bool(urls),
    }


@dataclass
class CapabilityProfile:
    """Ground-truth behavior of one simulated capability."""
    name: str
    requires: Tuple[str, ...] = ()          # surface hints that must be true
    assets: Dict[str, List[str]] = field(default_factory=dict)  # type -> values
    # assets only revealed when all `requires` hints are active
    partial_assets: Dict[str, List[str]] = field(default_factory=dict)
    noise: float = 0.0                      # chance a real tool would drop data


class SimulationEnv:
    """Deterministic (seeded) stand-in for one target's tool behavior."""

    def __init__(self, profiles: Sequence[CapabilityProfile], seed: int = 7,
                 surface: Optional[Dict[str, bool]] = None) -> None:
        self.profiles = {p.name: p for p in profiles}
        self.order = [p.name for p in profiles]
        self._surface = dict(surface or {})
        self._rng = random.Random(seed)

    def candidates(self) -> List[str]:
        return list(self.order)

    def surface(self) -> Dict[str, bool]:
        return dict(self._surface)

    def execute(self, capability: str, target: str = "sim.example.com") -> Tuple[ToolResult, Dict[str, bool]]:
        """Run the capability against the current surface, absorbing assets
        produced here into the running surface."""
        profile = self.profiles[capability]
        results: Dict[str, Any] = {}
        assets: Dict[str, List[str]] = {}

        def _gather(pool: Dict[str, List[str]]) -> None:
            for asset_type, values in pool.items():
                picked = [v for v in values if self._rng.random() >= profile.noise]
                assets.setdefault(asset_type, [])
                assets[asset_type].extend(picked)

        if all(self._surface.get(k) for k in profile.requires):
            _gather(profile.assets)
        else:
            _gather(profile.partial_assets)

        for asset_type, values in assets.items():
            if asset_type in ("subdomains",):
                results[asset_type] = values
            elif asset_type in ("open_ports",):
                results[asset_type] = values
            elif asset_type in ("technologies",):
                results[asset_type] = values
            elif asset_type in ("discovered_urls",):
                results[asset_type] = values
            elif asset_type in ("discovered_endpoints", "discovered_paths"):
                results.setdefault(asset_type, [])
                results[asset_type].extend(values)
            elif asset_type in ("discovered_parameters",):
                results[asset_type] = values

        # fold produced hints into the persistent surface
        produced = _hints_for(results) or {}
        for key in SURFACE_KEYS:
            self._surface[key] = bool(self._surface.get(key) or produced.get(key))

        result = ToolResult(tool=f"sim:{capability}", status="success",
                            capability=capability, results=results)
        return result, dict(self._surface)


class FauxToolManager:
    """Thin manager exposing the interface ActionScorer reads, backed by the
    SimulationEnv instead of real tool registries."""

    def __init__(self, env: SimulationEnv) -> None:
        self.env = env

    def risk_level_for_capability(self, capability: str, use_attack: bool = False) -> str:
        return "PASSIVE"

    def execute_capability(self, capability: str, target: str, **kwargs) -> ToolResult:
        result, _ = self.env.execute(capability, target)
        return result

    def execute_action(self, action: str, target: str, **kwargs) -> ToolResult:
        return self.execute_capability(action, target)

    def reliability(self, tool_name: str) -> float:
        return 0.8

    def tool_stats(self, tool_name: str) -> Dict[str, Any]:
        return {"attempts": 0.0, "successes": 0.0, "failures": 0.0,
                "total_duration": 0.0, "quality_sum": 0.0}

    def all_tool_stats(self) -> Dict[str, Any]:
        return {}


@dataclass
class Scorebox:
    strategy: str
    actions_run: int
    assets_found: int
    evidence_items: int
    coverage_ratio: float
    final_surface: Dict[str, bool]
    area_under_curve: float
    plan: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy": self.strategy, "actions_run": self.actions_run,
            "assets_found": self.assets_found, "evidence_items": self.evidence_items,
            "coverage_ratio": round(self.coverage_ratio, 3),
            "final_surface": self.final_surface,
            "area_under_curve": round(self.area_under_curve, 3),
            "plan": self.plan,
        }


def run_strategy(name: str, env: SimulationEnv, max_actions: int,
                 scorer: Optional[ActionScorer] = None,
                 allow_high_risk: bool = False,
                 min_action_score: float = 0.1,
                 seed: int = 0) -> Scorebox:
    """Play one strategy against a fresh clone of the environment."""
    env = SimulationEnv(list(env.profiles.values()), seed=seed)
    tm = FauxToolManager(env)
    scorer = scorer or ActionScorer(tool_manager=tm, allow_high_risk=allow_high_risk)

    st = AssessmentState(target="sim.example.com")
    candidates = env.candidates()
    attempted: List[str] = []
    coverage: Dict[str, int] = {}
    per_step_assets: List[int] = []
    plan: List[str] = []

    remaining = list(candidates)
    rng = random.Random(seed)

    for _ in range(max_actions):
        if name == "evidence":
            ranked = scorer.rank_flagged([(c, False) for c in candidates],
                                         coverage, attempted, env.surface())
            top = next((s for s in ranked if s.total >= min_action_score), None)
            if top is None:
                break
            pick = top.capability
        elif name == "registry":
            pick = next((c for c in candidates if c not in attempted), None)
            if pick is None:
                break
        else:  # random
            untried = [c for c in remaining if c not in attempted]
            if not untried:
                break
            pick = rng.choice(untried)

        result, _ = env.execute(pick, "sim.example.com")
        plan.append(pick)
        attempted.append(pick)
        ev = evidence_from_tool_result(result, "sim.example.com")
        if ev is not None:
            st.add_evidence(ev)
        st.add_action(ActionRecord(action=pick, tool=f"sim:{pick}",
                                   target="sim.example.com", status=result.status))
        from controller import absorb_tool_result
        absorb_tool_result(st, result, "sim.example.com")
        coverage = {}
        for e in st.evidence:
            coverage[e.capability] = coverage.get(e.capability, 0) + 1
        per_step_assets.append(len(st.assets))

    auc = sum(per_step_assets) / max(1, max_actions) if per_step_assets else 0.0
    explored = sum(1 for c in candidates if coverage.get(c, 0) > 0)
    return Scorebox(
        strategy=name, actions_run=len(plan), assets_found=len(st.assets),
        evidence_items=len(st.evidence),
        coverage_ratio=explored / len(candidates) if candidates else 0.0,
        final_surface=env.surface(), area_under_curve=auc, plan=plan,
    )


def benchmark_strategies(env: SimulationEnv, max_actions: int = 12,
                        strategies: Sequence[str] = ("evidence", "registry", "random"),
                        seed: int = 7) -> Dict[str, Scorebox]:
    """Run every strategy on an independent clone of the same env."""
    out: Dict[str, Scorebox] = {}
    for name in strategies:
        out[name] = run_strategy(name, env, max_actions, seed=seed)
    return out


def compare(scores: Dict[str, Scorebox]) -> str:
    rows = []
    for name, s in scores.items():
        rows.append(f"  {name:<10s} {s.actions_run} steps | {s.assets_found:>2} assets | "
                    f"auc={s.area_under_curve:>5.2f} | coverage={s.coverage_ratio:.2f}")
    return "\n".join(rows)


LAYERED_TARGET = [
    CapabilityProfile("HOST_DISCOVERY", assets={
        "discovered_urls": ["https://sim.example.com/"], "open_ports": ["80", "443"]}),
    CapabilityProfile("PORT_DISCOVERY", requires=("reachable",), assets={
        "open_ports": ["22", "443", "8080"]},
        partial_assets={"open_ports": ["443"]}),
    CapabilityProfile("SERVICE_DETECTION", requires=("reachable",), assets={
        "technologies": ["nginx", "php"]}, partial_assets={"technologies": []}),
    CapabilityProfile("TLS_ANALYSIS", requires=("ssl",), assets={
        "technologies": ["tls1.3"]}, partial_assets={"technologies": []}),
    CapabilityProfile("WEB_TECHNOLOGY_DISCOVERY", requires=("web",), assets={
        "technologies": ["wordpress"]}, partial_assets={"technologies": ["nginx"]}),
    CapabilityProfile("CONTENT_DISCOVERY", requires=("web",), assets={
        "discovered_endpoints": ["/admin", "/login", "/api"]},
        partial_assets={"discovered_endpoints": ["/login"]}),
    CapabilityProfile("PARAMETER_DISCOVERY", requires=("web",), assets={
        "discovered_parameters": ["id", "q", "next"]},
        partial_assets={"discovered_parameters": []}),
    CapabilityProfile("CMS_IDENTIFICATION", requires=("cms",), assets={
        "cms_detected": ["WordPress"]}, partial_assets={"cms_detected": []}),
]

# Registry-ordered target where a decoy capability that only fires after a
# cms hint is present sits FIRST. A fixed-order baseline wastes its opening
# move on it; evidence-driven ranking should defer it until cms is observed.
DECOY_TARGET = [
    CapabilityProfile("CMS_IDENTIFICATION_EARLY", requires=("cms",), assets={
        "cms_detected": ["WordPress"]}, partial_assets={"cms_detected": []}),
    CapabilityProfile("HOST_DISCOVERY", assets={
        "discovered_urls": ["https://sim.example.com/"], "open_ports": ["80", "443"]}),
    CapabilityProfile("PORT_DISCOVERY", requires=("reachable",), assets={
        "open_ports": ["22", "443", "8080"]}, partial_assets={"open_ports": ["443"]}),
    CapabilityProfile("SERVICE_DETECTION", requires=("reachable",), assets={
        "technologies": ["nginx", "php"]}, partial_assets={"technologies": []}),
    CapabilityProfile("TLS_ANALYSIS", requires=("ssl",), assets={
        "technologies": ["tls1.3"]}, partial_assets={"technologies": []}),
    CapabilityProfile("WEB_TECHNOLOGY_DISCOVERY", requires=("web",), assets={
        "technologies": ["wordpress"]}, partial_assets={"technologies": ["nginx"]}),
    CapabilityProfile("CONTENT_DISCOVERY", requires=("web",), assets={
        "discovered_endpoints": ["/admin", "/login", "/api"]},
        partial_assets={"discovered_endpoints": ["/login"]}),
    CapabilityProfile("PARAMETER_DISCOVERY", requires=("web",), assets={
        "discovered_parameters": ["id", "q", "next"]},
        partial_assets={"discovered_parameters": []}),
]


def run(max_actions: int = 12, seed: int = 7, iterations: int = 1) -> int:
    aggregate: Dict[str, Scorebox] = {}
    for i in range(iterations):
        env = SimulationEnv(LAYERED_TARGET, seed=seed + i)
        box = benchmark_strategies(env, max_actions=max_actions, seed=seed + i)
        for name, sb in box.items():
            if name not in aggregate:
                aggregate[name] = sb
            else:
                cur = aggregate[name]
                cur.assets_found += sb.assets_found
                cur.evidence_items += sb.evidence_items
                cur.actions_run += sb.actions_run
                cur.area_under_curve += sb.area_under_curve
                cur.coverage_ratio += sb.coverage_ratio

    print("ABLATION :: layered simulated target")
    if iterations > 1:
        show = {
            k: Scorebox(k, v.actions_run, round(v.assets_found / iterations, 2),
                        round(v.evidence_items / iterations, 2),
                        v.coverage_ratio / iterations, v.final_surface,
                        v.area_under_curve / iterations, v.plan)
            for k, v in aggregate.items()
        }
        print(compare(show))
        print(f"(averaged over {iterations} seeded runs)")
    else:
        print(compare(aggregate))
    return 0


def run_cli(argv: Optional[List[str]] = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="cyberswarm ablate",
                                description="Benchmark Controller selection strategies "
                                            "on deterministic simulated targets")
    p.add_argument("--max-actions", type=int, default=12)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--iterations", type=int, default=1,
                   help="average metrics over N independent seeds")
    args = p.parse_args(argv)
    return run(args.max_actions, args.seed, args.iterations)


if __name__ == "__main__":
    sys.exit(run_cli())