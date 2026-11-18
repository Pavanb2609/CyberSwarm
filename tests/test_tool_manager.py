"""Tests for the ToolManager: capability resolution, reliability-aware
ordering, fallback execution, retry caps, risk classification, and
persisted tool memory."""

import json

import pytest

from tool_manager import (
    ExecutionRecord,
    RISK_ACTIVE_HIGH,
    RISK_ACTIVE_LOW,
    RISK_PASSIVE,
    ToolAttempt,
    ToolManager,
    output_quality,
    tool_risk_level,
)
from tools.base import Tool, ToolResult


class FakeTool(Tool):
    name = "fake"
    capability = "FAKE"
    binary = "fake"

    def __init__(self, name, behavior="success", results=None):
        self.name = name
        self.behavior = behavior
        self._results = results or {"hits": ["x"]}
        self.calls = 0

    def is_available(self):
        return True

    def build_command(self, target, **kwargs):
        return []

    def parse(self, stdout, stderr):
        return {}

    def run(self, target, timeout=180, **kwargs):
        self.calls += 1
        if self.behavior == "raise":
            raise RuntimeError("boom")
        return ToolResult(
            tool=self.name,
            status=self.behavior,
            capability="FAKE",
            results=self._results if self.behavior == "success" else {},
            error=None if self.behavior == "success" else f"behavior={self.behavior}",
        )


def register_recon_chain(monkeypatch, capability, tool_names):
    from tools import registry as recon_registry
    monkeypatch.setitem(recon_registry.CAPABILITY_TOOL_MAP, capability, tool_names)


def register_attack_chain(monkeypatch, action, tool_names):
    from tools import attack_registry as atk
    monkeypatch.setitem(atk.ATTACK_TOOL_MAP, action, tool_names)


def make_manager(tmp_path, loader_map, attack_map=None, **kwargs):
    def recon_loader(name):
        return loader_map[name]

    def attack_loader(name):
        return (attack_map or loader_map)[name]

    return ToolManager(
        recon_loader=recon_loader,
        attack_loader=attack_loader,
        memory_path=tmp_path / "tool_memory.json",
        **kwargs,
    )


def test_tool_risk_level_classification():
    assert tool_risk_level("subfinder") == RISK_PASSIVE
    assert tool_risk_level("dns_resolve") == RISK_PASSIVE
    assert tool_risk_level("nmap") == RISK_ACTIVE_LOW
    assert tool_risk_level("whatweb") == RISK_ACTIVE_LOW
    assert tool_risk_level("sqlmap") == RISK_ACTIVE_HIGH
    assert tool_risk_level("nuclei_xxe") == RISK_ACTIVE_HIGH
    assert tool_risk_level("commix") == RISK_ACTIVE_HIGH
    assert tool_risk_level("unknown_tool") == RISK_ACTIVE_LOW


def test_preferred_tool_returns_first_registered_name(tmp_path):
    mgr = ToolManager(memory_path=tmp_path / "tool_memory.json")
    assert mgr.preferred_tool("SUBDOMAIN_DISCOVERY") == "subfinder"
    assert mgr.preferred_tool("XSS_SCAN", use_attack=True) == "dalfox"


def test_get_tool_chain_uses_real_registry(tmp_path):
    mgr = ToolManager(memory_path=tmp_path / "tool_memory.json")
    chain = mgr.get_tool_chain("PORT_DISCOVERY")
    assert [t.name for t in chain] == ["naabu", "nmap"]
    attack_chain = mgr.get_tool_chain("SQLI_SCAN", use_attack=True)
    assert [t.name for t in attack_chain] == ["sqlmap", "nuclei_sqli"]


def test_ordering_by_reliability(tmp_path, monkeypatch):
    a = FakeTool("alpha", behavior="error")
    b = FakeTool("beta", behavior="success")
    loader_map = {"alpha": a, "beta": b}
    register_recon_chain(monkeypatch, "SUB_DISCOVERY", ["alpha", "beta"])
    mgr = make_manager(tmp_path, loader_map)
    mgr.record_result("alpha", "success", 1.0, 0.5)
    mgr.record_result("alpha", "success", 1.0, 0.5)
    mgr.record_result("alpha", "success", 1.0, 0.5)
    mgr.record_result("beta", "error", 1.0, 0.0)
    ordered = mgr.order_tool_chain([a, b])
    assert [t.name for t in ordered] == ["alpha", "beta"]


def test_ordering_ties_keep_registry_preference(tmp_path, monkeypatch):
    a = FakeTool("alpha")
    b = FakeTool("beta")
    loader_map = {"alpha": a, "beta": b}
    register_recon_chain(monkeypatch, "SUB_DISCOVERY", ["alpha", "beta"])
    mgr = make_manager(tmp_path, loader_map)
    ordered = mgr.order_tool_chain([a, b])
    assert [t.name for t in ordered] == ["alpha", "beta"]


def test_execute_returns_first_success(tmp_path, monkeypatch):
    a = FakeTool("alpha", behavior="success", results={"k": 1})
    loader_map = {"alpha": a}
    register_recon_chain(monkeypatch, "SUB_DISCOVERY", ["alpha"])
    mgr = make_manager(tmp_path, loader_map)
    result = mgr.execute_capability("SUB_DISCOVERY", "example.com")
    assert result.status == "success"
    assert result.tool == "alpha"
    assert mgr.last_execution.chosen_tool == "alpha"
    assert not mgr.last_execution.fell_back


def test_execute_falls_back_on_runtime_error(tmp_path, monkeypatch):
    a = FakeTool("alpha", behavior="error")
    b = FakeTool("beta", behavior="success", results={"k": 2})
    loader_map = {"alpha": a, "beta": b}
    register_recon_chain(monkeypatch, "SUB_DISCOVERY", ["alpha", "beta"])
    mgr = make_manager(tmp_path, loader_map)
    result = mgr.execute_capability("SUB_DISCOVERY", "example.com")
    assert result.status == "success"
    assert result.tool == "beta"
    assert mgr.last_execution.fell_back is True
    assert [t.tool for t in mgr.last_attempts] == ["alpha", "beta"]
    assert a.calls == 1 and b.calls == 1


def test_execute_falls_back_on_not_installed(tmp_path, monkeypatch):
    a = FakeTool("alpha", behavior="not_installed")
    b = FakeTool("beta", behavior="success")
    loader_map = {"alpha": a, "beta": b}
    register_recon_chain(monkeypatch, "SUB_DISCOVERY", ["alpha", "beta"])
    mgr = make_manager(tmp_path, loader_map)
    result = mgr.execute_capability("SUB_DISCOVERY", "example.com")
    assert result.status == "success"
    assert result.tool == "beta"


def test_execute_falls_back_on_timeout_and_raise(tmp_path, monkeypatch):
    a = FakeTool("alpha", behavior="timeout")
    b = FakeTool("beta", behavior="raise")
    c = FakeTool("gamma", behavior="success")
    loader_map = {"alpha": a, "beta": b, "gamma": c}
    register_recon_chain(monkeypatch, "SUB_DISCOVERY", ["alpha", "beta", "gamma"])
    mgr = make_manager(tmp_path, loader_map, max_attempts=3)
    result = mgr.execute_capability("SUB_DISCOVERY", "example.com")
    assert result.status == "success"
    assert result.tool == "gamma"
    assert [t.tool for t in mgr.last_attempts] == ["alpha", "beta", "gamma"]


def test_attack_channel_execution(tmp_path, monkeypatch):
    a = FakeTool("alpha", behavior="error")
    b = FakeTool("beta", behavior="success")
    loader_map = {"alpha": a, "beta": b}
    register_attack_chain(monkeypatch, "SQLI_SCAN", ["alpha", "beta"])
    mgr = make_manager(tmp_path, loader_map)
    result = mgr.execute_action("SQLI_SCAN", "example.com")
    assert result.status == "success"
    assert result.tool == "beta"


def test_max_attempts_caps_chain(tmp_path, monkeypatch):
    a = FakeTool("alpha", behavior="error")
    b = FakeTool("beta", behavior="error")
    c = FakeTool("gamma", behavior="error")
    loader_map = {"alpha": a, "beta": b, "gamma": c}
    register_recon_chain(monkeypatch, "SUB_DISCOVERY", ["alpha", "beta", "gamma"])
    mgr = make_manager(tmp_path, loader_map, max_attempts=2)
    result = mgr.execute_capability("SUB_DISCOVERY", "example.com")
    assert result.status == "error"
    assert [t.tool for t in mgr.last_attempts] == ["alpha", "beta"]
    assert c.calls == 0


def test_unsupported_capability_returns_unsupported(tmp_path):
    mgr = ToolManager(memory_path=tmp_path / "tool_memory.json")
    result = mgr.execute_action("NOT_A_REAL_ACTION", "example.com")
    assert result.status == "unsupported"
    assert mgr.last_execution.chosen_tool is None


def test_force_tool_gets_promoted(tmp_path, monkeypatch):
    a = FakeTool("alpha", behavior="success", results={"from": "alpha"})
    b = FakeTool("beta", behavior="success", results={"from": "beta"})
    loader_map = {"alpha": a, "beta": b}
    register_recon_chain(monkeypatch, "SUB_DISCOVERY", ["alpha", "beta"])
    mgr = make_manager(tmp_path, loader_map)
    result = mgr.execute_capability("SUB_DISCOVERY", "example.com", force_tool="beta")
    assert result.tool == "beta"


def test_force_tool_unknown_falls_back(tmp_path, monkeypatch):
    a = FakeTool("alpha", behavior="success")
    loader_map = {"alpha": a}
    register_recon_chain(monkeypatch, "SUB_DISCOVERY", ["alpha"])
    mgr = make_manager(tmp_path, loader_map)
    result = mgr.execute_capability("SUB_DISCOVERY", "example.com", force_tool="ghost")
    assert result.status == "success"
    assert result.tool == "alpha"


def test_stats_recorded_and_reliability_laplace(tmp_path):
    a = FakeTool("alpha")
    loader_map = {"alpha": a}
    mgr = make_manager(tmp_path, loader_map)
    for _ in range(4):
        mgr.record_result("alpha", "success", 2.0, 0.8)
    mgr.record_result("alpha", "error", 3.0, 0.0)
    assert mgr.success_rate("alpha") == 0.8
    assert mgr.reliability("alpha") == pytest.approx((4 + 1) / (5 + 2))
    assert mgr.mean_duration("alpha") == pytest.approx((4 * 2.0 + 3.0) / 5)
    assert mgr.reliability("never_seen") == 0.5


def test_stats_update_through_execution(tmp_path, monkeypatch):
    a = FakeTool("alpha", behavior="error")
    b = FakeTool("beta", behavior="success")
    loader_map = {"alpha": a, "beta": b}
    register_recon_chain(monkeypatch, "SUB_DISCOVERY", ["alpha", "beta"])
    mgr = make_manager(tmp_path, loader_map)
    mgr.execute_capability("SUB_DISCOVERY", "example.com")
    assert a.calls == 1 and b.calls == 1
    assert mgr.success_rate("alpha") == 0.0
    assert mgr.success_rate("beta") == 1.0


def test_output_quality_heuristic():
    assert output_quality(ToolResult(tool="x", status="error", capability="C")) == 0.0
    assert output_quality(ToolResult(tool="x", status="success", capability="C")) == 0.3
    assert output_quality(
        ToolResult(tool="x", status="success", capability="C", results={"p": [80, 443]})
    ) == pytest.approx(0.6, abs=0.01)


def test_persistence_roundtrip(tmp_path):
    a = FakeTool("alpha", behavior="success")
    loader_map = {"alpha": a}
    mgr = make_manager(tmp_path, loader_map)
    mgr.record_result("alpha", "success", 1.5, 0.7)
    mgr.record_result("alpha", "error", 2.5, 0.0)
    mgr.save()

    reloaded = make_manager(tmp_path, loader_map)
    assert reloaded.success_rate("alpha") == pytest.approx(0.5, abs=0.01)
    assert reloaded.mean_duration("alpha") == pytest.approx(2.0, abs=0.01)

    raw = json.loads((tmp_path / "tool_memory.json").read_text())
    assert "tools" in raw and "alpha" in raw["tools"]


def test_load_missing_memory_is_ok(tmp_path):
    mgr = ToolManager(memory_path=tmp_path / "does_not_exist.json")
    assert mgr.all_tool_stats() == {}


def test_reset_stats(tmp_path):
    mgr = make_manager(tmp_path, {"alpha": FakeTool("alpha")})
    mgr.record_result("alpha", "success", 1.0, 0.5)
    mgr.reset_stats("alpha")
    assert mgr.reliability("alpha") == 0.5
    mgr.record_result("alpha", "success", 1.0, 0.5)
    mgr.reset_stats()
    assert mgr.all_tool_stats() == {}


def test_risk_level_for_capability(tmp_path):
    mgr = ToolManager(memory_path=tmp_path / "tool_memory.json")
    assert mgr.risk_level_for_capability("SUBDOMAIN_DISCOVERY") == RISK_PASSIVE
    assert mgr.risk_level_for_capability("PORT_DISCOVERY") == RISK_ACTIVE_LOW
    assert mgr.risk_level_for_capability("SQLI_SCAN", use_attack=True) == RISK_ACTIVE_HIGH


def test_execution_record_to_dict():
    record = ExecutionRecord(capability="X", target="t")
    record.attempts.append(ToolAttempt(tool="a", status="success", duration_s=0.5, quality=0.6))
    d = record.to_dict()
    assert d["attempts"][0]["tool"] == "a"
    assert d["capability"] == "X"