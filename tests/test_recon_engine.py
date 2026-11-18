"""Tests for recon_engine.py: the layer that turns a planner capability
into an actual tool execution, including fallback chains (first tool
missing -> second tool runs), unsupported-capability handling, and
per-capability timeout overrides.
"""

from unittest.mock import MagicMock

import pytest

import recon_engine
from tools.base import ToolResult


def _fake_tool(name, available=True, run_result=None):
    """A minimal stand-in for a Tool subclass instance."""
    tool = MagicMock()
    tool.name = name
    tool.validate.return_value = None if available else f"{name} not installed"
    tool.run.return_value = run_result or ToolResult(
        tool=name, status="success", capability="TEST_CAP", results={"ok": True})
    return tool


def test_unsupported_capability_returns_unsupported_result():
    result = recon_engine.execute_capability("NOT_A_REAL_CAPABILITY", "example.com")
    assert result.status == "unsupported"
    assert result.tool == "none"
    assert "NOT_A_REAL_CAPABILITY" in result.error


def test_falls_back_to_second_tool_when_first_is_unavailable(monkeypatch):
    # PORT_DISCOVERY -> ["naabu", "nmap"]; naabu unavailable, nmap should run.
    naabu = _fake_tool("naabu", available=False)
    nmap = _fake_tool("nmap", available=True,
                       run_result=ToolResult(tool="nmap", status="success",
                                             capability="PORT_DISCOVERY",
                                             results={"open_ports": [80]}))
    monkeypatch.setattr(recon_engine.registry, "get_tools_for_capability",
                        lambda cap: [naabu, nmap])

    result = recon_engine.execute_capability("PORT_DISCOVERY", "example.com")
    assert result.status == "success"
    assert result.tool == "nmap"
    naabu.run.assert_not_called()
    nmap.run.assert_called_once()


def test_returns_not_installed_when_every_tool_in_chain_is_unavailable(monkeypatch):
    a = _fake_tool("a", available=False)
    b = _fake_tool("b", available=False)
    monkeypatch.setattr(recon_engine.registry, "get_tools_for_capability",
                        lambda cap: [a, b])

    result = recon_engine.execute_capability("SOME_CAP", "example.com")
    assert result.status == "not_installed"
    assert "a: a not installed" in result.error
    assert "b: b not installed" in result.error


def test_tags_result_with_the_requested_capability_not_the_tool_default(monkeypatch):
    # A tool's own .capability default shouldn't leak into the result when
    # it's being invoked to satisfy a different (but related) capability.
    tool = _fake_tool("nmap", available=True,
                      run_result=ToolResult(tool="nmap", status="success",
                                            capability="SERVICE_DETECTION",
                                            results={}))
    monkeypatch.setattr(recon_engine.registry, "get_tools_for_capability",
                        lambda cap: [tool])

    result = recon_engine.execute_capability("PORT_DISCOVERY", "example.com")
    assert result.capability == "PORT_DISCOVERY"


def test_per_capability_timeout_override_is_used(monkeypatch):
    tool = _fake_tool("testssl", available=True)
    monkeypatch.setattr(recon_engine.registry, "get_tools_for_capability",
                        lambda cap: [tool])

    recon_engine.execute_capability("TLS_ANALYSIS", "example.com", timeout=180)

    # TLS_ANALYSIS has an override to 600s in CAPABILITY_TIMEOUTS -- the
    # global default (180) passed by the caller must NOT be used for it.
    _, kwargs = tool.run.call_args
    assert kwargs["timeout"] == 600


def test_capability_without_override_uses_the_passed_default_timeout(monkeypatch):
    tool = _fake_tool("naabu", available=True)
    monkeypatch.setattr(recon_engine.registry, "get_tools_for_capability",
                        lambda cap: [tool])

    recon_engine.execute_capability("PORT_DISCOVERY", "example.com", timeout=42)

    _, kwargs = tool.run.call_args
    assert kwargs["timeout"] == 42


def test_extra_kwargs_are_forwarded_to_the_tool(monkeypatch):
    tool = _fake_tool("nmap", available=True)
    monkeypatch.setattr(recon_engine.registry, "get_tools_for_capability",
                        lambda cap: [tool])

    recon_engine.execute_capability("SERVICE_DETECTION", "example.com", ports="80,443")

    _, kwargs = tool.run.call_args
    assert kwargs["ports"] == "80,443"
