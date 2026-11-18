"""Tests for scan_router and the ZAP fallback.

The behaviour that matters is the routing table -- especially that Burp
Community routes to ZAP rather than pretending to scan, because Community has
no scanner engine.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scan_router as sr  # noqa: E402
from tools.attack.zap_scan import ZAPScanTool, ZAPService  # noqa: E402


class FakeBurp:
    def __init__(self, edition="unknown", reachable=False):
        self._edition = edition
        self._reachable = reachable

    def edition(self):
        return self._edition

    def healthcheck(self):
        return self._reachable


@pytest.fixture
def route(monkeypatch):
    """Helper returning a decision for a given (burp, zap) world."""
    import burp_service
    import tools.attack.zap_scan as zap_mod

    def _route(burp, zap_ok, prefer="auto"):
        monkeypatch.setattr(burp_service, "get_burp_service", lambda cfg=None: burp)
        monkeypatch.setattr(zap_mod.ZAPScanTool, "is_available",
                            lambda self: zap_ok)
        return sr.choose_engine({}, prefer=prefer)

    return _route


# ── Routing table ────────────────────────────────────────────────────────────

def test_pro_reachable_uses_burp(route):
    d = route(FakeBurp("pro", reachable=True), zap_ok=True)
    assert d.engine == sr.BURP_PRO
    assert d.tool == "burp_scan"


def test_pro_installed_but_stopped_still_uses_burp(route):
    """burp_scan launches it, so Pro is chosen even when not yet reachable."""
    d = route(FakeBurp("pro", reachable=False), zap_ok=True)
    assert d.engine == sr.BURP_PRO
    assert "launch" in d.reason


def test_community_falls_through_to_zap(route):
    """The crux: Community has no scanner, so it must route to ZAP."""
    d = route(FakeBurp("community"), zap_ok=True)
    assert d.engine == sr.ZAP
    assert d.tool == "zap_scan"
    assert "Community" in d.reason and "no scanner" in d.reason
    assert d.burp_edition == "community"


def test_community_without_zap_reports_none_honestly(route):
    d = route(FakeBurp("community"), zap_ok=False)
    assert d.engine == sr.NONE
    assert d.tool is None
    assert d.can_scan is False
    assert "cannot active-scan" in d.reason


def test_no_burp_uses_zap(route):
    d = route(None, zap_ok=True)
    assert d.engine == sr.ZAP


def test_nothing_available_reports_none(route):
    d = route(None, zap_ok=False)
    assert d.engine == sr.NONE
    assert d.can_scan is False
    assert "ZAP" in d.reason


# ── Preference override ──────────────────────────────────────────────────────

def test_prefer_zap_skips_burp_even_when_present(route):
    d = route(FakeBurp("pro", reachable=True), zap_ok=True, prefer="zap")
    assert d.engine == sr.ZAP
    assert "configuration" in d.reason


def test_prefer_zap_without_zap_is_none(route):
    d = route(FakeBurp("pro", reachable=True), zap_ok=False, prefer="zap")
    assert d.engine == sr.NONE


def test_prefer_burp_without_burp_refuses_to_downgrade(route):
    """Some operators want a hard failure rather than a silent ZAP downgrade."""
    d = route(None, zap_ok=True, prefer="burp")
    assert d.engine == sr.NONE
    assert "no usable Burp" in d.reason


# ── Robustness ───────────────────────────────────────────────────────────────

def test_decision_serialises(route):
    payload = route(FakeBurp("community"), zap_ok=True).to_dict()
    assert payload["engine"] == sr.ZAP
    assert payload["can_scan"] is True


def test_scan_capability_tool_helper(route, monkeypatch):
    import burp_service
    import tools.attack.zap_scan as zap_mod
    monkeypatch.setattr(burp_service, "get_burp_service", lambda cfg=None: None)
    monkeypatch.setattr(zap_mod.ZAPScanTool, "is_available", lambda self: True)
    assert sr.scan_capability_tool({}) == "zap_scan"


# ── ZAP tool ─────────────────────────────────────────────────────────────────

def test_zap_unavailable_degrades_cleanly():
    class Dead(ZAPService):
        def healthcheck(self):
            return False

        def is_installed(self):
            return False

        def start(self):
            return False

    tool = ZAPScanTool(config={"service": Dead()})
    assert tool.is_available() is False
    assert tool.validate() is not None
    result = tool.run("https://web.test/")
    assert result.status == "not_installed"


def test_zap_alerts_map_to_findings():
    alerts = [
        {"alert": "SQL Injection", "risk": "High", "confidence": "Medium",
         "url": "https://t/x?id=1", "param": "id",
         "description": "sqli", "solution": "parameterise", "cweid": 89},
        {"alert": "SQL Injection", "risk": "High", "url": "https://t/x?id=1"},  # dup
        {"alert": "X-Frame-Options missing", "risk": "Low",
         "url": "https://t/", "description": "clickjacking"},
    ]
    findings = ZAPScanTool._to_findings(alerts)
    assert len(findings) == 2, "duplicate (name,url) should collapse"
    sqli = next(f for f in findings if "SQL" in f["name"])
    assert sqli["severity"] == "HIGH"
    assert sqli["cwe"] == 89


def test_zap_risk_mapping():
    assert ZAPScanTool._to_findings(
        [{"alert": "a", "risk": "Informational", "url": "u"}])[0]["severity"] == "INFO"
    assert ZAPScanTool._to_findings(
        [{"alert": "b", "risk": "Medium", "url": "u"}])[0]["severity"] == "MEDIUM"


def test_zap_service_builds_urls_with_api_key():
    svc = ZAPService({"api_key": "SECRET", "port": 8090})
    url = svc._url("core/view/version", {})
    assert "apikey=SECRET" in url
    assert ":8090" in url


def test_zap_service_finds_binary(monkeypatch):
    import tools.attack.zap_scan as zap_mod
    monkeypatch.setattr(zap_mod.shutil, "which",
                        lambda name: "/usr/bin/zap.sh" if name == "zap.sh" else None)
    assert ZAPService().is_installed() is True


def test_zap_tool_registered():
    from tools.attack_registry import ATTACK_TOOL_MAP, ATTACK_TOOL_MODULES
    assert "ACTIVE_SCAN" in ATTACK_TOOL_MAP
    assert "zap_scan" in ATTACK_TOOL_MODULES


# ── Agent integration ────────────────────────────────────────────────────────

def test_agent_falls_through_to_zap(monkeypatch):
    """The meesho case: no Burp, but the agent should scan with ZAP, not skip."""
    import burp_service
    import tools.attack.zap_scan as zap_mod
    from tools.base import ToolResult
    from agents.burp_agent import BurpAgent

    monkeypatch.setattr(burp_service, "get_burp_service",
                        lambda cfg=None: FakeBurp("unknown"))
    monkeypatch.setattr(zap_mod.ZAPScanTool, "is_available", lambda self: True)
    monkeypatch.setattr(zap_mod.ZAPScanTool, "run",
                        lambda self, target, url=None, **kw: ToolResult(
                            tool="zap_scan", status="success", capability="ACTIVE_SCAN",
                            results={"zap_alerts": [
                                {"name": "XSS", "severity": "HIGH",
                                 "confidence": "Medium", "url": "https://t/?q=x",
                                 "description": "d", "solution": "s"}],
                                "total_alerts": 1}))

    agent = BurpAgent(None)
    assert agent.should_run({"web_surfaces": [{"url": "https://t/"}]}) is True
    result = agent.run("t", {"web_surfaces": [{"url": "https://t/"}]}, {})
    assert result.status == "success"
    assert result.tools_run == ["zap_scan"]
    assert result.findings[0].severity == "HIGH"


def test_agent_reports_partial_when_no_engine(monkeypatch):
    import burp_service
    import tools.attack.zap_scan as zap_mod
    from agents.burp_agent import BurpAgent

    monkeypatch.setattr(burp_service, "get_burp_service",
                        lambda cfg=None: FakeBurp("community"))
    monkeypatch.setattr(zap_mod.ZAPScanTool, "is_available", lambda self: False)

    result = BurpAgent(None).run("t", {"web_surfaces": [{"url": "https://t/"}]}, {})
    assert result.status == "partial"
    assert "Community" in result.reasoning
