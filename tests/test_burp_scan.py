"""Tests for the optional Burp Suite integration (burp_scan tool, BurpAgent)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import burp_service  # noqa: E402
from burp_service import BurpService  # noqa: E402
from tools.attack.burp_scan import BurpScanTool  # noqa: E402
from agents.burp_agent import BurpAgent, _owasp_for  # noqa: E402


class _FakeService:
    api_host = "127.0.0.1"
    api_port = 1337
    api_key = ""

    def __init__(self, healthy: bool, installed: bool = True):
        self._healthy = healthy
        self._installed = installed
        self.started = False
        self.started_for = None

    def healthcheck(self):
        return self._healthy

    def start(self, target="cyberswarm"):
        self.started = True
        self.started_for = target
        return self._healthy

    def is_installed(self):
        return self._installed

    def wait_until_ready(self):
        return self._healthy

    def _rest_url(self, path=""):
        return f"http://{self.api_host}:{self.api_port}/v0.1{path}"


class _Resp:
    """Stands in for a requests.Response (has .json(), no .obj)."""

    def __init__(self, obj=None, headers=None):
        self._obj = obj
        self.headers = headers or {}
        self.status_code = 200

    def json(self):
        return self._obj


# ── Availability / degradation ───────────────────────────────────────────────

def test_burp_not_available_degrades_cleanly():
    svc = _FakeService(healthy=False)
    tool = BurpScanTool(config={"service": svc})
    assert tool.is_available() is False
    assert tool.validate() is not None
    res = tool.run("https://web.test/")
    assert res.status == "not_installed"


def test_burp_agent_skips_without_web_surface():
    agent = BurpAgent(None)
    assert agent.should_run({"web_surfaces": [], "endpoints": [], "api_paths": []}) is False


def test_burp_owasp_mapping():
    assert _owasp_for("SQL injection") == "A03"
    assert _owasp_for("Reflected XSS") == "A03"
    assert _owasp_for("TLS 1.0 detection") == "A02"
    assert _owasp_for("Broken authentication") == "A07"


# ── Transport ────────────────────────────────────────────────────────────────

def test_rest_api_uses_http_not_https():
    """Burp's REST API is plain HTTP on loopback; https makes every call fail."""
    svc = BurpService({"api_port": 1337})
    assert svc.api_base == "http://127.0.0.1:1337"


def test_rest_url_includes_api_key_segment():
    keyed = BurpService({"api_key": "SECRET"})
    assert keyed._rest_url("/scan") == "http://127.0.0.1:1337/SECRET/v0.1/scan"
    unkeyed = BurpService({})
    assert unkeyed._rest_url("/scan") == "http://127.0.0.1:1337/v0.1/scan"


def test_get_burp_service_rebuilds_on_new_config():
    """A config-less first caller must not pin everyone to the defaults."""
    burp_service.reset_burp_service()
    try:
        first = burp_service.get_burp_service()
        second = burp_service.get_burp_service({"api_port": 9999})
        assert second is not first
        assert second.api_port == 9999
        assert burp_service.get_burp_service({"api_port": 9999}) is second
    finally:
        burp_service.reset_burp_service()


def test_json_helper_handles_both_response_types():
    assert BurpScanTool._json(_Resp({"a": 1})) == {"a": 1}

    class _Simple:
        obj = {"b": 2}
    assert BurpScanTool._json(_Simple()) == {"b": 2}
    assert BurpScanTool._json(None) is None


def test_header_helper_is_case_insensitive():
    assert BurpScanTool._header(_Resp(headers={"location": "/v0.1/scan/7"}), "Location") \
        == "/v0.1/scan/7"
    assert BurpScanTool._header(_Resp(headers={"Location": "/v0.1/scan/8"}), "Location") \
        == "/v0.1/scan/8"
    assert BurpScanTool._header(_Resp(headers={}), "Location") == ""


# ── Scan payload ─────────────────────────────────────────────────────────────

def test_scan_payload_uses_burp_scope_schema():
    tool = BurpScanTool(config={"service": _FakeService(True)})
    payload = tool._scan_config("https://web.test/app", {})
    assert payload["urls"] == ["https://web.test/app"]
    assert payload["scope"] == {"include": [{"rule": "https://web.test/app"}]}
    # Keys Burp's schema does not accept would make it reject the request.
    for bogus in ("insertion_points", "exec_after", "protocol_optimization", "scan_type"):
        assert bogus not in payload


def test_scan_payload_passes_through_known_options():
    tool = BurpScanTool(config={"service": _FakeService(True)})
    cfgs = [{"type": "NamedConfiguration", "name": "Crawl and Audit - Fast"}]
    payload = tool._scan_config("https://web.test/", {"scan_configurations": cfgs})
    assert payload["scan_configurations"] == cfgs


def test_each_url_starts_its_own_scan(monkeypatch):
    """One POST per URL, each scoped to that URL only."""
    tool = BurpScanTool(config={"service": _FakeService(True)})
    sent = []

    def fake_request(method, url, payload=None, timeout=30):
        sent.append(payload)
        return _Resp({"task_id": str(len(sent))}, {"location": f"/v0.1/scan/{len(sent)}"})

    monkeypatch.setattr(tool, "_request", fake_request)
    ids = tool._start_scan("http://x/v0.1", {}, {},
                           ["https://a.test/", "https://b.test/"])
    assert ids == ["1", "2"]
    assert [p["urls"] for p in sent] == [["https://a.test/"], ["https://b.test/"]]


def test_task_id_falls_back_to_body(monkeypatch):
    tool = BurpScanTool(config={"service": _FakeService(True)})
    monkeypatch.setattr(tool, "_request",
                        lambda *a, **k: _Resp({"task_id": 42}, {}))
    assert tool._start_scan("http://x/v0.1", {}, {}, ["https://a.test/"]) == ["42"]


# ── Issue collection ─────────────────────────────────────────────────────────

_SCAN_BODY = {
    "task_id": "1",
    "scan_status": "succeeded",
    "issue_events": [
        {"type": "issue_found", "issue": {
            "name": "Cross-site scripting (reflected)", "severity": "high",
            "confidence": "certain", "origin": "https://web.test",
            "path": "/search", "issue_detail": "The value of the q parameter is echoed.",
            "remediation_detail": "Encode output.",
            "evidence": [{"type": "FirstOrderPayload"}]}},
        {"type": "issue_found", "issue": {
            "name": "TLS certificate", "severity": "info",
            "confidence": "certain", "origin": "https://web.test",
            "path": "/", "issue_background": "Certificate details."}},
    ],
}


def test_collect_issues_reads_scan_findings(monkeypatch):
    """Findings must come from issue_events, not the static issue catalogue."""
    tool = BurpScanTool(config={"service": _FakeService(True)})
    urls = []

    def fake_request(method, url, payload=None, timeout=30):
        urls.append(url)
        return _Resp(_SCAN_BODY)

    monkeypatch.setattr(tool, "_request", fake_request)
    issues = tool._collect_issues("http://x/v0.1", ["1"], 120)

    assert all("issue_definitions" not in u for u in urls), \
        "issue_definitions is Burp's static catalogue, not target findings"
    assert {i["name"] for i in issues} == {"Cross-site scripting (reflected)",
                                           "TLS certificate"}
    xss = next(i for i in issues if i["name"].startswith("Cross-site"))
    assert xss["severity"] == "HIGH"
    assert xss["url"] == "https://web.test/search"
    assert "echoed" in xss["description"]
    assert xss["remediation"] == "Encode output."


def test_same_name_on_different_paths_kept_separately(monkeypatch):
    body = {"scan_status": "succeeded", "issue_events": [
        {"issue": {"name": "XSS", "severity": "high", "origin": "https://w.test",
                   "path": "/a"}},
        {"issue": {"name": "XSS", "severity": "high", "origin": "https://w.test",
                   "path": "/b"}},
    ]}
    tool = BurpScanTool(config={"service": _FakeService(True)})
    monkeypatch.setattr(tool, "_request", lambda *a, **k: _Resp(body))
    assert len(tool._collect_issues("http://x/v0.1", ["1"], 120)) == 2


def test_polling_stops_on_terminal_status(monkeypatch):
    """A requests.Response has no .obj; reading it blindly used to make the
    poller spin until the full timeout."""
    tool = BurpScanTool(config={"service": _FakeService(True)})
    calls = []

    def fake_request(method, url, payload=None, timeout=30):
        calls.append(url)
        return _Resp(_SCAN_BODY)

    monkeypatch.setattr(tool, "_request", fake_request)
    monkeypatch.setattr("tools.attack.burp_scan.time.sleep",
                        lambda *_a: pytest.fail("should not sleep once terminal"))
    tool._collect_issues("http://x/v0.1", ["1"], 3600)
    assert len(calls) == 1


def test_partial_results_returned_on_timeout(monkeypatch):
    """A scan that never finishes should still yield what it found."""
    running = dict(_SCAN_BODY, scan_status="crawling")
    tool = BurpScanTool(config={"service": _FakeService(True)})
    monkeypatch.setattr(tool, "_request", lambda *a, **k: _Resp(running))
    monkeypatch.setattr("tools.attack.burp_scan.time.sleep", lambda *_a: None)
    issues = tool._collect_issues("http://x/v0.1", ["1"], 0)
    assert len(issues) == 2


def test_unreachable_status_endpoint_does_not_raise(monkeypatch):
    tool = BurpScanTool(config={"service": _FakeService(True)})

    def boom(*_a, **_kw):
        raise OSError("connection refused")

    monkeypatch.setattr(tool, "_request", boom)
    monkeypatch.setattr("tools.attack.burp_scan.time.sleep", lambda *_a: None)
    assert tool._collect_issues("http://x/v0.1", ["1"], 0) == []


# ── Agent wiring ─────────────────────────────────────────────────────────────

def test_agent_scan_produces_findings(monkeypatch):
    """End-to-end through BurpAgent with a reachable, issue-producing Burp."""
    from tools.base import ToolResult

    def fake_run(self, target, timeout=None, **kwargs):
        assert timeout is None or isinstance(timeout, int)
        return ToolResult(tool="burp_scan", status="success", capability="burp-scanner",
                          results={"burp_issues": [
                              {"name": "SQL injection", "severity": "HIGH",
                               "confidence": "Firm", "path": "/login",
                               "url": "https://web.test/login",
                               "description": "d", "remediation": "r"}],
                              "total_issues": 1})

    monkeypatch.setattr("tools.attack.burp_scan.BurpScanTool.run", fake_run)
    # Force the router to select Burp Pro so the Burp branch executes.
    import scan_router
    monkeypatch.setattr(scan_router, "choose_engine",
                        lambda *a, **k: scan_router.ScanDecision(
                            scan_router.BURP_PRO, "burp_scan", "test: pro", "pro"))
    result = BurpAgent(None).run("web.test",
                                 {"web_surfaces": [{"url": "https://web.test/"}]}, {})
    assert result.status == "success"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "HIGH"
    assert finding.url == "https://web.test/login"
    assert "Remediation: r" in finding.description


def test_agent_confidence_mapping():
    assert BurpAgent._conf("Certain") == 80
    assert BurpAgent._conf("Firm") == 65      # merged with ZAP's "Medium" band
    assert BurpAgent._conf("Tentative") == 55
    # ZAP uses High/Medium/Low; they map onto the same bands.
    assert BurpAgent._conf("High") == 80
    assert BurpAgent._conf("Medium") == 65
    assert BurpAgent._conf("Low") == 55


# ── Launching ────────────────────────────────────────────────────────────────

def test_agent_runs_when_burp_is_installed_but_stopped(monkeypatch):
    """The agent skipped itself unless Burp was already running. Now it routes:
    an installed-but-stopped Burp Pro is still a usable engine."""
    import scan_router
    monkeypatch.setattr(scan_router, "choose_engine",
                        lambda *a, **k: scan_router.ScanDecision(
                            scan_router.BURP_PRO, "burp_scan",
                            "installed; will launch", "pro"))
    assert BurpAgent(None).should_run(
        {"web_surfaces": [{"url": "https://web.test/"}]}) is True


def test_agent_skips_when_burp_is_absent_entirely(monkeypatch):
    """No Burp AND no ZAP: the router returns none, so the agent won't run."""
    import scan_router
    monkeypatch.setattr(scan_router, "choose_engine",
                        lambda *a, **k: scan_router.ScanDecision(
                            scan_router.NONE, None, "nothing available"))
    assert BurpAgent(None).should_run(
        {"web_surfaces": [{"url": "https://web.test/"}]}) is False


def test_should_run_does_not_launch_burp():
    """Planning calls should_run for every candidate; starting a JVM there
    would be a very expensive way to answer 'maybe'."""
    svc = _FakeService(healthy=False, installed=True)
    tool = BurpScanTool(config={"service": svc})
    agent = BurpAgent(None)
    agent._burp_tool = lambda: tool
    agent.should_run({"web_surfaces": [{"url": "https://web.test/"}]})
    assert svc.started is False


def test_ensure_running_starts_burp_for_the_target():
    svc = _FakeService(healthy=False, installed=True)
    svc._healthy = False
    tool = BurpScanTool(config={"service": svc})
    tool.ensure_running("shop.example.com")
    assert svc.started is True
    assert svc.started_for == "shop.example.com"


# ── Edition handling ─────────────────────────────────────────────────────────

def _install(tmp_path, jar_name):
    root = tmp_path / "burp"
    root.mkdir()
    (root / jar_name).write_text("", encoding="utf-8")
    return root


def test_pro_jar_detected_and_gets_a_project_file(tmp_path):
    svc = BurpService({"home": str(_install(tmp_path, "burpsuite_pro_v2025.1.jar"))})
    assert svc.edition() == "pro"
    assert svc.supports_projects() is True


def test_community_jar_detected_and_gets_no_project_file(tmp_path):
    """Community rejects --project-file; passing it looks like a crash."""
    svc = BurpService({"home": str(_install(tmp_path, "burpsuite_community_v2025.1.jar"))})
    assert svc.edition() == "community"
    assert svc.supports_projects() is False


def test_unknown_jar_is_treated_as_not_pro(tmp_path):
    svc = BurpService({"home": str(_install(tmp_path, "burpsuite.jar"))})
    assert svc.edition() == "unknown"
    assert svc.supports_projects() is False


def test_edition_can_be_overridden(tmp_path):
    root = _install(tmp_path, "burpsuite.jar")
    assert BurpService({"home": str(root), "edition": "pro"}).supports_projects() is True
    assert BurpService({"home": str(root), "edition": "community"}).edition() == "community"


def test_project_file_is_per_target_and_path_safe(tmp_path):
    svc = BurpService({"home": str(tmp_path)})
    a = svc.project_file_for("example.com")
    b = svc.project_file_for("other.example.org")
    assert a != b, "one shared project file would mix two targets' scan data"
    weird = svc.project_file_for("../../etc/passwd")
    assert weird.parent == tmp_path
    assert "/" not in weird.name


def test_is_installed_is_independent_of_running(tmp_path):
    root = _install(tmp_path, "burpsuite_pro_v2025.1.jar")
    svc = BurpService({"home": str(root)})
    assert svc.is_installed() is (svc._java() is not None)
    assert BurpService({"home": str(tmp_path / "nothing")}).is_installed() is False


def test_ensure_executable_repairs_a_lost_exec_bit(tmp_path):
    """An archive unpacked without the exec bit is a common 'Burp won't start'."""
    root = tmp_path / "burp"
    (root / "jre" / "bin").mkdir(parents=True)
    java = root / "jre" / "bin" / "java"
    java.write_text("#!/bin/sh\n", encoding="utf-8")
    java.chmod(0o644)
    svc = BurpService({"home": str(root)})
    assert svc.ensure_executable() == [str(java)]
    import os
    assert os.access(java, os.X_OK)
    assert svc.ensure_executable() == [], "already executable, nothing to do"
