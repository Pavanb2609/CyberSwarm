"""Tests for xss_proof — proving a reflected XSS actually executes.

Browser-driven tests are slow and need a Chromium download, so the payload
construction and degradation paths are tested directly and the live-browser
test is opt-in via CYBERSWARM_BROWSER_TESTS=1.
"""

import os
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.attack.xss_proof import XSSProofTool  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_browser_cache():
    XSSProofTool._browser_ok = None
    yield
    XSSProofTool._browser_ok = None


def test_candidate_urls_inject_into_every_parameter():
    urls = XSSProofTool.candidate_urls("http://t/s?q=hi&page=2", "NONCE")
    assert urls
    injected = {k for u in urls for k, v in parse_qs(urlparse(u).query).items()
                if any("NONCE" in item for item in v)}
    assert injected == {"q", "page"}


def test_candidate_urls_can_target_one_parameter():
    urls = XSSProofTool.candidate_urls("http://t/s?q=hi&page=2", "NONCE", param="q")
    for url in urls:
        params = parse_qs(urlparse(url).query)
        assert "NONCE" not in "".join(params.get("page", []))


def test_every_payload_carries_the_nonce():
    """A page echoing a previous run's marker must not register as a hit."""
    urls = XSSProofTool.candidate_urls("http://t/s?q=hi", "ABC123")
    assert all("ABC123" in u for u in urls)
    assert len(urls) >= 5, "several contexts should be attempted"


def test_url_without_parameters_is_left_alone():
    assert XSSProofTool.candidate_urls("http://t/page", "N") == ["http://t/page"]


def test_blank_parameter_values_are_still_injectable():
    urls = XSSProofTool.candidate_urls("http://t/s?q=", "N")
    assert len(urls) > 1


def test_reports_not_installed_without_playwright(monkeypatch):
    """Detection must keep working; the finding just stays unproven."""
    monkeypatch.setattr(XSSProofTool, "_playwright", staticmethod(lambda: None))
    tool = XSSProofTool()
    assert tool.is_available() is False
    assert "Playwright" in tool.validate()
    result = tool.run("http://t/s?q=1")
    assert result.status == "not_installed"


def test_no_injectable_parameter_is_success_not_error(monkeypatch):
    monkeypatch.setattr(XSSProofTool, "_playwright",
                        staticmethod(lambda: object()))
    monkeypatch.setattr(XSSProofTool, "_probe_browser", classmethod(lambda cls: True))
    monkeypatch.setattr(XSSProofTool, "candidate_urls",
                        staticmethod(lambda *a, **k: []))
    result = XSSProofTool().run("http://t/page")
    assert result.status == "success"
    assert result.results["proven"] == []


def test_non_browser_failure_is_still_an_error(monkeypatch):
    """A fault that is NOT browser-related should stay a hard error."""
    monkeypatch.setattr(XSSProofTool, "_playwright",
                        staticmethod(lambda: object()))
    monkeypatch.setattr(XSSProofTool, "_probe_browser", classmethod(lambda cls: True))
    monkeypatch.setattr(XSSProofTool, "_drive",
                        lambda self, *a: (_ for _ in ()).throw(ValueError("bad nonce logic")))
    result = XSSProofTool().run("http://t/s?q=1")
    assert result.status == "error"
    assert "bad nonce" in result.error


def test_tool_is_registered():
    from tools.attack_registry import ATTACK_TOOL_MAP, ATTACK_TOOL_MODULES
    assert "XSS_PROOF" in ATTACK_TOOL_MAP
    assert "xss_proof" in ATTACK_TOOL_MODULES


@pytest.mark.skipif(os.environ.get("CYBERSWARM_BROWSER_TESTS") != "1",
                    reason="set CYBERSWARM_BROWSER_TESTS=1 to run the live browser test")
def test_live_browser_distinguishes_execution_from_reflection(tmp_path):
    """Reflection is not execution: innerHTML echoes <script> without running it."""
    import http.server
    import threading

    page = tmp_path / "x.html"
    page.write_text(
        "<div id=o></div><script>"
        "document.getElementById('o').innerHTML="
        "new URLSearchParams(location.search).get('q')||'';</script>",
        encoding="utf-8")

    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(
        *a, directory=str(tmp_path), **k)
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        result = XSSProofTool().run(f"http://127.0.0.1:{port}/x.html?q=hi")
        assert result.results["executed"] is True
    finally:
        server.shutdown()


# ── Browser availability (the meesho crash) ──────────────────────────────────

def test_missing_browser_is_not_available(monkeypatch):
    """Module present, browser not installed: is_available must be False, not a
    crash inside the driver. This is exactly the meesho failure."""
    monkeypatch.setattr(XSSProofTool, "_playwright", staticmethod(lambda: object()))
    monkeypatch.setattr(XSSProofTool, "_probe_browser", classmethod(lambda cls: False))
    XSSProofTool._browser_ok = None
    tool = XSSProofTool()
    assert tool.is_available() is False
    assert "will not launch" in tool.validate()


def test_missing_browser_reports_not_installed(monkeypatch):
    monkeypatch.setattr(XSSProofTool, "_playwright", staticmethod(lambda: object()))
    monkeypatch.setattr(XSSProofTool, "_probe_browser", classmethod(lambda cls: False))
    XSSProofTool._browser_ok = None
    result = XSSProofTool().run("http://t/s?q=1")
    assert result.status == "not_installed"


def test_driver_crash_mid_run_degrades_to_not_installed(monkeypatch):
    """A driver that passes the probe but dies mid-run (the exact meesho
    stacktrace) must surface as not_installed, not a hard error."""
    monkeypatch.setattr(XSSProofTool, "_playwright", staticmethod(lambda: object()))
    monkeypatch.setattr(XSSProofTool, "_probe_browser", classmethod(lambda cls: True))
    XSSProofTool._browser_ok = None
    monkeypatch.setattr(XSSProofTool, "_drive",
                        lambda self, *a: (_ for _ in ()).throw(
                            Exception("Connection closed while reading from the driver")))
    result = XSSProofTool().run("http://t/s?q=1")
    assert result.status == "not_installed"


def test_browser_probe_is_cached(monkeypatch):
    """The launch probe is expensive; it must run once per process, not per URL."""
    calls = []
    monkeypatch.setattr(XSSProofTool, "_playwright", staticmethod(lambda: object()))
    monkeypatch.setattr(XSSProofTool, "_probe_browser",
                        classmethod(lambda cls: calls.append(1) or True))
    XSSProofTool._browser_ok = None
    tool = XSSProofTool()
    tool.is_available(); tool.is_available(); tool.is_available()
    assert len(calls) == 1
