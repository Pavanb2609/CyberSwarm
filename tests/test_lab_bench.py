"""lab_bench: deterministic detection run, summary logic, control server.

The detection run uses no model and no external tools, so it runs in CI and
pins the lab's known-answer recall. Proxy env is cleared so loopback probes
are not routed through a proxy.
"""

import os
import urllib.request

import pytest

from benchmarks import lab_bench, scoring


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


def test_summary_reports_recall_and_control_false_positives():
    vuln = scoring.score_benchmark("vulnerable", lab_bench.LAB_TRUTH, [
        {"name": "Reflected XSS proven to execute", "tool": "xss_proof", "verdict": "CONFIRM"},
        {"name": "SQL Injection (sqlmap)", "tool": "sqlmap", "verdict": "CONFIRM"},
    ])
    ctrl = scoring.score_benchmark("control", [], [
        {"name": "SQL Injection (sqlmap)", "tool": "sqlmap", "verdict": "CONFIRM"}])
    s = lab_bench.summarize([vuln, ctrl])
    assert s["vulnerable"]["recall"] == 0.5
    assert set(s["vulnerable"]["missed"]) == {"ssti", "lfi"}
    assert s["control"]["false_positives"] == 1
    md = lab_bench.to_markdown(s, "detection")
    assert "Recall on lab_app: 50%" in md and "False positives on the clean control: 1" in md


def test_lfi_companions_are_not_counted_as_extra():
    vuln = scoring.score_benchmark("vulnerable", lab_bench.LAB_TRUTH, [
        {"name": "Path traversal / file disclosure", "tool": "payload_probe",
         "description": "etc/passwd content observed via path traversal"},
    ])
    s = lab_bench.summarize([vuln])
    # path_traversal / information_disclosure accompany lfi -> not "extra"
    assert s["vulnerable"]["extra"] == []


def test_control_server_is_clean_static_page():
    port = lab_bench._free_port()
    srv = lab_bench.start_control(port)
    try:
        assert lab_bench._wait_for(port, 5)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/?q=<x>", timeout=5) as r:
            body = r.read().decode()
            assert "<x>" not in body  # reflects nothing
            assert r.headers["X-Frame-Options"] == "DENY"
    finally:
        srv.shutdown()


@pytest.mark.skipif(os.environ.get("CYBERSWARM_SKIP_LIVE") == "1",
                    reason="live loopback run disabled")
def test_detection_run_scores_full_recall_on_lab():
    """End-to-end deterministic detection: the lab app's four known bugs are
    all detected, and the clean control yields zero findings."""
    try:
        import flask  # noqa: F401
    except ImportError:
        pytest.skip("flask not installed")
    vuln = lab_bench.run_detection("vulnerable")
    assert vuln.error == "", vuln.error
    assert vuln.expected & vuln.detected == set(lab_bench.LAB_TRUTH)   # 4/4
    ctrl = lab_bench.run_detection("control")
    assert ctrl.findings == 0
    assert ctrl.detected == set()
