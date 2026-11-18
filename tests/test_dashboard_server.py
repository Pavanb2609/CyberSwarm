"""
Tests for dashboard_server.py: the stdlib-only HTTP server behind the
dashboard. Spins the real server up on an ephemeral port in a background
thread against isolated stores, then hits it with real HTTP requests --
no mocking of the HTTP layer itself, since the whole point is to catch
wiring bugs (wrong content-type, wrong status code, route not registered).
"""

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dashboard_server
import state as state_mod
from state import Asset, AssessmentState


@pytest.fixture
def live_server(isolated_stores, monkeypatch, tmp_path):
    monkeypatch.setattr(state_mod, "STORE_DIR", tmp_path / "state")

    st = AssessmentState(target="server.example")
    st.upsert_asset(Asset(type="port", value="443", source="naabu", confidence=0.7))
    state_mod.save_state(st)

    httpd = dashboard_server.make_server("127.0.0.1", 0)  # port 0 -> OS picks a free one
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        thread.join(timeout=2)


def _get(url: str):
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.status, resp.headers.get("Content-Type", ""), resp.read()


def test_index_serves_html(live_server):
    status, content_type, body = _get(live_server + "/")
    assert status == 200
    assert "text/html" in content_type
    assert b"CyberSwarm Dashboard" in body


def test_api_targets_lists_known_targets(live_server):
    status, content_type, body = _get(live_server + "/cyberswarm/targets")
    assert status == 200
    assert "application/json" in content_type
    data = json.loads(body)
    assert data["targets"] == ["server.example"]


def test_api_state_returns_full_snapshot_for_known_target(live_server):
    status, _, body = _get(live_server + "/cyberswarm/state/server.example")
    assert status == 200
    data = json.loads(body)
    assert data["target"] == "server.example"
    assert data["asset_counts"]["port"] == 1


def test_api_state_returns_valid_empty_snapshot_for_unknown_target(live_server):
    status, _, body = _get(live_server + "/cyberswarm/state/never-scanned.example")
    assert status == 200
    data = json.loads(body)
    assert data["target"] == "never-scanned.example"
    assert data["asset_counts"] == {}


def test_unknown_route_returns_404(live_server):
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _get(live_server + "/does/not/exist")
    assert exc_info.value.code == 404


def test_post_is_rejected_since_dashboard_is_read_only(live_server):
    req = urllib.request.Request(live_server + "/cyberswarm/state/server.example", method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=5)
    assert exc_info.value.code == 405


def test_put_and_delete_are_also_rejected(live_server):
    for method in ("PUT", "DELETE", "PATCH"):
        req = urllib.request.Request(live_server + "/cyberswarm/state/server.example", method=method)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 405


def test_old_api_prefix_is_not_registered(live_server):
    # Routes live under /cyberswarm/... specifically to avoid colliding
    # with a reserved /api/ prefix some remote dev environments proxy for
    # their own control plane -- assert the old path is genuinely gone,
    # not silently aliased.
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _get(live_server + "/api/targets")
    assert exc_info.value.code == 404


def test_target_with_special_characters_is_url_decoded(live_server, monkeypatch, tmp_path):
    st = AssessmentState(target="sub.server.example")
    state_mod.save_state(st)
    status, _, body = _get(live_server + "/cyberswarm/state/sub.server.example")
    assert status == 200
    assert json.loads(body)["target"] == "sub.server.example"
