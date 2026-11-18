"""Tests for model_client.py against a real local HTTP server (rather than
mocking `requests`), so request shaping, timeouts, and error handling are
exercised the same way they'd behave against a real Ollama/OpenAI-compatible
backend.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from model_client import ModelClient, resolve_backend_url


class _Handler(BaseHTTPRequestHandler):
    """Configurable via class attributes set per-test before the server starts."""

    response_body = b'{"message": {"content": "hello"}}'
    status_code = 200
    delay_s = 0
    captured_requests = []  # class-level, reset per test

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _Handler.captured_requests.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
            "json": json.loads(body) if body else None,
        })
        if self.delay_s:
            time.sleep(self.delay_s)
        self.send_response(self.status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.response_body)

    def do_GET(self):
        _Handler.captured_requests.append({"path": self.path, "method": "GET"})
        if self.delay_s:
            time.sleep(self.delay_s)
        self.send_response(self.status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"models": ["qwen3:8b", "qwen3:14b"]}')

    def log_message(self, fmt, *args):
        pass  # silence request logging in test output

@pytest.fixture
def http_server():
    _Handler.captured_requests = []
    _Handler.response_body = b'{"message": {"content": "hello"}}'
    _Handler.status_code = 200
    _Handler.delay_s = 0
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, _Handler
    server.shutdown()
    thread.join(timeout=2)


def _base_url(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}"


# ── ollama backend ───────────────────────────────────────────────────────────

def test_ollama_request_shape_and_response_parsing(http_server):
    server, handler = http_server
    client = ModelClient(backend="ollama", base_url=_base_url(server), model="qwen3:8b",
                         max_retries=0, timeout=5)
    reply = client.chat("system prompt", "user prompt", temperature=0.1)

    assert reply == "hello"
    assert len(handler.captured_requests) == 1
    req = handler.captured_requests[0]
    assert req["path"] == "/api/chat"
    assert req["json"]["model"] == "qwen3:8b"
    assert req["json"]["messages"] == [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "user prompt"},
    ]
    assert req["json"]["options"]["temperature"] == 0.1
    assert req["json"]["stream"] is False


def test_ollama_sends_think_false_by_default(http_server):
    server, handler = http_server
    client = ModelClient(backend="ollama", base_url=_base_url(server), max_retries=0, timeout=5)
    client.chat("s", "u")
    assert handler.captured_requests[0]["json"]["think"] is False


def test_ollama_max_tokens_maps_to_num_predict(http_server):
    server, handler = http_server
    client = ModelClient(backend="ollama", base_url=_base_url(server), max_tokens=512,
                         max_retries=0, timeout=5)
    client.chat("s", "u")
    assert handler.captured_requests[0]["json"]["options"]["num_predict"] == 512


# ── openai_compat backend ────────────────────────────────────────────────────

def test_openai_compat_request_shape(http_server):
    server, handler = http_server
    handler.response_body = json.dumps(
        {"choices": [{"message": {"content": "hi there"}}]}).encode()
    client = ModelClient(backend="openai_compat", base_url=_base_url(server),
                         model="gpt-oss-20b", max_retries=0, timeout=5)
    reply = client.chat("sys", "usr", temperature=0.2)

    assert reply == "hi there"
    req = handler.captured_requests[0]
    assert req["path"] == "/v1/chat/completions"
    assert req["json"]["model"] == "gpt-oss-20b"
    assert req["json"]["temperature"] == 0.2


def test_openai_compat_sends_bearer_token_when_api_key_set(http_server):
    server, handler = http_server
    handler.response_body = json.dumps(
        {"choices": [{"message": {"content": "hi"}}]}).encode()
    client = ModelClient(backend="openai_compat", base_url=_base_url(server),
                         api_key="secret-key-123", max_retries=0, timeout=5)
    client.chat("s", "u")
    assert handler.captured_requests[0]["headers"]["Authorization"] == "Bearer secret-key-123"


def test_openai_compat_omits_auth_header_when_no_api_key(http_server):
    server, handler = http_server
    handler.response_body = json.dumps(
        {"choices": [{"message": {"content": "hi"}}]}).encode()
    client = ModelClient(backend="openai_compat", base_url=_base_url(server),
                         max_retries=0, timeout=5)
    client.chat("s", "u")
    assert "Authorization" not in handler.captured_requests[0]["headers"]


# ── errors / retries / timeouts ──────────────────────────────────────────────

def test_unknown_backend_raises():
    client = ModelClient(backend="totally_made_up", max_retries=0, timeout=1)
    with pytest.raises(RuntimeError):
        client.chat("s", "u")


def test_http_error_status_raises_after_retries_exhausted(http_server, monkeypatch):
    server, handler = http_server
    handler.status_code = 500
    monkeypatch.setattr("time.sleep", lambda *_: None)  # don't actually wait during retries
    client = ModelClient(backend="ollama", base_url=_base_url(server), max_retries=1, timeout=5)
    with pytest.raises(RuntimeError, match="Model call failed after 2 attempts"):
        client.chat("s", "u")
    assert len(handler.captured_requests) == 2  # 1 initial + 1 retry


def test_malformed_json_response_raises_after_retries(http_server, monkeypatch):
    server, handler = http_server
    handler.response_body = b"not json at all"
    monkeypatch.setattr("time.sleep", lambda *_: None)
    client = ModelClient(backend="ollama", base_url=_base_url(server), max_retries=0, timeout=5)
    with pytest.raises(RuntimeError, match="Model call failed after 1 attempts"):
        client.chat("s", "u")


def test_missing_expected_field_in_response_raises(http_server, monkeypatch):
    server, handler = http_server
    handler.response_body = b'{"unexpected": "shape"}'  # no "message" key
    monkeypatch.setattr("time.sleep", lambda *_: None)
    client = ModelClient(backend="ollama", base_url=_base_url(server), max_retries=0, timeout=5)
    with pytest.raises(RuntimeError):
        client.chat("s", "u")


def test_request_timeout_raises(http_server):
    server, handler = http_server
    handler.delay_s = 2
    client = ModelClient(backend="ollama", base_url=_base_url(server), max_retries=0, timeout=0.2)
    with pytest.raises(RuntimeError, match="Model call failed"):
        client.chat("s", "u")


def test_default_temperature_used_when_none_passed(http_server):
    server, handler = http_server
    client = ModelClient(backend="ollama", base_url=_base_url(server), temperature=None,
                         default_temp=0.42, max_retries=0, timeout=5)
    client.chat("s", "u")  # no temperature kwarg -> should fall back to default_temp
    assert handler.captured_requests[0]["json"]["options"]["temperature"] == 0.42


# ── backend host auto-detection (resolve_backend_url) ────────────────────────

def test_resolve_keeps_a_healthy_configured_url(http_server):
    server, _ = http_server
    url = _base_url(server)
    assert resolve_backend_url(url, "ollama", probe_timeout=1) == url
    assert resolve_backend_url(url + "/", "ollama", probe_timeout=1) == url


def test_resolve_keeps_configured_when_nothing_answers(monkeypatch):
    monkeypatch.setattr("model_client._local_ipv4s", lambda: [])
    monkeypatch.setattr("model_client._gateway_ipv4s", lambda: [])

    def _refuse(url, timeout):
        raise ConnectionError("refused")

    monkeypatch.setattr("model_client.requests.get", _refuse)
    assert resolve_backend_url("http://10.9.9.9:11434", "ollama", probe_timeout=0.2) == \
        "http://10.9.9.9:11434"


def test_resolve_finds_backend_on_a_candidate_hop(monkeypatch):
    monkeypatch.setattr("model_client._local_ipv4s", lambda: ["203.0.113.7"])
    monkeypatch.setattr("model_client._gateway_ipv4s", lambda: ["10.0.2.2"])

    def _fake_get(url, timeout):
        if url == "http://10.0.2.2:11434/api/tags":
            return object()
        raise ConnectionError(f"no backend at {url}")

    monkeypatch.setattr("model_client.requests.get", _fake_get)
    assert resolve_backend_url("http://192.168.0.66:11434", "ollama", probe_timeout=0.2) == \
        "http://10.0.2.2:11434"


def test_resolve_default_port_for_openai_compat(monkeypatch):
    monkeypatch.setattr("model_client._local_ipv4s", lambda: [])
    monkeypatch.setattr("model_client._gateway_ipv4s", lambda: ["127.0.0.1"])

    def _fake_get(url, timeout):
        assert url == "http://127.0.0.1:8000/v1/models"
        return object()

    monkeypatch.setattr("model_client.requests.get", _fake_get)
    assert resolve_backend_url("", "openai_compat", probe_timeout=0.2) == \
        "http://127.0.0.1:8000"


# ── structured output (constrained JSON decoding) ───────────────────────────

_SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]}


def test_ollama_sends_format_schema(http_server):
    client = ModelClient(backend="ollama", base_url=_base_url(http_server[0]), max_retries=0)
    client.chat("sys", "user", json_schema=_SCHEMA)
    assert _Handler.captured_requests[-1]["json"]["format"] == _SCHEMA


def test_ollama_omits_format_without_schema(http_server):
    client = ModelClient(backend="ollama", base_url=_base_url(http_server[0]), max_retries=0)
    client.chat("sys", "user")
    assert "format" not in _Handler.captured_requests[-1]["json"]


def test_openai_compat_sends_response_format(http_server):
    _Handler.response_body = b'{"choices": [{"message": {"content": "{}"}}]}'
    client = ModelClient(backend="openai_compat", base_url=_base_url(http_server[0]), max_retries=0)
    client.chat("sys", "user", json_schema=_SCHEMA)
    rf = _Handler.captured_requests[-1]["json"]["response_format"]
    assert rf["type"] == "json_schema" and rf["json_schema"]["schema"] == _SCHEMA


def test_structured_output_can_be_disabled(http_server):
    client = ModelClient(backend="ollama", base_url=_base_url(http_server[0]), max_retries=0,
                         structured_output=False)
    client.chat("sys", "user", json_schema=_SCHEMA)
    assert "format" not in _Handler.captured_requests[-1]["json"]


def test_schema_rejection_falls_back_to_plain_call(http_server):
    """An older server that 400s on the schema field must still get an answer."""
    calls = {"n": 0}
    orig = _Handler.do_POST

    def flaky(self):
        calls["n"] += 1
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        _Handler.captured_requests.append({"json": body})
        status = 400 if "format" in body else 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error": "unknown field format"}' if status == 400
                         else b'{"message": {"content": "plain"}}')

    _Handler.do_POST = flaky
    try:
        client = ModelClient(backend="ollama", base_url=_base_url(http_server[0]), max_retries=0)
        assert client.chat("sys", "user", json_schema=_SCHEMA) == "plain"
        assert client._schema_unsupported is True
        # remembered: the next call goes straight to the plain form
        assert client.chat("sys", "user", json_schema=_SCHEMA) == "plain"
        assert "format" not in _Handler.captured_requests[-1]["json"]
    finally:
        _Handler.do_POST = orig
