"""
Reusable fixtures for enforcing parser contracts and making subprocess/requests
deterministic in tests. Curl-based tools call subprocess.run with capture_output/text;
urllib uses urlopen; requests is used by many tools (timeout, headers).

This is additive and does not affect tests that don't opt in.
"""

import io
from collections.abc import Callable
from typing import Any

import pytest


class _FakeProc:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@pytest.fixture
def fake_subprocess_run():
    """Factory returning a context manager or a monkeypatch target.

    Usage:
        def test_x(monkeypatch, fake_subprocess_run):
            def run(cmd, **kw):
                return _FakeProc(stdout="200\n", stderr="")
            monkeypatch.setattr("subprocess.run", run)
            ...
    (or use as-is). Simple factory of the call shape used across tools.
    """

    def _make(run_impl: Callable[..., Any]) -> Callable[..., Any]:
        return run_impl

    return _make


class _FakeUrlResp:
    def __init__(self, body: bytes = b"", status: int = 200, url: str = "http://example.com"):
        self._body = body
        self.status = status
        self._url = url

    def read(self, n: int | None = None):  # noqa: D401
        if n is None:
            data = self._body
            self._body = b""
            return data
        data = self._body[:n]
        self._body = self._body[n:]
        return data

    def __enter__(self):  # noqa: D401
        return self

    def __exit__(self, *a):  # noqa: D401
        pass

    def geturl(self):  # noqa: D401
        return self._url


@pytest.fixture
def fake_urllib_urlopen():
    def _make(body: bytes = b"", status: int = 200, url: str = "http://example.com"):
        def _urlopen(*a, **k):
            return _FakeUrlResp(body=body, status=status, url=url)

        return _urlopen

    return _make


class _FakeRespRequests:
    def __init__(self, status_code: int = 200, text: str = "", content: bytes = b"",
                 headers: dict[str, str] | None = None, url: str = "http://example.com"):
        self.status_code = status_code
        self.text = text
        self.content = content or text.encode("utf-8", "replace")
        self.headers = headers or {}
        self.url = url

    def raise_for_status(self):  # noqa: D401
        pass


@pytest.fixture
def fake_requests():
    def _make(**kw):
        def _get(*a, **k):
            return _FakeRespRequests(**kw)

        def _post(*a, **k):
            return _FakeRespRequests(**kw)

        class _Session:
            def get(self, *a, **k):
                return _FakeRespRequests(**kw)

            def post(self, *a, **k):
                return _FakeRespRequests(**kw)

            def close(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

        return {"get": _get, "post": _post, "Session": _Session}

    return _make