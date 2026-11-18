"""PayloadAgent case-scenario tests.

Two layers:

1. Matrix scenarios (offline, mocked tool boundary) that pin down the
   agent's *decisions*: which payload classes it selects from the situation,
   how cross-category server fingerprints are attributed, what happens when
   every probe misses, when the generator or the prober is unavailable, and
   how the request budget stays bounded.

2. Real-HTTP end-to-end scenarios against tiny in-process http.server
   targets — one intentionally vulnerable (reflected names, leaking SQL
   errors, template evaluation, file read) and one hardened (markers
   rejected, errors static, no evaluation, no file reads). The vulnerable
   run must produce findings WITH per-attempt proof; the hardened run must
   produce ZERO findings (the honest negative).
"""

import html
import http.server
import os
import re
import socketserver
import threading
import urllib.parse

import pytest

from agents.registry import load_agent
from tools.attack.payload_gen import PayloadGenTool
from tools.base import ToolResult


class _MC:
    model = "qwen3:8b"

    def complete(self, *a, **k):
        return {"content": "{}"}


# ── faker for the mocked matrix scenarios ───────────────────────────────


class ToolFaker:
    """Plug into PayloadAgent._run_tool.

    override: None  -> payload_gen answers with a payload per *requested*
                       category (mimics the real generator's behaviour);
               False -> payload_gen is unavailable (agent uses its fallback);
               ToolResult -> returned verbatim.
    probe_cb(kwargs) -> list of proof dicts for a payload_probe call.
    probe: if False, payload_probe is unavailable.
    """

    def __init__(self, override=None, probe_cb=None, probe=True):
        self.override = override
        self.probe_cb = probe_cb or (lambda kw: [])
        self.probe_enabled = probe
        self.probe_calls = []
        self.gen_calls = 0

    def __call__(self, tool_name, target, timeout=300, **kw):
        if tool_name == "payload_gen":
            self.gen_calls += 1
            if self.override is False:
                return None
            if isinstance(self.override, ToolResult):
                return self.override
            cats = kw.get("categories") or ["xss"]
            payloads = [{"id": i, "category": c, "payload": f"pl-{c}-{i}",
                         "engine": "seclists"} for i, c in enumerate(cats, 1)]
            return ToolResult(tool=tool_name, capability="PAYLOAD_GENERATION",
                              status="success",
                              results={"payloads": payloads, "count": len(payloads),
                                       "engines": ["seclists"], "rules": [],
                                       "nonce": "tst"})
        if tool_name == "payload_probe":
            if not self.probe_enabled:
                return None
            proofs = self.probe_cb(kw) or []
            self.probe_calls.append(kw)
            return ToolResult(tool=tool_name, capability="PAYLOAD_PROBE",
                              status="success",
                              results={"proofs": proofs,
                                       "hits": sum(1 for p in proofs if p.get("matched")),
                                       "url": kw.get("url"), "param": kw.get("param", ""),
                                       "probed": len(proofs)})
        return None

    @staticmethod
    def proof(payload, category, criterion, status=200, url="http://t/x", method="GET"):
        return {"payload": payload, "category": category, "matched": True,
                "match_criteria": criterion,
                "request": {"method": method, "url": f"{url}?x={payload}", "headers": {}, "body": ""},
                "response": {"status": status, "headers": {}, "body": "resp"}}

    def attach(self, agent):
        agent._run_tool = self
        return self


# ── 1. category-selection matrix ────────────────────────────────────────


def _run_with(smap, faker):
    ag = load_agent("payload", _MC())
    faker.attach(ag)
    return ag.run("t", smap, {})


def _base_smap(endpoints=None, technologies=None, parameters=None):
    return {"target": "t", "full_url": "http://t",
            "endpoints": endpoints or ["http://t/greet?name=x"],
            "technologies": technologies or [],
            "parameters": parameters or [],
            "services": [], "web_surfaces": [{"url": "http://t"}]}


@pytest.mark.parametrize("technologies,parameters,expected", [
    # cmdi is tested everywhere now — it isn't tied to a param name the way
    # LFI/open-redirect are, so it rides along with xss/sqli by default.
    ([], [], {"xss", "sqli", "cmdi"}),
    ([{"name": "Jinja2"}], [], {"xss", "sqli", "cmdi", "ssti"}),
    ([{"name": "Twig"}], ["page"], {"xss", "sqli", "cmdi", "ssti", "lfi"}),
    ([], ["file", "path", "doc"], {"xss", "sqli", "cmdi", "lfi"}),
    # crlf rides along with open_redirect — both commonly manifest on the
    # same redirect/location-echoing parameters.
    ([], ["url", "redirect", "next"], {"xss", "sqli", "cmdi", "open_redirect", "crlf"}),
    ([{"name": "Flask"}, {"name": "Jinja2"}], ["name", "file", "redirect"],
     {"xss", "sqli", "cmdi", "ssti", "lfi", "open_redirect", "crlf"}),
])
def test_scenario_category_selection_follows_situation(technologies, parameters, expected):
    smap = _base_smap(technologies=technologies, parameters=parameters)
    faker = ToolFaker(override=None, probe_cb=lambda kw: [
        ToolFaker.proof("x", kw.get("param", "xss"), "SQL error string in response")])
    res = _run_with(smap, faker)
    # assert the agent actually *asked* for exactly the expected categories
    assert faker.gen_calls == 1
    generated_cats = {p["category"] for p in faker.probe_calls[0]["payloads"]}
    assert generated_cats == expected


def test_scenario_no_surface_skips():
    ag = load_agent("payload", _MC())
    # no parameters, no query endpoints anywhere
    res = ag.run("t", {"target": "t", "full_url": "http://t",
                       "endpoints": ["http://t/plain"],
                       "technologies": [], "parameters": []}, {})
    assert res.status in ("partial", "skipped")
    assert res.findings == []


def test_scenario_malformed_map_skips():
    ag = load_agent("payload", _MC())
    res = ag.run("t", None, {})
    assert res.status == "skipped"


# ── 2. attribution & honesty scenarios ───────────────────────────────────


def test_scenario_cross_category_fingerprint_not_stolen():
    def probe_cb(kw):
        param = kw.get("param", "")
        if param == "q":  # server returns an SQL error for tested input
            return [ToolFaker.proof("' OR 1=1-- -", "sqli", "SQL error string in response",
                                    status=500),
                    ToolFaker.proof("{{7*7}}", "ssti", "SQL error string in response",
                                    status=500)]
        if param == "expr":  # server really evaluates templates
            return [ToolFaker.proof("{{7*7}}", "ssti",
                                    "numeric truth marker ({{7*7}})")]
        return []
    smap = _base_smap(
        endpoints=["http://t/search?q=a", "http://t/calc?expr=1"],
        technologies=[{"name": "Jinja2"}], parameters=["q", "expr"])
    res = _run_with(smap, ToolFaker(override=None, probe_cb=probe_cb))
    names = {f.name for f in res.findings}
    assert any("Server-side template injection" in n for n in names)
    ssti = [f for f in res.findings if "template injection" in f.name][0]
    assert len(ssti.proofs) >= 1
    # ONLY the real template-evaluation fingerprint survives for /calc; the
    # SQL-error fingerprint stolen from /search must never vote for SSTI.
    assert all("truth marker" in p["match_criteria"] for p in ssti.proofs)
    sqli = [f for f in res.findings if "SQL injection" in f.name][0]
    assert all(p["match_criteria"] == "SQL error string in response"
               for p in sqli.proofs)


def test_scenario_null_negative_when_server_clean():
    faker = ToolFaker(override=None, probe_cb=lambda kw: [])
    res = _run_with(_base_smap(), faker)
    assert res.status == "partial"
    assert res.findings == []
    assert faker.probe_calls  # it really probed and found nothing


def test_scenario_request_failure_is_a_miss_not_a_finding():
    def probe_cb(kw):
        return [{"payload": "x", "category": "xss", "matched": False,
                 "match_criteria": "request failed: Connection refused",
                 "request": {"method": "GET", "url": "http://t/x", "headers": {}, "body": ""},
                 "response": {"status": 0, "headers": {}, "body": ""}}]
    res = _run_with(_base_smap(), ToolFaker(override=None, probe_cb=probe_cb))
    assert res.findings == []
    assert res.status == "partial"
    assert "0 matched" in res.reasoning


def test_scenario_budget_stays_bounded():
    n_urls = 4
    endpoints = [f"http://t/e{i}?p={i}" for i in range(n_urls)]
    smap = _base_smap(endpoints=endpoints,
                      parameters=["a", "b", "c", "d"])  # 5 params per url -> capped at 3
    faker = ToolFaker(override=None, probe_cb=lambda kw: [])
    _run_with(smap, faker)
    assert len(faker.probe_calls) == n_urls * 3
    for call in faker.probe_calls:
        assert len(call.get("payloads") or []) <= 40


def test_scenario_gen_unavailable_falls_back_to_minimal_bundle():
    def probe_cb(kw):
        return [ToolFaker.proof("<script>x</script>", "xss",
                                "proof-marker reflected in response")]
    res = _run_with(_base_smap(), ToolFaker(override=False, probe_cb=probe_cb))
    assert any("Reflected XSS" in f.name for f in res.findings)
    assert "payload_gen" not in res.tools_run  # honest: generator did not run


def test_scenario_prober_unavailable_partial():
    res = _run_with(_base_smap(), ToolFaker(override=None, probe=False))
    assert res.status == "partial"
    assert res.findings == []
    # reasoning says payloads were engineered but nothing was delivered
    assert "payloads" in res.reasoning


# ── helpers + servers for the real-HTTP end-to-end scenarios ────────────


class _Quiet(http.server.BaseHTTPRequestHandler):
    server_version = "CSLab/1.0"

    def log_message(self, *a):
        pass


def _serve(handler_cls):
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    return httpd, f"http://{host}:{port}"


class _VulnHandler(_Quiet):
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if self.path.startswith("/search"):
            sq = q.get("q", [""])[0]
            if any(c in sq for c in ("'", "--")):
                self._send("query failed: near \"\": syntax error", 500)
            else:
                self._send("<html>no rows</html>")
        elif self.path.startswith("/calc"):
            expr = q.get("expr", [""])[0]
            if "{{7*7}}" in expr or "${7*7}" in expr:
                self._send("Result: 49")
            else:
                self._send(f"Result: {expr}")
        elif self.path.startswith("/page"):
            path = q.get("path", [""])[0]
            if re.fullmatch(r"[A-Za-z0-9_]+", path or ""):
                self._send("<html>ok</html>")
            elif path.endswith("etc/passwd") and os.path.isfile(path):
                with open(path, "r", errors="replace") as fh:
                    self._send(f"<html><pre>{fh.read()}</pre></html>")
            else:
                self._send("<html>not found</html>", 404)
        else:  # /greet reflects `name` UN-escaped
            name = q.get("name", ["world"])[0]
            self._send(f"<html><body>Hello, {name}!</body></html>")

    def _send(self, body, status=200):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class _HardenedHandler(_Quiet):
    """Rejects marker-bearing input (WAF-ish), never leaks SQL errors, never
    evaluates templates, never serves files."""

    _MARKERS = ("__cyberswarm_proof", "<script", "{{", "${", "etc/passwd", "root:")

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if self.path.startswith("/search"):
            sq = q.get("q", [""])[0]
            if any(c in sq for c in ("'", "--", "SELECT")):
                self._send("Bad request — invalid query", 400)
            else:
                self._send("<html>no results</html>")
        elif self.path.startswith("/calc"):
            expr = q.get("expr", [""])[0]
            self._send(f"<html><body>Result: {html.escape(expr)}</body></html>")
        elif self.path.startswith("/page"):
            path = q.get("path", [""])[0]
            if re.fullmatch(r"[A-Za-z0-9_]+", path or ""):
                self._send("<html>ok</html>")
            else:
                self._send("<html>nf</html>", 404)
        else:
            name = q.get("name", ["world"])[0]
            if any(m in name for m in self._MARKERS):
                self._send("Forbidden", 403)
            else:
                self._send(f"<html><body>Hello, {html.escape(name)}!</body></html>")

    def _send(self, body, status=200):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _lab_smap(base):
    return {"target": "127.0.0.1",
            "full_url": base,
            "web_surfaces": [{"url": base}],
            "endpoints": [f"{base}/greet?name=w", f"{base}/search?q=a",
                          f"{base}/calc?expr=1", f"{base}/page?path=oops"],
            "technologies": [{"name": "Flask"}, {"name": "Jinja2"}],
            "parameters": ["name", "q", "expr", "path"]}


@pytest.fixture
def loopback_proxy_off(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.delenv("http_proxy", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)


def test_scenario_live_vulnerable_app_finds_and_proves(loopback_proxy_off):
    httpd, base = _serve(_VulnHandler)
    try:
        res = load_agent("payload", _MC()).run("127.0.0.1", _lab_smap(base), {})
    finally:
        httpd.shutdown()
    assert res.status == "success"
    sevs = {f.severity for f in res.findings}
    assert sevs == {"HIGH", "MEDIUM"}
    ssti = [f for f in res.findings if "template injection" in f.name][0]
    lfi = [f for f in res.findings if "file disclosure" in f.name][0]
    assert any(p["response"]["status"] == 200 and "Result: 49" in p["response"]["body"]
               for p in ssti.proofs)
    assert all(p["match_criteria"] == "numeric truth marker ({{7*7}})"
               for p in ssti.proofs)
    assert any("root:" in p["response"]["body"] for p in lfi.proofs)


def test_scenario_live_hardened_app_confirms_nothing(loopback_proxy_off):
    httpd, base = _serve(_HardenedHandler)
    try:
        res = load_agent("payload", _MC()).run("127.0.0.1", _lab_smap(base), {})
    finally:
        httpd.shutdown()
    assert res.findings == []
    assert res.status == "partial"
    assert "0 matched" in res.reasoning
    assert res.proof_requests == []