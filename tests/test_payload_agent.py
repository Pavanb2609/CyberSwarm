"""Tests for the PayloadAgent stack: situation-aware payload generation,
continuous-probe proof recordings, honest category attribution, and the
folder-wise proof persistence used by the pipeline.

No live network: the probe + agent tests monkeypatch the tool boundary.
"""

import json

import pytest

from agents.memory_agent import MemoryAgent
from agents.payload_agent import PayloadAgent
from agents.registry import load_agent
from tools.attack.payload_gen import PayloadGenTool
from tools.attack.payload_probe import PayloadProbeTool, _classify
from tools.base import ToolResult


class _MC:
    model = "qwen3:8b"

    def complete(self, *a, **k):
        return {"content": "{}"}


def _resp(status, body, text=None):
    import types

    final_text = body if text is None else text

    class Resp:
        status_code = status
        headers = {"Content-Type": "text/html"}

    Resp.text = final_text
    return Resp()


# ── payload_gen ──────────────────────────────────────────────────────────


def test_payload_gen_selects_banks_by_situation():
    r = PayloadGenTool().run("x", timeout=30, categories=["xss", "sqli", "ssti"],
                             style="seclists", max_payloads=200)
    assert r.status == "success"
    cats = {p["category"] for p in r.results["payloads"]}
    assert cats == {"xss", "sqli", "ssti"}
    assert r.results["nonce"]
    assert any("{n}" not in p["payload"] and "window.__cyberswarm_proof" in p["payload"]
               for p in r.results["payloads"])
    assert "seclists" in r.results["engines"]


def test_payload_gen_crunch_and_burp_styles():
    r = PayloadGenTool().run("x", categories=["sqli"], style="all", max_payloads=60)
    cats = {p["category"] for p in r.results["payloads"]}
    assert cats <= {"xss", "sqli", "ssti", "lfi", "cmdi", "open_redirect", "crlf", "xxe"}
    assert "burp" in r.results["engines"]
    # raw charset^N junk is skipped unless a template / charset is supplied
    raw = PayloadGenTool().run("x", categories=["sqli"], style="crunch",
                               max_payloads=10)
    assert raw.results["payloads"] == []
    tmpl = PayloadGenTool().run("x", categories=["sqli"], style="crunch",
                                template="id={var}", variables=["1", "2"],
                                max_payloads=10)
    assert [p["payload"] for p in tmpl.results["payloads"]] == ["id=1", "id=2"]
    assert all(p["category"] == "fuzz" for p in tmpl.results["payloads"])


# ── payload_probe ────────────────────────────────────────────────────────


def test_probe_classify_rejects_echoed_payload_text():
    # The payload literally echoing back "etc/passwd" must NOT be a leak.
    ok, crit = _classify("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
                         "lfi", "../../../../etc/passwd")
    assert ok and "passwd-style entries" in crit
    ok, crit = _classify("Hello, ../../../../etc/passwd!", "lfi", "../../../../etc/passwd")
    assert not ok
    ok, crit = _classify("Hello, root:x:0:0:root:", "lfi", "../../../../etc/passwd")
    assert not ok  # single colon-fragment, not a real entry


def test_probe_ssti_truth_only_for_ssti_class():
    ok, crit = _classify("Result: 49", "ssti", "{{7*7}}")
    assert ok and "truth marker" in crit
    ok, _ = _classify("page had 49 results", "xss", "<img src=x>")
    assert not ok  # a version number on a random page is not SSTI


def test_probe_proof_structure(monkeypatch):
    import requests as rq
    import tools.attack.payload_probe as pp

    def fake_request(method, url, data=None, headers=None, timeout=None,
                     allow_redirects=True, verify=True):
        # Reflect only what was actually submitted, like a real page would —
        # this is what lets the baseline control request (a different,
        # inert value) come back clean while the real payload request
        # comes back with the marker.
        if "%3Cscript%3E" in url:
            body = "<html><script>x</script> __cyberswarm_proof</html>"
        else:
            body = "<html>hello</html>"
        return _resp(200, body)

    monkeypatch.setattr(rq, "request", fake_request)

    tr = PayloadProbeTool().run("x", timeout=15,
                                url="http://t.test/greet?name=a", param="name",
                                payloads=[{"payload": "<script>x</script>",
                                           "category": "xss"}],
                                nonce="n7")
    proofs = tr.results["proofs"]
    assert len(proofs) == 1, tr.results.get("error")
    p = proofs[0]
    assert p["payload"] == "<script>x</script>"
    assert p["request"]["method"] == "GET"
    assert "name=%3Cscript%3Ex%3C%2Fscript%3E" in p["request"]["url"]
    assert p["response"]["status"] == 200, p["match_criteria"]
    assert p["matched"] is True


# ── PayloadAgent ─────────────────────────────────────────────────────────


def _fake_tool_tool_factory(proofs_by_param):
    def _run_tool(self, tool_name, target, timeout=300, **kwargs):
        if tool_name == "payload_gen":
            cats = kwargs.get("categories") or ["xss"]
            payloads = [{"id": i, "category": c, "payload": f"payload-{c}-{i}",
                         "engine": "seclists"} for i, c in enumerate(cats, 1)]
            return ToolResult(tool=tool_name, capability="PAYLOAD_GENERATION",
                              status="success",
                              results={"payloads": payloads, "count": len(payloads),
                                       "engines": ["seclists"], "rules": [],
                                       "nonce": "testnonce"})
        if tool_name == "payload_probe":
            param = kwargs.get("param", "")
            made = proofs_by_param.get(param, [])
            return ToolResult(tool=tool_name, capability="PAYLOAD_PROBE",
                              status="success",
                              results={"proofs": made, "hits": sum(1 for x in made if x["matched"]),
                                       "url": kwargs.get("url"), "param": param,
                                       "probed": len(made)})
        return None

    return _run_tool


def test_payload_agent_creates_findings_with_proofs(monkeypatch):
    monkeypatch.setattr(PayloadAgent, "_run_tool",
                        _fake_tool_tool_factory(proofs_by_param={
                            "name": [{"payload": "<script>1</script>", "category": "xss",
                                      "matched": True,
                                      "match_criteria": "proof-marker reflected in response",
                                      "request": {"method": "GET", "url": "http://t/greet?name=%3Cscript%3E1%3C%2Fscript%3E",
                                                  "headers": {}, "body": ""},
                                      "response": {"status": 200, "headers": {}, "body": "<script>1</script>"}}],
                            "q": [{"payload": "' OR 1=1-- -", "category": "sqli",
                                   "matched": True,
                                   "match_criteria": "SQL error string in response",
                                   "request": {"method": "GET", "url": "http://t/search?q=%27OR"},
                                   "response": {"status": 500, "headers": {}, "body": "SQL syntax error"}},
                                  {"payload": "{{7*7}}", "category": "ssti",
                                   "matched": True,
                                   "match_criteria": "SQL error string in response",
                                   "request": {"method": "GET", "url": "http://t/search?q=%7B%7B"},
                                   "response": {"status": 500, "headers": {}, "body": "SQL syntax error"}}],
                            "expr": [{"payload": "{{7*7}}", "category": "ssti",
                                      "matched": True,
                                      "match_criteria": "numeric truth marker ({{7*7}})",
                                      "request": {"method": "GET", "url": "http://t/calc?expr=%7B%7B7"},
                                      "response": {"status": 200, "headers": {}, "body": "Result: 49"}}],
                            "path": [{"payload": "/etc/passwd", "category": "lfi",
                                      "matched": True,
                                      "match_criteria": "etc/passwd content leaked (passwd-style entries)",
                                      "request": {"method": "GET", "url": "http://t/page?path=%2Fetc"},
                                      "response": {"status": 200, "headers": {}, "body": "root:x:0:0:root"}}],
                        }))
    smap = {"target": "t",
            "full_url": "http://t",
            "endpoints": ["http://t/greet?name=a", "http://t/search?q=a",
                          "http://t/calc?expr=1", "http://t/page?path=oops"],
            "technologies": [{"name": "Flask"}, {"name": "Jinja2"}]}
    ag = load_agent("payload", _MC())
    res = ag.run("t", smap, {})
    assert res.status == "success"
    assert len(res.findings) == 4
    by_url = {f.url: f for f in res.findings}
    assert "http://t/greet" in by_url and "http://t/calc" in by_url
    ssti = by_url["http://t/calc"]
    assert ssti.severity == "HIGH"
    assert len(ssti.proofs) == 1
    # the ssti payload that only tripped the SQL error is NOT counted as SSTI
    sqli = by_url["http://t/search"]
    assert sqli.name == "Potential SQL injection — server error fingerprint"
    assert res.proof_requests


def test_payload_agent_skips_without_surface(monkeypatch):
    monkeypatch.setattr(PayloadAgent, "_run_tool",
                        _fake_tool_tool_factory(proofs_by_param={}))
    ag = load_agent("payload", _MC())
    res = ag.run("t", {"target": "t", "full_url": "http://t", "endpoints": []}, {})
    assert res.status in ("partial", "skipped")
    assert res.findings == []


# ── proof persistence + folder-wise delivery ─────────────────────────────


def test_memory_store_persists_proofs(tmp_path, monkeypatch):
    from agents import memory_agent
    monkeypatch.setattr(memory_agent, "STORE_DIR", tmp_path / "attack_evidence")

    f = _finding_with_proofs()
    mem = MemoryAgent("host.example").load()
    result = _result_like(f)
    mem = MemoryAgent("host.example").store_agent_result(
        mem, result, {"confirmed": [f]}, system_map={"target": "host.example"})
    assert mem["vulnerabilities"][0]["proofs"]
    MemoryAgent("host.example").save(mem)
    stored = json.loads((tmp_path / "attack_evidence" / "host.example.json").read_text())
    assert stored["vulnerabilities"][0]["proofs"][0]["payload"] == "<script>x</script>"


def test_engagement_renderer_writes_proof_per_attempt(tmp_path, monkeypatch):
    import engagement_report as er
    monkeypatch.setattr(er, "OUT_ROOT", tmp_path / "engagements")

    f = _finding_with_proofs()
    vuln = MemoryAgent("x")._finding_to_vuln(f)
    er.write_vulnerabilities("host.example", [vuln])
    folder = sorted((tmp_path / "engagements" / "host.example" / "vulnerabilities").iterdir())[0]
    assert (folder / "finding.md").exists()
    assert (folder / "meta.json").exists()
    assert (folder / "proofs" / "attempt_01.md").exists()
    md = (folder / "finding.md").read_text()
    assert "Continuous proof" in md and "Attempt 1" in md


def _finding_with_proofs():
    from agents.base_agent import AgentFinding
    return AgentFinding(
        agent="payload", tool="payload_probe",
        name="Reflected XSS — payload reflected, execution unproven",
        severity="MEDIUM", confidence=55, url="http://t/greet",
        description="reflected", verdict="CONFIRM",
        evidence_chain=["[payload_probe] x -> y"],
        proofs=[{"payload": "<script>x</script>", "category": "xss",
                 "matched": True,
                 "match_criteria": "proof-marker reflected in response",
                 "request": {"method": "GET", "url": "http://t/greet?name=x",
                             "headers": {}, "body": ""},
                 "response": {"status": 200, "headers": {}, "body": "<script>x</script>"}}])


def _result_like(f):
    def to_dict(self):
        return {"agent": f.agent, "status": "success", "findings": []}
    res = type("R", (), {"findings": [f], "proof_requests": ["need more"],
                         "tools_run": ["payload_probe"], "agent": "payload",
                         "status": "success", "attack_paths_discovered": [],
                         "to_dict": to_dict})()
    return res