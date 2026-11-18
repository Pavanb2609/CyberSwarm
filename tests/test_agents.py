"""Tests for planner, critic, memory, registry, base_agent helpers."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import system_map as sm
import agents.memory_agent as mem_mod
from agents.base_agent import AgentFinding, AgentResult, extract_json
from agents.planner_agent import PlannerAgent
from agents.critic_agent import CriticAgent
from agents.memory_agent import MemoryAgent
from agents.web_attack_agent import WebAttackAgent, detect_waf_cdn
from agents.specialists import AuthAgent, APIAgent
from tools.base import ToolResult

class FakeModelClient:
    """Returns a canned response for every chat call."""

    def __init__(self, response: str):
        self._resp = response

    def chat(self, system_prompt: str, user_prompt: str, temperature=None) -> str:
        return self._resp


def _web_map() -> dict:
    return sm.build_from_evidence("web.test", {
        "resolved_ip": "1.2.3.4",
        "reachable": True,
        "port_details": [{"port": 443, "service": "https", "state": "open"}],
        "open_ports": [443],
        "technologies": ["nginx"],
        "discovered_urls": ["https://web.test/"],
        "subdomains": [],
        "completed_actions": ["portscan"],
        "failed_actions": [],
        "zero_findings_actions": [],
        "discovered_parameters": [],
    })


def test_planner_rules_graph():
    p = PlannerAgent(None)
    m = _web_map()
    g = p.build_attack_graph(m, [], {}, use_llm=False)
    agents = {n["agent"] for n in g["attack_graph"] if not n.get("skip")}
    assert "web_attack" in agents
    assert "api" not in agents  # no API surface


def test_planner_skips_completed():
    p = PlannerAgent(None)
    m = _web_map()
    g = p.build_attack_graph(m, ["web_attack", "intelligence"], {}, use_llm=False)
    for n in g["attack_graph"]:
        if n["agent"] in ("web_attack", "intelligence"):
            assert n.get("skip") or n.get("completed")
    assert any(n.get("skip") for n in g["attack_graph"])


def test_planner_llm_cannot_drop_rule_active_agent():
    # The tiny 8b planner LLM sometimes trims valid rule-active agents out of
    # the graph (e.g. it dropped web_fuzz + session_hijack for flipkart.com).
    # Regression: an LLM-refined graph that omits a rule-active agent must have
    # that agent re-merged so coverage is never silently lost.
    m = _web_map()
    # Build the rule graph explicitly to know which agents are active.
    calm = PlannerAgent(None).build_attack_graph(m, [], {}, use_llm=False)
    active_rule = {n["agent"] for n in calm["attack_graph"] if not n.get("skip")}
    # Confirm web_fuzz is among the rule-active agents on a web map.
    assert "web_fuzz" in active_rule

    # LLM returns a graph that drops web_fuzz (and others) entirely.
    trimmed = json.dumps({
        "target_profile": "WEB_APPLICATION",
        "attack_graph": [
            {"agent": "web_attack", "priority": 1, "reason": "web", "skip": False},
            {"agent": "headers_attack", "priority": 2, "reason": "h", "skip": False},
        ],
        "skip_agents": [], "reasoning": "trimmed"})
    p = PlannerAgent(FakeModelClient(trimmed))
    g = p.build_attack_graph(m, [], {}, use_llm=True)
    final_active = {n["agent"] for n in g["attack_graph"] if not n.get("skip")}
    # Every rule-active agent must still be present after LLM refinement.
    assert active_rule <= final_active


def test_planner_survives_malformed_llm_graph():
    """A model that returns the attack graph as a list of bare strings (or
    other junk) must NOT crash the attack phase -- it used to raise
    'str' object has no attribute 'get' in _sanitize and abort the whole run.
    The planner falls back to / keeps the deterministic rule-active agents."""
    m = _web_map()
    active_rule = {n["agent"] for n in PlannerAgent(None).build_attack_graph(
        m, [], {}, use_llm=False)["attack_graph"] if not n.get("skip")}
    for bad in (
        json.dumps({"attack_graph": ["web_attack", "api", "intelligence"]}),  # list of strings
        json.dumps({"attack_graph": "web_attack"}),                           # not a list
        json.dumps(["web_attack", "headers_attack"]),                         # top-level list
        "total garbage, not json at all",
    ):
        p = PlannerAgent(FakeModelClient(bad))
        g = p.build_attack_graph(m, [], {}, use_llm=True)   # must not raise
        final_active = {n["agent"] for n in g["attack_graph"] if not n.get("skip")}
        assert "web_attack" in final_active
        assert active_rule <= final_active   # coverage preserved via rule fallback


def test_sanitize_coerces_string_and_altkey_nodes():
    p = PlannerAgent(None)
    out = p._sanitize({"attack_graph": ["web_attack", {"name": "api"},
                                        {"agent": "intelligence"}]}, [])
    agents = {n["agent"] for n in out["attack_graph"]}
    assert {"web_attack", "api", "intelligence"} <= agents
    assert p._sanitize({"attack_graph": "nope"}, []) == {}
    assert p._sanitize("nope", []) == {}


def test_extract_json_strips_think_and_fences():
    raw = "<think>hmm</think>```json\n{\"a\": 1}\n```"
    assert extract_json(raw) == {"a": 1}
    assert extract_json("not json") is None


def test_extract_json_returns_none_on_truncated_think_block():
    # <think> opened but response got cut off (hit num_predict) before
    # </think> ever appeared. Must fail cleanly, not slice from a bogus
    # rfind()==-1 offset and return mangled/wrong JSON.
    raw = "<think>reasoning that never finished because we ran out of tokens"
    assert extract_json(raw) is None


def test_make_finding_clamps_confidence():
    c = CriticAgent(None)
    f = c._make_finding(tool="x", name="y", severity="CRITICAL", confidence=150)
    assert f.severity == "CRITICAL"
    assert f.confidence == 100


def test_critic_offline_fallback():
    c = CriticAgent(None)
    f = AgentFinding(agent="web_attack", tool="nuclei", name="CVE-2026-1",
                     severity="HIGH", confidence=80)
    verdicts = c.review_batch([f], _web_map())
    assert f.verdict == "NEEDS_PROOF"
    assert "needs_proof" in verdicts


def test_critic_low_confidence_confirm_is_downgraded_to_needs_proof():
    # Regression: a CONFIRM verdict with a low adjusted_confidence used to
    # pass straight through and become a stored "vulnerability" in memory,
    # indistinguishable from a high-confidence CONFIRM. A CONFIRM the critic
    # itself isn't confident in should not count as confirmed.
    c = CriticAgent(FakeModelClient(json.dumps({
        "reviews": [{"index": 0, "verdict": "CONFIRM", "adjusted_confidence": 15,
                     "critique": "weak evidence", "false_positive_reasons": [],
                     "proof_needed": ""}]
    })))
    f = AgentFinding(agent="web_attack", tool="nuclei", name="Maybe-a-bug",
                     severity="MEDIUM", confidence=30,
                     evidence_chain=["nuclei matched template x"])
    buckets = c.review_batch([f], _web_map())
    assert f.verdict == "NEEDS_PROOF"
    assert f in buckets["needs_proof"]
    assert f not in buckets["confirmed"]
    assert "downgraded CONFIRM -> NEEDS_PROOF" in f.description


def test_critic_high_confidence_confirm_is_not_downgraded():
    c = CriticAgent(FakeModelClient(json.dumps({
        "reviews": [{"index": 0, "verdict": "CONFIRM", "adjusted_confidence": 95,
                     "critique": "solid evidence", "false_positive_reasons": [],
                     "proof_needed": ""}]
    })))
    f = AgentFinding(agent="web_attack", tool="nuclei", name="Definitely-a-bug",
                     severity="HIGH", confidence=90,
                     evidence_chain=["nuclei matched template x", "server echoed payload"])
    buckets = c.review_batch([f], _web_map())
    assert f.verdict == "CONFIRM"
    assert f in buckets["confirmed"]


def test_memory_store_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(mem_mod, "STORE_DIR", tmp_path)
    m = MemoryAgent("mem.test")
    mem = m.load()
    res = AgentResult(agent="web_attack", target="mem.test", status="success",
                      findings=[AgentFinding(agent="web_attack", tool="nuclei",
                                             name="x", severity="HIGH", confidence=90)])
    mem = m.store_agent_result(mem, res, {"confirmed": res.findings, "disputed": [],
                                          "needs_proof": []}, system_map=_web_map())
    m.save(mem)
    loaded = MemoryAgent("mem.test").load()
    assert loaded["vulnerabilities"]
    assert "web_attack" in loaded["completed_agents"]
    assert loaded["risk_rating"] == "HIGH"


def test_memory_dedupes_same_issue_from_two_agents(tmp_path, monkeypatch):
    monkeypatch.setattr(mem_mod, "STORE_DIR", tmp_path)
    m = MemoryAgent("mem.test")
    mem = m.load()
    # Same issue, different agents/scheme/casing -> one vulnerability only.
    f1 = AgentFinding(agent="web_attack", tool="header_analysis",
                      name="Missing Security Header: Referrer-Policy",
                      severity="MEDIUM", confidence=65,
                      url="https://mem.test")
    f2 = AgentFinding(agent="infra", tool="recon",
                      name="Missing security header: referrer-policy",
                      severity="MEDIUM", confidence=70,
                      url="http://mem.test")
    res = AgentResult(agent="web_attack", target="mem.test", status="success",
                      findings=[f1, f2])
    mem = m.store_agent_result(mem, res, {"confirmed": [f1, f2], "disputed": [],
                                          "needs_proof": []})
    assert len(mem["vulnerabilities"]) == 1

    # A genuinely different issue still gets stored.
    f3 = AgentFinding(agent="cloud", tool="s3_enum", name="Publicly listable S3 bucket: mem",
                      severity="HIGH", confidence=90, url="https://mem.s3.amazonaws.com")
    res2 = AgentResult(agent="cloud", target="mem.test", status="success", findings=[f3])
    mem = m.store_agent_result(mem, res2, {"confirmed": [f3], "disputed": [],
                                           "needs_proof": []})
    assert len(mem["vulnerabilities"]) == 2


def test_memory_merges_same_issue_reported_at_different_severities(tmp_path, monkeypatch):
    monkeypatch.setattr(mem_mod, "STORE_DIR", tmp_path)
    m = MemoryAgent("mem2.test")
    mem = m.load()
    # Same issue, same host -- but two agents disagree on severity.
    f_medium = AgentFinding(agent="web_attack", tool="nuclei",
                            name="Missing Security Header: HSTS",
                            severity="MEDIUM", confidence=60, url="https://mem2.test")
    res1 = AgentResult(agent="web_attack", target="mem2.test", status="success", findings=[f_medium])
    mem = m.store_agent_result(mem, res1, {"confirmed": [f_medium], "disputed": [], "needs_proof": []})
    assert len(mem["vulnerabilities"]) == 1
    assert mem["vulnerabilities"][0]["severity"] == "MEDIUM"

    f_high = AgentFinding(agent="infra", tool="testssl",
                          name="missing security header hsts",  # differs only by casing
                          severity="HIGH", confidence=85, url="https://mem2.test")
    res2 = AgentResult(agent="infra", target="mem2.test", status="success", findings=[f_high])
    mem = m.store_agent_result(mem, res2, {"confirmed": [f_high], "disputed": [], "needs_proof": []})

    # Must still be ONE vulnerability, upgraded to the higher severity -- not two entries.
    assert len(mem["vulnerabilities"]) == 1
    assert mem["vulnerabilities"][0]["severity"] == "HIGH"


# ── critic batching (1 LLM call per agent) ─────────────────────────────────

def _review_json(*reviews):
    return json.dumps({"reviews": list(reviews)})


def test_critic_batch_reviews_all_in_one_call():
    client = FakeModelClient(_review_json(
        {"index": 0, "verdict": "CONFIRM", "adjusted_confidence": 90,
         "critique": "direct evidence", "false_positive_reasons": [], "proof_needed": ""},
        {"index": 1, "verdict": "NEEDS_PROOF", "adjusted_confidence": 50,
         "critique": "only suggests", "false_positive_reasons": ["maybe FP"], "proof_needed": "log in"}))

    def counting_chat(system, user, temperature=None):
        counting_chat.calls += 1
        return client._resp
    counting_chat.calls = 0

    c = CriticAgent(FakeModelClient(""))
    c.model.chat = counting_chat
    f1 = AgentFinding(agent="auth", tool="auth_probe", name="a", severity="MEDIUM",
                      confidence=70, evidence_chain=["https://t.com/login -> HTTP 200, cookie Set-Cookie flag missing"])
    f2 = AgentFinding(agent="auth", tool="auth_probe", name="b", severity="INFO",
                      confidence=60, evidence_chain=["https://t.com/admin -> HTTP 403"])
    buckets = c.review_batch([f1, f2], _web_map())

    assert counting_chat.calls == 1, "batch must use exactly one LLM call"
    assert f1.verdict == "CONFIRM"
    assert f2.verdict == "NEEDS_PROOF"
    assert f1.final_confidence == int(70 * 0.4 + 90 * 0.6)
    assert [f.name for f in buckets["confirmed"]] == ["a"]
    assert [f.name for f in buckets["needs_proof"]] == ["b"]


def test_critic_batch_maps_reviews_by_index_even_when_counts_match():
    # Same count as findings (2 reviews, 2 findings) but returned OUT OF
    # ORDER by the model. Before the fix this was zipped positionally,
    # silently attaching index-1's review to finding f1 and vice versa.
    client = FakeModelClient(_review_json(
        {"index": 1, "verdict": "DISPUTE", "adjusted_confidence": 10,
         "critique": "fp", "false_positive_reasons": ["fp"], "proof_needed": ""},
        {"index": 0, "verdict": "CONFIRM", "adjusted_confidence": 95,
         "critique": "direct evidence", "false_positive_reasons": [], "proof_needed": ""}))
    c = CriticAgent(client)
    f1 = AgentFinding(agent="auth", tool="auth_probe", name="finding-0", severity="HIGH",
                      confidence=80, evidence_chain=["[dalfox] q reflected -> <script>alert(1)</script>"])
    f2 = AgentFinding(agent="auth", tool="auth_probe", name="finding-1", severity="LOW",
                      confidence=40, evidence_chain=["[dalfox] q reflected -> <script>alert(2)</script>"])
    buckets = c.review_batch([f1, f2], _web_map())

    assert f1.verdict == "CONFIRM", "index 0 (f1) must get the CONFIRM review, not whatever came first"
    assert f2.verdict == "DISPUTE", "index 1 (f2) must get the DISPUTE review"
    assert [f.name for f in buckets["confirmed"]] == ["finding-0"]
    assert [f.name for f in buckets["disputed"]] == ["finding-1"]


def test_critic_batch_partial_fallback_to_single_review():
    # only index 0 returned -> index 1 must still be handled (conservative NEEDS_PROOF)
    client = FakeModelClient(_review_json(
        {"index": 0, "verdict": "DISPUTE", "adjusted_confidence": 20,
         "critique": "fp", "false_positive_reasons": ["fp"], "proof_needed": ""}))
    c = CriticAgent(client)
    f1 = AgentFinding(agent="web_attack", tool="nuclei", name="a", severity="HIGH",
                      confidence=80, evidence_chain=["[dalfox] q reflected -> <script>alert(1)</script>"])
    f2 = AgentFinding(agent="web_attack", tool="nuclei", name="b", severity="LOW", confidence=40)
    buckets = c.review_batch([f1, f2], _web_map())
    assert f1.verdict == "DISPUTE"
    assert f2.verdict == "NEEDS_PROOF"
    assert "disputed" in buckets and "needs_proof" in buckets


# ── WAF/CDN-aware tool selection ───────────────────────────────────────────

def _cdn_map():
    m = _web_map()
    m["technologies"] = [{"name": "Cloudflare", "version": "", "source": "recon"},
                         {"name": "Shopify", "version": "", "source": "recon"}]
    m["web_surfaces"][0]["tech"] = ["Cloudflare", "Shopify"]
    return m


def test_detect_waf_cdn_detects_cloudflare():
    assert detect_waf_cdn(_cdn_map()) == "Cloudflare"
    assert detect_waf_cdn(_web_map()) is None


def test_web_attack_skips_nikto_under_cdn(capsys, monkeypatch):
    strategy = json.dumps({"attack_strategy": {
        "run_nuclei": True, "nuclei_tags": [], "run_nikto": True,
        "run_dalfox": False, "dalfox_targets": [], "run_sqlmap": False,
        "sqlmap_targets": [], "run_feroxbuster": True, "run_cors_check": True},
        "interesting_paths": [], "interesting_params": [], "reasoning": "test"})
    # waf_skip: true -> CDN-aware skipping stays enabled
    monkeypatch.setattr("agents.web_attack_agent.load_config",
                        lambda: {"attack": {"waf_skip": True}})
    a = WebAttackAgent(FakeModelClient(strategy))
    calls = []

    def fake_tool(tool_name, target, timeout=300, **kw):
        calls.append(tool_name)
        return ToolResult(tool=tool_name, status="success", capability="", results={})

    a._run_tool = fake_tool
    res = a.run("web.test", _cdn_map(), {})
    out, _ = capsys.readouterr()
    assert "nikto" not in res.tools_run and "feroxbuster" not in res.tools_run
    assert any(t.startswith("nuclei") for t in res.tools_run) and "corsy" in res.tools_run
    assert "nikto" not in calls and "feroxbuster" not in calls
    assert "[waf]" in out and "skipping" in out and "Cloudflare" in out
    assert "skipped" in res.reasoning


def test_web_attack_runs_heavy_scanners_under_cdn_when_waf_skip_disabled(capsys, monkeypatch):
    # waf_skip: false (new default) -> nikto/feroxbuster still run behind a CDN
    strategy = json.dumps({"attack_strategy": {
        "run_nuclei": True, "nuclei_tags": [], "run_nikto": True,
        "run_dalfox": False, "dalfox_targets": [], "run_sqlmap": False,
        "sqlmap_targets": [], "run_feroxbuster": True, "run_cors_check": True},
        "interesting_paths": [], "interesting_params": [], "reasoning": "test"})
    monkeypatch.setattr("agents.web_attack_agent.load_config",
                        lambda: {"attack": {"waf_skip": False}})
    a = WebAttackAgent(FakeModelClient(strategy))
    calls = []

    def fake_tool(tool_name, target, timeout=300, **kw):
        calls.append(tool_name)
        return ToolResult(tool=tool_name, status="success", capability="", results={})

    a._run_tool = fake_tool
    res = a.run("web.test", _cdn_map(), {})
    capsys.readouterr()
    assert "nikto" in res.tools_run and "feroxbuster" in res.tools_run
    assert "nikto" in calls and "feroxbuster" in calls


def test_web_attack_full_battery_without_cdn():
    strategy = json.dumps({"attack_strategy": {
        "run_nuclei": True, "nuclei_tags": [], "run_nikto": True,
        "run_dalfox": False, "dalfox_targets": [], "run_sqlmap": False,
        "sqlmap_targets": [], "run_feroxbuster": True, "run_cors_check": True},
        "interesting_paths": [], "interesting_params": [], "reasoning": "test"})
    a = WebAttackAgent(FakeModelClient(strategy))
    calls = []

    def fake_tool(tool_name, target, timeout=300, **kw):
        calls.append(tool_name)
        return ToolResult(tool=tool_name, status="success", capability="", results={})

    a._run_tool = fake_tool
    res = a.run("web.test", _web_map(), {})
    assert "nikto" in res.tools_run and "feroxbuster" in res.tools_run
    assert any(t.startswith("nuclei") for t in res.tools_run) and "corsy" in res.tools_run


# ── finding aggregation ────────────────────────────────────────────────────

def test_auth_agent_aggregates_findings():
    checks = [
        {"url": "https://web.test/login", "status": 200, "final_url": "https://web.test/login",
         "redirected": False, "login_form": True, "set_cookie": "session=abc; Path=/",
         "cookie_flags": {"secure": False, "httponly": False, "samesite": False},
         "server": "cloudflare", "auth_required": False},
        {"url": "https://web.test/admin", "status": 200, "final_url": "https://web.test/admin",
         "redirected": False, "login_form": False, "set_cookie": "",
         "cookie_flags": {"secure": True, "httponly": True, "samesite": True},
         "server": "cloudflare", "auth_required": False},
        {"url": "https://web.test/api", "status": 403, "final_url": "https://web.test/api",
         "redirected": False, "login_form": False, "set_cookie": "",
         "cookie_flags": {}, "server": "cloudflare", "auth_required": True},
        {"url": "https://web.test/account", "status": 401, "final_url": "https://web.test/account",
         "redirected": False, "login_form": False, "set_cookie": "",
         "cookie_flags": {}, "server": "cloudflare", "auth_required": True},
    ]
    m = _web_map()
    m["auth_paths"] = ["/login", "/admin", "/api", "/account"]
    a = AuthAgent(FakeModelClient(json.dumps({"weaknesses": [], "manual_steps": [], "reasoning": ""})))
    a._run_tool = lambda tool_name, target, timeout=300, **kw: ToolResult(
        tool="auth_probe", status="success", capability="AUTH_PROBE",
        results={"auth_checks": checks, "target": target})
    res = a.run("web.test", m, {})
    names = [f.name for f in res.findings]
    assert "Session cookies missing security flags (1 paths)" in names
    assert "Login page exposed (1 paths)" in names
    assert "Auth paths reachable unauthenticated (1 paths)" in names
    assert "Auth paths enforce authentication (2 paths)" in names
    assert "Server header disclosure on auth paths" in names
    assert len(res.findings) == 5, f"expected 5 aggregated findings, got {len(res.findings)}"


def test_api_agent_aggregates_findings():
    probes = [
        {"url": "https://web.test/api/orders", "method": "GET", "status": 200,
         "auth_required": False, "unauthenticated_200": True, "graphql": False, "notes": []},
        {"url": "https://web.test/api/users", "method": "GET", "status": 200,
         "auth_required": False, "unauthenticated_200": True, "graphql": False, "notes": []},
        {"url": "https://web.test/api/private", "method": "GET", "status": 403,
         "auth_required": True, "unauthenticated_200": False, "graphql": False, "notes": []},
    ]
    m = _web_map()
    m["api_paths"] = ["/api/orders", "/api/users", "/api/private"]

    def fake_tool(tool_name, target, timeout=300, **kw):
        if tool_name == "api_probe":
            return ToolResult(tool="api_probe", status="success", capability="API_PROBE",
                              results={"api_probes": probes, "target": target})
        return ToolResult(tool=tool_name, status="success", capability="", results={})

    a = APIAgent(FakeModelClient(json.dumps(
        {"run_api_probe": True, "interesting_endpoints": [], "idor_risk": False,
         "graphql_introspection_risk": False, "reasoning": ""})))
    a._run_tool = fake_tool
    res = a.run("web.test", m, {})
    names = [f.name for f in res.findings]
    assert "API endpoints return 200 unauthenticated (2)" in names
    assert "API endpoints enforce authentication (1)" in names
    assert len(res.findings) == 2, f"expected 2 aggregated findings, got {len(res.findings)}"


# ── replan trigger + report dedup ───────────────────────────────────────────

def test_new_api_auth_surface_triggers_replan():
    import run_agent_loop as ral
    res = AgentResult(agent="api", target="t", status="success")
    res.attack_paths_discovered = ["API:https://t/v2"]
    assert ral.new_api_auth_surface(res) is True
    res = AgentResult(agent="auth", target="t", status="success")
    res.attack_paths_discovered = ["AUTH:admin_panel:/admin"]
    assert ral.new_api_auth_surface(res) is True
    res = AgentResult(agent="web_attack", target="t", status="success")
    res.attack_paths_discovered = ["https://t/foo"]
    assert ral.new_api_auth_surface(res) is False


def test_report_dedupes_same_issue():
    import generate_attack_report as gar
    items = [
        {"severity": "MEDIUM", "name": "Missing Security Header: Referrer-Policy",
         "url": "https://web.test"},
        {"severity": "MEDIUM", "name": "Missing security header: referrer-policy",
         "url": "http://web.test"},
        {"severity": "HIGH", "name": "Publicly listable S3 bucket: web",
         "url": "https://web.s3.amazonaws.com"},
    ]
    out = gar._dedup(items)
    assert len(out) == 2
    assert out[0]["severity"] == "MEDIUM"


def test_insecure_design_agent_heuristics():
    from agents.attack_specialists import InsecureDesignAgent
    agent = InsecureDesignAgent(FakeModelClient("{}"))
    smap = {
        "web_surfaces": [{"url": "https://web.test/"}],
        "endpoints": ["/debug/reset", "/api/v1"],
        "params": ["id"],
        "technologies": [{"name": "nginx"}],
    }
    res = agent.run("web.test", smap, {"vulnerabilities": []})
    names = [f.name for f in res.findings]
    assert any("Debug" in n for n in names), names
    assert res.status in ("success", "partial")


# ── auth agent defensive login_brute handling ──────────────────────────────
# Regression: certifiedhacker.com run crashed with "int object is not iterable"
# because login_brute returned hits as a COUNT (results["hits"] = N) and the
# agent tried to iterate it. hits_detail / brute_results must be iterated
# defensively so no schema ever crashes the agent.

_AUTH_CHECKS = [
    {"url": "https://web.test/login", "status": 200, "final_url": "https://web.test/login",
     "redirected": False, "login_form": True, "set_cookie": "session=abc; Secure",
     "cookie_flags": {"secure": True, "httponly": True, "samesite": True},
     "server": "cloudflare", "auth_required": False},
]


def _auth_run_with_brute(brute_results=None, hits=None, hits_detail=None):
    m = _web_map()
    m["auth_paths"] = ["/login"]
    a = AuthAgent(FakeModelClient(json.dumps({"weaknesses": [], "manual_steps": [], "reasoning": ""})))

    def fake_tool(tool_name, target, timeout=300, **kw):
        if tool_name == "auth_probe":
            return ToolResult(tool="auth_probe", status="success",
                              capability="AUTH_PROBE",
                              results={"auth_checks": _AUTH_CHECKS, "target": target})
        if tool_name == "login_brute":
            results = {"brute_results": brute_results or []}
            if hits is not None:
                results["hits"] = hits
            if hits_detail is not None:
                results["hits_detail"] = hits_detail
            return ToolResult(tool="login_brute", status="success",
                              capability="LOGIN_BRUTE", results=results)
        return ToolResult(tool=tool_name, status="error", capability=tool_name.upper(), results={})

    a._run_tool = fake_tool
    return a.run("web.test", m, {})


def test_auth_agent_no_crash_when_login_brute_hits_is_int_count():
    res = _auth_run_with_brute(hits=3)  # legacy schema: count only, no detail
    assert res.status == "success", res.status
    names = [f.name for f in res.findings]
    assert not any(f.tool == "login_brute" for f in res.findings), \
        "an int hit count is not per-credential evidence; no findings emitted"


def test_auth_agent_emits_finding_from_hits_detail():
    hits_detail = [{"username": "admin", "password": "admin", "url": "https://web.test/login"}]
    res = _auth_run_with_brute(hits=1, hits_detail=hits_detail)
    brute = [f for f in res.findings if f.tool == "login_brute"]
    assert len(brute) == 1
    assert "admin / admin" in brute[0].name


def test_auth_agent_falls_back_to_brute_results_for_hits():
    brute_results = [{"username": "root", "password": "toor", "hit": True}]
    res = _auth_run_with_brute(brute_results=brute_results, hits=1)
    brute = [f for f in res.findings if f.tool == "login_brute"]
    assert len(brute) == 1
