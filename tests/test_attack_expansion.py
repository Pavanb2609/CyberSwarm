"""Tests for the expanded attack surface (capabilities, agents, run-all)."""

import json

import system_map as sm
from agents.base_agent import AgentResult
from agents.registry import load_agent
from tools import attack_registry


class _NullClient:
    """Minimal model client that never reaches the network (deterministic tests)."""
    model = "null"
    def __init__(self):
        self.base_url = "http://null"
        self.backend = "null"
        self.timeout = 1
        self.max_retries = 0
        self.max_tokens = 1
    def chat(self, system, user, temperature=0.2):
        raise RuntimeError("no LLM in tests")


def _agent(name):
    return load_agent(name, _NullClient())


def _web_map():
    m = sm.new_map("web.test")
    m["services"] = [{"port": 443, "proto": "tcp", "service": "http", "version": "", "ssl": True}]
    m["web_surfaces"] = [{"url": "https://web.test", "host": "web.test",
                          "ports": [443], "tech": [], "title": "", "status": 200,
                          "headers": {}}]
    m["endpoints"] = ["https://web.test/login", "https://web.test/api?x=1"]
    m["api_paths"] = ["/api"]
    m["auth_paths"] = ["/login"]
    m["parameters"] = ["x"]
    m["assets"]["subdomains"] = ["a.web.test"]
    m["technologies"] = [{"name": "Amazon CloudFront", "version": "", "source": "recon"}]
    m["signals"]["cloud"] = ["aws"]
    m["posture"]["response_headers"] = {"server": "AmazonS3"}
    return m


def test_attack_registry_has_expanded_actions():
    actions = set(attack_registry.supported_actions())
    for a in ("SSRF_SCAN", "LFI_SCAN", "SSTI_SCAN", "OPEN_REDIRECT_SCAN",
              "CMD_INJECTION_SCAN", "EXPOSED_PANELS_SCAN", "DEFAULT_CRED_SCAN",
              "MISCONFIG_SCAN", "SUBDOMAIN_TAKEOVER_SCAN", "HOST_HEADER_ATTACK",
              "CLICKJACKING_TEST", "SECRETS_SCAN", "WAF_DETECT", "JWT_ANALYSIS",
              "HTTP_METHOD_TEST"):
        assert a in actions, f"missing attack action {a}"
    assert len(actions) >= 26


def test_attack_registry_fallback_chains():
    assert attack_registry.ATTACK_TOOL_MAP["TLS_VULN_SCAN"] == ["testssl", "sslyze"]
    assert attack_registry.ATTACK_TOOL_MAP["XSS_SCAN"] == ["dalfox", "nuclei_xss"]
    assert attack_registry.ATTACK_TOOL_MAP["SUBDOMAIN_TAKEOVER_SCAN"] == ["nuclei_takeover", "subjack"]


def test_attack_registry_loads_all_new_tools():
    for action in attack_registry.supported_actions():
        for name in attack_registry.ATTACK_TOOL_MAP[action]:
            tool = attack_registry.load_attack_tool(name)  # must not raise
            assert tool.name == name


def test_nuclei_tag_wrappers_set_tags():
    t = attack_registry.load_attack_tool("nuclei_ssrf")
    assert t.capability == "SSRF_SCAN"
    assert "ssrf" in t.default_tags
    t2 = attack_registry.load_attack_tool("nuclei_lfi")
    assert t2.capability == "LFI_SCAN"


def test_derive_attack_surface_expanded_agents():
    surface = sm.derive_attack_surface(_web_map())
    agents = surface["agents"]
    # new agents present and not skipped
    assert not agents["web_fuzz"]["skip"]
    assert not agents["headers_attack"]["skip"]
    assert not agents["waf_bypass"]["skip"]
    assert not agents["subdomain_takeover"]["skip"]
    assert not agents["jwt"]["skip"]


def test_new_agents_should_run():
    m = _web_map()
    for name in ("web_fuzz", "headers_attack", "subdomain_takeover", "waf_bypass", "jwt"):
        assert _agent(name).should_run(m), f"{name}.should_run() should be True"


def test_new_agents_skip_without_surface():
    m = sm.new_map("naked.test")
    assert not _agent("subdomain_takeover").should_run(m)
    assert not _agent("jwt").should_run(m)


def test_web_fuzz_agent_runs_deterministically():
    a = _agent("web_fuzz")
    m = _web_map()
    # ffuf/arjun/feroxbuster may or may not be installed; agent must not crash
    result = a.run("web.test", m, {})
    assert isinstance(result, AgentResult)
    assert result.status in ("success", "partial", "failed", "skipped")


def test_headers_attack_agent_runs_deterministically():
    a = _agent("headers_attack")
    m = _web_map()
    result = a.run("web.test", m, {})
    assert isinstance(result, AgentResult)


def test_wafw00f_parser_schema():
    """wafw00f emits {detected, firewall, manufacturer}; parser must surface hits."""
    from tools.attack.wafw00f import Wafw00fTool
    t = Wafw00fTool()
    sample = json.dumps([{
        "detected": True, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc.",
        "url": "https://superhuman.com",
    }, {
        "detected": True, "firewall": "Cloudfront", "manufacturer": "Amazon",
        "url": "https://superhuman.com",
    }, {
        "detected": False, "firewall": "None", "manufacturer": "None",
        "url": "https://superhuman.com",
    }])
    out = t.parse(sample, "")
    assert out["count"] == 2
    names = {w["waf_name"] for w in out["wafs_detected"]}
    assert names == {"Cloudflare", "Cloudfront"}


def test_parse_target_url_path_scoped():
    from target_utils import parse_target_url, target_has_path
    assert parse_target_url("https://superhuman.com/admin") == ("superhuman.com", "https://superhuman.com/admin", None)
    assert parse_target_url("https://host:8443/x") == ("host", "https://host:8443/x", 8443)
    assert parse_target_url("scanme.nmap.org") == ("scanme.nmap.org", None, None)
    assert parse_target_url("https://host") == ("host", "https://host", None)
    assert target_has_path("https://host/admin")
    assert not target_has_path("https://host")
    assert not target_has_path("host")


def test_run_attack_injects_full_url(tmp_path, monkeypatch):
    import run_agent_loop
    import system_map as sm
    monkeypatch.setattr(sm, "STORE_DIR", tmp_path)

    m = sm.new_map("host")
    m["web_surfaces"] = [{"url": "https://host"}]

    # no path -> only full_url recorded, surfaces untouched
    out = run_agent_loop.inject_full_url(dict(m), "host", "https://host")
    assert out["full_url"] == "https://host"
    assert "https://host" not in out["endpoints"]

    # path -> endpoint added + surface prepended
    out = run_agent_loop.inject_full_url(dict(m), "host", "https://host/admin")
    assert out["full_url"] == "https://host/admin"
    assert "https://host/admin" in out["endpoints"]
    assert out["web_surfaces"][0]["url"] == "https://host/admin"

    # idempotent
    out2 = run_agent_loop.inject_full_url(out, "host", "https://host/admin")
    assert out2["endpoints"].count("https://host/admin") == 1
    assert out2["web_surfaces"][0]["url"] == "https://host/admin"

    # None -> unchanged
    out3 = run_agent_loop.inject_full_url(dict(m), "host", None)
    assert "full_url" not in out3


def test_find_urls_prefers_full_url():
    from utils import find_primary_url
    smap = {"target": "host", "full_url": "https://host/admin",
            "web_surfaces": [{"url": "https://host"}]}
    assert find_primary_url(smap, "host") == "https://host/admin"


def test_attack_engine_run_all_subset(monkeypatch):
    import attack_engine
    calls = []

    class _FakeTool:
        name = "fake"
        def validate(self):
            return None
        def run(self, target, timeout=180, **kwargs):
            calls.append((target, kwargs))
            from tools.base import ToolResult
            return ToolResult(tool="fake", status="success", capability="X",
                              results={"n": 1})

    monkeypatch.setattr(attack_registry, "get_tools_for_action", lambda a: [_FakeTool()])
    out = attack_engine.run_all("host", actions=["A", "B"], timeout=30)
    assert set(out.keys()) == {"A", "B"}
    assert all(r["status"] == "success" for r in out.values())
    assert calls == [("host", {}), ("host", {})]


# ── New agent surface detection tests ─────────────────────────────────────

def test_xxe_agent_should_run_xml_surface():
    from agents.attack_specialists import XXEAgent
    from model_client import ModelClient
    client = ModelClient(model="test", api_key="test")
    agent = XXEAgent(client)
    smap_xml = {"web_surfaces": [{"url": "https://host"}],
                "endpoints": ["/api/soap"], "technologies": [{"name": "SOAP"}],
                "posture": {"response_headers": {}},
                "assets": {"subdomains": []}, "services": [], "api_paths": [],
                "auth_paths": [], "js_endpoints": [], "signals": {}}
    assert agent.should_run(smap_xml)
    smap_clean = {"web_surfaces": [{"url": "https://host"}],
                  "endpoints": [], "technologies": [{"name": "nginx"}],
                  "posture": {"response_headers": {}},
                  "assets": {"subdomains": []}, "services": [], "api_paths": [],
                  "auth_paths": [], "js_endpoints": [], "signals": {}}
    assert not agent.should_run(smap_clean)


def test_csrf_agent_should_run_auth_surface():
    from agents.attack_specialists import CSRFScanAgent
    from model_client import ModelClient
    client = ModelClient(model="test", api_key="test")
    agent = CSRFScanAgent(client)
    # Agent now requires recon-detected csrf_surface
    smap_with_surface = {"csrf_surface": [{"action_url": "/transfer", "method": "POST", "has_csrf_token": False, "risk": "high"}],
                         "auth_paths": ["/login"], "endpoints": [],
                         "web_surfaces": [], "technologies": [], "posture": {"response_headers": {}},
                         "assets": {"subdomains": []}, "services": [], "api_paths": [],
                         "js_endpoints": [], "signals": {}}
    assert agent.should_run(smap_with_surface)
    smap_no_surface = {"csrf_surface": [], "auth_paths": ["/login"], "endpoints": [],
                       "web_surfaces": [], "technologies": [], "posture": {"response_headers": {}},
                       "assets": {"subdomains": []}, "services": [], "api_paths": [],
                       "js_endpoints": [], "signals": {}}
    assert not agent.should_run(smap_no_surface)


def test_deserialization_agent_should_run_java_tech():
    from agents.attack_specialists import DeserializationAgent
    from model_client import ModelClient
    client = ModelClient(model="test", api_key="test")
    agent = DeserializationAgent(client)
    # Agent now requires recon-detected deserialization_vectors
    smap_with_vectors = {"deserialization_vectors": [{"url": "http://host/rpc", "type": "java_class_reference", "severity": "HIGH"}],
                         "web_surfaces": [{"url": "https://host"}],
                         "endpoints": [], "technologies": [{"name": "Apache Tomcat"}],
                         "posture": {"response_headers": {}},
                         "assets": {"subdomains": []}, "services": [], "api_paths": [],
                         "auth_paths": [], "js_endpoints": [], "signals": {}}
    assert agent.should_run(smap_with_vectors)
    smap_no_vectors = {"deserialization_vectors": [],
                       "web_surfaces": [{"url": "https://host"}],
                       "endpoints": [], "technologies": [{"name": "nginx"}],
                       "posture": {"response_headers": {}},
                       "assets": {"subdomains": []}, "services": [], "api_paths": [],
                       "auth_paths": [], "js_endpoints": [], "signals": {}}
    assert not agent.should_run(smap_no_vectors)


def test_system_map_derives_xxe_csrf_deser_agents():
    from system_map import derive_attack_surface
    smap = {
        "services": [{"port": 443}],
        "web_surfaces": [{"url": "https://host"}],
        "endpoints": ["/api/soap"],
        "parameters": [],
        "api_paths": [],
        "auth_paths": ["/login"],
        "js_endpoints": [],
        "technologies": [{"name": "Apache Tomcat"}],
        "deserialization_vectors": [{"url": "http://host/rpc", "type": "java_class_reference"}],
        "upload_forms": [],
        "csrf_surface": [{"action_url": "/transfer", "method": "POST", "has_csrf_token": False, "risk": "high"}],
        "signals": {"cms": None, "cloud": [], "container": [], "iot": [], "api_types": []},
        "posture": {"tls_vulnerabilities": {}, "missing_security_headers": [],
                    "weak_ciphers": [], "response_headers": {}},
        "assets": {"subdomains": []},
    }
    surface = derive_attack_surface(smap)
    agents = surface["agents"]
    assert "xxe" in agents and not agents["xxe"]["skip"]
    assert "csrf" in agents and not agents["csrf"]["skip"]
    assert "deserialization" in agents and not agents["deserialization"]["skip"]


def test_registry_loads_new_agents():
    from agents.registry import AGENT_REGISTRY, load_agent
    from model_client import ModelClient
    client = ModelClient(model="test", api_key="test")
    for name in ["xxe", "csrf", "deserialization"]:
        assert name in AGENT_REGISTRY, f"{name} missing from registry"
        agent = load_agent(name, client)
        assert agent.agent_name == name
