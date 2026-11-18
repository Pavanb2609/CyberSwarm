"""Regression tests for capability -> evidence_store -> SystemMap fidelity.

Every recon capability's tool output must survive the full pipeline:
    tool.run() -> ToolResult.results
        -> evidence_store.merge_tool_result  (nothing dropped)
        -> system_map.build_from_evidence     (nothing dropped)
        -> derive_attack_surface              (data drives agent selection)

These tests pin the previously-unmapped capabilities (DNS records, httpx
probes, S3 assets, passive detection caps, cookies, GraphQL introspection,
robots.txt, cert info, sensitive endpoints, session + auth-flow analysis)
and guarantee the run-all sweep actually runs every registered capability.
"""

import pytest

import evidence_store as es
import run_recon_loop as rrl
import system_map as sm
from tools import registry
from tools.base import ToolResult


def _seed(open_ports=None):
    return {
        "target": "example.com",
        "open_ports": list(open_ports or []),
        "completed_actions": [],
        "failed_actions": [],
        "zero_findings_actions": [],
        "previous_observations": [],
        "subdomains": [],
    }


# capability, tool, sample ToolResult results, expected evidence key(s)
EXTENDED_RECON_SAMPLES = [
    pytest.param(
        "DNS_ENUMERATION", "dns_enum",
        {"dns_records": {"A": ["1.2.3.4"], "MX": [], "TXT": ["v=spf1"]}, "record_count": 1},
        ["dns_records"], id="DNS_ENUMERATION"),
    pytest.param(
        "WEB_PROBING", "httpx",
        {"probes": [{"url": "https://example.com", "status_code": 200,
                     "title": "Example", "webserver": "nginx"}],
         "technologies": ["nginx"], "reachable": True},
        ["web_probes"], id="WEB_PROBING"),
    pytest.param(
        "S3_LIST", "s3_enum",
        {"s3_assets": [{"bucket": "public-backups", "publicly_listable": True,
                        "object_count": 12}], "target": "public-backups"},
        ["s3_assets"], id="S3_LIST"),
    pytest.param(
        "DESERIALIZATION_DETECTION", "deserialization_detect",
        {"deserialization_vectors": [{"url": "https://example.com/api", "evidence": ["java"]}],
         "count": 1, "tested_urls": ["https://example.com"]},
        ["deserialization_detection", "deserialization_vectors"], id="DESERIALIZATION_DETECTION"),
    pytest.param(
        "UPLOAD_FORM_DETECTION", "upload_form_detect",
        {"upload_forms": [{"page_url": "https://example.com/upload", "action": "/upload"}],
         "count": 1, "tested_urls": []},
        ["upload_form_detection", "upload_forms"], id="UPLOAD_FORM_DETECTION"),
    pytest.param(
        "CSRF_SURFACE_DETECTION", "csrf_surface_detect",
        {"csrf_surface": [{"page_url": "https://example.com/login", "form_action": "/login"}],
         "count": 1, "tested_urls": []},
        ["csrf_surface_detection", "csrf_surface"], id="CSRF_SURFACE_DETECTION"),
    pytest.param(
        "COOKIE_ANALYSIS", "cookie_analyzer",
        {"cookies": [{"name": "sessionid", "flags": {"secure": False, "httponly": False},
                      "issues": ["missing Secure flag"], "severity": "MEDIUM"}],
         "count": 1, "insecure_count": 1, "insecure_cookies": ["sessionid"]},
        ["cookies"], id="COOKIE_ANALYSIS"),
    pytest.param(
        "GRAPHQL_INTROSPECTION", "graphql_introspection",
        {"endpoints": [{"url": "https://example.com/graphql", "type_count": 12,
                        "has_mutation": True, "query_fields": ["user"]}], "count": 1},
        ["graphql_endpoints"], id="GRAPHQL_INTROSPECTION"),
    pytest.param(
        "ROBOTS_TXT_ANALYSIS", "robots_txt",
        {"found": True, "disallowed_paths": ["/admin"], "allowed_paths": ["/public"],
         "sitemaps": ["https://example.com/sitemap.xml"], "internal_apis": ["/api/internal"],
         "sensitive_paths": ["/backup"], "internal_hosts": ["api-internal.example.com"],
         "severity": "HIGH"},
        ["robots_txt"], id="ROBOTS_TXT_ANALYSIS"),
    pytest.param(
        "CERT_INFO", "cert_info",
        {"subject": "example.com", "issuer": "Fake CA", "sans": ["example.com", "www.example.com"],
         "san_count": 2, "not_before": "Jan  1 00:00:00 2026 GMT", "not_after": "Jan  1 00:00:00 2027 GMT",
         "days_until_expiry": 90, "protocol": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256",
         "cipher_bits": 256, "issues": [], "severity": "INFO"},
        ["cert_info", "cert_subject", "cert_days_until_expiry"], id="CERT_INFO"),
    pytest.param(
        "SENSITIVE_ENDPOINT_DETECTION", "sensitive_endpoint_detect",
        {"found": [{"path": "/.env", "status": 200, "severity": "CRITICAL",
                    "description": "env file"}], "count": 1, "tested_count": 30},
        ["sensitive_endpoints"], id="SENSITIVE_ENDPOINT_DETECTION"),
    pytest.param(
        "SESSION_ANALYSIS", "session_analyzer",
        {"sessions": [{"token_name": "sessionid", "risk": "HIGH"}], "count": 1,
         "risky_count": 1, "high_risk_tokens": ["sessionid"]},
        ["session_findings"], id="SESSION_ANALYSIS"),
    pytest.param(
        "AUTH_FLOW_ANALYSIS", "auth_flow_analysis",
        {"auth_results": [{"url": "https://example.com/login", "status": 200,
                           "mechanisms": ["jwt"], "login_form": True}],
         "login_url": "https://example.com/login", "mechanisms": ["jwt"],
         "mfa_detected": False, "rate_limited": False, "csrf_protected": True},
        ["auth_flows"], id="AUTH_FLOW_ANALYSIS"),
]


def _merge(ev, capability, tool, results):
    r = ToolResult(tool=tool, status="success", capability=capability, results=results)
    return es.merge_tool_result(ev, r)


@pytest.mark.parametrize("capability,tool,results,evidence_keys", EXTENDED_RECON_SAMPLES)
def test_extended_recon_results_survive_merge(capability, tool, results, evidence_keys):
    ev = _merge(_seed(), capability, tool, results)
    for key in evidence_keys:
        assert key in ev, f"{capability}: evidence missing '{key}'"
        assert ev[key], f"{capability}: evidence '{key}' empty"
    assert capability in ev["completed_actions"]
    assert capability not in ev["zero_findings_actions"]


@pytest.mark.parametrize("capability,tool,results,_", EXTENDED_RECON_SAMPLES)
def test_extended_recon_results_reach_system_map(capability, tool, results, _):
    ev = _merge(_seed([443, 80]), capability, tool, results)
    m = sm.build_from_evidence("example.com", ev)
    got = {k: v for k, v in m.items() if v}
    assert got, "SystemMap completely empty"
    assert set(m) <= set(sm.new_map("example.com")), "unknown keys in built map"


@pytest.mark.parametrize("capability,tool,results,_", EXTENDED_RECON_SAMPLES)
def test_extended_recon_maps_are_not_dropped_by_build(capability, tool, results, _):
    ev = _merge(_seed([443, 80]), capability, tool, results)
    m = sm.build_from_evidence("example.com", ev)
    probe = {k: bool(v) for k, v in m.items()}
    probe["cert_info"] = bool(m["posture"]["cert_info"])
    assert any(probe[k] for k in (
        "dns_records", "web_probes", "s3_assets", "deserialization_vectors", "upload_forms",
        "csrf_surface", "cookies", "graphql_endpoints", "robots_txt",
        "sensitive_endpoints", "session_findings", "auth_flows", "cert_info")), capability


def test_httpx_probes_enrich_web_surfaces():
    ev = _merge(_seed([443]),
                "WEB_PROBING", "httpx",
                {"probes": [{"url": "https://example.com/", "status_code": 200,
                             "title": "Example", "webserver": "nginx"}],
                 "technologies": ["nginx"], "reachable": True})
    m = sm.build_from_evidence("example.com", ev)
    surf = next((s for s in m["web_surfaces"] if s["url"].startswith("https://example.com")), None)
    assert surf is not None
    assert surf["status"] == 200
    assert surf["title"] == "Example"
    assert "nginx" in surf["tech"]


def test_robots_internal_hosts_and_paths_feed_map():
    ev = _merge(_seed([443, 80]), "ROBOTS_TXT_ANALYSIS", "robots_txt",
                {"found": True, "disallowed_paths": ["/admin"], "internal_apis": ["/api/internal"],
                 "sensitive_paths": ["/backup"], "internal_hosts": ["api-internal.example.com"],
                 "severity": "HIGH"})
    m = sm.build_from_evidence("example.com", ev)
    assert "api-internal.example.com" in m["assets"]["subdomains"]
    assert "/api/internal" in m["endpoints"]
    assert "/backup" in m["endpoints"]


def test_graphql_endpoints_land_in_api_paths_and_trigger_api_agent():
    ev = _merge(_seed([443, 80]), "GRAPHQL_INTROSPECTION", "graphql_introspection",
                {"endpoints": [{"url": "https://example.com/graphql", "type_count": 12}],
                 "count": 1})
    m = sm.build_from_evidence("example.com", ev)
    assert "https://example.com/graphql" in m["api_paths"]
    surface = sm.derive_attack_surface(m)
    assert surface["agents"]["api"]["skip"] is False


def test_auth_flow_login_url_becomes_auth_path():
    ev = _merge(_seed([443, 80]), "AUTH_FLOW_ANALYSIS", "auth_flow_analysis",
                {"auth_results": [{"url": "https://example.com/login", "status": 200,
                                   "mechanisms": ["jwt"]}],
                 "login_url": "https://example.com/login", "mechanisms": ["jwt"]})
    m = sm.build_from_evidence("example.com", ev)
    assert "https://example.com/login" in m["auth_paths"]
    surface = sm.derive_attack_surface(m)
    assert surface["agents"]["auth"]["skip"] is False


def test_cert_info_aliases_into_canonical_cert_keys():
    ev = _merge(_seed(), "CERT_INFO", "cert_info",
                {"subject": "example.com", "days_until_expiry": 90,
                 "sans": ["example.com"], "issues": [], "severity": "INFO"})
    assert ev["cert_subject"] == "example.com"
    assert ev["cert_days_until_expiry"] == 90
    m = sm.build_from_evidence("example.com", ev)
    assert m["posture"]["cert_info"]["subject"] == "example.com"
    assert m["posture"]["cert_info"]["days_until_expiry"] == 90


def test_s3_assets_and_cookies_drive_attack_surface():
    ev = _merge(_seed([443]), "S3_LIST", "s3_enum",
                {"s3_assets": [{"bucket": "public-backups", "publicly_listable": True}],
                 "target": "public-backups"})
    ev = _merge(ev, "COOKIE_ANALYSIS", "cookie_analyzer",
                {"cookies": [{"name": "sessionid", "issues": ["missing Secure flag"],
                              "severity": "MEDIUM"}], "count": 1})
    m = sm.build_from_evidence("example.com", ev)
    surface = sm.derive_attack_surface(m)
    assert "public-backups" in m["signals"]["cloud"]
    assert surface["agents"]["cloud"]["skip"] is False
    assert m["cookies"]
    assert surface["agents"]["session_hijack"]["skip"] is False


def test_run_all_order_contains_every_registered_capability():
    missing = [c for c in registry.CAPABILITY_TOOL_MAP if c not in rrl.CAPABILITY_EXECUTION_ORDER]
    assert not missing, f"capabilities never run by --run-all: {missing}"
    assert len(rrl.CAPABILITY_EXECUTION_ORDER) == len(
        set(rrl.CAPABILITY_EXECUTION_ORDER)), "duplicate capabilities in run-all order"


def test_detection_caps_trigger_their_agents():
    ev = _seed([443])
    ev = _merge(ev, "CSRF_SURFACE_DETECTION", "csrf_surface_detect",
                {"csrf_surface": [{"page_url": "https://example.com/login"}], "count": 1})
    ev = _merge(ev, "DESERIALIZATION_DETECTION", "deserialization_detect",
                {"deserialization_vectors": [{"url": "https://example.com/api"}], "count": 1})
    m = sm.build_from_evidence("example.com", ev)
    surface = sm.derive_attack_surface(m)
    assert m["csrf_surface"]
    assert m["deserialization_vectors"]
    assert surface["agents"]["csrf"]["skip"] is False
    assert surface["agents"]["deserialization"]["skip"] is False