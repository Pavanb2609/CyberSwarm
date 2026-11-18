"""Unit tests — run from repo root: python -m pytest tests/ -q"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import system_map as sm


def _evidence() -> dict:
    return {
        "target": "scanme.nmap.org",
        "resolved_ip": "45.33.32.156",
        "reachable": True,
        "port_details": [
            {"port": 22, "service": "ssh", "state": "open"},
            {"port": 80, "service": "http", "state": "open"},
        ],
        "open_ports": [22, 80],
        "technologies": ["Apache httpd 2.4.7", "Ubuntu"],
        "discovered_urls": ["http://scanme.nmap.org/"],
        "subdomains": [],
        "completed_actions": ["portscan"],
        "failed_actions": [],
        "zero_findings_actions": [],
        "discovered_parameters": [],
    }


def test_new_map_defaults():
    m = sm.new_map("example.com")
    assert m["target"] == "example.com"
    assert m["schema_version"] == 1
    assert m["assets"]["resolved_ip"] is None
    assert m["links"] == []


def test_build_from_evidence_populates():
    m = sm.build_from_evidence("scanme.nmap.org", _evidence())
    assert m["assets"]["resolved_ip"] == "45.33.32.156"
    assert {s["port"] for s in m["services"]} == {22, 80}
    assert any("Apache" in t["name"] for t in m["technologies"])
    assert m["web_surfaces"]  # port 80 -> web surface


def test_add_link():
    m = sm.new_map("example.com")
    sm.add_link(m, "recon", "planner", "attack")
    assert m["links"][0]["from"] == "recon"
    sm.add_link(m, "recon", "planner", "attack")  # idempotent
    assert len(m["links"]) == 1


def test_derive_attack_surface_web():
    m = sm.build_from_evidence("scanme.nmap.org", _evidence())
    surface = sm.derive_attack_surface(m)
    assert surface["mapped"] is True
    agents = surface["agents"]
    assert not agents["web_attack"]["skip"]
    assert not agents["network"]["skip"]
    assert agents["api"]["skip"] and agents["auth"]["skip"] and agents["cloud"]["skip"]


def test_compress_for_llm_shape():
    m = sm.build_from_evidence("scanme.nmap.org", _evidence())
    c = sm.compress_for_llm(m)
    assert "services" in c and "technologies" in c
    assert {s["port"] for s in c["services"]} == {22, 80}


def test_save_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(sm, "STORE_DIR", tmp_path)
    m = sm.new_map("roundtrip.test")
    sm.save_map("roundtrip.test", m)
    loaded = sm.load_map("roundtrip.test")
    assert loaded["target"] == "roundtrip.test"


# ── signal heuristics ────────────────────────────────────────────────────────

def test_cloud_indicator_detected_from_technology_names():
    ev = _evidence()
    ev["technologies"] = ["nginx", "Amazon CloudFront"]
    m = sm.build_from_evidence("example.com", ev)
    assert "cloudfront" in m["signals"]["cloud"]


def test_ad_signal_set_from_kerberos_ldap_ports():
    ev = _evidence()
    ev["open_ports"] = [88, 389]  # Kerberos + LDAP
    m = sm.build_from_evidence("example.com", ev)
    assert m["signals"]["ad"] is True


def test_ad_signal_false_without_ad_ports():
    ev = _evidence()
    ev["open_ports"] = [80, 443]
    m = sm.build_from_evidence("example.com", ev)
    assert m["signals"]["ad"] is False


def test_container_signal_detected_from_docker_api_port():
    ev = _evidence()
    ev["open_ports"] = [2375]
    m = sm.build_from_evidence("example.com", ev)
    assert m["signals"]["container"] == ["detected_ports"]


def test_container_signal_from_explicit_evidence_takes_precedence():
    ev = _evidence()
    ev["open_ports"] = [2375]
    ev["container_apis_found"] = [{"api": "docker", "port": 2375}]
    m = sm.build_from_evidence("example.com", ev)
    assert m["signals"]["container"] == [{"api": "docker", "port": 2375}]


def test_iot_signal_from_explicit_evidence():
    ev = _evidence()
    ev["iot_services_found"] = [{"protocol": "mqtt", "port": 1883}]
    m = sm.build_from_evidence("example.com", ev)
    assert m["signals"]["iot"] == [{"protocol": "mqtt", "port": 1883}]


def test_cms_signal_populated_from_evidence():
    ev = _evidence()
    ev["cms_detected"] = "WordPress"
    ev["cms_version"] = "6.4"
    m = sm.build_from_evidence("example.com", ev)
    assert m["signals"]["cms"] == "WordPress"
    assert m["signals"]["cms_version"] == "6.4"


def test_auth_and_api_paths_classified_from_discovered_urls():
    ev = _evidence()
    ev["discovered_urls"] = ["https://example.com/login", "https://example.com/api/v1/users",
                             "https://example.com/about"]
    m = sm.build_from_evidence("example.com", ev)
    assert "https://example.com/login" in m["auth_paths"]
    assert "https://example.com/api/v1/users" in m["api_paths"]
    assert "https://example.com/about" not in m["auth_paths"]
    assert "https://example.com/about" not in m["api_paths"]


def test_auth_path_hint_rejects_mid_segment_false_positive():
    # "/login" must NOT match inside an unrelated segment like
    # "/how-to-login-safely" (a blog/help path, not an auth surface).
    ev = _evidence()
    ev["discovered_urls"] = ["https://example.com/blog/how-to-login-safely",
                             "https://example.com/user/login"]
    m = sm.build_from_evidence("example.com", ev)
    assert "https://example.com/user/login" in m["auth_paths"]
    assert "https://example.com/blog/how-to-login-safely" not in m["auth_paths"]


def test_api_path_hint_rejects_mid_segment_false_positive():
    # "/rest" must NOT match inside "/restaurant-finder".
    ev = _evidence()
    ev["discovered_urls"] = ["https://example.com/restaurant-finder",
                             "https://example.com/rest/v1/orders"]
    m = sm.build_from_evidence("example.com", ev)
    assert "https://example.com/rest/v1/orders" in m["api_paths"]
    assert "https://example.com/restaurant-finder" not in m["api_paths"]


def test_auth_path_hint_matches_at_end_of_path():
    # Hint at the very end of the path (no trailing char to check) must
    # still match -- boundary check shouldn't require a character after it.
    ev = _evidence()
    ev["discovered_urls"] = ["https://example.com/admin"]
    m = sm.build_from_evidence("example.com", ev)
    assert "https://example.com/admin" in m["auth_paths"]


def test_static_css_reset_file_is_not_classified_as_an_auth_path():
    # Real false positive from a live run against certifiedhacker.com:
    # "/css/reset.css" (a CSS *reset stylesheet*, a completely standard
    # web-dev convention) matched the "/reset" auth hint because ".css"
    # is a valid segment-boundary character by _hint_matches's own rules.
    # A static asset can never itself be a dynamic auth endpoint.
    ev = _evidence()
    ev["discovered_urls"] = [
        "http://example.com/Recipes/css/reset.css",
        "http://example.com/Social%20Media/css/reset.min.css",
        "http://example.com/css/reset.min.css",
    ]
    m = sm.build_from_evidence("example.com", ev)
    assert m["auth_paths"] == []


def test_a_genuine_reset_endpoint_still_classifies_as_an_auth_path():
    # The static-asset exclusion must not overcorrect -- a real
    # password-reset endpoint (no static file extension) still counts.
    ev = _evidence()
    ev["discovered_urls"] = ["http://example.com/reset.php",
                             "http://example.com/account/reset"]
    m = sm.build_from_evidence("example.com", ev)
    assert "http://example.com/reset.php" in m["auth_paths"]
    assert "http://example.com/account/reset" in m["auth_paths"]


def test_static_assets_excluded_from_api_paths_too():
    ev = _evidence()
    ev["discovered_urls"] = ["https://example.com/assets/api-client.js",
                             "https://example.com/api/v1/orders"]
    m = sm.build_from_evidence("example.com", ev)
    assert "https://example.com/assets/api-client.js" not in m["api_paths"]
    assert "https://example.com/api/v1/orders" in m["api_paths"]


def test_web_surface_created_for_web_ports():
    ev = _evidence()
    ev["open_ports"] = [443]
    ev["port_details"] = [{"port": 443, "service": "https"}]
    m = sm.build_from_evidence("example.com", ev)
    assert m["web_surfaces"][0]["url"] == "https://example.com"


def test_no_web_surface_when_no_web_ports_and_unreachable():
    ev = _evidence()
    ev["open_ports"] = [22]
    ev["port_details"] = [{"port": 22, "service": "ssh"}]
    ev["reachable"] = False
    m = sm.build_from_evidence("example.com", ev)
    assert m["web_surfaces"] == []


# ── compress_for_llm truncation budgets ─────────────────────────────────────

def test_compress_for_llm_respects_max_tech_budget():
    ev = _evidence()
    ev["technologies"] = [f"tech-{i}" for i in range(20)]
    m = sm.build_from_evidence("example.com", ev)
    c = sm.compress_for_llm(m, max_tech=3)
    assert len(c["technologies"]) == 3


def test_compress_for_llm_respects_max_paths_budget():
    ev = _evidence()
    ev["discovered_urls"] = [f"https://example.com/api/{i}" for i in range(30)]
    m = sm.build_from_evidence("example.com", ev)
    c = sm.compress_for_llm(m, max_paths=5)
    assert len(c["api_paths"]) <= 5
    assert len(c["endpoints"]) <= 5


def test_compress_for_llm_excludes_verbose_ldap_windows_signals():
    ev = _evidence()
    ev["ldap_naming_contexts"] = ["DC=example,DC=com"]
    ev["windows_enum"] = ["some huge dump"]
    m = sm.build_from_evidence("example.com", ev)
    c = sm.compress_for_llm(m)
    assert "ldap_naming_contexts" not in c["signals"]
    assert "windows_enum" not in c["signals"]


def test_compress_for_llm_truncates_completed_actions_to_last_8():
    ev = _evidence()
    ev["completed_actions"] = [f"CAP_{i}" for i in range(20)]
    m = sm.build_from_evidence("example.com", ev)
    c = sm.compress_for_llm(m)
    assert c["completed_actions"] == [f"CAP_{i}" for i in range(12, 20)]


# ── derive_attack_surface: expanded agents / skip rules ─────────────────────

def test_waf_bypass_agent_added_when_cdn_detected():
    ev = _evidence()
    ev["technologies"] = ["Cloudflare"]
    ev["open_ports"] = [443]
    ev["port_details"] = [{"port": 443, "service": "https"}]
    m = sm.build_from_evidence("example.com", ev)
    surface = sm.derive_attack_surface(m)
    assert "waf_bypass" in surface["agents"]
    assert not surface["agents"]["waf_bypass"]["skip"]


def test_waf_bypass_agent_absent_without_cdn_signal():
    m = sm.build_from_evidence("scanme.nmap.org", _evidence())
    surface = sm.derive_attack_surface(m)
    assert "waf_bypass" not in surface["agents"]


def test_subdomain_takeover_agent_added_when_subdomains_present():
    ev = _evidence()
    ev["subdomains"] = ["old.example.com", "staging.example.com"]
    m = sm.build_from_evidence("example.com", ev)
    surface = sm.derive_attack_surface(m)
    assert "subdomain_takeover" in surface["agents"]


def test_jwt_agent_added_when_api_paths_present():
    ev = _evidence()
    ev["discovered_urls"] = ["https://example.com/api/v1/token"]
    m = sm.build_from_evidence("example.com", ev)
    surface = sm.derive_attack_surface(m)
    assert "jwt" in surface["agents"]


def test_network_agent_skipped_when_only_standard_web_ports_open():
    ev = _evidence()
    ev["open_ports"] = [80, 443]
    ev["port_details"] = [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}]
    m = sm.build_from_evidence("example.com", ev)
    surface = sm.derive_attack_surface(m)
    assert surface["agents"]["network"]["skip"] is True


def test_network_agent_not_skipped_when_nonweb_port_open():
    m = sm.build_from_evidence("scanme.nmap.org", _evidence())  # has port 22 (ssh)
    surface = sm.derive_attack_surface(m)
    assert surface["agents"]["network"]["skip"] is False


def test_web_fuzz_agent_added_when_endpoints_present():
    ev = _evidence()
    ev["discovered_urls"] = ["https://example.com/page1"]
    ev["open_ports"] = [443]
    ev["port_details"] = [{"port": 443, "service": "https"}]
    m = sm.build_from_evidence("example.com", ev)
    surface = sm.derive_attack_surface(m)
    assert "web_fuzz" in surface["agents"]


# ── add_link edge cases ──────────────────────────────────────────────────────

def test_add_link_distinguishes_by_kind():
    m = sm.new_map("example.com")
    sm.add_link(m, "a", "b", "kind_one")
    sm.add_link(m, "a", "b", "kind_two")  # same from/to, different kind -> both kept
    assert len(m["links"]) == 2


def test_add_link_stores_confidence_and_source():
    m = sm.new_map("example.com")
    sm.add_link(m, "finding:x", "vulnerability", "confirmed_by_auth", confidence=95, source="auth")
    link = m["links"][0]
    assert link["confidence"] == 95
    assert link["source"] == "auth"


def test_build_from_evidence_creates_expected_links():
    ev = _evidence()
    ev["cms_detected"] = "WordPress"
    ev["discovered_urls"] = ["https://scanme.nmap.org/login", "https://scanme.nmap.org/api/v1"]
    m = sm.build_from_evidence("scanme.nmap.org", ev)
    kinds = {l["kind"] for l in m["links"]}
    assert "cms_hosts_site" in kinds
    assert "login_surface" in kinds
    assert "api_surface" in kinds
