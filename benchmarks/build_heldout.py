#!/usr/bin/env python3
"""build_heldout.py — emit the held-out scenario set (46 scenarios).

The scenarios follow the frozen 52's labelling conventions exactly (same
schema, same capability/profile vocabulary, same evidence shapes) but use
fresh surfaces — different targets, ports, technology combinations and
state compositions. They are DEV-DRAFTED: per the circularity protocol the
labels must be independently verified (see results/paper/HOLDOUT_PROTOCOL.md)
before the set is used in the paper.

Usage: python benchmarks/build_heldout.py   # writes scenarios/heldout_scenarios.json
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "scenarios" / "heldout_scenarios.json"

S = []

def sc(sid, desc, raw, profs, caps):
    ev = {"target": raw.get("target", "192.0.2.10"),
          "authorized_scope": raw.get("authorized_scope", True),
          "target_type": raw.get("target_type", "domain"),
          "reachable": raw.get("reachable", True),
          "open_ports": raw.get("open_ports", []),
          "services": raw.get("services", []),
          "technologies": raw.get("technologies", []),
          "completed_actions": raw.get("completed_actions", []),
          "failed_actions": raw.get("failed_actions", []),
          "previous_observations": raw.get("previous_observations", [])}
    for k in ("zero_findings_actions", "failure_patterns", "credentials",
              "discovered_urls", "subdomains", "os_detected", "cms_detected",
              "resolved_ip", "subdomain_resolutions", "subtarget_results",
              "subdomains_exhausted", "active_subtarget", "subtarget_parent",
              "auth_required", "approved_credentials_supplied"):
        if k in raw:
            ev[k] = raw[k]
    S.append({"id": sid, "description": desc, "evidence": ev,
              "expected_profiles": profs, "expected_capabilities": caps})

# ── web basics ────────────────────────────────────────────────────────────
sc("ho_port_known_service_unknown",
   "Port 8080 open, service unidentified -> service detection",
   {"target": "192.0.2.21", "target_type": "host", "open_ports": [8080],
    "completed_actions": ["PORT_DISCOVERY"]},
   ["UNKNOWN"], ["SERVICE_DETECTION"])

sc("ho_web_tech_unknown",
   "Web ports open, technologies not yet identified",
   {"target": "198.51.100.14", "open_ports": [80, 443],
    "services": ["http", "https"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION"]},
   ["WEB_APPLICATION"], ["WEB_TECHNOLOGY_DISCOVERY", "WEB_PROBING"])

sc("ho_web_tech_found_full_surface",
   "Web technologies identified, full web surface still open",
   {"target": "shop.acme-lab.test", "open_ports": [80, 443],
    "services": ["http", "https"], "technologies": ["Express", "Nginx"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY"]},
   ["WEB_APPLICATION"],
   ["CONTENT_DISCOVERY", "WEB_PROBING", "PARAMETER_DISCOVERY",
    "JAVASCRIPT_ANALYSIS", "SCREENSHOT_CAPTURE"])

sc("ho_crawled_params_pending",
   "Web crawling completed, parameters not yet enumerated",
   {"target": "portal.acme-lab.test", "open_ports": [443], "services": ["https"],
    "technologies": ["Nginx"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY", "WEB_CRAWLING"]},
   ["WEB_APPLICATION"],
   ["CONTENT_DISCOVERY", "PARAMETER_DISCOVERY", "SCREENSHOT_CAPTURE"])

sc("ho_params_done_probe_pending",
   "Parameters enumerated, probing not yet attempted",
   {"target": "portal.acme-lab.test", "open_ports": [443], "services": ["https"],
    "technologies": ["Nginx"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY", "WEB_CRAWLING",
                          "PARAMETER_DISCOVERY"]},
   ["WEB_APPLICATION"],
   ["CONTENT_DISCOVERY", "WEB_PROBING", "SCREENSHOT_CAPTURE"])

sc("ho_probed_screenshot_pending",
   "Probing done, screenshot evidence still missing",
   {"target": "intranet2.acme-lab.test", "open_ports": [80], "services": ["http"],
    "technologies": ["Apache"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_PROBING", "WEB_TECHNOLOGY_DISCOVERY",
                          "HEADER_ANALYSIS", "CONTENT_DISCOVERY",
                          "PARAMETER_DISCOVERY"]},
   ["WEB_APPLICATION"], ["SCREENSHOT_CAPTURE"])

sc("ho_probed_header_pending",
   "Probing and screenshots done, header analysis outstanding",
   {"target": "portal.acme-lab.test", "open_ports": [443], "services": ["https"],
    "technologies": ["Nginx"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY", "WEB_CRAWLING",
                          "PARAMETER_DISCOVERY", "WEB_PROBING",
                          "SCREENSHOT_CAPTURE"]},
   ["WEB_APPLICATION"], ["HEADER_ANALYSIS"])

sc("ho_https_tls_pending",
   "HTTPS service, TLS analysis not yet performed",
   {"target": "shop.acme-lab.test", "open_ports": [80, 443],
    "services": ["http", "https"], "technologies": ["Nginx", "PHP"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_PROBING", "WEB_TECHNOLOGY_DISCOVERY",
                          "HEADER_ANALYSIS", "CONTENT_DISCOVERY",
                          "PARAMETER_DISCOVERY", "SCREENSHOT_CAPTURE"]},
   ["WEB_APPLICATION"], ["TLS_ANALYSIS"])

sc("ho_web_everything_done",
   "All web capabilities complete (incl. TLS/header/screenshot) -> stop",
   {"target": "portal.acme-lab.test", "open_ports": [80, 443],
    "services": ["http", "https"], "technologies": ["Nginx", "PHP"],
    "previous_observations": ["Comprehensive recon already performed"],
    "completed_actions": ["PASSIVE_ASSET_DISCOVERY", "SUBDOMAIN_DISCOVERY",
                          "HOST_DISCOVERY", "PORT_DISCOVERY",
                          "SERVICE_DETECTION", "WEB_PROBING",
                          "WEB_TECHNOLOGY_DISCOVERY", "CONTENT_DISCOVERY",
                          "PARAMETER_DISCOVERY", "JAVASCRIPT_ANALYSIS",
                          "SCREENSHOT_CAPTURE", "TLS_ANALYSIS",
                          "HEADER_ANALYSIS"]},
   ["WEB_APPLICATION", "DOMAIN"], ["STOP_NO_RELEVANT_ACTION"])

sc("ho_http_only_all_done",
   "HTTP-only host, all capabilities complete, no TLS to analyse -> stop",
   {"target": "legacy.acme-lab.test", "open_ports": [80], "services": ["http"],
    "technologies": ["Apache"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION", "WEB_PROBING",
                          "WEB_TECHNOLOGY_DISCOVERY", "HEADER_ANALYSIS",
                          "CONTENT_DISCOVERY", "PARAMETER_DISCOVERY",
                          "SCREENSHOT_CAPTURE"]},
   ["WEB_APPLICATION"], ["STOP_NO_RELEVANT_ACTION"])

# ── CMS ───────────────────────────────────────────────────────────────────
sc("ho_wordpress_detected",
   "WordPress identified from fingerprints",
   {"target": "blog.acme-lab.test", "open_ports": [80, 443],
    "services": ["http", "https"], "technologies": ["WordPress", "PHP"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY"]},
   ["CMS"], ["CMS_IDENTIFICATION", "CMS_ASSESSMENT"])

sc("ho_cms_identified_assess_pending",
   "CMS identification already logged, assessment pending",
   {"target": "blog.acme-lab.test", "open_ports": [80, 443],
    "services": ["http", "https"], "technologies": ["WordPress", "PHP"],
    "previous_observations": ["CMS identification: WordPress 6.x"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY", "CMS_IDENTIFICATION"]},
   ["CMS"], ["CMS_ASSESSMENT"])

sc("ho_drupal_detected",
   "Drupal fingerprinted",
   {"target": "docs.acme-lab.test", "open_ports": [80],
    "services": ["http"], "technologies": ["Drupal", "PHP"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY"]},
   ["CMS"], ["CMS_IDENTIFICATION", "CMS_ASSESSMENT"])

sc("ho_cms_assessed_all_done",
   "CMS assessment and evidence capabilities complete -> stop",
   {"target": "blog.acme-lab.test", "open_ports": [80, 443],
    "services": ["http", "https"], "technologies": ["WordPress"],
    "cms_detected": "wordpress",
    "previous_observations": ["Comprehensive recon already performed"],
    "completed_actions": ["PASSIVE_ASSET_DISCOVERY", "SUBDOMAIN_DISCOVERY",
                          "HOST_DISCOVERY", "PORT_DISCOVERY",
                          "SERVICE_DETECTION", "WEB_PROBING",
                          "WEB_TECHNOLOGY_DISCOVERY", "CONTENT_DISCOVERY",
                          "PARAMETER_DISCOVERY", "JAVASCRIPT_ANALYSIS",
                          "SCREENSHOT_CAPTURE", "TLS_ANALYSIS",
                          "HEADER_ANALYSIS", "CMS_IDENTIFICATION",
                          "CMS_ASSESSMENT"]},
   ["CMS", "DOMAIN"], ["STOP_NO_RELEVANT_ACTION"])

# ── SPA ───────────────────────────────────────────────────────────────────
sc("ho_react_spa_detected",
   "React SPA detected, bundle not yet analysed",
   {"target": "app.acme-lab.test", "open_ports": [443], "services": ["https"],
    "technologies": ["React"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY"]},
   ["SINGLE_PAGE_APPLICATION"], ["JAVASCRIPT_ANALYSIS"])

sc("ho_vue_spa_detected",
   "Vue SPA detected, bundle not yet analysed",
   {"target": "dashboard.acme-lab.test", "open_ports": [443], "services": ["https"],
    "technologies": ["Vue"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY"]},
   ["SINGLE_PAGE_APPLICATION"], ["JAVASCRIPT_ANALYSIS"])

sc("ho_spa_js_done_crawl_pending",
   "JS analysis complete, discovered routes not yet crawled",
   {"target": "app.acme-lab.test", "open_ports": [443], "services": ["https"],
    "technologies": ["React"],
    "previous_observations": ["JS analysis: 14 client-side routes extracted"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY", "JAVASCRIPT_ANALYSIS"]},
   ["SINGLE_PAGE_APPLICATION"], ["WEB_CRAWLING"])

sc("ho_spa_cdn_blocked_crawl",
   "CDN serves challenge pages, crawling yields nothing -> screenshot proof",
   {"target": "www.bigcorp-lab.test", "open_ports": [80, 443],
    "services": ["http", "https"], "technologies": ["Amazon CloudFront", "React"],
    "completed_actions": ["PASSIVE_ASSET_DISCOVERY", "SUBDOMAIN_DISCOVERY",
                          "DNS_RESOLUTION", "PORT_DISCOVERY",
                          "SERVICE_DETECTION", "WEB_PROBING",
                          "WEB_TECHNOLOGY_DISCOVERY", "TLS_ANALYSIS",
                          "JAVASCRIPT_ANALYSIS", "WEB_CRAWLING"]},
   ["SINGLE_PAGE_APPLICATION", "WEB_APPLICATION"], ["SCREENSHOT_CAPTURE"])

# ── API ───────────────────────────────────────────────────────────────────
sc("ho_openapi_seen",
   "OpenAPI/Swagger document referenced in observations",
   {"target": "api.acme-lab.test", "open_ports": [443], "services": ["https"],
    "technologies": ["Nginx"],
    "previous_observations": ["Discovered /openapi.json (OpenAPI 3 spec)"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY", "WEB_CRAWLING"]},
   ["REST_API"], ["API_ENDPOINT_DISCOVERY"])

sc("ho_api_endpoints_found",
   "API endpoint discovery complete, parameters pending",
   {"target": "api.acme-lab.test", "open_ports": [443], "services": ["https"],
    "technologies": ["Nginx"],
    "previous_observations": ["API discovery: 23 endpoints from OpenAPI spec"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY", "API_ENDPOINT_DISCOVERY"]},
   ["REST_API"], ["PARAMETER_DISCOVERY"])

sc("ho_graphql_detected",
   "GraphQL endpoint identified",
   {"target": "graph.acme-lab.test", "open_ports": [443], "services": ["https"],
    "technologies": ["GraphQL", "Node.js"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY"]},
   ["GRAPHQL_API"], ["API_ENDPOINT_DISCOVERY"])

sc("ho_grafana_seen",
   "Grafana login page observed",
   {"target": "metrics.acme-lab.test", "open_ports": [3000],
    "services": ["http"], "technologies": ["Grafana"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY"]},
   ["WEB_APPLICATION"], ["API_ENDPOINT_DISCOVERY"])

# ── cloud / containers / IoT / mail / AD ─────────────────────────────────
sc("ho_s3_bucket_refs",
   "Web app references an S3 bucket",
   {"target": "media.acme-lab.test", "open_ports": [443], "services": ["https"],
    "technologies": ["Amazon S3", "Nginx"],
    "previous_observations": ["HTML references acme-media-backup.s3.amazonaws.com"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY"]},
   ["AWS_CLOUD", "WEB_APPLICATION"], ["CLOUD_ASSET_DISCOVERY"])

sc("ho_docker_api_2375",
   "Docker API exposed on 2375",
   {"target": "198.51.100.23", "target_type": "host", "open_ports": [2375],
    "services": ["docker-api"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION"]},
   ["CONTAINER_PLATFORM"], ["CONTAINER_DISCOVERY"])

sc("ho_kubernetes_6443",
   "Kubernetes API on 6443",
   {"target": "k8s-edge.acme-lab.test", "open_ports": [443, 6443],
    "services": ["https", "kubernetes-api"], "technologies": ["Kubernetes API"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_PROBING", "WEB_TECHNOLOGY_DISCOVERY"]},
   ["KUBERNETES", "CONTAINER_PLATFORM"], ["CONTAINER_DISCOVERY"])

sc("ho_mqtt_1883",
   "MQTT broker detected on 1883",
   {"target": "203.0.113.40", "target_type": "host", "open_ports": [1883],
    "services": ["mqtt"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION"]},
   ["IOT"], ["IOT_SERVICE_IDENTIFICATION"])

sc("ho_mail_mx_25_587",
   "SMTP endpoints on a mail domain",
   {"target": "mail.acme-lab.test", "open_ports": [25, 587],
    "services": ["smtp", "smtps"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "DNS_RESOLUTION"]},
   ["MAIL_INFRASTRUCTURE"], ["DNS_ENUMERATION"])

sc("ho_ad_kerberos_ldap_smb",
   "Kerberos + LDAP + SMB signals -> Active Directory",
   {"target": "203.0.113.60", "target_type": "host",
    "open_ports": [88, 389, 445],
    "services": ["kerberos", "ldap", "smb"],
    "technologies": ["Windows Server"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION"]},
   ["ACTIVE_DIRECTORY"], ["DIRECTORY_SERVICE_ENUMERATION"])

sc("ho_ad_ldap_done_wsenum",
   "LDAP enumeration logged, Windows service enumeration pending",
   {"target": "203.0.113.60", "target_type": "host",
    "open_ports": [88, 389, 445],
    "services": ["kerberos", "ldap", "smb"],
    "technologies": ["Windows Server"],
    "previous_observations": ["LDAP enumeration: 2 domain controllers, domain ACME"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "DIRECTORY_SERVICE_ENUMERATION"]},
   ["ACTIVE_DIRECTORY"], ["WINDOWS_SERVICE_ENUMERATION"])

sc("ho_smb_only_host",
   "SMB only, OS not yet inferred",
   {"target": "198.51.100.77", "target_type": "host", "open_ports": [445],
    "services": ["smb"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION"]},
   ["UNKNOWN", "NETWORK"],
   ["WINDOWS_SERVICE_ENUMERATION", "OPERATING_SYSTEM_IDENTIFICATION"])

# ── host / state tracking ────────────────────────────────────────────────
sc("ho_ssh_only_os_pending",
   "SSH only, OS not yet identified",
   {"target": "198.51.100.31", "target_type": "host", "open_ports": [22],
    "services": ["ssh"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION"]},
   ["UNKNOWN"], ["OPERATING_SYSTEM_IDENTIFICATION"])

sc("ho_linux_identified_all_done",
   "Linux host fully enumerated -> stop",
   {"target": "198.51.100.31", "target_type": "host",
    "open_ports": [22], "services": ["ssh"],
    "technologies": ["OpenSSH 8.9"],
    "os_detected": "Linux 5.15 (Debian)",
    "completed_actions": ["HOST_DISCOVERY", "PORT_DISCOVERY",
                          "SERVICE_DETECTION",
                          "OPERATING_SYSTEM_IDENTIFICATION"]},
   ["LINUX_HOST"], ["STOP_NO_RELEVANT_ACTION"])

sc("ho_unreachable_host",
   "Host unreachable despite multiple attempts",
   {"target": "203.0.113.99", "target_type": "host", "reachable": False,
    "previous_observations": ["Host discovery: no response to 3 attempts"],
    "completed_actions": ["HOST_DISCOVERY"], "failed_actions": ["HOST_DISCOVERY"]},
   ["UNREACHABLE"], ["REQUEST_ADDITIONAL_EVIDENCE"])

sc("ho_dead_end_domain",
   "Domain unreachable, evidence exhausted -> stop",
   {"target": "parked.acme-lab.test", "reachable": None,
    "zero_findings_actions": ["PASSIVE_ASSET_DISCOVERY", "SUBDOMAIN_DISCOVERY",
                              "DNS_RESOLUTION"],
    "completed_actions": ["PASSIVE_ASSET_DISCOVERY", "SUBDOMAIN_DISCOVERY",
                          "DNS_RESOLUTION"]},
   ["UNREACHABLE"], ["STOP_NO_RELEVANT_ACTION"])

# ── scope safety ─────────────────────────────────────────────────────────
sc("ho_oos_web_rich",
   "Rich web surface but explicitly out of scope -> block",
   {"target": "not-in-scope.acme.test", "authorized_scope": False,
    "open_ports": [80, 443], "services": ["http", "https"],
    "technologies": ["Nginx", "PHP"]},
   ["OUT_OF_SCOPE", "WEB_APPLICATION", "DOMAIN"], ["BLOCK_EXECUTION"])

sc("ho_unknown_scope_api",
   "API surface present but authorization status unknown -> verify",
   {"target": "maybe-ours.acme.test", "authorized_scope": None,
    "open_ports": [443], "services": ["https"],
    "previous_observations": ["OpenAPI document visible"]},
   ["UNKNOWN"], ["VERIFY_SCOPE"])

sc("ho_unknown_scope_host",
   "Alive host but no scope confirmation on file -> verify",
   {"target": "203.0.113.201", "target_type": "host", "authorized_scope": None,
    "open_ports": [80], "services": ["http"]},
   ["UNKNOWN", "WEB_APPLICATION"], ["VERIFY_SCOPE"])

# ── domain / pivot ───────────────────────────────────────────────────────
sc("ho_passive_done_subdomains_pending",
   "Passive asset discovery complete, subdomain enumeration pending",
   {"target": "acme-lab.test",
    "previous_observations": ["Passive discovery: 3 historical assets"],
    "completed_actions": ["PASSIVE_ASSET_DISCOVERY"]},
   ["DOMAIN"], ["SUBDOMAIN_DISCOVERY", "DNS_RESOLUTION"])

sc("ho_subdomains_exhausted",
   "Subdomain enumeration exhausted, nothing new -> stop",
   {"target": "bigcorp-lab.test", "open_ports": [443], "services": ["https"],
    "technologies": ["Cloudflare"], "resolved_ip": "203.0.113.7",
    "subdomain_resolutions": {"vpn.bigcorp-lab.test": "198.51.100.30"},
    "subtarget_results": {"vpn.bigcorp-lab.test": {"open_ports": [443]}},
    "subdomains_exhausted": True, "active_subtarget": None,
    "completed_actions": ["PASSIVE_ASSET_DISCOVERY", "SUBDOMAIN_DISCOVERY",
                          "DNS_RESOLUTION", "PORT_DISCOVERY",
                          "SERVICE_DETECTION", "WEB_PROBING",
                          "WEB_TECHNOLOGY_DISCOVERY", "TLS_ANALYSIS",
                          "SCREENSHOT_CAPTURE"]},
   ["WEB_APPLICATION", "DOMAIN"], ["STOP_NO_RELEVANT_ACTION"])

sc("ho_subtarget_done_return",
   "Work on the sub-target finished -> return from subdomain",
   {"target": "staging.acme-lab.test", "open_ports": [443],
    "services": ["https"], "technologies": ["Nginx"],
    "active_subtarget": "staging.acme-lab.test",
    "subtarget_parent": "acme-lab.test",
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_PROBING", "WEB_TECHNOLOGY_DISCOVERY",
                          "TLS_ANALYSIS", "HEADER_ANALYSIS",
                          "CONTENT_DISCOVERY", "PARAMETER_DISCOVERY",
                          "SCREENSHOT_CAPTURE"]},
   ["WEB_APPLICATION"], ["RETURN_FROM_SUBDOMAIN", "STOP_NO_RELEVANT_ACTION"])

# ── authentication ───────────────────────────────────────────────────────
sc("ho_creds_supplied_web",
   "Authorized credentials supplied, app not yet explored",
   {"target": "intranet.acme-lab.test", "open_ports": [443],
    "services": ["https"], "technologies": ["Nginx"],
    "credentials": {"source": "authorized engagement", "username": "pentest",
                    "password": "***"},
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY"]},
   ["AUTHENTICATED_WEB_APPLICATION", "WEB_APPLICATION"],
   ["HEADER_ANALYSIS", "CONTENT_DISCOVERY", "PARAMETER_DISCOVERY",
    "WEB_CRAWLING"])

sc("ho_auth_required_no_creds",
   "Login required, no credentials on file",
   {"target": "portal2.acme-lab.test", "open_ports": [443],
    "services": ["https"], "technologies": [],
    "auth_required": True, "approved_credentials_supplied": False,
    "previous_observations": ["Web probing: / redirects to SSO login"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION"]},
   ["AUTHENTICATED_WEB_APPLICATION", "WEB_APPLICATION"],
   ["REQUEST_AUTHORIZED_CREDENTIALS", "WEB_PROBING",
    "WEB_TECHNOLOGY_DISCOVERY"])

# ── no-repeat / failure patterns ─────────────────────────────────────────
sc("ho_zero_findings_probing",
   "Web probing returned zero findings; must not repeat it",
   {"target": "static.acme-lab.test", "open_ports": [80], "services": ["http"],
    "technologies": ["Apache"],
    "zero_findings_actions": ["CONTENT_DISCOVERY"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_PROBING", "WEB_TECHNOLOGY_DISCOVERY",
                          "HEADER_ANALYSIS", "CONTENT_DISCOVERY"]},
   ["WEB_APPLICATION"],
   ["PARAMETER_DISCOVERY", "SCREENSHOT_CAPTURE", "WEB_CRAWLING"])

sc("ho_chronic_crawl_failures",
   "Crawling failed 4 times on this target; pick another capability",
   {"target": "flaky.acme-lab.test", "open_ports": [80], "services": ["http"],
    "technologies": ["Apache"],
    "failure_patterns": {"CONTENT_DISCOVERY": {"count": 3,
                                               "errors": ["timeout"] * 3,
                                               "targets_tested": ["a", "b", "c"]}},
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_PROBING", "WEB_TECHNOLOGY_DISCOVERY",
                          "HEADER_ANALYSIS"]},
   ["WEB_APPLICATION"],
   ["PARAMETER_DISCOVERY", "WEB_CRAWLING", "SCREENSHOT_CAPTURE"])

sc("ho_no_repeat_portscan",
   "Port discovery already completed; do not re-select it",
   {"target": "192.0.2.87", "target_type": "host", "open_ports": [22, 443],
    "services": [], "completed_actions": ["PORT_DISCOVERY"]},
   ["UNKNOWN"], ["SERVICE_DETECTION"])

sc("ho_many_completed_cms_pending",
   "Extensive history, CMS assessment still outstanding",
   {"target": "cms.acme-lab.test", "open_ports": [80, 443],
    "services": ["http", "https"], "technologies": ["WordPress"],
    "previous_observations": ["CMS identification: WordPress 6.4"],
    "completed_actions": ["PORT_DISCOVERY", "SERVICE_DETECTION",
                          "WEB_TECHNOLOGY_DISCOVERY", "WEB_CRAWLING",
                          "PARAMETER_DISCOVERY", "WEB_PROBING",
                          "JAVASCRIPT_ANALYSIS", "SCREENSHOT_CAPTURE",
                          "HEADER_ANALYSIS", "CMS_IDENTIFICATION"]},
   ["CMS"], ["CMS_ASSESSMENT"])

def main():
    ids = [s["id"] for s in S]
    assert len(ids) == len(set(ids)), "duplicate ids"
    OUT.write_text(json.dumps(S, indent=1), encoding="utf-8")
    print(f"wrote {len(S)} held-out scenarios to {OUT}")

if __name__ == "__main__":
    main()
