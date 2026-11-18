"""
SystemMap — the shared "understanding" layer of CyberSwarm.

Phase 1 recon produces flat evidence in evidence_store. The SystemMap
turns that into a structured, relational model of the target that every
later phase (planner, attack agents, exploitation, pivot, intelligence,
report) reads from and extends.

Central idea: one model, many agents. Recon builds it, agents read/update
it, report renders it.

Layout:
    results/system_map/<target>.json
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

STORE_DIR = Path(__file__).parent / "results" / "system_map"

# Default web-ish ports treated as a web surface
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}

# Signals used by the hybrid planner's deterministic rules
CLOUD_INDICATORS = ["aws", "s3", "azure", "gcp", "cloudflare", "cloudfront",
                    "lambda", "beanstalk", "heroku", "vercel", "netlify", "ec2"]
AD_INDICATOR_PORTS = {88, 389, 636, 3268, 3269, 445, 139}
CONTAINER_INDICATOR_PORTS = {2375, 2376, 4243}
IOT_INDICATOR_PORTS = {1883, 5683, 1900}
API_PATH_HINTS = ["/api", "/graphql", "/swagger", "/openapi", "/rest", "/v1", "/v2"]
AUTH_PATH_HINTS = ["/login", "/admin", "/auth", "/signin", "/oauth", "/jwt",
                   "/token", "/reset", "/forgot", "/session"]

# Static asset extensions that must never be classified as an auth/API path,
# regardless of what hint their filename happens to contain. This exists
# because of a real false positive: /css/reset.css matched the "/reset"
# auth hint (a CSS *reset stylesheet*, a completely standard web-dev
# convention with zero relation to password-reset functionality) since
# ".css" is a valid segment-boundary character by _hint_matches's own
# rules -- the boundary check alone can't distinguish "reset" as a path
# segment (/api/reset) from "reset" as the stem of a static filename
# (/css/reset.css). A static asset can never itself be a dynamic
# login/reset/token endpoint, so it's excluded up front instead of trying
# to make the hint matching cleverer.
STATIC_ASSET_EXTENSIONS = {
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".pdf",
    ".txt", ".xml", ".json.map",
}


def _is_static_asset(path: str) -> bool:
    p = path.lower().split("?")[0].split("#")[0]
    return any(p.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS)


def _hint_matches(path: str, hints: list[str]) -> bool:
    """True if any hint matches `path` at a path-segment boundary, not just
    as a raw substring.

    Plain substring matching (the previous behavior) let a hint like
    "/rest" match inside an unrelated segment such as "/restaurant-finder",
    or "/login" match inside "/how-to-login-safely" -- a blog/help path,
    not an actual auth surface. Requiring the character immediately after
    the hint to end the segment (i.e. not be alphanumeric/-/_) keeps
    "/login" matching "/user/login" and "/login/reset" while rejecting
    "/how-to-login-safely" and "/restaurant-finder".
    """
    p = path.lower()
    for h in hints:
        start = 0
        while True:
            idx = p.find(h, start)
            if idx == -1:
                break
            end = idx + len(h)
            if end >= len(p) or not (p[end].isalnum() or p[end] in "-_"):
                return True
            start = idx + 1
    return False


def _path_for(target: str) -> Path:
    safe = target.replace("/", "_").replace(":", "_")
    return STORE_DIR / f"{safe}.json"


def new_map(target: str) -> dict[str, Any]:
    return {
        "target": target,
        "schema_version": 1,
        "assets": {
            "resolved_ip": None,
            "reachable": None,
            "subdomains": [],
            "subdomain_resolutions": {},
        },
        "services": [],            # [{"port", "proto", "service", "version", "ssl"}]
        "technologies": [],        # [{"name", "version", "source"}]
        "web_surfaces": [],        # [{"url", "host", "ports", "tech", "title", "status", "headers"}]
        "endpoints": [],           # discovered URLs / paths / API endpoints
        "parameters": [],
        "auth_paths": [],
        "api_paths": [],
        "js_endpoints": [],
        "historical_urls": [],
        "deserialization_vectors": [],  # detected deserialization endpoints from recon
        "upload_forms": [],             # detected file upload forms from recon
        "csrf_surface": [],             # detected CSRF-vulnerable forms from recon
        "cookies": [],                  # session-cookie flag audit (COOKIE_ANALYSIS)
        "dns_records": {},              # DNS_ENUMERATION: {rtype: [answers]}
        "web_probes": [],               # httpx probes: [{url, status_code, title, webserver}]
        "s3_assets": [],                # publicly-listable S3 buckets (S3_LIST)
        "graphql_endpoints": [],        # introspection-enabled GraphQL endpoints
        "robots_txt": {},               # robots.txt parse (ROBOTS_TXT_ANALYSIS)
        "sensitive_endpoints": [],      # /.env, /actuator, git leaks… (SENSITIVE_ENDPOINT_DETECTION)
        "session_findings": [],         # token entropy/flags (SESSION_ANALYSIS)
        "auth_flows": {},               # login-surface analysis (AUTH_FLOW_ANALYSIS)
        "ldap_domain": None,            # AD domain (e.g. ent.local) from LDAP recon
        "ldap_users": [],               # anonymous LDAP object pull (feeds AD agent)
        "ldap_groups": [],
        "ldap_computers": [],
        "ldap_kerberoastable": [],      # cached by-ready roast targets from recon
        "ldap_asrep_roastable": [],
        "signals": {
            "cms": None,
            "cms_version": None,
            "cms_assessment": None,
            "cloud": [],
            "ad": False,
            "container": [],
            "iot": [],
            "api_types": [],
            "ldap_naming_contexts": [],
            "windows_enum": [],
            "os_guesses": [],
        },
        "posture": {
            "missing_security_headers": [],
            "info_disclosure_headers": [],
            "response_headers": {},
            "tls_findings": [],
            "tls_protocols": {},
            "weak_ciphers": [],
            "tls_vulnerabilities": {},
            "certificate": {},
            "cert_info": {},           # CERT_INFO: subject/issuer/expiry/issues
        },
        "attack_surface": {},      # {"mapped": bool, "agents": {agent: {reason, priority, skip}}}
        "links": [],               # cross-node connections: {"from", "to", "kind", "confidence", "source"}
        "provenance": {},          # field -> tool that produced it
        "completed_actions": [],
        "failed_actions": [],
        "zero_findings_actions": [],
    }


def load_map(target: str) -> dict[str, Any]:
    path = _path_for(target)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return new_map(target)


def save_map(target: str, m: dict[str, Any]) -> None:
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    _path_for(target).write_text(json.dumps(m, indent=2), encoding="utf-8")


def map_age_days(target: str) -> float | None:
    """Age in days of the stored SystemMap, or None if it does not exist."""
    try:
        return (time.time() - _path_for(target).stat().st_mtime) / 86400.0
    except OSError:
        return None


def is_stale_map(target: str, max_age_days: float = 7) -> bool:
    """True when the stored map is too old to trust for a live target.

    A stale map (certifiedhacker.com's 1-month-old map) pointed agents at a
    previous incarnation of the host: Apache/Pure-FTPd tech, and dead
    admin.php/reset.php endpoints that are now SPA-routing artifacts. When the
    map is stale, run_agent_loop rebuilds it from current recon evidence."""
    age = map_age_days(target)
    return age is not None and age > max_age_days


def add_link(m: dict[str, Any], from_: str, to: str, kind: str,
             confidence: int = 70, source: str = "recon") -> None:
    link = {"from": from_, "to": to, "kind": kind, "confidence": confidence,
            "source": source}
    for existing in m.get("links", []):
        if (existing["from"], existing["to"], existing["kind"]) == (from_, to, kind):
            return
    m.setdefault("links", []).append(link)


# ─────────────────────────────────────────────────────────────────────────────
# Builder — from Phase 1 evidence_store output
# ─────────────────────────────────────────────────────────────────────────────

def build_from_evidence(target: str, evidence: dict[str, Any]) -> dict[str, Any]:
    """Construct a SystemMap from a Phase 1 evidence_store dict."""
    m = new_map(target)
    ev = evidence or {}

    m["assets"]["resolved_ip"] = ev.get("resolved_ip")
    m["assets"]["reachable"] = ev.get("reachable")
    m["assets"]["subdomains"] = list(ev.get("subdomains", []))
    m["assets"]["subdomain_resolutions"] = dict(ev.get("subdomain_resolutions", {}))

    # Services
    port_details = ev.get("port_details", [])
    if port_details:
        for d in port_details:
            m["services"].append({
                "port": d.get("port"),
                "proto": d.get("proto", "tcp"),
                "service": d.get("service", ""),
                "version": d.get("version", ""),
                "ssl": bool(d.get("ssl", d.get("tunnel", ""))),
            })
    else:
        for port in ev.get("open_ports", []):
            m["services"].append({"port": port, "proto": "tcp", "service": "", "version": "", "ssl": False})

    # Technologies
    for t in ev.get("technologies", []):
        if isinstance(t, str):
            m["technologies"].append({"name": t, "version": "", "source": "recon"})
        elif isinstance(t, dict):
            m["technologies"].append({
                "name": t.get("name", ""),
                "version": t.get("version", ""),
                "source": t.get("source", "recon"),
            })

    # Web surfaces (host + ports + tech)
    web_ports = [p for p in ev.get("open_ports", []) if p in WEB_PORTS]
    host = target
    for port in web_ports:
        scheme = "https" if port in (443, 8443) else "http"
        m["web_surfaces"].append({
            "url": f"{scheme}://{host}",
            "host": host,
            "ports": [port],
            "tech": [t.get("name") if isinstance(t, dict) else t for t in ev.get("technologies", [])],
            "title": "",
            "status": None,
            "headers": dict(ev.get("response_headers", {})),
        })
    if not web_ports and ev.get("reachable"):
        m["web_surfaces"].append({
            "url": f"https://{host}", "host": host, "ports": [443],
            "tech": [], "title": "", "status": None, "headers": {},
        })

    # Enrich web surfaces with real httpx probe data (status/title/webserver)
    # so the surface carries what the server actually serves, not just the port.
    for pr in ev.get("web_probes", []):
        purl = str(pr.get("url") or "").rstrip("/")
        if not purl:
            continue
        for surf in m["web_surfaces"]:
            base = surf["url"].rstrip("/")
            if purl == base or purl.startswith(base + "/"):
                if pr.get("status_code") is not None:
                    surf["status"] = pr["status_code"]
                if pr.get("title"):
                    surf["title"] = pr["title"]
                if pr.get("webserver") and pr["webserver"] not in surf["tech"]:
                    surf["tech"].append(pr["webserver"])
        if purl and not any(s["url"].rstrip("/") == purl for s in m["web_surfaces"]):
            host_only = purl.split("://", 1)[-1].split("/", 1)[0]
            if host_only == host:
                m["web_surfaces"].append({
                    "url": purl, "host": host, "ports": [],
                    "tech": [pr["webserver"]] if pr.get("webserver") else [],
                    "title": pr.get("title", ""), "status": pr.get("status_code"),
                    "headers": {},
                })

    m["endpoints"] = list(ev.get("discovered_urls", [])) + list(ev.get("discovered_paths", []))
    m["js_endpoints"] = list(ev.get("js_endpoints", []))
    m["historical_urls"] = list(ev.get("historical_urls", []))
    m["parameters"] = list(ev.get("discovered_parameters", []))

    # Signals
    sig = m["signals"]
    sig["cms"] = ev.get("cms_detected")
    sig["cms_version"] = ev.get("cms_version")
    sig["cms_assessment"] = ev.get("cms_assessment")
    sig["api_types"] = list(ev.get("detected_api_types", []))
    sig["ldap_naming_contexts"] = list(ev.get("ldap_naming_contexts", []))
    sig["windows_enum"] = list(ev.get("windows_enum", []))
    sig["os_guesses"] = list(ev.get("os_guesses", []))
    sig["cloud"] = list(ev.get("cloud_assets_found", []))

    # AD object data (enhanced ldap_enum) — carried verbatim so the AD agent
    # can build a relationship graph + drive AS-REP/Kerberoast exploitation
    # without a SharpHound collection.
    m["ldap_domain"] = str(ev.get("ldap_domain") or "") or None
    for _lk in ("ldap_users", "ldap_groups", "ldap_computers",
                "ldap_kerberoastable", "ldap_asrep_roastable"):
        data = ev.get(_lk)
        if isinstance(data, list):
            m[_lk] = data
    if ev.get("container_apis_found"):
        sig["container"] = ev["container_apis_found"]
    if ev.get("iot_services_found"):
        sig["iot"] = ev["iot_services_found"]

    all_tech = " ".join(str(x) for x in ev.get("technologies", [])).lower()
    for ind in CLOUD_INDICATORS:
        if ind in all_tech and ind not in sig["cloud"]:
            sig["cloud"].append(ind)
    ports = set(ev.get("open_ports", []))
    if ports & AD_INDICATOR_PORTS:
        sig["ad"] = True
    if not sig["container"] and ports & CONTAINER_INDICATOR_PORTS:
        sig["container"] = ["detected_ports"]

    # Posture
    pos = m["posture"]
    pos["missing_security_headers"] = list(ev.get("missing_security_headers", []))
    pos["info_disclosure_headers"] = list(ev.get("info_disclosure_headers", []))
    pos["response_headers"] = dict(ev.get("response_headers", {}))
    pos["tls_findings"] = list(ev.get("tls_findings", []))
    pos["tls_protocols"] = dict(ev.get("tls_protocols", {}))
    pos["weak_ciphers"] = list(ev.get("weak_ciphers", []))
    pos["tls_vulnerabilities"] = dict(ev.get("tls_vulnerabilities", {}))
    pos["certificate"] = dict(ev.get("tls_certificate", {}))
    if not pos["tls_vulnerabilities"] and ev.get("testssl_results"):
        tr = ev["testssl_results"]
        if isinstance(tr, dict) and isinstance(tr.get("vulnerabilities"), dict):
            pos["tls_vulnerabilities"] = tr["vulnerabilities"]
        if isinstance(tr, dict) and isinstance(tr.get("weak_ciphers"), list):
            pos["weak_ciphers"] = tr["weak_ciphers"]

    # Auth / API path detection. Static assets (stylesheets, scripts,
    # images, fonts...) are excluded before hint matching -- see
    # _is_static_asset()'s docstring for the concrete false positive
    # (reset.css) this prevents.
    all_paths = [p for p in (m["endpoints"] + m["js_endpoints"] + m["historical_urls"])
                if not _is_static_asset(str(p))]
    m["auth_paths"] = sorted({str(p) for p in all_paths if _hint_matches(str(p), AUTH_PATH_HINTS)})
    m["api_paths"] = sorted({str(p) for p in all_paths if _hint_matches(str(p), API_PATH_HINTS)})
    for p in ev.get("discovered_endpoints", []):
        sp = str(p)
        if not _is_static_asset(sp) and _hint_matches(sp, API_PATH_HINTS):
            m["api_paths"].append(sp)
    m["api_paths"] = sorted(set(m["api_paths"]))

    # ── Recon detection results (passive) ─────────────────────────────────
    deser_ev = ev.get("deserialization_detection", {})
    if isinstance(deser_ev, dict) and deser_ev:
        m["deserialization_vectors"] = deser_ev.get("deserialization_vectors", [])
    else:
        m["deserialization_vectors"] = list(ev.get("deserialization_vectors", []))
    upload_ev = ev.get("upload_form_detection", {})
    if isinstance(upload_ev, dict) and upload_ev:
        m["upload_forms"] = upload_ev.get("upload_forms", [])
    else:
        m["upload_forms"] = list(ev.get("upload_forms", []))
    csrf_ev = ev.get("csrf_surface_detection", {})
    if isinstance(csrf_ev, dict) and csrf_ev:
        m["csrf_surface"] = csrf_ev.get("csrf_surface", [])
    else:
        m["csrf_surface"] = list(ev.get("csrf_surface", []))

    # ── Extended recon consumption ────────────────────────────────────────
    m["cookies"] = list(ev.get("cookies", []))
    m["dns_records"] = dict(ev.get("dns_records", {}))
    m["web_probes"] = list(ev.get("web_probes", []))
    m["s3_assets"] = list(ev.get("s3_assets", []))
    m["graphql_endpoints"] = list(ev.get("graphql_endpoints", []))
    m["robots_txt"] = dict(ev.get("robots_txt", {}))
    m["sensitive_endpoints"] = list(ev.get("sensitive_endpoints", []))
    m["session_findings"] = list(ev.get("session_findings", []))
    m["auth_flows"] = dict(ev.get("auth_flows", {}))
    m["posture"]["cert_info"] = dict(ev.get("cert_info", {}))

    # robots.txt often reveals internal API/S3 hosts and disallowed paths that
    # are otherwise invisible to crawling — surface them as map nodes.
    robots = m["robots_txt"]
    if robots:
        for h in robots.get("internal_hosts", []) or []:
            if h and h not in m["assets"]["subdomains"]:
                m["assets"]["subdomains"].append(h)
        for p in (robots.get("internal_apis", []) or []) + (robots.get("sitemaps", []) or []) \
                 + (robots.get("sensitive_paths", []) or []):
            if p and p not in m["endpoints"]:
                m["endpoints"].append(p)

    # GraphQL introspection endpoints are API endpoints by definition.
    for g in ev.get("graphql_endpoints", []):
        gu = str(g.get("url") or "")
        if gu and gu not in m["endpoints"]:
            m["endpoints"].append(gu)
        if gu:
            m["api_paths"].append(gu)
    m["api_paths"] = sorted(set(m["api_paths"]))
    m["auth_paths"] = sorted({str(p) for p in m["auth_paths"]})

    # The login URL identified by auth-flow analysis is a genuine auth surface.
    login_url = (ev.get("auth_flows") or {}).get("login_url") or ""
    if login_url and login_url not in m["auth_paths"]:
        m["auth_paths"].append(login_url)

    # Publicly-listable buckets are cloud assets — feed the cloud signal so the
    # cloud/container attack agent fires (and S3 findings surface in reports).
    for a in ev.get("s3_assets", []):
        b = a.get("bucket")
        if b and b not in sig["cloud"]:
            sig["cloud"].append(b)

    # Provenance
    m["provenance"] = {k: "recon" for k in (
        "subdomains", "services", "technologies", "endpoints", "posture") if m.get(k) or m["posture"]}

    m["completed_actions"] = list(ev.get("completed_actions", []))
    m["failed_actions"] = list(ev.get("failed_actions", []))
    m["zero_findings_actions"] = list(ev.get("zero_findings_actions", []))

    _build_links(m)
    return m


def _build_links(m: dict[str, Any]) -> None:
    """Create relational links between map nodes from raw evidence."""
    for svc in m["services"]:
        port = svc.get("port")
        if port in (80, 443, 8080, 8443):
            add_link(m, f"port:{port}", "web_surface", "serves_web", 80, "recon")
        if port in AD_INDICATOR_PORTS:
            add_link(m, f"port:{port}", "ad_signal", "ad_service", 75, "recon")
        if port in CONTAINER_INDICATOR_PORTS:
            add_link(m, f"port:{port}", "container_signal", "container_api", 75, "recon")
        if port in IOT_INDICATOR_PORTS:
            add_link(m, f"port:{port}", "iot_signal", "iot_service", 75, "recon")
    if m["signals"].get("cms"):
        add_link(m, "cms", "web_surface", "cms_hosts_site", 80, "recon")
    if m["auth_paths"]:
        add_link(m, "auth_paths", "auth_surface", "login_surface", 80, "recon")
    if m["api_paths"]:
        add_link(m, "api_paths", "api_surface", "api_surface", 80, "recon")
    for tech in m["technologies"]:
        name = (tech.get("name") or "").lower()
        if any(c in name for c in CLOUD_INDICATORS):
            add_link(m, f"tech:{name}", "cloud_signal", "cloud_indicator", 70, "recon")
    if m["posture"]["tls_vulnerabilities"] or m["posture"]["weak_ciphers"]:
        add_link(m, "tls", "posture", "tls_weakness", 70, "recon")
    if m["posture"]["missing_security_headers"]:
        add_link(m, "headers", "posture", "missing_security_headers", 70, "recon")


# ─────────────────────────────────────────────────────────────────────────────
# Hybrid planner rule engine (deterministic half)
# ─────────────────────────────────────────────────────────────────────────────

def derive_attack_surface(m: dict[str, Any]) -> dict[str, Any]:
    """
    Deterministic mapping: SystemMap nodes -> which attack agents are relevant.
    Returns {"mapped": bool, "agents": {name: {"reason", "priority", "skip"}}}.
    This is the rules half of the hybrid planner; the LLM refines it.
    """
    agents: dict[str, dict[str, Any]] = {}

    def add(name, reason, priority, skip=False):
        agents[name] = {"reason": reason, "priority": priority, "skip": skip}

    web_ports = {s.get("port") for s in m["services"] if s.get("port") in WEB_PORTS}
    has_web = bool(web_ports) or bool(m["web_surfaces"]) or bool(m["endpoints"])
    if has_web:
        tech = ", ".join(t.get("name", "") for t in m["technologies"][:6])
        reason = "Web surface present" + (f" — tech: {tech}" if tech else "")
        add("web_attack", reason, 1)

    # Burp Suite active scan — runs only when Burp Professional's REST API is
    # reachable (burp_scan.is_available()). Degrades to a clean skip when the
    # REST API is not available (e.g. Community edition / misconfigured).
    if has_web:
        _burp_avail = False
        try:
            from tools.attack.burp_scan import BurpScanTool
            _burp_avail = BurpScanTool().is_available()
        except Exception:  # noqa: BLE001
            _burp_avail = False
        if _burp_avail:
            add("burp", "Web surface present and Burp REST API available — run active scan", 1)
        else:
            add("burp", "Burp REST API unavailable (Professional required) — skip", 1, skip=True)

    non_web = {s.get("port") for s in m["services"] if s.get("port") not in WEB_PORTS}
    if non_web:
        add("network", f"Non-web ports open: {sorted(non_web)}", 2)

    if m["api_paths"] or m["signals"].get("api_types") or m.get("graphql_endpoints"):
        gql_note = f" ({len(m['graphql_endpoints'])} GraphQL introspection-enabled)" if m.get("graphql_endpoints") else ""
        add("api", f"API surface: {m['api_paths'][:5]}{gql_note}", 3)

    if m["auth_paths"]:
        add("auth", f"Auth surface: {m['auth_paths'][:5]}", 4)

    # infra always relevant when there's web posture
    if has_web and (m["posture"]["tls_vulnerabilities"] or m["posture"]["missing_security_headers"]
                    or m["posture"]["weak_ciphers"] or m["assets"]["subdomains"]):
        add("infra", "TLS/headers/DNS posture to assess", 5)

    if m["signals"].get("cloud") or m["signals"].get("container") or m.get("s3_assets"):
        add("cloud", f"Cloud/container signals: {m['signals']['cloud'][:5]}", 6)

    # Payload agent: situation-aware payload engineering + delivered proof.
    # Runs when there's any parameter or query-string injection surface, so
    # every category of injection gets a payload set built for ITS context.
    _query_surface = [str(p) for p in m.get("endpoints", []) if "?" in str(p)]
    if has_web and (m.get("endpoints") or m.get("parameters") or m.get("params")
                    or _query_surface):
        add("payload", f"Injection surface present ({len(_query_surface)} query "
                       f"endpoints, {len(m.get('parameters') or m.get('params') or [])} "
                       f"parameters) — engineer and deliver context-aware payloads "
                       f"with replays", 6)

    # Active Directory surface: signals from recon (port 88/389/445/636/3268/3269,
    # ldap_naming_contexts, windows_enum) mean the target is domain-joined. The
    # ad agent analyzes relationships AND tests cheap exploitable configurations
    # (AS-REP roast, Kerberoast, SMB null session) when the evidence supports it.
    sig = m.get("signals") or {}
    ad_signal = sig.get("ad") or (sig.get("ldap_naming_contexts")) or (sig.get("windows_enum"))
    ad_ports_hit = bool({s.get("port") for s in m.get("services", [])} & AD_INDICATOR_PORTS)
    if ad_signal or ad_ports_hit:
        add("ad", "AD domain surface detected — analyze relationships and test "
                  "AS-REP/Kerberoast/null-session exposure", 2)
    else:
        add("ad", "No Active Directory surface detected", 9, skip=True)

    # ── Expanded attack surface mapping ─────────────────────────────────
    if has_web and (m["endpoints"] or m["parameters"] or m.get("sensitive_endpoints")):
        add("web_fuzz", f"Endpoints/params present ({len(m['endpoints'])} endpoints, "
                        f"{len(m['parameters'])} params, "
                        f"{len(m.get('sensitive_endpoints', []))} sensitive) — fuzz for hidden content", 7)

    if has_web:
        add("headers_attack", "Check clickjacking, host-header, cache poisoning "
                              "and missing security headers", 8)

    tech_blob = " ".join(str(t.get("name", "")) for t in m["technologies"]).lower()
    waf_blob = tech_blob + " " + " ".join(
        str(h.get("name", "")) for h in m["web_surfaces"]).lower()
    waf_indicators = ["cloudfront", "cloudflare", "akamai", "fastly", "incapsula",
                      "sucuri", "waf", "awswaf", "shield", "cdn"]
    if has_web and any(ind in waf_blob for ind in waf_indicators):
        add("waf_bypass", "CDN/WAF detected — fingerprint and probe bypasses", 9)

    if m["assets"].get("subdomains"):
        add("subdomain_takeover", f"Subdomains present ({len(m['assets']['subdomains'])}) — "
                                  f"check takeover candidates", 10)

    api_blob = " ".join(str(x) for x in m["api_paths"] + m["js_endpoints"]).lower()
    if (m["api_paths"] or "jwt" in api_blob or "bearer" in api_blob
            or "token" in api_blob):
        add("jwt", "JWT/token surface present — stateless weakness checks", 11)

    # ── New attack surface mapping (XXE, CSRF, Deserialization) ──────────
    tech_blob = " ".join(t.get("name", "").lower() for t in m.get("technologies", [])).lower()
    ep_blob = " ".join(str(x) for x in m.get("endpoints", []) + m.get("api_paths", [])).lower()
    xml_signals = ["xml", "soap", "wsdl", ".net", "axis"]
    has_xml = any(kw in ep_blob or kw in tech_blob for kw in xml_signals)

    # Recon detection results drive the attack surface
    has_deser_vectors = bool(m.get("deserialization_vectors"))
    has_csrf_surface = bool(m.get("csrf_surface"))

    if has_web and has_xml:
        add("xxe", "XML-capable endpoints/technologies detected — test for XXE", 12)
    if has_csrf_surface:
        add("csrf", f"Recon detected {len(m['csrf_surface'])} CSRF-vulnerable forms", 13)
    if has_deser_vectors:
        add("deserialization", f"Recon detected {len(m['deserialization_vectors'])} deserialization vectors", 14)

    # skip rules
    if not m["api_paths"] and not m["signals"].get("api_types") and not m.get("graphql_endpoints"):
        add("api", "No API surface detected", 9, skip=True)
    if not m["auth_paths"]:
        add("auth", "No login/auth paths found", 9, skip=True)
    if not m["signals"].get("cloud") and not m["signals"].get("container") and not m.get("s3_assets"):
        add("cloud", "No cloud indicators", 9, skip=True)
    if not non_web:
        add("network", "Only standard web ports", 9, skip=True)
    if not has_xml and not has_web:
        add("xxe", "No XML endpoints or web surface", 12, skip=True)
    if not has_csrf_surface:
        add("csrf", "No CSRF-vulnerable forms detected by recon", 13, skip=True)
    if not has_deser_vectors:
        add("deserialization", "No deserialization vectors detected by recon", 14, skip=True)

    # Session hijacking: run if there are auth paths, cookies, or web surfaces
    has_auth_or_cookies = bool(m.get("auth_paths")) or bool(m.get("cookies"))
    if has_web:
        add("session_hijack", "Web surface present — test session management", 15)
    elif has_auth_or_cookies:
        add("session_hijack", "Auth paths or cookies present — test session management", 15)
    else:
        add("session_hijack", "No auth paths or session tokens", 15, skip=True)

    # Intermediate exploitation agents
    # NOTE: the full SystemMap stores parameter evidence under "parameters"
    # ("params" only exists on the LLM-compressed view) — read both or the
    # SSTI/LFI/SSRF exploit agents stay rule-skipped forever.
    params_blob = " ".join(str(p) for p in
                           (m.get("params") or []) + (m.get("parameters") or [])).lower()
    has_ssti_tech = any(t.get("name", "").lower() in ("jinja2", "twig", "smarty", "freemarker", "mako")
                        for t in m.get("technologies", []))
    has_file_param = any(kw in params_blob for kw in ("file", "include", "path", "page", "doc", "load"))
    has_ssrf_param = any(kw in params_blob for kw in ("url", "fetch", "webhook", "redirect", "proxy", "img"))
    endpoints_blob = " ".join(str(e) for e in m.get("endpoints", []) + m.get("js_endpoints", [])).lower()
    has_jwt_signal = any(kw in endpoints_blob for kw in ("jwt", "bearer", "token", "auth"))

    has_any_params = bool(m.get("params") or m.get("parameters"))

    if has_web and (has_any_params or has_ssti_tech):
        add("ssti_exploit", "Web surface with params or template engines — test for SSTI", 16)
    else:
        add("ssti_exploit", "No SSTI-relevant surface", 16, skip=True)

    if has_web and (has_any_params or has_file_param):
        add("lfi_exploit", "Web surface with file/path parameters — test for LFI", 17)
    else:
        add("lfi_exploit", "No LFI-relevant surface", 17, skip=True)

    if has_web and (has_any_params or has_ssrf_param):
        add("ssrf_exploit", "Web surface with URL/fetch parameters — test for SSRF", 18)
    else:
        add("ssrf_exploit", "No SSRF-relevant surface", 18, skip=True)

    # Reflected XSS exploitation: dalfox/nuclei detect reflection; xss_proof
    # *proves execution* in a headless browser. Both belong to OWASP A03.
    query_endpoints = [str(p) for p in m.get("endpoints", []) if "?" in str(p)]
    if has_web and (query_endpoints or m.get("parameters")):
        add("xss_exploit", f"Web surface with {len(query_endpoints)} query endpoint(s) "
                           "or parameters — prove reflected XSS execution (A03)", 17)
    else:
        add("xss_exploit", "No query-string surface to prove XSS on", 17, skip=True)

    if bool(m.get("auth_paths")) or bool(m.get("cookies")) or has_jwt_signal:
        add("jwt_exploit", "Auth surface or JWT indicators — test for JWT weaknesses", 19)
    else:
        add("jwt_exploit", "No JWT surface detected", 19, skip=True)

    # A04 Insecure Design — analysis-only review for business-logic/design flaws.
    if has_web or m.get("endpoints") or m.get("api_paths"):
        add("insecure_design", "Web/API surface present — review for insecure design (A04)", 20)
    else:
        add("insecure_design", "No web/API surface to review", 20, skip=True)

    return {"mapped": True, "agents": agents}


# ─────────────────────────────────────────────────────────────────────────────
# Compression for LLM consumption
# ─────────────────────────────────────────────────────────────────────────────

def _as_entry_list(value) -> list:
    """Normalize a posture/scan field that some builders write as a dict of
    {id: {...}} and others as a plain list of names. Returns a list of entry
    strings so downstream readers never crash on .keys() of a list."""
    if value is None:
        return []
    if isinstance(value, dict):
        return list(value.keys())
    if isinstance(value, list):
        return [str(v.get("id", v)) if isinstance(v, dict) else str(v) for v in value]
    return [str(value)]


def _format_params(params: list, limit: int = 30) -> list:
    """Render parameter evidence as injectable URL strings.

    Dict entries ({"url","name","in"}) become "url?name=1" for query params;
    plain strings are kept when they look like "http...?param=1" (arjun output).
    Body params stay accessible via the full SystemMap (smap['parameters']).
    """
    out = []
    for p in params or []:
        if isinstance(p, dict):
            url, name = p.get("url") or "", p.get("name") or ""
            if url and name and name not in url:
                out.append(f"{url}{'&' if '?' in url else '?'}{name}=1")
        else:
            s = str(p)
            if s.startswith("http") and "=" in s:
                out.append(s)
    return sorted(dict.fromkeys(out))[:limit]


def compress_for_llm(
    m: dict[str, Any], max_tech: int = 12, max_paths: int = 20) -> dict[str, Any]:
    """Small, relevant view of the map for planner/agent prompts."""
    c: dict[str, Any] = {
        "target": m.get("target"),
        "resolved_ip": m["assets"].get("resolved_ip"),
        "reachable": m["assets"].get("reachable"),
        "subdomains": m["assets"].get("subdomains", [])[:15],
        "services": [s for s in m.get("services", []) if s.get("port")][:15],
        "technologies": [f"{t.get('name','')} {t.get('version','')}".strip()
                         for t in m.get("technologies", [])][:max_tech],
        "cms": m["signals"].get("cms"),
        "cms_version": m["signals"].get("cms_version"),
        "api_paths": m.get("api_paths", [])[:max_paths],
        "auth_paths": m.get("auth_paths", [])[:max_paths],
        "endpoints": m.get("endpoints", [])[:max_paths],
        "params": _format_params(m.get("parameters", [])),
        "missing_security_headers": m["posture"].get("missing_security_headers", [])[:8],
        "tls_vulnerabilities": _as_entry_list(m["posture"].get("tls_vulnerabilities", []))[:8],
        "weak_ciphers": len(m["posture"].get("weak_ciphers", [])),
        "signals": {k: v for k, v in m.get("signals", {}).items() if v
                    and k not in ("ldap_naming_contexts", "windows_enum")},
        "links": m.get("links", [])[:20],
        "completed_actions": m.get("completed_actions", [])[-8:],
        "failed_actions": m.get("failed_actions", [])[-8:],
    }
    return c
