"""
Tracks accumulated evidence for a target across multiple planner/tool
iterations, and persists it to disk so a session can be paused and resumed.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from tools.base import ToolResult

STORE_DIR = Path(__file__).parent / "results" / "evidence"
DECISION_LOG_PATH = Path(__file__).parent / "results" / "decision_log.jsonl"

# Recon evidence older than this (days) is treated as stale for a live target:
# its services/technologies/endpoints most likely describe a past incarnation
# of the host and would poison a fresh engagement (certifiedhacker.com's
# 24-day-old map pointed agents at dead admin.php/reset.php surfaces).
STALE_EVIDENCE_DAYS = 7


def _path_for(target: str) -> Path:
    safe_name = target.replace("/", "_").replace(":", "_")
    return STORE_DIR / f"{safe_name}.json"


def path_for(target: str) -> Path:
    return _path_for(target)


def file_age_days(path: Path) -> Optional[float]:
    """Age in days of a stored evidence/system-map file, or None if absent."""
    try:
        return (time.time() - path.stat().st_mtime) / 86400.0
    except (OSError, AttributeError):
        return None


def is_stale(target: str, max_age_days: float = STALE_EVIDENCE_DAYS) -> bool:
    """True when a stored evidence file is too old to trust for a live target."""
    age = file_age_days(_path_for(target))
    return age is not None and age > max_age_days


def _richest_logged_evidence(target: str) -> Dict[str, Any] | None:
    """
    decision_log.jsonl is append-only and never resets, so it can outlive a
    corrupted/overwritten/lost evidence file. Scan it for the evidence
    snapshot with the most completed_actions ever recorded for this target
    -- that's the most complete picture we've ever had, regardless of which
    session produced it.
    """
    if not DECISION_LOG_PATH.exists():
        return None

    best, best_count = None, -1
    with open(DECISION_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("target") != target:
                continue
            ev = entry.get("evidence") or {}
            count = len(ev.get("completed_actions", []))
            if count > best_count:
                best_count, best = count, ev
    return best


def _empty_evidence(target: str, authorized_scope: bool = True,
                    target_type: str = "domain") -> Dict[str, Any]:
    return {
        "target": target,
        "authorized_scope": authorized_scope,
        "target_type": target_type,
        "reachable": None,
        "open_ports": [],
        "services": [],
        "technologies": [],
        "completed_actions": [],
        "failed_actions": [],
        "zero_findings_actions": [],
        "previous_observations": [],
        "subdomains": [],
        "subdomain_resolutions": {},
        "failure_patterns": {},
        "active_subtarget": None,
        "subtarget_parent": None,
        "subtarget_results": {},
    }


def fresh(target: str, authorized_scope: bool = True,
          target_type: str = "domain") -> Dict[str, Any]:
    """A clean evidence dict with no history — used to discard stale recon
    data instead of letting an old incarnation poison a live engagement."""
    return _empty_evidence(target, authorized_scope, target_type)


def load(target: str, authorized_scope: bool = True, target_type: str = "domain",
         warn_on_regression: bool = True) -> Dict[str, Any]:
    path = _path_for(target)
    if path.exists():
        current = json.loads(path.read_text(encoding="utf-8"))
    else:
        current = _empty_evidence(target, authorized_scope, target_type)

    if warn_on_regression:
        richest = _richest_logged_evidence(target)
        current_count = len(current.get("completed_actions", []))
        richest_count = len(richest.get("completed_actions", [])) if richest else 0
        if richest and richest_count > current_count:
            missing = sorted(set(richest["completed_actions"]) - set(current.get("completed_actions", [])))
            print(f"\n[evidence_store] WARNING: results/decision_log.jsonl records a richer prior session "
                  f"for '{target}' ({richest_count} completed actions) than the saved evidence file "
                  f"({current_count}). Actions missing from the current file: {missing}.")
            resp = input("Restore the richer evidence from the decision log before continuing? [y/N]: ").strip().lower()
            if resp in ("y", "yes"):
                save(richest)
                print("Restored evidence from decision log.\n")
                return richest
            print("Continuing with the evidence file as-is.\n")

    return current


def save(evidence: Dict[str, Any]) -> None:
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    evidence.setdefault("saved_at", datetime.now(timezone.utc).isoformat())
    _path_for(evidence["target"]).write_text(json.dumps(evidence, indent=2), encoding="utf-8")


def merge_tool_result(evidence: Dict[str, Any], result: ToolResult) -> Dict[str, Any]:
    """Fold a tool's findings into the running evidence dict."""
    r = result.results or {}

    if "open_ports" in r:
        evidence["open_ports"] = sorted(set(evidence.get("open_ports", [])) | set(r["open_ports"]))
    if "services" in r:
        evidence["services"] = list(dict.fromkeys(evidence.get("services", []) + r["services"]))
    if "technologies" in r:
        evidence["technologies"] = list(dict.fromkeys(evidence.get("technologies", []) + r["technologies"]))
    if "subdomains" in r:
        evidence["subdomains"] = list(dict.fromkeys(evidence.get("subdomains", []) + r["subdomains"]))
    if "reachable" in r:
        evidence["reachable"] = r["reachable"]
    if "resolved_ip" in r:
        evidence["resolved_ip"] = r["resolved_ip"]
    if "subdomain_resolutions" in r:
        sr = evidence.setdefault("subdomain_resolutions", {})
        sr.update(r["subdomain_resolutions"])
    if "discovered_urls" in r:
        evidence["discovered_urls"] = list(dict.fromkeys(
            evidence.get("discovered_urls", []) + r["discovered_urls"]))
    if "discovered_paths" in r:
        evidence["discovered_paths"] = evidence.get("discovered_paths", []) + r["discovered_paths"]
    if "discovered_parameters" in r:
        # dict-shaped entries (e.g. OpenAPI body params) are unhashable for
        # dict.fromkeys; dedupe on a JSON key while preserving order.
        merged = evidence.get("discovered_parameters", [])
        seen = {x if isinstance(x, str) else json.dumps(x, sort_keys=True)
                for x in merged}
        for item in r["discovered_parameters"]:
            key = item if isinstance(item, str) else json.dumps(item, sort_keys=True)
            if key not in seen:
                seen.add(key)
                merged.append(item)
        evidence["discovered_parameters"] = merged[:120]
    if "port_details" in r:
        existing = {d["port"]: d for d in evidence.get("port_details", [])}
        for d in r["port_details"]:
            existing[d["port"]] = d
        evidence["port_details"] = sorted(existing.values(), key=lambda d: d["port"])
    if "os_guesses" in r:
        evidence["os_guesses"] = r["os_guesses"]
    if "js_endpoints" in r:
        evidence["js_endpoints"] = list(dict.fromkeys(
            evidence.get("js_endpoints", []) + r["js_endpoints"]))
    if "historical_urls" in r:
        evidence["historical_urls"] = list(dict.fromkeys(
            evidence.get("historical_urls", []) + r["historical_urls"]))
    if "discovered_endpoints" in r:
        evidence["discovered_endpoints"] = evidence.get("discovered_endpoints", []) + r["discovered_endpoints"]
    if "detected_api_types" in r:
        evidence["detected_api_types"] = list(dict.fromkeys(
            evidence.get("detected_api_types", []) + r["detected_api_types"]))
    if r.get("cms_detected"):
        evidence["cms_detected"] = r["cms_detected"]
    if "cms_signals" in r:
        evidence["cms_signals"] = list(dict.fromkeys(evidence.get("cms_signals", []) + r["cms_signals"]))
    if r.get("cms_version"):
        evidence["cms_version"] = r["cms_version"]
    if "cms_assessment" in r:
        evidence["cms_assessment"] = r["cms_assessment"]
    if "cms_assessment_skipped" in r:
        evidence["cms_assessment_skipped"] = r["cms_assessment_skipped"]
    if "screenshot_captured" in r:
        evidence["screenshot_captured"] = r["screenshot_captured"]
    if r.get("screenshot_path"):
        evidence["screenshot_path"] = r["screenshot_path"]
    if r.get("screenshot_paths"):
        evidence["screenshot_paths"] = list(dict.fromkeys(
            evidence.get("screenshot_paths", []) + r["screenshot_paths"]))
    if r.get("screenshots"):
        evidence["screenshots"] = evidence.get("screenshots", []) + r["screenshots"]
    if "ldap_naming_contexts" in r:
        evidence["ldap_naming_contexts"] = r["ldap_naming_contexts"]
    if "ldap_root_dse" in r:
        evidence["ldap_root_dse"] = r["ldap_root_dse"]
    if "windows_enum" in r:
        evidence["windows_enum"] = r["windows_enum"]
    for _ldap_key in ("ldap_domain", "ldap_users", "ldap_groups", "ldap_computers",
                      "ldap_kerberoastable", "ldap_asrep_roastable"):
        if _ldap_key in r:
            evidence[_ldap_key] = r[_ldap_key]
    if "cloud_assets_found" in r:
        evidence["cloud_assets_found"] = evidence.get("cloud_assets_found", []) + r["cloud_assets_found"]
    if "container_apis_found" in r:
        evidence["container_apis_found"] = r["container_apis_found"]
    if "iot_services_found" in r:
        evidence["iot_services_found"] = r["iot_services_found"]
    if "protocol" in r:
        evidence["protocol"] = r["protocol"]
    if "cipher" in r:
        evidence["cipher"] = r["cipher"]
    if "verify_return_code" in r:
        evidence["verify_return_code"] = r["verify_return_code"]
    if "cert_not_before" in r:
        evidence["cert_not_before"] = r["cert_not_before"]
    if "cert_not_after" in r:
        evidence["cert_not_after"] = r["cert_not_after"]
    if "cert_days_until_expiry" in r:
        evidence["cert_days_until_expiry"] = r["cert_days_until_expiry"]
    if "cert_subject" in r:
        evidence["cert_subject"] = r["cert_subject"]
    if "cert_issuer" in r:
        evidence["cert_issuer"] = r["cert_issuer"]
    if "tls_findings" in r:
        evidence["tls_findings"] = list(dict.fromkeys(evidence.get("tls_findings", []) + r["tls_findings"]))
    # testssl.sh structured results — store full results dict for report generation
    # The testssl tool returns flat keys (tls_findings, protocols, vulnerabilities, etc.)
    # not nested under "testssl_results". Store the full result when TLS-related keys exist.
    has_testssl_data = any(k in r for k in ("tls_findings", "protocols", "vulnerabilities", "certificate"))
    if has_testssl_data and result.tool == "testssl":
        evidence["testssl_results"] = r
        # Remove from zero_findings if testssl found actual vulnerabilities
        if r.get("tls_findings") or r.get("vulnerabilities"):
            zf = evidence.get("zero_findings_actions", [])
            if result.capability in zf:
                zf.remove(result.capability)
    elif "testssl_results" in r:
        evidence["testssl_results"] = r["testssl_results"]
    if "protocols" in r and isinstance(r["protocols"], dict):
        # Merge protocol info from testssl into evidence
        existing_protos = evidence.get("tls_protocols", {})
        existing_protos.update(r["protocols"])
        evidence["tls_protocols"] = existing_protos
    if "weak_ciphers" in r and isinstance(r["weak_ciphers"], list):
        existing_wc = evidence.get("weak_ciphers", [])
        existing_wc.extend(r["weak_ciphers"])
        evidence["weak_ciphers"] = existing_wc
    if "vulnerabilities" in r and isinstance(r["vulnerabilities"], dict):
        # Merge vuln info from testssl
        existing_vulns = evidence.get("tls_vulnerabilities", {})
        existing_vulns.update(r["vulnerabilities"])
        evidence["tls_vulnerabilities"] = existing_vulns
    if "certificate" in r and isinstance(r["certificate"], dict):
        existing_cert = evidence.get("tls_certificate", {})
        existing_cert.update(r["certificate"])
        evidence["tls_certificate"] = existing_cert
    if "response_headers" in r:
        evidence["response_headers"] = r["response_headers"]
    if "missing_security_headers" in r:
        evidence["missing_security_headers"] = r["missing_security_headers"]
    if "info_disclosure_headers" in r:
        evidence["info_disclosure_headers"] = r["info_disclosure_headers"]
    if "header_findings" in r:
        evidence["header_findings"] = list(dict.fromkeys(
            evidence.get("header_findings", []) + r["header_findings"]))

    # ── Extended recon folding (ensures every capability's output survives) ──
    # DNS_ENUMERATION: dns_enum returns {"dns_records": {rtype: [answers]}}
    if "dns_records" in r and isinstance(r["dns_records"], dict):
        dns = evidence.setdefault("dns_records", {})
        for rtype, answers in r["dns_records"].items():
            if isinstance(answers, list):
                dns[rtype] = sorted(set(dns.get(rtype, []) + answers))
        evidence["dns_records"] = dns

    # WEB_PROBING: httpx returns {"probes": [{url, status_code, title, webserver}]},
    # which enriches web_surfaces with real status/title/server data.
    if "probes" in r and isinstance(r["probes"], list):
        probes_by_url = {str(p.get("url")): p for p in evidence.get("web_probes", []) if p.get("url")}
        for p in r["probes"]:
            if p.get("url"):
                probes_by_url[str(p["url"])] = p
        evidence["web_probes"] = list(probes_by_url.values())

    # S3_LIST: s3_enum returns {"s3_assets": [{bucket, public_downloads, ...}]}
    if "s3_assets" in r and isinstance(r["s3_assets"], list):
        assets_by_bucket = {str(a.get("bucket")): a
                            for a in evidence.get("s3_assets", []) if a.get("bucket")}
        for a in r["s3_assets"]:
            if a.get("bucket"):
                assets_by_bucket[str(a["bucket"])] = a
        evidence["s3_assets"] = list(assets_by_bucket.values())

    # Passive detection caps: persist both the nested dict the SystemMap builder
    # reads and a flat key so zero-findings/agent consumers can see the data.
    if "deserialization_vectors" in r:
        evidence["deserialization_detection"] = {
            "deserialization_vectors": r["deserialization_vectors"],
            "count": r.get("count", len(r["deserialization_vectors"])),
            "tested_urls": r.get("tested_urls", []),
        }
        evidence["deserialization_vectors"] = r["deserialization_vectors"]
    if "upload_forms" in r:
        evidence["upload_form_detection"] = {
            "upload_forms": r["upload_forms"],
            "count": r.get("count", len(r["upload_forms"])),
            "tested_urls": r.get("tested_urls", []),
        }
        evidence["upload_forms"] = r["upload_forms"]
    if "csrf_surface" in r:
        evidence["csrf_surface_detection"] = {
            "csrf_surface": r["csrf_surface"],
            "count": r.get("count", len(r["csrf_surface"])),
            "tested_urls": r.get("tested_urls", []),
        }
        evidence["csrf_surface"] = r["csrf_surface"]

    # COOKIE_ANALYSIS: cookie_analyzer returns {"cookies": [{name, flags, issues}]}
    if "cookies" in r and isinstance(r["cookies"], list):
        cookies_by_name = {str(c.get("name")): c
                           for c in evidence.get("cookies", []) if c.get("name")}
        for c in r["cookies"]:
            if c.get("name"):
                cookies_by_name[str(c["name"])] = c
        evidence["cookies"] = list(cookies_by_name.values())
        if r.get("insecure_cookies"):
            evidence["insecure_cookies"] = list(dict.fromkeys(
                evidence.get("insecure_cookies", []) + r["insecure_cookies"]))

    # GRAPHQL_INTROSPECTION: {"endpoints": [{url, type_count, ...}]}; the
    # endpoint URLs also count as discovered API endpoints.
    if "endpoints" in r and isinstance(r["endpoints"], list) and r["endpoints"]:
        gql_by_url = {str(e.get("url")): e
                      for e in evidence.get("graphql_endpoints", []) if e.get("url")}
        for e in r["endpoints"]:
            if e.get("url"):
                gql_by_url[str(e["url"])] = e
        evidence["graphql_endpoints"] = list(gql_by_url.values())
        gql_urls = [e.get("url") for e in r["endpoints"] if e.get("url")]
        if gql_urls:
            evidence["discovered_endpoints"] = evidence.get("discovered_endpoints", []) + gql_urls

    # ROBOTS_TXT_ANALYSIS: robots_txt_parser returns a flat parse dict.
    if "disallowed_paths" in r or "sitemaps" in r or "internal_apis" in r:
        evidence["robots_txt"] = dict(r)

    # CERT_INFO: cert_info returns subject/issuer/sans/days_until_expiry/etc.
    # Alias the tool's key names onto the canonical cert_* evidence keys the
    # SystemMap/TLS posture already understands.
    if any(k in r for k in ("subject", "sans", "days_until_expiry", "serial", "issues")):
        evidence["cert_info"] = {
            "subject": r.get("subject"),
            "issuer": r.get("issuer"),
            "sans": r.get("sans", []),
            "san_count": r.get("san_count", len(r.get("sans", []))),
            "not_before": r.get("not_before"),
            "not_after": r.get("not_after"),
            "days_until_expiry": r.get("days_until_expiry"),
            "protocol": r.get("protocol"),
            "cipher": r.get("cipher"),
            "cipher_bits": r.get("cipher_bits"),
            "version": r.get("version"),
            "serial": r.get("serial"),
            "issues": r.get("issues", []),
            "severity": r.get("severity", "INFO"),
        }
        for _src, _dst in (("subject", "cert_subject"), ("issuer", "cert_issuer"),
                           ("not_before", "cert_not_before"), ("not_after", "cert_not_after"),
                           ("days_until_expiry", "cert_days_until_expiry")):
            if _src in r:
                evidence[_dst] = r[_src]

    # SENSITIVE_ENDPOINT_DETECTION: sensitive_endpoint_detect returns
    # {"found": [{path, status, severity, description}]}
    if isinstance(r.get("found"), list):
        se_by_path = {str(f.get("path")): f
                      for f in evidence.get("sensitive_endpoints", []) if f.get("path")}
        for f in r["found"]:
            if f.get("path"):
                se_by_path[str(f["path"])] = f
        evidence["sensitive_endpoints"] = list(se_by_path.values())

    # SESSION_ANALYSIS: session_analyzer returns {"sessions": [{token_name, risk}]}
    if "sessions" in r and isinstance(r["sessions"], list):
        evidence["session_findings"] = evidence.get("session_findings", []) + r["sessions"]
        if r.get("risky_count") is not None:
            evidence["session_risky_count"] = r["risky_count"]
        if r.get("high_risk_tokens"):
            evidence["session_high_risk_tokens"] = r["high_risk_tokens"]

    # AUTH_FLOW_ANALYSIS: auth_flow_analysis returns auth_results/login_url/etc.
    if "auth_results" in r or "login_url" in r:
        evidence["auth_flows"] = {
            "auth_results": r.get("auth_results", []),
            "login_url": r.get("login_url", ""),
            "mechanisms": r.get("mechanisms", []),
            "mfa_detected": bool(r.get("mfa_detected")),
            "rate_limited": bool(r.get("rate_limited")),
            "csrf_protected": bool(r.get("csrf_protected")),
        }

    if result.status == "success":
        if result.capability not in evidence["completed_actions"]:
            evidence["completed_actions"].append(result.capability)
        evidence["previous_observations"].append(
            f"{result.tool} ({result.capability}) succeeded: {json.dumps(r)[:100]}"
        )

        # Track capabilities that returned zero useful findings to prevent loops
        zero_findings = evidence.setdefault("zero_findings_actions", [])
        found_something = False
        for key in ("subdomains", "open_ports", "services", "technologies", "resolved_ip",
                     "reachable", "discovered_urls", "discovered_paths", "dns_records",
                     "web_probes", "s3_assets", "deserialization_vectors", "upload_forms",
                     "csrf_surface", "cookies", "graphql_endpoints", "robots_txt",
                     "sensitive_endpoints", "session_findings", "auth_flows", "cert_info",
                     # tool-facing keys (the tuple is inspected against r, the raw
                     # tool result, so the tool's own key names must be here too)
                     "probes", "endpoints", "sessions", "auth_results", "login_url",
                     "disallowed_paths", "sitemaps", "internal_apis", "found",
                     "subject", "issues", "serial",
                     "screenshot_captured", "protocol", "response_headers",
                     "tls_findings", "tls_vulnerabilities", "weak_ciphers",
                     "tls_certificate", "tls_protocols", "testssl_results"):
            val = r.get(key)
            if val and val != [] and val != {}:
                found_something = True
                break
        if not found_something and result.capability not in zero_findings:
            zero_findings.append(result.capability)
    else:
        if result.capability not in evidence["failed_actions"]:
            evidence["failed_actions"].append(result.capability)
        evidence["previous_observations"].append(
            f"{result.tool} ({result.capability}) failed: {result.error}"
        )

        # Track failure patterns for intelligence: count failures, record errors
        if result.status in ("error", "timeout"):
            fp = evidence.setdefault("failure_patterns", {})
            cap = result.capability
            if cap not in fp:
                fp[cap] = {"count": 0, "errors": [], "targets_tested": []}
            fp[cap]["count"] += 1
            if result.error and result.error[:100] not in fp[cap]["errors"]:
                fp[cap]["errors"].append(result.error[:100])
            tgt = evidence.get("target", "")
            if tgt and tgt not in fp[cap]["targets_tested"]:
                fp[cap]["targets_tested"].append(tgt)

    return evidence
