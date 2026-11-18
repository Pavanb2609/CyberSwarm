"""
planner_policy.py -- deterministic policy layer around the LLM recon planner.

Why this exists
---------------
The recon planner prompt lists ~40 rules. A small local model follows most of
them most of the time, which is how the benchmark landed at 53% full-pass. The
rules that are *mechanical* (scope, "never repeat a completed action",
"TLS before stopping on an HTTPS target", "don't run AD enumeration without
Kerberos/LDAP/SMB evidence") don't need judgement, so they are enforced here in
code. The model is left to make the calls that genuinely need it.

Three pieces:

* ``rules_decision(evidence)``   -- a complete, deterministic planner that walks
  the prompt's DECISION PRIORITY ladder. Used as the fallback when the model
  is unreachable or returns invalid JSON twice, and as a baseline in the
  benchmark (``run_benchmark.py --rules-only``).
* ``apply_guardrails(evidence, decision)`` -- post-checks an LLM decision and
  replaces it only when it breaks a hard rule. Every correction is recorded,
  so the decision log shows what the model picked and why it was changed.
* ``plan(client, system_prompt, evidence, user_prompt)`` -- the full pipeline:
  structured-output call -> validate -> one repair retry with the errors fed
  back -> rules fallback -> guardrails.

Everything here is a pure function over the evidence dict, so it is fully
testable without a model, tools or network.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from typing import Any

from schema.validator import decision_json_schema, validate_decision

HTTPS_PORTS = {443, 8443, 9443}
WEB_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888, 9443, 3000, 5000}

TERMINAL = {"STOP_NO_RELEVANT_ACTION", "BLOCK_EXECUTION"}
PAUSE = {"REQUEST_ADDITIONAL_EVIDENCE", "REQUEST_AUTHORIZED_CREDENTIALS", "VERIFY_SCOPE"}
PIVOT = {"PIVOT_TO_SUBDOMAIN", "RETURN_FROM_SUBDOMAIN"}
NON_REPEATABLE_EXEMPT = TERMINAL | PAUSE | PIVOT

CMS_WORDS = ("wordpress", "drupal", "joomla", "magento", "ghost", "typo3")
SPA_WORDS = ("react", "angular", "vue", "next.js", "nuxt", "svelte", "ember")
CDN_WORDS = ("cloudflare", "akamai", "cloudfront", "fastly", "imperva", "incapsula", "sucuri")
CLOUD_WORDS = ("aws", "amazon web services", "s3", "azure", "blob.core", "gcp",
               "google cloud", "storage.googleapis")
CONTAINER_WORDS = ("docker", "kubernetes", "k8s", "kubelet", "etcd", "containerd", "openshift")
IOT_WORDS = ("mqtt", "coap", "upnp", "rtsp", "modbus", "bacnet")
OS_WORDS_LINUX = ("linux", "ubuntu", "debian", "centos", "red hat", "rhel", "fedora", "alpine")
OS_WORDS_WINDOWS = ("windows", "microsoft-iis", "iis/")

# Capabilities that need specific evidence before they are allowed at all
# (mirrors the "Architecture-specific capabilities" rule in the prompt).
ARCH_REQUIREMENTS = {
    "DIRECTORY_SERVICE_ENUMERATION": "ad_signals",
    "WINDOWS_SERVICE_ENUMERATION": "ad_signals",
    "CLOUD_ASSET_DISCOVERY": "cloud",
    "CONTAINER_DISCOVERY": "container",
    "IOT_SERVICE_IDENTIFICATION": "iot",
    "CMS_ASSESSMENT": "cms",
}


# ── evidence facts ──────────────────────────────────────────────────────────

def _lower_blob(items: Iterable[Any]) -> str:
    out = []
    for x in items or []:
        out.append(json.dumps(x).lower() if isinstance(x, (dict, list)) else str(x).lower())
    return " | ".join(out)


def _ports(evidence: dict[str, Any]) -> set:
    ports = set()
    for p in evidence.get("open_ports") or []:
        try:
            ports.add(int(str(p).split("/")[0]))
        except (TypeError, ValueError):
            continue
    return ports


class Facts:
    """Normalised view of the evidence the rules reason over."""

    def __init__(self, evidence: dict[str, Any]):
        ev = evidence or {}
        self.ev = ev
        self.scope = ev.get("authorized_scope", None)
        self.target_type = str(ev.get("target_type") or "").lower()
        self.reachable = ev.get("reachable", None)
        self.ports = _ports(ev)
        self.completed = set(ev.get("completed_actions") or [])
        self.zero = set(ev.get("zero_findings_actions") or [])
        self.failed = set(ev.get("failed_actions") or [])
        # A capability that failed 3+ times across targets (timeouts, refused
        # connections) is treated as done -- the prompt's FAILURE PATTERN rule.
        self.chronic_failures = {
            cap for cap, info in (ev.get("failure_patterns") or {}).items()
            if isinstance(info, dict) and int(info.get("count") or 0) >= 3}
        self.done = self.completed | self.zero | self.failed | self.chronic_failures

        tech = _lower_blob(ev.get("technologies"))
        svc = _lower_blob(ev.get("services"))
        obs = _lower_blob(ev.get("previous_observations"))
        self.tech, self.svc, self.obs = tech, svc, obs
        everything = " | ".join((tech, svc, obs, str(ev.get("cms_detected") or "").lower()))

        self.has_services = bool(ev.get("services"))
        self.https = bool(self.ports & HTTPS_PORTS) or "https" in svc or any(
            str(u).lower().startswith("https://")
            for u in (ev.get("discovered_urls") or []) + (ev.get("web_urls") or []))
        self.web = bool(self.ports & WEB_PORTS) or "http" in svc or self.https
        self.cms = bool(ev.get("cms_detected")) or any(w in tech for w in CMS_WORDS)
        self.graphql = "graphql" in everything or "GRAPHQL_API" in (ev.get("detected_api_types") or [])
        self.openapi = any(w in everything for w in ("swagger", "openapi"))
        self.spa = any(w in tech for w in SPA_WORDS)
        self.cdn = any(w in tech for w in CDN_WORDS)
        self.cloud = any(w in tech or w in obs for w in CLOUD_WORDS)
        self.container = any(w in tech or w in svc for w in CONTAINER_WORDS) or bool(
            self.ports & {2375, 2376, 6443, 10250})
        self.iot = any(w in svc or w in tech for w in IOT_WORDS) or bool(self.ports & {1883, 5683, 1900})
        ad_hits = sum((88 in self.ports or "kerberos" in svc,
                       389 in self.ports or 636 in self.ports or "ldap" in svc,
                       445 in self.ports or "smb" in svc or "microsoft-ds" in svc))
        self.ad_signals = ad_hits >= 1
        self.active_directory = ad_hits >= 3
        self.smb = 445 in self.ports or 139 in self.ports or "smb" in svc \
            or "microsoft-ds" in svc or "samba" in tech
        self.ldap = 389 in self.ports or 636 in self.ports or "ldap" in svc
        self.mail = bool(self.ports & {25, 465, 587, 993, 995, 110, 143}) and any(
            w in tech or w in svc for w in ("postfix", "exchange", "zimbra", "exim",
                                            "sendmail", "smtp", "imap", "pop3"))
        self.grafana = "grafana" in tech
        self.auth_required = bool(ev.get("auth_required"))
        self.creds_supplied = bool(ev.get("approved_credentials_supplied"))
        self.os_linux = bool(ev.get("os_detected") or ev.get("os")) and any(
            w in str(ev.get("os_detected") or ev.get("os")).lower() for w in OS_WORDS_LINUX)
        self.os_windows = (bool(ev.get("os_detected") or ev.get("os")) and any(
            w in str(ev.get("os_detected") or ev.get("os")).lower() for w in OS_WORDS_WINDOWS)) \
            or "windows server" in tech
        self.os_evidence = bool(ev.get("os_detected") or ev.get("os")) or \
            "OPERATING_SYSTEM_IDENTIFICATION" in self.completed
        self.subdomains_exhausted = bool(ev.get("subdomains_exhausted"))

    def has(self, requirement: str) -> bool:
        return bool(getattr(self, requirement, False))


def classify_profile(f: Facts) -> str:
    if f.scope is False:
        return "OUT_OF_SCOPE"
    if f.reachable is False and not f.ports:
        return "UNREACHABLE"
    if f.active_directory:
        return "ACTIVE_DIRECTORY"
    if f.cms:
        return "CMS"
    if f.graphql:
        return "GRAPHQL_API"
    if f.openapi:
        return "REST_API"
    if f.auth_required:
        return "AUTHENTICATED_WEB_APPLICATION"
    if f.spa:
        return "SINGLE_PAGE_APPLICATION"
    if f.container:
        return "KUBERNETES" if "kubernetes" in f.tech or 6443 in f.ports else "CONTAINER_PLATFORM"
    if f.iot:
        return "IOT"
    if f.mail:
        return "MAIL_INFRASTRUCTURE"
    if f.web and (f.has_services or f.ev.get("technologies")):
        return "WEB_APPLICATION"
    if f.os_evidence and f.os_windows:
        return "WINDOWS_HOST"
    if f.os_evidence and f.os_linux:
        return "LINUX_HOST"
    if f.target_type == "domain" and not f.ports:
        return "DOMAIN"
    return "UNKNOWN"


# ── deterministic planner ───────────────────────────────────────────────────

def _decision(cap: str, profile: str, reason: str, conf: float = 0.8,
              missing: list[str] | None = None, **extra) -> dict[str, Any]:
    d = {
        "target_profile": profile,
        "next_capability": cap,
        "confidence": conf,
        "evidence_used": [],
        "missing_evidence": missing or [],
        "reason": f"[rules] {reason}",
        "requires_human_approval": cap not in TERMINAL | PAUSE,
        "decided_by": "rules",
    }
    d.update(extra)
    return d


def mandatory_before_stop(f: Facts) -> list[str]:
    """Capabilities the prompt says must run before STOP on this target."""
    req: list[str] = []
    if f.https and "TLS_ANALYSIS" not in f.done:
        req.append("TLS_ANALYSIS")
    if f.web and not f.cdn and "HEADER_ANALYSIS" not in f.done:
        req.append("HEADER_ANALYSIS")
    if f.web and "SCREENSHOT_CAPTURE" not in f.done and (
            "CONTENT_DISCOVERY" in f.done or f.cdn):
        req.append("SCREENSHOT_CAPTURE")
    return req


def _ladder(f: Facts) -> list[tuple[str, str]]:
    """Ordered (capability, why) candidates per the prompt's DECISION PRIORITY."""
    L: list[tuple[str, str]] = []
    early = not f.ports and not f.has_services
    if f.target_type == "domain" and early:
        L += [("PASSIVE_ASSET_DISCOVERY", "fresh domain, no assets known yet"),
              ("SUBDOMAIN_DISCOVERY", "fresh domain, no subdomains known yet"),
              ("DNS_RESOLUTION", "domain not resolved yet")]
    if early and f.reachable is None:
        L.append(("HOST_DISCOVERY", "host status unknown"))
    if not f.ports:
        L.append(("PORT_DISCOVERY", "host reachable but open ports unknown"))
    if f.ports and not f.has_services:
        L.append(("SERVICE_DETECTION", "ports known but services unknown"))
    if f.auth_required and not f.creds_supplied and f.web:
        L.append(("REQUEST_AUTHORIZED_CREDENTIALS",
                  "authentication required and no approved credentials supplied"))
    if f.web and "WEB_TECHNOLOGY_DISCOVERY" not in f.done:
        if not f.ev.get("technologies") and "WEB_PROBING" not in f.done:
            L.append(("WEB_PROBING", "web service detected but no HTTP metadata yet"))
        L.append(("WEB_TECHNOLOGY_DISCOVERY", "web service reachable, stack not profiled"))
    # architecture-specific follow-ups
    if f.active_directory:
        L += [("DIRECTORY_SERVICE_ENUMERATION", "Kerberos + LDAP + SMB present"),
              ("WINDOWS_SERVICE_ENUMERATION", "SMB present on an AD host")]
    else:
        if f.ldap:
            L.append(("DIRECTORY_SERVICE_ENUMERATION", "LDAP service present"))
        if f.smb:
            L.append(("WINDOWS_SERVICE_ENUMERATION", "SMB service present"))
    if f.mail:
        L.append(("DNS_ENUMERATION", "mail server software detected"))
    if f.grafana:
        L.append(("API_ENDPOINT_DISCOVERY", "Grafana detected (HTTP API)"))
    if f.cms:
        L += [("CMS_IDENTIFICATION", "CMS technology detected"),
              ("CMS_ASSESSMENT", "CMS technology detected")]
    if f.openapi or f.graphql:
        L.append(("API_ENDPOINT_DISCOVERY", "API description / GraphQL endpoint present"))
        if f.openapi:
            L.append(("PARAMETER_DISCOVERY", "OpenAPI follow-up"))
    if f.spa:
        L += [("JAVASCRIPT_ANALYSIS", "SPA framework detected"),
              ("WEB_CRAWLING", "SPA follow-up")]
    if f.container:
        L.append(("CONTAINER_DISCOVERY", "container platform evidence present"))
    if f.cloud:
        L.append(("CLOUD_ASSET_DISCOVERY", "cloud provider evidence present"))
    if f.iot:
        L.append(("IOT_SERVICE_IDENTIFICATION", "IoT protocol evidence present"))
    # generic web surface
    if f.web:
        if "WEB_PROBING" in f.done and not f.cdn:
            L.append(("HEADER_ANALYSIS", "web probing done, headers not analysed"))
        if not f.cdn:
            L += [("CONTENT_DISCOVERY", "web target, content not enumerated"),
                  ("PARAMETER_DISCOVERY", "web target, parameters not enumerated")]
        if not f.cdn and "WEB_PROBING" not in f.done:
            L.append(("WEB_PROBING", "web target not probed yet"))
    if f.https:
        L.append(("TLS_ANALYSIS", "HTTPS port open and TLS not analysed"))
    if f.web and not f.cdn:
        L.append(("HEADER_ANALYSIS", "web target, headers not analysed"))
    if f.web and ("CONTENT_DISCOVERY" in f.done or f.cdn):
        L.append(("SCREENSHOT_CAPTURE", "web target, screenshot not captured"))
    if f.ports and f.has_services and not f.os_evidence and not f.web:
        L.append(("OPERATING_SYSTEM_IDENTIFICATION",
                  "non-web host with services known but no OS evidence"))
    return L


def rules_decision(evidence: dict[str, Any]) -> dict[str, Any]:
    """Deterministic next-capability decision for this evidence."""
    f = Facts(evidence)
    profile = classify_profile(f)

    if f.scope is False:
        return _decision("BLOCK_EXECUTION", "OUT_OF_SCOPE",
                         "target is explicitly outside the authorized scope", 0.99)
    if f.scope is None:
        return _decision("VERIFY_SCOPE", profile if profile != "OUT_OF_SCOPE" else "UNKNOWN",
                         "authorization status is unknown", 0.95,
                         missing=["authorized_scope"])
    if {"PASSIVE_ASSET_DISCOVERY", "SUBDOMAIN_DISCOVERY", "DNS_RESOLUTION"} <= f.zero:
        return _decision("STOP_NO_RELEVANT_ACTION", "UNREACHABLE",
                         "dead-end domain: passive, subdomain and DNS discovery all empty", 0.85)
    if f.reachable is False and not f.ports:
        return _decision("REQUEST_ADDITIONAL_EVIDENCE", "UNREACHABLE",
                         "host is not responding; need confirmation it is up / correct address",
                         0.8, missing=["confirmation the host is reachable"])
    if f.ev.get("active_subtarget") is None and not f.subdomains_exhausted:
        pivot = _pivot_candidate(f.ev)
        if pivot and f.ports:
            return _decision("PIVOT_TO_SUBDOMAIN", profile,
                             f"{pivot} resolves to a different IP than the main target", 0.7,
                             next_subdomain=pivot)

    seen = set()
    for cap, why in _ladder(f):
        if cap in seen or cap in f.done:
            continue
        seen.add(cap)
        return _decision(cap, profile, why)

    if f.ev.get("active_subtarget"):
        return _decision("RETURN_FROM_SUBDOMAIN", profile,
                         "sub-target recon exhausted; resume parent target", 0.8)
    return _decision("STOP_NO_RELEVANT_ACTION", profile,
                     "no useful uncompleted capability remains", 0.85)


def _public_ip(ip: str) -> bool:
    """Private/internal addresses leaked through public DNS (10.x, 172.16/12,
    192.168.x) are not reachable from an external vantage point, so pivoting
    to them burns an iteration. wolt.com's evidence had dozens of these."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return True  # hostname / CNAME -- let the pivot logic decide
    return not any(addr in net for net in _INTERNAL_NETS if addr.version == net.version)


def _internal_nets():
    import ipaddress
    return [ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8",
        "::1/128", "fc00::/7", "fe80::/10")]


_INTERNAL_NETS = _internal_nets()


_PIVOT_PRIORITY = ("grafana", "kibana", "jenkins", "gitlab", "prometheus",
                   "kubernetes", "docker", "consul", "vault", "etcd",
                   "vpn", "gateway", "proxy", "external", "staging")


def _pivot_candidate(ev: dict[str, Any]) -> str | None:
    res = ev.get("subdomain_resolutions") or {}
    main_ip = ev.get("resolved_ip")
    if not res or not main_ip:
        return None
    done = set((ev.get("subtarget_results") or {}).keys())
    cands = [s for s, ip in res.items()
             if ip and ip != main_ip and s not in done and _public_ip(ip)]
    if not cands:
        return None

    def rank(s: str) -> tuple[int, str]:
        low = s.lower()
        for i, word in enumerate(_PIVOT_PRIORITY):
            if word in low:
                return (i, s)
        return (len(_PIVOT_PRIORITY), s)
    return sorted(cands, key=rank)[0]


# ── guardrails over an LLM decision ─────────────────────────────────────────

def apply_guardrails(evidence: dict[str, Any],
                     decision: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return (decision, corrections). Only hard-rule violations are changed."""
    f = Facts(evidence)
    d = dict(decision)
    corrections: list[str] = []
    cap = d.get("next_capability")

    def replace(why: str) -> None:
        nonlocal cap
        r = rules_decision(evidence)
        corrections.append(f"{cap} -> {r['next_capability']}: {why}")
        d["next_capability"] = r["next_capability"]
        if r.get("next_subdomain"):
            d["next_subdomain"] = r["next_subdomain"]
        d["reason"] = f"[guardrail: {why}] {r['reason']} (model said: {decision.get('reason', '')})"
        d["decided_by"] = "guardrail"
        cap = d["next_capability"]

    # scope always wins
    if f.scope is False and cap != "BLOCK_EXECUTION":
        replace("target is out of scope")
        d["target_profile"] = "OUT_OF_SCOPE"
    elif f.scope is None and cap not in ("VERIFY_SCOPE", "BLOCK_EXECUTION"):
        replace("authorization status unknown")
    elif cap == "DO_NOT_REPEAT_COMPLETED_ACTION":
        replace("DO_NOT_REPEAT_COMPLETED_ACTION is not a selectable capability")
    elif cap in f.done and cap not in NON_REPEATABLE_EXEMPT:
        replace("capability already completed / failed / returned zero findings")
    elif cap in ARCH_REQUIREMENTS and not f.has(ARCH_REQUIREMENTS[cap]):
        replace(f"{cap} has no supporting {ARCH_REQUIREMENTS[cap]} evidence")
    elif cap == "PIVOT_TO_SUBDOMAIN" and f.subdomains_exhausted:
        replace("subdomains_exhausted is true")
    elif cap == "STOP_NO_RELEVANT_ACTION" and f.scope is True:
        pending = mandatory_before_stop(f)
        if pending:
            corrections.append(f"STOP -> {pending[0]}: required before stopping on this target")
            d["next_capability"] = pending[0]
            d["reason"] = (f"[guardrail: {pending[0]} must run before STOP] "
                           f"(model said: {decision.get('reason', '')})")
            d["decided_by"] = "guardrail"
    elif cap == "REQUEST_AUTHORIZED_CREDENTIALS" and (not f.auth_required or f.creds_supplied):
        replace("no evidence that authentication is required without credentials")

    # profile sanity: host OS profiles need OS evidence
    if d.get("target_profile") in ("LINUX_HOST", "WINDOWS_HOST") and not f.os_evidence:
        corrections.append(f"profile {d['target_profile']} -> UNKNOWN: no OS-identifying evidence")
        d["target_profile"] = classify_profile(f) if classify_profile(f) not in (
            "LINUX_HOST", "WINDOWS_HOST") else "UNKNOWN"
    if f.scope is False:
        d["target_profile"] = "OUT_OF_SCOPE"

    if corrections:
        d["guardrail_corrections"] = corrections
    d.setdefault("decided_by", "llm")
    return d, corrections


# ── full pipeline ───────────────────────────────────────────────────────────

def plan(client, system_prompt: str, evidence: dict[str, Any],
         user_prompt: str | None = None, use_guardrails: bool | None = None,
         ) -> tuple[dict[str, Any], dict[str, Any]]:
    """LLM decision with structured output, one repair retry, rules fallback
    and guardrails. Returns (decision, info) where info records what happened
    (raw responses, validation errors, whether rules/guardrails stepped in)."""
    if use_guardrails is None:
        # env-forwarded toggle so ablation variants (e.g. an XBOW
        # "no-guardrails" run) can disable the guard layer cleanly.
        use_guardrails = os.environ.get("CYBERSWARM_GUARDRAILS", "1") not in ("-1", "0", "false", "False")
    from model_client import chat_structured

    user_prompt = user_prompt if user_prompt is not None else json.dumps(evidence)
    schema = decision_json_schema()
    info: dict[str, Any] = {"raw": [], "errors": [], "fallback": False,
                            "corrections": [], "llm_decision": None}
    decision = None
    prompt = user_prompt
    for _attempt in range(2):
        try:
            raw = chat_structured(client, system_prompt, prompt, json_schema=schema)
        except Exception as exc:
            info["errors"].append(f"model call failed: {exc}")
            break
        info["raw"].append(raw)
        ok, parsed, errors = validate_decision(raw)
        if ok:
            decision = parsed
            break
        info["errors"].append(errors)
        prompt = (user_prompt + "\n\nYour previous reply was rejected: "
                  + "; ".join(errors)
                  + "\nReturn ONLY the JSON object, using only the supported "
                    "profile and capability names.")

    if decision is None:
        info["fallback"] = True
        decision = rules_decision(evidence)
        return decision, info

    info["llm_decision"] = dict(decision)
    if use_guardrails:
        decision, corrections = apply_guardrails(evidence, decision)
        info["corrections"] = corrections
    return decision, info
