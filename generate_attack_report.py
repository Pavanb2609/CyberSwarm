#!/usr/bin/env python3
"""
CyberSwarm Phase 2 — Attack Report Generator

Reads attack_evidence/*.json and prints a structured markdown report
summarising all vulnerabilities, exploit candidates, and risk ratings.

Usage:
    python generate_attack_report.py scanme.nmap.org
    python generate_attack_report.py --all          # report every target
    python generate_attack_report.py scanme.nmap.org --out report.md
"""

import argparse
import json
import re
import sys
from pathlib import Path

from utils import finding_key as _finding_key, severity_rank, SEVERITY_ORDER
from cvss import enrich_findings, effective_severity
from attack_chains import detect_chains
import evidence_store

ROOT       = Path(__file__).parent
STORE_DIR  = ROOT / "results" / "attack_evidence"

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
    "UNKNOWN":  "⚫",
}


# OWASP Top 10 (2021) mapping keyed by CVSS finding_type (and by keyword
# fallback) so every reportable finding can be labelled with its OWASP A-code.
OWASP_BY_FINDING_TYPE = {
    "broken_access_control": "A01",            # A01 Broken Access Control
    "idor": "A01",
    "default_credentials": "A07",
    "weak_password": "A07",
    "cryptographic_failure": "A02",            # A02 Cryptographic Failures
    "weak_tls_configuration": "A02",
    "sql_injection": "A03",                    # A03 Injection
    "nosql_injection": "A03",
    "ldap_injection": "A03",
    "asrep_roastable": "A07",                  # A07 Identification & Auth Failures
    "kerberoastable": "A07",
    "smb_null_session": "A01",                 # A01 Broken Access Control (anonymous read)
    "cross_site_scripting_reflected": "A03",
    "cross_site_scripting_stored": "A03",
    "command_injection": "A03",
    "local_file_inclusion": "A03",
    "server_side_template_injection": "A03",
    "xml_external_entity": "A03",
    "crlf_injection": "A03",
    "insecure_design": "A04",                  # A04 Insecure Design
    "security_misconfiguration": "A05",        # A05 Security Misconfiguration
    "missing_security_header": "A05",
    "clickjacking": "A05",
    "directory_listing": "A05",
    "http_method_enabled": "A05",
    "file_upload": "A05",
    "vulnerable_component": "A06",             # A06 Vulnerable & Outdated Components
    "cwe_component": "A06",
    "identification_authentication_failure": "A07",   # A07 Identification & Auth Failures
    "jwt_weak_algorithm": "A07",
    "session_fixation": "A07",
    "session_hijacking": "A07",
    "insecure_deserialization": "A08",         # A08 Software & Data Integrity
    "server_side_request_forgery": "A10",      # A10 SSRF (OWASP 2021)
    "information_disclosure": "A05",
    "cors_misconfiguration": "A05",
    "host_header_injection": "A05",
    "open_redirect": "A03",
    "waf_bypass": "A05",
}

# Keyword -> OWASP fallback for findings whose finding_type is "unclassified".
OWASP_KEYWORDS = (
    ("A01", ("access control", "authorization", "idor", "broken access", "privilege escalat",
             "null session", "null-session", "anonymous smb")),
    ("A02", ("cryptograph", "tls", "ssl", "weak cipher", "deprecated", "cipher")),
    ("A03", ("injection", "sql", "xss", "script", "command", "template", "xxe", "lfi",
             "path traversal", "nosql", "ldap filter", "operator payload")),
    ("A04", ("insecure design", "logic flaw", "business logic", "design flaw")),
    ("A05", ("misconfiguration", "misconfig", "header", "clickjack", "directory listing", "cors",
             "exposed", "frame")),
    ("A06", ("outdated", "known vulnerability", "cve-", "component", "version")),
    ("A07", ("authentication", "login", "session", "jwt", "password", "credential", "brute",
             "kerberoast", "as-rep", "asrep", "pre-auth", "spn account")),
    ("A08", ("deserialization", "integrity", "untrusted")),
    ("A09", ("logging", "monitoring", "log")),
    ("A10", ("ssrf", "server-side request", "proxy")),
)

OWASP_LABELS = {
    "A01": "A01 Broken Access Control",
    "A02": "A02 Cryptographic Failures",
    "A03": "A03 Injection",
    "A04": "A04 Insecure Design",
    "A05": "A05 Security Misconfiguration",
    "A06": "A06 Vulnerable & Outdated Components",
    "A07": "A07 Identification & Authentication Failures",
    "A08": "A08 Software & Data Integrity Failures",
    "A09": "A09 Security Logging & Monitoring Failures",
    "A10": "A10 Server-Side Request Forgery",
}


def owasp_for(finding: dict) -> str:
    """Return the OWASP 2021 A-code for a finding, or 'A-OTHER'."""
    ft = str(finding.get("finding_type", "")).lower()
    if ft in OWASP_BY_FINDING_TYPE:
        return OWASP_BY_FINDING_TYPE[ft]
    ft_clean = ft.replace("-", "_").replace(" ", "_")
    if ft_clean in OWASP_BY_FINDING_TYPE:
        return OWASP_BY_FINDING_TYPE[ft_clean]
    haystack = " ".join(str(finding.get(k, "")) for k in
                        ("name", "description", "msg", "output", "cve_id")).lower()
    for code, kws in OWASP_KEYWORDS:
        if any(kw in haystack for kw in kws):
            return code
    return "A-OTHER"


def render_owasp_summary(reportable) -> str:
    """Build an OWASP Top-10 coverage summary table from the reportable findings."""
    ORDER = ["NONE", "UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]  # incl. NONE
    by_code: dict[str, dict] = {}
    for f in reportable:
        code = owasp_for(f)
        entry = by_code.setdefault(code, {"count": 0, "max_sev": "NONE", "rows": []})
        sev = effective_severity(f)
        entry["count"] += 1
        if ORDER.index(sev) > ORDER.index(entry["max_sev"]):
            entry["max_sev"] = sev
        entry["rows"].append(f.get("name") or f.get("msg") or "?")
    lines = ["## OWASP Top 10 Coverage", "", "| OWASP | Max Severity | # | Representative finding |", "|-------|--------------|---|-------------------------|"]
    for code in sorted(by_code):
        if code == "A-OTHER":
            continue
        e = by_code[code]
        rep = (e["rows"][0] or "")[:60]
        lines.append(f"| {OWASP_LABELS.get(code, code)} | {e['max_sev']} | {e['count']} | {rep} |")
    if "A-OTHER" in by_code:
        lines.append(f"| Other/Unclassified | {by_code['A-OTHER']['max_sev']} | {by_code['A-OTHER']['count']} | — |")
    return "\n".join(lines)



def load_evidence(target: str) -> dict:
    safe = target.replace("/", "_").replace(":", "_")
    path = STORE_DIR / f"{safe}.json"
    if not path.exists():
        print(f"[ERROR] No attack evidence found for '{target}' at {path}")
        sys.exit(1)
    return json.loads(path.read_text(encoding="utf-8"))


def _dedup(items, key_fn=None):
    """Dedupe by key_fn, keeping the higher-severity item when two entries
    share an identity (higher SEVERITY_ORDER index = more severe)."""
    if key_fn is None:
        key_fn = _finding_key
    by_key: dict = {}
    order = []
    for it in items:
        k = key_fn(it)
        if k not in by_key:
            by_key[k] = it
            order.append(k)
        elif severity_rank(it.get("severity", "UNKNOWN")) > severity_rank(by_key[k].get("severity", "UNKNOWN")):
            by_key[k] = it
    return [by_key[k] for k in order]


def _render_target_graph(smap: dict) -> str:
    """Render the SystemMap's links as a compact mermaid flowchart.

    Returns an empty string when the map has no links to draw, so the report
    simply omits the section instead of emitting an empty diagram.
    """
    links = smap.get("links") or []
    if not links:
        return ""

    def node_id(raw: str) -> str:
        return raw.replace(":", "_").replace("/", "_").replace(" ", "_")

    seen, parts = set(), ["```mermaid", "graph LR"]
    for ln in links[:40]:
        frm, to = str(ln.get("from", "")), str(ln.get("to", ""))
        if not frm or not to:
            continue
        label = str(ln.get("kind", ""))
        conf = ln.get("confidence")
        if isinstance(conf, (int, float)):
            label += f" ({conf}%)"
        edge = f"    {node_id(frm)} -->|{label}| {node_id(to)}"
        if edge not in seen:
            seen.add(edge)
            parts.append(edge)
    parts.append("```")
    return "\n".join(parts) if len(parts) > 3 else ""


def _data_quality_summary(target: str) -> dict:
    """Pull recon-phase failure_patterns/reachable/zero_findings_actions so
    the report can tell a reader *why* results look thin, instead of
    silently rendering as if recon fully succeeded when it mostly didn't.

    Concretely motivated by a real report where "Technologies: none
    detected" and near-empty crawl results were caused by httpx timing out
    reaching a live, reachable site -- information that existed only in
    the raw recon evidence JSON, nowhere in the rendered report."""
    try:
        recon_ev = evidence_store.load(target, warn_on_regression=False)
    except Exception:  # noqa: BLE001
        return {}
    return {
        "reachable": recon_ev.get("reachable"),
        "failure_patterns": recon_ev.get("failure_patterns", {}),
        "failed_actions": recon_ev.get("failed_actions", []),
        "zero_findings_actions": recon_ev.get("zero_findings_actions", []),
    }


def render_report(evidence: dict) -> str:
    target = evidence.get("target", "unknown")
    risk   = evidence.get("risk_rating", "UNKNOWN")

    # ── Normalise new MemoryAgent format + legacy Phase-2 format ────────────
    actions = evidence.get("completed_agents") or evidence.get("attack_actions_completed") or []
    vulns   = enrich_findings(_dedup(evidence.get("vulnerabilities", [])))
    chains  = detect_chains(vulns)
    exploits = evidence.get("exploit_candidates", [])
    observations = (evidence.get("new_attack_paths", [])
                    or evidence.get("attack_observations", [])
                    or [])
    for req in evidence.get("proof_requests", []):
        observations.append(f"[PROOF NEEDED] {req}")

    # Pull technologies / ports / endpoints from the SystemMap when available
    techs, ports, endpoints = [], [], evidence.get("discovered_endpoints", []) or evidence.get("discovered_paths", [])
    smap = None
    smap_paths = []
    smap_path = ROOT / "results" / "system_map" / f"{target.replace('/', '_').replace(':', '_')}.json"
    if smap_path.exists():
        try:
            smap = json.loads(smap_path.read_text(encoding="utf-8"))
            techs = [f"{t.get('name', '')} {t.get('version', '')}".strip()
                     for t in smap.get("technologies", []) if t.get("name")]
            ports = [s.get("port") for s in smap.get("services", []) if s.get("port")]
            endpoints = smap.get("endpoints", []) or endpoints
            smap_paths = list(smap.get("auth_paths", []) or []) + list(smap.get("api_paths", []) or [])
        except Exception:  # noqa: BLE001
            pass

    # Exploit candidates from intelligence/searchsploit findings in new format
    if not exploits:
        for v in vulns:
            if v.get("tool") in ("searchsploit", "intelligence"):
                exploits.append({"title": v.get("name", ""), "edb_id": "",
                                 "type": "searchsploit", "cve": [], "url": ""})

    nuclei = evidence.get("nuclei_findings", [])
    nikto  = evidence.get("nikto_findings", [])
    nse    = evidence.get("nmap_vuln_findings", [])
    testssl= evidence.get("testssl_findings", [])

    emoji = SEVERITY_EMOJI.get(risk, "⚫")
    lines = []

    lines.append(f"# CyberSwarm Phase 2 — Attack Report")
    lines.append(f"\n**Target:** `{target}`")
    lines.append(f"**Overall Risk Rating:** {emoji} **{risk}**")
    lines.append(f"**Attack Actions Completed:** {', '.join(actions) or 'none'}")
    lines.append(f"**Technologies:** {', '.join(techs[:10]) or 'none detected'}")
    lines.append(f"**Open Ports:** {', '.join(str(p) for p in ports) or 'none'}")

    # ── Data quality: surface recon failures prominently, not buried in raw JSON ──
    dq = _data_quality_summary(target)
    if dq.get("reachable") is False:
        lines.append(
            "\n> ⚠️ **Data quality warning: the target was marked UNREACHABLE during recon.** "
            "Everything below (\"none detected\", thin findings, etc.) may reflect a failed probe, "
            "not the target's actual surface. See the Data Quality section for the specific error.")
    if dq.get("failure_patterns") or dq.get("zero_findings_actions"):
        lines.append("\n## ⚠️ Data Quality — Recon Tool Failures")
        lines.append("_These recon steps failed or found nothing; results above may be incomplete "
                     "because of this, not because the target genuinely has none of these findings._")
        for capability, info in dq.get("failure_patterns", {}).items():
            errors = info.get("errors", []) if isinstance(info, dict) else []
            err_text = errors[0] if errors else "unknown error"
            lines.append(f"- **{capability}** failed: {err_text[:200]}")
        zero = dq.get("zero_findings_actions", [])
        if zero:
            lines.append(f"- Ran successfully but found nothing: {', '.join(zero[:10])}")


    # ── Target graph (SystemMap links) ──────────────────────────────────────
    graph = _render_target_graph(smap) if smap else ""
    if graph:
        lines.append("\n---\n## Target Graph (SystemMap)")
        lines.append(graph)

    # ── Vulnerability summary ────────────────────────────────────────────────
    # De-noise: only report findings with effective severity >= LOW as
    # "Vulnerabilities Found". Things CVSS classifies as NONE (e.g. missing
    # security headers) move to a separate Low-Severity / Hardening section
    # so real findings stop being drowned out.
    reportable = [v for v in vulns
                  if effective_severity(v) in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")]
    hardening = [v for v in vulns if effective_severity(v) == "NONE"]

    lines.append(f"\n---\n## Vulnerabilities Found ({len(reportable)})")

    if not reportable:
        lines.append("_No vulnerabilities confirmed (see Hardening Notes for low-severity items)._")
    else:
        sorted_vulns = sorted(
            reportable,
            key=lambda v: -SEVERITY_ORDER.index(effective_severity(v))
                          if effective_severity(v) in SEVERITY_ORDER else 99
        )
        for v in sorted_vulns:
            sev   = effective_severity(v)
            em    = SEVERITY_EMOJI.get(sev, "⚫")
            name  = v.get("name") or v.get("msg") or v.get("script") or "Unnamed"
            src   = v.get("source") or v.get("source_agent") or v.get("tool", "")
            url   = v.get("url", "")
            desc  = v.get("description") or v.get("output", "")
            cve   = v.get("cve_id") or v.get("cve") or []
            cwe   = v.get("cwe_id") or []
            raw_severity = str(v.get("severity", "UNKNOWN")).upper()
            owasp = owasp_for(v)

            lines.append(f"\n### {em} [{sev}] {name}")
            lines.append(f"- **OWASP:** {OWASP_LABELS.get(owasp, owasp)}")
            if raw_severity != sev:
                lines.append(f"- _(tool reported severity: {raw_severity} — shown severity reflects CVSS classification)_")
            lines.append(f"- **Source:** {src}")
            if url:
                lines.append(f"- **URL:** `{url}`")
            if cve:
                lines.append(f"- **CVE:** {', '.join(cve) if isinstance(cve, list) else cve}")
            if cwe:
                lines.append(f"- **CWE:** {', '.join(cwe) if isinstance(cwe, list) else cwe}")
            if v.get("cvss_score") is not None:
                src_note = "" if v.get("cvss_source") == "finding_type_default" \
                    else " _(from tool severity label, not a scored CVSS assessment)_"
                lines.append(f"- **CVSS:** {v['cvss_score']} ({v.get('cvss_severity', sev)}) "
                            f"`{v.get('cvss_vector') or 'n/a'}`{src_note}")
            if desc:
                lines.append(f"- **Detail:** {desc[:300]}")

    # ── OWASP Top 10 coverage summary ───────────────────────────────────────
    if reportable:
        lines.append("\n---\n" + render_owasp_summary(reportable))

    # ── Authentication: did the target have a login, and was it tested? ─────
    auth = evidence.get("auth")
    if auth:
        try:
            import auth_handling
            lines.append("\n---\n" + auth_handling.render_auth_section(auth))
        except Exception as exc:  # noqa: BLE001
            lines.append(f"\n_(authentication section unavailable: {exc})_")

    # ── OWASP Top 10 per-target coverage (what actually ran, and why findings
    #    did or did not hold up) -- always shown, even with zero confirmed vulns,
    #    so an empty report reads as "here is what was tested" not "broken". ──
    try:
        import owasp_registry
        lines.append("\n---\n" + owasp_registry.render_target_coverage(
            evidence, classify=owasp_for))
    except Exception as exc:  # noqa: BLE001 - reporting must never crash the run
        lines.append(f"\n_(per-target OWASP coverage unavailable: {exc})_")

    # ── Low-Severity / Hardening notes (NONE-severity findings) ─────────────
    if hardening:
        lines.append(f"\n---\n## Low-Severity / Hardening Notes ({len(hardening)})")
        lines.append("_Findings CVSS classifies as NONE (configuration/hardening). "
                     "Track these for defence-in-depth; they are not reported as exploitable vulnerabilities._")
        for v in sorted(hardening,
                        key=lambda x: str(x.get("name", ""))):
            name = v.get("name") or v.get("msg") or "?"
            src  = v.get("source") or v.get("tool", "")
            url  = v.get("url", "")
            lines.append(f"- **{name}** (source: {src}){f' — `{url}`' if url else ''}")

    # ── Cross-finding attack chains ──────────────────────────────────────────
    if chains:
        lines.append(f"\n---\n## Cross-Finding Attack Chains ({len(chains)}) \u26a0\ufe0f requires manual verification")
        lines.append("_Two or more individually lower-severity findings that combine into a higher-impact "
                     "scenario via a documented attack pattern. These are hypotheses for a reviewer to "
                     "verify, not confirmed exploitation._")
        for c in chains:
            d = c.to_dict()
            lines.append(f"\n### {d['name']} — {d['host']}")
            lines.append(d["description"])
            if d.get("cvss_score") is not None:
                lines.append(f"- **Assessed impact if verified:** CVSS {d['cvss_score']} ({d['cvss_severity']})")
            contributors = ", ".join(f"{cf['name']} ({cf['finding_type']})" for cf in d.get("contributing_findings", []))
            lines.append(f"- **Contributing findings:** {contributors}")

    # ── Exploit candidates ────────────────────────────────────────────────────
    lines.append(f"\n---\n## Exploit Candidates ({len(exploits)})")
    if not exploits:
        lines.append("_No exploit candidates found via Searchsploit._")
    else:
        for ex in exploits[:15]:
            edb  = ex.get("edb_id", "")
            title= ex.get("title", "")
            etype= ex.get("type", "")
            cves = ex.get("cve", [])
            url  = ex.get("url", "")
            lines.append(f"\n- **[EDB-{edb}]** {title}")
            if cves:
                lines.append(f"  - CVE: {', '.join(cves)}")
            lines.append(f"  - Type: {etype}  |  [View]({url})")

    # ── Raw tool output summaries ─────────────────────────────────────────────
    if nuclei:
        lines.append(f"\n---\n## Nuclei Findings ({len(nuclei)})")
        for f in nuclei[:20]:
            sev = f.get("severity", "UNKNOWN").upper()
            em  = SEVERITY_EMOJI.get(sev, "⚫")
            lines.append(f"- {em} `{f.get('template_id', '')}` — {f.get('name', '')} @ `{f.get('url', '')}`")

    if nikto:
        lines.append(f"\n---\n## Nikto Findings ({len(nikto)})")
        for f in nikto[:20]:
            lines.append(f"- `{f.get('osvdbid', 'OSVDB-?')}` — {f.get('msg', '')[:150]}")

    if nse:
        lines.append(f"\n---\n## Nmap NSE Vuln Findings ({len(nse)})")
        for f in nse[:20]:
            sev = f.get("severity", "INFO").upper()
            em  = SEVERITY_EMOJI.get(sev, "⚫")
            cve = ", ".join(f.get("cve", [])) if f.get("cve") else ""
            lines.append(f"- {em} Port `{f.get('port','')}` / `{f.get('script','')}` {cve}")
            if f.get("output"):
                lines.append(f"  ```\n  {f['output'][:200]}\n  ```")

    if testssl:
        lines.append(f"\n---\n## TLS/SSL Vulnerability Findings — testssl.sh ({len(testssl)})")
        for f in testssl[:30]:
            sev  = f.get("severity", "INFO").upper()
            em   = SEVERITY_EMOJI.get(sev, "⚫")
            name = f.get("id", "?")
            finding = f.get("finding", "")
            cve  = f.get("cve", "")
            cwe  = f.get("cwe", "")
            cve_str = f" — CVE: {cve}" if cve else ""
            cwe_str = f" — CWE: {cwe}" if cwe else ""
            lines.append(f"- {em} **{name}**: {finding}{cve_str}{cwe_str}")

    # ── Recommended next steps ────────────────────────────────────────────────
    lines.append(f"\n---\n## Recommended Next Steps")
    critical_high = [v for v in reportable if effective_severity(v) in ("CRITICAL", "HIGH")]
    medium = [v for v in reportable if effective_severity(v) == "MEDIUM"]
    if critical_high:
        lines.append("1. **Immediate remediation required** for CRITICAL/HIGH findings above:")
        for v in critical_high[:5]:
            lines.append(f"   - [{effective_severity(v)}] {v.get('name') or v.get('msg','?')} (OWASP {owasp_for(v)})")
        lines.append("2. Validate each CRITICAL/HIGH finding manually before reporting.")
        lines.append("3. For exploit candidates: confirm patch status before attempting PoC.")
    elif medium:
        lines.append("1. Review the MEDIUM findings above — many are exploitable in combination:")
        for v in medium[:5]:
            lines.append(f"   - [{effective_severity(v)}] {v.get('name') or v.get('msg','?')} (OWASP {owasp_for(v)})")
        lines.append("2. Prioritise the highest-impact items first (broken access control / injection before hardening).")
    elif hardening:
        lines.append("1. No exploitable vulnerabilities confirmed. Address the Low-Severity / Hardening notes for defence-in-depth.")
    else:
        lines.append("1. No critical findings. Consider deeper manual testing on discovered paths/APIs.")
        lines.append("2. Run authenticated scans if credentials are available.")

    if evidence.get("discovered_endpoints") or evidence.get("discovered_paths") or endpoints:
        lines.append("3. **MANUAL_PROBE recommended** — API endpoints detected; check for IDOR and broken auth.")

    if observations:
        lines.append("\n### Observations")
        for obs in observations[:10]:
            lines.append(f"- {str(obs)[:200]}")

    # ── Manual verification checklist (URLs / endpoints to check) ─────────────
    lines.append(f"\n---\n## Manual Verification Checklist — URLs / Endpoints to Check")
    url_re = re.compile(r"https?://[^\s]+?(?=$|\s|https?://)")
    checklist = []
    seen = set()

    def _add(kind: str, sev: str, label: str, url: str) -> None:
        url = (url or "").strip().rstrip(".,'\";)")
        if not url or url in seen:
            return
        seen.add(url)
        checklist.append((kind, sev, (label or "")[:70], url[:150]))

    def _host_of(url: str) -> str:
        return url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]

    def _target_owned(url: str) -> bool:
        host = _host_of(url)
        return host == target or host.endswith("." + target.rstrip("."))

    # Confirmed vulnerabilities -> their URLs (also extract URLs from the
    # aggregated descriptions, which embed the full path lists).
    for v in reportable:
        _add("CONFIRMED", effective_severity(v), v.get("name", ""), v.get("url", ""))
        for m in url_re.findall(v.get("description") or ""):
            m = m.rstrip(".,');")
            if _target_owned(m):
                _add("CONFIRMED", effective_severity(v), v.get("name", ""), m)

    # Critic-disputed / needs-proof findings still deserve a human look
    # (external URLs matter here: they are the redirect/exfil targets to check).
    for d in _dedup(evidence.get("disputed_findings", [])):
        _add("CRITIC-DISPUTED", d.get("severity", "INFO").upper(), d.get("name", ""), d.get("url", ""))
        for m in url_re.findall(d.get("description") or ""):
            _add("CRITIC-DISPUTED", d.get("severity", "INFO").upper(), d.get("name", ""), m.rstrip(".,');"))
    for req in evidence.get("proof_requests", []):
        req = str(req)
        urls = url_re.findall(req) or []
        for m in urls:
            _add("NEEDS-PROOF", "INFO", req[:70], m.rstrip(".,);"))
        if not urls:
            _add("NEEDS-PROOF", "INFO", req[:70], f"{target} (manual step)")

    # Auth / API surfaces from recon — the concrete places a human should probe.
    for p in smap_paths:
        full = p if p.startswith("http") else f"https://{target}{p}"
        # skip masked ("****"), truncated ("…"), or double-URL artifacts from recon
        if "****" in full or "\u2026" in full or full.count("http") > 1:
            continue
        _add("RECON", "INFO", "auth/api surface", full)

    if not checklist:
        lines.append("_No URLs to verify — nothing surfaced by the agents._")
    else:
        lines.append("| # | Status | Severity | Finding | URL / Endpoint |")
        lines.append("|---|--------|----------|---------|----------------|")
        for i, (kind, sev, label, url) in enumerate(checklist[:40], 1):
            lines.append(f"| {i} | {kind} | {sev} | {label} | `{url}` |")

    lines.append(f"\n---\n_Report generated by CyberSwarm Phase 2 | Target: {target}_")

    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="CyberSwarm Phase 2 Report Generator")
    p.add_argument("target",  nargs="?", help="Target domain to report on")
    p.add_argument("--all",   action="store_true", help="Report all targets in attack_evidence/")
    p.add_argument("--out",   default="",           help="Write report to this file (default: stdout)")
    args = p.parse_args()

    if args.all:
        targets = [f.stem for f in STORE_DIR.glob("*.json")] if STORE_DIR.exists() else []
        if not targets:
            print("[INFO] No attack evidence files found.")
            sys.exit(0)
    elif args.target:
        targets = [args.target]
    else:
        p.print_help()
        sys.exit(1)

    reports = []
    for target in targets:
        evidence = load_evidence(target)
        reports.append(render_report(evidence))

    full_report = "\n\n---\n\n".join(reports)

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(full_report, encoding="utf-8")
        print(f"[OK] Report written to {args.out}")
    else:
        print(full_report)


if __name__ == "__main__":
    main()
