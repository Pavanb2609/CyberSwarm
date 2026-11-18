"""
owasp_registry.py — OWASP Top 10 (2021) coverage map.

Maps each Top-10 category to:
  * the planner capabilities / attack actions that exercise it,
  * the agent(s) that own it,
  * the exploitation tools that turn a *finding* into *proof*.

This replaces the WIKISTYLE "coverage" claims with a machine-checkable,
registry-driven report so the pipeline can prove what A01..A10 are covered by
at build time and at runtime (coverage_report()).

Adding a category = the full OWASP Top-10 already exists here; adding a NEW
control = add tool names to the right category's vectors and wire them in the
agent that triggers them (see agents/specialists.py, agents/xss_agent.py,
agents/ad_agent.py).
"""

# category -> {title, agents, actions (attack_registry actions), tools (agency-level)}
# capabilities are planner issue-actions; tools are actual tool-names.
OWASP_TOP_10: dict[str, dict] = {
    "A01": {
        "title": "Broken Access Control",
        "agents": ["api", "web"],
        "capabilities": ["IDOR_TEST", "HTTP_METHOD_TEST"],
        "actions": ["IDOR_TEST", "HTTP_METHOD_TEST"],
        "tools": ["idor_test", "http_methods", "nuclei_misconfig"],
        "exploits": ["idor_test", "http_methods"],
        "notes": "IDOR/BOLA probe on API endpoints; HTTP verb tampering (TRACE/PUT).",
    },
    "A02": {
        "title": "Cryptographic Failures (was Sensitive Data Exposure)",
        "agents": ["tls", "web"],
        "capabilities": ["TLS_VULN_SCAN", "TLS_ANALYSIS"],
        "actions": ["TLS_VULN_SCAN"],
        "tools": ["testssl", "sslyze", "tls_analysis", "cert_info"],
        "exploits": ["testssl", "sslyze"],
        "notes": "Weak cipher/protocol detection; expired certs; HSTS/header gaps feed A05.",
    },
    "A03": {
        "title": "Injection",
        "agents": ["web", "api", "xss_exploit"],
        "capabilities": ["SQLI_SCAN", "XSS_SCAN", "CMD_INJECTION_SCAN", "NOSQL_INJECTION_SCAN",
                          "LDAP_INJECTION_SCAN", "XXE_SCAN", "CRLF_INJECTION_SCAN"],
        "actions": ["SQLI_SCAN", "XSS_SCAN", "CMD_INJECTION_SCAN", "NOSQL_INJECTION_SCAN",
                     "LDAP_INJECTION_SCAN", "XXE_SCAN", "CRLF_INJECTION_SCAN"],
        "tools": ["sqlmap", "dalfox", "xss_proof", "commix", "nosql_inj", "ldap_inj",
                  "nuclei_sqli", "nuclei_xss", "xxe", "crlf"],
        "exploits": ["sqlmap", "xss_proof", "commix", "nosql_inj", "ldap_inj", "xxe"],
        "notes": "SQLi/XSS/LDAP/NoSQL/XXE/CRLF: A03 is the widest surface.",
    },
    "A04": {
        "title": "Insecure Design",
        "agents": ["insecure_design"],
        "capabilities": [],
        "actions": [],
        "tools": ["deserialization_detect", "upload_form_detect", "csrf_surface_detect",
                  "cookie_analyzer", "sensitive_endpoint_detect", "auth_flow_analysis"],
        "exploits": [],
        "notes": "Architecture+predictability: default creds, auth-flow gaps, weak session design.",
    },
    "A05": {
        "title": "Security Misconfiguration",
        "agents": ["web", "nuclei"],
        "capabilities": ["MISCONFIG_SCAN", "HOST_HEADER_ATTACK", "EXPOSED_PANELS_SCAN",
                          "DEFAULT_CRED_SCAN", "WAF_DETECT"],
        "actions": ["MISCONFIG_SCAN", "HOST_HEADER_ATTACK", "EXPOSED_PANELS_SCAN",
                     "DEFAULT_CRED_SCAN", "WAF_DETECT", "DEFAULT_CRED_CHECK"],
        "tools": ["nuclei_misconfig", "host_header", "nuclei_panels", "nuclei_defaultlogin",
                  "wafw00f", "default_creds_check", "headers", "header_analysis"],
        "exploits": ["default_creds_check", "host_header"],
        "notes": "Misconfig panels, default credentials, host-header confusion, verbose errors.",
    },
    "A06": {
        "title": "Vulnerable and Outdated Components",
        "agents": ["intelligence", "web"],
        "capabilities": ["VULN_SCAN", "SERVICE_VULN_SCAN", "PASSIVE_ASSET_DISCOVERY"],
        "actions": ["VULN_SCAN", "SERVICE_VULN_SCAN"],
        "tools": ["nuclei", "nmap_nse", "searchsploit", "nuclei_takeover"],
        "exploits": ["searchsploit"],
        "notes": "Version/banner matching against nuclei + searchsploit KBs; subdomain takeover.",
    },
    "A07": {
        "title": "Identification and Authentication Failures",
        "agents": ["auth"],
        "capabilities": ["AUTH_PROBE", "LOGIN_BRUTE", "SESSION_FIXATION", "SESSION_HIJACK",
                          "JWT_ANALYSIS"],
        "actions": ["AUTH_PROBE", "LOGIN_BRUTE", "SESSION_FIXATION", "SESSION_HIJACK",
                     "JWT_ANALYSIS"],
        "tools": ["auth_probe", "login_brute", "login_fill", "session_fixation",
                  "session_hijack", "jwt_tool", "default_creds_check"],
        "exploits": ["login_brute", "jwt_exploit"],
        "notes": "Weak login/brute-force; session fixation; JWT weakness; default creds.",
    },
    "A08": {
        "title": "Software and Data Integrity Failures",
        "agents": ["deserialization"],
        "capabilities": ["DESERIALIZATION_SCAN", "JWT_ANALYSIS"],
        "actions": ["DESERIALIZATION_SCAN"],
        "tools": ["deserialization", "nuclei_deserialization", "jwt_tool", "ssti_exploit"],
        "exploits": ["deserialization", "jwt_exploit"],
        "notes": "Insecure deserialization endpoints; JWT key confusion; CI/CD dependency risk.",
    },
    "A09": {
        "title": "Security Logging and Monitoring Failures",
        "agents": ["http_methods"],
        "capabilities": ["HTTP_METHOD_TEST"],
        "actions": ["HTTP_METHOD_TEST"],
        "tools": ["http_methods", "header_analysis", "headers"],
        "exploits": [],
        "notes": "TRACE enabled / missing audit headers → weak logging; no verification hook.",
    },
    "A10": {
        "title": "Server-Side Request Forgery (SSRF)",
        "agents": ["web"],
        "capabilities": ["SSRF_SCAN", "SSRF_EXPLOIT"],
        "actions": ["SSRF_SCAN"],
        "tools": ["ssrf_exploit", "nuclei_ssrf"],
        "exploits": ["ssrf_exploit"],
        "notes": "Endpoint-triggered SSRF (URL/path de-referencing) with canary round-trip.",
    },
}

# Alias A0x -> canonical key.
_ALIASES = {f"A{i:02d}": f"A{i:02d}" for i in range(0, 11)}
_ALIASES.update({f"A{i}": f"A{i:02d}" for i in range(0, 11)})


def canonical(category: str) -> str:
    """Normalize 'A3'/'A03'/'A-03' -> 'A03'."""
    c = str(category).strip().upper().replace("-", "").replace("_", "")
    return _ALIASES.get(c, c)


def category_agents(category: str) -> list[str]:
    return list(OWASP_TOP_10.get(canonical(category), {}).get("agents", []))


def category_actions(category: str) -> list[str]:
    return list(OWASP_TOP_10.get(canonical(category), {}).get("capabilities", []))


def category_tools(category: str) -> list[str]:
    return list(OWASP_TOP_10.get(canonical(category), {}).get("tools", []))


def category_exploits(category: str) -> list[str]:
    return list(OWASP_TOP_10.get(canonical(category), {}).get("exploits", []))


def coverage_report() -> list[dict]:
    """Machine-checkable coverage summary for every Top-10 category."""
    rows = []
    for i in range(1, 11):
        code = f"A{i:02d}"
        entry = OWASP_TOP_10[code]
        rows.append({
            "code": code,
            "title": entry["title"],
            "agents": entry["agents"],
            "actions": len(entry["capabilities"]),
            "tools": len(entry["tools"]),
            "exploits": entry["exploits"],
            "exploitable": bool(entry["exploits"]),
        })
    return rows


def _run_base(entry) -> str:
    """Tool name from a tools_run entry: 'dalfox(https://x)' -> 'dalfox'."""
    return str(entry or "").split("(")[0].strip().lower()


def _tool_matches(registry_tool: str, ran_base: str) -> bool:
    """A registry tool is 'exercised' only by an equal or MORE-specific run.

    A specific run satisfies a generic registry tool (run 'nuclei_takeover'
    exercises registry 'nuclei'), but a generic run does NOT satisfy a specific
    registry tool -- a plain 'nuclei' run with a few tags must not be reported
    as having tested SSRF, SQLi and every other 'nuclei_*' template family.
    That one-directional rule is what keeps the coverage honest."""
    rt = registry_tool.lower()
    if not ran_base:
        return False
    return rt == ran_base or ran_base.startswith(rt + "_")


def _tool_to_categories() -> dict:
    """Base tool/exploit name -> set of OWASP codes that use it."""
    index: dict = {}
    for code, entry in OWASP_TOP_10.items():
        for name in list(entry.get("tools", [])) + list(entry.get("exploits", [])):
            index.setdefault(name.lower(), set()).add(code)
    return index


def _iter_findings(evidence: dict):
    """Every finding recorded for the target, from the per-agent runs and the
    confirmed-vulnerability list, de-duplicated by (name, tool, url)."""
    seen = set()
    buckets = [f for run in evidence.get("agent_runs", []) or []
               for f in (run.get("findings") or [])]
    buckets += evidence.get("vulnerabilities", []) or []
    for f in buckets:
        if not isinstance(f, dict):
            continue
        key = (str(f.get("name", "")).strip().lower(),
               _run_base(f.get("tool", "")), str(f.get("url", "")).strip())
        if key in seen:
            continue
        seen.add(key)
        yield f


def _verdict_bucket(f: dict) -> str:
    """proven | confirmed | disputed | unproven for one finding."""
    verdict = str(f.get("verdict", "") or "").upper()
    has_proof = bool(f.get("proofs")) or bool(f.get("proven"))
    if verdict == "CONFIRM":
        return "proven" if has_proof else "confirmed"
    if verdict == "DISPUTE":
        return "disputed"
    return "unproven"


def _has_real_evidence(f: dict) -> bool:
    """True when a captured tool artefact backs the finding (not model prose)."""
    return bool(f.get("evidence_chain") or f.get("raw_output_excerpt") or f.get("proofs"))


_REASON_TAGS = ("[CRITIC]", "[EVIDENCE GATE]", "[PROOF NEEDED]", "[severity]")


def _reason(f: dict) -> str:
    """The note that explains the verdict, pulled from the description."""
    desc = str(f.get("description", "") or "")
    for line in desc.splitlines():
        s = line.strip()
        if any(s.startswith(tag) for tag in _REASON_TAGS):
            return s
    return (desc.strip().splitlines() or [""])[0][:200]


def per_target_coverage(evidence: dict, classify=None) -> list:
    """What each OWASP Top-10 category actually did on this target.

    Reads the stored attack evidence (per-agent runs + findings) and, for every
    category A01..A10, reports:
      * status    -- tested / attempted (no tool output) / not tested / no tooling
      * tools_ran -- which of the category's tools actually executed
      * findings  -- counts by verdict (proven / confirmed / disputed / unproven)
      * reasons   -- why disputed/unproven items did not hold up

    `classify(finding) -> code` is an optional extra classifier (the report's
    keyword mapper) used when a finding's tool name does not map to a category.
    Pure over dicts; no tools, LLM or network.
    """
    tool_to_cats = _tool_to_categories()
    ran_bases = {_run_base(t) for run in evidence.get("agent_runs", []) or []
                 for t in (run.get("tools_run") or [])}
    ran_bases |= {_run_base(f.get("tool", "")) for f in _iter_findings(evidence)}
    ran_bases.discard("")
    ran_bases.discard("analysis")  # 'analysis' = model-written, not a real tool run

    findings = list(_iter_findings(evidence))
    cats_by_finding = []
    for f in findings:
        cats = set()
        base = _run_base(f.get("tool", ""))
        for rt, codes in tool_to_cats.items():
            if _tool_matches(rt, base):
                cats |= codes
        if not cats and classify:
            c = classify(f)
            if c and c != "A-OTHER":
                cats.add(c)
        cats_by_finding.append(cats or {"A-OTHER"})

    rows = []
    for i in range(1, 11):
        code = f"A{i:02d}"
        entry = OWASP_TOP_10[code]
        expected_tools = list(entry.get("tools", [])) + list(entry.get("exploits", []))
        tools_ran = sorted({rt for rt in expected_tools
                            for rb in ran_bases if _tool_matches(rt, rb)})
        cat_findings = [f for f, cats in zip(findings, cats_by_finding, strict=False)
                        if code in cats]

        counts = {"proven": 0, "confirmed": 0, "disputed": 0, "unproven": 0}
        reasons = []
        for f in cat_findings:
            counts[_verdict_bucket(f)] += 1
            if _verdict_bucket(f) in ("disputed", "unproven"):
                r = _reason(f)
                if r and r not in reasons:
                    reasons.append(r)

        real_evidence = any(_has_real_evidence(f) for f in cat_findings)
        if not expected_tools:
            status = "no_tooling"
        elif tools_ran or real_evidence:
            status = "tested"
        elif cat_findings:
            status = "attempted"      # findings exist but all model-written / evidence-gated
        else:
            status = "not_tested"

        rows.append({
            "code": code,
            "title": entry["title"],
            "status": status,
            "agents": entry.get("agents", []),
            "tools_expected": expected_tools,
            "tools_ran": tools_ran,
            "findings_total": len(cat_findings),
            **counts,
            "reasons": reasons[:3],
        })
    return rows


_STATUS_LABEL = {
    "tested": "tested",
    "attempted": "attempted (no tool output)",
    "not_tested": "not tested",
    "no_tooling": "no tooling wired",
}


def render_target_coverage(evidence: dict, classify=None) -> str:
    """Markdown: per-target OWASP Top-10 coverage + why findings did not hold."""
    rows = per_target_coverage(evidence, classify=classify)
    tested = sum(1 for r in rows if r["status"] == "tested")
    proven = sum(r["proven"] for r in rows)
    confirmed = sum(r["confirmed"] for r in rows)
    L = ["## OWASP Top 10 — Per-Target Coverage", "",
         f"Categories with a tool actually run: **{tested}/10**.  "
         f"Proven (execution evidence): **{proven}**.  "
         f"Confirmed (no execution proof): **{confirmed}**.", "",
         "A category is only **tested** when a real tool produced output. "
         "**attempted (no tool output)** means an agent ran but produced only "
         "model-written findings that the evidence gate would not confirm.", "",
         "| OWASP | Status | Tools run | Proven | Confirmed | Disputed | Unproven |",
         "|-------|--------|-----------|:------:|:---------:|:--------:|:--------:|"]
    for r in rows:
        tools = ", ".join(r["tools_ran"]) or "—"
        L.append(f"| {r['code']} {r['title'][:34]} | {_STATUS_LABEL[r['status']]} | "
                 f"{tools} | {r['proven']} | {r['confirmed']} | {r['disputed']} | {r['unproven']} |")

    detail = [r for r in rows if r["reasons"]]
    if detail:
        L += ["", "### Why findings were not confirmed", ""]
        for r in detail:
            L.append(f"**{r['code']} {r['title']}**")
            for reason in r["reasons"]:
                L.append(f"- {reason}")
            L.append("")
    return "\n".join(L).rstrip() + "\n"


def load_attack_tools_for_category(category: str) -> list:
    """Resolve instantiated Tool objects (respecting availability order)."""
    from tools.attack_registry import load_attack_tool
    tools = []
    for name in category_tools(category):
        try:
            tools.append(load_attack_tool(name))
        except Exception:
            continue
    return tools


if __name__ == "__main__":
    import json
    print(json.dumps(coverage_report(), indent=2))
