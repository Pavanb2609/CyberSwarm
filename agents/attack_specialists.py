"""
Expanded specialist agents: WebFuzz, HeadersAttack, SubdomainTakeover,
WafBypass, JWT.

Each follows the same contract as specialists.py: reason over the SystemMap,
run owned tools, emit AgentResult findings with deterministic fallbacks so the
agent is useful without the LLM.
"""

from __future__ import annotations

import json
from typing import Any

from agents.base_agent import AgentResult, BaseAgent
from utils import find_primary_url

REASON_FUZZ = """You are the WebFuzzAgent for CyberSwarm.
You discover hidden content and parameters on the web surface. Choose fuzz
targets (paths/params) from the SystemMap and analyze results. Output JSON:
{"run_dir_fuzz": true, "fuzz_paths": ["..."], "run_param_fuzz": true,
 "param_targets": ["..."], "reasoning": "..."}"""

REASON_HEADERS = """You are the HeadersAttackAgent for CyberSwarm.
Analyze HTTP response headers for clickjacking, host-header injection, cache
poisoning, and missing security headers. Output JSON:
{"clickjack_risk": true, "host_header_risk": false, "missing": ["..."],
 "findings": [{"name","severity","confidence","description"}], "reasoning": "..."}"""

REASON_TAKEOVER = """You are the SubdomainTakeoverAgent for CyberSwarm.
Given discovered subdomains, decide which to check for takeover. Output JSON:
{"check_all": true, "candidates": ["..."], "reasoning": "..."}"""

REASON_WAF = """You are the WafBypassAgent for CyberSwarm.
Detect the WAF/CDN in front of the target and suggest non-intrusive bypass
paths. Output JSON:
{"waf_detected": "...", "bypass_techniques": ["..."], "run_detection": true,
 "reasoning": "..."}"""

REASON_JWT = """You are the JWTAnalystAgent for CyberSwarm.
You find JWTs in the attack surface and test them for known stateless
weaknesses (alg=none, weak keys) — NO brute forcing. Output JSON:
{"found_jwt": true, "token": "<prefix>", "test": true, "reasoning": "..."}"""


class WebFuzzAgent(BaseAgent):
    """Content + parameter fuzzing on the web surface (ffuf/arjun)."""

    agent_name = "web_fuzz"
    owned_tools = ["feroxbuster", "ffuf", "arjun"]

    def should_run(self, smap: dict[str, Any]) -> bool:
        return bool(smap.get("web_surfaces")) or bool(smap.get("endpoints"))

    def run(self, target: str, smap: dict[str, Any], memory: dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)
        fuzz_paths = smap.get("endpoints", [])[:8]
        param_targets = [p for p in smap.get("endpoints", [])[:6] if "?" in str(p)]

        strat = self._llm_json(REASON_FUZZ,
                               f"URLs: {json.dumps(fuzz_paths)}\nParams: {json.dumps(param_targets)}",
                               temperature=0.2)
        if strat and strat.get("param_targets"):
            param_targets = [t for t in strat["param_targets"] if isinstance(t, str)][:4]

        # Directory fuzz via ffuf (attack_registry resolves it). The wrapper
        # caps the wordlist to ~500 entries (see DEFAULT_MAX_WORDS) so the
        # scan can't hammer the target into an IP block again.
        tr = self._run_tool("ffuf", base, timeout=180)
        if tr and tr.status == "success" and tr.results.get("discovered_paths"):
            result.tools_run.append(f"ffuf({len(tr.results['discovered_paths'])} paths)")
            for p in tr.results["discovered_paths"][:20]:
                if isinstance(p, dict):
                    p = p.get("url") or p.get("path") or str(p)
                result.attack_paths_discovered.append(p)
                result.findings.append(self._make_finding(
                    tool="ffuf", name=f"Fuzzed path: {p}", severity="INFO", confidence=70,
                    url=p, false_positive_risk="LOW"))

        # Param fuzz on interesting endpoints
        for p in param_targets:
            trp = self._run_tool("arjun", p if str(p).startswith("http") else f"{base}{p}",
                                 timeout=120)
            if trp and trp.status == "success" and trp.results.get("parameters"):
                result.tools_run.append(f"arjun({p})")
                params = trp.results["parameters"]
                result.findings.append(self._make_finding(
                    tool="arjun", name=f"Parameters on {p}: {', '.join(params[:8])}",
                    severity="INFO", confidence=75, url=str(p), false_positive_risk="LOW"))
                result.attack_paths_discovered.append(f"PARAM:{p}:{','.join(params[:5])}")

        result.status = "success" if result.findings else "partial"
        return result


class HeadersAttackAgent(BaseAgent):
    """Check headers for clickjacking, host-header, cache poisoning, and CRLF injection."""

    agent_name = "headers_attack"
    owned_tools = ["clickjack", "host_header", "header_analysis", "crlf"]

    def should_run(self, smap: dict[str, Any]) -> bool:
        return bool(smap.get("web_surfaces")) or bool(smap["posture"].get("response_headers"))

    def run(self, target: str, smap: dict[str, Any], memory: dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        tr = self._run_tool("clickjack", base, timeout=60)
        if tr and tr.status == "success" and tr.results.get("clickjacking"):
            result.tools_run.append("clickjack")
            for c in tr.results["clickjacking"]:
                missing = ", ".join(c.get("missing", []))
                result.findings.append(self._make_finding(
                    tool="clickjack", name=f"Clickjacking possible — missing {missing}",
                    severity="MEDIUM", confidence=70, url=base,
                    description=f"Page lacks {missing}; may be frameable. "
                                f"XFO={tr.results.get('x_frame_options')!r} CSP={tr.results.get('csp')!r}",
                    false_positive_risk="MEDIUM"))

        tr2 = self._run_tool("host_header", base, timeout=60)
        if tr2 and tr2.status == "success" and tr2.results.get("host_header_findings"):
            result.tools_run.append("host_header")
            for h in tr2.results["host_header_findings"]:
                result.findings.append(self._make_finding(
                    tool="host_header", name=f"Host-header issue: {h.get('issue')}",
                    severity="MEDIUM", confidence=65, url=base,
                    description=json.dumps(h)[:300], false_positive_risk="MEDIUM"))

        # CRLF injection testing
        crlf_tr = self._run_tool("crlf", base, timeout=90,
                                 full_url=base, endpoints=smap.get("endpoints", []))
        if crlf_tr and crlf_tr.status == "success" and crlf_tr.results.get("crlf_findings"):
            result.tools_run.append("crlf")
            for cf in crlf_tr.results["crlf_findings"]:
                result.findings.append(self._make_finding(
                    tool="crlf", name=f"CRLF injection: {cf.get('injected_header', 'header inject')}",
                    severity="HIGH", confidence=cf.get("confidence", 80),
                    url=cf.get("url", base), description=cf.get("description", "")[:300],
                    false_positive_risk="LOW"))

        # Missing security headers already captured in recon posture
        for h in smap["posture"].get("missing_security_headers", [])[:8]:
            if h not in [f.name for f in result.findings]:
                result.findings.append(self._make_finding(
                    tool="header_analysis", name=f"Missing security header: {h}",
                    severity="LOW", confidence=60, url=base, false_positive_risk="LOW"))

        analysis = self._llm_json(REASON_HEADERS,
                                  f"Headers: {json.dumps(smap['posture'].get('response_headers', {}))}",
                                  temperature=0.2)
        if analysis and analysis.get("findings"):
            for f in analysis["findings"][:5]:
                result.findings.append(self._make_finding(
                    tool="analysis", name=f.get("name", "Header weakness"),
                    severity=f.get("severity", "MEDIUM"), confidence=f.get("confidence", 55),
                    description=f.get("description", ""), false_positive_risk="MEDIUM"))

        result.status = "success" if result.findings else "partial"
        return result


class SubdomainTakeoverAgent(BaseAgent):
    """Check discovered subdomains for takeover (nuclei takeover / subjack)."""

    agent_name = "subdomain_takeover"
    owned_tools = ["nuclei_takeover", "subjack"]

    def should_run(self, smap: dict[str, Any]) -> bool:
        return bool(smap["assets"].get("subdomains"))

    def run(self, target: str, smap: dict[str, Any], memory: dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        subs = smap["assets"].get("subdomains", [])[:15]
        if not subs:
            result.status = "skipped"
            return result

        domain = str(smap.get("target", target)).split(":")[0].replace("https://", "").replace("http://", "")
        tr = self._run_tool("nuclei_takeover", domain, timeout=180)
        if tr and tr.status == "success":
            result.tools_run.append(f"nuclei_takeover({len(tr.results.get('nuclei_findings', []))} findings)")
            for f in tr.results.get("nuclei_findings", []):
                result.findings.append(self._make_finding(
                    tool="nuclei", name=f"Takeover candidate: {f.get('name', f.get('template_id'))}",
                    severity="HIGH", confidence=75, url=f.get("url", ""),
                    description=f.get("description", "")[:300], false_positive_risk="LOW"))

        if not result.findings:
            tr2 = self._run_tool("subjack", domain, timeout=120)
            if tr2 and tr2.status == "success":
                result.tools_run.append(f"subjack({len(tr2.results.get('takeover_candidates', []))} candidates)")
                for c in tr2.results.get("takeover_candidates", []):
                    if "not vulnerable" not in str(c.get("status", "")).lower():
                        result.findings.append(self._make_finding(
                            tool="subjack", name=f"Takeover candidate: {c.get('domain')}",
                            severity="HIGH", confidence=70, url=c.get("domain", ""),
                            description=c.get("status", ""), false_positive_risk="LOW"))

        strat = self._llm_json(REASON_TAKEOVER,
                               f"Subdomains: {json.dumps(subs)}\nFindings: {json.dumps([f.to_dict() for f in result.findings])}",
                               temperature=0.2)
        if strat and strat.get("candidates"):
            for c in strat["candidates"][:5]:
                result.attack_paths_discovered.append(f"PIVOT:{c}|web_attack|takeover candidate")

        result.status = "success" if result.findings else "partial"
        return result


class WafBypassAgent(BaseAgent):
    """Detect WAF/CDN and pick non-intrusive bypass probes."""

    agent_name = "waf_bypass"
    owned_tools = ["wafw00f", "nuclei_wafdetect", "waf_bypass_payloads"]

    def should_run(self, smap: dict[str, Any]) -> bool:
        return bool(smap.get("web_surfaces")) or bool(smap.get("technologies"))

    def run(self, target: str, smap: dict[str, Any], memory: dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        tr = self._run_tool("wafw00f", base, timeout=90)
        if tr and tr.status == "success" and tr.results.get("wafs_detected"):
            result.tools_run.append("wafw00f")
            for w in tr.results["wafs_detected"]:
                result.findings.append(self._make_finding(
                    tool="wafw00f", name=f"WAF detected: {w.get('waf_name', '')}",
                    severity="INFO", confidence=85, url=base,
                    description=f"Manufacturer: {w.get('waf_manufacturer', '')}",
                    false_positive_risk="LOW"))

        if not result.findings:
            tr2 = self._run_tool("nuclei_wafdetect", base, timeout=120)
            if tr2 and tr2.status == "success" and tr2.results.get("nuclei_findings"):
                result.tools_run.append("nuclei_wafdetect")
                for f in tr2.results["nuclei_findings"]:
                    result.findings.append(self._make_finding(
                        tool="nuclei", name=f"WAF detection: {f.get('name')}",
                        severity="INFO", confidence=80, url=f.get("url", ""),
                        false_positive_risk="LOW"))

        if result.findings:
            analysis = self._llm_json(REASON_WAF,
                                      f"WAF findings: {json.dumps([f.to_dict() for f in result.findings])}",
                                      temperature=0.2)
            if analysis and analysis.get("bypass_techniques"):
                result.proof_requests = analysis["bypass_techniques"]
                result.reasoning = analysis.get("reasoning", "")

        # Step 2: If a WAF was detected, test bypass payloads
        waf_name = ""
        for f in result.findings:
            if "WAF detected" in f.name:
                waf_name = f.name.split(": ", 1)[-1] if ": " in f.name else "unknown"
                break
        if waf_name:
            bypass_tr = self._run_tool("waf_bypass_payloads", base, timeout=120,
                                       full_url=base, waf_type=waf_name)
            if bypass_tr and bypass_tr.status == "success":
                result.tools_run.append("waf_bypass_payloads")
                for bf in bypass_tr.results.get("bypass_findings", []):
                    result.findings.append(self._make_finding(
                        tool="waf_bypass", name=f"WAF bypass via {bf.get('encoding', '?')}: {bf.get('attack_type', '?')}",
                        severity="HIGH", confidence=bf.get("confidence", 60),
                        url=bf.get("url", base), description=bf.get("description", "")[:300],
                        false_positive_risk="MEDIUM"))

        result.status = "success" if result.findings else "skipped"
        return result


class JWTAnalystAgent(BaseAgent):
    """Stateless JWT weakness checks (alg=none / key confusion). No brute force.

    Searches the SystemMap for JWT-like tokens in endpoints, headers, and
    JavaScript files before giving up. Only skips when truly no token signal exists.
    """

    agent_name = "jwt"
    owned_tools = ["jwt_tool"]

    def should_run(self, smap: dict[str, Any]) -> bool:
        blob = " ".join(str(x) for x in (smap.get("endpoints", []) + smap.get("js_endpoints", []))).lower()
        return "jwt" in blob or "bearer" in blob or "token" in blob or bool(smap.get("api_paths"))

    def run(self, target: str, smap: dict[str, Any], memory: dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="skipped")
        # Search for JWT signals in the SystemMap before giving up
        jwt_signals = []
        for ep in smap.get("endpoints", []) + smap.get("js_endpoints", []):
            ep_str = str(ep).lower()
            if "jwt" in ep_str or "token" in ep_str or "bearer" in ep_str:
                jwt_signals.append(ep)
        for header_val in str(smap.get("posture", {}).get("response_headers", {})).lower().split():
            if "bearer" in header_val or "jwt" in header_val:
                jwt_signals.append(header_val)

        if not jwt_signals:
            result.error = "No JWT token signal found in SystemMap; supply token manually to jwt_tool."
            return result

        # We have signals but no captured token — report what we found for manual investigation
        result.status = "partial"
        result.reasoning = f"JWT signals detected ({len(jwt_signals)} sources) but no captured token to test."
        result.findings.append(self._make_finding(
            tool="analysis", name="JWT/token surface detected",
            severity="INFO", confidence=60,
            description=f"JWT/bearer/token references found in: {', '.join(str(s)[:80] for s in jwt_signals[:5])}. "
                        "Manual token capture required for automated testing.",
            false_positive_risk="LOW"))
        result.proof_requests = ["Capture a valid JWT from the target for automated alg/weakness testing"]
        return result


# ── XXE Agent ─────────────────────────────────────────────────────────────

REASON_XXE = """You are the XXEAgent for CyberSwarm.
Analyze the SystemMap for XML-capable endpoints (SOAP, WSDL, Content-Type
application/xml/text/xml, REST APIs accepting XML). Decide which endpoints
to test for XML External Entity injection. Output JSON:
{"xml_endpoints": ["..."], "run_xxe": true, "run_nuclei_xxe": true,
 "content_type": "application/xml", "reasoning": "..."}"""


class XXEAgent(BaseAgent):
    """Test for XML External Entity (XXE) injection on XML-capable endpoints."""

    agent_name = "xxe"
    owned_tools = ["xxe", "nuclei_xxe"]

    def should_run(self, smap: dict[str, Any]) -> bool:
        blob = " ".join(str(x) for x in (
            smap.get("endpoints", []) + smap.get("api_paths", [])
        )).lower()
        tech_blob = " ".join(t.get("name", "").lower() for t in smap.get("technologies", [])).lower()
        has_xml = any(kw in blob for kw in ("xml", "soap", "wsdl", "graphql"))
        has_xml_tech = any(kw in tech_blob for kw in ("soap", "xml", "wsdl", ".net", "axis"))
        # Also check for Content-Type headers that accept XML
        headers = smap.get("posture", {}).get("response_headers", {})
        ct = str(headers.get("content-type", "")).lower()
        has_xml_ct = "xml" in ct
        return has_xml or has_xml_tech or has_xml_ct

    def run(self, target: str, smap: dict[str, Any], memory: dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        # Collect XML-relevant endpoints from SystemMap
        xml_endpoints = []
        for ep in smap.get("endpoints", []) + smap.get("api_paths", []):
            ep_str = str(ep).lower()
            if any(kw in ep_str for kw in ("xml", "soap", "wsdl", "api", "graphql")):
                xml_endpoints.append(str(ep))

        # LLM strategy
        strat = self._llm_json(REASON_XXE,
                               f"SystemMap endpoints: {json.dumps(xml_endpoints[:15])}\n"
                               f"Technologies: {json.dumps([t.get('name') for t in smap.get('technologies', [])])}",
                               temperature=0.2)
        if strat:
            result.reasoning = strat.get("reasoning", "")
            if not strat.get("run_xxe", True):
                result.status = "skipped"
                return result
            xml_endpoints = strat.get("xml_endpoints", xml_endpoints)

        # Run custom XXE tool
        tr = self._run_tool("xxe", base, timeout=120,
                            full_url=base, endpoints=xml_endpoints)
        if tr and tr.status == "success":
            result.tools_run.append("xxe")
            for f in tr.results.get("xxe_findings", []):
                result.findings.append(self._make_finding(
                    tool="xxe", name=f"XXE injection ({f.get('variant', 'unknown')})",
                    severity=f.get("severity", "HIGH"), confidence=f.get("confidence", 70),
                    url=f.get("url", base), description=f.get("description", "")[:300],
                    false_positive_risk="MEDIUM"))

        # Fallback: nuclei XXE templates
        if not result.findings:
            tr2 = self._run_tool("nuclei_xxe", base, timeout=180,
                                 tags="xxe", severity="low,medium,high,critical")
            if tr2 and tr2.status == "success" and tr2.results.get("nuclei_findings"):
                result.tools_run.append("nuclei_xxe")
                for f in tr2.results["nuclei_findings"]:
                    result.findings.append(self._make_finding(
                        tool="nuclei", name=f"XXE: {f.get('name', f.get('template_id'))}",
                        severity=f.get("severity", "HIGH"), confidence=75,
                        url=f.get("url", base), description=f.get("description", "")[:300],
                        false_positive_risk="MEDIUM"))

        result.status = "success" if result.findings else "partial"
        return result


# ── CSRF Agent ────────────────────────────────────────────────────────────

REASON_CSRF = """You are the CSRFScanAgent for CyberSwarm.
Analyze the SystemMap for state-changing operations that may lack CSRF
protection. Look for forms, auth paths, admin panels, PUT/DELETE endpoints.
Output JSON:
{"check_forms": true, "state_changing_gets": ["..."], "forms_to_test": ["..."],
 "run_csrf": true, "reasoning": "..."}"""


class CSRFScanAgent(BaseAgent):
    """Test CSRF-vulnerable forms detected during recon for token bypass."""

    agent_name = "csrf"
    owned_tools = ["csrf"]

    def should_run(self, smap: dict[str, Any]) -> bool:
        # Only run if recon detected CSRF-vulnerable surface
        return bool(smap.get("csrf_surface"))

    def run(self, target: str, smap: dict[str, Any], memory: dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        # Read CSRF surface from recon detection
        csrf_surface = smap.get("csrf_surface", [])
        if not csrf_surface:
            result.status = "skipped"
            result.error = "No CSRF surface detected during recon"
            return result

        strat = self._llm_json(REASON_CSRF,
                               f"CSRF surface from recon: {json.dumps(csrf_surface[:10])}",
                               temperature=0.2)
        if strat:
            result.reasoning = strat.get("reasoning", "")

        # Pass recon-detected forms to the attack tool
        tr = self._run_tool("csrf", base, timeout=120,
                            full_url=base, csrf_surface=csrf_surface)
        if tr and tr.status == "success":
            result.tools_run.append("csrf")
            for f in tr.results.get("csrf_findings", []):
                result.findings.append(self._make_finding(
                    tool="csrf", name=f"CSRF: {f.get('issue', 'missing protection')}",
                    severity=f.get("severity", "MEDIUM"), confidence=f.get("confidence", 60),
                    url=f.get("url", base), description=f.get("description", "")[:300],
                    false_positive_risk="MEDIUM"))

        result.status = "success" if result.findings else "partial"
        return result


# ── Deserialization Agent ─────────────────────────────────────────────────

REASON_DESER = """You are the DeserializationAgent for CyberSwarm.
Analyze the SystemMap for technologies and endpoints vulnerable to
deserialization attacks (Java RMI, .NET ViewState, PHP unserialize, Python pickle).
Output JSON:
{"tech_indicators": ["..."], "endpoints_to_check": ["..."],
 "run_nuclei_deser": true, "reasoning": "..."}"""


class DeserializationAgent(BaseAgent):
    """Test deserialization endpoints detected during recon for active exploitation."""

    agent_name = "deserialization"
    owned_tools = ["deserialization", "nuclei_deserialization"]

    def should_run(self, smap: dict[str, Any]) -> bool:
        # Only run if recon detected deserialization vectors
        return bool(smap.get("deserialization_vectors"))

    def run(self, target: str, smap: dict[str, Any], memory: dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        # Read deserialization vectors from recon detection
        deser_vectors = smap.get("deserialization_vectors", [])
        if not deser_vectors:
            result.status = "skipped"
            result.error = "No deserialization vectors detected during recon"
            return result

        # Extract endpoints from recon vectors
        deser_endpoints = [v.get("url", "") for v in deser_vectors if v.get("url")]

        strat = self._llm_json(REASON_DESER,
                               f"Deserialization vectors from recon: {json.dumps(deser_vectors[:10])}",
                               temperature=0.2)
        if strat:
            result.reasoning = strat.get("reasoning", "")

        # Pass recon-detected endpoints to the attack tool
        tr = self._run_tool("deserialization", base, timeout=120,
                            full_url=base, endpoints=deser_endpoints)
        if tr and tr.status == "success":
            result.tools_run.append("deserialization")
            for f in tr.results.get("deserialization_findings", []):
                result.findings.append(self._make_finding(
                    tool="deserialization", name=f"Deserialization: {f.get('issue', 'vector confirmed')}",
                    severity=f.get("severity", "HIGH"), confidence=f.get("confidence", 65),
                    url=f.get("url", base), description=f.get("description", "")[:300],
                    false_positive_risk="MEDIUM"))

        # Fallback: nuclei deserialization templates
        if not result.findings:
            tr2 = self._run_tool("nuclei_deserialization", base, timeout=180,
                                 tags="deserialization")
            if tr2 and tr2.status == "success" and tr2.results.get("nuclei_findings"):
                result.tools_run.append("nuclei_deserialization")
                for f in tr2.results["nuclei_findings"]:
                    result.findings.append(self._make_finding(
                        tool="nuclei", name=f"Deserialization: {f.get('name', f.get('template_id'))}",
                        severity=f.get("severity", "HIGH"), confidence=75,
                        url=f.get("url", base), description=f.get("description", "")[:300],
                        false_positive_risk="MEDIUM"))

        result.status = "success" if result.findings else "partial"
        return result


# ── Session Hijacking Agent ──────────────────────────────────────────────

REASON_SESSION = """You are the SessionHijackAgent for CyberSwarm.
Analyze the SystemMap for session security issues: cookie flags, token entropy,
session fixation vectors, and token leakage. Output JSON:
{"check_fixation": true, "check_hijack": true, "auth_paths": ["..."],
 "risk_areas": ["..."], "reasoning": "..."}"""


class SessionHijackAgent(BaseAgent):
    """Test session management for fixation, hijacking, and token leakage."""

    agent_name = "session_hijack"
    owned_tools = ["session_analyzer", "session_fixation", "session_hijack"]

    def should_run(self, smap: dict) -> bool:
        has_cookies = bool(smap.get("cookies"))
        has_auth = bool(smap.get("auth_paths"))
        has_web = bool(smap.get("web_surfaces"))
        return has_auth or has_cookies or has_web

    def run(self, target: str, smap: dict, memory: dict) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        cookies = {}

        strat = self._llm_json(REASON_SESSION,
                               f"Auth paths: {json.dumps(smap.get('auth_paths', [])[:10])}\n"
                               f"Technologies: {json.dumps([t.get('name') for t in smap.get('technologies', [])])}\n"
                               f"Posture: {json.dumps(smap.get('posture', {}))}",
                               temperature=0.2)
        if strat:
            result.reasoning = strat.get("reasoning", "")

        tr = self._run_tool("session_analyzer", base, timeout=30,
                            full_url=base, auth_paths=smap.get("auth_paths", []))
        if tr and tr.status == "success":
            result.tools_run.append("session_analyzer")
            for s in tr.results.get("sessions", []):
                if s.get("risk") in ("HIGH", "CRITICAL"):
                    issues_text = "; ".join(s.get("issues", []))
                    result.findings.append(self._make_finding(
                        tool="session_analyzer",
                        name=f"Session token weakness: {s.get('token_name', '?')} ({s.get('token_format', '?')})",
                        severity=s.get("risk", "MEDIUM"), confidence=80,
                        url=base,
                        description=f"Token '{s.get('token_name')}' ({s.get('token_length')} chars, "
                                    f"{s.get('token_format')} format, {s.get('entropy', 0):.1f} entropy, "
                                    f"{s.get('bit_strength', 0):.0f} bits). {issues_text}",
                        false_positive_risk="LOW"))
            for s in tr.results.get("sessions", []):
                if s.get("token_name") and s.get("sample_token"):
                    cookies[s["token_name"]] = s.get("sample_token", "")

        tr2 = self._run_tool("session_fixation", base, timeout=30,
                             full_url=base, auth_paths=smap.get("auth_paths", []))
        if tr2 and tr2.status == "success":
            result.tools_run.append("session_fixation")
            for f in tr2.results.get("findings", []):
                result.findings.append(self._make_finding(
                    tool="session_fixation",
                    name=f"Session fixation: {f.get('type', 'vulnerability')}",
                    severity=f.get("severity", "HIGH"), confidence=75,
                    url=f.get("url", base),
                    description=f"{f.get('evidence', '')}. {f.get('description', '')}",
                    false_positive_risk="MEDIUM"))

        if cookies:
            tr3 = self._run_tool("session_hijack", base, timeout=30,
                                 full_url=base, cookies=cookies)
            if tr3 and tr3.status == "success":
                result.tools_run.append("session_hijack")
                for f in tr3.results.get("findings", []):
                    result.findings.append(self._make_finding(
                        tool="session_hijack",
                        name=f"Session hijack: {f.get('type', 'vulnerability')}",
                        severity=f.get("severity", "MEDIUM"), confidence=65,
                        url=f.get("url", base),
                        description=f"{f.get('evidence', '')}. {f.get('description', '')}",
                        false_positive_risk="MEDIUM"))

        result.status = "success" if result.findings else "partial"
        return result


# ── SSTI Exploitation Agent ────────────────────────────────────────────────

REASON_SSTI = """You are the SSTIExploitAgent for CyberSwarm.
Analyze the SystemMap for Server-Side Template Injection vectors: user input in
URL params, POST body, headers reflected in response. Identify template engine
from technologies (Jinja2/Twig/Smarty/Freemarker/Mako). Output JSON:
{"param": "...", "engine_hint": "...", "method": "GET|POST", "reasoning": "..."}"""


class SSTIExploitAgent(BaseAgent):
    """Active SSTI exploitation — engine fingerprinting, file read, RCE."""

    agent_name = "ssti_exploit"
    owned_tools = ["ssti_exploit", "nuclei_ssti"]

    def should_run(self, smap: dict) -> bool:
        has_web = bool(smap.get("web_surfaces") or smap.get("endpoints"))
        has_params = bool(smap.get("params"))
        has_ssti_tech = any(t.get("name", "").lower() in ("jinja2", "twig", "smarty", "freemarker", "mako")
                           for t in smap.get("technologies", []))
        return has_web and (has_params or has_ssti_tech or bool(smap.get("endpoints")))

    def _ssti_candidates(self, base: str, smap: dict, strat: dict) -> list:
        """Build (endpoint_url, param_name) candidates from map + live forms.

        The template engine evaluates the value of the *form* parameter (e.g.
        /greet?name=), which is usually not the site root, so probing
        base?param=payload alone misses the real surface.

        Freeze-3 fix (env-gated, CYBERSWARM_SSTI_ENDPOINT_CANDS=1): recon's
        discovered parameterized endpoints (smap['endpoints'], e.g.
        /calc?expr=1) are expanded into candidates.  Diagnosis of the 0/5
        ssti e2e misses (2026-11-13) showed /calc was already in the map but
        never probed — params[] was empty, forms capped at 4, and the single
        LLM-suggested param was applied to the root URL only.
        """
        cands: list = []
        seen: set = set()
        import os as _os
        if _os.environ.get("CYBERSWARM_SSTI_ENDPOINT_CANDS") == "1":
            for e in (smap.get("endpoints") or [])[:8]:
                u = e.get("url") if isinstance(e, dict) else (e if isinstance(e, str) else "")
                if "?" not in u or not u.startswith("http"):
                    continue
                b, q = u.split("?", 1)
                name = q.split("=", 1)[0]
                if name and (b, name) not in seen:
                    seen.add((b, name))
                    cands.append((b, name))
        for p in (smap.get("params") or [])[:8]:
            if isinstance(p, dict):
                url, name = p.get("url", ""), p.get("name", "")
            elif isinstance(p, str) and p.startswith("http") and "?" in p:
                url, name = p.split("?", 1)
                name = name.split("=", 1)[0]
            else:
                continue
            key = (url.split("?")[0], name)
            if url and name and key not in seen:
                seen.add(key)
                cands.append(key)
        try:
            from agents.web_attack_agent import WebAttackAgent
            urls, _bodies = WebAttackAgent.__new__(
                WebAttackAgent)._form_inject_targets(base)
            for u in urls[:4]:
                b, q = u.split("?", 1)
                name = q.split("=", 1)[0]
                if (b, name) not in seen:
                    seen.add((b, name))
                    cands.append((b, name))
        except Exception:  # noqa: BLE001
            pass
        llm_param = (strat or {}).get("param", "")
        if llm_param and (base, llm_param) not in seen:
            cands.append((base, llm_param))
        if not cands:
            cands.append((base, ""))
        return cands[:4]

    def run(self, target: str, smap: dict, memory: dict) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        strat = self._llm_json(REASON_SSTI,
                               f"Params: {json.dumps(smap.get('params', [])[:10])}\n"
                               f"Technologies: {json.dumps([t.get('name') for t in smap.get('technologies', [])])}\n"
                               f"Endpoints: {json.dumps(smap.get('endpoints', [])[:10])}",
                               temperature=0.2)
        if strat:
            result.reasoning = strat.get("reasoning", "")

        for cand_base, cand_param in self._ssti_candidates(base, smap, strat):
            tr = self._run_tool("ssti_exploit", cand_base, timeout=90,
                                full_url=cand_base, param=cand_param)
            if tr and tr.status == "success" and tr.results.get("ssti_findings"):
                result.tools_run.append(f"ssti_exploit({cand_base}?{cand_param})")
                for f in tr.results.get("ssti_findings", []):
                    result.findings.append(self._make_finding(
                        tool="ssti_exploit",
                        name=f"SSTI: {f.get('type', 'injection')} ({f.get('engine', '?')})",
                        severity=f.get("severity", "HIGH"), confidence=f.get("confidence", 70),
                        url=f.get("url", cand_base),
                        description=f"{f.get('description', '')}",
                        false_positive_risk="MEDIUM",
                        raw_output_excerpt=f.get("evidence", "")[:300]))
                break  # engine confirmed on this candidate; no need for more

        if not result.findings:
            tr2 = self._run_tool("nuclei_ssti", base, timeout=180,
                                 tags="ssti", severity="low,medium,high,critical")
            if tr2 and tr2.status == "success":
                result.tools_run.append("nuclei_ssti")
                for f in tr2.results.get("nuclei_findings", []):
                    result.findings.append(self._make_finding(
                        tool="nuclei", name=f"SSTI: {f.get('name', f.get('template_id'))}",
                        severity=f.get("severity", "HIGH"), confidence=75,
                        url=f.get("url", base), description=f.get("description", "")[:300],
                        false_positive_risk="MEDIUM"))

        result.status = "success" if result.findings else "partial"
        return result


# ── LFI Exploitation Agent ─────────────────────────────────────────────────

REASON_LFI = """You are the LFIExploitAgent for CyberSwarm.
Analyze the SystemMap for Local File Inclusion / path traversal vectors:
file parameters, include parameters, path parameters in URLs. Check for
PHP wrappers, null byte injection potential. Output JSON:
{"param": "...", "endpoint": "...", "method": "GET|POST", "reasoning": "..."}"""


class LFIExploitAgent(BaseAgent):
    """Active LFI exploitation — path traversal, PHP wrappers, file read."""

    agent_name = "lfi_exploit"
    owned_tools = ["lfi_exploit", "nuclei_lfi"]

    def should_run(self, smap: dict) -> bool:
        has_web = bool(smap.get("web_surfaces"))
        has_params = bool(smap.get("params"))
        params_blob = " ".join(str(p) for p in smap.get("params", [])).lower()
        has_file_param = any(kw in params_blob for kw in ("file", "include", "path", "page", "doc", "load"))
        return has_web and (has_params or has_file_param)

    def run(self, target: str, smap: dict, memory: dict) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        strat = self._llm_json(REASON_LFI,
                               f"Params: {json.dumps(smap.get('params', [])[:10])}\n"
                               f"Endpoints: {json.dumps(smap.get('endpoints', [])[:10])}",
                               temperature=0.2)
        if strat:
            result.reasoning = strat.get("reasoning", "")

        param = (strat or {}).get("param", "")
        endpoint = (strat or {}).get("endpoint", "")
        tr = self._run_tool("lfi_exploit", base, timeout=60,
                            full_url=base, param=param, endpoint=endpoint)
        if tr and tr.status == "success":
            result.tools_run.append("lfi_exploit")
            for f in tr.results.get("lfi_findings", []):
                result.findings.append(self._make_finding(
                    tool="lfi_exploit",
                    name=f"LFI: {f.get('type', 'injection')} ({f.get('variant', '?')})",
                    severity=f.get("severity", "HIGH"), confidence=f.get("confidence", 70),
                    url=f.get("url", base),
                    description=f"{f.get('description', '')}",
                    false_positive_risk="MEDIUM",
                    raw_output_excerpt=f.get("evidence", "")[:300]))

        if not result.findings:
            tr2 = self._run_tool("nuclei_lfi", base, timeout=180,
                                 tags="lfi", severity="low,medium,high,critical")
            if tr2 and tr2.status == "success":
                result.tools_run.append("nuclei_lfi")
                for f in tr2.results.get("nuclei_findings", []):
                    result.findings.append(self._make_finding(
                        tool="nuclei", name=f"LFI: {f.get('name', f.get('template_id'))}",
                        severity=f.get("severity", "HIGH"), confidence=75,
                        url=f.get("url", base), description=f.get("description", "")[:300],
                        false_positive_risk="MEDIUM"))

        result.status = "success" if result.findings else "partial"
        return result


# ── SSRF Exploitation Agent ────────────────────────────────────────────────

REASON_SSRF = """You are the SSRFExploitAgent for CyberSwarm.
Analyze the SystemMap for Server-Side Request Forgery vectors: URLs in params,
webhook endpoints, file fetch functionality, image proxy. Output JSON:
{"param": "...", "endpoint": "...", "method": "GET|POST", "reasoning": "..."}"""


class SSRFExploitAgent(BaseAgent):
    """Active SSRF exploitation — cloud metadata, internal network, protocol smuggling."""

    agent_name = "ssrf_exploit"
    owned_tools = ["ssrf_exploit", "nuclei_ssrf"]

    def should_run(self, smap: dict) -> bool:
        has_web = bool(smap.get("web_surfaces"))
        has_params = bool(smap.get("params"))
        params_blob = " ".join(str(p) for p in smap.get("params", [])).lower()
        has_ssrf_param = any(kw in params_blob for kw in ("url", "fetch", "webhook", "redirect", "proxy", "img"))
        return has_web and (has_params or has_ssrf_param)

    def run(self, target: str, smap: dict, memory: dict) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        strat = self._llm_json(REASON_SSRF,
                               f"Params: {json.dumps(smap.get('params', [])[:10])}\n"
                               f"Endpoints: {json.dumps(smap.get('endpoints', [])[:10])}",
                               temperature=0.2)
        if strat:
            result.reasoning = strat.get("reasoning", "")

        param = (strat or {}).get("param", "")
        endpoint = (strat or {}).get("endpoint", "")
        tr = self._run_tool("ssrf_exploit", base, timeout=60,
                            full_url=base, param=param, endpoint=endpoint)
        if tr and tr.status == "success":
            result.tools_run.append("ssrf_exploit")
            for f in tr.results.get("ssrf_findings", []):
                result.findings.append(self._make_finding(
                    tool="ssrf_exploit",
                    name=f"SSRF: {f.get('type', 'forgery')}",
                    severity=f.get("severity", "HIGH"), confidence=f.get("confidence", 70),
                    url=f.get("url", base),
                    description=f"{f.get('description', '')}",
                    false_positive_risk="MEDIUM",
                    raw_output_excerpt=f.get("evidence", "")[:300]))

        if not result.findings:
            tr2 = self._run_tool("nuclei_ssrf", base, timeout=180,
                                 tags="ssrf", severity="low,medium,high,critical")
            if tr2 and tr2.status == "success":
                result.tools_run.append("nuclei_ssrf")
                for f in tr2.results.get("nuclei_findings", []):
                    result.findings.append(self._make_finding(
                        tool="nuclei", name=f"SSRF: {f.get('name', f.get('template_id'))}",
                        severity=f.get("severity", "HIGH"), confidence=75,
                        url=f.get("url", base), description=f.get("description", "")[:300],
                        false_positive_risk="MEDIUM"))

        result.status = "success" if result.findings else "partial"
        return result


# ── JWT Exploitation Agent (enhanced) ──────────────────────────────────────

REASON_JWT_EXPLOIT = """You are the JWTExploitAgent for CyberSwarm.
Find JWT tokens in cookies, Authorization headers, or response bodies.
Perform active attacks: alg:none bypass, weak secret cracking, claim
tampering, kid injection. Output JSON:
{"found_jwt": true, "token": "<prefix>", "endpoint": "...", "reasoning": "..."}"""


class JWTExploitAgent(BaseAgent):
    """Active JWT exploitation — algorithm confusion, weak secrets, claim tampering."""

    agent_name = "jwt_exploit"
    owned_tools = ["jwt_exploit", "jwt_tool"]

    def should_run(self, smap: dict) -> bool:
        has_auth = bool(smap.get("auth_paths"))
        has_cookies = bool(smap.get("cookies"))
        endpoints_blob = " ".join(str(e) for e in smap.get("endpoints", []) + smap.get("js_endpoints", [])).lower()
        has_jwt_signal = any(kw in endpoints_blob for kw in ("jwt", "bearer", "token", "auth"))
        return has_auth or has_cookies or has_jwt_signal

    def run(self, target: str, smap: dict, memory: dict) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        strat = self._llm_json(REASON_JWT_EXPLOIT,
                               f"Auth paths: {json.dumps(smap.get('auth_paths', [])[:5])}\n"
                               f"Cookies: {json.dumps(list(smap.get('cookies', {}).keys())[:5])}\n"
                               f"Technologies: {json.dumps([t.get('name') for t in smap.get('technologies', [])])}",
                               temperature=0.2)
        if strat:
            result.reasoning = strat.get("reasoning", "")

        endpoint = (strat or {}).get("endpoint", "")
        tr = self._run_tool("jwt_exploit", base, timeout=60,
                            full_url=base, endpoint=endpoint)
        if tr and tr.status == "success":
            result.tools_run.append("jwt_exploit")
            for f in tr.results.get("jwt_findings", []):
                result.findings.append(self._make_finding(
                    tool="jwt_exploit",
                    name=f"JWT: {f.get('type', 'weakness')}",
                    severity=f.get("severity", "HIGH"), confidence=f.get("confidence", 70),
                    url=f.get("url", base),
                    description=f"{f.get('description', '')}",
                    false_positive_risk="MEDIUM",
                    raw_output_excerpt=f.get("evidence", "")[:300]))

        token = (strat or {}).get("token", "")
        if token:
            tr2 = self._run_tool("jwt_tool", base, timeout=30, token=token)
            if tr2 and tr2.status == "success":
                result.tools_run.append("jwt_tool")
                for f in tr2.results.get("jwt_findings", []):
                    result.findings.append(self._make_finding(
                        tool="jwt_tool",
                        name=f"JWT analysis: {f.get('issue', 'weakness')}",
                        severity=f.get("severity", "MEDIUM"), confidence=65,
                        url=base,
                        description=f"{f.get('issue', '')}",
                        false_positive_risk="LOW"))

        result.status = "success" if result.findings else "partial"
        return result


# ── Insecure Design Analysis Agent (OWASP A04) ─────────────────────────────

REASON_DESIGN = """You are the InsecureDesignAgent for CyberSwarm.
Analyze the SystemMap for OWASP A04 Insecure Design: business-logic flaws,
missing rate limiting, debug/insecure defaults, trust-boundary violations,
and excessive trust in client-side controls. This is ANALYSIS ONLY — do not
run any active exploitation. Output JSON:
{"design_risks": [{"name","severity","confidence","description","remediation"}],
 "reasoning": "..."}"""


class InsecureDesignAgent(BaseAgent):
    """Analysis-only review for OWASP A04 Insecure Design (business logic)."""

    agent_name = "insecure_design"
    owned_tools = []

    def should_run(self, smap: dict) -> bool:
        return bool(smap.get("web_surfaces")) or bool(smap.get("endpoints")) or bool(smap.get("api_paths"))

    def run(self, target: str, smap: dict, memory: dict) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        # Deterministic heuristics for common insecure-design signals.
        endpoints = " ".join(str(e) for e in smap.get("endpoints", []))
        params = " ".join(str(p) for p in smap.get("params", []))
        blob = (endpoints + " " + params).lower()
        found = []
        if any(kw in blob for kw in ("debug", "test", "demo", "dev", "staging", "sandbox")):
            found.append({"name": "Debug/staging endpoints exposed",
                          "severity": "LOW", "confidence": 55,
                          "description": "Surface references debug, test, demo, dev, staging or sandbox paths.",
                          "remediation": "Remove or gate non-production endpoints."})
        if any(kw in blob for kw in ("reset", "forgot", "password/", "recover")):
            found.append({"name": "Credential-reset flow present (verify rate limiting)",
                          "severity": "MEDIUM", "confidence": 50,
                          "description": "Password reset/recovery surface present; verify enumeration and "
                                         "rate-limiting protections.",
                          "remediation": "Enforce rate limiting and prevent user/ID enumeration."})

        analysis = self._llm_json(REASON_DESIGN,
                                  f"Endpoints: {json.dumps(smap.get('endpoints', [])[:15])}\n"
                                  f"Params: {json.dumps(smap.get('params', [])[:15])}\n"
                                  f"Technologies: {json.dumps([t.get('name') for t in smap.get('technologies', [])])}",
                                  temperature=0.3)
        if analysis and analysis.get("design_risks"):
            for r in analysis["design_risks"]:
                found.append({"name": r.get("name", "Design risk"),
                              "severity": r.get("severity", "MEDIUM"),
                              "confidence": r.get("confidence", 55),
                              "description": r.get("description", ""),
                              "remediation": r.get("remediation", "")})

        if found:
            for f in found[:8]:
                result.findings.append(self._make_finding(
                    tool="analysis", name=f.get("name", "Insecure design"),
                    severity=f.get("severity", "MEDIUM"), confidence=f.get("confidence", 55),
                    url=base, description=f.get("description", ""),
                    false_positive_risk="HIGH"))
            result.reasoning = "Insecure design analysis produced heuristics + LLM review."
        else:
            found.append({"name": "No obvious insecure-design flaws", "severity": "INFO",
                          "confidence": 60, "description": "No debug/test endpoints or exposed flows detected."})
            result.findings.append(self._make_finding(
                tool="analysis", name=found[0]["name"], severity="INFO", confidence=60,
                url=base, description=found[0]["description"], false_positive_risk="HIGH"))

        result.status = "success" if result.findings else "partial"
        return result
