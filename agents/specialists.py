"""
Specialist agents: Network, API, Auth, Infra, Cloud.
Each reasons over the SystemMap, runs its owned tools, and emits findings.
Deterministic fallbacks keep them useful without the LLM.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from agents.base_agent import AgentResult, BaseAgent
from utils import find_primary_url

REASON_NET = """You are the NetworkAgent for CyberSwarm.
Given open ports/services, choose which NSE vuln scripts or service checks to run
and flag credential/AD surfaces. Output JSON:
{"targets": {"ports": ["<port>"]}, "run_service_vuln": true, "nse_ports": ["<ports>"],
 "ad_environment": false, "credential_attack_surface": false, "reasoning": "..."}"""

REASON_API = """You are the APIAgent for CyberSwarm.
Analyze API surface. Output JSON:
{"run_api_probe": true, "interesting_endpoints": ["..."], "idor_risk": false,
 "graphql_introspection_risk": false, "reasoning": "..."}"""

REASON_AUTH = """You are the AuthAgent for CyberSwarm.
Analyze the authentication surface. DO NOT brute-force. Output JSON:
{"weaknesses": [{"name","severity","confidence","description"}],
 "manual_steps": ["..."], "reasoning": "..."}"""

REASON_INFRA = """You are the InfraAgent for CyberSwarm.
Analyze TLS/headers/DNS posture. Output JSON:
{"tls_issues": [{"name","severity","confidence","description"}],
 "header_issues": [{"name","severity","confidence","description"}],
 "dns_issues": [{"name","severity","confidence","description"}],
 "reasoning": "..."}"""

REASON_CLOUD = """You are the CloudAgent for CyberSwarm.
Identify passive cloud misconfigurations (public buckets, metadata, exposed APIs).
NO destructive probing. Output JSON:
{"cloud_findings": [{"name","severity","confidence","description"}], "reasoning": "..."}"""


class NetworkAgent(BaseAgent):
    agent_name = "network"
    owned_tools = ["nmap_nse", "smb_enum", "ldap_enum"]

    def should_run(self, smap: Dict[str, Any]) -> bool:
        ports = {s.get("port") for s in smap.get("services", [])}
        return bool(ports - {80, 443, 8080, 8443, 8000})

    def run(self, target: str, smap: Dict[str, Any], memory: Dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        ports = [str(s.get("port")) for s in smap.get("services", []) if s.get("port")]
        non_web = [p for p in ports if int(p) not in (80, 443, 8080, 8443, 8000)]
        if not non_web:
            result.status = "skipped"
            return result

        strat = self._llm_json(REASON_NET,
                               f"Services: {json.dumps(smap.get('services', []))}\nPorts: {non_web}",
                               temperature=0.2)
        ports_to_scan = non_web[:10]
        tr = self._run_tool("nmap_nse", target, timeout=300, ports=",".join(ports_to_scan))
        if tr and tr.status == "success":
            result.tools_run.append(f"nmap_nse(ports={','.join(ports_to_scan[:5])}...)")
            for f in tr.results.get("nmap_vuln_findings", []):
                result.findings.append(self._make_finding(
                    tool="nmap_nse", name=f.get("script", ""),
                    severity=f.get("severity", "UNKNOWN"), confidence=60,
                    port=str(f.get("port", "")), description=f.get("output", "")[:300],
                    false_positive_risk="MEDIUM"))
        if any(p in ("139", "445") for p in ports):
            tr2 = self._run_tool("smb_enum", target, timeout=120,
                                 ports=",".join(sorted({"139", "445"} & set(ports))))
            if tr2 and tr2.status == "success" and tr2.results.get("windows_enum"):
                result.tools_run.append("smb_enum")
                win = tr2.results["windows_enum"]
                shares = win.get("shares") or []
                users = win.get("users") or []
                if shares or users:
                    result.findings.append(self._make_finding(
                        tool="smb_enum",
                        name="SMB anonymous enumeration exposed shares/users",
                        severity="MEDIUM", confidence=65, port="445",
                        description=(
                            f"Anonymous SMB enumeration on {target} returned "
                            f"{len(shares)} share(s) and {len(users)} user(s): "
                            + ", ".join(shares[:8])
                            + ("; users: " + ", ".join(users[:8]) if users else "")
                            + ". Guest/anonymous read is enabled — enumerate further "
                            "for writable shares."),
                        false_positive_risk="MEDIUM"))
        if any(p in ("389", "636", "3268", "3269") for p in ports):
            tr3 = self._run_tool("ldap_enum", target, timeout=120,
                                 ports=",".join(sorted({"389", "636", "3268", "3269"} & set(ports))))
            if tr3 and tr3.status == "success" and tr3.results.get("ldap_naming_contexts"):
                result.tools_run.append("ldap_enum")
                asrep = tr3.results.get("ldap_asrep_roastable") or []
                spns = tr3.results.get("ldap_kerberoastable") or []
                hints = []
                if asrep:
                    hints.append(f"{len(asrep)} AS-REP roastable")
                if spns:
                    hints.append(f"{len(spns)} Kerberoastable")
                if hints:
                    result.findings.append(self._make_finding(
                        tool="ldap_enum",
                        name="Anonymous LDAP bind enabled on domain controller",
                        severity="MEDIUM", confidence=70, port="389",
                        description=(
                            "Anonymous LDAP bind succeeded against "
                            f"{tr3.results.get('ldap_root_dse', {}).get('dns_host_name') or target} "
                            f"(naming contexts: {tr3.results.get('ldap_naming_contexts', [])[:3]}). "
                            "Attack-facing exposure: \u2022 " + ", \u2022 ".join(hints) +
                            ". Blind-accessible object data can power AS-REP roasting "
                            "and login-spray planning."),
                        evidence_chain=[f"anonymous bind -> {h}" for h in hints],
                        false_positive_risk="MEDIUM", raw_output_excerpt="ldap_anonymous_bind: true"))

        if strat and strat.get("ad_environment"):
            result.attack_paths_discovered.append("AD environment detected — test Kerberoasting/PtH")
        if result.tools_run:
            result.status = "success" if result.findings else "partial"
        else:
            result.status = "skipped"
        return result


class APIAgent(BaseAgent):
    agent_name = "api"
    owned_tools = ["api_probe", "api_discover", "arjun"]

    def should_run(self, smap: Dict[str, Any]) -> bool:
        return bool(smap.get("api_paths")) or bool(smap["signals"].get("api_types"))

    def run(self, target: str, smap: Dict[str, Any], memory: Dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)
        api_paths = smap.get("api_paths", [])[:15]

        # Live probe of the discovered endpoints -- real evidence, not speculation.
        probed = []
        graphql_ok = []    # urls
        unauth_200 = []    # urls
        auth_required = [] # urls
        tr = self._run_tool("api_probe", base, timeout=150, paths=api_paths)
        if tr and tr.status == "success" and tr.results.get("api_probes"):
            result.tools_run.append(f"api_probe({len(tr.results['api_probes'])} endpoints)")
            for p in tr.results["api_probes"]:
                probed.append(p)
                if p.get("graphql") and p.get("graphql_responded"):
                    graphql_ok.append(p.get("url", ""))
                elif p.get("unauthenticated_200"):
                    unauth_200.append(p.get("url", ""))
                elif p.get("auth_required"):
                    auth_required.append(p.get("url", ""))

        # Aggregated findings: one per issue type with the endpoint list. Each
        # keeps its raw probe evidence so the critic can CONFIRM on evidence.
        def _api_evidence(*predicates):
            return json.dumps([p for p in probed if any(pd(p) for pd in predicates)],
                              default=str)[:400]

        if graphql_ok:
            result.findings.append(self._make_finding(
                tool="api_probe",
                name=f"GraphQL endpoints respond unauthenticated ({len(graphql_ok)})",
                severity="MEDIUM", confidence=70, url=graphql_ok[0],
                description=f"GraphQL endpoint(s) accepted a __typename probe. Endpoints: {', '.join(graphql_ok)}",
                evidence_chain=[f"{u} -> __typename accepted" for u in graphql_ok],
                false_positive_risk="MEDIUM",
                raw_output_excerpt=_api_evidence(lambda p: p.get("graphql") and p.get("graphql_responded"))))
        if unauth_200:
            result.findings.append(self._make_finding(
                tool="api_probe",
                name=f"API endpoints return 200 unauthenticated ({len(unauth_200)})",
                severity="INFO", confidence=70, url=unauth_200[0],
                description=("GET returned HTTP 200 without credentials — confirm whether sensitive "
                             "data is exposed. Endpoints: " + ", ".join(unauth_200)),
                evidence_chain=[f"{u} -> HTTP 200 no auth" for u in unauth_200],
                false_positive_risk="LOW",
                raw_output_excerpt=_api_evidence(lambda p: p.get("unauthenticated_200"))))
        if auth_required:
            result.findings.append(self._make_finding(
                tool="api_probe",
                name=f"API endpoints enforce authentication ({len(auth_required)})",
                severity="INFO", confidence=85, url=auth_required[0],
                description=("GET returned 401/403 without credentials — auth is enforced. Endpoints: "
                             + ", ".join(auth_required)),
                evidence_chain=[f"{u} -> 401/403" for u in auth_required],
                false_positive_risk="LOW",
                raw_output_excerpt=_api_evidence(lambda p: p.get("auth_required"))))

        tr1 = self._run_tool("api_discover", base, timeout=120)
        if tr1 and tr1.status == "success" and tr1.results.get("api_endpoints"):
            result.tools_run.append("api_discover")
            for ep in tr1.results["api_endpoints"][:20]:
                if ep not in result.attack_paths_discovered:
                    result.attack_paths_discovered.append(f"API:{ep}")

        for path in api_paths[:2]:
            tr2 = self._run_tool("arjun", f"{base}{path}" if not str(path).startswith("http") else path,
                                 timeout=120)
            if tr2 and tr2.status == "success" and tr2.results.get("parameters"):
                result.tools_run.append(f"arjun({path})")

        # ── A03 Injection: NoSQL & LDAP operator probes on discovered params ──
        # nosql_inj and ldap_inj are registered in the attack registry but were
        # never wired to an agent. Feed them the discovered API surface.
        probe_targets = []
        for p in probed[:10]:
            url = p.get("url") or p.get("path") or ""
            if not url.startswith("http"):
                url = f"{base}{url}"
            qp = p.get("query") or {}
            probe_targets.append({"full_url": url, "query": qp})
        for p in api_paths[:6]:
            url = p if str(p).startswith("http") else f"{base}{p}"
            probe_targets.append({"full_url": url, "query": {}})

        for probe in probe_targets:
            n_tr = self._run_tool("nosql_inj", probe["full_url"], timeout=120,
                                  query=probe["query"], endpoints=[probe["full_url"]])
            if n_tr and n_tr.status == "success" and n_tr.results.get("probes"):
                for hit in n_tr.results["probes"]:
                    result.findings.append(self._make_finding(
                        tool="nosql_inj",
                        name="NoSQL injection anomaly",
                        severity="HIGH", confidence=70,
                        url=hit.get("url", probe["full_url"]),
                        description=(f"Operator payload {hit.get('payload', '')!r} "
                                     "produced an anomalous response (status flip or "
                                     "error hint). Deep-validate before reporting."),
                        raw_output_excerpt=str(hit)[:400],
                        false_positive_risk="HIGH"))
            l_tr = self._run_tool("ldap_inj", probe["full_url"], timeout=120,
                                  query=probe["query"])
            if l_tr and l_tr.status == "success" and l_tr.results.get("probes"):
                for hit in l_tr.results["probes"]:
                    result.findings.append(self._make_finding(
                        tool="ldap_inj",
                        name="LDAP injection anomaly",
                        severity="HIGH", confidence=70,
                        url=hit.get("url", probe["full_url"]),
                        description=(f"Filter payload {hit.get('payload', '')!r} "
                                     "produced an anomalous response (wildcard or "
                                     "error hint). Deep-validate before reporting."),
                        raw_output_excerpt=str(hit)[:400],
                        false_positive_risk="HIGH"))

        strat = self._llm_json(REASON_API,
                               f"API paths: {json.dumps(api_paths)}\n"
                               f"Live probe: {json.dumps(probed[:10])}\n"
                               f"Types: {smap['signals'].get('api_types')}",
                               temperature=0.2)
        if strat:
            idor_evidence = any(p.get("unauthenticated_200") for p in probed)
            if strat.get("idor_risk"):
                result.findings.append(self._make_finding(
                    tool="analysis", name="IDOR / BOLA risk", severity="HIGH" if idor_evidence else "MEDIUM",
                    confidence=60 if idor_evidence else 50,
                    description=("Sequential/numeric object IDs suggest IDOR; endpoints return 200 "
                                 "unauthenticated. Needs manual probe." if idor_evidence else
                                 "Sequential/numeric object IDs suggest IDOR. Needs manual probe."),
                    false_positive_risk="HIGH"))
            if strat.get("graphql_introspection_risk") and any(p.get("graphql") for p in probed):
                result.findings.append(self._make_finding(
                    tool="analysis", name="GraphQL introspection exposure", severity="MEDIUM",
                    confidence=60, description="GraphQL endpoint may allow introspection; endpoint reachable.",
                    false_positive_risk="MEDIUM"))

        # ── A01 Broken Access Control: IDOR / BOLA test on API endpoints ────
        # idor_test is registered in the attack registry but was never wired to
        # an agent. Run it against probed API endpoints. It needs an
        # authenticated EngagementContext (passed via kwargs["context"]); when
        # none is available the tool safely no-ops rather than crashing.
        idor_targets = (unauth_200 + [p.get("url") for p in probed if p.get("path")])[:8]
        if idor_targets:
            idor_tr = self._run_tool("idor_test", base, timeout=120,
                                     full_url=base, endpoints=idor_targets,
                                     context=memory.get("context"))
            if idor_tr and idor_tr.status == "success":
                for f in idor_tr.results.get("vulnerabilities", []):
                    result.findings.append(self._make_finding(
                        tool="idor_test",
                        name=f.get("name", "IDOR / BOLA object access"),
                        severity=f.get("severity", "HIGH"), confidence=70,
                        url=f.get("url", base),
                        description=f.get("kind", "cross-identity object access"),
                        false_positive_risk="MEDIUM"))

        if result.tools_run:
            result.status = "success" if result.findings else "partial"
        else:
            result.status = "skipped"
        return result


class AuthAgent(BaseAgent):
    agent_name = "auth"
    owned_tools = ["auth_probe"]

    def should_run(self, smap: Dict[str, Any]) -> bool:
        return bool(smap.get("auth_paths"))

    def run(self, target: str, smap: Dict[str, Any], memory: Dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)
        auth_paths = smap.get("auth_paths", [])[:15]

        # Live probe of the auth surface -- real status codes + cookie flags.
        checks = []
        cookie_flag_vulns = []   # (url, [missing flags])
        login_forms = []         # (url, status)
        unauth_200 = []          # urls
        auth_required = []       # urls
        server_disclosures = {}  # server -> [urls]
        tr = self._run_tool("auth_probe", base, timeout=180, paths=auth_paths)
        if tr and tr.status == "success" and tr.results.get("auth_checks"):
            result.tools_run.append(f"auth_probe({len(tr.results['auth_checks'])} paths)")
            for c in tr.results["auth_checks"]:
                checks.append(c)
                url = c.get("url", "")
                flags = c.get("cookie_flags", {})
                if c.get("set_cookie") and not all(flags.values()):
                    missing = [k for k, v in flags.items() if not v]
                    cookie_flag_vulns.append((url, missing))
                if c.get("login_form"):
                    login_forms.append((url, c.get("status")))
                elif c.get("status") == 200 and not c.get("redirected"):
                    unauth_200.append(url)
                if c.get("auth_required"):
                    auth_required.append(url)
                if c.get("server"):
                    server_disclosures.setdefault(c["server"], []).append(url)

        # Aggregated findings: one per issue type with the full path list, so the
        # critic reviews ~4 findings instead of 18 (one LLM call either way).
        # Each keeps its raw probe evidence so the critic can CONFIRM on evidence.
        def _auth_evidence(*predicates):
            return json.dumps([c for c in checks
                               if any(p(c) for p in predicates)],
                              default=str)[:400]

        if cookie_flag_vulns:
            paths = [u for u, _ in cookie_flag_vulns]
            missing = sorted({m for _, ms in cookie_flag_vulns for m in ms})
            result.findings.append(self._make_finding(
                tool="auth_probe",
                name=f"Session cookies missing security flags ({len(cookie_flag_vulns)} paths)",
                severity="MEDIUM", confidence=70, url=paths[0],
                description=(f"Live Set-Cookie on {len(cookie_flag_vulns)} auth path(s) lacks: "
                             f"{', '.join(missing)}. Paths: {', '.join(paths)}"),
                evidence_chain=[f"{u} -> missing {', '.join(ms)}" for u, ms in cookie_flag_vulns],
                false_positive_risk="LOW",
                raw_output_excerpt=_auth_evidence(lambda c: c.get("set_cookie", ""))))
        if login_forms:
            paths = [u for u, _ in login_forms]
            statuses = sorted({s for _, s in login_forms})
            result.findings.append(self._make_finding(
                tool="auth_probe", name=f"Login page exposed ({len(login_forms)} paths)",
                severity="INFO", confidence=80, url=paths[0],
                description=(f"HTTP {'/'.join(map(str, statuses))} on {len(login_forms)} path(s) "
                             f"contains a login form. Paths: {', '.join(paths)}"),
                evidence_chain=[f"{u} -> HTTP {s}" for u, s in login_forms],
                false_positive_risk="LOW",
                raw_output_excerpt=_auth_evidence(lambda c: c.get("login_form"))))
        if unauth_200:
            result.findings.append(self._make_finding(
                tool="auth_probe",
                name=f"Auth paths reachable unauthenticated ({len(unauth_200)} paths)",
                severity="MEDIUM", confidence=60, url=unauth_200[0],
                description=("Paths returned HTTP 200 directly (no redirect to a login page) — review "
                             "access control. Paths: " + ", ".join(unauth_200)),
                evidence_chain=[f"{u} -> HTTP 200, no redirect" for u in unauth_200],
                false_positive_risk="MEDIUM",
                raw_output_excerpt=_auth_evidence(lambda c: c.get("status") == 200 and not c.get("redirected"))))
        if auth_required:
            result.findings.append(self._make_finding(
                tool="auth_probe",
                name=f"Auth paths enforce authentication ({len(auth_required)} paths)",
                severity="INFO", confidence=85, url=auth_required[0],
                description=("Paths returned 401/403 without credentials — access control enforced. "
                             "Paths: " + ", ".join(auth_required)),
                evidence_chain=[f"{u} -> 401/403" for u in auth_required],
                false_positive_risk="LOW",
                raw_output_excerpt=_auth_evidence(lambda c: c.get("auth_required"))))
        if server_disclosures:
            servers = ", ".join(sorted(server_disclosures.keys()))
            result.findings.append(self._make_finding(
                tool="auth_probe", name="Server header disclosure on auth paths",
                severity="INFO", confidence=70, url=list(server_disclosures.values())[0][0],
                description=f"Server header disclosed on auth paths: {servers}.",
                evidence_chain=[f"{s} on {len(u)} path(s)" for s, u in server_disclosures.items()],
                false_positive_risk="LOW",
                raw_output_excerpt=json.dumps({s: u for s, u in server_disclosures.items()})[:300]))

        headers = dict(list(smap["posture"].get("response_headers", {}).items())[:8])
        analysis = self._llm_json(REASON_AUTH,
                                  f"Auth paths: {json.dumps(auth_paths)}\n"
                                  f"Live probe: {json.dumps(checks[:10])}\n"
                                  f"Headers: {json.dumps(headers)}",
                                  temperature=0.3)
        if analysis and analysis.get("weaknesses"):
            for w in analysis["weaknesses"][:5]:
                result.findings.append(self._make_finding(
                    tool="analysis", name=w.get("name", "Auth weakness"),
                    severity=w.get("severity", "MEDIUM"), confidence=w.get("confidence", 55),
                    description=w.get("description", ""), false_positive_risk="MEDIUM"))
            result.proof_requests = analysis.get("manual_steps", [])
            result.reasoning = analysis.get("reasoning", "")

        # ── A07 Identification & Auth Failures: login brute force ───────────
        # login_brute is registered but was never wired to an agent. Run a
        # conservative default-credentials pass against any detected login
        # forms. It needs an EngagementContext (kwargs["context"]) or a
        # brute_spec; without one it safely no-ops.
        if login_forms:
            login_url = login_forms[0][0]
            lb_tr = self._run_tool("login_brute", base, timeout=180,
                                   full_url=base, login_url=login_url,
                                   context=memory.get("context"))
            if lb_tr and lb_tr.status == "success":
                # login_brute returns hits as a COUNT in results['hits'] and the
                # per-attempt detail in 'brute_results'/'hits_detail'. Iterate
                # defensively so an int count can never crash the agent
                # ('int' object is not iterable in the certifiedhacker run).
                hits = lb_tr.results.get("hits_detail")
                if not isinstance(hits, list):
                    hits = [h for h in lb_tr.results.get("brute_results", [])
                            if isinstance(h, dict) and h.get("hit")]
                if not isinstance(hits, list):
                    hits = []
                for hit in hits:
                    result.findings.append(self._make_finding(
                        tool="login_brute",
                        name=f"Default/weak credentials: {hit.get('username', '?')} / {hit.get('password', '?')}",
                        severity="HIGH", confidence=70, url=hit.get("url", login_url),
                        description="Default or weak credentials accepted on the login form.",
                        false_positive_risk="LOW"))

        if result.tools_run:
            result.status = "success" if result.findings else "partial"
        else:
            # Last resort deterministic fallback from recon headers
            cookies = str(headers)
            if "set-cookie" in cookies.lower():
                if "samesite" not in cookies.lower() or "secure" not in cookies.lower():
                    result.findings.append(self._make_finding(
                        tool="analysis", name="Weak session cookie flags",
                        severity="MEDIUM", confidence=55,
                        description="Session cookies without Secure/SameSite flags.",
                        false_positive_risk="MEDIUM"))
            if any("admin" in p.lower() for p in auth_paths):
                result.findings.append(self._make_finding(
                    tool="analysis", name="Admin panel exposed", severity="MEDIUM",
                    confidence=65, description="Admin/auth surface found; review access control.",
                    false_positive_risk="MEDIUM"))
                result.attack_paths_discovered.append(f"AUTH:admin_panel:{[p for p in auth_paths if 'admin' in p.lower()][:1]}")
            result.status = "success" if result.findings else "skipped"
        return result


class InfraAgent(BaseAgent):
    agent_name = "infra"
    owned_tools = ["testssl", "tls_analysis", "header_analysis", "dns_enum"]

    def should_run(self, smap: Dict[str, Any]) -> bool:
        return bool(smap.get("web_surfaces")) or bool(smap["posture"].get("tls_findings"))

    def run(self, target: str, smap: Dict[str, Any], memory: Dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        if smap["posture"].get("tls_vulnerabilities") or smap["posture"].get("weak_ciphers"):
            tr = self._run_tool("testssl", target, timeout=600)
            if tr and tr.status == "success":
                result.tools_run.append("testssl")
                for vid, vdata in (tr.results.get("vulnerabilities") or {}).items():
                    if isinstance(vdata, dict) and vdata.get("severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                        result.findings.append(self._make_finding(
                            tool="testssl", name=vid, severity=vdata["severity"], confidence=70,
                            description=vdata.get("finding", ""), false_positive_risk="LOW",
                            raw_output_excerpt=json.dumps(vdata)[:200]))

        # header_analysis follows redirects itself when given a full https URL.
        # Passing the bare base (often http://, which 301s) used to grade the
        # redirect response, not the live site — the flipkart.com "missing
        # security headers" false positives came from that.
        hs_url = base if str(base).startswith("https://") else f"https://{target}"
        tr2 = self._run_tool("header_analysis", hs_url, timeout=120, full_url=hs_url)
        if tr2 and tr2.status == "success":
            result.tools_run.append("header_analysis")
            for h in tr2.results.get("missing_security_headers", []):
                result.findings.append(self._make_finding(
                    tool="header_analysis", name=f"Missing security header: {h}",
                    severity="LOW", confidence=60, url=hs_url, false_positive_risk="LOW"))

        result.status = "success" if result.findings else "skipped"
        return result


class CloudAgent(BaseAgent):
    agent_name = "cloud"
    owned_tools = ["cloud_enum", "container_probe"]

    def should_run(self, smap: Dict[str, Any]) -> bool:
        return bool(smap["signals"].get("cloud")) or bool(smap["signals"].get("container"))

    def run(self, target: str, smap: Dict[str, Any], memory: Dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        cloud_signals = smap["signals"].get("cloud", [])
        subdomains = smap["assets"].get("subdomains", [])[:15]
        analysis = self._llm_json(REASON_CLOUD,
                                  f"Cloud signals: {json.dumps(cloud_signals)}\nSubdomains: {json.dumps(subdomains)}",
                                  temperature=0.2)

        tr = self._run_tool("cloud_enum", target, timeout=180)
        if tr and tr.status == "success" and tr.results.get("cloud_assets_found"):
            result.tools_run.append("cloud_enum")
            public_buckets = []
            for asset in tr.results["cloud_assets_found"]:
                result.findings.append(self._make_finding(
                    tool="cloud_enum", name=f"Public cloud asset: {asset.get('bucket', asset)}",
                    severity="MEDIUM", confidence=55,
                    description=f"{asset.get('provider', 'Cloud')} asset resolved publicly at {asset.get('url', '')}.",
                    false_positive_risk="MEDIUM",
                    raw_output_excerpt=json.dumps(asset)[:200]))
                result.attack_paths_discovered.append(f"CLOUD:{asset.get('bucket', asset)}")
                if asset.get("publicly_listable"):
                    public_buckets.append(asset.get("bucket", ""))

            # List publicly-listable S3 buckets -> concrete confirmed evidence.
            if public_buckets:
                trs = self._run_tool("s3_enum", target, timeout=120, buckets=public_buckets)
                if trs and trs.status == "success" and trs.results.get("s3_assets"):
                    result.tools_run.append(f"s3_enum({len(public_buckets)} buckets)")
                    for asset in trs.results["s3_assets"]:
                        keys = asset.get("sample_keys", [])
                        downloads = asset.get("downloadable_objects", [])
                        downloadable = [d for d in downloads if d.get("status") == 200]
                        name = f"Publicly listable S3 bucket: {asset['bucket']}"
                        chain = [asset.get("list_url", ""),
                                 f"object_count={asset.get('object_count')}"]
                        desc = (
                            f"Anonymous S3 ListObjectsV2 returned {asset['object_count']} object(s) "
                            f"(truncated={asset.get('is_truncated')}) on {asset['bucket']}. "
                            + (f"Sample keys: {', '.join(keys[:10])}" if keys else "No sample keys parsed.")
                        )
                        if downloadable:
                            name = f"Publicly listable + downloadable S3 bucket: {asset['bucket']}"
                            dl_desc = "; ".join(
                                f"{d['key']} ({d.get('content_type', '?')}, {d.get('content_length', '?')} bytes)"
                                for d in downloadable)
                            desc += f" Anonymous HEAD confirmed {len(downloadable)} sample object(s) publicly downloadable: {dl_desc}."
                            chain += [f"downloadable: {d['url']}" for d in downloadable]
                        result.findings.append(self._make_finding(
                            tool="s3_enum",
                            name=name,
                            severity="HIGH", confidence=95 if downloadable else 90,
                            url=asset.get("list_url", ""),
                            description=desc,
                            evidence_chain=chain,
                            false_positive_risk="LOW",
                            raw_output_excerpt=json.dumps(asset)[:250]))

        if smap["signals"].get("container"):
            tr2 = self._run_tool("container_probe", target, timeout=120)
            if tr2 and tr2.status == "success" and tr2.results.get("container_apis_found"):
                result.tools_run.append("container_probe")

        if analysis and analysis.get("cloud_findings"):
            for f in analysis["cloud_findings"]:
                result.findings.append(self._make_finding(
                    tool="analysis", name=f.get("name", "Cloud misconfiguration"),
                    severity=f.get("severity", "MEDIUM"), confidence=f.get("confidence", 50),
                    description=f.get("description", ""), false_positive_risk="MEDIUM"))

        if result.tools_run or result.findings:
            result.status = "success" if result.findings else "partial"
        else:
            result.status = "skipped"
        return result
