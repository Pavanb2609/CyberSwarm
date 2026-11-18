"""
WebAttackAgent — owns HTTP-layer attack capabilities.
Reasons about the recon map before running tools, then analyzes output.
Falls back to deterministic finding extraction when the LLM is unavailable.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from typing import Any

import system_map as sm
from agents.base_agent import AgentResult, BaseAgent
from utils import find_primary_url, load_config


class _FormParser(HTMLParser):
    """Extract forms from landing-page HTML: action URL, method, input names."""

    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self.forms: list[dict[str, Any]] = []
        self._cur: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v for k, v in attrs}
        if tag == "form":
            action = a.get("action") or ""
            try:
                from urllib.parse import urljoin
                url = urljoin(self.base, action) if action else self.base
            except Exception:  # noqa: BLE001
                url = self.base
            self._cur = {"url": url, "method": (a.get("method") or "get").lower(),
                         "inputs": []}
            self.forms.append(self._cur)
        elif tag == "input" and self._cur is not None:
            name = a.get("name")
            if name and name not in self._cur["inputs"]:
                self._cur["inputs"].append(name)
        elif tag in ("textarea", "select") and self._cur is not None:
            name = a.get("name")
            if name and name not in self._cur["inputs"]:
                self._cur["inputs"].append(name)

# CDN/WAF markers: matched (case-insensitively) against SystemMap technologies,
# web-surface tech, and response headers. When one is present the backend is
# hidden behind a proxy that swallows nikto/feroxbuster noise, so we skip them.
CDN_WAF_MARKERS: dict[str, list[str]] = {
    "Cloudflare": ["cloudflare", "cf-ray", "cf-cache-status", "cf-nel", "server:cloudflare"],
    "Akamai": ["akamai", "akamaized", "x-akamai"],
    "Amazon CloudFront": ["cloudfront", "x-amz-cf-id", "x-cache: cloudfront"],
    "Fastly": ["fastly", "x-served-by: fastly"],
    "Imperva/Incapsula": ["incapsula", "imperva", "x-iinfo"],
    "Sucuri": ["sucuri", "x-sucuri"],
    "AWS WAF / Shield": ["awswaf", "x-aws-waf"],
    "GCP Cloud CDN": ["google cloud cdn", "x-goog-cache"],
    "Varnish": ["varnish"],
    "haproxy": ["haproxy"],
}


def detect_waf_cdn(smap: dict[str, Any]) -> str | None:
    """Return the first CDN/WAF vendor name present in the SystemMap, else None."""
    techs: list[str] = [str(t.get("name", "")).lower() for t in smap.get("technologies", [])]
    for surf in smap.get("web_surfaces", []):
        techs += [str(t).lower() for t in surf.get("tech", [])]
    headers = {k.lower(): str(v).lower() for k, v in
               smap.get("posture", {}).get("response_headers", {}).items()}
    blob = " ".join(techs) + " " + " ".join(f"{k}:{v}" for k, v in headers.items())
    for name, markers in CDN_WAF_MARKERS.items():
        for mk in markers:
            if mk in blob:
                return name
    return None

REASON_SYSTEM = """You are the WebAttackAgent for CyberSwarm.
Analyze the recon SystemMap and pick the most promising HTTP attack vectors.
Reason step-by-step before choosing tools and targets.

Output JSON:
{
  "attack_strategy": {
    "run_nuclei": true,
    "nuclei_tags": ["...", "..."],
    "run_nikto": true,
    "run_dalfox": true,
    "dalfox_targets": ["<urls with params>"],
    "run_sqlmap": true,
    "sqlmap_targets": ["<urls with params>"],
    "run_feroxbuster": true,
    "run_cors_check": true
  },
  "interesting_paths": ["..."],
  "interesting_params": ["..."],
  "reasoning": "<step-by-step>"
}"""

ANALYZE_SYSTEM = """You are the WebAttackAgent for CyberSwarm.
Interpret the raw tool output. Do NOT repeat it — analyze it.
For each finding output:
{
  "findings": [{"name","severity","confidence","false_positive_risk","url","impact","evidence"}],
  "overall_assessment": "...",
  "needs_manual_investigation": ["..."]
}"""


class WebAttackAgent(BaseAgent):
    agent_name = "web_attack"
    owned_tools = ["nuclei", "nikto", "dalfox", "sqlmap", "feroxbuster", "corsy"]

    def should_run(self, smap: dict[str, Any]) -> bool:
        ports = {s.get("port") for s in smap.get("services", [])}
        return bool(ports & {80, 443, 8080, 8443, 8000}) or bool(smap.get("web_surfaces"))

    def _compress(self, smap: dict[str, Any]) -> dict[str, Any]:
        c = sm.compress_for_llm(smap, max_tech=12, max_paths=25)
        c["response_headers"] = dict(list(smap["posture"].get("response_headers", {}).items())[:8])
        return c

    def _form_inject_targets(self, base_url: str, limit: int = 16) -> tuple:
        """Parse landing-page HTML forms into explicit injection targets.

        Returns (urls, bodies): urls are GET targets "url?param=1"; bodies is
        {POST url: (json_sample, "POST")}.
        """
        try:
            import urllib3  # noqa: WPS433
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            import requests
            resp = requests.get(base_url, timeout=15, verify=False,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; CyberSwarm)"})
            html = resp.text or ""
        except Exception:  # noqa: BLE001
            return [], {}
        parser = _FormParser(base_url)
        try:
            parser.feed(html)
        except Exception:  # noqa: BLE001
            parser.forms = parser.forms  # keep whatever parsed
        urls: list[str] = []
        bodies: dict[str, tuple] = {}
        for form in parser.forms[:8]:
            inputs = form.get("inputs") or []
            if not inputs:
                continue
            url = form["url"]
            if form.get("method") == "get":
                for name in inputs[:4]:
                    q = f"{url}{'&' if '?' in url else '?'}{name}=1"
                    if q not in urls:
                        urls.append(q)
            else:
                if inputs and url not in bodies:
                    bodies[url] = (json.dumps({n: "1" for n in inputs[:4]}), "POST")
        return urls[:limit], bodies

    def run(self, target: str, smap: dict[str, Any], memory: dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        compressed = self._compress(smap)
        base_url = find_primary_url(smap, target)

        strategy = self._llm_json(REASON_SYSTEM,
                                  f"Recon SystemMap:\n```json\n{json.dumps(compressed, indent=2)}```",
                                  temperature=0.2)
        if not strategy:
            strategy = self._default_strategy(compressed, base_url)
        result.reasoning = strategy.get("reasoning", "")

        plan = strategy.get("attack_strategy", {})
        raw = {}

        # ── Form-derived injection targets ─────────────────────────────────
        # Recon may finish parameter discovery before content discovery runs,
        # so params on form-backed endpoints can be missing. The landing-page
        # HTML is the ground truth here: parse its forms and build explicit
        # "?param=1" targets (GET) / --data bodies (POST). Closes the XBEN-076
        # "/greet?name=" class of miss.
        form_urls, form_bodies = self._form_inject_targets(base_url)
        plan.setdefault("run_sqlmap", False)
        if form_urls and not plan.get("run_dalfox"):
            plan["run_dalfox"] = True

        # ── Deterministic injection coverage (OWASP A03 Injection) ──────────
        # sqlmap (SQLi) and dalfox (XSS) should ALWAYS run against any web
        # surface endpoint that carries a query string -- not only when the LLM
        # strategy happens to enable them. commix (command injection) runs when
        # an injectable-looking param is present. This guarantees SQL/XSS/
        # CMDi are tested on every run regardless of planner/model variance.
        inj_targets = []
        seen = set()
        for ep in (list(compressed.get("endpoints", []))
                   + list(compressed.get("params", [])) + list(form_urls)):
            s = str(ep)
            if not s or s in seen:
                continue
            seen.add(s)
            # bare parameter names (no path separators) produce garbage
            # targets like "http://host/name" -- skip them
            if not s.startswith("http") and not s.startswith("/") and "/" not in s:
                continue
            inj_targets.append(s if s.startswith("http") else f"{base_url}{s}")
        injectable = [t for t in inj_targets if "?" in t]

        # Body-parameter endpoints (e.g. POST JSON APIs): injectable too —
        # sqlmap gets --data with a sample JSON body built from the spec.
        def _body_sample(url: str) -> tuple:
            pts = [p for p in smap.get("parameters", [])
                   if isinstance(p, dict) and p.get("url") == url
                   and p.get("in") == "body" and p.get("name")][:3]
            if not pts:
                return "", ""
            sample = json.dumps({p["name"]: "1" for p in pts})
            return sample, (pts[0].get("method") or "post").upper()

        body_targets: dict[str, tuple] = {}
        for t in inj_targets:
            if "?" not in t:
                sample, meth = _body_sample(t)
                if sample:
                    if not plan.get("run_sqlmap"):
                        plan["run_sqlmap"] = True
                    body_targets.setdefault(t, (sample, meth))
        for bt, (sample, meth) in form_bodies.items():
            if bt not in body_targets:
                body_targets[bt] = (sample, meth)
                plan["run_sqlmap"] = True
        if injectable:
            plan["run_dalfox"] = True
            plan["dalfox_targets"] = list(dict.fromkeys(
                plan.get("dalfox_targets", []) + injectable[:4]))
            plan["run_sqlmap"] = True
            plan["sqlmap_targets"] = list(dict.fromkeys(
                plan.get("sqlmap_targets", []) + injectable[:2]))
            if any(kw in " ".join(injectable).lower() for kw in ("cmd", "exec", "ping", "host", "run")):
                plan["run_commix"] = True
                plan["commix_targets"] = injectable[:2]
        if body_targets:
            plan["run_sqlmap"] = True

        # WAF/CDN-aware tool selection: a front proxy swallows content-discovery
        # and banner-scan noise, so skip nikto + feroxbuster and save real time.
        # config.attack.waf_skip (default true) disables this so heavy content
        # discovery still runs behind CDNs for deeper coverage.
        try:
            waf_skip = (load_config() or {}).get("attack", {}).get("waf_skip", True)
        except Exception:  # noqa: BLE001
            waf_skip = True
        cdn = detect_waf_cdn(smap)
        skipped = []
        if cdn and waf_skip:
            if plan.get("run_nikto", True):
                plan["run_nikto"] = False
                skipped.append("nikto")
            if plan.get("run_feroxbuster", True):
                plan["run_feroxbuster"] = False
                skipped.append("feroxbuster")
            print(f"[waf] CDN/WAF detected ({cdn}) — skipping "
                  f"{' + '.join(skipped) if skipped else 'heavy scanners'} "
                  f"(CDN swallows them) for time saving; keeping nuclei + corsy.")
            note = f"CDN/WAF detected ({cdn}); skipped {'/'.join(skipped)}."
            result.reasoning = f"{result.reasoning} | {note}" if result.reasoning else note

        # ── build tool tasks, run concurrently ────────────────────────────────
        tasks: list[tuple] = []

        if plan.get("run_nuclei", True):
            def _nuclei(_tags=",".join(plan.get("nuclei_tags", []))):
                tr = self._run_tool("nuclei", base_url, timeout=240, tags=_tags)
                if tr and tr.status == "success":
                    return ("nuclei", f"nuclei(tags={_tags or 'all'})", tr.results)
                return None
            tasks.append(("nuclei", "nuclei", _nuclei))

        if plan.get("run_nikto", True):
            def _nikto():
                tr = self._run_tool("nikto", base_url, timeout=240)
                if tr and tr.status == "success":
                    return ("nikto", "nikto", tr.results)
                return None
            tasks.append(("nikto", "nikto", _nikto))

        # SQLi (sqlmap), XSS (dalfox), CMDi (commix) — targets come from the
        # plan (LLM strategy + our deterministic injection fallback).
        for tool, urls_key in (("dalfox", "dalfox_targets"),
                               ("sqlmap", "sqlmap_targets"),
                               ("commix", "commix_targets")):
            if plan.get(f"run_{tool}", False):
                extra = list(dict.fromkeys(plan.get(urls_key, [])))[:2]
                if tool == "sqlmap":
                    for bt, (sample, meth) in body_targets.items():
                        if bt not in extra:
                            extra.append(bt)
                    extra = extra[:3]
                    if extra and not plan.get("run_sqlmap"):
                        plan["run_sqlmap"] = True
                for url in extra:
                    def _scanner(_tool=tool, _url=url):
                        kw: dict[str, Any] = {}
                        if _tool == "sqlmap" and _url in body_targets:
                            kw = {"data": body_targets[_url][0],
                                  "method": body_targets[_url][1]}
                        tr = self._run_tool(_tool, _url, timeout=150, **kw)
                        if tr and tr.status == "success":
                            return (_tool, f"{_tool}({_url})", tr.results)
                        return None
                    tasks.append((tool, url, _scanner))

        if plan.get("run_feroxbuster", True):
            def _ferox():
                tr = self._run_tool("feroxbuster", base_url, timeout=240)
                if tr and tr.status == "success":
                    return ("feroxbuster", "feroxbuster", tr.results)
                return None
            tasks.append(("feroxbuster", "feroxbuster", _ferox))

        if plan.get("run_cors_check", True):
            def _cors():
                tr = self._run_tool("corsy", base_url, timeout=90)
                if tr and tr.status == "success":
                    return ("corsy", "corsy", tr.results)
                return None
            tasks.append(("corsy", "corsy", _cors))

        if plan.get("run_file_upload", True):
            def _file_upload():
                # Pass upload forms detected during recon (from SystemMap)
                upload_urls = [f.get("action_url", "") for f in smap.get("upload_forms", [])
                               if f.get("action_url")]
                tr = self._run_tool("file_upload", base_url, timeout=90,
                                    full_url=base_url, upload_urls=upload_urls)
                if tr and tr.status == "success":
                    return ("file_upload", "file_upload", tr.results)
                return None
            tasks.append(("file_upload", "file_upload", _file_upload))

        def _safe(fn):
            try:
                return fn()
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=min(4, len(tasks) or 1)) as ex:
            futures = {ex.submit(_safe, fn): label for _, label, fn in tasks}
            for fut in as_completed(futures):
                out = fut.result()
                if out:
                    key, label, results = out
                    if key in ("dalfox", "sqlmap"):
                        raw.setdefault(key, []).append(results)
                    else:
                        raw[key] = results
                    result.tools_run.append(label)

        if not result.tools_run:
            result.status = "skipped"
            result.error = "No tools ran (not installed or surface unsuitable)"
            return result

        # LLM analysis, else deterministic extraction
        analysis = self._llm_json(ANALYZE_SYSTEM,
                                  f"Raw tool output:\n```json\n{json.dumps(raw, indent=2)[:3500]}```"
                                  f"\n\nRecon context:\n```json\n{json.dumps(compressed, indent=2)}```",
                                  temperature=0.1)
        if analysis and analysis.get("findings"):
            for f in analysis["findings"]:
                result.findings.append(self._make_finding(
                    tool=f.get("tool", "web_attack"),
                    name=f.get("name", "Unknown"),
                    severity=f.get("severity", "INFO"),
                    confidence=f.get("confidence", 50),
                    url=f.get("url", ""),
                    description=f.get("impact", ""),
                    false_positive_risk=f.get("false_positive_risk", "MEDIUM"),
                    raw_output_excerpt=str(f.get("evidence", ""))[:200]))
            result.proof_requests = analysis.get("needs_manual_investigation", [])
        else:
            # LLM unavailable or returned no findings -> deterministic extraction
            self._deterministic_findings(result, raw)

        result.status = "success" if result.findings else "partial"
        return result

    # ── helpers ──────────────────────────────────────────────────────────────

    def _default_strategy(self, compressed: dict[str, Any], base_url: str) -> dict[str, Any]:
        tags = []
        if compressed.get("cms"):
            tags += ["cms", str(compressed["cms"]).lower().split()[0]]
        return {
            "attack_strategy": {
                "run_nuclei": True, "nuclei_tags": tags,
                "run_nikto": True, "run_dalfox": False, "dalfox_targets": [],
                "run_sqlmap": False, "sqlmap_targets": [], "run_feroxbuster": True,
                "run_cors_check": True,
            },
            "interesting_paths": [], "interesting_params": [],
            "reasoning": "Deterministic fallback: full battery (Nuclei + Nikto + feroxbuster + corsy).",
        }

    def _deterministic_findings(self, result: AgentResult, raw: dict[str, Any]) -> None:
        SEV_MAP = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                   "low": "LOW", "info": "INFO"}
        for f in raw.get("nuclei", {}).get("nuclei_findings", []):
            sev = SEV_MAP.get(str(f.get("severity", "")).lower(), "INFO")
            conf = 70 if sev in ("CRITICAL", "HIGH") else 55
            result.findings.append(self._make_finding(
                tool="nuclei", name=f.get("name", f.get("template_id", "")),
                severity=sev, confidence=conf, url=f.get("url", ""),
                description=f.get("description", "")[:300],
                false_positive_risk="MEDIUM" if sev in ("MEDIUM", "INFO") else "LOW",
                raw_output_excerpt=json.dumps(f)[:200]))
        for f in raw.get("nikto", {}).get("nikto_findings", []):
            result.findings.append(self._make_finding(
                tool="nikto", name=f.get("msg", ""), severity="MEDIUM",
                confidence=50, url=f.get("url", ""), false_positive_risk="MEDIUM"))
        for f in raw.get("dalfox", []) or []:
            for item in f if isinstance(f, list) else [f]:
                result.findings.append(self._make_finding(
                    tool="dalfox", name="Reflected XSS (Dalfox)", severity="HIGH",
                    confidence=65, url=item.get("url", ""), false_positive_risk="LOW",
                    raw_output_excerpt=str(item)[:200]))
        for f in raw.get("sqlmap", []) or []:
            for item in f if isinstance(f, list) else [f]:
                result.findings.append(self._make_finding(
                    tool="sqlmap", name="SQL Injection (sqlmap)", severity="CRITICAL",
                    confidence=70, url=item.get("url", ""), false_positive_risk="LOW",
                    raw_output_excerpt=str(item)[:200]))
        cmix = raw.get("commix", {})
        for f in cmix.get("commix_findings", []) if isinstance(cmix, dict) else cmix:
            result.findings.append(self._make_finding(
                tool="commix", name=f.get("issue", "Command Injection"), severity="CRITICAL",
                confidence=60, url=base_url, false_positive_risk="LOW",
                raw_output_excerpt=str(f.get("detail", ""))[:200]))
        for u in raw.get("feroxbuster", {}).get("discovered_urls", []):
            result.attack_paths_discovered.append(u)
            result.findings.append(self._make_finding(
                tool="feroxbuster", name=f"Discovered endpoint: {u}", severity="INFO",
                confidence=80, url=u, false_positive_risk="LOW"))
        for f in raw.get("corsy", {}).get("cors_findings", []):
            result.findings.append(self._make_finding(
                tool="corsy", name="CORS Misconfiguration", severity="MEDIUM",
                confidence=70, url=f.get("url", ""), false_positive_risk="MEDIUM",
                raw_output_excerpt=str(f.get("reason", ""))[:200]))
        for f in raw.get("file_upload", {}).get("upload_findings", []):
            result.findings.append(self._make_finding(
                tool="file_upload", name=f.get("issue", "File upload issue"),
                severity=f.get("severity", "MEDIUM"), confidence=f.get("confidence", 60),
                url=f.get("url", ""), description=f.get("description", "")[:300],
                false_positive_risk="MEDIUM"))
