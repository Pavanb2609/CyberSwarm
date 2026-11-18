"""
payload_agent.py — PayloadAgent: situation-aware payload engineering + delivery.

The agent understands the assessed situation (injection points, parameter
names, template engine / WAF / tech stack from the SystemMap) and *builds* the
payloads instead of relying on a fixed wordlist baked into a binary:

  * ``payload_gen``  — SecLists-style preset banks + crunch-style
                       charset/mutation generation + Burp-style encoding and
                       boundary customization, selected by the context
  * ``payload_probe`` — delivers each payload against a live parameter and
                        records an XSStrike-style continuous proof: the exact
                        payload, the full HTTP request, and the response

Verdicts stay honest:
  * a reflected proof-marker is a MEDIUM "reflected, execution unproven"
    finding (the separate xss_exploit agent *proves* browser execution);
  * server fingerprints that only the application could produce (an SQL error
    string, an SSTI ``{{7*7}}``->49 truth value, /etc/passwd content) earn
    concrete severities backed by the proof chain.

Deterministic fallback: with no LLM the agent still runs (generation is a
pure function); the LLM is only an optional analysis pass that is skipped on
failure, exactly like every other specialist.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlparse

from agents.base_agent import AgentFinding, AgentResult, BaseAgent
from utils import find_primary_url

# Defaults preserve the frozen-run behaviour exactly. The env overrides exist
# for the v2 lab benchmark (12 endpoints) and for context-window experiments:
#   CYBERSWARM_PAYLOAD_MAX_TARGETS   probe more URLs than the first 4
#   CYBERSWARM_PAYLOAD_PER_ENDPOINT  one finding per endpoint+class instead
#                                    of one finding per class (v1 collapse)
MAX_TARGETS = int(os.environ.get("CYBERSWARM_PAYLOAD_MAX_TARGETS", "4"))
PER_ENDPOINT = os.environ.get("CYBERSWARM_PAYLOAD_PER_ENDPOINT", "0") == "1"
MAX_PARAMS_PER_URL = 3
PAYLOADS_PER_PARAM = 40
DEFAULT_TOKEN_BUDGET = 300

_FILE_PARAM_HINTS = ("file", "include", "path", "page", "doc", "load", "read",
                     "url", "download", "template")
_URL_PARAM_HINTS = ("url", "fetch", "webhook", "redirect", "next", "proxy",
                    "img", "image", "src", "ref")
_TEMPLATE_ENGINES = ("jinja2", "twig", "smarty", "freemarker", "mako", ".erb")
_XML_HINTS = ("soap", "xml", "wsdl")

_MARKER_TO_SEVERITY = {
    "xss": ("Reflected XSS — payload reflected, execution unproven", "MEDIUM", 55),
    "sqli": ("Potential SQL injection — server error fingerprint", "MEDIUM", 60),
    "ssti": ("Server-side template injection — truth marker executed", "HIGH", 78),
    "lfi": ("Path traversal / file disclosure — file content observed", "HIGH", 85),
    "cmdi": ("Command injection — execution marker observed", "HIGH", 70),
    "open_redirect": ("Open redirect — off-host / script location", "MEDIUM", 55),
    "crlf": ("CRLF injection — injected response header observed", "MEDIUM", 70),
    "xxe": ("XML external entity injection — file content observed", "HIGH", 82),
}


class PayloadAgent(BaseAgent):
    agent_name = "payload"
    owned_tools = ["payload_gen", "payload_probe", "xss_proof"]

    def should_run(self, smap: Dict[str, Any]) -> bool:
        """Injection surface = parameters or query-string endpoints."""
        if not isinstance(smap, dict):
            return False
        if smap.get("parameters") or smap.get("params"):
            return True
        return any("?" in str(p) for p in smap.get("endpoints", []))

    # ── surface extraction ──────────────────────────────────────────────────

    @staticmethod
    def _surface(smap: Dict[str, Any]) -> Dict[str, Any]:
        urls: List[str] = []
        for ep in smap.get("endpoints", []) or []:
            if "?" in str(ep):
                urls.append(str(ep))
        base = find_primary_url(smap, smap.get("target", ""))
        if base and base not in urls:
            urls.append(base.strip("/") + "")
        tech = " ".join(str(t.get("name", "")) for t in (smap.get("technologies") or [])) \
            .lower()
        waf = any(k in tech for k in ("cloudflare", "akamai", "aws waf", "waf",
                                      "cloudfront", "incapsula", "shield"))
        params_blob = " ".join(
            str(p.get("name", p)) if isinstance(p, dict) else str(p)
            for p in (smap.get("parameters") or smap.get("params") or []))
        # xss/sqli/cmdi are tested everywhere — real command injection isn't
        # tied to a specific parameter name the way LFI or open-redirect are.
        categories = ["xss", "sqli", "cmdi"]
        if any(k in tech for k in _TEMPLATE_ENGINES):
            categories.append("ssti")
        if any(k in params_blob for k in ("file", "path", "page", "include",
                                          "doc", "load", "read", "template")):
            categories.append("lfi")
        if any(k in params_blob for k in _URL_PARAM_HINTS):
            # Redirect/location-echoing parameters are exactly where header
            # injection (CRLF) and open-redirect commonly co-occur.
            categories.append("open_redirect")
            categories.append("crlf")
        if any(k in tech for k in _XML_HINTS) or any(k in params_blob for k in _XML_HINTS):
            categories.append("xxe")
        json_api = ("json" in tech
                    or any("/api/" in str(e) for e in (smap.get("endpoints") or [])))
        return {"urls": urls, "base": base, "tech": tech, "waf": waf,
                "categories": categories, "json_api": json_api,
                "parameters": smap.get("parameters") or smap.get("params") or []}

    @staticmethod
    def _params_for(url: str, discovered: List[Any]) -> List[str]:
        """Parameters to probe: parsed from the URL query first, then any
        discovered parameters recorded against this URL, then the base list."""
        parsed = urlparse(url)
        q = [k for k, _ in parse_qsl(parsed.query)]
        for p in discovered:
            if isinstance(p, dict):
                if p.get("url") and urlparse(str(p["url"])).path == parsed.path:
                    q.append(str(p.get("name", "")))
            elif isinstance(p, str) and "?" not in p:
                q.append(p)
        return list(dict.fromkeys([n for n in q if n]))

    # ── run ─────────────────────────────────────────────────────────────────

    def run(self, target: str, smap: Dict[str, Any],
            memory: Dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target,
                             status="failed")
        if not isinstance(smap, dict):
            result.status = "skipped"
            result.reasoning = ("No SystemMap supplied; no injection surface "
                                "to engineer payloads for.")
            return result
        surf = self._surface(smap)

        url_slots: List[str] = []
        for u in surf["urls"][:MAX_TARGETS + 2]:
            if u not in url_slots:
                url_slots.append(u)

        if not surf["categories"] or not url_slots:
            result.status = "skipped"
            result.reasoning = ("No parameter/query injection surface in the "
                                "SystemMap; no payloads to engineer.")
            return result

        gen_tr = self._run_tool("payload_gen", target, timeout=60,
                                categories=surf["categories"],
                                contexts=["reflected"],
                                tech=surf["tech"].split(),
                                waf=surf["waf"],
                                style="all",
                                max_payloads=DEFAULT_TOKEN_BUDGET)
        if gen_tr and gen_tr.status == "success":
            result.tools_run.append("payload_gen")
        nonce = (gen_tr.results.get("nonce") if gen_tr else None) or "x"
        generated = (gen_tr.results.get("payloads") if gen_tr else []) or []
        if not generated:
            generated = _minimal_bundle(surf["categories"], nonce)

        matched_by_cat: Dict[str, List[Dict[str, Any]]] = {
            c: [] for c in surf["categories"]}
        probed = 0

        def _collect(tr) -> None:
            nonlocal probed
            if tr and tr.status == "success":
                result.tools_run.append("payload_probe")
            if not tr or tr.status != "success":
                return
            proofs = tr.results.get("proofs", []) or []
            probed += len(proofs)
            for proof in proofs:
                if proof.get("matched"):
                    matched_by_cat.setdefault(
                        proof.get("category", "xss"), []).append(proof)

        xxe_chunk = [p for p in generated if p.get("category") == "xxe"][:5]
        query_chunk = _interleave_by_category(
            [p for p in generated if p.get("category") != "xxe"])

        for url in url_slots[:MAX_TARGETS]:
            params = self._params_for(url, surf["parameters"])[:MAX_PARAMS_PER_URL]
            if not params:
                continue
            for param in params:
                chunk = query_chunk[:PAYLOADS_PER_PARAM]
                if chunk:
                    _collect(self._run_tool(
                        "payload_probe", target, timeout=180,
                        url=url, param=param, payloads=chunk, nonce=nonce))
                # JSON-body pass: the same field, delivered as a POST JSON
                # body instead of a query string — most real APIs never
                # expose an injectable field any other way.
                if surf.get("json_api") and chunk:
                    _collect(self._run_tool(
                        "payload_probe", target, timeout=180,
                        url=url, param=param, payloads=chunk, nonce=nonce,
                        method="POST", body_format="json"))
            # XXE is a whole-body attack, not a per-parameter one — one POST
            # per XXE payload per URL, not fanned out across params.
            if xxe_chunk:
                _collect(self._run_tool(
                    "payload_probe", target, timeout=180,
                    url=url, param="__xxe_body__", payloads=xxe_chunk,
                    nonce=nonce, method="POST", body_format="xml"))

        # Keep only proofs whose criterion matches the finding's own class so a
        # cross-category fingerprint can't inflate a different finding.
        criteria_ok = {
            "xss": {"proof-marker reflected in response"},
            "sqli": {"SQL error string in response",
                     "time-based blind response delay"},
            "ssti": {"numeric truth marker ({{7*7}})"},
            "lfi": {"etc/passwd content leaked (passwd-style entries)"},
            "cmdi": {"command execution marker",
                     "time-based blind response delay"},
            "crlf": {"response header injected (not present in baseline)"},
            "open_redirect": {"redirect Location points to injected off-host target"},
            "xxe": {"etc/passwd content leaked (passwd-style entries)"},
        }
        for cat in list(matched_by_cat):
            want = criteria_ok.get(cat)
            if want:
                matched_by_cat[cat] = [p for p in matched_by_cat[cat]
                                       if p.get("match_criteria") in want]

        findings: List[AgentFinding] = []
        if PER_ENDPOINT:
            # one finding per (category, endpoint): preserves instance-level
            # granularity for benchmarks with multiple sinks per class
            grouped: Dict[Any, list] = {}
            for cat, proofs in matched_by_cat.items():
                if not proofs:
                    continue
                for p in proofs:
                    url = (p.get("request", {}).get("url", "") or surf["base"])
                    grouped.setdefault((cat, url.split("?")[0]), []).append(p)
            groups = grouped.items()
        else:
            groups = matched_by_cat.items()
        for cat, proofs in groups:
            if not proofs:
                continue
            name, sev, conf = _MARKER_TO_SEVERITY.get(
                cat, ("Injection marker observed", "MEDIUM", 55))
            first = proofs[0]
            req_url = first.get("request", {}).get("url", "")
            clean_url = req_url.split("?")[0] or surf["base"]
            finding = self._make_finding(
                tool="payload_probe",
                name=name,
                severity=sev,
                confidence=conf,
                url=clean_url,
                description=(
                    f"{len(proofs)} probe(s) matched '{cat}' at {clean_url}: "
                    f"{first.get('match_criteria')}. Payload/request/response "
                    "proof is attached and replayable."),
                evidence_chain=[
                    f"[payload_probe] {p.get('payload', '')[:120]} -> "
                    f"{p.get('request', {}).get('url', '')[:200]} -> "
                    f"HTTP {p.get('response', {}).get('status')} "
                    f"({p.get('match_criteria', 'matched')})"
                    for p in proofs[:8]],
                proofs=proofs[:12],
                false_positive_risk="MEDIUM" if sev == "HIGH" else "LOW",
                raw_output_excerpt=json.dumps({
                    "url": clean_url,
                    "category": cat,
                    "matched": len(proofs),
                    "criteria": first.get("match_criteria"),
                })[:400])
            findings.append(finding)
            result.proof_requests.append(
                f"[payload] confirm whether the {cat} reflection at "
                f"{clean_url} is exploitable in a real client session.")

        result.findings = findings
        if not result.tools_run:
            result.status = "skipped"
        elif findings:
            result.status = "success"
        else:
            result.status = "partial"
        result.reasoning = (
            f"Engineered {len(generated)} payloads across "
            f"{surf['categories']}; delivered {probed} probe(s); "
            f"{sum(len(v) for v in matched_by_cat.values())} matched.")
        return result


def _interleave_by_category(payloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Round-robin across categories before any per-param slice is taken.

    Without this, a fixed-size slice (PAYLOADS_PER_PARAM) just takes the
    first N of the combined list — so whichever categories were appended
    FIRST always survive, and whichever category has the biggest bank
    crowds out everything appended after it. That silently starved ssti/lfi
    out of every probe the moment cmdi became a default category with a
    bigger bank. Round-robin guarantees every requested category gets a
    fair turn regardless of bank size or append order."""
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    order: List[str] = []
    for p in payloads:
        cat = p.get("category", "misc")
        if cat not in buckets:
            buckets[cat] = []
            order.append(cat)
        buckets[cat].append(p)
    out: List[Dict[str, Any]] = []
    while any(buckets[c] for c in order):
        for c in order:
            if buckets[c]:
                out.append(buckets[c].pop(0))
    return out


def _minimal_bundle(categories: List[str], nonce: str) -> List[Dict[str, Any]]:
    """Deterministic fallback bundle if payload_gen could not run."""
    bundles = {
        "xss": [f'"><script>window.__cyberswarm_proof={nonce}</script>',
                "<img src=x onerror=alert(1)>"],
        "sqli": ["' OR 1=1-- -", "' UNION SELECT NULL-- -"],
        "ssti": ["{{7*7}}", "${7*7}"],
        "lfi": ["../../../../etc/passwd"],
        "cmdi": [";id", "`id`"],
        "open_redirect": ["//example.com"],
        "crlf": ["%0d%0aX-Injected: 1"],
        "xxe": ['<!DOCTYPE x [<!ENTITY e "x">]><x>&e;</x>'],
    }
    out = []
    for c in categories:
        for v in bundles.get(c, []):
            out.append({"id": len(out) + 1, "category": c, "payload": v,
                        "contexts": ["reflected"], "note": "fallback",
                        "engine": "fallback"})
    return out