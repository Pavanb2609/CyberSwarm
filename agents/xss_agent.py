"""
xss_agent.py — XSSExploitAgent, proven Reflected XSS (OWASP A03).

Reflection is not execution. dalfox/nuclei tell us a payload came back in the
response; this agent goes the last mile and *proves* the JavaScript runs in a
real headless browser via tools/attack/xss_proof.py (nonce-correlated proof:
window marker / dialog / console, defeated against cross-run leakage).

Flow per query-parameter-bearing endpoint:
    1. dalfox (when installed) finds reflection candidates.
    2. xss_proof loads each candidate with bound payloads; a hit = the payload
       actually executed. That is an EXPLOIT-CONFIRMED HIGH finding.
    3. If dalfox saw reflection but the browser proof could not run or did not
       fire, emit a MEDIUM "reflected but unproven" finding so the report is
       truthful about what was demonstrated vs. suspected.

Deterministic fallback, like every other agent: with no LLM and xss_proof
unavailable the agent degrades to "skipped"/"partial", never crashes the loop.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from agents.base_agent import AgentResult, BaseAgent
from utils import find_primary_url

DALFOX_TAGS = ["xss", "dalfox"]
MAX_URLS = 10


class XSSExploitAgent(BaseAgent):
    agent_name = "xss_exploit"
    owned_tools = ["dalfox", "xss_proof"]

    def should_run(self, smap: Dict[str, Any]) -> bool:
        """Query-string endpoints or discovered parameters are the surface."""
        if not isinstance(smap, dict):
            return False
        if smap.get("query_endpoint_candidates") or smap.get("parameters"):
            return True
        return any("?" in str(p) for p in smap.get("endpoints", []))

    def run(self, target: str, smap: Dict[str, Any],
            memory: Dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        base = find_primary_url(smap, target)

        urls = [str(p) for p in smap.get("endpoints", []) if "?" in str(p)]
        for extra in smap.get("parameters", []):
            if isinstance(extra, dict) and extra.get("url") and "?" in str(extra["url"]):
                ep = str(extra["url"])
                if ep not in urls:
                    urls.append(ep)
        urls = urls[:MAX_URLS]

        if not urls and base:
            # No pre-discovered query endpoints; probe the primary URL itself
            # (it may embed query strings at runtime).
            urls = [base + p for p in ("", "/")]

        reflected: List[str] = []
        dalfox_tr = self._run_tool("dalfox", base, timeout=180, urls=urls)
        if dalfox_tr and dalfox_tr.status == "success":
            result.tools_run.append("dalfox")
            reflected = [str(r.get("url", "")) for r in dalfox_tr.results.get("vulns", [])]
            if not reflected:
                for hit in dalfox_tr.results.get("xss_findings", []):
                    reflected.append(str(hit.get("url", "") or hit.get("target", "")))

        proof_urls = list(dict.fromkeys(reflected or urls))
        proven: List[Dict[str, Any]] = []
        proof_tr = self._run_tool("xss_proof", base, timeout=240, urls=proof_urls)
        if proof_tr and proof_tr.status == "success":
            result.tools_run.append("xss_proof")
            proven = proof_tr.results.get("proven", []) or []

        if proven:
            for p in proven:
                result.findings.append(self._make_finding(
                    tool="xss_proof",
                    name="Reflected XSS proven to execute",
                    severity="HIGH", confidence=90,
                    url=p.get("url", ""),
                    description=(
                        f"Payload executed in a headless browser at {p.get('url')} — "
                        f"{p.get('evidence', 'script executed')}. Nonce-verified, so a "
                        "page echoing a stale marker cannot false-positive. A real "
                        "attacker could run arbitrary JavaScript in a victim's session."),
                    evidence_chain=[f"{p.get('url')} -> {p.get('evidence')}"],
                    false_positive_risk="LOW",
                    raw_output_excerpt=json.dumps(p)[:500]))
            result.status = "success"
            result.reasoning = f"{len(proven)} XSS proof(s) captured (A03, executed)."
            return result

        if reflected:
            result.findings.append(self._make_finding(
                tool="dalfox",
                name="Reflected XSS — reflected but not proven to execute",
                severity="MEDIUM", confidence=55,
                url=reflected[0],
                description=(
                    "One or more payloads were reflected in the response. The "
                    "headless-browser proof did not fire (CSP/encoding/wrapper) or "
                    "could not run, so execution is unproven. Verify in a browser: "
                    + ", ".join(reflected[:5])),
                evidence_chain=[f"{u} reflected payload" for u in reflected[:5]],
                false_positive_risk="MEDIUM"))
            result.status = "success"
            result.reasoning = "Reflection detected, execution not proven (A03)."
            return result

        result.status = "partial"
        result.reasoning = "No reflected/proven XSS surface found (A03)."
        if not result.tools_run:
            result.status = "skipped"
            result.reasoning = "dalfox/xss_proof unavailable; nothing to prove (A03)."
        return result