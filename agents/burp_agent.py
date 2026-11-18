"""
burp_agent.py — BurpAgent, an OPTIONAL active-scanner agent.

Drives Burp Suite Professional's active scanner (REST API, port 1337) over
the web attack surface discovered by recon, and folds Burp's issue
definitions back into CyberSwarm findings.

Availability contract (matches the rest of the tooling):

  * No reachable Burp REST API  -> plan skips this agent (should_run False,
    or run() returns no findings and never raises).
  * Reachable Burp, clean scan  -> success with zero findings.
  * Reachable Burp, issues      -> success with HIGH/MEDIUM/LOW findings.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from agents.base_agent import AgentResult, BaseAgent

_OWASP = {
    "sql": "A03", "xss": "A03", "command injection": "A03", "injection": "A03",
    "csrf": "A01", "path traversal": "A01", "idor": "A01", "broken access": "A01",
    "directory traversal": "A01",
    "ssl": "A02", "tls": "A02", "cryptographic": "A02", "weak cryptography": "A02",
    "security misconfiguration": "A05", "misconfiguration": "A05",
    "vulnerable and outdated": "A06", "outdated components": "A06",
    "deserialization": "A08", "sensitive data": "A02", "express": "A05",
    "clickjacking": "A05", "frame": "A05", "cors": "A01", "header": "A05",
    "log4j": "A06", "spring": "A06", "struts": "A06", "jwt": "A07",
    "authentication": "A07", "broken authentication": "A07", "password": "A07",
    "captcha": "A04", "rate limiting": "A04", "business logic": "A04",
    "websocket": "A03", "soap": "A03", "jsonp": "A01", "ssrf": "A01",
    "http/2": "A05", "http2": "A05", "httprequestsmuggling": "A05",
    "http request smuggling": "A05", "server side template": "A03",
    "ssti": "A03", "llm": "A01",
}


def _owasp_for(issue_name: str) -> str:
    name = issue_name.lower()
    for kw, cat in _OWASP.items():
        if kw in name:
            return cat
    return "A05"  # default: misconfiguration


class BurpAgent(BaseAgent):
    agent_name = "burp"
    owned_tools = ["burp_scan"]

    def _burp_tool(self):
        from tools.attack.burp_scan import BurpScanTool
        return BurpScanTool()

    def should_run(self, smap: dict) -> bool:
        """Applicable when there is a web surface and Burp is usable.

        "Usable" means already reachable OR installed on disk -- an installed
        but stopped Burp counts, because run() starts it. Checking only the
        healthcheck here meant the agent skipped itself forever unless someone
        had launched Burp by hand.

        Deliberately does NOT start Burp: should_run is called during planning,
        for every candidate agent, and launching a JVM to answer a planning
        question would be a very expensive way to say "maybe".
        """
        if not (smap.get("web_surfaces") or smap.get("endpoints") or smap.get("api_paths")):
            return False
        try:
            import scan_router
            # Applicable if *any* active-scan engine resolves: Burp Pro, or ZAP
            # as the free fallback (including when Burp is Community, which has
            # no scanner of its own).
            return scan_router.choose_engine(self._config()).can_scan
        except Exception:  # noqa: BLE001
            # Fall back to the old Burp-only check if routing is unavailable.
            try:
                tool = self._burp_tool()
                if tool.is_available():
                    return True
                service = getattr(tool, "_svc", None)
                return bool(service is not None and service.is_installed())
            except Exception:  # noqa: BLE001
                return False

    @staticmethod
    def _config():
        try:
            from utils import load_config
            return load_config()
        except Exception:  # noqa: BLE001
            return {}

    def run(self, target: str, smap: dict, memory: dict) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")

        urls = self._collect_urls(smap, target)
        if not urls:
            result.reasoning = "No web URLs to scan; skipping."
            result.status = "success"
            return result

        # Pick the active-scan engine: Burp Pro, else ZAP. Community has no
        # scanner, so the router routes it to ZAP or reports none.
        try:
            import scan_router
            decision = scan_router.choose_engine(self._config())
        except Exception:  # noqa: BLE001
            decision = None

        if decision is not None and decision.engine == scan_router.ZAP:
            return self._run_zap(target, urls, decision, result)
        if decision is not None and not decision.can_scan:
            result.reasoning = decision.reason
            result.status = "partial"
            return result

        from tools.attack.burp_scan import BurpScanTool
        try:
            tr = BurpScanTool().run(target, urls=urls[:10], project_target=target)
        except Exception:  # noqa: BLE001
            result.reasoning = "Burp scan failed (unavailable or exception)."
            return result

        if tr.status == "not_installed":
            result.reasoning = "Burp REST API unavailable; skipping."
            result.status = "partial"
            return result
        if tr.status != "success":
            result.reasoning = f"Burp scan errored: {tr.error}"
            result.status = "partial"
            return result

        result.tools_run.append("burp_scan")
        issues = tr.results.get("burp_issues", []) or []
        issue_map = {f"{f.get('name')}|{f.get('path', '')}": f for f in issues}
        for iss in issue_map.values():
            desc = iss.get("description", "") or ""
            rem = iss.get("remediation", "") or ""
            if rem and desc:
                desc = f"{desc}\nRemediation: {rem}"
            elif rem:
                desc = rem
            result.findings.append(self._make_finding(
                tool="burp_scan", name=iss.get("name", "Burp issue"),
                severity=iss.get("severity", "MEDIUM"),
                confidence=self._conf(iss.get("confidence")),
                url=iss.get("url") or target, description=desc,
                false_positive_risk="MEDIUM",
                raw_output_excerpt=json.dumps({"owasp": _owasp_for(iss.get("name", ""))})))

        total = tr.results.get("total_issues", len(issue_map))
        result.status = "success"
        result.reasoning = (f"Burp active scan complete: {len(issue_map)} distinct issues "
                            f"({total} reported).")
        return result

    def _run_zap(self, target: str, urls: List[str], decision: Any,
                 result: AgentResult) -> AgentResult:
        """Run the ZAP fallback and fold its alerts into findings."""
        from tools.attack.zap_scan import ZAPScanTool
        try:
            zap_cfg = (self._config() or {}).get("zap") if isinstance(self._config(), dict) else None
            tr = ZAPScanTool(zap_cfg).run(target, url=urls[0])
        except Exception as exc:  # noqa: BLE001
            result.reasoning = f"ZAP scan failed: {exc}"
            result.status = "partial"
            return result

        if tr.status == "not_installed":
            result.reasoning = decision.reason + " (ZAP not launchable)"
            result.status = "partial"
            return result
        if tr.status != "success":
            result.reasoning = f"ZAP scan errored: {tr.error}"
            result.status = "partial"
            return result

        result.tools_run.append("zap_scan")
        for alert in tr.results.get("zap_alerts", []) or []:
            desc = alert.get("description", "") or ""
            sol = alert.get("solution", "") or ""
            if sol and desc:
                desc = f"{desc}\nSolution: {sol}"
            result.findings.append(self._make_finding(
                tool="zap_scan", name=alert.get("name", "ZAP alert"),
                severity=alert.get("severity", "LOW"),
                confidence=self._conf(alert.get("confidence")),
                url=alert.get("url") or target, description=desc,
                false_positive_risk="MEDIUM",
                raw_output_excerpt=json.dumps({"owasp": _owasp_for(alert.get("name", "")),
                                               "cwe": alert.get("cwe", "")})))
        total = tr.results.get("total_alerts", len(result.findings))
        result.status = "success"
        result.reasoning = (f"ZAP active scan complete ({decision.reason}): "
                            f"{len(result.findings)} distinct alert(s) ({total} reported).")
        return result

    @staticmethod
    def _conf(confidence: str) -> int:
        c = str(confidence).lower()
        if "certain" in c or "high" in c:
            return 80
        if "tentative" in c or "low" in c:
            return 55
        if "firm" in c or "medium" in c:
            return 65
        return 60

    @staticmethod
    def _collect_urls(smap: dict, target: str) -> List[str]:
        urls: List[str] = []
        for surf in smap.get("web_surfaces", []) or []:
            if isinstance(surf, dict):
                b = surf.get("url") or surf.get("base_url")
                if b:
                    urls.append(str(b).rstrip("/"))
            elif isinstance(surf, str):
                urls.append(surf.rstrip("/"))
        for e in smap.get("endpoints", []) or []:
            if isinstance(e, dict):
                u = e.get("url") or e.get("path")
            else:
                u = e
            if u:
                urls.append(str(u))
        urls = list(dict.fromkeys(urls))
        return urls or [str(target)]
