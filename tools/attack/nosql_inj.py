"""
nosql_inj.py — NoSQL injection probe (OWASP A03 Injection).

MongoDB-family backends are reachable through the same HTTP surface as SQL
but take operator objects (`{"$ne": ""}`) instead of SQL fragments. Reflection
tests of SQL payloads miss them entirely. This tool re-tests API endpoints
with JSON operator objects and query-string `[$ne]` / `[$gt]` vectors and
flags behavior that changes the way a $ne filter changes an access check:
the injected variant behaves differently from the baseline (e.g. a 403 that
becomes 200, an error string, or an out-of-spec response length).

Pure python + requests. Read-only: GET and one POST with an injected body —
nothing is written, created, or deleted on the target.

Heuristic on purpose (shared with waf_bypass/ldap_inj): differences are
surfaced as candidates to verify, not as auto-claims of compromise.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from tools.base import Tool, ToolResult

DEFAULT_TIMEOUT = 8
_OP_VECTORS_GET = ["[$ne]", "[$gt]", "[$nin]", "[$exists]"]
_OP_VECTORS_JSON = lambda v: [{"$ne": v}, {"$gt": ""}, {"$nin": [v]}]  # noqa: E731
_MONGO_ERROR_HINTS = ("mongo", "bulkwriteerror", "command failed", "e11000",
                      "cast to objectid", "no document for query", "bson")
_BODY_DELTA = 80  # bytes


class NoSQLInjectionTool(Tool):
    name = "nosql_inj"
    capability = "NOSQL_INJECTION_SCAN"
    binary = ""  # python + requests, no external tool

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
        candidates: List[Dict[str, Any]] = []
        tested = 0

        for url in urls[:20]:
            base = str(url)
            # GET operator injection on query params
            get_params = self._query_params(base)
            if not get_params:
                continue
            names = [param] if param else [k for k, _ in get_params]
            for name in names:
                baseline = self._get(requests, base, timeout)
                if baseline is None:
                    continue
                for vec in _OP_VECTORS_GET:
                    injected = self._inject_get(base, name, vec)
                    resp = self._get(requests, injected, timeout)
                    tested += 1
                    if resp is None:
                        continue
                    if self._is_anomaly(baseline, resp):
                        candidates.append({"url": injected, "param": name,
                                           "vector": f"{name}{vec}",
                                           "baseline_status": baseline[0],
                                           "injected_status": resp[0],
                                           "len_delta": abs(len(resp[1]) - len(baseline[1]))})
                        break
            # JSON operator injection (POST) on a JSON-ish endpoint
            if kwargs.get("json_probe") and self._jsonish(base):
                json_candidates = self._probe_json(requests, base, names[0],
                                                   kwargs.get("post_data") or {}, timeout)
                tested += len(json_candidates)
                candidates.extend(json_candidates)

        if not candidates:
            return ToolResult(tool=self.name, status="success", capability=self.capability,
                              results={"tested": tested, "nosql_results": [],
                                       "vulnerable": [], "note": "no NoSQL anomaly observed"})

        out: Dict[str, Any] = {"tested": tested, "nosql_results": candidates,
                               "vulnerable": candidates}
        out["vulnerabilities"] = [
            {"name": "NoSQL injection — operator filter anomaly",
             "severity": "HIGH", "url": c["url"], "kind": "nosql_injection"}
            for c in candidates]
        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results=out)

    # ── internals ───────────────────────────────────────────────────────

    @staticmethod
    def _query_params(url: str) -> List[tuple]:
        from urllib.parse import parse_qsl
        return parse_qsl(url.split("?", 1)[1] if "?" in url else "", keep_blank_values=True)

    @staticmethod
    def _inject_get(url: str, name: str, vec: str) -> str:
        from urllib.parse import urlencode, urlparse, urlunparse
        parsed = urlparse(url)
        params = NoSQLInjectionTool._query_params(url)
        built = []
        for k, _ in params:
            if k == name:
                built.append((f"{k}{vec}", "x"))
            else:
                built.append((k, ""))
        return urlunparse(parsed._replace(query=urlencode(built)))

    def _get(self, requests, url: str, timeout: int):
        try:
            r = requests.get(url, headers={"User-Agent": "Mozilla/5.0 CyberSwarm-nosql/1.0"},
                             timeout=timeout, allow_redirects=False, verify=True)
            return r.status_code, r.text[:6000]
        except Exception:  # noqa: BLE001 - network hiccup is not a finding
            return None

    @staticmethod
    def _jsonish(url: str) -> bool:
        u = url.lower()
        return any(k in u for k in ("/api", "graphql", "/rest", "json"))

    def _probe_json(self, requests, url: str, name: str, base_data: dict,
                    timeout: int) -> List[Dict[str, Any]]:
        baseline = self._post(requests, url, base_data, timeout)
        found: List[Dict[str, Any]] = []
        if baseline is None:
            return found
        for op in _OP_VECTORS_JSON("x"):
            body = dict(base_data)
            if name in body or not body:
                body = {name or "id": op}
            else:  # place operator on the first key
                k = next(iter(body))
                body[k] = op
            resp = self._post(requests, url, body, timeout)
            if resp is None:
                continue
            err = any(h in (resp[1] or "").lower() for h in _MONGO_ERROR_HINTS)
            delta = abs(len(resp[1]) - len(baseline[1]))
            if err or delta > _BODY_DELTA:
                found.append({"url": url, "param": name or "id", "vector": str(op),
                              "baseline_status": baseline[0], "injected_status": resp[0],
                              "len_delta": delta, "error_hint": err})
        return found

    def _post(self, requests, url: str, body: dict, timeout: int):
        try:
            r = requests.post(url, json=body,
                              headers={"User-Agent": "Mozilla/5.0 CyberSwarm-nosql/1.0"},
                              timeout=timeout, allow_redirects=False, verify=True)
            return r.status_code, r.text[:6000]
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _is_anomaly(baseline, injected) -> bool:
        b_status, b_body = baseline
        i_status, i_body = injected
        if b_status in (401, 403, 404) and i_status in (200, 201, 202):
            return True  # operator bypassed an access check
        if b_status in (200, 201) and i_status in (500, 422, 400):
            return True  # operator blew up a filter -> error-bearing injection
        delta = abs(len(i_body) - len(b_body))
        return delta > _BODY_DELTA and (b_status == i_status)