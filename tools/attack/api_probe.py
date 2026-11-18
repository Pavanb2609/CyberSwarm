"""
API_PROBE -- live-probes discovered API endpoints: GET for reachability / auth
status, plus a lightweight GraphQL `__typename` probe on GraphQL paths. Pure
Python (urllib + ssl), no external binary. Non-destructive: read-only requests.
"""

import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List

from tools.base import Tool, ToolResult

DEFAULT_TIMEOUT = 30


class ApiProbeTool(Tool):
    name = "api_probe"
    capability = "API_PROBE"
    binary = ""

    def is_available(self) -> bool:
        return True

    def validate(self):
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["python-urllib-api-probe", target]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = DEFAULT_TIMEOUT, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or f"https://{target}"
        paths = [p for p in (kwargs.get("paths") or []) if p][:12]
        paths = [p if p.startswith("http") else f"{base.rstrip('/')}/{p.lstrip('/')}"
                 for p in paths]

        probes = []
        for url in paths:
            probe = self._probe_url(url, timeout)
            if probe is not None:
                probes.append(probe)

        if not probes:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                              error="No API paths responded over HTTPS/HTTP.")
        return ToolResult(tool=self.name, status="success", capability=self.capability,
                          results={"api_probes": probes, "target": target})

    @staticmethod
    def _request(url: str, data: bytes | None, method: str,
                 timeout: int) -> Dict[str, Any] | None:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={"User-Agent": "Mozilla/5.0 (compatible; CyberSwarm-api-probe/1.0)",
                     "Content-Type": "application/json" if data else "text/plain"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return {"status": resp.status, "body": resp.read(5000).decode("utf-8", errors="replace")}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:  # noqa: BLE001
            return None

    def _probe_url(self, url: str, timeout: int) -> Dict[str, Any] | None:
        get = self._request(url, None, "GET", timeout)
        if get is None:
            return None
        is_graphql = "graphql" in url.lower()
        result: Dict[str, Any] = {
            "url": url,
            "method": "GET",
            "status": get["status"],
            "auth_required": get["status"] in (401, 403),
            "unauthenticated_200": get["status"] == 200,
            "graphql": is_graphql,
            "notes": [],
        }

        if is_graphql:
            payload = json.dumps({"query": "{__typename}"}).encode()
            post = self._request(url, payload, "POST", timeout)
            if post is not None:
                gql_ok = post["status"] in (200, 400, 500) and self._looks_like_json(post["body"])
                result["graphql_responded"] = post["status"] == 200
                result["graphql_probe_status"] = post["status"]
                result["notes"].append(
                    f"GraphQL __typename probe -> HTTP {post['status']}"
                    + (" (endpoint responds)" if gql_ok else ""))

        return result

    @staticmethod
    def _looks_like_json(body: str) -> bool:
        body = (body or "").strip()
        if not body:
            return False
        try:
            json.loads(body)
            return True
        except (ValueError, TypeError):
            return "errors" in body and body.startswith("{")
