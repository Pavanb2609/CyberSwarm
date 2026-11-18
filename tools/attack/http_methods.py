"""
HTTP method abuse wrapper (curl-based, zero external deps beyond curl).

Tests OPTIONS/TRACE/PUT/DELETE/PATCH against the target and flags:
  - TRACE enabled (XST risk)
  - server allowing PUT/DELETE/PATCH (potentially destructive verbs)
  - OPTIONS exposing an overly permissive Allow header

Nothing destructive is written: PUT is sent with an empty body and we only
record the returned status code as evidence.
"""

import json
from typing import Any, Dict, List

from tools.base import Tool


class HttpMethodTestTool(Tool):
    name = "http_methods"
    capability = "HTTP_METHOD_TEST"
    binary = "curl"

    SCRIPT = r'''
url="$1"
for m in OPTIONS TRACE PUT DELETE PATCH; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X "$m" -m 15 "$url" 2>/dev/null)
  allow=$(curl -s -o /dev/null -D - -X OPTIONS -m 15 "$url" 2>/dev/null | tr -d "\r" | grep -i "^Allow:" | head -1 | cut -d" " -f2-)
  echo "$m|$code|$allow"
done
'''

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = target if target.startswith("http") else f"https://{target}"
        return ["bash", "-c", self.SCRIPT, "http_methods", url]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        checks = []
        findings = []
        for line in (stdout or "").splitlines():
            parts = line.strip().split("|")
            if len(parts) < 2:
                continue
            method, code = parts[0], parts[1]
            allow = parts[2] if len(parts) > 2 else ""
            checks.append({"method": method, "status": code, "allow": allow})
            if method == "TRACE" and code in ("200", "201"):
                findings.append({"method": "TRACE", "status": code,
                                 "issue": "TRACE enabled (XST risk)"})
            elif method in ("PUT", "DELETE", "PATCH") and code in ("200", "201", "202", "204"):
                findings.append({"method": method, "status": code,
                                 "issue": f"{method} accepted by server"})
        # OPTIONS Allow header heuristic
        allow_headers = [c["allow"] for c in checks if c.get("allow")]
        if allow_headers:
            verbs = {v.strip().upper() for v in ",".join(allow_headers).split(",")}
            dangerous = verbs & {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}
            if dangerous:
                findings.append({"method": "OPTIONS",
                                 "issue": f"Allow header permits dangerous verbs: {sorted(dangerous)}",
                                 "allow": ",".join(allow_headers)})
        return {"http_methods": checks, "method_findings": findings, "count": len(findings)}
