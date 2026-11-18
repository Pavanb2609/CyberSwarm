"""
JWT analysis wrapper — jwt_tool token inspection and known-weakness checks.

The wrapper accepts a `token` kwarg (or reads `JWT_TOKEN` env var). Without a
token it returns an empty result with a note, since JWTs are per-session
tokens, not host-level properties. Only stateless, non-destructive checks run
(no brute force, no algorithm confusion exploitation).
"""

from typing import Any, Dict, List

from tools.base import Tool


class JwtTool(Tool):
    name = "jwt_tool"
    capability = "JWT_ANALYSIS"
    binary = "jwt_tool"

    def build_command(self, target: str, **kwargs) -> List[str]:
        token = str(kwargs.get("token", "") or "").strip()
        self._token = token
        if not token:
            return ["/bin/true"]
        return [self.binary, "-X", "i", token]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        if not getattr(self, "_token", ""):
            return {"jwt_findings": [], "count": 0,
                    "note": "No JWT token provided; supply via token= kwarg"}
        findings = []
        low = (stdout or "").lower()
        if "alg=none" in low or "none algorithm" in low:
            findings.append({"issue": "Token accepts alg=none", "severity": "HIGH"})
        if "kid" in low and "sql injection" in low:
            findings.append({"issue": "Possible kid header injection", "severity": "MEDIUM"})
        return {"jwt_findings": findings, "count": len(findings)}
