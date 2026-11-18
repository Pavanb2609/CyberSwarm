"""
DEFAULT_CRED_CHECK -- quick check of well-known/default credentials against
discovered auth endpoints (admin panels, login forms, basic-auth). The
small, safe sibling of LOGIN_BRUTE: only the bundled defaults list runs, and
findings are rated MEDIUM (low-effort, no wordlist). Pure Python.

When nuclei + its templates are installed, the registry keeps
nuclei_defaultlogin as the fallback chain member -- this tool just runs a
faster, deterministic defaults-only pass first.
"""

from typing import Any

from tools.attack.login_brute import DEFAULT_CREDENTIALS, LoginBruteTool
from tools.base import ToolResult


class DefaultCredsCheckTool(LoginBruteTool):
    name = "default_creds_check"
    capability = "DEFAULT_CRED_CHECK"

    def _python_brute(self, target: str, ctx, kwargs, timeout: int) -> Any:
        if ctx is not None and ctx.credentials:
            supplied = [c.username for c in ctx.credentials]
            extra = [(u, p) for (u, p) in DEFAULT_CREDENTIALS if u not in supplied]
        else:
            extra = DEFAULT_CREDENTIALS
        kwargs = dict(kwargs, extra_creds=extra)
        res = super()._python_brute(target, ctx, kwargs, timeout)
        if not isinstance(res, ToolResult):
            return res
        results = dict(res.results or {})
        for v in (results.get("vulnerabilities") or []):
            v["severity"] = "MEDIUM"
        results["source"] = "default-credentials-list"
        if not results.get("vulnerabilities"):
            results["vulnerabilities"] = []
        res.results = results
        return res