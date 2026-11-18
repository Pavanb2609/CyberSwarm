"""
Clickjacking detection wrapper (curl-based).

Checks response headers for frame-busting controls: X-Frame-Options and/or
Content-Security-Policy with frame-ancestors. If neither is present the page
is likely frameable — reported as an informational/medium finding for review.
"""

from typing import Any, Dict, List

from tools.base import Tool


class ClickjackingTool(Tool):
    name = "clickjack"
    capability = "CLICKJACKING_TEST"
    binary = "curl"

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = target if target.startswith("http") else f"https://{target}"
        return [self.binary, "-s", "-D", "-", "-o", "/dev/null", "-m", "15", url]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        headers = {}
        for line in (stdout or "").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")
        protected = bool(xfo) or ("frame-ancestors" in csp.lower())
        findings = []
        if not protected:
            findings.append({
                "url": "",
                "frameable": True,
                "missing": ["X-Frame-Options", "Content-Security-Policy frame-ancestors"]
                if not csp else ["X-Frame-Options"],
            })
        return {
            "clickjacking": findings,
            "x_frame_options": xfo,
            "csp": csp,
            "count": len(findings),
        }
