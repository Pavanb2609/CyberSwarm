"""
Host-header injection / cache-poisoning probe (curl-based).

Sends the request with a non-canonical Host header and compares the response
(Location redirect, rendered content, Cache-Control) against a baseline. A
difference is evidence of host-header reflection that may support cache
poisoning or routing attacks. Read-only — nothing is cached back.
"""

from typing import Any, Dict, List

from tools.base import Tool


class HostHeaderAttackTool(Tool):
    name = "host_header"
    capability = "HOST_HEADER_ATTACK"
    binary = "curl"

    SCRIPT = r'''
url="$1"
evil="evil.example"
base_headers=$(curl -s -D - -o /dev/null -m 15 "$url" 2>/dev/null)
evil_headers=$(curl -s -D - -o /dev/null -m 15 -H "Host: $evil" "$url" 2>/dev/null)
base_body=$(curl -s -m 15 "$url" 2>/dev/null)
evil_body=$(curl -s -m 15 -H "Host: $evil" "$url" 2>/dev/null)
echo "===BASELINE-HEADERS==="
printf "%s" "$base_headers"
echo "===EVIL-HEADERS==="
printf "%s" "$evil_headers"
echo "===BASELINE-BODY==="
printf "%s" "$base_body" | head -c 3000
echo "===EVIL-BODY==="
printf "%s" "$evil_body" | head -c 3000
echo "===BODYLEN==="
printf "%s" "$base_body" | wc -c
printf "%s" "$evil_body" | wc -c
'''

    def build_command(self, target: str, **kwargs) -> List[str]:
        url = target if target.startswith("http") else f"https://{target}"
        return ["bash", "-c", self.SCRIPT, "host_header", url]

    def _section(self, blob: str, marker: str) -> str:
        if marker not in blob:
            return ""
        return blob.split(marker, 1)[1].split("===", 1)[0]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        base_h = self._section(stdout, "===BASELINE-HEADERS===")
        evil_h = self._section(stdout, "===EVIL-HEADERS===")
        base_b = self._section(stdout, "===BASELINE-BODY===")
        evil_b = self._section(stdout, "===EVIL-BODY===")

        def get_status(h: str) -> str:
            first = (h or "").strip().splitlines()[0] if (h or "").strip() else ""
            return first.split(" ", 2)[1] if len(first.split(" ")) > 1 else ""

        def get_location(h: str) -> str:
            for ln in (h or "").splitlines():
                if ln.lower().startswith("location:"):
                    return ln.split(":", 1)[1].strip()
            return ""

        findings = []
        base_loc = get_location(base_h)
        evil_loc = get_location(evil_h)
        if evil_loc and "evil.example" in evil_loc.lower():
            findings.append({
                "issue": "Host header reflected into Location header",
                "baseline_location": base_loc,
                "evil_location": evil_loc,
            })
        if "evil.example" in evil_b.lower() and "evil.example" not in base_b.lower():
            findings.append({
                "issue": "Host header reflected into response body (potential cache poisoning)",
                "body_reflects_host": True,
            })
        if get_status(base_h) != get_status(evil_h) and get_status(evil_h) not in ("", "400", "403", "421"):
            findings.append({
                "issue": "Non-canonical Host yields different HTTP status",
                "baseline_status": get_status(base_h),
                "evil_status": get_status(evil_h),
            })
        return {"host_header_findings": findings, "count": len(findings)}
