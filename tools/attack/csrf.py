"""
CSRF_SCAN -- active CSRF token bypass testing.

Detection (passive) lives in tools/recon/csrf_surface_detect.py and provides
``csrf_surface`` (form action/method/token presence).  This tool then proves
attacker-controllable cross-site submission behaviorally:

  1. A POST with a *same-origin* Origin header  -> baseline code
  2. The same POST with a *cross-site* Origin header  -> oracle code

A server that rejects the cross-site request (4xx/5xx) is Origin-protected
and is reported as such -- never as a finding.  A tokenless state-changing
form that also *accepts* the cross-site request is the only signal that
produces a HIGH finding, and the confidence is derived from exactly which
proof criteria were met.

Honesty notes: a 2xx/302 alone proves nothing (the state change is not
observable from one request), so confirmed findings carry
``requires_browser_oracle`` and a SameSite cookie check is folded into the
criteria stack rather than assumed safe by default.

Pure Python + curl.  Non-destructive: submits benign form data only.
"""

import re
import subprocess
from typing import Any
from urllib.parse import urlparse

from tools.attack.verdict import confidence_from_criteria, criteria_label
from tools.base import Tool, ToolResult

STATE_METHODS = {"POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
ACCEPTED_CODES = {200, 201, 202, 204, 302, 303, 307, 308}
REJECTED_CODES = {400, 401, 403, 405, 429, 500, 501}

# Proof criteria and their weight -- confidence is 50 + sum of the criteria
# actually satisfied, capped at 96.
CRITERIA_WEIGHTS = {
    "tokenless": 10,
    "state_changing": 10,
    "cross_origin_accepted": 30,
    "no_samesite_protection": 10,
}
CRITERIA_HINTS = {
    "tokenless": "form has no anti-CSRF token",
    "state_changing": f"state-changing method ({'/'.join(sorted(STATE_METHODS))})",
    "cross_origin_accepted": "cross-site request accepted (Origin unchecked)",
    "no_samesite_protection": "session cookie lacks SameSite=Lax/Strict",
}


class CSRFScanTool(Tool):
    """Active CSRF token/Origin behavior testing."""

    name = "csrf"
    capability = "CSRF_SCAN"
    binary = "curl"

    def build_command(self, target: str, **kwargs) -> list[str]:
        return ["echo", "csrf-active-placeholder"]

    def parse(self, stdout: str, stderr: str) -> dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 60, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        forms = kwargs.get("csrf_surface") or []

        if not forms:
            return ToolResult(
                tool=self.name, status="success", capability=self.capability,
                results={"csrf_findings": [], "protected": [], "count": 0,
                         "message": "No CSRF-vulnerable forms provided from recon detection"},
            )

        findings = []
        protected = []
        for form in forms[:10]:
            action_url = form.get("action_url", "")
            method = str(form.get("method", "POST")).upper()
            has_token = bool(form.get("has_csrf_token"))
            if not action_url:
                continue
            action_url = action_url if action_url.startswith("http") else f"{base.rstrip('/')}/{action_url.lstrip('/')}"

            outcome = self._probe(action_url, method, timeout)
            if outcome is None:
                protected.append({"url": action_url, "method": method,
                                  "reason": "probe failed (timeout/unreachable)"})
                continue

            met = []
            if not has_token:
                met.append("tokenless")
            if method in STATE_METHODS:
                met.append("state_changing")
            if outcome["cross_code"] in ACCEPTED_CODES:
                met.append("cross_origin_accepted")
            if outcome["samesite"] not in ("strict", "lax"):
                met.append("no_samesite_protection")

            if has_token:
                protected.append({"url": action_url, "method": method,
                                  "reason": "anti-CSRF token present in form"})
                continue
            if outcome["cross_code"] in REJECTED_CODES:
                protected.append({"url": action_url, "method": method,
                                  "reason": f"cross-site request rejected (HTTP {outcome['cross_code']})"})
                continue
            if not met or "cross_origin_accepted" not in met:
                protected.append({"url": action_url, "method": method,
                                  "reason": "no decisive cross-origin acceptance observed"})
                continue

            severity = "HIGH" if "cross_origin_accepted" in met else "MEDIUM"
            conf = confidence_from_criteria(met, CRITERIA_WEIGHTS)
            findings.append({
                "url": action_url,
                "method": method,
                "issue": "Cross-site request accepted without CSRF token",
                "severity": severity,
                "confidence": conf,
                "description": f"Form at {action_url} accepted cross-site {method} without "
                               f"anti-CSRF token (baseline HTTP {outcome['baseline_code']}, "
                               f"cross-site HTTP {outcome['cross_code']}); proof: "
                               f"{criteria_label(met, CRITERIA_HINTS)}",
                "response_code": outcome["cross_code"],
                "same_origin_code": outcome["baseline_code"],
                "cross_origin_code": outcome["cross_code"],
                "proof_criteria": met,
                "requires_browser_oracle": True,
                "note": "2xx/3xx proves the request is accepted, not that the "
                        "state change applied; confirm in a real cross-site session.",
            })

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={"csrf_findings": findings, "protected": protected,
                     "count": len(findings)},
        )

    def _probe(self, url: str, method: str, timeout: int) -> dict[str, Any] | None:
        """Behavioral oracle: same-origin vs cross-site Origin + SameSite sniff."""
        timeout = min(timeout, 20)
        samesite = self._samesite(url, method, timeout)
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        baseline = self._send(url, method, f"Origin: {origin}", timeout)
        cross = self._send(url, method, "Origin: https://evil.example", timeout)
        if baseline is None or cross is None:
            return None
        return {"baseline_code": baseline, "cross_code": cross, "samesite": samesite}

    @staticmethod
    def _send(url: str, method: str, origin_header: str, timeout: int) -> int | None:
        cmd = [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-m", str(timeout),
            "-X", method,
            "-H", origin_header,
            "-H", "Content-Type: application/x-www-form-urlencoded",
            "-A", "Mozilla/5.0 (compatible; CyberSwarm-csrf/1.0)",
            "-d", "test=1",
            url,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout + 5, errors="replace")
            code = proc.stdout.strip()
            return int(code) if code.isdigit() else None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    @staticmethod
    def _samesite(url: str, method: str, timeout: int) -> str | None:
        """Best-effort SameSite read of any session cookie the server sets."""
        cmd = [
            "curl", "-s", "-D", "-", "-o", "/dev/null",
            "-m", str(timeout), "-A", "Mozilla/5.0",
            url,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout + 5, errors="replace")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
        for line in proc.stdout.splitlines():
            if ":" not in line:
                continue
            name, _, value = line.partition(":")
            if name.strip().lower() != "set-cookie":
                continue
            m = re.search(r";\s*samesite\s*=\s*(\w+)", value, re.IGNORECASE)
            if m:
                return m.group(1).lower()
        return None  # no cookie observed — SameSite defense not proven either way