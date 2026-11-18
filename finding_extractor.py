"""
finding_extractor.py — turn raw RUN-ALL tool output into findings worth reviewing.

The RUN-ALL sweep (attack_engine.run_all) used to write every tool's raw output
straight into the evidence store as a CONFIRMED vulnerability, with no review.
That is how an amazon.in sweep produced 27 "vulnerabilities" of which 22 were
Nikto log lines ("Target IP: ...", "Nikto is out of date") and 4 were the tool
mistaking a benign 301 redirect for SSRF / CRLF / a valid credential.

This module sits between the raw results and the evidence store and does two
things, in order:

  1. Deterministic filtering. Scan metadata and self-refuting results are
     dropped before anything else looks at them. A Nikto banner is not a
     finding; a brute-force result whose own record says ``hit: false`` is not
     a credential. This needs no model and cannot itself hallucinate.

  2. Evidence gating. What survives is only marked CONFIRM if its own evidence
     actually supports the claim. A CRLF result whose "injected" header is
     URL-encoded (so it never split the response) is downgraded to NEEDS_PROOF,
     not confirmed. An SSRF result whose evidence is an HTML error page is
     downgraded. This is the check the critic is supposed to make; doing a
     deterministic version first means the critic is never asked to bless
     obvious garbage, and its budget goes to the genuinely ambiguous cases.

The output is a list of AgentFinding with a provisional verdict. The caller
(run_all) then sends the survivors through the real CriticAgent for the final
say. Deterministic filtering is not a replacement for the critic — it is the
floor that stops the critic being handed noise.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from agents.base_agent import AgentFinding

# ── Nikto: raw stdout lines that are metadata, not findings ──────────────────
#
# Nikto prints its findings interleaved with a banner and a footer. Only the
# lines describing an actual issue matter; everything else is scan bookkeeping.

_NIKTO_NOISE_PREFIXES = (
    "target ip", "target hostname", "target port", "start time", "end time",
    "server:", "ssl info", "platform:", "multiple ips", "no cgi",
    "scan terminated", "host(s) tested", "1 host", "nikto", "- nikto",
    "your nikto installation", "+ target", "+ start", "+ end", "+ server",
    "+ ssl", "+ root page", "+ no cgi", "+ scan", "+ 1 host",
)

# Nikto lines that ARE findings: a missing security header, a dangerous method,
# an exposed path, a known-vuln OSVDB/CVE reference.
_NIKTO_SIGNAL = (
    "security header missing", "uncommon header", "wildcard certificate",
    "osvdb", "cve-", "cookie", "x-frame-options", "clickjacking",
    "directory indexing", "backup", "put method", "trace method",
    "default file", "admin", "phpinfo",
)


def _looks_like_nikto_noise(text: str) -> bool:
    low = str(text or "").strip().lower()
    if not low:
        return True
    if any(sig in low for sig in _NIKTO_SIGNAL):
        return False
    return any(low.startswith(prefix) or prefix in low[:24]
               for prefix in _NIKTO_NOISE_PREFIXES)


# ── Evidence checks per finding type ─────────────────────────────────────────

def _crlf_actually_split(record: Dict[str, Any]) -> bool:
    """A real CRLF splits the response; an encoded payload does not.

    The amazon.in false positive: the payload landed as
    ``...&%0d%0aX-Injected:%20true`` inside a redirect Location — URL-encoded,
    after an ``&``, never interpreted as a line break. A genuine CRLF shows the
    injected header as its own decoded header, not a percent-encoded query
    fragment.
    """
    injected = str(record.get("injected_header", "") or "")
    if not injected:
        return False
    # If the CR/LF is still percent-encoded in the reflected value, the server
    # did not interpret it -- no split happened.
    if "%0d%0a" in injected.lower() or "%0a" in injected.lower():
        return False
    # A real split puts the injected header on its own line.
    return "\r\n" in injected or "\n" in injected


def _ssrf_has_service_evidence(record: Dict[str, Any]) -> bool:
    """Real SSRF returns the internal service's response, not an HTML page.

    gopher->Redis returns Redis INFO; gopher->memcached returns stats. The
    amazon.in false positives all had ``evidence`` starting ``<html>`` (a web
    error page) or "HTTP 301" (the site's redirect to www) -- neither proves an
    internal service answered.
    """
    evidence = str(record.get("evidence", "") or "").strip().lower()
    if not evidence:
        return False
    if evidence.startswith("<html") or "<head>" in evidence[:40]:
        return False
    # A bare redirect is the site bouncing you, not an internal service.
    if re.match(r"^http\s*30[1237]", evidence) or "301," in evidence[:12]:
        return False
    variant = str(record.get("variant", "")).lower()
    service_markers = {
        "gopher_redis": ("redis_version", "used_memory", "# server"),
        "gopher_memcached": ("stat ", "version ", "curr_connections"),
    }
    markers = service_markers.get(variant)
    if markers:
        return any(m in evidence for m in markers)
    # Internal port scan: a real hit distinguishes ports; identical 301s for
    # every port are the redirect, not open services.
    return "301" not in evidence and "redirect" not in evidence


def _brute_actually_hit(record: Dict[str, Any]) -> bool:
    """A credential finding is real only if the brute record says it hit.

    The amazon.in CRITICAL: the raw record was ``{username:'', status:200,
    hit:false}``. The wrapper reported a "valid credential" anyway, reading a
    200 (the login page loading) as success. Honour the tool's own ``hit``.
    """
    if record.get("hit") is False:
        return False
    if not record.get("hit") and not record.get("valid"):
        # No positive hit signal at all, and an empty username is never a
        # credential.
        if not str(record.get("username", "")).strip():
            return False
    return True


# ── Extraction ───────────────────────────────────────────────────────────────

# verdict values used before the real critic runs.
CONFIRM = "CONFIRM"
NEEDS_PROOF = "NEEDS_PROOF"
DISPUTE = "DISPUTE"


def _finding(name: str, severity: str, confidence: int, tool: str, action: str,
             description: str = "", url: str = "", verdict: str = NEEDS_PROOF,
             evidence: str = "") -> AgentFinding:
    f = AgentFinding(
        name=name, severity=severity, confidence=confidence,
        url=url, description=description,
        agent=f"run_all:{action}", tool=tool)
    # Stash the provisional verdict where the caller and critic can read it.
    try:
        f.verdict = verdict            # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    if evidence:
        f.raw_output_excerpt = evidence[:500]
    return f


def extract_findings(action: str, tr_results: Dict[str, Any],
                     tool: str) -> List[AgentFinding]:
    """Turn one action's raw results into provisionally-graded findings.

    Applies the deterministic filters above. Nothing here confirms a finding on
    its own beyond the cases where the evidence is unambiguous (a missing
    header is a fact); everything else comes out NEEDS_PROOF for the critic.
    """
    if not isinstance(tr_results, dict):
        return []
    out: List[AgentFinding] = []

    # CRLF ---------------------------------------------------------------
    for rec in tr_results.get("crlf_findings", []) or _as_list(tr_results, "crlf"):
        if not isinstance(rec, dict):
            continue
        real = _crlf_actually_split(rec)
        out.append(_finding(
            "CRLF Injection", "HIGH" if real else "LOW",
            int(rec.get("confidence", 75)) if real else 30,
            tool, action, str(rec.get("description", "")),
            str(rec.get("url", "")),
            verdict=CONFIRM if real else DISPUTE,
            evidence=str(rec.get("injected_header", ""))))

    # SSRF ---------------------------------------------------------------
    for rec in tr_results.get("ssrf_findings", []) or []:
        if not isinstance(rec, dict):
            continue
        real = _ssrf_has_service_evidence(rec)
        sev = rec.get("severity", "MEDIUM") if real else "LOW"
        out.append(_finding(
            f"SSRF ({rec.get('type', 'unknown')})", sev,
            int(rec.get("confidence", 60)) if real else 25,
            tool, action, str(rec.get("description", "")),
            str(rec.get("url", "")),
            verdict=CONFIRM if real else DISPUTE,
            evidence=str(rec.get("evidence", ""))))

    # Brute force --------------------------------------------------------
    for rec in tr_results.get("brute_results", []) or []:
        if not isinstance(rec, dict):
            continue
        if not _brute_actually_hit(rec):
            continue    # dropped entirely: no hit means no finding
        out.append(_finding(
            "Valid credentials disclosed", "CRITICAL",
            int(rec.get("confidence", 90)), tool, action,
            f"username={rec.get('username')!r} validated",
            str(rec.get("url", "")), verdict=NEEDS_PROOF,
            evidence=str(rec)[:300]))

    # Nikto --------------------------------------------------------------
    for rec in tr_results.get("nikto_findings", []) or []:
        text = rec.get("description", rec) if isinstance(rec, dict) else rec
        text = str(text or "")
        if _looks_like_nikto_noise(text):
            continue    # scan metadata, not a finding
        out.append(_finding(
            _nikto_name(text), "INFO", 40, tool, action, text[:200],
            verdict=CONFIRM if "missing" in text.lower() else NEEDS_PROOF,
            evidence=text[:300]))

    return out


def _nikto_name(text: str) -> str:
    low = text.lower()
    if "security header missing" in low or "header: " in low:
        header = text.split(":")[-1].strip()
        return f"Missing security header: {header}" if header else "Missing security header"
    if "wildcard cert" in low:
        return "Wildcard TLS certificate"
    if "uncommon header" in low:
        return "Uncommon response header"
    return text[:60].strip() or "Nikto finding"


def _as_list(d: Dict[str, Any], key: str) -> List[Any]:
    v = d.get(key)
    return v if isinstance(v, list) else []


def summarise(findings: List[AgentFinding]) -> Dict[str, int]:
    counts = {CONFIRM: 0, NEEDS_PROOF: 0, DISPUTE: 0}
    for f in findings:
        v = getattr(f, "verdict", NEEDS_PROOF)
        counts[v] = counts.get(v, 0) + 1
    return counts
