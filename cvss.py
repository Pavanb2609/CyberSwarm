"""
cvss.py — CVSS 3.1 base-score computation + finding-type classification.

Every attack tool wrapper currently produces a vulnerability dict shaped
differently (nuclei has template_id/severity, nikto has msg/osvdbid, nmap
NSE has script/output, ...) and the only severity signal is whatever string
label the source tool assigned -- "MEDIUM" for every Nikto hit regardless
of what it actually found, "UNKNOWN" when a tool doesn't score at all.

This module adds two things on top of that, without touching how any tool
wrapper produces its raw output:

1. classify_finding_type(vuln) -- a deterministic, keyword-based classifier
   mapping a raw finding into a controlled vocabulary (FINDING_TYPES).
   Deliberately NOT LLM-based: the project's own testing philosophy is
   "deterministic where possible", and classification feeds a score that
   ends up in a report, so it needs to be reproducible and debuggable.

2. enrich_finding(vuln) -- adds cvss_vector / cvss_score / cvss_severity /
   finding_type to a copy of the finding, using a curated default CVSS 3.1
   vector per finding type (FINDING_TYPE_CVSS_DEFAULTS) when the type is
   recognized. These are archetypal vectors for the *class* of bug (e.g.
   "unauthenticated reflected XSS" in general), not a per-instance
   assessment -- cvss_source records that honestly rather than presenting
   a computed number as more rigorous than it is. When nothing classifies,
   it falls back to the tool's own severity label with cvss_vector=None,
   so a caller can always tell the difference between "we scored this"
   and "we're repeating what the tool said".

The base-score formula itself (weights, ISS, Exploitability, the Roundup
function) is the public CVSS 3.1 specification published by FIRST.org --
the same formula every CVSS calculator (including NVD's own) implements.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# ── CVSS 3.1 base metric weights (FIRST.org CVSS v3.1 specification) ───────

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

SEVERITY_BANDS = (  # (lower_bound_inclusive, upper_bound_inclusive, label)
    (0.0, 0.0, "NONE"),
    (0.1, 3.9, "LOW"),
    (4.0, 6.9, "MEDIUM"),
    (7.0, 8.9, "HIGH"),
    (9.0, 10.0, "CRITICAL"),
)

# Rough midpoint used ONLY as a last resort, when a finding can't be
# classified into a finding_type at all -- see enrich_finding().
_SEVERITY_LABEL_MIDPOINT = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.5, "UNKNOWN": None}


@dataclass(frozen=True)
class CVSSVector:
    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    S: str = "U"   # Unchanged | Changed
    C: str = "N"
    I: str = "N"   # noqa: E741 - CVSS's own metric name
    A: str = "N"

    def as_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}/"
                f"S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}")


def _roundup(x: float) -> float:
    """The official CVSS 3.1 Roundup function: round UP to 1 decimal place,
    computed via integer arithmetic to avoid float-precision edge cases
    (this is FIRST.org's own published algorithm, not an approximation)."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(vector: CVSSVector) -> float:
    """CVSS 3.1 base score, 0.0-10.0."""
    av, ac = _AV[vector.AV], _AC[vector.AC]
    ui = _UI[vector.UI]
    pr_table = _PR_CHANGED if vector.S == "C" else _PR_UNCHANGED
    pr = pr_table[vector.PR]
    c, i, a = _CIA[vector.C], _CIA[vector.I], _CIA[vector.A]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if vector.S == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui

    if vector.S == "C":
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    for lo, hi, label in SEVERITY_BANDS:
        if lo <= score <= hi:
            return label
    return "UNKNOWN"


# ── Finding-type classification ─────────────────────────────────────────────
# Ordered: more specific patterns must come before generic ones that would
# otherwise shadow them (e.g. "stored xss" before the bare "xss" check).

_CLASSIFIERS: List[Tuple[str, Tuple[str, ...]]] = [
    ("remote_code_execution", ("remote code execution", "rce", "command injection", "code execution")),
    ("server_side_template_injection", ("ssti", "template injection")),
    ("server_side_request_forgery", ("ssrf", "server-side request forgery", "server side request forgery")),
    ("xml_external_entity", ("xxe", "xml external entity")),
    ("insecure_deserialization", ("deserialization",)),
    # NoSQL/LDAP must match before the generic SQL check: "NoSQL injection"
    # contains the substring "SQL injection", so order here decides the class.
    ("nosql_injection", ("nosql", "no-sql", "mongodb injection", "operator payload")),
    ("ldap_injection", ("ldap filter", "ldap injection", "ldap wildcard")),
    ("sql_injection", ("sql injection", "sqli", "sql-injection")),
    ("asrep_roastable", ("as-rep roast", "asrep", "pre-auth", "dont_req_preauth",
                         "krb5asrep", "no pre-auth", "no preauthentication")),
    ("kerberoastable", ("kerberoast", "krb5tgs", "spn account", "service account tgs")),
    ("smb_null_session", ("null session", "smb null", "anonymous share", "null-session")),
    ("cross_site_scripting_stored", ("stored xss", "persistent xss", "stored cross-site")),
    ("cross_site_scripting_reflected", ("xss", "cross-site scripting", "cross site scripting")),
    ("csrf", ("csrf", "cross-site request forgery")),
    ("idor", ("idor", "insecure direct object", "broken object level")),
    ("unrestricted_file_upload", ("file upload", "unrestricted upload")),
    ("local_file_inclusion", ("lfi", "local file inclusion", "path traversal", "directory traversal")),
    ("subdomain_takeover", ("subdomain takeover", "subjack", "dangling cname", "dangling dns")),
    ("default_credentials", ("default credential", "default password", "weak credential")),
    ("jwt_weak_algorithm", ("jwt", "alg:none", "jwt none", "none algorithm")),
    ("cors_misconfiguration", ("cors", "cross-origin resource sharing")),
    ("clickjacking", ("clickjack", "x-frame-options")),
    ("host_header_injection", ("host header",)),
    ("session_fixation", ("session fixation", "session hijack")),
    ("crlf_injection", ("crlf",)),
    ("http_method_enabled", ("http method", "trace method", "dangerous method")),
    ("directory_listing", ("directory listing", "index of /")),
    ("waf_bypass", ("waf bypass", "waf evasion")),
    ("weak_tls_configuration", ("tls", "ssl", "cipher", "certificate")),
    ("missing_security_header", ("missing header", "security header", "strict-transport-security",
                                 "x-content-type-options")),
    ("information_disclosure", ("information disclosure", "info leak", "exposed", "disclosure")),
    ("open_redirect", ("open redirect",)),
    ("security_misconfiguration", ("misconfiguration", "misconfigured")),
]

FINDING_TYPES = tuple(name for name, _ in _CLASSIFIERS)


def classify_finding_type(vuln: Dict[str, Any]) -> Optional[str]:
    haystack = " ".join(str(vuln.get(k, "")) for k in
                        ("name", "template_id", "description", "msg")).lower()
    for finding_type, keywords in _CLASSIFIERS:
        if any(kw in haystack for kw in keywords):
            return finding_type
    return None


# ── Archetypal CVSS 3.1 vectors per finding_type ────────────────────────────
# These describe the class of bug in its typical unauthenticated,
# black-box-discoverable form -- NOT a per-instance assessment. A specific
# instance can be more or less severe depending on what it actually
# exposes; treat this as a documented, consistent starting point a human
# reviewer can adjust, not a final verdict.

FINDING_TYPE_CVSS_DEFAULTS: Dict[str, CVSSVector] = {
    "remote_code_execution": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
    "server_side_template_injection": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
    "sql_injection": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    "nosql_injection": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
    "ldap_injection": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="L"),
    "asrep_roastable": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="L", A="L"),
    "kerberoastable": CVSSVector(AV="N", AC="L", PR="L", UI="N", S="C", C="H", I="L", A="L"),
    "smb_null_session": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N"),
    "insecure_deserialization": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    "unrestricted_file_upload": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    "server_side_request_forgery": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="L", A="N"),
    "xml_external_entity": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="N"),
    "jwt_weak_algorithm": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"),
    "default_credentials": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    "subdomain_takeover": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"),
    "local_file_inclusion": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    "idor": CVSSVector(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="N", A="N"),
    "cross_site_scripting_stored": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="L", I="L", A="N"),
    "cross_site_scripting_reflected": CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
    "csrf": CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="N", I="L", A="N"),
    "session_fixation": CVSSVector(AV="N", AC="H", PR="N", UI="R", S="U", C="L", I="L", A="N"),
    "weak_tls_configuration": CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N"),
    "cors_misconfiguration": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    "clickjacking": CVSSVector(AV="N", AC="H", PR="N", UI="R", S="U", C="N", I="L", A="N"),
    "http_method_enabled": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N"),
    "host_header_injection": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="L", A="N"),
    "crlf_injection": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N"),
    "open_redirect": CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="N", I="L", A="N"),
    "directory_listing": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    "information_disclosure": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    "security_misconfiguration": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    "waf_bypass": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N"),
    "missing_security_header": CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N"),
}


def score_finding_type(finding_type: str) -> Optional[Dict[str, Any]]:
    """CVSS vector/score/severity for a known finding_type, or None."""
    vector = FINDING_TYPE_CVSS_DEFAULTS.get(finding_type)
    if vector is None:
        return None
    score = base_score(vector)
    return {"cvss_vector": vector.as_string(), "cvss_score": score,
            "cvss_severity": severity_from_score(score)}


def effective_severity(finding: Dict[str, Any]) -> str:
    """The best available severity label for a finding: the CVSS-derived
    severity when it was actually classified and scored (cvss_source ==
    'finding_type_default'), otherwise whatever severity label the source
    tool provided. Sorting/display should use this instead of the raw
    `severity` field once a finding has been through enrich_finding() --
    a tool that reports "UNKNOWN" for something we can classify as, say,
    SQL injection should not have that finding sort to the bottom of a
    report or display an uninformative badge just because the tool itself
    didn't score it."""
    if finding.get("cvss_source") == "finding_type_default":
        return finding.get("cvss_severity", "UNKNOWN")
    return str(finding.get("severity", "UNKNOWN")).upper()


def enrich_finding(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of `vuln` with finding_type/cvss_* fields added.

    Idempotent and non-destructive: if the finding already carries a
    finding_type or cvss_vector (e.g. a tool wrapper set one explicitly
    with more specific knowledge than a keyword match could have), that is
    left untouched rather than overwritten.
    """
    if vuln.get("finding_type") or vuln.get("cvss_vector"):
        return dict(vuln)

    v = dict(vuln)
    finding_type = classify_finding_type(v)
    v["finding_type"] = finding_type or "unclassified"

    scored = score_finding_type(finding_type) if finding_type else None
    if scored:
        v.update(scored)
        v["cvss_source"] = "finding_type_default"
        # Severity ceiling: never let the type-default heuristic promote a
        # finding whose *source tool* already scored it as INFO or LOW up to
        # HIGH/CRITICAL. The archetypal vector describes the class of bug in
        # general; the source tool's own low assessment is a legitimate
        # signal that should keep it out of the reportable top tier. (Fixes
        # plain-INFO api/auth probes being shown as fake CVSS 10.0 CRITICALs.)
        label = str(v.get("severity", "UNKNOWN")).upper()
        if label in ("INFO", "LOW"):
            _cap_low = {
                "INFO": _SEVERITY_LABEL_MIDPOINT.get("LOW", 2.5),
                "LOW": _SEVERITY_LABEL_MIDPOINT.get("LOW", 2.5),
            }
            v["cvss_score"] = _cap_low[label]
            v["cvss_severity"] = "LOW"
    else:
        label = str(v.get("severity", "UNKNOWN")).upper()
        v["cvss_vector"] = None
        v["cvss_score"] = _SEVERITY_LABEL_MIDPOINT.get(label)
        v["cvss_severity"] = label
        v["cvss_source"] = "tool_severity_label"  # no finding-type match -- not a scored CVSS assessment
    return v


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [enrich_finding(f) for f in findings]
