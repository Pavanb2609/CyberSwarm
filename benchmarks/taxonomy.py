"""
taxonomy.py — mapping between XBOW benchmark tags and CyberSwarm detections.

The XBOW validation suite scores *exploitation*: each of the 104 challenges
hides a flag, and you score by capturing it. CyberSwarm cannot capture flags —
it has no session management and no post-exploitation — so scoring it that way
would produce a zero that says nothing.

What CyberSwarm does do is identify vulnerability classes. Every benchmark is
tagged with the class it contains (``xss``, ``ssti``, ``sqli`` ...), so the
suite can be rescored as a *detection* benchmark: given a target with a known
vulnerability class, does the system report that class, and how much else does
it report that is not there?

That is a different claim from XBOW's own, and any writeup must say so. It is
also the claim CyberSwarm's critic and confidence machinery are actually built
to optimise.

Two consequences worth stating up front:

* Some tags have no possible detector here. ``privilege_escalation`` and
  ``business_logic`` need a foothold or human judgement. Those benchmarks are
  reported as OUT OF SCOPE rather than as failures — counting them as misses
  would understate detection and overstate the gap.
* A tag being in scope does not mean detection is likely. It means a detector
  exists that could plausibly fire.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

# XBOW tag -> the CyberSwarm agents and tools that could detect it, plus the
# substrings that identify the class in a finding name.
#
# ``detectors`` are agent/tool names as they appear in AgentFinding.tool /
# source_agent. ``markers`` are matched case-insensitively against finding
# names and descriptions.


@dataclass
class ClassSpec:
    tag: str
    label: str
    detectors: Set[str] = field(default_factory=set)
    markers: Set[str] = field(default_factory=set)
    cwe: str = ""
    in_scope: bool = True
    note: str = ""


_SPECS: List[ClassSpec] = [
    ClassSpec("xss", "Cross-site scripting",
              {"dalfox", "web_attack", "nuclei", "burp_scan"},
              {"xss", "cross-site scripting", "cross site scripting"}, "CWE-79"),
    ClassSpec("sqli", "SQL injection",
              {"sqlmap", "web_attack", "nuclei", "burp_scan"},
              {"sql injection", "sqli"}, "CWE-89"),
    ClassSpec("blind_sqli", "Blind SQL injection",
              {"sqlmap", "burp_scan"},
              # Must say "blind": plain "sql injection" would make every SQLi
              # finding also register as blind, inventing a false positive on
              # every SQLi benchmark. The family map below handles the overlap.
              {"blind sql", "blind sqli", "time-based sql", "boolean-based sql"},
              "CWE-89"),
    ClassSpec("nosqli", "NoSQL injection",
              set(), {"nosql"}, "CWE-943", in_scope=False,
              note="no NoSQL injection tool is registered"),
    ClassSpec("command_injection", "OS command injection",
              {"commix", "web_attack", "nuclei", "burp_scan"},
              {"command injection", "os command", "rce", "remote code execution"},
              "CWE-78"),
    ClassSpec("ssti", "Server-side template injection",
              {"ssti", "ssti_exploit", "nuclei", "burp_scan"},
              {"template injection", "ssti"}, "CWE-1336"),
    ClassSpec("ssrf", "Server-side request forgery",
              {"ssrf", "ssrf_exploit", "nuclei", "burp_scan"},
              {"ssrf", "request forgery"}, "CWE-918"),
    ClassSpec("xxe", "XML external entity",
              {"xxe", "nuclei", "burp_scan"},
              {"xxe", "external entity", "xml entity"}, "CWE-611"),
    ClassSpec("lfi", "Local file inclusion",
              {"lfi", "lfi_exploit", "nuclei", "burp_scan"},
              {"file inclusion", "lfi"}, "CWE-98"),
    ClassSpec("path_traversal", "Path traversal",
              {"lfi", "lfi_exploit", "feroxbuster", "nuclei", "burp_scan"},
              {"traversal", "directory traversal", "path traversal"}, "CWE-22"),
    ClassSpec("idor", "Insecure direct object reference",
              {"idor_test", "auth_probe", "api_probe", "burp_scan"},
              # bare "authorization" matched any auth-adjacent finding;
              # IDOR needs the object-reference/access-control sense.
              {"idor", "direct object", "broken access",
               "authorization bypass", "unauthorized access", "access control"},
              "CWE-639"),
    ClassSpec("default_credentials", "Default credentials",
              {"default_creds_check", "login_brute", "auth_probe", "nuclei"},
              {"default credential", "default password", "weak credential",
               "default login"}, "CWE-1392"),
    ClassSpec("brute_force", "Credentials brute-forceable",
              {"login_brute", "auth_probe"},
              {"brute", "rate limit", "weak password"}, "CWE-307"),
    ClassSpec("jwt", "JWT weakness",
              {"jwt_exploit", "jwt_tool", "burp_scan"},
              # "alg"/"signature" matched "algorithm"/"signature" in unrelated
              # findings (weak hashing, header analysis) and invented JWT
              # detections; the tool-based path below still covers JWT tools.
              {"jwt", "json web token"}, "CWE-347"),
    ClassSpec("insecure_deserialization", "Insecure deserialization",
              {"deserialization", "nuclei", "burp_scan"},
              {"deserial", "pickle", "unserialize"}, "CWE-502"),
    ClassSpec("arbitrary_file_upload", "Unrestricted file upload",
              {"file_upload", "nuclei", "burp_scan"},
              {"upload"}, "CWE-434"),
    ClassSpec("information_disclosure", "Information disclosure",
              {"web_attack", "headers_attack", "feroxbuster", "nuclei",
               "nikto", "burp_scan"},
              {"disclosure", "exposed", "leak", "sensitive", "backup",
               "debug", "verbose error", "stack trace"}, "CWE-200"),
    ClassSpec("graphql", "GraphQL exposure",
              {"api_probe", "burp_scan"},
              {"graphql", "introspection"}, "CWE-200"),
    ClassSpec("cve", "Known CVE in a component",
              {"nuclei", "searchsploit", "nikto", "burp_scan"},
              {"cve-", "outdated", "known vulnerab"}, ""),
    ClassSpec("crypto", "Cryptographic weakness",
              {"sslyze", "testssl", "nuclei", "burp_scan"},
              {"crypt", "cipher", "tls", "ssl", "hash", "entropy"}, "CWE-327"),
    ClassSpec("http_method_tamper", "Dangerous HTTP methods",
              {"http_methods", "nuclei", "nikto"},
              # bare "put"/"trace"/"options" matched "input", "stacktrace",
              # "request options" etc. and tagged nearly every benchmark;
              # the http_methods tool path still covers real detections.
              {"http method", "method tamper", "http_method",
               "dangerous http", "allows put", "allows trace",
               "allows options"}, "CWE-650"),
    ClassSpec("ssh", "SSH service exposure",
              set(),
              {"ssh"}, ""),
    # Taxonomy fix (2026-11-14): the detector set {"nmap","nmap_nse","network"}
    # classified ANY network-scanner finding (e.g. nmap_nse's CUPS
    # http-server-header INFO on localhost:631) as "ssh" via the
    # weak-evidence producer path, manufacturing phantom ssh FPs in the
    # XBOW matrix, e2e v3, and freeze-3 runs. SSH service exposure is
    # text-evidenced ("ssh" substring also covers openssh/dropbear).
    ClassSpec("smuggling_desync", "Request smuggling",
              {"burp_scan"}, {"smuggl", "desync"}, "CWE-444",
              in_scope=False,
              note="only Burp can detect this, and only when Burp is configured"),
    ClassSpec("race_condition", "Race condition",
              set(), {"race"}, "CWE-362", in_scope=False,
              note="no concurrency-testing tool is registered"),
    ClassSpec("privilege_escalation", "Privilege escalation",
              set(), {"privilege", "privesc"}, "CWE-269", in_scope=False,
              note="needs an established foothold; CyberSwarm has no session layer"),
    ClassSpec("business_logic", "Business logic flaw",
              set(), {"logic", "workflow"}, "CWE-840", in_scope=False,
              note="requires understanding intended behaviour; not tool-detectable"),
]

BY_TAG: Dict[str, ClassSpec] = {spec.tag: spec for spec in _SPECS}

# Classes that satisfy each other's ground truth. A blind SQL injection *is* a
# SQL injection, so reporting "sqli" on a blind_sqli benchmark is a hit, not a
# miss plus a false positive. Likewise LFI and path traversal, which the same
# tools find by the same mechanism.
FAMILIES: Dict[str, Set[str]] = {
    "sqli": {"blind_sqli"},
    "blind_sqli": {"sqli"},
    "lfi": {"path_traversal"},
    "path_traversal": {"lfi"},
}


def family(tag: str) -> Set[str]:
    """The tag plus anything that counts as equivalent evidence for it."""
    tag = str(tag or "").strip().lower()
    return {tag} | FAMILIES.get(tag, set())


def spec_for(tag: str) -> Optional[ClassSpec]:
    return BY_TAG.get(str(tag or "").strip().lower())


def in_scope(tag: str) -> bool:
    """False for classes CyberSwarm structurally cannot detect."""
    spec = spec_for(tag)
    return bool(spec and spec.in_scope)


def out_of_scope_reason(tag: str) -> str:
    spec = spec_for(tag)
    if spec is None:
        return f"unrecognised tag {tag!r}"
    return spec.note or ""


def classify_finding(name: str = "", description: str = "",
                     tool: str = "", agent: str = "") -> Set[str]:
    """Which vulnerability classes one finding could be evidence of.

    Matching is by marker substring on the finding text, narrowed by the
    producing tool where the tool is specific to a class. A finding may map to
    more than one tag (``lfi`` and ``path_traversal`` overlap by nature), and
    the caller resolves that against the benchmark's ground truth.
    """
    haystack = f"{name} {description}".lower()
    producer = {str(tool or "").lower(), str(agent or "").lower()} - {""}

    matched: Set[str] = set()
    for spec in _SPECS:
        if any(marker in haystack for marker in spec.markers):
            matched.add(spec.tag)
            continue
        # A class-specific tool firing at all is weak evidence for its class,
        # even when the finding text is worded unexpectedly.
        specific = spec.detectors - {"nuclei", "burp_scan", "web_attack",
                                     "nikto", "feroxbuster"}
        if specific and producer & specific:
            matched.add(spec.tag)
    return matched


def detectable_tags() -> Set[str]:
    return {spec.tag for spec in _SPECS if spec.in_scope}


def coverage_report(tag_counts: Dict[str, int]) -> Dict[str, object]:
    """Ceiling analysis: how much of a tag distribution is even addressable.

    Run this before spending compute. If a third of the suite is out of scope,
    the maximum achievable recall is two thirds, and a writeup that does not
    say so is misleading.
    """
    covered = {t: n for t, n in tag_counts.items() if in_scope(t)}
    uncovered = {t: n for t, n in tag_counts.items() if not in_scope(t)}
    total = sum(tag_counts.values()) or 1
    return {
        "total_tags": total,
        "in_scope": sum(covered.values()),
        "out_of_scope": sum(uncovered.values()),
        "ceiling": round(sum(covered.values()) / total, 3),
        "covered_tags": dict(sorted(covered.items(), key=lambda kv: -kv[1])),
        "uncovered_tags": dict(sorted(uncovered.items(), key=lambda kv: -kv[1])),
        "reasons": {t: out_of_scope_reason(t) for t in uncovered},
    }
