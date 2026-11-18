"""
attack_chains.py — cross-finding attack chain detection.

The Critic validates findings one at a time. Nothing else in the pipeline
looks at whether two or more individually low/medium findings *combine*
into something worse -- a CORS misconfiguration means little on its own,
but paired with a CSRF gap on the same host it's a real cross-origin
account-takeover path. This module is the correlation pass that catches
that.

Design constraints, on purpose:

- Deterministic, rule-based, not LLM-based. Same reasoning as cvss.py:
  this feeds a report, so it has to be reproducible and debuggable, and
  the project's own testing philosophy already says "deterministic where
  possible, don't rely on an LLM's natural-language output for
  assertions."
- Every CHAIN_RULE here is a well-documented, textbook pattern (OWASP /
  PortSwigger Web Security Academy class material), not a novel or
  speculative claim -- see each rule's `narrative`.
- A chain is a *hypothesis for a human to verify*, never an auto-confirmed
  finding. Every ChainedFinding carries requires_manual_verification=True
  and is additive to the existing findings list; it never changes an
  existing finding's own severity or auto-escalates risk_rating. That
  stays the Critic/approval-gate's job, unchanged.
- Findings are grouped by host (utils.host_of_url) before a rule is
  checked, so a chain is only raised when its prerequisite findings were
  actually observed on the SAME target, not just anywhere in the report.

Run detect_chains() on an already-CVSS-enriched findings list (see
cvss.enrich_findings) -- it reads each finding's `finding_type`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from cvss import score_finding_type
from utils import host_of_url


@dataclass(frozen=True)
class ChainRule:
    id: str
    name: str
    requires: Tuple[str, ...]          # finding_types that must ALL be present on the same host
    narrative: str                     # human-readable explanation; {host} is substituted
    resulting_impact: Optional[str] = None  # finding_type key used to look up an assessed-impact CVSS vector


CHAIN_RULES: Tuple[ChainRule, ...] = (
    ChainRule(
        id="xss_session_hijack",
        name="XSS without cookie/header protection → session hijacking risk",
        requires=("cross_site_scripting_reflected", "missing_security_header"),
        narrative=("{host} has both a cross-site scripting finding and a missing security-header finding. "
                   "Without protective headers (CSP / HttpOnly-related), a working XSS payload can typically "
                   "read the session cookie directly, turning a reflected-XSS finding into full session "
                   "hijacking rather than a one-off script execution."),
        resulting_impact="session_fixation",  # closest archetype for "attacker obtains a live session"
    ),
    ChainRule(
        id="xss_session_hijack_stored",
        name="Stored XSS without cookie/header protection → session hijacking risk",
        requires=("cross_site_scripting_stored", "missing_security_header"),
        narrative=("{host} has a stored XSS finding and a missing security-header finding. Stored XSS fires "
                   "for every visitor without needing to lure them individually, so the missing header gap "
                   "raises this from script execution to reliable session hijacking at scale."),
        resulting_impact="cross_site_scripting_stored",
    ),
    ChainRule(
        id="clickjacking_csrf",
        name="Clickjacking + CSRF → UI-redress-driven forced state change",
        requires=("clickjacking", "csrf"),
        narrative=("{host} can be framed (no clickjacking protection) AND lacks CSRF protection on at least "
                   "one state-changing action. Framing plus a forgeable request is the classic UI-redressing "
                   "combination: a victim can be tricked into submitting the CSRF-vulnerable action without "
                   "realizing it, even without needing a same-site request trigger."),
        resulting_impact="csrf",
    ),
    ChainRule(
        id="directory_listing_disclosure",
        name="Directory listing + information disclosure → source/backup exposure",
        requires=("directory_listing", "information_disclosure"),
        narrative=("{host} exposes directory listings alongside a separate information-disclosure finding. "
                   "Together these commonly mean backup files, config files, or source artifacts are "
                   "browsable and retrievable, not just theoretically present."),
        resulting_impact="information_disclosure",
    ),
    ChainRule(
        id="takeover_cors_trust",
        name="Subdomain takeover + CORS trust → cross-origin credential theft",
        requires=("subdomain_takeover", "cors_misconfiguration"),
        narrative=("{host} has a claimable/dangling subdomain AND a CORS misconfiguration. If the CORS "
                   "allowlist trusts the takeover-able subdomain (or a wildcard that covers it), an attacker "
                   "who claims the subdomain can serve cross-origin requests the target already trusts."),
        resulting_impact="subdomain_takeover",
    ),
    ChainRule(
        id="jwt_idor_takeover",
        name="Weak JWT algorithm acceptance + IDOR → account takeover",
        requires=("jwt_weak_algorithm", "idor"),
        narrative=("{host} accepts a weak/forgeable JWT AND has an IDOR finding. A forged token for an "
                   "arbitrary user ID combined with an endpoint that doesn't re-check object ownership is a "
                   "direct path to impersonating any account, not just the two issues independently."),
        resulting_impact="jwt_weak_algorithm",
    ),
    ChainRule(
        id="creds_upload_webshell",
        name="Default credentials + unrestricted upload → full compromise",
        requires=("default_credentials", "unrestricted_file_upload"),
        narrative=("{host} has default/weak credentials on a panel AND an unrestricted file-upload finding. "
                   "Authenticated access plus an unrestricted upload is the textbook path to a web shell and "
                   "full host compromise, not two separate lower-severity issues."),
        resulting_impact="remote_code_execution",
    ),
    ChainRule(
        id="lfi_upload_rce",
        name="LFI + unrestricted upload → remote code execution via log/file poisoning",
        requires=("local_file_inclusion", "unrestricted_file_upload"),
        narrative=("{host} has a local file inclusion finding AND an unrestricted upload finding. Uploading "
                   "a file containing code and then including it via the LFI path (or poisoning a log the "
                   "LFI can reach) is a well-known route from 'read a file' to 'execute code'."),
        resulting_impact="remote_code_execution",
    ),
    ChainRule(
        id="tls_session_fixation",
        name="Weak TLS + session fixation → session token interception",
        requires=("weak_tls_configuration", "session_fixation"),
        narrative=("{host} has a weak TLS/cipher finding AND a session-fixation finding. A network position "
                   "able to exploit the TLS weakness can intercept or fixate the session token in transit, "
                   "compounding what session fixation alone would allow."),
        resulting_impact="session_fixation",
    ),
    ChainRule(
        id="host_header_open_redirect",
        name="Host header injection + open redirect → password-reset / phishing chain",
        requires=("host_header_injection", "open_redirect"),
        narrative=("{host} trusts the Host header for at least one flow AND has an open redirect. If any "
                   "password-reset or email-link flow incorporates the Host header, this combination can "
                   "redirect password-reset tokens to an attacker-controlled domain."),
        resulting_impact="host_header_injection",
    ),
)


@dataclass
class ChainedFinding:
    rule_id: str
    name: str
    host: str
    narrative: str
    contributing_finding_types: Tuple[str, ...]
    contributing_findings: List[Dict[str, Any]] = field(default_factory=list)
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_severity: str = "UNKNOWN"
    requires_manual_verification: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_type": "attack_chain",
            "chain_rule_id": self.rule_id,
            "name": self.name,
            "host": self.host,
            "url": self.host,  # so existing url-keyed helpers (finding_key, host_of_url) still work on chains
            "description": self.narrative,
            "severity": self.cvss_severity,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "cvss_severity": self.cvss_severity,
            "cvss_source": "chain_assessed_impact" if self.cvss_vector else "unscored",
            "contributing_finding_types": list(self.contributing_finding_types),
            "contributing_findings": [
                {"name": f.get("name", ""), "finding_type": f.get("finding_type", ""),
                 "source": f.get("source", ""), "url": f.get("url", "")}
                for f in self.contributing_findings
            ],
            "requires_manual_verification": self.requires_manual_verification,
            "source": "attack_chains",
        }


def _group_by_host(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        host = host_of_url(f.get("url", "")) or "(unspecified host)"
        groups.setdefault(host, []).append(f)
    return groups


def detect_chains(findings: List[Dict[str, Any]],
                  rules: Tuple[ChainRule, ...] = CHAIN_RULES) -> List[ChainedFinding]:
    """Findings must already be CVSS-enriched (each carries `finding_type`;
    see cvss.enrich_findings). Returns one ChainedFinding per (rule, host)
    match -- never mutates the input findings list."""
    chains: List[ChainedFinding] = []
    for host, group in _group_by_host(findings).items():
        present_types = {f.get("finding_type") for f in group if f.get("finding_type")}
        for rule in rules:
            if not set(rule.requires).issubset(present_types):
                continue
            contributing = [f for f in group if f.get("finding_type") in rule.requires]
            scored = score_finding_type(rule.resulting_impact) if rule.resulting_impact else None
            chains.append(ChainedFinding(
                rule_id=rule.id,
                name=rule.name,
                host=host,
                narrative=rule.narrative.format(host=host),
                contributing_finding_types=rule.requires,
                contributing_findings=contributing,
                cvss_vector=scored["cvss_vector"] if scored else None,
                cvss_score=scored["cvss_score"] if scored else None,
                cvss_severity=scored["cvss_severity"] if scored else "UNKNOWN",
            ))
    return chains


def detect_chains_as_dicts(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [c.to_dict() for c in detect_chains(findings)]
