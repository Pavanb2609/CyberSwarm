"""
Canonical enums for the Attack Planner (Phase 2).
Keep this in sync with prompts/attack_planner.txt if you ever edit the prompt.

The model can return new profiles/actions not in these seed sets.
Validator treats them as warnings, not errors, and registers them for the
rest of the session so the system self-expands.
"""

ATTACK_ACTIONS = {
    # Active scanning
    "VULN_SCAN",            # Nuclei — template-based vuln detection
    "WEB_VULN_SCAN",        # Nikto  — web server misconfig scan
    "SERVICE_VULN_SCAN",    # Nmap NSE vuln scripts — port-specific checks
    "EXPLOIT_SEARCH",       # Searchsploit — match tech+version to known exploits
    "TLS_VULN_SCAN",        # testssl.sh — comprehensive SSL/TLS vulnerability detection

    # Manual / escalation
    "MANUAL_PROBE",         # No automated tool; flags step for human
    "REQUEST_PROOF",        # PoC required before escalating severity

    # Flow control
    "PIVOT_FINDING",        # Move to next finding/subdomain with open attack surface
    "STOP_ATTACK",          # No exploitable finding — clean stop
    "BLOCK_ATTACK",         # Out of scope / dangerous — hard stop
}

SEVERITY_LEVELS = {
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN",
}

VULN_CLASSES = {
    "MISSING_SECURITY_HEADERS",
    "TLS_WEAKNESS",
    "OPEN_REDIRECT",
    "XSS",
    "SQLI",
    "IDOR",
    "BROKEN_ACCESS_CONTROL",
    "SENSITIVE_DATA_EXPOSURE",
    "OUTDATED_SOFTWARE",
    "MISCONFIGURATION",
    "INFORMATION_DISCLOSURE",
    "INJECTION",
    "SSRF",
    "RCE",
    "PATH_TRAVERSAL",
    "CSRF",
    "AUTH_BYPASS",
    "UNKNOWN",
}

ATTACK_REQUIRED_KEYS = {
    "target_profile",
    "next_attack_action",
    "vulnerability_class",
    "severity",
    "confidence",
    "evidence_used",
    "missing_evidence",
    "reason",
    "requires_human_approval",
}
