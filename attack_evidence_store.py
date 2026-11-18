"""
Tracks accumulated attack findings for a target across Phase 2 iterations.
Persists to results/attack_evidence/ so a session can be paused and resumed.

Mirrors evidence_store.py exactly — same load/save/merge pattern.
New fields added: vulnerabilities, exploit_candidates, attack_actions_completed.
"""

import json
from pathlib import Path
from typing import Any, Dict

from tools.base import ToolResult
from cvss import effective_severity, enrich_finding

STORE_DIR = Path(__file__).parent / "results" / "attack_evidence"
ATTACK_LOG_PATH = Path(__file__).parent / "results" / "attack_decision_log.jsonl"


def _path_for(target: str) -> Path:
    safe_name = target.replace("/", "_").replace(":", "_")
    return STORE_DIR / f"{safe_name}.json"


def load(target: str, recon_evidence: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Load existing attack evidence for a target, or seed from Phase 1 recon
    evidence if no attack session has started yet.
    """
    path = _path_for(target)
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))

    # Fresh attack session — seed with Phase 1 recon output
    base = {
        "target": target,
        "authorized_scope": True,
        # --- inherited from Phase 1 recon ---
        "technologies": [],
        "open_ports": [],
        "services": [],
        "header_findings": [],
        "tls_findings": [],
        "missing_security_headers": [],
        "cms_detected": None,
        "cms_version": None,
        "discovered_paths": [],
        "discovered_endpoints": [],
        "response_headers": {},
        # --- Phase 2 attack fields ---
        "vulnerabilities": [],          # list of confirmed/suspected vuln dicts
        "exploit_candidates": [],       # searchsploit / CVE matches
        "nikto_findings": [],
        "nuclei_findings": [],
        "nmap_vuln_findings": [],
        "testssl_findings": [],
        "attack_actions_completed": [],
        "attack_actions_failed": [],
        "attack_zero_findings": [],
        "attack_observations": [],
        "risk_rating": "UNKNOWN",  
             # overall: CRITICAL/HIGH/MEDIUM/LOW/INFO
    }

    # Merge in Phase 1 evidence if provided
    if recon_evidence:
        for field in (
            "technologies", "open_ports", "services", "header_findings",
            "tls_findings", "missing_security_headers", "cms_detected",
            "cms_version", "discovered_paths", "discovered_endpoints",
            "response_headers",
        ):
            if recon_evidence.get(field):
                base[field] = recon_evidence[field]

    return base


def save(evidence: Dict[str, Any]) -> None:
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    _path_for(evidence["target"]).write_text(
        json.dumps(evidence, indent=2), encoding="utf-8"
    )


def merge_tool_result(evidence: Dict[str, Any], result: ToolResult) -> Dict[str, Any]:
    """Fold a Phase 2 tool's findings into the running attack evidence dict."""
    r = result.results or {}

    # --- Nuclei ---
    if "nuclei_findings" in r:
        existing_ids = {f.get("template_id") for f in evidence.get("nuclei_findings", [])}
        for finding in r["nuclei_findings"]:
            if finding.get("template_id") not in existing_ids:
                evidence.setdefault("nuclei_findings", []).append(finding)
                existing_ids.add(finding.get("template_id"))
        # Promote to top-level vulnerabilities list
        for finding in r["nuclei_findings"]:
            vuln = {
                "source": "nuclei",
                "name": finding.get("name", ""),
                "severity": finding.get("severity", "UNKNOWN").upper(),
                "template_id": finding.get("template_id", ""),
                "url": finding.get("url", ""),
                "description": finding.get("description", ""),
            }
            if vuln not in evidence.get("vulnerabilities", []):
                evidence.setdefault("vulnerabilities", []).append(vuln)

    # --- Nikto ---
    if "nikto_findings" in r:
        existing = {f.get("id") for f in evidence.get("nikto_findings", [])}
        for finding in r["nikto_findings"]:
            if finding.get("id") not in existing:
                evidence.setdefault("nikto_findings", []).append(finding)
                existing.add(finding.get("id"))
        for finding in r["nikto_findings"]:
            vuln = {
                "source": "nikto",
                "name": finding.get("msg", ""),
                "severity": "MEDIUM",   # Nikto doesn't score — default to MEDIUM
                "url": finding.get("url", ""),
                "osvdb": finding.get("osvdbid", ""),
            }
            if vuln not in evidence.get("vulnerabilities", []):
                evidence.setdefault("vulnerabilities", []).append(vuln)

    # --- Nmap NSE ---
    if "nmap_vuln_findings" in r:
        for finding in r["nmap_vuln_findings"]:
            if finding not in evidence.get("nmap_vuln_findings", []):
                evidence.setdefault("nmap_vuln_findings", []).append(finding)
        for finding in r["nmap_vuln_findings"]:
            vuln = {
                "source": "nmap_nse",
                "name": finding.get("script", ""),
                "severity": finding.get("severity", "UNKNOWN").upper(),
                "port": finding.get("port", ""),
                "output": finding.get("output", "")[:200],
            }
            if vuln not in evidence.get("vulnerabilities", []):
                evidence.setdefault("vulnerabilities", []).append(vuln)

    # --- Searchsploit ---
    if "exploit_candidates" in r:
        existing_edb = {e.get("edb_id") for e in evidence.get("exploit_candidates", [])}
        for exploit in r["exploit_candidates"]:
            if exploit.get("edb_id") not in existing_edb:
                evidence.setdefault("exploit_candidates", []).append(exploit)
                existing_edb.add(exploit.get("edb_id"))

    # --- testssl.sh TLS vulnerabilities ---
    if "vulnerabilities" in r and isinstance(r["vulnerabilities"], dict):
        existing_vuln_ids = {v.get("id") for v in evidence.get("testssl_findings", [])}
        for vid, vdata in r["vulnerabilities"].items():
            if isinstance(vdata, dict) and vid not in existing_vuln_ids:
                entry = {
                    "id": vid,
                    "severity": vdata.get("severity", "OK"),
                    "finding": vdata.get("finding", ""),
                    "cve": vdata.get("cve", ""),
                    "cwe": vdata.get("cwe", ""),
                    "source": "testssl",
                }
                evidence.setdefault("testssl_findings", []).append(entry)
                existing_vuln_ids.add(vid)
                # Promote non-OK findings to top-level vulnerabilities list
                if vdata.get("severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    vuln = {
                        "source": "testssl",
                        "name": vid,
                        "severity": vdata["severity"],
                        "cve_id": vdata.get("cve", ""),
                        "description": vdata.get("finding", ""),
                    }
                    if vuln not in evidence.get("vulnerabilities", []):
                        evidence.setdefault("vulnerabilities", []).append(vuln)
    # Also handle weak_ciphers from testssl
    if "weak_ciphers" in r and isinstance(r["weak_ciphers"], list):
        for wc in r["weak_ciphers"]:
            if isinstance(wc, dict):
                entry = {
                    "id": f"weak_cipher:{wc.get('cipher', '?')}",
                    "severity": wc.get("severity", "MEDIUM"),
                    "finding": f"Weak cipher supported: {wc.get('cipher', '?')}",
                    "cve": wc.get("cve", ""),
                    "source": "testssl",
                }
                existing_ids = {v.get("id") for v in evidence.get("testssl_findings", [])}
                if entry["id"] not in existing_ids:
                    evidence.setdefault("testssl_findings", []).append(entry)
                    if wc.get("severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                        vuln = {
                            "source": "testssl",
                            "name": f"Weak cipher: {wc.get('cipher', '?')}",
                            "severity": wc["severity"],
                            "cve_id": wc.get("cve", ""),
                        }
                        if vuln not in evidence.get("vulnerabilities", []):
                            evidence.setdefault("vulnerabilities", []).append(vuln)

    # --- Enrich vulnerabilities with finding_type + CVSS (see cvss.py) ---
    # Idempotent: enrich_finding() is a no-op for an entry that already
    # carries a finding_type/cvss_vector, so re-running this every merge
    # call never reprocesses or overwrites an already-scored finding.
    evidence["vulnerabilities"] = [enrich_finding(v) for v in evidence.get("vulnerabilities", [])]

    # --- Risk rating: escalate but never de-escalate ---
    # Use effective_severity (CVSS-derived when type-classified) instead of
    # the raw source severity so config/hardening items that CVSS scores NONE
    # (e.g. missing security headers) no longer inflate the headline rating.
    SEVERITY_ORDER = ["UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    current_idx = SEVERITY_ORDER.index(evidence.get("risk_rating", "UNKNOWN"))
    for vuln in evidence.get("vulnerabilities", []):
        sev = effective_severity(vuln)
        if sev in SEVERITY_ORDER:
            new_idx = SEVERITY_ORDER.index(sev)
            if new_idx > current_idx:
                current_idx = new_idx
    evidence["risk_rating"] = SEVERITY_ORDER[current_idx]

    # --- Track actions ---
    if result.status == "success":
        cap = result.capability
        if cap not in evidence["attack_actions_completed"]:
            evidence["attack_actions_completed"].append(cap)
        evidence.setdefault("attack_observations", []).append(
            f"{result.tool} ({cap}) succeeded: {json.dumps(r)[:120]}"
        )
        # Zero findings tracking
        found_something = any([
            r.get("nuclei_findings"),
            r.get("nikto_findings"),
            r.get("nmap_vuln_findings"),
            r.get("exploit_candidates"),
            r.get("testssl_findings"),
        ])
        if not found_something:
            zero = evidence.setdefault("attack_zero_findings", [])
            if cap not in zero:
                zero.append(cap)
    else:
        cap = result.capability
        if cap not in evidence["attack_actions_failed"]:
            evidence["attack_actions_failed"].append(cap)
        evidence.setdefault("attack_observations", []).append(
            f"{result.tool} ({cap}) failed: {result.error}"
        )

    return evidence


def compress(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Trim evidence to fit small context windows before sending to the LLM.
    Mirrors compress_evidence() in run_recon_loop.py.
    """
    c: Dict[str, Any] = {"target": evidence.get("target", "")}

    if evidence.get("technologies"):
        c["technologies"] = evidence["technologies"][:15]
    if evidence.get("open_ports"):
        c["open_ports"] = evidence["open_ports"]
    if evidence.get("services"):
        c["services"] = evidence["services"][:8]
    if evidence.get("header_findings"):
        c["header_findings"] = evidence["header_findings"]
    if evidence.get("tls_findings"):
        c["tls_findings"] = evidence["tls_findings"]
    if evidence.get("missing_security_headers"):
        c["missing_security_headers"] = evidence["missing_security_headers"]
    if evidence.get("cms_detected"):
        c["cms_detected"] = evidence["cms_detected"]
        if evidence.get("cms_version"):
            c["cms_version"] = evidence["cms_version"]
    if evidence.get("discovered_paths"):
        c["discovered_paths"] = evidence["discovered_paths"][:20]
    if evidence.get("discovered_endpoints"):
        c["discovered_endpoints"] = evidence["discovered_endpoints"][:10]

    # Attack-specific fields
    c["vulnerabilities_found"] = len(evidence.get("vulnerabilities", []))
    c["risk_rating"] = evidence.get("risk_rating", "UNKNOWN")

    if evidence.get("vulnerabilities"):
        # Show latest 5 findings so model doesn't re-action completed ones
        c["recent_vulnerabilities"] = evidence["vulnerabilities"][-5:]

    if evidence.get("exploit_candidates"):
        c["exploit_candidates"] = evidence["exploit_candidates"][:5]

    if evidence.get("testssl_findings"):
        c["testssl_findings"] = evidence["testssl_findings"][:20]

    c["attack_actions_completed"] = evidence.get("attack_actions_completed", [])
    c["attack_actions_failed"]    = evidence.get("attack_actions_failed", [])
    c["attack_zero_findings"]     = evidence.get("attack_zero_findings", [])

    if evidence.get("attack_observations"):
        c["recent_observations"] = evidence["attack_observations"][-6:]


    return c


