"""
Validates a raw model response string against the Attack Planner schema.

Usage:
    from schema.attack_validator import validate_attack_decision
    ok, parsed_or_none, errors = validate_attack_decision(raw_text)
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from schema.attack_enums import (
    ATTACK_ACTIONS, ATTACK_REQUIRED_KEYS, SEVERITY_LEVELS, VULN_CLASSES,
)

_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _strip_code_fences(text: str) -> str:
    return _CODE_FENCE_RE.sub("", text).strip()


def _extract_json_blob(text: str) -> str:
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return text
    return text[start:end + 1]


def _coerce_partial_response(parsed: dict) -> dict:
    """Coerce simplified model responses into the full attack schema."""
    result = dict(parsed)

    # Map common abbreviations
    ACTION_ALIASES = {
        "STOP":          "STOP_ATTACK",
        "BLOCK":         "BLOCK_ATTACK",
        "VULN":          "VULN_SCAN",
        "NIKTO":         "WEB_VULN_SCAN",
        "NSE":           "SERVICE_VULN_SCAN",
        "SEARCHSPLOIT":  "EXPLOIT_SEARCH",
        "MANUAL":        "MANUAL_PROBE",
        "PROOF":         "REQUEST_PROOF",
        "PIVOT":         "PIVOT_FINDING",
        "NUCLEI":        "VULN_SCAN",
    }
    action = result.get("next_attack_action", "")
    if action in ACTION_ALIASES:
        result["next_attack_action"] = ACTION_ALIASES[action]

    result.setdefault("next_attack_action", "STOP_ATTACK")
    result.setdefault("target_profile", "UNKNOWN")
    result.setdefault("vulnerability_class", "UNKNOWN")
    result.setdefault("severity", "UNKNOWN")
    result.setdefault("confidence", 0.5)
    result.setdefault("reason", "No reason provided.")
    result.setdefault("evidence_used", [])
    result.setdefault("missing_evidence", [])
    result.setdefault("requires_human_approval", True)
    result.setdefault("exploit_candidates", [])
    result.setdefault("mitre_tactic", "")
    result.setdefault("mitre_technique", "")
    result.setdefault("nuclei_tags", [])

    for key in ("evidence_used", "missing_evidence", "exploit_candidates", "nuclei_tags"):
        if not isinstance(result.get(key), list):
            result[key] = []

    return result


def validate_attack_decision(
    raw_text: str,
) -> Tuple[bool, Optional[Dict[str, Any]], List[str]]:
    errors: List[str] = []

    cleaned = _strip_code_fences(raw_text)
    blob = _extract_json_blob(cleaned)

    try:
        parsed = json.loads(blob)
    except json.JSONDecodeError as e:
        return False, None, [f"Response is not valid JSON: {e}"]

    if not isinstance(parsed, dict):
        return False, None, ["Top-level JSON value must be an object."]

    parsed = _coerce_partial_response(parsed)

    missing_keys = ATTACK_REQUIRED_KEYS - set(parsed.keys())
    if missing_keys:
        errors.append(f"Missing required keys: {sorted(missing_keys)}")

    action = parsed.get("next_attack_action")
    if action not in ATTACK_ACTIONS:
        print(f"[attack_validator] WARNING: unknown next_attack_action {action!r} "
              "-- auto-registering for this session")
        ATTACK_ACTIONS.add(action)

    severity = parsed.get("severity")
    if severity not in SEVERITY_LEVELS:
        errors.append(f"Invalid severity {severity!r}. Must be one of {sorted(SEVERITY_LEVELS)}")

    vuln_class = parsed.get("vulnerability_class")
    if vuln_class not in VULN_CLASSES:
        print(f"[attack_validator] WARNING: unknown vulnerability_class {vuln_class!r} "
              "-- auto-registering for this session")
        VULN_CLASSES.add(vuln_class)

    conf = parsed.get("confidence")
    if not isinstance(conf, (int, float)) or not (0.0 <= float(conf) <= 1.0):
        errors.append(f"Invalid confidence (must be 0.00-1.00): {conf!r}")

    for key in ("evidence_used", "missing_evidence", "exploit_candidates", "nuclei_tags"):
        val = parsed.get(key)
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            errors.append(f"{key} must be a list of strings")

    reason = parsed.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        errors.append("reason must be a non-empty string")

    approval = parsed.get("requires_human_approval")
    if not isinstance(approval, bool):
        errors.append("requires_human_approval must be a boolean")

    return (len(errors) == 0), parsed, errors
