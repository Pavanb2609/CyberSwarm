"""
Validates a raw model response string against the Recon Planner schema.

Usage:
    from schema.validator import validate_decision
    ok, parsed_or_none, errors = validate_decision(raw_text)

Behaviour (changed 2026-10-24):

* Unknown capability / profile names are NO LONGER auto-registered into the
  global enum sets. Auto-registration meant a single hallucinated name (e.g.
  "TLS_SCAN") became "valid" for the rest of the session, and the recon loop
  then stopped with "no tool registered". Names are now normalised (case,
  spaces, hyphens, known aliases, close spelling matches) and anything still
  unknown is a validation error, so the caller can retry or fall back to the
  deterministic planner (see planner_policy.py).
* A response with no next_capability is an error. It used to default silently
  to STOP_NO_RELEVANT_ACTION, which ended recon runs early for no reason.
* Common small-model slips are repaired instead of failing the whole response:
  confidence given as 85 instead of 0.85, booleans given as strings, a single
  string where a list was expected.
"""

import difflib
import json
import re
from typing import Any

from schema.enums import CAPABILITIES, REQUIRED_KEYS, TARGET_PROFILES

_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)

CAPABILITY_ALIASES = {
    "STOP": "STOP_NO_RELEVANT_ACTION",
    "BLOCK": "BLOCK_EXECUTION",
    "VERIFY": "VERIFY_SCOPE",
    "PIVOT": "PIVOT_TO_SUBDOMAIN",
    "RETURN": "RETURN_FROM_SUBDOMAIN",
    "PORT_SCAN": "PORT_DISCOVERY",
    "SERVICE_SCAN": "SERVICE_DETECTION",
    "WEB_SCAN": "WEB_PROBING",
    "TECH_DETECT": "WEB_TECHNOLOGY_DISCOVERY",
    "SUBDOMAIN": "SUBDOMAIN_DISCOVERY",
    "DNS_RES": "DNS_RESOLUTION",
    "DNS_ENUM": "DNS_ENUMERATION",
    "PASSIVE": "PASSIVE_ASSET_DISCOVERY",
    "OS_DETECT": "OPERATING_SYSTEM_IDENTIFICATION",
    "CMS_DETECT": "CMS_IDENTIFICATION",
    "CMS_SCAN": "CMS_ASSESSMENT",
    "SCREENSHOT": "SCREENSHOT_CAPTURE",
    "TLS": "TLS_ANALYSIS",
    "TLS_SCAN": "TLS_ANALYSIS",
    "SSL_ANALYSIS": "TLS_ANALYSIS",
    "HEADER": "HEADER_ANALYSIS",
    "HEADERS": "HEADER_ANALYSIS",
    "CRAWL": "WEB_CRAWLING",
    "FFUF": "CONTENT_DISCOVERY",
    "CONTENT": "CONTENT_DISCOVERY",
    "DIRECTORY_BRUTEFORCE": "CONTENT_DISCOVERY",
    "PARAM": "PARAMETER_DISCOVERY",
    "JS_ANALYSIS": "JAVASCRIPT_ANALYSIS",
    "HISTORICAL": "HISTORICAL_URL_DISCOVERY",
    "API_DISC": "API_ENDPOINT_DISCOVERY",
    "LDAP": "DIRECTORY_SERVICE_ENUMERATION",
    "SMB": "WINDOWS_SERVICE_ENUMERATION",
    "CLOUD": "CLOUD_ASSET_DISCOVERY",
    "CONTAINER": "CONTAINER_DISCOVERY",
    "IOT": "IOT_SERVICE_IDENTIFICATION",
    "HOST": "HOST_DISCOVERY",
}

PROFILE_ALIASES = {
    "WEB_APP": "WEB_APPLICATION",
    "WEBAPP": "WEB_APPLICATION",
    "SPA": "SINGLE_PAGE_APPLICATION",
    "API": "REST_API",
    "GRAPHQL": "GRAPHQL_API",
    "AD": "ACTIVE_DIRECTORY",
    "LINUX": "LINUX_HOST",
    "WINDOWS": "WINDOWS_HOST",
    "OUT_OF_SCOPE_TARGET": "OUT_OF_SCOPE",
}


def _registered_capabilities() -> set[str]:
    """Capabilities that have a tool wired, even if not in the seed enum list
    (e.g. GRAPHQL_INTROSPECTION, CERT_INFO)."""
    try:
        from tools.registry import CAPABILITY_TOOL_MAP
        return set(CAPABILITY_TOOL_MAP)
    except Exception:
        return set()


def allowed_capabilities() -> set[str]:
    return set(CAPABILITIES) | _registered_capabilities()


def _canon(name: Any) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", str(name or "").strip().upper()).strip("_")


def normalize_name(name: Any, allowed: set[str], aliases: dict[str, str]) -> str | None:
    """Map a model-supplied enum value onto the allowed set, or None."""
    c = _canon(name)
    if not c:
        return None
    if c in allowed:
        return c
    if c in aliases:
        return aliases[c]
    close = difflib.get_close_matches(c, sorted(allowed), n=1, cutoff=0.88)
    return close[0] if close else None


def decision_json_schema() -> dict[str, Any]:
    """JSON schema for constrained decoding (Ollama `format`, OpenAI
    `response_format`). DO_NOT_REPEAT_COMPLETED_ACTION is excluded: the prompt
    says it is never a valid next_capability."""
    caps = sorted(allowed_capabilities() - {"DO_NOT_REPEAT_COMPLETED_ACTION"})
    return {
        "type": "object",
        "properties": {
            "target_profile": {"type": "string", "enum": sorted(TARGET_PROFILES)},
            "next_capability": {"type": "string", "enum": caps},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "evidence_used": {"type": "array", "items": {"type": "string"}},
            "missing_evidence": {"type": "array", "items": {"type": "string"}},
            "reason": {"type": "string"},
            "requires_human_approval": {"type": "boolean"},
            "next_subdomain": {"type": ["string", "null"]},
        },
        "required": sorted(REQUIRED_KEYS),
    }


def _to_bool(v: Any) -> Any:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "yes", "1"):
        return True
    if isinstance(v, str) and v.strip().lower() in ("false", "no", "0"):
        return False
    return v


def _to_conf(v: Any) -> Any:
    if isinstance(v, str):
        s = v.strip().rstrip("%")
        try:
            v = float(s)
        except ValueError:
            return v
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        if 1.0 < float(v) <= 100.0:
            return round(float(v) / 100.0, 3)
        return float(v)
    return v


def _to_str_list(v: Any) -> Any:
    if v is None:
        return []
    if isinstance(v, str):
        return [v] if v.strip() else []
    if isinstance(v, list):
        return [x if isinstance(x, str) else json.dumps(x) for x in v]
    return v


def _coerce_partial_response(parsed: dict) -> dict:
    """Repair common shape slips. Never invents a next_capability."""
    result = dict(parsed)
    if "next_capability" not in result and "action" in result:
        result["next_capability"] = result.pop("action")
    result.pop("action", None)

    result.setdefault("target_profile", "UNKNOWN")
    result.setdefault("confidence", 0.5)
    result.setdefault("reason", "No reason provided.")
    result["evidence_used"] = _to_str_list(result.get("evidence_used"))
    result["missing_evidence"] = _to_str_list(result.get("missing_evidence"))
    result["requires_human_approval"] = _to_bool(result.get("requires_human_approval", False))
    result["confidence"] = _to_conf(result.get("confidence"))
    if result.get("next_subdomain") in ("", "null", "None"):
        result["next_subdomain"] = None
    return result


def _strip_code_fences(text: str) -> str:
    """Defensively strip markdown fences and <think> blocks even though the
    prompt forbids them -- local models don't always obey."""
    text = _THINK_RE.sub("", text or "")
    return _CODE_FENCE_RE.sub("", text).strip()


def _extract_json_blob(text: str) -> str:
    """If the model added stray text before/after the JSON object, pull out
    the outermost {...} block."""
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return text
    return text[start:end + 1]


def validate_decision(raw_text: str) -> tuple[bool, dict[str, Any] | None, list[str]]:
    errors: list[str] = []

    cleaned = _strip_code_fences(raw_text if isinstance(raw_text, str) else "")
    blob = _extract_json_blob(cleaned)

    try:
        parsed = json.loads(blob)
    except json.JSONDecodeError as e:
        return False, None, [f"Response is not valid JSON: {e}"]

    if not isinstance(parsed, dict):
        return False, None, ["Top-level JSON value must be an object."]

    parsed = _coerce_partial_response(parsed)

    if "next_capability" not in parsed:
        errors.append("Missing required key: next_capability")

    missing_keys = REQUIRED_KEYS - set(parsed.keys())
    if missing_keys:
        errors.append(f"Missing required keys: {sorted(missing_keys)}")

    raw_tp = parsed.get("target_profile")
    tp = normalize_name(raw_tp, set(TARGET_PROFILES), PROFILE_ALIASES)
    if tp is None:
        errors.append(f"Unknown target_profile {raw_tp!r}")
    else:
        parsed["target_profile"] = tp

    if "next_capability" in parsed:
        raw_cap = parsed.get("next_capability")
        cap = normalize_name(raw_cap, allowed_capabilities(), CAPABILITY_ALIASES)
        if cap is None:
            errors.append(f"Unknown next_capability {raw_cap!r}")
        else:
            parsed["next_capability"] = cap
    cap = parsed.get("next_capability")

    conf = parsed.get("confidence")
    if not isinstance(conf, (int, float)) or isinstance(conf, bool) or not (0.0 <= float(conf) <= 1.0):
        errors.append(f"Invalid confidence (must be 0.00-1.00): {conf!r}")

    ev_used = parsed.get("evidence_used")
    if not isinstance(ev_used, list) or not all(isinstance(x, str) for x in ev_used):
        errors.append("evidence_used must be a list of strings")

    missing_ev = parsed.get("missing_evidence")
    if not isinstance(missing_ev, list) or not all(isinstance(x, str) for x in missing_ev):
        errors.append("missing_evidence must be a list of strings")

    reason = parsed.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        errors.append("reason must be a non-empty string")

    approval = parsed.get("requires_human_approval")
    if not isinstance(approval, bool):
        errors.append("requires_human_approval must be a boolean")

    # Optional: next_subdomain (required when capability is PIVOT_TO_SUBDOMAIN)
    ns = parsed.get("next_subdomain")
    if cap == "PIVOT_TO_SUBDOMAIN":
        if not isinstance(ns, str) or not ns.strip():
            errors.append("next_subdomain is required when next_capability is PIVOT_TO_SUBDOMAIN")
    elif ns is not None and not isinstance(ns, str):
        errors.append("next_subdomain must be a string if provided")

    return (len(errors) == 0), parsed, errors
