"""
Shared utilities for CyberSwarm — single source of truth for helpers
duplicated across agents, memory, report, and CLI modules.
"""

import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

ROOT = Path(__file__).parent
DEFAULT_CONFIG = ROOT / "config.yaml"

SEVERITY_ORDER = ["UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def get_logger(name: str) -> logging.Logger:
    """Get a configured logger for a CyberSwarm module.

    Usage:
        from utils import get_logger
        log = get_logger(__name__)
        log.info("Starting recon for %s", target)
        log.warning("Model backend unreachable, falling back to deterministic")
        log.error("Tool %s failed: %s", tool_name, error)
    """
    return logging.getLogger(f"cyberswarm.{name}")


def load_config() -> dict[str, Any]:
    """Load config.yaml once. Used by cli.py, run_agent_loop.py, etc."""
    if DEFAULT_CONFIG.exists():
        return yaml.safe_load(DEFAULT_CONFIG.read_text(encoding="utf-8")) or {}
    return {}


def find_primary_url(smap: dict[str, Any], target: str) -> str:
    """Extract the best primary URL from a SystemMap for a given target.

    Deduplicates the identical logic in web_attack_agent._primary_url(),
    exploitation_agent._primary_url(), specialists._find_urls(), and
    attack_specialists._find_urls().
    """
    if smap.get("full_url"):
        return smap["full_url"]
    for w in smap.get("web_surfaces", []):
        if w.get("url"):
            return w["url"]
    return f"https://{target}"


def norm_finding_name(s: str) -> str:
    """Normalize a finding name for deduplication (lowercase, alphanumeric only).

    Single source of truth replacing memory_agent._norm() and
    generate_attack_report._norm().
    """
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def host_of_url(url: str) -> str:
    """Extract the lowercase hostname from a URL.

    Single source of truth replacing memory_agent._host_of() and
    generate_attack_report._host_of().
    """
    try:
        return (urlparse(url or "").netloc or "").lower()
    except Exception:
        return ""


def finding_key(v: dict[str, Any]) -> tuple:
    """Normalized identity for a vulnerability dict: (name, host).

    Used to dedupe the same issue reported by different agents.
    Severity is deliberately NOT part of the identity — two agents
    reporting the same issue at different severities are still the
    same issue and should merge, keeping the higher severity.
    """
    return (norm_finding_name(v.get("name", "")),
            host_of_url(v.get("url", "")))


def severity_rank(severity: str) -> int:
    """Return numeric rank for a severity string (lower = more severe)."""
    sev = str(severity).upper()
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def validate_target(target: str) -> tuple[bool, str]:
    """Validate a target string is a plausible hostname, IP, or URL.

    Returns (is_valid, reason_if_invalid).
    Prevents injection of shell metacharacters or arbitrary strings into
    subprocess commands via tool wrappers.
    """
    import ipaddress

    if not target or not target.strip():
        return False, "target is empty"

    t = target.strip()

    # Extract hostname from URL
    if "://" in t:
        try:
            parsed = urlparse(t)
            hostname = parsed.hostname
            if not hostname:
                return False, f"could not extract hostname from URL: {t}"
            t = hostname
        except Exception:
            return False, f"invalid URL: {t}"

    # Check for shell metacharacters
    dangerous_chars = set(";&|`$(){}[]!#~'\"\\")
    if any(c in t for c in dangerous_chars):
        return False, f"target contains shell metacharacters: {t}"

    # Try as IP address
    try:
        ipaddress.ip_address(t)
        return True, ""
    except ValueError:
        pass

    # Validate as hostname (RFC 952 / 1123)
    # Must be: labels separated by dots, each label alphanumeric or hyphens,
    # not starting/ending with hyphen, total <= 253 chars.
    if len(t) > 253:
        return False, f"target too long ({len(t)} chars, max 253)"

    labels = t.split(".")
    if len(labels) < 1:
        return False, "target has no valid labels"

    for label in labels:
        if not label:
            return False, f"empty label in target: {t}"
        if label.startswith("-") or label.endswith("-"):
            return False, f"label '{label}' starts/ends with hyphen"
        if not all(c.isalnum() or c == "-" for c in label):
            return False, f"label '{label}' contains invalid characters"

    return True, ""
