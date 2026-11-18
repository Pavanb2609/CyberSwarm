"""
scan_router.py — pick the active-scan engine that is actually available.

Three tiers, in order of preference:

    1. Burp Suite Professional  — Burp's own REST scanner (burp_scan)
    2. Burp Suite Community     — has NO scanner engine; cannot active-scan
    3. OWASP ZAP                — the free active scanner (zap_scan)

The important, non-obvious fact this module encodes: **Burp Community cannot
active-scan at all.** The scanner is a paid feature; Community ships the proxy
and manual tools only, and its automation story (the archived burp-rest-api
extension) drives the *Professional* JAR's engine. So when the installed Burp
is Community, the honest move is not to fake a Burp scan — it is to fall
through to ZAP and say so.

The router returns a decision, not a scan. It answers "which engine, and why",
and the caller runs that engine's tool. Selection never launches anything and
never raises: an undecidable situation returns a decision whose ``tool`` is
None with a human-readable reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    from utils import get_logger
except ImportError:  # standalone import
    import logging

    def get_logger(name: str):  # type: ignore[misc]
        return logging.getLogger(name)

log = get_logger("scan_router")

BURP_PRO = "burp_pro"
BURP_COMMUNITY = "burp_community"
ZAP = "zap"
NONE = "none"


@dataclass
class ScanDecision:
    engine: str                 # burp_pro | zap | none
    tool: Optional[str]         # tool name to run, or None
    reason: str
    burp_edition: str = "unknown"

    @property
    def can_scan(self) -> bool:
        return self.tool is not None

    def describe(self) -> str:
        return f"active-scan engine: {self.engine} — {self.reason}"

    def to_dict(self) -> Dict[str, Any]:
        return {"engine": self.engine, "tool": self.tool,
                "reason": self.reason, "burp_edition": self.burp_edition,
                "can_scan": self.can_scan}


def _burp_service(config: Optional[Dict[str, Any]]):
    try:
        from burp_service import get_burp_service
        section = (config or {}).get("burp") if isinstance(config, dict) else None
        return get_burp_service(section)
    except Exception as exc:  # noqa: BLE001
        log.debug("Burp service unavailable: %s", exc)
        return None


def _zap_available(config: Optional[Dict[str, Any]]) -> bool:
    try:
        from tools.attack.zap_scan import ZAPScanTool
        section = (config or {}).get("zap") if isinstance(config, dict) else None
        return ZAPScanTool(section).is_available()
    except Exception as exc:  # noqa: BLE001
        log.debug("ZAP availability check failed: %s", exc)
        return False


def choose_engine(config: Optional[Dict[str, Any]] = None,
                  prefer: Optional[str] = None) -> ScanDecision:
    """Decide which active-scan engine to use.

    ``prefer`` forces a tier when set to "burp" or "zap" (from config
    ``scan.prefer``), for operators who want ZAP even with Burp present, or who
    want the run to fail rather than silently downgrade. Default is "auto".
    """
    if config is None:
        try:
            from utils import load_config
            config = load_config()
        except Exception:  # noqa: BLE001
            config = {}

    prefer = str(prefer or (config or {}).get("scan", {}).get("prefer", "auto")).lower()

    # Explicit ZAP preference short-circuits Burp entirely.
    if prefer == "zap":
        if _zap_available(config):
            return ScanDecision(ZAP, "zap_scan",
                                "ZAP selected by configuration (scan.prefer=zap)")
        return ScanDecision(NONE, None,
                            "scan.prefer=zap but ZAP is not available")

    # Burp tier.
    service = _burp_service(config)
    edition = "unknown"
    if service is not None:
        try:
            edition = service.edition()
        except Exception:  # noqa: BLE001
            edition = "unknown"

        if edition == "pro":
            # Reachable Pro REST API -> use it. Installed but not yet running is
            # still Pro; burp_scan launches it. Either way Pro can scan.
            reachable = False
            try:
                reachable = service.healthcheck()
            except Exception:  # noqa: BLE001
                reachable = False
            reason = ("Burp Professional REST API reachable"
                      if reachable else
                      "Burp Professional installed; burp_scan will launch it")
            return ScanDecision(BURP_PRO, "burp_scan", reason, burp_edition="pro")

        if edition == "community":
            # The crux: Community has no scanner. Do not pretend otherwise.
            if _zap_available(config):
                return ScanDecision(
                    ZAP, "zap_scan",
                    "Burp Community has no scanner engine (Professional only); "
                    "falling back to ZAP", burp_edition="community")
            return ScanDecision(
                NONE, None,
                "Burp Community cannot active-scan and ZAP is not available; "
                "install ZAP or use Burp Professional", burp_edition="community")

    # No usable Burp at all -> ZAP.
    if prefer == "burp":
        return ScanDecision(NONE, None,
                            "scan.prefer=burp but no usable Burp was found")
    if _zap_available(config):
        return ScanDecision(ZAP, "zap_scan",
                            "No Burp available; using ZAP", burp_edition=edition)

    return ScanDecision(
        NONE, None,
        "No active-scan engine available. Install OWASP ZAP for free scanning, "
        "or Burp Professional.", burp_edition=edition)


def scan_capability_tool(config: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Convenience: just the tool name the router would run, or None."""
    return choose_engine(config).tool
