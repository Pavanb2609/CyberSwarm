"""
Centralized confidence scoring for CyberSwarm.

Reconciles the two scales used across the codebase (agents/tools use 0-100
integers, the new state layer uses 0-1 floats) and provides deterministic,
non-LLM math for turning raw tool output into a defensible confidence value:

  - base confidence per tool (how much to trust its raw output)
  - reliability adjustment from observed ToolManager history
  - corroboration adjustment (independent sources -> higher confidence)
  - recency decay for stale evidence
  - noiseless-OR combination of independent measurements
  - the same 40/60 agent/critic blend the CriticAgent already applies, and
    the 0.5 (== 50/100) CONFIRM floor, centralized here so every consumer
    agrees on the thresholds.

All public helpers return a unit confidence in [0.0, 1.0] unless a *
_100* sibling is used.
"""

from typing import Any, Callable, Dict, Iterable, List, Optional

CEILING = 0.99
CONFIRM_FLOOR = 0.50

DEFAULT_LLM_FALLBACK = 0.35

_HIGH = 0.75
_MEDIUM = 0.60
_LOW = 0.50
_DEFAULT = 0.60

# tool -> group -> base confidence. Unknown tools fall back to _DEFAULT.
_HIGH_BASE_NAMES = {
    "dns_resolve", "dns_enum", "cert_info", "subfinder", "amass",
    "nmap", "naabu", "httpx", "testssl", "tls_analysis", "sqlmap",
    "gowitness", "smb_enum", "ldap_enum", "graphql_introspection",
    "robots_txt",
}
_MEDIUM_BASE_NAMES = {
    "whatweb", "katana", "ffuf", "arjun", "linkfinder", "gau",
    "waybackurls", "api_discover", "cms_identify", "wpscan", "nuclei",
    "nikto", "nmap_nse", "sslyze", "feroxbuster", "dalfox", "s3_enum",
    "cloud_enum", "searchsploit", "corsy", "wafw00f", "http_methods",
    "nuclei_ssrf", "nuclei_lfi", "nuclei_ssti", "nuclei_redirect",
    "nuclei_cmdi", "nuclei_xss", "nuclei_sqli", "nuclei_panels",
    "nuclei_defaultlogin", "nuclei_misconfig", "nuclei_takeover",
    "nuclei_hostheader", "nuclei_clickjack", "nuclei_exposure",
    "nuclei_wafdetect", "nuclei_xxe", "nuclei_crlf",
    "nuclei_deserialization",
}
_LOW_BASE_NAMES = {
    "subjack", "host_header", "clickjack", "file_upload", "csrf", "crlf",
    "xxe", "header_analysis", "session_analyzer", "cookie_analyzer",
    "sensitive_endpoint_detect", "container_probe", "iot_probe", "commix",
    "waf_bypass_payloads", "session_fixation", "session_hijack",
    "auth_probe", "api_probe", "deserialization", "ssti_exploit",
    "lfi_exploit", "ssrf_exploit", "jwt_exploit", "jwt_tool",
}


def clamp_unit(value: float) -> float:
    return max(0.0, min(CEILING, float(value)))


def to_unit(value: Any, default: float = 0.0) -> float:
    """Coerce a value that may be 0-100 or 0-1 into a 0-1 unit score."""
    if value is None:
        return default
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    if v > 1.0:
        v /= 100.0
    return max(0.0, min(1.0, v))


def to_percent(value: Any, default: float = 0.0) -> float:
    """Coerce a value that may be 0-100 or 0-1 into a 0-100 percentage."""
    return round(to_unit(value, default=default) * 100.0, 1)


def base_confidence(tool_name: str) -> float:
    name = (tool_name or "").lower()
    if name in _HIGH_BASE_NAMES:
        return _HIGH
    if name in _MEDIUM_BASE_NAMES:
        return _MEDIUM
    if name in _LOW_BASE_NAMES:
        return _LOW
    return _DEFAULT


def reliability_adjustment(score: float, reliability: float) -> float:
    """Scale a score by the observed reliability of the producing tool.

    Reliability is interpreted as a success rate. Neutral (0.5) is a no-op;
    a tool that always fails drags the score down; a tool that always
    succeeds lifts it, capped at CEILING.
    """
    score = clamp_unit(score)
    r = max(0.0, min(1.0, float(reliability)))
    if r == 0.5:
        return score
    return clamp_unit(score * (0.5 + r))


def corroboration_adjustment(score: float, n_sources: int) -> float:
    """Adjust for the number of independent sources behind a claim.

    A single unconfirmed source gets a mild discount; each additional
    source raises confidence along a diminishing curve capped at CEILING.
    """
    score = clamp_unit(score)
    n = max(0, int(n_sources))
    if n <= 1:
        factor = 0.9 if n == 1 else 0.85
    elif n == 2:
        factor = 0.97
    else:
        factor = min(1.15, 0.85 + 0.05 * n)
    return clamp_unit(score * factor)


def recency_adjustment(score: float, age_hours: Optional[float],
                       half_life_hours: float = 72.0) -> float:
    """Exponentially decay stale evidence. Half-life defaults to 72h."""
    score = clamp_unit(score)
    if age_hours is None or age_hours <= 0:
        return score
    half_life = max(0.001, float(half_life_hours))
    return clamp_unit(score * (0.5 ** (float(age_hours) / half_life)))


def combine_scores(scores: Iterable[float]) -> float:
    """Combine independent measurements via noiseless-OR (1 - prod(1-s))."""
    components = [clamp_unit(round(s, 6)) for s in scores if s is not None and s > 0]
    if not components:
        return 0.0
    p = 1.0
    for s in components:
        p *= (1.0 - s)
    return clamp_unit(1.0 - p)


def blend_agent_critic(agent_conf: float, critic_conf: float) -> float:
    """Central 40/60 agent/critic blend, matching agents/critic_agent.py."""
    return clamp_unit(0.4 * to_unit(agent_conf) + 0.6 * to_unit(critic_conf))


def confidence_label(score: float) -> str:
    s = to_unit(score)
    if s >= 0.85:
        return "CONFIRMED"
    if s >= CONFIRM_FLOOR:
        return "HIGH"
    if s >= 0.3:
        return "MEDIUM"
    return "LOW"


def llm_fallback_confidence() -> float:
    """Deterministic conservative confidence when the LLM is unavailable."""
    return DEFAULT_LLM_FALLBACK


class ConfidenceEngine:
    """Applies the confidence pipeline to tool results and findings."""

    def __init__(
        self,
        tool_manager: Any = None,
        reliability_provider: Optional[Callable[[str], float]] = None,
        base_overrides: Optional[Dict[str, float]] = None,
    ) -> None:
        if reliability_provider is None and tool_manager is not None:
            reliability_provider = getattr(tool_manager, "reliability", None)
        self._provider = reliability_provider
        self._overrides = dict(base_overrides or {})

    def _reliability_for(self, tool_name: str) -> Optional[float]:
        if self._provider is None:
            return None
        try:
            return float(self._provider(tool_name))
        except Exception:  # noqa: BLE001 - never let stats break scoring
            return None

    def base_confidence(self, tool_name: str) -> float:
        name = (tool_name or "").lower()
        if name in self._overrides:
            return clamp_unit(self._overrides[name])
        return base_confidence(name)

    def adjusted_confidence(
        self,
        score: float,
        tool_name: Optional[str] = None,
        reliability: Optional[float] = None,
        n_sources: int = 1,
        age_hours: Optional[float] = None,
    ) -> float:
        s = clamp_unit(score)
        if reliability is None and tool_name:
            reliability = self._reliability_for(tool_name)
        if reliability is not None:
            s = reliability_adjustment(s, reliability)
        s = corroboration_adjustment(s, n_sources)
        if age_hours is not None:
            s = recency_adjustment(s, age_hours)
        return s

    def score_tool_result(
        self,
        tool_name: str,
        status: str,
        quality: Optional[float] = None,
        n_sources: int = 1,
        reliability: Optional[float] = None,
    ) -> float:
        """Full pipeline for one tool run. Non-success runs score 0."""
        if status != "success":
            return 0.0
        base = self.base_confidence(tool_name)
        if quality is not None:
            q = max(0.0, min(1.0, float(quality)))
            base = clamp_unit(base + (q - 0.5) * 0.3)
        if reliability is None:
            reliability = self._reliability_for(tool_name)
        return self.adjusted_confidence(
            base, reliability=reliability, n_sources=n_sources)

    def final_confidence(self, agent_conf: float, critic_conf: float) -> float:
        return blend_agent_critic(agent_conf, critic_conf)

    def confirm_floor(self) -> float:
        return CONFIRM_FLOOR

    def decided_verdict(self, score: float,
                        min_confirm: Optional[float] = None) -> str:
        """Map a blended confidence to a verdict for reporting layers."""
        s = to_unit(score)
        floor = min_confirm if min_confirm is not None else CONFIRM_FLOOR
        if s >= floor:
            return "CONFIRMED"
        if s >= 0.3:
            return "NEEDS_PROOF"
        return "REJECTED"