"""
ActionScorer — deterministic, evidence-driven action selection.

Turns raw capability coverage into an ordered execution plan WITHOUT an LLM,
by scoring every candidate capability on four axes:

  - information_gain: how unexplored this area is (evidence coverage gaps)
  - success:          how likely a run is to produce output given the surface
  - novelty:          how many times we already tried (avoid hammering)
  - risk:             blast radius penalty, honoring a high-risk gate

The Controller (Stage 7) uses rankings here to decide which capability to run
next; PlannerAgent can also rescore its own attack graph through
`score_plan()`. Everything is a pure function over small dicts so it is fully
testable without tools, LLMs, or network access.
"""

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from tool_manager import RISK_ACTIVE_HIGH, RISK_ACTIVE_LOW, RISK_PASSIVE, tool_risk_level

DEFAULT_WEIGHTS = {"info_gain": 0.4, "success": 0.3, "novelty": 0.2, "risk": 0.1}

RISK_PENALTY = {
    RISK_PASSIVE: 0.0,
    RISK_ACTIVE_LOW: 0.1,
    RISK_ACTIVE_HIGH: 0.3,
}

# (capabilities, surface_key, boost) — applied when surface[key] is truthy.
SUCCESS_HINTS: List[Tuple[set, str, float]] = [
    ({"HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_DETECTION",
      "OPERATING_SYSTEM_IDENTIFICATION", "TLS_ANALYSIS", "DNS_RESOLUTION",
      "DNS_ENUMERATION", "SUBDOMAIN_DISCOVERY", "PASSIVE_ASSET_DISCOVERY"},
     "reachable", 0.4),
    ({"WEB_PROBING", "WEB_TECHNOLOGY_DISCOVERY", "WEB_CRAWLING",
      "CONTENT_DISCOVERY", "PARAMETER_DISCOVERY", "HEADER_ANALYSIS",
      "COOKIE_ANALYSIS", "ROBOTS_TXT_ANALYSIS", "HISTORICAL_URL_DISCOVERY",
      "JAVASCRIPT_ANALYSIS", "SCREENSHOT_CAPTURE", "CMS_IDENTIFICATION",
      "SENSITIVE_ENDPOINT_DETECTION", "CSRF_SURFACE_DETECTION",
      "UPLOAD_FORM_DETECTION", "DESERIALIZATION_DETECTION",
      "GRAPHQL_INTROSPECTION", "SESSION_ANALYSIS", "WEB_VULN_SCAN",
      "XSS_SCAN", "CORS_SCAN", "CLICKJACKING_TEST", "HTTP_METHOD_TEST",
      "HOST_HEADER_ATTACK", "SECRETS_SCAN", "SQLI_SCAN", "SSTI_SCAN",
      "LFI_SCAN", "SSRF_SCAN", "CMD_INJECTION_SCAN", "XXE_SCAN",
      "CRLF_INJECTION_SCAN", "CSRF_SCAN", "WAF_BYPASS_TEST",
      "SESSION_FIXATION", "OPEN_REDIRECT_SCAN", "DEFAULT_CRED_SCAN",
      "MISCONFIG_SCAN", "EXPOSED_PANELS_SCAN"},
     "web", 0.35),
    ({"API_ENDPOINT_DISCOVERY", "API_PROBE", "GRAPHQL_INTROSPECTION"},
     "api", 0.35),
    ({"CMS_IDENTIFICATION", "CMS_ASSESSMENT"}, "cms", 0.3),
    ({"SQLI_SCAN", "XSS_SCAN", "SSTI_SCAN", "LFI_SCAN", "SSRF_SCAN",
      "CMD_INJECTION_SCAN", "XXE_SCAN", "CRLF_INJECTION_SCAN", "CSRF_SCAN",
      "CORS_SCAN", "WAF_BYPASS_TEST", "SESSION_FIXATION",
      "SSTI_EXPLOIT", "LFI_EXPLOIT", "SSRF_EXPLOIT"},
     "params_found", 0.25),
    ({"TLS_ANALYSIS", "TLS_VULN_SCAN", "HEADER_ANALYSIS"}, "ssl", 0.3),
    ({"CLOUD_ASSET_DISCOVERY", "S3_LIST"}, "cloud", 0.3),
    ({"CONTAINER_DISCOVERY", "IOT_SERVICE_IDENTIFICATION",
      "WINDOWS_SERVICE_ENUMERATION", "DIRECTORY_SERVICE_ENUMERATION"},
     "network", 0.2),
]

# planner agent name -> (primary capability, use_attack)
AGENT_CAPABILITY: Dict[str, Tuple[str, bool]] = {
    "web_attack": ("WEB_VULN_SCAN", True),
    "network": ("PORT_DISCOVERY", False),
    "api": ("API_ENDPOINT_DISCOVERY", False),
    "auth": ("AUTH_PROBE", True),
    "infra": ("SERVICE_DETECTION", False),
    "cloud": ("CLOUD_ASSET_DISCOVERY", False),
    "web_fuzz": ("CONTENT_DISCOVERY", False),
    "headers_attack": ("HEADER_ANALYSIS", False),
    "subdomain_takeover": ("SUBDOMAIN_TAKEOVER_SCAN", True),
    "waf_bypass": ("WAF_DETECT", True),
    "jwt": ("JWT_ANALYSIS", True),
    "xxe": ("XXE_SCAN", True),
    "csrf": ("CSRF_SCAN", True),
    "deserialization": ("DESERIALIZATION_SCAN", True),
    "session_hijack": ("SESSION_HIJACK", True),
    "ssti_exploit": ("SSTI_EXPLOIT", True),
    "lfi_exploit": ("LFI_EXPLOIT", True),
    "ssrf_exploit": ("SSRF_EXPLOIT", True),
    "jwt_exploit": ("JWT_EXPLOIT", True),
    "payload": ("PAYLOAD_GENERATION", True),
    "exploitation": ("EXPLOIT_SEARCH", True),
    "intelligence": ("EXPLOIT_SEARCH", True),
    "recon": ("PORT_DISCOVERY", False),
}


def information_gap(coverage: Dict[str, int], capability: str) -> float:
    """How unexplored a capability is, 1.0 (untouched) down to ~0.0."""
    seen = int(coverage.get(capability, 0) or 0)
    return 1.0 / (1.0 + seen)


def novelty_ratio(attempted: List[str], capability: str) -> float:
    """1.0 when fresh; exponential decay for every repeat attempt."""
    n = sum(1 for a in (attempted or []) if a == capability)
    if n == 0:
        return 1.0
    return 0.4 * (0.5 ** (n - 1))


def risk_penalty_for(risk_level: str, allow_high_risk: bool = True) -> float:
    """0.0 for passive, mild for active scans, heavy for exploits.

    When high-risk actions are disallowed they return 1.0, forcing a total
    score of zero in score_action().
    """
    if risk_level == RISK_ACTIVE_HIGH and not allow_high_risk:
        return 1.0
    return RISK_PENALTY.get(risk_level, 0.1)


def success_prior(capability: str, surface: Dict[str, Any]) -> float:
    """Prior probability this capability yields output, from surface hints."""
    base = 0.5
    for caps, key, boost in SUCCESS_HINTS:
        if capability in caps and surface.get(key):
            base += boost
    return min(1.0, base)


@dataclass
class ActionScore:
    capability: str
    use_attack: bool
    info_gain: float
    success: float
    novelty: float
    risk_level: str
    risk_penalty: float
    total: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability": self.capability,
            "use_attack": self.use_attack,
            "info_gain": round(self.info_gain, 3),
            "success": round(self.success, 3),
            "novelty": round(self.novelty, 3),
            "risk_level": self.risk_level,
            "risk_penalty": round(self.risk_penalty, 3),
            "total": round(self.total, 3),
        }


class ActionScorer:
    """Evidence-driven action selector with optional ToolManager risk data."""

    def __init__(self, tool_manager: Any = None, weights: Optional[Dict[str, float]] = None,
                 allow_high_risk: bool = True) -> None:
        self.tool_manager = tool_manager
        self.weights = {**DEFAULT_WEIGHTS, **(weights or {})}
        self.allow_high_risk = bool(allow_high_risk)

    def risk_level(self, capability: str, use_attack: bool = False) -> str:
        if self.tool_manager is not None:
            try:
                return self.tool_manager.risk_level_for_capability(capability, use_attack=use_attack)
            except Exception:  # noqa: BLE001
                pass
        return tool_risk_level(capability)

    def score_action(self, capability: str, coverage: Dict[str, int],
                     attempted: Optional[List[str]] = None,
                     surface: Optional[Dict[str, Any]] = None,
                     use_attack: bool = False,
                     risk_level: Optional[str] = None) -> ActionScore:
        risk = risk_level or self.risk_level(capability, use_attack)
        penalty = risk_penalty_for(risk, self.allow_high_risk)
        total = (
            self.weights["info_gain"] * information_gap(coverage, capability)
            + self.weights["success"] * success_prior(capability, surface or {})
            + self.weights["novelty"] * novelty_ratio(attempted or [], capability)
        ) - self.weights["risk"] * penalty
        if penalty >= 1.0:
            total = 0.0
        return ActionScore(
            capability=capability, use_attack=use_attack,
            info_gain=information_gap(coverage, capability),
            success=success_prior(capability, surface or {}),
            novelty=novelty_ratio(attempted or [], capability),
            risk_level=risk, risk_penalty=penalty, total=max(0.0, total),
        )

    def rank(self, capabilities: Iterable[str], coverage: Dict[str, int],
             attempted: Optional[List[str]] = None,
             surface: Optional[Dict[str, Any]] = None) -> List[ActionScore]:
        scores = [self.score_action(c, coverage, attempted, surface) for c in capabilities]
        scores.sort(key=lambda s: (-s.total, -s.info_gain, s.risk_level))
        return scores

    def rank_flagged(self, candidates: Iterable[Tuple[str, bool]],
                     coverage: Dict[str, int],
                     attempted: Optional[List[str]] = None,
                     surface: Optional[Dict[str, Any]] = None) -> List[ActionScore]:
        """Rank capabilities that may belong to different channels; each
        candidate is a (capability, use_attack) pair."""
        scores = [self.score_action(cap, coverage, attempted, surface, use_attack=flag)
                  for cap, flag in candidates]
        scores.sort(key=lambda s: (-s.total, -s.info_gain, s.risk_level))
        return scores

    def next_action(self, capabilities: Iterable[str], coverage: Dict[str, int],
                    attempted: Optional[List[str]] = None,
                    surface: Optional[Dict[str, Any]] = None) -> Optional[ActionScore]:
        ranked = self.rank(capabilities, coverage, attempted, surface)
        return ranked[0] if ranked else None

    def score_plan(self, nodes: List[Dict[str, Any]], coverage: Dict[str, int],
                   attempted: Optional[List[str]] = None,
                   surface: Optional[Dict[str, Any]] = None,
                   agent_capability: Dict[str, Tuple[str, bool]] = AGENT_CAPABILITY,
                   plan_name: str = "evidence-driven") -> Dict[str, Any]:
        """Rescore a planner attack graph (nodes of {agent, priority, ...})
        in place of raw priorities, using the primary capability per agent."""
        ordered: List[Dict[str, Any]] = []
        for node in nodes:
            entry = dict(node)
            agent = str(entry.get("agent", ""))
            mapping = agent_capability.get(agent)
            if mapping is None or entry.get("skip"):
                entry["evidence_priority"] = entry.get("priority", 5)
                ordered.append(entry)
                continue
            cap, use_attack = mapping
            score = self.score_action(cap, coverage, attempted, surface, use_attack=use_attack)
            entry["capability"] = cap
            entry["evidence_score"] = score.to_dict()
            entry["evidence_priority"] = int(round(score.total * 9)) + 1
            ordered.append(entry)
        ordered.sort(key=lambda n: (
            n.get("skip", False),
            n.get("evidence_priority", n.get("priority", 5)),
            n.get("priority", 5),
        ))
        reasoning = (f"{plan_name}: {' > '.join(n['agent'] for n in ordered if not n.get('skip'))}"
                     if ordered else "no actionable plan")
        return {
            "attack_graph": ordered,
            "skip_agents": [n["agent"] for n in ordered if n["skip"]],
            "reasoning": reasoning,
        }