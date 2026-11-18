"""
state.py — unified, typed assessment state for CyberSwarm.

The existing codebase represents SystemMap, evidence, and memory as raw
Dict[str, Any]. This module introduces a structured, JSON-serializable model
of the current engagement: assets, relationships, evidence, executed actions,
decisions, and confidence scores.

Every entity carries a stable, deterministic identifier so the same
observation deduplicates across runs and across tools. Relationships carry
provenance (which tool discovered them, with what confidence).

This is the foundation the Controller / ToolManager / Planner / Critic will
read from and update. It is additive: existing Dict-based stores continue to
work untouched.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

STORE_DIR = Path(__file__).parent / "results" / "state"

# ── Asset type constants ──────────────────────────────────────────────────
ASSET_DOMAIN = "domain"
ASSET_SUBDOMAIN = "subdomain"
ASSET_IP = "ip"
ASSET_HOST = "host"
ASSET_PORT = "port"
ASSET_SERVICE = "service"
ASSET_TECHNOLOGY = "technology"
ASSET_URL = "url"
ASSET_ENDPOINT = "endpoint"
ASSET_PARAMETER = "parameter"
ASSET_API = "api"
ASSET_AUTH_PATH = "auth_path"
ASSET_FINDING = "finding"
ASSET_CREDENTIAL = "credential"
ASSET_CMS = "cms"

VALID_ASSET_TYPES = {
    ASSET_DOMAIN, ASSET_SUBDOMAIN, ASSET_IP, ASSET_HOST, ASSET_PORT,
    ASSET_SERVICE, ASSET_TECHNOLOGY, ASSET_URL, ASSET_ENDPOINT,
    ASSET_PARAMETER, ASSET_API, ASSET_AUTH_PATH, ASSET_FINDING,
    ASSET_CREDENTIAL, ASSET_CMS,
}

DEFAULT_PORTS = {"http": 80, "https": 443}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Normalization (single source of truth for dedup identity) ─────────────

def normalize_hostname(host: str) -> str:
    """Lowercase, strip slashes and a trailing dot. Safe for dedup."""
    if not host:
        return ""
    h = str(host).strip().lower().rstrip(".")
    return re.sub(r"[^a-z0-9._\-]", "", h)


def normalize_port(port: Any) -> str:
    if port is None or str(port) == "":
        return ""
    try:
        p = int(port)
        if 1 <= p <= 65535:
            return str(p)
    except (TypeError, ValueError):
        pass
    return str(port).strip()


def normalize_url(url: str) -> str:
    """Normalize a URL for dedup: lowercase scheme/host, drop default port,
    drop fragment, collapse trailing slashes on the path."""
    if not url:
        return ""
    u = str(url).strip()
    if not u:
        return ""
    try:
        parsed = urlparse(u)
    except ValueError:
        return u
    scheme = (parsed.scheme or "http").lower()
    host = normalize_hostname(parsed.hostname or "")
    port = parsed.port
    if port and scheme in DEFAULT_PORTS and port == DEFAULT_PORTS[scheme]:
        port = None
    path = parsed.path or ""
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    netloc = host
    if port:
        netloc = f"{host}:{port}"
    # Keep query; drop fragment.
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{netloc}{path or '/'}{query}"


def normalize_value(asset_type: str, value: str) -> str:
    """Normalize a raw value according to its asset type."""
    if asset_type in (ASSET_URL, ASSET_ENDPOINT, ASSET_API, ASSET_AUTH_PATH):
        return normalize_url(value)
    if asset_type in (ASSET_DOMAIN, ASSET_SUBDOMAIN, ASSET_HOST):
        return normalize_hostname(value)
    if asset_type == ASSET_PORT:
        return normalize_port(value)
    return str(value or "").strip()


def asset_identity(asset_type: str, value: str) -> str:
    """Deterministic, stable identity for an asset. Same (type, value) always
    yields the same id, so it deduplicates across tools and sessions."""
    nv = normalize_value(asset_type, value)
    if not nv:
        return ""
    return f"{asset_type}:{nv}"


def _short_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# ── Confidence (basic aggregation, refined by confidence.py in Stage 3) ────

def merge_confidence(current: Optional[float], new: float,
                     source_count: int = 1) -> float:
    """Combine an existing confidence with a new observation.

    Repeated independent confirmation raises confidence toward the source_mean
    but never to 1.0 (ceiling). Disagreement is handled by passing a lower
    `new` value, which drags the aggregate down.
    """
    if current is None:
        return round(min(0.99, max(0.0, new)), 3)
    alpha = min(0.5, 0.25 + 0.05 * (source_count - 1))
    merged = current + alpha * (new - current)
    return round(min(0.99, max(0.0, merged)), 3)


# ── Structured types ──────────────────────────────────────────────────────

@dataclass
class Asset:
    type: str
    value: str
    source: str = "unknown"
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    confidence: float = 0.5
    properties: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in VALID_ASSET_TYPES:
            raise ValueError(f"unknown asset type: {self.type!r}")
        self.value = normalize_value(self.type, self.value)
        if not self.value:
            raise ValueError("asset value is empty after normalization")

    @property
    def id(self) -> str:
        return asset_identity(self.type, self.value)

    def touched(self, source: str = "") -> None:
        """Mark this asset as re-observed now (last_seen refresh)."""
        self.last_seen = _now()
        if source:
            self.source = source

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "type": self.type, "value": self.value,
            "source": self.source, "first_seen": self.first_seen,
            "last_seen": self.last_seen, "confidence": self.confidence,
            "properties": self.properties,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Asset":
        return cls(
            type=d["type"], value=d["value"], source=d.get("source", "unknown"),
            first_seen=d.get("first_seen", _now()),
            last_seen=d.get("last_seen", d.get("first_seen", _now())),
            confidence=float(d.get("confidence", 0.5)),
            properties=dict(d.get("properties", {})),
        )


@dataclass
class Relationship:
    from_id: str
    to_id: str
    kind: str                      # e.g. "discovers", "resolves_to", "serves"
    source: str = "unknown"
    confidence: float = 0.5
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from": self.from_id, "to": self.to_id, "kind": self.kind,
            "source": self.source, "confidence": self.confidence,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Relationship":
        return cls(
            from_id=d["from"], to_id=d["to"], kind=d["kind"],
            source=d.get("source", "unknown"),
            confidence=float(d.get("confidence", 0.5)),
            timestamp=d.get("timestamp", _now()),
        )


@dataclass
class EvidenceItem:
    target: str
    source_tool: str
    capability: str
    status: str = "success"        # success/error/timeout/not_installed
    timestamp: str = field(default_factory=_now)
    parsed_result: Dict[str, Any] = field(default_factory=dict)
    raw_output_reference: str = ""  # file path or excerpt
    confidence: float = 0.5
    related_asset_id: str = ""
    related_finding_id: str = ""
    integrity_hash: str = ""

    def __post_init__(self) -> None:
        if not self.integrity_hash:
            self.integrity_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        blob = json.dumps(
            {"target": self.target, "tool": self.source_tool,
             "capability": self.capability, "status": self.status,
             "parsed": self.parsed_result,
             "raw": self.raw_output_reference},
            sort_keys=True, default=str,
        )
        return _short_hash(blob)

    @property
    def id(self) -> str:
        return f"evidence:{self.integrity_hash}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "target": self.target, "source_tool": self.source_tool,
            "capability": self.capability, "status": self.status,
            "timestamp": self.timestamp, "parsed_result": self.parsed_result,
            "raw_output_reference": self.raw_output_reference,
            "confidence": self.confidence, "related_asset_id": self.related_asset_id,
            "related_finding_id": self.related_finding_id,
            "integrity_hash": self.integrity_hash,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvidenceItem":
        return cls(
            target=d["target"], source_tool=d["source_tool"],
            capability=d.get("capability", ""), status=d.get("status", "success"),
            timestamp=d.get("timestamp", _now()),
            parsed_result=dict(d.get("parsed_result", {})),
            raw_output_reference=d.get("raw_output_reference", ""),
            confidence=float(d.get("confidence", 0.5)),
            related_asset_id=d.get("related_asset_id", ""),
            related_finding_id=d.get("related_finding_id", ""),
            integrity_hash=d.get("integrity_hash", ""),
        )


@dataclass
class ActionRecord:
    action: str                    # capability e.g. "SUBDOMAIN_DISCOVERY"
    tool: str
    target: str
    timestamp: str = field(default_factory=_now)
    status: str = "success"        # success/error/timeout/not_installed/unsupported
    duration_s: float = 0.0
    output_quality: float = 0.5    # 0-1 heuristic from parse richness
    cost: float = 0.0              # e.g. elapsed time budget consumed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action, "tool": self.tool, "target": self.target,
            "timestamp": self.timestamp, "status": self.status,
            "duration_s": round(self.duration_s, 2),
            "output_quality": self.output_quality, "cost": round(self.cost, 2),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ActionRecord":
        return cls(
            action=d["action"], tool=d.get("tool", ""), target=d.get("target", ""),
            timestamp=d.get("timestamp", _now()), status=d.get("status", "success"),
            duration_s=float(d.get("duration_s", 0.0)),
            output_quality=float(d.get("output_quality", 0.5)),
            cost=float(d.get("cost", 0.0)),
        )


@dataclass
class Decision:
    target: str
    selected_action: str
    reasoning: str = ""
    timestamp: str = field(default_factory=_now)
    context_snapshot: Dict[str, Any] = field(default_factory=dict)
    knowledge_gaps: List[str] = field(default_factory=list)
    candidate_actions: List[Dict[str, Any]] = field(default_factory=list)
    selected_tool: str = ""
    result_status: str = ""
    critic_verdict: str = ""
    state_update_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp, "target": self.target,
            "context_snapshot": self.context_snapshot,
            "knowledge_gaps": self.knowledge_gaps,
            "candidate_actions": self.candidate_actions,
            "selected_action": self.selected_action,
            "selected_tool": self.selected_tool, "reasoning": self.reasoning,
            "result_status": self.result_status, "critic_verdict": self.critic_verdict,
            "state_update_summary": self.state_update_summary,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Decision":
        return cls(
            target=d.get("target", ""), selected_action=d.get("selected_action", ""),
            reasoning=d.get("reasoning", ""), timestamp=d.get("timestamp", _now()),
            context_snapshot=dict(d.get("context_snapshot", {})),
            knowledge_gaps=list(d.get("knowledge_gaps", [])),
            candidate_actions=list(d.get("candidate_actions", [])),
            selected_tool=d.get("selected_tool", ""),
            result_status=d.get("result_status", ""),
            critic_verdict=d.get("critic_verdict", ""),
            state_update_summary=d.get("state_update_summary", ""),
        )


@dataclass
class AssessmentState:
    target: str
    created: str = field(default_factory=_now)
    updated: str = field(default_factory=_now)
    schema_version: int = 1
    assets: List[Asset] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    evidence: List[EvidenceItem] = field(default_factory=list)
    actions: List[ActionRecord] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    decisions: List[Decision] = field(default_factory=list)
    risk_rating: str = "UNKNOWN"
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ── marker methods ────────────────────────────────────────────────────

    def mark_updated(self) -> None:
        self.updated = _now()

    # ── asset management (deduplicating) ──────────────────────────────────

    def upsert_asset(self, asset: Asset) -> Asset:
        """Add an asset, or merge with an existing identical one.

        Returns the stored Asset. Deduplicates on (type, normalized value);
        refreshes last_seen and blends confidence across independent sources.
        """
        if asset.type not in VALID_ASSET_TYPES:
            raise ValueError(f"unknown asset type: {asset.type!r}")
        key = asset.id
        existing = self._asset_map().get(key)
        if existing is None:
            self.assets.append(asset)
            self.mark_updated()
            return asset
        existing.touched(asset.source)
        existing.confidence = merge_confidence(
            existing.confidence, asset.confidence,
            source_count=len({existing.source, asset.source}),
        )
        if asset.properties:
            existing.properties.update(asset.properties)
        self.mark_updated()
        return existing

    def has_asset(self, asset_type: str, value: str) -> bool:
        ident = asset_identity(asset_type, value)
        return ident in self._asset_map()

    def get_asset(self, asset_type: str, value: str) -> Optional[Asset]:
        return self._asset_map().get(asset_identity(asset_type, value))

    def _asset_map(self) -> Dict[str, Asset]:
        return {a.id: a for a in self.assets}

    # ── relationships (deduplicating) ─────────────────────────────────────

    def add_relationship(self, rel: Relationship) -> Optional[Relationship]:
        key = (rel.from_id, rel.to_id, rel.kind)
        for existing in self.relationships:
            if (existing.from_id, existing.to_id, existing.kind) == key:
                existing.confidence = merge_confidence(
                    existing.confidence, rel.confidence, source_count=2)
                existing.source = rel.source or existing.source
                existing.timestamp = _now()
                self.mark_updated()
                return existing
        self.relationships.append(rel)
        self.mark_updated()
        return rel

    # ── evidence / actions / decisions (append with dedup) ────────────────

    def add_evidence(self, ev: EvidenceItem) -> Optional[EvidenceItem]:
        for existing in self.evidence:
            if existing.id == ev.id:
                return existing
        self.evidence.append(ev)
        self.mark_updated()
        return ev

    def add_action(self, rec: ActionRecord) -> ActionRecord:
        self.actions.append(rec)
        self.mark_updated()
        return rec

    def add_decision(self, d: Decision) -> Decision:
        self.decisions.append(d)
        self.mark_updated()
        return d

    # ── convenience queries ───────────────────────────────────────────────

    def assets_of_type(self, asset_type: str) -> List[Asset]:
        return [a for a in self.assets if a.type == asset_type]

    def update_risk_rating(self, rating: str) -> None:
        self.risk_rating = str(rating).upper()
        self.mark_updated()

    # ── serialization ─────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target, "created": self.created, "updated": self.updated,
            "schema_version": self.schema_version,
            "assets": [a.to_dict() for a in self.assets],
            "relationships": [r.to_dict() for r in self.relationships],
            "evidence": [e.to_dict() for e in self.evidence],
            "actions": [a.to_dict() for a in self.actions],
            "findings": self.findings,
            "decisions": [d.to_dict() for d in self.decisions],
            "risk_rating": self.risk_rating,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AssessmentState":
        return cls(
            target=d.get("target", ""),
            created=d.get("created", _now()),
            updated=d.get("updated", _now()),
            schema_version=int(d.get("schema_version", 1)),
            assets=[Asset.from_dict(x) for x in d.get("assets", [])],
            relationships=[Relationship.from_dict(x) for x in d.get("relationships", [])],
            evidence=[EvidenceItem.from_dict(x) for x in d.get("evidence", [])],
            actions=[ActionRecord.from_dict(x) for x in d.get("actions", [])],
            findings=list(d.get("findings", [])),
            decisions=[Decision.from_dict(x) for x in d.get("decisions", [])],
            risk_rating=d.get("risk_rating", "UNKNOWN"),
            metadata=dict(d.get("metadata", {})),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def from_json(cls, text: str) -> "AssessmentState":
        return cls.from_dict(json.loads(text))

    def snapshot(self) -> Dict[str, Any]:
        """Compact snapshot for decision tracing / planner context."""
        return {
            "target": self.target,
            "risk_rating": self.risk_rating,
            "assets_by_type": {t: [a.value for a in self.assets_of_type(t)]
                               for t in sorted({a.type for a in self.assets})},
            "asset_counts": {t: len(self.assets_of_type(t))
                             for t in sorted({a.type for a in self.assets})},
            "relationships": len(self.relationships),
            "evidence_count": len(self.evidence),
            "actions_taken": [a.action for a in self.actions],
            "failed_actions": [a.action for a in self.actions if a.status != "success"],
            "findings": len(self.findings),
        }


# ── Persistence helpers ───────────────────────────────────────────────────

def _safe_path(target: str) -> Path:
    safe = normalize_hostname(target) or str(target).replace("/", "_").replace(":", "_")
    return STORE_DIR / f"{safe}.json"


def save_state(state: AssessmentState, target: Optional[str] = None) -> Path:
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    path = _safe_path(target or state.target)
    path.write_text(state.to_json(), encoding="utf-8")
    return path


def load_state(target: str) -> AssessmentState:
    """Load a saved assessment state, or return an empty one for `target`."""
    path = _safe_path(target)
    if path.exists():
        try:
            return AssessmentState.from_json(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            pass
    return AssessmentState(target=target)


def new_state(target: str) -> AssessmentState:
    return AssessmentState(target=target)


# ── Convenience factory bridging ToolResult -> structured types ───────────

def asset_from_tool_result(asset_type: str, value: str, source_tool: str,
                           confidence: float = 0.5,
                           properties: Optional[Dict[str, Any]] = None) -> Asset:
    """Build an Asset from a tool-produced value (e.g. a subdomain, port)."""
    return Asset(type=asset_type, value=value, source=source_tool,
                 confidence=confidence, properties=properties or {})


def evidence_from_tool_result(result, target: str) -> Optional[EvidenceItem]:
    """Build an EvidenceItem from an existing ToolResult if available.

    `result` may be None (e.g. a tool that failed to load) — returns None.
    """
    if result is None or getattr(result, "tool", None) is None:
        return None
    try:
        from tools.base import ToolResult  # noqa: F401
    except ImportError:
        pass
    return EvidenceItem(
        target=target,
        source_tool=result.tool,
        capability=getattr(result, "capability", ""),
        status=result.status,
        parsed_result=dict(result.results or {}),
        raw_output_reference=(result.raw_stdout or "")[:2000],
        confidence=0.9 if result.status == "success" else 0.1,
    )