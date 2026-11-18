"""Target — one persisted, relational model per target.

Unifies the scattered stores (SystemMap, recon evidence, attack memory)
behind a single object so every phase reads/extends the same target model.

    t = Target("superhuman.com", full_url="https://superhuman.com/docs")
    t.load()                 # lazily builds a sparse SystemMap if missing
    t.system_map["endpoints"].append(...)
    t.save_map()
    t.memory["completed_agents"].append("web_fuzz")
    t.save_memory()
"""

from pathlib import Path
from typing import Any, Dict, Optional

import build_system_map
import evidence_store
import system_map as sm
from agents.memory_agent import MemoryAgent

ROOT = Path(__file__).resolve().parent


class Target:
    """Central, persisted model for a single target across recon/attack/report."""

    def __init__(self, host: str, full_url: Optional[str] = None):
        self.host = host
        self.full_url = full_url
        self._map: Optional[Dict[str, Any]] = None
        self._evidence: Optional[Dict[str, Any]] = None
        self._memory: Optional[Dict[str, Any]] = None
        self._memory_store: Optional[MemoryAgent] = None
        self._loaded = False

    # ── SystemMap ─────────────────────────────────────────────────────────

    def load_map(self, force_build: bool = False) -> Dict[str, Any]:
        if self._map is None or force_build:
            self._map = sm.load_map(self.host)
            if force_build or not self._map.get("provenance"):
                self._map = build_system_map.build_for(self.host)
                sm.save_map(self.host, self._map)
        return self._map

    def save_map(self) -> None:
        if self._map is not None:
            sm.save_map(self.host, self._map)

    def attach_full_url(self, full_url: str) -> None:
        """Record a path-scoped URL target (https://host/path) on the map."""
        from run_agent_loop import inject_full_url
        self.full_url = full_url
        self._map = inject_full_url(self.load_map() or sm.new_map(self.host),
                                    self.host, full_url)
        sm.save_map(self.host, self._map)

    def clear_full_url(self) -> None:
        if self._map is not None and self._map.get("full_url"):
            self._map.pop("full_url", None)
            sm.save_map(self.host, self._map)

    # ── Recon evidence ────────────────────────────────────────────────────

    def load_evidence(self) -> Dict[str, Any]:
        if self._evidence is None:
            self._evidence = evidence_store.load(self.host, warn_on_regression=False)
        return self._evidence

    # ── Attack memory (persisted at results/attack_evidence/<host>.json) ──

    def load_memory(self) -> Dict[str, Any]:
        if self._memory is None:
            self._memory_store = MemoryAgent(self.host)
            self._memory = self._memory_store.load()
            self._memory.setdefault("target", self.host)
            self._memory.setdefault("completed_agents", [])
        return self._memory

    def save_memory(self) -> None:
        if self._memory is not None and self._memory_store is not None:
            self._memory_store.save(self._memory)

    def reset_memory(self) -> None:
        if self._memory_store is None:
            self._memory_store = MemoryAgent(self.host)
        self._memory = self._memory_store._empty()
        self._memory["target"] = self.host
        self._memory_store.save(self._memory)

    # ── Convenience ───────────────────────────────────────────────────────

    @property
    def system_map(self) -> Dict[str, Any]:
        return self.load_map()

    @property
    def evidence(self) -> Dict[str, Any]:
        return self.load_evidence()

    @property
    def memory(self) -> Dict[str, Any]:
        return self.load_memory()

    def to_context(self) -> Dict[str, Any]:
        """Compact summary for CLI status / reports / debugging."""
        m = self.load_map()
        tech = []
        for t in m.get("technologies", [])[:8]:
            if isinstance(t, dict):
                tech.append(t.get("name") or "")
            else:
                tech.append(str(t))
        return {
            "target": self.host,
            "full_url": self.full_url or m.get("full_url"),
            "subdomains": len(m["assets"].get("subdomains", [])),
            "services": len(m.get("services", [])),
            "ports": sorted({s.get("port") for s in m.get("services", []) if s.get("port")}),
            "technologies": [t for t in tech if t],
            "cms": m.get("cms"),
            "endpoints": len(m.get("endpoints", [])),
            "auth_paths": len(m.get("auth_paths", [])),
            "api_paths": len(m.get("api_paths", [])),
            "links": len(m.get("links", [])),
            "provenance": bool(m.get("provenance")),
            "recon_actions": len(self.load_evidence().get("completed_actions", [])),
            "attack_memory": {
                "risk_rating": self.memory.get("risk_rating"),
                "vulnerabilities": len(self.memory.get("vulnerabilities", [])),
                "completed_agents": list(self.memory.get("completed_agents", [])),
            },
        }
