"""
memory_store.py — unified memory facade over all persisted CyberSwarm stores.

One object that ties together the four places a run currently remembers things:
  - AssessmentState        (results/state/         ) new structured state
  - recon evidence         (results/evidence/      ) evidence_store
  - attack memory          (results/attack_evidence/) MemoryAgent
  - tool reliability       (results/tool_memory.json) ToolManager

The Controller reads its canonical picture from `load()` (an AssessmentState),
writes back through `save()`, and the legacy stores are re-derived on save so
the old report pipeline keeps working untouched. Evidence hydration from
legacy sessions means a State directory never needs to exist to get started.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

import evidence_store as _evidence_store
import state as _state
from agents.memory_agent import MemoryAgent
from state import (
    ASSET_API,
    ASSET_CMS,
    ASSET_ENDPOINT,
    ASSET_HOST,
    ASSET_IP,
    ASSET_PARAMETER,
    ASSET_PORT,
    ASSET_SERVICE,
    ASSET_SUBDOMAIN,
    ASSET_TECHNOLOGY,
    ASSET_URL,
    ActionRecord,
    AssessmentState,
    Asset,
    EvidenceItem,
    load_state,
    save_state,
)
from tool_manager import ToolManager
from utils import finding_key, severity_rank

_WEB_PORTS = {"80", "443", "8080", "8443"}


def merge_findings(existing: List[Dict[str, Any]],
                   incoming: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate vulnerability dicts on (normalized name, host).

    Same issue reported twice (even at different severities, by different
    agents) stays ONE entry; the higher severity and confidence win.
    """
    out: List[Dict[str, Any]] = list(existing)
    by_key = {finding_key(v): v for v in out}
    for f in incoming:
        if not isinstance(f, dict):
            continue
        key = finding_key(f)
        cur = by_key.get(key)
        if cur is None:
            out.append(f)
            by_key[key] = f
            continue
        if severity_rank(f.get("severity")) > severity_rank(cur.get("severity")):
            idx = out.index(cur)
            out[idx] = f
            by_key[key] = f
        else:
            cur["confidence"] = max(float(cur.get("confidence", 0)),
                                    float(f.get("confidence", 0)))
    return out


class MemoryStore:
    """Unified read/write facade over the state, evidence, and tool memory."""

    def __init__(self, target: str, tool_manager: Optional[ToolManager] = None,
                 memory_agent: Optional[MemoryAgent] = None) -> None:
        self.target = target
        self.tool_manager = tool_manager or ToolManager()
        self.memory_agent = memory_agent or MemoryAgent(target)

    # ── load ────────────────────────────────────────────────────────────────

    def load(self) -> AssessmentState:
        """Canonical state: the saved State file, hydrated from legacy evidence
        when a State file has never been written."""
        st = load_state(self.target)
        if not st.actions and not st.assets and not st.evidence:
            self.hydrate_from_evidence(st, self.evidence())
        return st

    def evidence(self) -> Dict[str, Any]:
        return _evidence_store.load(self.target, warn_on_regression=False)

    def attack_memory(self) -> Dict[str, Any]:
        return self.memory_agent.load()

    def tool_stats(self) -> Dict[str, Any]:
        return self.tool_manager.all_tool_stats()

    # ── queries feeding the planner/scorer ─────────────────────────────────

    def coverage_map(self, st: Optional[AssessmentState] = None) -> Dict[str, int]:
        """capability -> number of recorded evidence items (0 means untouched)."""
        st = st or self.load()
        cov: Dict[str, int] = {}
        for e in st.evidence:
            cov[e.capability] = cov.get(e.capability, 0) + 1
        return cov

    def attempted_capabilities(self, st: Optional[AssessmentState] = None) -> List[str]:
        st = st or self.load()
        return list(dict.fromkeys(a.action for a in st.actions))

    def surface_hints(self, st: Optional[AssessmentState] = None) -> Dict[str, Any]:
        """Derived surface booleans for ActionScorer success priors."""
        st = st or self.load()
        ports = {a.value for a in st.assets_of_type(ASSET_PORT)}
        web = bool(st.assets_of_type(ASSET_URL)) or bool(st.assets_of_type(ASSET_ENDPOINT)) \
            or bool(ports & _WEB_PORTS)
        api = bool(st.assets_of_type(ASSET_API)) or any(
            a.value.startswith("http") and "/api/" in a.value
            for a in st.assets_of_type(ASSET_ENDPOINT))
        cloud = any(a.value.startswith("http") and ("amazonaws" in a.value or ".s3" in a.value)
                    for a in st.assets_of_type(ASSET_URL))
        return {
            "reachable": bool(ports) or bool(st.assets_of_type(ASSET_IP))
                         or bool(st.metadata.get("reachable")),
            "web": web,
            "api": api,
            "params_found": bool(st.assets_of_type(ASSET_PARAMETER)),
            "ssl": bool(ports & {"443", "8443"}),
            "cms": bool(st.assets_of_type(ASSET_CMS)),
            "cloud": cloud,
            "network": bool(ports) and not web,
        }

    def overview(self, st: Optional[AssessmentState] = None) -> Dict[str, Any]:
        """One dict describing everything the memory system knows."""
        st = st or self.load()
        mem = self.memory_agent.load()
        return {
            "target": self.target,
            "state": st.snapshot(),
            "evidence_actions_completed": st.snapshot()["actions_taken"],
            "vulnerabilities": len(mem.get("vulnerabilities", [])),
            "disputed_findings": len(mem.get("disputed_findings", [])),
            "proof_requests": len(mem.get("proof_requests", [])),
            "completed_agents": mem.get("completed_agents", []),
            "risk_rating": mem.get("risk_rating", st.risk_rating),
            "tool_reliability": {name: round(
                self.tool_manager.reliability(name), 3)
                for name in self.tool_manager.all_tool_stats()},
        }

    # ── legacy <-> state bridges ───────────────────────────────────────────

    def hydrate_from_evidence(self, st: AssessmentState,
                              evidence: Dict[str, Any]) -> AssessmentState:
        """Fold a legacy evidence dict into an AssessmentState (used when a
        State file does not exist yet, so no coverage is lost on migration)."""
        ev = evidence or {}
        st.metadata.setdefault("reachable", ev.get("reachable"))
        if ev.get("resolved_ip"):
            st.upsert_asset(Asset(type=ASSET_IP, value=ev["resolved_ip"], source="dns_resolve"))
        for sub in ev.get("subdomains", []) or []:
            st.upsert_asset(Asset(type=ASSET_SUBDOMAIN, value=sub, source="subfinder"))
        for p in ev.get("open_ports", []) or []:
            st.upsert_asset(Asset(type=ASSET_PORT, value=p, source="naabu"))
        details = ev.get("port_details", []) or []
        for d in details:
            port = d.get("port")
            if not port:
                continue
            st.upsert_asset(Asset(type=ASSET_SERVICE,
                                  value=f"{port}/{d.get('service', '') or 'unknown'}",
                                  source="nmap",
                                  properties={"port": port, "service": d.get("service", "")}))
        for tech in ev.get("technologies", []) or []:
            st.upsert_asset(Asset(type=ASSET_TECHNOLOGY, value=tech, source="whatweb"))
        for u in ev.get("discovered_urls", []) or []:
            st.upsert_asset(Asset(type=ASSET_URL, value=u, source="httpx"))
        for ep in (ev.get("discovered_paths", []) or []) + (ev.get("discovered_endpoints", []) or []):
            url = ep if str(ep).startswith("http") else f"{self.target}{ep}"
            st.upsert_asset(Asset(type=ASSET_ENDPOINT, value=url, source="ffuf"))
        for par in ev.get("discovered_parameters", []) or []:
            st.upsert_asset(Asset(type=ASSET_PARAMETER, value=par, source="arjun"))
        if ev.get("cms_detected"):
            st.upsert_asset(Asset(type=ASSET_CMS, value=ev["cms_detected"], source="cms_identify"))
        for at in ev.get("detected_api_types", []) or []:
            st.upsert_asset(Asset(type=ASSET_API, value=at, source="api_discover"))
        for cap in ev.get("completed_actions", []) or []:
            self._record_capability(st, cap, status="success", recorded={cap: "legacy"})
        for cap in ev.get("failed_actions", []) or []:
            self._record_capability(st, cap, status="error")
        return st

    def _record_capability(self, st: AssessmentState, capability: str,
                           status: str, recorded: Optional[Dict[str, str]] = None) -> None:
        st.add_action(ActionRecord(action=capability, tool="legacy",
                                   target=self.target, status=status))
        if recorded is None:
            return
        st.add_evidence(EvidenceItem(
            target=self.target, source_tool="legacy", capability=capability,
            status=status if status == "success" else "error",
            parsed_result=dict(recorded),
            confidence=0.5 if status == "success" else 0.1,
        ))

    def state_to_evidence(self, st: Optional[AssessmentState] = None,
                          evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Derive the legacy recon evidence shape from an AssessmentState."""
        st = st or self.load()
        base = dict(evidence or {"target": self.target})
        base["target"] = self.target
        base.setdefault("open_ports", [])
        base.setdefault("subdomains", [])
        base.setdefault("technologies", [])
        base.setdefault("discovered_urls", [])
        base.setdefault("services", [])
        base.setdefault("completed_actions", [])
        base.setdefault("failed_actions", [])
        base.setdefault("zero_findings_actions", [])
        base.setdefault("previous_observations", [])

        base["open_ports"] = sorted(
            {a.value for a in st.assets_of_type(ASSET_PORT)} | set(base["open_ports"]),
            key=lambda v: int(v) if str(v).isdigit() else 0)
        subs = {a.value for a in st.assets_of_type(ASSET_SUBDOMAIN)}
        if subs:
            base["subdomains"] = sorted(subs)
        techs = {a.value for a in st.assets_of_type(ASSET_TECHNOLOGY)}
        if techs:
            base["technologies"] = sorted(techs)
        urls = [a.value for a in st.assets_of_type(ASSET_URL)]
        if urls:
            base["discovered_urls"] = list(dict.fromkeys(urls))
        ports = st.assets_of_type(ASSET_PORT)
        if ports:
            base["open_ports"] = sorted(
                {int(a.value) for a in ports if a.value.isdigit()} | {
                    int(p) for p in base["open_ports"] if str(p).isdigit()})
        svc = [a for a in st.assets_of_type(ASSET_SERVICE) if a.properties.get("port")]
        if svc:
            detail = {d["port"]: d for d in base.get("port_details", [])}
            for a in svc:
                detail[int(a.properties["port"])] = {
                    "port": int(a.properties["port"]),
                    "service": str(a.properties.get("service", "")) or "",
                    "state": "open",
                }
            base["port_details"] = [detail[k] for k in sorted(detail)]

        base["completed_actions"] = list(dict.fromkeys(
            base["completed_actions"]
            + [a.action for a in st.actions if a.status == "success"]))
        base["failed_actions"] = list(dict.fromkeys(
            base["failed_actions"]
            + [a.action for a in st.actions if a.status != "success"]))
        if st.metadata.get("reachable") is not None:
            base["reachable"] = st.metadata.get("reachable")
        if st.assets_of_type(ASSET_CMS) and "cms_detected" not in base:
            base["cms_detected"] = st.assets_of_type(ASSET_CMS)[0].value
        return base

    # ── save ───────────────────────────────────────────────────────────────

    def save(self, st: Optional[AssessmentState] = None) -> None:
        """Persist the State and re-derive the legacy recon evidence file so
        the pre-existing report pipeline sees the same facts."""
        st = st or self.load()
        save_state(st, self.target)
        _evidence_store.save(self.state_to_evidence(st, self.evidence()))
        self.tool_manager.save()

    def import_attack_memory(self, st: AssessmentState) -> AssessmentState:
        """Pull confirmed vulnerabilities from attack memory into state.findings."""
        mem = self.memory_agent.load()
        incoming = list(st.findings) + list(mem.get("vulnerabilities", []))
        st.findings = merge_findings([], incoming)
        st.mark_updated()
        return st

    def export_attack_memory(self, st: Optional[AssessmentState] = None) -> Dict[str, Any]:
        """Rebuild the attack-memory JSON from state.findings (dedup preserved)."""
        st = st or self.load()
        mem = self.memory_agent.load()
        mem["vulnerabilities"] = merge_findings(
            mem.get("vulnerabilities", []), st.findings)
        mem["target"] = self.target
        return mem