"""
ad_graph.py — Active Directory relationship graph and attack-path analysis.

CyberSwarm had no AD model at all. `state.py` carries generic `Relationship`
objects, but nothing understood that "Alice is a member of Helpdesk, Helpdesk
has GenericAll on the Server Admins group, and Server Admins is AdminTo DC01"
composes into a path to domain compromise.

This module supplies that: a typed graph over AD principals, built from
SharpHound/BloodHound JSON, with shortest-path search toward high-value
targets.

Scope
-----
This is **analysis of data already collected**, not collection. It reads
SharpHound output you produced separately, or LDAP/SMB enumeration CyberSwarm
already performs, and tells you what the relationships imply. It issues no
Kerberos requests, forges no tickets and opens no sessions — those need a
domain foothold and the session layer CyberSwarm does not have.

What that means in practice: point it at a GOAD lab's SharpHound collection and
it will tell you the paths to Domain Admin. It will not walk them for you.

Graph model
-----------
Nodes are principals (User, Computer, Group, Domain, GPO, OU, Container).
Edges are AD relationships, each with a traversal cost — `MemberOf` is free and
certain, `GenericAll` requires an action, `HasSession` depends on a user being
logged in and may evaporate. Path cost reflects how much work and luck a path
needs, so "shortest" means "most reliable", not "fewest hops".
"""

from __future__ import annotations

import heapq
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    from utils import get_logger
except ImportError:  # standalone import
    import logging

    def get_logger(name: str):  # type: ignore[misc]
        return logging.getLogger(name)

log = get_logger("ad_graph")

# Traversal cost per edge type. Lower is cheaper and more reliable.
#
# The spread matters more than the absolute numbers: a path through three
# group memberships is far more dependable than one hop that needs a user to
# happen to be logged in right now, and the search should prefer the former.
EDGE_COST: Dict[str, float] = {
    # Free and certain — already true, nothing to do.
    "MemberOf": 0.5,
    "Contains": 0.5,
    "TrustedBy": 1.0,
    # Direct rights: usable immediately with the principal in hand.
    "AdminTo": 1.0,
    "CanRDP": 1.5,
    "CanPSRemote": 1.5,
    "ExecuteDCOM": 2.0,
    "SQLAdmin": 2.0,
    # Object-control rights: need an action, but are deterministic.
    "GenericAll": 2.0,
    "GenericWrite": 2.5,
    "WriteDacl": 2.5,
    "WriteOwner": 2.5,
    "Owns": 2.5,
    "AllExtendedRights": 2.5,
    "ForceChangePassword": 3.0,
    "AddMember": 2.0,
    "AddSelf": 2.0,
    "WriteSPN": 3.0,
    "AddKeyCredentialLink": 3.0,
    # GPO abuse: powerful but noisy and slow to take effect.
    "GpLink": 3.5,
    # Credential-dependent: needs cracking or a session that may be gone.
    "HasSession": 4.0,
    "CanPSRemoteAsAdmin": 2.0,
    "ReadLAPSPassword": 2.5,
    "ReadGMSAPassword": 2.5,
    "DCSync": 1.0,
    "GetChanges": 1.5,
    "GetChangesAll": 1.5,
    "AllowedToDelegate": 3.0,
    "AllowedToAct": 3.0,
    "HasSIDHistory": 2.0,
}
DEFAULT_EDGE_COST = 3.0

HIGH_VALUE_GROUPS = {
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS",
    "SCHEMA ADMINS", "ACCOUNT OPERATORS", "BACKUP OPERATORS",
    "DOMAIN CONTROLLERS", "ENTERPRISE DOMAIN CONTROLLERS",
    "KEY ADMINS", "ENTERPRISE KEY ADMINS",
}


@dataclass
class Node:
    """One AD principal."""

    name: str                       # UPPERCASE, usually SAM@DOMAIN
    kind: str = "Unknown"           # User | Computer | Group | Domain | GPO | OU
    objectid: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)

    @property
    def high_value(self) -> bool:
        if self.properties.get("highvalue"):
            return True
        base = self.name.split("@", 1)[0].upper()
        return base in HIGH_VALUE_GROUPS

    @property
    def enabled(self) -> bool:
        return self.properties.get("enabled", True) is not False

    @property
    def kerberoastable(self) -> bool:
        """Has an SPN set, so a service ticket can be requested for it.

        The exploration half reports this as an observation; the ADAgent
        drives Kerberoasting via tools/directory/ad_exploit.py when domain
        credentials are supplied, capturing $krb5tgs$ hashes for offline crack.
        """
        return bool(self.kind == "User" and self.properties.get("hasspn"))

    @property
    def asrep_roastable(self) -> bool:
        return bool(self.kind == "User"
                    and self.properties.get("dontreqpreauth"))

    @property
    def unconstrained_delegation(self) -> bool:
        return bool(self.properties.get("unconstraineddelegation"))


@dataclass
class Edge:
    source: str
    target: str
    kind: str

    @property
    def cost(self) -> float:
        return EDGE_COST.get(self.kind, DEFAULT_EDGE_COST)


@dataclass
class AttackPath:
    """One route from a starting principal to a target."""

    nodes: List[str] = field(default_factory=list)
    edges: List[Edge] = field(default_factory=list)

    @property
    def cost(self) -> float:
        return sum(e.cost for e in self.edges)

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def weakest_link(self) -> Optional[Edge]:
        """The edge most likely to fail — the one to verify first."""
        return max(self.edges, key=lambda e: e.cost) if self.edges else None

    def describe(self) -> str:
        if not self.nodes:
            return "(empty path)"
        parts = [self.nodes[0]]
        for edge, node in zip(self.edges, self.nodes[1:]):
            parts.append(f"--[{edge.kind}]-->")
            parts.append(node)
        return " ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": list(self.nodes), "length": self.length,
                "cost": round(self.cost, 2),
                "edges": [{"from": e.source, "to": e.target, "kind": e.kind}
                          for e in self.edges],
                "weakest_link": (self.weakest_link.kind
                                 if self.weakest_link else None)}


class ADGraph:
    """Directed graph of AD principals and the rights between them."""

    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self._out: Dict[str, List[Edge]] = defaultdict(list)
        self._in: Dict[str, List[Edge]] = defaultdict(list)

    # ── construction ─────────────────────────────────────────────────────────

    def add_node(self, name: str, kind: str = "Unknown", objectid: str = "",
                 properties: Optional[Dict[str, Any]] = None) -> Node:
        key = _norm(name)
        if not key:
            raise ValueError("node name cannot be empty")
        existing = self.nodes.get(key)
        if existing is None:
            existing = Node(name=key, kind=kind, objectid=objectid,
                            properties=dict(properties or {}))
            self.nodes[key] = existing
            return existing
        # A node can be referenced as an edge endpoint before its own record is
        # read, so later information fills in rather than replaces.
        if existing.kind in ("Unknown", "") and kind:
            existing.kind = kind
        if not existing.objectid and objectid:
            existing.objectid = objectid
        if properties:
            existing.properties.update(properties)
        return existing

    def add_edge(self, source: str, target: str, kind: str) -> Optional[Edge]:
        src, dst = _norm(source), _norm(target)
        if not src or not dst or src == dst:
            return None
        self.add_node(src)
        self.add_node(dst)
        edge = Edge(source=src, target=dst, kind=str(kind or "Unknown"))
        self._out[src].append(edge)
        self._in[dst].append(edge)
        return edge

    # ── queries ──────────────────────────────────────────────────────────────

    @property
    def edges(self) -> List[Edge]:
        return [e for edges in self._out.values() for e in edges]

    def out_edges(self, name: str) -> List[Edge]:
        return list(self._out.get(_norm(name), []))

    def in_edges(self, name: str) -> List[Edge]:
        return list(self._in.get(_norm(name), []))

    def find(self, substring: str) -> List[Node]:
        needle = _norm(substring)
        return [n for n in self.nodes.values() if needle in n.name]

    def high_value_targets(self) -> List[Node]:
        return sorted((n for n in self.nodes.values() if n.high_value),
                      key=lambda n: n.name)

    def kerberoastable(self) -> List[Node]:
        return sorted((n for n in self.nodes.values() if n.kerberoastable),
                      key=lambda n: n.name)

    def asrep_roastable(self) -> List[Node]:
        return sorted((n for n in self.nodes.values() if n.asrep_roastable),
                      key=lambda n: n.name)

    def unconstrained_delegation(self) -> List[Node]:
        return sorted((n for n in self.nodes.values()
                       if n.unconstrained_delegation), key=lambda n: n.name)

    # ── path finding ─────────────────────────────────────────────────────────

    def shortest_path(self, start: str, target: str,
                      max_cost: float = 30.0) -> Optional[AttackPath]:
        """Cheapest path from ``start`` to ``target``.

        Dijkstra over edge cost rather than hop count, so a long chain of
        certain steps beats a short chain that depends on a live session.
        """
        src, dst = _norm(start), _norm(target)
        if src not in self.nodes or dst not in self.nodes:
            return None
        if src == dst:
            return AttackPath(nodes=[src], edges=[])

        queue: List[Tuple[float, int, str, List[Edge]]] = [(0.0, 0, src, [])]
        best: Dict[str, float] = {src: 0.0}
        counter = 0

        while queue:
            cost, _, current, trail = heapq.heappop(queue)
            if current == dst:
                return AttackPath(nodes=[src] + [e.target for e in trail], edges=trail)
            if cost > max_cost or cost > best.get(current, float("inf")):
                continue
            for edge in self._out.get(current, []):
                new_cost = cost + edge.cost
                if new_cost > max_cost:
                    continue
                if new_cost < best.get(edge.target, float("inf")):
                    best[edge.target] = new_cost
                    counter += 1
                    heapq.heappush(queue, (new_cost, counter, edge.target,
                                           trail + [edge]))
        return None

    def paths_to_high_value(self, start: str, limit: int = 10,
                            max_cost: float = 30.0) -> List[AttackPath]:
        """Every reachable high-value target from one principal, cheapest first."""
        found: List[AttackPath] = []
        for target in self.high_value_targets():
            if _norm(start) == target.name:
                continue
            path = self.shortest_path(start, target.name, max_cost=max_cost)
            if path and path.edges:
                found.append(path)
        return sorted(found, key=lambda p: p.cost)[:limit]

    def owned_paths(self, owned: Sequence[str], limit: int = 10,
                    max_cost: float = 30.0) -> List[AttackPath]:
        """Paths from any principal you already control to anything high value."""
        found: List[AttackPath] = []
        for principal in owned:
            found.extend(self.paths_to_high_value(principal, limit=limit,
                                                  max_cost=max_cost))
        return sorted(found, key=lambda p: p.cost)[:limit]

    def choke_points(self, paths: Sequence[AttackPath], top: int = 5) -> List[Tuple[str, int]]:
        """Nodes appearing on the most paths — the highest-leverage fixes.

        This is the defensive read of the same graph: remove the choke point
        and many paths break at once.
        """
        counts: Dict[str, int] = defaultdict(int)
        for path in paths:
            for name in path.nodes[1:-1]:
                counts[name] += 1
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top]

    def summary(self) -> Dict[str, Any]:
        kinds: Dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            kinds[node.kind] += 1
        edge_kinds: Dict[str, int] = defaultdict(int)
        for edge in self.edges:
            edge_kinds[edge.kind] += 1
        return {
            "nodes": len(self.nodes), "edges": len(self.edges),
            "by_kind": dict(sorted(kinds.items())),
            "edge_types": dict(sorted(edge_kinds.items(), key=lambda kv: -kv[1])),
            "high_value": [n.name for n in self.high_value_targets()],
            "kerberoastable": [n.name for n in self.kerberoastable()],
            "asrep_roastable": [n.name for n in self.asrep_roastable()],
            "unconstrained_delegation": [n.name for n in self.unconstrained_delegation()],
        }


def _norm(name: Any) -> str:
    return str(name or "").strip().upper()


# ── BloodHound / SharpHound ingestion ────────────────────────────────────────

# SharpHound file kinds -> the node type they describe.
_FILE_KINDS = {
    "users": "User", "computers": "Computer", "groups": "Group",
    "domains": "Domain", "gpos": "GPO", "ous": "OU",
    "containers": "Container",
}

# Where each file kind stores its outbound relationships, and under what edge
# name. BloodHound's JSON nests these differently per type.
_MEMBER_KEYS = ("Members", "members")
_ACE_KEYS = ("Aces", "aces")


def ingest_bloodhound(paths: Iterable[Any], graph: Optional[ADGraph] = None) -> ADGraph:
    """Build a graph from SharpHound JSON files.

    Accepts the modern (v4/v5) shape, where each file has a ``data`` list and a
    ``meta`` block naming the type. Files that cannot be parsed are skipped with
    a warning rather than aborting the ingest — a collection is often partial.
    """
    import pathlib

    graph = graph or ADGraph()
    payloads = []
    for raw in paths:
        path = pathlib.Path(raw)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            log.warning("Skipping unreadable SharpHound file %s: %s", path, exc)
            continue
        if isinstance(payload, dict):
            payloads.append((payload, path.name.lower()))

    # Pass 1: every node with its SID, so pass 2 can resolve references.
    for payload, hint in payloads:
        _ingest_nodes(payload, graph, hint)
    # Pass 2: edges, now that every SID maps to a real principal.
    for payload, hint in payloads:
        _ingest_edges(payload, graph)
    return graph


def ingest_bloodhound_dir(directory: Any,
                          graph: Optional[ADGraph] = None) -> ADGraph:
    import pathlib
    root = pathlib.Path(directory)
    if not root.is_dir():
        log.warning("SharpHound directory %s does not exist", root)
        return graph or ADGraph()
    return ingest_bloodhound(sorted(root.glob("*.json")), graph)


def _kind_of(payload: Dict[str, Any], hint: str = "") -> str:
    meta = payload.get("meta") or {}
    kind = str(meta.get("type") or "").lower()
    if not kind:
        kind = next((k for k in _FILE_KINDS if k in hint), "")
    return _FILE_KINDS.get(kind, "Unknown")


def _ingest_nodes(payload: Dict[str, Any], graph: ADGraph, hint: str = "") -> None:
    """Pass 1: register principals and their SIDs."""
    node_kind = _kind_of(payload, hint)
    for entry in payload.get("data") or []:
        if not isinstance(entry, dict):
            continue
        props = entry.get("Properties") or entry.get("properties") or {}
        name = props.get("name") or entry.get("Name") or entry.get("ObjectIdentifier")
        if not name:
            continue
        graph.add_node(name, kind=node_kind,
                       objectid=str(entry.get("ObjectIdentifier", "")),
                       properties={str(k).lower(): v for k, v in props.items()})


def _ingest_edges(payload: Dict[str, Any], graph: ADGraph, hint: str = "") -> None:
    for entry in payload.get("data") or []:
        if not isinstance(entry, dict):
            continue
        props = entry.get("Properties") or entry.get("properties") or {}
        name = props.get("name") or entry.get("Name") or entry.get("ObjectIdentifier")
        if not name:
            continue

        # Group membership: BloodHound stores members on the group.
        for key in _MEMBER_KEYS:
            for member in entry.get(key) or []:
                member_name = (member.get("ObjectIdentifier")
                               if isinstance(member, dict) else member)
                member_kind = (member.get("ObjectType", "Unknown")
                               if isinstance(member, dict) else "Unknown")
                resolved = _resolve(graph, member_name, member_kind)
                if resolved:
                    graph.add_edge(resolved, name, "MemberOf")

        # ACEs: a principal holds a right *over* this object.
        for key in _ACE_KEYS:
            for ace in entry.get(key) or []:
                if not isinstance(ace, dict):
                    continue
                principal = ace.get("PrincipalSID") or ace.get("PrincipalName")
                right = ace.get("RightName") or ace.get("rightname") or "Unknown"
                resolved = _resolve(graph, principal,
                                    ace.get("PrincipalType", "Unknown"))
                if resolved:
                    graph.add_edge(resolved, name, str(right))

        # Sessions and local admin, stored on computers.
        for field_name, edge_kind in (("Sessions", "HasSession"),
                                      ("LocalAdmins", "AdminTo"),
                                      ("RemoteDesktopUsers", "CanRDP"),
                                      ("PSRemoteUsers", "CanPSRemote"),
                                      ("DcomUsers", "ExecuteDCOM")):
            block = entry.get(field_name)
            results = (block.get("Results") if isinstance(block, dict) else block) or []
            for item in results:
                if not isinstance(item, dict):
                    continue
                principal = (item.get("UserSID") or item.get("ObjectIdentifier")
                             or item.get("UserName"))
                resolved = _resolve(graph, principal,
                                    item.get("ObjectType", "Unknown"))
                if not resolved:
                    continue
                if edge_kind == "HasSession":
                    # A session means the computer holds the user's credentials.
                    graph.add_edge(name, resolved, "HasSession")
                else:
                    graph.add_edge(resolved, name, edge_kind)


def _resolve(graph: ADGraph, identifier: Any, kind: str = "Unknown") -> str:
    """Map a SID or name onto a graph node name.

    SharpHound references principals by SID in some places and by name in
    others; unresolved SIDs are kept as nodes so the path is not silently
    broken by a lookup failure.
    """
    value = str(identifier or "").strip()
    if not value:
        return ""
    index = getattr(graph, "_sid_index", None)
    if index is None:
        index = {n.objectid.upper(): n.name
                 for n in graph.nodes.values() if n.objectid}
        graph._sid_index = index          # noqa: SLF001 - ingest-time cache
    hit = index.get(value.upper())
    if hit:
        return hit
    if _norm(value) in graph.nodes:
        return _norm(value)
    # An unresolved SID is kept rather than dropped, so a partial collection
    # still yields a path with one opaque hop instead of no path at all.
    graph.add_node(value, kind=kind or "Unknown")
    return _norm(value)


# ── Enumeration ingestion ────────────────────────────────────────────────────

def ingest_ldap_evidence(evidence: Dict[str, Any],
                         graph: Optional[ADGraph] = None) -> ADGraph:
    """Build a partial graph from CyberSwarm's own LDAP/SMB enumeration.

    Far thinner than SharpHound — anonymous LDAP rarely exposes ACLs — but it
    means the AD agent produces something on a target where no SharpHound
    collection exists.
    """
    graph = graph or ADGraph()
    if not isinstance(evidence, dict):
        return graph

    def _listy(*keys) -> list:
        """A field that should be a list. A bare string would otherwise be
        iterated character by character, inventing one node per letter."""
        for key in keys:
            value = evidence.get(key)
            if isinstance(value, (list, tuple)):
                return list(value)
        return []

    domain = str(evidence.get("domain") or evidence.get("ldap_domain") or "").upper()
    if domain:
        graph.add_node(domain, kind="Domain")

    for user in _listy("ldap_users", "users"):
        name = user.get("name") if isinstance(user, dict) else user
        if not name:
            continue
        props = {str(k).lower(): v for k, v in user.items()} if isinstance(user, dict) else {}
        node = graph.add_node(name, kind="User", properties=props)
        groups = user.get("groups") if isinstance(user, dict) else None
        for group in groups if isinstance(groups, (list, tuple)) else []:
            if group:
                graph.add_edge(node.name, group, "MemberOf")

    for group in _listy("ldap_groups", "groups"):
        name = group.get("name") if isinstance(group, dict) else group
        if name:
            graph.add_node(name, kind="Group")

    for computer in _listy("ldap_computers", "computers"):
        name = computer.get("name") if isinstance(computer, dict) else computer
        if name:
            graph.add_node(name, kind="Computer")

    return graph
