from typing import Any, Dict, List, Optional

from tools.base import Tool, ToolResult

LDAP_PORTS = {389, 636, 3268, 3269}

# userAccountControl bits that matter for AD exploitation posture
UF_DONT_REQUIRE_PREAUTH = 0x400000  # AS-REP roastable
UF_ACCOUNTDISABLE = 0x0002          # disabled accounts are not roastable targets
_MAX_USERS = 500                    # bound the anonymous pull per DC


def _domain_from_contexts(naming_contexts: List[str]) -> str:
    """DC=ent,DC=local -> 'ent.local'."""
    for nc in naming_contexts or []:
        parts = []
        for seg in str(nc).split(","):
            seg = seg.strip()
            if seg.lower().startswith("dc="):
                parts.append(seg[3:])
        if parts:
            return ".".join(parts)
    return ""


def _dn_cn(dn: str) -> str:
    """'CN=Domain Admins,CN=Groups,DC=ent,DC=local' -> 'Domain Admins'."""
    for part in (str(dn or "").split(",")):
        if part.strip().lower().startswith("cn="):
            return part.strip()[3:]
    return str(dn) or ""


def _uac_flags(uac) -> Dict[str, bool]:
    try:
        value = int(uac or 0)
    except (TypeError, ValueError):
        return {"value": 0, "disabled": False, "dont_require_preauth": False,
                "account_enabled": True}
    return {
        "value": value,
        "disabled": bool(value & UF_ACCOUNTDISABLE),
        "dont_require_preauth": bool(value & UF_DONT_REQUIRE_PREAUTH),
        "account_enabled": not bool(value & UF_ACCOUNTDISABLE),
    }


class DirectoryServiceEnumerationTool(Tool):
    """
    Queries the LDAP RootDSE anonymously (no bind credentials) to pull
    naming contexts, domain functional level, and the DC's advertised
    hostname -- standard low-impact AD recon, works even against servers
    that reject anonymous binds (the RootDSE itself is usually still
    readable). Uses the `ldap3` Python library, no external binary. Gated:
    only runs if PORT_DISCOVERY already found an LDAP port open -- matches
    the planner prompt's rule that this capability needs LDAP/Kerberos/SMB
    evidence, not plausibility.
    """

    name = "ldap_enum"
    capability = "DIRECTORY_SERVICE_ENUMERATION"
    binary = ""

    def is_available(self) -> bool:
        try:
            import ldap3  # noqa: F401
            return True
        except ImportError:
            return False

    def validate(self) -> Optional[str]:
        try:
            import ldap3  # noqa: F401
        except ImportError:
            return "ldap3 is not installed (pip install ldap3)"
        return None

    def build_command(self, target: str, **kwargs) -> List[str]:
        return []

    def parse(self, stdout: str, stderr: str) -> Dict[str, Any]:
        return {}

    def run(self, target: str, timeout: int = 180, **kwargs) -> ToolResult:
        ports_str = kwargs.get("ports") or ""
        open_ports = {int(p) for p in ports_str.split(",") if p.strip().isdigit()}
        relevant = open_ports & LDAP_PORTS
        if not relevant:
            return ToolResult(
                tool=self.name, status="success", capability=self.capability,
                results={"directory_enum_skipped": True,
                         "reason": "None of the known LDAP ports (389, 636, 3268, 3269) are in "
                                   "open_ports -- skipping rather than probing blind."},
            )

        import ldap3

        host = target.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
        port = min(relevant)
        use_ssl = port in (636, 3269)

        try:
            server = ldap3.Server(host, port=port, use_ssl=use_ssl, get_info=ldap3.ALL,
                                   connect_timeout=kwargs.get("per_request_timeout", 6))
            conn = ldap3.Connection(server, auto_bind=True)  # anonymous bind
        except Exception as e:
            return ToolResult(tool=self.name, status="error", capability=self.capability,
                               error=f"LDAP connection/bind failed: {e}")

        info = server.info
        naming_contexts = list(info.naming_contexts) if info and info.naming_contexts else []
        root_dse = {
            "default_naming_context": getattr(info, "other", {}).get("defaultNamingContext", [None])[0]
                if info and info.other else None,
            "dns_host_name": getattr(info, "other", {}).get("dnsHostName", [None])[0]
                if info and info.other else None,
            "domain_functionality": getattr(info, "other", {}).get("domainFunctionality", [None])[0]
                if info and info.other else None,
            "forest_functionality": getattr(info, "other", {}).get("forestFunctionality", [None])[0]
                if info and info.other else None,
            "supported_ldap_versions": list(info.supported_ldap_versions) if info else [],
        }
        domain = kwargs.get("domain") or _domain_from_contexts(naming_contexts)

        # Extend the anonymous connection into a shallow object pull. DCs that
        # refuse anonymous searches today (recent Windows) decline with an error
        # and we fall back to RootDSE-only — never a crash.
        users, groups, computers = [], [], []
        if conn.bound:
            users, groups, computers = self._extract(conn, naming_contexts,
                                                     timeout=kwargs.get("per_request_timeout", 6))
        conn.unbind()

        kerberoastable = [
            {"name": u.get("name"), "spn": u.get("spns", [])[:3]}
            for u in users if u.get("has_spn")]
        asrep_roastable = [
            {"name": u.get("name")}
            for u in users if u.get("dont_require_preauth") and not u.get("disabled")]

        return ToolResult(
            tool=self.name, status="success", capability=self.capability,
            results={
                "ldap_anonymous_bind": True,
                "ldap_naming_contexts": naming_contexts,
                "ldap_root_dse": root_dse,
                "ldap_domain": domain,
                "ldap_users": users,
                "ldap_groups": groups,
                "ldap_computers": computers[:200],
                "ldap_kerberoastable": kerberoastable,
                "ldap_asrep_roastable": asrep_roastable,
            },
        )

    # ── anonymous object extraction ──────────────────────────────────────────

    @staticmethod
    def _extract(conn, naming_contexts: List[str], timeout: int = 6):
        """Determine a base DN, then pull users/groups/computers anonymously.

        Returns ([user_dict], [group_dict], [computer_dict]). Any search that is
        denied is skipped and the rest still runs. All attributes requested are
        read-only; nothing is modified."""
        import ldap3

        base = next((nc for nc in naming_contexts if str(nc).upper().startswith("DC=")), None)
        if not base:
            return [], [], []

        out_users, out_groups, out_computers = [], [], []

        def _search(filter_, attributes, limit):
            try:
                conn.search(
                    base, filter_, attributes=attributes,
                    search_scope=ldap3.SUBTREE, size_limit=limit, time_limit=timeout)
                return conn.entries if conn.entries else []
            except Exception:  # noqa: BLE001 - anonymous search refused -> empty
                return []

        for entry in _search("(&(objectClass=user)(objectCategory=person))",
                             ["sAMAccountName", "userAccountControl", "servicePrincipalName",
                              "memberOf", "mail", "description", "userPrincipalName"],
                             _MAX_USERS):
            attrs = entry.entry_attributes_as_dict if hasattr(entry, "entry_attributes_as_dict") else {}
            uac = attrs.get("userAccountControl", [0])
            uac_value = int(uac[0]) if uac else 0
            flags = _uac_flags(uac_value)
            spns = [str(s) for s in (attrs.get("servicePrincipalName") or [])]
            groups = [_dn_cn(g) for g in (attrs.get("memberOf") or [])]
            sam = str(attrs.get("sAMAccountName", [""])[0] or "") or str(entry.entry_dn)
            out_users.append({
                "name": sam,
                "sam_account_name": sam,
                "user_principal_name": str(attrs.get("userPrincipalName", [""])[0] or ""),
                "uac": uac_value,
                "disabled": flags["disabled"],
                "dont_require_preauth": flags["dont_require_preauth"],
                "has_spn": bool(spns),
                "spns": spns[:10],
                "groups": [g for g in groups if g][:30],
                "mail": str(attrs.get("mail", [""])[0] or ""),
                "description": str(attrs.get("description", [""])[0] or "")[:200],
            })

        for entry in _search("(objectClass=group)",
                             ["cn", "member"], _MAX_USERS):
            attrs = entry.entry_attributes_as_dict if hasattr(entry, "entry_attributes_as_dict") else {}
            cn = str(attrs.get("cn", [""])[0] or "") or str(entry.entry_dn)
            out_groups.append({
                "name": cn,
                "members": [_dn_cn(m)
                            for m in (attrs.get("member") or [])][:30],
            })

        for entry in _search("(objectClass=computer)",
                             ["dNSHostName", "operatingSystem", "sAMAccountName"], 200):
            attrs = entry.entry_attributes_as_dict if hasattr(entry, "entry_attributes_as_dict") else {}
            out_computers.append({
                "name": str(attrs.get("sAMAccountName", [""])[0] or "") or str(entry.entry_dn),
                "dns_hostname": str(attrs.get("dNSHostName", [""])[0] or ""),
                "operating_system": str(attrs.get("operatingSystem", [""])[0] or "")[:80],
            })

        return out_users, out_groups, out_computers
