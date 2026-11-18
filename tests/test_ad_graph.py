"""Tests for ad_graph.py and the ADAgent.

The two things most likely to be wrong in this kind of code are SID resolution
(references arrive before the records they point at) and path cost (a short
flaky route must not beat a long certain one). Most of this file is those.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ad_graph as ad  # noqa: E402
from agents.ad_agent import ADAgent  # noqa: E402

DOM = "NORTH.SEVENKINGDOMS.LOCAL"


def _graph():
    g = ad.ADGraph()
    g.add_node(f"ARYA@{DOM}", "User", "S-1-1107")
    g.add_node(f"HELPDESK@{DOM}", "Group", "S-1-2002")
    g.add_node(f"STARK ADMINS@{DOM}", "Group", "S-1-2001")
    g.add_node(f"DOMAIN ADMINS@{DOM}", "Group", "S-1-512", {"highvalue": True})
    g.add_edge(f"ARYA@{DOM}", f"HELPDESK@{DOM}", "MemberOf")
    g.add_edge(f"HELPDESK@{DOM}", f"STARK ADMINS@{DOM}", "GenericAll")
    g.add_edge(f"STARK ADMINS@{DOM}", f"DOMAIN ADMINS@{DOM}", "MemberOf")
    return g


# ── Graph basics ─────────────────────────────────────────────────────────────

def test_names_are_normalised():
    g = ad.ADGraph()
    g.add_node("alice@corp.local", "User")
    assert "ALICE@CORP.LOCAL" in g.nodes
    assert g.shortest_path("alice@corp.local", "ALICE@CORP.LOCAL").length == 0


def test_repeated_add_enriches_rather_than_replaces():
    """Nodes are referenced as edge endpoints before their own record is read."""
    g = ad.ADGraph()
    g.add_node("BOB@CORP", "Unknown")
    g.add_node("BOB@CORP", "User", "S-1-9", {"hasspn": True})
    node = g.nodes["BOB@CORP"]
    assert node.kind == "User"
    assert node.objectid == "S-1-9"
    assert node.kerberoastable is True


def test_self_and_empty_edges_are_rejected():
    g = ad.ADGraph()
    assert g.add_edge("A@X", "A@X", "MemberOf") is None
    assert g.add_edge("", "B@X", "MemberOf") is None
    assert g.edges == []


def test_high_value_by_name_or_flag():
    g = ad.ADGraph()
    g.add_node("DOMAIN ADMINS@CORP", "Group")
    g.add_node("RANDOM@CORP", "Group", properties={"highvalue": True})
    g.add_node("PLAIN@CORP", "Group")
    names = {n.name for n in g.high_value_targets()}
    assert names == {"DOMAIN ADMINS@CORP", "RANDOM@CORP"}


# ── Path finding ─────────────────────────────────────────────────────────────

def test_finds_a_multi_hop_path():
    path = _graph().shortest_path(f"ARYA@{DOM}", f"DOMAIN ADMINS@{DOM}")
    assert path is not None
    assert path.length == 3
    assert path.nodes[-1] == f"DOMAIN ADMINS@{DOM}"


def test_reliable_path_beats_a_shorter_flaky_one():
    """A HasSession hop may evaporate; three certain hops should win."""
    g = _graph()
    g.add_edge(f"ARYA@{DOM}", f"DOMAIN ADMINS@{DOM}", "HasSession")
    path = g.shortest_path(f"ARYA@{DOM}", f"DOMAIN ADMINS@{DOM}")
    assert path.length == 3, "cost, not hop count, must drive the search"
    assert ad.EDGE_COST["HasSession"] > ad.EDGE_COST["MemberOf"] * 3


def test_weakest_link_is_the_costliest_edge():
    assert _graph().shortest_path(
        f"ARYA@{DOM}", f"DOMAIN ADMINS@{DOM}").weakest_link.kind == "GenericAll"


def test_no_path_returns_none():
    g = _graph()
    g.add_node(f"ORPHAN@{DOM}", "User")
    assert g.shortest_path(f"ORPHAN@{DOM}", f"DOMAIN ADMINS@{DOM}") is None


def test_unknown_endpoints_return_none():
    assert _graph().shortest_path("NOBODY@X", f"DOMAIN ADMINS@{DOM}") is None


def test_max_cost_bounds_the_search():
    assert _graph().shortest_path(f"ARYA@{DOM}", f"DOMAIN ADMINS@{DOM}",
                                  max_cost=1.0) is None


def test_cycles_do_not_hang():
    g = ad.ADGraph()
    g.add_node("DOMAIN ADMINS@CORP", "Group", properties={"highvalue": True})
    for a, b in (("A@CORP", "B@CORP"), ("B@CORP", "C@CORP"), ("C@CORP", "A@CORP")):
        g.add_edge(a, b, "MemberOf")
    assert g.shortest_path("A@CORP", "DOMAIN ADMINS@CORP") is None


def test_paths_to_high_value_sorted_by_cost():
    paths = _graph().paths_to_high_value(f"ARYA@{DOM}")
    assert len(paths) == 1
    assert paths[0].cost == pytest.approx(3.0)


def test_choke_points_rank_shared_intermediates():
    g = _graph()
    g.add_edge(f"SANSA@{DOM}", f"HELPDESK@{DOM}", "MemberOf")
    paths = g.paths_to_high_value(f"ARYA@{DOM}") + g.paths_to_high_value(f"SANSA@{DOM}")
    chokes = dict(g.choke_points(paths))
    assert chokes[f"HELPDESK@{DOM}"] == 2


def test_path_serialises():
    payload = _graph().shortest_path(f"ARYA@{DOM}", f"DOMAIN ADMINS@{DOM}").to_dict()
    assert payload["length"] == 3
    assert payload["weakest_link"] == "GenericAll"


# ── Account exposures ────────────────────────────────────────────────────────

def test_exposure_flags_read_from_properties():
    g = ad.ADGraph()
    g.add_node("SVC@CORP", "User", properties={"hasspn": True})
    g.add_node("NOPREAUTH@CORP", "User", properties={"dontreqpreauth": True})
    g.add_node("DC@CORP", "Computer", properties={"unconstraineddelegation": True})
    assert [n.name for n in g.kerberoastable()] == ["SVC@CORP"]
    assert [n.name for n in g.asrep_roastable()] == ["NOPREAUTH@CORP"]
    assert [n.name for n in g.unconstrained_delegation()] == ["DC@CORP"]


def test_computers_are_not_kerberoastable():
    """The flag is a user-account property; computers always have SPNs."""
    g = ad.ADGraph()
    g.add_node("WS01@CORP", "Computer", properties={"hasspn": True})
    assert g.kerberoastable() == []


# ── BloodHound ingestion ─────────────────────────────────────────────────────

@pytest.fixture
def sharphound(tmp_path):
    (tmp_path / "users.json").write_text(json.dumps({"meta": {"type": "users"}, "data": [
        {"ObjectIdentifier": "S-1-1107", "Properties": {"name": f"ARYA@{DOM}", "enabled": True}},
        {"ObjectIdentifier": "S-1-1105", "Properties": {"name": f"ROBB@{DOM}", "hasspn": True}},
    ]}), encoding="utf-8")
    (tmp_path / "groups.json").write_text(json.dumps({"meta": {"type": "groups"}, "data": [
        {"ObjectIdentifier": "S-1-512",
         "Properties": {"name": f"DOMAIN ADMINS@{DOM}", "highvalue": True},
         "Members": [{"ObjectIdentifier": "S-1-2001", "ObjectType": "Group"}]},
        {"ObjectIdentifier": "S-1-2001", "Properties": {"name": f"STARK ADMINS@{DOM}"},
         "Aces": [{"PrincipalSID": "S-1-2002", "PrincipalType": "Group",
                   "RightName": "GenericAll"}]},
        {"ObjectIdentifier": "S-1-2002", "Properties": {"name": f"HELPDESK@{DOM}"},
         "Members": [{"ObjectIdentifier": "S-1-1107", "ObjectType": "User"}]},
    ]}), encoding="utf-8")
    return tmp_path


def test_ingest_builds_a_connected_graph(sharphound):
    """SIDs are referenced before their records are read; a single-pass ingest
    created one node per SID and a second per name, leaving no path."""
    g = ad.ingest_bloodhound_dir(sharphound)
    path = g.shortest_path(f"ARYA@{DOM}", f"DOMAIN ADMINS@{DOM}")
    assert path is not None, "SID references must resolve to named principals"
    assert path.length == 3


def test_ingest_resolves_sids_not_duplicates(sharphound):
    g = ad.ingest_bloodhound_dir(sharphound)
    assert not [n for n in g.nodes if n.startswith("S-1-")], \
        "every referenced SID should have resolved to a principal"


def test_ingest_reads_properties(sharphound):
    g = ad.ingest_bloodhound_dir(sharphound)
    assert [n.name for n in g.kerberoastable()] == [f"ROBB@{DOM}"]
    assert [n.name for n in g.high_value_targets()] == [f"DOMAIN ADMINS@{DOM}"]


def test_ingest_maps_ace_rights_to_edges(sharphound):
    g = ad.ingest_bloodhound_dir(sharphound)
    assert any(e.kind == "GenericAll" for e in g.edges)


def test_sessions_point_from_computer_to_user(tmp_path):
    """A session means the computer holds the user's credentials, not the reverse."""
    (tmp_path / "computers.json").write_text(json.dumps({"meta": {"type": "computers"}, "data": [
        {"ObjectIdentifier": "S-1-1001", "Properties": {"name": f"WINTERFELL@{DOM}"},
         "Sessions": {"Results": [{"UserSID": "S-1-1105"}]}}]}), encoding="utf-8")
    (tmp_path / "users.json").write_text(json.dumps({"meta": {"type": "users"}, "data": [
        {"ObjectIdentifier": "S-1-1105", "Properties": {"name": f"ROBB@{DOM}"}}]}),
        encoding="utf-8")
    g = ad.ingest_bloodhound_dir(tmp_path)
    session = next(e for e in g.edges if e.kind == "HasSession")
    assert session.source == f"WINTERFELL@{DOM}"
    assert session.target == f"ROBB@{DOM}"


def test_unreadable_files_are_skipped(tmp_path):
    (tmp_path / "broken.json").write_text("{ not json", encoding="utf-8")
    (tmp_path / "users.json").write_text(json.dumps({"meta": {"type": "users"}, "data": [
        {"ObjectIdentifier": "S-1", "Properties": {"name": f"A@{DOM}"}}]}), encoding="utf-8")
    assert len(ad.ingest_bloodhound_dir(tmp_path).nodes) == 1


def test_missing_directory_is_not_an_error(tmp_path):
    assert ad.ingest_bloodhound_dir(tmp_path / "absent").nodes == {}


def test_ldap_evidence_ingest():
    g = ad.ingest_ldap_evidence({
        "domain": "corp.local",
        "ldap_users": [{"name": "ALICE@CORP.LOCAL", "groups": ["HELPDESK@CORP.LOCAL"]}],
        "ldap_groups": ["HELPDESK@CORP.LOCAL"]})
    assert "ALICE@CORP.LOCAL" in g.nodes
    assert any(e.kind == "MemberOf" for e in g.edges)


def test_ldap_evidence_tolerates_junk():
    assert ad.ingest_ldap_evidence(None).nodes == {}
    assert ad.ingest_ldap_evidence({"ldap_users": "nope"}).nodes == {}


# ── Agent ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("smap,expected", [
    ({"services": [{"port": 389, "service": "ldap"}]}, True),
    ({"services": [{"port": 88, "service": "kerberos"}]}, True),
    ({"signals": {"ad": True}}, True),
    ({"completed_actions": ["DIRECTORY_SERVICE_ENUMERATION"]}, True),
    ({"services": [{"port": 443, "service": "https"}]}, False),
    ({}, False),
])
def test_should_run_detects_domain_targets(smap, expected):
    assert ADAgent(None).should_run(smap) is expected


def test_agent_reports_paths_and_exposures(sharphound):
    result = ADAgent(None).run(
        "north.local", {"services": [{"port": 389, "service": "ldap"}]},
        {"config": {"ad": {"sharphound_dir": str(sharphound)}}})
    assert result.status == "success"
    names = [f.name for f in result.findings]
    assert any("attack path" in n for n in names)
    assert any("Kerberoastable" in n for n in names)


def test_agent_findings_carry_the_path_as_evidence(sharphound):
    result = ADAgent(None).run(
        "north.local", {"services": [{"port": 389, "service": "ldap"}]},
        {"config": {"ad": {"sharphound_dir": str(sharphound)}}})
    path_finding = next(f for f in result.findings if "attack path" in f.name)
    assert "MemberOf" in path_finding.description
    assert path_finding.raw_output_excerpt


def test_agent_states_the_path_was_not_walked(sharphound):
    """Severity must not imply the path was executed."""
    result = ADAgent(None).run(
        "north.local", {"services": [{"port": 389, "service": "ldap"}]},
        {"config": {"ad": {"sharphound_dir": str(sharphound)}}})
    path_finding = next(f for f in result.findings if "attack path" in f.name)
    assert "not been walked" in path_finding.description


def test_agent_without_sharphound_still_succeeds():
    result = ADAgent(None).run(
        "north.local", {"services": [{"port": 389, "service": "ldap"}]}, {})
    assert result.status == "success"
    assert "SharpHound" in result.reasoning


def test_agent_reports_no_tickets_were_requested(sharphound):
    """The tool enumerates exposure; it does not roast anything."""
    result = ADAgent(None).run(
        "north.local", {"services": [{"port": 389, "service": "ldap"}]},
        {"config": {"ad": {"sharphound_dir": str(sharphound)}}})
    roast = next(f for f in result.findings if "Kerberoastable" in f.name)
    assert "no tickets were requested" in roast.description.lower()


def test_agent_is_registered():
    from agents import registry
    mapping = (getattr(registry, "AGENT_REGISTRY", None)
               or getattr(registry, "AGENTS", {}))
    assert "ad" in mapping
