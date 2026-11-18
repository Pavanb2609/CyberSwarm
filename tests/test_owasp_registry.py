"""Tests for the OWASP Top-10 coverage registry (owasp_registry.py)."""

import owasp_registry
from owasp_registry import (OWASP_TOP_10, canonical, category_agents,
                            category_exploits, category_tools,
                            coverage_report)


def test_all_ten_categories_present():
    for i in range(1, 11):
        code = f"A{i:02d}"
        assert code in OWASP_TOP_10, f"{code} missing"
        assert OWASP_TOP_10[code]["title"]


def test_every_category_has_agents_and_tools():
    for entry in OWASP_TOP_10.values():
        assert entry["agents"], f"{entry['title']} has no owning agent"
        assert entry["tools"], f"{entry['title']} has no tool coverage"


def test_exploitative_categories_carry_exploit_tools():
    # The whole point of the Top-10 implementation is *proving* findings, so
    # every category that can be exploited must name a real exploit tool.
    for code in ("A01", "A02", "A03", "A05", "A06", "A07", "A08", "A10"):
        assert category_exploits(code), f"{code} must have exploit tool(s)"


def test_identity_expressions():
    assert canonical("A03") == "A03"
    assert canonical("A3") == "A03"
    assert canonical("A-03") == "A03"
    assert canonical("A10") == "A10"
    assert canonical("a01") == "A01"


def test_category_accessors():
    assert "xss_exploit" in OWASP_TOP_10["A03"]["agents"]
    assert "idor_test" in category_tools("A01")
    assert "ssrf_exploit" in category_exploits("A10")


def test_coverage_report_shape():
    rows = coverage_report()
    assert len(rows) == 10
    by_code = {r["code"]: r for r in rows}
    for i in range(1, 11):
        code = f"A{i:02d}"
        r = by_code[code]
        assert r["title"]
        assert isinstance(r["agents"], list) and r["agents"]
        assert r["actions"] >= 0 and r["tools"] > 0
        assert r["exploitable"] == bool(r["exploits"])


def test_load_attack_tools_resolves_category():
    # A03 (Injection) must resolve its widest wheelhouse without raising,
    # even when no binary is installed — availability is runtime-gated.
    tools = owasp_registry.load_attack_tools_for_category("A03")
    assert any(t.name == "nosql_inj" for t in tools)
    assert any(t.name == "ldap_inj" for t in tools)
    assert any(t.name == "xss_proof" for t in tools)