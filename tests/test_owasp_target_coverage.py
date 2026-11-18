"""Per-target OWASP coverage: honest status, verdict counts, and the reasons
findings did not hold up. Pure over evidence dicts -- no tools or model."""

import json
from pathlib import Path

import owasp_registry as o
from generate_attack_report import owasp_for

ROOT = Path(__file__).resolve().parent.parent
WOLT = ROOT / "results" / "attack_evidence" / "wolt.com.json"


def _run(agent, tools_run, findings=(), status="success"):
    return {"agent": agent, "status": status, "tools_run": list(tools_run),
            "findings": list(findings)}


def _f(name, tool, verdict="NEEDS_PROOF", evidence=True, proofs=None, desc=""):
    d = {"name": name, "tool": tool, "verdict": verdict, "description": desc,
         "proofs": proofs or []}
    if evidence:
        d["evidence_chain"] = [f"[{tool}] output"]
        d["raw_output_excerpt"] = "output"
    return d


def _codes(rows):
    return {r["code"]: r for r in rows}


def test_tool_match_is_one_directional():
    # a specific run satisfies a generic registry tool ...
    assert o._tool_matches("nuclei", "nuclei_takeover")
    assert o._tool_matches("nuclei", "nuclei")
    # ... but a generic run does NOT satisfy a specific registry tool
    assert not o._tool_matches("nuclei_ssrf", "nuclei")
    assert not o._tool_matches("nuclei_sqli", "nuclei")


def test_status_tested_only_with_real_tool():
    ev = {"agent_runs": [
        _run("web_attack", ["dalfox(https://x)", "sqlmap(https://x)"],
             [_f("Reflected XSS (Dalfox)", "dalfox", "DISPUTE")]),
    ]}
    rows = _codes(o.per_target_coverage(ev, classify=owasp_for))
    assert rows["A03"]["status"] == "tested"
    assert "dalfox" in rows["A03"]["tools_ran"]
    assert rows["A03"]["disputed"] == 1
    # categories whose tools never ran are honestly "not_tested"
    assert rows["A10"]["status"] == "not_tested"
    assert rows["A10"]["tools_ran"] == []


def test_generic_nuclei_does_not_claim_ssrf_or_injection():
    ev = {"agent_runs": [_run("web_attack", ["nuclei(tags=http,cloud)"])]}
    rows = _codes(o.per_target_coverage(ev, classify=owasp_for))
    assert rows["A06"]["status"] == "tested"        # generic nuclei == A06 tool
    assert rows["A10"]["status"] == "not_tested"    # SSRF templates not run
    assert rows["A03"]["status"] == "not_tested"    # injection templates not run


def test_model_written_finding_is_attempted_not_tested():
    # no evidence_chain / raw_output -> evidence-gated, no real tool
    ev = {"agent_runs": [_run("insecure_design", [],
          [_f("No obvious insecure-design flaws", "analysis", "NEEDS_PROOF",
              evidence=False, desc="[EVIDENCE GATE]: No real tool output behind this finding.")])]}
    rows = _codes(o.per_target_coverage(ev, classify=owasp_for))
    assert rows["A04"]["status"] == "attempted"
    assert rows["A04"]["unproven"] == 1


def test_proven_vs_confirmed_counts():
    ev = {"agent_runs": [_run("web_attack", ["xss_proof"], [
        _f("Reflected XSS proven", "xss_proof", "CONFIRM", proofs=[{"proven": True}]),
        _f("SQLi likely", "sqlmap", "CONFIRM"),   # confirmed, no proof artefact
    ])]}
    rows = _codes(o.per_target_coverage(ev, classify=owasp_for))
    assert rows["A03"]["proven"] == 1
    assert rows["A03"]["confirmed"] == 1


def test_reasons_are_surfaced():
    ev = {"agent_runs": [_run("web_attack", ["sqlmap"], [
        _f("SQL Injection (sqlmap)", "sqlmap", "DISPUTE",
           desc="\n[CRITIC]: raw output explicitly states no vulnerabilities were found.")])]}
    rows = _codes(o.per_target_coverage(ev, classify=owasp_for))
    assert any("CRITIC" in r for r in rows["A03"]["reasons"])


def test_render_is_markdown_and_counts_tested():
    ev = {"agent_runs": [_run("web_attack", ["dalfox", "sqlmap"],
          [_f("x", "dalfox", "DISPUTE")])]}
    md = o.render_target_coverage(ev, classify=owasp_for)
    assert "OWASP Top 10 — Per-Target Coverage" in md
    assert "| A03" in md and "tested" in md


def test_all_ten_categories_present_even_when_empty():
    rows = o.per_target_coverage({}, classify=owasp_for)
    assert [r["code"] for r in rows] == [f"A{i:02d}" for i in range(1, 11)]
    assert all(r["status"] == "not_tested" for r in rows)


def test_a09_a10_labels_match_official_2021_order():
    import generate_attack_report as gar
    assert "Logging" in gar.OWASP_LABELS["A09"]
    assert "Request Forgery" in gar.OWASP_LABELS["A10"]
    assert gar.owasp_for({"finding_type": "server_side_request_forgery"}) == "A10"


def test_real_wolt_evidence_reads_honestly():
    if not WOLT.exists():
        return
    ev = json.loads(WOLT.read_text())
    rows = _codes(o.per_target_coverage(ev, classify=owasp_for))
    assert rows["A03"]["status"] == "tested"          # dalfox + sqlmap ran
    assert sum(r["proven"] for r in rows.values()) == 0   # nothing proven on a WAF'd target
    assert rows["A03"]["reasons"]                      # and we say why
