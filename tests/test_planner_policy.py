"""planner_policy: deterministic rules planner, guardrails over LLM decisions,
and the plan() pipeline (structured call -> repair retry -> rules fallback)."""

import json
from pathlib import Path

import pytest

import planner_policy as pp
from schema.validator import validate_decision

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = json.loads((ROOT / "scenarios" / "scenarios.json").read_text())


def _web(**kw):
    ev = {"target": "app.example", "authorized_scope": True, "target_type": "domain",
          "reachable": True, "open_ports": [80, 443], "services": ["http", "https"],
          "technologies": ["Nginx"], "completed_actions": [
              "PORT_DISCOVERY", "SERVICE_DETECTION", "WEB_PROBING", "WEB_TECHNOLOGY_DISCOVERY"],
          "failed_actions": [], "previous_observations": []}
    ev.update(kw)
    return ev


def _llm(cap, profile="WEB_APPLICATION", **kw):
    d = {"target_profile": profile, "next_capability": cap, "confidence": 0.8,
         "evidence_used": [], "missing_evidence": [], "reason": "model reason",
         "requires_human_approval": False}
    d.update(kw)
    return d


# ── rules planner ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("sc", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_rules_planner_matches_every_scenario(sc):
    d = pp.rules_decision(sc["evidence"])
    assert d["next_capability"] in sc["expected_capabilities"]
    assert d["target_profile"] in sc["expected_profiles"]
    ok, _, errors = validate_decision(json.dumps(d))
    assert ok, errors  # the fallback must itself be schema-valid


def test_scenarios_have_rules_and_unique_ids():
    ids = [s["id"] for s in SCENARIOS]
    assert len(ids) == len(set(ids))
    assert len(SCENARIOS) >= 50


def test_rules_never_repeat_done_capabilities():
    for sc in SCENARIOS:
        ev = sc["evidence"]
        done = set(ev.get("completed_actions", [])) | set(ev.get("failed_actions", [])) \
            | set(ev.get("zero_findings_actions", []))
        cap = pp.rules_decision(ev)["next_capability"]
        assert cap not in done or cap in pp.NON_REPEATABLE_EXEMPT, sc["id"]


def test_private_ip_subdomains_are_not_pivot_targets():
    ev = _web(completed_actions=_web()["completed_actions"] + ["TLS_ANALYSIS"],
              resolved_ip="203.0.113.1",
              subdomain_resolutions={"argo.internal.example": "10.98.8.197",
                                     "vpn.example": "172.31.1.2"})
    assert pp._pivot_candidate(ev) is None


def test_pivot_prefers_management_interfaces():
    ev = _web(resolved_ip="203.0.113.1",
              subdomain_resolutions={"shop.example": "198.51.100.5",
                                     "jenkins.example": "198.51.100.6"})
    assert pp._pivot_candidate(ev) == "jenkins.example"


# ── guardrails ───────────────────────────────────────────────────────────────

def test_guardrail_blocks_out_of_scope():
    d, corr = pp.apply_guardrails(_web(authorized_scope=False), _llm("CONTENT_DISCOVERY"))
    assert d["next_capability"] == "BLOCK_EXECUTION"
    assert d["target_profile"] == "OUT_OF_SCOPE"
    assert corr


def test_guardrail_forces_verify_scope_when_unknown():
    d, _ = pp.apply_guardrails(_web(authorized_scope=None), _llm("CONTENT_DISCOVERY"))
    assert d["next_capability"] == "VERIFY_SCOPE"


def test_guardrail_replaces_repeated_capability():
    d, corr = pp.apply_guardrails(_web(), _llm("WEB_PROBING"))
    assert d["next_capability"] != "WEB_PROBING"
    assert d["decided_by"] == "guardrail"
    assert "already completed" in corr[0]


def test_guardrail_replaces_zero_findings_capability():
    ev = _web(zero_findings_actions=["CONTENT_DISCOVERY"])
    d, _ = pp.apply_guardrails(ev, _llm("CONTENT_DISCOVERY"))
    assert d["next_capability"] != "CONTENT_DISCOVERY"


def test_guardrail_rejects_do_not_repeat_pseudo_capability():
    d, _ = pp.apply_guardrails(_web(), _llm("DO_NOT_REPEAT_COMPLETED_ACTION"))
    assert d["next_capability"] != "DO_NOT_REPEAT_COMPLETED_ACTION"


def test_guardrail_blocks_ad_enum_without_ad_evidence():
    d, corr = pp.apply_guardrails(_web(), _llm("DIRECTORY_SERVICE_ENUMERATION"))
    assert d["next_capability"] != "DIRECTORY_SERVICE_ENUMERATION"
    assert "ad_signals" in corr[0]


def test_guardrail_allows_ad_enum_with_ad_evidence():
    ev = _web(open_ports=[88, 389, 445], services=["kerberos", "ldap", "smb"])
    d, corr = pp.apply_guardrails(ev, _llm("DIRECTORY_SERVICE_ENUMERATION", "ACTIVE_DIRECTORY"))
    assert d["next_capability"] == "DIRECTORY_SERVICE_ENUMERATION"
    assert corr == []


def test_guardrail_requires_tls_before_stop_on_https():
    ev = _web(completed_actions=_web()["completed_actions"]
              + ["HEADER_ANALYSIS", "CONTENT_DISCOVERY", "PARAMETER_DISCOVERY",
                 "SCREENSHOT_CAPTURE"])
    d, _ = pp.apply_guardrails(ev, _llm("STOP_NO_RELEVANT_ACTION"))
    assert d["next_capability"] == "TLS_ANALYSIS"


def test_guardrail_does_not_force_tls_on_http_only():
    ev = _web(open_ports=[80], services=["http"],
              completed_actions=_web()["completed_actions"]
              + ["HEADER_ANALYSIS", "CONTENT_DISCOVERY", "PARAMETER_DISCOVERY",
                 "SCREENSHOT_CAPTURE"])
    d, corr = pp.apply_guardrails(ev, _llm("STOP_NO_RELEVANT_ACTION"))
    assert d["next_capability"] == "STOP_NO_RELEVANT_ACTION"
    assert corr == []


def test_guardrail_leaves_valid_llm_judgement_alone():
    """A legitimate, uncompleted, evidence-supported pick is never overridden,
    even if the rules planner would have picked something else."""
    d, corr = pp.apply_guardrails(_web(), _llm("TLS_ANALYSIS"))
    assert d["next_capability"] == "TLS_ANALYSIS"
    assert corr == [] and d["decided_by"] == "llm"


def test_guardrail_downgrades_os_profile_without_os_evidence():
    ev = _web(open_ports=[22], services=["ssh"], technologies=["OpenSSH"])
    d, corr = pp.apply_guardrails(ev, _llm("OPERATING_SYSTEM_IDENTIFICATION", "LINUX_HOST"))
    assert d["target_profile"] != "LINUX_HOST"
    assert any("OS-identifying" in c for c in corr)


def test_guardrail_rejects_cred_request_when_creds_supplied():
    ev = _web(auth_required=True, approved_credentials_supplied=True)
    d, _ = pp.apply_guardrails(ev, _llm("REQUEST_AUTHORIZED_CREDENTIALS"))
    assert d["next_capability"] != "REQUEST_AUTHORIZED_CREDENTIALS"


def test_guardrail_blocks_pivot_when_exhausted():
    ev = _web(subdomains_exhausted=True)
    d, _ = pp.apply_guardrails(ev, _llm("PIVOT_TO_SUBDOMAIN", next_subdomain="x.example"))
    assert d["next_capability"] != "PIVOT_TO_SUBDOMAIN"


# ── plan() pipeline ──────────────────────────────────────────────────────────

class _Scripted:
    """Fake model returning queued replies; records whether a schema was sent."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def chat(self, system_prompt, user_prompt, temperature=None, json_schema=None):
        self.calls.append({"user": user_prompt, "schema": json_schema})
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r if isinstance(r, str) else json.dumps(r)


class _OldSignature:
    def __init__(self, reply):
        self.reply = reply

    def chat(self, system_prompt, user_prompt, temperature=None):
        return json.dumps(self.reply)


def test_plan_sends_schema_and_accepts_valid_reply():
    client = _Scripted(_llm("CONTENT_DISCOVERY"))
    d, info = pp.plan(client, "sys", _web())
    assert d["next_capability"] == "CONTENT_DISCOVERY"
    assert client.calls[0]["schema"]["properties"]["next_capability"]["enum"]
    assert not info["fallback"]


def test_plan_repairs_invalid_reply_with_feedback():
    client = _Scripted("Sure! I think you should scan more.", _llm("CONTENT_DISCOVERY"))
    d, info = pp.plan(client, "sys", _web())
    assert d["next_capability"] == "CONTENT_DISCOVERY"
    assert len(client.calls) == 2
    assert "previous reply was rejected" in client.calls[1]["user"]
    assert not info["fallback"]


def test_plan_falls_back_to_rules_after_two_bad_replies():
    client = _Scripted("not json", '{"next_capability": "HACK_THE_PLANET"}')
    d, info = pp.plan(client, "sys", _web())
    assert info["fallback"] is True
    assert d["decided_by"] == "rules"
    assert d["next_capability"] == pp.rules_decision(_web())["next_capability"]


def test_plan_falls_back_when_model_unreachable():
    client = _Scripted(ConnectionError("connection refused"))
    d, info = pp.plan(client, "sys", _web())
    assert info["fallback"] is True
    assert d["next_capability"]


def test_plan_works_with_old_client_signature():
    d, _info = pp.plan(_OldSignature(_llm("CONTENT_DISCOVERY")), "sys", _web())
    assert d["next_capability"] == "CONTENT_DISCOVERY"


def test_plan_applies_guardrails():
    d, info = pp.plan(_Scripted(_llm("WEB_PROBING")), "sys", _web())
    assert d["next_capability"] != "WEB_PROBING"
    assert info["corrections"]
    assert info["llm_decision"]["next_capability"] == "WEB_PROBING"


def test_guarded_pipeline_beats_noisy_model_on_benchmark():
    """Simulate a small model that, on every scenario, repeats a completed
    action or stops early. Guardrails must recover a large share."""
    import run_benchmark as rb

    class _Noisy:
        def __init__(self):
            self.i = 0

        def chat(self, s, user, temperature=None, json_schema=None):
            ev = json.loads(user.split("\n\nYour previous")[0])
            done = ev.get("completed_actions") or []
            self.i += 1
            cap = done[-1] if (done and self.i % 2) else "STOP_NO_RELEVANT_ACTION"
            return json.dumps(_llm(cap, "UNKNOWN"))

    schema = {}
    rows = [rb.run_scenario(_Noisy(), "sys", sc, schema) for sc in SCENARIOS]
    llm = rb.summarize(rows, "llm")["capability_accuracy"]
    guarded = rb.summarize(rows, "guarded")["capability_accuracy"]
    assert guarded > llm + 0.3


def test_decision_log_overrides_become_scenarios(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "d2s", ROOT / "scripts" / "decisions_to_scenarios.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    log = tmp_path / "decision_log.jsonl"
    rows = [
        {"timestamp": "2026-10-01T00:00:00", "target": "a.example", "evidence": _web(),
         "model_decision": _llm("WEB_PROBING"), "approved": False,
         "override_capability": "content_discovery", "human_note": "probing already done"},
        {"timestamp": "2026-10-01T00:00:00", "target": "b.example", "evidence": _web(),
         "model_decision": _llm("CONTENT_DISCOVERY"), "approved": True,
         "override_capability": None, "human_note": ""},
        {"timestamp": "2026-10-01T00:00:00", "target": "c.example",
         "evidence": _web(target="c.example"), "model_decision": _llm("WEB_PROBING"),
         "approved": False, "override_capability": None, "human_note": "no"},
    ]
    log.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    out = mod.convert(log)
    assert len(out) == 1 and out[0]["expected_capabilities"] == ["CONTENT_DISCOVERY"]
    out = mod.convert(log, include_rejected=True)
    assert len(out) == 2 and out[1]["needs_review"] is True
