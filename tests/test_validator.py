"""schema/validator.py: strict names, repairs for common small-model slips."""

import json

from schema import enums
from schema.validator import decision_json_schema, normalize_name, validate_decision


def _base(**kw):
    d = {"target_profile": "WEB_APPLICATION", "next_capability": "CONTENT_DISCOVERY",
         "confidence": 0.7, "evidence_used": ["port 80 open"], "missing_evidence": [],
         "reason": "content not enumerated", "requires_human_approval": False}
    d.update(kw)
    return json.dumps(d)


def test_valid_decision_passes():
    ok, _parsed, errors = validate_decision(_base())
    assert ok and errors == []


def test_hallucinated_capability_is_rejected_and_not_registered():
    before = set(enums.CAPABILITIES)
    ok, _, errors = validate_decision(_base(next_capability="HACK_THE_PLANET"))
    assert not ok and any("Unknown next_capability" in e for e in errors)
    assert set(enums.CAPABILITIES) == before  # no global mutation


def test_alias_and_spelling_are_normalised():
    ok, p, _ = validate_decision(_base(next_capability="tls scan"))
    assert ok and p["next_capability"] == "TLS_ANALYSIS"
    ok, p, _ = validate_decision(_base(next_capability="CONTENT_DISCOVRY"))
    assert ok and p["next_capability"] == "CONTENT_DISCOVERY"
    ok, p, _ = validate_decision(_base(target_profile="web-app"))
    assert ok and p["target_profile"] == "WEB_APPLICATION"


def test_registered_tool_capabilities_are_accepted():
    from tools.registry import CAPABILITY_TOOL_MAP
    extra = next(c for c in CAPABILITY_TOOL_MAP if c not in enums.CAPABILITIES)
    ok, p, _ = validate_decision(_base(next_capability=extra))
    assert ok and p["next_capability"] == extra


def test_missing_capability_is_an_error_not_silent_stop():
    raw = json.dumps({"target_profile": "DOMAIN", "confidence": 0.5,
                      "evidence_used": [], "missing_evidence": [], "reason": "x",
                      "requires_human_approval": False})
    ok, _, errors = validate_decision(raw)
    assert not ok and any("next_capability" in e for e in errors)


def test_small_model_slips_are_repaired():
    raw = json.dumps({"target_profile": "WEB_APPLICATION", "next_capability": "WEB_PROBING",
                      "confidence": 85, "evidence_used": "port 80 open",
                      "missing_evidence": None, "reason": "probe it",
                      "requires_human_approval": "false"})
    ok, p, errors = validate_decision(raw)
    assert ok, errors
    assert p["confidence"] == 0.85
    assert p["evidence_used"] == ["port 80 open"]
    assert p["requires_human_approval"] is False


def test_think_block_and_fences_are_stripped():
    raw = "<think>let me reason</think>\n```json\n" + _base() + "\n```"
    ok, _, errors = validate_decision(raw)
    assert ok, errors


def test_action_key_alias():
    ok, p, _ = validate_decision(json.dumps({"action": "STOP", "reason": "done",
                                             "target_profile": "DOMAIN"}))
    assert ok and p["next_capability"] == "STOP_NO_RELEVANT_ACTION"


def test_schema_excludes_pseudo_capability():
    caps = decision_json_schema()["properties"]["next_capability"]["enum"]
    assert "DO_NOT_REPEAT_COMPLETED_ACTION" not in caps
    assert "TLS_ANALYSIS" in caps


def test_normalize_name_returns_none_for_garbage():
    assert normalize_name("zzzz", {"TLS_ANALYSIS"}, {}) is None
    assert normalize_name("", {"TLS_ANALYSIS"}, {}) is None
