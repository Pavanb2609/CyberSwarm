"""Tests for the --run-all recon planner's LLM response parsing.

Regression test for the `[recon-llm] LLM planning failed (Unterminated string ...)`
error: `_llm_plan_todo` must survive fenced JSON and truncated replies by falling
back to the deterministic order instead of crashing the run.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import run_recon_loop as rrl


class FakeModelClient:
    def __init__(self, responses):
        self._responses = list(responses)

    def chat(self, system_prompt, user_prompt, temperature=None):
        if self._responses:
            return self._responses.pop(0)
        return ""


CAPS = ["PASSIVE_ASSET_DISCOVERY", "SUBDOMAIN_DISCOVERY", "DNS_RESOLUTION"]


def test_runall_planner_parses_fenced_json():
    payload = json.dumps({
        "order": ["DNS_RESOLUTION", "PASSIVE_ASSET_DISCOVERY", "SUBDOMAIN_DISCOVERY"],
        "rationale": "DNS first",
        "param_hints": {"DNS_RESOLUTION": {"hosts": "a"}},
    })
    fenced = f"```json\n{payload}\n```"
    client = FakeModelClient([fenced])
    ordered, hints = rrl._llm_plan_todo(client, "example.com", {"target": "example.com"}, list(CAPS))
    assert ordered == ["DNS_RESOLUTION", "PASSIVE_ASSET_DISCOVERY", "SUBDOMAIN_DISCOVERY"]
    assert hints.get("DNS_RESOLUTION") == {"hosts": "a"}


def test_runall_planner_ignores_unknown_caps_and_keeps_rest():
    payload = json.dumps({"order": ["DNS_RESOLUTION", "MADE_UP_CAP"]})
    client = FakeModelClient([payload])
    ordered, _ = rrl._llm_plan_todo(client, "example.com", {"target": "example.com"}, list(CAPS))
    assert ordered[0] == "DNS_RESOLUTION"
    assert set(ordered) == set(CAPS)  # unknown cap dropped, nothing lost


def test_runall_planner_falls_back_on_truncated_json():
    truncated = '{"order": ["PASSIVE_ASSET_DISCOVERY", "SUBDOMAIN_DISCOVERY", "DNS'
    client = FakeModelClient([truncated, truncated])  # both attempts fail
    ordered, hints = rrl._llm_plan_todo(client, "example.com", {"target": "example.com"}, list(CAPS))
    assert ordered == list(CAPS)  # deterministic order
    assert hints == {}


def test_runall_planner_falls_back_on_empty_reply():
    client = FakeModelClient(["", ""])
    ordered, _ = rrl._llm_plan_todo(client, "example.com", {"target": "example.com"}, list(CAPS))
    assert ordered == list(CAPS)


# ── build_capability_kwargs: regression for the run-all crash on real targets ──
# In production this crashed with:
#   TypeError: recon_engine.execute_capability() got multiple values for
#   keyword argument 'timeout'
# because an LLM param_hint for WEB_PROBING happened to use the key
# "timeout", which collided with the explicit timeout=args.tool_timeout
# passed at the call site.

def test_build_capability_kwargs_timeout_hint_overrides_default_without_crashing():
    kwargs, timeout = rrl.build_capability_kwargs(
        evidence={}, cap_hints={"timeout": 30}, default_timeout=180)
    assert timeout == 30
    assert "timeout" not in kwargs  # must never end up duplicated into kwargs


def test_build_capability_kwargs_no_hint_uses_default_timeout():
    kwargs, timeout = rrl.build_capability_kwargs(
        evidence={}, cap_hints={}, default_timeout=180)
    assert timeout == 180
    assert "timeout" not in kwargs


def test_build_capability_kwargs_drops_reserved_capability_and_target_hints():
    # A hint dict should never be able to override which capability/target
    # execute_capability() is actually called with.
    kwargs, _ = rrl.build_capability_kwargs(
        evidence={}, cap_hints={"capability": "EVIL", "target": "evil.com", "ports": "443"},
        default_timeout=180)
    assert "capability" not in kwargs
    assert "target" not in kwargs
    assert kwargs["ports"] == "443"


def test_build_capability_kwargs_merges_evidence_and_full_url():
    kwargs, _ = rrl.build_capability_kwargs(
        evidence={"open_ports": [80, 443], "technologies": ["nginx"]},
        cap_hints={"discovered_paths": ["/admin"]},
        default_timeout=180, full_url="https://example.com/notes")
    assert kwargs["ports"] == "80,443"
    assert kwargs["technologies"] == ["nginx"]
    assert kwargs["discovered_paths"] == ["/admin"]
    assert kwargs["full_url"] == "https://example.com/notes"
