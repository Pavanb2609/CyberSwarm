"""Regression test for the pivot-signal parsing bug.

PivotAgent emits signals as "PIVOT:<target>|<agent_hint>|<reason>". The main
loop used to take the WRONG segment (the agent_hint, e.g. "web_attack")
as the pivot target instead of the actual discovered host, silently
breaking auto-pivot. See run_agent_loop.parse_pivot_target().
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from run_agent_loop import parse_pivot_target


def test_parse_pivot_target_extracts_the_host_not_the_agent_hint():
    signal = "PIVOT:sub.example.com|web_attack|subdomain found in recon"
    assert parse_pivot_target(signal) == "sub.example.com"


def test_parse_pivot_target_handles_reason_containing_pipes():
    signal = "PIVOT:api.example.com|api|reason with a | pipe in it"
    assert parse_pivot_target(signal) == "api.example.com"


def test_parse_pivot_target_ignores_non_pivot_signals():
    assert parse_pivot_target("API:/v1/users discovered") is None
    assert parse_pivot_target("AUTH:/login form found") is None


def test_parse_pivot_target_handles_empty_target():
    assert parse_pivot_target("PIVOT:|web_attack|no host") is None


def test_parse_pivot_target_handles_missing_segments():
    # Malformed signal with no "|" at all should still not crash, and
    # should not be mistaken for a valid target.
    assert parse_pivot_target("PIVOT:onlytarget") == "onlytarget"
