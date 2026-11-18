#!/usr/bin/env python3
"""
Turn human overrides from the approval gate into benchmark scenarios.

Every time an operator answers [o]verride in the approval gate, the decision
log records the full evidence, what the model picked, and what the human chose
instead -- a labelled example of the planner being wrong. This script converts
those entries into scenarios.json format so the benchmark grows from real runs
instead of only hand-written cases.

    python scripts/decisions_to_scenarios.py                       # preview
    python scripts/decisions_to_scenarios.py --write               # append to scenarios.json
    python scripts/decisions_to_scenarios.py --log other_log.jsonl --include-rejected

Rejections (no replacement capability) are skipped by default because they
only say what was wrong, not what was right. With --include-rejected they are
written with the rules planner's answer as the expected label and flagged
`needs_review: true` so a human checks them before trusting the score.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import planner_policy  # noqa: E402

DEFAULT_LOG = ROOT / "results" / "decision_log.jsonl"
SCENARIOS = ROOT / "scenarios" / "scenarios.json"
EVIDENCE_KEYS = ("target", "authorized_scope", "target_type", "reachable", "open_ports",
                 "services", "technologies", "completed_actions", "failed_actions",
                 "zero_findings_actions", "previous_observations", "auth_required",
                 "approved_credentials_supplied", "cms_detected", "resolved_ip",
                 "subdomains", "subdomain_resolutions", "subdomains_exhausted",
                 "active_subtarget", "subtarget_results", "failure_patterns", "os_detected")


def _slim(evidence: dict) -> dict:
    ev = {k: evidence[k] for k in EVIDENCE_KEYS if k in evidence}
    ev["previous_observations"] = list(ev.get("previous_observations") or [])[-8:]
    return ev


def _sid(entry: dict) -> str:
    h = hashlib.sha1(json.dumps(entry.get("evidence", {}), sort_keys=True,
                                default=str).encode()).hexdigest()[:8]
    return f"log_{str(entry.get('target', 'target')).replace('.', '_')}_{h}"


def convert(log_path: Path, include_rejected: bool = False) -> list:
    out = []
    if not log_path.exists():
        return out
    for line in log_path.read_text(encoding="utf-8").splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("approved") or not isinstance(e.get("evidence"), dict):
            continue
        ev = _slim(e["evidence"])
        model = e.get("model_decision") or {}
        override = (e.get("override_capability") or "").strip().upper()
        if override:
            expected, review = [override], False
        elif include_rejected:
            expected = [planner_policy.rules_decision(ev)["next_capability"]]
            review = True
        else:
            continue
        profile = model.get("target_profile") or planner_policy.classify_profile(
            planner_policy.Facts(ev))
        sc = {"id": _sid(e),
              "description": f"From decision log ({e.get('timestamp', '')[:10]}): model chose "
                             f"{model.get('next_capability')}; human: {e.get('human_note') or override or 'rejected'}",
              "evidence": ev,
              "expected_profiles": sorted({profile, planner_policy.classify_profile(
                  planner_policy.Facts(ev))}),
              "expected_capabilities": expected,
              "rule": "human override from approval gate",
              "source": "decision_log"}
        if review:
            sc["needs_review"] = True
        out.append(sc)
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--log", default=str(DEFAULT_LOG))
    p.add_argument("--scenarios", default=str(SCENARIOS))
    p.add_argument("--include-rejected", action="store_true")
    p.add_argument("--write", action="store_true", help="append new scenarios to the file")
    a = p.parse_args(argv)

    new = convert(Path(a.log), a.include_rejected)
    existing = json.loads(Path(a.scenarios).read_text(encoding="utf-8"))
    known = {s["id"] for s in existing}
    new = [s for s in new if s["id"] not in known]
    print(f"{len(new)} new scenario(s) from {a.log}")
    for s in new:
        print(f"  {s['id']}: expect {s['expected_capabilities']}"
              + ("  [needs review]" if s.get("needs_review") else ""))
    if a.write and new:
        Path(a.scenarios).write_text(json.dumps(existing + new, indent=2) + "\n", encoding="utf-8")
        print(f"appended to {a.scenarios}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
