"""
Human approval gate for Recon Planner decisions.

Every decision the planner makes is:
  1. Printed clearly for human review.
  2. Explicitly approved / rejected / overridden by a human.
  3. Logged permanently to results/decision_log.jsonl -- an append-only
     audit trail regardless of outcome, so there's always a record of
     what the model recommended and what a human actually decided.

This module never executes anything itself. It only gates and records
the decision to move forward. Execution is a separate concern (Phase 2).
"""

import json
from pathlib import Path
from datetime import datetime, timezone

LOG_PATH = Path(__file__).parent / "results" / "decision_log.jsonl"


def review(decision: dict, target: str, evidence: dict) -> dict:
    """
    Present the planner's decision to a human and require an explicit
    approve / reject / override before it's considered actionable.
    Always appends an entry to the audit log, whatever the outcome.
    """
    flagged = bool(decision.get("requires_human_approval"))

    print("\n" + "=" * 60)
    print("HUMAN APPROVAL REQUIRED" if flagged else "DECISION REVIEW")
    print("=" * 60)
    print(f"Target:            {target}")
    print(f"Target profile:    {decision.get('target_profile')}")
    print(f"Next capability:   {decision.get('next_capability')}")
    print(f"Confidence:        {decision.get('confidence')}")
    print(f"Reason:            {decision.get('reason')}")
    if decision.get("evidence_used"):
        print(f"Evidence used:     {decision.get('evidence_used')}")
    if decision.get("missing_evidence"):
        print(f"Missing evidence:  {decision.get('missing_evidence')}")
    print("-" * 60)

    approved = False
    override_capability = None
    note = ""

    resp = input("Approve this next capability? [y]es / [n]o / [o]verride: ").strip().lower()
    if resp in ("y", "yes"):
        approved = True
    elif resp in ("o", "override"):
        override_capability = input("Enter the capability to use instead: ").strip()
        note = input("Reason for override (optional): ").strip()
    else:
        note = input("Reason for rejection (optional): ").strip()

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "evidence": evidence,
        "model_decision": decision,
        "approved": approved,
        "override_capability": override_capability,
        "human_note": note,
    }

    LOG_PATH.parent.mkdir(exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    outcome = "APPROVED" if approved else ("OVERRIDDEN" if override_capability else "REJECTED")
    print(f"\nLogged as: {outcome} -> {LOG_PATH}")
    print("=" * 60)

    return entry


def auto_log(decision: dict, target: str, evidence: dict) -> dict:
    """Non-interactive: auto-approve and log. Used with --auto-approve."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "evidence": evidence,
        "model_decision": decision,
        "approved": True,
        "override_capability": None,
        "human_note": "auto-approved (--auto-approve mode)",
    }

    LOG_PATH.parent.mkdir(exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    return entry



def gate(decision: dict, target: str, evidence: dict, policy=None) -> dict:
    """Route a planner decision through the session policy.

    ``guided`` asks a human before the action runs; ``auto`` and ``free``
    approve and log it. Passing ``policy=None`` keeps the historical
    behaviour of prompting, so existing callers are unaffected.
    """
    if policy is None:
        return review(decision, target=target, evidence=evidence)
    if policy.requires_approval_before_action():
        return review(decision, target=target, evidence=evidence)
    entry = auto_log(decision, target=target, evidence=evidence)
    entry["human_note"] = f"auto-approved ({policy.mode.value} mode)"
    return entry


def pause_for_review(label: str, findings=None, policy=None,
                     phase_changed: bool = False) -> bool:
    """Stop and wait after a result when the pause policy says so.

    Returns True to continue, False if the operator asked to stop. A policy of
    ``never`` (the default) returns True without printing anything.
    """
    if policy is None or not policy.should_pause_after_result(
            findings=findings, phase_changed=phase_changed):
        return True

    count = len(findings or [])
    reason = "phase boundary" if phase_changed else f"{count} finding(s)"
    print("\n" + "-" * 60)
    print(f"CHECKPOINT — {label} ({reason})")
    for finding in list(findings or [])[:5]:
        severity = getattr(finding, "severity", None)
        name = getattr(finding, "name", None)
        if severity is None and isinstance(finding, dict):
            severity, name = finding.get("severity"), finding.get("name")
        print(f"  [{severity}] {str(name)[:60]}")
    print("-" * 60)
    try:
        resp = input("Continue? [Y]es / [n]o: ").strip().lower()
    except EOFError:
        return True
    return resp not in ("n", "no")
