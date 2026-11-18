#!/usr/bin/env python3
"""
phase_ctl.py — inspect and steer the engagement phase for a target.

    python scripts/phase_ctl.py example.com                 # status + gate report
    python scripts/phase_ctl.py example.com --advance       # move to next phase
    python scripts/phase_ctl.py example.com --set EXPLOITATION
    python scripts/phase_ctl.py example.com --set EXPLOITATION --force
    python scripts/phase_ctl.py example.com --history
    python scripts/phase_ctl.py example.com --reset

Status is the useful one: it prints each gate with the number it is actually
comparing, so "why won't it exploit?" is answerable without reading code.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import phases  # noqa: E402

try:
    from utils import ROOT
except ImportError:  # pragma: no cover
    ROOT = Path(__file__).resolve().parent.parent


def _load_context(target: str) -> phases.PhaseContext:
    """Build gate context from whatever evidence exists on disk."""
    evidence, attack = {}, {}
    for path, sink in ((ROOT / "results" / "evidence" / f"{target}.json", "ev"),
                       (ROOT / "results" / "attack_evidence" / f"{target}.json", "att")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(data, dict):
            if sink == "ev":
                evidence = data
            else:
                attack = data
    return phases.PhaseContext.from_evidence(evidence, attack, target=target)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect and steer engagement phases.")
    parser.add_argument("target", help="target the phase state belongs to")
    parser.add_argument("--advance", action="store_true",
                        help="move to the next phase if its gates pass")
    parser.add_argument("--set", dest="set_phase", default=None,
                        choices=phases.PHASE_ORDER,
                        help="jump to an explicit phase")
    parser.add_argument("--force", action="store_true",
                        help="proceed even when gates fail (recorded in history)")
    parser.add_argument("--note", default="",
                        help="reason, stored alongside a forced transition")
    parser.add_argument("--history", action="store_true",
                        help="print the transition history")
    parser.add_argument("--reset", action="store_true",
                        help="reset this target to DISCOVERY")
    args = parser.parse_args()

    controller = phases.get_controller(args.target)
    ctx = _load_context(args.target)

    if args.reset:
        controller.reset()
        print(f"{args.target}: reset to {controller.current}")
        return 0

    if args.history:
        history = controller.load().history
        if not history:
            print("(no transitions recorded)")
            return 0
        for entry in history:
            forced = "  [FORCED]" if entry.get("forced") else ""
            print(f"{entry.get('at', '?')}  {entry.get('from')} -> {entry.get('to')}{forced}")
            if entry.get("note"):
                print(f"    note: {entry['note']}")
            for gate in entry.get("gates", []):
                mark = "PASS" if gate.get("passed") else "FAIL"
                print(f"    [{mark}] {gate.get('name')}: {gate.get('detail')}")
        return 0

    if args.set_phase or args.advance:
        if args.set_phase:
            moved, message, results = controller.set_phase(
                args.set_phase, ctx, force=args.force, note=args.note)
        else:
            moved, message, results = controller.advance(
                ctx, force=args.force, note=args.note)
        print(message)
        for result in results:
            print(f"  {result}")
        if not moved:
            print("\nRe-run with --force to override.")
            return 1
        return 0

    print(controller.summary(ctx))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
