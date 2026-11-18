#!/usr/bin/env python3
"""
Build a SystemMap from completed Phase 1 recon evidence.

Usage:
    python build_system_map.py <target>
    python build_system_map.py --all
"""

import argparse
import json
import sys
from pathlib import Path

import evidence_store
import system_map

ROOT = Path(__file__).parent


def build_for(target: str, verbose: bool = True) -> dict:
    evidence = evidence_store.load(target, warn_on_regression=False)
    if not evidence.get("completed_actions"):
        print(f"[WARNING] No Phase 1 recon for '{target}' — map will be sparse.")
    m = system_map.build_from_evidence(target, evidence)
    # Compute and persist the attack surface BEFORE saving -- previously this
    # was computed after save_map() purely for console output, so the
    # "attack_surface" field was always {} on disk and every downstream
    # reader had to recompute it from scratch. Now it's saved once and can
    # be trusted by anything reading the JSON directly.
    m["attack_surface"] = system_map.derive_attack_surface(m)
    system_map.save_map(target, m)
    if verbose:
        print(f"\n[SystemMap] {target}")
        print(f"  subdomains   : {len(m['assets']['subdomains'])}  "
              f"ip={m['assets'].get('resolved_ip')}")
        print(f"  services     : {len(m['services'])}  "
              f"ports={[s.get('port') for s in m['services'][:12]]}")
        print(f"  technologies : {[t.get('name') for t in m['technologies'][:8]]}")
        print(f"  cms          : {m['signals'].get('cms')} {m['signals'].get('cms_version') or ''}")
        print(f"  auth_paths   : {len(m['auth_paths'])}  api_paths={len(m['api_paths'])}")
        print(f"  links        : {len(m['links'])}")
        for name, info in sorted(m["attack_surface"]["agents"].items(),
                                 key=lambda kv: kv[1].get("priority", 9)):
            marker = "SKIP" if info.get("skip") else f"P{info['priority']}"
            print(f"    [{marker}] {name}: {info['reason']}")
        print(f"  saved        : results/system_map/{target}.json")
    return m


def main():
    p = argparse.ArgumentParser(description="Build SystemMap from Phase 1 evidence")
    p.add_argument("target", nargs="?", help="Target domain")
    p.add_argument("--all", action="store_true", help="Build for every evidence file")
    args = p.parse_args()

    if args.all:
        evdir = ROOT / "results" / "evidence"
        if not evdir.exists():
            print("[ERROR] No results/evidence/ directory")
            sys.exit(1)
        targets = sorted(p.stem for p in evdir.glob("*.json"))
        for t in targets:
            try:
                build_for(t)
            except Exception as e:
                print(f"[ERROR] {t}: {e}")
        return

    if not args.target:
        p.print_help()
        sys.exit(1)
    build_for(args.target)


if __name__ == "__main__":
    main()
