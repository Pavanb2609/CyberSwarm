"""
Preflight sweep over every registered tool wrapper (recon + attack).

Runtime already skips unavailable tools lazily via Tool.validate()
(see agents/base_agent.py::_run_tool and tools/base.py::run). This module
exists to give the "show me everything up front" view -- which external
binaries this framework expects, whether they are present, and which
registered tools will be silently unavailable -- plus a pinned
tool-version reference (config/tool_reference.json) so the operator can
see at a glance what an installed tool "should" be.

Usage:
    python -m tools.preflight
    # or from code:
    report = run_preflight()
    print(report.as_text())
    if report.all_ok:
        print("all external binaries resolved")
"""

import importlib
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from tools.attack_registry import ATTACK_TOOL_MODULES, load_attack_tool
from tools.registry import TOOL_MODULES, load_tool

_REFERENCE_FILE = Path(__file__).resolve().parent.parent / "config" / "tool_reference.json"


@dataclass
class PreflightReport:
    resolved: dict[str, str] = field(default_factory=dict)      # binary -> abs path
    missing: dict[str, list[str]] = field(default_factory=dict)  # binary -> tools wanting it
    pure_python: list[str] = field(default_factory=list)         # wrappers with no external binary
    load_errors: list[str] = field(default_factory=list)
    pinned_warnings: list[str] = field(default_factory=list)     # pinned tools that are missing

    @property
    def all_ok(self) -> bool:
        return not self.missing and not self.load_errors

    def as_text(self) -> str:
        lines: list[str] = []
        if self.load_errors:
            lines.append(f"Tool load errors ({len(self.load_errors)}):")
            lines += [f"  ✗ {e}" for e in self.load_errors]
        if self.resolved:
            lines.append(f"Resolved binaries ({len(self.resolved)}):")
            lines += [f"  ✓ {b} -> {self.resolved[b]}" for b in sorted(self.resolved)]
        if self.missing:
            lines.append(f"MISSING binaries ({len(self.missing)}):")
            for b in sorted(self.missing):
                owners = ", ".join(sorted(set(self.missing[b])))
                lines.append(f"  ✗ {b}  (needed by: {owners})")
        if self.pinned_warnings:
            lines.append("Pinned reference tools not installed (from config/tool_reference.json):")
            lines += [f"  · {w}" for w in self.pinned_warnings]
        if self.pure_python:
            lines.append(f"Pure-python wrappers, no external binary ({len(self.pure_python)}): "
                         f"{', '.join(self.pure_python)}")
        if self.all_ok:
            lines.append("OK: every external binary the framework may use is resolvable on PATH.")
        return "\n".join(lines)


def _binary_for(tool) -> str:
    b = getattr(tool.__class__, "binary", "") or getattr(tool, "binary", "") or ""
    return str(b).strip()


def _binary_key(b: str) -> str:
    if not b:
        return ""
    # if it's an absolute path or contains a slash, use basename
    if os.sep in b or b.startswith(("./", "../")) or Path(b).is_absolute():
        return Path(b).name
    return b


def run_preflight() -> PreflightReport:
    """Instantiate every registered tool and probe for its external binary."""
    report = PreflightReport()
    pinned = _load_pinned_reference()

    def scan(modules, loader):
        for name in modules:
            try:
                tool = loader(name)
            except Exception as e:  # noqa: BLE001
                report.load_errors.append(f"{name}: {type(e).__name__}: {e}")
                continue
            binary = _binary_for(tool)
            if not binary:
                report.pure_python.append(name)
                continue
            bkey = _binary_key(binary)
            if bkey in report.missing:
                report.missing[bkey].append(name)
                continue
            if bkey in report.resolved:
                continue
            # resolve: absolute path or name in PATH
            if Path(binary).is_absolute():
                path = str(binary) if (Path(binary).exists() and os.access(binary, os.X_OK)) else None
            else:
                path = shutil.which(binary)
            if path:
                report.resolved[bkey] = path
            else:
                report.missing.setdefault(bkey, []).append(name)

    scan(TOOL_MODULES, load_tool)
    scan(ATTACK_TOOL_MODULES, load_attack_tool)

    for ref_binary in sorted(pinned.get("binaries", {})):
        rkey = _binary_key(ref_binary)
        if rkey not in report.resolved:
            req = pinned["binaries"][ref_binary]
            report.pinned_warnings.append(
                f"{ref_binary} (reference: {req.get('about', req.get('reference', '?'))})")

    return report


def _load_pinned_reference() -> dict:
    if not _REFERENCE_FILE.exists():
        return {}
    import json
    try:
        return json.loads(_REFERENCE_FILE.read_text())
    except (ValueError, OSError):
        return {}


def main() -> int:
    report = run_preflight()
    print(report.as_text())
    return 0 if report.all_ok else 1


if __name__ == "__main__":
    sys.exit(main())