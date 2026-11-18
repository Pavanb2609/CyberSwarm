#!/usr/bin/env python3
"""
Build a clean, shareable zip of the project.

The hand-made zips carried ~3,700 extra files: .opencode/node_modules,
__pycache__, .pytest_cache and runtime results (which can contain real target
data). This builds the archive from source only.

    python scripts/package.py                         # -> dist/CyberSwarm_<date>.zip
    python scripts/package.py --with-results          # include results/ (careful: target data)
    python scripts/package.py --out /tmp/cs.zip
"""

from __future__ import annotations

import argparse
import fnmatch
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

EXCLUDE_DIRS = {"__pycache__", ".pytest_cache", ".ruff_cache", ".git", "venv", ".venv",
                "node_modules", "dist", "build", ".mypy_cache"}
EXCLUDE_FILES = ("*.pyc", "*.pyo", "*.egg-info", ".env", "session.txt", "*.bak", ".DS_Store")


def iter_files(with_results: bool):
    for path in sorted(ROOT.rglob("*")):
        rel = path.relative_to(ROOT)
        parts = set(rel.parts)
        if parts & EXCLUDE_DIRS:
            continue
        if not with_results and rel.parts[0] == "results":
            continue
        if path.is_dir():
            if not any(path.iterdir()):
                yield path, rel  # keep empty folders (e.g. results/.../vulnerabilities/)
            continue
        if any(fnmatch.fnmatch(path.name, pat) for pat in EXCLUDE_FILES):
            continue
        yield path, rel


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Build a clean project zip")
    p.add_argument("--out", default=None)
    p.add_argument("--with-results", action="store_true",
                   help="include results/ (may contain real target data)")
    a = p.parse_args(argv)

    out = Path(a.out) if a.out else ROOT / "dist" / f"{ROOT.name}_{time.strftime('%Y%m%d')}.zip"
    out.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, rel in iter_files(a.with_results):
            if path.resolve() == out.resolve():
                continue
            zf.write(path, Path(ROOT.name) / rel)
            n += 1
    print(f"{n} files -> {out} ({out.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
