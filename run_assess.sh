#!/bin/bash
# CyberSwarm evidence-driven assessment launcher (Controller flow).
#
# Pipeline:
#   1. Authorize ..... persist target into the assessment scope
#   2. Assess ........ Controller: evidence-scored capability ranking -> ToolManager
#                               -> unified state + decision trace (results/state + traces)
#   3. Report ........ report-assess: assets, coverage, findings, trace (results/reports)
#
# Usage: ./run_assess.sh <target> [extra cyberswarm args]
#   ./run_assess.sh example.com
#   ./run_assess.sh example.com --max-actions 200         # override budget
#   ./run_assess.sh --help                                # cyberswarm help
#
# Defaults are full-aggressive: high-risk testing allowed, up to 100
# capability probes and a 30-minute budget. Pass --no-high-risk to tone down.
#
# Target may also come from the $TARGET env var:
#   TARGET=example.com ./run_assess.sh

set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-/usr/bin/python3}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  exec "$PY" bin/cyberswarm --help
fi

TARGET="${TARGET:-${1:-}}"
if [[ -z "$TARGET" ]]; then
  echo "ERROR: no target given." >&2
  echo "Usage: ./run_assess.sh <target> [extra args]" >&2
  echo "  e.g. ./run_assess.sh example.com --max-actions 200" >&2
  echo "  or   TARGET=example.com ./run_assess.sh" >&2
  exit 1
fi
shift 2>/dev/null || true

SAFE_TARGET="${TARGET//\//_}"
SAFE_TARGET="${SAFE_TARGET//:/_}"

echo "=============================================================="
echo "  CyberSwarm ASSESS — target: $TARGET"
echo "  pipeline: authorize -> Controller (evidence-driven) "
echo "            -> unified state + decision trace -> assess report"
echo "=============================================================="

echo
echo "==> [1/3] Authorizing $TARGET"
echo "=============================================================="
env PYTHONUNBUFFERED=1 "$PY" bin/cyberswarm authorize "$TARGET"

echo
echo "==> [2/3] Assessing $TARGET (Controller loop)"
echo "=============================================================="
env PYTHONUNBUFFERED=1 "$PY" bin/cyberswarm assess "$TARGET" "$@"

echo
echo "==> [3/3] Generating ASSESS REPORT ($TARGET)"
echo "=============================================================="
mkdir -p results/reports
env PYTHONUNBUFFERED=1 "$PY" bin/cyberswarm report-assess "$TARGET" --out "results/reports/${SAFE_TARGET}.assess.md"

echo
echo "CyberSwarm assessment complete for $TARGET — report: results/reports/${SAFE_TARGET}.assess.md"