#!/bin/bash
# Usage: ./run_all_target.sh <target> [--dry-run] [--no-llm]
# Runs the full evidence-driven Controller assessment for one target and
# drops a run record + decision trace in results/.
#
#   --dry-run  : plan without executing any live capability
#   --no-llm   : deterministic (no planner model calls)
#   --fast     : tight per-tool cap (60s) for quick sanity scans

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "${1:-}" ]; then
    echo "Usage: $0 <target> [--dry-run] [--no-llm] [--fast]"
    echo "Example: $0 example.com"
    echo "    use --no-llm when the Ollama host is unreachable (fallback planner)"
    echo "    use --dry-run to preview the plan without touching the target"
    echo "    use --fast to cap each tool at 60s (recommended first run)"
    exit 1
fi

TARGET="$1"
shift
EXTRA=()
DRY=""
TOOL_TIMEOUT=90
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=--dry-run ;;
        --no-llm) EXTRA+=(--no-llm-planner) ;;
        --fast) TOOL_TIMEOUT=60 ;;
        *) EXTRA+=("$1") ;;
    esac
    shift
done

echo "==>[run_all_target] ${TARGET} ${DRY} tool_timeout=${TOOL_TIMEOUT}s actions=100 budget=1800s"

cd "$SCRIPT_DIR"
python3 -u cli.py assess "$TARGET" ${DRY} --max-actions 100 --max-time 1800 \
    --tool-timeout "${TOOL_TIMEOUT}" "${EXTRA[@]}"

echo "<==[run_all_target] done: ${TARGET}"