#!/bin/bash
# CyberSwarm launcher — end-to-end offensive pipeline on a target.
#
# Pipeline (matches bin/cyberswarm):
#   1. Phase 1  Recon .......... all 37 recon capabilities (--run-all), LLM-optimized order
#   2. SystemMap ............... build/refresh SystemMap from recon evidence
#   3. Phase 2  Attack .......... PlannerAgent (LLM attack graph, built once)
#                                -> multi-agent sweep (web_attack/api/auth/infra/cloud/intelligence)
#                                -> WAF/CDN-aware tool skipping + concurrent tools
#                                -> batched CriticAgent (1 LLM call per agent, confirm-on-evidence)
#                                -> aggregated findings (grouped per issue type)
#                                -> MemoryAgent (only confirmed findings become vulnerabilities)
#   4. Report .................. generate_attack_report.py (confirmed vulns + risk rating)
#
# Usage: ./run.sh <target> [extra cyberswarm args]
#   ./run.sh example.com
#   ./run.sh example.com --dry-run        # planner + agent selection only, no tools
#   ./run.sh --help                       # cyberswarm help
#
# Target may also come from the $TARGET env var:
#   TARGET=example.com ./run.sh

set -euo pipefail
cd "$(dirname "$0")"

# Tool discovery: Go binaries installed via `go install` land in ~/go/bin,
# and Python CLIs (arjun, corsy, ...) land in venv/bin — neither is on PATH
# in non-login shells or when the venv isn't activated.
export PATH="$HOME/.local/bin:$HOME/go/bin:$(pwd)/venv/bin:$HOME/zap/ZAP_2.17.0:$PATH"

# Content-discovery wordlist (ffuf/feroxbuster via tools/wordlists.py):
# prefer a common.txt in the repo root when present, else the system dirs.
if [ -f "$(pwd)/common.txt" ]; then
    export FFUF_WORDLIST="$(pwd)/common.txt"
fi

PY=${PYTHON:-"$(pwd)/venv/bin/python"}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  exec "$PY" bin/cyberswarm --help
fi

TARGET="${TARGET:-${1:-}}"
if [[ -z "$TARGET" ]]; then
  echo "ERROR: no target given." >&2
  echo "Usage: ./run.sh <target> [extra args]" >&2
  echo "  e.g. ./run.sh example.com --dry-run" >&2
  echo "  or   TARGET=example.com ./run.sh" >&2
  exit 1
fi
shift 2>/dev/null || true

# Safe filename slug (mirrors the .replace("/", "_").replace(":", "_") used
# across the codebase for evidence/system-map stores) so URLs don't create
# nested directories when used in the report path.
SAFE_TARGET="${TARGET//\//_}"
SAFE_TARGET="${SAFE_TARGET//:/_}"

# Pull model + backend + base_url from config.yaml so run.sh always matches
# what the pipeline actually uses (default qwen3:8b for GPU speed).
read -r MODEL CONF_URL <<< "$("$PY" - <<'PYEOF'
import yaml
from pathlib import Path
cfg = (yaml.safe_load(Path("config.yaml").read_text(encoding="utf-8")) or {}).get("model", {})
print(cfg.get("model", "qwen3:8b"), cfg.get("base_url", "http://localhost:11434"))
PYEOF
)"

# Model backend selection. Precedence:
#   1) an explicit --base-url or --base-url=URL passed to run.sh (it is pulled
#      out of "$@" and re-inserted BEFORE the subcommand, where cyberswarm's
#      top-level argparse accepts it);
#   2) the config.yaml base_url, if a live backend answers its health endpoint;
#   3) otherwise auto-detect: probe localhost, every local interface IP, and
#      gateway/NAT hosts (VM host, docker0 bridge) on the backend's default
#      port. The detected URL is passed as --base-url into every pipeline step.
ARGS=("$@")
USER_BASE_URL=""
FILTERED=()
i=0
while [ "$i" -lt "${#ARGS[@]}" ]; do
  a="${ARGS[$i]}"
  if [[ "$a" == "--base-url" ]]; then
    USER_BASE_URL="${ARGS[$((i+1))]:-}"
    i=$((i+2)); continue
  elif [[ "$a" == --base-url=* ]]; then
    USER_BASE_URL="${a#--base-url=}"
    i=$((i+1)); continue
  fi
  FILTERED+=("$a")
  i=$((i+1))
done

BASE_URL="$USER_BASE_URL"
if [ -z "$BASE_URL" ]; then
  CANDIDATES=("http://localhost:11434" "http://127.0.0.1:11434")
  for ip in $(hostname -I 2>/dev/null); do
    [[ "$ip" == *.* ]] && CANDIDATES+=("http://$ip:11434")
  done
  # Gateways/NAT hosts: a model server often sits on the VM host or a bridge
  # host (VirtualBox NAT gw at .2, docker0 at 172.x.0.1) rather than an
  # own-interface address.
  for gw in $(ip route 2>/dev/null | awk '/ via / {print $3}'); do
    CANDIDATES+=("http://$gw:11434")
  done

  BASE_URL="$CONF_URL"
  if ! curl -sf -m 3 "$BASE_URL/api/tags" >/dev/null 2>&1; then
    for cand in "${CANDIDATES[@]}"; do
      if curl -sf -m 3 "$cand/api/tags" >/dev/null 2>&1; then
        echo "[run.sh] configured model host $CONF_URL unreachable — auto-detected Ollama at $cand"
        BASE_URL="$cand"
        break
      fi
    done
    if [[ "$BASE_URL" == "$CONF_URL" ]]; then
      echo "[warn] no reachable local Ollama host found — keeping configured $CONF_URL"
      echo "       (pipeline will fall back to deterministic/offline modes)."
    fi
  fi
fi

echo "=============================================================="
echo "  CyberSwarm — target: $TARGET"
echo "  model: $MODEL   backend: $BASE_URL"
echo "  pipeline: recon (37 capabilities) -> SystemMap"
echo "            -> multi-agent attack (batch critic / WAF-aware / aggregate / S3-enum)"
echo "            -> report"
echo "=============================================================="

echo
echo "==> [1/4] Phase-1 RECON: all 37 capabilities ($TARGET)"
echo "=============================================================="
env PYTHONUNBUFFERED=1 "$PY" bin/cyberswarm --base-url "$BASE_URL" recon "$TARGET" --run-all --auto-approve "${FILTERED[@]}"

echo
echo "==> [2/4] Building SystemMap ($TARGET)"
echo "=============================================================="
env PYTHONUNBUFFERED=1 "$PY" bin/cyberswarm --base-url "$BASE_URL" map "$TARGET"

echo
echo "==> [3/4] Phase-2 MULTI-AGENT ATTACK ($TARGET)"
echo "       (planner graph once | WAF/CDN-aware skipping | concurrent tools"
echo "       | batched critic with confirm-on-evidence | aggregated findings"
echo "       | S3 bucket enumeration | memory stores confirmed vulns only)"
echo "=============================================================="
env PYTHONUNBUFFERED=1 "$PY" bin/cyberswarm --base-url "$BASE_URL" attack "$TARGET" --auto-approve --reset-memory "${FILTERED[@]}"

echo
echo "==> [4/4] Generating REPORT ($TARGET)"
echo "=============================================================="
mkdir -p results/reports
env PYTHONUNBUFFERED=1 "$PY" bin/cyberswarm --base-url "$BASE_URL" report "$TARGET" --out "results/reports/${SAFE_TARGET}.md"

echo
echo "CyberSwarm complete for $TARGET — report: results/reports/${SAFE_TARGET}.md"
