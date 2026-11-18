#!/usr/bin/env bash
# run_xbow_matrix.sh — CyberSwarm XBOW paper matrix (user-facing runner)
#
# Stratified ~30-benchmark subset x 4 pipeline variants.
#   variants: baseline | no-difficulty | no-rag | no-llm-planner
#
# - LIVE PROGRESS : prints one line per benchmark with verdict + rolling ETA
# - RESUMABLE     : safe to Ctrl+C; re-run continues where it stopped
# - LOG           : everything is also tee'd to results/xbow/matrix/run_*.log
#
# Usage:
#   bash run_xbow_matrix.sh                 # run / resume the whole matrix
#   bash run_xbow_matrix.sh --status        # show done/total + aggregate ETA
#   bash run_xbow_matrix.sh --finalize      # rebuild reports & comparison table
set -u
cd "$(dirname "$0")"

BENCH_LIST=(
  XBEN-021-24 XBEN-052-24 XBEN-036-24 XBEN-032-24 XBEN-072-24 XBEN-073-24
  XBEN-020-24 XBEN-067-24 XBEN-077-24 XBEN-095-24 XBEN-084-24 XBEN-085-24
  XBEN-080-24 XBEN-092-24 XBEN-078-24 XBEN-029-24 XBEN-094-24 XBEN-081-24
  XBEN-014-24 XBEN-103-24 XBEN-079-24 XBEN-055-24 XBEN-057-24 XBEN-101-24
  XBEN-093-24 XBEN-066-24 XBEN-088-24
)
VARIANTS=(baseline no-difficulty no-rag no-llm-planner no-guardrails)

OUT=results/xbow/matrix
mkdir -p "$OUT"
LOG="$OUT/run_$(date +%Y%m%d_%H%M%S).log"

TOTAL=$(( ${#BENCH_LIST[@]} * ${#VARIANTS[@]} ))

# ── progress bookkeeping: (variant,bench) -> done /  duration ──────────────
count_done() {
  local n=0
  for v in "${VARIANTS[@]}"; do
    f="$OUT/$v.json"
    [ -f "$f" ] && n=$(( n + $(./venv/bin/python -c "
import json,sys
try: print(len(json.load(open('$f'))))
except Exception: print(0)") ))
  done
  echo "$n"
}

total_time_spent() {
  local sum=0 s
  for v in "${VARIANTS[@]}"; do
    f="$OUT/$v.json"
    [ -f "$f" ] || continue
    s=$(./venv/bin/python -c "
import json
try:
    d=json.load(open('$f')); print(int(sum(r.get('duration_s',0.0) for r in d)))
except Exception: print(0)")
    sum=$(( sum + s ))
  done
  echo "$sum"
}

fmt_hm() {
  local m=$(( ($1 + 59) / 60 ))
  if [ "$m" -ge 60 ]; then
    echo "$(( m / 60 ))h$(( m % 60 ))m"
  else
    echo "${m}m"
  fi
}

status() {
  local done undone s per remaining
  done=$(count_done)
  s=$(total_time_spent)
  undone=$(( TOTAL - done ))
  if [ "$done" -gt 0 ]; then
    per=$(( s / done ))
    remaining=$(( per * undone ))
    echo "progress: $done/$TOTAL runs done | avg $(fmt_hm "$per")/run | remaining ~$(fmt_hm "$remaining")"
  else
    echo "progress: $done/$TOTAL runs done | avg unknown yet (plan: ~108 runs x ~11 min ≈ 20 h total)"
  fi
}

if [ "${1:-}" = "--status" ]; then status; exit 0; fi

{
  echo "=============================================================="
  echo " XBOW matrix — $(date)"
  echo " benchmarks: ${#BENCH_LIST[@]} x variants: ${#VARIANTS[@]} = $TOTAL runs"
  echo " plan: stratified L1/L2/L3 subset, per-run timeout 900 s"
  echo " Ctrl+C safe — re-run this script to resume"
  echo "=============================================================="
  bash "$0" --status
} | tee -a "$LOG"

t_all=$SECONDS
run_no=0

for v in "${VARIANTS[@]}"; do
  echo "=== variant: $v — $(date) ===" | tee -a "$LOG"
  for b in "${BENCH_LIST[@]}"; do
    skip=$(./venv/bin/python - <<PYEOF
import json, os
try:
    d = json.load(open("$OUT/$v.json"))
    print("skip" if any(r.get("benchmark") == "$b" for r in d) else "run")
except Exception:
    print("run")
PYEOF
)
    if [ "$skip" = "skip" ]; then
      echo "[skip] $v $b (already done)" | tee -a "$LOG"
      continue
    fi
    run_no=$(( run_no + 1 ))
    t0=$SECONDS
    echo "[run $(date +%H:%M:%S)] $v $b" | tee -a "$LOG"
    sg docker -c "./venv/bin/python benchmarks/xbow_bench.py \
        --repo ../validation-benchmarks --only $b --timeout 900 \
        --out $OUT --variant $v" 2>&1 | tee -a "$LOG" | tail -3
    dt=$(( SECONDS - t0 ))
    run_no=$(( run_no + 1 ))
    echo "[$(date +%H:%M:%S)] finished $v $b in ${dt}s — $(bash "$0" --status)" | tee -a "$LOG"
  done
  echo "=== variant $v complete — $(date) — total elapsed $(fmt_hm $(( SECONDS - t_all ))) ===" | tee -a "$LOG"
done

echo "ALL RUNS COMPLETE — $(date)" | tee -a "$LOG"
echo "final reports: $OUT/{variant}.md + comparison.md"
