#!/usr/bin/env bash
set -euo pipefail

MAIN_BIN="${MAIN_BIN:?MAIN_BIN is required}"
CANDIDATE_BIN="${CANDIDATE_BIN:?CANDIDATE_BIN is required}"
OUTPUT="${OUTPUT:-perf-artifacts/async-tap-v2-raw.tsv}"
PERF_SECONDS="${PERF_SECONDS:-10}"

mkdir -p "$(dirname "$OUTPUT")"
printf 'round\tslot\tvariant\tconns\tenc_algo\tpad_mode\tdirection\tmbps\n' > "$OUTPUT"

run_once() {
  local round="$1" slot="$2" variant="$3" bin="$4" conns="$5" enc="$6" pad="$7"
  local tmp
  tmp=$(mktemp)
  echo "=== round=$round slot=$slot variant=$variant conns=$conns enc=$enc pad=$pad ==="
  sudo -E env \
    BIN="$bin" PERF_CONNS="$conns" PERF_ENC_ALGO="$enc" \
    PERF_PAD_MODE="$pad" PERF_DIRECTION=download PERF_SECONDS="$PERF_SECONDS" \
    PERF_MIN_MBPS=500 PERF_RESULT_FILE="$tmp" \
    bash scripts/real_tap_perf.sh
  awk -F '\t' -v OFS='\t' -v r="$round" -v s="$slot" -v v="$variant" \
    '{print r,s,v,$1,$2,$3,$4,$5}' "$tmp" >> "$OUTPUT"
  rm -f "$tmp"
}

run_abba() {
  local conns="$1" enc="$2" pad="$3" rounds="$4"
  local r
  for r in $(seq 1 "$rounds"); do
    # ABBA order reduces monotonic runner warm-up / throttling bias.
    run_once "$r" 1 main      "$MAIN_BIN"      "$conns" "$enc" "$pad"
    run_once "$r" 2 candidate "$CANDIDATE_BIN" "$conns" "$enc" "$pad"
    run_once "$r" 3 candidate "$CANDIDATE_BIN" "$conns" "$enc" "$pad"
    run_once "$r" 4 main      "$MAIN_BIN"      "$conns" "$enc" "$pad"
  done
}

# Primary signal: the v1 experiment showed the async TAP handoff can help the
# single-connection client RX/download path, but a 3-second one-shot sample was
# too noisy. Exercise all current inner-cipher/padding combinations for 5 ABBA
# rounds (10 samples per variant per configuration).
for enc in gcm256 gcm128; do
  for pad in bucket off; do
    run_abba 1 "$enc" "$pad" 5
  done
done

# Regression controls: v2 deliberately keeps direct TAP delivery for multipath.
# Three ABBA rounds are enough to catch accidental activation/regression there.
run_abba 2 gcm256 bucket 3
run_abba 4 gcm256 bucket 3

sudo chown -R "$USER:$USER" "$(dirname "$OUTPUT")" 2>/dev/null || true
python3 scripts/summarize_async_tap_v2.py "$OUTPUT" "$(dirname "$OUTPUT")/async-tap-v2-summary.tsv"
