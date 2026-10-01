#!/usr/bin/env bash
set -euo pipefail
root="$(pwd)"
mkdir -p artifacts
export PERF_LOG_LEVEL=info
# Baseline omits the new config fields, so an immutable pre-change binary can
# use the exact same workload harness. Candidate-single catches wrapper cost.
for round in 1 2 3 4 5; do
  mapfile -t variants < <(python3 - "$round" <<'PY'
import random, sys
variants = ['baseline', 'single', 'flag', 'q2', 'q4']
random.Random(int(sys.argv[1])).shuffle(variants)
print('\n'.join(variants))
PY
  )
  for variant in "${variants[@]}"; do
    export BIN="$root/perf-bin/candidate" PERF_TAP_QUEUES=1 PERF_TAP_MULTI_QUEUE=false
    case "$variant" in
      baseline) export BIN="$root/perf-bin/baseline" PERF_TAP_QUEUES="" ;;
      flag) export PERF_TAP_MULTI_QUEUE=true ;;
      q2) export PERF_TAP_QUEUES=2 ;;
      q4) export PERF_TAP_QUEUES=4 ;;
    esac
    export PERF_RAW_DIR="$root/artifacts/$variant/$round"
    export PERF_RESULT_FILE="$PERF_RAW_DIR/results.tsv"
    mkdir -p "$PERF_RAW_DIR"
    bash scripts/real_tap_perf.sh 2>&1 | tee "$PERF_RAW_DIR/run.log"
    test "$(wc -l < "$PERF_RESULT_FILE")" -eq 2
    if [[ "$variant" != baseline ]]; then
      grep -F "TAP tap_t0: $PERF_TAP_QUEUES read queue(s)" "$PERF_RAW_DIR/server.log"
      grep -F "TAP tap_t1: $PERF_TAP_QUEUES read queue(s)" "$PERF_RAW_DIR/client.log"
    fi
  done
done
# Profiling runs are separate from measurement runs to avoid instrumentation
# changing the measured effect. Profile both endpoints and both directions.
for variant in baseline q4; do
  export BIN="$root/perf-bin/candidate" PERF_TAP_QUEUES=4 PERF_TAP_MULTI_QUEUE=false
  if [[ "$variant" == baseline ]]; then export BIN="$root/perf-bin/baseline" PERF_TAP_QUEUES=""; fi
  export PERF_PROFILE_DIR="$root/artifacts/profiles-$variant" PERF_SECONDS=5
  export PERF_RAW_DIR="$PERF_PROFILE_DIR" PERF_RESULT_FILE="$PERF_PROFILE_DIR/results.tsv"
  mkdir -p "$PERF_PROFILE_DIR"
  bash scripts/real_tap_perf.sh 2>&1 | tee "$PERF_PROFILE_DIR/run.log"
  go tool pprof -top "$PERF_PROFILE_DIR/server.cpu.prof" > "$PERF_PROFILE_DIR/server-cpu.txt"
  go tool pprof -top "$PERF_PROFILE_DIR/client.cpu.prof" > "$PERF_PROFILE_DIR/client-cpu.txt"
done
