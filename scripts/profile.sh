#!/usr/bin/env bash
# profile.sh — 本地 pprof 性能剖析：跑 perf 套件并生成交互式火焰图。
#
#   ./scripts/profile.sh            # CPU + 堆剖析，起 pprof web UI（含火焰图）
#   ./scripts/profile.sh cpu        # 只剖析 CPU，打印 top25 后退出
#   ./scripts/profile.sh mem        # 只剖析堆分配
#
# 输出保存在 .prof-out/（已 gitignore）。火焰图在浏览器打开 http://localhost:8080
# 后切到 "Create Profile" 下拉中的 Flame Graph 视图。

set -euo pipefail
cd "$(dirname "$0")/.."
OUT=".prof-out"
mkdir -p "$OUT"

mode="${1:-all}"
run_cpu() { go test -count=1 -run TestPerfThroughput -timeout 10m -cpuprofile "$OUT/cpu.prof" ./...; }
run_mem() { go test -count=1 -run TestPerfThroughput -timeout 10m -memprofile "$OUT/mem.prof" ./...; }

case "$mode" in
  cpu)
    run_cpu
    go tool pprof -top -nodecount=25 "$OUT/cpu.prof"
    ;;
  mem)
    run_mem
    go tool pprof -top -nodecount=25 "$OUT/mem.prof"
    ;;
  all)
    run_cpu
    run_mem
    go tool pprof -top -nodecount=25 "$OUT/cpu.prof" | head -30
    echo "---- starting pprof UI: http://localhost:8080 (Ctrl-C to stop) ----"
    # -http 提供交互式调用图 + 火焰图（Flame Graph）视图
    go tool pprof -http=:8080 "$OUT/cpu.prof"
    ;;
  *)
    echo "usage: $0 [cpu|mem|all]" >&2
    exit 2
    ;;
esac
