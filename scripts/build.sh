#!/bin/bash
# build.sh — 编译 tlsvpn（Go）。
#
# 用法：
#   ./scripts/build.sh                 # 交叉编译 Linux 矩阵（发布用，默认）
#   ./scripts/build.sh host            # 仅编译当前宿主平台（本机开发）
#   ./scripts/build.sh linux/arm64     # 指定单个 GOOS/GOARCH
#   ./scripts/build.sh host linux/amd64 linux/arm64   # 混合指定
#
# 环境变量：
#   VERSION=1.2.3   覆盖注入到 main.appVersion 的版本号
#                   （默认：git describe --tags → 时间戳）
#   JOBS=N          并行编译度（默认取 CPU 核数）
#   HOST_ALIAS=0    不生成宿主平台的固定名副本 bin/tlsvpn[.exe]。发布 workflow
#                   需要设为 0：runner 是 linux/amd64，而矩阵里正好有这个目标，
#                   多出的无平台名副本上传后会成为 release 里的重复件。
#   GOARM64_LEVEL=... 仅作用于 GOARCH=arm64 的可选最低 ISA，例如 v8.2 或
#                   v8.2,crypto。默认留空，Go 使用通用 v8.0。只有确认目标
#                   CPU 支持对应扩展时才设置；例如：
#                   GOARM64_LEVEL=v8.2 ./scripts/build.sh linux/arm64
#   ARTIFACT_SUFFIX=s  输出文件追加 "_s"，用于同一目录并存优化变体。
#   CLEAN_OUTPUT=0     不清理已有 bin/tlsvpn_*；默认 1。
#
# 说明：本项目依赖 Linux 的 TAP 与 netlink，非 Linux 平台的编译仅用于代码
# 检查 / 本地 e2e（-tap mem），无法实际建隧道。

set -euo pipefail

cd "$(dirname "$0")/.."

APP_NAME="tlsvpn"
OUTPUT_DIR="bin"
VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || date +%Y%m%d_%H%M%S)}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
HOST_ALIAS="${HOST_ALIAS:-1}"
ARTIFACT_SUFFIX="${ARTIFACT_SUFFIX:-}"
CLEAN_OUTPUT="${CLEAN_OUTPUT:-1}"

# 默认目标：Linux 发布矩阵
LINUX_MATRIX=(
    "linux/amd64"   # 傳統 64 位伺服器
    "linux/386"     # 傳統 32 位伺服器
    "linux/arm64"   # 新型伺服器 (AWS Graviton), 樹莓派 4/5
    "linux/arm"     # 嵌入式設備, 舊款樹莓派
    "linux/mipsle"  # 路由器常見架構 (Little Endian)
    "linux/mips"    # 路由器常見架構 (Big Endian)
)

# 解析命令行目标：无参数=Linux 矩阵；host=当前平台；其余按 GOOS/GOARCH 处理
TARGETS=()
if [ "$#" -eq 0 ]; then
    TARGETS=("${LINUX_MATRIX[@]}")
else
    for arg in "$@"; do
        case "$arg" in
            host)   TARGETS+=("$(go env GOOS)/$(go env GOARCH)") ;;
            linux)  TARGETS+=("${LINUX_MATRIX[@]}") ;;
            */*)    TARGETS+=("$arg") ;;
            *) echo "unknown target: $arg (use 'host', 'linux', or GOOS/GOARCH)" >&2; exit 2 ;;
        esac
    done
fi

mkdir -p "$OUTPUT_DIR"
# 清理旧产物（仅本脚本命名的文件，避免误删）。多变体构建可设 CLEAN_OUTPUT=0。
if [ "$CLEAN_OUTPUT" = "1" ]; then
    rm -f "$OUTPUT_DIR/${APP_NAME}_"* "$OUTPUT_DIR/${APP_NAME}" "$OUTPUT_DIR/${APP_NAME}.exe" 2>/dev/null || true
fi

echo "Building $APP_NAME (version $VERSION, jobs $JOBS) for: ${TARGETS[*]}"

# 单个平台构建：输出到 bin/，失败退出码非零。
# CGO_ENABLED=0 静态无依赖；-trimpath 可复现；-X 注入版本；-s -w 压缩。
# go build 对显式 -o 使用精确文件名（不会自动补 .exe），故 windows 目标
# 由我们显式加 .exe。宿主平台额外复制一份固定名 bin/tlsvpn[.exe] 方便本机
# 直接运行（HOST_ALIAS=0 关闭，发布 workflow 就是靠这个避免多出无平台名副本）。
build_one() {
    local platform="$1"
    local goos="${platform%%/*}"
    local goarch="${platform##*/}"
    local goext=""
    [ "$goos" = "windows" ] && goext=".exe"
    local suffix=""
    [ -n "$ARTIFACT_SUFFIX" ] && suffix="_$ARTIFACT_SUFFIX"
    local built="$OUTPUT_DIR/${APP_NAME}_${goos}_${goarch}${suffix}${goext}"
    # 用变量前缀而非 `env ...`：MSYS/Git Bash 下 `env GOOS=… go build -o` 会
    # 把产物静默写到别处（exit 0 但当前目录无文件），前缀形式跨平台一致。
    if [ "$goarch" = "arm64" ] && [ -n "${GOARM64_LEVEL:-}" ]; then
        echo "  arm64 ISA: GOARM64=$GOARM64_LEVEL"
        CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM64="$GOARM64_LEVEL" go build \
            -ldflags "-s -w -X main.appVersion=$VERSION" -trimpath \
            -o "$built" .
    else
        CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
            -ldflags "-s -w -X main.appVersion=$VERSION" -trimpath \
            -o "$built" .
    fi
    if [ "$HOST_ALIAS" = "1" ] \
        && [ "$goos" = "$(go env GOOS)" ] && [ "$goarch" = "$(go env GOARCH)" ]; then
        cp "$built" "$OUTPUT_DIR/${APP_NAME}${goext}"
    fi
    echo "  ok: $(basename "$built")"
}

# 并行构建：按 JOBS 限流，收集后台 PID 与对应平台，任一失败则整体失败。
pids=(); plats=()
fail=0
for platform in "${TARGETS[@]}"; do
    # 控制在飞任务数
    while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do sleep 0.2; done
    ( build_one "$platform" ) &
    pids+=("$!"); plats+=("$platform")
done
for i in "${!pids[@]}"; do
    if ! wait "${pids[$i]}"; then
        echo "  FAIL: ${plats[$i]}" >&2
        fail=1
    fi
done
[ "$fail" -eq 0 ] || { echo "one or more targets failed" >&2; exit 1; }

echo "---------------------------------------"
echo "Build complete ($VERSION). Output in '$OUTPUT_DIR/':"
ls -lh "$OUTPUT_DIR"
