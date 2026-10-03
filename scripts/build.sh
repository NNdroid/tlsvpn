#!/bin/bash
# build.sh — 编译 tlsvpn（Go）。
#
# 用法：
#   ./scripts/build.sh                         # 完整 Linux 发布矩阵
#   ./scripts/build.sh host                    # 仅当前宿主平台
#   ./scripts/build.sh linux                   # 完整 Linux 发布矩阵
#   ./scripts/build.sh linux/amd64@v3          # GOAMD64=v3 专属优化版
#   ./scripts/build.sh linux/arm64@v8.2        # GOARM64=v8.2 专属优化版
#   ./scripts/build.sh linux/ppc64le@power10   # GOPPC64=power10
#   ./scripts/build.sh linux/riscv64@rva22u64  # GORISCV64=rva22u64
#   ./scripts/build.sh --list                  # 仅列出默认发布矩阵，不编译
#
# @variant 根据 GOARCH 映射到 Go 的架构环境变量：
#   amd64    -> GOAMD64=v1|v2|v3|v4
#   arm64    -> GOARM64=v8.x/v9.x[,lse][,crypto]
#   arm      -> GOARM=5|6|7（也接受 v5|v6|v7）
#   ppc64*   -> GOPPC64=power8|power9|power10
#   riscv64  -> GORISCV64=rva20u64|rva22u64|rva23u64
#
# 环境变量：
#   VERSION=1.2.3       覆盖 main.appVersion（默认 git describe / 时间戳）
#   JOBS=N              并行编译度
#   HOST_ALIAS=0        不生成 bin/tlsvpn[.exe] 宿主固定名副本
#   GOARM64_LEVEL=...   兼容旧调用：未写 @variant 的 arm64 目标可指定 GOARM64
#   PGO_MODE=auto       auto | off | profile-file
#   ARTIFACT_SUFFIX=s   输出名追加 _s
#   CLEAN_OUTPUT=0      保留已有 bin/tlsvpn_*；默认清理
#
# 说明：linux/amd64 保持 Go 默认 GOAMD64=v1，确保最广兼容；v2/v3/v4 是额外
# release 产物而不是替换基线。高 ISA 二进制会在不满足最低 CPU 特性的机器上拒绝运行。

set -euo pipefail

cd "$(dirname "$0")/.."

APP_NAME="tlsvpn"
OUTPUT_DIR="bin"
VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || date +%Y%m%d_%H%M%S)}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
HOST_ALIAS="${HOST_ALIAS:-1}"
PGO_MODE="${PGO_MODE:-auto}"
ARTIFACT_SUFFIX="${ARTIFACT_SUFFIX:-}"
CLEAN_OUTPUT="${CLEAN_OUTPUT:-1}"

if [ "$PGO_MODE" != "auto" ] && [ "$PGO_MODE" != "off" ] && [ ! -f "$PGO_MODE" ]; then
    echo "PGO profile not found: $PGO_MODE" >&2
    exit 2
fi

if [ "$PGO_MODE" = "auto" ]; then
    if [ -f default.pgo ]; then
        echo "PGO: auto -> default.pgo"
    else
        echo "PGO: auto -> no default.pgo (compiler will build without PGO)"
    fi
else
    echo "PGO: $PGO_MODE"
fi

# 完整 Linux 发布矩阵。
# 文件名规则：通用基线不带 ISA 后缀，专属优化版带后缀。
LINUX_MATRIX=(
    "linux/amd64"              # GOAMD64=v1，所有 x86-64 的兼容基线
    "linux/amd64@v2"           # SSE3/SSSE3/SSE4/POPCNT 等
    "linux/amd64@v3"           # AVX/AVX2/BMI/FMA 等，现代服务器推荐
    "linux/amd64@v4"           # AVX-512 系列
    "linux/386"                # 32 位 x86
    "linux/arm64"              # GOARM64=v8.0 通用基线
    "linux/arm64@v8.2"         # ARMv8.2-A（RK3588 等）
    "linux/arm@v5"             # ARMv5 老设备
    "linux/arm@v6"             # ARMv6
    "linux/arm"                # Go 交叉编译默认 GOARM=7；保持旧文件名兼容
    "linux/mipsle"
    "linux/mips"
    "linux/mips64le"
    "linux/mips64"
    "linux/riscv64"
    "linux/ppc64le"
    "linux/ppc64le@power9"
    "linux/ppc64le@power10"
    "linux/ppc64"
    "linux/s390x"
    "linux/loong64"
)

safe_variant() {
    local v="$1"
    v="${v//,/_}"
    v="${v//\//_}"
    printf '%s' "$v"
}

normalize_variant() {
    local arch="$1" variant="$2"
    case "$arch" in
        amd64)
            case "$variant" in v1|v2|v3|v4) printf '%s' "$variant" ;; *) return 1 ;; esac
            ;;
        arm64)
            # Go 自己负责最终版本/扩展合法性校验；这里只拒绝明显危险字符。
            [[ "$variant" =~ ^v(8\.[0-9]|9\.[0-9])(,(lse|crypto))*$ ]] || return 1
            printf '%s' "$variant"
            ;;
        arm)
            case "$variant" in
                5|6|7) printf '%s' "$variant" ;;
                v5|v6|v7) printf '%s' "${variant#v}" ;;
                5,softfloat|6,softfloat|6,hardfloat|7,softfloat|7,hardfloat) printf '%s' "$variant" ;;
                *) return 1 ;;
            esac
            ;;
        ppc64|ppc64le)
            case "$variant" in power8|power9|power10) printf '%s' "$variant" ;; *) return 1 ;; esac
            ;;
        riscv64)
            case "$variant" in rva20u64|rva22u64|rva23u64) printf '%s' "$variant" ;; *) return 1 ;; esac
            ;;
        *) return 1 ;;
    esac
}

variant_env_name() {
    case "$1" in
        amd64) printf 'GOAMD64' ;;
        arm64) printf 'GOARM64' ;;
        arm) printf 'GOARM' ;;
        ppc64|ppc64le) printf 'GOPPC64' ;;
        riscv64) printf 'GORISCV64' ;;
        *) return 1 ;;
    esac
}

artifact_name() {
    local target="$1" platform="$1" variant="" variant_suffix="" goext=""
    if [[ "$target" == *@* ]]; then
        platform="${target%%@*}"
        variant="${target#*@}"
    fi
    local goos="${platform%%/*}" goarch="${platform##*/}"
    [ "$goos" = "windows" ] && goext=".exe"
    if [ -n "$variant" ]; then
        local display_variant="$variant"
        [ "$goarch" = "arm" ] && [[ "$display_variant" =~ ^[567]($|,) ]] && display_variant="v$display_variant"
        variant_suffix="_$(safe_variant "$display_variant")"
    fi
    local artifact_suffix=""
    [ -n "$ARTIFACT_SUFFIX" ] && artifact_suffix="_$ARTIFACT_SUFFIX"
    printf '%s/%s_%s_%s%s%s%s' "$OUTPUT_DIR" "$APP_NAME" "$goos" "$goarch" "$variant_suffix" "$artifact_suffix" "$goext"
}

list_matrix() {
    local target platform variant goarch envname normalized
    for target in "${LINUX_MATRIX[@]}"; do
        platform="${target%%@*}"
        variant=""
        [[ "$target" == *@* ]] && variant="${target#*@}"
        goarch="${platform##*/}"
        if [ -n "$variant" ]; then
            normalized="$(normalize_variant "$goarch" "$variant")" || normalized="INVALID"
            envname="$(variant_env_name "$goarch" 2>/dev/null || true)"
            printf '%-30s -> %-42s %s=%s\n' "$target" "$(basename "$(artifact_name "$target")")" "$envname" "$normalized"
        else
            printf '%-30s -> %s\n' "$target" "$(basename "$(artifact_name "$target")")"
        fi
    done
}

if [ "${1:-}" = "--list" ]; then
    list_matrix
    exit 0
fi

TARGETS=()
if [ "$#" -eq 0 ]; then
    TARGETS=("${LINUX_MATRIX[@]}")
else
    for arg in "$@"; do
        case "$arg" in
            host) TARGETS+=("$(go env GOOS)/$(go env GOARCH)") ;;
            linux) TARGETS+=("${LINUX_MATRIX[@]}") ;;
            */*) TARGETS+=("$arg") ;;
            *) echo "unknown target: $arg (use host, linux, --list, or GOOS/GOARCH[@variant])" >&2; exit 2 ;;
        esac
    done
fi

mkdir -p "$OUTPUT_DIR"
if [ "$CLEAN_OUTPUT" = "1" ]; then
    rm -f "$OUTPUT_DIR/${APP_NAME}_"* "$OUTPUT_DIR/${APP_NAME}" "$OUTPUT_DIR/${APP_NAME}.exe" \
        "$OUTPUT_DIR/SHA256SUMS-native.txt" 2>/dev/null || true
fi

echo "Building $APP_NAME (version $VERSION, jobs $JOBS, pgo $PGO_MODE) for: ${TARGETS[*]}"

build_one() {
    local target="$1" platform="$1" variant=""
    if [[ "$target" == *@* ]]; then
        platform="${target%%@*}"
        variant="${target#*@}"
    fi

    local goos="${platform%%/*}" goarch="${platform##*/}"
    if [ "$goos" = "$platform" ] || [ -z "$goos" ] || [ -z "$goarch" ]; then
        echo "  invalid target: $target" >&2
        return 2
    fi

    local normalized="" envname=""
    if [ -n "$variant" ]; then
        normalized="$(normalize_variant "$goarch" "$variant")" || {
            echo "  invalid variant @$variant for GOARCH=$goarch ($target)" >&2
            return 2
        }
        envname="$(variant_env_name "$goarch")" || {
            echo "  architecture $goarch does not support @variant syntax" >&2
            return 2
        }
    elif [ "$goarch" = "arm64" ] && [ -n "${GOARM64_LEVEL:-}" ]; then
        normalized="$GOARM64_LEVEL"
        envname="GOARM64"
    fi

    local built
    built="$(artifact_name "$target")"

    # 每个 build_one 本身运行在独立子 shell 中，直接 export 不会污染其它并行目标。
    export CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch"
    if [ -n "$envname" ]; then
        export "$envname=$normalized"
        echo "  $goarch ISA: $envname=$normalized -> $(basename "$built")"
    fi

    go build -pgo="$PGO_MODE" -ldflags "-s -w -X main.appVersion=$VERSION" -trimpath \
        -o "$built" .

    local goext=""
    [ "$goos" = "windows" ] && goext=".exe"
    if [ "$HOST_ALIAS" = "1" ] && [ -z "$variant" ] \
        && [ "$goos" = "$(go env GOOS)" ] && [ "$goarch" = "$(go env GOARCH)" ]; then
        cp "$built" "$OUTPUT_DIR/${APP_NAME}${goext}"
    fi
    echo "  ok: $(basename "$built")"
}

pids=(); plats=(); fail=0
for platform in "${TARGETS[@]}"; do
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

# Native release assets get one deterministic checksum manifest. Do not include the
# host alias, because release workflows set HOST_ALIAS=0 and only publish platform names.
if command -v sha256sum >/dev/null 2>&1; then
    (
        cd "$OUTPUT_DIR"
        find . -maxdepth 1 -type f -name "${APP_NAME}_*" -printf '%f\n' | sort | xargs -r sha256sum
    ) > "$OUTPUT_DIR/SHA256SUMS-native.txt"
fi

echo "---------------------------------------"
echo "Build complete ($VERSION). Output in '$OUTPUT_DIR/':"
ls -lh "$OUTPUT_DIR"
