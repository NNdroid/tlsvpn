#!/bin/bash
# build.sh — 交叉编译 tlsvpn 到常见路由器/服务器架构（静态、无 CGO）。
#
# 版本号：默认取 git describe（tag），无 git 元数据时退回时间戳；
# 可用环境变量覆盖：VERSION=1.2.3 ./scripts/build.sh
# 注入到 main.appVersion（见 api.go），面板 /api/stats 与日志会显示该值。
#
# 注意：本项目依赖 Linux 的 TAP 与 netlink，非 Linux 平台编译仅用于代码检查。

set -euo pipefail

cd "$(dirname "$0")/.."

# 項目名稱
APP_NAME="tlsvpn"
# 輸出目錄
OUTPUT_DIR="bin"
# 版本號：env 覆盖 > git describe > 时间戳
VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || date +%Y%m%d_%H%M%S)}"

# 建立輸出目錄並清理舊的編譯檔案
mkdir -p "$OUTPUT_DIR"
echo "Cleaning old binaries..."
rm -f "$OUTPUT_DIR"/*.exe "$OUTPUT_DIR/${APP_NAME}_"* 2>/dev/null || true

# 定義要編譯的目標平台 (OS/Arch)
PLATFORMS=(
    "linux/amd64"   # 傳統 64 位伺服器
    "linux/386"     # 傳統 32 位伺服器
    "linux/arm64"   # 新型伺服器 (如 AWS Graviton), 樹莓派 4/5
    "linux/arm"     # 嵌入式設備, 舊款樹莓派
    "linux/mipsle"  # 路由器常見架構 (Little Endian)
    "linux/mips"    # 路由器常見架構 (Big Endian)
)

echo "Starting build process for $APP_NAME (version $VERSION)..."

build_one() {
    local platform="$1"
    local goos goarch output_name
    IFS="/" read -r goos goarch <<< "$platform"

    output_name="${APP_NAME}_${goos}_${goarch}"

    # CGO_ENABLED=0: 靜態編譯，不依賴系統 libc，提高移植性
    # -ldflags="-s -w -X main.appVersion=...": 壓縮體積並注入版本號
    # -trimpath: 去除本機構建路徑，產物可復現
    echo "Building $platform -> $output_name"
    env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
        -ldflags "-s -w -X main.appVersion=$VERSION" -trimpath \
        -o "$OUTPUT_DIR/$output_name" .
}

for PLATFORM in "${PLATFORMS[@]}"
do
    build_one "$PLATFORM"
done

echo "---------------------------------------"
echo "Build complete! Check the '$OUTPUT_DIR' directory."
ls -lh "$OUTPUT_DIR"
