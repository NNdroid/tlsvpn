#!/usr/bin/env bash
# Build OpenWrt 25.12+ APK packages with an official OpenWrt SDK.
#
# Required/optional environment variables:
#   OPENWRT_VERSION=25.12.5          OpenWrt release (must use APK packaging)
#   OPENWRT_TARGET=x86               OpenWrt target
#   OPENWRT_SUBTARGET=64             OpenWrt subtarget
#   OPENWRT_SDK_BASE_URL=...         Override official SDK directory URL
#   OPENWRT_WORK_DIR=...             SDK download/extract workspace
#   OPENWRT_OUTPUT_DIR=...           APK output directory
#   OPENWRT_INCLUDE_ARCH_INDEPENDENT=1
#                                     Also export tlsvpn-proto and LuCI APKs.
#                                     Enable this for only one matrix target.
#   TLSVPN_SOURCE_VERSION=<git SHA>  Exact repo commit to package
#   TLSVPN_SOURCE_DATE=YYYY-MM-DD    Source date used by OpenWrt package metadata
#   TLSVPN_PKG_VERSION=1.2.3         APK package version (leading v is stripped)
#   JOBS=N                           Parallel make jobs
#
# Example:
#   OPENWRT_TARGET=rockchip OPENWRT_SUBTARGET=armv8 \
#     ./scripts/build_openwrt_apk.sh
#
# The output APK filenames are suffixed with the OpenWrt release/target so
# GitHub Release assets from multiple SDK matrix jobs never collide.

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OPENWRT_VERSION="${OPENWRT_VERSION:-25.12.5}"
OPENWRT_TARGET="${OPENWRT_TARGET:-x86}"
OPENWRT_SUBTARGET="${OPENWRT_SUBTARGET:-64}"
OPENWRT_INCLUDE_ARCH_INDEPENDENT="${OPENWRT_INCLUDE_ARCH_INDEPENDENT:-0}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

case "$OPENWRT_VERSION" in
    25.12*|SNAPSHOT) ;;
    *)
        echo "error: OpenWrt APK builds require 25.12+; got OPENWRT_VERSION=$OPENWRT_VERSION" >&2
        exit 2
        ;;
esac

for tool in curl sha256sum tar zstd git make; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: required tool not found: $tool" >&2
        exit 2
    }
done

SOURCE_VERSION="${TLSVPN_SOURCE_VERSION:-$(git rev-parse HEAD)}"
SOURCE_DATE="${TLSVPN_SOURCE_DATE:-$(git show -s --format=%cs "$SOURCE_VERSION" 2>/dev/null || date -u +%Y-%m-%d)}"

if [ -n "${TLSVPN_PKG_VERSION:-}" ]; then
    PACKAGE_VERSION="$TLSVPN_PKG_VERSION"
elif [ "${GITHUB_REF_TYPE:-}" = "tag" ] && [ -n "${GITHUB_REF_NAME:-}" ]; then
    PACKAGE_VERSION="$GITHUB_REF_NAME"
else
    short_source="$(printf '%s' "$SOURCE_VERSION" | cut -c1-12)"
    source_day="$(printf '%s' "$SOURCE_DATE" | tr -d '-')"
    PACKAGE_VERSION="0.0.${source_day}+git.${short_source}"
fi
PACKAGE_VERSION="${PACKAGE_VERSION#v}"
PACKAGE_VERSION="$(printf '%s' "$PACKAGE_VERSION" | tr -c 'A-Za-z0-9._+-' '-')"
PACKAGE_VERSION="${PACKAGE_VERSION%-}"
[ -n "$PACKAGE_VERSION" ] || PACKAGE_VERSION="0.0.0"

SDK_BASE_URL="${OPENWRT_SDK_BASE_URL:-https://downloads.openwrt.org/releases/$OPENWRT_VERSION/targets/$OPENWRT_TARGET/$OPENWRT_SUBTARGET}"

# Keep the SDK workspace outside the repository tree. OpenWrt builds Go through
# several bootstrap toolchains; if the SDK lives below ROOT_DIR, an older Go
# command can walk up to ROOT_DIR/go.mod and incorrectly trigger automatic
# toolchain selection for TLSVPN (for example, trying to download Go 1.26.x
# while OpenWrt is still compiling its Go 1.24 bootstrap stage).
if [ -n "${RUNNER_TEMP:-}" ]; then
    DEFAULT_OPENWRT_WORK_ROOT="$RUNNER_TEMP/tlsvpn-openwrt-sdk"
else
    CACHE_HOME="${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}"
    DEFAULT_OPENWRT_WORK_ROOT="$CACHE_HOME/tlsvpn/openwrt-sdk"
fi
WORK_DIR="${OPENWRT_WORK_DIR:-$DEFAULT_OPENWRT_WORK_ROOT/$OPENWRT_VERSION-$OPENWRT_TARGET-$OPENWRT_SUBTARGET}"
DOWNLOAD_DIR="$WORK_DIR/download"
SDK_DIR="$WORK_DIR/sdk"
OUTPUT_DIR="${OPENWRT_OUTPUT_DIR:-$ROOT_DIR/bin/openwrt/$OPENWRT_TARGET-$OPENWRT_SUBTARGET}"

mkdir -p "$DOWNLOAD_DIR" "$OUTPUT_DIR"

echo "==> OpenWrt APK build"
echo "    version:       $OPENWRT_VERSION"
echo "    target:        $OPENWRT_TARGET/$OPENWRT_SUBTARGET"
echo "    source commit: $SOURCE_VERSION"
echo "    source date:   $SOURCE_DATE"
echo "    package ver:   $PACKAGE_VERSION"
echo "    sdk index:     $SDK_BASE_URL"

index_html="$(curl --retry 4 --retry-all-errors --fail --silent --show-error --location "$SDK_BASE_URL/")"
sdk_name="$(
    printf '%s' "$index_html" |
        grep -oE 'openwrt-sdk-[^"<> ]+\.Linux-x86_64\.tar\.zst' |
        sort -u |
        head -n 1
)"

if [ -z "$sdk_name" ]; then
    echo "error: no Linux x86_64 SDK archive found at $SDK_BASE_URL/" >&2
    exit 1
fi

archive="$DOWNLOAD_DIR/$sdk_name"
sums="$DOWNLOAD_DIR/sha256sums"

if [ ! -s "$archive" ]; then
    echo "==> Downloading $sdk_name"
    curl --retry 4 --retry-all-errors --fail --location         "$SDK_BASE_URL/$sdk_name" -o "$archive"
else
    echo "==> Reusing cached $archive"
fi

curl --retry 4 --retry-all-errors --fail --silent --show-error --location     "$SDK_BASE_URL/sha256sums" -o "$sums"

# OpenWrt publishes GNU sha256sum binary-mode entries as
#   <hash> *filename
# while some mirrors/tools may use the text-mode form
#   <hash>  filename
# Match the filename field semantically instead of assuming either separator.
checksum_line="$(
    awk -v name="$sdk_name" '
        $2 == name || $2 == "*" name { print; exit }
    ' "$sums"
)"
if [ -z "$checksum_line" ]; then
    echo "error: checksum for $sdk_name not found in sha256sums" >&2
    exit 1
fi

echo "==> Verifying official SDK checksum"
(
    cd "$DOWNLOAD_DIR"
    printf '%s\n' "$checksum_line" | sha256sum -c -
)

echo "==> Extracting SDK"
rm -rf "$SDK_DIR"
mkdir -p "$SDK_DIR"
tar --zstd -xf "$archive" -C "$SDK_DIR" --strip-components=1

echo "==> Preparing the OpenWrt Go build feed"
(
    cd "$SDK_DIR"
    # TLSVPN only needs the Go packaging helpers at build time. The LuCI
    # protocol package is static JavaScript, while kmod-tun, ca-bundle,
    # resolveip and luci-base are runtime dependencies supplied by the target
    # firmware repositories. Installing entire feeds here makes an SDK build
    # scan thousands of unrelated packages and can drag kernel/Lua build
    # dependencies into package/tlsvpn/compile.
    ./scripts/feeds update packages
    ./scripts/feeds install -p packages golang
)

echo "==> Injecting TLSVPN packages"
rm -rf "$SDK_DIR/package/tlsvpn" "$SDK_DIR/package/luci-proto-tlsvpn"
cp -a "$ROOT_DIR/openwrt/package/tlsvpn" "$SDK_DIR/package/tlsvpn"
cp -a "$ROOT_DIR/openwrt/luci-proto-tlsvpn" "$SDK_DIR/package/luci-proto-tlsvpn"

cat >> "$SDK_DIR/.config" <<'EOF'
CONFIG_PACKAGE_tlsvpn=m
CONFIG_PACKAGE_tlsvpn-proto=m
CONFIG_PACKAGE_luci-proto-tlsvpn=m
EOF

make_args=(
    "TLSVPN_SOURCE_VERSION=$SOURCE_VERSION"
    "TLSVPN_SOURCE_DATE=$SOURCE_DATE"
    "TLSVPN_PKG_VERSION=$PACKAGE_VERSION"
)

echo "==> Resolving package configuration"
make -C "$SDK_DIR" "${make_args[@]}" defconfig

echo "==> Building tlsvpn + tlsvpn-proto APKs"
make -C "$SDK_DIR" -j"$JOBS" "${make_args[@]}" package/tlsvpn/compile V=sc

echo "==> Building luci-proto-tlsvpn APK"
make -C "$SDK_DIR" -j"$JOBS" "${make_args[@]}" package/luci-proto-tlsvpn/compile V=sc

echo "==> Collecting APKs"
rm -f "$OUTPUT_DIR"/*.apk "$OUTPUT_DIR"/SHA256SUMS-*.txt 2>/dev/null || true

main_count=0
independent_count=0

while IFS= read -r apk; do
    base="$(basename "$apk")"

    case "$base" in
        tlsvpn-proto-*.apk|luci-proto-tlsvpn-*.apk)
            [ "$OPENWRT_INCLUDE_ARCH_INDEPENDENT" = "1" ] || continue
            dest="${base%.apk}-openwrt-$OPENWRT_VERSION-all.apk"
            independent_count=$((independent_count + 1))
            ;;
        tlsvpn-*.apk)
            dest="${base%.apk}-openwrt-$OPENWRT_VERSION-$OPENWRT_TARGET-$OPENWRT_SUBTARGET.apk"
            main_count=$((main_count + 1))
            ;;
        *)
            continue
            ;;
    esac

    cp -f "$apk" "$OUTPUT_DIR/$dest"
    echo "    $dest"
done < <(find "$SDK_DIR/bin" -type f -name '*.apk' | sort)

if [ "$main_count" -lt 1 ]; then
    echo "error: tlsvpn APK was not produced" >&2
    find "$SDK_DIR/bin" -type f -name '*.apk' -print >&2 || true
    exit 1
fi

if [ "$OPENWRT_INCLUDE_ARCH_INDEPENDENT" = "1" ] && [ "$independent_count" -lt 2 ]; then
    echo "error: expected tlsvpn-proto and luci-proto-tlsvpn APKs" >&2
    find "$SDK_DIR/bin" -type f -name '*.apk' -print >&2 || true
    exit 1
fi

checksum_file="$OUTPUT_DIR/SHA256SUMS-openwrt-$OPENWRT_VERSION-$OPENWRT_TARGET-$OPENWRT_SUBTARGET.txt"
(
    cd "$OUTPUT_DIR"
    sha256sum ./*.apk > "$(basename "$checksum_file")"
)

echo "==> APK build complete"
ls -lh "$OUTPUT_DIR"
