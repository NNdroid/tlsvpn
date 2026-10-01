#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
OPENWRT_VERSION="${OPENWRT_VERSION:-25.12.5}"
OPENWRT_TARGET="${OPENWRT_TARGET:-x86}"
OPENWRT_SUBTARGET="${OPENWRT_SUBTARGET:-64}"
OPENWRT_INCLUDE_ARCH_INDEPENDENT="${OPENWRT_INCLUDE_ARCH_INDEPENDENT:-0}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
case "$OPENWRT_VERSION" in 25.12*|SNAPSHOT) ;; *) echo "error: OpenWrt APK builds require 25.12+" >&2; exit 2;; esac
for tool in curl sha256sum tar zstd git make; do command -v "$tool" >/dev/null || exit 2; done
SOURCE_VERSION="${TLSVPN_SOURCE_VERSION:-$(git rev-parse HEAD)}"
SOURCE_DATE="${TLSVPN_SOURCE_DATE:-$(git show -s --format=%cs "$SOURCE_VERSION" 2>/dev/null || date -u +%Y-%m-%d)}"
# A shared source commit gives feed and release builds a stable APK revision.
SOURCE_EPOCH="$(git show -s --format=%ct "$SOURCE_VERSION")"
[[ "$SOURCE_EPOCH" =~ ^[0-9]+$ ]] || { echo 'error: invalid source commit timestamp' >&2; exit 1; }
PACKAGE_RELEASE="$SOURCE_EPOCH"
source_day="$(printf '%s' "$SOURCE_DATE" | tr -d '-')"
normalize_apk_version(){ local raw="${1#v}"; if [[ "$raw" =~ ^[0-9]+([.][0-9]+)*(_(alpha|beta|pre|rc|cvs|svn|git|hg|p)[0-9]+)?$ ]]; then printf '%s\n' "$raw"; elif [[ "$raw" =~ ^([0-9]+([.][0-9]+)*)-([0-9]+)-g[0-9A-Fa-f]+$ ]]; then printf '%s_p%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}"; else printf '0.0.%s_git%s\n' "$source_day" "$SOURCE_EPOCH"; fi; }
PACKAGE_VERSION="$(normalize_apk_version "${TLSVPN_PKG_VERSION:-0.0.${source_day}_git${SOURCE_EPOCH}}")"
SDK_BASE_URL="${OPENWRT_SDK_BASE_URL:-https://downloads.openwrt.org/releases/$OPENWRT_VERSION/targets/$OPENWRT_TARGET/$OPENWRT_SUBTARGET}"
CACHE_HOME="${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}"; WORK_DIR="${OPENWRT_WORK_DIR:-${RUNNER_TEMP:-$CACHE_HOME}/tlsvpn-openwrt-sdk/$OPENWRT_VERSION-$OPENWRT_TARGET-$OPENWRT_SUBTARGET}"; DOWNLOAD_DIR="$WORK_DIR/download"; SDK_DIR="$WORK_DIR/sdk"; OUTPUT_DIR="${OPENWRT_OUTPUT_DIR:-$ROOT_DIR/bin/openwrt/$OPENWRT_TARGET-$OPENWRT_SUBTARGET}"; mkdir -p "$DOWNLOAD_DIR" "$OUTPUT_DIR"
index_html="$(curl --retry 4 --retry-all-errors --fail -sSL "$SDK_BASE_URL/")"; sdk_name="$(printf '%s' "$index_html"|grep -oE 'openwrt-sdk-[^"<> ]+\.Linux-x86_64\.tar\.zst'|sort -u|head -1)"; [ -n "$sdk_name" ] || exit 1
archive="$DOWNLOAD_DIR/$sdk_name"; sums="$DOWNLOAD_DIR/sha256sums"; [ -s "$archive" ] || curl --retry 4 --retry-all-errors --fail -L "$SDK_BASE_URL/$sdk_name" -o "$archive"; curl --fail -sSL "$SDK_BASE_URL/sha256sums" -o "$sums"; checksum_line="$(awk -v name="$sdk_name" '$2 == name || $2 == "*" name {print;exit}' "$sums")"; (cd "$DOWNLOAD_DIR"; printf '%s\n' "$checksum_line"|sha256sum -c -)
rm -rf "$SDK_DIR"; mkdir -p "$SDK_DIR"; tar --zstd -xf "$archive" -C "$SDK_DIR" --strip-components=1
(cd "$SDK_DIR"; ./scripts/feeds update packages luci; ./scripts/feeds install -p packages golang; ./scripts/feeds install -p luci luci-base)
rm -rf "$SDK_DIR/package/tlsvpn" "$SDK_DIR/package/luci-proto-tlsvpn"; cp -a openwrt/package/tlsvpn "$SDK_DIR/package/tlsvpn"; cp -a openwrt/luci-proto-tlsvpn "$SDK_DIR/package/luci-proto-tlsvpn"

# LuCI creates translation APKs from real po/* directories. English is the
# source language, so LUCI_LANG.en does not create luci-i18n-tlsvpn-en.apk.
luci_i18n_packages=()
while IFS= read -r lang_dir; do
  lang="$(basename "$lang_dir")"
  case "$lang" in
    zh_Hans) suffix="zh-cn" ;;
    zh_Hant) suffix="zh-tw" ;;
    *) suffix="${lang//_/-}"; suffix="${suffix,,}" ;;
  esac
  luci_i18n_packages+=("luci-i18n-tlsvpn-$suffix")
done < <(find openwrt/luci-proto-tlsvpn/po -mindepth 1 -maxdepth 1 -type d | sort)
[ "${#luci_i18n_packages[@]}" -gt 0 ] || { echo 'error: no LuCI translation directories found' >&2; exit 1; }

cat >>"$SDK_DIR/.config" <<'EOF'
CONFIG_PACKAGE_tlsvpn=m
CONFIG_PACKAGE_tlsvpn-proto=m
CONFIG_PACKAGE_luci-proto-tlsvpn=m
EOF
for pkg in "${luci_i18n_packages[@]}"; do printf 'CONFIG_PACKAGE_%s=m\n' "$pkg" >>"$SDK_DIR/.config"; done
make_args=("TLSVPN_SOURCE_VERSION=$SOURCE_VERSION" "TLSVPN_SOURCE_DATE=$SOURCE_DATE" "TLSVPN_PKG_VERSION=$PACKAGE_VERSION" "TLSVPN_PKG_RELEASE=$PACKAGE_RELEASE"); make -C "$SDK_DIR" "${make_args[@]}" defconfig; make -C "$SDK_DIR" -j"$JOBS" "${make_args[@]}" package/tlsvpn/compile V=sc; make -C "$SDK_DIR" -j"$JOBS" "${make_args[@]}" package/luci-proto-tlsvpn/compile V=sc
rm -f "$OUTPUT_DIR"/*.apk "$OUTPUT_DIR"/SHA256SUMS-*.txt 2>/dev/null || true; main_count=0
while IFS= read -r apk; do base="$(basename "$apk")"; case "$base" in luci-i18n-tlsvpn-*.apk) [ "$OPENWRT_INCLUDE_ARCH_INDEPENDENT" = 1 ]||continue; dest="${base%.apk}-openwrt-$OPENWRT_VERSION-all.apk";; tlsvpn-proto-*.apk|luci-proto-tlsvpn-*.apk) [ "$OPENWRT_INCLUDE_ARCH_INDEPENDENT" = 1 ]||continue; dest="${base%.apk}-openwrt-$OPENWRT_VERSION-all.apk";; tlsvpn-*.apk) dest="${base%.apk}-openwrt-$OPENWRT_VERSION-$OPENWRT_TARGET-$OPENWRT_SUBTARGET.apk"; main_count=$((main_count+1));; *) continue;; esac; cp -f "$apk" "$OUTPUT_DIR/$dest"; done < <(find "$SDK_DIR/bin" -type f -name '*.apk'|sort)
[ "$main_count" -ge 1 ] || { echo 'error: tlsvpn APK was not produced' >&2; exit 1; }
if [ "$OPENWRT_INCLUDE_ARCH_INDEPENDENT" = 1 ]; then
  required_independent_packages=(tlsvpn-proto luci-proto-tlsvpn "${luci_i18n_packages[@]}")
  missing_packages=()
  for pkg in "${required_independent_packages[@]}"; do
    if ! find "$OUTPUT_DIR" -maxdepth 1 -type f -name "${pkg}-*-openwrt-$OPENWRT_VERSION-all.apk" -print -quit | grep -q .; then
      missing_packages+=("$pkg")
    fi
  done
  if [ "${#missing_packages[@]}" -ne 0 ]; then
    printf 'error: missing architecture-independent OpenWrt APK(s): %s\n' "${missing_packages[*]}" >&2
    exit 1
  fi
fi
checksum_file="$OUTPUT_DIR/SHA256SUMS-openwrt-$OPENWRT_VERSION-$OPENWRT_TARGET-$OPENWRT_SUBTARGET.txt"; (cd "$OUTPUT_DIR"; sha256sum ./*.apk >"$(basename "$checksum_file")"); ls -lh "$OUTPUT_DIR"
