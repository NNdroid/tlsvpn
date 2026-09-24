#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
proto="${repo_root}/openwrt/package/tlsvpn/files/lib/netifd/proto/tlsvpn.sh"
up="${repo_root}/openwrt/package/tlsvpn/files/lib/netifd/tlsvpn-up"
down="${repo_root}/openwrt/package/tlsvpn/files/lib/netifd/tlsvpn-down"
luci="${repo_root}/openwrt/luci-proto-tlsvpn/htdocs/luci-static/resources/protocol/tlsvpn.js"
apk_builder="${repo_root}/scripts/build_openwrt_apk.sh"
release_workflow="${repo_root}/.github/workflows/build_and_release.yml"
package_makefile="${repo_root}/openwrt/package/tlsvpn/Makefile"
luci_makefile="${repo_root}/openwrt/luci-proto-tlsvpn/Makefile"

for script in "${proto}" "${up}" "${down}"; do
	sh -n "${script}"
done
bash -n "${apk_builder}"

grep -Fq 'json_add_string interface_manager netifd' "${proto}"
grep -Fq 'proto_add_host_dependency "$interface" "$ip" "$tunlink"' "${proto}"
grep -Fq 'proto_run_command "$interface" /usr/bin/tlsvpn -c "$config"' "${proto}"
grep -Fq 'TLSVPN_NETIFD_INTERFACE=$interface' "${proto}"
grep -Fq 'resolved_server="$resolved_server$resolved_endpoint"' "${proto}"
grep -Fq 'resolved_socks5="$scheme$userinfo$resolved_endpoint"' "${proto}"
grep -Fq 'SOCKS5_HOST_DEPENDENCY_FAILED' "${proto}"
grep -Fq '[ -n "$min_enc" ] && json_add_string min_enc "$min_enc"' "${proto}"

grep -Fq 'proto_init_update "$device" 1' "${up}"
if grep -Fq 'proto_set_keep 1' "${up}"; then
	echo "tlsvpn-up must replace stale netifd addresses instead of preserving them" >&2
	exit 1
fi
grep -Fq 'proto_add_ipv4_address' "${up}"
grep -Fq 'proto_add_ipv6_address' "${up}"
grep -Fq 'proto_add_ipv4_route "0.0.0.0" 0' "${up}"
grep -Fq 'proto_add_ipv6_route "::" 0' "${up}"
grep -Fq 'proto_init_update "$device" 0' "${down}"

grep -Fq "network.registerProtocol('tlsvpn'" "${luci}"
grep -Fq "getPackageName" "${luci}"
grep -Fq "'tlsvpn-proto'" "${luci}"

if command -v node >/dev/null 2>&1; then
	node --check "${luci}"
fi

grep -Fq 'OPENWRT_VERSION="${OPENWRT_VERSION:-25.12.5}"' "${apk_builder}"
grep -Fq 'TLSVPN_SOURCE_VERSION' "${apk_builder}"
grep -Fq 'sha256sum -c -' "${apk_builder}"
grep -Fq 'package/tlsvpn/compile' "${apk_builder}"
grep -Fq 'package/luci-proto-tlsvpn/compile' "${apk_builder}"
grep -Fq 'OPENWRT_INCLUDE_ARCH_INDEPENDENT' "${apk_builder}"
grep -Fq 'normalize_apk_version()' "${apk_builder}"
grep -Fq '0.0.${source_day}_git${SOURCE_EPOCH}' "${apk_builder}"
if grep -Ev '^[[:space:]]*#' "${apk_builder}" | grep -Fq '+git.'; then
	echo "APK package version generation must not use SemVer +git build metadata" >&2
	exit 1
fi

grep -Fq './scripts/feeds update packages' "${apk_builder}"
grep -Fq './scripts/feeds install -p packages golang' "${apk_builder}"
if grep -Fq './scripts/feeds update packages luci' "${apk_builder}"; then
	echo "APK builder must not install the full LuCI feed" >&2
	exit 1
fi

grep -Fq 'EXTRA_DEPENDS:=kmod-tun (>=0), ca-bundle (>=0)' "${package_makefile}"
grep -Fq 'EXTRA_DEPENDS:=resolveip (>=0)' "${package_makefile}"
if grep -Fq 'DEPENDS:=$(GO_ARCH_DEPENDS) +kmod-tun' "${package_makefile}"; then
	echo "kmod-tun must remain runtime-only for standalone SDK builds" >&2
	exit 1
fi
if grep -Fq 'define Package/tlsvpn/install' "${package_makefile}"; then
	echo "tlsvpn must use GoBinPackage's install rule directly" >&2
	exit 1
fi

grep -Fq 'EXTRA_DEPENDS:=luci-base (>=0)' "${luci_makefile}"
grep -Fq 'define Build/Compile' "${luci_makefile}"
grep -Fq 'endef' "${luci_makefile}"
grep -Fq '$(INSTALL_DATA) ./htdocs/luci-static/resources/protocol/tlsvpn.js' "${luci_makefile}"
if grep -Fq 'luci.mk' "${luci_makefile}"; then
	echo "static LuCI protocol package must not require luci.mk/lua-host" >&2
	exit 1
fi

# OpenWrt 25.12 sha256sums uses GNU binary-mode entries ("*filename").
# Keep a behavioral regression check for the exact lookup form used by the
# APK builder so official SDK checksums are not rejected again.
checksum_fixture="$(mktemp)"
trap 'rm -f "$checksum_fixture"' EXIT
printf '%s\n' \
	'0123456789abcdef *openwrt-sdk-test.Linux-x86_64.tar.zst' \
	> "$checksum_fixture"
checksum_match="$(
	awk -v name='openwrt-sdk-test.Linux-x86_64.tar.zst' '
		$2 == name || $2 == "*" name { print; exit }
	' "$checksum_fixture"
)"
[ -n "$checksum_match" ] || {
	echo "binary-mode OpenWrt checksum lookup failed" >&2
	exit 1
}
grep -Fq '$2 == name || $2 == "*" name' "${apk_builder}"

grep -Fq 'scripts/build_openwrt_apk.sh' "${release_workflow}"
grep -Fq 'rockchip' "${release_workflow}"
grep -Fq 'mediatek' "${release_workflow}"
grep -Fq 'ath79' "${release_workflow}"
grep -Fq 'TLSVPN_PKG_VERSION: ${{' "${release_workflow}"
grep -Fq "startsWith(github.ref, 'refs/tags/v') && github.ref_name" "${release_workflow}"
grep -Fq 'VERSION: ${{' "${release_workflow}"
grep -Fq "format('dev-{0}', github.run_number)" "${release_workflow}"

echo "[PASS] OpenWrt netifd/LuCI/APK release integration static checks passed"
