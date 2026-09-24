#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
proto="${repo_root}/openwrt/package/tlsvpn/files/lib/netifd/proto/tlsvpn.sh"
up="${repo_root}/openwrt/package/tlsvpn/files/lib/netifd/tlsvpn-up"
down="${repo_root}/openwrt/package/tlsvpn/files/lib/netifd/tlsvpn-down"
luci="${repo_root}/openwrt/luci-proto-tlsvpn/htdocs/luci-static/resources/protocol/tlsvpn.js"

for script in "${proto}" "${up}" "${down}"; do
	sh -n "${script}"
done

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

echo "[PASS] OpenWrt netifd/LuCI integration static checks passed"
