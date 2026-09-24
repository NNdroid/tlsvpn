#!/bin/sh

. /lib/functions.sh
. /lib/functions/network.sh
. /lib/netifd/netifd-proto.sh

init_proto "$@"

_tlsvpn_endpoint_host() {
	local endpoint="$1"
	case "$endpoint" in
		\[*\]:*)
			endpoint="${endpoint#\[}"
			printf '%s\n' "${endpoint%%\]*}"
			;;
		*:* )
			printf '%s\n' "${endpoint%:*}"
			;;
		*)
			printf '%s\n' "$endpoint"
			;;
	esac
}

_tlsvpn_bool_default() {
	local value="$1"
	local fallback="$2"
	[ -n "$value" ] && printf '%s\n' "$value" || printf '%s\n' "$fallback"
}

_tlsvpn_write_config() {
	local file="$1"
	local tap="$2"
	local server="$3"
	local psk="$4"
	local sni="$5"
	local cert_sha256="$6"
	local req_v4="$7"
	local req_v6="$8"
	shift 8

	local conns="$1"; shift
	local fec="$1"; shift
	local fec_group="$1"; shift
	local encrypt="$1"; shift
	local min_enc="$1"; shift
	local pad_mode="$1"; shift
	local brutal="$1"; shift
	local brutal_up="$1"; shift
	local brutal_down="$1"; shift
	local socks5="$1"; shift
	local insecure="$1"; shift
	local mac="$1"; shift
	local log_level="$1"

	encrypt="$(_tlsvpn_bool_default "$encrypt" 1)"
	fec="$(_tlsvpn_bool_default "$fec" 0)"
	brutal="$(_tlsvpn_bool_default "$brutal" 0)"
	insecure="$(_tlsvpn_bool_default "$insecure" 0)"
	[ -n "$conns" ] || conns=1
	[ -n "$fec_group" ] || fec_group=4
	[ -n "$min_enc" ] || min_enc=gcm
	[ -n "$pad_mode" ] || pad_mode=bucket
	[ -n "$brutal_up" ] || brutal_up=100
	[ -n "$brutal_down" ] || brutal_down=500
	[ -n "$sni" ] || sni=www.cloudflare.com
	[ -n "$log_level" ] || log_level=info

	json_init
	json_add_string mode client
	json_add_string psk "$psk"
	json_add_string addr "$server"
	json_add_string tap "$tap"
	[ -n "$mac" ] && json_add_string mac "$mac"
	json_add_string log_level "$log_level"
	json_add_boolean encrypt "$encrypt"
	json_add_string min_enc "$min_enc"
	json_add_string pad_mode "$pad_mode"
	[ -n "$socks5" ] && json_add_string socks5 "$socks5"
	json_add_boolean brutal "$brutal"
	json_add_int brutal_up "$brutal_up"
	json_add_int brutal_down "$brutal_down"

	json_add_object client
	json_add_string interface_manager netifd
	json_add_int conns "$conns"
	json_add_boolean fec "$fec"
	json_add_int fec_group "$fec_group"
	json_add_string sni "$sni"
	json_add_boolean insecure "$insecure"
	[ -n "$cert_sha256" ] && json_add_string cert_sha256 "$cert_sha256"
	[ -n "$req_v4" ] && json_add_string req_v4 "$req_v4"
	[ -n "$req_v6" ] && json_add_string req_v6 "$req_v6"
	json_close_object

	umask 077
	json_dump > "$file"
}

proto_tlsvpn_init_config() {
	no_device=1
	available=1

	proto_config_add_string "server"
	proto_config_add_string "psk"
	proto_config_add_string "tap"
	proto_config_add_string "mac"
	proto_config_add_string "tunlink"
	proto_config_add_string "sni"
	proto_config_add_string "cert_sha256"
	proto_config_add_string "req_v4"
	proto_config_add_string "req_v6"
	proto_config_add_string "min_enc"
	proto_config_add_string "pad_mode"
	proto_config_add_string "socks5"
	proto_config_add_string "log_level"
	proto_config_add_int "conns"
	proto_config_add_int "fec_group"
	proto_config_add_int "brutal_up"
	proto_config_add_int "brutal_down"
	proto_config_add_boolean "fec"
	proto_config_add_boolean "encrypt"
	proto_config_add_boolean "insecure"
	proto_config_add_boolean "brutal"
	proto_config_add_defaults
}

proto_tlsvpn_setup() {
	local interface="$1"
	local server psk tap mac tunlink sni cert_sha256 req_v4 req_v6
	local min_enc pad_mode socks5 log_level conns fec_group brutal_up brutal_down
	local fec encrypt insecure brutal defaultroute metric
	local config host endpoint ip dependency_count=0

	json_get_vars server psk tap mac tunlink sni cert_sha256 req_v4 req_v6
	json_get_vars min_enc pad_mode socks5 log_level conns fec_group brutal_up brutal_down
	json_get_vars fec encrypt insecure brutal defaultroute metric

	[ -n "$server" ] || {
		proto_notify_error "$interface" "MISSING_SERVER"
		proto_setup_failed "$interface"
		return 1
	}
	[ -n "$psk" ] || {
		proto_notify_error "$interface" "MISSING_PSK"
		proto_setup_failed "$interface"
		return 1
	}

	if [ -z "$tap" ]; then
		tap="tvpn-$interface"
		tap="$(printf '%s' "$tap" | cut -c1-15)"
	fi
	config="/var/etc/tlsvpn-$interface.json"
	mkdir -p /var/etc

	_tlsvpn_write_config "$config" "$tap" "$server" "$psk" "$sni" 		"$cert_sha256" "$req_v4" "$req_v6" "$conns" "$fec" "$fec_group" 		"$encrypt" "$min_enc" "$pad_mode" "$brutal" "$brutal_up" 		"$brutal_down" "$socks5" "$insecure" "$mac" "$log_level" || {
		proto_notify_error "$interface" "CONFIG_GENERATION_FAILED"
		proto_setup_failed "$interface"
		return 1
	}

	# Pin every transport endpoint to the pre-tunnel routing domain. Without
	# host dependencies a default route learned from TLSVPN can recursively
	# route its own TCP/TLS transport back into the tunnel.
	local old_ifs="$IFS"
	IFS=','
	for endpoint in $server; do
		endpoint="${endpoint# }"
		endpoint="${endpoint% }"
		host="$(_tlsvpn_endpoint_host "$endpoint")"
		[ -n "$host" ] || continue
		for ip in $(resolveip -t 5 "$host" 2>/dev/null); do
			( proto_add_host_dependency "$interface" "$ip" "$tunlink" )
			dependency_count=$((dependency_count + 1))
		done
	done
	IFS="$old_ifs"

	[ "$dependency_count" -gt 0 ] || {
		rm -f "$config"
		proto_notify_error "$interface" "HOST_DEPENDENCY_FAILED"
		proto_setup_failed "$interface"
		return 1
	}

	[ -n "$defaultroute" ] || defaultroute=1
	[ -n "$metric" ] || metric=0
	proto_export "TLSVPN_NETIFD_INTERFACE=$interface"
	proto_export "TLSVPN_NETIFD_DEFAULTROUTE=$defaultroute"
	proto_export "TLSVPN_NETIFD_METRIC=$metric"

	proto_run_command "$interface" /usr/bin/tlsvpn -c "$config"
}

proto_tlsvpn_teardown() {
	local interface="$1"
	proto_kill_command "$interface" TERM
	rm -f "/var/etc/tlsvpn-$interface.json"
}

add_protocol tlsvpn
