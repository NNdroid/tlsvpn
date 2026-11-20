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

_tlsvpn_one_of() {
	# value followed by the allowed literals; used to mirror the binary's
	# enum validation so a typo fails at `ifup` with a clear proto error
	# instead of a post-start log.Fatalf from the daemon.
	local value="$1"
	shift
	local allowed
	for allowed in "$@"; do
		[ "$value" = "$allowed" ] && return 0
	done
	return 1
}

_tlsvpn_int_in_range() {
	local value="$1" min="$2" max="$3"
	case "$value" in
		''|*[!0-9]*) return 1 ;;
	esac
	[ "$value" -ge "$min" ] && [ "$value" -le "$max" ]
}

_tlsvpn_valid_cert_sha256() {
	# 64 hex digits after stripping colons; the binary is colon/case tolerant
	# when pinning client.cert_sha256.
	local value
	value="$(printf '%s' "$1" | tr -d ':')"
	case "$value" in
		*[!0-9a-fA-F]*) return 1 ;;
	esac
	[ "${#value}" -eq 64 ]
}

_tlsvpn_blob_values() {
	# $1 = option name. UCI list options (LuCI DynamicList) reach the proto
	# handler as JSON arrays in the netifd config blob; plain scalar options
	# (hand-written UCI) arrive as strings. Read either shape: arrays via
	# json_get_values (space-separated), scalars verbatim via json_get_var.
	local name="$1" type values=""
	json_get_type type "$name"
	case "$type" in
		array|object)
			json_get_values values "$name"
			;;
		*)
			json_get_var values "$name"
			;;
	esac
	printf '%s\n' "$values"
}

_tlsvpn_csv() {
	# Normalize space/comma-separated raw values into a clean comma list.
	# Accepts both legacy hand-written UCI comma strings and the
	# whitespace-joined output of json_get_values.
	local raw="$1" item out="" saved_ifs="$IFS"
	IFS=', '
	for item in $raw; do
		[ -n "$item" ] || continue
		out="${out:+$out,}$item"
	done
	IFS="$saved_ifs"
	printf '%s\n' "$out"
}

_tlsvpn_fail() {
	# Report a setup error and abort. Every netifd protocol action (setup,
	# teardown, ...) runs as its own process, so exiting here only ends this
	# setup attempt — netifd keeps running and marks the interface failed via
	# the proto_notify_error/proto_setup_failed notifications above.
	local interface="$1" code="$2" detail="$3"
	if [ -n "$detail" ]; then
		proto_notify_error "$interface" "$code" "$detail"
	else
		proto_notify_error "$interface" "$code"
	fi
	proto_setup_failed "$interface"
	exit 1
}

# Validates the full client option set before any endpoint resolution starts.
# All variables (except $interface) are the dynamically scoped locals of
# proto_tlsvpn_setup, already normalized to the binary's built-in defaults.
# Ranges and enums mirror config.go Validate() so config that the binary would
# reject never reaches a half-started daemon.
_tlsvpn_validate_options() {
	local interface="$1"

	[ "${#psk}" -ge 16 ] ||
		_tlsvpn_fail "$interface" "PSK_TOO_SHORT" "psk needs at least 16 bytes"
	_tlsvpn_one_of "$log_level" debug info warn error ||
		_tlsvpn_fail "$interface" "INVALID_LOG_LEVEL" "$log_level"
	_tlsvpn_one_of "$pad_mode" bucket off ||
		_tlsvpn_fail "$interface" "INVALID_PAD_MODE" "$pad_mode"

	if [ "$encrypt" != "1" ]; then
		[ -n "$enc_algo" ] &&
			_tlsvpn_fail "$interface" "ENC_ALGO_REQUIRES_ENCRYPT" "enc_algo requires encrypt=1"
		[ -n "$min_enc" ] && [ "$min_enc" != "any" ] &&
			_tlsvpn_fail "$interface" "MIN_ENC_REQUIRES_ENCRYPT" "min_enc requires encrypt=1"
	else
		_tlsvpn_one_of "$enc_algo" gcm256 gcm128 chacha20 xchacha20 ||
			_tlsvpn_fail "$interface" "INVALID_ENC_ALGO" "$enc_algo"
		_tlsvpn_one_of "$min_enc" gcm any ||
			_tlsvpn_fail "$interface" "INVALID_MIN_ENC" "$min_enc"
	fi

	_tlsvpn_int_in_range "$conns" 1 65536 ||
		_tlsvpn_fail "$interface" "INVALID_CONNS" "$conns"
	# fec_group is validated unconditionally, like config.go Validate():
	# applyDefaults fills 4 when unset, so only an explicit out-of-range
	# value can land here, fec enabled or not.
	_tlsvpn_int_in_range "$fec_group" 2 64 ||
		_tlsvpn_fail "$interface" "INVALID_FEC_GROUP" "$fec_group"
	_tlsvpn_int_in_range "$brutal_up" 0 1000000 ||
		_tlsvpn_fail "$interface" "INVALID_BRUTAL_RATE" "$brutal_up"
	_tlsvpn_int_in_range "$brutal_down" 0 1000000 ||
		_tlsvpn_fail "$interface" "INVALID_BRUTAL_RATE" "$brutal_down"

	[ "$insecure" != "1" ] || [ -n "$cert_sha256" ] ||
		_tlsvpn_fail "$interface" "INSECURE_NEEDS_CERT_SHA256" \
			"insecure=1 requires the cert_sha256 fingerprint"
	[ -z "$cert_sha256" ] || _tlsvpn_valid_cert_sha256 "$cert_sha256" ||
		_tlsvpn_fail "$interface" "INVALID_CERT_SHA256" "$cert_sha256"

	_tlsvpn_one_of "$routing_algo" auto latency_strict latency_sticky \
		min_rtt_strict min_rtt_adaptive roundtrip_strict ||
		_tlsvpn_fail "$interface" "INVALID_ROUTING_ALGO" "$routing_algo"
	_tlsvpn_one_of "$sched_envelope" rtt fwd ||
		_tlsvpn_fail "$interface" "INVALID_SCHED_ENVELOPE" "$sched_envelope"
	_tlsvpn_int_in_range "$sched_envelope_ms" 1 500 ||
		_tlsvpn_fail "$interface" "INVALID_SCHED_ENVELOPE_MS" "$sched_envelope_ms"
	_tlsvpn_int_in_range "$sched_health_penalty_us" 0 60000 ||
		_tlsvpn_fail "$interface" "INVALID_SCHED_HEALTH_PENALTY" "$sched_health_penalty_us"
	_tlsvpn_one_of "$fec_strategy" auto near ||
		_tlsvpn_fail "$interface" "INVALID_FEC_STRATEGY" "$fec_strategy"
	_tlsvpn_int_in_range "$fec_near_window_ms" 1 100 ||
		_tlsvpn_fail "$interface" "INVALID_FEC_NEAR_WINDOW" "$fec_near_window_ms"
	_tlsvpn_int_in_range "$priority_control" 0 10 ||
		_tlsvpn_fail "$interface" "INVALID_FRAME_PRIORITY" "$priority_control"
	_tlsvpn_int_in_range "$priority_data" 0 10 ||
		_tlsvpn_fail "$interface" "INVALID_FRAME_PRIORITY" "$priority_data"
	_tlsvpn_int_in_range "$probe_min_half_rtt_us" 0 3600000 ||
		_tlsvpn_fail "$interface" "INVALID_PROBE_MIN_HALF_RTT" "$probe_min_half_rtt_us"
	_tlsvpn_int_in_range "$traffic_days" 1 3650 ||
		_tlsvpn_fail "$interface" "INVALID_TRAFFIC_DAYS" "$traffic_days"

	if [ -n "$web_addr" ]; then
		[ -n "$web_auth" ] ||
			_tlsvpn_fail "$interface" "WEB_AUTH_REQUIRED" "web_addr requires web_auth"
		case "$web_auth" in
			*:* ) : ;;
			* ) _tlsvpn_fail "$interface" "INVALID_WEB_AUTH" "web_auth must be user:password" ;;
		esac
		_tlsvpn_one_of "$web_bind" tunnel all ||
			_tlsvpn_fail "$interface" "INVALID_WEB_BIND" "$web_bind"
		if [ -n "$web_cert" ] || [ -n "$web_key" ]; then
			[ -n "$web_cert" ] && [ -n "$web_key" ] ||
				_tlsvpn_fail "$interface" "WEB_TLS_PAIR_REQUIRED" \
					"web_cert and web_key must be provided together"
		fi
		if [ "$web_bind" = "all" ]; then
			web_host="$(_tlsvpn_endpoint_host "$web_addr")"
			# Mirror webAddrIsPublic: only literal loopback IPs are private;
			# an empty host (":8080") binds every interface and is public.
			if [ "$web_host" != "127.0.0.1" ] && [ "$web_host" != "::1" ]; then
				[ -n "$web_cert" ] ||
					_tlsvpn_fail "$interface" "WEB_TLS_REQUIRED_FOR_BIND_ALL" \
						"web_bind=all on a public listener requires web_cert and web_key"
			fi
		fi
	fi

	if [ -n "$mcp_auth_mode" ]; then
		_tlsvpn_one_of "$mcp_auth_mode" inherit_web none basic bearer api_key oauth_jwt ||
			_tlsvpn_fail "$interface" "INVALID_MCP_AUTH_MODE" "$mcp_auth_mode"
		case "$mcp_auth_mode" in
			basic)
				[ -n "$mcp_username" ] ||
					_tlsvpn_fail "$interface" "MCP_USERNAME_REQUIRED" \
						"mcp_auth_mode=basic requires mcp_username"
				[ -n "$mcp_credential" ] ||
					_tlsvpn_fail "$interface" "MCP_CREDENTIAL_REQUIRED" \
						"mcp_auth_mode=basic requires mcp_credential"
				;;
			bearer|api_key)
				[ -n "$mcp_credential" ] ||
					_tlsvpn_fail "$interface" "MCP_CREDENTIAL_REQUIRED" \
						"mcp_auth_mode=$mcp_auth_mode requires mcp_credential"
				;;
			oauth_jwt)
				[ -n "$mcp_jwks_url" ] && [ -n "$mcp_issuer" ] && \
					[ -n "$mcp_audience" ] && [ -n "$mcp_resource" ] ||
					_tlsvpn_fail "$interface" "MCP_OAUTH_FIELDS_REQUIRED" \
						"mcp_auth_mode=oauth_jwt requires mcp_jwks_url, mcp_issuer, mcp_audience and mcp_resource"
				;;
		esac
	fi
	if [ -n "$mcp_path" ]; then
		case "$mcp_path" in
			/* ) case "$mcp_path" in
					*//*|*' '*|*"	"*) _tlsvpn_fail "$interface" "INVALID_MCP_PATH" "$mcp_path" ;;
					* ) : ;;
				esac ;;
			* ) _tlsvpn_fail "$interface" "INVALID_MCP_PATH" "$mcp_path" ;;
		esac
	fi

	# Reaching here means every check passed; _tlsvpn_fail exits the process
	# on failure, so this return only normalizes the success status (the last
	# command above may legitimately evaluate to false, e.g. empty mcp_path).
	return 0
}

# Emits the daemon JSON. Only file/tap/resolved_server/resolved_socks5 are
# passed as arguments; every other value comes from the normalized locals of
# proto_tlsvpn_setup (ash locals are visible to called functions). Scheduler,
# FEC-strategy, priority, traffic and web/mcp fields are written only when
# configured — omitted fields fall back to the binary's own defaults, so this
# script never duplicates default constants that could drift from config.go.
_tlsvpn_write_config() {
	local file="$1"
	local tap="$2"
	local resolved_server="$3"
	local resolved_socks5="$4"
	local mcp_item saved_ifs

	json_init
	json_add_string mode client
	json_add_string psk "$psk"
	json_add_string addr "$resolved_server"
	json_add_string tap "$tap"
	[ -n "$mac" ] && json_add_string mac "$mac"
	json_add_string log_level "$log_level"
	json_add_boolean encrypt "$encrypt"
	[ -n "$enc_algo" ] && json_add_string enc_algo "$enc_algo"
	[ -n "$min_enc" ] && json_add_string min_enc "$min_enc"
	json_add_string pad_mode "$pad_mode"
	[ -n "$resolved_socks5" ] && json_add_string socks5 "$resolved_socks5"
	json_add_boolean brutal "$brutal"
	json_add_int brutal_up "$brutal_up"
	json_add_int brutal_down "$brutal_down"

	[ -n "$routing_algo" ] && json_add_string routing_algo "$routing_algo"
	[ -n "$sched_envelope" ] && json_add_string sched_envelope "$sched_envelope"
	[ -n "$sched_envelope_ms" ] && json_add_int sched_envelope_ms "$sched_envelope_ms"
	[ -n "$sched_health_penalty_us" ] && json_add_int sched_health_penalty_us "$sched_health_penalty_us"
	[ -n "$fec_strategy" ] && json_add_string fec_strategy "$fec_strategy"
	[ -n "$fec_near_window_ms" ] && json_add_int fec_near_window_ms "$fec_near_window_ms"
	[ -n "$priority_control" ] && json_add_int priority_control "$priority_control"
	[ -n "$priority_data" ] && json_add_int priority_data "$priority_data"
	[ -n "$probe_min_half_rtt_us" ] && json_add_int probe_min_half_rtt_us "$probe_min_half_rtt_us"
	[ -n "$traffic_days" ] && json_add_int traffic_days "$traffic_days"
	# Always written: proto_tlsvpn_setup fills the persistent OpenWrt default
	# when UCI leaves it empty.
	json_add_string traffic_file "$traffic_file"

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

	if [ -n "$web_addr" ]; then
		json_add_object web
		json_add_string addr "$web_addr"
		# The binary defaults bind to "all", which on a router also exposes the
		# dashboard on WAN and requires a TLS pair. Tunnel-only binding is the
		# safe OpenWrt default; web_bind=all overrides it explicitly.
		[ -n "$web_bind" ] || web_bind=tunnel
		json_add_string bind "$web_bind"
		json_add_string auth "$web_auth"
		[ -n "$web_cert" ] && json_add_string cert "$web_cert"
		[ -n "$web_key" ] && json_add_string key "$web_key"
		[ "$web_behind_proxy" = "1" ] && json_add_boolean behind_proxy 1

		if [ -n "$mcp_auth_mode$mcp_username$mcp_credential$mcp_api_key_header$mcp_path" ] ||
			[ -n "$mcp_jwks_url$mcp_issuer$mcp_audience$mcp_resource$mcp_authorization_servers$mcp_required_scopes" ]; then
			json_add_object mcp
			[ -n "$mcp_auth_mode" ] && json_add_string auth_mode "$mcp_auth_mode"
			[ -n "$mcp_username" ] && json_add_string username "$mcp_username"
			[ -n "$mcp_credential" ] && json_add_string credential "$mcp_credential"
			[ -n "$mcp_api_key_header" ] && json_add_string api_key_header "$mcp_api_key_header"
			[ -n "$mcp_path" ] && json_add_string path "$mcp_path"
			if [ -n "$mcp_jwks_url$mcp_issuer$mcp_audience$mcp_resource" ] ||
				[ -n "$mcp_authorization_servers$mcp_required_scopes" ]; then
				json_add_object oauth
				[ -n "$mcp_jwks_url" ] && json_add_string jwks_url "$mcp_jwks_url"
				[ -n "$mcp_issuer" ] && json_add_string issuer "$mcp_issuer"
				[ -n "$mcp_audience" ] && json_add_string audience "$mcp_audience"
				[ -n "$mcp_resource" ] && json_add_string resource "$mcp_resource"
				if [ -n "$mcp_authorization_servers" ]; then
					json_add_array authorization_servers
					saved_ifs="$IFS"
					IFS=','
					for mcp_item in $mcp_authorization_servers; do
						mcp_item="${mcp_item# }"
						mcp_item="${mcp_item% }"
						[ -n "$mcp_item" ] && json_add_string "" "$mcp_item"
					done
					IFS="$saved_ifs"
					json_close_array
				fi
				if [ -n "$mcp_required_scopes" ]; then
					json_add_array required_scopes
					saved_ifs="$IFS"
					IFS=','
					for mcp_item in $mcp_required_scopes; do
						mcp_item="${mcp_item# }"
						mcp_item="${mcp_item% }"
						[ -n "$mcp_item" ] && json_add_string "" "$mcp_item"
					done
					IFS="$saved_ifs"
					json_close_array
				fi
				json_close_object
			fi
			json_close_object
		fi
		json_close_object
	fi

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
	proto_config_add_string "enc_algo"
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
	# Multipath scheduler / FEC parity strategy (hot-reloadable in the daemon)
	proto_config_add_string "routing_algo"
	proto_config_add_string "sched_envelope"
	proto_config_add_int "sched_envelope_ms"
	proto_config_add_int "sched_health_penalty_us"
	proto_config_add_string "fec_strategy"
	proto_config_add_int "fec_near_window_ms"
	# Data-plane write-queue priorities and observation knobs
	proto_config_add_int "priority_control"
	proto_config_add_int "priority_data"
	proto_config_add_int "probe_min_half_rtt_us"
	# Daily traffic accounting
	proto_config_add_int "traffic_days"
	proto_config_add_string "traffic_file"
	# Web dashboard (shares the daemon process; MCP rides the same listener)
	proto_config_add_string "web_addr"
	proto_config_add_string "web_bind"
	proto_config_add_string "web_auth"
	proto_config_add_string "web_cert"
	proto_config_add_string "web_key"
	proto_config_add_boolean "web_behind_proxy"
	proto_config_add_string "mcp_auth_mode"
	proto_config_add_string "mcp_username"
	proto_config_add_string "mcp_credential"
	proto_config_add_string "mcp_api_key_header"
	proto_config_add_string "mcp_path"
	proto_config_add_string "mcp_jwks_url"
	proto_config_add_string "mcp_issuer"
	proto_config_add_string "mcp_audience"
	proto_config_add_string "mcp_resource"
	# UCI list options (LuCI DynamicList) reach the blob as JSON arrays and
	# hand-written comma strings as scalars; both shapes are read by
	# _tlsvpn_blob_values and normalized by _tlsvpn_csv before emission.
	proto_config_add_string "mcp_authorization_servers"
	proto_config_add_string "mcp_required_scopes"
	proto_config_add_defaults
}

proto_tlsvpn_setup() {
	local interface="$1"
	local server psk tap mac tunlink sni cert_sha256 req_v4 req_v6
	local enc_algo min_enc pad_mode socks5 log_level conns fec_group brutal_up brutal_down
	local fec encrypt insecure brutal defaultroute metric
	local routing_algo sched_envelope sched_envelope_ms sched_health_penalty_us
	local fec_strategy fec_near_window_ms priority_control priority_data
	local probe_min_half_rtt_us traffic_days traffic_file
	local web_addr web_bind web_auth web_cert web_key web_behind_proxy web_host
	local mcp_auth_mode mcp_username mcp_credential mcp_api_key_header mcp_path
	local mcp_jwks_url mcp_issuer mcp_audience mcp_resource
	local mcp_authorization_servers mcp_required_scopes
	local config host endpoint ip dependency_count=0
	local resolved_socks5 proxy scheme userinfo proxy_endpoint proxy_ip

	json_get_vars server psk tap mac tunlink sni cert_sha256 req_v4 req_v6
	json_get_vars enc_algo min_enc pad_mode socks5 log_level conns fec_group brutal_up brutal_down
	json_get_vars fec encrypt insecure brutal defaultroute metric
	json_get_vars routing_algo sched_envelope sched_envelope_ms sched_health_penalty_us
	json_get_vars fec_strategy fec_near_window_ms priority_control priority_data
	json_get_vars probe_min_half_rtt_us traffic_days traffic_file
	json_get_vars web_addr web_bind web_auth web_cert web_key web_behind_proxy
	json_get_vars mcp_auth_mode mcp_username mcp_credential mcp_api_key_header mcp_path
	json_get_vars mcp_jwks_url mcp_issuer mcp_audience mcp_resource
	# List-shaped MCP oauth options: read both blob shapes (JSON array from a
	# UCI list, string from hand-written comma-separated UCI) and normalize
	# into the comma list the JSON writer splits on.
	mcp_authorization_servers="$(_tlsvpn_csv "$(_tlsvpn_blob_values mcp_authorization_servers)")"
	mcp_required_scopes="$(_tlsvpn_csv "$(_tlsvpn_blob_values mcp_required_scopes)")"

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

	# Normalize booleans and built-in defaults to the effective values the
	# binary would compute (config.go applyDefaults) so validation and JSON
	# emission below see exactly what the daemon would run with.
	encrypt="$(_tlsvpn_bool_default "$encrypt" 1)"
	fec="$(_tlsvpn_bool_default "$fec" 0)"
	brutal="$(_tlsvpn_bool_default "$brutal" 0)"
	insecure="$(_tlsvpn_bool_default "$insecure" 0)"
	[ -n "$conns" ] || conns=1
	[ -n "$fec_group" ] || fec_group=4
	if [ "$encrypt" = "1" ]; then
		[ -n "$enc_algo" ] || enc_algo=gcm256
		[ -n "$min_enc" ] || min_enc=gcm
	fi
	[ -n "$pad_mode" ] || pad_mode=bucket
	[ -n "$brutal_up" ] || brutal_up=100
	[ -n "$brutal_down" ] || brutal_down=500
	[ -n "$sni" ] || sni=www.cloudflare.com
	[ -n "$log_level" ] || log_level=info

	# Contradictory cipher settings are rejected (like the binary) instead of
	# silently dropped: dropping enc_algo would downgrade the tunnel to
	# unauthenticated inner traffic without the user noticing.
	_tlsvpn_validate_options "$interface"

	# Daily-traffic persistence: the generated JSON lives on tmpfs and is
	# rebuilt at every ifup, and the daemon defaults traffic_file beside it —
	# statistics would be lost at reboot. Default to a persistent store under
	# /etc/tlsvpn/ per interface; an explicitly configured traffic_file
	# overrides this, and pointing it at tmpfs keeps statistics RAM-only.
	if [ -z "$traffic_file" ]; then
		traffic_file="/etc/tlsvpn/tlsvpn-$interface-traffic.json"
	fi
	# The daemon does not create missing parent directories for traffic_file.
	mkdir -p "$(dirname "$traffic_file")" 2>/dev/null || :

	# Resolve every transport endpoint before tlsvpn starts and feed the exact
	# same IP set to both the process and netifd host dependencies. If a
	# hostname is allowed to be resolved again after the tunnel installs a
	# default route, a different DNS answer could recursively route TLSVPN's
	# own TCP transport into the tunnel.
	local old_ifs="$IFS"
	local resolved_server="" resolved_endpoint="" port=""
	local endpoint_count=0 endpoint_deps=0
	IFS=','
	for endpoint in $server; do
		endpoint="${endpoint# }"
		endpoint="${endpoint% }"
		host="$(_tlsvpn_endpoint_host "$endpoint")"
		case "$endpoint" in
			\[*\]:*) port="${endpoint##*:}" ;;
			*:*) port="${endpoint##*:}" ;;
			*) port="" ;;
		esac
		[ -n "$host" ] && [ -n "$port" ] || {
			IFS="$old_ifs"
			proto_notify_error "$interface" "INVALID_SERVER_ENDPOINT" "$endpoint"
			proto_setup_failed "$interface"
			return 1
		}

		endpoint_count=$((endpoint_count + 1))
		endpoint_deps=0
		for ip in $(resolveip -t 5 "$host" 2>/dev/null); do
			case "$ip" in
				*:*) resolved_endpoint="[$ip]:$port" ;;
				*) resolved_endpoint="$ip:$port" ;;
			esac
			[ -n "$resolved_server" ] && resolved_server="$resolved_server,"
			resolved_server="$resolved_server$resolved_endpoint"
			( proto_add_host_dependency "$interface" "$ip" "$tunlink" )
			dependency_count=$((dependency_count + 1))
			endpoint_deps=$((endpoint_deps + 1))
		done
		if [ "$endpoint_deps" -eq 0 ]; then
			IFS="$old_ifs"
			proto_notify_error "$interface" "HOST_DEPENDENCY_FAILED" "$host"
			proto_setup_failed "$interface"
			return 1
		fi
	done
	IFS="$old_ifs"

	[ "$endpoint_count" -gt 0 ] && [ "$dependency_count" -gt 0 ] || {
		proto_notify_error "$interface" "HOST_DEPENDENCY_FAILED"
		proto_setup_failed "$interface"
		return 1
	}

	# In SOCKS5 mode the real local TCP peer is the proxy, so it needs its own
	# host dependency as well. Resolve it once and rewrite the generated JSON to
	# the same fixed IP to avoid a reconnect resolving a new, unpinned proxy IP.
	resolved_socks5="$socks5"
	if [ -n "$socks5" ]; then
		proxy="$socks5"
		scheme=""
		case "$proxy" in
			socks5://*) scheme="socks5://"; proxy="${proxy#socks5://}" ;;
			socks5h://*) scheme="socks5h://"; proxy="${proxy#socks5h://}" ;;
		esac

		userinfo=""
		case "$proxy" in
			*@*)
				userinfo="${proxy%@*}@"
				proxy_endpoint="${proxy##*@}"
				;;
			*) proxy_endpoint="$proxy" ;;
		esac

		host="$(_tlsvpn_endpoint_host "$proxy_endpoint")"
		case "$proxy_endpoint" in
			\[*\]:*) port="${proxy_endpoint##*:}" ;;
			*:*) port="${proxy_endpoint##*:}" ;;
			*) port="" ;;
		esac
		[ -n "$host" ] && [ -n "$port" ] || {
			proto_notify_error "$interface" "INVALID_SOCKS5_ENDPOINT"
			proto_setup_failed "$interface"
			return 1
		}

		proxy_ip="$(resolveip -t 5 "$host" 2>/dev/null | head -n 1)"
		[ -n "$proxy_ip" ] || {
			proto_notify_error "$interface" "SOCKS5_HOST_DEPENDENCY_FAILED" "$host"
			proto_setup_failed "$interface"
			return 1
		}
		( proto_add_host_dependency "$interface" "$proxy_ip" "$tunlink" )
		case "$proxy_ip" in
			*:*) resolved_endpoint="[$proxy_ip]:$port" ;;
			*) resolved_endpoint="$proxy_ip:$port" ;;
		esac
		resolved_socks5="$scheme$userinfo$resolved_endpoint"
	fi

	_tlsvpn_write_config "$config" "$tap" "$resolved_server" "$resolved_socks5" || {
		rm -f "$config"
		proto_notify_error "$interface" "CONFIG_GENERATION_FAILED"
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
