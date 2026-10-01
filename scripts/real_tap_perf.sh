#!/usr/bin/env bash
# real_tap_perf.sh — Go tlsvpn real-TAP throughput/profiling harness.
#
# The server and client live in separate network namespaces connected only by
# a veth underlay, so iperf traffic cannot bypass the tunnel through table
# local. The tunnel path therefore includes TAP + framing + TLS + inner crypto
# + VSwitch.
#
# Environment:
#   BIN                 tlsvpn binary (default: ./tlsvpn)
#   PERF_CONNS          client physical connections (default: 1)
#   PERF_ENC_ALGO       gcm256 | gcm128 | chacha20 | xchacha20 (default: gcm256)
#   PERF_PAD_MODE       bucket | off (default: bucket)
#   PERF_FEC            true | false (default: false)
#   PERF_FEC_GROUP      XOR group K when PERF_FEC=true (default: 4)
#   PERF_DIRECTION      upload | download | both (default: both)
#   PERF_SECONDS        iperf duration per direction (default: 3)
#   PERF_MIN_MBPS       hard minimum for each measured direction (default: 500)
#   PERF_RESULT_FILE    append TSV results here (optional)
#   PERF_PROFILE_DIR    enable CPU/heap profiles for both endpoints (optional)
#   PERF_DIAG_FILE       append adaptive scheduler per-connection diagnostics (optional)
#
# When PERF_PROFILE_DIR is set the binary receives TLSVPN_CPU_PROFILE and
# TLSVPN_HEAP_PROFILE. The processes are terminated with SIGTERM and awaited so
# deferred profile finalization runs before artifacts are collected.
set -uo pipefail

BIN="${BIN:-./tlsvpn}"
PERF_CONNS="${PERF_CONNS:-1}"
PERF_ENC_ALGO="${PERF_ENC_ALGO:-gcm256}"
PERF_PAD_MODE="${PERF_PAD_MODE:-bucket}"
PERF_FEC="${PERF_FEC:-false}"
PERF_FEC_GROUP="${PERF_FEC_GROUP:-4}"
PERF_DIRECTION="${PERF_DIRECTION:-both}"
PERF_SECONDS="${PERF_SECONDS:-3}"
PERF_MIN_MBPS="${PERF_MIN_MBPS:-500}"
PERF_RESULT_FILE="${PERF_RESULT_FILE:-}"
PERF_PROFILE_DIR="${PERF_PROFILE_DIR:-}"
PERF_DIAG_FILE="${PERF_DIAG_FILE:-}"
PERF_TAP_QUEUES="${PERF_TAP_QUEUES:-}"
PERF_TAP_MULTI_QUEUE="${PERF_TAP_MULTI_QUEUE:-false}"
PERF_STREAMS="${PERF_STREAMS:-1}"
PERF_REQUIRE_TAP="${PERF_REQUIRE_TAP:-false}"
PERF_WARMUP="${PERF_WARMUP:-0}"
PERF_LOG_LEVEL="${PERF_LOG_LEVEL:-warn}"

PORT="${PORT:-18600}"
WEB_ADDR="127.0.0.1:18780"
WEB_AUTH="perf:tlsvpn"
GW_V4="10.77.0.1"
CLI_V4="10.77.0.2"
SUBNET_V4="10.77.0.0/24"
GW_V6="fd77::1"
SUBNET_V6="fd77::/64"
TAP_SRV="tap_t0"
TAP_CLI="tap_t1"
UNDERLAY_SRV="192.0.2.1"
UNDERLAY_CLI="192.0.2.2"
UNDERLAY_PREFIX=30
NS_SRV="tlsvpn-perf-srv-$$"
NS_CLI="tlsvpn-perf-cli-$$"
VETH_SRV="tps$$"
VETH_CLI="tpc$$"

TMP=""
PIDS=()
RESULTS=()

log() { echo "[real-tap-perf] $*"; }
die() { log "ERROR: $*"; exit 1; }

validate_inputs() {
  [[ "$PERF_CONNS" =~ ^[1-9][0-9]*$ ]] || die "PERF_CONNS must be a positive integer"
  case "$PERF_ENC_ALGO" in gcm256|gcm128) ;; *) die "PERF_ENC_ALGO must be gcm256 or gcm128" ;; esac
  case "$PERF_PAD_MODE" in bucket|off) ;; *) die "PERF_PAD_MODE must be bucket or off" ;; esac
  case "$PERF_FEC" in true|false) ;; *) die "PERF_FEC must be true or false" ;; esac
  [[ "$PERF_FEC_GROUP" =~ ^[0-9]+$ ]] || die "PERF_FEC_GROUP must be an integer"
  (( PERF_FEC_GROUP >= 2 && PERF_FEC_GROUP <= 64 )) || die "PERF_FEC_GROUP must be in [2,64]"
  case "$PERF_DIRECTION" in upload|download|both) ;; *) die "PERF_DIRECTION must be upload, download or both" ;; esac
  [[ "$PERF_SECONDS" =~ ^[1-9][0-9]*$ ]] || die "PERF_SECONDS must be a positive integer"
  [[ "$PERF_WARMUP" =~ ^[0-9]+$ ]] || die "invalid warmup"
  [[ "$PERF_STREAMS" =~ ^[1-9][0-9]*$ ]] || die "PERF_STREAMS must be positive"
  if [[ -n "$PERF_TAP_QUEUES" ]]; then
    [[ "$PERF_TAP_QUEUES" =~ ^[0-9]+$ ]] || die "invalid TAP queue count"
    (( PERF_TAP_QUEUES >= 1 && PERF_TAP_QUEUES <= 16 )) || die "invalid TAP queue count"
  fi
  case "$PERF_TAP_MULTI_QUEUE" in true|false) ;; *) die "invalid multi-queue flag" ;; esac
  [[ -x "$BIN" ]] || die "BIN is not executable: $BIN"
  command -v ip >/dev/null || die "iproute2 is required"
  command -v iperf3 >/dev/null || die "iperf3 is required"
  command -v openssl >/dev/null || die "openssl is required"
  command -v awk >/dev/null || die "awk is required"
}

capability_gate() {
  if [[ $EUID -ne 0 ]]; then
    [[ "$PERF_REQUIRE_TAP" != true ]] || die "root/CAP_NET_ADMIN required"
    log "SKIP: root/CAP_NET_ADMIN required"
    exit 0
  fi
  if [[ ! -c /dev/net/tun ]]; then
    [[ "$PERF_REQUIRE_TAP" != true ]] || die "/dev/net/tun unavailable"
    log "SKIP: /dev/net/tun unavailable"
    exit 0
  fi

  local cap_ns="tlsvpn-perf-cap-$$" cap_a="tpa$$" cap_b="tpb$$" reason=""
  if ! ip netns add "$cap_ns" 2>/dev/null; then
    reason="cannot create network namespace"
  elif ! ip link add "$cap_a" type veth peer name "$cap_b" 2>/dev/null; then
    reason="cannot create veth pair"
  elif ! ip link set "$cap_b" netns "$cap_ns" 2>/dev/null; then
    reason="cannot move veth into namespace"
  elif ! ip netns exec "$cap_ns" ip link set lo up 2>/dev/null; then
    reason="cannot configure namespace loopback"
  elif ! ip netns exec "$cap_ns" ip tuntap add dev tap_cap mode tap 2>/dev/null; then
    reason="cannot create TAP"
  elif ! ip netns exec "$cap_ns" ip link set tap_cap up 2>/dev/null; then
    reason="cannot bring TAP up"
  elif ! ip netns exec "$cap_ns" ip addr add 10.77.99.1/24 dev tap_cap 2>/dev/null; then
    reason="cannot configure TAP address"
  fi
  ip link del "$cap_a" 2>/dev/null || true
  ip netns del "$cap_ns" 2>/dev/null || true
  if [[ -n "$reason" ]]; then
    [[ "$PERF_REQUIRE_TAP" != true ]] || die "$reason"
    log "SKIP: $reason"
    exit 0
  fi
}

gracious_stop() {
  local p
  for p in "${PIDS[@]:-}"; do
    kill -TERM "$p" 2>/dev/null || true
  done
  local deadline=$((SECONDS + 8))
  for p in "${PIDS[@]:-}"; do
    while kill -0 "$p" 2>/dev/null && (( SECONDS < deadline )); do
      sleep 0.1
    done
    if kill -0 "$p" 2>/dev/null; then
      kill -KILL "$p" 2>/dev/null || true
    fi
    wait "$p" 2>/dev/null || true
  done
  PIDS=()
}

cleanup() {
  gracious_stop
  if [[ -n "${PERF_RAW_DIR:-}" && -n "$TMP" ]]; then
    mkdir -p "$PERF_RAW_DIR"
    cp "$TMP"/*.log "$PERF_RAW_DIR/" 2>/dev/null || true
  fi
  ip netns del "$NS_SRV" 2>/dev/null || true
  ip netns del "$NS_CLI" 2>/dev/null || true
  ip link del "$VETH_SRV" 2>/dev/null || true
  ip link del "$VETH_CLI" 2>/dev/null || true
  [[ -n "$TMP" && -d "$TMP" ]] && rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

setup_namespaces() {
  ip netns add "$NS_SRV" || return 1
  ip netns add "$NS_CLI" || return 1
  ip link add "$VETH_SRV" type veth peer name "$VETH_CLI" || return 1
  ip link set "$VETH_SRV" netns "$NS_SRV" || return 1
  ip link set "$VETH_CLI" netns "$NS_CLI" || return 1
  ip netns exec "$NS_SRV" ip link set lo up || return 1
  ip netns exec "$NS_CLI" ip link set lo up || return 1
  ip netns exec "$NS_SRV" ip link set "$VETH_SRV" name underlay0 || return 1
  ip netns exec "$NS_CLI" ip link set "$VETH_CLI" name underlay0 || return 1
  ip netns exec "$NS_SRV" ip addr add "$UNDERLAY_SRV/$UNDERLAY_PREFIX" dev underlay0 || return 1
  ip netns exec "$NS_CLI" ip addr add "$UNDERLAY_CLI/$UNDERLAY_PREFIX" dev underlay0 || return 1
  ip netns exec "$NS_SRV" ip link set underlay0 up || return 1
  ip netns exec "$NS_CLI" ip link set underlay0 up || return 1
}

wait_for_port() {
  local deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    if ip netns exec "$NS_CLI" bash -c "exec 3<>/dev/tcp/$UNDERLAY_SRV/$PORT" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

wait_for_client_ip() {
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if ip netns exec "$NS_CLI" ip -4 addr show "$TAP_CLI" 2>/dev/null | grep -q "$CLI_V4"; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

write_configs() {
  local fp="$1" psk="$2" tap_config=""
  if [[ -n "$PERF_TAP_QUEUES" ]]; then
    tap_config="\"tap_queues\": $PERF_TAP_QUEUES, \"tap_multi_queue\": $PERF_TAP_MULTI_QUEUE,"
  fi
  cat >"$TMP/server.json" <<EOF
{
  "mode": "server",
  "addr": "$UNDERLAY_SRV:$PORT",
  "psk": "$psk",
  "tap": "$TAP_SRV",
  $tap_config
  "encrypt": true,
  "enc_algo": "$PERF_ENC_ALGO",
  "pad_mode": "$PERF_PAD_MODE",
  "log_level": "$PERF_LOG_LEVEL",
  "web": {"addr": "$WEB_ADDR", "bind": "all", "auth": "$WEB_AUTH"},
  "server": {
    "cert": "$TMP/cert.pem",
    "key": "$TMP/key.pem",
    "v4_cidr": "$SUBNET_V4",
    "v6_cidr": "$SUBNET_V6"
  }
}
EOF

  cat >"$TMP/client.json" <<EOF
{
  "mode": "client",
  "addr": "$UNDERLAY_SRV:$PORT",
  "psk": "$psk",
  "tap": "$TAP_CLI",
  $tap_config
  "encrypt": true,
  "enc_algo": "$PERF_ENC_ALGO",
  "pad_mode": "$PERF_PAD_MODE",
  "log_level": "$PERF_LOG_LEVEL",
  "web": {"addr": "$WEB_ADDR", "bind": "all", "auth": "$WEB_AUTH"},
  "client": {
    "conns": $PERF_CONNS,
    "fec": $PERF_FEC,
    "fec_group": $PERF_FEC_GROUP,
    "cert_sha256": "$fp",
    "insecure": true
  }
}
EOF
}

profile_env_for() {
  local side="$1"
  if [[ -z "$PERF_PROFILE_DIR" ]]; then
    return 0
  fi
  mkdir -p "$PERF_PROFILE_DIR"
  printf 'TLSVPN_CPU_PROFILE=%s/%s.cpu.prof\n' "$PERF_PROFILE_DIR" "$side"
  printf 'TLSVPN_HEAP_PROFILE=%s/%s.heap.prof\n' "$PERF_PROFILE_DIR" "$side"
}

start_endpoint() {
  local ns="$1" side="$2" cfg="$3" log_file="$4"
  local -a env_args=()
  if [[ -n "$PERF_PROFILE_DIR" ]]; then
    mkdir -p "$PERF_PROFILE_DIR"
    env_args+=("TLSVPN_CPU_PROFILE=$PERF_PROFILE_DIR/$side.cpu.prof")
    env_args+=("TLSVPN_HEAP_PROFILE=$PERF_PROFILE_DIR/$side.heap.prof")
  fi
  ip netns exec "$ns" env "${env_args[@]}" "$BIN" -c "$cfg" >"$log_file" 2>&1 &
  PIDS+=($!)
}

route_path_check() {
  local croute sroute
  croute=$(ip netns exec "$NS_CLI" ip -4 route get "$GW_V4" 2>&1) || return 1
  sroute=$(ip netns exec "$NS_SRV" ip -4 route get "$CLI_V4" 2>&1) || return 1
  [[ "$croute" == *"dev $TAP_CLI"* ]] || { log "client route bypasses TAP: $croute"; return 1; }
  [[ "$sroute" == *"dev $TAP_SRV"* ]] || { log "server route bypasses TAP: $sroute"; return 1; }
  log "route proof: client->$GW_V4 via $TAP_CLI; server->$CLI_V4 via $TAP_SRV"
}

parse_mbps() {
  awk -F: '/"bits_per_second"[[:space:]]*:/ {gsub(/[ ,[:space:]]/, "", $2); v=$2} END {if (v=="") exit 1; printf "%.1f", v/1000000}'
}

record_result() {
  local direction="$1" mbps="$2"
  RESULTS+=("$direction=$mbps")
  printf '%s\t%s\t%s\t%s\t%s\n' "$PERF_CONNS" "$PERF_ENC_ALGO" "$PERF_PAD_MODE" "$direction" "$mbps"
  if [[ -n "$PERF_RESULT_FILE" ]]; then
    printf '%s\t%s\t%s\t%s\t%s\n' "$PERF_CONNS" "$PERF_ENC_ALGO" "$PERF_PAD_MODE" "$direction" "$mbps" >>"$PERF_RESULT_FILE"
  fi
  if ! awk -v a="$mbps" -v b="$PERF_MIN_MBPS" 'BEGIN {exit !(a+0 >= b+0)}'; then
    die "$direction throughput ${mbps} Mbps is below PERF_MIN_MBPS=${PERF_MIN_MBPS}"
  fi
}


scheduler_diag() {
  local direction="$1" ns role
  if [[ "$direction" == "upload" ]]; then
    ns="$NS_CLI"; role="client"
  else
    ns="$NS_SRV"; role="server"
  fi
  ip netns exec "$ns" python3 - "$WEB_ADDR" "$WEB_AUTH" "$PERF_DIAG_FILE" "$PERF_CONNS" "$PERF_ENC_ALGO" "$PERF_PAD_MODE" "$direction" "$role" <<'PY'
import base64, json, sys, time, urllib.request
addr, auth, out, conns, enc, pad, direction, role = sys.argv[1:]
url = 'http://' + addr + '/api/stats'
req = urllib.request.Request(url, headers={'Authorization': 'Basic ' + base64.b64encode(auth.encode()).decode()})
last = None
for _ in range(20):
    try:
        with urllib.request.urlopen(req, timeout=0.5) as r:
            data = json.load(r)
        break
    except Exception as e:
        last = e
        time.sleep(0.05)
else:
    print(f'[real-tap-perf] scheduler diagnostic unavailable: {last}', file=sys.stderr)
    raise SystemExit(0)
rows = data.get('conns', []) if role == 'client' else data.get('server_conns', [])
# Baseline main has no scheduler object. In that case diagnostics are a no-op.
if not any(isinstance(c.get('scheduler'), dict) for c in rows):
    raise SystemExit(0)
reorder = data.get('reorder') or {}
records = []
assigned = []
for i, c in enumerate(rows):
    sched = c.get('scheduler') or {}
    ident = c.get('index', i) if role == 'client' else c.get('remote', str(i))
    n = int(sched.get('assigned_bytes', 0) or 0)
    assigned.append(n)
    records.append([
        conns, enc, pad, direction, role, str(ident),
        str(c.get('tx_bytes', 0)), str(c.get('rx_bytes', 0)),
        str(n), str(sched.get('assigned_batches', 0)),
        '1' if sched.get('active') else '0',
        str(sched.get('queued_bytes', 0)), str(sched.get('rate_mbps', 0)), str(sched.get('eta_us', 0)),
        '1' if sched.get('carry_pending') else '0',
        str(reorder.get('gap_events', 0)), str(reorder.get('timeout_flushes', 0)),
        str(reorder.get('skipped_frames', 0)), str(reorder.get('dropped_frames', 0)),
    ])
if out:
    with open(out, 'a', encoding='utf-8') as f:
        for vals in records:
            f.write('\t'.join(vals) + '\n')
total = sum(assigned)
shares = [(n / total if total else 0.0) for n in assigned]
print('[real-tap-perf] scheduler %s/%s assigned=%s shares=%s' % (
    direction, role, assigned, [round(x, 4) for x in shares]))
want = int(conns)
if want > 1:
    used = sum(n > 0 for n in assigned)
    if len(assigned) < want or used < want:
        raise SystemExit('adaptive scheduler used %d/%d paths: %s' % (used, want, assigned))
    if total and max(shares) > 0.80:
        raise SystemExit('adaptive scheduler path monopoly %.1f%%: %s' % (max(shares) * 100, shares))
PY
}

iperf_direction() {
  local direction="$1" json mbps extra=""
  [[ "$direction" == "download" ]] && extra="-R"
  json=$(ip netns exec "$NS_CLI" iperf3 -c "$GW_V4" -p "$((PORT + 1))" -t "$PERF_SECONDS" -P "$PERF_STREAMS" -O "$PERF_WARMUP" -J $extra 2>"$TMP/iperf-$direction.err") || {
    cat "$TMP/iperf-$direction.err" >&2 || true
    die "iperf3 $direction failed"
  }
  if [[ -n "${PERF_RAW_DIR:-}" ]]; then
    mkdir -p "$PERF_RAW_DIR"
    printf '%s\n' "$json" > "$PERF_RAW_DIR/iperf-$direction.json"
    ip netns exec "$NS_CLI" ip -s link show dev "$TAP_CLI" > "$PERF_RAW_DIR/client-link-$direction.txt"
    ip netns exec "$NS_SRV" ip -s link show dev "$TAP_SRV" > "$PERF_RAW_DIR/server-link-$direction.txt"
  fi
  mbps=$(printf '%s\n' "$json" | parse_mbps) || die "cannot parse iperf3 $direction result"
  log "$direction: ${mbps} Mbps (conns=$PERF_CONNS enc=$PERF_ENC_ALGO pad=$PERF_PAD_MODE)"
  record_result "$direction" "$mbps"
  scheduler_diag "$direction" || die "adaptive scheduler utilization gate failed"
}

verify_profiles() {
  [[ -n "$PERF_PROFILE_DIR" ]] || return 0
  local f
  for f in server.cpu.prof server.heap.prof client.cpu.prof client.heap.prof; do
    [[ -s "$PERF_PROFILE_DIR/$f" ]] || die "profile missing or empty: $PERF_PROFILE_DIR/$f"
  done
}

validate_inputs
capability_gate
TMP=$(mktemp -d)
setup_namespaces || die "failed to create isolated real-TAP topology"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -days 2 \
  -subj "/CN=tlsvpn-real-tap-perf" >/dev/null 2>&1 || die "certificate generation failed"
FP=$(openssl x509 -in "$TMP/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-Z' 'a-z')
PSK=$(openssl rand -hex 16)
write_configs "$FP" "$PSK"

start_endpoint "$NS_SRV" server "$TMP/server.json" "$TMP/server.log"
if ! wait_for_port; then
  tail -80 "$TMP/server.log" >&2 || true
  die "server did not become reachable"
fi
start_endpoint "$NS_CLI" client "$TMP/client.json" "$TMP/client.log"
if ! wait_for_client_ip; then
  tail -80 "$TMP/client.log" >&2 || true
  die "client tunnel address did not appear"
fi
sleep 0.5
route_path_check || die "real-TAP route proof failed"

ip netns exec "$NS_SRV" iperf3 -s -B "$GW_V4" -p "$((PORT + 1))" >"$TMP/iperf-server.log" 2>&1 &
PIDS+=($!)
sleep 0.3

case "$PERF_DIRECTION" in
  upload) iperf_direction upload ;;
  download) iperf_direction download ;;
  both)
    iperf_direction upload
    iperf_direction download
    ;;
esac

# Stop iperf first, then client/server. SIGTERM lets tlsvpn return through main
# and flush deferred CPU/heap profiles.
gracious_stop
verify_profiles
log "completed: ${RESULTS[*]}"
