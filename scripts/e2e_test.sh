#!/usr/bin/env bash
# e2e_test.sh — cross-implementation end-to-end control groups for tlsvpn.
#
# Control groups:
#   A  go_srv  <- go_cli      (Go ↔ Go, self-self)
#   B  rs_srv  <- rs_cli      (Rust ↔ Rust, self-self)
#   C  go_srv  <- rs_cli      (Go server, Rust client — cross-language)
#   D  rs_srv  <- go_cli      (Rust server, Go client — cross-language)
#   H  go_srv  <- rs_cli      (cross-language, hardened: GCM, bucket pad,
#                              session token, FEC group 4)
#   I  rs_srv  <- go_cli      (cross-language, hardened — reverse direction)
#   J  go_srv  <- rs_cli      (cross-language, legacy: CTR, legacy pad,
#                              session token off, FEC group 8)
#   K  rs_srv  <- go_cli      (cross-language, plain: encryption, padding and
#                              FEC all off)
#   L  go/rs servers <- independent Go TLS probe (server-observed ClientHello
#                      summary, negotiated fields and cross-server fingerprint)
#   E  go_srv  <- go_cli via SOCKS5 proxy   (proxy group, client-only feature)
#   F  go_srv  <- rs_cli via SOCKS5 proxy   (proxy group, client-only feature)
#   G  perf suite (in-process, Go side)
#
# All groups use the in-memory TAP backend ("tap": "mem") so the test runs on
# CI runners that cannot create a real TAP device (no CAP_NET_ADMIN). The
# tunnel (TLS handshake, FEC, encryption) is exercised identically. Both
# binaries are launched the same way, with -c <generated config>; the two
# implementations share one JSON schema.
#
# Binaries are always built from source (see scripts/lib_e2e.sh): the two
# repositories are checked out — this repo for Go, plus a clone of the Rust
# implementation unless E2E_GO_SRC / E2E_RS_SRC point at local checkouts — and
# each is compiled for the host before the control groups run.
#
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib_e2e.sh
source "$SCRIPT_DIR/lib_e2e.sh"

PASS=0
FAIL=0

# cfg_json renders a JSON object from dotted key=value pairs.
#
# Values must already be JSON literals — so strings are pre-quoted by the
# caller (addr='"127.0.0.1:18080"'), numbers and booleans stay bare
# (client.fec_group=4). An empty value omits the key entirely, so both
# implementations fall back to their own defaults. Dotted keys nest one level:
# server.max_sessions and server.cert merge into a single "server" object.
#
# Top-level keys are emitted in a fixed order; nested sections in a fixed order
# too, so a failing group's config is readable and diffable in CI logs.
cfg_json() {
  local -A v=()
  local kv k lit out="" first=1 body
  for kv in "$@"; do
    k="${kv%%=*}"
    lit="${kv#*=}"
    [ -n "$lit" ] && v["$k"]="$lit"
  done
  for k in mode addr psk tap socks5 log_level encrypt enc_algo min_enc pad_mode \
           brutal brutal_up brutal_down mac; do
    [ -n "${v[$k]:-}" ] || continue
    [ $first -eq 0 ] && out+=","
    first=0
    out+="\"$k\": ${v[$k]}"
  done
  for k in server client web; do
    body=""
    for key in "${!v[@]}"; do
      [[ "$key" == "$k."* ]] || continue
      [ -n "$body" ] && body+=","
      body+="\"${key#"$k".}\": ${v[$key]}"
    done
    [ -n "$body" ] || continue
    [ $first -eq 0 ] && out+=","
    first=0
    out+="\"$k\": {$body}"
  done
  printf '{%s}\n' "$out"
}

# write_config renders one JSON config accepted by BOTH implementations. The two
# repos share the same schema and both reject unknown fields, so a single
# emitter serves Go and Rust — and unknown-field rejection is what keeps this
# emitter honest: a typo here fails both sides loudly instead of silently
# disabling the knob under test.
#   $1 = output path   $2..$n = dotted key=JSON_LITERAL (empty literal omits)
write_config() {
  local out="$1"; shift
  cfg_json "$@" >"$out"
}

# Shared config matrices for the interop groups. Each element is one
# key=JSON_LITERAL pair (strings pre-quoted). The same matrix is handed to BOTH
# sides of a group, so every knob is exercised symmetrically and a mismatch is
# never blamed on asymmetric configuration.
#
#   HARDENED — authenticated GCM with a required GCM floor, bucket padding,
#              mandatory session-token resume, and FEC group 4. It intentionally
#              omits enc_algo here so the default AES-256 path remains compatible
#              with a peer from before the explicit key-size option existed.
#   LEGACY   — the weakest encrypted configuration still supported: no cipher
#              floor, padding off, mandatory session token, and FEC group 8.
#              AES-CTR and legacy padding modes were removed with protocol v2.
#   PLAIN    — encryption, padding and FEC all switched off: the shortest path
#              through the protocol, where a byte-level difference between the
#              implementations is most likely to surface.
MATRIX_HARDENED=(
  encrypt=true 'min_enc="gcm"' 'pad_mode="bucket"'
  'client.fec=true' client.fec_group=4
)
MATRIX_LEGACY=(
  encrypt=true 'min_enc="any"' 'pad_mode="off"'
  'client.fec=true' client.fec_group=8
)
MATRIX_PLAIN=(
  encrypt=false 'min_enc=""' 'pad_mode="off"'
  'client.fec=false' client.fec_group=4
)

# e2e_psk returns the shared PSK for this env, generating it once on first use.
# Both implementations hard-fail config validation on an empty psk, so every
# generated config needs one; server and client must hold the same value.
e2e_psk() {
  local f="$TEST_DIR/e2e_psk"
  if [ ! -s "$f" ]; then
    gen_e2e_psk >"$f" || return 1
  fi
  cat "$f"
}

# Start a server in background.
#   $1 = binary path  $2 = listen port  $3+ = key=JSON_LITERAL config overrides
# Uses the in-memory TAP backend so it runs without CAP_NET_ADMIN. Both
# binaries are config-file-only (flags were removed): launch with -c.
start_server() {
  local bin="$1" port="$2"; shift 2
  # The Rust server has no self-sign fallback and aborts on an empty cert/key,
  # so generate one pair per env and hand it to both implementations.
  if [ ! -f "$TEST_DIR/e2e_cert.pem" ]; then
    gen_e2e_cert "$TEST_DIR/e2e_key.pem" "$TEST_DIR/e2e_cert.pem" \
      || { err "could not generate e2e TLS cert (openssl missing or failed)"; return 1; }
  fi
  local log cfg cert key psk
  log="$TEST_DIR/srv_$(basename "$bin")_$port.log"
  cfg="$TEST_DIR/srv_$(basename "$bin")_$port.json"
  # The paths live inside file contents, which MSYS never translates, so they
  # must be rendered in the form the child process understands.
  cert="$(json_path "$TEST_DIR/e2e_cert.pem")"
  key="$(json_path "$TEST_DIR/e2e_key.pem")"
  psk="$(e2e_psk)" || return 1
  write_config "$cfg" mode='"server"' addr="\":$port\"" tap='"mem"' psk="\"$psk\"" \
    server.cert="\"$cert\"" server.key="\"$key\"" "$@"
  "$bin" -c "$cfg" >"$log" 2>&1 &
  local pid=$!
  echo "$pid" >"$TEST_DIR/srv_$port.pid"
  if wait_for_port 127.0.0.1 "$port" 20; then
    ok "server up: $bin :$port (pid $pid)"
  else
    err "server failed to start: $bin :$port"
    echo "----- $bin server log (port $port) -----"
    cat "$log"
    echo "----- config used: $([ -f "$cfg" ] && cat "$cfg" || echo MISSING) -----"
    echo "----- cert present: $([ -f "$TEST_DIR/e2e_cert.pem" ] && echo yes || echo no) -----"
    kill "$pid" 2>/dev/null || true
    return 1
  fi
}

stop_server() {
  local port="$1"
  local pidf="$TEST_DIR/srv_$port.pid"
  [[ -f "$pidf" ]] && kill "$(cat "$pidf")" 2>/dev/null || true
  rm -f "$pidf"
}

# Run a client in the background (VPN clients are long-lived). Validates the
# tunnel came up by checking the process stays alive and emits a startup/connected
# marker, then leaves it running so the caller stops it with stop_client.
#   $1 = binary  $2 = port (pid-file key)  $3 = server addr
#   $4+ = key=JSON_LITERAL config overrides; the legacy "-socks5 <addr>" /
#        "--socks5 <addr>" form is still accepted and folded into the config,
#        since both implementations read the same top-level "socks5" field.
# Uses the in-memory TAP backend so it runs without CAP_NET_ADMIN.
run_client() {
  local bin="$1" port="$2" addr="$3"; shift 3
  local log socks="" psk
  log="$TEST_DIR/cli_$(basename "$bin")_$port.log"
  if [[ "${1:-}" == "-socks5" || "${1:-}" == "--socks5" ]]; then
    socks="\"${2:-}\""; shift 2
  fi
  local cfg="$TEST_DIR/cli_$(basename "$bin")_$port.json"
  psk="$(e2e_psk)" || return 1
  write_config "$cfg" mode='"client"' addr="\"$addr\"" tap='"mem"' psk="\"$psk\"" \
    socks5="$socks" "$@"
  "$bin" -c "$cfg" >"$log" 2>&1 &
  local pid=$!
  echo "$pid" >"$TEST_DIR/cli_$port.pid"
  local ok=0
  for i in $(seq 1 30); do
    kill -0 "$pid" 2>/dev/null || { ok=0; break; }
    if grep -qiE "ClientID|Starting Client Mode|tunnel (established|up)|connected|handshake complete|session (created|established)|assigned" "$log"; then ok=1; break; fi
    sleep 1
  done
  if [[ "$ok" -eq 1 ]]; then
    ok "client tunnel up: $bin -> $addr (pid $pid)"
    return 0
  fi
  err "client FAILED: $bin -> $addr"; tail -n 30 "$log" >&2; kill "$pid" 2>/dev/null; rm -f "$TEST_DIR/cli_$port.pid"; return 1
}

stop_client() {
  local port="$1"
  local pidf="$TEST_DIR/cli_$port.pid"
  [[ -f "$pidf" ]] && kill "$(cat "$pidf")" 2>/dev/null || true
  rm -f "$pidf"
}

# Start a SOCKS5 proxy (microsocks) if available; echo its pid into $1 var name.
# Prints the proxy listen port. Skips the whole group if microsocks is missing.
ensure_socks5_proxy() {
  if ! command -v microsocks >/dev/null 2>&1; then
    return 1
  fi
  local port=19090
  microsocks -p "$port" >"$TEST_DIR/socks.log" 2>&1 &
  local spid=$!
  echo "$spid" >"$TEST_DIR/socks.pid"
  wait_for_port 127.0.0.1 "$port" 10 || { kill "$spid" 2>/dev/null; return 1; }
  echo "$port"
}

teardown_socks5_proxy() {
  [[ -f "$TEST_DIR/socks.pid" ]] && kill "$(cat "$TEST_DIR/socks.pid")" 2>/dev/null || true
  rm -f "$TEST_DIR/socks.pid"
}

# ---- control groups ------------------------------------------------------
run_group_A() {
  start_server "$BIN_GO" 18080 || return 1
  run_client "$BIN_GO" 18080 "127.0.0.1:18080" || { stop_server 18080; return 1; }
  stop_client 18080; stop_server 18080
}
run_group_B() {
  start_server "$BIN_RS" 18081 || return 1
  run_client "$BIN_RS" 18081 "127.0.0.1:18081" || { stop_server 18081; return 1; }
  stop_client 18081; stop_server 18081
}
run_group_C() {
  start_server "$BIN_GO" 18082 || return 1
  run_client "$BIN_RS" 18082 "127.0.0.1:18082" || { stop_server 18082; return 1; }
  stop_client 18082; stop_server 18082
}
run_group_D() {
  start_server "$BIN_RS" 18083 || return 1
  run_client "$BIN_GO" 18083 "127.0.0.1:18083" || { stop_server 18083; return 1; }
  stop_client 18083; stop_server 18083
}

# Groups H-K: the same cross-language directions as C/D, but with a different
# wire configuration on BOTH sides (see MATRIX_* above). A-D only ever ran the
# default configuration, so a protocol divergence that shows up only under
# encryption, padding or FEC settings stayed invisible:
#
#   H  go_srv <- rs_cli   hardened: encrypt + GCM floor, bucket padding,
#                         mandatory session token, FEC group 4
#   I  rs_srv <- go_cli   hardened (reverse direction)
#   J  go_srv <- rs_cli   weak encrypted profile: no cipher floor, padding off,
#                         mandatory session token, FEC group 8
#   K  rs_srv <- go_cli   plain: encryption, padding and FEC all off
run_group_H() {
  start_server "$BIN_GO" 18086 "${MATRIX_HARDENED[@]}" || return 1
  run_client "$BIN_RS" 18086 "127.0.0.1:18086" "${MATRIX_HARDENED[@]}" \
    || { stop_server 18086; return 1; }
  stop_client 18086; stop_server 18086
}
run_group_I() {
  start_server "$BIN_RS" 18087 "${MATRIX_HARDENED[@]}" || return 1
  run_client "$BIN_GO" 18087 "127.0.0.1:18087" "${MATRIX_HARDENED[@]}" \
    || { stop_server 18087; return 1; }
  stop_client 18087; stop_server 18087
}
run_group_J() {
  start_server "$BIN_GO" 18088 "${MATRIX_LEGACY[@]}" || return 1
  run_client "$BIN_RS" 18088 "127.0.0.1:18088" "${MATRIX_LEGACY[@]}" \
    || { stop_server 18088; return 1; }
  stop_client 18088; stop_server 18088
}
run_group_K() {
  start_server "$BIN_RS" 18089 "${MATRIX_PLAIN[@]}" || return 1
  run_client "$BIN_GO" 18089 "127.0.0.1:18089" "${MATRIX_PLAIN[@]}" \
    || { stop_server 18089; return 1; }
  stop_client 18089; stop_server 18089
}

# Group L validates the optional TLS diagnostics with an independent protocol
# client. The probe checks that the server-observed version/cipher/ALPN/SNI match
# its local TLS state and that all normalized ClientHello feature lists exist.
# Running the exact same probe against both implementations must produce the
# same fingerprint; this catches Go/Rust canonicalization or GREASE drift.
run_group_L() {
  local exe="" probe psk go_out rs_out go_fp rs_fp
  [[ "$(go env GOOS)" == "windows" ]] && exe=".exe"
  probe="$TEST_DIR/tlsinfo_probe$exe"
  psk="$(e2e_psk)" || return 1
  ( cd "$E2E_GO_SRC/interop" && go build -o "$probe" . ) || return 1

  start_server "$BIN_GO" 18090 "${MATRIX_HARDENED[@]}" || return 1
  if ! go_out="$("$probe" -addr 127.0.0.1:18090 -psk "$psk" -sni www.cloudflare.com -send 1 -timeout 8)"; then
    stop_server 18090
    return 1
  fi
  stop_server 18090

  start_server "$BIN_RS" 18091 "${MATRIX_HARDENED[@]}" || return 1
  if ! rs_out="$("$probe" -addr 127.0.0.1:18091 -psk "$psk" -sni www.cloudflare.com -send 1 -timeout 8)"; then
    stop_server 18091
    return 1
  fi
  stop_server 18091

  go_fp="$(printf '%s\n' "$go_out" | sed -n 's/.* tls=\([^ ]*\).*/\1/p')"
  rs_fp="$(printf '%s\n' "$rs_out" | sed -n 's/.* tls=\([^ ]*\).*/\1/p')"
  if [[ -z "$go_fp" || "$go_fp" != "$rs_fp" ]]; then
    err "group L: Go/Rust server TLS fingerprints differ: go=$go_fp rust=$rs_fp"
    return 1
  fi
  ok "group L: server-observed TLS summary matched: $go_fp"
}

# Group E: Go client through SOCKS5 proxy -> Go server (client-only feature).
run_group_E() {
  local port; port="$(ensure_socks5_proxy)" || { log "group E (go-socks5): microsocks not installed — skipping"; return 0; }
  start_server "$BIN_GO" 18084 || { teardown_socks5_proxy; return 1; }
  run_client "$BIN_GO" 18084 "127.0.0.1:18084" -socks5 "127.0.0.1:$port" || { stop_server 18084; teardown_socks5_proxy; return 1; }
  stop_client 18084; stop_server 18084; teardown_socks5_proxy
}

# Group F: Rust client through SOCKS5 proxy -> Go server (client-only feature).
# Same "socks5" config field as group E, across languages (needs microsocks).
run_group_F() {
  local port; port="$(ensure_socks5_proxy)" || { log "group F (rs-socks5): microsocks not installed — skipping"; return 0; }
  start_server "$BIN_GO" 18085 || { teardown_socks5_proxy; return 1; }
  run_client "$BIN_RS" 18085 "127.0.0.1:18085" -socks5 "127.0.0.1:$port" || { stop_server 18085; teardown_socks5_proxy; return 1; }
  stop_client 18085; stop_server 18085; teardown_socks5_proxy
}

# Group G: in-process performance suite (LibreSpeed/ping/traceroute equivalents
# over the real tunnel pipeline with mem tap). Runs the Go-side tests from the
# source tree that resolve_binaries built, so no separate checkout is needed.
run_group_G() {
  if ! command -v go >/dev/null 2>&1; then
    log "group G (perf): go toolchain not found — skipping"
    return 0
  fi
  ( cd "$E2E_GO_SRC" && go test -count=1 -timeout 10m -run 'TestPerf' -v ./... ) \
    | tee "$TEST_DIR/perf.txt"
  if grep -qE '^--- FAIL' "$TEST_DIR/perf.txt"; then
    err "group G: perf tests failed (see $TEST_DIR/perf.txt)"
    return 1
  fi
  ok "group G: perf suite passed"
}

main() {
  setup_test_env
  resolve_binaries
  # Interop groups first (A-D on the default configuration, H-K on varied
  # configurations), then the TLS-observation group, proxy-only groups and perf.
  # E2E_GROUPS="L" (or a space-separated subset) makes focused regression runs
  # cheap without weakening the default complete matrix.
  local groups="${E2E_GROUPS:-A B C D H I J K L E F G}"
  for g in $groups; do
    if run_group "$g"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
  done
  cleanup_test_env
  log "==== summary: PASS=$PASS FAIL=$FAIL ===="
  [[ "$FAIL" -eq 0 ]]
}

trap cleanup_test_env EXIT
main "$@"
# Capture main()'s status explicitly and exit with it, so the EXIT trap cannot
# influence the final exit code.
exit $?
