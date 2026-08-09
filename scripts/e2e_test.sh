#!/usr/bin/env bash
# e2e_test.sh — cross-implementation end-to-end control groups for tlsvpn.
#
# Control groups:
#   A  go_srv  <- go_cli      (Go ↔ Go, self-self)
#   B  rs_srv  <- rs_cli      (Rust ↔ Rust, self-self)
#   C  go_srv  <- rs_cli      (Go server, Rust client — cross-language)
#   D  rs_srv  <- go_cli      (Rust server, Go client — cross-language)
#   E  go_srv  <- go_cli via SOCKS5 proxy   (proxy group, client-only feature)
#   F  go_srv  <- rs_cli via SOCKS5 proxy   (proxy group, client-only feature)
#
# All groups use the in-memory TAP backend (-tap mem / --tap mem) so the test
# runs on CI runners that cannot create a real TAP device (no CAP_NET_ADMIN).
# The tunnel (TLS handshake, FEC, encryption) is exercised identically.
#
# Binaries come from GitHub releases in CI, or local build otherwise
# (see scripts/lib_e2e.sh). Set E2E_USE_RELEASE=0 to force local build.
#
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib_e2e.sh
source "$SCRIPT_DIR/lib_e2e.sh"

PASS=0
FAIL=0

# Emit the flag style for a given binary. Go uses single-dash flags
# (-mode/-addr/-socks5); Rust uses long-only flags (--mode/--addr/--socks5).
# We map a logical "verb" to the concrete flag string for the binary.
#   $1 = binary path
#   $2 = verb: mode|addr|socks5
# Prints the flag prefix WITHOUT the value (caller appends " value").
flag_for() {
  local bin="$1" verb="$2"
  case "$(basename "$bin")" in
    tlsvpn_rs) case "$verb" in mode) echo "--mode";; addr) echo "--addr";; socks5) echo "--socks5";; tap) echo "--tap";; esac ;;
    *)         case "$verb" in mode) echo "-mode";;  addr) echo "-addr";;  socks5) echo "-socks5";; tap) echo "-tap";;  esac ;;
  esac
}

# Start a server in background.
#   $1 = binary path
#   $2 = listen port
#   $3 = extra args (optional)
# Uses the in-memory TAP backend so it runs without CAP_NET_ADMIN.
start_server() {
  local bin="$1" port="$2"; shift 2
  local mode_flag addr_flag tap_flag
  mode_flag="$(flag_for "$bin" mode)"
  addr_flag="$(flag_for "$bin" addr)"
  tap_flag="$(flag_for "$bin" tap)"
  local log="$TEST_DIR/srv_$(basename "$bin")_$port.log"
  "$bin" "$@" "$mode_flag" server "$addr_flag" ":$port" "$tap_flag" mem >"$log" 2>&1 &
  local pid=$!
  echo "$pid" >"$TEST_DIR/srv_$port.pid"
  if wait_for_port 127.0.0.1 "$port" 20; then
    ok "server up: $bin :$port (pid $pid)"
  else
    err "server failed to start: $bin :$port"; cat "$log" >&2; kill "$pid" 2>/dev/null || true; return 1
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
#   $1 = binary  $2 = port (pid-file key)  $3 = server addr  rest = extra args
# Uses the in-memory TAP backend so it runs without CAP_NET_ADMIN.
run_client() {
  local bin="$1" port="$2" addr="$3"; shift 3
  local mode_flag addr_flag tap_flag
  mode_flag="$(flag_for "$bin" mode)"
  addr_flag="$(flag_for "$bin" addr)"
  tap_flag="$(flag_for "$bin" tap)"
  local log="$TEST_DIR/cli_$(basename "$bin")_$port.log"
  "$bin" "$@" "$mode_flag" client "$addr_flag" "$addr" "$tap_flag" mem >"$log" 2>&1 &
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

# Group E: Go client through SOCKS5 proxy -> Go server (client-only feature).
run_group_E() {
  local port; port="$(ensure_socks5_proxy)" || { log "group E (go-socks5): microsocks not installed — skipping"; return 0; }
  start_server "$BIN_GO" 18084 || { teardown_socks5_proxy; return 1; }
  run_client "$BIN_GO" 18084 "127.0.0.1:18084" -socks5 "127.0.0.1:$port" || { stop_server 18084; teardown_socks5_proxy; return 1; }
  stop_client 18084; stop_server 18084; teardown_socks5_proxy
}

# Group F: Rust client through SOCKS5 proxy -> Go server (client-only feature).
# Rust --socks5 shipped in release v1.0.20260809 and later; this group runs in
# both release and local-build modes (requires microsocks for the proxy).
run_group_F() {
  local port; port="$(ensure_socks5_proxy)" || { log "group F (rs-socks5): microsocks not installed — skipping"; return 0; }
  start_server "$BIN_GO" 18085 || { teardown_socks5_proxy; return 1; }
  run_client "$BIN_RS" 18085 "127.0.0.1:18085" --socks5 "127.0.0.1:$port" || { stop_server 18085; teardown_socks5_proxy; return 1; }
  stop_client 18085; stop_server 18085; teardown_socks5_proxy
}

main() {
  setup_test_env
  resolve_binaries
  for g in A B C D E F; do
    if run_group "$g"; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
  done
  cleanup_test_env
  log "==== summary: PASS=$PASS FAIL=$FAIL ===="
  [[ "$FAIL" -eq 0 ]]
}

trap cleanup_test_env EXIT
main "$@"
