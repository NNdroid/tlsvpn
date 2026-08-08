#!/usr/bin/env bash
# e2e_test.sh — cross-implementation end-to-end control groups for tlsvpn.
#
# Control groups:
#   A  go_srv  <- go_cli      (Go ↔ Go, self-self)
#   B  rs_srv  <- rs_cli      (Rust ↔ Rust, self-self)
#   C  go_srv  <- rs_cli      (Go server, Rust client — cross-language)
#   D  rs_srv  <- go_cli      (Rust server, Go client — cross-language)
#   E  go_srv  <- go_cli via SOCKS5 proxy   (proxy group, client-only feature)
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

# Start a server in background.
#   $1 = binary path
#   $2 = listen port
#   $3 = extra args (optional)
start_server() {
  local bin="$1" port="$2"; shift 2
  local log="$TEST_DIR/srv_$(basename "$bin")_$port.log"
  "$bin" "$@" -mode server -listen ":$port" >"$log" 2>&1 &
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

# Run a client to completion (short-lived), asserting exit 0.
#   $1 = binary  $2 = server addr  rest = extra args (forwarded verbatim)
# SOCKS5 flag differs between binaries: Go uses -socks5, Rust uses --socks5.
# Callers pass the correct flag form explicitly.
run_client() {
  local bin="$1" addr="$2"; shift 2
  local log="$TEST_DIR/cli_$(basename "$bin")_$$.log"
  if "$bin" "$@" -mode client -server "$addr" >"$log" 2>&1; then
    ok "client ok: $bin -> $addr"
    return 0
  else
    err "client FAILED: $bin -> $addr"; tail -n 30 "$log" >&2; return 1
  fi
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
run_group_A() { start_server "$BIN_GO" 18080 && run_client "$BIN_GO" "127.0.0.1:18080"; local r=$?; stop_server 18080; return $r; }
run_group_B() { start_server "$BIN_RS" 18081 && run_client "$BIN_RS" "127.0.0.1:18081"; local r=$?; stop_server 18081; return $r; }
run_group_C() { start_server "$BIN_GO" 18082 && run_client "$BIN_RS" "127.0.0.1:18082"; local r=$?; stop_server 18082; return $r; }
run_group_D() { start_server "$BIN_RS" 18083 && run_client "$BIN_GO" "127.0.0.1:18083"; local r=$?; stop_server 18083; return $r; }

# Group E: Go client through SOCKS5 proxy -> Go server (client-only feature).
run_group_E() {
  local port; port="$(ensure_socks5_proxy)" || { log "group E (go-socks5): microsocks not installed — skipping"; return 0; }
  start_server "$BIN_GO" 18084
  local r=0
  run_client "$BIN_GO" "127.0.0.1:18084" -socks5 "127.0.0.1:$port" || r=1
  stop_server 18084
  teardown_socks5_proxy
  return $r
}

# Group F: Rust client through SOCKS5 proxy -> Go server (client-only feature,
# now both implementations support --socks5).
run_group_F() {
  local port; port="$(ensure_socks5_proxy)" || { log "group F (rs-socks5): microsocks not installed — skipping"; return 0; }
  start_server "$BIN_GO" 18085
  local r=0
  run_client "$BIN_RS" "127.0.0.1:18085" --socks5 "127.0.0.1:$port" || r=1
  stop_server 18085
  teardown_socks5_proxy
  return $r
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
