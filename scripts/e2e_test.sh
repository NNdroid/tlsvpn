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
# All groups use the in-memory TAP backend ("tap": "mem" / --tap mem) so the
# test runs on CI runners that cannot create a real TAP device (no
# CAP_NET_ADMIN). The tunnel (TLS handshake, FEC, encryption) is exercised
# identically. The Go binary is launched with -c <generated config>; the Rust
# binary keeps its command-line flags.
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

# Generate a Go-side JSON config. Only long-standing fields (present since the
# original JSON config support) are written, so the same generator also works
# against E2E_USE_RELEASE release binaries; newer fields keep their defaults.
#   $1 = output path  $2 = mode  $3 = addr  $4 = socks5 (optional, client only)
write_go_config() {
  local out="$1" mode="$2" addr="$3" socks5="${4:-}"
  local socks_line=""
  [ -n "$socks5" ] && socks_line=",
  \"socks5\": \"$socks5\""
  cat >"$out" <<EOF
{
  "mode": "$mode",
  "addr": "$addr",
  "tap": "mem"$socks_line
}
EOF
}

# Start a server in background.
#   $1 = binary path
#   $2 = listen port
#   $3+ = extra args (optional, passed through to the Rust binary only)
# Uses the in-memory TAP backend so it runs without CAP_NET_ADMIN.
# The Go binary is config-file-only (flags were removed): launch with -c.
start_server() {
  local bin="$1" port="$2"; shift 2
  # Provide a self-signed cert so the Rust server (which requires --cert/--key,
  # unlike Go which self-signs when omitted) can start. Generated once per env.
  if [ ! -f "$TEST_DIR/e2e_cert.pem" ]; then
    gen_e2e_cert "$TEST_DIR/e2e_key.pem" "$TEST_DIR/e2e_cert.pem" \
      || { err "could not generate e2e TLS cert (openssl missing or failed)"; return 1; }
  fi
  local log="$TEST_DIR/srv_$(basename "$bin")_$port.log"
  case "$(basename "$bin")" in
    tlsvpn_rs*)
      "$bin" "$@" --mode server --addr ":$port" --tap mem \
        --cert "$TEST_DIR/e2e_cert.pem" --key "$TEST_DIR/e2e_key.pem" >"$log" 2>&1 &
      ;;
    *)
      # -print-config doubles as a capability probe: release binaries that
      # predate JSON config support fail here with an actionable message
      # instead of a mysterious start failure.
      "$bin" -print-config >/dev/null 2>&1 \
        || { err "$bin lacks JSON config support; cut a newer release or set E2E_USE_RELEASE=0"; return 1; }
      local cfg="$TEST_DIR/go_srv_$port.json"
      write_go_config "$cfg" server ":$port"
      "$bin" -c "$cfg" "$@" >"$log" 2>&1 &
      ;;
  esac
  local pid=$!
  echo "$pid" >"$TEST_DIR/srv_$port.pid"
  if wait_for_port 127.0.0.1 "$port" 20; then
    ok "server up: $bin :$port (pid $pid)"
  else
    err "server failed to start: $bin :$port"
    echo "----- $bin server log (port $port) -----"
    cat "$log"
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
#   $1 = binary  $2 = port (pid-file key)  $3 = server addr  rest = extra args
#   (Go extras: "-socks5 <addr>" is folded into the config; Rust extras such as
#   "--socks5 <addr>" pass through unchanged)
# Uses the in-memory TAP backend so it runs without CAP_NET_ADMIN.
run_client() {
  local bin="$1" port="$2" addr="$3"; shift 3
  local log="$TEST_DIR/cli_$(basename "$bin")_$port.log"
  case "$(basename "$bin")" in
    tlsvpn_rs*)
      "$bin" "$@" --mode client --addr "$addr" --tap mem >"$log" 2>&1 &
      ;;
    *)
      local socks=""
      [ "${1:-}" = "-socks5" ] && socks="${2:-}"
      local cfg="$TEST_DIR/go_cli_$port.json"
      write_go_config "$cfg" client "$addr" "$socks"
      "$bin" -c "$cfg" >"$log" 2>&1 &
      ;;
  esac
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

# Group G: in-process performance suite (LibreSpeed/ping/traceroute equivalents
# over the real tunnel pipeline with mem tap). Runs Go-side tests from the
# checked-out source; requires a Go toolchain. In release mode the repo is not
# checked out by resolve_binaries unless E2E_KEEP_SRC=1, so we skip gracefully
# outside CI-source runs.
run_group_G() {
  if ! command -v go >/dev/null 2>&1; then
    log "group G (perf): go toolchain not found — skipping"
    return 0
  fi
  go test -count=1 -timeout 10m -run 'TestPerf' -v ./... | tee "$TEST_DIR/perf.txt"
  if grep -qE '^--- FAIL' "$TEST_DIR/perf.txt"; then
    err "group G: perf tests failed (see $TEST_DIR/perf.txt)"
    return 1
  fi
  ok "group G: perf suite passed"
}

main() {
  setup_test_env
  resolve_binaries
  for g in A B C D E F G; do
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
