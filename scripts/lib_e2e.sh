#!/usr/bin/env bash
# lib_e2e.sh — shared helpers for tlsvpn / tlsvpn-rs end-to-end tests.
#
# Binary sourcing strategy
# ------------------------
# Control groups test *released* builds of the two implementations against each
# other. In CI we download the latest GitHub release binaries; locally we build
# from the checked-out source tree.
#
#   E2E_USE_RELEASE=1   force download from GitHub releases (default inside CI)
#   E2E_USE_RELEASE=0   force local build (default outside CI)
#   CI=true             implies E2E_USE_RELEASE=1 unless explicitly overridden
#
# Asset naming (must stay in sync with each repo's build_and_release workflow):
#   Go : tlsvpn_linux_<arch>          e.g. tlsvpn_linux_amd64
#   Rs : tlsvpn-<arch>-unknown-linux-musl   e.g. tlsvpn-x86_64-unknown-linux-musl
#
# For local builds we produce the same in-tree binaries:
#   Go : bin/tlsvpn (or just `go run`/built binary named tlsvpn)
#   Rs : target/release/tlsvpn
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (overridable via environment)
# ---------------------------------------------------------------------------
E2E_GO_REPO="${E2E_GO_REPO:-NNdroid/tlsvpn}"
E2E_RS_REPO="${E2E_RS_REPO:-NNdroid/tlsvpn-rs}"
E2E_GO_TAG="${E2E_GO_TAG:-latest}"      # or a specific tag like v1.0.20260615
E2E_RS_TAG="${E2E_RS_TAG:-latest}"

# Resolve use-release flag.
if [[ -z "${E2E_USE_RELEASE:-}" ]]; then
  if [[ "${CI:-false}" == "true" ]]; then
    E2E_USE_RELEASE=1
  else
    E2E_USE_RELEASE=0
  fi
fi

# Detect host architecture → Go/Rust asset suffixes.
detect_arch() {
  local m
  m="$(uname -m)"
  case "$m" in
    x86_64|amd64)  E2E_ARCH_GO="amd64";  E2E_ARCH_RS="x86_64" ;;
    aarch64|arm64) E2E_ARCH_GO="arm64";  E2E_ARCH_RS="aarch64" ;;
    armv7l|armv7)  E2E_ARCH_GO="arm";    E2E_ARCH_RS="armv7" ;;
    *) echo "unsupported arch: $m" >&2; exit 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log()  { echo "[e2e] $*"; }
ok()   { echo "[e2e][ok] $*"; }
err()  { echo "[e2e][FAIL] $*" >&2; }
fail() { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Release binary download
# ---------------------------------------------------------------------------
fetch_latest_tag() {
  # $1 = owner/repo
  # NOTE: do NOT pipe curl into grep — grep -m1 closes the pipe early, causing
  # curl to hit SIGPIPE and exit 23 under `set -o pipefail`. Save to a file first.
  local repo="$1" tmp api
  tmp="$(mktemp)"
  api="https://api.github.com/repos/$repo/releases/latest"
  local -a auth=()
  [[ -n "${GITHUB_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  if ! curl -fsSL "${auth[@]}" -o "$tmp" "$api" 2>/dev/null; then
    err "failed to fetch latest release metadata for $repo (rate-limited or no release?)"
    rm -f "$tmp"
    return 1
  fi
  local tag
  tag="$(grep -m1 '"tag_name"' "$tmp" | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
  rm -f "$tmp"
  [[ -n "$tag" ]] && echo "$tag" || return 1
}

download_release_asset() {
  # $1 = owner/repo  $2 = tag  $3 = asset name  $4 = output path
  local repo="$1" tag="$2" asset="$3" out="$4" url
  if [[ "$tag" == "latest" ]]; then
    url="https://github.com/$repo/releases/latest/download/$asset"
  else
    url="https://github.com/$repo/releases/download/$tag/$asset"
  fi
  log "downloading $repo @ $tag asset=$asset"
  if ! curl -fsSL -o "$out" "$url"; then
    err "download failed: $url"
    return 1
  fi
  # Guard against HTML error pages (e.g. 404) being saved as the "binary".
  if [[ ! -s "$out" ]] || head -c 15 "$out" | grep -qi '<!doctype\|<html'; then
    err "downloaded asset is empty or an HTML error page: $asset"
    return 1
  fi
  chmod +x "$out"
}

fetch_release_binaries() {
  detect_arch
  local dir="${E2E_BIN_DIR:-$(mktemp -d /tmp/tlsvpn-e2e.XXXXXX)}"
  mkdir -p "$dir"

  local go_tag="$E2E_GO_TAG" rs_tag="$E2E_RS_TAG"
  if [[ "$go_tag" == "latest" ]]; then
    go_tag="$(fetch_latest_tag "$E2E_GO_REPO")" || fail "could not resolve latest Go tag"
  fi
  if [[ "$rs_tag" == "latest" ]]; then
    rs_tag="$(fetch_latest_tag "$E2E_RS_REPO")" || fail "could not resolve latest Rust tag"
  fi
  log "using Go release tag=$go_tag  Rust release tag=$rs_tag"

  download_release_asset "$E2E_GO_REPO" "$go_tag" "tlsvpn_linux_${E2E_ARCH_GO}" "$dir/tlsvpn_go" \
    || fail "Go release asset missing: tlsvpn_linux_${E2E_ARCH_GO} @ $go_tag"
  download_release_asset "$E2E_RS_REPO" "$rs_tag" "tlsvpn-${E2E_ARCH_RS}-unknown-linux-musl" "$dir/tlsvpn_rs" \
    || fail "Rust release asset missing: tlsvpn-${E2E_ARCH_RS}-unknown-linux-musl @ $rs_tag"

  BIN_GO="$dir/tlsvpn_go"
  BIN_RS="$dir/tlsvpn_rs"
  ok "release binaries ready: $BIN_GO , $BIN_RS"
}

# ---------------------------------------------------------------------------
# Local build fallback
# ---------------------------------------------------------------------------
build_local_binaries() {
  local go_src="${E2E_GO_SRC:-$(pwd)}"
  local rs_src="${E2E_RS_SRC:-../tlsvpn-rs}"
  local dir="${E2E_BIN_DIR:-$(mktemp -d /tmp/tlsvpn-e2e.XXXXXX)}"
  mkdir -p "$dir"

  log "building Go binary from $go_src"
  ( cd "$go_src" && go build -o "$dir/tlsvpn_go" . )

  log "building Rust binary from $rs_src"
  ( cd "$rs_src" && cargo build --release && cp target/release/tlsvpn "$dir/tlsvpn_rs" )

  BIN_GO="$dir/tlsvpn_go"
  BIN_RS="$dir/tlsvpn_rs"
  ok "local binaries ready: $BIN_GO , $BIN_RS"
}

# ---------------------------------------------------------------------------
# Binary resolver — picks release or local based on E2E_USE_RELEASE
# ---------------------------------------------------------------------------
resolve_binaries() {
  if [[ "$E2E_USE_RELEASE" == "1" ]]; then
    fetch_release_binaries
  else
    build_local_binaries
  fi
}

# ---------------------------------------------------------------------------
# Test environment
# ---------------------------------------------------------------------------
TEST_DIR=""
setup_test_env() {
  TEST_DIR="$(mktemp -d /tmp/tlsvpn-test.XXXXXX)"
  LOG_GO_SRV="$TEST_DIR/go_srv.log"
  LOG_RS_SRV="$TEST_DIR/rs_srv.log"
  LOG_CLI="$TEST_DIR/cli.log"
  LOG_SOCKS="$TEST_DIR/socks.log"
  # A TUN device index per test; tests that need TUN must run privileged.
  TUN_DEV="${TUN_DEV:-tun0}"
  ok "test env: $TEST_DIR"
}

cleanup_test_env() {
  [[ -n "${TEST_DIR:-}" && -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
}

# Wait until a TCP port is accepting connections (poll up to $2 seconds).
wait_for_port() {
  local host="$1" port="$2" deadline=$(( $(date +%s) + ${3:-15} ))
  while ! (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; do
    [[ $(date +%s) -lt $deadline ]] || return 1
    sleep 0.3
  done
  exec 3>&- 2>/dev/null || true
  return 0
}

# Run a single control group; expects run_group_<name>() to be defined by caller.
run_group() {
  local name="$1"
  log "=== control group: $name ==="
  if "run_group_$name"; then
    ok "group $name passed"
    return 0
  else
    err "group $name FAILED"
    return 1
  fi
}
