#!/usr/bin/env bash
# lib_e2e.sh — shared helpers for tlsvpn / tlsvpn-rs end-to-end tests.
#
# Binary sourcing strategy
# ------------------------
# Control groups build BOTH implementations from source and run those two
# freshly compiled binaries against each other. Pre-compiled release assets are
# never downloaded, so the test always exercises the code in the repositories
# rather than whatever happens to be published on GitHub.
#
#   E2E_GO_REPO/E2E_RS_REPO   owner/repo cloned when no local source is given
#                             (defaults: NNdroid/tlsvpn, NNdroid/tlsvpn-rs)
#   E2E_GO_REF/E2E_RS_REF     branch, tag or commit-ish; empty = the repo's
#                             default branch
#   E2E_GO_SRC/E2E_RS_SRC     existing checkout to build from instead of
#                             cloning. E2E_GO_SRC defaults to the repository
#                             containing this script, since this repo IS the Go
#                             implementation; E2E_RS_SRC must be set for a
#                             Rust checkout or else the Rust repo is cloned.
#   E2E_BIN_DIR               where the compiled binaries land
#                             (default: mktemp -d, removed on exit)
#
# Binaries are produced as:
#   Go : $E2E_BIN_DIR/tlsvpn_go
#   Rs : $E2E_BIN_DIR/tlsvpn_rs
#
# Requires: git, go, cargo, curl. Groups A-F need openssl as well (self-signed cert
# for the Rust server).
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (overridable via environment)
# ---------------------------------------------------------------------------
E2E_GO_REPO="${E2E_GO_REPO:-NNdroid/tlsvpn}"
E2E_RS_REPO="${E2E_RS_REPO:-NNdroid/tlsvpn-rs}"
E2E_GO_REF="${E2E_GO_REF:-}"
E2E_RS_REF="${E2E_RS_REF:-}"

# This repo is the Go implementation, so absent an override the Go source is
# resolved relative to this script instead of being re-cloned.
E2E_GO_SRC="${E2E_GO_SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
E2E_RS_SRC="${E2E_RS_SRC:-}"
E2E_BIN_DIR="${E2E_BIN_DIR:-}"

# Temp dirs this library creates and owns; removed by cleanup_test_env.
E2E_CLEANUP_DIRS=()

# git accepts POSIX paths ("E:/...") even on MSYS, so a user-supplied Windows
# path is left alone and only converted when it is not already a valid dir.
e2e_posix_dir() {
  local dir="$1"
  if [[ -d "$dir" ]]; then echo "$dir"; return; fi
  if command -v cygpath >/dev/null 2>&1; then cygpath -u "$dir"; else echo "$dir"; fi
}

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log()  { echo "[e2e] $*"; }
ok()   { echo "[e2e][ok] $*"; }
err()  { echo "[e2e][FAIL] $*" >&2; }
fail() { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Source acquisition — checkout both implementations, never download assets
# ---------------------------------------------------------------------------
clone_into() {
  # $1 = owner/repo  $2 = dest dir  $3 = ref ("" = default branch)
  local repo="$1" dest="$2" ref="$3"
  rm -rf "$dest"
  mkdir -p "$(dirname "$dest")"
  local -a branch=()
  [[ -n "$ref" ]] && branch=(--branch "$ref")
  log "cloning $repo${ref:+ @ $ref} -> $dest"
  if ! git clone --quiet --depth 1 "${branch[@]}" "https://github.com/$repo.git" "$dest" 2>/dev/null; then
    # Retry over ssh: private forks and ssh-only runners fail the https URL.
    log "https clone failed, retrying over ssh"
    git clone --quiet --depth 1 "${branch[@]}" "git@github.com:$repo.git" "$dest"
  fi
}

acquire_source() {
  # $1 = role (go|rs)  $2 = local source dir ("" = clone)  $3 = owner/repo  $4 = ref
  # Resolves the source into E2E_GO_SRC / E2E_RS_SRC and records any clone it
  # made for cleanup. Deliberately NOT called inside a command substitution:
  # array mutation would be lost in the subshell and the clone would leak.
  local role="$1" local_dir="$2" repo="$3" ref="$4" clone_dir
  if [[ -n "$local_dir" ]]; then
    local_dir="$(e2e_posix_dir "$local_dir")"
    [[ -d "$local_dir" ]] || fail "$role source dir does not exist: $local_dir"
    log "using $role source: $local_dir"
  else
    clone_dir="$(mktemp -d "${TMPDIR:-/tmp}/tlsvpn-e2e-src.XXXXXX")"
    clone_into "$repo" "$clone_dir/src" "$ref" || fail "could not clone $repo"
    E2E_CLEANUP_DIRS+=("$clone_dir")
    local_dir="$clone_dir/src"
  fi
  if [[ "$role" == "go" ]]; then
    E2E_GO_SRC="$local_dir"
  else
    E2E_RS_SRC="$local_dir"
  fi
}

# ---------------------------------------------------------------------------
# Build both implementations from source
# ---------------------------------------------------------------------------
resolve_binaries() {
  command -v git >/dev/null 2>&1 || fail "git is required to fetch sources"
  command -v go  >/dev/null 2>&1 || fail "go toolchain is required to build the Go binary"
  command -v cargo >/dev/null 2>&1 || fail "cargo is required to build the Rust binary"
  command -v curl >/dev/null 2>&1 || fail "curl is required to query client runtime state"

  acquire_source go "$E2E_GO_SRC" "$E2E_GO_REPO" "$E2E_GO_REF"
  acquire_source rs "$E2E_RS_SRC" "$E2E_RS_REPO" "$E2E_RS_REF"
  export E2E_GO_SRC E2E_RS_SRC

  local dir exe=""
  [[ "$(go env GOOS)" == "windows" ]] && exe=".exe"

  if [[ -n "$E2E_BIN_DIR" ]]; then
    dir="$E2E_BIN_DIR"
    [[ -d "$dir" ]] || mkdir -p "$dir"
  else
    dir="$(mktemp -d "${TMPDIR:-/tmp}/tlsvpn-e2e.XXXXXX")"
    E2E_CLEANUP_DIRS+=("$dir")
  fi
  export E2E_BIN_DIR="$dir"

  log "building Go binary from $E2E_GO_SRC"
  ( cd "$E2E_GO_SRC" && go build -o "$dir/tlsvpn_go$exe" . )

  log "building Rust binary from $E2E_RS_SRC"
  ( cd "$E2E_RS_SRC" && cargo build --release --quiet \
      && cp "target/release/tlsvpn$exe" "$dir/tlsvpn_rs$exe" )

  BIN_GO="$dir/tlsvpn_go$exe"
  BIN_RS="$dir/tlsvpn_rs$exe"
  ok "source-built binaries ready: $BIN_GO , $BIN_RS"
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

# Remove the temp test dir. Must always return 0: this runs from an EXIT trap,
# and a non-zero return there would override the script's real exit status
# (turning a fully passing run into a failed job).
cleanup_test_env() {
  # GitHub Actions uploads /tmp/tlsvpn-test.*/** after this script exits.
  # Preserve TEST_DIR on CI so failed client/server/config logs actually reach
  # the artifact step; hosted runners are disposable. Local runs still clean it.
  if [[ "${GITHUB_ACTIONS:-}" != "true" && -n "${TEST_DIR:-}" && -d "$TEST_DIR" ]]; then
    rm -rf "$TEST_DIR"
  fi
  # Also drop the source clones and build dir resolve_binaries created. An
  # `if` (not an `&&` list) so a vanished dir cannot trip set -e inside the
  # EXIT trap and mask the run's real status.
  for d in "${E2E_CLEANUP_DIRS[@]:-}"; do
    if [[ -n "$d" && -d "$d" ]]; then
      rm -rf "$d"
    fi
  done
  return 0
}

# Emit a filesystem path in a form a native process will actually find, JSON
# escaped. Git Bash translates POSIX paths only in command-line arguments, never
# inside file contents, so a config that names "/tmp/.../cert.pem" makes the
# Go/Rust binary look for that literal string on Windows. Convert to the native
# form (backslashes escaped for JSON) on MSYS, keep POSIX elsewhere.
json_path() {
  local p="$1"
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      command -v cygpath >/dev/null 2>&1 && p="$(cygpath -w "$p")"
      ;;
  esac
  printf '%s' "$p" | sed 's/\\/\\\\/g'
}

# Generate a self-signed cert into $1 (key) / $2 (cert), valid 2 days.
# On MSYS/Git Bash we must disable path conversion and pass Windows paths,
# otherwise `-subj /CN=...` is rewritten to a bogus filesystem path and openssl
# fails with a misleading "could not generate cert" error.
gen_e2e_cert() {
  local key="$1" crt="$2"
  if command -v cygpath >/dev/null 2>&1; then
    MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$(cygpath -w "$key")" -out "$(cygpath -w "$crt")" \
      -days 2 -subj "/CN=tlsvpn-e2e" >/dev/null 2>&1
  else
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$key" -out "$crt" -days 2 -subj "/CN=tlsvpn-e2e" >/dev/null 2>&1
  fi
}

# Generate a fresh random PSK and print it as 64 hex chars (256 bits). Server
# and client must hold the SAME secret: it seeds the handshake key material on
# both sides. Prefer openssl (already a hard requirement for the e2e cert),
# fall back to /dev/urandom so nothing extra has to be installed.
gen_e2e_psk() {
  local hex=""
  if command -v openssl >/dev/null 2>&1; then
    hex="$(MSYS_NO_PATHCONV=1 openssl rand -hex 32 2>/dev/null || true)"
  fi
  if ! [[ "$hex" =~ ^[0-9a-f]{64}$ ]]; then
    hex="$(od -An -tx1 -N32 /dev/urandom 2>/dev/null | tr -d ' \t\n')"
  fi
  if [[ ! "$hex" =~ ^[0-9a-f]{64}$ ]]; then
    err "could not generate a random PSK (need openssl or /dev/urandom)"
    return 1
  fi
  printf '%s' "$hex"
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
