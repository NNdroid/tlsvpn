#!/usr/bin/env bash
# run_all_tests.sh — full test orchestration for tlsvpn interop.
#
# Layers:
#   L1  Go unit tests        ( go test -v ./... )                [this repo]
#   L1  Rust unit tests      ( cargo test --verbose )            [tlsvpn-rs]
#   L2  Protocol conformance golden vectors (shared JSON contract)
#   L3  End-to-end control groups (self-self + cross-language + socks5)
#
# Usage:
#   E2E_GO_SRC=/path/to/tlsvpn E2E_RS_SRC=/path/to/tlsvpn-rs ./scripts/run_all_tests.sh
#
# In CI both E2E_*_SRC default to the checked-out workspace; e2e binary sourcing
# defaults to GitHub releases (see lib_e2e.sh).
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GO_SRC="${E2E_GO_SRC:-$REPO_ROOT}"
RS_SRC="${E2E_RS_SRC:-${REPO_ROOT}/../tlsvpn-rs}"

export E2E_GO_SRC="$GO_SRC"
export E2E_RS_SRC="$RS_SRC"

TOTAL=0
FAILED=0

run_step() {
  local name="$1"; shift
  echo "=================================================================="
  echo ">>> STEP: $name"
  echo "=================================================================="
  TOTAL=$((TOTAL+1))
  if "$@"; then
    echo ">>> STEP OK: $name"
  else
    echo ">>> STEP FAILED: $name" >&2
    FAILED=$((FAILED+1))
  fi
}

# L1 — Go unit tests (this repo).
run_step "go-unit" bash -c "cd '$GO_SRC' && go test -v ./..."

# L1 — Rust unit tests.
if [[ -d "$RS_SRC" ]]; then
  run_step "rust-unit" bash -c "cd '$RS_SRC' && cargo test --verbose"
else
  echo ">>> SKIP rust-unit: $RS_SRC not found"
fi

# L2 — Protocol conformance (golden vectors). Validates both impls agree on the
# shared contract. Go side generates/verifies; Rust side verifies the same file.
run_step "go-conformance" bash -c "cd '$GO_SRC' && go test -v -run 'TestProtocol|TestGenerateGoldenVectors' ./..."
if [[ -d "$RS_SRC" ]]; then
  run_step "rust-conformance" bash -c "cd '$RS_SRC' && TLSVPN_GOLDEN='$GO_SRC/testdata/protocol_golden.json' cargo test --verbose --test protocol_conformance"
fi

# L3 — End-to-end control groups (release binaries in CI / local build fallback).
run_step "e2e" bash -c "cd '$GO_SRC' && bash '$SCRIPT_DIR/e2e_test.sh'"

echo "=================================================================="
echo ">>> TOTAL STEPS: $TOTAL   FAILED: $FAILED"
echo "=================================================================="
[[ "$FAILED" -eq 0 ]]
