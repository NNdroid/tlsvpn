#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

script="scripts/build_openwrt_customfeed.sh"
key_script="scripts/prepare_openwrt_feed_keys.sh"
workflow=".github/workflows/openwrt_customfeed.yml"
doc="docs/openwrt-customfeed.md"

bash -n "$script"
bash -n "$key_script"

# Repository construction and signature verification.
grep -Fq 'OPENWRT_FEED_SIGNING_KEY_FILE' "$script"
grep -Fq 'OPENWRT_FEED_PUBLIC_KEY_FILE' "$script"
grep -Fq 'configured OpenWrt feed public key does not match the signing private key' "$script"
grep -Fq 'OPENWRT_INCLUDE_ARCH_INDEPENDENT=1' "$script"
grep -Fq 'staging_dir/host/bin/apk' "$script"
grep -Fq 'mkndx' "$script"
grep -Fq -- '--sign "$OPENWRT_FEED_SIGNING_KEY_FILE"' "$script"
grep -Fq 'adbdump --format json packages.adb' "$script"
grep -Fq 'verify "$FEED_DIR/packages.adb"' "$script"
grep -Fq 'tlsvpn-feed.pem' "$script"
grep -Fq 'find "$SDK_DIR/bin" -type f -name' "$script"
grep -Fq 'conflicting APKs with the same canonical filename' "$script"
grep -Fq 'git describe --tags --long --always' "$script"
grep -Fq 'trap fail_with_context ERR' "$script"
grep -Fq 'stage=%s line=%s exit=%s command=%q' "$script"
grep -Fq 'set_stage validate-signing-keys' "$script"
grep -Fq 'derived_public_key_sha256=' "$script"
grep -Fq '"$OPENSSL_TOOL" ec -in "$OPENWRT_FEED_SIGNING_KEY_FILE" -pubout' "$script"
grep -Fq '"$OPENSSL_TOOL" ec -pubin -in "$OPENWRT_FEED_PUBLIC_KEY_FILE" -pubout' "$script"
if grep -Fq '"$OPENSSL_TOOL" pkey' "$script"; then
  echo 'SDK OpenSSL must use the EC command supported by the OpenWrt build path' >&2
  exit 1
fi
if grep -Eq '"\$OPENSSL_TOOL" ec .* -check([[:space:]]|$)' "$script"; then
  echo 'SDK LibreSSL EC command does not support the OpenSSL-only -check flag' >&2
  exit 1
fi

# GitHub pull_request jobs are checked out at refs/pull/<n>/merge. That
# synthetic github.sha cannot be fetched by the OpenWrt GitHub downloader, so
# the builder must normalize it to the merge commit's second parent (PR head).
grep -Fq 'GITHUB_EVENT_NAME:-' "$script"
grep -Fq 'git rev-parse HEAD^2' "$script"
grep -Fq 'TLSVPN_SOURCE_VERSION="$pr_head_sha"' "$script"
grep -Fq 'Pull request merge SHA' "$script"

# The feed must be assembled from canonical SDK outputs, not renamed GitHub
# Release assets that include target suffixes.
if grep -Fq 'release-assets' "$script"; then
  echo 'custom feed builder must not use renamed GitHub Release assets' >&2
  exit 1
fi

# Production publication comes from main/tags/manual dispatch. Pull requests
# validate the whole feed matrix but cannot publish.
grep -Fq 'pull_request:' "$workflow"
grep -Fq -- '- main' "$workflow"
grep -Fq 'tags:' "$workflow"
grep -Fq -- "- 'v*'" "$workflow"
grep -Fq "github.event_name != 'pull_request'" "$workflow"
grep -Fq "github.ref == 'refs/heads/main'" "$workflow"
if grep -Fq 'feature/openwrt-customfeed' "$workflow"; then
  echo 'production workflow must not depend on the old feature branch' >&2
  exit 1
fi

# Stable private key material must only come from Actions Secrets. The public
# trust root is deliberately stored in an Actions Variable and must be checked
# against the private key before any production feed can publish.
grep -Fq 'secrets.OPENWRT_FEED_SIGNING_KEY_B64' "$workflow"
grep -Fq 'vars.OPENWRT_FEED_PUBLIC_KEY_B64' "$workflow"
grep -Fq "github.event_name != 'pull_request' && secrets.OPENWRT_FEED_SIGNING_KEY_B64" "$workflow"
if grep -Fq 'vars.OPENWRT_FEED_SIGNING_KEY' "$workflow" || \
   grep -Fq 'vars.OPENWRT_FEED_SIGNING_KEY_B64' "$workflow"; then
  echo 'feed signing private key must not come from Actions Variables' >&2
  exit 1
fi
grep -Fq 'using an ephemeral CI-only key pair' "$workflow"
grep -Fq 'OPENWRT_FEED_SIGNING_KEY_B64 is required for main/tag/manual publication.' "$workflow"
grep -Fq 'OPENWRT_FEED_PUBLIC_KEY_B64 Actions Variable is required for main/tag/manual publication.' "$workflow"
grep -Fq 'scripts/prepare_openwrt_feed_keys.sh pair "$key" "$public_key"' "$workflow"
grep -Fq 'scripts/prepare_openwrt_feed_keys.sh public "$expected"' "$workflow"
grep -Fq 'feed public key differs from OPENWRT_FEED_PUBLIC_KEY_B64' "$workflow"
grep -Fq 'OPENWRT_FEED_PUBLIC_KEY_FILE: ${{ steps.signing.outputs.public_key_file }}' "$workflow"
grep -Fq 'rm -f "$RUNNER_TEMP/tlsvpn-openwrt-feed-key.pem"' "$workflow"
grep -Fq 'rm -f "$RUNNER_TEMP/tlsvpn-openwrt-feed-public.pem"' "$workflow"
grep -Fq 'OpenWrt custom feed failure diagnostics' "$workflow"
grep -Fq 'builder_exit=' "$workflow"
grep -Fq 'missing SDK host tool:' "$workflow"

# openwrt-feed is a generated branch. Replacing only the selected OpenWrt
# version prevents stale package versions while preserving older releases.
grep -Fq 'HEAD:openwrt-feed' "$workflow"
grep -Fq 'rm -rf "releases/$OPENWRT_VERSION"' "$workflow"
grep -Fq 'raw.githubusercontent.com/${GITHUB_REPOSITORY}/openwrt-feed' "$workflow"
grep -Fq 'group: openwrt-feed-publish' "$workflow"

# Keep every supported OpenWrt target in the feed matrix.
for target in \
  'target: x86' \
  'target: armsr' \
  'target: rockchip' \
  'target: mediatek' \
  'target: ramips' \
  'target: ath79'; do
  grep -Fq "$target" "$workflow"
done

# Documentation must describe main as the production source and the persistent
# OpenWrt 25.12 customfeeds.list client configuration.
grep -Fq 'main' "$doc"
grep -Fq 'OPENWRT_FEED_PUBLIC_KEY_B64' "$doc"
grep -Fq '/etc/apk/repositories.d/customfeeds.list' "$doc"
grep -Fq 'openwrt-feed' "$doc"
if grep -Fq 'next push to `feature/openwrt-customfeed`' "$doc"; then
  echo 'documentation still describes the obsolete feature-branch publisher' >&2
  exit 1
fi

# Exercise the repository assembly and SDK-OpenSSL compatibility path without
# downloading a full SDK. The fake builder leaves canonical APKs and wrappers
# around the host OpenSSL plus a deterministic apk stub.
tmp="$(mktemp -d)"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

mock_builder="$tmp/mock-openwrt-builder.sh"
cat > "$mock_builder" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
sdk="${OPENWRT_WORK_DIR:?}/sdk"
mkdir -p "$sdk/staging_dir/host/bin" "$sdk/bin/packages/test/base"
for package in \
  tlsvpn-1.0-r1.apk \
  tlsvpn-proto-1.0-r1.apk \
  luci-proto-tlsvpn-1.0-r1.apk \
  luci-i18n-tlsvpn-zh-cn-1.0.apk; do
  printf 'mock-apk:%s\n' "$package" > "$sdk/bin/packages/test/base/$package"
done
cat > "$sdk/staging_dir/host/bin/openssl" <<'WRAPPER'
#!/usr/bin/env bash
if [[ "${1:-}" == 'pkey' ]]; then
  echo 'mock SDK OpenSSL intentionally has no pkey command' >&2
  exit 65
fi
for arg in "$@"; do
  if [[ "$arg" == '-check' ]]; then
    echo 'mock SDK LibreSSL intentionally has no ec -check flag' >&2
    exit 66
  fi
done
exec openssl "$@"
WRAPPER
cat > "$sdk/staging_dir/host/bin/apk" <<'WRAPPER'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == '--version' ]]; then
  echo 'apk-tools mock 3'
  exit 0
fi
if [[ "${1:-}" == 'mkndx' ]]; then
  if [[ "${MOCK_APK_FAIL_MKNDX:-0}" == '1' ]]; then
    echo 'synthetic mkndx failure for diagnostic regression test' >&2
    exit 17
  fi
  shift
  output=''
  while [[ "$#" -gt 0 ]]; do
    if [[ "$1" == '--output' ]]; then
      output="$2"
      shift 2
    else
      shift
    fi
  done
  [[ -n "$output" ]]
  printf 'mock-signed-index\n' > "$output"
  exit 0
fi
if [[ "${1:-}" == 'adbdump' ]]; then
  printf '[{"name":"tlsvpn"}]\n'
  exit 0
fi
for arg in "$@"; do
  [[ "$arg" == 'verify' ]] && exit 0
done
echo "unexpected mock apk invocation: $*" >&2
exit 64
WRAPPER
chmod +x "$sdk/staging_dir/host/bin/openssl" "$sdk/staging_dir/host/bin/apk"
EOF
chmod +x "$mock_builder"

private_key="$tmp/feed-private.pem"
public_key="$tmp/feed-public.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$private_key"
openssl ec -in "$private_key" -pubout -out "$public_key" 2>/dev/null

# Exercise the production secret importer with the documented encoding, raw
# PEM recovery, one accidental extra Base64 layer, and actionable rejection of
# a public key placed in the private-key secret.
private_b64="$(base64 < "$private_key" | tr -d '\r\n')"
public_b64="$(base64 < "$public_key" | tr -d '\r\n')"
imported_private="$tmp/imported-private.pem"
imported_public="$tmp/imported-public.pem"
OPENWRT_FEED_SIGNING_KEY_B64="$private_b64" \
OPENWRT_FEED_PUBLIC_KEY_B64="$public_b64" \
  bash "$key_script" pair "$imported_private" "$imported_public" > "$tmp/key-import.log"
openssl ec -in "$imported_private" -check -noout >/dev/null 2>&1
cmp -s "$public_key" "$imported_public"
grep -Fq 'curve=prime256v1 pair_match=true' "$tmp/key-import.log"

OPENWRT_FEED_SIGNING_KEY_B64="$(base64 < "$private_key" | base64 | tr -d '\r\n')" \
OPENWRT_FEED_PUBLIC_KEY_B64="$(< "$public_key")" \
  bash "$key_script" pair "$tmp/double-private.pem" "$tmp/raw-public.pem" > "$tmp/key-import-recovery.log"
grep -Fq 'encoding=double-base64' "$tmp/key-import-recovery.log"
grep -Fq 'encoding=raw-pem' "$tmp/key-import-recovery.log"

pkcs8_key="$tmp/feed-private-pkcs8.pem"
openssl pkcs8 -topk8 -nocrypt -in "$private_key" -out "$pkcs8_key"
OPENWRT_FEED_SIGNING_KEY_B64="$(base64 < "$pkcs8_key" | tr -d '\r\n')" \
OPENWRT_FEED_PUBLIC_KEY_B64="$public_b64" \
  bash "$key_script" pair "$tmp/pkcs8-private.pem" "$tmp/pkcs8-public.pem" > "$tmp/key-import-pkcs8.log"
grep -Fq 'pem_label=PRIVATE KEY' "$tmp/key-import-pkcs8.log"
grep -Fq 'curve=prime256v1 pair_match=true' "$tmp/key-import-pkcs8.log"

private_der="$tmp/feed-private.der"
public_der="$tmp/feed-public.der"
openssl pkey -in "$private_key" -outform DER -out "$private_der"
openssl pkey -pubin -in "$public_key" -outform DER -out "$public_der"
OPENWRT_FEED_SIGNING_KEY_B64="$(base64 < "$private_der" | tr -d '\r\n')" \
OPENWRT_FEED_PUBLIC_KEY_B64="$(base64 < "$public_der" | tr -d '\r\n')" \
  bash "$key_script" pair "$tmp/der-private.pem" "$tmp/der-public.pem" > "$tmp/key-import-der.log"
grep -Fq 'pem_label=none' "$tmp/key-import-der.log"
grep -Fq 'private_key_format=DER normalized=PEM' "$tmp/key-import-der.log"
grep -Fq 'public_key_format=DER normalized=PEM' "$tmp/key-import-der.log"
grep -Fq 'curve=prime256v1 pair_match=true' "$tmp/key-import-der.log"

OPENWRT_FEED_SIGNING_KEY_B64="$(base64 < "$private_der" | base64 | tr -d '\r\n')" \
OPENWRT_FEED_PUBLIC_KEY_B64="$(base64 < "$public_der" | base64 | tr -d '\r\n')" \
  bash "$key_script" pair "$tmp/double-der-private.pem" "$tmp/double-der-public.pem" > "$tmp/key-import-double-der.log"
grep -Fq 'encoding=double-base64 pem_label=none' "$tmp/key-import-double-der.log"
grep -Fq 'private_key_format=DER normalized=PEM' "$tmp/key-import-double-der.log"
grep -Fq 'public_key_format=DER normalized=PEM' "$tmp/key-import-double-der.log"
grep -Fq 'curve=prime256v1 pair_match=true' "$tmp/key-import-double-der.log"

set +e
OPENWRT_FEED_SIGNING_KEY_B64="$public_b64" \
OPENWRT_FEED_PUBLIC_KEY_B64="$public_b64" \
  bash "$key_script" pair "$tmp/wrong-private.pem" "$tmp/wrong-public.pem" > "$tmp/key-import-failure.log" 2>&1
key_import_status=$?
set -e
[[ "$key_import_status" -ne 0 ]]
grep -Fq 'contains a public key' "$tmp/key-import-failure.log"
test ! -e "$tmp/wrong-private.pem"

other_private="$tmp/other-private.pem"
other_public="$tmp/other-public.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$other_private"
openssl ec -in "$other_private" -pubout -out "$other_public" 2>/dev/null
set +e
OPENWRT_FEED_SIGNING_KEY_B64="$private_b64" \
OPENWRT_FEED_PUBLIC_KEY_B64="$(base64 < "$other_public" | tr -d '\r\n')" \
  bash "$key_script" pair "$tmp/mismatch-private.pem" "$tmp/mismatch-public.pem" > "$tmp/key-import-mismatch.log" 2>&1
key_mismatch_status=$?
set -e
[[ "$key_mismatch_status" -ne 0 ]]
grep -Fq 'does not match OPENWRT_FEED_SIGNING_KEY_B64' "$tmp/key-import-mismatch.log"
test ! -e "$tmp/mismatch-private.pem"

mock_log="$tmp/customfeed.log"
OPENWRT_APK_BUILD_SCRIPT="$mock_builder" \
OPENWRT_WORK_DIR="$tmp/work" \
OPENWRT_FEED_OUTPUT_DIR="$tmp/output" \
OPENWRT_FEED_SIGNING_KEY_FILE="$private_key" \
OPENWRT_FEED_PUBLIC_KEY_FILE="$public_key" \
TLSVPN_SOURCE_VERSION="$(git rev-parse HEAD)" \
TLSVPN_PKG_VERSION='1.0.0-1-gabcdef0' \
  bash "$script" > "$mock_log" 2>&1

mock_feed="$tmp/output/releases/25.12.5/x86/64"
test -s "$mock_feed/packages.adb"
test -s "$mock_feed/index.json"
test -s "$mock_feed/tlsvpn-feed.pem"
test -s "$mock_feed/SHA256SUMS"
grep -Fq 'stage=validate-signing-keys' "$mock_log"
grep -Fq 'derived_public_key_sha256=' "$mock_log"
grep -Fq 'stage=complete' "$mock_log"

failure_log="$tmp/customfeed-failure.log"
set +e
MOCK_APK_FAIL_MKNDX=1 \
OPENWRT_APK_BUILD_SCRIPT="$mock_builder" \
OPENWRT_WORK_DIR="$tmp/failure-work" \
OPENWRT_FEED_OUTPUT_DIR="$tmp/failure-output" \
OPENWRT_FEED_SIGNING_KEY_FILE="$private_key" \
OPENWRT_FEED_PUBLIC_KEY_FILE="$public_key" \
TLSVPN_SOURCE_VERSION="$(git rev-parse HEAD)" \
TLSVPN_PKG_VERSION='1.0.0-1-gabcdef0' \
  bash "$script" > "$failure_log" 2>&1
failure_status=$?
set -e
[[ "$failure_status" -eq 17 ]]
grep -Fq 'synthetic mkndx failure for diagnostic regression test' "$failure_log"
grep -Fq 'stage=build-index' "$failure_log"
grep -Fq 'line=' "$failure_log"
grep -Fq 'exit=17' "$failure_log"
grep -Fq 'command=' "$failure_log"
grep -Fq 'error: context: version=25.12.5 target=x86/64' "$failure_log"

echo 'OpenWrt custom feed contract: OK'
