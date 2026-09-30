#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

script="scripts/build_openwrt_customfeed.sh"
workflow=".github/workflows/openwrt_customfeed.yml"
doc="docs/openwrt-customfeed.md"

bash -n "$script"

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
grep -Fq '"$OPENSSL_TOOL" ec -in "$OPENWRT_FEED_SIGNING_KEY_FILE" -check -noout' "$script"
grep -Fq '"$OPENSSL_TOOL" ec -pubin -in "$OPENWRT_FEED_PUBLIC_KEY_FILE" -pubout' "$script"
if grep -Fq '"$OPENSSL_TOOL" pkey' "$script"; then
  echo 'SDK OpenSSL must use the EC command supported by the OpenWrt build path' >&2
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
grep -Fq 'OPENWRT_FEED_PUBLIC_KEY_B64 does not match OPENWRT_FEED_SIGNING_KEY_B64.' "$workflow"
grep -Fq 'feed public key differs from OPENWRT_FEED_PUBLIC_KEY_B64' "$workflow"
grep -Fq 'OPENWRT_FEED_PUBLIC_KEY_FILE: ${{ steps.signing.outputs.public_key_file }}' "$workflow"
grep -Fq 'rm -f "${{ steps.signing.outputs.key_file }}"' "$workflow"
grep -Fq 'rm -f "${{ steps.signing.outputs.public_key_file }}"' "$workflow"
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
