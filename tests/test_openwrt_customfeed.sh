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

# Stable private key material must only come from Actions Secrets. Ephemeral
# keys are allowed for validation jobs, never for publication.
grep -Fq 'secrets.OPENWRT_FEED_SIGNING_KEY_B64' "$workflow"
if grep -Fq 'vars.OPENWRT_FEED_SIGNING_KEY' "$workflow" || \
   grep -Fq 'vars.OPENWRT_FEED_SIGNING_KEY_B64' "$workflow"; then
  echo 'feed signing private key must not come from Actions Variables' >&2
  exit 1
fi
grep -Fq 'using an ephemeral CI-only key' "$workflow"
grep -Fq 'OPENWRT_FEED_SIGNING_KEY_B64 is required for main/tag/manual publication.' "$workflow"
grep -Fq 'rm -f "${{ steps.signing.outputs.key_file }}"' "$workflow"

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
grep -Fq '/etc/apk/repositories.d/customfeeds.list' "$doc"
grep -Fq 'openwrt-feed' "$doc"
if grep -Fq 'next push to `feature/openwrt-customfeed`' "$doc"; then
  echo 'documentation still describes the obsolete feature-branch publisher' >&2
  exit 1
fi

echo 'OpenWrt custom feed contract: OK'
