#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OPENWRT_VERSION="${OPENWRT_VERSION:-25.12.5}"
OPENWRT_TARGET="${OPENWRT_TARGET:-x86}"
OPENWRT_SUBTARGET="${OPENWRT_SUBTARGET:-64}"
OPENWRT_FEED_OUTPUT_DIR="${OPENWRT_FEED_OUTPUT_DIR:-$ROOT_DIR/bin/openwrt-customfeed}"
OPENWRT_WORK_DIR="${OPENWRT_WORK_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/tlsvpn-openwrt-customfeed/$OPENWRT_VERSION-$OPENWRT_TARGET-$OPENWRT_SUBTARGET}"
OPENWRT_FEED_SIGNING_KEY_FILE="${OPENWRT_FEED_SIGNING_KEY_FILE:-}"
OPENWRT_FEED_PUBLIC_KEY_FILE="${OPENWRT_FEED_PUBLIC_KEY_FILE:-}"
TLSVPN_SOURCE_VERSION="${TLSVPN_SOURCE_VERSION:-$(git rev-parse HEAD)}"
TLSVPN_PKG_VERSION="${TLSVPN_PKG_VERSION:-$(git describe --tags --long --always 2>/dev/null || true)}"
JOBS="${JOBS:-2}"

# On pull_request workflows GitHub checks out refs/pull/<n>/merge and github.sha
# points at that synthetic merge commit. OpenWrt's GitHub source downloader and
# fallback clone cannot fetch that SHA through normal repository refs. When the
# requested source SHA is exactly the checked-out merge commit, use its second
# parent instead: that is the real PR head commit and is fetchable from GitHub.
if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" ]]; then
  checkout_sha="$(git rev-parse HEAD)"
  if [[ "$TLSVPN_SOURCE_VERSION" == "$checkout_sha" ]]; then
    if pr_head_sha="$(git rev-parse HEAD^2 2>/dev/null)" && [[ -n "$pr_head_sha" ]]; then
      printf 'Pull request merge SHA %s is not a stable source ref; using PR head %s\n' \
        "$TLSVPN_SOURCE_VERSION" "$pr_head_sha"
      TLSVPN_SOURCE_VERSION="$pr_head_sha"
    fi
  fi
fi

[[ -n "$OPENWRT_FEED_SIGNING_KEY_FILE" ]] || {
  echo "error: OPENWRT_FEED_SIGNING_KEY_FILE is required" >&2
  exit 2
}
[[ -s "$OPENWRT_FEED_SIGNING_KEY_FILE" ]] || {
  echo "error: signing key not found: $OPENWRT_FEED_SIGNING_KEY_FILE" >&2
  exit 2
}
[[ -n "$OPENWRT_FEED_PUBLIC_KEY_FILE" ]] || {
  echo "error: OPENWRT_FEED_PUBLIC_KEY_FILE is required" >&2
  exit 2
}
[[ -s "$OPENWRT_FEED_PUBLIC_KEY_FILE" ]] || {
  echo "error: public key not found: $OPENWRT_FEED_PUBLIC_KEY_FILE" >&2
  exit 2
}

case "$OPENWRT_VERSION" in
  25.12*|SNAPSHOT) ;;
  *) echo "error: custom APK feeds require OpenWrt 25.12+" >&2; exit 2 ;;
esac

# Build through the existing SDK path, but assemble the repository from the
# SDK's canonical APK filenames. Release assets intentionally carry additional
# target suffixes and are not valid repository package filenames.
OPENWRT_INCLUDE_ARCH_INDEPENDENT=1 \
OPENWRT_WORK_DIR="$OPENWRT_WORK_DIR" \
OPENWRT_OUTPUT_DIR="$ROOT_DIR/bin/openwrt-customfeed-release/$OPENWRT_TARGET-$OPENWRT_SUBTARGET" \
OPENWRT_VERSION="$OPENWRT_VERSION" \
OPENWRT_TARGET="$OPENWRT_TARGET" \
OPENWRT_SUBTARGET="$OPENWRT_SUBTARGET" \
JOBS="$JOBS" \
TLSVPN_SOURCE_VERSION="$TLSVPN_SOURCE_VERSION" \
TLSVPN_PKG_VERSION="$TLSVPN_PKG_VERSION" \
  "$ROOT_DIR/scripts/build_openwrt_apk.sh"

SDK_DIR="$OPENWRT_WORK_DIR/sdk"
APK_TOOL="$SDK_DIR/staging_dir/host/bin/apk"
OPENSSL_TOOL="$SDK_DIR/staging_dir/host/bin/openssl"
[[ -x "$APK_TOOL" ]] || { echo "error: SDK apk host tool missing: $APK_TOOL" >&2; exit 1; }
[[ -x "$OPENSSL_TOOL" ]] || { echo "error: SDK openssl host tool missing: $OPENSSL_TOOL" >&2; exit 1; }

FEED_DIR="$OPENWRT_FEED_OUTPUT_DIR/releases/$OPENWRT_VERSION/$OPENWRT_TARGET/$OPENWRT_SUBTARGET"
rm -rf "$FEED_DIR"
mkdir -p "$FEED_DIR"

main_count=0
package_count=0
while IFS= read -r apk; do
  base="$(basename "$apk")"
  case "$base" in
    tlsvpn-proto-*.apk|luci-proto-tlsvpn-*.apk|luci-i18n-tlsvpn-*.apk)
      ;;
    tlsvpn-*.apk)
      main_count=$((main_count + 1))
      ;;
    *)
      continue
      ;;
  esac

  dest="$FEED_DIR/$base"
  if [[ -e "$dest" ]]; then
    cmp -s "$apk" "$dest" || {
      echo "error: conflicting APKs with the same canonical filename: $base" >&2
      exit 1
    }
    continue
  fi
  cp -f "$apk" "$dest"
  package_count=$((package_count + 1))
done < <(find "$SDK_DIR/bin" -type f -name '*.apk' | sort)

[[ "$main_count" -ge 1 ]] || { echo "error: canonical tlsvpn APK was not found" >&2; exit 1; }
[[ "$package_count" -ge 4 ]] || { echo "error: custom feed package set is incomplete ($package_count APKs)" >&2; exit 1; }

# Canonicalize both keys with the SDK OpenSSL build and prove that the public
# key configured for clients belongs to the private key used to sign the feed.
# The configured public key, never a separately derived trust root, is what gets
# published as tlsvpn-feed.pem.
chmod 600 "$OPENWRT_FEED_SIGNING_KEY_FILE"
"$OPENSSL_TOOL" pkey -in "$OPENWRT_FEED_SIGNING_KEY_FILE" -check -noout >/dev/null 2>&1
canonical_private_public="$OPENWRT_WORK_DIR/signing-key-derived-public.pem"
"$OPENSSL_TOOL" pkey -in "$OPENWRT_FEED_SIGNING_KEY_FILE" -pubout > "$canonical_private_public" 2>/dev/null
"$OPENSSL_TOOL" pkey -pubin -in "$OPENWRT_FEED_PUBLIC_KEY_FILE" -pubout > "$FEED_DIR/tlsvpn-feed.pem" 2>/dev/null
cmp -s "$canonical_private_public" "$FEED_DIR/tlsvpn-feed.pem" || {
  echo "error: configured OpenWrt feed public key does not match the signing private key" >&2
  exit 1
}

(
  cd "$FEED_DIR"
  "$APK_TOOL" mkndx \
    --root "$SDK_DIR" \
    --keys-dir "$SDK_DIR" \
    --allow-untrusted \
    --sign "$OPENWRT_FEED_SIGNING_KEY_FILE" \
    --output packages.adb \
    ./*.apk

  # Ensure apk v3 can decode the generated repository and retain a JSON form
  # for diagnostics without making clients depend on it.
  "$APK_TOOL" adbdump --format json packages.adb > index.json
)

# Verify the signed repository using only the configured public key that clients
# receive. This catches a wrong Actions Variable before anything can publish.
VERIFY_ROOT="$OPENWRT_WORK_DIR/feed-verify-root"
rm -rf "$VERIFY_ROOT"
mkdir -p "$VERIFY_ROOT/etc/apk/keys"
cp "$FEED_DIR/tlsvpn-feed.pem" "$VERIFY_ROOT/etc/apk/keys/tlsvpn-feed.pem"
"$APK_TOOL" \
  --root "$VERIFY_ROOT" \
  --keys-dir etc/apk/keys \
  verify "$FEED_DIR/packages.adb"
rm -rf "$VERIFY_ROOT"

cat > "$FEED_DIR/feed-info.json" <<EOF
{
  "repository": "NNdroid/tlsvpn",
  "openwrt_version": "$OPENWRT_VERSION",
  "target": "$OPENWRT_TARGET",
  "subtarget": "$OPENWRT_SUBTARGET",
  "source_commit": "$TLSVPN_SOURCE_VERSION",
  "source_version": "$TLSVPN_PKG_VERSION",
  "package_count": $package_count
}
EOF

(
  cd "$FEED_DIR"
  sha256sum ./*.apk packages.adb index.json tlsvpn-feed.pem feed-info.json > SHA256SUMS
)

printf 'Custom feed ready: %s\n' "$FEED_DIR"
printf 'Repository index: %s/packages.adb\n' "$FEED_DIR"
find "$FEED_DIR" -maxdepth 1 -type f -printf '%f\n' | sort
