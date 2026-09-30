# OpenWrt 25.12 custom APK feed

TLSVPN publishes an OpenWrt 25.12+ APK repository from the repository's `main` branch and release tags. The generated repository lives on the dedicated `openwrt-feed` branch; it is not stored in `main` and it does not replace the normal GitHub Release APK artifacts.

## Publication model

The production flow is:

```text
main / v* tag
    -> GitHub Actions build + validation
    -> signed APK repository payload
    -> generated openwrt-feed branch
    -> raw.githubusercontent.com repository URL
    -> OpenWrt /etc/apk/repositories.d/customfeeds.list
```

Pull requests targeting `main` build and validate the complete feed matrix but never publish. A push to `main`, a `v*` tag, or a manual workflow dispatch with `publish=true` can publish after all target builds succeed. Production publication requires the stable signing secret `OPENWRT_FEED_SIGNING_KEY_B64` and the stable public-key Actions Variable `OPENWRT_FEED_PUBLIC_KEY_B64`.

The generated `openwrt-feed` branch is machine-owned. Do not edit it by hand.

## Repository layout

The generated branch uses this layout:

```text
openwrt-feed/
├── tlsvpn-feed.pem
└── releases/
    └── 25.12.5/
        ├── x86/64/
        │   ├── packages.adb
        │   ├── index.json
        │   ├── tlsvpn-<version>.apk
        │   ├── tlsvpn-proto-<version>.apk
        │   ├── luci-proto-tlsvpn-<version>.apk
        │   ├── luci-i18n-tlsvpn-*.apk
        │   ├── SHA256SUMS
        │   └── feed-info.json
        ├── armsr/armv8/
        ├── armsr/armv7/
        ├── rockchip/armv8/
        ├── mediatek/filogic/
        ├── ramips/mt7621/
        └── ath79/generic/
```

For x86/64 the repository database URL is:

```text
https://raw.githubusercontent.com/NNdroid/tlsvpn/openwrt-feed/releases/25.12.5/x86/64/packages.adb
```

Each OpenWrt version directory is replaced atomically by the publisher when that version is rebuilt. Older OpenWrt version directories are preserved, while stale APK versions inside the currently published OpenWrt version are removed.

## Why canonical SDK package names are required

The normal Release workflow renames APK assets to append the OpenWrt release and target/subtarget, for example:

```text
tlsvpn-1.0.20260928-r1-openwrt-25.12.5-x86-64.apk
```

That is useful for human downloads but is not the canonical repository package filename expected by apk. The custom-feed builder therefore reuses the existing OpenWrt SDK build and copies the original package files from `sdk/bin/` before creating `packages.adb`.

For non-tagged `main` builds the workflow derives the source version with `git describe --tags --long --always`. This lets the existing APK version normalizer produce post-release versions such as `_pN` instead of falling back to a lower `0.0.*` version after a release tag.

## Stable repository signing key

A production feed must use one stable signing key pair. The private key must never be committed to Git, uploaded as an artifact, or stored in GitHub Actions Variables. The public key is not secret and is intentionally stored as an Actions Variable so the workflow has an explicit, stable client trust root.

Generate an EC P-256 private key once:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out tlsvpn-openwrt-feed-key.pem
```

Derive the matching public key:

```sh
openssl pkey -in tlsvpn-openwrt-feed-key.pem -pubout -out tlsvpn-openwrt-feed-public.pem
```

Encode the private key:

```sh
base64 -w0 tlsvpn-openwrt-feed-key.pem
```

Store the result as a GitHub Actions **Secret** named:

```text
OPENWRT_FEED_SIGNING_KEY_B64
```

Encode the public key:

```sh
base64 -w0 tlsvpn-openwrt-feed-public.pem
```

Store that result as a GitHub Actions **Variable** named:

```text
OPENWRT_FEED_PUBLIC_KEY_B64
```

For production builds the workflow decodes both values and verifies with OpenSSL that `OPENWRT_FEED_PUBLIC_KEY_B64` belongs to `OPENWRT_FEED_SIGNING_KEY_B64`. A mismatch is a hard failure. The configured public key is then used as `tlsvpn-feed.pem` and is also used to verify the generated `packages.adb` before publication.

Pull-request jobs never receive the production private key. They generate an ephemeral EC private/public key pair only to validate the repository-generation and signature-verification path. `main`, tag, and explicit production publication fail instead of publishing if either stable key setting is missing or if the configured key pair does not match.

## OpenWrt client configuration

OpenWrt 25.12 and newer uses apk. Repository database URLs are read from `/etc/apk/repositories.d/`, and custom feeds belong in `/etc/apk/repositories.d/customfeeds.list`.

The target/subtarget is available as `DISTRIB_TARGET` in `/etc/openwrt_release`, so one setup sequence works for all supported targets:

```sh
. /etc/openwrt_release

TLSVPN_FEED_VERSION="25.12.5"
TLSVPN_FEED_BASE="https://raw.githubusercontent.com/NNdroid/tlsvpn/openwrt-feed"

wget -O /etc/apk/keys/tlsvpn-feed.pem \
  "$TLSVPN_FEED_BASE/tlsvpn-feed.pem"

feed_url="$TLSVPN_FEED_BASE/releases/$TLSVPN_FEED_VERSION/$DISTRIB_TARGET/packages.adb"
mkdir -p /etc/apk/repositories.d

tmp="$(mktemp)"
grep -Fvx "$feed_url" /etc/apk/repositories.d/customfeeds.list 2>/dev/null > "$tmp" || true
printf '%s\n' "$feed_url" >> "$tmp"
mv "$tmp" /etc/apk/repositories.d/customfeeds.list

apk update
apk add tlsvpn tlsvpn-proto luci-proto-tlsvpn
```

For x86/64 the resulting entry is:

```text
https://raw.githubusercontent.com/NNdroid/tlsvpn/openwrt-feed/releases/25.12.5/x86/64/packages.adb
```

The public key can be retained explicitly over sysupgrade:

```sh
mkdir -p /lib/upgrade/keep.d
printf '%s\n' /etc/apk/keys/tlsvpn-feed.pem > /lib/upgrade/keep.d/tlsvpn-feed
```

Install and update TLSVPN by package name from the repository rather than by downloading an individual APK. Do not use a blanket `apk upgrade` for the entire OpenWrt system; update the TLSVPN packages explicitly when needed.

## Workflow behavior

`.github/workflows/openwrt_customfeed.yml` behaves as follows:

1. Pull requests to `main` run the contract test and build every supported target with an ephemeral key pair. They never receive the production private key and never publish.
2. Pushes to `main` build every target and publish/update `openwrt-feed`. A missing stable signing secret or public-key variable is an error.
3. `v*` tag pushes also publish the feed with the stable configured key pair.
4. `workflow_dispatch` always supports validation; setting `publish=true` turns it into a production publication and requires the stable configured key pair.
5. Before production publication the workflow verifies that all target feeds contain the public key from `OPENWRT_FEED_PUBLIC_KEY_B64`.
6. The publish job is serialized with the `openwrt-feed-publish` concurrency group so concurrent runs cannot race when updating the generated branch.
7. Existing GitHub Release assets and `build_and_release.yml` remain independent and unchanged.
