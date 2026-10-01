# TLSVPN OpenWrt APK feed

This branch is generated automatically from the repository main branch and release tags. Do not edit it by hand.

OpenWrt release: 25.12.5

Feed layout:

`releases/25.12.5/<target>/<subtarget>/packages.adb`

Example for x86/64:

`https://raw.githubusercontent.com/NNdroid/tlsvpn/openwrt-feed/releases/25.12.5/x86/64/packages.adb`

Stable public key:

`https://raw.githubusercontent.com/NNdroid/tlsvpn/openwrt-feed/tlsvpn-feed.pem`

## Install on OpenWrt

The following commands detect the current OpenWrt release and target automatically, install the TLSVPN feed signing key, add the matching APK repository, refresh the package index, and install the TLSVPN LuCI protocol with Simplified Chinese translations.

```sh
. /etc/openwrt_release

BASE="https://raw.githubusercontent.com/NNdroid/tlsvpn/openwrt-feed/releases/${DISTRIB_RELEASE}/${DISTRIB_TARGET}"

echo "OpenWrt release: $DISTRIB_RELEASE"
echo "OpenWrt target:  $DISTRIB_TARGET"
echo "TLSVPN feed:     $BASE/packages.adb"

mkdir -p /etc/apk/keys /etc/apk/repositories.d

wget -O /etc/apk/keys/tlsvpn-feed.pem \
  https://raw.githubusercontent.com/NNdroid/tlsvpn/openwrt-feed/tlsvpn-feed.pem

echo "$BASE/packages.adb" \
  > /etc/apk/repositories.d/tlsvpn.list

apk update

apk add \
  luci-proto-tlsvpn \
  luci-i18n-tlsvpn-zh-cn
```
