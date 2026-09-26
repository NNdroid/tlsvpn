# SPDX-License-Identifier: AGPL-3.0-or-later

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-proto-tlsvpn
PKG_VERSION:=0.1.0
PKG_RELEASE:=2
PKGARCH:=all

LUCI_TITLE:=LuCI support for the TLSVPN netifd protocol
LUCI_DEPENDS:=+tlsvpn-proto
LUCI_PKGARCH:=all
LUCI_LANG.en:=English
LUCI_LANG.fr:=Français
LUCI_LANG.de:=Deutsch
LUCI_LANG.zh_Hans:=简体中文
LUCI_LANG.zh_Hant:=繁體中文
LUCI_LANG.ja:=日本語

# Use the standard LuCI package infrastructure. Besides installing the protocol
# JavaScript it compiles po/*/tlsvpn.po into separate luci-i18n-tlsvpn-* APKs.
include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
