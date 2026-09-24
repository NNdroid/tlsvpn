# SPDX-License-Identifier: AGPL-3.0-or-later

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-proto-tlsvpn
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

LUCI_TITLE:=LuCI support for the TLSVPN netifd protocol
LUCI_DESCRIPTION:=Configure TLSVPN clients as native OpenWrt network interfaces.
LUCI_DEPENDS:=+tlsvpn-proto

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
