# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=tlsvpn

# These defaults keep local SDK builds convenient. Release builds override all
# three variables from scripts/build_openwrt_apk.sh so the APK is built from
# the exact tagged commit rather than from a moving branch.
TLSVPN_PKG_VERSION?=0.1.0
TLSVPN_SOURCE_VERSION?=feature/openwrt-netifd-proto
TLSVPN_SOURCE_DATE?=2026-09-24

PKG_VERSION:=$(TLSVPN_PKG_VERSION)
PKG_RELEASE:=1
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/NNdroid/tlsvpn.git
PKG_SOURCE_VERSION:=$(TLSVPN_SOURCE_VERSION)
PKG_SOURCE_DATE:=$(TLSVPN_SOURCE_DATE)
PKG_MIRROR_HASH:=skip

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=NNdroid
PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=tlsvpn
GO_PKG_BUILD_PKG:=tlsvpn

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/tlsvpn
  SECTION:=net
  CATEGORY:=Network
  TITLE:=TLS-based Layer-2 VPN
  URL:=https://github.com/NNdroid/tlsvpn
  DEPENDS:=$(GO_ARCH_DEPENDS) +kmod-tun +ca-bundle
endef

define Package/tlsvpn/description
 High-performance Layer-2 VPN over TCP+TLS with optional GCM, XOR FEC,
 multipath and TCP Brutal support.
endef

define Package/tlsvpn-proto
  SECTION:=net
  CATEGORY:=Network
  TITLE:=netifd protocol support for TLSVPN
  DEPENDS:=+tlsvpn +resolveip
  PKGARCH:=all
endef

define Package/tlsvpn-proto/description
 Native OpenWrt netifd protocol integration for TLSVPN client interfaces.
 TLSVPN owns the TAP/data plane; netifd owns addresses, routes and firewall
 lifecycle.
endef

define Package/tlsvpn/install
	$(call GoPackage/Package/Install/Bin,$(PKG_INSTALL_DIR))
endef

define Package/tlsvpn-proto/install
	$(INSTALL_DIR) $(1)/lib/netifd/proto
	$(INSTALL_BIN) ./files/lib/netifd/proto/tlsvpn.sh $(1)/lib/netifd/proto/tlsvpn.sh
	$(INSTALL_DIR) $(1)/lib/netifd
	$(INSTALL_BIN) ./files/lib/netifd/tlsvpn-up $(1)/lib/netifd/tlsvpn-up
	$(INSTALL_BIN) ./files/lib/netifd/tlsvpn-down $(1)/lib/netifd/tlsvpn-down
endef

$(eval $(call GoBinPackage,tlsvpn))
$(eval $(call BuildPackage,tlsvpn))
$(eval $(call BuildPackage,tlsvpn-proto))
