# SPDX-License-Identifier: AGPL-3.0-or-later

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-proto-tlsvpn
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKGARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/luci-proto-tlsvpn
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=Protocols
  TITLE:=LuCI support for the TLSVPN netifd protocol
  DEPENDS:=+tlsvpn-proto
  # Runtime-only: this package ships static JavaScript and does not need the
  # LuCI/Lua build toolchain in a standalone OpenWrt SDK build.
  EXTRA_DEPENDS:=luci-base (>=0)
endef

define Package/luci-proto-tlsvpn/description
 Configure TLSVPN clients as native OpenWrt network interfaces from LuCI.
endef

# This package only installs static LuCI JavaScript. package.mk's default
# Build/Compile invokes $(MAKE) inside PKG_BUILD_DIR, but there is no upstream
# Makefile to build. Explicitly make the compile phase a no-op.
define Build/Compile
endef

define Package/luci-proto-tlsvpn/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/protocol
	$(INSTALL_DATA) ./htdocs/luci-static/resources/protocol/tlsvpn.js \
		$(1)/www/luci-static/resources/protocol/tlsvpn.js
endef

$(eval $(call BuildPackage,luci-proto-tlsvpn))
