package main

import (
	"os"
	"strings"
	"testing"
)

func TestOpenWrtAPKBuildTracksRealLuCITranslations(t *testing.T) {
	scriptBytes, err := os.ReadFile("scripts/build_openwrt_apk.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(scriptBytes)

	for _, stale := range []string{
		"CONFIG_PACKAGE_luci-i18n-tlsvpn-en=m",
		"expected protocol/LuCI plus 6 i18n APKs",
		"expected 6 LuCI i18n APKs",
	} {
		if strings.Contains(script, stale) {
			t.Fatalf("OpenWrt build script still contains stale LuCI translation assumption %q", stale)
		}
	}

	for _, required := range []string{
		"find openwrt/luci-proto-tlsvpn/po -mindepth 1 -maxdepth 1 -type d",
		"zh_Hans) suffix=\"zh-cn\"",
		"zh_Hant) suffix=\"zh-tw\"",
		"required_independent_packages=(tlsvpn-proto luci-proto-tlsvpn",
		"missing architecture-independent OpenWrt APK(s)",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("OpenWrt build script is missing artifact-validation contract %q", required)
		}
	}

	makefileBytes, err := os.ReadFile("openwrt/luci-proto-tlsvpn/Makefile")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(makefileBytes), "LUCI_LANG.en:=") {
		t.Fatal("English must remain LuCI's source language, not a separate i18n APK")
	}
}
