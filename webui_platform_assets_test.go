package main

import (
	"io/fs"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebUIPlatformAssetsAndFavicon(t *testing.T) {
	index, err := fs.ReadFile(webuiFS, "webui/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), "/favicon.ico") {
		t.Fatal("index.html missing local favicon")
	}
	app, err := fs.ReadFile(webuiFS, "webui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"platformSummary", "platformAssetName", "icons/"} {
		if !strings.Contains(string(app), needle) {
			t.Fatalf("app.js missing %q", needle)
		}
	}
	for _, name := range []string{"os-linux.svg", "os-windows.svg", "os-macos.svg", "os-android.svg", "arch-x86_64.svg", "arch-arm64.svg", "arch-riscv64.svg"} {
		if _, err := fs.ReadFile(webuiFS, "webui/icons/"+name); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	b, err := fs.ReadFile(webuiFS, "webui/favicon.ico")
	if err != nil || len(b) < 100 {
		t.Fatalf("invalid favicon.ico: len=%d err=%v", len(b), err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/favicon.ico", nil)
	webuiHandler().ServeHTTP(rr, req)
	if rr.Code != 200 || rr.Body.Len() < 100 {
		t.Fatalf("favicon response status=%d len=%d", rr.Code, rr.Body.Len())
	}
}
