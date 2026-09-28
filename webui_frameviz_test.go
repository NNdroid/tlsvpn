package main

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebUIFrameVisualizerIsInjected(t *testing.T) {
	ts := httptest.NewServer(webuiHandler())
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("index status = %d", resp.StatusCode)
	}
	html := string(body)
	for _, want := range []string{`data-v="zh-TW"`, `>繁中</button>`, `<script src="zh-tw.js"></script>`, `<script src="frameviz.js"></script>`, `<script src="frameviz-zh-tw.js"></script>`} {
		if !strings.Contains(html, want) {
			t.Fatalf("index response missing %q", want)
		}
	}

	for _, asset := range []struct {
		path string
		want []string
	}{
		{"/frameviz.js", []string{
			"Frame format example", "帧格式示例", "訊框格式範例", "Beispiel für Frame-Format", "Exemple de format de trame", "フレーム形式の例",
			"AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305", "XChaCha20-Poly1305",
			"1514 B", "1530 B", "60 B → 1600 B", "dataLen", "padLen", "4 B BE", "seq=0", "1 MiB",
		}},
		{"/zh-tw.js", []string{"I18N['zh-TW']", "用戶端", "伺服器", "位址池", "工作階段", "金鑰"}},
		{"/frameviz-zh-tw.js", []string{"native zh-TW", "compatibility asset", "framevizLocale"}},
	} {
		resp, err = ts.Client().Get(ts.URL + asset.path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s status = %d", asset.path, resp.StatusCode)
		}
		src := string(b)
		for _, want := range asset.want {
			if !strings.Contains(src, want) {
				t.Fatalf("%s missing %q", asset.path, want)
			}
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("%s Cache-Control = %q, want no-store", asset.path, cc)
		}
	}
}
