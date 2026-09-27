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
	if !strings.Contains(string(body), `<script src="frameviz.js"></script>`) {
		t.Fatal("index response must load frameviz.js")
	}

	resp, err = ts.Client().Get(ts.URL + "/frameviz.js")
	if err != nil {
		t.Fatal(err)
	}
	js, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("frameviz status = %d", resp.StatusCode)
	}
	src := string(js)
	for _, want := range []string{
		"Frame format example",
		"帧格式示例",
		"Beispiel für Frame-Format",
		"Exemple de format de trame",
		"フレーム形式の例",
		"dataLen",
		"padLen",
		"RandomPool",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("frameviz.js missing %q", want)
		}
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("frameviz Cache-Control = %q, want no-store", cc)
	}
}
