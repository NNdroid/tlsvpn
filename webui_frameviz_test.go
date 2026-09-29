package main

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebUII18nAndFrameVisualizerAreInjected(t *testing.T) {
	ts := httptest.NewServer(webuiHandler())
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	i18nPos := strings.Index(html, `<script src="i18n.js"></script>`)
	appPos := strings.Index(html, `<script src="app.js"></script>`)
	if i18nPos < 0 || appPos < 0 || i18nPos > appPos {
		t.Fatal("i18n.js must load before app.js")
	}
	for _, want := range []string{
		`data-v="zh-TW"`,
		`>繁中</button>`,
		`<script src="frameviz.js"></script>`,
		`<script src="metrics.js"></script>`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("index response missing %q", want)
		}
	}
	for _, stale := range []string{`zh-tw.js`, `frameviz-zh-tw.js`} {
		if strings.Contains(html, stale) {
			t.Fatalf("index still references obsolete locale asset %q", stale)
		}
	}

	assets := []struct {
		path string
		want []string
	}{
		{"/i18n.js", []string{"const I18N={", "const FRAMEVIZ_I18N=", "'zh-CN'", "'zh-TW'", "'de'", "'fr'", "'ja'", "Frame format example", "FEC recovery rate"}},
		{"/frameviz.js", []string{"FRAMEVIZ_I18N[LANG]", "AES-256-GCM", "12 KiB", "16 KiB", "padLen=0", "1 MiB"}},
		{"/metrics.js", []string{"assigned - p.assigned", "_share_pct", "_queue_eta_us"}},
	}
	for _, a := range assets {
		resp, err = ts.Client().Get(ts.URL + a.path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s status=%d", a.path, resp.StatusCode)
		}
		src := string(b)
		for _, want := range a.want {
			if !strings.Contains(src, want) {
				t.Fatalf("%s missing %q", a.path, want)
			}
		}
		if a.path != "/i18n.js" && strings.Contains(src, "const I18N={") {
			t.Fatalf("%s must not embed locale dictionaries", a.path)
		}
	}

	for _, old := range []string{"/zh-tw.js", "/frameviz-zh-tw.js"} {
		resp, err = ts.Client().Get(ts.URL + old)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("obsolete asset %s must be 404, got %d", old, resp.StatusCode)
		}
	}
}
