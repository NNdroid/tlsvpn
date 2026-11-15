package main

import (
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestWebUIMetricFormulaContract(t *testing.T) {
	b, err := os.ReadFile("webui/metric-corrections.js")
	if err != nil {
		t.Fatalf("read webui/metric-corrections.js: %v", err)
	}
	js := string(b)
	for _, want := range []string{
		"Math.ceil(v.length * 0.95) - 1",
		"const reorder = data.reorder || {}",
		"fec.counter_domain === 'written'",
		"const txAttempts = c.txPackets + dropped",
		"c.rxBytes/c.rxPackets",
		"parityWire/dataWire*100",
		"const missing = recovered + lost",
		"recovered/missing*100",
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("metric formula contract missing %q", want)
		}
	}
	if strings.Contains(js, "data.quality") {
		t.Fatal("metric-corrections.js must derive quality values from real counters, not the nonexistent data.quality field")
	}
	for _, wrong := range []string{
		"recovered / parityTx",
		"recovered / num(fec.parity_tx)",
		"parityTx / c.txPackets",
		"const txAttempts = dataTxPackets + dropped",
	} {
		if strings.Contains(js, wrong) {
			t.Fatalf("mixed-domain metric formula reintroduced: %q", wrong)
		}
	}
}

func TestWebUILoadsMetricCorrections(t *testing.T) {
	h := webuiHandler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != 200 {
		t.Fatalf("GET / status=%d", rr.Code)
	}
	html := rr.Body.String()
	app := strings.Index(html, `<script src="app.js"></script>`)
	metrics := strings.Index(html, `<script src="metric-corrections.js"></script>`)
	if app < 0 || metrics < 0 || metrics <= app {
		t.Fatalf("metric-corrections.js must load after app.js: app=%d metrics=%d", app, metrics)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metric-corrections.js", nil))
	if rr.Code != 200 {
		t.Fatalf("GET /metric-corrections.js status=%d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Result().Body)
	if !strings.Contains(string(body), "fecRecoveryPct") {
		t.Fatal("served metric-corrections.js is not the metric correction asset")
	}
}
