package main

import (
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestWebUIMetricFormulaContract(t *testing.T) {
	b, err := os.ReadFile("webui/metrics.js")
	if err != nil {
		t.Fatalf("read webui/metrics.js: %v", err)
	}
	js := string(b)
	for _, want := range []string{
		"Math.ceil(v.length * 0.95) - 1",
		"const reorder = data.reorder || {}",
		"const txAttempts = c.txPackets + queueDropped",
		"const missing = recovered + lost",
		"recovered / missing * 100",
	} {
		if !strings.Contains(js, want) {
			t.Fatalf("metric formula contract missing %q", want)
		}
	}
	if strings.Contains(js, "data.quality") {
		t.Fatal("metrics.js must derive quality values from real counters, not the nonexistent data.quality field")
	}
	if strings.Contains(js, "parity_tx") && strings.Contains(js, "fecRecoveryPct") {
		t.Fatal("FEC recovery rate must not use locally transmitted parity as its denominator")
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
	metrics := strings.Index(html, `<script src="metrics.js"></script>`)
	if app < 0 || metrics < 0 || metrics <= app {
		t.Fatalf("metrics.js must load after app.js: app=%d metrics=%d", app, metrics)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics.js", nil))
	if rr.Code != 200 {
		t.Fatalf("GET /metrics.js status=%d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Result().Body)
	if !strings.Contains(string(body), "fecRecoveryPct") {
		t.Fatal("served metrics.js is not the metric correction asset")
	}
}
