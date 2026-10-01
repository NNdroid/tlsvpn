package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestWebDiagnosticsSSEAndBackgroundSampling(t *testing.T) {
	h := &diagnosticHistory{}
	mgr := &WebManager{srv: statsAuditServer(), diagnostics: h}
	mgr.sampleDiagnostics()
	if len(h.snapshot("2m").Points) != 1 {
		t.Fatal("background sampler did not collect without a browser")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/stream?range=2m", nil).WithContext(ctx)
	handleDashboardStream(statsCancelRecorder{rr, cancel}, r, mgr.srv, nil, h)
	lines := strings.Split(rr.Body.String(), "\n")
	for i, line := range lines {
		if line == "event: diagnostics" && i+1 < len(lines) {
			var got diagnosticSnapshot
			if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[i+1], "data: ")), &got); err != nil {
				t.Fatal(err)
			}
			if got.Instance != dashboardInstanceID || got.Step != 2 || len(got.Points) != 1 {
				t.Fatalf("SSE history mismatch: %+v", got)
			}
			if len(h.snapshot("2m").Points) != 1 {
				t.Fatal("browser read created duplicate samples")
			}
			return
		}
	}
	t.Fatal("SSE diagnostics frame missing")
}

func diagnosticFixture(at int64, n uint64) WebStats {
	return WebStats{InstanceID: "process-a", SampleTimeMs: at, Mode: "client", LiveConns: 1,
		Conns: []connSnapshot{{ConnID: "physical-a", State: "up", Target: "peer", TxBytes: n * 1000, RxBytes: n * 2000, Scheduler: schedulerConnJSON{AssignedBytes: n * 800, QueuedBytes: 128}}},
		Fec:   fecStatsJSON{DataWireBytes: n * 1000, ParityWireBytes: n * 250, Recovered: n * 2, Lost: n},
		Pad:   &padStatsJSON{Epoch: 1, WireBytes: n * 1000, PadBytes: n * 100}, ReconnectAttempts: n, Dropped: n * 2, TapErrors: n,
	}
}
func diagnosticAssert(t *testing.T, m map[string]*float64, key string, want float64) {
	t.Helper()
	v := m[key]
	if v == nil || *v != want {
		t.Fatalf("%s=%v want %g", key, v, want)
	}
}
func TestWebDiagnosticsRatesDirectionsAndBoundaries(t *testing.T) {
	h := &diagnosticHistory{}
	h.record(diagnosticFixture(60000, 10))
	h.record(diagnosticFixture(64000, 12))
	points := h.snapshot("2m").Points
	p := points[1]
	if points[0].Conns[0].Metrics["up"] != nil {
		t.Fatal("first sample fabricated a rate")
	}
	diagnosticAssert(t, p.Conns[0].Metrics, "up", 500)
	diagnosticAssert(t, p.Conns[0].Metrics, "down", 1000)
	diagnosticAssert(t, p.Conns[0].Metrics, "assigned", 400)
	diagnosticAssert(t, p.Conns[0].Metrics, "queue", 128)
	if p.Conns[0].Metrics["rtt"] != nil {
		t.Fatal("unknown RTT fabricated")
	}
	diagnosticAssert(t, p.Metrics, "fec_pct", 25)
	diagnosticAssert(t, p.Metrics, "pad_pct", 10)
	diagnosticAssert(t, p.Metrics, "recovered", 1)
	s := diagnosticFixture(66000, 13)
	s.Conns[0].ConnID = "physical-b"
	s.Pad.Epoch = 2
	h.record(s)
	p = h.snapshot("2m").Points[2]
	if p.Conns[0].Metrics["up"] != nil || p.Metrics["pad"] != nil {
		t.Fatal("reconnect/padding epoch crossed rate baseline")
	}
	s = diagnosticFixture(68000, 1)
	s.Conns[0].ConnID = "physical-b"
	h.record(s)
	if h.snapshot("2m").Points[3].Metrics["fec_data"] != nil {
		t.Fatal("counter rollback underflowed")
	}
	s = diagnosticFixture(70000, 1)
	s.InstanceID = "process-b"
	h.record(s)
	if len(h.snapshot("24h").Points) != 1 || h.snapshot("2m").Instance != "process-b" {
		t.Fatal("restart retained stale history")
	}
	server := &diagnosticHistory{}
	a := diagnosticFixture(60000, 10)
	a.Mode = "server"
	a.Conns = nil
	a.ServerConns = []serverConnSnapshot{{ConnID: "server-a", ClientID: "client-a", TxBytes: 1000, RxBytes: 2000, RttMs: 22}}
	server.record(a)
	a.SampleTimeMs = 62000
	a.ServerConns[0].TxBytes += 400
	a.ServerConns[0].RxBytes += 600
	server.record(a)
	c := server.snapshot("2m").Points[1].Conns[0]
	if server.snapshot("2m").Points[1].Metrics["reconnect"] != nil {
		t.Fatal("server fabricated a reconnect-attempt measurement")
	}
	diagnosticAssert(t, c.Metrics, "up", 300)
	diagnosticAssert(t, c.Metrics, "down", 200)
	diagnosticAssert(t, c.Metrics, "rtt", 22)
	a.SampleTimeMs = 64000
	a.ServerConns = nil
	a.LiveConns = 0
	server.record(a)
	if len(server.snapshot("2m").Points[2].Conns) != 0 {
		t.Fatal("retired connection remained live")
	}
}

func TestWebDiagnosticsSamplingGapsAndAlignedBuckets(t *testing.T) {
	h := &diagnosticHistory{}
	h.record(diagnosticFixture(60000, 1))
	h.record(diagnosticFixture(62000, 2))
	h.record(diagnosticFixture(660000, 20))
	h.record(diagnosticFixture(662000, 21))
	got := h.snapshot("24h")
	if len(got.Points) != 2 {
		t.Fatalf("distinct five-minute buckets merged across outage: %+v", got)
	}
	if h.snapshot("2m").Points[0].Conns[0].Metrics["up"] != nil {
		t.Fatal("long sampling gap generated a rate")
	}
	before := len(h.snapshot("2m").Points)
	h.record(diagnosticFixture(662000, 22))
	if len(h.snapshot("2m").Points) != before {
		t.Fatal("duplicate timestamp created a sample")
	}
}
func TestWebDiagnosticsAggregationRetentionAndConcurrency(t *testing.T) {
	h := &diagnosticHistory{}
	h.record(diagnosticFixture(60000, 0))
	h.record(diagnosticFixture(62000, 2))
	h.record(diagnosticFixture(68000, 3))
	p := h.snapshot("1h").Points[0]
	// 3000 actual bytes over 8 observed seconds, not the unweighted rate mean.
	diagnosticAssert(t, p.Conns[0].Metrics, "up", 375)
	diagnosticAssert(t, p.Metrics, "fec_pct", 25)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 1; i <= 1500; i++ {
			h.record(diagnosticFixture(120000+int64(i)*60000, uint64(i)))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1500; i++ {
			h.snapshot("24h")
			h.snapshot("2m")
		}
	}()
	wg.Wait()
	if len(h.minutes) > 1440 || len(h.recent) > 60 || len(h.snapshot("24h").Points) > 289 {
		t.Fatal("history retention unbounded")
	}
	s := diagnosticFixture(1000000000, 1501)
	s.Conns = nil
	for i := 0; i < 40; i++ {
		s.Conns = append(s.Conns, connSnapshot{ConnID: fmt.Sprintf("conn-%02d", i), State: "up"})
	}
	h.record(s)
	last := h.snapshot("2m").Points
	lastPoint := last[len(last)-1]
	if !lastPoint.Truncated || len(lastPoint.Conns) != 32 || len(h.prev.conns) != 32 {
		t.Fatal("connection retention cap not enforced")
	}
}
