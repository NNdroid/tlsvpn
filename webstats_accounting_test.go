package main

import (
	"bytes"
	"context"
	"encoding/json"
	"go.uber.org/zap/zapcore"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestWebStatsPaddingMixedRecords(t *testing.T) {
	prev := padModeName()
	setPadMode(padModeOff)
	setPadMode(padModeBucket)
	defer setPadMode(prev)
	recordPadBytes(100, 20)
	recordPadBytes(900, 0)
	got := padStatsJSONPtr()
	if got.WireBytes != 1000 || got.PadBytes != 20 || got.OverheadPct != 2 {
		t.Fatalf("mixed records: %+v", got)
	}
	oldEpoch := padAccountingEpoch()
	setPadMode(padModeOff)
	recordPadBytesAt(100, 20, oldEpoch)
	recordPadBytes(900, 0)
	got = padStatsJSONPtr()
	if got.Mode != "off" || got.WireBytes != 900 || got.PadBytes != 0 || got.OverheadPct != 0 {
		t.Fatalf("epoch/off accounting: %+v", got)
	}
}

func TestWebStatsPaddingConcurrentSnapshot(t *testing.T) {
	prev := padModeName()
	defer setPadMode(prev)
	setPadMode(padModeOff)
	setPadMode(padModeBucket)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				recordPadBytes(10, 1)
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		s := padStatsJSONPtr()
		if s.PadBytes > s.WireBytes {
			t.Fatalf("torn snapshot: %+v", s)
		}
	}
	wg.Wait()
	s := padStatsJSONPtr()
	if s.WireBytes != 40000 || s.PadBytes != 4000 || s.OverheadPct != 10 {
		t.Fatalf("lost records: %+v", s)
	}
}

type statsShortWriter struct{}

func (statsShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestWebStatsShortWriteNotSuccess(t *testing.T) {
	before := padStatsJSONPtr()
	if err := writeStreamFrame(statsShortWriter{}, []byte("control")); err != io.ErrShortWrite {
		t.Fatalf("short write: %v", err)
	}
	after := padStatsJSONPtr()
	if before.WireBytes != after.WireBytes || before.PadBytes != after.PadBytes {
		t.Fatal("failed write counted as success")
	}
}

func TestWebStatsWrittenFrameDomains(t *testing.T) {
	b := getOwnedVPNFrameBatch()
	appendOwnedVPNFrame(b, VPNFrame{Seq: 1, Data: cloneFrame([]byte("data"))})
	appendOwnedVPNFrame(b, VPNFrame{Data: cloneFrame([]byte{controlKindFECParity, 1, 2, 3, 4, 4})})
	appendOwnedVPNFrame(b, VPNFrame{Data: cloneFrame(appendFECModeControl(nil, fecModeControl{Generation: 1, Op: fecControlSuspend, Boundary: 5}))})
	var totals txFrameTotals
	var scratch nonceAADScratch
	wire, n, _ := appendOwnedVPNFrameBatchStreamWithScratch(nil, b, nil, &scratch, &totals)
	if n != 3 || totals.DataFrames != 1 || totals.ParityFrames != 1 || totals.ControlFrames != 1 || totals.DataWireBytes != 14 || totals.ParityWireBytes != 16 {
		t.Fatalf("frame domains: %+v", totals)
	}
	p := &AsyncPort{}
	p.paritySent.Add(10)
	var f fecStatsJSON
	f.setWritten(p.written.snapshot())
	if f.ParityTx != 0 {
		t.Fatal("attempted parity counted as written")
	}
	p.written.record(totals)
	f.setWritten(p.written.snapshot())
	if f.ParityTx != 1 || f.DataTx != 1 || f.ControlTx != 1 || f.CounterDomain != "written" {
		t.Fatalf("written snapshot: %+v", f)
	}
	scanner := NewFrameScanner(bytes.NewReader(wire))
	var received uint64
	for i := 0; i < n; i++ {
		frame, _, err := scanner.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		received += scanner.lastWireSize
		putFrame(frame)
	}
	if received != uint64(len(wire)) {
		t.Fatalf("TX/RX wire differs: %d/%d", len(wire), received)
	}
}

func TestWebStatsScannerIncludesPadding(t *testing.T) {
	prev := padModeName()
	setPadMode(padModeBucket)
	defer setPadMode(prev)
	wire, pad := appendPaddedFrame(nil, VPNFrame{Seq: 1, Data: []byte{42}}, nil)
	scanner := NewFrameScanner(bytes.NewReader(wire))
	frame, _, err := scanner.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	defer putFrame(frame)
	if pad == 0 || scanner.lastWireSize != uint64(len(wire)) || len(frame) != 1 {
		t.Fatalf("payload/wire: %d/%d pad=%d", len(frame), scanner.lastWireSize, pad)
	}
	_, _, err = scanner.ReadFrame()
	if err != io.EOF || scanner.lastWireSize != 0 {
		t.Fatalf("failed read retained successful size: %v/%d", err, scanner.lastWireSize)
	}
}

func statsAuditServer() *Server {
	return &Server{startedAt: time.Now(), vswitch: NewVSwitch(), activeClients: map[string]*ClientSession{}, usedV4: map[string]bool{}, usedV6: map[string]bool{}, v4Net: mustCIDR("10.0.0.0/24"), banned: map[string]int64{}}
}
func readAuditStats(t *testing.T, s *Server, c *Client) WebStats {
	t.Helper()
	rr := httptest.NewRecorder()
	startWebStatsHandler(rr, httptest.NewRequest("GET", "/api/stats", nil), s, c)
	var got WebStats
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode stats: %v: %s", err, rr.Body.String())
	}
	return got
}
func TestWebStatsRetiredSessionKeepsProcessTotals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := statsAuditServer()
	cfg := &Config{Server: ServerConfig{MaxSessions: 10}}
	s.cfg.Store(cfg)
	p := NewAsyncPort(ctx, "audit")
	defer p.Close()
	session := &ClientSession{Port: p, IPv4: "10.0.0.2", ActiveConns: 1, CreatedAt: time.Now(), conns: map[*connInfo]struct{}{}}
	s.activeClients["a"] = session
	s.txBytesTotal.Store(1000)
	s.rxBytesTotal.Store(500)
	s.txPacketsTotal.Store(10)
	s.rxPacketsTotal.Store(5)
	s.written.record(txFrameTotals{DataFrames: 8, ParityFrames: 2, DataWireBytes: 800, ParityWireBytes: 200})
	s.fecLifetime.recovered.Store(7)
	p.dropN(3)
	before := readAuditStats(t, s, nil)
	if before.ActiveClients != 1 || before.LiveConns != 1 || before.RetainedSessions != 1 {
		t.Fatalf("online: %+v", before)
	}
	session.ActiveConns = 0
	held := readAuditStats(t, s, nil)
	if held.ActiveClients != 0 || held.RetainedSessions != 1 || held.Sessions.Active != 1 {
		t.Fatalf("held session: active=%d held=%d water=%+v", held.ActiveClients, held.RetainedSessions, held.Sessions)
	}
	s.mu.Lock()
	s.destroySessionLocked(session, "a")
	s.mu.Unlock()
	after := readAuditStats(t, s, nil)
	if after.GlobalTxBytes != 1000 || after.GlobalRxBytes != 500 || after.GlobalTxPackets != 10 || after.Fec.ParityTx != 2 || after.Fec.Recovered != 7 || after.Dropped != 3 {
		t.Fatalf("lost retired totals: %+v", after)
	}
	if after.Fec.Enabled || after.Negotiate.FEC || after.ActiveClients != 0 || after.RetainedSessions != 0 {
		t.Fatal("empty server reports active FEC/client")
	}
	if after.InstanceID == "" || after.SampleTimeMs == 0 {
		t.Fatal("missing process/sample identity")
	}
	rr := httptest.NewRecorder()
	handleMetrics(s, nil)(rr, httptest.NewRequest("GET", "/metrics", nil))
	if !bytes.Contains(rr.Body.Bytes(), []byte("tlsvpn_tx_bytes_total 1000")) || !bytes.Contains(rr.Body.Bytes(), []byte("tlsvpn_fec_parity_frames_total 2")) {
		t.Fatalf("metrics disagrees: %s", rr.Body.String())
	}
}

func TestWebStatsConnectionOwnsNegotiation(t *testing.T) {
	c := &Client{connsCount: 2, conns: map[int]*clientConnInfo{}, negInfo: &sessionNeg{TxRateMbps: 999}}
	for i := 0; i < 2; i++ {
		ci := &clientConnInfo{rttCache: new(uint32)}
		ci.state.Store("up")
		ci.negotiated.Store(&sessionNeg{TxRateMbps: uint64(10 + i), TLS: &TLSHandshakeInfo{SNI: []string{"first.example", "second.example"}[i], Version: []string{"TLS 1.2", "TLS 1.3"}[i]}})
		c.conns[i] = ci
	}
	got := c.snapshotConns()
	if got[0].BrutalTxMbps != 10 || got[1].BrutalTxMbps != 11 || got[0].SNI == got[1].SNI || got[0].TLSVersion == got[1].TLSVersion {
		t.Fatalf("shared negotiation leaked: %+v", got)
	}
	c.conns[0].state.Store("retrying")
	got = c.snapshotConns()
	if got[0].SNI != "" || got[0].RttMs != 0 || got[0].BrutalTxMbps != 0 {
		t.Fatalf("disconnected path reports live values: %+v", got[0])
	}
}

func TestTrafficRetireAndRecreateBetweenSamples(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := statsAuditServer()
	accounting := NewTrafficAccounting()
	s.installTrafficAccounting(accounting)
	p := NewAsyncPort(ctx, "old")
	defer p.Close()
	old := &ClientSession{Port: p, CreatedAt: time.Now(), RxBytes: 100, TxBytes: 200}
	s.activeClients["same-client"] = old
	first := accounting.ClientSnapshot()
	if len(first) != 1 || first[0].Daily[0].Up != 100 || first[0].Daily[0].Down != 200 {
		t.Fatalf("first live sample: %+v", first)
	}
	old.RxBytes += 50
	old.TxBytes += 75
	s.mu.Lock()
	s.destroySessionLocked(old, "same-client")
	s.mu.Unlock()
	s.activeClients["same-client"] = &ClientSession{RxBytes: 10, TxBytes: 20}
	next := accounting.ClientSnapshot()
	if len(next) != 1 || next[0].Daily[0].Up != 160 || next[0].Daily[0].Down != 295 {
		t.Fatalf("lost retired tail/new-session traffic: %+v", next)
	}
	again := accounting.ClientSnapshot()
	if again[0].Daily[0] != next[0].Daily[0] {
		t.Fatal("repeated snapshot double counted traffic")
	}
	if len(s.retiredTraffic) != 0 || len(s.trafficLast) != 1 {
		t.Fatal("retired sampling state leaked")
	}
}

func TestTrafficTrendUsesActualElapsedTime(t *testing.T) {
	a := NewTrafficAccounting()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	a.lastFlush = base
	a.Add(12000, 6000)
	a.flush(base.Add(120 * time.Second))
	got := a.TrendSnapshot(60)
	if len(got.Points) != 1 || got.Points[0].UpBps != 100 || got.Points[0].DownBps != 50 {
		t.Fatalf("delayed sample rate: %+v", got)
	}
}

func TestTrafficConcurrentFlushSnapshot(t *testing.T) {
	a := NewTrafficAccounting()
	base := time.Now()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			a.Add(10, 5)
			a.flush(base.Add(time.Duration(i) * time.Second))
		}
	}()
	for i := 0; i < 1000; i++ {
		s := a.Snapshot()
		if s.Down > s.Up {
			t.Fatalf("impossible traffic snapshot: %+v", s)
		}
	}
	wg.Wait()
	s := a.Snapshot()
	if s.Up != 10000 || s.Down != 5000 {
		t.Fatalf("lost cumulative traffic: %+v", s)
	}
}

func TestWebStatsBootstrapRTTNotMeasured(t *testing.T) {
	cold := &clientConnInfo{rttCache: new(uint32)}
	cold.state.Store("up")
	*cold.rttCache = 50000
	hot := &clientConnInfo{rttCache: new(uint32)}
	hot.state.Store("up")
	*hot.rttCache = 20000
	hot.rttMeasured.Store(true)
	c := &Client{connsCount: 2, conns: map[int]*clientConnInfo{0: cold, 1: hot}}
	if c.snapshotConns()[0].RttMs != 0 || c.avgRTT() != 20 {
		t.Fatalf("bootstrap/disconnected RTT contaminated average: %+v", c.snapshotConns())
	}
	hot.state.Store("retrying")
	if c.avgRTT() != 0 {
		t.Fatal("disconnected RTT was treated as live")
	}
}

type statsCancelRecorder struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (r statsCancelRecorder) Flush() { r.ResponseRecorder.Flush(); r.cancel() }
func TestWebStatsSSEPriorProcessCursorResets(t *testing.T) {
	previousLogs, previousEvents := logRing, evBus
	logRing = newLogRing(10)
	evBus = newEventBus(10)
	defer func() { logRing, evBus = previousLogs, previousEvents }()
	logRing.add(zapcore.Entry{Message: "new-process-log", Level: zapcore.InfoLevel, Time: time.Now()})
	evBus.emit("up", "info", "test", "new-process-event")
	for _, tc := range []struct {
		id   string
		want bool
	}{{"previous-process", true}, {dashboardInstanceID, false}} {
		ctx, cancel := context.WithCancel(context.Background())
		rr := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/stream?instance_id="+tc.id+"&log_after=1000&event_after=1000", nil).WithContext(ctx)
		handleDashboardStream(statsCancelRecorder{rr, cancel}, r, statsAuditServer(), nil)
		cancel()
		if bytes.Contains(rr.Body.Bytes(), []byte("new-process-log")) != tc.want || bytes.Contains(rr.Body.Bytes(), []byte("new-process-event")) != tc.want {
			t.Fatalf("instance=%s wrong replay: %s", tc.id, rr.Body.String())
		}
	}
}

func TestWebStatsReconnectOwnsCounters(t *testing.T) {
	old := &clientConnInfo{target: "old.example:443", txBytes: 5000, rxBytes: 2000, retries: 3}
	c := &Client{connsCount: 1, conns: map[int]*clientConnInfo{0: old}}
	next := c.beginConnAttempt(0, "new.example:443")
	old.txBytes += 1000
	next.txBytes = 10
	got := c.snapshotConns()[0]
	if got.Target != "new.example:443" || got.TxBytes != 10 || got.RxBytes != 0 || got.Retries != 3 || got.State != "connecting" {
		t.Fatalf("reused connection attempt metadata: %+v", got)
	}
}
