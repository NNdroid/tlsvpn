package main

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const diagnosticConnectionLimit = 32

type diagnosticConn struct {
	ID      string              `json:"id"`
	Client  string              `json:"client"`
	Label   string              `json:"label"`
	Metrics map[string]*float64 `json:"metrics"`
}
type diagnosticPoint struct {
	Seconds   float64             `json:"seconds"`
	T         int64               `json:"t"`
	Metrics   map[string]*float64 `json:"metrics"`
	Conns     []diagnosticConn    `json:"conns"`
	Truncated bool                `json:"truncated"`
}
type diagnosticSnapshot struct {
	Instance string            `json:"instance_id"`
	Step     int               `json:"step_sec"`
	Points   []diagnosticPoint `json:"points"`
}
type diagnosticBaseline struct {
	instance string
	t        int64
	counters map[string]uint64
	conns    map[string]map[string]uint64
	padEpoch uint64
}

// WebManager owns the sampler: reading a chart never creates samples or changes
// another browser's baseline. Retention is bounded and is not persisted.
type diagnosticHistory struct {
	mu                      sync.RWMutex
	prev                    diagnosticBaseline
	recent, minutes, bucket []diagnosticPoint
}

func diagnosticValue(v float64) *float64 { return &v }
func diagnosticRate(now, old uint64, seconds float64, valid bool) *float64 {
	if !valid || seconds <= 0 || now < old {
		return nil
	}
	return diagnosticValue(float64(now-old) / seconds)
}
func (h *diagnosticHistory) record(s WebStats) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.prev.instance != s.InstanceID {
		h.prev = diagnosticBaseline{}
		h.recent = nil
		h.minutes = nil
		h.bucket = nil
	}
	if s.SampleTimeMs <= h.prev.t {
		return
	}
	seconds := float64(s.SampleTimeMs-h.prev.t) / 1000
	valid := h.prev.t != 0 && seconds <= 10
	counters := map[string]uint64{"fec_data": s.Fec.DataWireBytes, "fec_parity": s.Fec.ParityWireBytes, "recovered": s.Fec.Recovered, "lost": s.Fec.Lost, "reconnect": s.ReconnectAttempts, "drop": s.Dropped, "tap_error": s.TapErrors}
	if s.Mode != "client" {
		delete(counters, "reconnect")
	}
	if s.Pad != nil {
		counters["pad"] = s.Pad.PadBytes
		counters["pad_wire"] = s.Pad.WireBytes
	}
	weight := seconds
	if !valid {
		weight = 2
	}
	p := diagnosticPoint{Seconds: weight, T: s.SampleTimeMs, Metrics: map[string]*float64{"online": diagnosticValue(float64(s.LiveConns))}, Conns: []diagnosticConn{}}
	for k, v := range counters {
		old, ok := h.prev.counters[k]
		p.Metrics[k] = diagnosticRate(v, old, seconds, valid && ok)
	}
	if s.Pad == nil || s.Pad.Epoch != h.prev.padEpoch {
		p.Metrics["pad"] = nil
		p.Metrics["pad_wire"] = nil
	}
	ratio := func(a, b *float64) *float64 {
		if a == nil || b == nil || *b <= 0 {
			return nil
		}
		return diagnosticValue(100 * (*a) / (*b))
	}
	p.Metrics["fec_pct"] = ratio(p.Metrics["fec_parity"], p.Metrics["fec_data"])
	p.Metrics["pad_pct"] = ratio(p.Metrics["pad"], p.Metrics["pad_wire"])
	next := map[string]map[string]uint64{}
	add := func(id, client, label string, tx, rx uint64, rtt uint32, scheduler schedulerConnJSON) {
		if id == "" {
			return
		}
		current := map[string]uint64{"up": tx, "down": rx, "assigned": scheduler.AssignedBytes}
		if s.Mode == "server" {
			current["up"], current["down"] = rx, tx
		}
		old, ok := h.prev.conns[id]
		m := map[string]*float64{"queue": diagnosticValue(float64(scheduler.QueuedBytes)), "rtt": nil}
		for k, v := range current {
			m[k] = diagnosticRate(v, old[k], seconds, valid && ok)
		}
		if rtt > 0 {
			m["rtt"] = diagnosticValue(float64(rtt))
		}
		p.Conns = append(p.Conns, diagnosticConn{ID: id, Client: client, Label: label, Metrics: m})
		next[id] = current
	}
	for _, c := range s.Conns {
		if c.State == "up" {
			add(c.ConnID, "local", c.Target, c.TxBytes, c.RxBytes, c.RttMs, c.Scheduler)
		}
	}
	for _, c := range s.ServerConns {
		add(c.ConnID, c.ClientID, c.Remote, c.TxBytes, c.RxBytes, c.RttMs, c.Scheduler)
	}
	sort.Slice(p.Conns, func(i, j int) bool { return p.Conns[i].ID < p.Conns[j].ID })
	if len(p.Conns) > diagnosticConnectionLimit {
		p.Truncated = true
		p.Conns = p.Conns[:diagnosticConnectionLimit]
		keep := map[string]bool{}
		for _, c := range p.Conns {
			keep[c.ID] = true
		}
		for id := range next {
			if !keep[id] {
				delete(next, id)
			}
		}
	}
	h.recent = append(h.recent, p)
	if len(h.recent) > 60 {
		h.recent = h.recent[len(h.recent)-60:]
	}
	if len(h.bucket) > 0 && h.bucket[0].T/60000 != p.T/60000 {
		h.minutes = append(h.minutes, aggregateDiagnostics(h.bucket))
		h.bucket = nil
		if len(h.minutes) > 1440 {
			h.minutes = h.minutes[len(h.minutes)-1440:]
		}
	}
	h.bucket = append(h.bucket, p)
	epoch := uint64(0)
	if s.Pad != nil {
		epoch = s.Pad.Epoch
	}
	h.prev = diagnosticBaseline{instance: s.InstanceID, t: s.SampleTimeMs, counters: counters, conns: next, padEpoch: epoch}
}

// Each metric averages only real observations. Connection identities are never
// merged across reconnects; absent or unmeasured metrics remain gaps.
func aggregateDiagnostics(points []diagnosticPoint) diagnosticPoint {
	out := diagnosticPoint{T: points[len(points)-1].T, Metrics: map[string]*float64{}, Conns: []diagnosticConn{}}
	sums := map[string]float64{}
	counts := map[string]float64{}
	byID := map[string]diagnosticConn{}
	cs := map[string]map[string]float64{}
	cn := map[string]map[string]float64{}
	for _, p := range points {
		weight := p.Seconds
		if weight <= 0 {
			weight = 2
		}
		out.Seconds += weight
		out.Truncated = out.Truncated || p.Truncated
		for k, v := range p.Metrics {
			if v != nil {
				sums[k] += *v * weight
				counts[k] += weight
			}
		}
		for _, c := range p.Conns {
			if _, ok := byID[c.ID]; !ok {
				if len(byID) >= diagnosticConnectionLimit {
					out.Truncated = true
					continue
				}
				byID[c.ID] = c
				cs[c.ID] = map[string]float64{}
				cn[c.ID] = map[string]float64{}
			}
			for k, v := range c.Metrics {
				if v != nil {
					cs[c.ID][k] += *v * weight
					cn[c.ID][k] += weight
				}
			}
		}
	}
	for k, n := range counts {
		out.Metrics[k] = diagnosticValue(sums[k] / float64(n))
	}
	for id, c := range byID {
		c.Metrics = map[string]*float64{}
		for k, n := range cn[id] {
			c.Metrics[k] = diagnosticValue(cs[id][k] / float64(n))
		}
		out.Conns = append(out.Conns, c)
	}
	sort.Slice(out.Conns, func(i, j int) bool { return out.Conns[i].ID < out.Conns[j].ID })
	// Ratios are based on the averaged byte rates, never averages of percentages.
	for _, pair := range [][3]string{{"fec_pct", "fec_parity", "fec_data"}, {"pad_pct", "pad", "pad_wire"}} {
		a, b := out.Metrics[pair[1]], out.Metrics[pair[2]]
		out.Metrics[pair[0]] = nil
		if a != nil && b != nil && *b > 0 {
			out.Metrics[pair[0]] = diagnosticValue(100 * (*a) / (*b))
		}
	}
	return out
}
func (h *diagnosticHistory) snapshot(rng string) diagnosticSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := diagnosticSnapshot{Instance: h.prev.instance, Step: 2, Points: []diagnosticPoint{}}
	if rng == "2m" {
		for _, p := range h.recent {
			if p.T >= h.prev.t-120000 {
				out.Points = append(out.Points, p)
			}
		}
		return out
	}
	raw := append([]diagnosticPoint{}, h.minutes...)
	if len(h.bucket) > 0 {
		raw = append(raw, aggregateDiagnostics(h.bucket))
	}
	cutoff := h.prev.t - int64(time.Hour/time.Millisecond)
	step := 1
	out.Step = 60
	if rng == "24h" {
		cutoff = h.prev.t - int64(24*time.Hour/time.Millisecond)
		step = 5
		out.Step = 300
	}
	selected := []diagnosticPoint{}
	for _, p := range raw {
		if p.T >= cutoff {
			selected = append(selected, p)
		}
	}
	for i := 0; i < len(selected); {
		end := i + 1
		for end < len(selected) && selected[end].T/int64(step*60000) == selected[i].T/int64(step*60000) {
			end++
		}
		out.Points = append(out.Points, aggregateDiagnostics(selected[i:end]))
		i = end
	}
	return out
}
func (w *WebManager) sampleDiagnostics() {
	if w.diagnostics == nil {
		return
	}
	// Read only the existing counters. Avoid a full stats HTTP/JSON round trip,
	// runtime.ReadMemStats and host route/process probes in the background sampler.
	s := WebStats{InstanceID: dashboardInstanceID, SampleTimeMs: time.Now().UnixMilli(), Pad: padStatsJSONPtr()}
	if srv := w.srv; srv != nil {
		s.Mode = "server"
		s.ServerConns = srv.snapshotServerConns()
		srv.mu.RLock()
		s.Dropped = srv.retiredDropped
		for _, session := range srv.activeClients {
			session.sessionMu.RLock()
			s.LiveConns += session.ActiveConns
			s.Dropped += session.Port.Dropped()
			session.sessionMu.RUnlock()
		}
		srv.mu.RUnlock()
		s.Fec.Recovered = srv.fecLifetime.recovered.Load()
		s.Fec.Lost = srv.fecLifetime.lost.Load()
		s.Fec.setWritten(srv.written.snapshot())
		s.TapErrors = srv.tapWriteErrs.Load()
	} else if cli := w.cli; cli != nil {
		s.Mode = "client"
		s.Conns = cli.snapshotConns()
		s.LiveConns = int(atomic.LoadInt32(&cli.liveConns))
		if cli.txPort != nil {
			s.Dropped = cli.txPort.Dropped()
			s.Fec.setWritten(cli.txPort.written.snapshot())
		}
		s.Fec.Recovered, s.Fec.Lost = cli.FECStats()
		s.TapErrors = cli.tapWriteErrs.Load()
		s.ReconnectAttempts = cli.ReconnectAttempts()
	}
	w.diagnostics.record(s)
}
