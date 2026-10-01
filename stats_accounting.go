package main

import (
	"sync"
	"sync/atomic"
)

// Application wire bytes include VPN headers, inner AEAD tags and cover padding,
// but exclude heartbeat records and outer TLS/TCP/IP overhead.
type txFrameTotals struct {
	DataFrames, ParityFrames, ControlFrames uint64
	DataWireBytes, ParityWireBytes          uint64
}

func (s *txFrameTotals) add(v VPNFrame, wire int) {
	if v.Seq != 0 {
		s.DataFrames++
		s.DataWireBytes += uint64(wire)
	} else if len(v.Data) > 0 && v.Data[0] == controlKindFECParity {
		s.ParityFrames++
		s.ParityWireBytes += uint64(wire)
	} else {
		s.ControlFrames++
	}
}

type txFrameCounters struct {
	mu                                      sync.Mutex
	dataFrames, parityFrames, controlFrames atomic.Uint64
	dataWireBytes, parityWireBytes          atomic.Uint64
}

func (c *txFrameCounters) record(s txFrameTotals) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dataFrames.Add(s.DataFrames)
	c.parityFrames.Add(s.ParityFrames)
	c.controlFrames.Add(s.ControlFrames)
	c.dataWireBytes.Add(s.DataWireBytes)
	c.parityWireBytes.Add(s.ParityWireBytes)
}
func (c *txFrameCounters) snapshot() txFrameTotals {
	c.mu.Lock()
	defer c.mu.Unlock()
	return txFrameTotals{c.dataFrames.Load(), c.parityFrames.Load(), c.controlFrames.Load(), c.dataWireBytes.Load(), c.parityWireBytes.Load()}
}
func (f *fecStatsJSON) setWritten(s txFrameTotals) {
	f.ParityTx = s.ParityFrames
	f.DataTx = s.DataFrames
	f.ControlTx = s.ControlFrames
	f.DataWireBytes = s.DataWireBytes
	f.ParityWireBytes = s.ParityWireBytes
	f.CounterDomain = "written"
}
func (d *fecDecoder) bypassSnapshot() bool {
	if d == nil {
		return false
	}
	from, until := unpackFECBypassWindow(d.fence.window.Load())
	return d.staticSingle.Load() || (from != 0 && until == 0)
}

// Lifetime counters survive decoder rebuilds and retired sessions.
type fecLifetimeCounters struct{ recovered, lost atomic.Uint64 }

type retiredTrafficSession struct {
	id      string
	session *ClientSession
}

func (s *Server) installTrafficAccounting(t *TrafficAccounting) {
	s.collectClientTraffic.Store(true)
	t.SetRTTSampler(s.avgRTT)
	t.SetClientDeltaSampler(s.sampleClientTraffic)
}
