package main

import (
	"net"
	"runtime"
	"sync/atomic"
	"time"
)

// Values are observations of this socket, never desired settings from Config.
// Missing fields have a reason; zero and false are valid observed values.
type tcpSocketSnapshot struct {
	Source       string                 `json:"source"`
	Scope        string                 `json:"scope"`
	SampleTimeMs int64                  `json:"sample_time_ms"`
	Peer         string                 `json:"peer,omitempty"`
	Values       map[string]interface{} `json:"values"`
	Unavailable  map[string]string      `json:"unavailable"`
}

func newTCPSnapshot(conn *net.TCPConn, proxy bool) *tcpSocketSnapshot {
	scope := "local_tcp"
	if proxy {
		scope = "local_to_proxy"
	}
	s := &tcpSocketSnapshot{Source: runtime.GOOS + "_socket", Scope: scope, SampleTimeMs: time.Now().UnixMilli(), Values: map[string]interface{}{}, Unavailable: map[string]string{}}
	if conn != nil {
		s.Peer = conn.RemoteAddr().String()
	}
	return s
}
func addTCPRetransDelta(now, previous *tcpSocketSnapshot) {
	if previous == nil || now.SampleTimeMs <= previous.SampleTimeMs || now.SampleTimeMs-previous.SampleTimeMs > 10000 {
		return
	}
	current, ok := now.Values["total_retrans"].(uint64)
	old, oldOK := previous.Values["total_retrans"].(uint64)
	if ok && oldOK && current >= old {
		now.Values["retrans_delta"] = current - old
		now.Values["retrans_interval_ms"] = now.SampleTimeMs - previous.SampleTimeMs
	}
}

// Copy ownership handles under the registry locks, then perform syscalls without
// session/connection locks. Go RawConn.Control protects against concurrent close
// and descriptor reuse; snapshots remain attached to this physical attempt.
func (w *WebManager) sampleTCPObservations() {
	type target struct {
		conn  *net.TCPConn
		proxy bool
		cache *atomic.Pointer[tcpSocketSnapshot]
	}
	targets := []target{}
	if c := w.cli; c != nil {
		c.connsMu.Lock()
		for _, ci := range c.conns {
			state, _ := ci.state.Load().(string)
			if state == "up" {
				targets = append(targets, target{ci.observedTCP.Load(), ci.observedProxy.Load(), &ci.tcpObservation})
			}
		}
		c.connsMu.Unlock()
	}
	if s := w.srv; s != nil {
		s.mu.RLock()
		for _, session := range s.activeClients {
			session.sessionMu.RLock()
			for ci := range session.conns {
				targets = append(targets, target{ci.tcpConn, false, &ci.tcpObservation})
			}
			session.sessionMu.RUnlock()
		}
		s.mu.RUnlock()
	}
	for _, t := range targets {
		sample := readTCPSocketSnapshot(t.conn, t.proxy)
		addTCPRetransDelta(sample, t.cache.Load())
		t.cache.Store(sample)
	}
}
