package main

import (
	"context"
	"math"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestRandomSessionTokensAreUniqueAndExact(t *testing.T) {
	a, err := newSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(a) != 64 || len(b) != 64 {
		t.Fatalf("session tokens must be independent 256-bit hex values: %q %q", a, b)
	}
	if !verifyRandomSessionToken(a, a) || verifyRandomSessionToken(a, b) || verifyRandomSessionToken(a, "") {
		t.Fatal("random session-token comparison contract failed")
	}
}

func TestAsyncPortSequenceNeverWraps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := NewAsyncPort(ctx, "sequence-test", false)
	atomic.StoreUint32(&p.txSeq, math.MaxUint32-1)
	var exhausted atomic.Int32
	p.SetSequenceExhaustedHandler(func() { exhausted.Add(1) })
	seq, ok := p.nextSeq()
	if !ok || seq != math.MaxUint32 {
		t.Fatalf("last legal sequence = %d,%v; want %d,true", seq, ok, uint32(math.MaxUint32))
	}
	if seq, ok = p.nextSeq(); ok || seq != 0 {
		t.Fatalf("exhausted sequence must stop instead of wrapping: %d,%v", seq, ok)
	}
	_, _ = p.nextSeq()
	deadline := time.Now().Add(time.Second)
	for exhausted.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := exhausted.Load(); got != 1 {
		t.Fatalf("exhaustion callback count = %d, want 1", got)
	}
}

func TestForceReconnectClosesEveryActiveConnection(t *testing.T) {
	c := &Client{wake: make(chan struct{}, 1), conns: make(map[int]*clientConnInfo)}
	peers := make([]net.Conn, 0, 3)
	for i := 0; i < 3; i++ {
		local, peer := net.Pipe()
		ci := &clientConnInfo{}
		ci.conn.Store(connHolder{c: local})
		c.conns[i] = ci
		peers = append(peers, peer)
		defer peer.Close()
	}
	c.ForceReconnect()
	if got := atomic.LoadUint64(&c.forceGen); got != 1 {
		t.Fatalf("force generation = %d, want 1", got)
	}
	for i, peer := range peers {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		var one [1]byte
		if _, err := peer.Read(one[:]); err == nil {
			t.Fatalf("connection %d remained open", i)
		}
	}
}

func TestReplaySequenceIsDeliveredOnlyOnce(t *testing.T) {
	delivered := make(chan []byte, 2)
	rb := NewReorderBuffer(func(frame []byte) {
		delivered <- append([]byte(nil), frame...)
	})
	defer rb.Close()
	first := getFrame()[:1]
	first[0] = 0x41
	rb.Insert(42, first)
	select {
	case got := <-delivered:
		if len(got) != 1 || got[0] != 0x41 {
			t.Fatalf("unexpected first delivery: %x", got)
		}
	case <-time.After(time.Second):
		t.Fatal("first packet was not delivered")
	}
	replay := getFrame()[:1]
	replay[0] = 0x42
	rb.Insert(42, replay)
	select {
	case got := <-delivered:
		t.Fatalf("authenticated replay was delivered twice: %x", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestDestroySessionPointerGuardPreventsABARemoval(t *testing.T) {
	oldSession := &ClientSession{SessionID: "old"}
	newSession := &ClientSession{SessionID: "new"}
	s := &Server{activeClients: map[string]*ClientSession{"client": newSession}}
	s.destroySessionLocked(oldSession, "client")
	if got := s.activeClients["client"]; got != newSession {
		t.Fatal("stale destroy timer removed a newer session with the same client ID")
	}
}

func TestKickDestroysLogicalSessionInsteadOfLeavingReusableState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := NewAsyncPort(ctx, "client", false)
	reorder := NewReorderBuffer(func([]byte) {})
	session := &ClientSession{
		SessionID: "session", Port: port, IPv4: "10.0.0.2", IPv6: "fd00::2",
		MAC: "02:00:00:00:00:02", RxReorder: reorder, conns: make(map[*connInfo]struct{}),
	}
	s := &Server{
		activeClients: map[string]*ClientSession{"client": session},
		usedV4:        map[string]bool{"10.0.0.2": true}, usedV6: map[string]bool{"fd00::2": true},
		macToIP: map[string]MacBinding{"02:00:00:00:00:02": {IPv4: "10.0.0.2", IPv6: "fd00::2"}},
		vswitch: NewVSwitch(),
	}
	s.vswitch.AddPort(port)
	s.kickSession(session)
	if _, ok := s.activeClients["client"]; ok {
		t.Fatal("kick left the logical session reusable")
	}
	if s.usedV4["10.0.0.2"] || s.usedV6["fd00::2"] {
		t.Fatal("kick did not release tunnel addresses")
	}
}
