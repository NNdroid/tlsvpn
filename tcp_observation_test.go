package main

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestWebTCPRetransDeltaAndAttemptIdentity(t *testing.T) {
	old := newTCPSnapshot(nil, false)
	old.SampleTimeMs = 1000
	old.Values["total_retrans"] = uint64(8)
	now := newTCPSnapshot(nil, false)
	now.SampleTimeMs = 3000
	now.Values["total_retrans"] = uint64(11)
	addTCPRetransDelta(now, old)
	if now.Values["retrans_delta"] != uint64(3) || now.Values["retrans_interval_ms"] != int64(2000) {
		t.Fatalf("bad retrans delta: %+v", now.Values)
	}
	rollback := newTCPSnapshot(nil, false)
	rollback.SampleTimeMs = 4000
	rollback.Values["total_retrans"] = uint64(1)
	addTCPRetransDelta(rollback, now)
	if _, ok := rollback.Values["retrans_delta"]; ok {
		t.Fatal("rollback fabricated retransmissions")
	}
	ci := &clientConnInfo{target: "old"}
	ci.state.Store("up")
	ci.tcpObservation.Store(now)
	c := &Client{connsCount: 1, conns: map[int]*clientConnInfo{0: ci}}
	if c.snapshotConns()[0].TCP != now {
		t.Fatal("kernel cache not exposed")
	}
	ci.state.Store("retrying")
	if c.snapshotConns()[0].TCP != nil {
		t.Fatal("disconnected socket still presented as current")
	}
	replacement := c.beginConnAttempt(0, "new")
	replacement.state.Store("up")
	if c.snapshotConns()[0].TCP != nil {
		t.Fatal("replacement inherited prior attempt socket")
	}
}

func TestWebTCPProxyObservationPreservesTransport(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		greeting := make([]byte, 3)
		if _, err = io.ReadFull(conn, greeting); err != nil {
			return
		}
		conn.Write([]byte{5, 0})
		request := make([]byte, 4)
		if _, err = io.ReadFull(conn, request); err != nil {
			return
		}
		switch request[3] {
		case 1:
			request = make([]byte, 6)
		case 3:
			n := []byte{0}
			if _, err = io.ReadFull(conn, n); err != nil {
				return
			}
			request = make([]byte, int(n[0])+2)
		case 4:
			request = make([]byte, 18)
		default:
			return
		}
		if _, err = io.ReadFull(conn, request); err != nil {
			return
		}
		conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
		data := make([]byte, 4)
		if _, err = io.ReadFull(conn, data); err == nil {
			conn.Write(data)
		}
	}()
	previousDialer, previousAddr := globalDialer, globalSocks5Addr
	defer func() { globalDialer, globalSocks5Addr = previousDialer, previousAddr }()
	if err = initGlobalProxy(listener.Addr().String(), 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialContext(ctx, "tcp", "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	observed, ok := conn.(*observedProxyTransport)
	if !ok || observed.tcp == nil {
		t.Fatal("SOCKS local socket not captured")
	}
	if observed.tcp.RemoteAddr().String() != listener.Addr().String() {
		t.Fatal("proxy socket incorrectly identified as VPN endpoint")
	}
	if underlyingTCPConn(conn) != nil {
		t.Fatal("observation unexpectedly changed the existing proxy tuning behavior")
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 4)
	if _, err = io.ReadFull(conn, data); err != nil || string(data) != "ping" {
		t.Fatalf("proxy transport changed: %q %v", data, err)
	}
	wg.Wait()
}
