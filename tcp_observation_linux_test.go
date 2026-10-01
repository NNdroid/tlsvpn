//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestWebTCPLinuxSocketReadsActualValues(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	peer.Write([]byte("sample"))
	data := make([]byte, 6)
	if _, err = conn.Read(data); err != nil {
		t.Fatal(err)
	}
	if err = conn.SetNoDelay(false); err != nil {
		t.Fatal(err)
	}
	if err = conn.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 21 * time.Second, Interval: 7 * time.Second, Count: 4}); err != nil {
		t.Fatal(err)
	}
	conn.SetWriteBuffer(65536)
	first := readTCPSocketSnapshot(conn, false)
	for key, want := range map[string]interface{}{"nodelay": false, "keepalive": true, "keepidle_sec": 21, "keepintvl_sec": 7, "keepcnt": 4, "state": "ESTABLISHED"} {
		if first.Values[key] != want {
			t.Fatalf("%s=%v want %v, unavailable=%v", key, first.Values[key], want, first.Unavailable)
		}
	}
	if first.Source != "linux_socket" || first.Peer != listener.Addr().String() || first.Values["mss_bytes"] == nil || first.Values["congestion"] == nil {
		t.Fatalf("socket facts missing: %+v", first)
	}
	if err = conn.SetNoDelay(true); err != nil {
		t.Fatal(err)
	}
	raw, _ := conn.SyscallConn()
	var setErr error
	raw.Control(func(fd uintptr) { setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_CORK, 1) })
	if setErr != nil {
		t.Fatal(setErr)
	}
	second := readTCPSocketSnapshot(conn, true)
	if second.Values["nodelay"] != true || second.Values["cork"] != true || second.Scope != "local_to_proxy" {
		t.Fatalf("actual option changes not read: %+v", second)
	}
	raw.Control(func(fd uintptr) { unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_CORK, 0) })
	sci := &connInfo{connID: "server-physical", tcpConn: peer, remote: peer.RemoteAddr().String(), linkedAt: time.Now().Unix()}
	srv := &Server{activeClients: map[string]*ClientSession{"client": {conns: map[*connInfo]struct{}{sci: {}}}}}
	(&WebManager{srv: srv}).sampleTCPObservations()
	if rows := srv.snapshotServerConns(); len(rows) != 1 || rows[0].TCP == nil || rows[0].TCP.Values["state"] != "ESTABLISHED" {
		t.Fatalf("server socket not exposed: %+v", rows)
	}
	ci := &clientConnInfo{target: "test"}
	ci.state.Store("up")
	ci.observedTCP.Store(conn)
	client := &Client{connsCount: 1, conns: map[int]*clientConnInfo{0: ci}}
	mgr := &WebManager{cli: client}
	mgr.sampleTCPObservations()
	if got := client.snapshotConns()[0].TCP; got == nil || got.Values["nodelay"] != true {
		t.Fatal("background sampler did not expose actual socket")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			mgr.sampleTCPObservations()
		}
	}()
	conn.Close()
	for i := 0; i < 50; i++ {
		client.snapshotConns()
	}
	wg.Wait()
	closed := readTCPSocketSnapshot(conn, false)
	if len(closed.Values) != 0 || closed.Unavailable["socket"] == "" {
		t.Fatalf("closed fd reused/stale: %+v", closed)
	}
}

func TestWebTCPOlderKernelLengthsDoNotInventValues(t *testing.T) {
	var info unix.TCPInfo
	b := make([]byte, 104)
	b[0] = 1
	b[5] = 3
	binary.NativeEndian.PutUint32(b[int(unsafe.Offsetof(info.Total_retrans)):], 7)
	s := newTCPSnapshot(nil, false)
	decodeTCPInfo(s, b)
	if s.Values["total_retrans"] != uint64(7) || s.Values["sack"] != true || s.Values["ecn"] != false {
		t.Fatalf("base fields incorrectly decoded: %+v", s)
	}
	for _, key := range []string{"notsent_bytes", "delivery_rate_Bps", "pacing_rate_Bps", "snd_wnd_bytes"} {
		if _, ok := s.Values[key]; ok || s.Unavailable[key] != "unsupported_short_tcp_info" {
			t.Fatalf("%s fabricated on short kernel response", key)
		}
	}
	for n := 0; n < 104; n++ {
		decodeTCPInfo(newTCPSnapshot(nil, false), b[:n])
	}
}
