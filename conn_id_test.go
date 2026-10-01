package main

import (
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHandshakeConnIDWire(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	b, err := json.Marshal(HandshakeReq{ClientID: "c", PSK: "p", ConnID: id})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if got := m["conn_id"]; got != id {
		t.Fatalf("conn_id = %v, want %s", got, id)
	}

}

func TestClientSnapshotCarriesConnID(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000002"
	ci := &clientConnInfo{target: "example:443", rttCache: new(uint32)}
	ci.connID.Store(id)
	ci.state.Store("up")
	ci.remote.Store("127.0.0.1:443")
	c := &Client{connsCount: 1, conns: map[int]*clientConnInfo{0: ci}}
	got := c.snapshotConns()
	if len(got) != 1 || got[0].ConnID != id {
		t.Fatalf("client snapshot = %+v, want conn_id %s", got, id)
	}
}

func TestServerSnapshotCarriesConnID(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000003"
	rtt := uint32(0)
	ci := &connInfo{connID: id, remote: "127.0.0.1:12345", rttCache: &rtt, linkedAt: time.Now().Unix()}
	sess := &ClientSession{conns: map[*connInfo]struct{}{ci: {}}}
	s := &Server{activeClients: map[string]*ClientSession{"client-a": sess}}
	got := s.snapshotServerConns()
	if len(got) != 1 || got[0].ConnID != id {
		t.Fatalf("server snapshot = %+v, want conn_id %s", got, id)
	}
}

func TestConnIDGenerationIsUniqueUUID(t *testing.T) {
	a := uuid.New().String()
	b := uuid.New().String()
	if a == b {
		t.Fatalf("generated duplicate conn IDs: %s", a)
	}
	if _, err := uuid.Parse(a); err != nil {
		t.Fatalf("generated conn ID is not a UUID: %v", err)
	}
	var v atomic.Value
	v.Store(a)
	if got, _ := v.Load().(string); got != a {
		t.Fatalf("stored conn ID = %q, want %q", got, a)
	}
}
