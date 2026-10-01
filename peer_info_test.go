package main

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPeerInfoOptionalV3Handshake(t *testing.T) {
	raw := []byte(`{"protocol_version":3,"client_id":"x","psk":"y"}`)
	var req HandshakeReq
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	if req.PeerInfo != nil {
		t.Fatalf("v3 handshake without metadata unexpectedly has peer info: %+v", req.PeerInfo)
	}
	req.PeerInfo = &PeerInfo{Implementation: "go", Hostname: "node-a", OS: "linux", Arch: "arm64", Version: "v1"}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var round HandshakeReq
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	if round.PeerInfo == nil || round.PeerInfo.Hostname != "node-a" || round.PeerInfo.Arch != "arm64" {
		t.Fatalf("peer info lost: %+v", round.PeerInfo)
	}
}

func TestNormalizePeerInfoBoundsUntrustedFields(t *testing.T) {
	in := &PeerInfo{Hostname: "  host  ", OSVersion: strings.Repeat("x", peerInfoFieldMax+100)}
	got := normalizePeerInfo(in)
	if got.Hostname != "host" {
		t.Fatalf("hostname=%q", got.Hostname)
	}
	if len(got.OSVersion) != peerInfoFieldMax {
		t.Fatalf("os_version len=%d", len(got.OSVersion))
	}
}

func TestNormalizePeerInfoPreservesUTF8WhenTruncated(t *testing.T) {
	in := &PeerInfo{OSVersion: strings.Repeat("界", 200)}
	got := normalizePeerInfo(in)
	if len(got.OSVersion) > peerInfoFieldMax {
		t.Fatalf("os_version exceeds bound: %d", len(got.OSVersion))
	}
	if !utf8.ValidString(got.OSVersion) {
		t.Fatalf("os_version is invalid UTF-8 after truncation: %q", got.OSVersion)
	}
}

func TestLocalPeerInfoHasStableCoreFields(t *testing.T) {
	p := localPeerInfo()
	if p == nil || p.Implementation != "go" || p.OS == "" || p.Arch == "" || p.Version == "" {
		t.Fatalf("incomplete local peer info: %+v", p)
	}
}
