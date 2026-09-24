package main

import (
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
)

func TestTLSClientHelloFingerprintStableAcrossGREASE(t *testing.T) {
	want := tlsClientHelloFingerprint(
		[]uint16{0x1301, 0x1302, 0xc02f},
		[]uint16{0x0804, 0x0403},
		[]uint16{0x001d, 0x0017},
		[]string{"h2", "http/1.1"},
	)
	got := tlsClientHelloFingerprint(
		[]uint16{0x0a0a, 0x1301, 0x1302, 0xc02f, 0xfafa},
		[]uint16{0x0804, 0x2a2a, 0x0403},
		[]uint16{0x1a1a, 0x001d, 0x0017},
		[]string{"h2", "http/1.1"},
	)
	if got != want {
		t.Fatalf("GREASE changed fingerprint: got %s want %s", got, want)
	}
	if len(got) != 64 {
		t.Fatalf("fingerprint length = %d, want 64 hex chars", len(got))
	}
}

func TestTLSClientHelloFingerprintKeepsOpaqueALPNBytes(t *testing.T) {
	raw := tlsClientHelloFingerprint([]uint16{0x1301}, nil, nil, []string{string([]byte{0xff, 0x00})})
	replacement := tlsClientHelloFingerprint([]uint16{0x1301}, nil, nil, []string{"\uFFFD\x00"})
	if raw == replacement {
		t.Fatal("opaque ALPN bytes collapsed through UTF-8 replacement")
	}
	if got := displayTLSALPNs([]string{string([]byte{0xff, 0x00})}); len(got) != 1 || got[0] != "hex:ff00" {
		t.Fatalf("opaque ALPN display = %v, want [hex:ff00]", got)
	}
}

func TestTLSHandshakeInfoUsesServerObservedState(t *testing.T) {
	hello := tlsClientHelloObservation{
		cipherSuites: []uint16{0x1301, 0x1302}, signatureSchemes: []uint16{0x0804},
		groups: []uint16{0x001d}, alpn: []string{"h2", "http/1.1"}, sni: "example.com",
	}
	hello.fingerprint = tlsClientHelloFingerprint(hello.cipherSuites, hello.signatureSchemes, hello.groups, hello.alpn)
	info := tlsHandshakeInfoFromState(tls.ConnectionState{
		Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2", ServerName: "WWW.Example.COM.",
	}, hello)
	if info.Version != "TLS 1.3" || info.VersionID != tls.VersionTLS13 {
		t.Fatalf("version = %q/%#x", info.Version, info.VersionID)
	}
	if info.CipherSuite != "TLS_AES_128_GCM_SHA256" || info.CipherSuiteID != 0x1301 {
		t.Fatalf("cipher = %q/%#x", info.CipherSuite, info.CipherSuiteID)
	}
	if info.SNI != "www.example.com" || info.ALPN != "h2" {
		t.Fatalf("SNI/ALPN = %q/%q", info.SNI, info.ALPN)
	}
}

func TestHandshakeRespTLSIsOptionalAndBoundedToPublicSummary(t *testing.T) {
	without, err := json.Marshal(HandshakeResp{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(without), `"tls"`) {
		t.Fatalf("empty response unexpectedly contains tls: %s", without)
	}
	with, err := json.Marshal(HandshakeResp{TLS: fullTLSInfoSample()})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"client_random", "server_random", "session_ticket", "private_key", "master_secret", "certificate_der"} {
		if strings.Contains(string(with), forbidden) {
			t.Fatalf("TLS summary leaked forbidden field %q: %s", forbidden, with)
		}
	}
}

func TestHandshakeTLSRollingUpgradeCompatibility(t *testing.T) {
	// old writer -> new reader：旧服务端没有 tls 字段，新客户端必须照常上线。
	oldWire := []byte(`{"success":true,"message":"OK","client_id":"c","ipv4":"10.0.0.2/24","ipv6":"fd00::2/80"}`)
	var current HandshakeResp
	if err := json.Unmarshal(oldWire, &current); err != nil {
		t.Fatalf("new reader rejected old response: %v", err)
	}
	if current.TLS != nil {
		t.Fatalf("old response produced unexpected TLS summary: %+v", current.TLS)
	}

	// new writer -> old reader：Go JSON 默认忽略未知字段，旧客户端不得因 tls 扩展断线。
	newWire, err := json.Marshal(HandshakeResp{
		Success: true, Message: "OK", ClientID: "c", IPv4: "10.0.0.2/24", IPv6: "fd00::2/80",
		TLS: fullTLSInfoSample(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var legacy struct {
		Success  bool   `json:"success"`
		Message  string `json:"message"`
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(newWire, &legacy); err != nil {
		t.Fatalf("old reader rejected new response: %v", err)
	}
	if !legacy.Success || legacy.ClientID != "c" {
		t.Fatalf("legacy reader lost required fields: %+v", legacy)
	}
}
