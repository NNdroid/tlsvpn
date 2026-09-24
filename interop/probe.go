// Command probe is a self-contained protocol-v2 interoperability client.
// It intentionally does not import the main package, so it can detect wire
// incompatibilities instead of sharing the implementation under test.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // UUID v3 is required to reproduce the established client-id namespace.
	"crypto/rand"
	"crypto/sha1" // UUID v5 is required by the established client-id derivation.
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const (
	headerSize = 10
	gcmTagSize = 16
)

type handshakeReq struct {
	ProtocolVersion int    `json:"protocol_version"`
	ClientInstance  string `json:"client_instance"`
	ClientID        string `json:"client_id"`
	PSK             string `json:"psk"`
	MAC             string `json:"mac"`
	IPv4            string `json:"ipv4,omitempty"`
	Encrypt         bool   `json:"encrypt"`
	EncAlgo         int    `json:"enc_algo"`
	BrutalGroups    bool   `json:"brutal_groups,omitempty"`
	BrutalTotalTx   uint64 `json:"brutal_total_tx,omitempty"`
	BrutalTotalRx   uint64 `json:"brutal_total_rx,omitempty"`
	BrutalConns     int    `json:"brutal_conns,omitempty"`
	BrutalConnIndex int    `json:"brutal_conn_index,omitempty"`
}

type handshakeResp struct {
	ProtocolVersion int               `json:"protocol_version"`
	SessionEpoch    uint64            `json:"session_epoch"`
	Success         bool              `json:"success"`
	Message         string            `json:"message"`
	SessionID       string            `json:"session_id"`
	IPv4            string            `json:"ipv4"`
	Encrypt         bool              `json:"encrypt"`
	EncAlgo         int               `json:"enc_algo"`
	EncSalt         string            `json:"enc_salt"`
	EncSalt2        string            `json:"enc_salt2"`
	TLS             *tlsHandshakeInfo `json:"tls"`
}

type tlsHandshakeInfo struct {
	FingerprintKind         string   `json:"fingerprint_kind"`
	FingerprintSHA256       string   `json:"fingerprint_sha256"`
	VersionID               uint16   `json:"version_id"`
	CipherSuiteID           uint16   `json:"cipher_suite_id"`
	ALPN                    string   `json:"alpn"`
	SNI                     string   `json:"sni"`
	OfferedCipherSuites     []uint16 `json:"offered_cipher_suites"`
	OfferedSignatureSchemes []uint16 `json:"offered_signature_schemes"`
	OfferedGroups           []uint16 `json:"offered_groups"`
	OfferedALPN             []string `json:"offered_alpn"`
}

type recordScanner struct {
	buf []byte
}

func (s *recordScanner) read(r net.Conn, deadline time.Time) ([]byte, uint32, error) {
	tmp := make([]byte, 16*1024)
	for {
		if len(s.buf) >= headerSize {
			dataLen := uint64(binary.BigEndian.Uint32(s.buf[:4]))
			padLen := uint64(binary.BigEndian.Uint16(s.buf[4:6]))
			total := uint64(headerSize) + dataLen + padLen
			if total > 128*1024+headerSize {
				return nil, 0, fmt.Errorf("record too large: %d", total)
			}
			if uint64(len(s.buf)) >= total {
				seq := binary.BigEndian.Uint32(s.buf[6:10])
				body := append([]byte(nil), s.buf[10:10+int(dataLen)]...)
				s.buf = append(s.buf[:0], s.buf[int(total):]...)
				return body, seq, nil
			}
		}
		if err := r.SetReadDeadline(deadline); err != nil {
			return nil, 0, err
		}
		n, err := r.Read(tmp)
		if n > 0 {
			s.buf = append(s.buf, tmp[:n]...)
			continue
		}
		if err != nil {
			return nil, 0, err
		}
	}
}

type probeCipher struct {
	aead cipher.AEAD
	salt [8]byte
}

func newProbeCipher(psk string, salt []byte, algo int) (*probeCipher, error) {
	if len(salt) != 8 {
		return nil, fmt.Errorf("bad salt length %d", len(salt))
	}
	label := "_enc_key"
	if algo == 3 {
		label = "_enc_key_gcm_v2"
	}
	key := sha256.Sum256([]byte(psk + label))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pc := &probeCipher{aead: aead}
	copy(pc.salt[:], salt)
	return pc, nil
}

func (c *probeCipher) nonce(seq uint32) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n[:4], seq)
	copy(n[4:], c.salt[:])
	return n
}

func record(seq uint32, plain []byte, c *probeCipher) []byte {
	wireLen := len(plain)
	if c != nil && seq != 0 && len(plain) > 0 {
		wireLen += gcmTagSize
	}
	const padLen = 100
	out := make([]byte, headerSize+wireLen+padLen)
	binary.BigEndian.PutUint32(out[:4], uint32(wireLen))
	binary.BigEndian.PutUint16(out[4:6], padLen)
	binary.BigEndian.PutUint32(out[6:10], seq)
	if c == nil || seq == 0 || len(plain) == 0 {
		copy(out[10:], plain)
	} else {
		var aad [8]byte
		binary.BigEndian.PutUint32(aad[:4], uint32(wireLen))
		binary.BigEndian.PutUint32(aad[4:], seq)
		sealed := c.aead.Seal(out[10:10], c.nonce(seq), plain, aad[:])
		if len(sealed) != wireLen {
			panic("unexpected GCM length")
		}
	}
	for i := headerSize + wireLen; i < len(out); i++ {
		out[i] = byte(i)
	}
	return out
}

func uuidFromHash(sum []byte, version byte) [16]byte {
	var id [16]byte
	copy(id[:], sum[:16])
	id[6] = (id[6] & 0x0f) | version<<4
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}

func uuidBytes(s string) [16]byte {
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(raw) != 16 {
		panic("invalid UUID constant")
	}
	var id [16]byte
	copy(id[:], raw)
	return id
}

func namedUUID(namespace [16]byte, name string, version byte) [16]byte {
	input := append(namespace[:0:0], namespace[:]...)
	input = append(input, name...)
	if version == 3 {
		sum := md5.Sum(input)
		return uuidFromHash(sum[:], version)
	}
	sum := sha1.Sum(input)
	return uuidFromHash(sum[:], version)
}

func formatUUID(id [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

func clientID(mac, psk string) string {
	urlNS := uuidBytes("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
	ns := namedUUID(urlNS, "my_vpn_tunnel", 3)
	return formatUUID(namedUUID(ns, strings.ToLower(mac)+psk, 5))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:4400", "server address")
	psk := flag.String("psk", "e2e_secret", "pre-shared key")
	mac := flag.String("mac", "aa:bb:cc:dd:ee:ff", "client MAC")
	sni := flag.String("sni", "www.cloudflare.com", "TLS server name sent in ClientHello")
	sendN := flag.Int("send", 8, "number of encrypted data records")
	timeoutSec := flag.Int("timeout", 10, "overall timeout in seconds")
	encAlgo := flag.Int("enc-algo", 2, "declared inner encryption algorithm")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
	defer cancel()
	d := &tls.Dialer{Config: &tls.Config{ // Test-only probe; production clients must verify or pin the certificate.
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         *sni,
		NextProtos:         []string{"h2", "http/1.1"},
	}}
	connRaw, err := d.DialContext(ctx, "tcp", *addr)
	if err != nil {
		fatalf("dial: %v", err)
	}
	defer connRaw.Close()
	conn := connRaw.(*tls.Conn)

	var instance [16]byte
	if _, err := io.ReadFull(rand.Reader, instance[:]); err != nil {
		fatalf("random client instance: %v", err)
	}
	pskHash := sha256.Sum256([]byte(*psk))
	req := handshakeReq{
		ProtocolVersion: 2,
		ClientInstance:  hex.EncodeToString(instance[:]),
		ClientID:        clientID(*mac, *psk),
		PSK:             hex.EncodeToString(pskHash[:]),
		MAC:             strings.ToLower(*mac),
		IPv4:            "10.7.0.77",
		Encrypt:         true,
		EncAlgo:         *encAlgo,
		BrutalGroups:    true,
		BrutalTotalTx:   100,
		BrutalTotalRx:   500,
		BrutalConns:     1,
		BrutalConnIndex: 0,
	}
	reqJSON, err := json.Marshal(req)
	if err != nil {
		fatalf("marshal handshake: %v", err)
	}
	if _, err := conn.Write(record(0, reqJSON, nil)); err != nil {
		fatalf("write handshake: %v", err)
	}

	scanner := &recordScanner{buf: make([]byte, 0, 64*1024)}
	body, seq, err := scanner.read(conn, time.Now().Add(5*time.Second))
	if err != nil {
		fatalf("read handshake: %v", err)
	}
	var resp handshakeResp
	if err := json.Unmarshal(body, &resp); err != nil {
		fatalf("decode handshake: %v", err)
	}
	if !resp.Success {
		fatalf("handshake rejected: %s", resp.Message)
	}
	if resp.ProtocolVersion != 2 || resp.SessionEpoch == 0 {
		fatalf("server lacks protocol-v2 key epochs: version=%d epoch=%d", resp.ProtocolVersion, resp.SessionEpoch)
	}
	if resp.TLS == nil {
		fatalf("server did not return server-observed TLS summary")
	}
	state := conn.ConnectionState()
	if resp.TLS.FingerprintKind != "tls-clienthello-v1" || len(resp.TLS.FingerprintSHA256) != 64 {
		fatalf("invalid TLS fingerprint metadata: kind=%q sha256=%q", resp.TLS.FingerprintKind, resp.TLS.FingerprintSHA256)
	}
	if resp.TLS.VersionID != state.Version || resp.TLS.CipherSuiteID != state.CipherSuite ||
		resp.TLS.ALPN != state.NegotiatedProtocol || !strings.EqualFold(resp.TLS.SNI, *sni) {
		fatalf("server-observed TLS negotiation mismatch: server=%+v local={version=%#x cipher=%#x alpn=%q sni=%q}",
			*resp.TLS, state.Version, state.CipherSuite, state.NegotiatedProtocol, *sni)
	}
	if len(resp.TLS.OfferedCipherSuites) == 0 || len(resp.TLS.OfferedSignatureSchemes) == 0 || len(resp.TLS.OfferedGroups) == 0 || len(resp.TLS.OfferedALPN) == 0 {
		fatalf("server returned incomplete ClientHello feature lists: %+v", *resp.TLS)
	}
	if !resp.Encrypt || (resp.EncAlgo != 2 && resp.EncAlgo != 3) {
		fatalf("unexpected encryption negotiation: enabled=%v algo=%d", resp.Encrypt, resp.EncAlgo)
	}
	salt, err := hex.DecodeString(resp.EncSalt)
	if err != nil {
		fatalf("decode c2s salt: %v", err)
	}
	tx, err := newProbeCipher(*psk, salt, resp.EncAlgo)
	if err != nil {
		fatalf("create c2s cipher: %v", err)
	}

	for i := 0; i < *sendN; i++ {
		payload := []byte(fmt.Sprintf("PROBE-DATA-GO-%04d", i))
		if _, err := conn.Write(record(uint32(i+1), payload, tx)); err != nil {
			fatalf("write data: %v", err)
		}
	}

	deadline := time.Now().Add(time.Duration(*timeoutSec) * time.Second)
	for time.Now().Before(deadline) {
		body, seq, err = scanner.read(conn, deadline)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}
			fatalf("read data: %v", err)
		}
		if seq == 0 && len(body) == 0 {
			fmt.Printf("PASS protocol=2 epoch=%d algo=%d session=%s ipv4=%s tls=%s:%s\n", resp.SessionEpoch, resp.EncAlgo, resp.SessionID, resp.IPv4, resp.TLS.FingerprintKind, resp.TLS.FingerprintSHA256)
			return
		}
		if seq != 0 && bytes.HasPrefix(body, []byte("FAIL")) {
			fatalf("server returned failure data")
		}
	}
	fatalf("no server heartbeat before timeout")
}
