package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// updateGolden 控制是否重写黄金向量文件
var updateGolden = flag.Bool("update-golden", false, "重新生成协议黄金向量文件")

// ==========================================
// 跨语言协议一致性：黄金向量 (Golden Vectors)
// ==========================================
//
// 目的：Go 与 Rust 两套实现必须能互通。协议层任何不一致（字段名、字节序、
// 密钥派生、帧布局）都会导致两端无法通信，且这类问题在单元测试里很难暴露。
//
// 做法：由 Go 侧生成一份与语言无关的 JSON 黄金向量文件，Rust 侧读取同一份文件
// 做比对。任一端改动协议导致偏离，测试立即失败。
//
// 生成：go test -run TestGenerateGoldenVectors -update-golden
// 校验：go test -run TestGolden

const goldenPath = "testdata/protocol_golden.json"

// GoldenVectors 是跨语言比对的数据契约，字段命名保持语言中立
type GoldenVectors struct {
	Version int `json:"version"`

	// PSK 哈希：握手鉴权依赖它，必须一致
	PSKHashes []PSKHashVec `json:"psk_hashes"`

	// GCM 数据/FEC 域分离：锁定 key label、nonce、AAD 与 tag 字节
	GCMDomainVectors []GCMDomainVec `json:"gcm_domain_vectors"`

	// 帧头布局：10 字节头 [4B dataLen][2B padLen][4B seq]
	FrameHeaders []FrameHeaderVec `json:"frame_headers"`
	// 服务端观测 ClientHello 的跨语言规范化摘要
	TLSFingerprintVectors []TLSFingerprintVec `json:"tls_fingerprint_vectors"`

	// 握手 JSON 字段名契约
	HandshakeReqKeys  []string `json:"handshake_req_keys"`
	HandshakeRespKeys []string `json:"handshake_resp_keys"`
	TLSInfoKeys       []string `json:"tls_info_keys"`
}

type GCMDomainVec struct {
	PSK           string `json:"psk"`
	SaltHex       string `json:"salt_hex"`
	Domain        string `json:"domain"`
	Seq           uint32 `json:"seq"`
	PlaintextHex  string `json:"plaintext_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

type PSKHashVec struct {
	PSK  string `json:"psk"`
	Hash string `json:"hash"`
}

type FrameHeaderVec struct {
	DataLen   uint32 `json:"data_len"`
	PadLen    uint16 `json:"pad_len"`
	Seq       uint32 `json:"seq"`
	HeaderHex string `json:"header_hex"`
}

type TLSFingerprintVec struct {
	CipherSuites     []uint16 `json:"cipher_suites"`
	SignatureSchemes []uint16 `json:"signature_schemes"`
	Groups           []uint16 `json:"groups"`
	ALPN             []string `json:"alpn"`
	Fingerprint      string   `json:"fingerprint_sha256"`
}

func fullTLSInfoSample() *TLSHandshakeInfo {
	return &TLSHandshakeInfo{
		FingerprintKind: tlsClientHelloFingerprintKind, FingerprintSHA256: "abc",
		VersionID: tls.VersionTLS13, Version: "TLS 1.3",
		CipherSuiteID: 0x1301, CipherSuite: "TLS_AES_128_GCM_SHA256",
		ALPN: "h2", SNI: "example.com",
		OfferedCipherSuites: []uint16{0x1301}, OfferedSignatureSchemes: []uint16{0x0804},
		OfferedGroups: []uint16{0x001d}, OfferedALPN: []string{"h2"},
	}
}

// buildGoldenVectors 用当前 Go 实现计算出全部向量
func buildGoldenVectors() *GoldenVectors {
	gv := &GoldenVectors{Version: 2}

	for _, psk := range []string{"", "test_psk", "my_super_secret_test_key", "中文密钥🔑", "a"} {
		gv.PSKHashes = append(gv.PSKHashes, PSKHashVec{PSK: psk, Hash: hashPSK(psk)})
	}

	gcmPSK := "cross-language-domain-vector"
	gcmSalt := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	gcmPlain := []byte("ethernet-payload")
	for _, domain := range []string{"data", "fec"} {
		ic, err := newGCMInnerCipherDomain(gcmPSK, gcmSalt, domain)
		if err != nil {
			panic(err)
		}
		wire := make([]byte, len(gcmPlain)+gcmTagSize)
		copy(wire, gcmPlain)
		ic.sealInPlace(wire, len(gcmPlain), 0x01020304, uint32(len(wire)))
		gv.GCMDomainVectors = append(gv.GCMDomainVectors, GCMDomainVec{
			PSK: gcmPSK, SaltHex: hex.EncodeToString(gcmSalt),
			Domain: domain, Seq: 0x01020304, PlaintextHex: hex.EncodeToString(gcmPlain),
			CiphertextHex: hex.EncodeToString(wire),
		})
	}

	headers := []struct {
		dataLen uint32
		padLen  uint16
		seq     uint32
	}{
		{0, 0, 0},
		{1, 2, 3},
		{1400, 100, 65536},
		{65535, 65535, 4294967295},
	}
	for _, h := range headers {
		var hdr [10]byte
		binary.BigEndian.PutUint32(hdr[0:4], h.dataLen)
		binary.BigEndian.PutUint16(hdr[4:6], h.padLen)
		binary.BigEndian.PutUint32(hdr[6:10], h.seq)
		gv.FrameHeaders = append(gv.FrameHeaders, FrameHeaderVec{
			DataLen:   h.dataLen,
			PadLen:    h.padLen,
			Seq:       h.seq,
			HeaderHex: hex.EncodeToString(hdr[:]),
		})
	}
	for _, v := range []TLSFingerprintVec{
		{CipherSuites: []uint16{0x0a0a, 0x1301, 0x1302, 0xc02f}, SignatureSchemes: []uint16{0x0804, 0x0403}, Groups: []uint16{0x1a1a, 0x001d, 0x0017}, ALPN: []string{"h2", "http/1.1"}},
		{CipherSuites: []uint16{0x1303}, SignatureSchemes: []uint16{}, Groups: []uint16{}, ALPN: []string{}},
	} {
		v.Fingerprint = tlsClientHelloFingerprint(v.CipherSuites, v.SignatureSchemes, v.Groups, v.ALPN)
		gv.TLSFingerprintVectors = append(gv.TLSFingerprintVectors, v)
	}

	// 两个样本都必须把 omitempty 字段填成非零值，否则 jsonFieldNames 收不到它们，
	// 写出的键列表会静默漏字段（曾漏掉 session_token，Rust 侧被迫把契约测试
	// 降级成单向子集）。
	gv.HandshakeReqKeys = jsonFieldNames(HandshakeReq{
		ProtocolVersion: 2, ClientInstance: "x",
		ClientID: "x", PSK: "x", MAC: "x", IPv4: "x", IPv6: "x",
		Padding: "x", BrutalGroups: true,
		BrutalTotalTx: 30, BrutalTotalRx: 500, BrutalConns: 4, BrutalConnIndex: 1,
		FEC: true, FecGroup: 4, Encrypt: true, EncAlgo: 2,
		SessionToken: "x",
	})
	gv.HandshakeRespKeys = jsonFieldNames(HandshakeResp{
		ProtocolVersion: 2, SessionEpoch: 1,
		Success: true, Message: "x", SessionID: "x", ClientID: "x",
		IPv4: "x", IPv6: "x", GwV4: "x", GwV6: "x", Padding: "x",
		BrutalGroups: true, BrutalTotalTx: 30, BrutalTotalRx: 500,
		FEC: true, FecGroup: 4, Encrypt: true,
		EncAlgo: 2, EncSalt: "x", EncSalt2: "x", SessionToken: "x", TLS: fullTLSInfoSample(),
	})
	gv.TLSInfoKeys = jsonFieldNames(*fullTLSInfoSample())

	return gv
}

func jsonFieldNames(v any) []string {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// TestGenerateGoldenVectors 生成/更新黄金向量文件。
// 常规运行时它只校验文件与当前实现是否一致；带 -update-golden 时才重写文件。
func TestGenerateGoldenVectors(t *testing.T) {
	gv := buildGoldenVectors()
	data, err := json.MarshalIndent(gv, "", "  ")
	if err != nil {
		t.Fatalf("序列化黄金向量失败: %v", err)
	}
	data = append(data, '\n')

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("创建 testdata 目录失败: %v", err)
		}
		if err := os.WriteFile(goldenPath, data, 0o644); err != nil {
			t.Fatalf("写入黄金向量失败: %v", err)
		}
		t.Logf("已更新黄金向量文件: %s", goldenPath)
		return
	}

	old, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("读取黄金向量失败（首次请运行 go test -run TestGenerateGoldenVectors -update-golden）: %v", err)
	}
	// 用结构化深度比较而非字节比较：JSON 对象内的键排列顺序对协议语义
	// 没有影响（Rust 端 serde 按字段名匹配），但若出现真实的协议变更
	// （密钥派生、字段名、向量值、数量），DeepEqual 仍会捕获并失败。
	var oldGV GoldenVectors
	if err := json.Unmarshal(bytes.TrimSpace(old), &oldGV); err != nil {
		t.Fatalf("解析已有黄金向量失败: %v", err)
	}
	if !reflect.DeepEqual(oldGV, *gv) {
		t.Errorf("当前实现与黄金向量不一致！\n"+
			"这意味着协议发生了变更，Rust 端必须同步修改，否则两端无法互通。\n"+
			"确认变更无误后运行: go test -run TestGenerateGoldenVectors -update-golden\n"+
			"文件: %s", goldenPath)
	}
}

// TestGoldenSelfConsistency 校验黄金向量能被当前实现正确复现（自洽性）
func TestGoldenSelfConsistency(t *testing.T) {
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Skipf("黄金向量文件不存在，跳过（先运行 -update-golden 生成）: %v", err)
	}
	var gv GoldenVectors
	if err := json.Unmarshal(raw, &gv); err != nil {
		t.Fatalf("解析黄金向量失败: %v", err)
	}

	for _, h := range gv.PSKHashes {
		if got := hashPSK(h.PSK); got != h.Hash {
			t.Errorf("PSK %q 的哈希不一致，黄金 %s 实际 %s", h.PSK, h.Hash, got)
		}
	}

	for _, v := range gv.GCMDomainVectors {
		salt, _ := hex.DecodeString(v.SaltHex)
		plain, _ := hex.DecodeString(v.PlaintextHex)
		ic, err := newGCMInnerCipherDomain(v.PSK, salt, v.Domain)
		if err != nil {
			t.Fatalf("GCM domain vector init: %v", err)
		}
		wire := make([]byte, len(plain)+gcmTagSize)
		copy(wire, plain)
		ic.sealInPlace(wire, len(plain), v.Seq, uint32(len(wire)))
		if got := hex.EncodeToString(wire); got != v.CiphertextHex {
			t.Errorf("GCM domain %s mismatch: got %s want %s", v.Domain, got, v.CiphertextHex)
		}
	}

	for _, h := range gv.FrameHeaders {
		var hdr [10]byte
		binary.BigEndian.PutUint32(hdr[0:4], h.DataLen)
		binary.BigEndian.PutUint16(hdr[4:6], h.PadLen)
		binary.BigEndian.PutUint32(hdr[6:10], h.Seq)
		if got := hex.EncodeToString(hdr[:]); got != h.HeaderHex {
			t.Errorf("帧头布局不一致 dataLen=%d padLen=%d seq=%d\n黄金: %s\n实际: %s",
				h.DataLen, h.PadLen, h.Seq, h.HeaderHex, got)
		}
	}
	for _, v := range gv.TLSFingerprintVectors {
		if got := tlsClientHelloFingerprint(v.CipherSuites, v.SignatureSchemes, v.Groups, v.ALPN); got != v.Fingerprint {
			t.Errorf("TLS ClientHello fingerprint mismatch: got %s want %s", got, v.Fingerprint)
		}
	}

	// 握手键列表：Rust 端读它来对齐 serde 字段名，漏一个字段两端就静默错配。
	// 按全填充样本复算再比对——样本必须填满 omitempty 字段，否则会自己漏掉
	// 自己该锁的字段（历史上 session_token 就是这样漏出去的）。
	checkKeys := func(name string, goldenKeys, want []string) {
		if !equalStrings(goldenKeys, want) {
			t.Errorf("%s 不一致\n黄金: %v\n复算: %v", name, goldenKeys, want)
		}
	}
	checkKeys("handshake_req_keys", gv.HandshakeReqKeys, jsonFieldNames(HandshakeReq{
		ProtocolVersion: 2, ClientInstance: "x",
		ClientID: "x", PSK: "x", MAC: "x", IPv4: "x", IPv6: "x",
		Padding: "x", BrutalGroups: true,
		BrutalTotalTx: 30, BrutalTotalRx: 500, BrutalConns: 4, BrutalConnIndex: 1,
		FEC: true, FecGroup: 4, Encrypt: true, EncAlgo: 2,
		SessionToken: "x",
	}))
	checkKeys("handshake_resp_keys", gv.HandshakeRespKeys, jsonFieldNames(HandshakeResp{
		ProtocolVersion: 2, SessionEpoch: 1,
		Success: true, Message: "x", SessionID: "x", ClientID: "x",
		IPv4: "x", IPv6: "x", GwV4: "x", GwV6: "x", Padding: "x",
		BrutalGroups: true, BrutalTotalTx: 30, BrutalTotalRx: 500,
		FEC: true, FecGroup: 4, Encrypt: true,
		EncAlgo: 2, EncSalt: "x", EncSalt2: "x", SessionToken: "x", TLS: fullTLSInfoSample(),
	}))
	checkKeys("tls_info_keys", gv.TLSInfoKeys, jsonFieldNames(*fullTLSInfoSample()))
}

// TestHandshakeJSONContract 锁定握手 JSON 的字段名。
// Rust 端 serde 的字段名必须与此完全一致，否则握手会失败或字段静默丢失。
func TestHandshakeJSONContract(t *testing.T) {
	// 全字段填充，确保 omitempty 字段也出现
	req := HandshakeReq{
		ProtocolVersion: 2, ClientInstance: "instance-1",
		ClientID: "c1", PSK: "p", MAC: "00:11:22:33:44:55",
		IPv4: "10.0.0.2", IPv6: "fd00::2", Padding: "ab",
		BrutalGroups: true, BrutalTotalTx: 400, BrutalTotalRx: 800, BrutalConns: 4, BrutalConnIndex: 1,
		FEC: true, FecGroup: 4, Encrypt: true, EncAlgo: 2,
		SessionToken: "tok",
	}
	wantReq := []string{
		"brutal_conn_index", "brutal_conns", "brutal_groups", "brutal_total_rx", "brutal_total_tx", "client_id", "client_instance", "enc_algo", "encrypt", "fec",
		"fec_group", "ipv4", "ipv6", "mac", "padding", "protocol_version", "psk", "session_token",
	}
	if got := jsonFieldNames(req); !equalStrings(got, wantReq) {
		t.Errorf("HandshakeReq 字段名契约被破坏\n预期: %v\n实际: %v\nRust 端 serde 必须同步", wantReq, got)
	}

	resp := HandshakeResp{
		ProtocolVersion: 2, SessionEpoch: 1,
		Success: true, Message: "ok", SessionID: "s1", ClientID: "c1",
		IPv4: "10.0.0.2", IPv6: "fd00::2", GwV4: "10.0.0.1", GwV6: "fd00::1",
		Padding: "ab", BrutalGroups: true, BrutalTotalTx: 400, BrutalTotalRx: 800, FEC: true, FecGroup: 4, Encrypt: true,
		EncAlgo: 2, EncSalt: "x", EncSalt2: "x", SessionToken: "tok", TLS: fullTLSInfoSample(),
	}
	wantResp := []string{
		"brutal_groups", "brutal_total_rx", "brutal_total_tx", "client_id", "enc_algo", "enc_salt", "enc_salt2",
		"encrypt", "fec", "fec_group", "gw_v4", "gw_v6", "ipv4", "ipv6", "message",
		"padding", "protocol_version", "session_epoch", "session_id", "session_token", "success", "tls",
	}
	if got := jsonFieldNames(resp); !equalStrings(got, wantResp) {
		t.Errorf("HandshakeResp 字段名契约被破坏\n预期: %v\n实际: %v\nRust 端 serde 必须同步", wantResp, got)
	}
}

// TestHandshakeOmitEmpty 验证 omitempty 行为：
// 这决定了 Rust 端对应字段必须是 Option 或带 #[serde(default)]
func TestHandshakeOmitEmpty(t *testing.T) {
	b, err := json.Marshal(HandshakeReq{ClientID: "c", PSK: "p"})
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)

	// 这些字段带 omitempty，零值时不出现
	for _, k := range []string{"protocol_version", "client_instance", "mac", "ipv4", "ipv6", "padding", "brutal_groups", "brutal_total_tx", "brutal_total_rx", "brutal_conns", "brutal_conn_index", "fec", "fec_group", "encrypt", "enc_algo", "enc_salt", "enc_salt2", "session_token"} {
		if _, ok := m[k]; ok {
			t.Errorf("字段 %q 应因 omitempty 而省略，实际出现了", k)
		}
	}
	// 这些字段无 omitempty，必须始终出现
	for _, k := range []string{"client_id", "psk"} {
		if _, ok := m[k]; !ok {
			t.Errorf("字段 %q 必须始终出现", k)
		}
	}

	rb, _ := json.Marshal(HandshakeResp{})
	var rm map[string]any
	json.Unmarshal(rb, &rm)
	// Resp 中这几个无 omitempty，Rust 端反序列化时必须能接受它们恒存在
	for _, k := range []string{"success", "message", "client_id", "ipv4", "ipv6"} {
		if _, ok := rm[k]; !ok {
			t.Errorf("HandshakeResp 字段 %q 必须始终出现", k)
		}
	}
	if _, ok := rm["tls"]; ok {
		t.Error("HandshakeResp 字段 \"tls\" 应因 omitempty 在旧式/空响应中省略")
	}
}

// TestFrameGCMRoundTrip 帧编解码闭环（GCM：线路负载含 16B 标签）
func TestFrameGCMRoundTrip(t *testing.T) {
	psk := "gcm_roundtrip_key"
	salt := randomSalt()
	tx, _ := newGCMInnerCipher(psk, salt)
	rx, _ := newGCMInnerCipher(psk, salt)

	payloads := [][]byte{
		[]byte("gcm-a"),
		bytes.Repeat([]byte("g"), 1400),
		bytes.Repeat([]byte("h"), 77),
	}
	buf := new(bytes.Buffer)
	for i, p := range payloads {
		f := appendPaddedFrame(nil, VPNFrame{Seq: uint32(i + 1), Data: p}, tx)
		buf.Write(f)
	}
	scanner := NewFrameScanner(buf)
	for i, want := range payloads {
		got, seq, err := scanner.ReadFrame()
		if err != nil {
			t.Fatalf("第 %d 帧读取失败: %v", i, err)
		}
		if len(got) != len(want)+gcmTagSize {
			t.Fatalf("第 %d 帧线路负载应含标签: got %d want %d", i, len(got), len(want)+gcmTagSize)
		}
		plain, err := rx.openInPlace(got, seq, uint32(len(got)))
		if err != nil {
			t.Fatalf("第 %d 帧 GCM 解密失败: %v", i, err)
		}
		if !bytes.Equal(plain, want) {
			t.Fatalf("第 %d 帧 GCM 明文不一致", i)
		}
	}
}

// TestFrameSeqZeroNotEncrypted 控制帧 (seq=0) 不加密，两端必须一致
func TestFrameSeqZeroNotEncrypted(t *testing.T) {
	payload := []byte("control frame must stay plaintext")

	f := appendPaddedFrame(nil, VPNFrame{Seq: 0, Data: payload}, encIC("k"))
	// 头部 10 字节之后即为负载，seq=0 时不应被加密
	got := f[10 : 10+len(payload)]
	if !bytes.Equal(got, payload) {
		t.Errorf("seq=0 的控制帧不应被加密\n预期 %q\n实际 %q", payload, got)
	}
}

// TestFrameHeaderByteOrder 显式锁定大端字节序
func TestFrameHeaderByteOrder(t *testing.T) {
	f := appendPaddedFrame(nil, VPNFrame{Seq: 0x01020304, Data: []byte("ab")}, nil)

	if dl := binary.BigEndian.Uint32(f[0:4]); dl != 2 {
		t.Errorf("dataLen 应为 2，实际 %d", dl)
	}
	if seq := binary.BigEndian.Uint32(f[6:10]); seq != 0x01020304 {
		t.Errorf("seq 应为 0x01020304，实际 0x%08X", seq)
	}
	// 显式校验字节序：0x01020304 大端应为 01 02 03 04
	if !bytes.Equal(f[6:10], []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("seq 必须为大端序，实际字节 % X", f[6:10])
	}
}

// TestPadModeOff off 模式恒不填充
func TestPadModeOff(t *testing.T) {
	prev := setPadMode(padModeOff)
	defer setPadMode(prev)
	for _, n := range []int{0, 1, 100, 200, 1500, 70000} {
		if got := currentPadLength(n); got != 0 {
			t.Fatalf("off 模式下 wireLen=%d 的填充应为 0，实际 %d", n, got)
		}
	}
	if padModeName() != padModeOff {
		t.Fatalf("padModeName 应为 %q，实际 %q", padModeOff, padModeName())
	}
}

// TestPadModeBucket bucket 模式按完整记录（10B 头 + 载荷 + 填充）分桶，
// 且除 off 外每条记录都必须有正填充，避免边界长度泄漏。
func TestPadModeBucket(t *testing.T) {
	prev := setPadMode(padModeBucket)
	defer setPadMode(prev)

	for _, c := range []struct {
		wireLen, want int
	}{
		{0, 118},
		{1, 117},
		{118, 128}, // 完整记录正好 128B 时推进到 256B 桶
		{128, 118},
		{129, 117},
		{1500, 90},
		{1514, 76},
	} {
		if got := currentPadLength(c.wireLen); got != c.want {
			t.Fatalf("bucket 模式 wireLen=%d 应填 %d，实际 %d", c.wireLen, c.want, got)
		}
	}
	// 超出最大桶的 jumbo 帧只加小额随机填充
	for i := 0; i < 100; i++ {
		if got := currentPadLength(4090); got < 1 || got > 100 {
			t.Fatalf("jumbo 帧填充应为 [1,100]，实际 %d", got)
		}
	}
	if padModeName() != padModeBucket {
		t.Fatalf("padModeName 应为 %q，实际 %q", padModeBucket, padModeName())
	}
}

func TestBucketPaddingCoversEveryNormalIPPacketLength(t *testing.T) {
	prev := setPadMode(padModeBucket)
	defer setPadMode(prev)
	for wireLen := 1; wireLen <= 1514+gcmTagSize; wireLen++ {
		pad := currentPadLength(wireLen)
		if pad <= 0 {
			t.Fatalf("wireLen=%d was emitted without padding", wireLen)
		}
		recordLen := 10 + wireLen + pad
		found := false
		for _, bucket := range padBuckets {
			if recordLen == bucket {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("wireLen=%d produced non-bucket record length %d", wireLen, recordLen)
		}
	}
}

// TestPadModeFallback 非法值必须回落 bucket 而不是静默生效
func TestPadModeFallback(t *testing.T) {
	prev := setPadMode(padModeBucket)
	defer setPadMode(prev)
	if got := setPadMode("bogus"); got != padModeBucket {
		t.Fatalf("非法 pad_mode 应回落 %q，实际 %q", padModeBucket, got)
	}
	if padModeName() != padModeBucket {
		t.Fatalf("非法 pad_mode 后生效值应为 %q，实际 %q", padModeBucket, padModeName())
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
