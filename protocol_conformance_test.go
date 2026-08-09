package main

import (
	"bytes"
	"crypto/sha256"
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

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

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

	// 密钥派生：给定 PSK，AES key 与 base IV 必须逐字节一致
	CipherContexts []CipherContextVec `json:"cipher_contexts"`

	// XOR/CTR 加密：给定明文与 seq，密文必须逐字节一致
	XorVectors []XorVec `json:"xor_vectors"`

	// PSK 哈希：握手鉴权依赖它，必须一致
	PSKHashes []PSKHashVec `json:"psk_hashes"`

	// 帧头布局：10 字节头 [4B dataLen][2B padLen][4B seq]
	FrameHeaders []FrameHeaderVec `json:"frame_headers"`

	// 握手 JSON 字段名契约
	HandshakeReqKeys  []string `json:"handshake_req_keys"`
	HandshakeRespKeys []string `json:"handshake_resp_keys"`
}

type CipherContextVec struct {
	PSK    string `json:"psk"`
	KeyHex string `json:"key_hex"`
	IVHex  string `json:"iv_hex"`
}

type XorVec struct {
	PSK           string `json:"psk"`
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

// buildGoldenVectors 用当前 Go 实现计算出全部向量
func buildGoldenVectors() *GoldenVectors {
	gv := &GoldenVectors{Version: 1}

	psks := []string{"", "test_psk", "my_super_secret_test_key", "中文密钥🔑", "a"}
	for _, psk := range psks {
		block, iv := getCipherContext(psk)
		key := deriveKeyBytes(psk)
		_ = block
		gv.CipherContexts = append(gv.CipherContexts, CipherContextVec{
			PSK:    psk,
			KeyHex: hex.EncodeToString(key),
			IVHex:  hex.EncodeToString(iv),
		})
		gv.PSKHashes = append(gv.PSKHashes, PSKHashVec{PSK: psk, Hash: hashPSK(psk)})
	}

	type xorCase struct {
		psk  string
		seq  uint32
		data []byte
	}
	cases := []xorCase{
		{"test_psk", 0, []byte("hello")},
		{"test_psk", 1, []byte("hello")},
		{"test_psk", 42, []byte("The quick brown fox jumps over the lazy dog")},
		{"test_psk", 4294967295, []byte{0x00, 0xFF, 0x7F, 0x80}},
		{"my_super_secret_test_key", 12345, bytes.Repeat([]byte{0xAB}, 64)},
		{"中文密钥🔑", 7, []byte("多字节 PSK 派生必须一致")},
	}
	for _, c := range cases {
		block, iv := getCipherContext(c.psk)
		buf := make([]byte, len(c.data))
		copy(buf, c.data)
		xorCryptInPlace(buf, c.seq, block, iv)
		gv.XorVectors = append(gv.XorVectors, XorVec{
			PSK:           c.psk,
			Seq:           c.seq,
			PlaintextHex:  hex.EncodeToString(c.data),
			CiphertextHex: hex.EncodeToString(buf),
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

	gv.HandshakeReqKeys = jsonFieldNames(HandshakeReq{
		ClientID: "x", PSK: "x", MAC: "x", IPv4: "x", IPv6: "x",
		Padding: "x", BrutalTx: 1, BrutalRx: 1, FEC: true, Encrypt: true,
	})
	gv.HandshakeRespKeys = jsonFieldNames(HandshakeResp{
		Success: true, Message: "x", SessionID: "x", ClientID: "x",
		IPv4: "x", IPv6: "x", GwV4: "x", GwV6: "x", Padding: "x",
		BrutalTx: 1, BrutalRx: 1, FEC: true, Encrypt: true,
	})

	return gv
}

// deriveKeyBytes 复算 AES key 原始字节（getCipherContext 只返回 cipher.Block，
// 拿不到原始 key，这里按同一算法重算，同时也验证了派生公式没有漂移）
func deriveKeyBytes(psk string) []byte {
	return sha256Sum([]byte(psk + "_enc_key"))
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

	for _, c := range gv.CipherContexts {
		_, iv := getCipherContext(c.PSK)
		if got := hex.EncodeToString(iv); got != c.IVHex {
			t.Errorf("PSK %q 的 IV 不一致，黄金 %s 实际 %s", c.PSK, c.IVHex, got)
		}
		if got := hex.EncodeToString(deriveKeyBytes(c.PSK)); got != c.KeyHex {
			t.Errorf("PSK %q 的 key 不一致，黄金 %s 实际 %s", c.PSK, c.KeyHex, got)
		}
	}

	for _, h := range gv.PSKHashes {
		if got := hashPSK(h.PSK); got != h.Hash {
			t.Errorf("PSK %q 的哈希不一致，黄金 %s 实际 %s", h.PSK, h.Hash, got)
		}
	}

	for _, v := range gv.XorVectors {
		plain, err := hex.DecodeString(v.PlaintextHex)
		if err != nil {
			t.Fatalf("黄金向量明文解码失败: %v", err)
		}
		block, iv := getCipherContext(v.PSK)
		buf := make([]byte, len(plain))
		copy(buf, plain)
		xorCryptInPlace(buf, v.Seq, block, iv)
		if got := hex.EncodeToString(buf); got != v.CiphertextHex {
			t.Errorf("PSK %q seq %d 加密结果不一致\n黄金: %s\n实际: %s", v.PSK, v.Seq, v.CiphertextHex, got)
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
}

// TestHandshakeJSONContract 锁定握手 JSON 的字段名。
// Rust 端 serde 的字段名必须与此完全一致，否则握手会失败或字段静默丢失。
func TestHandshakeJSONContract(t *testing.T) {
	// 全字段填充，确保 omitempty 字段也出现
	req := HandshakeReq{
		ClientID: "c1", PSK: "p", MAC: "00:11:22:33:44:55",
		IPv4: "10.0.0.2", IPv6: "fd00::2", Padding: "ab",
		BrutalTx: 100, BrutalRx: 200, FEC: true, Encrypt: true,
	}
	wantReq := []string{
		"brutal_rx", "brutal_tx", "client_id", "encrypt", "fec",
		"ipv4", "ipv6", "mac", "padding", "psk",
	}
	if got := jsonFieldNames(req); !equalStrings(got, wantReq) {
		t.Errorf("HandshakeReq 字段名契约被破坏\n预期: %v\n实际: %v\nRust 端 serde 必须同步", wantReq, got)
	}

	resp := HandshakeResp{
		Success: true, Message: "ok", SessionID: "s1", ClientID: "c1",
		IPv4: "10.0.0.2", IPv6: "fd00::2", GwV4: "10.0.0.1", GwV6: "fd00::1",
		Padding: "ab", BrutalTx: 100, BrutalRx: 200, FEC: true, Encrypt: true,
	}
	wantResp := []string{
		"brutal_rx", "brutal_tx", "client_id", "encrypt", "fec",
		"gw_v4", "gw_v6", "ipv4", "ipv6", "message", "padding",
		"session_id", "success",
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
	for _, k := range []string{"mac", "ipv4", "ipv6", "padding", "brutal_tx", "brutal_rx", "fec", "encrypt"} {
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
}

// TestFrameRoundTripWithEncryption 帧编解码闭环（含加密）
func TestFrameRoundTripWithEncryption(t *testing.T) {
	psk := "roundtrip_key"
	block, iv := getCipherContext(psk)

	payloads := [][]byte{
		[]byte("a"),
		[]byte("short"),
		bytes.Repeat([]byte("x"), 199),  // < 200 分支
		bytes.Repeat([]byte("y"), 500),  // < 800 分支
		bytes.Repeat([]byte("z"), 1400), // >= 800 分支
	}

	buf := new(bytes.Buffer)
	seqs := []uint32{1, 2, 3, 4, 5}
	for i, p := range payloads {
		f := appendPaddedFrame(nil, VPNFrame{Seq: seqs[i], Data: p}, block, iv)
		buf.Write(f)
	}

	scanner := NewFrameScanner(buf)
	for i, want := range payloads {
		got, seq, err := scanner.ReadFrame()
		if err != nil {
			t.Fatalf("第 %d 帧读取失败: %v", i, err)
		}
		if seq != seqs[i] {
			t.Errorf("第 %d 帧 seq 不符，预期 %d 实际 %d", i, seqs[i], seq)
		}
		xorCryptInPlace(got, seq, block, iv)
		if !bytes.Equal(got, want) {
			t.Errorf("第 %d 帧解密后与原文不符\n预期长度 %d\n实际长度 %d", i, len(want), len(got))
		}
	}
}

// TestFrameSeqZeroNotEncrypted 控制帧 (seq=0) 不加密，两端必须一致
func TestFrameSeqZeroNotEncrypted(t *testing.T) {
	block, iv := getCipherContext("k")
	payload := []byte("control frame must stay plaintext")

	f := appendPaddedFrame(nil, VPNFrame{Seq: 0, Data: payload}, block, iv)
	// 头部 10 字节之后即为负载，seq=0 时不应被加密
	got := f[10 : 10+len(payload)]
	if !bytes.Equal(got, payload) {
		t.Errorf("seq=0 的控制帧不应被加密\n预期 %q\n实际 %q", payload, got)
	}
}

// TestFrameHeaderByteOrder 显式锁定大端字节序
func TestFrameHeaderByteOrder(t *testing.T) {
	f := appendPaddedFrame(nil, VPNFrame{Seq: 0x01020304, Data: []byte("ab")}, nil, nil)

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

// TestGetPaddingLengthRanges 填充长度分支必须与 Rust 端一致
func TestGetPaddingLengthRanges(t *testing.T) {
	checks := []struct {
		dataLen  int
		min, max int
	}{
		{0, 100, 300},
		{1, 300, 499},
		{199, 300, 499},
		{200, 100, 299},
		{799, 100, 299},
		{800, 0, 99},
		{1400, 0, 99},
	}
	for _, c := range checks {
		for i := 0; i < 200; i++ {
			got := getPaddingLength(c.dataLen)
			if got < c.min || got > c.max {
				t.Fatalf("dataLen=%d 的填充长度 %d 超出预期范围 [%d,%d]", c.dataLen, got, c.min, c.max)
			}
		}
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
