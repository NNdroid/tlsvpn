#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    s = p.read_text()
    if old not in s:
        raise SystemExit(f"marker not found in {path}: {old[:100]!r}")
    p.write_text(s.replace(old, new, 1))

# crypto.go: import + replace the whole inner-encryption block.
p = Path('crypto.go')
s = p.read_text()
if 'golang.org/x/crypto/chacha20poly1305' not in s:
    s = s.replace('"time"\n)', '"time"\n\n\t"golang.org/x/crypto/chacha20poly1305"\n)', 1)
start = s.index('// ======================= 内层加密 =======================')
end = s.index('// verifyCertHash', start)
section = r'''// ======================= 内层加密 =======================

const (
	// encAlgoNone 未启用内层加密（encrypt=false）：线路负载即明文，只靠 TLS。
	encAlgoNone = 0
	// 2 保持既有 AES-256-GCM wire 语义；3 曾被历史 GCM-v2 占用；4 是 AES-128-GCM。
	// 新算法只扩展握手 enc_algo，帧头、16B tag、8B session salt 字段均保持不变。
	encAlgoGCM       = 2
	encAlgoGCM128    = 4
	encAlgoChaCha20  = 5
	encAlgoXChaCha20 = 6

	aeadTagSize       = 16
	standardNonceSize = 12
	xNonceSize         = 24
	encSaltSize        = 8

	gcmKeyLabel       = "_enc_key"
	gcm128KeyLabel    = "_enc_key128"
	chachaKeyLabel    = "_enc_chacha20"
	xchachaKeyLabel   = "_enc_xchacha20"
	xchachaNonceLabel = "tlsvpn-xchacha20-nonce-v1"
)

// 历史名称保留，避免测试/外部辅助代码因常量重命名失效。
const (
	gcmTagSize   = aeadTagSize
	gcmNonceSize = standardNonceSize
)

// innerCipher 是统一的内层 AEAD。AES-GCM 与 ChaCha20-Poly1305 使用 12B nonce：
// seq(4BE)||salt(8B)。XChaCha20-Poly1305 需要 24B nonce；为了不新增握手字段，
// 使用现有随机 salt 确定性派生 20B prefix，再追加 seq(4BE)。salt 每个 session
// epoch、每个方向都会重新随机，seq 在 epoch 内单调，因此 nonce 不复用。
type innerCipher struct {
	aead cipher.AEAD
	algo int
	salt [encSaltSize]byte
	xnoncePrefix [20]byte
}

// 兼容历史 AES-256-GCM 构造 API。
func newGCMInnerCipher(psk string, salt []byte) (*innerCipher, error) {
	return newInnerCipherForAlgo(psk, salt, encAlgoGCM)
}
func newGCMInnerCipherForAlgo(psk string, salt []byte, algo int) (*innerCipher, error) {
	return newInnerCipherForAlgo(psk, salt, algo)
}
func newGCMInnerCipherDomain(psk string, salt []byte, domain string) (*innerCipher, error) {
	return newInnerCipherDomainForAlgo(psk, salt, domain, encAlgoGCM)
}
func newGCMInnerCipherDomainForAlgo(psk string, salt []byte, domain string, algo int) (*innerCipher, error) {
	return newInnerCipherDomainForAlgo(psk, salt, domain, algo)
}

func newInnerCipherForAlgo(psk string, salt []byte, algo int) (*innerCipher, error) {
	return newInnerCipherDomainForAlgo(psk, salt, "data", algo)
}

func newInnerCipherDomainForAlgo(psk string, salt []byte, domain string, algo int) (*innerCipher, error) {
	if domain != "data" && domain != "fec" {
		return nil, fmt.Errorf("unknown AEAD domain %q", domain)
	}
	if len(salt) != encSaltSize {
		return nil, fmt.Errorf("encryption salt must be %d bytes, got %d", encSaltSize, len(salt))
	}

	var label string
	var keyLen int
	switch algo {
	case encAlgoGCM:
		label, keyLen = gcmKeyLabel, 32
	case encAlgoGCM128:
		label, keyLen = gcm128KeyLabel, 16
	case encAlgoChaCha20:
		label, keyLen = chachaKeyLabel, chacha20poly1305.KeySize
	case encAlgoXChaCha20:
		label, keyLen = xchachaKeyLabel, chacha20poly1305.KeySize
	default:
		return nil, fmt.Errorf("unsupported inner AEAD algorithm %d", algo)
	}
	if domain == "fec" {
		label += "_fec"
	}
	keyHash := sha256.Sum256([]byte(psk + label))
	key := keyHash[:keyLen]

	var aead cipher.AEAD
	var err error
	switch algo {
	case encAlgoGCM, encAlgoGCM128:
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err == nil {
			aead, err = cipher.NewGCM(block)
		}
	case encAlgoChaCha20:
		aead, err = chacha20poly1305.New(key)
	case encAlgoXChaCha20:
		aead, err = chacha20poly1305.NewX(key)
	}
	if err != nil {
		return nil, err
	}
	if aead.Overhead() != aeadTagSize {
		return nil, fmt.Errorf("unexpected AEAD tag size %d", aead.Overhead())
	}

	ic := &innerCipher{aead: aead, algo: algo}
	copy(ic.salt[:], salt)
	if algo == encAlgoXChaCha20 {
		h := sha256.New()
		h.Write([]byte(xchachaNonceLabel))
		h.Write(salt)
		sum := h.Sum(nil)
		copy(ic.xnoncePrefix[:], sum[:20])
	}
	return ic, nil
}

func newRandomSalt() [encSaltSize]byte {
	var s [encSaltSize]byte
	if _, err := rand.Read(s[:]); err != nil {
		panic("Failed to generate encryption salt: " + err.Error())
	}
	return s
}

func encAlgoFromConfig(mode string) int {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "gcm128":
		return encAlgoGCM128
	case "chacha20":
		return encAlgoChaCha20
	case "xchacha20":
		return encAlgoXChaCha20
	default:
		return encAlgoGCM
	}
}

func encAlgoLabel(algo int) string {
	switch algo {
	case encAlgoGCM128:
		return "gcm128"
	case encAlgoChaCha20:
		return "chacha20"
	case encAlgoXChaCha20:
		return "xchacha20"
	case encAlgoGCM:
		return "gcm256"
	default:
		return "none"
	}
}

func isGCMAlgo(algo int) bool { return algo == encAlgoGCM || algo == encAlgoGCM128 }
func isInnerAEADAlgo(algo int) bool {
	return isGCMAlgo(algo) || algo == encAlgoChaCha20 || algo == encAlgoXChaCha20
}

func (ic *innerCipher) isGCM() bool { return ic != nil && isGCMAlgo(ic.algo) }

// min_enc 的配置值 "gcm" 为历史兼容名称。过去全部内层认证加密都是 GCM，
// 所以它事实上承担的是“必须启用认证 AEAD”的策略。新增 ChaCha 后继续沿用同一
// 配置值，不增加配置项：gcm 表示任何受支持的认证内层 AEAD 均可，具体算法仍
// 由 enc_algo 精确匹配，不做隐式升级/降级。
const (
	minEncNone = 0
	minEncGCM  = 1
)
func minEncRank(mode string) int {
	if strings.EqualFold(strings.TrimSpace(mode), "gcm") {
		return minEncGCM
	}
	return minEncNone
}

func (ic *innerCipher) tagLen() int {
	if ic == nil { return 0 }
	return ic.aead.Overhead()
}

// nonceAADScratch 同时容纳最大 24B nonce 与 8B AAD，避免热路径每帧分配。
type nonceAADScratch [xNonceSize + 8]byte
var aeadScratchPool = sync.Pool{New: func() any { return new(nonceAADScratch) }}

func (ic *innerCipher) nonceAAD(seq uint32, wireLen uint32, buf *nonceAADScratch) (nonce, aad []byte) {
	if ic.algo == encAlgoXChaCha20 {
		copy(buf[0:20], ic.xnoncePrefix[:])
		binary.BigEndian.PutUint32(buf[20:24], seq)
		binary.BigEndian.PutUint32(buf[24:28], wireLen)
		binary.BigEndian.PutUint32(buf[28:32], seq)
		return buf[:xNonceSize], buf[xNonceSize:xNonceSize+8]
	}
	binary.BigEndian.PutUint32(buf[0:4], seq)
	copy(buf[4:12], ic.salt[:])
	binary.BigEndian.PutUint32(buf[12:16], wireLen)
	binary.BigEndian.PutUint32(buf[16:20], seq)
	return buf[:standardNonceSize], buf[standardNonceSize:standardNonceSize+8]
}

// 历史测试辅助函数保留 AES-GCM 的 nonce/AAD 观察语义。
func (ic *innerCipher) gcmNonce(seq uint32) []byte {
	var nonce [standardNonceSize]byte
	binary.BigEndian.PutUint32(nonce[0:4], seq)
	copy(nonce[4:], ic.salt[:])
	return nonce[:]
}
func gcmAAD(wireLen, seq uint32) []byte {
	var aad [8]byte
	binary.BigEndian.PutUint32(aad[0:4], wireLen)
	binary.BigEndian.PutUint32(aad[4:8], seq)
	return aad[:]
}

func (ic *innerCipher) sealInPlace(region []byte, ptLen int, seq uint32, wireLen uint32) int {
	if ptLen == 0 || ic == nil { return ptLen }
	scratch := aeadScratchPool.Get().(*nonceAADScratch)
	nonce, aad := ic.nonceAAD(seq, wireLen, scratch)
	out := ic.aead.Seal(region[:0], nonce, region[:ptLen], aad)
	aeadScratchPool.Put(scratch)
	return len(out)
}

func (ic *innerCipher) openInPlace(data []byte, seq uint32, wireLen uint32) ([]byte, error) {
	if len(data) == 0 || ic == nil { return data, nil }
	if len(data) < ic.tagLen() { return nil, fmt.Errorf("AEAD payload too short: %d", len(data)) }
	scratch := aeadScratchPool.Get().(*nonceAADScratch)
	nonce, aad := ic.nonceAAD(seq, wireLen, scratch)
	plain, err := ic.aead.Open(data[:0], nonce, data, aad)
	aeadScratchPool.Put(scratch)
	return plain, err
}

func (ic *innerCipher) openTo(dst, src []byte, seq uint32, wireLen uint32) ([]byte, error) {
	if ic == nil {
		copy(dst, src)
		return dst, nil
	}
	if len(src) < ic.tagLen() { return nil, fmt.Errorf("AEAD payload too short: %d", len(src)) }
	scratch := aeadScratchPool.Get().(*nonceAADScratch)
	nonce, aad := ic.nonceAAD(seq, wireLen, scratch)
	plain, err := ic.aead.Open(dst[:0], nonce, src, aad)
	aeadScratchPool.Put(scratch)
	return plain, err
}

'''
s = s[:start] + section + s[end:]
p.write_text(s)

# Config accepts new values without adding any new field.
p = Path('config.go'); s = p.read_text()
s = s.replace('// gcm256（默认）| gcm128（显式性能模式）', '// gcm256（默认）| gcm128 | chacha20 | xchacha20')
s = s.replace('case "", "gcm256", "gcm128":', 'case "", "gcm256", "gcm128", "chacha20", "xchacha20":')
s = s.replace('invalid enc_algo %q (want gcm256 or gcm128)', 'invalid enc_algo %q (want gcm256, gcm128, chacha20 or xchacha20)')
p.write_text(s)

for name in ['client.go', 'server.go']:
    p = Path(name); s = p.read_text()
    s = s.replace('newGCMInnerCipherForAlgo', 'newInnerCipherForAlgo')
    s = s.replace('newGCMInnerCipherDomainForAlgo', 'newInnerCipherDomainForAlgo')
    s = s.replace('isGCMAlgo(', 'isInnerAEADAlgo(')
    s = s.replace('GCM cipher init failed', 'inner AEAD init failed')
    s = s.replace('任一种认证 GCM', '任一种认证内层 AEAD')
    s = s.replace('AES-128 悄悄升级/降级成 AES-256', '不同 AEAD 悄悄升级/降级')
    p.write_text(s)

# Comments / UI selectors / perf help.
for name in ['frame.go', 'README.md', 'scripts/real_tap_perf.sh']:
    p = Path(name); s = p.read_text()
    s = s.replace('none / AES-256-GCM / AES-128-GCM', 'none / AES-256-GCM / AES-128-GCM / ChaCha20-Poly1305 / XChaCha20-Poly1305')
    s = s.replace('gcm256 | gcm128 (default: gcm256)', 'gcm256 | gcm128 | chacha20 | xchacha20 (default: gcm256)')
    s = s.replace('authenticated AES-GCM inside the tunnel', 'authenticated AEAD inside the tunnel (AES-GCM, ChaCha20-Poly1305 or XChaCha20-Poly1305)')
    p.write_text(s)

p = Path('openwrt/luci-proto-tlsvpn/htdocs/luci-static/resources/protocol/tlsvpn.js')
s = p.read_text()
needle = "\t\to.value('gcm128', _('AES-128-GCM (faster)'));\n"
if needle in s and "o.value('chacha20'" not in s:
    s = s.replace(needle, needle + "\t\to.value('chacha20', _('ChaCha20-Poly1305'));\n\t\to.value('xchacha20', _('XChaCha20-Poly1305'));\n", 1)
p.write_text(s)

p = Path('tests/test_openwrt_integration.sh'); s = p.read_text()
needle = 'grep -Fq "o.value(\'gcm128\'" "${luci}"\n'
if needle in s and "o.value('chacha20'" not in s:
    s = s.replace(needle, needle + 'grep -Fq "o.value(\'chacha20\'" "${luci}"\ngrep -Fq "o.value(\'xchacha20\'" "${luci}"\n', 1)
p.write_text(s)

# Extend golden vectors with all AEAD algorithms while retaining the legacy GCM field.
p = Path('protocol_conformance_test.go'); s = p.read_text()
s = s.replace('\tGCMDomainVectors []GCMDomainVec `json:"gcm_domain_vectors"`\n', '\tGCMDomainVectors []GCMDomainVec `json:"gcm_domain_vectors"`\n\tAEADDomainVectors []AEADDomainVec `json:"aead_domain_vectors"`\n', 1)
marker = '''type GCMDomainVec struct {\n\tPSK           string `json:"psk"`\n\tSaltHex       string `json:"salt_hex"`\n\tDomain        string `json:"domain"`\n\tSeq           uint32 `json:"seq"`\n\tPlaintextHex  string `json:"plaintext_hex"`\n\tCiphertextHex string `json:"ciphertext_hex"`\n}\n'''
add = marker + '''\ntype AEADDomainVec struct {\n\tAlgo          int    `json:"algo"`\n\tPSK           string `json:"psk"`\n\tSaltHex       string `json:"salt_hex"`\n\tDomain        string `json:"domain"`\n\tSeq           uint32 `json:"seq"`\n\tPlaintextHex  string `json:"plaintext_hex"`\n\tCiphertextHex string `json:"ciphertext_hex"`\n}\n'''
if marker not in s: raise SystemExit('GCMDomainVec marker not found')
s = s.replace(marker, add, 1)
needle = '''\tfor _, domain := range []string{"data", "fec"} {\n\t\tic, err := newGCMInnerCipherDomain(gcmPSK, gcmSalt, domain)\n'''
if needle not in s: raise SystemExit('golden GCM loop not found')
# Insert generic AEAD vectors immediately after the existing GCM loop's closing block by using the next headers marker.
headers_marker = '\n\theaders := []struct {\n'
idx = s.index(headers_marker, s.index(needle))
aead_block = '''\n\tfor _, algo := range []int{encAlgoGCM, encAlgoGCM128, encAlgoChaCha20, encAlgoXChaCha20} {\n\t\tfor _, domain := range []string{"data", "fec"} {\n\t\t\tic, err := newInnerCipherDomainForAlgo(gcmPSK, gcmSalt, domain, algo)\n\t\t\tif err != nil { panic(err) }\n\t\t\twire := make([]byte, len(gcmPlain)+aeadTagSize)\n\t\t\tcopy(wire, gcmPlain)\n\t\t\tic.sealInPlace(wire, len(gcmPlain), 0x01020304, uint32(len(wire)))\n\t\t\tgv.AEADDomainVectors = append(gv.AEADDomainVectors, AEADDomainVec{\n\t\t\t\tAlgo: algo, PSK: gcmPSK, SaltHex: hex.EncodeToString(gcmSalt),\n\t\t\t\tDomain: domain, Seq: 0x01020304, PlaintextHex: hex.EncodeToString(gcmPlain),\n\t\t\t\tCiphertextHex: hex.EncodeToString(wire),\n\t\t\t})\n\t\t}\n\t}\n'''
s = s[:idx] + aead_block + s[idx:]
p.write_text(s)

# Add generic unit/nonce tests.
Path('chacha_cipher_test.go').write_text(r'''package main

import (
    "bytes"
    "encoding/binary"
    "testing"
)

func TestChaChaInnerAEADRoundTripAndTamper(t *testing.T) {
    salt := []byte{0, 1, 2, 3, 4, 5, 6, 7}
    pt := []byte("chacha inner payload")
    for _, algo := range []int{encAlgoChaCha20, encAlgoXChaCha20} {
        tx, err := newInnerCipherForAlgo("chacha-test-psk", salt, algo)
        if err != nil { t.Fatalf("algo=%d tx init: %v", algo, err) }
        rx, err := newInnerCipherForAlgo("chacha-test-psk", salt, algo)
        if err != nil { t.Fatalf("algo=%d rx init: %v", algo, err) }
        buf := make([]byte, len(pt)+tx.tagLen())
        copy(buf, pt)
        wireLen := uint32(len(buf))
        gotLen := tx.sealInPlace(buf, len(pt), 0x10203040, wireLen)
        if gotLen != len(buf) { t.Fatalf("algo=%d len=%d want=%d", algo, gotLen, len(buf)) }
        out, err := rx.openInPlace(buf, 0x10203040, wireLen)
        if err != nil || !bytes.Equal(out, pt) { t.Fatalf("algo=%d roundtrip err=%v out=%x", algo, err, out) }

        bad := make([]byte, len(pt)+tx.tagLen())
        copy(bad, pt)
        tx.sealInPlace(bad, len(pt), 7, uint32(len(bad)))
        bad[len(bad)-1] ^= 1
        if _, err := rx.openInPlace(bad, 7, uint32(len(bad))); err == nil { t.Fatalf("algo=%d accepted tampered tag", algo) }
    }
}

func TestXChaChaNonceDerivedFromExistingSalt(t *testing.T) {
    salt := []byte{0, 1, 2, 3, 4, 5, 6, 7}
    a, _ := newInnerCipherForAlgo("xnonce-psk", salt, encAlgoXChaCha20)
    b, _ := newInnerCipherForAlgo("xnonce-psk", salt, encAlgoXChaCha20)
    sa := new(nonceAADScratch)
    sb := new(nonceAADScratch)
    n1, aad1 := a.nonceAAD(1, 100, sa)
    n2, _ := b.nonceAAD(1, 100, sb)
    if len(n1) != 24 { t.Fatalf("xchacha nonce len=%d", len(n1)) }
    if !bytes.Equal(n1, n2) { t.Fatal("same existing salt must derive the same XChaCha nonce") }
    if binary.BigEndian.Uint32(n1[20:24]) != 1 { t.Fatalf("seq suffix=%x", n1[20:24]) }
    if binary.BigEndian.Uint32(aad1[:4]) != 100 || binary.BigEndian.Uint32(aad1[4:]) != 1 { t.Fatalf("aad=%x", aad1) }
    sc := new(nonceAADScratch)
    n3, _ := a.nonceAAD(2, 100, sc)
    if bytes.Equal(n1, n3) { t.Fatal("different seq reused XChaCha nonce") }
}

func TestEncAlgoConfigIncludesChaCha(t *testing.T) {
    cases := map[string]int{"gcm256": encAlgoGCM, "gcm128": encAlgoGCM128, "chacha20": encAlgoChaCha20, "xchacha20": encAlgoXChaCha20}
    for name, want := range cases {
        if got := encAlgoFromConfig(name); got != want { t.Fatalf("%s => %d want %d", name, got, want) }
        if got := encAlgoLabel(want); got != name { t.Fatalf("label(%d)=%s want %s", want, got, name) }
        if !isInnerAEADAlgo(want) { t.Fatalf("algo %s not recognized as inner AEAD", name) }
    }
}
''')

Path('chacha_bench_test.go').write_text(r'''package main

import "testing"

func benchmarkInnerAEADSealOpen(b *testing.B, algo int) {
    salt := []byte{0,1,2,3,4,5,6,7}
    tx, err := newInnerCipherForAlgo("bench-inner-aead", salt, algo)
    if err != nil { b.Fatal(err) }
    rx, err := newInnerCipherForAlgo("bench-inner-aead", salt, algo)
    if err != nil { b.Fatal(err) }
    pt := make([]byte, 1400)
    buf := make([]byte, len(pt)+tx.tagLen())
    b.SetBytes(int64(len(pt)))
    b.ReportAllocs()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        copy(buf, pt)
        seq := uint32(i+1)
        tx.sealInPlace(buf, len(pt), seq, uint32(len(buf)))
        if _, err := rx.openInPlace(buf, seq, uint32(len(buf))); err != nil { b.Fatal(err) }
    }
}
func BenchmarkChaCha20Poly1305SealOpen(b *testing.B) { benchmarkInnerAEADSealOpen(b, encAlgoChaCha20) }
func BenchmarkXChaCha20Poly1305SealOpen(b *testing.B) { benchmarkInnerAEADSealOpen(b, encAlgoXChaCha20) }
''')
