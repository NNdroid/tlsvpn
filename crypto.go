package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// pskKey 由 PSK 派生的 32 字节密钥材料（hashPSK 的二进制形式）
func pskKey(psk string) []byte {
	h := sha256.Sum256([]byte(psk))
	return h[:]
}

func hashPSK(psk string) string { return hex.EncodeToString(pskKey(psk)) }

// computeSessionToken 会话令牌 = HMAC-SHA256(pskKey, "session-token-v1" ‖ sessionID)。
//
// 身份伪造的根因是"共享 PSK + 自报 MAC"：clientID 完全由 (mac, psk) 推导，
// 任何持密者只要知道目标 MAC 就能算出对方 clientID，触发会话复活分支接管
// 其隧道流量。令牌只在受害者的 TLS 会话内下发一次，重连时必须回带——
// 第三方从未见过它，因此无法冒充既有会话。首次接入仍走 PSK 校验。
func computeSessionToken(psk, sessionID string) string {
	m := hmac.New(sha256.New, pskKey(psk))
	m.Write([]byte("session-token-v1"))
	m.Write([]byte(sessionID))
	return hex.EncodeToString(m.Sum(nil))
}

// verifySessionToken 常量时间比较令牌
func verifySessionToken(psk, sessionID, want string) bool {
	return hmac.Equal([]byte(want), []byte(computeSessionToken(psk, sessionID)))
}

// newSessionToken 生成独立于共享 PSK 和可预测会话标识的重连凭据。共享 PSK
// 只证明“属于这个 VPN”，随机令牌才证明“拥有这个既有会话”。
func newSessionToken() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return hex.EncodeToString(token[:]), nil
}

func verifyRandomSessionToken(stored, want string) bool {
	return len(stored) == 64 && len(want) == 64 && hmac.Equal([]byte(stored), []byte(want))
}

// ======================= 内层加密 =======================

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
	xNonceSize        = 24
	encSaltSize       = 8

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
	aead         cipher.AEAD
	algo         int
	salt         [encSaltSize]byte
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
	if ic == nil {
		return 0
	}
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
		return buf[:xNonceSize], buf[xNonceSize : xNonceSize+8]
	}
	binary.BigEndian.PutUint32(buf[0:4], seq)
	copy(buf[4:12], ic.salt[:])
	binary.BigEndian.PutUint32(buf[12:16], wireLen)
	binary.BigEndian.PutUint32(buf[16:20], seq)
	return buf[:standardNonceSize], buf[standardNonceSize : standardNonceSize+8]
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
	if ptLen == 0 || ic == nil {
		return ptLen
	}
	scratch := aeadScratchPool.Get().(*nonceAADScratch)
	nonce, aad := ic.nonceAAD(seq, wireLen, scratch)
	out := ic.aead.Seal(region[:0], nonce, region[:ptLen], aad)
	aeadScratchPool.Put(scratch)
	return len(out)
}

func (ic *innerCipher) openInPlace(data []byte, seq uint32, wireLen uint32) ([]byte, error) {
	if len(data) == 0 || ic == nil {
		return data, nil
	}
	if len(data) < ic.tagLen() {
		return nil, fmt.Errorf("AEAD payload too short: %d", len(data))
	}
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
	if len(src) < ic.tagLen() {
		return nil, fmt.Errorf("AEAD payload too short: %d", len(src))
	}
	scratch := aeadScratchPool.Get().(*nonceAADScratch)
	nonce, aad := ic.nonceAAD(seq, wireLen, scratch)
	plain, err := ic.aead.Open(dst[:0], nonce, src, aad)
	aeadScratchPool.Put(scratch)
	return plain, err
}

// verifyCertHash 用服务器证书叶子证书的 SHA-256 指纹校验 -cert-sha256。
// expected 为 hex 编码（大小写不敏感、允许冒号分隔格式）。
func verifyCertHash(rawCerts [][]byte, expected string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates provided")
	}
	sum := sha256.Sum256(rawCerts[0])
	got := hex.EncodeToString(sum[:])
	want := strings.ToLower(strings.ReplaceAll(expected, ":", ""))
	if got != want {
		return fmt.Errorf("cert SHA-256 mismatch: expected %s, got %s", want, got)
	}
	return nil
}

// ======================= TLS 伪装 =======================
const (
	selfSignedCertFile = "tlsvpn-selfsigned-cert.pem"
	selfSignedKeyFile  = "tlsvpn-selfsigned-key.pem"
)

func getServerTLSConfig(certFile, keyFile string) *tls.Config {
	var cert tls.Certificate
	var err error

	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to load custom TLS pair: %v", err)
		}
	} else {
		cert = loadOrGenerateSelfSigned()
	}

	// 有效期快照供面板显示"证书剩余天数"：过期前运维就能看到，而不是等客户端全挂
	serverCertExp.Store(certExpiryInfo(&cert, certFile == "" || keyFile == ""))

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		// TLSVPN 是长连接 bulk transport。固定最大 record 可减少高吞吐数据面
		// 的 TLS record/AEAD/write 次数；不改变 TLS 协议或对端兼容性。
		DynamicRecordSizingDisabled: true,
	}
}

// certExpiry 监听证书的有效期。面板协议的一部分，只有一份定义。
type certExpiry struct {
	notAfter   time.Time
	selfSigned bool
}

var serverCertExp atomic.Pointer[certExpiry]

// certExpiryInfo 解析证书有效期。LoadX509KeyPair 会填 Leaf，自签生成的证书
// 只有 DER，两种都要处理；解析失败返回零值，面板按"未知"渲染。
func certExpiryInfo(cert *tls.Certificate, selfSigned bool) *certExpiry {
	var leaf *x509.Certificate
	if cert.Leaf != nil {
		leaf = cert.Leaf
	} else if len(cert.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	if leaf == nil {
		return &certExpiry{selfSigned: selfSigned}
	}
	return &certExpiry{notAfter: leaf.NotAfter, selfSigned: selfSigned}
}

// loadOrGenerateSelfSigned 加载/生成自签名证书并持久化到磁盘：
// 每次重启复用同一证书，客户端的 -cert-sha256 指纹锁定不会因重启失效。
func loadOrGenerateSelfSigned() tls.Certificate {
	if _, err1 := os.Stat(selfSignedCertFile); err1 == nil {
		if _, err2 := os.Stat(selfSignedKeyFile); err2 == nil {
			cert, err := tls.LoadX509KeyPair(selfSignedCertFile, selfSignedKeyFile)
			if err == nil {
				log.Infof("Loaded existing self-signed certificate from %s (fingerprint sha256 %s)",
					selfSignedCertFile, certFingerprintHex(cert.Certificate[0]))
				return cert
			}
			log.Warnf("Failed to load existing self-signed pair (%v), regenerating", err)
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// 持久化：私钥 0600，证书 0644。写入失败不影响运行（退化为内存内证书），
	// 但指纹会在下次重启变化，需重新固定 -cert-sha256。
	if err := os.WriteFile(selfSignedKeyFile, keyPEM, 0o600); err != nil {
		log.Warnf("Could not persist self-signed key: %v", err)
	} else if err := os.WriteFile(selfSignedCertFile, certPEM, 0o644); err != nil {
		log.Warnf("Could not persist self-signed cert: %v", err)
	} else {
		log.Infof("Generated self-signed certificate, saved to %s (fingerprint sha256 %s). "+
			"Pin it on clients with -cert-sha256 %s",
			selfSignedCertFile, certFingerprintHex(certDER), certFingerprintHex(certDER))
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return cert
}

// certFingerprintHex 证书 DER 的 SHA-256 十六进制指纹
func certFingerprintHex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
