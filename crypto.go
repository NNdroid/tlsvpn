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
	// 与算法号区分：0 不再表示任何加密算法，面板可无歧义地显示"明文"。
	encAlgoNone = 0
	// encAlgoGCM AES-256-GCM：nonce = seq(4BE) || salt(8B)。salt 每会话随机
	// 且 c2s/s2c 各一个，seq 会话内连续 —— 密钥流空间按 (salt, seq) 严格
	// 不相交，根治密钥流重放；GCM 标签同时提供完整性，任何篡改/异源注入
	// 的帧在解密时被丢弃（重放帧被重排窗口吸收或标签校验拦截）。
	// 唯一支持的内层算法：旧版 AES-CTR（无完整性校验、密钥流仅由 (PSK, seq)
	// 决定，跨会话/跨客户端重用）已随旧协议兼容一并移除，不再存在回退路径。
	encAlgoGCM    = 2 // AES-256-GCM（兼容既有协议）
	encAlgoGCM128 = 4 // AES-128-GCM（显式性能模式；3 曾被历史 GCM-v2 占用）
	gcmTagSize    = 16
	gcmNonceSize = 12
	encSaltSize  = 8
	// 不同算法使用独立 KDF label，避免 AES-128/256 在同一 PSK 下复用 key material。
	gcmKeyLabel    = "_enc_key"
	gcm128KeyLabel = "_enc_key128"
)

// innerCipher 封装内层 AES-GCM（AES-256 默认，AES-128 显式性能模式）：密文后附 16B 标签
// （线路 dataLen = 明文长 + 16，帧格式不变），AAD 覆盖 [线路 dataLen(4BE) ||
// seq(4BE)]，防止把有效密文挪到别的 seq 位置。nil 表示本方向未启用内层加密。
type innerCipher struct {
	aead cipher.AEAD
	salt [encSaltSize]byte
}

// newGCMInnerCipher 保持历史 AES-256-GCM 构造语义，供旧测试/调用继续使用。
func newGCMInnerCipher(psk string, salt []byte) (*innerCipher, error) {
	return newGCMInnerCipherForAlgo(psk, salt, encAlgoGCM)
}

func newGCMInnerCipherForAlgo(psk string, salt []byte, algo int) (*innerCipher, error) {
	return newGCMInnerCipherDomainForAlgo(psk, salt, "data", algo)
}

// newGCMInnerCipherDomain 保持历史 AES-256-GCM 语义。
func newGCMInnerCipherDomain(psk string, salt []byte, domain string) (*innerCipher, error) {
	return newGCMInnerCipherDomainForAlgo(psk, salt, domain, encAlgoGCM)
}

// newGCMInnerCipherDomainForAlgo 为数据帧/FEC 和 AES-128/256 分别派生独立 key。
// nonce/AAD/tag/frame wire format 完全相同，因此变化只由握手 enc_algo 显式协商。
func newGCMInnerCipherDomainForAlgo(psk string, salt []byte, domain string, algo int) (*innerCipher, error) {
	if domain != "data" && domain != "fec" {
		return nil, fmt.Errorf("unknown GCM domain %q", domain)
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
	default:
		return nil, fmt.Errorf("unsupported GCM algorithm %d", algo)
	}
	if domain == "fec" {
		label += "_fec"
	}
	keyHash := sha256.Sum256([]byte(psk + label))
	block, err := aes.NewCipher(keyHash[:keyLen])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ic := &innerCipher{aead: aead}
	copy(ic.salt[:], salt)
	return ic, nil
}

// newRandomSalt 生成会话盐（crypto/rand）
func newRandomSalt() [encSaltSize]byte {
	var s [encSaltSize]byte
	if _, err := rand.Read(s[:]); err != nil {
		panic("Failed to generate encryption salt: " + err.Error())
	}
	return s
}

// gcmNonce nonce = seq(4BE) || salt(8B)。GCM 计数器从 nonce||0x00000002 起
// 递增，永不触碰 nonce 本身。
func (ic *innerCipher) gcmNonce(seq uint32) []byte {
	var nonce [gcmNonceSize]byte
	binary.BigEndian.PutUint32(nonce[0:4], seq)
	copy(nonce[4:], ic.salt[:])
	return nonce[:]
}

// gcmAAD AAD 覆盖线路负载长度（含 tag）与 seq
func gcmAAD(wireLen, seq uint32) []byte {
	var aad [8]byte
	binary.BigEndian.PutUint32(aad[0:4], wireLen)
	binary.BigEndian.PutUint32(aad[4:8], seq)
	return aad[:]
}

func newGCMScratch() any { return new([gcmNonceSize + 8]byte) }

var gcmScratchPool = sync.Pool{New: newGCMScratch}

// gcmNonceAAD 在调用方提供的 20 字节 scratch 上一次构造 nonce 与 AAD。
// 热路径（每帧 Seal/Open）单独调用 gcmNonce/gcmAAD 会因接口调用逃逸产生
// 两次小堆分配；合并成单块 scratch 后每帧至多一次 20B 分配。
// 布局：buf[0:12] = nonce = seq(4BE) || salt(8B)；buf[12:20] = AAD = wireLen(4BE) || seq(4BE)。
func (ic *innerCipher) gcmNonceAAD(seq uint32, wireLen uint32, buf *[gcmNonceSize + 8]byte) (nonce, aad []byte) {
	binary.BigEndian.PutUint32(buf[0:4], seq)
	copy(buf[4:12], ic.salt[:])
	binary.BigEndian.PutUint32(buf[12:16], wireLen)
	binary.BigEndian.PutUint32(buf[16:20], seq)
	return buf[:gcmNonceSize], buf[gcmNonceSize:]
}

func encAlgoFromConfig(mode string) int {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "gcm128":
		return encAlgoGCM128
	default:
		return encAlgoGCM
	}
}

func encAlgoLabel(algo int) string {
	switch algo {
	case encAlgoGCM128:
		return "gcm128"
	case encAlgoGCM:
		return "gcm256"
	default:
		return "none"
	}
}

func isGCMAlgo(algo int) bool {
	return algo == encAlgoGCM || algo == encAlgoGCM128
}

func (ic *innerCipher) isGCM() bool {
	return ic != nil
}

// ======================= 加密强度下限 =======================
//
// 内层算法属于同一认证 GCM 家族（AES-256-GCM / AES-128-GCM），所以
// "强度下限"表示是否强制要求 GCM；具体 key size 由 enc_algo 精确匹配。
// 取值 ""/"any"（不设下限）与 "gcm"。
// 历史上的 ctr / legacy 档位对应的 AES-CTR 回退路径已移除。

const (
	minEncNone = 0 // 不设下限
	minEncGCM  = 1 // 最低要求 GCM 能力声明
)

// minEncRank 解析最低强度配置；0 表示不设下限
func minEncRank(mode string) int {
	if strings.EqualFold(strings.TrimSpace(mode), "gcm") {
		return minEncGCM
	}
	return minEncNone
}

// tagLen 该加密器在线路上额外占用的字节数
func (ic *innerCipher) tagLen() int {
	if ic.isGCM() {
		return gcmTagSize
	}
	return 0
}

// sealInPlace 就地加密 region 的前 ptLen 字节；region 必须预留 tagLen 空间。
// 返回写入总长（明文长 + tagLen）。
func (ic *innerCipher) sealInPlace(region []byte, ptLen int, seq uint32, wireLen uint32) int {
	if ptLen == 0 || ic == nil {
		return ptLen
	}
	// cipher.AEAD 是接口调用，栈上的 [20]byte scratch 会逃逸。池中保存的是
	// *[20]byte 指针，不会产生 slice-header 装箱分配；AEAD 返回前不会保留
	// nonce/AAD 引用，因此调用结束即可安全归池。
	scratch := gcmScratchPool.Get().(*[gcmNonceSize + 8]byte)
	nonce, aad := ic.gcmNonceAAD(seq, wireLen, scratch)
	out := ic.aead.Seal(region[:0], nonce, region[:ptLen], aad)
	gcmScratchPool.Put(scratch)
	return len(out)
}

// openInPlace 就地解密并校验，返回明文切片（dst 的前缀，复用原缓冲）。
// 校验失败返回错误，data 内容不可信。
func (ic *innerCipher) openInPlace(data []byte, seq uint32, wireLen uint32) ([]byte, error) {
	if len(data) == 0 || ic == nil {
		return data, nil
	}
	scratch := gcmScratchPool.Get().(*[gcmNonceSize + 8]byte)
	nonce, aad := ic.gcmNonceAAD(seq, wireLen, scratch)
	plain, err := ic.aead.Open(data[:0], nonce, data, aad)
	gcmScratchPool.Put(scratch)
	return plain, err
}

// openTo 解密 src（含标签）写入 dst（长度须等于明文长），返回明文。
// wireLen 与 seal 时的 AAD 长度字段一致。nonce + AAD 共用池化 scratch，
// 避免 FEC parity 解密路径再单独生成一个逃逸的 []byte AAD。
func (ic *innerCipher) openTo(dst, src []byte, seq uint32, wireLen uint32) ([]byte, error) {
	if ic == nil {
		copy(dst, src)
		return dst, nil
	}
	if len(src) < gcmTagSize {
		return nil, fmt.Errorf("gcm payload too short: %d", len(src))
	}
	scratch := gcmScratchPool.Get().(*[gcmNonceSize + 8]byte)
	nonce, aad := ic.gcmNonceAAD(seq, wireLen, scratch)
	plain, err := ic.aead.Open(dst[:0], nonce, src, aad)
	gcmScratchPool.Put(scratch)
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

	return &tls.Config{
		Certificates:                []tls.Certificate{cert},
		NextProtos:                  []string{"h2", "http/1.1"},
		// TLSVPN 是长连接 bulk transport。固定最大 record 可减少高吞吐数据面
		// 的 TLS record/AEAD/write 次数；不改变 TLS 协议或对端兼容性。
		DynamicRecordSizingDisabled: true,
	}
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
