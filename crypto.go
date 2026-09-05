package main

import (
	"crypto/aes"
	"crypto/cipher"
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
)

func hashPSK(psk string) string {
	h := sha256.Sum256([]byte(psk))
	return hex.EncodeToString(h[:])
}

// ======================= 内层加密 =======================

const (
	// encAlgoLegacyCTR 旧版 AES-CTR 异或：无完整性校验，密钥流仅由 (PSK, seq)
	// 决定（跨会话/跨客户端重用）。仅在握手协商发现对端不支持 GCM 时回退使用。
	encAlgoLegacyCTR = 0
	// encAlgoGCM AES-256-GCM：nonce = seq(4BE) || salt(8B)。salt 每会话随机
	// 且 c2s/s2c 各一个，seq 会话内连续 —— 密钥流空间按 (salt, seq) 严格
	// 不相交，根治密钥流重放；GCM 标签同时提供完整性，任何篡改/异源注入
	// 的帧在解密时被丢弃（重放帧被重排窗口吸收或标签校验拦截）。
	encAlgoGCM   = 2
	gcmTagSize   = 16
	gcmNonceSize = 12
	encSaltSize  = 8
)

// innerCipher 封装内层载荷加密，两种算法共用一个调用面：
//   - legacy：xorCryptInPlace，帧长不变；
//   - gcm：密文后附 16B 标签（线路 dataLen = 明文长 + 16，帧格式不变），
//     AAD 覆盖 [线路 dataLen(4BE) || seq(4BE)]，防止把有效密文挪到别的 seq 位置。
type innerCipher struct {
	algo   int
	block  cipher.Block      // legacy
	baseIV []byte            // legacy 16B IV
	aead   cipher.AEAD       // gcm
	salt   [encSaltSize]byte // gcm
}

func newLegacyInnerCipher(psk string) *innerCipher {
	block, baseIV := getCipherContext(psk)
	return &innerCipher{algo: encAlgoLegacyCTR, block: block, baseIV: baseIV}
}

// newGCMInnerCipher 用会话盐构造 GCM 加密器。两个方向各用一个实例
// （c2s 用 resp.enc_salt，s2c 用 resp.enc_salt2）。
func newGCMInnerCipher(psk string, salt []byte) (*innerCipher, error) {
	if len(salt) != encSaltSize {
		return nil, fmt.Errorf("encryption salt must be %d bytes, got %d", encSaltSize, len(salt))
	}
	keyHash := sha256.Sum256([]byte(psk + "_enc_key"))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ic := &innerCipher{algo: encAlgoGCM, block: block, aead: aead}
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

// clientEncAlgoSupport 客户端握手请求里声明的本端最高算法支持
const clientEncAlgoSupport = encAlgoGCM

func (ic *innerCipher) isGCM() bool { return ic != nil && ic.algo == encAlgoGCM }

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
	switch ic.algo {
	case encAlgoGCM:
		// 复用明文存储：dst = region[:0]，密文+标签原地覆盖
		out := ic.aead.Seal(region[:0], ic.gcmNonce(seq), region[:ptLen], gcmAAD(wireLen, seq))
		return len(out)
	default:
		xorCryptInPlace(region[:ptLen], seq, ic.block, ic.baseIV)
		return ptLen
	}
}

// openInPlace 就地解密并校验，返回明文切片（dst 的前缀，复用原缓冲）。
// legacy 模式无校验、恒成功；gcm 校验失败返回错误，data 内容不可信。
func (ic *innerCipher) openInPlace(data []byte, seq uint32, wireLen uint32) ([]byte, error) {
	if len(data) == 0 || ic == nil {
		return data, nil
	}
	switch ic.algo {
	case encAlgoGCM:
		return ic.aead.Open(data[:0], ic.gcmNonce(seq), data, gcmAAD(wireLen, seq))
	default:
		xorCryptInPlace(data, seq, ic.block, ic.baseIV)
		return data, nil
	}
}

// openTo 解密 src（GCM 时含标签）写入 dst（长度须等于明文长），返回明文。
// legacy 模式 src 无标签，dst 长度等于 src。aad 必须与 seal 时一致。
func (ic *innerCipher) openTo(dst, src []byte, seq uint32, aad []byte) ([]byte, error) {
	if ic.isGCM() {
		if len(src) < gcmTagSize {
			return nil, fmt.Errorf("gcm payload too short: %d", len(src))
		}
		return ic.aead.Open(dst[:0], ic.gcmNonce(seq), src, aad)
	}
	copy(dst, src)
	if ic != nil {
		xorCryptInPlace(dst, seq, ic.block, ic.baseIV)
	}
	return dst, nil
}

// getCipherContext 根据 PSK 派生出 AES 块和基础 IV（legacy CTR + GCM 共用密钥）
func getCipherContext(psk string) (cipher.Block, []byte) {
	keyHash := sha256.Sum256([]byte(psk + "_enc_key"))
	ivHash := sha256.Sum256([]byte(psk + "_enc_iv"))
	block, err := aes.NewCipher(keyHash[:]) // 衍生为 AES-256
	if err != nil {
		panic(err)
	}
	return block, ivHash[:16]
}

// xorCryptInPlace 高速流式异或，原址修改数据（加解密通用，legacy 专用）
func xorCryptInPlace(data []byte, seq uint32, block cipher.Block, baseIV []byte) {
	if len(data) == 0 || block == nil {
		return
	}
	iv := make([]byte, 16)
	copy(iv, baseIV)
	// 将包的序列号(Seq)混淆进 IV，确保每个数据包的异或密钥流完全不同
	binary.BigEndian.PutUint32(iv[12:], seq)

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, data) // 高速异或位运算
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

	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
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
