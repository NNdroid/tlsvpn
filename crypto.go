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
	"math/big"
)

func hashPSK(psk string) string {
	h := sha256.Sum256([]byte(psk))
	return hex.EncodeToString(h[:])
}

// getCipherContext 根据 PSK 派生出 AES 块和基础 IV
func getCipherContext(psk string) (cipher.Block, []byte) {
	keyHash := sha256.Sum256([]byte(psk + "_enc_key"))
	ivHash := sha256.Sum256([]byte(psk + "_enc_iv"))
	block, err := aes.NewCipher(keyHash[:]) // 衍生为 AES-256
	if err != nil {
		panic(err)
	}
	return block, ivHash[:16]
}

// xorCryptInPlace 高速流式异或，原址修改数据（加解密通用）
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

// ======================= TLS 伪装 =======================
func getServerTLSConfig(certFile, keyFile string) *tls.Config {
	var cert tls.Certificate
	var err error

	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to load custom TLS pair: %v", err)
		}
	} else {
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
		cert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			panic(err)
		}
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
}
