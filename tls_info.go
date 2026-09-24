package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// tlsClientHelloFingerprintKind 是本项目定义的、跨 Go/Rust 一致的 ClientHello
// 摘要格式。它不是 JA3/JA4：标准库没有暴露扩展的完整原始顺序，冒充标准指纹会
// 给运维造成错误结论。这里仅哈希两端都能可靠观测的有序特征，并过滤 GREASE，
// 因而同一客户端的多连接不会只因随机 GREASE 值而产生不同结果。
const tlsClientHelloFingerprintKind = "tls-clienthello-v1"

// TLSHandshakeInfo 是服务端实际观测到的 TLS 握手摘要。它随成功的应用层握手
// 返回给已通过 PSK 验证的客户端；不包含随机数、会话票据、证书正文或密钥材料。
type TLSHandshakeInfo struct {
	FingerprintKind         string   `json:"fingerprint_kind,omitempty"`
	FingerprintSHA256       string   `json:"fingerprint_sha256,omitempty"`
	VersionID               uint16   `json:"version_id,omitempty"`
	Version                 string   `json:"version,omitempty"`
	CipherSuiteID           uint16   `json:"cipher_suite_id,omitempty"`
	CipherSuite             string   `json:"cipher_suite,omitempty"`
	ALPN                    string   `json:"alpn,omitempty"`
	SNI                     string   `json:"sni,omitempty"`
	OfferedCipherSuites     []uint16 `json:"offered_cipher_suites,omitempty"`
	OfferedSignatureSchemes []uint16 `json:"offered_signature_schemes,omitempty"`
	OfferedGroups           []uint16 `json:"offered_groups,omitempty"`
	OfferedALPN             []string `json:"offered_alpn,omitempty"`
}

type tlsClientHelloObservation struct {
	cipherSuites     []uint16
	signatureSchemes []uint16
	groups           []uint16
	alpn             []string
	sni              string
	fingerprint      string
}

func observeTLSClientHello(hello *tls.ClientHelloInfo) tlsClientHelloObservation {
	if hello == nil {
		return tlsClientHelloObservation{}
	}
	ciphers := normalizeTLSUint16(hello.CipherSuites)
	signatures := make([]uint16, len(hello.SignatureSchemes))
	for i, v := range hello.SignatureSchemes {
		signatures[i] = uint16(v)
	}
	signatures = normalizeTLSUint16(signatures)
	groups := make([]uint16, len(hello.SupportedCurves))
	for i, v := range hello.SupportedCurves {
		groups[i] = uint16(v)
	}
	groups = normalizeTLSUint16(groups)
	alpn := append([]string(nil), hello.SupportedProtos...)
	return tlsClientHelloObservation{
		cipherSuites:     ciphers,
		signatureSchemes: signatures,
		groups:           groups,
		alpn:             alpn,
		sni:              normalizeTLSSNI(hello.ServerName),
		fingerprint:      tlsClientHelloFingerprint(ciphers, signatures, groups, alpn),
	}
}

func tlsHandshakeInfoFromState(state tls.ConnectionState, hello tlsClientHelloObservation) *TLSHandshakeInfo {
	info := &TLSHandshakeInfo{
		FingerprintKind:         tlsClientHelloFingerprintKind,
		FingerprintSHA256:       hello.fingerprint,
		VersionID:               state.Version,
		Version:                 tlsVersionName(state.Version),
		CipherSuiteID:           state.CipherSuite,
		CipherSuite:             tls.CipherSuiteName(state.CipherSuite),
		ALPN:                    state.NegotiatedProtocol,
		SNI:                     normalizeTLSSNI(state.ServerName),
		OfferedCipherSuites:     append([]uint16(nil), hello.cipherSuites...),
		OfferedSignatureSchemes: append([]uint16(nil), hello.signatureSchemes...),
		OfferedGroups:           append([]uint16(nil), hello.groups...),
		OfferedALPN:             displayTLSALPNs(hello.alpn),
	}
	if info.SNI == "" {
		info.SNI = hello.sni
	}
	return info
}

func displayTLSALPNs(protocols []string) []string {
	out := make([]string, len(protocols))
	for i, proto := range protocols {
		if utf8.ValidString(proto) {
			out[i] = proto
		} else {
			out[i] = "hex:" + hex.EncodeToString([]byte(proto))
		}
	}
	return out
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		if version == 0 {
			return ""
		}
		return fmt.Sprintf("0x%04x", version)
	}
}

func normalizeTLSSNI(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

func isTLSGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && byte(v)&0x0f == 0x0a
}

func normalizeTLSUint16(values []uint16) []uint16 {
	out := make([]uint16, 0, len(values))
	for _, v := range values {
		if !isTLSGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// tlsClientHelloFingerprint 的规范字节串为：kind + NUL，随后依次是 cipher、
// signature、group 三个 u16 大端列表（u16 项数 + 各项），最后是 ALPN 列表
// （u16 项数 + 每项 u16 字节长度 + 原始字节）。SNI 刻意不参与哈希，避免同一
// 客户端只因伪装域名变化就变成另一种“客户端指纹”。
func tlsClientHelloFingerprint(ciphers, signatures, groups []uint16, alpn []string) string {
	var canonical bytes.Buffer
	canonical.WriteString(tlsClientHelloFingerprintKind)
	canonical.WriteByte(0)
	writeU16List := func(values []uint16) {
		if len(values) > int(^uint16(0)) {
			values = values[:int(^uint16(0))]
		}
		_ = binary.Write(&canonical, binary.BigEndian, uint16(len(values)))
		for _, v := range values {
			_ = binary.Write(&canonical, binary.BigEndian, v)
		}
	}
	writeU16List(normalizeTLSUint16(ciphers))
	writeU16List(normalizeTLSUint16(signatures))
	writeU16List(normalizeTLSUint16(groups))
	if len(alpn) > int(^uint16(0)) {
		alpn = alpn[:int(^uint16(0))]
	}
	_ = binary.Write(&canonical, binary.BigEndian, uint16(len(alpn)))
	for _, proto := range alpn {
		b := []byte(proto)
		if len(b) > int(^uint16(0)) {
			b = b[:int(^uint16(0))]
		}
		_ = binary.Write(&canonical, binary.BigEndian, uint16(len(b)))
		canonical.Write(b)
	}
	sum := sha256.Sum256(canonical.Bytes())
	return hex.EncodeToString(sum[:])
}
