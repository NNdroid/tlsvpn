package main

import "net"

// TLSVPN frames are written as TLS plaintext. TCP_MAXSEG is the maximum TCP
// payload, so keep one frame's padding target below it with enough room for a
// TLS record header + AEAD expansion. TLS 1.2 AES-GCM needs ~29 bytes and TLS
// 1.3 AEAD ~22 bytes; 32 bytes is a conservative common reserve.
const (
	fallbackTCPMSS           = 1440 // conservative 1500-MTU IPv6 fallback
	tlsRecordOverheadReserve = 32
)

// paddingRecordLimitForMSS returns the maximum TLSVPN record length
// (10-byte TLSVPN header + wire payload + padding) that bucket padding may
// target. It is deliberately a soft padding ceiling: frames that are already
// larger are sent unchanged rather than padded further.
func paddingRecordLimitForMSS(mss int) int {
	if mss < 256 {
		mss = fallbackTCPMSS
	}
	limit := mss - tlsRecordOverheadReserve
	if limit < 128 {
		return 128
	}
	return limit
}

// paddingRecordLimit uses the connected socket's effective TCP MSS when it is
// observable. SOCKS/proxied and non-Linux paths fall back conservatively.
func paddingRecordLimit(conn *net.TCPConn) int {
	mss, err := getTCPMSS(conn)
	if err != nil || mss <= 0 {
		mss = fallbackTCPMSS
	}
	return paddingRecordLimitForMSS(mss)
}
