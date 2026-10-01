package main

import "fmt"

// protocolVersion is the only application protocol version accepted by this
// implementation. v3 intentionally breaks compatibility with the older
// seq=0 magic-dispatch semantics: post-handshake seq=0 is now an explicit
// control plane with typed payloads.
const protocolVersion = 3

const (
	controlKindFECParity byte = 0x01
	controlKindFECMode   byte = 0x02
)

func parseControlKind(payload []byte) (byte, error) {
	if len(payload) == 0 {
		return 0, fmt.Errorf("empty payload is keepalive, not a typed control frame")
	}
	switch payload[0] {
	case controlKindFECParity, controlKindFECMode:
		return payload[0], nil
	default:
		return 0, fmt.Errorf("unsupported control kind 0x%02x", payload[0])
	}
}
