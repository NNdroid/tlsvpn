package main

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
)

// Dynamic RX FEC bypass research primitives. These are intentionally not wired
// into AsyncPort or the receive loops yet. The purpose of this stage is to make
// the sender-authoritative fence format and generation/window semantics testable
// before changing the data path.
const (
	fecControlMagic   byte = 0xFD
	fecControlVersion byte = 1

	fecControlSuspend byte = 1
	fecControlResume  byte = 2

	fecControlWireLen = 16
)

type fecModeControl struct {
	Generation uint64
	Op         byte
	Boundary   uint32
}

func appendFECModeControl(dst []byte, c fecModeControl) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, fecControlWireLen)...)
	dst[start] = fecControlMagic
	dst[start+1] = fecControlVersion
	dst[start+2] = c.Op
	// start+3 is reserved for future flags and remains zero in v1.
	binary.BigEndian.PutUint64(dst[start+4:start+12], c.Generation)
	binary.BigEndian.PutUint32(dst[start+12:start+16], c.Boundary)
	return dst
}

func parseFECModeControl(payload []byte) (fecModeControl, bool) {
	if len(payload) != fecControlWireLen || payload[0] != fecControlMagic || payload[1] != fecControlVersion {
		return fecModeControl{}, false
	}
	if payload[3] != 0 {
		return fecModeControl{}, false
	}
	op := payload[2]
	if op != fecControlSuspend && op != fecControlResume {
		return fecModeControl{}, false
	}
	c := fecModeControl{
		Generation: binary.BigEndian.Uint64(payload[4:12]),
		Op:         op,
		Boundary:   binary.BigEndian.Uint32(payload[12:16]),
	}
	if c.Generation == 0 || c.Boundary == 0 {
		return fecModeControl{}, false
	}
	return c, true
}

// fecGroupStart returns the arithmetic FEC group start containing seq.
// Data sequence zero is reserved for control traffic and has no FEC group.
func fecGroupStart(seq uint32, k int) uint32 {
	if seq == 0 {
		return 0
	}
	k = clampFecGroup(k)
	return seq - ((seq - 1) % uint32(k))
}

// fecNextGroupStart returns the first complete arithmetic FEC group boundary
// at or after seq. TX uses this when >=2 physical paths return after a period in
// which FEC was suppressed. Zero means no complete group boundary remains in the
// current uint32 sequence epoch; TX must stay suppressed until the epoch resets.
func fecNextGroupStart(seq uint32, k int) uint32 {
	if seq == 0 {
		return 0
	}
	k = clampFecGroup(k)
	offset := (seq - 1) % uint32(k)
	if offset == 0 {
		return seq
	}
	delta := uint32(k) - offset
	next := uint64(seq) + uint64(delta)
	if next > uint64(^uint32(0)) {
		return 0
	}
	return uint32(next)
}

func packFECBypassWindow(from, until uint32) uint64 {
	return uint64(from)<<32 | uint64(until)
}

func unpackFECBypassWindow(v uint64) (from, until uint32) {
	return uint32(v >> 32), uint32(v)
}

// fecRXFenceState is the receiver-side model for dynamic sender-authoritative
// bypass. window is hot-path readable with one atomic load; mu/generation are
// touched only by rare control frames.
//
// Window semantics:
//
//	0,0        decoder active
//	from,0     bypass seq >= from
//	from,until bypass from <= seq < until
//
// A newer SUSPEND replaces any older historical window. Very late data from an
// older interval may then take the conservative decoder path, which is safe; it
// only loses some optimization.
type fecRXFenceState struct {
	mu         sync.Mutex
	generation uint64
	window     atomic.Uint64
}

func (s *fecRXFenceState) Apply(c fecModeControl) bool {
	if c.Generation == 0 || c.Boundary == 0 || (c.Op != fecControlSuspend && c.Op != fecControlResume) {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if c.Generation <= s.generation {
		return false
	}

	from, _ := unpackFECBypassWindow(s.window.Load())
	s.generation = c.Generation
	switch c.Op {
	case fecControlSuspend:
		s.window.Store(packFECBypassWindow(c.Boundary, 0))
	case fecControlResume:
		// RESUME can overtake a previous SUSPEND on another TCP stream. If that
		// SUSPEND was never observed, staying fully active is the conservative
		// choice. If it was observed, preserve the single-path interval until the
		// sender-declared complete-group boundary.
		if from == 0 || c.Boundary <= from {
			s.window.Store(0)
		} else {
			s.window.Store(packFECBypassWindow(from, c.Boundary))
		}
	}
	return true
}

func (s *fecRXFenceState) Window() (from, until uint32) {
	return unpackFECBypassWindow(s.window.Load())
}

func (s *fecRXFenceState) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

func (s *fecRXFenceState) BypassData(seq uint32) bool {
	if seq == 0 {
		return false
	}
	from, until := unpackFECBypassWindow(s.window.Load())
	if from == 0 || seq < from {
		return false
	}
	return until == 0 || seq < until
}

func (s *fecRXFenceState) BypassParity(groupStart uint32) bool {
	if groupStart == 0 {
		return false
	}
	from, until := unpackFECBypassWindow(s.window.Load())
	if from == 0 || groupStart < from {
		return false
	}
	return until == 0 || groupStart < until
}
