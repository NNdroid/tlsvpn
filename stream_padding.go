package main

import (
	"encoding/binary"
	mathrand "math/rand/v2"
	"time"
)

// streamTLSBatchSoftLimit keeps each application Write comfortably below the
// TLS 16KiB plaintext record limit. The outer TLS layer can therefore emit one
// record whose ciphertext is close to an integer number of TCP MSS segments.
const streamTLSBatchSoftLimit = 12 * 1024
const maxTLSPlaintextRecord = 16 * 1024

// MSS alignment is a traffic-shaping hint, not a reason to spend a large
// fraction of the useful bandwidth on cover bytes. Tail padding is therefore
// allowed only when it fits BOTH the relative and absolute budgets below.
const streamPadRatioPercent = 10
const streamPadAbsoluteLimit = 512

// Sparse bursts get a bounded chance to accumulate more TAP frames before the
// writer decides whether the remaining tail is worth padding. Sustained loads
// already have queued frames and therefore do not sleep in the hot path.
const streamCoalesceMax = 500 * time.Microsecond

// appendUnpaddedFrame is the data-plane framing primitive for stream buckets.
// Individual VPN frames are no longer bucket-padded; only the final frame in
// an aggregated TLS plaintext batch receives cover padding.
func appendUnpaddedFrame(buf []byte, vf VPNFrame, ic *innerCipher) ([]byte, int) {
	dataLen := len(vf.Data)
	encTag := 0
	if ic != nil && vf.Seq != 0 && dataLen > 0 {
		encTag = ic.tagLen()
	}
	wireLen := dataLen + encTag
	needed := 10 + wireLen
	startIdx := len(buf)
	if cap(buf)-startIdx < needed {
		newCap := cap(buf) * 2
		if newCap < startIdx+needed {
			newCap = startIdx + needed
		}
		if newCap == 0 {
			newCap = needed
		}
		nb := make([]byte, startIdx, newCap)
		copy(nb, buf)
		buf = nb
	}
	buf = buf[:startIdx+needed]
	binary.BigEndian.PutUint32(buf[startIdx:startIdx+4], uint32(wireLen))
	binary.BigEndian.PutUint16(buf[startIdx+4:startIdx+6], 0)
	binary.BigEndian.PutUint32(buf[startIdx+6:startIdx+10], vf.Seq)
	if dataLen > 0 {
		payloadStart := startIdx + 10
		copy(buf[payloadStart:payloadStart+dataLen], vf.Data)
		if ic != nil && vf.Seq != 0 {
			ic.sealInPlace(buf[payloadStart:payloadStart+wireLen], dataLen, vf.Seq, uint32(wireLen))
		}
	}
	return buf, startIdx
}

func appendOwnedFrameBatchStream(buf []byte, frames []VPNFrame, ic *innerCipher) ([]byte, int, int) {
	n := len(frames)
	last := -1
	for _, vf := range frames {
		var start int
		buf, start = appendUnpaddedFrame(buf, vf, ic)
		last = start
	}
	freeFrames(frames)
	putVPNFrameBatch(frames)
	return buf, n, last
}

// streamAlignedTLSPlaintextTarget returns the smallest TLS plaintext length
// whose conservative TLS ciphertext budget is an integer number of TCP MSS
// segments. The caller still applies a cover-traffic budget before accepting
// this target.
func streamAlignedTLSPlaintextTarget(n, mss int) int {
	if n <= 0 {
		return n
	}
	if mss < 256 {
		mss = fallbackTCPMSS
	}
	segs := (n + tlsRecordOverheadReserve + mss - 1) / mss
	target := segs*mss - tlsRecordOverheadReserve
	if target < n || target > maxTLSPlaintextRecord {
		return n
	}
	return target
}

// streamPaddingBudget returns the maximum number of cover bytes worth spending
// for this batch. A candidate must fit both limits: <=10% of useful plaintext
// and <=512 bytes. In particular, a lone MTU-sized TAP frame will not be blown
// up to two full MSS segments just to make the final segment look full.
func streamPaddingBudget(batchLen int) int {
	if batchLen <= 0 {
		return 0
	}
	relative := batchLen * streamPadRatioPercent / 100
	if relative > streamPadAbsoluteLimit {
		return streamPadAbsoluteLimit
	}
	return relative
}

// streamCoalesceDelay is intentionally longest for tiny sparse bursts and
// quickly drops to zero as a useful TLS batch forms. The caller only consults
// it when the input queue is currently empty, so sustained bulk traffic takes
// the zero-sleep path regardless of batch size.
func streamCoalesceDelay(batchBytes int) time.Duration {
	switch {
	case batchBytes <= 0:
		return 0
	case batchBytes < 2*1024:
		return streamCoalesceMax
	case batchBytes < 4*1024:
		return 350 * time.Microsecond
	case batchBytes < 8*1024:
		return 150 * time.Microsecond
	default:
		return 0
	}
}

// padStreamBatchTail adds cover bytes only to the final TLSVPN frame in the
// aggregated plaintext batch. Earlier frames naturally pack one another's
// slack. MSS alignment is applied only when the remaining tail fits the cover
// traffic budget; otherwise the batch is sent as-is and TCP is allowed to carry
// a partial final segment rather than wasting a large fraction of the link.
func padStreamBatchTail(buf []byte, lastFrameStart, recordLimit int) ([]byte, int) {
	if padModeCode.Load() == padCodeOff || len(buf) == 0 || lastFrameStart < 0 {
		return buf, 0
	}
	mss := recordLimit + tlsRecordOverheadReserve
	target := streamAlignedTLSPlaintextTarget(len(buf), mss)
	padLen := target - len(buf)
	if padLen <= 0 || lastFrameStart+10 > len(buf) || padLen > 0xffff {
		return buf, 0
	}
	if padLen > streamPaddingBudget(len(buf)) {
		return buf, 0
	}
	oldPad := int(binary.BigEndian.Uint16(buf[lastFrameStart+4 : lastFrameStart+6]))
	if oldPad+padLen > 0xffff {
		return buf, 0
	}
	binary.BigEndian.PutUint16(buf[lastFrameStart+4:lastFrameStart+6], uint16(oldPad+padLen))
	offset := mathrand.IntN(RandomPoolSize - padLen)
	buf = append(buf, randomPool[offset:offset+padLen]...)
	return buf, padLen
}
