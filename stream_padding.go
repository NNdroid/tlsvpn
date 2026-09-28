package main

import (
	"encoding/binary"
	"io"
	mathrand "math/rand/v2"
	"time"
)

// streamTLSBatchSoftLimit remains the AsyncPort batch target. The connection
// writer now keeps a persistent encoded byte stream above that layer, so one
// transport chunk may span multiple AsyncPort batches and may also cut through
// a TLSVPN frame boundary.
const streamTLSBatchSoftLimit = 12 * 1024
const maxTLSPlaintextRecord = 16 * 1024

// MSS alignment is only a shaping hint. Never spend a large share of the link
// on cover traffic just to close the final segment.
const streamPadRatioPercent = 10
const streamPadAbsoluteLimit = 512

// Low-rate traffic gets a bounded opportunity to accumulate another TAP frame.
// Bulk traffic reaches a full aligned chunk before this deadline and never
// sleeps in the data hot path.
const streamCoalesceMax = 500 * time.Microsecond

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

// streamAlignedTLSPlaintextTarget returns the smallest plaintext size whose
// conservative TLS ciphertext budget ends on a TCP MSS boundary.
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

// streamMaxAlignedTLSPlaintext returns the largest N*MSS plaintext target that
// still fits in one <=16KiB TLS plaintext record. Sustained traffic is sliced
// at exactly this byte count; a slice is allowed to cross TLSVPN frame/IP packet
// boundaries because FrameScanner reconstructs the continuous byte stream.
func streamMaxAlignedTLSPlaintext(mss int) int {
	if mss < 256 {
		mss = fallbackTCPMSS
	}
	segs := (maxTLSPlaintextRecord + tlsRecordOverheadReserve) / mss
	if segs < 1 {
		return maxTLSPlaintextRecord
	}
	target := segs*mss - tlsRecordOverheadReserve
	if target <= 0 || target > maxTLSPlaintextRecord {
		return maxTLSPlaintextRecord
	}
	return target
}

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

// padStreamBatchTail is kept for compatibility with focused framing tests and
// old call sites. New data-plane writers use tunnelStreamPacker and an explicit
// zero-data cover frame instead, so they can split the byte stream through an
// arbitrary VPN frame without rewriting a header that may already be sent.
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

// tunnelStreamPacker owns a persistent encoded TLSVPN byte stream. It tracks
// complete frame end offsets only for packet statistics; transport chunks are
// deliberately independent from those offsets.
type tunnelStreamPacker struct {
	buf       []byte
	off       int
	mss       int
	produced  uint64
	consumed  uint64
	frameEnds []uint64
	frameHead int
}

func newTunnelStreamPacker(recordLimit int) *tunnelStreamPacker {
	mss := recordLimit + tlsRecordOverheadReserve
	if mss < 256 {
		mss = fallbackTCPMSS
	}
	return &tunnelStreamPacker{
		buf:       make([]byte, 0, 2*maxTLSPlaintextRecord+4096),
		mss:       mss,
		frameEnds: make([]uint64, 0, 128),
	}
}

func (p *tunnelStreamPacker) available() int { return len(p.buf) - p.off }
func (p *tunnelStreamPacker) fullChunkSize() int {
	return streamMaxAlignedTLSPlaintext(p.mss)
}

// alignedPrefixSize returns the largest MSS-aligned plaintext prefix already
// present in the stream. It deliberately requires at least two outer segments:
// a lone ~1500B inner frame must not be split into one full record plus a tiny
// immediate tail. The unsent remainder is <1 MSS and naturally joins the next
// producer batch.
func (p *tunnelStreamPacker) alignedPrefixSize() int {
	avail := p.available()
	if avail <= 0 {
		return 0
	}
	maxTarget := streamMaxAlignedTLSPlaintext(p.mss)
	if avail >= maxTarget {
		return maxTarget
	}
	segs := (avail + tlsRecordOverheadReserve) / p.mss
	if segs < 2 {
		return 0
	}
	target := segs*p.mss - tlsRecordOverheadReserve
	if target <= 0 || target > avail {
		return 0
	}
	return target
}

// appendOwnedFrames encodes complete VPN frames consecutively but does not
// preserve those frame boundaries for transport writes. Ownership is released
// immediately after encoding.
func (p *tunnelStreamPacker) appendOwnedFrames(frames []VPNFrame, ic *innerCipher) int {
	n := len(frames)
	for _, vf := range frames {
		before := len(p.buf)
		p.buf, _ = appendUnpaddedFrame(p.buf, vf, ic)
		added := len(p.buf) - before
		p.produced += uint64(added)
		p.frameEnds = append(p.frameEnds, p.produced)
	}
	freeFrames(frames)
	putVPNFrameBatch(frames)
	return n
}

func (p *tunnelStreamPacker) peek(n int) []byte {
	if n < 0 || n > p.available() {
		return nil
	}
	return p.buf[p.off : p.off+n]
}

// consume advances by transport bytes and returns the number of complete
// TLSVPN data frames whose final byte has now been written.
func (p *tunnelStreamPacker) consume(n int) int {
	if n <= 0 {
		return 0
	}
	if n > p.available() {
		n = p.available()
	}
	p.off += n
	p.consumed += uint64(n)
	completed := 0
	for p.frameHead < len(p.frameEnds) && p.frameEnds[p.frameHead] <= p.consumed {
		p.frameHead++
		completed++
	}
	if p.frameHead >= 256 && p.frameHead*2 >= len(p.frameEnds) {
		copy(p.frameEnds, p.frameEnds[p.frameHead:])
		p.frameEnds = p.frameEnds[:len(p.frameEnds)-p.frameHead]
		p.frameHead = 0
	}
	if p.off == len(p.buf) {
		p.buf = p.buf[:0]
		p.off = 0
	} else if p.off >= 64*1024 {
		copy(p.buf, p.buf[p.off:])
		p.buf = p.buf[:len(p.buf)-p.off]
		p.off = 0
	}
	return completed
}

// appendIdleCover appends one explicit seq=0/dataLen=0 frame whose total size
// closes a small MSS gap. Because it is a separate frame, it remains valid even
// when the preceding data frame was already split across transport chunks.
// Large gaps are left unpadded.
func (p *tunnelStreamPacker) appendIdleCover() int {
	if padModeCode.Load() == padCodeOff || p.available() <= 0 {
		return 0
	}
	avail := p.available()
	target := streamAlignedTLSPlaintextTarget(avail, p.mss)
	cover := target - avail
	if cover < 10 || cover > streamPaddingBudget(avail) || cover > 0xffff+10 {
		return 0
	}
	start := len(p.buf)
	p.buf = append(p.buf, make([]byte, cover)...)
	binary.BigEndian.PutUint32(p.buf[start:start+4], 0)
	binary.BigEndian.PutUint16(p.buf[start+4:start+6], uint16(cover-10))
	binary.BigEndian.PutUint32(p.buf[start+6:start+10], 0)
	if cover > 10 {
		padLen := cover - 10
		offset := mathrand.IntN(RandomPoolSize - padLen)
		copy(p.buf[start+10:], randomPool[offset:offset+padLen])
	}
	p.produced += uint64(cover)
	return cover
}

// writeFull preserves stream position even if an io.Writer happens to return a
// short successful write. TLS writers normally consume the whole slice, but the
// loop makes the chunker semantics explicit and testable.
func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
