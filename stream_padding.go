package main

import (
	"encoding/binary"
	mathrand "math/rand/v2"
)

// streamTLSBatchSoftLimit keeps each application Write comfortably below the
// TLS 16KiB plaintext record limit. The outer TLS layer can therefore emit one
// record whose ciphertext is close to an integer number of TCP MSS segments.
const streamTLSBatchSoftLimit = 12 * 1024
const maxTLSPlaintextRecord = 16 * 1024

// MSS alignment is only a shaping hint. TCP itself is a continuous byte stream,
// so the next TLS write can naturally fill the previous segment's remaining
// space. Never spend a large share of useful traffic on cover bytes merely to
// force one application batch to an MSS boundary.
const streamPadRatioPercent = 10
const streamPadAbsoluteLimit = 512

// appendUnpaddedFrame is the data-plane framing primitive for stream buckets.
// Individual VPN frames are no longer bucket-padded; only the final frame in
// an aggregated TLS plaintext batch receives cover padding.
//
// 注意：本函数只写帧头（padLen 暂置 0）与明文负载，不做内层加密封装——
// 尾帧 padLen 要等整批聚合完成、padStreamBatchTail 决策后才能确定，而 AAD
// 必须绑定最终 padLen。整批的加密封装由 sealStreamBatchInPlace 在填充决策
// 之后统一执行。
func appendUnpaddedFrameWithScratch(buf []byte, vf VPNFrame, ic *innerCipher, scratch *nonceAADScratch) ([]byte, int) {
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
		// 标签预留区保持零值，sealStreamBatchInPlace 统一填充
	}
	return buf, startIdx
}

// sealStreamBatchInPlace 对聚合批次里的每个数据帧就地加密封装。必须在
// padStreamBatchTail 决定尾帧 padLen 之后调用：AAD 绑定每帧帧头的最终
// padLen（此前 padLen 不被认证，可被内层篡改导致帧边界去同步），接收端
// 按帧头 padLen 校验，两端自然一致。ic==nil 或 pad 关闭时同样正确（seq=0
// 控制帧跳过）。批次自描述（逐帧头推进），无需额外簿记。
func sealStreamBatchInPlace(buf []byte, ic *innerCipher, scratch *nonceAADScratch) {
	if ic == nil {
		return
	}
	tagLen := ic.tagLen()
	off := 0
	for off+10 <= len(buf) {
		wireLen := int(binary.BigEndian.Uint32(buf[off : off+4]))
		padLen := binary.BigEndian.Uint16(buf[off+4 : off+6])
		seq := binary.BigEndian.Uint32(buf[off+6 : off+10])
		if seq == 0 || wireLen <= tagLen {
			// 控制帧/心跳不加密；wireLen<=tagLen 是畸形容忍（接收端会拒）
			off += 10 + wireLen + int(padLen)
			continue
		}
		payload := buf[off+10 : off+10+wireLen]
		ic.sealInPlaceWithScratch(payload, wireLen-tagLen, seq, uint32(wireLen), padLen, scratch)
		off += 10 + wireLen + int(padLen)
	}
}

func appendUnpaddedFrame(buf []byte, vf VPNFrame, ic *innerCipher) ([]byte, int) {
	var scratch nonceAADScratch
	return appendUnpaddedFrameWithScratch(buf, vf, ic, &scratch)
}

func appendOwnedFrameBatchStreamWithScratch(buf []byte, frames []VPNFrame, ic *innerCipher, scratch *nonceAADScratch) ([]byte, int, int) {
	n := len(frames)
	last := -1
	for _, vf := range frames {
		var start int
		buf, start = appendUnpaddedFrameWithScratch(buf, vf, ic, scratch)
		last = start
	}
	freeFrames(frames)
	putVPNFrameBatch(frames)
	return buf, n, last
}

func appendOwnedVPNFrameBatchStreamWithScratch(buf []byte, batch *VPNFrameBatch, ic *innerCipher, scratch *nonceAADScratch, totals ...*txFrameTotals) ([]byte, int, int) {
	if batch == nil {
		return buf, 0, -1
	}
	n := len(batch.Frames)
	last := -1
	for _, vf := range batch.Frames {
		var start int
		buf, start = appendUnpaddedFrameWithScratch(buf, vf, ic, scratch)
		if len(totals) > 0 && totals[0] != nil {
			totals[0].add(vf, len(buf)-start)
		}
		last = start
	}
	freeFrames(batch.Frames)
	putOwnedVPNFrameBatch(batch)
	return buf, n, last
}

func appendOwnedFrameBatchStream(buf []byte, frames []VPNFrame, ic *innerCipher) ([]byte, int, int) {
	var scratch nonceAADScratch
	return appendOwnedFrameBatchStreamWithScratch(buf, frames, ic, &scratch)
}

// streamAlignedTLSPlaintextTarget returns the smallest TLS plaintext length
// whose conservative TLS ciphertext budget is an integer number of TCP MSS
// segments. Padding is bounded by streamPaddingBudget before this target is
// accepted.
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

// padStreamBatchTail adds cover bytes only to the final TLSVPN frame in the
// aggregated plaintext batch. Earlier frames naturally pack one another's
// slack. If closing the final MSS gap would cost more than 10% of useful bytes
// or 512B, send the real bytes unchanged and let TCP combine the next write
// into the same continuous stream.
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
