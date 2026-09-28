from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    s = p.read_text()
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{path}: expected 1 match, got {n}")
    p.write_text(s.replace(old, new, 1))

stream_go = r'''package main

import (
    "encoding/binary"
    mathrand "math/rand/v2"
)

// streamTLSBatchSoftLimit keeps each application Write comfortably below the
// TLS 16KiB plaintext record limit. The outer TLS layer can therefore emit one
// record whose ciphertext is close to an integer number of TCP MSS segments.
const streamTLSBatchSoftLimit = 12 * 1024
const maxTLSPlaintextRecord = 16 * 1024

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
// segments. Padding is bounded to <1 MSS and never pushes plaintext above the
// TLS 16KiB record limit.
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

// padStreamBatchTail adds cover bytes only to the final TLSVPN frame in the
// aggregated plaintext batch. Earlier frames naturally pack one another's
// slack, so cover traffic is paid only for the final partial TCP segment.
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
    oldPad := int(binary.BigEndian.Uint16(buf[lastFrameStart+4 : lastFrameStart+6]))
    if oldPad+padLen > 0xffff {
        return buf, 0
    }
    binary.BigEndian.PutUint16(buf[lastFrameStart+4:lastFrameStart+6], uint16(oldPad+padLen))
    offset := mathrand.IntN(RandomPoolSize - padLen)
    buf = append(buf, randomPool[offset:offset+padLen]...)
    return buf, padLen
}
'''
Path("stream_padding.go").write_text(stream_go)

stream_test = r'''package main

import (
    "encoding/binary"
    "testing"
)

func TestStreamAlignedTLSPlaintextTarget(t *testing.T) {
    if got := streamAlignedTLSPlaintextTarget(2000, 1440); got != 2848 {
        t.Fatalf("2000B batch target=%d want 2848", got)
    }
    if got := streamAlignedTLSPlaintextTarget(10000, 1440); got != 10048 {
        t.Fatalf("10000B batch target=%d want 10048", got)
    }
}

func TestStreamTailPaddingOnlyTouchesLastFrame(t *testing.T) {
    old := setPadMode(padModeBucket)
    defer setPadMode(old)
    frames := getVPNFrameBatch(2)
    frames[0] = VPNFrame{Seq: 1, Data: cloneFrame(make([]byte, 700))}
    frames[1] = VPNFrame{Seq: 2, Data: cloneFrame(make([]byte, 700))}
    buf, _, last := appendOwnedFrameBatchStream(nil, frames, nil)
    firstPad := binary.BigEndian.Uint16(buf[4:6])
    if firstPad != 0 {
        t.Fatalf("first frame unexpectedly padded: %d", firstPad)
    }
    before := len(buf)
    buf, pad := padStreamBatchTail(buf, last, paddingRecordLimitForMSS(1440))
    if pad <= 0 || len(buf) <= before {
        t.Fatalf("tail padding not added: pad=%d before=%d after=%d", pad, before, len(buf))
    }
    if got := binary.BigEndian.Uint16(buf[last+4 : last+6]); int(got) != pad {
        t.Fatalf("last frame pad header=%d want %d", got, pad)
    }
    if (len(buf)+tlsRecordOverheadReserve)%1440 != 0 {
        t.Fatalf("batch is not MSS aligned: plaintext=%d", len(buf))
    }
}
'''
Path("stream_padding_test.go").write_text(stream_test)

replace_once("frame.go", "const maxTLSWriteBatchBytes = 64 * 1024", "const maxTLSWriteBatchBytes = streamTLSBatchSoftLimit")
replace_once("client.go", "const MaxBatchBytes = 64 * 1024", "const MaxBatchBytes = streamTLSBatchSoftLimit")
replace_once("client.go", "\t\t\tbatchBytes += len(frame)\n\n\t\t\tqueueLen := len(p.ch)", "\t\t\tbatchBytes += len(frame)\n\n\t\t\t// Interactive bursts get one very short coalescing opportunity. Under\n\t\t\t// sustained load p.ch is already non-empty, so the hot bulk path never sleeps.\n\t\t\tif len(p.ch) == 0 && batchBytes < MaxBatchBytes {\n\t\t\t\ttime.Sleep(150 * time.Microsecond)\n\t\t\t}\n\n\t\t\tqueueLen := len(p.ch)")

old_client = '''\t\t\t\tsendBuffer = sendBuffer[:0]\n\t\t\t\ttxPackets := 0\n\t\t\t\tvar padTotal uint64\n\t\t\tdrainBatches:\n\t\t\t\tfor {\n\t\t\t\t\tvar n int\n\t\t\t\t\tvar p uint64\n\t\t\t\t\tsendBuffer, n, p = appendOwnedFrameBatch(sendBuffer, frames, icTx, padRecordLimit)\n\t\t\t\t\ttxPackets += n\n\t\t\t\t\tpadTotal += p\n\t\t\t\t\tif len(sendBuffer) >= maxTLSWriteBatchBytes {\n\t\t\t\t\t\tbreak\n\t\t\t\t\t}\n\t\t\t\t\tselect {\n\t\t\t\t\tcase frames = <-connTxChan:\n\t\t\t\t\t\tcontinue\n\t\t\t\t\tdefault:\n\t\t\t\t\t\tbreak drainBatches\n\t\t\t\t\t}\n\t\t\t\t}\n'''
new_client = '''\t\t\t\tsendBuffer = sendBuffer[:0]\n\t\t\t\ttxPackets := 0\n\t\t\t\tlastFrameStart := -1\n\t\t\tdrainBatches:\n\t\t\t\tfor {\n\t\t\t\t\tvar n, last int\n\t\t\t\t\tsendBuffer, n, last = appendOwnedFrameBatchStream(sendBuffer, frames, icTx)\n\t\t\t\t\ttxPackets += n\n\t\t\t\t\tif last >= 0 {\n\t\t\t\t\t\tlastFrameStart = last\n\t\t\t\t\t}\n\t\t\t\t\tif len(sendBuffer) >= maxTLSWriteBatchBytes {\n\t\t\t\t\t\tbreak\n\t\t\t\t\t}\n\t\t\t\t\tselect {\n\t\t\t\t\tcase frames = <-connTxChan:\n\t\t\t\t\t\tcontinue\n\t\t\t\t\tdefault:\n\t\t\t\t\t\tbreak drainBatches\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t\tvar tailPad int\n\t\t\t\tsendBuffer, tailPad = padStreamBatchTail(sendBuffer, lastFrameStart, padRecordLimit)\n\t\t\t\tpadTotal := uint64(tailPad)\n'''
replace_once("client.go", old_client, new_client)
replace_once("server.go", old_client, new_client)
