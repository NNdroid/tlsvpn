#!/usr/bin/env python3
from pathlib import Path
import re


def read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")


def must_replace(text: str, old: str, new: str, label: str, count: int = 1) -> str:
    found = text.count(old)
    if found < count:
        raise SystemExit(f"missing expected pattern {label}: found={found} need={count}")
    return text.replace(old, new, count)


def must_sub(text: str, pattern: str, repl: str, label: str, count: int = 1, flags: int = 0) -> str:
    out, n = re.subn(pattern, repl, text, count=count, flags=flags)
    if n != count:
        raise SystemExit(f"regex replacement {label}: got={n} want={count}")
    return out


# crypto.go: remove the process-wide pool and add scratch-aware primitives.
p = "crypto.go"
s = read(p)
if "aeadScratchPool" in s:
    s = must_replace(s, '\t"sync"\n', "", "crypto sync import")
    s = must_replace(
        s,
        "var aeadScratchPool = sync.Pool{New: func() any { return new(nonceAADScratch) }}\n\n",
        "",
        "aead scratch pool",
    )
    start = s.index("func (ic *innerCipher) sealInPlace(")
    end = s.index("\n// verifyCertHash", start)
    replacement = r'''func (ic *innerCipher) sealInPlaceWithScratch(region []byte, ptLen int, seq uint32, wireLen uint32, scratch *nonceAADScratch) int {
	if ptLen == 0 || ic == nil {
		return ptLen
	}
	nonce, aad := ic.nonceAAD(seq, wireLen, scratch)
	out := ic.aead.Seal(region[:0], nonce, region[:ptLen], aad)
	return len(out)
}

// sealInPlace is retained for tests/cold callers. The hot writer path passes a
// goroutine-local scratch explicitly via sealInPlaceWithScratch.
func (ic *innerCipher) sealInPlace(region []byte, ptLen int, seq uint32, wireLen uint32) int {
	var scratch nonceAADScratch
	return ic.sealInPlaceWithScratch(region, ptLen, seq, wireLen, &scratch)
}

func (ic *innerCipher) openInPlaceWithScratch(data []byte, seq uint32, wireLen uint32, scratch *nonceAADScratch) ([]byte, error) {
	if len(data) == 0 || ic == nil {
		return data, nil
	}
	if len(data) < ic.tagLen() {
		return nil, fmt.Errorf("AEAD payload too short: %d", len(data))
	}
	nonce, aad := ic.nonceAAD(seq, wireLen, scratch)
	return ic.aead.Open(data[:0], nonce, data, aad)
}

// openInPlace is retained for tests/cold callers. The hot reader path passes a
// goroutine-local scratch explicitly via openInPlaceWithScratch.
func (ic *innerCipher) openInPlace(data []byte, seq uint32, wireLen uint32) ([]byte, error) {
	var scratch nonceAADScratch
	return ic.openInPlaceWithScratch(data, seq, wireLen, &scratch)
}

func (ic *innerCipher) openToWithScratch(dst, src []byte, seq uint32, wireLen uint32, scratch *nonceAADScratch) ([]byte, error) {
	if ic == nil {
		copy(dst, src)
		return dst, nil
	}
	if len(src) < ic.tagLen() {
		return nil, fmt.Errorf("AEAD payload too short: %d", len(src))
	}
	nonce, aad := ic.nonceAAD(seq, wireLen, scratch)
	return ic.aead.Open(dst[:0], nonce, src, aad)
}

// openTo is retained for tests/cold callers. FEC RX passes its connection-local
// scratch explicitly via openToWithScratch.
func (ic *innerCipher) openTo(dst, src []byte, seq uint32, wireLen uint32) ([]byte, error) {
	var scratch nonceAADScratch
	return ic.openToWithScratch(dst, src, seq, wireLen, &scratch)
}
'''
    s = s[:start] + replacement + s[end:]
    write(p, s)


# stream_padding.go: thread the writer goroutine's scratch through batched frames.
p = "stream_padding.go"
s = read(p)
if "appendUnpaddedFrameWithScratch" not in s:
    s = must_replace(
        s,
        "func appendUnpaddedFrame(buf []byte, vf VPNFrame, ic *innerCipher) ([]byte, int) {",
        "func appendUnpaddedFrameWithScratch(buf []byte, vf VPNFrame, ic *innerCipher, scratch *nonceAADScratch) ([]byte, int) {",
        "appendUnpaddedFrame signature",
    )
    s = must_replace(
        s,
        "ic.sealInPlace(buf[payloadStart:payloadStart+wireLen], dataLen, vf.Seq, uint32(wireLen))",
        "ic.sealInPlaceWithScratch(buf[payloadStart:payloadStart+wireLen], dataLen, vf.Seq, uint32(wireLen), scratch)",
        "stream AEAD seal",
    )
    marker = "\treturn buf, startIdx\n}\n\nfunc appendOwnedFrameBatchStream("
    replacement = '''\treturn buf, startIdx
}

func appendUnpaddedFrame(buf []byte, vf VPNFrame, ic *innerCipher) ([]byte, int) {
	var scratch nonceAADScratch
	return appendUnpaddedFrameWithScratch(buf, vf, ic, &scratch)
}

func appendOwnedFrameBatchStreamWithScratch('''
    s = must_replace(s, marker, replacement, "stream batch signature")
    s = must_replace(
        s,
        "func appendOwnedFrameBatchStreamWithScratch(buf []byte, frames []VPNFrame, ic *innerCipher) ([]byte, int, int) {",
        "func appendOwnedFrameBatchStreamWithScratch(buf []byte, frames []VPNFrame, ic *innerCipher, scratch *nonceAADScratch) ([]byte, int, int) {",
        "stream scratch parameter",
    )
    s = must_replace(
        s,
        "buf, start = appendUnpaddedFrame(buf, vf, ic)",
        "buf, start = appendUnpaddedFrameWithScratch(buf, vf, ic, scratch)",
        "stream scratch use",
    )
    marker = "\treturn buf, n, last\n}\n\n// streamAlignedTLSPlaintextTarget"
    replacement = '''\treturn buf, n, last
}

func appendOwnedFrameBatchStream(buf []byte, frames []VPNFrame, ic *innerCipher) ([]byte, int, int) {
	var scratch nonceAADScratch
	return appendOwnedFrameBatchStreamWithScratch(buf, frames, ic, &scratch)
}

// streamAlignedTLSPlaintextTarget'''
    s = must_replace(s, marker, replacement, "stream compatibility wrapper")
    write(p, s)


# client/server: exactly one scratch per connection TX goroutine and one per RX
# goroutine. Reusing the RX scratch for parity is safe because OnControl is
# synchronous on that same reader goroutine.
for p in ("client.go", "server.go"):
    s = read(p)
    if "var txAEADScratch nonceAADScratch" not in s:
        s = must_sub(
            s,
            r"^(\s*)sendBuffer := make\(\[\]byte, 0, 64\*1024\+4096\)$",
            r"\1sendBuffer := make([]byte, 0, 64*1024+4096)\n\1var txAEADScratch nonceAADScratch",
            f"{p} TX scratch",
            flags=re.M,
        )
        if "appendOwnedFrameBatchStream(sendBuffer, frames, icTx)" not in s:
            raise SystemExit(f"missing {p} stream hot call")
        s = s.replace(
            "appendOwnedFrameBatchStream(sendBuffer, frames, icTx)",
            "appendOwnedFrameBatchStreamWithScratch(sendBuffer, frames, icTx, &txAEADScratch)",
        )
    if "var rxAEADScratch nonceAADScratch" not in s:
        s = must_sub(
            s,
            r"^(\s*)var rxBytesBatch, rxPacketsBatch uint64$",
            r"\1var rxBytesBatch, rxPacketsBatch uint64\n\1var rxAEADScratch nonceAADScratch",
            f"{p} RX scratch",
            flags=re.M,
        )
        if "icRx.openInPlace(frame, seq, uint32(len(frame)))" not in s:
            raise SystemExit(f"missing {p} RX AEAD hot call")
        s = s.replace(
            "icRx.openInPlace(frame, seq, uint32(len(frame)))",
            "icRx.openInPlaceWithScratch(frame, seq, uint32(len(frame)), &rxAEADScratch)",
        )
        # Client and server use different decoder receiver spellings.
        s = s.replace(
            "c.fecDec.OnControl(frame)",
            "c.fecDec.OnControlWithScratch(frame, &rxAEADScratch)",
        )
        s = s.replace(
            "fecDec.OnControl(frame)",
            "fecDec.OnControlWithScratch(frame, &rxAEADScratch)",
        )
    write(p, s)


# FEC TX is serial inside AsyncPort.run, so the encoder can retain one scratch.
# FEC RX is concurrently called by physical connection readers, so it receives
# the caller's RX-local scratch instead of storing a decoder-global scratch.
p = "fec.go"
s = read(p)
if "aeadScratch nonceAADScratch" not in s:
    s = must_replace(
        s,
        "\tic         *innerCipher\n\tparitySent uint64",
        "\tic          *innerCipher\n\taeadScratch nonceAADScratch\n\tparitySent  uint64",
        "fec encoder scratch field",
    )
    s = must_replace(
        s,
        "e.ic.sealInPlace(buf[off:off+maxLen+tagLen], maxLen, e.seqs[0], uint32(maxLen+tagLen))",
        "e.ic.sealInPlaceWithScratch(buf[off:off+maxLen+tagLen], maxLen, e.seqs[0], uint32(maxLen+tagLen), &e.aeadScratch)",
        "fec encoder scratch use",
    )

    old = '''func (d *fecDecoder) OnControl(payload []byte) error {
	kind, err := parseControlKind(payload)
	if err != nil {
		return err
	}
	switch kind {
	case controlKindFECParity:
		d.OnParity(payload)
		return nil
'''
    new = '''func (d *fecDecoder) OnControl(payload []byte) error {
	var scratch nonceAADScratch
	return d.OnControlWithScratch(payload, &scratch)
}

func (d *fecDecoder) OnControlWithScratch(payload []byte, scratch *nonceAADScratch) error {
	kind, err := parseControlKind(payload)
	if err != nil {
		return err
	}
	switch kind {
	case controlKindFECParity:
		d.OnParityWithScratch(payload, scratch)
		return nil
'''
    s = must_replace(s, old, new, "fec control scratch")

    old = '''// OnParity 处理一个校验帧负载。payload 只读借用，不转移所有权。
func (d *fecDecoder) OnParity(payload []byte) {
	if d.staticSingle.Load() || len(payload) < 7 || payload[0] != controlKindFECParity {
'''
    new = '''// OnParity 处理一个校验帧负载。payload 只读借用，不转移所有权。
func (d *fecDecoder) OnParity(payload []byte) {
	var scratch nonceAADScratch
	d.OnParityWithScratch(payload, &scratch)
}

func (d *fecDecoder) OnParityWithScratch(payload []byte, scratch *nonceAADScratch) {
	if d.staticSingle.Load() || len(payload) < 7 || payload[0] != controlKindFECParity {
'''
    s = must_replace(s, old, new, "fec parity scratch")
    s = must_replace(
        s,
        "d.ic.openTo(pb, payload[descLen:descLen+maxLen+tagLen], start, wireLen)",
        "d.ic.openToWithScratch(pb, payload[descLen:descLen+maxLen+tagLen], start, wireLen, scratch)",
        "fec decoder scratch use",
    )
    write(p, s)


# A microbenchmark for the exact API used by TX/RX goroutines. It is kept with
# the source change so future regressions can report allocs/op directly.
bench = Path("aead_local_scratch_bench_test.go")
if not bench.exists():
    bench.write_text(r'''package main

import "testing"

func benchmarkInnerAEADLocalScratch(b *testing.B, algo int) {
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	tx, err := newInnerCipherForAlgo("local-scratch-bench", salt, algo)
	if err != nil {
		b.Fatal(err)
	}
	rx, err := newInnerCipherForAlgo("local-scratch-bench", salt, algo)
	if err != nil {
		b.Fatal(err)
	}
	plaintext := make([]byte, 1400)
	buf := make([]byte, len(plaintext)+tx.tagLen())
	var txScratch, rxScratch nonceAADScratch
	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf, plaintext)
		seq := uint32(i + 1)
		tx.sealInPlaceWithScratch(buf, len(plaintext), seq, uint32(len(buf)), &txScratch)
		if _, err := rx.openInPlaceWithScratch(buf, seq, uint32(len(buf)), &rxScratch); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGCM256SealOpenLocalScratch(b *testing.B) {
	benchmarkInnerAEADLocalScratch(b, encAlgoGCM)
}

func BenchmarkGCM128SealOpenLocalScratch(b *testing.B) {
	benchmarkInnerAEADLocalScratch(b, encAlgoGCM128)
}

func BenchmarkChaCha20SealOpenLocalScratch(b *testing.B) {
	benchmarkInnerAEADLocalScratch(b, encAlgoChaCha20)
}

func BenchmarkXChaCha20SealOpenLocalScratch(b *testing.B) {
	benchmarkInnerAEADLocalScratch(b, encAlgoXChaCha20)
}
''', encoding="utf-8")
