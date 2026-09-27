package main

import "testing"

func benchmarkInnerAEADSealOpen(b *testing.B, algo int) {
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	tx, err := newInnerCipherForAlgo("bench-inner-aead", salt, algo)
	if err != nil {
		b.Fatal(err)
	}
	rx, err := newInnerCipherForAlgo("bench-inner-aead", salt, algo)
	if err != nil {
		b.Fatal(err)
	}
	pt := make([]byte, 1400)
	buf := make([]byte, len(pt)+tx.tagLen())
	b.SetBytes(int64(len(pt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf, pt)
		seq := uint32(i + 1)
		tx.sealInPlace(buf, len(pt), seq, uint32(len(buf)))
		if _, err := rx.openInPlace(buf, seq, uint32(len(buf))); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkChaCha20Poly1305SealOpen(b *testing.B) { benchmarkInnerAEADSealOpen(b, encAlgoChaCha20) }
func BenchmarkXChaCha20Poly1305SealOpen(b *testing.B) {
	benchmarkInnerAEADSealOpen(b, encAlgoXChaCha20)
}
