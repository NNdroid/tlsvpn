package main

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
