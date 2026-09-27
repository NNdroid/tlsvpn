package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestChaChaInnerAEADRoundTripAndTamper(t *testing.T) {
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	pt := []byte("chacha inner payload")
	for _, algo := range []int{encAlgoChaCha20, encAlgoXChaCha20} {
		tx, err := newInnerCipherForAlgo("chacha-test-psk", salt, algo)
		if err != nil {
			t.Fatalf("algo=%d tx init: %v", algo, err)
		}
		rx, err := newInnerCipherForAlgo("chacha-test-psk", salt, algo)
		if err != nil {
			t.Fatalf("algo=%d rx init: %v", algo, err)
		}
		buf := make([]byte, len(pt)+tx.tagLen())
		copy(buf, pt)
		wireLen := uint32(len(buf))
		gotLen := tx.sealInPlace(buf, len(pt), 0x10203040, wireLen)
		if gotLen != len(buf) {
			t.Fatalf("algo=%d len=%d want=%d", algo, gotLen, len(buf))
		}
		out, err := rx.openInPlace(buf, 0x10203040, wireLen)
		if err != nil || !bytes.Equal(out, pt) {
			t.Fatalf("algo=%d roundtrip err=%v out=%x", algo, err, out)
		}

		bad := make([]byte, len(pt)+tx.tagLen())
		copy(bad, pt)
		tx.sealInPlace(bad, len(pt), 7, uint32(len(bad)))
		bad[len(bad)-1] ^= 1
		if _, err := rx.openInPlace(bad, 7, uint32(len(bad))); err == nil {
			t.Fatalf("algo=%d accepted tampered tag", algo)
		}
	}
}

func TestXChaChaNonceDerivedFromExistingSalt(t *testing.T) {
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	a, _ := newInnerCipherForAlgo("xnonce-psk", salt, encAlgoXChaCha20)
	b, _ := newInnerCipherForAlgo("xnonce-psk", salt, encAlgoXChaCha20)
	sa := new(nonceAADScratch)
	sb := new(nonceAADScratch)
	n1, aad1 := a.nonceAAD(1, 100, sa)
	n2, _ := b.nonceAAD(1, 100, sb)
	if len(n1) != 24 {
		t.Fatalf("xchacha nonce len=%d", len(n1))
	}
	if !bytes.Equal(n1, n2) {
		t.Fatal("same existing salt must derive the same XChaCha nonce")
	}
	if binary.BigEndian.Uint32(n1[20:24]) != 1 {
		t.Fatalf("seq suffix=%x", n1[20:24])
	}
	if binary.BigEndian.Uint32(aad1[:4]) != 100 || binary.BigEndian.Uint32(aad1[4:]) != 1 {
		t.Fatalf("aad=%x", aad1)
	}
	sc := new(nonceAADScratch)
	n3, _ := a.nonceAAD(2, 100, sc)
	if bytes.Equal(n1, n3) {
		t.Fatal("different seq reused XChaCha nonce")
	}
}

func TestEncAlgoConfigIncludesChaCha(t *testing.T) {
	cases := map[string]int{"gcm256": encAlgoGCM, "gcm128": encAlgoGCM128, "chacha20": encAlgoChaCha20, "xchacha20": encAlgoXChaCha20}
	for name, want := range cases {
		if got := encAlgoFromConfig(name); got != want {
			t.Fatalf("%s => %d want %d", name, got, want)
		}
		if got := encAlgoLabel(want); got != name {
			t.Fatalf("label(%d)=%s want %s", want, got, name)
		}
		if !isInnerAEADAlgo(want) {
			t.Fatalf("algo %s not recognized as inner AEAD", name)
		}
	}
}

func TestChaChaFECParityRoundTrip(t *testing.T) {
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	for _, algo := range []int{encAlgoChaCha20, encAlgoXChaCha20} {
		tx, err := newInnerCipherDomainForAlgo("chacha-fec-psk", salt, "fec", algo)
		if err != nil {
			t.Fatalf("algo=%d tx init: %v", algo, err)
		}
		rx, err := newInnerCipherDomainForAlgo("chacha-fec-psk", salt, "fec", algo)
		if err != nil {
			t.Fatalf("algo=%d rx init: %v", algo, err)
		}

		enc := newFECEncoder(2, tx)
		f1 := []byte{1, 2, 3, 4, 5}
		f2 := []byte{9, 8, 7, 6, 5}
		if got := enc.add(VPNFrame{Seq: 1, Data: f1}); got != nil {
			t.Fatalf("algo=%d parity emitted early", algo)
		}
		parity := enc.add(VPNFrame{Seq: 2, Data: f2})
		if parity == nil {
			t.Fatalf("algo=%d no parity", algo)
		}
		defer putFrame(parity)

		recovered := make(chan []byte, 1)
		dec := NewFECDecoder(2, rx, func(seq uint32, frame []byte) {
			if seq != 2 {
				t.Errorf("algo=%d recovered seq=%d want=2", algo, seq)
			}
			cp := append([]byte(nil), frame...)
			recovered <- cp
			putFrame(frame)
		})
		dec.OnData(1, f1)
		dec.OnParity(parity)
		select {
		case got := <-recovered:
			if !bytes.Equal(got, f2) {
				t.Fatalf("algo=%d recovered=%x want=%x", algo, got, f2)
			}
		default:
			t.Fatalf("algo=%d FEC did not recover missing frame", algo)
		}
	}
}
