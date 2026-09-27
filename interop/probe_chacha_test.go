package main

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestProbeChaChaKnownAnswerVectors(t *testing.T) {
	psk := "cross-language-domain-vector"
	salt, err := hex.DecodeString("0011223344556677")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := hex.DecodeString("65746865726e65742d7061796c6f6164")
	if err != nil {
		t.Fatal(err)
	}
	const seq = uint32(0x01020304)

	cases := []struct {
		algo int
		want string
	}{
		{5, "720c46b7bdec71fd38fbde65073f9bab7b0f40fa6bed33a973127531ce7f14d5"},
		{6, "dab95dcd60c7526fea52c69928fcce4fe639b2d03e02e543dc5158522649d397"},
	}
	for _, tc := range cases {
		c, err := newProbeCipher(psk, salt, tc.algo)
		if err != nil {
			t.Fatalf("algo=%d init: %v", tc.algo, err)
		}
		wireLen := uint32(len(plain) + gcmTagSize)
		var aad [8]byte
		binary.BigEndian.PutUint32(aad[:4], wireLen)
		binary.BigEndian.PutUint32(aad[4:], seq)
		got := c.aead.Seal(nil, c.nonce(seq), plain, aad[:])
		if hex.EncodeToString(got) != tc.want {
			t.Fatalf("algo=%d got=%x want=%s", tc.algo, got, tc.want)
		}
	}
}
