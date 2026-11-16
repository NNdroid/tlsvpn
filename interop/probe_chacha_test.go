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
		// KDF 自 v2 起为 HKDF-SHA256(ikm=psk, salt=encSalt, info=label)（见
		// crypto.go newInnerCipherDomainForAlgo）。这些是加盐派生后的已知答案
		// 向量，跨语言实现必须复现。
		{5, "6c8cfe69b7093e921a6dbb35a2079b3c9636dc3ea4b91a8a33f8968524516c9f"},
		{6, "22d72483819893a0dc0e40f9e64e9fed1178928504a377529bf8f01b6cee8e09"},
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
