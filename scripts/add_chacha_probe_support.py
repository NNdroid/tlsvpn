#!/usr/bin/env python3
from pathlib import Path

p = Path('interop/probe.go')
s = p.read_text()
if 'golang.org/x/crypto/chacha20poly1305' not in s:
    s = s.replace('"time"\n)', '"time"\n\n\t"golang.org/x/crypto/chacha20poly1305"\n)', 1)

old = '''type probeCipher struct {\n\taead cipher.AEAD\n\tsalt [8]byte\n}\n\nfunc newProbeCipher(psk string, salt []byte, algo int) (*probeCipher, error) {\n\tif len(salt) != 8 {\n\t\treturn nil, fmt.Errorf("bad salt length %d", len(salt))\n\t}\n\tlabel := "_enc_key"\n\tkeyLen := 32\n\tswitch algo {\n\tcase 2:\n\t\t// existing AES-256-GCM\n\tcase 4:\n\t\tlabel = "_enc_key128"\n\t\tkeyLen = 16\n\tdefault:\n\t\treturn nil, fmt.Errorf("unsupported inner cipher %d", algo)\n\t}\n\tkey := sha256.Sum256([]byte(psk + label))\n\tblock, err := aes.NewCipher(key[:keyLen])\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\taead, err := cipher.NewGCM(block)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\tpc := &probeCipher{aead: aead}\n\tcopy(pc.salt[:], salt)\n\treturn pc, nil\n}\n\nfunc (c *probeCipher) nonce(seq uint32) []byte {\n\tn := make([]byte, 12)\n\tbinary.BigEndian.PutUint32(n[:4], seq)\n\tcopy(n[4:], c.salt[:])\n\treturn n\n}\n'''
new = '''type probeCipher struct {\n\taead cipher.AEAD\n\talgo int\n\tsalt [8]byte\n\txnoncePrefix [20]byte\n}\n\nfunc newProbeCipher(psk string, salt []byte, algo int) (*probeCipher, error) {\n\tif len(salt) != 8 {\n\t\treturn nil, fmt.Errorf("bad salt length %d", len(salt))\n\t}\n\tlabel := "_enc_key"\n\tkeyLen := 32\n\tswitch algo {\n\tcase 2:\n\tcase 4:\n\t\tlabel, keyLen = "_enc_key128", 16\n\tcase 5:\n\t\tlabel, keyLen = "_enc_chacha20", chacha20poly1305.KeySize\n\tcase 6:\n\t\tlabel, keyLen = "_enc_xchacha20", chacha20poly1305.KeySize\n\tdefault:\n\t\treturn nil, fmt.Errorf("unsupported inner cipher %d", algo)\n\t}\n\tkey := sha256.Sum256([]byte(psk + label))\n\tvar aead cipher.AEAD\n\tvar err error\n\tswitch algo {\n\tcase 2, 4:\n\t\tvar block cipher.Block\n\t\tblock, err = aes.NewCipher(key[:keyLen])\n\t\tif err == nil { aead, err = cipher.NewGCM(block) }\n\tcase 5:\n\t\taead, err = chacha20poly1305.New(key[:])\n\tcase 6:\n\t\taead, err = chacha20poly1305.NewX(key[:])\n\t}\n\tif err != nil { return nil, err }\n\tpc := &probeCipher{aead: aead, algo: algo}\n\tcopy(pc.salt[:], salt)\n\tif algo == 6 {\n\t\th := sha256.New()\n\t\th.Write([]byte("tlsvpn-xchacha20-nonce-v1"))\n\t\th.Write(salt)\n\t\tsum := h.Sum(nil)\n\t\tcopy(pc.xnoncePrefix[:], sum[:20])\n\t}\n\treturn pc, nil\n}\n\nfunc (c *probeCipher) nonce(seq uint32) []byte {\n\tif c.algo == 6 {\n\t\tn := make([]byte, chacha20poly1305.NonceSizeX)\n\t\tcopy(n[:20], c.xnoncePrefix[:])\n\t\tbinary.BigEndian.PutUint32(n[20:], seq)\n\t\treturn n\n\t}\n\tn := make([]byte, 12)\n\tbinary.BigEndian.PutUint32(n[:4], seq)\n\tcopy(n[4:], c.salt[:])\n\treturn n\n}\n'''
if old not in s: raise SystemExit('probe cipher block not found')
s = s.replace(old, new, 1)
s = s.replace('if !resp.Encrypt || (resp.EncAlgo != 2 && resp.EncAlgo != 4) {', 'if !resp.Encrypt || (resp.EncAlgo != 2 && resp.EncAlgo != 4 && resp.EncAlgo != 5 && resp.EncAlgo != 6) {', 1)
s = s.replace('panic("unexpected GCM length")', 'panic("unexpected AEAD length")')
p.write_text(s)

p = Path('interop/go.mod')
s = p.read_text()
if 'golang.org/x/crypto' not in s:
    s += '\nrequire golang.org/x/crypto v0.42.0\n'
p.write_text(s)
