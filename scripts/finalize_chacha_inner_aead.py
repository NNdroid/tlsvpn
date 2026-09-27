#!/usr/bin/env python3
from pathlib import Path

# FEC must treat every inner AEAD as having its actual tag length, not just AES-GCM.
p = Path('fec.go')
s = p.read_text()
s = s.replace('''\ttagLen := 0\n\tif e.ic != nil && e.ic.isGCM() {\n\t\ttagLen = gcmTagSize\n\t}\n''', '''\ttagLen := 0\n\tif e.ic != nil {\n\t\ttagLen = e.ic.tagLen()\n\t}\n''', 1)
s = s.replace('''\ttagLen := 0\n\tif d.ic != nil && d.ic.isGCM() {\n\t\ttagLen = gcmTagSize\n\t}\n''', '''\ttagLen := 0\n\tif d.ic != nil {\n\t\ttagLen = d.ic.tagLen()\n\t}\n''', 1)
s = s.replace('seq 用 GCM 独立 key domain 加密（见 newGCMInnerCipherDomain）。', 'seq 用独立 AEAD key domain 加密（见 newInnerCipherDomainForAlgo）。')
s = s.replace('（GCM 时附标签）', '（AEAD 附标签）')
s = s.replace('以 groupStart 为 CTR/GCM 的 seq。', '以 groupStart 为 AEAD 的 seq。')
p.write_text(s)

# Add a regression proving FEC parity works with both ChaCha variants.
p = Path('chacha_cipher_test.go')
s = p.read_text()
if 'TestChaChaFECParityRoundTrip' not in s:
    s += r'''

func TestChaChaFECParityRoundTrip(t *testing.T) {
    salt := []byte{0, 1, 2, 3, 4, 5, 6, 7}
    for _, algo := range []int{encAlgoChaCha20, encAlgoXChaCha20} {
        tx, err := newInnerCipherDomainForAlgo("chacha-fec-psk", salt, "fec", algo)
        if err != nil { t.Fatalf("algo=%d tx init: %v", algo, err) }
        rx, err := newInnerCipherDomainForAlgo("chacha-fec-psk", salt, "fec", algo)
        if err != nil { t.Fatalf("algo=%d rx init: %v", algo, err) }

        enc := newFECEncoder(2, tx)
        f1 := []byte{1,2,3,4,5}
        f2 := []byte{9,8,7,6,5}
        if got := enc.add(VPNFrame{Seq: 1, Data: f1}); got != nil { t.Fatalf("algo=%d parity emitted early", algo) }
        parity := enc.add(VPNFrame{Seq: 2, Data: f2})
        if parity == nil { t.Fatalf("algo=%d no parity", algo) }
        defer putFrame(parity)

        recovered := make(chan []byte, 1)
        dec := NewFECDecoder(2, rx, func(seq uint32, frame []byte) {
            if seq != 2 { t.Errorf("algo=%d recovered seq=%d want=2", algo, seq) }
            cp := append([]byte(nil), frame...)
            recovered <- cp
            putFrame(frame)
        })
        dec.OnData(1, f1)
        dec.OnParity(parity)
        select {
        case got := <-recovered:
            if !bytes.Equal(got, f2) { t.Fatalf("algo=%d recovered=%x want=%x", algo, got, f2) }
        default:
            t.Fatalf("algo=%d FEC did not recover missing frame", algo)
        }
    }
}
'''
p.write_text(s)

# Web dashboard: do not mislabel new authenticated algorithms as plaintext.
p = Path('webui/app.js')
s = p.read_text()
old = '''function encBadge(a){if(a===2)return '<span class="badge b-on">AES-256-GCM</span>';\n  if(a===4)return '<span class="badge b-on">AES-128-GCM</span>';\n  return '<span class="badge b-off">'+t('badge.plain')+'</span>';}'''
new = '''function encBadge(a){if(a===2)return '<span class="badge b-on">AES-256-GCM</span>';\n  if(a===4)return '<span class="badge b-on">AES-128-GCM</span>';\n  if(a===5)return '<span class="badge b-on">ChaCha20-Poly1305</span>';\n  if(a===6)return '<span class="badge b-on">XChaCha20-Poly1305</span>';\n  return '<span class="badge b-off">'+t('badge.plain')+'</span>';}'''
if old not in s: raise SystemExit('encBadge marker not found')
s = s.replace(old, new, 1)
p.write_text(s)

# Correct UI wording while retaining the existing stored min_enc value "gcm".
p = Path('openwrt/luci-proto-tlsvpn/htdocs/luci-static/resources/protocol/tlsvpn.js')
s = p.read_text()
s = s.replace("_('Inner AES-GCM encryption')", "_('Inner AEAD encryption')")
s = s.replace("o.value('gcm', _('Require GCM'));", "o.value('gcm', _('Require authenticated AEAD'));")
p.write_text(s)

p = Path('openwrt/luci-proto-tlsvpn/po/zh_Hans/tlsvpn.po')
s = p.read_text()
if 'msgid "ChaCha20-Poly1305"' not in s:
    insert_after = 'msgid "AES-128-GCM (faster)"\nmsgstr "AES-128-GCM（更快）"\n'
    if insert_after not in s: raise SystemExit('zh AES marker not found')
    s = s.replace(insert_after, insert_after + 'msgid "ChaCha20-Poly1305"\nmsgstr "ChaCha20-Poly1305"\nmsgid "XChaCha20-Poly1305"\nmsgstr "XChaCha20-Poly1305"\n', 1)
s = s.replace('msgid "Inner AES-GCM encryption"\nmsgstr "内层 AES-GCM 加密"', 'msgid "Inner AEAD encryption"\nmsgstr "内层 AEAD 加密"')
s = s.replace('msgid "Require GCM"\nmsgstr "要求 GCM"', 'msgid "Require authenticated AEAD"\nmsgstr "要求认证 AEAD"')
p.write_text(s)

# Documentation and API comments should describe all four algorithm IDs.
p = Path('api.go'); s = p.read_text()
s = s.replace('// encAlgoNone=0（TLS only）/ 2（AES-256-GCM）/ 4（AES-128-GCM）。', '// encAlgoNone=0（TLS only）/ 2（AES-256-GCM）/ 4（AES-128-GCM）/ 5（ChaCha20）/ 6（XChaCha20）。')
p.write_text(s)

p = Path('README.md'); s = p.read_text()
s = s.replace('| `encrypt` | `true` when omitted in JSON | Enable inner authenticated AES-GCM |', '| `encrypt` | `true` when omitted in JSON | Enable inner authenticated AEAD |')
s = s.replace('| `enc_algo` | `gcm256` | Inner cipher key size: `gcm256` (AES-256-GCM, compatibility default) or `gcm128` (AES-128-GCM performance mode). Both peers must match exactly |', '| `enc_algo` | `gcm256` | Inner AEAD: `gcm256` (AES-256-GCM, compatibility default), `gcm128`, `chacha20`, or `xchacha20`. Both peers must match exactly |')
s = s.replace('| `min_enc` | (Empty) | Strength floor: `gcm` requires authenticated GCM (either configured key size), `any`/empty sets no floor (needs `encrypt`) |', '| `min_enc` | (Empty) | Legacy floor value `gcm` now means any supported authenticated inner AEAD; `any`/empty sets no floor (needs `encrypt`) |')
p.write_text(s)

# Config validation should explicitly exercise the two new values.
p = Path('config_test.go'); s = p.read_text()
anchor = '''\tfast := base\n\tfast.EncAlgo = "gcm128"\n\tif err := fast.Validate(); err != nil {\n\t\tt.Fatalf("explicit gcm128 config rejected: %v", err)\n\t}\n'''
if anchor in s and 'explicit chacha20 config rejected' not in s:
    s = s.replace(anchor, anchor + '''\n\tfor _, algo := range []string{"chacha20", "xchacha20"} {\n\t\tcfg := base\n\t\tcfg.EncAlgo = algo\n\t\tif err := cfg.Validate(); err != nil {\n\t\t\tt.Fatalf("explicit %s config rejected: %v", algo, err)\n\t\t}\n\t}\n''', 1)
p.write_text(s)
