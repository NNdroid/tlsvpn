from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))


# P0/P1: track only the accumulator range touched by the current FEC group.
# A transient jumbo frame must not force every later MTU-sized group to clear the
# historical jumbo-sized accumulator.
replace_once(
    "fec.go",
    '''type fecEncoder struct {\n\tk          int\n\tseqs       []uint32 // 当前组成员的 seq\n\tlens       []int    // 当前组成员的负载长度\n\tacc        []byte   // 成员负载的异或累加（按最大长度对齐）\n\tic         *innerCipher\n\tparitySent uint64 // 已生成校验帧计数（面板/metrics）\n}\n''',
    '''type fecEncoder struct {\n\tk          int\n\tseqs       []uint32 // 当前组成员的 seq\n\tlens       []int    // 当前组成员的负载长度\n\tacc        []byte   // 成员负载的异或累加（按历史最大长度复用）\n\tactiveLen  int      // 当前组实际触碰的最大长度；reset 只清这一段\n\tic         *innerCipher\n\tparitySent uint64 // 已生成校验帧计数（面板/metrics）\n}\n''',
)
replace_once(
    "fec.go",
    '''\tsubtle.XORBytes(e.acc[:len(vf.Data)], e.acc[:len(vf.Data)], vf.Data)\n\tif len(e.seqs) < e.k {\n''',
    '''\tif len(vf.Data) > e.activeLen {\n\t\te.activeLen = len(vf.Data)\n\t}\n\tsubtle.XORBytes(e.acc[:len(vf.Data)], e.acc[:len(vf.Data)], vf.Data)\n\tif len(e.seqs) < e.k {\n''',
)
replace_once(
    "fec.go",
    '''func (e *fecEncoder) reset() {\n\te.seqs = e.seqs[:0]\n\te.lens = e.lens[:0]\n\tclear(e.acc)\n}\n\nfunc (e *fecEncoder) buildParity() []byte {\n\tmaxLen := len(e.acc)\n''',
    '''func (e *fecEncoder) reset() {\n\te.seqs = e.seqs[:0]\n\te.lens = e.lens[:0]\n\tclear(e.acc[:e.activeLen])\n\te.activeLen = 0\n}\n\nfunc (e *fecEncoder) buildParity() []byte {\n\tmaxLen := e.activeLen\n''',
)
replace_once(
    "fec.go",
    "\tcopy(buf[off:], e.acc)\n",
    "\tcopy(buf[off:off+maxLen], e.acc[:maxLen])\n",
)

# P1: AsyncPort.run() currently scans the entire backend slice under RLock before
# assigning every first sequence in a batch. The selected backend is already kept
# in an atomic pointer. On the overwhelmingly common healthy path, use that queue's
# free slot as the fast admission signal and avoid the lock/scan entirely.
replace_once(
    "client.go",
    '''func (p *AsyncPort) waitForBackendSlot() bool {\n\tfor {\n\t\tselect {\n\t\tcase <-p.ctx.Done():\n\t\t\treturn false\n\t\tdefault:\n\t\t}\n\n\t\tp.backendsMu.RLock()\n''',
    '''func (p *AsyncPort) waitForBackendSlot() bool {\n\tfor {\n\t\tselect {\n\t\tcase <-p.ctx.Done():\n\t\t\treturn false\n\t\tdefault:\n\t\t}\n\n\t\t// Fast path: dispatchBatch keeps the preferred backend in an atomic\n\t\t// pointer. When that queue has room, no backend-list lock/scan is needed.\n\t\tif b := p.preferred.Load(); b != nil && cap(b.ch) > 0 && len(b.ch) < cap(b.ch) {\n\t\t\treturn true\n\t\t}\n\n\t\tp.backendsMu.RLock()\n''',
)

# Regression coverage: a jumbo frame followed by MTU traffic must shrink the active
# reset range back to MTU size while keeping the retained capacity for reuse.
replace_once(
    "fec_test.go",
    '''func TestFECEncoderReset''',
    '''func TestFECEncoderActiveRangeShrinksAfterJumboGroup(t *testing.T) {\n\te := newFECEncoder(2, nil)\n\tjumbo := make([]byte, 64*1024)\n\tfor i := 0; i < 2; i++ {\n\t\tif par := e.add(VPNFrame{Seq: uint32(i + 1), Data: jumbo}); par != nil {\n\t\t\tputFrame(par)\n\t\t}\n\t}\n\tif e.activeLen != 0 {\n\t\tt.Fatalf("activeLen after jumbo flush = %d, want 0", e.activeLen)\n\t}\n\tif cap(e.acc) < len(jumbo) {\n\t\tt.Fatalf("acc capacity = %d, want retained jumbo capacity", cap(e.acc))\n\t}\n\n\tmtu := make([]byte, 1400)\n\tif par := e.add(VPNFrame{Seq: 3, Data: mtu}); par != nil {\n\t\tputFrame(par)\n\t}\n\tif e.activeLen != len(mtu) {\n\t\tt.Fatalf("activeLen after MTU frame = %d, want %d", e.activeLen, len(mtu))\n\t}\n\tif par := e.add(VPNFrame{Seq: 4, Data: mtu}); par != nil {\n\t\tputFrame(par)\n\t}\n\tif e.activeLen != 0 {\n\t\tt.Fatalf("activeLen after MTU flush = %d, want 0", e.activeLen)\n\t}\n}\n\nfunc TestFECEncoderReset''',
)

print("Go dataplane performance patch applied")
