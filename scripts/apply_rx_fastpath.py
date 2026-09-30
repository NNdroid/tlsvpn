#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"{path}: expected exactly one replacement target, found {text.count(old)}")
    p.write_text(text.replace(old, new, 1))


# ---- fec.go: P0 full-data early finish + P1 static-single decoder bypass ----
replace_once(
    "fec.go",
    '''type fecDecoder struct {
\tmu         sync.Mutex
\tk          int
\tic         *innerCipher
\tout        func(seq uint32, frame []byte)
''',
    '''type fecDecoder struct {
\tmu           sync.Mutex
\tk            int
\tfullMask     uint64
\tstaticSingle atomic.Bool // configured topology is exactly one physical path: RX FEC has no recovery value
\tic           *innerCipher
\tout          func(seq uint32, frame []byte)
''',
)

replace_once(
    "fec.go",
    '''func NewFECDecoder(k int, ic *innerCipher, out func(seq uint32, frame []byte)) *fecDecoder {
\treturn &fecDecoder{
\t\tk:          clampFecGroup(k),
\t\tic:         ic,
\t\tout:        out,
\t\tgroups:     make(map[uint32]*fecGroupState, 64),
\t\tgroupOrder: make([]uint32, 0, fecMaxPendingGroups+64),
\t\tspares:     make([]*fecGroupState, 0, fecMaxPendingGroups),
\t}
}
''',
    '''func NewFECDecoder(k int, ic *innerCipher, out func(seq uint32, frame []byte)) *fecDecoder {
\tk = clampFecGroup(k)
\tfullMask := ^uint64(0)
\tif k < 64 {
\t\tfullMask = (uint64(1) << uint(k)) - 1
\t}
\treturn &fecDecoder{
\t\tk:          k,
\t\tfullMask:   fullMask,
\t\tic:         ic,
\t\tout:        out,
\t\tgroups:     make(map[uint32]*fecGroupState, 64),
\t\tgroupOrder: make([]uint32, 0, fecMaxPendingGroups+64),
\t\tspares:     make([]*fecGroupState, 0, fecMaxPendingGroups),
\t}
}

// isStaticSinglePathTopology is deliberately strict: zero means "unknown", not
// single-path. The client has an authoritative configured count; the server only
// uses this when the authenticated peer also advertised group/topology semantics.
func isStaticSinglePathTopology(configuredConns int) bool { return configuredConns == 1 }

// SetStaticSinglePath enables the RX fast bypass only for a topology configured
// to have exactly one physical connection. This is intentionally NOT driven by
// the current live connection count: a temporary 2->1 failover is precisely when
// already-in-flight parity from the surviving path can still recover lost data.
func (d *fecDecoder) SetStaticSinglePath(single bool) {
\tif !single {
\t\td.staticSingle.Store(false)
\t\treturn
\t}
\tif d.staticSingle.Swap(true) {
\t\treturn
\t}
\t// Publish bypass before clearing state so new readers stop creating groups;
\t// OnData/OnParity re-check under d.mu to close the in-flight race window.
\td.Reset()
}
''',
)

replace_once(
    "fec.go",
    '''func (d *fecDecoder) OnData(seq uint32, frame []byte) {
\tif len(frame) == 0 || seq == 0 {
\t\treturn
\t}
\tstart := d.groupStartOf(seq)
\td.mu.Lock()
\tdefer d.mu.Unlock()
\tif d.isDoneLocked(start) {
\t\treturn
\t}
''',
    '''func (d *fecDecoder) OnData(seq uint32, frame []byte) {
\tif len(frame) == 0 || seq == 0 || d.staticSingle.Load() {
\t\treturn
\t}
\tstart := d.groupStartOf(seq)
\td.mu.Lock()
\tdefer d.mu.Unlock()
\tif d.staticSingle.Load() || d.isDoneLocked(start) {
\t\treturn
\t}
''',
)

replace_once(
    "fec.go",
    '''\tg.gotMask |= mask
\tif len(frame) > len(g.acc) {
\t\tg.acc = d.growAccLocked(g.acc, len(frame))
\t}
\tsubtle.XORBytes(g.acc[:len(frame)], g.acc[:len(frame)], frame)
\td.tryRecoverLocked(g)
}
''',
    '''\tg.gotMask |= mask
\t// P0: once all K original members arrived, parity can no longer add value.
\t// Finish immediately even if parity has not arrived yet. Besides bounding the
\t// pending-group map, checking before XOR means the Kth frame avoids the final
\t// accumulator pass entirely. fullMask is precomputed and handles K=64 without
\t// an invalid 1<<64 shift.
\tif g.gotMask == d.fullMask {
\t\td.finishGroupLocked(g)
\t\treturn
\t}
\tif len(frame) > len(g.acc) {
\t\tg.acc = d.growAccLocked(g.acc, len(frame))
\t}
\tsubtle.XORBytes(g.acc[:len(frame)], g.acc[:len(frame)], frame)
\td.tryRecoverLocked(g)
}
''',
)

replace_once(
    "fec.go",
    '''func (d *fecDecoder) OnParity(payload []byte) {
\tif len(payload) < 7 || payload[0] != fecMagic {
\t\treturn
\t}
''',
    '''func (d *fecDecoder) OnParity(payload []byte) {
\tif d.staticSingle.Load() || len(payload) < 7 || payload[0] != fecMagic {
\t\treturn
\t}
''',
)

replace_once(
    "fec.go",
    '''\td.mu.Lock()
\tdefer d.mu.Unlock()
\tif d.isDoneLocked(start) {
\t\tputFECLens(lens)
\t\treturn
\t}
''',
    '''\td.mu.Lock()
\tdefer d.mu.Unlock()
\tif d.staticSingle.Load() || d.isDoneLocked(start) {
\t\tputFECLens(lens)
\t\treturn
\t}
''',
)

# ---- client.go: configured client.conns is authoritative and restart-only ----
replace_once(
    "client.go",
    '''\t\tif fecRebuild {
\t\t\t// XOR FEC 解码器：恢复出的帧按原 seq 注入重排缓冲，保证输出有序
\t\t\tc.fecDec = NewFECDecoder(c.fecNegotiated, fecRx, c.rxReorder.Insert)
\t\t\tc.txPort.AttachFEC(c.fecNegotiated, fecTx)
\t\t}
''',
    '''\t\tif fecRebuild {
\t\t\t// XOR FEC 解码器：恢复出的帧按原 seq 注入重排缓冲，保证输出有序。
\t\t\t// client.conns 属于 restart-only 拓扑配置，因此 ==1 时可以安全使用
\t\t\t// 静态 RX bypass；不能用 liveConns，因为临时 2->1 时 parity 仍有价值。
\t\t\tc.fecDec = NewFECDecoder(c.fecNegotiated, fecRx, c.rxReorder.Insert)
\t\t\tc.fecDec.SetStaticSinglePath(isStaticSinglePathTopology(lv.connsCount))
\t\t\tc.txPort.AttachFEC(c.fecNegotiated, fecTx)
\t\t}
''',
)

# ---- server.go: trust single-path only when the authenticated peer advertises
# the existing group/topology semantics; unknown/legacy declarations stay safe. ----
replace_once(
    "server.go",
    '''\t\t\tif err := s.rotateSessionEpochLocked(session, req.ClientInstance, psk); err != nil {
\t\t\t\tlog.Errorf("[%s] failed to rotate the session key epoch: %v", clientID, err)
\t\t\t\ts.mu.Unlock()
\t\t\t\treturn
\t\t\t}
\t\t\tif err := ensurePendingResumeToken(session); err != nil {
''',
    '''\t\t\tif err := s.rotateSessionEpochLocked(session, req.ClientInstance, psk); err != nil {
\t\t\t\tlog.Errorf("[%s] failed to rotate the session key epoch: %v", clientID, err)
\t\t\t\ts.mu.Unlock()
\t\t\t\treturn
\t\t\t}
\t\t\t// A new client process is a clean epoch boundary, so a restart-time
\t\t\t// client.conns change may safely switch the RX decoder fast-path mode.
\t\t\tif session.FecDec != nil {
\t\t\t\tsession.FecDec.SetStaticSinglePath(req.BrutalGroups && isStaticSinglePathTopology(req.BrutalConns))
\t\t\t}
\t\t\tif err := ensurePendingResumeToken(session); err != nil {
''',
)

replace_once(
    "server.go",
    '''\t\tif fecEncK > 0 {
\t\t\tsession.FecDec = NewFECDecoder(fecEncK, fecRx, session.RxReorder.Insert)
\t\t}
''',
    '''\t\tif fecEncK > 0 {
\t\t\tsession.FecDec = NewFECDecoder(fecEncK, fecRx, session.RxReorder.Insert)
\t\t\t// Current Go clients always advertise BrutalGroups/BrutalConns as the
\t\t\t// authenticated physical-topology declaration even when shaping is off.
\t\t\t// Legacy/unknown peers (no group semantics) deliberately keep RX FEC on.
\t\t\tsession.FecDec.SetStaticSinglePath(req.BrutalGroups && isStaticSinglePathTopology(req.BrutalConns))
\t\t}
''',
)

# ---- focused correctness tests ----
Path("fec_rx_fastpath_test.go").write_text(r'''package main

import (
    "bytes"
    "testing"
)

func TestFECDecoderFullDataGroupReleasedWithoutParity(t *testing.T) {
    for _, k := range []int{2, 4, 64} {
        t.Run(string(rune('A'+k%26)), func(t *testing.T) {
            d := NewFECDecoder(k, nil, nil)
            frame := bytes.Repeat([]byte{0x5a}, 256)
            for i := 0; i < k; i++ {
                d.OnData(uint32(i+1), frame)
            }

            d.mu.Lock()
            groups := len(d.groups)
            done := d.isDoneLocked(1)
            d.mu.Unlock()
            if groups != 0 {
                t.Fatalf("K=%d full data-only group retained %d pending groups, want 0", k, groups)
            }
            if !done {
                t.Fatalf("K=%d full data-only group was not marked done", k)
            }
            recovered, lost := d.FECStats()
            if recovered != 0 || lost != 0 {
                t.Fatalf("K=%d full data-only group stats recovered/lost=%d/%d, want 0/0", k, recovered, lost)
            }
        })
    }
}

func TestFECDecoderStaticSinglePathBypassesAllGroupState(t *testing.T) {
    d := NewFECDecoder(4, nil, nil)
    d.SetStaticSinglePath(true)
    frame := bytes.Repeat([]byte{0x33}, 1400)

    for seq := uint32(1); seq <= 128; seq++ {
        d.OnData(seq, frame)
    }

    e := newFECEncoder(4, nil)
    var parity []byte
    for seq := uint32(129); seq <= 132; seq++ {
        if p := e.add(VPNFrame{Seq: seq, Data: frame}); p != nil {
            parity = p
        }
    }
    if parity == nil {
        t.Fatal("expected parity test fixture")
    }
    d.OnParity(parity)
    putFrame(parity)

    d.mu.Lock()
    groups := len(d.groups)
    order := len(d.groupOrder)
    d.mu.Unlock()
    if groups != 0 || order != 0 {
        t.Fatalf("static single-path RX created decoder state: groups=%d order=%d", groups, order)
    }
    recovered, lost := d.FECStats()
    if recovered != 0 || lost != 0 {
        t.Fatalf("static single-path RX stats recovered/lost=%d/%d, want 0/0", recovered, lost)
    }
}

func TestFECDecoderStaticSinglePathToggleClearsAndRestores(t *testing.T) {
    recovered := make(chan uint32, 1)
    d := NewFECDecoder(4, nil, func(seq uint32, frame []byte) {
        recovered <- seq
        putFrame(frame)
    })
    frame := bytes.Repeat([]byte{0x44}, 512)

    d.OnData(1, frame)
    d.mu.Lock()
    before := len(d.groups)
    d.mu.Unlock()
    if before != 1 {
        t.Fatalf("precondition pending groups=%d, want 1", before)
    }

    d.SetStaticSinglePath(true)
    d.mu.Lock()
    after := len(d.groups)
    d.mu.Unlock()
    if after != 0 {
        t.Fatalf("enabling static single-path did not clear pending state: %d groups", after)
    }

    d.OnData(2, frame) // bypassed
    d.SetStaticSinglePath(false)

    e := newFECEncoder(4, nil)
    var parity []byte
    for seq := uint32(5); seq <= 8; seq++ {
        if p := e.add(VPNFrame{Seq: seq, Data: frame}); p != nil {
            parity = p
        }
        if seq != 8 {
            d.OnData(seq, frame)
        }
    }
    if parity == nil {
        t.Fatal("expected parity after re-enabling decoder")
    }
    d.OnParity(parity)
    putFrame(parity)

    select {
    case seq := <-recovered:
        if seq != 8 {
            t.Fatalf("recovered seq=%d, want 8", seq)
        }
    default:
        t.Fatal("decoder did not recover after static bypass was disabled")
    }
}

func TestStaticSinglePathTopologyIsStrict(t *testing.T) {
    if !isStaticSinglePathTopology(1) {
        t.Fatal("configuredConns=1 must enable static single-path topology")
    }
    for _, n := range []int{0, 2, 4, 16} {
        if isStaticSinglePathTopology(n) {
            t.Fatalf("configuredConns=%d must not be treated as static single-path", n)
        }
    }
}
''')

# ---- RX data-path benchmark: normal decoder vs static-single atomic bypass ----
bench = Path("bench_test.go")
bench_text = bench.read_text()
if "func BenchmarkFECDecodeDataPath" not in bench_text:
    bench_text += r'''

// BenchmarkFECDecodeDataPath measures the per-data-frame RX decoder cost after
// P0 group retirement and the P1 configured-single-path atomic fast bypass.
func BenchmarkFECDecodeDataPath(b *testing.B) {
    pt := benchPayload()
    for _, tc := range []struct {
        name   string
        bypass bool
    }{
        {name: "multipath", bypass: false},
        {name: "static-single", bypass: true},
    } {
        b.Run(tc.name, func(b *testing.B) {
            d := NewFECDecoder(4, nil, nil)
            d.SetStaticSinglePath(tc.bypass)
            var seq uint32
            b.SetBytes(int64(len(pt)))
            b.ReportAllocs()
            b.ResetTimer()
            for i := 0; i < b.N; i++ {
                seq++
                d.OnData(seq, pt)
            }
        })
    }
}
'''
    bench.write_text(bench_text)

print("RX FEC P0/P1 patch applied")
