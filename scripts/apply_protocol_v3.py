#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{path}: expected one match, got {n}\n--- needle ---\n{old}")
    p.write_text(text.replace(old, new, 1))


def replace_all(path: str, old: str, new: str) -> int:
    p = Path(path)
    text = p.read_text()
    n = text.count(old)
    if n:
        p.write_text(text.replace(old, new))
    return n


# ---- FEC mode control wire layout: v3 typed seq=0 control plane ----
replace_once(
    "fec_control.go",
    '''// Dynamic RX FEC bypass research primitives. These are intentionally not wired
// into AsyncPort or the receive loops yet. The purpose of this stage is to make
// the sender-authoritative fence format and generation/window semantics testable
// before changing the data path.
const (
\tfecControlMagic   byte = 0xFD
\tfecControlVersion byte = 1

\tfecControlSuspend byte = 1
\tfecControlResume  byte = 2

\tfecControlWireLen = 16
)
''',
    '''// FEC_MODE is a protocol-v3 typed seq=0 control. The application protocol
// version owns the payload layout; there is no nested legacy magic/version byte.
const (
\tfecControlSuspend byte = 1
\tfecControlResume  byte = 2
\tfecControlWireLen      = 16
)
''',
)

replace_once(
    "fec_control.go",
    '''func appendFECModeControl(dst []byte, c fecModeControl) []byte {
\tstart := len(dst)
\tdst = append(dst, make([]byte, fecControlWireLen)...)
\tdst[start] = fecControlMagic
\tdst[start+1] = fecControlVersion
\tdst[start+2] = c.Op
\t// start+3 is reserved for future flags and remains zero in v1.
\tbinary.BigEndian.PutUint64(dst[start+4:start+12], c.Generation)
\tbinary.BigEndian.PutUint32(dst[start+12:start+16], c.Boundary)
\treturn dst
}

func parseFECModeControl(payload []byte) (fecModeControl, bool) {
\tif len(payload) != fecControlWireLen || payload[0] != fecControlMagic || payload[1] != fecControlVersion {
\t\treturn fecModeControl{}, false
\t}
\tif payload[3] != 0 {
\t\treturn fecModeControl{}, false
\t}
\top := payload[2]
\tif op != fecControlSuspend && op != fecControlResume {
\t\treturn fecModeControl{}, false
\t}
\tc := fecModeControl{
\t\tGeneration: binary.BigEndian.Uint64(payload[4:12]),
\t\tOp:         op,
\t\tBoundary:   binary.BigEndian.Uint32(payload[12:16]),
\t}
\tif c.Generation == 0 || c.Boundary == 0 {
\t\treturn fecModeControl{}, false
\t}
\treturn c, true
}
''',
    '''func appendFECModeControl(dst []byte, c fecModeControl) []byte {
\tstart := len(dst)
\tdst = append(dst, make([]byte, fecControlWireLen)...)
\tdst[start] = controlKindFECMode
\tdst[start+1] = c.Op
\t// start+2:start+4 is the v3 flags field and MUST remain zero.
\tbinary.BigEndian.PutUint64(dst[start+4:start+12], c.Generation)
\tbinary.BigEndian.PutUint32(dst[start+12:start+16], c.Boundary)
\treturn dst
}

func parseFECModeControl(payload []byte) (fecModeControl, bool) {
\tif len(payload) != fecControlWireLen || payload[0] != controlKindFECMode {
\t\treturn fecModeControl{}, false
\t}
\tif binary.BigEndian.Uint16(payload[2:4]) != 0 {
\t\treturn fecModeControl{}, false
\t}
\top := payload[1]
\tif op != fecControlSuspend && op != fecControlResume {
\t\treturn fecModeControl{}, false
\t}
\tc := fecModeControl{
\t\tGeneration: binary.BigEndian.Uint64(payload[4:12]),
\t\tOp:         op,
\t\tBoundary:   binary.BigEndian.Uint32(payload[12:16]),
\t}
\tif c.Generation == 0 || c.Boundary == 0 {
\t\treturn fecModeControl{}, false
\t}
\treturn c, true
}
''',
)

# ---- FEC parity becomes control kind 0x01 rather than legacy magic 0xFE ----
fec = Path("fec.go")
text = fec.read_text()
text = text.replace('"encoding/binary"\n', '"encoding/binary"\n\t"fmt"\n', 1)
text = text.replace("fecMagic", "controlKindFECParity")
old_comment = '''// 协商：客户端 -fec -fec-group K 时握手请求带 fec_group=K。支持 XOR 的
// 服务端在响应中回带 fec_group 并对两个方向启用该模式；旧实现（Rust 或
// 旧版 Go）忽略未知字段、响应中不带 fec_group，双方自动回退到传统复制
// 模式，互通性不受影响。
//
'''
new_comment = '''// 协商：协议 v3 中客户端 -fec -fec-group K 时握手请求带 fec_group=K，
// 服务端必须明确接受并回带同一 K；不支持/不匹配时拒绝握手，不做旧协议回退。
//
'''
if old_comment not in text:
    raise SystemExit("fec.go: legacy negotiation comment not found")
text = text.replace(old_comment, new_comment, 1)
old_wire = '''// 校验帧线路格式（沿用 10 字节头，seq=0、padLen 随机，加密与否不影响帧头）：
//
//\t[1B 0xFE][4B groupStart(大端)][1B 成员数][成员数×4B 长度(大端)][异或载荷]
//
// 异或载荷为组内成员【明文】负载的异或，-encrypt 开启时以 groupStart 为
// seq 用独立 AEAD key domain 加密（见 newInnerCipherDomainForAlgo）。
// seq=0 + 负载首字节 0xFE 即为识别标志；握手帧同为 seq=0 但以 '{' 开头，
// 且仅出现在数据循环建立之前，不会混淆。
'''
new_wire = '''// 协议 v3 校验帧是 seq=0 的 typed control：
//
//\t[1B kind=0x01][4B groupStart(大端)][1B K][K×4B 长度(大端)][异或载荷]
//
// 异或载荷为组内成员【明文】负载的异或，-encrypt 开启时以 groupStart 为
// seq 用独立 AEAD key domain 加密（见 newInnerCipherDomainForAlgo）。
'''
if old_wire not in text:
    raise SystemExit("fec.go: legacy wire comment not found")
text = text.replace(old_wire, new_wire, 1)
old_ondata = '''// OnData 记录一个已解密的数据帧。frame 只读借用，不转移所有权。
func (d *fecDecoder) OnData(seq uint32, frame []byte) {
\tif len(frame) == 0 {
\t\treturn
\t}
\tif seq == 0 {
\t\t// Unknown seq=0 controls remain backward-compatible: old peers drop them
\t\t// in reorder, while new peers consume only the strict 0xFD/versioned form.
\t\tif ctrl, ok := parseFECModeControl(frame); ok {
\t\t\td.handleModeControl(ctrl)
\t\t}
\t\treturn
\t}
'''
new_ondata = '''// OnControl handles a non-empty post-handshake protocol-v3 seq=0 control.
// Unknown kinds and malformed FEC_MODE payloads are protocol errors; callers
// terminate the affected physical connection rather than reinterpret v2 bytes.
func (d *fecDecoder) OnControl(payload []byte) error {
\tkind, err := parseControlKind(payload)
\tif err != nil {
\t\treturn err
\t}
\tswitch kind {
\tcase controlKindFECParity:
\t\td.OnParity(payload)
\t\treturn nil
\tcase controlKindFECMode:
\t\tctrl, ok := parseFECModeControl(payload)
\t\tif !ok {
\t\t\treturn fmt.Errorf("malformed FEC_MODE control")
\t\t}
\t\td.handleModeControl(ctrl)
\t\treturn nil
\tdefault:
\t\treturn fmt.Errorf("unsupported control kind 0x%02x", kind)
\t}
}

// OnData records one decrypted VPN data frame. seq=0 is control-plane only and
// must be dispatched through OnControl by the post-handshake receive loop.
func (d *fecDecoder) OnData(seq uint32, frame []byte) {
\tif len(frame) == 0 || seq == 0 {
\t\treturn
\t}
'''
if old_ondata not in text:
    raise SystemExit("fec.go: OnData control block not found")
text = text.replace(old_ondata, new_ondata, 1)
fec.write_text(text)

# Replace the old parity identifier in tests/helpers too.
for p in Path('.').glob('*.go'):
    if p.name == 'fec.go':
        continue
    s = p.read_text()
    if 'fecMagic' in s:
        p.write_text(s.replace('fecMagic', 'controlKindFECParity'))

# ---- Strict post-handshake control dispatch in client ----
client = Path("client.go")
text = client.read_text()
text = text.replace("ProtocolVersion: 2,", "ProtocolVersion: protocolVersion,")
text = text.replace("if resp.ProtocolVersion != 2 {", "if resp.ProtocolVersion != protocolVersion {")
old = '''\t\t\t\tif seq == 0 && useXorFec && c.isParityFrame(frame) {
\t\t\t\t\t// XOR 校验帧：交给 FEC 解码器，恢复出的帧由其回调写 TAP
\t\t\t\t\tc.fecDec.OnParity(frame)
\t\t\t\t\tputFrame(frame)
\t\t\t\t\tcontinue
\t\t\t\t}
\t\t\t\tif useXorFec {
\t\t\t\t\tc.fecDec.OnData(seq, frame)
\t\t\t\t}
'''
new = '''\t\t\t\tif seq == 0 {
\t\t\t\t\tif !useXorFec || c.fecDec == nil {
\t\t\t\t\t\tputFrame(frame)
\t\t\t\t\t\terrChan <- fmt.Errorf("protocol v%d: unexpected typed control without negotiated FEC", protocolVersion)
\t\t\t\t\t\treturn
\t\t\t\t\t}
\t\t\t\t\tif cerr := c.fecDec.OnControl(frame); cerr != nil {
\t\t\t\t\t\tputFrame(frame)
\t\t\t\t\t\terrChan <- fmt.Errorf("protocol v%d control: %w", protocolVersion, cerr)
\t\t\t\t\t\treturn
\t\t\t\t\t}
\t\t\t\t\tputFrame(frame)
\t\t\t\t\tcontinue
\t\t\t\t}
\t\t\t\tif useXorFec {
\t\t\t\t\tc.fecDec.OnData(seq, frame)
\t\t\t\t}
'''
if old not in text:
    raise SystemExit("client.go: RX FEC dispatch block not found")
text = text.replace(old, new, 1)
old_helper = '''// isParityFrame 识别 XOR 校验帧：线路帧 seq=0（不加密），负载首字节为魔数
// 0xFE；普通控制/心跳帧负载为空，握手帧以 '{' 开头，均不会误判。
func (c *Client) isParityFrame(frame []byte) bool {
\treturn len(frame) >= 7 && frame[0] == controlKindFECParity
}

'''
if old_helper not in text:
    raise SystemExit("client.go: legacy isParityFrame helper not found")
text = text.replace(old_helper, "", 1)
client.write_text(text)

# ---- Server: exact v3 + strict typed control dispatch ----
server = Path("server.go")
text = server.read_text()
text = text.replace("if req.ProtocolVersion != 2 {", "if req.ProtocolVersion != protocolVersion {")
# Exact-version handshake means the response always advertises our protocol,
# never an echoed compatibility version.
text = text.replace("sessionEncrypt, req.ProtocolVersion, sessionEpoch, tlsInfo, padRecordLimit)",
                    "sessionEncrypt, protocolVersion, sessionEpoch, tlsInfo, padRecordLimit)")
old = '''\t\t\tif seq == 0 && fecDec != nil && len(frame) >= 7 && frame[0] == controlKindFECParity {
\t\t\t\t// XOR 校验帧：交给会话级 FEC 解码器
\t\t\t\tfecDec.OnParity(frame)
\t\t\t\tputFrame(frame)
\t\t\t\tcontinue
\t\t\t}
\t\t\tif fecDec != nil {
\t\t\t\tfecDec.OnData(seq, frame)
\t\t\t}
'''
new = '''\t\t\tif seq == 0 {
\t\t\t\tif fecDec == nil {
\t\t\t\t\tputFrame(frame)
\t\t\t\t\tlog.Debugf("[%s] protocol v%d violation: typed control without negotiated FEC", clientID, protocolVersion)
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t\tif cerr := fecDec.OnControl(frame); cerr != nil {
\t\t\t\t\tputFrame(frame)
\t\t\t\t\tlog.Debugf("[%s] protocol v%d control violation: %v", clientID, protocolVersion, cerr)
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t\tputFrame(frame)
\t\t\t\tcontinue
\t\t\t}
\t\t\tif fecDec != nil {
\t\t\t\tfecDec.OnData(seq, frame)
\t\t\t}
'''
if old not in text:
    raise SystemExit("server.go: RX FEC dispatch block not found")
text = text.replace(old, new, 1)
server.write_text(text)

# ---- Exact protocol version in API/tests/probe ----
for p in Path('.').glob('*.go'):
    s = p.read_text()
    s = s.replace("ProtocolVersion: 2,", "ProtocolVersion: protocolVersion,")
    s = s.replace("ProtocolVersion: 2}", "ProtocolVersion: protocolVersion}")
    s = s.replace("ProtocolVersion: 2 ", "ProtocolVersion: protocolVersion ")
    p.write_text(s)

api = Path("api.go")
s = api.read_text().replace("runtimeNegJSON{ProtocolVersion: 2,", "runtimeNegJSON{ProtocolVersion: protocolVersion,")
api.write_text(s)

probe = Path("interop/probe.go")
s = probe.read_text()
s = s.replace("protocol-v2 interoperability client", "protocol-v3 interoperability client")
s = s.replace("ProtocolVersion: 2,", "ProtocolVersion: 3,")
s = s.replace("resp.ProtocolVersion != 2", "resp.ProtocolVersion != 3")
probe.write_text(s)

# ---- Golden vectors: v3 version plus typed-control vectors ----
pc = Path("protocol_conformance_test.go")
s = pc.read_text()
s = s.replace("Version: 2", "Version: protocolVersion")
s = s.replace("ProtocolVersion: 2,", "ProtocolVersion: protocolVersion,")
field_needle = '''\t// 帧头布局：10 字节头 [4B dataLen][2B padLen][4B seq]
\tFrameHeaders []FrameHeaderVec `json:"frame_headers"`
'''
field_new = '''\t// 帧头布局：10 字节头 [4B dataLen][2B padLen][4B seq]
\tFrameHeaders []FrameHeaderVec `json:"frame_headers"`
\t// v3 seq=0 typed-control payload contract.
\tControlFrames []ControlFrameVec `json:"control_frames"`
'''
if field_needle not in s:
    raise SystemExit("protocol_conformance_test.go: FrameHeaders field needle missing")
s = s.replace(field_needle, field_new, 1)
struct_needle = '''type FrameHeaderVec struct {
\tDataLen   uint32 `json:"data_len"`
\tPadLen    uint16 `json:"pad_len"`
\tSeq       uint32 `json:"seq"`
\tHeaderHex string `json:"header_hex"`
}
'''
struct_new = struct_needle + '''
type ControlFrameVec struct {
\tName       string `json:"name"`
\tPayloadHex string `json:"payload_hex"`
}
'''
if struct_needle not in s:
    raise SystemExit("protocol_conformance_test.go: FrameHeaderVec needle missing")
s = s.replace(struct_needle, struct_new, 1)
insert_after = '''\tfor _, h := range headers {
\t\tvar hdr [10]byte
\t\tbinary.BigEndian.PutUint32(hdr[0:4], h.dataLen)
\t\tbinary.BigEndian.PutUint16(hdr[4:6], h.padLen)
\t\tbinary.BigEndian.PutUint32(hdr[6:10], h.seq)
\t\tgv.FrameHeaders = append(gv.FrameHeaders, FrameHeaderVec{
\t\t\tDataLen:   h.dataLen,
\t\t\tPadLen:    h.padLen,
\t\t\tSeq:       h.seq,
\t\t\tHeaderHex: hex.EncodeToString(hdr[:]),
\t\t})
\t}
'''
insert_new = insert_after + '''
\tmode := appendFECModeControl(nil, fecModeControl{
\t\tGeneration: 0x0102030405060708,
\t\tOp:         fecControlSuspend,
\t\tBoundary:   9,
\t})
\tgv.ControlFrames = append(gv.ControlFrames, ControlFrameVec{
\t\tName: "fec_mode_suspend", PayloadHex: hex.EncodeToString(mode),
\t})
\te := newFECEncoder(2, nil)
\t_ = e.add(VPNFrame{Seq: 1, Data: []byte{0x01, 0x02}})
\tparity := e.add(VPNFrame{Seq: 2, Data: []byte{0x03, 0x04}})
\tif parity == nil {
\t\tpanic("golden FEC parity was not generated")
\t}
\tgv.ControlFrames = append(gv.ControlFrames, ControlFrameVec{
\t\tName: "fec_parity_k2", PayloadHex: hex.EncodeToString(parity),
\t})
\tputFrame(parity)
'''
if insert_after not in s:
    raise SystemExit("protocol_conformance_test.go: header generation block missing")
s = s.replace(insert_after, insert_new, 1)
pc.write_text(s)

# ---- v3 control tests ----
Path("protocol_v3_control_test.go").write_text(r'''package main

import (
    "encoding/hex"
    "testing"
)

func TestProtocolV3VersionAndControlKinds(t *testing.T) {
    if protocolVersion != 3 {
        t.Fatalf("protocolVersion=%d want=3", protocolVersion)
    }
    for _, kind := range []byte{controlKindFECParity, controlKindFECMode} {
        got, err := parseControlKind([]byte{kind})
        if err != nil || got != kind {
            t.Fatalf("kind=0x%02x got=0x%02x err=%v", kind, got, err)
        }
    }
    if _, err := parseControlKind([]byte{0x7f}); err == nil {
        t.Fatal("unknown v3 control kind was accepted")
    }
    if _, err := parseControlKind(nil); err == nil {
        t.Fatal("empty keepalive payload was accepted as typed control")
    }
}

func TestProtocolV3FECModeWireLayout(t *testing.T) {
    payload := appendFECModeControl(nil, fecModeControl{
        Generation: 0x0102030405060708,
        Op:         fecControlSuspend,
        Boundary:   9,
    })
    const want = "02010000010203040506070800000009"
    if got := hex.EncodeToString(payload); got != want {
        t.Fatalf("FEC_MODE payload=%s want=%s", got, want)
    }
    ctrl, ok := parseFECModeControl(payload)
    if !ok || ctrl.Generation != 0x0102030405060708 || ctrl.Op != fecControlSuspend || ctrl.Boundary != 9 {
        t.Fatalf("decoded control=%+v ok=%v", ctrl, ok)
    }
}

func TestProtocolV3DecoderRejectsUnknownOrMalformedControls(t *testing.T) {
    d := NewFECDecoder(4, nil, nil)
    if err := d.OnControl([]byte{0x7f, 1, 2, 3}); err == nil {
        t.Fatal("unknown typed control was silently ignored")
    }
    bad := appendFECModeControl(nil, fecModeControl{Generation: 1, Op: fecControlSuspend, Boundary: 5})
    bad[2] = 1 // flags are reserved and MUST be zero in v3.
    if err := d.OnControl(bad); err == nil {
        t.Fatal("malformed FEC_MODE was silently ignored")
    }
}

func TestProtocolV3ParityUsesTypedControlKind(t *testing.T) {
    e := newFECEncoder(2, nil)
    if p := e.add(VPNFrame{Seq: 1, Data: []byte{1, 2}}); p != nil {
        putFrame(p)
        t.Fatal("unexpected early parity")
    }
    p := e.add(VPNFrame{Seq: 2, Data: []byte{3, 4}})
    if p == nil {
        t.Fatal("missing parity")
    }
    defer putFrame(p)
    if p[0] != controlKindFECParity {
        t.Fatalf("parity kind=0x%02x want=0x%02x", p[0], controlKindFECParity)
    }
    if err := NewFECDecoder(2, nil, nil).OnControl(p); err != nil {
        t.Fatalf("valid FEC_PARITY control rejected: %v", err)
    }
}
''')

# Dynamic-research doc is rationale; protocol_v3.md is normative.
doc = Path("docs/dynamic_rx_fec_bypass.md")
ds = doc.read_text()
if "Normative wire specification:" not in ds:
    ds = ds.replace("# Dynamic 2→1 RX FEC bypass research\n", "# Dynamic 2→1 RX FEC bypass research\n\nNormative wire specification: [`protocol_v3.md`](protocol_v3.md). This file records design rationale and implementation staging only.\n", 1)
ds = ds.replace("Unknown `seq=0` frames are already discarded by both current Go and Rust reorder paths, so old peers can safely ignore the hint.\n", "Protocol v3 reserves non-empty post-handshake `seq=0` for typed controls. Unknown control kinds are protocol errors; no v2 compatibility fallback is defined.\n")
ds = ds.replace("Suggested payload (v1):", "Protocol-v3 FEC_MODE payload:")
ds = ds.replace("[1B magic=0xFD]\n[1B version=1]\n[1B op]\n[1B reserved]\n[8B generation, big endian]\n[4B boundary_seq, big endian]", "[1B control_kind=0x02]\n[1B op]\n[2B flags=0, big endian]\n[8B generation, big endian]\n[4B boundary_seq, big endian]")
# Remove the obsolete backward-compatibility section if present.
start = ds.find("## Backward compatibility")
end = ds.find("## Tests required", start)
if start != -1 and end != -1:
    ds = ds[:start] + "## Protocol-version rule\n\nThis mechanism is normative in protocol v3. v2 peers are rejected at handshake; unknown post-handshake control kinds are not ignored.\n\n" + ds[end:]
doc.write_text(ds)

print("protocol v3 migration applied")
