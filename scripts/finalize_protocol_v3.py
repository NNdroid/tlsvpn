#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    s = p.read_text()
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{path}: expected one match, got {n}\n--- needle ---\n{old}")
    p.write_text(s.replace(old, new, 1))


# Remove obsolete compatibility/broadcast descriptions from code comments.
replace_once(
    "fec.go",
    """// 编码（端口级，按全局 seq 分组，跨所有物理连接）：数据帧仍按 MinRTT
// 单路分发，组满时生成校验帧并向所有连接各广播一份副本——任何单条连接
// 失效，只要其余连接存活就能收到校验帧完成恢复。会话内数据帧 seq 从 1
// 起连续编号（0 保留给心跳），分组起点固定 ≡ 1 (mod K)，两端无需额外
// 同步即可算出任一帧所属的组。
""",
    """// 编码（端口级，按全局 seq 分组，跨所有物理连接）：数据帧按调度器
// 单路发送；组满时只生成一份 parity，并优先投递到与当前数据路径不同的健康
// backend。会话级 decoder 汇聚所有物理连接，因此任意健康连接收到该 parity
// 即可用于恢复。会话内数据帧 seq 从 1 起连续编号；0 专用于握手/控制平面。
// 分组起点固定 ≡ 1 (mod K)，两端独立按算术规则确定组边界。
""",
)
replace_once(
    "fec.go",
    """\t// multipath/armed/lastSeq/control* 只由 AsyncPort.run goroutine 修改。
\t// 直接构造 encoder 的单元测试/benchmark 默认保持旧语义（立即编码）；
""",
    """\t// multipath/armed/lastSeq/control* 只由 AsyncPort.run goroutine 修改。
\t// 独立构造 encoder 的单元测试/benchmark 默认立即编码；
""",
)
replace_once(
    "client.go",
    "// wire format 不变，旧端/新端 decoder 都只要求收到至少一份 parity。\n",
    "// 协议 v3 的 data/control wire semantics 以 docs/protocol_v3.md 为准；\n// 每个完整 FEC group 只发送一份 parity。\n",
)
replace_once(
    "frame.go",
    """\t// SessionToken：客户端回带上一次收到的会话令牌（hex）。
\t// 服务端开启 session_token 时，重连既有会话必须携带正确令牌，
\t// 仅持有共享 PSK 的第三方无法冒充既有会话（见 computeSessionToken）。
""",
    """\t// SessionToken：客户端回带上一次收到的会话令牌（hex）。
\t// 重连既有会话必须携带正确令牌；仅持有共享 PSK 的第三方无法冒充
\t// 既有会话。
""",
)
replace_once(
    "frame.go",
    """\t// SessionToken：本次会话的重连接入令牌（hex），客户端须在下一次握手回带。
\t// 仅在服务端开启 session_token 时下发。
""",
    """\t// SessionToken：本次会话的重连接入令牌（hex），客户端须在下一次握手回带。
\t// 协议 v3 始终使用该令牌进行既有会话接续。
""",
)
replace_once(
    "frame.go",
    """\t// TLS 是服务端实际观测到的 ClientHello 与最终协商摘要。新增客户端接受
\t// 字段缺失，旧客户端会忽略该可选字段，支持滚动升级与回滚。
""",
    """\t// TLS 是服务端实际观测到的 ClientHello 与最终协商摘要，仅用于诊断，
\t// 不参与认证或授权。
""",
)
replace_once(
    "peer_info.go",
    """// normalizePeerInfo 在信任边界裁剪对端自报字段，避免异常大的字符串长期挂在
// logical session 上。nil 表示旧版本对端未提供 metadata。
""",
    """// normalizePeerInfo 在信任边界裁剪对端自报字段，避免异常大的字符串长期挂在
// logical session 上。nil 表示本次 v3 握手省略了可选诊断 metadata。
""",
)

# Golden handshake key contract must include optional peer_info.
p = Path("protocol_conformance_test.go")
s = p.read_text()
old = '\t\tSessionToken: "x",\n\t})'
new = '\t\tSessionToken: "x", PeerInfo: &PeerInfo{Implementation: "go"},\n\t})'
if s.count(old) != 2:
    raise SystemExit(f"protocol_conformance_test.go: req sample count={s.count(old)}, want 2")
s = s.replace(old, new)
old = '\t\tEncAlgo: 2, EncSalt: "x", EncSalt2: "x", SessionToken: "x", TLS: fullTLSInfoSample(),\n\t})'
new = '\t\tEncAlgo: 2, EncSalt: "x", EncSalt2: "x", SessionToken: "x", TLS: fullTLSInfoSample(),\n\t\tPeerInfo: &PeerInfo{Implementation: "go"},\n\t})'
if s.count(old) != 2:
    raise SystemExit(f"protocol_conformance_test.go: resp sample count={s.count(old)}, want 2")
p.write_text(s.replace(old, new))

# Rewrite dynamic-RX rationale to v3-only semantics.
p = Path("docs/dynamic_rx_fec_bypass.md")
s = p.read_text()
start = s.index("## Sender-authoritative FEC mode fence")
operations = s.index("Operations:", start)
new_prefix = """## Sender-authoritative FEC mode fence

Protocol v3 reserves every non-empty post-handshake `seq=0` record for the typed control plane. Dynamic RX bypass uses `control_kind=0x02` (`FEC_MODE`); this is a required v3 wire semantic, not an optional compatibility hint.

FEC_MODE payload (exactly 16 bytes):

```
[1B control_kind=0x02]
[1B op]
[2B flags=0, big endian]
[8B generation, big endian]
[4B boundary_seq, big endian]
```

Unknown control kinds or malformed FEC_MODE payloads are protocol errors and terminate the affected physical connection.

"""
s = s[:start] + new_prefix + s[operations:]
s = s.replace(
    "The encoder constructor defaults to multipath semantics so direct unit tests/benchmarks keep their historical behavior.",
    "The encoder constructor defaults to multipath semantics so standalone encoder tests/benchmarks begin in an immediately armed state.",
)
bc = s.index("## Backward compatibility")
validation = s.index("## P2a/P2b/P2c validation coverage", bc)
v3_rule = """## Protocol v3 interoperability rule

There is no v2 compatibility path. The application handshake requires `protocol_version=3`, and post-handshake non-empty `seq=0` records use the typed control plane defined in `docs/protocol_v3.md`.

Go and Rust implementations must implement the same v3 control kinds, FEC layouts, handshake fields and golden vectors before they are considered interoperable. An implementation that only understands the earlier magic-dispatch `seq=0` semantics must be upgraded rather than silently ignored or downgraded around.

"""
s = s[:bc] + v3_rule + s[validation:]
s = s.replace(
    "1. control codec and strict version/reserved-field parsing;",
    "1. v3 control codec and strict kind/flags/op/length parsing;",
)
s = s.replace(
    "- **P2e:** optional Rust implementation for symmetric RX CPU savings; old Rust remains wire-compatible without it.",
    "- **P2e:** migrate the Rust implementation to the exact protocol-v3 control plane and golden contract; v2 Rust is intentionally not wire-compatible with v3.",
)
p.write_text(s)

# Expand normative v3 specification with complete diagnostic subobjects.
p = Path("docs/protocol_v3.md")
s = p.read_text()
marker = """| `peer_info` | object | Authenticated peer diagnostics. |

## 6. Session identity, token and epoch rules
"""
expanded = """| `peer_info` | object | Authenticated peer diagnostics. |

Fields carrying `omitempty` in the Go structs may be absent when their semantic value is empty. Absence does not change the protocol version or enable a legacy interpretation. `protocol_version=3` is mandatory on every handshake request and successful response.

### 5.1 `peer_info` object

`peer_info` is diagnostic only and MUST NOT participate in authentication or authorization. When present, its string fields are:

```text
implementation
hostname
os
os_version
kernel
arch
version
git_commit
build_time
```

Each peer may omit the object or individual empty fields. Receivers bound stored field sizes at the trust boundary.

### 5.2 `tls` object

The successful server response may include a diagnostic summary of the TLS handshake actually observed by the server:

```text
fingerprint_kind          string
fingerprint_sha256        string
version_id                uint16
version                   string
cipher_suite_id           uint16
cipher_suite              string
alpn                      string
sni                       string
offered_cipher_suites     []uint16
offered_signature_schemes []uint16
offered_groups            []uint16
offered_alpn              []string
```

The current fingerprint kind is `tls-clienthello-v1`. It is project-specific and is not JA3/JA4. TLS diagnostics MUST NOT be used as application-layer authentication input.

## 6. Session identity, token and epoch rules
"""
if marker not in s:
    raise SystemExit("docs/protocol_v3.md: handshake-response insertion marker missing")
s = s.replace(marker, expanded, 1)
s = s.replace(
    "Protocol errors should terminate the affected physical connection rather than silently reinterpret the bytes using v2 semantics.",
    "Protocol errors MUST terminate the affected physical connection rather than silently reinterpret the bytes using v2 semantics.",
)
s = s.replace(
    "Go and Rust implementations should both validate the same golden vectors for:",
    "Go and Rust implementations MUST both validate the same golden vectors for:",
)
p.write_text(s)

print("protocol v3 finalization applied")
