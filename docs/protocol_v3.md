# TLSVPN Protocol v3

Status: normative protocol specification for the current implementation.

This document is the protocol source of truth. Code, tests and cross-language implementations MUST follow it. Protocol v3 intentionally does **not** preserve wire compatibility with v2.

## 1. Transport and connection model

TLSVPN runs over TCP protected by TLS. A logical VPN session may use multiple simultaneous physical TCP/TLS connections. Each physical connection performs the application handshake independently and then carries framed data/control records for the same logical session epoch.

The application protocol version is exactly:

```text
protocol_version = 3
```

A peer advertising any other version MUST be rejected. There is no v2 fallback or downgrade path.

The implementation currently advertises ALPN `h2`; TLS is still used as a byte-stream transport, not as HTTP/2 framing.

## 2. Stream frame format

Every application record is encoded inside the TLS byte stream with a fixed 10-byte header:

```text
0               4       6              10
+---------------+-------+---------------+
| data_len u32  | pad u16| seq u32      |
+---------------+-------+---------------+
| data_len bytes payload                 |
+----------------------------------------+
| pad_len bytes cover padding            |
+----------------------------------------+
```

All integers are big-endian.

Fields:

- `data_len`: payload bytes on the wire, excluding the 10-byte frame header and excluding padding. For encrypted data records this includes the AEAD tag.
- `pad_len`: opaque cover-padding byte count.
- `seq`: data sequence number. `seq=0` is reserved for handshake/control traffic; normal VPN data uses `1..0xffffffff`.

The authenticated post-handshake maximum `data_len` is `131070` bytes. The pre-authentication handshake frame limit is `16384` bytes.

Padding bytes are not interpreted by the receiver and are not included in inner-AEAD AAD.

## 3. Connection state machine

A physical connection has two protocol phases.

### 3.1 Pre-handshake phase

The first TLSVPN record uses `seq=0` and contains UTF-8 JSON for `HandshakeReq`. The server replies with one `seq=0` JSON `HandshakeResp` record.

During this phase the `seq=0` payload is JSON, not a v3 typed control payload.

### 3.2 Post-handshake phase

After a successful handshake:

- `seq > 0`: VPN data record.
- `seq = 0`, `data_len = 0`: KEEPALIVE.
- `seq = 0`, `data_len > 0`: typed v3 control record. The first payload byte is `control_kind`.

Unknown or malformed post-handshake control kinds are protocol errors. They MUST NOT be silently ignored for compatibility.

## 4. Handshake request

The client sends a JSON object with these fields:

| Field | Type | Meaning |
|---|---|---|
| `protocol_version` | integer | MUST equal `3`. |
| `client_instance` | string | Process-instance identity used to detect a new key/sequence epoch. |
| `conn_id` | string | Diagnostic UUID for correlating client/server views of one physical connection. |
| `client_id` | string | Stable logical client UUID derived from authenticated identity inputs. |
| `psk` | string | Hex SHA-256 of the configured PSK. |
| `mac` | string | Client tunnel MAC address. |
| `ipv4` | string | Requested/remembered IPv4 address, if any. |
| `ipv6` | string | Requested/remembered IPv6 address, if any. |
| `padding` | string | Random handshake camouflage material. |
| `brutal_groups` | bool | Enables grouped/aggregate TCP Brutal rate semantics. |
| `brutal_total_tx` | integer | Requested aggregate client→server Mbps budget. |
| `brutal_total_rx` | integer | Requested aggregate server→client Mbps budget. |
| `brutal_conns` | integer | Declared physical connection count. |
| `brutal_conn_index` | integer | Zero-based physical connection index. |
| `fec` | bool | Requests XOR FEC. |
| `fec_group` | integer | XOR FEC group size K; valid negotiated range is 2..64 and may be narrowed by server policy. |
| `encrypt` | bool | Whether inner AEAD is enabled. |
| `enc_algo` | integer | Inner AEAD algorithm identifier. |
| `session_token` | string | 32-byte random session possession token encoded as 64 hex characters. |
| `peer_info` | object | Diagnostic peer metadata only; never authorization input. |

The server MUST require exact v3 and exact configured inner-encryption compatibility. FEC requests outside server policy MUST be rejected rather than silently clamped to another wire value.

## 5. Handshake response

A successful server response contains:

| Field | Type | Meaning |
|---|---|---|
| `protocol_version` | integer | MUST equal `3`. |
| `session_epoch` | integer | Monotonic logical key/sequence epoch. |
| `success` | bool | Handshake result. |
| `message` | string | Human-readable result. |
| `session_id` | string | Logical session UUID. |
| `client_id` | string | Accepted logical client identifier. |
| `ipv4` / `ipv6` | string | Assigned tunnel addresses. |
| `gw_v4` / `gw_v6` | string | Tunnel gateway addresses. |
| `padding` | string | Handshake camouflage field. |
| `brutal_groups` | bool | Negotiated grouped rate semantics. |
| `brutal_total_tx` / `brutal_total_rx` | integer | Negotiated aggregate Mbps budgets. |
| `fec` | bool | Negotiated FEC enablement. |
| `fec_group` | integer | Negotiated XOR group size K. |
| `encrypt` | bool | Negotiated inner-AEAD enablement. |
| `enc_algo` | integer | Exact selected inner AEAD algorithm. |
| `enc_salt` | string | 8-byte c2s salt, hex encoded. |
| `enc_salt2` | string | 8-byte s2c salt, hex encoded. |
| `session_token` | string | Current/pending random reconnect token. |
| `tls` | object | Server-observed TLS ClientHello/final TLS diagnostics. |
| `peer_info` | object | Authenticated peer diagnostics. |

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

The PSK hash authenticates membership in the VPN, while `session_token` proves possession of an existing logical session.

A session token is 32 random bytes encoded as 64 hex characters. The implementation uses a two-phase current/pending rollover so a lost handshake response does not permanently desynchronize the token.

A change of `client_instance` creates a new session epoch. A new epoch MUST reset:

- data sequence allocation;
- FEC-mode transition generation;
- backend remembered FEC fence generation;
- RX reorder state;
- RX FEC decoder state;
- per-direction inner-AEAD salts/nonce domain.

Old physical connections from a previous epoch must not continue injecting data into the new epoch.

## 7. Data sequencing

Normal VPN data uses `seq=1..0xffffffff` and is globally allocated by the logical sending port across all physical backends.

`seq=0` is never a VPN data sequence.

When the uint32 data sequence space is exhausted, the implementation must force a fresh key/sequence epoch before sequence reuse. Reusing a sequence within an AEAD epoch is forbidden.

The receiver uses a reorder buffer keyed by the global data sequence. Gaps are tolerated for a bounded interval; after the reorder deadline, missing sequence numbers may be skipped and later arrivals below the retired horizon no longer affect ordered output.

## 8. Post-handshake control plane

For every non-empty post-handshake frame with `seq=0`, payload byte 0 is `control_kind`.

Current v3 kinds:

```text
0x01  FEC_PARITY
0x02  FEC_MODE
```

No other kind is valid in v3. Unknown kinds are protocol errors.

An empty `seq=0` payload is KEEPALIVE and has no `control_kind` byte.

## 9. FEC_PARITY control (`control_kind = 0x01`)

XOR FEC groups normal data into fixed arithmetic groups of K sequences. Group starts satisfy:

```text
group_start ≡ 1 (mod K)
```

Payload layout:

```text
0        1              5      6
+--------+--------------+------+
| kind=1 | start u32 BE | K u8 |
+--------+--------------+------+
| K × member_len u32 BE        |
+-------------------------------+
| XOR parity payload            |
+-------------------------------+
```

The parity payload is the bytewise XOR of the K **plaintext** member payloads, zero-extended to the longest member.

When inner encryption is enabled, only the XOR parity body is encrypted with the FEC AEAD domain. The descriptor (`kind/start/K/lengths`) remains visible inside TLS.

Parity AEAD uses:

- sequence input: `group_start`;
- wire length input: encrypted parity-body length including AEAD tag;
- key domain: `fec`.

A parity record is useful only when exactly one member of the group is missing.

## 10. Dynamic FEC mode control (`control_kind = 0x02`)

Dynamic mode control exists to let RX safely skip decoder map/allocation/XOR work when TX temporarily has fewer than two useful physical paths.

Payload length is exactly 16 bytes:

```text
0        1        2              4              12             16
+--------+--------+--------------+---------------+--------------+
| kind=2 | op u8  | flags u16 BE | generation u64| boundary u32 |
+--------+--------+--------------+---------------+--------------+
```

`flags` MUST be zero in v3.

Operations:

```text
1  SUSPEND
2  RESUME
```

`generation` starts at 1 for each session epoch and strictly increases for each real dynamic FEC mode transition. A receiver applies only a generation newer than the last accepted generation.

`boundary` is always a non-zero arithmetic FEC group start.

### 10.1 SUSPEND

`SUSPEND(boundary)` means the sender will not produce useful parity for groups whose start is at or beyond `boundary` until a later RESUME.

If a 2→1 transition abandons a partially accumulated group, the boundary rewinds to that partial group's arithmetic start.

The receiver may immediately discard decoder state inside the declared bypass interval, but groups before the boundary remain eligible for already-in-flight old parity until reorder progress proves they can no longer affect output.

### 10.2 RESUME

After physical multipath becomes available again, TX does not resume from a partial arithmetic group. It resumes only at the next complete group start.

`RESUME(boundary)` closes the bypass interval at that boundary. Data with `seq >= boundary` is decoded normally again.

If no complete FEC group boundary remains before uint32 sequence exhaustion, TX MUST NOT emit a wrapped RESUME; it remains suppressed until a new session epoch.

### 10.3 Startup semantics

Starting with one physical backend is not a dynamic 2→1 transition. No synthetic SUSPEND is emitted. If a second backend later joins before any real SUSPEND existed, no RESUME is needed because RX never entered a bypass window.

### 10.4 Ordering

The current Go sender prepends the current FEC_MODE control descriptor to the same backend channel batch as the first governed data batch selected for that physical backend.

The control boundary, not immediate byte adjacency, defines applicability. A control may precede older queued data whose sequence lies before the boundary.

Generation ordering resolves control reordering across independent TCP streams.

## 11. FEC decoder cleanup and reorder interaction

On SUSPEND, decoder groups inside the now-unrecoverable bypass interval may be released immediately without incrementing FEC-loss counters.

Groups before the SUSPEND boundary may still be useful to delayed old parity. They may be retired only after:

```text
reorder.expected_seq >= suspend_boundary
```

After retirement, late data/parity below the retired boundary must not recreate decoder state.

The implementation deliberately keeps this cleanup off the normal active-data hot path. Progress is checked on control/parity paths and sparsely during long bypass intervals.

## 12. Inner AEAD

Inner AEAD is optional because TLS already authenticates/encrypts the transport. When enabled, both peers must use the same explicit `enc_algo`; there is no implicit downgrade.

Current algorithm IDs:

```text
0  none
2  AES-256-GCM
4  AES-128-GCM
5  ChaCha20-Poly1305
6  XChaCha20-Poly1305
```

All supported AEADs use a 16-byte tag.

### 12.1 Key derivation

`psk` means the configured plaintext PSK here.

Data-domain key material is:

```text
SHA256(psk || algorithm_label)
```

FEC-domain key material uses the same algorithm label with `_fec` appended.

Labels:

```text
AES-256-GCM       _enc_key
AES-128-GCM       _enc_key128
ChaCha20          _enc_chacha20
XChaCha20         _enc_xchacha20
```

The digest is truncated to the algorithm key length where required.

### 12.2 Nonce

AES-GCM and ChaCha20-Poly1305 use a 12-byte nonce:

```text
seq_u32_be || salt_8B
```

XChaCha20-Poly1305 uses a 24-byte nonce:

```text
SHA256("tlsvpn-xchacha20-nonce-v1" || salt_8B)[0:20] || seq_u32_be
```

### 12.3 AAD

For both data and FEC AEAD domains:

```text
AAD = wire_len_u32_be || seq_u32_be
```

For normal data, `seq` is the data sequence. For FEC parity body encryption, `seq` is `group_start`.

Post-handshake typed control payloads themselves are not inner-AEAD encrypted; they are already protected by TLS. FEC parity body encryption remains independently authenticated when inner encryption is enabled.

## 13. Padding

Padding mode is negotiated/configured out of band by implementation configuration, not as a separate v3 control exchange.

The stream frame header carries `pad_len`; the receiver skips those bytes after reading `data_len` payload bytes.

Current modes:

- `off`: no cover padding.
- `bucket`: pads records toward configured size buckets, bounded by the implementation's stream/TLS batching limits.

Padding is not part of inner-AEAD AAD.

## 14. Multipath scheduling and ownership

Data is sent once on the selected backend; it is not replicated to every physical connection. Under load, the scheduler may stripe across eligible paths. FEC parity is generated once per full group and assigned according to the FEC path policy.

A physical backend channel owns the frame descriptors/payloads after successful enqueue. FEC_MODE fencing follows the backend that actually accepted the governed data after scheduler fallback.

## 15. Keepalive and failure detection

A post-handshake KEEPALIVE is a stream frame with:

```text
seq = 0
data_len = 0
```

It refreshes liveness/read deadlines but carries no typed control payload.

A malformed non-empty `seq=0` control payload is not a keepalive.

## 16. Protocol errors

At minimum, these are protocol errors in v3:

- application `protocol_version != 3`;
- unknown non-empty post-handshake `control_kind`;
- malformed FEC_MODE payload;
- FEC control traffic when FEC was not negotiated;
- impossible/invalid negotiated FEC group parameters;
- incompatible inner-encryption settings or algorithm;
- sequence/key epoch misuse that would permit nonce reuse.

Protocol errors MUST terminate the affected physical connection rather than silently reinterpret the bytes using v2 semantics.

## 17. Cross-language conformance

`testdata/protocol_golden.json` is the machine-readable cross-language contract for deterministic wire components. It MUST carry `version: 3` and be regenerated whenever a deliberate v3 wire contract change is made.

Go and Rust implementations MUST both validate the same golden vectors for:

- PSK hashing;
- frame header layout;
- handshake JSON field names;
- AEAD domains/nonces/AAD/ciphertext;
- TLS diagnostic normalization;
- v3 control payload layouts.

Any deliberate wire-incompatible change after this specification should increment the application protocol version again instead of adding compatibility ambiguity to v3.
