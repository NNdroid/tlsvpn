# Dynamic 2→1 RX FEC bypass

Normative wire specification: [`protocol_v3.md`](protocol_v3.md).

This document records the design rationale, implementation stages and validation evidence for dynamic RX FEC bypass. It is not an alternate wire specification; where wording differs, `protocol_v3.md` is authoritative.

Status: **P2a, P2b, P2c and P2d are implemented and validated in Go.** Rust protocol-v3 migration remains separate work.

Baseline: `perf/single-path-fec-bypass` / PR #68.

## 1. Problem

TX has no reason to build XOR parity while fewer than two useful physical backends exist. RX should likewise avoid per-data decoder work during that interval, but RX cannot infer the interval from its own physical connection count.

Path-loss detection is asynchronous. When one TCP stream fails, data/parity sent before the collapse can still arrive on another stream. A receiver that immediately disables FEC when local `liveConns == 1` can discard the exact pre-collapse state needed to recover a missing frame.

The governing invariant is therefore:

> RX may bypass a data sequence only after the sender has authoritatively declared that the group containing that sequence will not receive useful parity.

## 2. Protocol-v3 control model

Protocol v3 reserves non-empty post-handshake `seq=0` records for typed controls.

Dynamic FEC uses `control_kind=0x02` (`FEC_MODE`):

```text
[1B kind=0x02]
[1B op]
[2B flags=0, big endian]
[8B generation, big endian]
[4B boundary, big endian]
```

Operations:

```text
1  SUSPEND
2  RESUME
```

There is no v2 compatibility interpretation. Unknown or malformed post-handshake controls are protocol errors.

`generation` is monotonic inside one sequence/key epoch. Controls with `generation <= last_generation` are stale and cannot regress receiver state after cross-TCP reordering.

## 3. Sender transition rules

### 3.1 Startup

Starting with one physical backend is not a dynamic collapse. TX suppresses FEC work but sends no synthetic SUSPEND. If a second backend joins before any real SUSPEND, no RESUME is required because RX never entered a dynamic bypass window.

### 3.2 Genuine >=2 → 1 collapse

A genuine physical backend collapse publishes SUSPEND.

If an incomplete encoder group exists, TX discards it. The SUSPEND boundary is therefore the arithmetic start of that abandoned group, not simply the first sequence observed after path loss.

For K=4:

```text
1..4  complete
5,6   partial while multipath
path collapses
7     first newly dispatched data after collapse

SUSPEND boundary = 5
```

General group start:

```text
group_start(seq) = seq - ((seq - 1) % K)
```

### 3.3 Genuine 1 → >=2 restore

After a real SUSPEND, FEC does not restart halfway through an arithmetic group. RESUME uses the next complete group start at or after the first restored-multipath sequence.

If the next boundary would overflow uint32, TX remains suppressed until epoch rotation.

## 4. Fence ordering

`sendBatchToAnyFenced` attaches the current FEC_MODE descriptor to the same backend batch as the governed data that was actually accepted after scheduler fallback:

```text
[seq=0 FEC_MODE] [data] [data] ...
```

The backend's remembered generation advances only after successful channel enqueue.

This provides four important properties:

1. the fence follows the backend that actually accepted the data;
2. fence and governed data share one backend queue/TLS writer ordering domain;
3. backend-channel pressure cannot independently drop a control queue entry;
4. a newly registered backend receives the current generation before its first governed data batch.

The boundary, not physical adjacency, defines applicability. A fence may legally precede older queued data whose sequence is below the boundary.

## 5. Receiver hot path

RX stores the sender-declared dynamic bypass interval in one packed atomic 64-bit window:

```text
0,0        decoder active
from,0     bypass seq >= from
from,until bypass from <= seq < until
```

`OnData` checks this window before taking the decoder mutex and rechecks it after locking, closing the race where SUSPEND arrives between the fast-path check and group allocation/XOR.

Static configured-single-path bypass remains a separate faster path.

Dynamic parity handling remains conservative: parity is still parsed while data is bypassed. At roughly 1/K of data frequency this costs much less than per-data map/mutex/XOR work and avoids requiring a RESUME on one TCP stream to precede parity arriving on another.

## 6. Decoder-state cleanup

P2c separates state into two classes.

### 6.1 Groups inside the bypass interval

These groups are sender-declared unrecoverable and can be released immediately. Releasing them:

- does not mark them `done`;
- does not increment `fec_lost`;
- releases parity/lens/accumulator storage;
- prevents parity-only buildup during a long bypass interval.

### 6.2 Groups before SUSPEND

Older groups may still be recoverable by delayed pre-collapse parity. They remain until ordered output proves they are obsolete:

```text
reorder.expected_seq >= suspend_boundary
```

After that point `retiredBefore` blocks late data/parity from recreating obsolete decoder state.

`ReorderBuffer.ExpectedSeqSnapshot()` is intentionally a cold mutex-protected read. Normal active data does not acquire the reorder mutex for cleanup. During a long parity-free bypass interval, data probes progress only once per 256 sequence numbers.

`controlMu` serializes accepted generation application with its cleanup so a slower old-control goroutine cannot delete groups after a newer generation has already resumed FEC.

## 7. Epoch rules

FEC transition generations are scoped to the logical sequence/key epoch.

`AsyncPort.ResetEpoch` resets every surviving backend's remembered fence generation because the replacement encoder starts generation numbering from one.

A physical TCP path dropping and rejoining the same logical session is **not** an epoch reset. It keeps:

- the global data sequence;
- current FEC transition generation;
- reorder state;
- inner-AEAD salts and nonce domain.

This distinction is normative in `protocol_v3.md`.

## 8. Validation stages

### P2a — state machine and codec

Validated:

- strict FEC_MODE codec;
- arithmetic SUSPEND/RESUME boundaries;
- uint32 exhaustion without wrap;
- stale-generation rejection;
- rapid transition ordering;
- concurrent state access under `-race`.

### P2b — Go data-path integration

Validated:

- actual backend fallback receives fence + governed data together;
- one fence per backend generation;
- newly joined backend fencing;
- backend generation reset on epoch reset;
- bypassed data performs no decoder group/XOR work;
- resumed data re-enters normal decoder processing.

### P2c — stale decoder-state retirement

Validated:

- immediate SUSPEND interval cleanup;
- RESUME cleanup of parity-only bypass groups;
- preservation of pre-boundary recoverable groups;
- reorder-gated retirement;
- prevention of late retired-state recreation;
- sparse cleanup probing;
- race-safe locking.

### P2d — real physical-path fault injection

The in-process P2d test runs the real Go client/server transport stack:

```text
TCP
→ TLS
→ protocol-v3 handshake/control
→ AsyncPort multipath
→ XOR FEC
→ inner AEAD
→ reorder
→ VSwitch
→ mem TAP
```

The test establishes two authenticated physical TCP connections, warms multipath FEC, prevents replacement handshakes, closes one real server-side TCP connection, sustains one-path traffic, restores replacement authentication, waits for the second physical connection to rejoin, then resumes multipath traffic.

The hard assertions are:

- physical topology reaches 2 → 1 → 2;
- SUSPEND opens an RX bypass interval;
- parity generation stops during the one-path interval;
- no decoder groups remain inside the bypass range;
- RESUME closes the interval at a valid complete group boundary;
- parity generation resumes after multipath returns;
- all injected application frames are delivered exactly once and in order;
- `fec_lost == 0`;
- the complete protocol/FEC suite passes under the Go race detector.

CI result on 2026-09-30:

```text
SUSPEND boundary: 33
RESUME boundary:  97
Parity count:      8 -> 24
FEC recovered:     20
FEC lost:          0
Live fault test:   PASS (2.20s)
Race gate:         PASS
```

## 9. Decoder microbenchmark

Same CI runner, AMD EPYC 7763, 1400-byte data frames, zero allocations:

```text
active decoder:    ~92.7–94.3 ns/frame
dynamic bypass:    ~3.46–3.49 ns/frame
static single:     ~2.79–2.82 ns/frame
```

Dynamic bypass removes roughly **96.3%** of the active decoder per-data-frame CPU cost while retaining sender-authoritative recovery safety.

## 10. Remaining work

The Go protocol-v3 dynamic RX design is validated through P2d.

Remaining interoperability work is to migrate `NNdroid/tlsvpn-rs` to the same exact protocol-v3 handshake, typed control plane, golden vectors, dynamic FEC state machine and path-transition semantics. No v2 shim should be retained in that implementation.
