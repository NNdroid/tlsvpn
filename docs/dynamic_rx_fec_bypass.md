# Dynamic 2→1 RX FEC bypass research

Status: research design, not yet data-plane implementation.

Baseline: `perf/single-path-fec-bypass` / PR #68.

## Problem

TX already suppresses XOR/FEC work when the physical backend count falls below two. RX cannot safely infer the same state from its local live-connection count because sender/receiver path-loss detection is asynchronous and old data/parity may still be in flight on either TCP stream.

A receiver that simply disables FEC when `liveConns == 1` can discard a parity frame that was generated before the collapse and could still recover a missing pre-collapse data frame.

## Required invariant

RX may bypass a data sequence only after the sender has authoritatively stated that no parity can be generated for the FEC group containing that sequence.

The sender, not the receiver's local connection count, owns that fact.

## Proposed mechanism: sender-authoritative FEC mode fence

Use a new optional `seq=0` control frame. Unknown `seq=0` frames are already discarded by both current Go and Rust reorder paths, so old peers can safely ignore the hint.

Suggested payload (v1):

```
[1B magic=0xFD]
[1B version=1]
[1B op]
[1B reserved]
[8B generation, big endian]
[4B boundary_seq, big endian]
```

Operations:

- `SUSPEND`: FEC has no recovery value for all groups whose start is `>= boundary_seq`.
- `RESUME`: FEC may again be generated beginning at the complete group starting at `boundary_seq`.

`generation` monotonically increases on every sender-side FEC mode transition. Receivers ignore controls with `generation <= last_generation`, preventing an old SUSPEND arriving from a slow TCP stream after a newer RESUME from disabling FEC incorrectly.

Generation is scoped to the current sequence/key epoch. A fresh epoch recreates decoder state and starts control generation from zero again; old physical connections are already rejected/closed by the existing epoch machinery.

## Why the SUSPEND boundary is a group start, not merely the first single-path data seq

When physical backends collapse from >=2 to 1, the current encoder resets any partial group. Therefore the partial group can never receive parity even if some members were transmitted while multiple paths still existed.

For K=4:

```
... group 1..4 complete
seq 5,6 sent while 2 paths exist (partial group)
path collapses
seq 7 is first batch observed with only 1 path
```

The correct SUSPEND boundary is `5`, not `7`: group 5..8 can no longer produce parity because TX discarded its partial encoder state.

General formula for first seq `S` observed in the single-path dispatch:

```
bypass_from = S - ((S - 1) % K)
```

All decoder work for `seq >= bypass_from` is unnecessary until RESUME.

Because `dispatchBatch` holds `backendsMu.RLock`, backend register/unregister cannot change the physical-path snapshot in the middle of one dispatched batch. This makes the first sequence in the first single-path batch a stable transition observation point.

## RESUME boundary

When a second backend returns, TX already waits until the next arithmetic group boundary before re-arming the encoder.

For first seq `S` observed after >=2 paths return:

```
offset = (S - 1) % K
resume_from = S                  if offset == 0
resume_from = S + (K - offset)   otherwise
```

The RESUME control may be sent before `resume_from`. RX must therefore keep bypassing `[bypass_from, resume_from)` and only decode sequences `>= resume_from`.

### Sequence exhaustion

The boundary calculation must be done without uint32 wraparound. If the next complete FEC group boundary would be greater than `MaxUint32`, there is no valid RESUME boundary in the current epoch. In that case TX stays FEC-suppressed until the existing sequence-exhaustion path forces a fresh epoch.

A wrapped RESUME boundary such as `0xFFFFFFFE -> 1` would be incorrect and must never be emitted.

## Receiver hot-path representation

Use one atomic 64-bit bypass window:

```
window = uint64(from) << 32 | uint64(until)
```

Semantics:

- `0`: decoder fully active
- `from > 0, until == 0`: bypass all data `seq >= from`
- `from > 0, until > from`: bypass `from <= seq < until`

This permits one atomic load in `OnData`.

Static single-path mode is equivalent to `from=1, until=0`, though the existing `staticSingle` flag can remain initially to keep the patch small.

For parity, parse `groupStart` first and drop parity only when its group lies in the active bypass window. Old parity for groups before `from` must remain accepted after SUSPEND.

## Ordering rule

### Correctness asymmetry

SUSPEND may arrive late without breaking correctness: RX merely wastes some decoder CPU until it sees the fence.

RESUME is different. If data at/after `resume_from` is processed while RX still believes the old open-ended SUSPEND window, RX will skip those members; a later parity frame can no longer recover a missing member because the decoder never accumulated the already-arrived members. Therefore RESUME must be visible before any backend can deliver data/parity governed by the resumed FEC interval.

### Refined implementation: per-backend pending fence consumed by the TLS writer

Do not write control frames directly to TLS from `AsyncPort`, and do not refactor `sendBatchToAny` into a target-specific control injector.

A cleaner ordering primitive already exists: every physical `Backend` has exactly one TLS writer, while `AsyncPort` is the only producer of its batch channel.

Recommended P2b design:

1. `AsyncPort` detects the physical-path mode transition while holding the backend-list read lock for a dispatch.
2. It increments the global FEC control generation and publishes the same pending control to every backend in that dispatch snapshot **before** enqueueing the current post-transition batch.
3. Each backend writer checks/consumes its pending control immediately after it receives a channel batch and **before framing that batch**.
4. The writer prepends the `seq=0` control record to its TLS plaintext, then frames the normal batch.
5. The writer must repeat this pending-control check for every batch taken by its inner `drainBatches` loop, not merely once at the outer select. Otherwise a transition can occur while the writer is coalescing multiple channel batches and a resumed batch could slip out before its RESUME fence.

The Go memory model helps here: `AsyncPort` publishes the pending fence before the channel send of the post-transition batch; that send/receive synchronization means the writer can observe the published fence when it receives that batch.

This design has several useful properties:

- no separate control queue slot, so a full backend channel cannot drop the fence;
- no payload ownership rewrite in `sendBatchToAny` or `sendOwnedFrameTo`;
- fallback from preferred backend to another backend remains correct automatically;
- data and parity writers share the same backend channel/fence mechanism;
- a fence may be emitted before older already-queued sequences on that TCP stream, which is safe because the explicit boundary governs which sequences are affected;
- on RESUME, every backend that can carry resumed traffic is guaranteed to write its own RESUME fence before its first affected batch.

For a backend added while the sender was in a single-path interval, the next dispatch observes >=2 paths, creates RESUME, and marks both the survivor and new backend pending before either can receive resumed traffic from that dispatch.

## Why writer-side fence can legally precede old queued data

Example: SUSPEND says `boundary=21`, but the surviving backend still has seq 11..20 queued. The writer may emit SUSPEND before 11..20; RX still decodes 11..20 because they are `<21`.

Likewise RESUME may say `boundary=25` and be emitted before single-path seq 21..24; RX continues bypassing `[suspend_from,25)` and activates the decoder only at 25.

Therefore the hard requirement is not “control immediately adjacent to boundary data”; it is:

- the control boundary must be correct;
- generation must reject cross-stream stale controls;
- RESUME must be emitted before any `seq >= resume_from` traffic on every backend that can carry such traffic.

## Rapid 2→1→2 races

Controls can arrive out of order across TCP streams. Example:

```
A: SUSPEND generation 10 is stuck behind old ciphertext
B: new path joins and delivers RESUME generation 11 quickly
A: old SUSPEND generation 10 arrives later
```

Without `generation`, RX would regress to bypass mode and miss valid new FEC groups. With generation ordering, generation 10 is ignored after 11 is applied.

If RESUME arrives before an earlier SUSPEND was ever observed, RX simply remains conservative (decoder active). This loses optimization only; correctness is preserved.

A later SUSPEND can replace an older closed bypass window. Very late packets from the old interval may then take the decoder path again, but that is conservative CPU work rather than a correctness failure.

## Pending decoder state after SUSPEND

Groups with `start >= bypass_from` are provably unrecoverable and may be released immediately because the sender reset the partial group and will not emit parity for them.

Groups with `start < bypass_from` must remain eligible for late parity. They cannot be cleared solely because the SUSPEND fence arrived: parity/data from the failed TCP path may still arrive later.

Safe eventual cleanup condition:

```
reorder.expectedSeq >= bypass_from
```

At that point all earlier sequences have either been delivered/recovered or the reorder timeout has already skipped them, so recovering an older frame can no longer affect output.

A future implementation should expose a cheap reorder progress snapshot or schedule cleanup from the cold transition path. Do not add a lock acquisition to every normal RX packet just for cleanup.

P2b does not need to solve this immediately for correctness: keeping the bounded pre-fence decoder groups alive only costs memory. P2c should add the progress-based cleanup separately so the hot-path fence patch stays auditable.

## Backward compatibility

### Old Go receiver

Unknown `seq=0` payload:

- does not match `fecMagic`
- `fecDecoder.OnData(0, ...)` is a no-op
- `ReorderBuffer.Insert(0, ...)` drops it

Therefore it safely ignores the new fence.

### Current Rust receiver

Rust explicitly treats `seq==0` as control-class traffic and its reorder buffer drops sequence zero. Unknown fence payloads are therefore also safely ignored.

No protocol-version bump is required for correctness. A future capability bit may still be useful for observability, but TX does not depend on receiver support: sender-side single-path FEC suppression already exists today.

## Tests required before implementation can be considered safe

1. 2→1 mid-group: SUSPEND boundary rewinds to that group's arithmetic start.
2. 2→1 exactly on boundary.
3. Old parity before SUSPEND arrives after SUSPEND and still recovers an old missing member.
4. Data in the bypass interval performs zero decoder group/map/XOR work.
5. 1→2 mid-group: RESUME waits until next complete boundary.
6. Near sequence exhaustion: RESUME boundary never wraps; no RESUME is emitted if no full group remains this epoch.
7. RESUME fence is processed before the first resumed data/parity on each backend.
8. Writer coalescing race: transition occurs between two batches drained in one TLS write; the second batch still gets fenced first.
9. SUSPEND generation N arriving after RESUME generation N+1 is ignored.
10. Multiple rapid 2→1→2→1 transitions with cross-stream control reordering.
11. Failed control capability / old peer: tunnel remains correct, only optimization is absent.
12. Go↔Rust interop with unknown control frames in both directions.
13. Race detector with concurrent control application, parity arrival and data arrival.
14. Real-TAP fault injection: kill one of two TCP connections under sustained FEC traffic, verify no added reorder loss and measure decoder CPU during the single-path interval.

## Recommended implementation split

- P2a: control payload codec + generation/window state machine unit tests only.
- P2b: AsyncPort transition detection, per-backend writer fence ordering and Go RX integration.
- P2c: reorder-progress cleanup of pre-fence groups.
- P2d: fault-injection / Real-TAP benchmark.
- P2e: optional Rust implementation for symmetric CPU savings; old Rust remains wire-compatible without it.
