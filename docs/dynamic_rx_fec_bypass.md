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

## RESUME boundary

When a second backend returns, TX already waits until the next arithmetic group boundary before re-arming the encoder.

For first seq `S` observed after >=2 paths return:

```
offset = (S - 1) % K
resume_from = S                  if offset == 0
resume_from = S + (K - offset)   otherwise
```

The RESUME control may be sent before `resume_from`. RX must therefore keep bypassing `[bypass_from, resume_from)` and only decode sequences `>= resume_from`.

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

A control fence must be ordered before the first data/parity record governed by that transition on every physical backend that carries post-transition traffic.

Do not write control frames directly to the TLS connection from another goroutine.

`AsyncPort` is the sole producer of backend queues, so ordering must be established there.

Recommended approach:

1. `AsyncPort` increments a global FEC mode generation on a 2→1 or 1→2 transition.
2. Each `Backend` remembers the last generation it has been fenced for.
3. Before the first post-transition batch sent to a backend, prepend the current `seq=0` control frame to that same backend batch.
4. Only after the control descriptor may data/parity descriptors for that generation be queued on that backend.

This avoids a separate control queue slot and cannot lose the fence merely because the backend channel is full.

For a newly added backend during RESUME, its first data/parity batch must carry the RESUME fence first.

## Rapid 2→1→2 races

Controls can arrive out of order across TCP streams. Example:

```
A: SUSPEND generation 10 is stuck behind old ciphertext
B: new path joins and delivers RESUME generation 11 quickly
A: old SUSPEND generation 10 arrives later
```

Without `generation`, RX would regress to bypass mode and miss valid new FEC groups. With generation ordering, generation 10 is ignored after 11 is applied.

If RESUME arrives before an earlier SUSPEND was ever observed, RX simply remains conservative (decoder active). This loses optimization only; correctness is preserved.

## Pending decoder state after SUSPEND

Groups with `start >= bypass_from` are provably unrecoverable and may be released immediately because the sender reset the partial group and will not emit parity for them.

Groups with `start < bypass_from` must remain eligible for late parity. They cannot be cleared solely because the SUSPEND fence arrived: parity/data from the failed TCP path may still arrive later.

Safe eventual cleanup condition:

```
reorder.expectedSeq >= bypass_from
```

At that point all earlier sequences have either been delivered/recovered or the reorder timeout has already skipped them, so recovering an older frame can no longer affect output.

A future implementation should expose a cheap reorder progress snapshot or schedule cleanup from the cold transition path. Do not add a lock acquisition to every normal RX packet just for cleanup.

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
6. RESUME fence is processed before the first resumed data/parity on each backend.
7. SUSPEND generation N arriving after RESUME generation N+1 is ignored.
8. Multiple rapid 2→1→2→1 transitions with cross-stream control reordering.
9. Failed control capability / old peer: tunnel remains correct, only optimization is absent.
10. Go↔Rust interop with unknown control frames in both directions.
11. Race detector with concurrent control application, parity arrival and data arrival.
12. Real-TAP fault injection: kill one of two TCP connections under sustained FEC traffic, verify no added reorder loss and measure decoder CPU during the single-path interval.

## Recommended implementation split

- P2a: control payload codec + generation/window state machine unit tests only.
- P2b: AsyncPort per-backend fence ordering and Go RX integration.
- P2c: reorder-progress cleanup of pre-fence groups.
- P2d: fault-injection / Real-TAP benchmark.
- P2e: optional Rust implementation for symmetric CPU savings; old Rust remains wire-compatible without it.
