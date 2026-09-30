# Dynamic 2→1 RX FEC bypass research

Status: P2a state machine and P2b Go data-path integration implemented on the research branch. P2c decoder-state cleanup and P2d fault-injection/performance validation remain pending.

Baseline: `perf/single-path-fec-bypass` / PR #68.

## Problem

TX already suppresses XOR/FEC work when the physical backend count falls below two. RX cannot safely infer the same state from its local live-connection count because sender/receiver path-loss detection is asynchronous and old data/parity may still be in flight on either TCP stream.

A receiver that simply disables FEC when `liveConns == 1` can discard useful pre-collapse state or can resume too early after a path returns.

## Required invariant

RX may bypass a data sequence only after the sender has authoritatively stated that no parity can be generated for the FEC group containing that sequence.

The sender, not the receiver's local connection count, owns that fact.

## Sender-authoritative FEC mode fence

P2b uses an optional `seq=0` control frame. Unknown `seq=0` frames are already discarded by old Go/Rust receive paths, so peers that do not understand the hint remain wire-compatible.

Wire payload v1:

```
[1B magic=0xFD]
[1B version=1]
[1B op]
[1B reserved=0]
[8B generation, big endian]
[4B boundary_seq, big endian]
```

Operations:

- `SUSPEND`: FEC has no recovery value for data groups whose start is `>= boundary_seq`.
- `RESUME`: FEC may again be generated beginning at the complete group starting at `boundary_seq`.

`generation` monotonically increases on every sender-side FEC mode transition. RX ignores controls with `generation <= last_generation`, preventing an old SUSPEND arriving from a slow TCP stream after a newer RESUME from regressing the receiver.

Generation is scoped to the sequence/key epoch. `AsyncPort.ResetEpoch` resets each surviving backend's remembered fence generation to zero because the replacement encoder restarts its control generation at one. Without this reset, a backend that had observed generation 9 in the old epoch could incorrectly suppress generation 1 in the new epoch.

## SUSPEND boundary

When physical backends collapse from >=2 to 1, the encoder resets any partial group. The abandoned partial group can never receive parity even if some of its members were transmitted while multiple paths still existed.

For K=4:

```
... group 1..4 complete
seq 5,6 sent while 2 paths exist (partial group)
path collapses
seq 7 is first batch observed with only 1 path
```

The correct SUSPEND boundary is `5`, not `7`.

General formula for the first single-path sequence `S` when there is no already-open partial encoder group:

```
bypass_from = S - ((S - 1) % K)
```

If a partial encoder group already exists, its stored first sequence is the authoritative boundary.

`dispatchBatch` holds `backendsMu.RLock`, so backend register/unregister cannot change the physical-path snapshot in the middle of one dispatch. `pickAdaptiveBackend` updates encoder topology before the current batch is fed to the encoder, making `lastSeq + 1` the first sequence governed by that transition.

## RESUME boundary

When a second backend returns, TX waits until the next arithmetic group boundary before re-arming XOR accumulation.

For the first sequence `S` governed by the restored multipath topology:

```
offset = (S - 1) % K
resume_from = S                  if offset == 0
resume_from = S + (K - offset)   otherwise
```

RX therefore keeps bypassing `[bypass_from, resume_from)` and resumes data accumulation at `resume_from`.

### Sequence exhaustion

The boundary calculation must not wrap uint32. If the next complete group start would exceed `MaxUint32`, there is no valid RESUME boundary in the current epoch. TX stays FEC-suppressed until the existing sequence-exhaustion path establishes a fresh epoch.

## Receiver hot-path representation

The dynamic receive state is a packed atomic 64-bit bypass window:

```
window = uint64(from) << 32 | uint64(until)
```

Semantics:

- `0,0`: dynamic decoder active
- `from,0`: bypass data `seq >= from`
- `from,until`: bypass data `from <= seq < until`

`OnData` performs an atomic window check before taking the FEC decoder mutex and repeats the check after locking to close the race where SUSPEND arrives between the fast-path check and group allocation/XOR.

The existing `staticSingle` fast bypass remains independent and still handles a topology configured with exactly one physical connection.

## P2b ordering implementation: fence travels in the actual data batch

The implemented P2b ordering primitive is simpler and stronger than the earlier writer-pending design.

`sendBatchToAnyFenced` chooses the real writable backend exactly as normal scheduling/fallback does. If that backend has not yet carried the current control generation, it constructs one backend batch whose descriptors are:

```
[seq=0 FEC control] [data frame] [data frame] ...
```

The batch is then sent through that backend's existing channel. The backend's `fecFenceGen` is advanced only after the channel send succeeds.

This gives several useful properties:

1. The fence follows the **actual** backend selected after preferred-path fallback. A full preferred backend is never incorrectly marked fenced.
2. Fence and governed data occupy the same channel batch, so the single TLS writer necessarily frames the control before those data records.
3. No independent control queue slot can be dropped under backend-channel pressure.
4. If the backend send fails, the fence generation is not advanced; another backend or retry still receives the fence.
5. A newly registered backend starts with fence generation zero and receives the current generation before its first data batch.
6. The control may precede older queued data. This is safe because applicability is determined by `boundary_seq`, not by physical adjacency on a TCP stream.

Example: SUSPEND has `boundary=21`, while the same TCP stream still has seq 11..20 queued. The control may appear before 11..20; RX continues decoding those sequences because they are `<21`.

Likewise RESUME may advertise `boundary=25` before seq 21..24; those sequences remain inside the bypass window while seq 25+ are decoded.

## Why P2b dynamically bypasses data but keeps parity conservative

P2b deliberately applies the dynamic window only to `fecDecoder.OnData`.

`OnParity` remains active except for the existing static-single-path bypass. This is intentional:

- parity frequency is only about 1/K of data frequency;
- the expensive hot work targeted by this optimization is per-data group lookup/allocation/XOR;
- keeping parity conservative removes a cross-TCP correctness dependency on a RESUME fence arriving before a parity frame on another stream;
- an early resumed parity frame may create/hold a group and later data can complete it after RESUME becomes visible;
- old parity for a group before SUSPEND continues to recover a missing pre-collapse member.

This choice spends a small amount of cold parity work to make P2b ordering easier to audit. P2c can release provably useless parity/group state without changing this rule.

## Rapid 2→1→2 races

Controls can arrive out of order across TCP streams:

```
A: SUSPEND generation 10 is delayed
B: a restored path delivers RESUME generation 11
A: SUSPEND generation 10 arrives later
```

Generation ordering makes the final SUSPEND stale and it is ignored.

If RESUME arrives before the receiver ever observed the earlier SUSPEND, RX remains conservative with the decoder active. That loses CPU optimization only; it cannot lose recoverability.

If a later SUSPEND replaces an older closed bypass window, very late packets from an older interval may also take the decoder path again. This again costs CPU but is conservative for correctness.

## Pending decoder state after SUSPEND — P2c

P2b stops creating/updating decoder groups for data inside the bypass interval, but it does not yet aggressively delete pre-existing group state.

Groups with `start >= bypass_from` are provably unrecoverable after the sender has discarded that partial encoder group and can be released on SUSPEND.

Groups with `start < bypass_from` must remain eligible for late parity/data from the old multipath interval. They cannot be discarded solely because the fence arrived.

Safe eventual cleanup condition for the older groups is:

```
reorder.expectedSeq >= bypass_from
```

At that point earlier sequences have either been delivered/recovered or skipped by reorder timeout, so a late recovery cannot affect ordered output.

P2c should expose a cheap reorder progress snapshot and perform this cleanup from the cold control path rather than adding a mutex acquisition to every normal RX packet.

## Backward compatibility

### Old Go receiver

An unknown `seq=0` payload does not match `fecMagic`; old `fecDecoder.OnData(0, ...)` is a no-op and `ReorderBuffer.Insert(0, ...)` drops/frees it. The tunnel remains correct and simply misses the RX CPU optimization.

### Current Rust receiver

Rust already treats `seq==0` as control-class traffic and drops unknown sequence-zero payloads. It is therefore wire-compatible without implementing the dynamic bypass state machine.

No protocol-version bump is required for correctness. A future capability bit may still be useful for observability.

## P2a/P2b validation coverage

Current tests cover:

1. control codec and strict version/reserved-field parsing;
2. 2→1 mid-group SUSPEND boundary rewind;
3. 1→2 RESUME at the next complete group boundary;
4. sequence exhaustion without uint32 boundary wrap;
5. stale lower-generation SUSPEND after newer RESUME;
6. rapid control transitions and concurrent receiver state access under `-race`;
7. preferred backend full → fallback backend receives fence + data together;
8. one fence per backend per generation;
9. backend fence generation reset on sequence/key epoch change;
10. bypass-interval data creates no decoder group;
11. resumed data creates decoder state again at the declared boundary;
12. old parity after SUSPEND still recovers a pre-boundary missing member;
13. control is encoded as a normal TLSVPN frame with wire `seq=0`.

The research CI runs build, focused FEC/dynamic tests, and the same set under the Go race detector.

## Remaining stages

- **P2c:** cleanup decoder groups using SUSPEND boundary + reorder progress.
- **P2d:** sustained 2→1→2 path-kill fault injection, including Real-TAP CPU profile and loss/reorder checks.
- **P2e:** optional Rust implementation for symmetric RX CPU savings; old Rust remains wire-compatible without it.
