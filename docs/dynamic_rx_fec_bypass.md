# Dynamic 2→1 RX FEC bypass research

Normative wire specification: [`protocol_v3.md`](protocol_v3.md). This file records design rationale and implementation staging only.

Status: P2a state machine, P2b Go data-path integration, and P2c decoder-state cleanup are implemented on the research branch. P2d fault-injection/performance validation remains pending.

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

### Startup is not a dynamic transition

The encoder constructor defaults to multipath semantics so direct unit tests/benchmarks keep their historical behavior. Runtime topology detection is stricter: if the first real dispatch sees only one physical backend, TX enters single-path suppression without publishing SUSPEND because no multipath group has ever existed. If a second backend subsequently appears and no SUSPEND generation has ever been published, no RESUME is needed either—the receiver stayed conservatively active throughout startup.

Only a genuine `>=2 -> 1` transition opens a dynamic bypass interval; only a later `1 -> >=2` transition closes it.

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

P2c adds one monotonic `retiredBefore` atomic load to active data. It does **not** query ReorderBuffer or acquire a cleanup mutex on each normal packet. Once ordered delivery proves sequences below a boundary can no longer affect output, very late data below `retiredBefore` is rejected before group allocation.

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

## Why dynamic bypass keeps parity conservative

The dynamic window applies to `fecDecoder.OnData`; `OnParity` remains active except for the existing static-single-path bypass.

This is intentional:

- parity frequency is only about 1/K of data frequency;
- the expensive hot work targeted by the optimization is per-data group lookup/allocation/XOR;
- keeping parity conservative removes a cross-TCP correctness dependency on a RESUME fence arriving before a parity frame on another stream;
- an early resumed parity frame may create/hold a group and later data can complete it after RESUME becomes visible;
- old parity for a group before SUSPEND continues to recover a missing pre-collapse member.

P2c makes this conservative choice cheap by deleting parity-only groups as soon as a control proves their interval has no recoverable data.

## Rapid 2→1→2 races

Controls can arrive out of order across TCP streams:

```
A: SUSPEND generation 10 is delayed
B: a restored path delivers RESUME generation 11
A: SUSPEND generation 10 arrives later
```

Generation ordering makes the final SUSPEND stale and it is ignored.

`fecDecoder.controlMu` serializes accepted control application and its group cleanup as one cold operation. This matters even though `fecRXFenceState` already serializes generation updates: without the outer serialization, cleanup belonging to an older control goroutine could run after a newer RESUME had already created valid groups.

If RESUME arrives before the receiver ever observed the earlier SUSPEND, RX remains conservative with the decoder active. That loses CPU optimization only; it cannot lose recoverability.

## P2c decoder-state retirement

P2c separates two classes of state.

### 1. Groups inside the declared bypass interval

These can be released immediately on control processing:

- SUSPEND `[from, infinity)`: sender reset the partial encoder state and will not emit parity for these groups.
- RESUME `[from, until)`: data in this single-path interval was deliberately bypassed, so a parity-only decoder group in the same interval cannot become useful later.

This cleanup only releases buffers/map entries. It does **not** mark the group done and does **not** increment `fec_lost`, because topology suppression is not packet loss.

### 2. Older groups before `bypass_from`

These may still be recoverable from delayed pre-collapse data/parity and therefore survive the fence until ordered delivery proves they are obsolete.

The safe retirement condition is:

```
reorder.expectedSeq >= cleanup_boundary
```

At that point every earlier sequence has already been delivered/recovered or skipped by reorder timeout. A later recovered frame below the boundary cannot affect output.

`ReorderBuffer.ExpectedSeqSnapshot()` is a cold mutex-protected read. P2c deliberately does not publish `expectedSeq` atomically from every Insert/drain, avoiding another write in the RX hot path.

The decoder tracks:

- `cleanupBefore`: highest accepted SUSPEND boundary that may retire old groups once reorder reaches it.
- `retiredBefore`: highest boundary already proven obsolete by reorder progress.

After retirement, late data/parity below `retiredBefore` is rejected so removed decoder state cannot be recreated.

### Sparse progress checks

Reorder progress is checked on already-cold control/parity paths. During a long single-path interval where no parity exists, bypassed data performs one progress probe only when `seq & 0xff == 0`—at most once per 256 sequence numbers. Normal active data never calls the reorder progress callback.

The existing lock direction remains `fecDecoder.mu -> ReorderBuffer.mu`, the same direction already used by FEC recovery callbacks. No reverse lock order is introduced.

## Backward compatibility

### Old Go receiver

An unknown `seq=0` payload does not match `fecMagic`; old `fecDecoder.OnData(0, ...)` is a no-op and `ReorderBuffer.Insert(0, ...)` drops/frees it. The tunnel remains correct and simply misses the RX CPU optimization.

### Current Rust receiver

Rust already treats `seq==0` as control-class traffic and drops unknown sequence-zero payloads. It is therefore wire-compatible without implementing the dynamic bypass state machine.

No protocol-version bump is required for correctness. A future capability bit may still be useful for observability.

## P2a/P2b/P2c validation coverage

Current tests cover:

1. control codec and strict version/reserved-field parsing;
2. 2→1 mid-group SUSPEND boundary rewind;
3. startup single-path suppression without a synthetic dynamic transition;
4. 1→2 RESUME at the next complete group boundary after a real SUSPEND;
5. sequence exhaustion without uint32 boundary wrap;
6. stale lower-generation SUSPEND after newer RESUME;
7. rapid control transitions and concurrent receiver state access under `-race`;
8. preferred backend full → fallback backend receives fence + data together;
9. one fence per backend per generation;
10. backend fence generation reset on sequence/key epoch change;
11. bypass-interval data creates no decoder group;
12. resumed data creates decoder state again at the declared boundary;
13. late old parity after SUSPEND still recovers a pre-boundary missing member;
14. SUSPEND immediately drops only bypass-range groups and preserves older recoverable groups;
15. RESUME removes parity-only groups from the closed bypass interval while preserving the first resumed group;
16. old groups retire only after reorder progress reaches the fence;
17. late retired data/parity cannot recreate obsolete groups;
18. bypass data progress probing is sparse (one per 256 sequence numbers);
19. ReorderBuffer cold expected-sequence snapshot semantics;
20. control is encoded as a normal TLSVPN frame with wire `seq=0`.

The research CI runs format, build, focused `FEC|Dynamic|ReorderExpected` tests, and the same set under the Go race detector.

## Remaining stages

- **P2d:** sustained 2→1→2 path-kill fault injection, including Real-TAP CPU profile and loss/reorder checks.
- **P2e:** optional Rust implementation for symmetric RX CPU savings; old Rust remains wire-compatible without it.
