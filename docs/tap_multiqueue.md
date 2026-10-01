# Linux TAP multi-queue experiment

`tap_queues` selects 1..16 read queues, default 1. Values above 1 enable
water's existing `IFF_MULTI_QUEUE` support and open independent fds for the
same device name. `tap_multi_queue: true` enables the flag with one fd for the
experiment's flag-only control. Both fields require a process restart.

Each reader owns its buffer. Client frames enter the existing AsyncPort;
server frames enter the existing concurrent VSwitch. Sequence allocation,
epoch transitions and FEC stay serialized in AsyncPort. Per-queue order is
preserved; there is no promised total order between independent kernel queues.
Kernel flow steering determines queue assignment and a live queue count change
can change that assignment, so this experiment never resizes queues at runtime.

Delivery into TAP remains serialized through queue zero, including the existing
single-path FIFO delivery worker. Parallel receive writers are deliberately
deferred until read-side results justify another isolated experiment.

All owned fds are closed once. Partial creation failure closes all already
opened fds before fallback. Only EINVAL/EOPNOTSUPP permits single-queue fallback;
permission/resource errors remain failures. Shutdown closes the fds and joins
the readers before tearing down their consumers. The privileged kernel test
requires the requested queue count and cannot silently accept fallback.

The TAP multi-queue CI compares an immutable PR-base binary, candidate single
queue, flag-only single queue, two queues and four queues. It runs five
randomized paired rounds per 1/4/16 iperf streams and 1/4 physical connections,
with FEC enabled, 3 seconds warmup and 20 measured seconds in each direction.
PGO and build settings are identical. Raw iperf JSON, retransmits, TAP counters,
runner details and separate CPU profiles are uploaded. Missing TAP capabilities
are a hard failure, not a skip. CI success does not imply a throughput gain.

Merge requires repeatable >=5% multi-flow improvement, no material single-flow
regression, and passing correctness/race/protocol/mixed E2E checks. Linux
arm64/mipsle cross-builds and netifd checks cover OpenWrt build integration;
they do not prove support or throughput on a physical OpenWrt target. No kernel
version heuristic substitutes for an actual successful multi-queue open.

Adaptive network-quality FEC and dynamic K are separate protocol/policy work.
This experiment does not change negotiated K or the existing path-count bypass.
