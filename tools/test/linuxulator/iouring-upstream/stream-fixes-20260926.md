# Stream I/O and cancellation fixes — September 26, 2026

This follow-up fixes the libuv regular-file cancellation race and the private
kqueue lifetime problem that previously prevented enabling stream I/O. It also
fixes two count-related errors exposed by the upstream cancellation tests.
It does not establish complete liburing compatibility.

## Changes

- Single-request Linux cancellation distinguishes queued work from executing
  regular-file I/O. It reports `EALREADY` when execution cannot be cancelled,
  instead of reporting success followed by a successful transfer. Completed and
  partial transfers retain their real results. Native cancellation keeps its
  existing return-value convention.
- Pipes and eventfds accept stream offsets. Sockets accept zero or current-position
  offsets and reject positive positioned offsets with `ESPIPE`, matching Linux.
  Ordinary stream submissions and SQPOLL use per-operation nonblocking I/O and
  readiness retries without changing the descriptor's `O_NONBLOCK` setting.
  Forced-async operations retain workers and make progress without another
  `enter` call. Executing stream workers can be interrupted; asynchronous cancel
  reports the execution race, and single-request synchronous cancel waits for the worker.
- Registered-file readiness retries retain the selected file generation when
  a slot is replaced. The private kqueue retains its creator's descriptor-table
  storage until kqueue close. This retains the required lock/list, not the open
  descriptors, and avoids a ring/file reference cycle.
- Synchronous cancellation no longer mistakes a successful count of four for
  native `EINTR`. Count-based timeouts compare unsigned distances from their
  starting count, avoiding premature completion when a large target wraps.

## Qualification

The candidate is a clean GENERIC kernel and matching Linux/ZFS modules built
from committed base `bc76c4a8af17` plus these changes, in an isolated source
snapshot. Unrelated concurrent working-tree changes are excluded. The exact
kernel, module, source, and executable hashes are in the JSON record below.

The same final stream executable runs in disposable Linux 6.18.35 and candidate
VMs. It checks 18 combinations of pipe/socket/eventfd, raw/registered files, and
ordinary/forced-async/SQPOLL submission, plus three full-buffer write checks and
32 creator-exit iterations. Registered-slot replacement is tested after ordinary
or SQPOLL issue; forced-async file lookup can legitimately race a slot update.
SQPOLL submission counts can race kernel consumption, so completions establish
that every request was processed.

The broader candidate run repeats the six libuv 1.53.0 cases under both the
advertised Linux 5.15.0 identity and a VM-only 6.18.35 override, then runs the
SQPOLL cancellation race in 20 fresh processes. The previous candidate failed
12 of 20 repetitions. Successful cancellation must produce `UV_ECANCELED`;
completed reads must instead report `UV_EBUSY` from cancellation and return
valid data. Both outcomes occur in the fixed run.

The focused upstream set contains 16 unmodified liburing 2.12 binaries. Native
checks cover linked operations, fixed buffers, progress without another enter,
SIGPIPE behavior, readiness lifetime, and fork lifetime. These checks do not
replace the earlier 70-case qualification or its remaining failures.

| Final check | Result |
| --- | --- |
| Identical stream executable on Linux and candidate | Both pass all 18 modes, three backpressure checks, and 32 exit iterations |
| Libuv advertised identity | 6/6 pass |
| Libuv diagnostic identity | 6/6 pass |
| Diagnostic SQPOLL cancellation repetitions | 20/20 pass |
| Focused upstream liburing set | 15/16 pass; inherited-ring exit cancellation remains |
| Native regressions | 11/11 pass |
| Resource counters, ZFS, shutdown | All five counters zero at every sample; healthy pools; clean shutdown |

The final kernel SHA-256 is
`eeed7c2181fa44aa2d174f9935f2c51989519f38e496af07d642061df54a96f0`.
Individual results and executable hashes are recorded in
[the machine-readable results](stream-fixes-20260926.json).

## Remaining failure

`io-cancel` reaches `test_cancel_inflight_exit()` and still fails: a child submits
a linked poll of its inherited ring and exits while the parent retains the ring.
The poll returns readiness (`1`) instead of `ECANCELED`. This requires matching
Linux's task-exit cancellation ownership. The earlier across-fork cancellation
step no longer panics, but the whole `io-cancel` binary is still a failure;
subtests after the failing assertion are not qualified by this run.

No optional device backend is needed to address that remaining behavior.

## Evidence and reproduction

- [Build and run instructions](README.md#stream-and-cancellation-regression)
- [Commands, individual results, and hashes](stream-fixes-20260926.json)
- [Candidate console](evidence-20260926/stream-candidate.log.gz)
- [Linux stream comparison](evidence-20260926/stream-oracle.log.gz)
- [Original libuv mismatch](libuv-results-20260926.md)
- [Original teardown panic and reverted offset patch](fixes-20260926.md)

VM completion markers alone are not passes: individual exits, completion/data
checks, all five resource counters, kernel panic detection, ZFS health, and
clean shutdown are recorded separately. These are bounded correctness checks
under QEMU TCG, not hardware performance or long-duration endurance results.
