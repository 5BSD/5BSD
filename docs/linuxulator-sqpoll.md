# SQPOLL implementation boundary and oracle

`IORING_SETUP_SQPOLL` now has a candidate implementation in shared squeue. The
poller is a kernel thread in the ring creator's process so `copyin()`, `fget()`,
and credential checks resolve against the submitter's process. The Linuxulator
initializes the poller's emulation-thread state; SQ/CQ publication, idle
transition, `NEED_WAKEUP`, wake, and teardown live in shared squeue.
`SQ_AFF` has a shared implementation and its named CPU-placement contracts passed the full amd64 ZFS-root VM gate. The broader option/lifecycle matrix remains separate work.

A direct kernel-process call to `sq_submit()` is unsafe with the current
backend. Preparation uses `copyin()` for timeout/iovec SQEs and `fget()` against
`curthread` for ordinary descriptor identity. Execution and front-end hooks
also use the submitting thread's credentials, file table, and vmspace. A
poller must preserve the ring creator's process/file and credential context
(or explicitly resolve those references in another safe context), and stop
before that context is torn down. The reference returns Linux `EOWNERDEAD`
when another process tries to wake an inherited SQPOLL ring after its creator
exits; the engine must report that state rather than silently leave the ring
idle. Ring close, registered-fd-only lifetime, process death, and a blocked
worker must join/drain the poller before ring backing is freed. Admission
alone would misreport support and risk wrong-file access or use-after-free.

The first pinned Linux 6.18.35 amd64 QEMU oracle binary is
`tests/sys/kern/linux_iouring_sqpoll.c`. Its first six cases passed in
`/tmp/linuxulator-gate-20260919/sqpoll-oracle11.console.log`:
`auto_submit` (after an explicit wake, no enter to submit a NOP),
`idle_wakeup` (observe `IORING_SQ_NEED_WAKEUP`, publish a NOP and wake),
`fd_context` (ordinary pipe READ and invalid-fd CQE),
`owner_exit_contract` (inherited ring returns `EOWNERDEAD` after creator
exit), `failed_exec_preserves_ring` (a failed exec leaves SQPOLL live), and
`invalid_setup` (`SQ_AFF` without SQPOLL). The reference contract is
[Linux 6.18 io_uring.c](https://github.com/torvalds/linux/blob/v6.18/io_uring/io_uring.c)
and [the UAPI header](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/io_uring.h).
An earlier owner-exit probe used thread-only `exit` and waited indefinitely;
`exit_group` is required to exercise process death. An intermediate reference
run observed Linux errno 130 (`EOWNERDEAD`) before the final assertion was
added.

The first oracle attempt showed that assuming the poller is awake immediately
after setup is unreliable even with a long idle interval. The passing case
wakes it and confirms `NEED_WAKEUP` cleared before testing syscall-free
submission. This is an observed reference result, not candidate qualification.

The remaining SQPOLL stress matrix includes:

- Repeated no-enter submissions, SQ wraparound, CQ overflow, linked SQEs,
  invalid SQEs, fixed and ordinary fds, and credentials/file-table isolation.
- Idle transition, lost-wakeup race with producer-tail publication, redundant
  wake calls, enter `SQ_WAIT`, signal interruption, and disabled ring behavior.
- `SQ_AFF` CPU hotplug and cpuset restriction transitions, plus interactions
  with `IOPOLL`, `ATTACH_WQ`, `NO_MMAP`, resize and registered-fd-only setup.
- Close, fork, exec, thread/process exit and ring-registry teardown while the
  poller is awake, asleep, or blocked, with no leaked threads, requests, pins,
  or wired pages.

For every admitted mode, require positive and negative Linux oracle cases,
native/Linux shared cases, three focused rounds, and the full amd64 ZFS-root
QEMU gate with WITNESS/INVARIANTS and zero diagnostics. Arm64 is reserved for
architecture-specific changes, per the current phase instruction.

The first candidate amd64 ZFS-root QEMU run exposed a RACCT_NTHR underflow
on process exit after an SQPOLL worker died. `kthread_add()` does not charge
RACCT_NTHR for a user process, while forced thread exit subtracts it. The
SQPOLL start/normal-exit paths now charge and release this resource explicitly.
The rebuilt candidate passed all six focused cases for three rounds in
`/tmp/linuxulator-gate-20260919/sqpoll-focus-run2.console.log`. The full
gate remains a separate requirement.

A seventh Linux oracle case, `sq_wait_space`, fills the SQ, then calls
`io_uring_enter()` with `SQ_WAKEUP|SQ_WAIT`. Linux 6.18.35 passed it in
`/tmp/linuxulator-gate-20260919/sqpoll-wait-oracle.console.log`; the
candidate passed all seven cases for three rounds on a 1 GiB amd64 ZFS-root
guest in `/tmp/linuxulator-gate-20260919/sqpoll-wait-focus.console.log`.

A shared native/Linux `sqpoll_shared` group submits sixteen NOPs across
ring wraparound, checks SQ head and CQ results, fills the SQ, exercises
`SQ_WAKEUP|SQ_WAIT`, verifies repeated wake, and rejects `SQ_AFF` without
SQPOLL. Linux 6.18.35 passed the expanded group in
`/tmp/linuxulator-gate-20260919/sqpoll-shared-wait-oracle.console.log`; the
candidate passed three rounds through each frontend in
`/tmp/linuxulator-gate-20260919/sqpoll-shared-wait-focus.console.log`. The same
candidate guest then passed twenty consecutive `linux_rseq_signal` reruns.
The first full gate failed once in the rseq signal case before reaching SQPOLL.
A later run exposed stale native and Linux regression assertions that expected
SQPOLL setup to fail; both now check the current contract. The existing
`links_close` test was also made deterministic under slow QEMU scheduling and
passed three rounds in each ABI, plus a Linux 6.18.35 oracle. Earlier
interrupted QEMU runs remain incomplete evidence. The first complete
`/tmp/linuxulator-gate-20260919/sqpoll-full9-gate/results.json` records an
amd64 ZFS-root PASS: 900 shared-option runs, 343 general io_uring
cases, 21 dedicated SQPOLL runs, all three standalone native squeue runs,
zero nonzero results or kernel diagnostics, zero final ring pages, healthy
ZFS pool, and clean shutdown. This qualifies only the named core contracts.

The expanded native/Linux SQ_WAIT case passed the Linux reference, focused
three-round candidate runs in both ABIs, and the full amd64 ZFS-root gate.
Extended process/option lifecycle combinations remain pending.

## SQ_AFF implementation and oracle

The shared squeue engine checks `SQ_AFF` only with `SQPOLL`, requires an online
CPU in the creator's cpuset, and pins the poller before setup reports success.
The reference is [Linux v6.18 sqpoll.c](https://github.com/torvalds/linux/blob/v6.18/io_uring/sqpoll.c).
The Linuxulator supplies the Linux setup layout and thread initialization; CPU
validation and placement live in shared squeue for native callers too. Failed
placement aborts setup and joins the poller before freeing the ring.

Linux 6.18.35 checks the caller's **cpuset** allowance, not the caller
thread's `sched_setaffinity` mask. The first Linux VM oracle run exposed this:
a ring pinned to another CPU in the same cpuset succeeds after the caller
narrows its own thread mask. The corrected `affinity_valid` and
`affinity_mask_contract` cases passed in
`/tmp/linuxulator-gate-20260919/sqaff-oracle2.console.log`.
The candidate passed 27 Linux SQPOLL cases and six shared native/Linux affinity cases
across three rounds in `/tmp/linuxulator-gate-20260919/sqaff-focus.console.log`.
A separate native test finds the poller in the process thread list and checks
its exact one-CPU affinity mask; three rounds passed in
`/tmp/linuxulator-gate-20260919/sqaff-pin.console.log`.
The complete `/tmp/linuxulator-gate-20260919/sqaff-cpuset-full-gate/results.json` records an amd64 ZFS-root PASS: 906 shared-option runs, 27 dedicated SQPOLL runs, 343 general io_uring cases, zero nonzero subtests or kernel diagnostics, final ring pages 0/0, healthy ZFS pool and clean shutdown. Artifact and source hashes are in the adjacent `manifest.json`. The first full attempt stopped at an accidentally changed query-case count in the guest script; it did not reach final cleanup and is not acceptance evidence. A child process with a private native cpuset also rejects an excluded CPU and succeeds on an included CPU; its poller has the exact one-CPU mask. Three focused VM rounds passed in `/tmp/linuxulator-gate-20260919/sqaff-cpuset-focus.console.log`, and all three native shared-option rounds passed in the full gate. The Linux 6.18.35 oracle guest lacks the cpuset controller, so Linux-side cpuset exclusion remains untested there. CPU hotplug, post-setup cpuset transitions and broader option/lifecycle combinations remain separate tests.

## Next setup-combination audit

[Linux v6.18 `io_uring_sanitise_params()`](https://github.com/torvalds/linux/blob/v6.18/io_uring/io_uring.c)
rejects `SQPOLL` combined with `COOP_TASKRUN`, `TASKRUN_FLAG`, or
`DEFER_TASKRUN`. The shared setup path now rejects those combinations before ring allocation.
The `taskrun_incompatible` Linux oracle and `sqpoll_taskrun_shared` native/Linux
cases each cover all four incompatible combinations repeatedly, then create
a valid SQPOLL ring to check recovery. The Linux 6.18.35 oracle and three focused candidate rounds passed.
`/tmp/linuxulator-gate-20260919/taskrun-full-gate/results.json` records a
complete amd64 ZFS-root PASS: 912 native/Linux shared-option runs, 30
dedicated SQPOLL runs, 343 general io_uring cases, no nonzero results or
kernel diagnostics, final ring pages 0/0, healthy ZFS pool and clean
shutdown. The new task-run group passed all three rounds in both frontends. Positive `SQPOLL` interactions with `NO_MMAP` and
`REGISTERED_FD_ONLY` need separate lifecycle tests.

## SQPOLL layout combinations

Linux 6.18.35 accepted `SQPOLL|SINGLE_ISSUER`, `SQPOLL|NO_MMAP`, and
`SQPOLL|NO_MMAP|REGISTERED_FD_ONLY` in
`/tmp/linuxulator-gate-20260919/sqpoll-positive-oracle.console.log`.
The dedicated Linux cases create eight `SINGLE_ISSUER` rings and check one
NOP completion and close on each, then submit eight NOPs through each
caller-owned layout with SQ wakeups. They advance the CQ head between
completions, reject ordinary entry on the registered-fd-only ring, reject
mmap on the caller-owned ring, unregister the slot, and verify that entry
through the removed slot returns `EBADF`. The dual-ABI
`sqpoll_layout_shared` group repeats completion and teardown through native
squeue and Linux io_uring. The diagnostic amd64 ZFS-root VM run passed all
five focused cases in `/tmp/linuxulator-gate-20260919/sqpoll-positive-debug.console.log`.
The first focused script's 30-second timeout expired on the eight-ring
`SINGLE_ISSUER` stress loop; the same case completed successfully in 37
seconds with a 120-second diagnostic bound. The full gate now allows 90
seconds per dedicated SQPOLL case. The complete
`/tmp/linuxulator-gate-20260919/sqpoll-positive-full-gate4/results.json`
records an amd64 ZFS-root PASS: 918 shared-option runs, 39 dedicated
`NO_MMAP` runs, 33 dedicated SQPOLL runs and 343 general io_uring cases,
zero nonzero subtests or kernel diagnostics, final ring pages 0/0,
issuer/file/request counts 0, healthy ZFS pool and clean shutdown. Each new
case passed all three rounds. The prior three complete-suite attempts ended
with QEMU signal 9 before final cleanup, without a failing guest assertion;
they are not acceptance evidence. This gate qualifies the named combinations,
not CPU hotplug or post-setup cpuset changes.

## ATTACH_WQ boundary

The shared squeue engine now accepts `ATTACH_WQ` on an ordinary ring after
validating `wq_fd` as another squeue descriptor. The global worker pool already
serves both native and Linux rings, so the ordinary worker path needs no new
backend. The focused amd64 ZFS-root VM test covers both ABIs on ZFS and tmpfs,
source-ring closure, worker-backed reads, and invalid/wrong-type descriptors.
All 12 focused runs passed in `/tmp/linuxulator-gate-20260919/attach-wq-focus3.console.log`.
The full amd64 gate passed with 394 io_uring cases, 930 shared-option runs,
39 NO_MMAP, 33 SQPOLL and 24 MEM_REGION runs, zero nonzero subtests or kernel
diagnostics, healthy ZFS, zero final ring/request/issuer counts and clean
shutdown. Exact artifact hashes are in
`/tmp/linuxulator-gate-20260919/attach-wq-full-gate2/manifest.json`.

`ATTACH_WQ|SQPOLL` now attaches a ring to the source ring's poller when
both rings use the same frontend in one process. The poller visits each live
ring once per pass and caps each ring at eight SQEs per visit. Each ring keeps
its own SQ/CQ, wake flag, completion waiters, and close path. Attached contexts
retain the poller owner through the last in-flight job, so closing the source
first does not strand an attached ring or free shared worker controls. A
forked process attaching an inherited source descriptor gets its own poller,
matching Linux's process boundary. A native/Linux cross-frontend attachment
returns `EINVAL`: the source poller cannot acquire the other frontend's
thread state after it has started.

SQPOLL attachments share `IOWQ_MAX_WORKERS` and `IOWQ_AFF` state through the
poller owner. Ordinary `ATTACH_WQ` rings still use the global native worker
pool with per-ring controls; Linux's ordinary task-local io-wq controls need a
separate cross-ring audit. The Linux 7.1.5 oracle demonstrated shared SQPOLL
worker-limit values and a successful forked-process attachment in
`/tmp/linuxulator-gate-20260919/linux715/oracle-sqpoll-attach7.console.log`.
Its SQPOLL worker-slot scheduling is not a strict proxy for a blocked pipe
read, so the permanent test checks limit propagation and I/O without imposing
an unobserved completion order.

## SQPOLL with ordinary descriptors

The process-context poller already resolves ordinary file descriptors through
the creator's file table. `IORING_FEAT_SQPOLL_NONFIXED` is now advertised by
shared squeue and Linuxulator. `sqpoll_nonfixed_shared` tests the feature bit
on ordinary and SQPOLL rings, a pipe read through an ordinary descriptor,
and an `EBADF` CQE for a closed descriptor in both frontends. Twelve focused
ZFS-root amd64 VM executions passed on ZFS and tmpfs in
`/tmp/linuxulator-gate-20260919/sqpoll-nonfixed-focus.console.log`; the
same test passed on the Linux 7.1.5 oracle in
`/tmp/linuxulator-gate-20260919/linux715/oracle-sqpoll-nonfixed.console.log`.
The full amd64 gate passed with 394 io_uring cases, 936 shared-option runs,
39 NO_MMAP, 33 SQPOLL and 24 MEM_REGION runs, zero nonzero subtests or kernel
diagnostics, healthy ZFS, zero final ring/request/issuer counts and clean
shutdown. Exact hashes are in
`/tmp/linuxulator-gate-20260919/sqpoll-nonfixed-full-gate/manifest.json`.

### SQPOLL attachment coverage and remaining gate

The permanent shared tests in `squeue_options.c` cover simultaneous source
and attached NOPs, pipe READ and closed-fd `-EBADF`, nested attachment after
source close, both close orders, idle `NEED_WAKEUP`, `SQ_WAIT`, invalid/stale
and wrong-type `wq_fd`, a non-SQPOLL source, forked attachment, failed exec,
owner exit, shared worker-limit registration and malformed limits, pending
WAITID close/cancellation, and native/Linux cross-frontend rejection. The Linux 7.1.5 reference VM passed
the nine Linux-relevant cases in
`/tmp/linuxulator-gate-20260919/linux715/oracle-sqpoll-attach8.console.log`.
The candidate passed 84 repeated native/Linux ZFS/tmpfs attachment executions
in `/tmp/linuxulator-gate-20260919/sqpoll-attach-focus3.console.log`, 12
worker-control executions in `sqpoll-attach-worker-focus.console.log`, and
12 cross-frontend negative executions in
`sqpoll-crossabi-focus.console.log`, all with clean shutdown and no kernel
diagnostics. The 24 dedicated/shared empty-wakeup checks passed in
`sqpoll-wake-focus.console.log`. A full-gate teardown check then found that
`waitid_close_pending` left one live request: the new poller skipped its final
extension poll on stop. Restoring that pass and draining canceled extension
waits before an attached ring leaves its group returned `live_requests` to
zero in 40 repeated attached/ordinary WAITID close executions on ZFS and
tmpfs (`sqpoll-waitid-attach-focus2.console.log`). The complete amd64
ZFS-root gate then passed at
`/tmp/linuxulator-gate-20260919/sqpoll-attach-repaired-full-gate3/results.json`:
1002 native/Linux shared-option runs, 395 general io_uring cases, 39 NO_MMAP,
33 dedicated SQPOLL, and 24 MEM_REGION runs; no failing cases or recognized
kernel diagnostics, zero final request/file/issuer counts, healthy ZFS, and
clean shutdown. Its `manifest.json` pins the exact image, kernel, module,
test binaries, source, oracle, and focused-run hashes.

The group idle-time interval now tracks the maximum requested by its live
members and is recalculated when an attached ring joins or either ring closes,
matching [Linux sqpoll.c](https://github.com/torvalds/linux/blob/master/io_uring/sqpoll.c).
The `sqpoll_attach_group_idle_shared` case first checks that a rejected attach
does not change the source interval. It then checks that a longer attached
interval prevents early sleep, removing that ring restores the short interval,
and closing the source leaves the attached ring's short interval in force.
Each transition also wakes and completes a NOP. Linux 7.1.5 passed the case
in `/tmp/linuxulator-gate-20260919/linux715/oracle-sqpoll-idle.console.log`.
The first candidate focus run caught a stale `NEED_WAKEUP` flag after attach;
the poller now clears member flags when it observes an idle-interval change.
The repaired focus VM passed all 12 native/Linux ZFS/tmpfs runs, with zero
resources, healthy ZFS and clean shutdown, in
`/tmp/linuxulator-gate-20260919/sqpoll-idle-focus2.console.log`. The complete amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-idle-final-full-gate/results.json`:
1008 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; zero failures, diagnostics and final
request/file/issuer counts; healthy ZFS and clean shutdown. Its
`manifest.json` pins the artifacts and source used for this gate.

The `sqpoll_attach_nommap_shared` case combines a shared poller with
caller-owned ring/SQE memory, including `REGISTERED_FD_ONLY`. It rejects an
invalid source using a separate memory region, closes the valid source first,
reaps eight NOPs on the attached ring, rejects ordinary entry on the
registered-only slot, removes that slot and checks stale entry. The Linux
7.1.5 oracle passed this case alongside the existing SQPOLL layout case in
`/tmp/linuxulator-gate-20260919/linux715/oracle-sqpoll-nommap-attach6.console.log`.
The candidate passed all 12 native/Linux ZFS/tmpfs focused runs with zero
tracked resources and clean shutdown in
`/tmp/linuxulator-gate-20260919/sqpoll-nommap-attach-focus.console.log`.
The complete amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-nommap-attach-full-gate/results.json`:
1014 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; zero failed cases, diagnostics and final
request/file/issuer counts; healthy ZFS and clean shutdown. Its
`manifest.json` pins exact source, binary, oracle and VM artifact hashes.

The shared poller's `IOWQ_AFF` registration is now directly tested across
source and attached rings. The `sqpoll_attach_worker_affinity_shared` case
rejects malformed registration/unregistration, pins actual blocked native
workers to CPU 1, completes reads submitted through both rings, closes the
source and checks another attached read, then restores the affinity. Linux
7.1.5 passed the Linux-relevant registration and I/O path in
`/tmp/linuxulator-gate-20260919/linux715/oracle-sqpoll-affinity4.console.log`.
The candidate passed all 12 native/Linux ZFS/tmpfs focused runs with zero
resources and clean shutdown in
`/tmp/linuxulator-gate-20260919/sqpoll-affinity-focus2.console.log`.
The complete amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-affinity-final-full-gate/results.json`:
1020 native/Linux shared-option, 395 general io_uring, 39 NO_MMAP,
33 dedicated SQPOLL and 24 MEM_REGION executions; zero failed cases or
recognized kernel diagnostics, zero final request/file/issuer counts, healthy
ZFS and clean shutdown. The adjacent `manifest.json` pins the exact source,
test binaries, Linux oracle, focused run and VM artifacts.

The `sqpoll_attach_cq_overflow_shared` case fills each member's CQ in turn,
checks that the other member still completes NOPs, drains every backlogged CQE
exactly once, and closes a third attached ring with overflow pending. The
shared backend now follows Linux's CQ accounting: `IORING_SQ_CQ_OVERFLOW`
marks queued completions, while `cq_overflow` counts only completions that
were actually dropped. Linux 7.1.5 passed the attachment case and the three
updated general CQ-overflow cases. The candidate passed 30 focused native/
Linux ZFS/tmpfs executions with zero tracked resources and healthy ZFS. The
complete amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-overflow-full-gate/results.json`:
1026 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; zero failed cases or recognized kernel
diagnostics, zero final request/file/issuer counts, healthy ZFS and clean
shutdown. The adjacent `manifest.json` pins the exact source, candidate
artifacts and oracle/focused-run logs.

The attached-poller blocked-read and close-race gate now passes. SQPOLL
READ/WRITE/READV/WRITEV transfers, including fixed-buffer forms, use the
shared worker pool when they could block the poller. The poller also publishes
worker-ready CQEs on an empty SQ pass, so a caller watching mapped CQ memory
needs no extra submission or `io_uring_enter`. The permanent
`sqpoll_attach_blocked_read_progress_shared` case holds a source-ring pipe
READ, completes an attached-ring NOP, then supplies the byte and reaps the
READ. `sqpoll_attach_concurrent_close_shared` closes source and attached
rings simultaneously with pending polls, both with and without explicit
cancellation, rejects stale entry, and checks a fresh SQPOLL ring. The
standalone `fd_context` case catches a worker completion that remains ready
without reaching the CQ. Linux 7.1.5 passed the attachment oracle; 24 focused
native/Linux ZFS/tmpfs runs passed. An initial complete candidate gate found
`fd_context` failing three times, which led to the empty-SQ ready-drain fix.
The repaired amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-close-repair-full-gate/results.json`:
1038 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; no failures or recognized kernel diagnostics,
zero final request/file/issuer counts, healthy ZFS and clean shutdown. Its
`manifest.json` pins the corrected kernel, module, tests, source, oracle and
focused-run hashes.

Selected-buffer SQPOLL READ and READV now take their buffer before worker
submission and consume or recycle it on worker completion without holding the
ring mutex recursively. The same shared path supports explicit `IOSQE_ASYNC`
selected-buffer READ. `sqpoll_attach_pbuf_read_shared` checks empty-group
`ENOBUFS`, source-ring blocked READ with attached-ring NOP progress, exact
buffer IDs and data, registered-ring head movement, and bad-fd recycling
followed by READV reuse. `async_pbuf_worker_shared` checks NOP progress while
a selected-buffer read is blocked, successful completion, bad-fd recycling
and subsequent reuse. Both cases passed Linux 7.1.5 and 24 focused native/
Linux ZFS/tmpfs candidate runs. The first focused candidate exposed a nested
ring-mutex acquisition in buffer completion; the corrected candidate passed
all focused runs with zero tracked resources and healthy ZFS. The first full
run executed all cases successfully but the verifier lacked the two new names
in its expected inventory; after correcting that inventory and strengthening
the async negative, the complete amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-pbuf-final-full-gate/results.json`:
1050 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; zero failures or recognized diagnostics, zero
final request/file/issuer counts, healthy ZFS and clean shutdown. Its
`manifest.json` pins source, kernel, module, test binaries, oracle and focused
VM logs.

Incremental provided-buffer progress and cancellation during a selected-buffer
SQPOLL transfer now have separate native/Linux contracts. The
`sqpoll_pbuf_incremental_shared` case checks attached-ring progress while a
selected read is blocked, `BUF_MORE` and unchanged ring head after a partial
read, descriptor address/length advancement, final buffer consumption, and
`ENOBUFS` after exhaustion. The `sqpoll_pbuf_cancel_shared` case cancels a
blocked selected-buffer read by user data, requires `-ECANCELED` without a
buffer flag and an unadvanced head, then reuses the same buffer in a successful
read. Both passed the Linux 7.1.5 reference and 48 focused native/Linux
ZFS/tmpfs candidate executions. An initial focused candidate exposed stale
buffer flags and late recycling after cancellation; the shared worker path
now recycles a failed selected buffer before publishing its CQE. The complete
amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-pbuf-lifecycle-full-gate/results.json`:
1062 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; zero failures or recognized diagnostics, zero
final request/file/issuer counts, healthy ZFS and clean shutdown. The adjacent
`manifest.json` pins the candidate artifacts and reference logs. Other SQPOLL
combinations retain their own coverage requirements.

A separate `sqpoll_pbuf_incremental_cancel_shared` case now qualifies
cancellation after partial incremental-buffer progress. It consumes two bytes
from a four-byte descriptor with `BUF_MORE`, cancels a subsequent blocked read
and requires `-ECANCELED` without a buffer flag, then reads the remaining two
bytes with the original buffer ID and advances the head exactly once. It also
requires `ENOBUFS` after exhaustion. Linux 7.1.5 passed the oracle; the
candidate passed 12 focused native/Linux ZFS/tmpfs executions, `fd_context`,
zero tracked resources and healthy ZFS. The complete amd64 ZFS-root gate passed
at `/tmp/linuxulator-gate-20260919/sqpoll-pbuf-inc-cancel-full-gate/results.json`:
1068 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions, with no failures or recognized diagnostics,
zero final request/file/issuer counts, healthy ZFS and clean shutdown. The
adjacent `manifest.json` pins the exact kernel, module, binaries, source,
oracle, focused log and guest image. No new backend change was needed for this
combination.
