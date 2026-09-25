# squeue / io_uring: implementation design

> **Naming.** The native 5BSD interface is **`squeue`** ("shared queue"): the
> syscalls `squeue_setup`/`squeue_enter`/`squeue_register`, the engine
> `sys/kern/sys_squeue.c`, and the KPI `kern_squeue_*` in `sys/sys/squeue.h`.
> The Linux **`io_uring`** front-end keeps its name and drives the same engine,
> exactly as `kqueue` relates to Linux `epoll`.  This document uses "io_uring"
> when discussing the shared wire ABI and "squeue" for the native interface.

## Registered-file lifetime update (2026-09-17)

The shared engine rejects ring descriptors in registered-file tables, including
updates, to avoid reference cycles. A dedicated sleepable file-table lock
serializes initial registration, unregister and both update entry paths. Fixed
lookup holds its shared side while acquiring the file and copying captured
Capsicum rights, including allocating ioctl whitelists; no ring mutex is held.
A fixed operation then owns its independent file reference across replacement.

Initial registration rolls back completely. Updates import and commit one
entry at a time: SKIP preserves, -1 removes, and later errors return the completed
prefix. Descriptor lookup failure clears the failed slot; input-copy failure
leaves it unchanged. FILES_UPDATE preparation validates prohibited flags and
fields before chain effects, including SUBMIT_ALL stop/continue behavior.

Old-kernel VM reproductions exposed both sleeping-allocation warnings and an
update/unregister kernel panic. The mandatory gate now rejects those warnings
and requires zero registered-file references after options and at final cleanup.
See [the implementation gate](linuxulator-implementation-gate.md) for exact
contracts, qualification and remaining resource-registration boundaries.

## Setup and restriction update (2026-09-17)

Shared squeue accepts SUBMIT_ALL, SINGLE_ISSUER and R_DISABLED. Disabled rings
allow resource registration; RESTRICTIONS installs a transactional policy and
ENABLE_RINGS activates it permanently. An sx lock serializes registration and
activation, and publication under the context mutex orders later enter calls.
The policy checks SQE opcodes and required/allowed flags before chain effects.
A failed preparation poisons the collected chain; a terminal preparation
failure stops the default batch while SUBMIT_ALL continues. Execution errors
continue either mode. Invalid SQ-array indices drop without a submitted count.

SINGLE_ISSUER uses a reference-counted thread OSD token, binding at setup or
at enable for disabled rings. Ring ownership survives exec and owner death
without assigning a reused tid or thread pointer. Other tasks may wait without
submitting, but cannot submit or register after ownership is established.
The shared invalid-state sentinel becomes native EBADF or Linux EBADFD in the
respective syscall wrapper. Mechanisms and policy remain native BSD code.

The new gate checks identity references and tokens as well as request and page
cleanup. See [the implementation gate](linuxulator-implementation-gate.md) for
qualification and the remaining per-opcode preparation/error-precedence audit.

## Linked deadlines and cancellation update (2026-09-17)

The shared squeue engine prepares linked timestamps before chain side effects,
arms a deadline when its predecessor starts, and cancels that predecessor by
request identity. Ordinary completion disarms the timer. User-data cancellation
supports ALL counts; POLL_REMOVE is restricted to POLL_ADD, and timeout removal
does not find linked deadlines by their own keys. Active I/O retains its file,
VM and buffer ownership until execution ends; queued cancellation does not wait
behind unrelated blocked workers.

Private readiness uses shared descriptor/filter knotes and an EVFILT_USER wake
note. A coalesced task triggers the user event outside the ring mutex; teardown
stops publication and drains that task before dropping the kqueue. This avoids
a ring-file reference cycle on process exit. Registration and request publication
are serialized with event matching, and surviving same-fd subscriptions do not
depend on the identity of a canceled request.

See [the implementation gate](linuxulator-implementation-gate.md) for exact
qualification results. FD/ANY/opcode cancellation matching, synchronous
cancellation, and timeout updates are implemented and included in the mandatory
matrix. Absolute realtime clocks are converted to a monotonic delay when armed;
clock adjustments after arming and suspend/resume are not qualified. Historical
status and design targets below must not be read as current certification.

## Completion-wait update (2026-09-15)

`io_uring_enter` now passes its wait arguments to the shared squeue engine.
With GETEVENTS, the legacy argument is an optional signal mask; EXT_ARG accepts
`io_uring_getevents_arg`, an optional signal mask and a 64-bit timeout. Relative
and ABS_TIMER/CLOCK_MONOTONIC deadlines use one deadline across all wakeups,
including both the condition sleep and kqueue readiness paths. Setup advertises
IORING_FEAT_EXT_ARG. Native squeue callers supply a native sigset_t; Linux
callers use Linux signal numbering and the Linux sigset size, translated by a
callback supplied by the syscall front end (not by the ring's originating ABI).

A timeout returns Linux ETIME (native ETIMEDOUT), does not cancel outstanding
operations, and creates no CQE. A partial CQ batch suppresses a wait error;
a positive submission count also takes precedence over a subsequent wait error.
The signal-mask restoration follows native pselect's AST mechanism: an
interrupting signal is delivered before restoring the caller's original mask,
including for SA_RESTART handlers (the wait returns EINTR). Expired waits first
drain queued poll readiness once without sleeping, and check pending signals
before returning a timeout. This also applies to zero-length waits. The original
`kern_squeue_enter` calling convention is retained; the Linux front end uses
`kern_squeue_enter_sigmask` to supply its translator.

Wait arguments are inspected only with GETEVENTS, after submission; a ready CQ
does not require copying/installing a signal mask. EXT_ARG size and pointers
are still validated. `min_complete` is bounded by CQ capacity. The newer
`min_wait_usec` wait option is implemented in shared squeue for both ordinary
and registered arguments, and FEAT_MIN_TIMEOUT is advertised. See the
[minimum-wait contract](linuxulator-min-wait.md). Registered wait arguments
and registered-ring enter are qualified;
The SQPOLL core and named shared-poller attachment, affinity, overflow,
blocked-read and close-race contracts passed their
[amd64 ZFS-root VM gates](linuxulator-sqpoll.md); additional combinations
remain pending.
Later matrices in this document describe design targets, not an implementation
guarantee. The native helper library exists in `lib/libsqueue`.

Validation: see the 2026-09-15 entry in `linuxulator-option-review.md`.

## Implementation status (2026-09-13, on `origin/dev`)

Complete and VM-validated (245 subtests, every build):
- **Relocated to `sys/kern/sys_squeue.c`** as an ABI-neutral engine with native
  `squeue_*` syscalls (636/637/638); the Linux `io_uring` front-end
  (`sys/compat/linux/linux_io_uring.c`) is a thin wrapper over the same
  `kern_squeue_*` KPI. All 65 local opcodes now have a dispatch path;
  URING_CMD and URING_CMD128 have Linuxulator socket subsets, and RECV_ZC
  advertises the Linux v7.1 copied NODEV subset.
- **Registered wait clocks** — shared squeue stores the selected absolute-enter
  wait clock and converts deadlines to the callout domain at wait admission.
  The Linux frontend translates Linux `CLOCK_MONOTONIC`/`CLOCK_BOOTTIME`; native
  squeue accepts the corresponding native clock IDs.
- **Async worker pool** — `IOSQE_ASYNC` file I/O runs on a bounded, global
  pool of kprocs that borrow the owner's vmspace (aio(4) pattern), off the
  submitter. `kern.squeue.max_workers` is a boot tunable and runtime sysctl
  (default 8, valid range 1-256). Lowering it limits future growth and does not
  terminate existing workers. `kern.squeue.workers` and
  `kern.squeue.idle_workers` expose the live and idle counts read-only. Each
  ring also has independent bounded/unbounded admission limits and an optional
  worker CPU mask, configured by the Linux-compatible IOWQ register commands.
  Per-ring limits schedule work within the system-wide ceiling.
- **kqueue-native readiness** — POLL_ADD and fast-poll retries are driven by a
  per-ring in-kernel kqueue; the ring is also a first-class kqueue **source**
  (`EVFILT_READ`) and can signal a registered **eventfd** (REGISTER_EVENTFD).
  Multishot POLL (`IORING_POLL_ADD_MULTI`) is supported. The former
  registration was keyed by the submitting process's descriptor number and
  `knote_fdclose()` removed it on close. A focused `POLL_ADD` close/reuse
  oracle passed on Linux 6.18.35 at
  `/tmp/linuxulator-gate-20260919/iouring-poll-lifetime-oracle.console.log`:
  after closing and reusing the target fd, readiness of the new file did not
  complete the poll, while readiness of the original held file did. The
  regression is now in `tests/sys/kern/linux_iouring.c` and is part of the
  mandatory io_uring case list.
  It passed the Linux oracle from current source at
  `/tmp/linuxulator-gate-20260919/iouring-poll-lifetime-source-oracle.console.log`.
  The same branded binary timed out (exit 124 after 25 seconds) in a
  disposable amd64 ZFS-root FreeBSD guest at
  `/tmp/linuxulator-gate-20260919/iouring-poll-lifetime-bsd-diag/amd64.console.log`,
  with a clean guest shutdown. A second negative test confirms that
  `POLL_REMOVE` cancels the original request after its fd is reused; it passed
  Linux 6.18.35 at
  `/tmp/linuxulator-gate-20260919/iouring-poll-cancel-source-oracle.console.log`.
  A direct `kern_poll_fps()` scan serves one-shot legacy AIO, but it cannot
  preserve io_uring multishot edge behavior: repeated level scans of a readable
  target would flood the CQ. Shared kqueue now registers each `POLL_ADD` knote
  against the held `struct file`, hashes it by a per-ring request identity and
  keeps it out of `knote_fdclose()`'s descriptor list. Kqueue owns a separate
  file reference through deletion or teardown; squeue matches completions and
  poll updates by request identity. Ring-file poll targets remain on the
  descriptor-keyed path: a strong reference from a request to its own ring
  would create a close-time cycle. Linux accepts self-ring poll and removal;
  the new oracle and amd64 ZFS-root guest both passed self-ring close/cancel,
  and `kern.squeue.live_requests` stayed at zero. Ordinary-descriptor fast-poll
  requests now capture the target file and its capability rights before the
  submitter returns. Readiness is armed against that held file under a private
  request identity, and retry temporarily installs the same file with the
  captured rights. Closing or reusing the original descriptor therefore cannot
  strand or retarget the request. Fixed-file retries use the registered-file
  generation already resolved by shared squeue and do not repeat ambient-file
  resolution in the Linux front end. Ring-target requests retain their separate
  cycle-safe path. No native syscall number was added.
- **Capsicum-integrated** — the syscalls are `CAPENABLED`; every op honours the
  target descriptor's `cap_rights` (captured at register time for fixed files);
  a ring created in capability mode may operate only on registered files.
- **PIPE direct output** — the Linux frontend validates Linux pipe flags and
  creates the two endpoints; shared squeue installs them into consecutive
  registered-file slots, performs range allocation, retains capabilities and
  applies Linux's sequential failure cleanup. Ordinary descriptor output remains
  available when no direct-file index is requested.
- **MSG_RING ownership** — shared squeue owns target-ring CQ publication,
  fixed-file reference/capability transfer, allocation, replacement and rollback.
  It drops the source table lock before taking the target lock, so reciprocal
  transfers cannot deadlock, and the source registration remains intact. Ring
  descriptors cannot be registered, preventing transfer-created ring cycles.
  The Linux front end retains Linux errno-domain translation.
- **NODROP** — a full CQ backlogs completions and flushes them in order as the
  application drains, rather than dropping them.
- **Hardened** — bounded overflow backlog, provided-buffer count, and wired ring
  memory (`RLIMIT_MEMLOCK` + `kern.squeue.max_wired_pages`); passed an
  adversarial security audit (capsicum-rights capture, close-vs-timeout UAF,
  FILES_UPDATE overflow, fast-poll fixed-file all fixed).

**SQPOLL** now has a candidate in-process poller in shared squeue. Its
process-context, lifecycle and wake behavior require the dedicated VM gate;
see [the current SQPOLL audit](linuxulator-sqpoll.md).

## 0. Architecture: native core + Linux front-end (decided)

squeue is a **first-class 5BSD kernel subsystem**, not a Linux-only shim.  The
engine, rings, registration tables and opcode dispatch live in the native file
**`sys/kern/sys_squeue.c`** with a public KPI in `sys/sys/squeue.h` (the wire
structures are in `sys/sys/io_uring.h`).  It is reached two ways over the *same*
core:
- **Native syscalls** `squeue_setup`/`squeue_enter`/`squeue_register` in
  `sys/kern/syscalls.master` (a librqueue/liburing-style native consumer).
- **Linux front-end** in `sys/compat/linux/linux_io_uring.c`: the three
  `linux_io_uring_*` calls are thin ABI wrappers (copyin the Linux structs,
  translate opcode/flag/errno where they differ, call the native core via the
  `struct sq_frontend` hook that carries the errno translator and the
  Linux-flavoured opcode extension).
The wire ABI (SQE/CQE/params/ring layout, opcode numbers, ring offsets) is
Linux's - adopting it verbatim means one engine serves both front-ends and
all existing liburing tooling works.  The core dispatches onto ABI-neutral
`kern_*` primitives, so nothing in it is Linux-specific.

Goal: a *real* io_uring (not a minimal stub) - the complete submit/complete
engine with shared rings, the full SQE/CQE/setup/enter/register flag surface,
registered files & buffers, provided-buffer rings, linked/drained/async
ordering, poll/timeout/cancel, and the common opcode set - dispatched onto the
`kern_*` primitives the Linuxulator already uses.  Exotic modes with no
FreeBSD primitive (zero-copy TX, URING_CMD passthrough, IOPOLL busy-poll,
NAPI) are implemented where possible and otherwise report a defined error;
they are feature-gated so probing apps see the truth.

## 1. Building blocks in our tree
- `fo_mmap` fileops hook (sys/file.h): a custom fd type can expose mmap'd
  memory.  `kern/uipc_shm.c:shm_mmap` is the model - a swap-backed VM object
  (`vm_pager_allocate(OBJT_SWAP...)`) referenced and mapped via
  `vm_mmap_object`.  The rings live in one such wired object.
- POSIX aio engine (kern/vfs_aio.c): per-process taskqueue kicks
  (`taskqueue_aiod_kick`, `aio_kick_helper`), `aio_process_rw` running
  `fo_read`/`fo_write` on worker threads, the `bio` fast path, and
  `aio_complete()`.  io_uring reuses this pattern with its own taskqueue.
- Existing Linuxulator `kern_*` call sites: kern_readv/writev/preadv/pwritev,
  kern_fsync, kern_fspacectl (fallocate), kern_openat2 helpers, kern_statat,
  kern_accept4, kern_connectat, kern_sendit/kern_recvit, kern_close,
  kern_renameat/unlinkat/mkdirat/symlinkat/linkat, kern_posix_fadvise,
  kern_shutdown, linux_splice/linux_tee, kern_kevent (poll), the futex code,
  linux_statx, xattr helpers.  Each opcode dispatches to one of these.
- New file type `DTYPE_LINUXIORING` (sys/file.h), SYSINIT at SI_SUB_TASKQ
  (same as pidfd/signalfd).

## 2. Ring memory layout (mmap'd, IORING_OFF_*)
One wired swap VM object per ring holds three regions the app mmaps at fixed
offsets returned in io_uring_params:
- IORING_OFF_SQ_RING (0): struct io_rings head - SQ head/tail/mask/entries/
  flags/dropped + the SQ `array` (indices into the SQE table).
- IORING_OFF_CQ_RING (0x8000000): CQ head/tail/mask/entries/overflow/flags +
  the CQE array.  With IORING_FEAT_SINGLE_MMAP the SQ and CQ rings share one
  mapping (we set the feature and lay both in the same object).
- IORING_OFF_SQES (0x10000000): the io_uring_sqe[] table (64B, or 128B with
  IORING_SETUP_SQE128).
- IORING_OFF_PBUF_RING | (bgid<<16): per-group provided-buffer rings.
`fo_mmap` maps the object sub-range selected by the masked offset.  The
kernel keeps its own pointers to head/tail/array/cqes within the wired object
(always resident, no copyin/out on the hot path).

## 3. io_uring_setup(entries, params)
- Validate `params.flags` against the supported IORING_SETUP_* set; reject
  unknown bits (EINVAL).  Honor CQSIZE (app cq size), CLAMP, SQE128, CQE32,
  NO_SQARRAY, R_DISABLED, SUBMIT_ALL, COOP_TASKRUN/TASKRUN_FLAG,
  SINGLE_ISSUER, DEFER_TASKRUN.  SQPOLL starts a kernel submission
  thread; SQ_AFF has a shared affinity implementation with named VM-qualified contracts, while IOPOLL
  remains rejected pending its actual polling contract.  NO_MMAP and REGISTERED_FD_ONLY use
  caller-owned pinned ring backing and the per-thread ring registry;
  ATTACH_WQ validates and accepts a source ring without SQPOLL. Every
  attachment shares the source chain's canonical IOWQ limits and affinity,
  retains that owner across source and intermediate-ring close, and keeps
  independent SQ/CQ state. With SQPOLL, same-frontend rings in one process
  also share the poller. Forked-process SQPOLL attachment starts another
  poller while retaining the shared worker controls, and mixed native/Linux
  SQPOLL attachment is rejected.
- sq_entries = roundup_pow2(entries) (cap IORING_MAX_ENTRIES 32768);
  cq_entries = CQSIZE ? roundup_pow2(params.cq_entries) : 2*sq_entries.
- Allocate the wired ring object; fill sq_off/cq_off with the field offsets;
  set features = SINGLE_MMAP|NODROP|SUBMIT_STABLE|RW_CUR_POS|CUR_PERSONALITY|
  FAST_POLL|POLL_32BITS|EXT_ARG|CQE_SKIP|LINKED_FILE|RSRC_TAGS (those we
  honor).  falloc() the fd (DTYPE_LINUXIORING), return it.

## 4. io_uring_enter(fd, to_submit, min_complete, flags, arg, argsz)
Submit phase: read shared SQ tail; for i in [SQ head, tail): index via the
`array` (or direct with NO_SQARRAY), fetch the SQE from the wired table,
build a `struct linux_iou_job`.  Apply SQE flags:
- IOSQE_FIXED_FILE: resolve fd from the registered-file table, not the fdtable.
- IOSQE_BUFFER_SELECT: pull a buffer from the SQE's buf_group provided ring.
- IOSQE_IO_DRAIN: defer until all prior jobs complete.
- IOSQE_IO_LINK/IO_HARDLINK: chain; the next SQE starts only when this one
  completes (HARDLINK ignores failure, LINK breaks the chain on error).
- IOSQE_ASYNC: force the taskqueue path even for a cheap op.
- IOSQE_CQE_SKIP_SUCCESS: suppress the CQE on success.
Dispatch: cheap/non-blocking ops (NOP, POLL_ADD arm, TIMEOUT arm, FILES_UPDATE)
run inline; blocking ops go to the io_uring taskqueue worker pool.  Update SQ
head, count submitted.
Complete/wait phase: if IORING_ENTER_GETEVENTS, wait until the CQ has
min_complete entries or the (EXT_ARG) timeout expires, via a per-ring
sleepqueue the completion path wakes.  Return the number submitted.

## 5. Execution engine + opcode dispatch
A dispatch table indexed by opcode.  Worker executes, then `sq_complete(job,
res, cflags)` writes a CQE (user_data, res, flags) into the CQ ring at tail,
handles overflow (NODROP: a kernel overflow list flushed as space frees, set
IORING_SQ_CQ_OVERFLOW), increments the CQ `overflow` field only if a CQE is
actually dropped, wakes waiters and any registered eventfd, and, for a
completed link head, submits the next link.

Opcode -> kern_* mapping (65 concrete opcodes; "impl" = maps to an existing primitive,
"gap" = no FreeBSD primitive, returns -EOPNOTSUPP and is advertised via the
REGISTER_PROBE not-supported bit):
- impl: NOP, READV, WRITEV, READ, WRITE, READ_FIXED, WRITE_FIXED (registered
  bufs), FSYNC, SYNC_FILE_RANGE, FALLOCATE, FADVISE, MADVISE, STATX, CLOSE,
  OPENAT, OPENAT2, RENAMEAT, UNLINKAT, MKDIRAT, SYMLINKAT, LINKAT, FTRUNCATE,
  SPLICE, TEE, SHUTDOWN, ACCEPT, CONNECT, SEND, RECV, SENDMSG, RECVMSG,
  SOCKET, BIND, LISTEN, POLL_ADD, POLL_REMOVE, TIMEOUT, TIMEOUT_REMOVE,
  LINK_TIMEOUT, ASYNC_CANCEL, FILES_UPDATE, EPOLL_CTL, PROVIDE_BUFFERS,
  REMOVE_BUFFERS, FSETXATTR/SETXATTR/FGETXATTR/GETXATTR, WAITID, FUTEX_WAIT/
  WAKE/WAITV, FIXED_FD_INSTALL, MSG_RING (same-proc), EPOLL_WAIT.
- copied receive: RECV_ZC with Linux v7.1 ZCRX NODEV registration is implemented
  through the shared registered-area/refill backend described in
  [the ZCRX phase contract](linuxulator-iouring-zcrx.md). Hardware zero-copy
  still needs a native network-queue backend. URING_CMD and URING_CMD128 have
  Linuxulator socket subsets; unsupported target-file commands return
  EOPNOTSUPP. IOPOLL is rejected until a real polled-I/O backend exists.

## 6. io_uring_register(fd, op, arg, nr) (38 ordinary ops plus the registered-ring mode bit)
- REGISTER/UNREGISTER_BUFFERS: shared squeue holds writable pages and their
  backing objects, with bounded kernel aliases for flat and vectored fixed I/O.
  Requests retain immutable table generations across unregister; shared VM
  support preserves storage across munmap/remap and private fork. BUFFERS2 and
  BUFFERS_UPDATE provide sparse tables, tagged immutable generations and
  prefix-counted replacement while in-flight requests keep the old pinned
  generation alive. CLONE_BUFFERS creates untagged resource generations over a
  shared pin/accounting backing, supports slices and destination replacement,
  and serializes source/destination registration transactions.
- REGISTER/UNREGISTER_RING_FDS: a 16-entry task-local table holds ring files.
  ENTER_REGISTERED_RING, REGISTER_USE_REGISTERED_RING and clone-source indexes
  resolve through it; task exit defers potentially sleeping file closes outside
  the OSD lock.
  Qualification and limits are recorded in
  [the implementation gate](linuxulator-implementation-gate.md).
- REGISTER/UNREGISTER_FILES (+ _UPDATE, _tags): a table of held file refs for
  IOSQE_FIXED_FILE and file_index installs.
- REGISTER_EVENTFD(_ASYNC)/UNREGISTER: signal an eventfd on completion.
- REGISTER_PROBE: fill io_uring_probe with per-opcode supported bits.
- REGISTER_PERSONALITY/UNREGISTER: retain a per-ring credential snapshot;
  SQE.personality resolves and holds it during preparation, so unregister does
  not change prepared inline or worker requests and teardown releases unused
  registrations.
- REGISTER_ENABLE_RINGS (with R_DISABLED), REGISTER_RESTRICTIONS,
  REGISTER_RING_FDS/UNREGISTER (registered ring fds), REGISTER_PBUF_RING/
  UNREGISTER (provided-buffer rings), REGISTER_SYNC_CANCEL, REGISTER_FILE_ALLOC_RANGE.
- REGISTER_IOWQ_AFF/UNREGISTER_IOWQ_AFF and REGISTER_IOWQ_MAX_WORKERS:
  per-ring worker affinity and bounded/unbounded admission limits over the
  shared worker pool.
- REGISTER_SEND_MSG_RING: a blind, source-ring-free synchronous MSG_DATA
  publication to a target ring.
- REGISTER_BPF_FILTER uses the shared classic-BPF verifier and interpreter for
  immutable, lockless per-ring request filters. Linux blind registration stores
  a task-scoped filter set that is inherited across fork and snapshotted into
  rings created later.
- REGISTER_NAPI/UNREGISTER_NAPI preserve Linux configuration, previous-state
  copyout, timeout clamping, tracking modes and static-ID list semantics in the
  shared engine. FreeBSD drivers expose no Linux NAPI poll hook, so the stored
  latency hint does not alter network progress. ZCRX_IFQ/ZCRX_CTRL support the
  copied NODEV subset and reject hardware/import/export modes; MEM_REGION is
  qualified for mapped and user-backed regions with indexed timespec waits.

## 7. Phased build (each phase VM-tested with a freestanding linux_io_uring test)
- P1 [DONE] rings + setup + fo_mmap + enter skeleton + NOP + CQ post/wait +
  REGISTER_PROBE.
- P2 [DONE] READ/WRITE/READV/WRITEV/FSYNC via the engine (inline, in the
  submitting thread; exact byte counts and errno).
- P3 [DONE] CLOSE/FTRUNCATE/FALLOCATE/FADVISE. Linux FALLOCATE delegates
  mode and errno policy to the Linuxulator fallocate handler; native squeue
  provides mode-zero allocation.
- P4 [DONE] IOSQE_IO_LINK/HARDLINK/IO_DRAIN/CQE_SKIP_SUCCESS ordering, TIMEOUT
  (relative/abs/count/ETIME_SUCCESS)/TIMEOUT_REMOVE/ASYNC_CANCEL, and
  LINK_TIMEOUT.  Requests are tracked (struct sq_req); a TIMEOUT completes
  from callout context (posting its CQE directly so a poll-blocked waiter
  wakes) and a linked successor runs when a thread next drives io_uring_enter.
  IOSQE_ASYNC file transfers use the shared bounded worker pool; fixed-file
  transfers resolve through their captured rights and retain the selected
  generation until worker completion.
- POLL [DONE, module-feasible after all] POLL_ADD/POLL_REMOVE.  The waiting
  thread (io_uring_enter, which owns the caller's fd table) calls the exported
  kern_poll_kfds() over the ring fd plus every armed target fd; the ring fd is
  in the set so one wait blocks on either a completion or a target becoming
  ready, no kqueue EVFILT_USER injection needed.  A ready single-shot poll is
  moved to the ready list and posted by run_ready.  Multishot poll (and
  multishot accept/recv) still need kqueue's persistent edge-triggered
  registration and belong to the sys/kern move (§11); POLL_ADD_MULTI is
  rejected with -EINVAL for now.  POLLNVAL on a bad target maps to -EBADF.
- P6 fs [DONE for the inline-feasible set] OPENAT/OPENAT2/STATX/RENAMEAT/
  UNLINKAT/MKDIRAT/SYMLINKAT/LINKAT/MADVISE/SYNC_FILE_RANGE, each delegating to
  the Linuxulator's own syscall handler so flag/path translation is identical
  to the direct syscall.  Also EPOLL_CTL and the extended-attribute opcodes
  FSETXATTR/SETXATTR/FGETXATTR/GETXATTR (same delegation).  Also TEE
  (fd_in=splice_fd_in, fd_out=fd), the SQE form of FILES_UPDATE (off=offset,
  len=nr, addr=fd array) and MSG_RING. MSG_DATA posts a CQE to same-process
  same- or cross-ring targets and implements FLAGS_PASS. SEND_FD copies a held
  registered-file reference and its capability rights to an explicit or
  automatically allocated target slot; CQE_SKIP suppresses target notification.
  SPLICE now accepts explicit input/output offsets through a Linuxulator-only
  common splice path; `splice_offsets` passed the Linux oracle and full amd64
  ZFS-root gate. `SPLICE_F_FD_IN_FIXED` now resolves the secondary input
  through the shared registered-file table for SPLICE and TEE; its Linux
  oracle, focused ZFS/tmpfs rounds and full amd64 gate passed. WAITID now has ECHILD, child-exit, pidfd, stop and continue cases, including
  WNOHANG/WNOWAIT, with Linux oracles and a 348-case full amd64 ZFS-root
  gate. Pending WAITID now uses a per-ring process-context pump and supports
  exit, pidfd, cancellation, linked timeout, close and exit/cancel races; see
  [the WAITID audit](linuxulator-waitid-lifecycle.md). Pending futex waits now
  use callback-backed umtx waiters with wake, vector-index, bitset,
  cancellation, linked-timeout, close and race coverage; see
  [the futex pending gate](linuxulator-iouring-futex-pending.md). EPOLL_WAIT now has deferred readiness, fixed and ambient
  descriptor identity, cancellation, negative SQE-field cases and a
  readiness/cancellation race, qualified by the 355-case amd64 ZFS-root
  gate; see [the EPOLL_WAIT audit](linuxulator-epoll-wait-async.md).
- P5 net [DONE for the named contracts] SOCKET/CONNECT/ACCEPT/BIND/LISTEN/
  SHUTDOWN/SEND/RECV/SENDMSG/RECVMSG delegate to Linuxulator socket handlers.
  Linux-only preparation validates POLL_FIRST, ACCEPT multishot/DONTWAIT,
  RECV/RECVMSG multishot, SEND vector/fixed-buffer modes, SEND_ZC usage
  reporting, and SEND/RECV bundles. Shared squeue owns readiness retries,
  intermediate-CQE accounting, selected-buffer rollback and contiguous batch
  selection. `IORING_FEAT_RECVSEND_BUNDLE` is advertised only by Linux rings.
- FAST POLL [DONE - the real async fast path, honoring IORING_FEAT_FAST_POLL].
  A would-block data op does NOT block the submitting thread: RECV/SEND/
  RECVMSG/SENDMSG are forced non-blocking (MSG_DONTWAIT) and READ/WRITE/READV/
  WRITEV/ACCEPT honor a non-blocking fd; on EAGAIN the request is parked on a
  readiness poll (ctx->polls, req->retry) and re-issued from sq_poll_scan when
  the fd is ready, its linked successors running then.  So one thread drives
  many concurrent in-flight socket ops - the io_uring server sweet spot -
  without per-op worker threads. Multishot poll, accept and receive reuse this
  shared readiness path and account each intermediate CQE. Remaining speed
  items include a real zero-copy send path and newer registered provided-buffer
  rings; the current SEND_ZC path correctly reports copied usage.
- P7 [DONE for registered files/buffers] REGISTER_FILES/FILES2/
  UNREGISTER_FILES/FILES_UPDATE/FILES_UPDATE2 with held generation references
  and lifetime tag CQEs (a fixed op works even after the app closes its own fd;
  the reference is installed into a transient descriptor so every opcode stays
  fixed-file agnostic); IOSQE_FIXED_FILE; REGISTER_BUFFERS/
  UNREGISTER_BUFFERS + READ_FIXED/WRITE_FIXED and fixed vectors (every range
  is checked against its selected slot; inline, readiness retries and worker
  I/O retain the registered pages until the request retires). Provided buffers:
  PROVIDE_BUFFERS/REMOVE_BUFFERS build per-group buffer pools and
  IOSQE_BUFFER_SELECT on READ/RECV consumes one, reporting its id in
  cqe->flags (IORING_CQE_F_BUFFER | bid<<16); an empty group yields -ENOBUFS.
  The pool also supports capacity-preserving retry and atomic contiguous batch
  detach/return for Linux SEND/RECV bundles. Ring-mapped provided buffers
  (PBUF_RING), personalities, SQPOLL, and tagged buffer registration/update
  variants are implemented and covered by their named mandatory matrices.

## 8. Concurrency & lifetime
Per-ring mutex for SQ/CQ head/tail and the job lists; jobs hold references to
their target file (fhold) and are cancellable (a cancel table keyed by
user_data).  Close tears down: drain/cancel in-flight jobs, unregister
buffers/files/eventfd, free the wired object.  SQE reads are bounded by the
ring mask; all user pointers inside SQEs are validated per-op (copyin), never
trusted from the shared page.

## 9. Complete UAPI surface - verified against include/uapi/linux/io_uring.h (1065 lines)

Legend: [G] reproducible exactly on the FreeBSD core; [C] reproducible with a
named caveat; [X] internals-bound, report unsupported via REGISTER_PROBE /
features (a correct app treats it as an older kernel lacking the feature).

### 9.1 Structures (28) - all must be defined byte-identically
io_uring_sqe [G], io_uring_attr_pi [C: PI/RW_ATTR only if backing supports it],
io_uring_cqe (+CQE32 big_cqe) [G], io_sqring_offsets [G], io_cqring_offsets [G],
io_uring_params [G], io_uring_files_update [G], io_uring_region_desc [C],
io_uring_mem_region_reg [G], io_uring_rsrc_register [G], io_uring_rsrc_update
[G], io_uring_rsrc_update2 [G], io_uring_probe_op [G], io_uring_probe [G],
io_uring_restriction [G], io_uring_task_restriction [C], io_uring_clock_register
[G], io_uring_clone_buffers [C], io_uring_buf [G], io_uring_buf_ring [G],
io_uring_buf_reg [G], io_uring_buf_status [G], io_uring_napi [C], io_uring_reg_wait
[C], io_uring_getevents_arg [G], io_uring_sync_cancel_reg [G],
io_uring_file_index_range [G], io_uring_recvmsg_out [G], io_timespec [G].

### 9.2 Opcodes (65 concrete entries, enum io_uring_op) - dispatch table entry each
[G]: NOP, READV, WRITEV, READ, WRITE, READ_FIXED, WRITE_FIXED, FSYNC,
SYNC_FILE_RANGE, FALLOCATE, FADVISE, MADVISE, STATX, CLOSE, OPENAT, OPENAT2,
RENAMEAT, UNLINKAT, MKDIRAT, SYMLINKAT, LINKAT, FTRUNCATE, SPLICE, TEE,
SHUTDOWN, ACCEPT, CONNECT, BIND, LISTEN, SOCKET, SEND, RECV, SENDMSG, RECVMSG,
POLL_ADD, POLL_REMOVE, TIMEOUT, TIMEOUT_REMOVE, LINK_TIMEOUT, ASYNC_CANCEL,
FILES_UPDATE, EPOLL_CTL, EPOLL_WAIT, PROVIDE_BUFFERS, REMOVE_BUFFERS,
FSETXATTR, SETXATTR, FGETXATTR, GETXATTR, WAITID, FUTEX_WAIT, FUTEX_WAKE,
FUTEX_WAITV, FIXED_FD_INSTALL, MSG_RING (same/cross-ring), NOP.
[G]: READ_MULTISHOT, POLL_ADD multishot, ACCEPT multishot, RECV/RECVMSG
multishot, and SEND/RECV bundle over legacy provided-buffer groups and
registered PBUF_RING groups.
[G]: READV_FIXED, WRITEV_FIXED (vectored + registered buffers), PIPE (kern
pipe2 with optional fixed-fd install).
[C, hard/achievable]: SEND_ZC, SENDMSG_ZC - zero-copy send is buildable on
FreeBSD's m_ext_free / M_EXTPG external mbufs (pin the user pages into external
mbufs; the ext_free callback fires the second IORING_CQE_F_NOTIF completion
when the stack releases them, as sendfile already does).  NOP128 = NOP with a
128-byte SQE, trivially [G] once SETUP_SQE128 is.
[X, delegates its meaning to another subsystem - not byte-reproducible on any
non-Linux kernel]: URING_CMD device-specific commands / URING_CMD128
(interpreted by a specific driver's ->uring_cmd, e.g. NVMe/ublk passthrough -
would require porting each driver's Linux command ABI), and hardware-backed
RECV_ZC/zcrx (needs NIC RX flow steering into user memory, like AF_XDP
zero-copy RX). The copied Linux v7.1 NODEV mode is implemented. See also NAPI in 9.3 (a Linux
net-driver polling framework with no FreeBSD analogue; a pure latency hint) and
IOPOLL in 9.4 (no polled-bio API in FreeBSD; setup rejects the flag).

The enum currently has 65 concrete opcodes (`IORING_OP_LAST == 65`); the table
sizes to `IORING_OP_LAST` and every index has an entry (real handler or the
shared "unsupported opcode -> -EINVAL" stub advertised as absent by PROBE).

### 9.3 Register ops (enum io_uring_register_op)
[G]: BUFFERS, UNREGISTER_BUFFERS, FILES, UNREGISTER_FILES, FILES_UPDATE,
FILES2, FILES_UPDATE2, BUFFERS2, BUFFERS_UPDATE, EVENTFD, EVENTFD_ASYNC,
UNREGISTER_EVENTFD, PROBE, PERSONALITY, UNREGISTER_PERSONALITY,
ENABLE_RINGS, RESTRICTIONS, RING_FDS, UNREGISTER_RING_FDS, PBUF_RING,
UNREGISTER_PBUF_RING, PBUF_STATUS, SYNC_CANCEL, FILE_ALLOC_RANGE,
CLOCK, RESIZE_RINGS, IOWQ_AFF, UNREGISTER_IOWQ_AFF, IOWQ_MAX_WORKERS,
SEND_MSG_RING, MEM_REGION, QUERY (Linux front end), BPF_FILTER,
USE_REGISTERED_RING (op flag).
[G/C]: NAPI and UNREGISTER_NAPI preserve the registration ABI and state but
cannot invoke Linux driver busy-poll callbacks; ZCRX_IFQ and ZCRX_CTRL support
Linux v7.1 copied NODEV receive.
[X]: Hardware/import/export ZCRX modes.

### 9.4 Flag families - every bit handled or rejected
- IORING_SETUP_* (21): IOPOLL[X], SQPOLL[C], SQ_AFF[C], CQSIZE[G],
  CLAMP[G], ATTACH_WQ[G for non-SQPOLL, C for SQPOLL], R_DISABLED[G],
  SUBMIT_ALL[G], COOP_TASKRUN[G],
  TASKRUN_FLAG[G], SQE128[G], CQE32[G], SINGLE_ISSUER[G], DEFER_TASKRUN[G],
  NO_MMAP[G], REGISTERED_FD_ONLY[G], NO_SQARRAY[G], HYBRID_IOPOLL[X],
  CQE_MIXED[G], SQE_MIXED[G], SQ_REWIND[G].
- IORING_ENTER_* (8): GETEVENTS[G], SQ_WAKEUP[C], SQ_WAIT[C], EXT_ARG[G],
  REGISTERED_RING[G], ABS_TIMER[G], EXT_ARG_REG[G], NO_IOWAIT[G].
- IOSQE_* (7): FIXED_FILE, IO_DRAIN, IO_LINK, IO_HARDLINK, ASYNC,
  BUFFER_SELECT, CQE_SKIP_SUCCESS - all [G].
- IORING_FEAT_* (18): shared squeue advertises SINGLE_MMAP, NODROP,
  SUBMIT_STABLE, RW_CUR_POS, CUR_PERSONALITY, FAST_POLL, POLL_32BITS,
  SQPOLL_NONFIXED, EXT_ARG, RSRC_TAGS, CQE_SKIP, LINKED_FILE,
  REG_REG_RING, MIN_TIMEOUT and NO_IOWAIT. Linuxulator additionally advertises
  RECVSEND_BUNDLE. NATIVE_WORKERS and RW_ATTR remain clear; see the
  [feature-flag audit](linuxulator-iouring-feature-flags.md).
- Per-op: IORING_FSYNC_DATASYNC[G]; TIMEOUT_* (ABS/BOOTTIME/REALTIME/
  CLOCK_MASK/ETIME_SUCCESS/MULTISHOT/UPDATE/IMMEDIATE_ARG)[G/C]; POLL_ADD_MULTI/
  POLL_ADD_LEVEL/POLL_UPDATE*[G]; ASYNC_CANCEL_ALL/ANY/FD/FD_FIXED/OP/USERDATA[G];
  ACCEPT_MULTISHOT/DONTWAIT/POLL_FIRST[G/C]; RECVSEND_POLL_FIRST/FIXED_BUF/
  BUNDLE[G/C]; RECV_MULTISHOT[C]; MSG_RING_CQE_SKIP/FLAGS_PASS[G];
  NOP_INJECT_RESULT/FILE/FIXED_FILE/FIXED_BUFFER/TW/NOP_CQE32[G];
  SPLICE_F_FD_IN_FIXED[G]; IORING_FILE_INDEX_ALLOC[G]; URING_CMD_*[X]; NOTIF_*[X].
- CQE flags emitted: IORING_CQE_F_BUFFER, F_MORE, F_SOCK_NONEMPTY, F_BUF_MORE,
  F_SKIP, F_32 [G]; F_NOTIF [X].
- Ring state flags: IORING_SQ_NEED_WAKEUP/CQ_OVERFLOW/TASKRUN [G],
  IORING_CQ_EVENTFD_DISABLED [G].
- IORING_OFF_* mmap offsets incl. PBUF_RING|(bgid<<PBUF_SHIFT) and MMAP_MASK [G].

### 9.5 REGISTER_PROBE is the compatibility contract
The probe result and params.features are generated FROM this matrix at build
time, so an app's feature detection sees exactly the [G]+[C] set as supported
and every [X] as absent - indistinguishable from a Linux kernel configured
without those features.  No [X] op ever returns a wrong result; it returns
-EINVAL/-EOPNOTSUPP exactly as the probe advertises.

## 10. Limitations and the compatibility guarantee (verified vs Linux source)

Verified against torvalds/linux io_uring/io_uring.c, opdef.c, register.c:
Linux implements feature negotiation with exactly the mechanism we adopt, so
an unsupported item here is indistinguishable from a Linux kernel built
without that feature:
- `io_uring_setup` sets `p->features = IORING_FEAT_FLAGS` (a build-time OR of
  supported FEAT bits) and returns `-EINVAL` for unknown/!supported SETUP
  flags.  We set `features` to the OR of what we implement and reject unknown
  SETUP bits the same way.
- Unsupported opcodes carry `.prep = io_eopnotsupp_prep` in `io_issue_defs[]`;
  `io_uring_op_supported(op)` is "prep != io_eopnotsupp_prep".
- `IORING_REGISTER_PROBE` (`io_probe`) sets `last_op = IORING_OP_LAST-1` and,
  for each op, `ops[i].flags = IO_URING_OP_SUPPORTED` iff supported.  We build
  the probe from our support matrix by the identical loop.
- A submitted-anyway unsupported op completes with CQE `res = -EINVAL`; an
  unsupported REGISTER op returns `-EINVAL`/`-EOPNOTSUPP`.
So liburing's `io_uring_queue_init_params` (reads `features`) and
`io_uring_opcode_supported` (reads the probe) - the near-universal client
path - degrade automatically, as they already do across Linux kernel versions.

### 10.1 What is NOT supported, why, and how software copes
| Item | Why not reproducible | Negotiation signal | App-visible result |
|------|----------------------|--------------------|--------------------|
| URING_CMD socket subset | Linuxulator maps socket queue queries and common options; target-device commands remain file-specific | PROBE: URING_CMD supported only on Linux rings | Socket subset completes; unsupported target files and commands return EOPNOTSUPP. |
| URING_CMD128 / device-specific URING_CMD | Socket URING_CMD128 uses SQE128 and the Linuxulator socket command handler; NVMe/ublk passthrough still needs each target driver's Linux command ABI and VM gate | PROBE: URING_CMD128 present on Linux rings | Socket command subset completes on SQE128 rings; unsupported target files and commands return EOPNOTSUPP. |
| RECV_ZC + zcrx (REGISTER_ZCRX_IFQ) | Linux v7.1 copied NODEV receive is supported; hardware zero-copy still needs NIC RX ownership | PROBE advertises RECV_ZC; registration admits NODEV and rejects hardware/import/export modes | NODEV clients receive through registered copied buffers; hardware-only clients see the reference error |
| NAPI (REGISTER/UNREGISTER_NAPI) | Linux net-driver polling callbacks have no FreeBSD analogue; the configuration is a pure latency hint | Registration succeeds and reports the prior per-ring state | Apps retain functional I/O and ABI-compatible configuration; the hint does not change driver polling latency. |
| RW_ATTR protection information | Native squeue has no storage-metadata iterator or target-device PI contract | `IORING_FEAT_RW_ATTR` is clear | Zero masks work normally; unknown masks return EINVAL and known PI requests return EOPNOTSUPP before I/O. |
| MEM_REGION | Shared squeue owns kernel-allocated and pinned-user region backing, mmap lifetime and indexed waits; Linuxulator translates the ABI | Native and Linux forms pass the named VM gate; minimum waits use the shared timer path | Apps can use registered timespec waits or ordinary EXT_ARG waits. |
| QUERY | Linux linked-list header/data ABI is implemented in Linuxulator; shared squeue supplies admitted masks and ring registration checks | Blind and ring-fd query work; unsupported query operations return per-entry errors | Apps can inspect supported flag families and use PROBE for individual SQE opcodes. |

### 10.2 Proposed modes and behavioral caveats (not qualification)
| Item | Caveat | Detectable? |
|------|--------|-------------|
| IORING_SETUP_IOPOLL / HYBRID_IOPOLL | Rejected with EINVAL. Shared squeue has no polled block-I/O completion backend, so advertising either mode would misstate the progress contract. | Yes: setup fails, allowing a caller to retry with an ordinary ring. |
| SEND_ZC / SENDMSG_ZC | The current Linuxulator path copies data and posts a notification CQE after the send completes. With REPORT_USAGE it sets ZC_COPIED. A true pinned-page transmit path would need separate socket-stack ownership and completion work. | Yes: ZC_COPIED reports the fallback. IOSQE_CQE_SKIP_SUCCESS is rejected on these opcodes, matching Linux 7.1.5. |
| SQPOLL | A process-context poller and blocking-transfer worker offload are implemented in shared squeue, with Linux thread initialization in the frontend. See [the SQPOLL audit](linuxulator-sqpoll.md). | The named attachment, affinity, overflow, blocked-read, concurrent-close and registered selected-buffer contracts passed the VM gate; further option combinations remain pending. |
| Provided-buffer bundles | SEND produces ordered buffer-tagged CQEs until the group is empty. Registered PBUF_RING RECV batches can span multiple entries; legacy multishot RECV selects one descriptor per completion. A bundle without IOSQE_BUFFER_SELECT is rejected to avoid Linux 6.18's unbounded no-buffer SEND behavior. | Yes: Linux rings advertise `IORING_FEAT_RECVSEND_BUNDLE`; invalid combinations complete with EINVAL. The registered-ring and legacy multishot contracts passed the 404-case ZFS-root QEMU gate. |

### 10.3 Guarantee
Every unsupported item is (a) reported absent through the same negotiation
channel Linux uses for its own build-time feature gating, and (b) never
returns a *wrong* result - only "absent" (PROBE) or "-EINVAL/-EOPNOTSUPP"
(setup/register/CQE).  IOPOLL is rejected at setup rather than silently using interrupt-driven
completion. Applications can retry with an ordinary ring when polling is
optional. Hardware-bound features such as real zero-copy RX and device-specific
URING_CMD still require their driver backends.

## 11. Userland library (verified) - what each front-end needs

io_uring is useless without a userland ring-management library (liburing).
There are two front-ends and the library story differs:

### 11.1 Linux ABI path (primary consumer: Bun/Node/libuv, databases)
Linux binaries **supply their own liburing**, exactly as they supply libc:
either statically linked into the app, dlopen'd, or as
`/compat/linux/usr/lib/liburing.so*` from the Linux distro (Alpine
`apk add liburing`, Debian `libliburing`).  We ship nothing for them.  Our
obligations for these apps to work transparently:
1. Implement the three syscalls in the Linux front-end (linux_io_uring_*),
   translating the Linux SQE/CQE/params (identical layout - no translation
   needed) and errno.
2. Expose the ring fd's mmap.  VERIFIED: a Linux `mmap()` on the ring fd
   flows linux_mmap -> kern_mmap (mmap_req, mr_fd) -> fget_mmap ->
   `fo_mmap(fp,...)` (vm/vm_mmap.c:473), so our fd's fo_mmap handler is
   reached with the IORING_OFF_* offset as foff.  MAP_POPULATE (used by
   liburing) is already supported.
No base library is required for the Linux path; the app brings liburing.
TEST RIG: to exercise a real liburing binary under the Linuxulator, stage a
Linux liburing (musl build from Alpine) into ~/vm/alpine-root and link a
freestanding test against it, in addition to the raw-syscall tests.

### 11.2 Native 5BSD path (option 2)
For native programs, provide a native liburing in base:
1. Add native io_uring_setup/enter/register to sys/kern/syscalls.master; the
   build auto-generates the libc syscall stubs (io_uring_setup(2), etc.).
2. Install the UAPI/KPI header as `sys/sys/io_uring.h` ->
   /usr/include/sys/io_uring.h (precedent: sys/sys/eventfd.h, timerfd.h).
3. Import upstream liburing to `contrib/liburing` + `lib/liburing` (Makefile),
   under its **MIT** option (liburing is dual LGPL-2.1 OR MIT; MIT keeps base
   GPL-free).  Port only its syscall layer (src/syscall.c) to call the libc
   stubs / __sys_io_uring_* instead of inline Linux `__NR_io_uring_*` numbers;
   the ring-management code (queue init, sqe get/prep, cqe peek/seen, probe
   helpers) is arch-neutral and unchanged.  Native apps link `-luring` and
   include <liburing.h>.
This makes io_uring a first-class 5BSD facility while the Linux ABI rides the
same core.

### 11.3 Action items (deferred until the engine exists)
- P1..P7: build the native core + both front-ends.
- After native syscalls land: import contrib/liburing + lib/liburing (MIT),
  port syscall.c, install sys/sys/io_uring.h.
- Test-rig: add a musl liburing to the Linux rootfs for an end-to-end
  liburing-under-Linuxulator test.
Nothing to import before the syscalls exist (a native liburing cannot link
without the stubs); the requirement is captured here so it is not missed.
