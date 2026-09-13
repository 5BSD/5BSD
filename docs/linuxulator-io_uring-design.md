# Linuxulator io_uring: full implementation design

## 0. Architecture: native core + Linux front-end (decided)

io_uring is built as a **first-class 5BSD kernel subsystem**, not a Linux-only
shim.  The engine, rings, registration tables and opcode dispatch live in a
native file **`sys/kern/sys_io_uring.c`** with a public KPI in
`sys/sys/io_uring.h`.  It is reached two ways over the *same* core:
- **Native syscalls** `io_uring_setup`/`io_uring_enter`/`io_uring_register`
  added to `sys/kern/syscalls.master` (a liburing-style native consumer).
- **Linux front-end** in `sys/compat/linux/linux_io_uring.c`: the three
  `linux_io_uring_*` calls are thin ABI wrappers (copyin the Linux structs,
  translate opcode/flag/errno where they differ, call the native core).
The ABI itself (SQE/CQE/params/ring layout, opcode numbers, ring offsets) is
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
  SINGLE_ISSUER, DEFER_TASKRUN.  SQPOLL/SQ_AFF start a kernel submission
  thread (phase 7); IOPOLL is accepted but completions run through the normal
  path (no driver busy-poll on FreeBSD).  ATTACH_WQ/NO_MMAP/REGISTERED_FD_ONLY
  handled or rejected explicitly.
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
A dispatch table indexed by opcode.  Worker executes, then `iou_complete(job,
res, cflags)` writes a CQE (user_data, res, flags) into the CQ ring at tail,
handles overflow (NODROP: a kernel overflow list flushed as space frees, set
IORING_SQ_CQ_OVERFLOW), wakes waiters and any registered eventfd, and, for a
completed link head, submits the next link.

Opcode -> kern_* mapping (all 66; "impl" = maps to an existing primitive,
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
- gap (report unsupported): URING_CMD, SEND_ZC, SENDMSG_ZC, RECV_ZC,
  READ_MULTISHOT (multishot only), zcrx.  IOPOLL falls back to normal
  completion.

## 6. io_uring_register(fd, op, arg, nr)  (42 ops)
- REGISTER/UNREGISTER_BUFFERS (+ _UPDATE, _tags/RSRC): pin user iovecs into a
  registered-buffer table for READ_FIXED/WRITE_FIXED (vm_fault_quick_hold_pages,
  like MAP_POPULATE).
- REGISTER/UNREGISTER_FILES (+ _UPDATE, _tags): a table of held file refs for
  IOSQE_FIXED_FILE and file_index installs.
- REGISTER_EVENTFD(_ASYNC)/UNREGISTER: signal an eventfd on completion.
- REGISTER_PROBE: fill io_uring_probe with per-opcode supported bits.
- REGISTER_PERSONALITY/UNREGISTER: stash a cred snapshot; SQE.personality
  selects it.
- REGISTER_ENABLE_RINGS (with R_DISABLED), REGISTER_RESTRICTIONS,
  REGISTER_RING_FDS/UNREGISTER (registered ring fds), REGISTER_PBUF_RING/
  UNREGISTER (provided-buffer rings), REGISTER_SYNC_CANCEL, REGISTER_FILE_ALLOC_RANGE.
- gap: REGISTER_IOWQ_AFF/MAX_WORKERS (accept, best-effort), NAPI, ZCRX,
  MEM_REGION -> report unsupported.

## 7. Phased build (each phase VM-tested with a freestanding linux_io_uring test)
- P1 [DONE] rings + setup + fo_mmap + enter skeleton + NOP + CQ post/wait +
  REGISTER_PROBE.
- P2 [DONE] READ/WRITE/READV/WRITEV/FSYNC via the engine (inline, in the
  submitting thread; exact byte counts and errno).
- P3 [DONE] CLOSE/FTRUNCATE/FALLOCATE/FADVISE.
- P4 [DONE, except as noted] IOSQE_IO_LINK/HARDLINK/IO_DRAIN/CQE_SKIP_SUCCESS
  ordering, TIMEOUT (relative/abs/count/ETIME_SUCCESS)/TIMEOUT_REMOVE/
  ASYNC_CANCEL.  Requests are tracked (struct iou_req); an async op completes
  from callout context and a linked successor runs when a thread next drives
  io_uring_enter.  IOSQE_ASYNC is accepted (ops still run inline).
  NOT YET, and internals-bound for the loadable module (see §10.x):
  POLL_ADD/POLL_REMOVE and LINK_TIMEOUT.  A correct async wait on an arbitrary
  target fd needs the kernel's seltd/selfdalloc or kqueue_register machinery,
  all static in kern_{generic,event}.c and unreachable from a module.  These
  land when the engine moves into sys/kern (§11) where that machinery, or a
  small readiness KPI, is available.  Until then PROBE reports them
  unsupported so applications negotiate (liburing falls back to epoll/poll).
- P6 fs [DONE for the inline-feasible set] OPENAT/OPENAT2/STATX/RENAMEAT/
  UNLINKAT/MKDIRAT/SYMLINKAT/LINKAT/MADVISE/SYNC_FILE_RANGE, each delegating to
  the Linuxulator's own syscall handler so flag/path translation is identical
  to the direct syscall.  Remaining: SPLICE/TEE, xattr, EPOLL_CTL, FILES_UPDATE
  (FILES_UPDATE needs registered files, P7).
- P5 net [DONE for the inline set] SOCKET/CONNECT/ACCEPT/BIND/LISTEN/SHUTDOWN/
  SEND/RECV/SENDMSG/RECVMSG, each delegating to the Linuxulator's own socket
  handler so sockaddr and flag translation is identical to the direct syscall.
  Runs inline in the submitting thread; a blocking socket blocks that thread
  (Linux would offload to io-wq) - documented caveat.  Multishot ACCEPT/RECV
  and SEND_ZC/RECV_ZC remain for later (need the poll retry loop / provided
  buffers / m_ext_free).
- P7 [PENDING] REGISTER_FILES/BUFFERS + IOSQE_FIXED_FILE + READ_FIXED/
  WRITE_FIXED + REGISTER_EVENTFD; provided-buffer rings + BUFFER_SELECT +
  multishot; personalities; SQPOLL thread; restrictions; REGISTER_PROBE
  reflects the final matrix.

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
io_uring_mem_region_reg [X], io_uring_rsrc_register [G], io_uring_rsrc_update
[G], io_uring_rsrc_update2 [G], io_uring_probe_op [G], io_uring_probe [G],
io_uring_restriction [G], io_uring_task_restriction [C], io_uring_clock_register
[G], io_uring_clone_buffers [C], io_uring_buf [G], io_uring_buf_ring [G],
io_uring_buf_reg [G], io_uring_buf_status [G], io_uring_napi [X], io_uring_reg_wait
[C], io_uring_getevents_arg [G], io_uring_sync_cancel_reg [G],
io_uring_file_index_range [G], io_uring_recvmsg_out [G], io_timespec [G].

### 9.2 Opcodes (66, enum io_uring_op) - dispatch table entry each
[G]: NOP, READV, WRITEV, READ, WRITE, READ_FIXED, WRITE_FIXED, FSYNC,
SYNC_FILE_RANGE, FALLOCATE, FADVISE, MADVISE, STATX, CLOSE, OPENAT, OPENAT2,
RENAMEAT, UNLINKAT, MKDIRAT, SYMLINKAT, LINKAT, FTRUNCATE, SPLICE, TEE,
SHUTDOWN, ACCEPT, CONNECT, BIND, LISTEN, SOCKET, SEND, RECV, SENDMSG, RECVMSG,
POLL_ADD, POLL_REMOVE, TIMEOUT, TIMEOUT_REMOVE, LINK_TIMEOUT, ASYNC_CANCEL,
FILES_UPDATE, EPOLL_CTL, EPOLL_WAIT, PROVIDE_BUFFERS, REMOVE_BUFFERS,
FSETXATTR, SETXATTR, FGETXATTR, GETXATTR, WAITID, FUTEX_WAIT, FUTEX_WAKE,
FUTEX_WAITV, FIXED_FD_INSTALL, MSG_RING (same/cross-ring), NOP.
[C]: READ_MULTISHOT, RECV/ACCEPT multishot (needs provided-buffer rings + the
poll retry loop - phase 7); SEND/RECV bundle (RECVSEND_BUNDLE).
[G]: READV_FIXED, WRITEV_FIXED (vectored + registered buffers), PIPE (kern
pipe2 with optional fixed-fd install).
[C, hard/achievable]: SEND_ZC, SENDMSG_ZC - zero-copy send is buildable on
FreeBSD's m_ext_free / M_EXTPG external mbufs (pin the user pages into external
mbufs; the ext_free callback fires the second IORING_CQE_F_NOTIF completion
when the stack releases them, as sendfile already does).  NOP128 = NOP with a
128-byte SQE, trivially [G] once SETUP_SQE128 is.
[X, delegates its meaning to another subsystem - not byte-reproducible on any
non-Linux kernel]: URING_CMD / URING_CMD128 (interpreted by a specific device
driver's ->uring_cmd, e.g. NVMe/ublk passthrough - would require porting each
driver's Linux command ABI), RECV_ZC + zcrx (need NIC hardware RX flow-steering
into user memory, like AF_XDP zero-copy RX). See also NAPI in 9.3 (a Linux
net-driver polling framework with no FreeBSD analogue; a pure latency hint) and
IOPOLL in 9.4 (no polled-bio API in FreeBSD, so completions are correct but
interrupt-driven, not busy-polled).

The enum currently runs to IORING_OP_LAST = 71 opcodes (verified); the table
sizes to IORING_OP_LAST and every index has an entry (real handler or the
shared "unsupported opcode -> -EINVAL" stub advertised as absent by PROBE).

### 9.3 Register ops (37, enum io_uring_register_op)
[G]: BUFFERS, UNREGISTER_BUFFERS, FILES, UNREGISTER_FILES, FILES_UPDATE,
FILES2, FILES_UPDATE2, BUFFERS2, BUFFERS_UPDATE, EVENTFD, EVENTFD_ASYNC,
UNREGISTER_EVENTFD, PROBE, PERSONALITY, UNREGISTER_PERSONALITY,
ENABLE_RINGS, RESTRICTIONS, RING_FDS, UNREGISTER_RING_FDS, PBUF_RING,
UNREGISTER_PBUF_RING, PBUF_STATUS, SYNC_CANCEL, FILE_ALLOC_RANGE,
CLOCK, RESIZE_RINGS, USE_REGISTERED_RING (op flag).
[C]: IOWQ_AFF/UNREGISTER_IOWQ_AFF, IOWQ_MAX_WORKERS (accept, best-effort on the
taskqueue pool), CLONE_BUFFERS, SEND_MSG_RING.
[X]: NAPI/UNREGISTER_NAPI, ZCRX_IFQ, ZCRX_CTRL, MEM_REGION, QUERY, BPF_FILTER.

### 9.4 Flag families - every bit handled or rejected
- IORING_SETUP_* (21): IOPOLL[C fallback], SQPOLL[C], SQ_AFF[C], CQSIZE[G],
  CLAMP[G], ATTACH_WQ[C], R_DISABLED[G], SUBMIT_ALL[G], COOP_TASKRUN[G],
  TASKRUN_FLAG[G], SQE128[G], CQE32[G], SINGLE_ISSUER[G], DEFER_TASKRUN[G],
  NO_MMAP[G], REGISTERED_FD_ONLY[G], NO_SQARRAY[G], HYBRID_IOPOLL[C],
  CQE_MIXED[C], SQE_MIXED[C], SQ_REWIND[C].
- IORING_ENTER_* (8): GETEVENTS[G], SQ_WAKEUP[C], SQ_WAIT[C], EXT_ARG[G],
  REGISTERED_RING[G], ABS_TIMER[G], EXT_ARG_REG[G], NO_IOWAIT[G].
- IOSQE_* (7): FIXED_FILE, IO_DRAIN, IO_LINK, IO_HARDLINK, ASYNC,
  BUFFER_SELECT, CQE_SKIP_SUCCESS - all [G].
- IORING_FEAT_* (18): advertise those honored (SINGLE_MMAP, NODROP,
  SUBMIT_STABLE, RW_CUR_POS, CUR_PERSONALITY, FAST_POLL, POLL_32BITS, EXT_ARG,
  NATIVE_WORKERS, RSRC_TAGS, CQE_SKIP, LINKED_FILE, REG_REG_RING, MIN_TIMEOUT,
  NO_IOWAIT); leave RECVSEND_BUNDLE/RW_ATTR/SQPOLL_NONFIXED clear until [C]/[X]
  pieces land.
- Per-op: IORING_FSYNC_DATASYNC[G]; TIMEOUT_* (ABS/BOOTTIME/REALTIME/
  CLOCK_MASK/ETIME_SUCCESS/MULTISHOT/UPDATE/IMMEDIATE_ARG)[G/C]; POLL_ADD_MULTI/
  POLL_ADD_LEVEL/POLL_UPDATE*[G]; ASYNC_CANCEL_ALL/ANY/FD/FD_FIXED/OP/USERDATA[G];
  ACCEPT_MULTISHOT/DONTWAIT/POLL_FIRST[G/C]; RECVSEND_POLL_FIRST/FIXED_BUF/
  BUNDLE[G/C]; RECV_MULTISHOT[C]; MSG_RING_CQE_SKIP/FLAGS_PASS[G]; NOP_* flags[G];
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
| URING_CMD / URING_CMD128 | opcode meaning is a target *driver's* ->uring_cmd (NVMe/ublk passthrough); would need each driver's Linux command ABI ported | PROBE: op not SUPPORTED | opcode reported absent; liburing users skip it, direct submit gets CQE -EINVAL |
| RECV_ZC + zcrx (REGISTER_ZCRX_IFQ) | needs NIC hardware RX flow-steering into user memory (AF_XDP-class) | PROBE: RECV_ZC absent; REGISTER_ZCRX_IFQ -> -EINVAL | app falls back to RECV/RECVMSG |
| NAPI (REGISTER/UNREGISTER_NAPI) | Linux net-driver polling framework; no FreeBSD analogue; pure latency hint | REGISTER_NAPI -> -EINVAL | app skips busy-poll tuning, functions normally |
| MEM_REGION / BPF_FILTER / QUERY (newest register ops) | Linux-internal (huge-page region registration, bpf, query) | REGISTER op -> -EINVAL | not used unless present; absent = older kernel |

### 10.2 Supported but with a documented behavioral caveat
| Item | Caveat | Detectable? |
|------|--------|-------------|
| IORING_SETUP_IOPOLL | Accepted; completions are correct but interrupt-driven, not device busy-polled (FreeBSD has no polled-bio API).  DECISION: accept rather than reject, so IOPOLL-requiring apps run - they lose only the polling latency win. | No - there is no ABI bit distinguishing real vs emulated IOPOLL.  This is the ONE limitation feature negotiation cannot express.  Correctness is unaffected. |
| SEND_ZC / SENDMSG_ZC | Real zero-copy via m_ext_free/M_EXTPG; the NOTIF CQE fires when the stack releases the pages.  Copy fallback if a path cannot pin (reported via IORING_NOTIF_USAGE_ZC_COPIED, exactly as Linux does when it copies). | Yes - the ZC_COPIED bit is the Linux-defined signal. |
| SQPOLL | Supported via a kernel submission thread; timing/latency differs from Linux but the contract (submit without enter) holds. | Partially - FEAT_SQPOLL_NONFIXED advertises the mode. |
| POLL_ADD / POLL_REMOVE / LINK_TIMEOUT (loadable-module build only) | An async readiness wait on an arbitrary target fd needs the kernel's per-thread select machinery (seltdinit/selfdalloc/seltdwait) or an internal kqueue (kqueue_alloc/kqueue_register) - all `static` in kern_generic.c / kern_event.c and unreachable from a loadable module.  DECISION: report these ops NOT supported via PROBE for the module build; implement them when the engine is resident in sys/kern (§11), where that machinery or a minimal readiness KPI is reachable. | Yes - PROBE reports the ops absent, exactly Linux's own gate; liburing and correctly-written apps fall back to epoll/poll/select for readiness.  No wrong result is ever returned. |

### 10.3 Guarantee
Every unsupported item is (a) reported absent through the same negotiation
channel Linux uses for its own build-time feature gating, and (b) never
returns a *wrong* result - only "absent" (PROBE) or "-EINVAL/-EOPNOTSUPP"
(setup/register/CQE).  The sole exception is IOPOLL, where by explicit
decision we accept the flag and run correctly without the busy-poll speedup,
which no ABI bit can advertise.  Therefore any correctly-written app - i.e.
one that checks features/probe, as it must to run across Linux versions -
runs here transparently or degrades gracefully; only apps that *hard-require*
a genuinely hardware/driver-bound feature (real zero-copy RX, NVMe
passthrough) cannot run, and those cannot run on any Linux lacking that
hardware/driver either.

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
