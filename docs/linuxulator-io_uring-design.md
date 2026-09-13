# Linuxulator io_uring: full implementation design

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
- P1 rings + setup + fo_mmap + enter skeleton + NOP + CQ post/wait.
- P2 READ/WRITE/READV/WRITEV/FSYNC/SYNC_FILE_RANGE/FALLOCATE via the engine.
- P3 REGISTER_FILES/BUFFERS, IOSQE_FIXED_FILE, READ_FIXED/WRITE_FIXED,
  REGISTER_PROBE, REGISTER_EVENTFD.
- P4 IOSQE_IO_LINK/HARDLINK/IO_DRAIN/ASYNC/CQE_SKIP_SUCCESS ordering,
  POLL_ADD/REMOVE, TIMEOUT/TIMEOUT_REMOVE/LINK_TIMEOUT, ASYNC_CANCEL.
- P5 net: ACCEPT/CONNECT/SEND/RECV/SENDMSG/RECVMSG/SOCKET/BIND/LISTEN/SHUTDOWN.
- P6 fs: OPENAT/OPENAT2/CLOSE/STATX/RENAMEAT/UNLINKAT/MKDIRAT/SYMLINKAT/LINKAT/
  FTRUNCATE/FADVISE/MADVISE/SPLICE/TEE/xattr/EPOLL_CTL/FILES_UPDATE.
- P7 provided-buffer rings + BUFFER_SELECT + multishot, personalities,
  SQPOLL thread, restrictions; REGISTER_PROBE reflects the final matrix.

## 8. Concurrency & lifetime
Per-ring mutex for SQ/CQ head/tail and the job lists; jobs hold references to
their target file (fhold) and are cancellable (a cancel table keyed by
user_data).  Close tears down: drain/cancel in-flight jobs, unregister
buffers/files/eventfd, free the wired object.  SQE reads are bounded by the
ring mask; all user pointers inside SQEs are validated per-op (copyin), never
trusted from the shared page.
