# io_uring and squeue

squeue ("shared queue") is 5BSD's native completion-ring interface: an application submits I/O through a submission ring and reaps results from a completion ring, both shared with the kernel, so many operations cost one system call and completions cost none. It adopts the Linux io_uring wire format verbatim, and the Linux `io_uring_*` syscalls are a thin front end over the same engine, in the same relationship that kqueue(2) bears to Linux epoll. 5BSD built it because the runtimes that matter (Bun, Node and libuv, databases) probe for io_uring and either use it or fall back silently, and a fallback is not compatibility. The design is in `docs/linuxulator-io_uring-design.md`; every qualified contract is in `docs/book/src/compat/linux/overview.md`.

## The native engine

The engine lives in `sys/kern/sys_squeue.c` with its KPI in `sys/sys/squeue.h` and the wire structures in `sys/sys/io_uring.h`, installed as `<sys/io_uring.h>`. Nothing in the engine is Linux-specific: it dispatches onto the same `kern_*` primitives the rest of the kernel uses (`kern_readv`, `kern_fsync`, `kern_accept4`, `kern_kevent`, the umtx futex code, and so on), and each front end supplies a `struct sq_frontend` carrying its errno translator and opcode extensions.

| Piece | Where | Notes |
|---|---|---|
| Syscalls | `squeue_setup` (636), `squeue_enter` (637), `squeue_register` (638) in `sys/kern/syscalls.master` | libc stubs are generated; documented in squeue(2) |
| Ring memory | one wired swap-backed VM object per ring, mapped at `IORING_OFF_SQ_RING`, `IORING_OFF_CQ_RING`, `IORING_OFF_SQES` and `IORING_OFF_PBUF_RING` | `IORING_FEAT_SINGLE_MMAP` is advertised; `NO_MMAP` rings use caller-owned memory |
| Worker pool | a system-wide pool of kernel worker processes for operations that must block (regular files, pipes, `IOSQE_ASYNC`) | `kern.squeue.max_workers`, default 8, range 1 to 256, boot tunable and runtime writable |
| Readiness | kqueue-native: the ring subscribes descriptor knotes and wakes through an `EVFILT_USER` note; a ring descriptor is itself an `EVFILT_READ` source | so a ring can sit inside a kqueue or an epoll set |
| Descriptor type | `DTYPE_IORING` (26) in `sys/sys/file.h`; `KF_TYPE_SQUEUE` for procstat and fstat, which print `[squeue]` | renumbered from 20 because it collided with `DTYPE_LINUXPIDFD` |
| Overflow | `IORING_FEAT_NODROP`: completions beyond the CQ go to a backlog and set `IORING_CQ_OVERFLOW` | the `overflowed` counter records it |
| Observability | DTrace provider `squeue` with probes `setup`, `submit`, `complete`, `overflow`, `offload`, `ready`, `wait`, `wakeup` | `squeue_dtrace_test` proves them |

The sysctls under `kern.squeue` are the operator's view. `max_workers`, `workers` and `idle_workers` describe the pool; `max_wired_pages` (default one eighth of RAM) and `wired_pages` bound and report ring and registered-buffer memory, with `RLIMIT_MEMLOCK` applying per user on top; `live_requests`, `registered_files`, `issuer_tokens` and `issuer_refs` are the resource counters the QEMU gate requires to return to zero; `rings`, `submitted`, `completed` and `overflowed` are lifetime statistics.

Capsicum applies to native rings with one extra rule. The three syscalls are `CAPENABLED`, per-descriptor `cap_rights` are enforced on every operation by the usual `fget` paths, and registered files capture their rights (including ioctl whitelists) at registration time. In capability mode a native ring is treated as a closed capability set: an operation that names a descriptor must use `IOSQE_FIXED_FILE` and a registered slot, or it completes with `ENOTCAPABLE`; only the opcodes that reference no descriptor (`NOP`, timeouts, cancellation, `POLL_REMOVE`, provided-buffer management, `FILES_UPDATE`, `FIXED_FD_INSTALL`) are exempt. The Linux front end is deliberately untouched by that rule, because Linux programs cannot enter capability mode themselves. Rings also work and stay confined inside a jail (`squeue_jail_test`).

## The Linux front end

`sys/compat/linux/linux_io_uring.c` implements `io_uring_setup`, `io_uring_enter` and `io_uring_register` by copying in the Linux structures (the layout is identical, so no translation), translating errno (`ETIMEDOUT` becomes Linux `ETIME`, the invalid-state sentinel becomes `EBADFD`), converting Linux signal masks at the boundary, and calling the engine. A Linux program brings its own liburing, statically linked or from `/compat/linux/usr/lib`; the base system ships nothing for that path, and the ring fd's `fo_mmap` handler is reached through the ordinary Linux `mmap` path, so liburing's `MAP_POPULATE` mappings work unchanged.

**Setup flags.** The engine admits the set below and rejects any other bit with `EINVAL`, exactly as Linux rejects flags it was not built with.

| Accepted | Notes |
|---|---|
| `CQSIZE`, `CLAMP`, `NO_SQARRAY`, `SUBMIT_ALL`, `SINGLE_ISSUER`, `R_DISABLED`, `COOP_TASKRUN`, `TASKRUN_FLAG`, `DEFER_TASKRUN`, `SQE128`, `CQE32`, `CQE_MIXED`, `SQE_MIXED`, `SQ_REWIND`, `NO_MMAP`, `REGISTERED_FD_ONLY`, `ATTACH_WQ` | gate-passed; `SQE128` and `SQE_MIXED`, or `CQE32` and `CQE_MIXED`, are mutually exclusive |
| `SQPOLL`, `SQ_AFF` | a process-context poller and worker offload in the engine; the named attachment, affinity, overflow, blocked-read, close-race and selected-buffer contracts are gate-passed (`docs/book/src/compat/linux/io-uring.md`); further option combinations are still on the backlog, so treat SQPOLL as gated rather than complete |
| `IOPOLL`, `HYBRID_IOPOLL` | rejected at setup with `EINVAL`: there is no polled block-I/O completion backend, and advertising the flag would misstate the progress contract; a program that treats polling as optional retries with an ordinary ring |

**Opcodes.** All 65 concrete `IORING_OP_*` values through `IORING_OP_LAST` have a dispatch entry. The general set (read, write, fixed and vectored-fixed variants, fsync, fallocate, fadvise, madvise, statx, close, openat and openat2, the pathname operations, ftruncate, splice, tee, pipe, shutdown, accept, connect, bind, listen, socket, send, recv, sendmsg, recvmsg, poll add and remove, timeouts, link timeouts, async cancel, files update, epoll ctl and wait, provided buffers, xattr, waitid, futex wait, wake and waitv, fixed-fd install, msg ring, nop and nop128) runs on the engine. Multishot read, poll, accept and receive, provided-buffer bundles over legacy groups and registered `PBUF_RING` groups, and incremental buffer consumption are gate-passed.

**Register commands.** All 38 ordinary `IORING_REGISTER_*` commands (0 through `BPF_FILTER`, 37) dispatch, plus the `USE_REGISTERED_RING` flag bit. That covers buffers and files with their v2, update and tagged forms, eventfd, probe, personality, enable rings, restrictions, ring fds, provided-buffer rings and status, sync cancel, file alloc range, clock, resize rings, IOWQ affinity and max workers, send msg ring, mem region, query, ZCRX ifq and ctrl, NAPI and BPF filter. `REGISTER_RESTRICTIONS` and `REGISTER_BPF_FILTER` (a classic-BPF filter over request metadata, verified with the shared BPF verifier) are the per-ring policy points; a blind BPF registration is task-scoped, inherited across fork, and snapshotted into rings created later.

**Features.** Setup advertises `SINGLE_MMAP`, `NODROP`, `SUBMIT_STABLE`, `RW_CUR_POS`, `CUR_PERSONALITY`, `FAST_POLL`, `POLL_32BITS`, `SQPOLL_NONFIXED`, `EXT_ARG`, `RSRC_TAGS`, `CQE_SKIP`, `LINKED_FILE`, `REG_REG_RING`, `MIN_TIMEOUT` and `NO_IOWAIT`; the Linux front end alone adds `RECVSEND_BUNDLE`. `NATIVE_WORKERS` and `RW_ATTR` stay clear on purpose (`docs/book/src/compat/linux/io-uring.md`).

## What is rejected or negotiated, and why

The compatibility guarantee is that every unsupported item is reported through the same channel Linux uses for its own build-time feature gating, and never returns a wrong result. `REGISTER_PROBE` is built from the support matrix by the same loop Linux uses, so liburing's `io_uring_opcode_supported` and `io_uring_queue_init_params` see an older-kernel-shaped truth and degrade as they already do across Linux versions.

| Item | Behaviour | Signal to the application |
|---|---|---|
| `IOPOLL`, `HYBRID_IOPOLL` | setup fails | `EINVAL` from `io_uring_setup` |
| `SEND_ZC`, `SENDMSG_ZC` | the data is copied and a notification CQE is posted after the send completes; with `REPORT_USAGE` the notification carries `IORING_NOTIF_USAGE_ZC_COPIED`; `IOSQE_CQE_SKIP_SUCCESS` is rejected on these opcodes as on Linux 7.1.5 | `ZC_COPIED` in the notification |
| `RECV_ZC` and `REGISTER_ZCRX_IFQ` | the Linux 7.1 copied `NODEV` mode is implemented; hardware, import and export modes are rejected | `ENODEV` for a zero interface index, `EOPNOTSUPP` for hardware and export, `EINVAL` for incompatible area flags; `CAP_NET_ADMIN`-equivalent privilege is checked before copyin |
| `URING_CMD`, `URING_CMD128` | the socket subset (queue queries and common options) completes; device-specific commands such as NVMe or ublk passthrough are not ported | `EOPNOTSUPP` for an unsupported target file or command |
| `RW_ATTR` protection information | a zero attribute mask works normally | `IORING_FEAT_RW_ATTR` clear; unknown masks `EINVAL`, known PI requests `EOPNOTSUPP` before any I/O |
| `REGISTER_NAPI`, `UNREGISTER_NAPI` | the registration ABI, previous-state copyout, timeout clamping and tracking modes are preserved, but no driver busy-poll hook exists, so the stored latency hint changes nothing | registration succeeds; it is advisory |
| `MEM_REGION`, `QUERY`, `RESIZE_RINGS`, `min_wait_usec`, registered wait arguments | implemented and gate-passed | ordinary success |

The `SQPOLL` row above is the other place to read carefully: it is implemented and its named contracts passed, but the design document says plainly that its remaining option combinations are pending, and this book does not promote that to "complete".

## Using squeue natively

`lib/libsqueue` is a header-only, liburing-shaped helper: every function is `static inline` in `<squeue.h>`, and `-lsqueue` is needed only for `squeue_major_version` and `squeue_minor_version`. squeue(3) documents it. The program below reads the first block of a file through a ring and waits for the completion.

```c
#include <sys/io_uring.h>
#include <squeue.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct squeue q;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	char buf[4096];
	int fd, r;

	if (argc != 2)
		errx(1, "usage: sqread file");
	if ((fd = open(argv[1], O_RDONLY)) < 0)
		err(1, "%s", argv[1]);
	if ((r = squeue_init(&q, 8)) < 0)
		errc(1, -r, "squeue_init");

	sqe = squeue_get_sqe(&q);		/* NULL if the SQ is full */
	squeue_prep_read(sqe, fd, buf, sizeof(buf), 0);
	squeue_sqe_set_data(sqe, 42);

	if ((r = squeue_submit_and_wait(&q, 1)) < 0)
		errc(1, -r, "squeue_submit_and_wait");
	if ((r = squeue_wait_cqe(&q, &cqe)) < 0)
		errc(1, -r, "squeue_wait_cqe");
	if (cqe->res < 0)
		errc(1, -cqe->res, "read completion");
	printf("user_data %llu: %d bytes\n",
	    (unsigned long long)cqe->user_data, cqe->res);
	squeue_cqe_seen(&q, cqe);

	squeue_exit(&q);
	return (0);
}
```

Build it with `cc -o sqread sqread.c` (add `-lsqueue` only if you call the version accessors). The helpers cover `nop`, `read`, `write`, `readv`, `writev`, `fsync` and `poll_add` preparation, `squeue_register_files`, `squeue_register_buffers` and `squeue_register_eventfd`; for any other opcode, fill the `struct io_uring_sqe` from `<sys/io_uring.h>` directly, since the wire format is the whole contract. A completion error arrives as a negative errno in `cqe->res` and never fails the submitting call; a positive submission count takes precedence over a later wait error, so check `res` on every CQE. To run the ring in capability mode, register the files first and set `IOSQE_FIXED_FILE` on each SQE.

To watch the engine while the program runs:

```sh
dtrace -n 'squeue:::submit { @[arg1] = count(); } squeue:::offload { @off = count(); }'
sysctl kern.squeue
fstat -p $(pgrep sqread)          # shows the ring as [squeue]
```

## Tests and evidence

Native: `squeue_native`, `squeue_options` (191 option groups, run through both front ends), `squeue_stress`, `squeue_soak`, `squeue_fuzz`, `squeue_jail`, `squeue_copy`, `squeue_hold`, `squeue_dtrace`, `squeue_fstat` and `squeue_lib`, all under `tests/sys/kern/`. Linux: `linux_iouring` with the 477-case inventory in `tools/test/linuxulator/iouring-cases.json` (the JSON is authoritative; changing the binary's list requires reconciling it), plus `linux_iouring_sqpoll`, `_nommap`, `_query`, `_resize` and `_mem_region`. The gate runs every option group three times on ZFS and tmpfs through both APIs, requires the resource counters to return to zero, and runs the portable groups on the Linux reference guest. Historical design matrices in the design document are targets, not certification; the implementation-gate batches are the record.
