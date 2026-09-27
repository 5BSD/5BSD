# io_uring and squeue

squeue ("shared queue") is 5BSD's native completion-ring interface: an application submits I/O through a submission ring and reaps results from a completion ring, both shared with the kernel, so many operations cost one system call and completions cost none. It adopts the Linux io_uring wire format verbatim, and the Linux `io_uring_*` syscalls are a thin front end over the same engine, in the same relationship that kqueue(2) bears to Linux epoll. The compatibility goal is correct behavior for application workloads, including accurate feature discovery and Linux-compatible rejection of unsupported optional facilities. Qualification records actual ring use separately from application fallback: a working fallback can preserve application behavior, but does not establish that the io_uring operation works. The design is in `docs/linuxulator-io_uring-design.md`; every qualified contract is in `docs/book/src/compat/linux/overview.md`.

## Upstream qualification warning (September 26, 2026)

The in-tree gates below establish the named contracts, not general liburing
compatibility. A new 70-case liburing 2.12 comparison found 35 candidate passes,
26 failures, six timeouts, two skips, and a hard-link kernel assertion captured
in a separate run. Linux passed 68 cases and skipped two. Several failures
involve ordinary cancellation, linked requests, and pipe/eventfd operations;
the missing advanced backends are not the only remaining work. The continuation
run also ended with four registered files and two wired pages still accounted
for, whose ownership needs investigation.

Fio 3.41 passed checksum verification in buffered, direct, registered-buffer/file,
and SQPOLL modes on the candidate. That success does not supersede the upstream
failures. See the [upstream qualification results](../../../../../tools/test/linuxulator/iouring-upstream/results-20260926.md)
for the exact payload, stress results, hardware-baseline limits, and follow-up
priorities. No kernel fix is claimed by this qualification run.

The [hard-link follow-up](../../../../../tools/test/linuxulator/iouring-upstream/fixes-20260926.md)
fixed the empty-path assertion. Its first stream-offset patch was reverted after
a cancellation/teardown panic. The [subsequent stream and cancellation fixes](../../../../../tools/test/linuxulator/iouring-upstream/stream-fixes-20260926.md)
retain the private kqueue's descriptor-table storage through teardown, enable
ordinary pipe/eventfd/socket I/O with readiness retries, preserve forced-async
worker progress, and retain registered-file generations across retries.

The [initial libuv 1.53.0 application check](../../../../../tools/test/linuxulator/iouring-upstream/libuv-results-20260926.md)
verified filesystem and epoll ring use but exposed a cancellation race under a
VM-only newer-version identity: 12 of 20 repetitions reported successful
cancellation followed by a successful read. The follow-up distinguishes queued
work from executing regular-file I/O; its final candidate passes all six cases
under each identity and all 20 cancellation repetitions. Completed I/O retains
its real result instead of being relabelled as cancelled.

The focused follow-up passes 15 of 16 upstream cases. `io-cancel` still fails
when a child exits after submitting a linked poll of an inherited ring retained
by its parent: readiness is returned where Linux cancels the request. This is
remaining task-exit ownership work, not an optional backend. The focused run
also passes the native regression checks and returns all five resource counters
to zero, but does not supersede the earlier full 70-case inventory.

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

The intended compatibility contract is that unsupported items use Linux-compatible feature negotiation. The upstream failures above show that this contract is not yet established for all combinations. `REGISTER_PROBE` is built from the support matrix by the same loop Linux uses, so liburing's `io_uring_opcode_supported` and `io_uring_queue_init_params` see an older-kernel-shaped truth and degrade as they already do across Linux versions.

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

Native: `squeue_native`, `squeue_options` (194 option groups, run through both front ends), `squeue_stress`, `squeue_soak`, `squeue_fuzz`, `squeue_jail`, `squeue_copy`, `squeue_hold`, `squeue_dtrace`, `squeue_fstat` and `squeue_lib`, all under `tests/sys/kern/`. Linux: `linux_iouring` with the 477-case inventory in `tools/test/linuxulator/iouring-cases.json` (the JSON is authoritative; changing the binary's list requires reconciling it), plus `linux_iouring_sqpoll`, `_nommap`, `_query`, `_resize` and `_mem_region`. The gate runs every option group three times on ZFS through both APIs, repeats selected contracts on tmpfs, requires the resource counters to return to zero, and runs portable groups on the Linux reference guest. Historical design matrices in the design document are targets, not certification; the implementation-gate batches are the record.

### September 26 restart checkpoint

The latest io_uring implementation commit is `672ddb5c9e86` (September 24),
which added NAPI registration state after worker-ownership and BPF-filter work.
All 38 locally declared ordinary register commands now dispatch. NAPI remains
an advisory setting without a driver busy-poll backend.

The retained September 24 amd64 ZFS-root shared-suite log,
`/tmp/iouring-napi-20260924/full.console.log`, contains 193 cases in each of
three rounds through each frontend: 1,158 successful executions. Its six
resource reports each contain ten zero values, and it records healthy ZFS,
gate exit zero and synchronized shutdown. On September 26 the case names and
multiplicities were checked against the then-current source inventory; no recognized
panic, debugger-entry, lock-order, non-sleepable-lock or fatal-trap diagnostics
were found. The log's SHA256 is
`311a27c5f3c014075b093d307f677cf7c55214bc81b0670aadda04bf851228b3`.
This is recovered evidence for those guest artifacts, not a new runtime
qualification of the current working tree or a run of the separate 477-case
Linux suite. The log includes the guest kernel, module and test binary hashes.

The resumed audit targets CPU-affinity behavior when a process's cpuset changes
after setup. The detailed historical matrix is recoverable from
`44cce4c970c1^:docs/linuxulator-sqpoll.md` and the option backlog from
`44cce4c970c1^:docs/linuxulator-next-phase-options.md`.

### SQPOLL cpuset inheritance

The audit found that `kthread_add()` placed the poller in the kernel cpuset.
Checking the requested CPU at setup did not make that thread a member of the
creator's named cpuset, so later changes to the creator's set did not constrain
the poller. Startup now creates the thread stopped, inherits the creator's named
set under the process and thread locks, then starts it. `SQ_AFF` applies its
pin within that hierarchy. Per-thread caller affinity remains independent,
matching the separate setup contract in
[Linux v6.18 sqpoll.c](https://github.com/torvalds/linux/blob/v6.18/io_uring/sqpoll.c).

The permanent `sqpoll_affinity_transitions_shared` case changes the caller's
thread mask after setup and requires continued completions through both APIs.
Its native half creates private cpusets and checks actual poller membership and
masks, narrowing and widening, attached-ring progress after source close, and
final pin release. FreeBSD rejects an empty cpuset, or a parent change that
would empty a pinned child, with `EDEADLK`; the rejected change must preserve
the original set. A poller without `SQ_AFF` follows valid parent-set changes.

The September 26 amd64 WITNESS/INVARIANTS qualification passed 36 focused
ZFS/tmpfs executions, all 194 shared cases in three rounds through both APIs
(1,164 executions), the 477-case Linux suite, 117 dedicated SQPOLL/NO_MMAP/
memory-region/query executions, and three native smoke runs. Linux 6.18.35
passed six caller-affinity oracle executions. Final request, registered-file,
issuer-reference, issuer-token and wired-page counters were zero; completed
guests reported healthy ZFS and synchronized shutdown with no recognized
kernel diagnostics. Arm64 Linux test compilation passed with warnings treated
as errors; runtime qualification is amd64 only.

The [qualification record](../../../../../tools/test/linuxulator/sqpoll-affinity-qualification-20260926.json)
pins source, guest artifacts and logs, including the baseline membership
failure, an intermediate scheduler-unlock panic, and fixture corrections.
The first main-suite attempt omitted loopback setup; its shared phase passed,
and the separate main/dedicated phase passed after correcting that fixture.
The gate inventories now include BPF and NAPI registration as well as the new
affinity case. This qualification covers io_uring/squeue, not the entire
Linuxulator syscall/filesystem matrix. No candidate kernel was installed on
the host.

Linux cgroup-controller transitions and CPU hotplug remain unqualified.
Other open backend boundaries are polled block I/O, hardware/import/export
ZCRX, device-specific URING_CMD and actual network busy polling.
