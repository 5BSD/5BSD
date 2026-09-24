# Next phase: options within implemented Linux syscalls

Requested on 2026-09-17 after the ZFS-root correctness gate. A syscall being
present does not mean all of its commands, flags or indirect entry paths work.
This is a source-review backlog, not a claim that the options below passed
runtime tests. The mandatory acceptance contract remains
[the implementation gate](linuxulator-implementation-gate.md): disposable
ZFS-root QEMU guests on **amd64**, native regressions for shared mechanisms,
positive and negative cases, Linux reference results and provenance. Repeat
arm64 when a change touches its ABI, syscall tables or machine-dependent code.

## Initial audit and reference boundary

The current code, not older design tables, is the starting point. Reviewed
`sys/kern/sys_squeue.c`, the Linux io_uring front end and UAPI header, the
existing io_uring tests, Linux file/futex/ptrace handlers and arm64 register
conversion. [The recorded inventory](../tools/test/linuxulator/option-audit.json)
contains source hashes and every locally declared setup/enter/register option
with its dispatcher status before the first option batch. These statuses describe admission only;
accepted does not mean semantically complete or tested.

Use [Linux v6.18 UAPI](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/io_uring.h)
and [its implementation](https://github.com/torvalds/linux/blob/v6.18/io_uring/io_uring.c)
as the initial pinned comparison, matching our Linux 6.18.35 reference guest.
The local header also defines newer options. Assign each of those a separately
verified Linux revision before implementation; do not inherit the older
review document's blanket version/completeness claims.
[Upstream liburing documentation](https://github.com/axboe/liburing/tree/master/man)
is an additional contract reference, with a commit pinned when a case is added.

The preceding 405-case ZFS gate validated its named locking, sealing, ABI and pathname
subsets. It **did not include the io_uring/squeue suites**. The expanded gate below
adds them; historical io_uring logs alone do not qualify current source.

## io_uring: admission gaps at the initial audit

| Entry point | Current source | Next-phase work |
|---|---|---|
| `io_uring_setup` | `CQSIZE`, `CLAMP`, `NO_SQARRAY`, `SUBMIT_ALL`, `SINGLE_ISSUER`, `R_DISABLED`, cooperative/deferred task modes, expanded layouts, `NO_MMAP` and `REGISTERED_FD_ONLY` are qualified | SQPOLL and wake/wait passed their named core VM gate; SQ_AFF passed its named shared affinity VM gate. |
| Setup layout/memory | `SQE128`, `CQE32`, `CQE_MIXED`, `SQ_REWIND`, caller-owned `NO_MMAP` rings and registered-fd-only setup are qualified | `SQE_MIXED` consumes two contiguous slots for 128-byte opcodes in shared squeue; the 394-case ZFS-root gate passed. |
| Setup scheduling | `COOP_TASKRUN`, `TASKRUN_FLAG` and `DEFER_TASKRUN` are qualified, and their SQPOLL combinations now reject as on Linux 6.18. `SQ_AFF` passed its named affinity gate; `IOPOLL` and hybrid polling reject; `ATTACH_WQ` and SQPOLL core are qualified | Implement the remaining modes only with their actual submission, affinity, progress and completion contracts. |
| `io_uring_enter` | `GETEVENTS`, `EXT_ARG`, `ABS_TIMER`, registered-ring entry, registered wait arguments, `NO_IOWAIT` and signal masks are qualified | SQ wake/wait passed their named SQPOLL core gate; `min_wait_usec` uses the shared two-stage timer and advertises `IORING_FEAT_MIN_TIMEOUT`. |
| `io_uring_register` | 36 of 38 locally declared ordinary commands are handled, including ring resize, memory regions, query, BPF filters and copied NODEV ZCRX | Remaining: NAPI/UNREGISTER_NAPI. Hardware/import/export ZCRX modes remain rejected until their backends exist. |
| Register lifecycle/policy | Restrictions/enable, registered clocks, ring-fd lifetime, cloned-buffer accounting, personality credentials, per-ring IOWQ policy, resizing and query are qualified | Implement the remaining registration contracts only with their actual kernel backends. The per-ring bounded/unbounded limits schedule within the separate system-wide `kern.squeue.max_workers` ceiling. |

The qualified register commands are BUFFERS/BUFFERS2/BUFFERS_UPDATE/
UNREGISTER_BUFFERS, FILES/FILES2/UNREGISTER_FILES, FILES_UPDATE/FILES_UPDATE2,
EVENTFD/EVENTFD_ASYNC/UNREGISTER_EVENTFD, PROBE, PERSONALITY/
UNREGISTER_PERSONALITY, RESTRICTIONS, ENABLE_RINGS, RING_FDS/
UNREGISTER_RING_FDS, PBUF_RING/UNREGISTER_PBUF_RING/PBUF_STATUS, SYNC_CANCEL,
FILE_ALLOC_RANGE, CLOCK, CLONE_BUFFERS, IOWQ_AFF/UNREGISTER_IOWQ_AFF and
IOWQ_MAX_WORKERS, SEND_MSG_RING, RESIZE_RINGS, MEM_REGION, QUERY and BPF_FILTER.
`IORING_REGISTER_USE_REGISTERED_RING` is a qualified high-bit mode and is not a
39th ordinary command.

`SPLICE_F_FD_IN_FIXED` for SPLICE and TEE now uses the shared registered-file
lookup and Linuxulator flag translation. Its [named contract and gate](linuxulator-splice-fixed-input.md)
passed the Linux oracle, three ZFS and three tmpfs focused rounds, and the full
amd64 ZFS-root gate.

The SQPOLL slice has [a pinned oracle and ownership audit](linuxulator-sqpoll.md). Its Linux reference, focused native/Linux cases, and full amd64 ZFS-root VM gate passed for the named core, SQ_AFF, task-run exclusion, and `SINGLE_ISSUER`/caller-owned/registered-fd-only layout combinations. CPU hotplug and post-setup cpuset transitions remain pending; initial native cpuset exclusion passed the VM gate. The broader lifecycle matrix remains separate work.

## Ring resize: shared engine and Linux ABI

`IORING_REGISTER_RESIZE_RINGS` (33) is implemented in shared squeue because
it replaces SQ, CQ and SQE storage for native and Linux rings. The Linuxulator
retains the Linux registration number and output convention. Pinned
[Linux v6.18 register.c](https://github.com/torvalds/linux/blob/v6.18/io_uring/register.c)
requires `DEFER_TASKRUN`, a non-null parameter pointer and `nr_args == 1`;
only `CQSIZE` and `CLAMP` may be new flags. The implementation copies pending
SQEs/CQEs, rejects occupied shrink with `EOVERFLOW`, and preserves readable
old mappings independently of the replacement. The backing uses managed VM
objects so retired mappings can remain pageable after the ring releases its
wired-page charge.

[The resize record](linuxulator-ring-resize.md) names eleven native/Linux
cases and five dedicated Linux oracle cases. They cover invalid arguments,
overflow and copyout rollback, grow/shrink, clamping, extended layouts, mapping
lifetime and races, and an in-flight worker completion. The Linux oracle, focused amd64 ZFS-root guest, and full amd64 ZFS-root gate
passed. The full run recorded 66 resize cases and 852 squeue-option cases with
zero diagnostics and clean shutdown; see the resize record for hashes and logs.

## Register query: Linux ABI over shared admission masks

`IORING_REGISTER_QUERY` (35) uses the Linuxulator for its linked header/data
wire ABI and blind `fd == -1` entry. A ring-fd query passes through shared
squeue registration policy; the shared backend owns the supported setup,
enter, SQE and feature masks to keep discovery consistent with actual
admission. Native squeue does not expose the Linux query ABI.

[The query record](linuxulator-register-query.md) maps seven named oracle
cases to positive and negative contracts, including linked entries,
per-entry errors, variable output sizes, read-only/guard-page faults and a
1000-entry cycle limit. The Linux 6.18.35 oracle and focused amd64 ZFS-root
runs passed. The full amd64 ZFS-root gate passed 21 query runs and 852 shared squeue
option runs with zero diagnostics and clean shutdown; the exact result is
`/tmp/linuxulator-gate-20260919/query-full-gate3/results.json`.

## Registered memory region: shared backing and indexed wait

`IORING_REGISTER_MEM_REGION` (34) now uses shared squeue VM backing. A
kernel-owned region maps at Linux offset `0x20000000`; a user-backed region
pins the supplied pages for ring lifetime. `IORING_ENTER_EXT_ARG_REG` reads a
registered wait record by byte index. Linuxulator retains its syscall and
errno translation. The [memory-region gate](linuxulator-mem-region.md) records
eight Linux-specific and four dual-ABI oracle groups, 48 focused guest runs,
and a passing full amd64 ZFS-root gate with 876 shared option runs and zero
recognized diagnostics. The subsequent [minimum-wait phase](linuxulator-min-wait.md) implements
and tests `min_wait_usec` through both ordinary and registered wait forms.

## First work: reproduce and fix semantic gaps

These are code-review findings; runtime reproduction and exact Linux errno
checks are required before deciding the fix. They take priority over adding
setup flags.

| Priority | Finding in current code | Required tests and ownership |
|---|---|---|
| P0 | The initial source used plain SQ-tail consumption and SQ-head publication; the first batch adds explicit acquire/release operations to SQ/CQ publication and consumption | Qualify the new forked producer/submitter wrap test; extend to independent reapers and affinity-controlled workers. Include arm64 evidence and distinguish QEMU testing from weak-memory proofs. |
| P0 | The initial READ/WRITE and vectored dispatch ignored `sqe.rw_flags`; the qualified RWF batch below adds shared enforcement and front-end decoding | Compare direct syscall and SQE behavior for every RWF bit, including denied/unsupported operations with unchanged file contents. Shared I/O enforcement; Linux flag translation in the front end. |
| P0, named contracts qualified | Central SQE flags, personalities and the reviewed network ioprio fields are validated during preparation. Additional opcode-specific reserved fields remain in the audit | Keep negative tests for unknown bits, incompatible modes and side-effect-free preparation failures; continue through opcodes outside the qualified network/RWF/link/file subsets. |
| P0, named contracts qualified | The initial REGISTER_BUFFERS copied iovecs without pinning; fixed vectors lacked per-vector bounds checks. The registered-buffer batch below adds shared squeue/VM pinning, lifetime and range enforcement | Both architecture gates cover unmap/remap, wrong regions, guard pages, active unregister, fork/COW/protection races, quota exhaustion and rollback. New resource variants and ring-backing/RACCT accounting remain separate work. |
| P0, named contracts qualified | The initial LINK_TIMEOUT implementation only completed ECANCELED. The linked-deadline batch below adds preparation, predecessor arming and identity-based cancellation in shared squeue | Both architecture gates cover expiry/completion/cancel/close races, worker ownership, rollback and zero retained resources. Clock changes after arming and suspend/resume remain unqualified. |
| P0 | The initial PROBE table advertised Linux extensions on native rings; the qualified PROBE batch below scopes advertisement by front end and validates the full zeroed input contract | Compare every advertised opcode against executable native and Linux dispatch. Check partial-mode claims separately; opcode presence is not evidence for all of its flags. |
| P0, qualified | `IORING_OP_FALLOCATE` now shares the direct Linux mode, descriptor and errno policy; mode-zero allocation and PUNCH_HOLE|KEEP_SIZE are covered | Keep unsupported-mode, offset, descriptor, size/data and seal preservation cases mandatory. Add new filesystem modes only with matching rollback tests. |
| P1, named contracts qualified | Asynchronous cancellation supports user-data, ALL, FD, ANY, fixed-FD, explicit-user-data and opcode matching in shared squeue | The qualified matrix covers counts and errno semantics, duplicate and closed descriptors, fixed slots, cross-request classes, unrelated requests and invalid combinations. Synchronous registration cancellation remains separate work. |
| P1, named contracts qualified | Poll replacement and timeout update/multishot modes are implemented and gated; per-opcode reserved-field validation remains uneven | Keep the poll/timeout negative and leak matrix mandatory while auditing remaining opcodes. |
| P1, named contracts qualified | ACCEPT/RECV/RECVMSG/SEND/SEND_ZC now consume the reviewed ioprio options, including legacy provided-buffer bundles | Dual-architecture cases cover poll-first, multishot, limits, fixed/vector sends, usage notifications, bundle CQEs, cancellation/reuse and invalid combinations. Registered PBUF_RING mmap, user-pinned, status, unregister and incremental-consumption contracts are now qualified. |
| P1, direct files and MSG_RING qualified | Direct OPENAT/OPENAT2/SOCKET/ACCEPT, allocation ranges, OPENAT/OPENAT2 preparation ordering, and MSG_RING DATA/SEND_FD variants are gated. Remaining opcode-specific reserved fields still need a complete matrix | Preserve direct-file rollback and MSG_RING lifetime, transfer, publication-order, error-domain, and side-effect-free rejection coverage while auditing the remaining opcodes. |

## Then audit other implemented families

| Family | Confirmed gaps or requalification scope |
|---|---|
| `preadv2` / `pwritev2` | NOWAIT, ATOMIC and DONTCACHE reject. NOSIGNAL is mapped across direct vectored I/O, io_uring, shared squeue and legacy AIO. The RWF batch below qualifies shared SYNC/DSYNC and APPEND/NOAPPEND behavior on ZFS, tmpfs and memfd; HIPRI remains a direct-syscall hint and is rejected on non-polling rings. Continue unsupported-mode and errno-precedence work separately. |
| `fallocate` | KEEP_SIZE alone, ZERO_RANGE, COLLAPSE_RANGE, INSERT_RANGE, UNSHARE_RANGE and WRITE_ZEROES reject. Add filesystem support only with ZFS size/data/hole and rollback tests. |
| `openat2` / open / `fcntl` / memfd | CACHED always returns EAGAIN; O_TMPFILE and execution sealing remain unsupported. Extend the existing path/lock/seal matrix to indirect io_uring entry points. Include SQE close versus OFD last-close lifetime. |
| `ptrace` | SETREGSET, additional register sets, seize/event operations and option combinations need work. Reproduce arm64 register-conversion findings: missing LR assignment and syscall-info IP taken from LR rather than ELR. |
| futex/futex2 | PI requeue and NUMA/memory-policy options remain rejected. Track word-size and architecture restrictions against the pinned Linux implementation rather than treating every rejection as a bug. |
| `prctl`, sockets, mmap/mremap, mount, ioctl and remaining implemented handlers | Continue the option-by-option source audit. Some older GAP rows are already implemented (for example GET_AUXV and MDWE); separate missing implementation, deliberate rejection and missing test evidence. |

## Execution order and required evidence

1. Import current native squeue and Linux io_uring suites into the ZFS-root
   dual-architecture gate, with explicit case inventories. Record existing
   failures without relaxing assertions to make the baseline green.
2. Add focused Linux-reference reproductions for the P0 findings, then fix the
   shared mechanisms and ABI translations with native and Linux regression
   tests. Exercise this batch's seals and pathname constraints through SQEs.
3. Implement the highest-value setup/register/enter options in dependency order.
   Each option gets independent success, rejection, fault, permission,
   lifetime, concurrency and rollback cases, plus meaningful combinations.
4. Expand the audit across both syscall tables, assigning every implemented
   handler an option inventory and coverage status. Preserve the larger
   pending-syscall backlog; this phase supplements it.

Ring ownership, request lifetime, scheduling, registration, limits and readiness
belong in shared squeue/native facilities. Linux syscall numbers, structures,
flag/errno translation and Linux policy belong in Linuxulator. Native and Linux
PROBE/feature outputs must describe what their respective front ends can do.
A syscall number, header definition, accepted flag or passing one-shot operation
is never sufficient evidence for an entire option family.


## First implementation batch: VM results

`NO_SQARRAY` now has shared-engine implementation: no submission-index array
is allocated, its reported offset is zero, and submissions use the masked ring
head as the SQE index. Native and Linux front ends use the same code. The
engine rejects unknown SQE bits and nonzero unregistered personalities before
inline, worker or asynchronous issue, and pairs acquire/release operations
for SQ/CQ publication and consumption. Linux's invalid mmap-offset errno is
front-end policy; native BSD retains its own rejection errno.

The dual-ABI `squeue_options.c` suite covers mode combinations, queue wrap,
legacy indirection, setup/mapping faults, actual I/O, invalid requests without
writes, linked failure, descriptor churn, fork lifetime and a concurrent
producer completing 4096 submissions in each layout. All nine portable groups
passed Linux 6.18.35 (`options-linux-reference7.console.log`). A tenth group
checks ZFS reservation-allocation rejection without changing data or size;
the successful allocation case runs on tmpfs. ZFS VOP_ALLOCATE remains
unsupported.

`options-run5/results.json` passed **738 case runs on each architecture** in
ZFS-root QEMU guests, plus three amd64 regression binaries. This includes all
270 older Linux io_uring groups (now ported to arm64), three native squeue runs
and 60 new option runs per architecture. Both guests shut down successfully,
reported healthy ZFS pools and had no detected kernel faults or lock-order
reports. Source/build evidence is `options-final-*` under
`/tmp/linuxulator-gate-20260917`; the mandatory gate document records earlier
failed attempts and their disposition, including one unresolved historical
pathname-race timeout. These results certify the named assertions only.

At the end of that batch, registered-buffer pinning, RWF/ioprio semantics,
link timeouts and native PROBE accuracy still needed P0 fixes. The following
batches resolve PROBE and the named RWF and registered-buffer contracts; the remaining items still
precede additional setup, enter and registration modes. General thread helpers in `linux_test.h` remain amd64-only;
the arm64 io_uring port uses fork-like clone and does not depend on them.


## PROBE batch: VM results

Both amd64 and arm64 ZFS-root baseline VMs reproduced native over-advertisement
and acceptance of nonzero probe input (`probe-baseline-run/results.json`).
The shared engine now advertises its 27 core dispatch operations and asks the
front end for extension availability; Linux contributes its 35 extension
operations. The shared wire-protocol checks reject null arguments, counts
above 256 and any nonzero byte in the effective input buffer before copyout.
This matches the [Linux v6.18 registration implementation](https://github.com/torvalds/linux/blob/v6.18/io_uring/register.c).

Seven dual-ABI test groups add 42 case runs per architecture. They cover the
complete local opcode inventory, actual native rejection/Linux execution,
output bounds, all nonzero input bytes, fault and permission paths, descriptor
and fork lifetime, Capsicum and concurrent queries/submissions. Six portable
PROBE groups plus the preceding nine portable option groups passed Linux
6.18.35 (`probe-linux-reference1.console.log`). The expanded gate passed **780 case runs on each architecture**, plus three
amd64 regressions (`probe-run1/results.json`). Both ZFS-root guests shut down
successfully with healthy pools and no detected kernel faults or lock-order
reports. Immutable source/build evidence is `probe-final-*` under
`/tmp/linuxulator-gate-20260917`. This fixes dispatch advertisement;
known per-opcode semantic gaps, including link-timeout behavior, remain open.

## RWF batch: VM and crash/reboot results

Shared BSD file-operation flags now express per-write SYNC, DSYNC, APPEND and
NOAPPEND. Vnode writes apply sync policy in VOP_WRITE, using the same held file
reference as the transfer; direct Linux pwritev2 no longer performs a second
fd lookup for fsync. Append writes take the full vnode range lock, and shared
memory/memfd append selects EOF under its range lock. Neither per-operation
append policy changes descriptor flags. Memfd growth/write seals remain enforced.

Linux raw flag decoding belongs to Linuxulator and supplies the ring's decoding
callback. Native rings decode their public wire flags separately. The engine
validates before worker offload or provided-buffer consumption and carries the
translated policy through flat, vectored, fixed-buffer and registered-file I/O.
Worker errors after partial transfers no longer hide hard failures such as EIO.
Fast-poll readiness now derives from the opcode instead of overwriting the
SQE union containing the original RWF or socket flags.
The new filesystem-unmount check also exposed an existing registered-file
reference leak: the temporary file hold now drops after successful finstall.

NOWAIT, ATOMIC and DONTCACHE still reject with EOPNOTSUPP. NOSIGNAL now
suppresses SIGPIPE for pipe and socket writes across direct, io_uring, shared
squeue and legacy AIO paths, and is accepted as a no-op for reads. DONTCACHE
was incorrectly treated as an unconditional hint by direct vectored I/O; the
pinned Linux implementation requires filesystem support. HIPRI remains a direct
syscall hint, but rings reject it with EINVAL until IOPOLL exists. APPEND combined
with NOAPPEND returns EINVAL. References: [Linux v6.18 flag validation](https://github.com/torvalds/linux/blob/v6.18/include/linux/fs.h)
and [ring I/O](https://github.com/torvalds/linux/blob/v6.18/io_uring/rw.c).

Twelve new groups cover flag/operation combinations, unknown bits, unchanged
contents and offsets on rejection, append-open descriptors, faults, linked
failure, fixed-file lifetime, concurrent append, worker descriptor reuse, readiness retries and
memfd seals. They run through both APIs on ZFS and tmpfs, three times on each
architecture. Six direct-syscall regression runs bring the expanded normal gate
to **930 case runs per architecture**, plus three existing amd64 regressions.
A separate private-overlay crash/reboot gate checks 28 synchronous writes per
architecture through native rings, Linux rings and direct Linux pwritev2.
**Both gates passed.** `rwf-run7/results.json` records all 930 case runs on
each architecture, plus three amd64 regressions. Both guests shut down cleanly
with healthy ZFS pools and no detected kernel faults or lock-order reports.
`rwf-durability-run3/results.json` records abrupt QEMU termination followed by
successful reboot and verification of all 28 files on each architecture.
Source/build evidence is frozen as `rwf-final-*` under
`/tmp/linuxulator-gate-20260917`.

The raw-descriptor reuse stress is a BSD worker lifetime invariant, not a
portable Linux contract: Linux may acquire forced-async file references later
in its worker. [Linux v6.18 dispatch](https://github.com/torvalds/linux/blob/v6.18/io_uring/io_uring.c)
shows this delayed lookup. Keep this test and the unsupported-option matrix
separate from the ten portable RWF groups; do not weaken their BSD assertions
to accommodate a reference-platform difference. Linux-reference run 3 passed
those nine groups, and failed the original raw-fd reuse assertion. The final
reference run (`rwf-linux-reference5.console.log`) passed all ten portable RWF
groups, including the new retry group, and the preceding 15 portable option
groups: **25 groups passed**.

At the end of the RWF batch, registered-buffer pinning/range/lifetime enforcement
remained open; the next batch below qualifies its named contracts. Remaining
work includes linked deadlines, per-opcode ioprio and reserved-field validation, and the setup,
enter and registration backlog above. These tests do not certify every errno
precedence combination or unimplemented per-operation policy. QEMU crash tests
exercise the guest's persistence path, not physical-device power-loss behavior.


### Registered-buffer batch: VM results

Shared squeue now owns held pages, bounded kernel aliases, request references
and complete fixed-vector bounds checks. Shared VM changes preserve the
registration across munmap/remap and private fork without redirecting I/O.
Fifteen buffer groups extend the two-architecture ZFS-root gate to **1110
passing runs per architecture**, plus three amd64 regressions, in
`buffers-run4/results.json`. Both APIs run each new group three times on ZFS
and tmpfs; wired-page counts return to zero and both guests shut down with
healthy pools and no detected kernel faults. The matching crash/reboot run,
`buffers-durability-run1/results.json`, verifies all 28 files per architecture.
The final Linux reference passes 39 portable groups and three corrected older
fixed-buffer regressions. Evidence is frozen as `buffers-final-*` under
`/tmp/linuxulator-gate-20260917`.

See the registered-buffer section of [the implementation gate](linuxulator-implementation-gate.md)
for retained failures, exact acceptance requirements and limits: owner-vmspace
retention, conservative overlap charges, 1024 slots, privileged MEMLOCK policy,
remaining ring-backing/RACCT accounting and newer registration variants.
Linked deadlines and cancellation races are next, before additional setup,
enter and registration modes.


### Linked deadlines and cancellation: VM results

The current batch implements linked-deadline preparation, predecessor-relative
arming, identity-based cancellation, soft/hard link propagation, user_data
cancel-all counts, queued-work removal and active-worker ownership in shared
BSD squeue. It also fixes private-kqueue process-exit cleanup. Linux numbering,
structures and errno translation stay in Linuxulator. Twenty groups cover the
new contracts through both APIs on amd64 and arm64. `links-run4/results.json`
passes **1350 cases per architecture**, plus three amd64 regressions, with zero
retained requests/pages and healthy ZFS pools. `links-durability-run1/results.json`
passes crash/reboot verification of 28 files per architecture. The final Linux
reference passes 58 portable groups and eight older regressions. Exact source,
build inputs and retained failures are frozen as `links-final-*` under
`/tmp/linuxulator-gate-20260917`; see the implementation gate for contract limits.

The following batch adds SUBMIT_ALL, SINGLE_ISSUER,
and disabled-ring/restriction/enable lifecycle. Cancellation FD/ANY/opcode
matching, synchronous cancellation, timeout updates and resource-update/tag
variants remain separate work. Absolute realtime clock changes after arming
and suspend/resume behavior remain unqualified.


### Setup, issuer and restriction batch

Shared BSD squeue now implements disabled/enable state, transactional operation
and registration restrictions, stable thread ownership and the named SUBMIT_ALL
submission boundaries. Linuxulator maps invalid state to Linux EBADFD; native
calls return EBADF. Twenty-two new groups test both front ends, including real
threads, fork/exec/owner death, races, rollback and negative SQE/registration
cases. The mandatory inventory is 86 option groups and 1614 total runs per
architecture, plus three amd64 regressions. Both architecture gates pass in `setup-run2/results.json`, with zero retained
issuer identities/references, requests and wired pages. Matching crash/reboot
checks verify 28 files per architecture in `setup-durability-run1/results.json`.
The final Linux reference passes 80 portable groups and 11 older regressions.
Evidence is frozen as `setup-final-*` under `/tmp/linuxulator-gate-20260917`.

The next review should finish per-opcode preparation, reserved-field and ioprio
validation before expanding cancellation matching or resource variants.
The registered-file findings from this review are addressed in the following
batch, with old-kernel panic and leak reproductions retained as evidence. The
current SUBMIT_ALL matrix covers common opcode/flag/personality/restriction
failures and timeout preparation; it does not certify every per-opcode input
import or errno-precedence combination. See the contract table in
[the implementation gate](linuxulator-implementation-gate.md).


### Registered-file lifetime and update batch

Shared BSD changes reject ring references in registered-file tables, serialize
SQE updates with table removal, and copy captured Capsicum ioctl limits under
a sleepable lock. Updates implement SKIP, per-entry partial progress and the
Linux distinction between failed descriptor lookup and failed input copying.
FILES_UPDATE field validation now participates in submission preparation.

Twelve new groups extend the mandatory gate to 98 option groups and 1758 cases
per architecture, plus three amd64 regressions. Old kernels reproduce reference
leaks, allocation-under-mutex warnings and update/unregister panics on both
architectures. `files-run1/results.json` passes both architectures with zero
retained file references, issuer state, requests or wired pages.
`files-durability-run1/results.json` passes abrupt-stop/reboot verification of
28 files per architecture. The Linux reference passes 91 portable groups and
11 retained regressions. Evidence is frozen as `files-final-*` under
`/tmp/linuxulator-gate-20260917`.

Per-opcode reserved-field/ioprio validation remains next. New resource tags/v2
registration, automatic allocation and direct-file outputs remain separate work;
this batch does not certify their lifetime or accounting contracts.


## Network ioprio and legacy bundle batch

Linux-specific preparation owns the ioprio masks and incompatible-mode rules
for SEND, SENDMSG, SEND_ZC, SENDMSG_ZC, RECV, RECVMSG and ACCEPT. Shared squeue
owns readiness retry, per-CQE multishot accounting, provided-buffer selection
and rollback, fixed-buffer mapping, and atomic contiguous buffer-batch detach
and return. The Linux front end adds `IORING_FEAT_RECVSEND_BUNDLE`; native
squeue does not advertise that Linux-only policy bit.

The mandatory focused cases are `setup_features`, `ioprio_send_bundle`,
`ioprio_recv_bundle`, `ioprio_recv_bundle_limit`,
`ioprio_recv_bundle_multishot`, `ioprio_bundle_retry_reuse` and
`ioprio_bundle_invalid`. They supplement the earlier POLL_FIRST, ACCEPT,
RECV/RECVMSG multishot, vector/fixed SEND and SEND_ZC notification cases.
Every case must pass in fresh amd64 and arm64 ZFS-root QEMU guests with zero
live request, file, issuer and wired-page counters. The complete 301-case
inventory and crash/reboot gate are mandatory before final qualification.

Linux 6.18 accepts `IORING_RECVSEND_BUNDLE` without
`IOSQE_BUFFER_SELECT`; a SEND can then repeat the same ordinary buffer as a
multishot operation. This implementation rejects that malformed combination
with EINVAL. Positive bundle semantics and cancellation/reuse are still checked
against Linux 6.18; the deliberate rejection is recorded separately instead of
weakening the BSD negative test.

This batch is qualified by `bundle-full-run3/results.json`: fresh ZFS-root
amd64 and arm64 guests pass all 301 Linux io_uring cases and all 642 repeated
native/Linux option cases. The totals are 1,846 named results on amd64 and
1,843 on arm64 because the existing three direct regression binaries are
amd64-only. Both architectures finish with zero live request, file, issuer and
wired-page counters, zero diagnostic findings, healthy pools and clean
shutdown. `bundle-durability-run1/results.json` passes abrupt-stop/reboot
verification on both architectures using the same final artifacts. The gate
also asserts on every setup that only the Linux frontend advertises the bundle
feature. Registered provided-buffer rings and their mmap/register lifecycle
remain the next buffer-delivery phase.


## Registered provided-buffer rings

`IORING_REGISTER_PBUF_RING`, `IORING_UNREGISTER_PBUF_RING`, and
`IORING_REGISTER_PBUF_STATUS` are implemented in the ABI-neutral squeue engine.
That placement is required because buffer selection, retry rollback, mmap object
lifetime, pinned-memory accounting, and close cleanup are shared with native
squeue. The Linux front end continues to own Linux-only network `ioprio` and
bundle validation.

The implemented contract covers kernel-allocated `IOU_PBUF_RING_MMAP` rings,
page-aligned user rings pinned to the registering process, power-of-two entry
validation, unique buffer-group ownership, acquire reads of the producer tail,
wraparound, deferred head advancement until successful completion, status
queries, busy-safe unregister, and complete teardown/accounting on ring close.
A legacy `PROVIDE_BUFFERS` group and a registered ring cannot share a group ID.
`IOU_PBUF_RING_INC` mutates the active descriptor's address and remaining
length after each successful transfer, preserves its buffer ID and head while
bytes remain above `min_left`, and sets `IORING_CQE_F_BUF_MORE`. Exhaustion or
the threshold retires the descriptor exactly once.

The mandatory cases are `pbuf_ring_mmap`, `pbuf_ring_user_wrap`,
`pbuf_ring_retry_cancel`, `pbuf_ring_incremental`,
`pbuf_ring_incremental_user`, `pbuf_ring_incremental_multishot`,
`pbuf_ring_incremental_bundle`, and `pbuf_ring_invalid`. They check mmap
and user-pinned consumption, CQE buffer IDs and payloads, status-head
advancement, ring wrap, partial descriptor mutation, exact and `min_left`
exhaustion, zero-byte retention, multishot reuse, busy unregister, cancellation,
remaining-range reuse, invalid flag combinations, legacy-group conflicts, and
registered-group rejection by `PROVIDE_BUFFERS`. The initial focused result is
`/tmp/linuxulator-gate-20260917/pbuf-recover-focus-results1.json`; the retry,
busy-unregister and cancellation extension is qualified by
`/tmp/linuxulator-gate-20260917/pbuf-life-results2.json`. Both pass on amd64
and arm64 with clean counters and healthy ZFS pools.

Final qualification is
`/tmp/linuxulator-gate-20260917/pbuf-full-run2/results.json`. Both ZFS-root QEMU
guests pass all 305 Linux io_uring cases, all 642 repeated native/Linux squeue
option executions, zero diagnostic failures, unchanged request/file/issuer and
wired-page counters, and healthy pools. The amd64 guest additionally passes its
three architecture-specific regressions. The matching crash gate is
`/tmp/linuxulator-gate-20260917/pbuf-durability-run2/results.json`; both guests
were terminated with exit `-9` during the write workload and then rebooted with
exit `0` and healthy ZFS verification.

The native/Linux shared-front-end case passes on both architectures in
`pbuf-shared-results3.json`.  The expanded amd64 complete gate in
`pbuf-full-run4/results.json` passes 305 Linux io_uring cases and 648 repeated
squeue option executions.  Future architecture-neutral phases require the
amd64 ZFS-root gate; arm64 is repeated only for changes to its ABI, syscall
tables, or machine-dependent paths.


## Incremental provided-buffer consumption

`IOU_PBUF_RING_INC` is implemented in shared squeue. Registration accepts
`min_left` only with incremental mode. Completion commits the actual byte
count, updates the active descriptor, emits `IORING_CQE_F_BUF_MORE` while it
remains reusable, and advances the head only on exhaustion or threshold
retirement. Batch SEND/RECV commits use the same byte-based mechanism.

The shared case `pbuf_ring_incremental_shared` runs three times through both
native squeue and Linux io_uring. Linux cases `pbuf_ring_incremental`,
`pbuf_ring_incremental_user`, `pbuf_ring_incremental_multishot`, and
`pbuf_ring_incremental_bundle` cover partial and threshold exhaustion,
zero-byte retention, status queries, readiness parking, busy unregister,
multiple CQEs with one buffer ID, cancellation after partial progress, remaining
range reuse, and cleanup. Final evidence is
`/tmp/linuxulator-gate-20260917/pbuf-inc-full-run3/results.json`: the amd64
ZFS-root guest passes 309 Linux io_uring cases, 654 repeated shared-option
executions, three native squeue runs and all surrounding regressions, with zero
diagnostic findings and unchanged request, file, issuer and wired-page counters.
The guest shuts down cleanly with a healthy ZFS pool.

The later SQPOLL combination is qualified separately: a blocked selected read
canceled after partial incremental progress leaves its remaining range and
buffer ID available for a subsequent read. The named native/Linux case and
amd64 ZFS-root VM result are recorded in
[the SQPOLL gate](linuxulator-sqpoll.md).


## Extended `IORING_OP_ASYNC_CANCEL` match modes

The shared squeue matcher supports `ALL`, `FD`, `ANY`, `FD_FIXED`, `USERDATA`
and `OP`.  It compares retained open-file identities rather than descriptor
numbers, resolves fixed targets through the registered-file table, treats ANY
as an all-request selection, and composes FD or opcode criteria with explicit
user data.  Linux validation rejects unknown bits, ANY combined with FD or OP,
out-of-range opcodes and invalid normal or fixed descriptors without affecting
other requests.

The Linux cases are `cancel_fd_identity`, `cancel_fd_all`, `cancel_any`,
`cancel_op`, `cancel_fd_userdata`, `cancel_fd_fixed`, and the expanded
`cancel_badflag`.  They include duplicate and closed descriptors, both fixed-fd
encodings, match counts, unrelated requests, cleanup, and negative validation.
`cancel_modes_shared` runs the reusable mechanism three times through each
frontend.  Final evidence is
`/tmp/linuxulator-gate-20260917/cancel-full-run6/results.json`: the amd64
ZFS-root gate passes 315 io_uring cases and 660 shared-option executions with
clean accounting, diagnostics and pool health.  Arm64 is not repeated because
this phase is architecture-neutral.


### Poll and timeout update modes

The shared squeue engine now implements Linux 6.18 poll update and timeout
update semantics.  `POLL_REMOVE` can replace the target user data, event mask,
or both, and can promote a one-shot poll to multishot.  Update preserves the
outstanding target instead of completing it.  `TIMEOUT` supports finite and
unbounded multishot operation, while `TIMEOUT_REMOVE` updates regular and linked
timeouts using relative or absolute deadlines.  The Linux frontend owns Linux
SQE flag decoding and errno translation; request lookup, kqueue rearming,
callout rearming, multishot accounting, and CQE `F_MORE` behavior are shared.

The Linux-specific suite adds `poll_update_userdata`, `poll_update_events`,
`poll_update_combined`, `poll_update_invalid`, `timeout_multishot_finite`,
`timeout_multishot_cancel`, `timeout_update`, `timeout_update_absolute`,
`link_timeout_update`, and `timeout_update_invalid`.  The shared groups
`poll_update_shared` and `timeout_modes_shared` repeat the core behavior through
both native squeue and Linux io_uring.  Negative coverage includes unknown and
incomplete update flags, missing targets, invalid event masks and timespecs,
and proof that rejected updates leave their target usable.  The mandatory gate
now requires 325 Linux io_uring cases and 672 repeated shared-option executions.
Final evidence is `/tmp/linuxulator-gate-20260917/polltimeout-full-run1/results.json`: all 325 Linux cases, 672 shared-option executions, three native runs, resource counters, diagnostics, and ZFS health passed. This work is architecture-neutral, so qualification uses the amd64 ZFS-root VM.


### Synchronous registration cancellation

`IORING_REGISTER_SYNC_CANCEL` now uses the shared cancellation matcher for user
data, `ALL`, `ANY`, file identity, fixed-file slots, explicit user data, and
opcode selection.  The LP64 registration structure is part of the common ring contract, while the
Linux timeout errno is translated at the Linux frontend boundary. Shared squeue
owns lookup, cancellation,
worker-completion waiting, wakeups, and retained file references.  The native
registration API exposes the same shared operation with BSD errno values.

Linux cases cover user-data, match counts, ANY, FD and opcode selection, fixed
slots after numeric-fd close, bad pointers and counts, every reserved region,
unknown flags, invalid descriptors, missing targets, and preservation of an
unrelated request after rejected calls.  `sync_cancel_shared` repeats the core
contract through native and Linux ABI.  The mandatory inventory is now 330
Linux io_uring cases and 678 repeated shared-option executions.
Final evidence is `/tmp/linuxulator-gate-20260917/synccancel-full-run1/results.json`; the amd64 ZFS-root gate passed completely with clean accounting and diagnostics.


### Registered-file allocation ranges and direct descriptors

`IORING_REGISTER_FILE_ALLOC_RANGE` and automatic direct-descriptor allocation
are owned by shared squeue: the engine validates the range, serializes table
lifetime, scans and wraps within the configured window, replaces explicit
one-based slots, retains file capabilities, closes the transient descriptor on
every outcome, and returns the zero-based allocated slot. Linux `OPENAT`,
`OPENAT2`, `SOCKET`, and `ACCEPT` retain Linux path, flag, sockaddr and errno
translation in the Linuxulator frontend and hand successful descriptors to the
shared installer. Multishot direct ACCEPT remains rejected because one SQE
cannot safely name multiple direct slots through the current Linux encoding.

The Linux cases `file_alloc_range_invalid`, `open_direct_alloc_range`,
`open_socket_direct_explicit`, `openat2_direct`, and `accept_direct` cover absent
and sparse tables, zero and bounded windows, overflow/reserved/OOB inputs, scan
wrap and exhaustion, replacement, failed-open rollback, fixed-fd recovery,
bidirectional accepted-socket I/O, multishot rejection before connection
consumption, accepted-fd cleanup on a full table, and listener recovery.
`file_alloc_range_shared` repeats range validation through native squeue and
Linux io_uring. Focused amd64 ZFS-root evidence is
`/tmp/linuxulator-gate-20260917/direct-focus-images3/amd64.img`; all seven runs
passed with unchanged request, registered-file and wired-page counts and a
healthy pool. The mandatory inventory is now 335 Linux cases and 684 repeated
shared-option executions.

### MSG_RING DATA and SEND_FD variants

MSG_RING target publication and fixed-file transfer are shared squeue
operations. DATA supports same- and cross-ring delivery and exact FLAGS_PASS
CQE flags. SEND_FD retains the source registration while installing a held
file reference and copied capability rights into an explicit or automatically
allocated target slot; CQE_SKIP suppresses its target notification. Source and
target file-table locks are not held together. The Linux frontend supplies the
Linux-only EBADFD result for non-ring and disabled targets.

The `msg_ring_shared` matrix covers successful delivery and transfer, source
and destination lifetime, explicit replacement, range allocation/exhaustion,
notification suppression, both errno domains, invalid commands, fields, flags,
descriptors and tables, failure rollback, target preservation, and resource
cleanup. Focused evidence is
`/tmp/linuxulator-gate-20260917/msg-ring-focus-images1/amd64.img`. Full evidence
is `/tmp/linuxulator-gate-20260917/msg-ring-full-run1/results.json`: 337 Linux
io_uring cases and 690 repeated shared-option executions passed with clean
resource counters, diagnostics, shutdown and ZFS health. The next option phase
is the remaining per-opcode reserved-field audit.

### NOP options

NOP option handling belongs to shared squeue. INJECT_RESULT, FILE, FIXED_FILE,
FIXED_BUFFER and TW are now implemented for both frontends, with CQE32 rejected
until 32-byte completion queues are supported. The negative matrix verifies
preparation ordering, empty and absent registrations, descriptor and buffer
lifetime, signed result injection, combined flags and cleanup. Focused evidence
is `/tmp/linuxulator-gate-20260917/nop-focus-images2/amd64.img`; complete
evidence is `/tmp/linuxulator-gate-20260917/nop-full-run2/results.json`, with
337 Linux io_uring cases and 696 repeated shared-option executions passing on
an amd64 ZFS-root VM.

### FIXED_FD_INSTALL flags

FIXED_FD_INSTALL now creates close-on-exec descriptors by default and honors
`IORING_FIXED_FD_NO_CLOEXEC`, while rejecting all unknown bits before slot
lookup. The shared native/Linux test covers both flag states, retained source
lifetime, invalid and absent tables, preparation precedence, repeated install
and close cycles, rights-preserving source ownership, and cleanup. Focused
evidence is
`/tmp/linuxulator-gate-20260917/fixed-install-focus-images2/amd64.img`; full
evidence is
`/tmp/linuxulator-gate-20260917/fixed-install-full-run1/results.json`, with 337
Linux io_uring cases and 702 repeated shared-option executions passing in the
amd64 ZFS-root VM.


### PIPE direct-file output

`IORING_OP_PIPE` supports ordinary descriptor output and direct installation of
both ends into the shared registered-file table. Shared squeue owns consecutive
slot allocation, explicit replacement, retained file capabilities and cleanup;
the Linux frontend owns Linux pipe flags and errno translation. The Linux 6.18
sequential failure rule is preserved: if the second installation or result
copyout fails, the newly installed ends are removed, and any slots whose prior
contents were already replaced remain empty.

The mandatory `pipe_direct` case covers automatic allocation ranges, explicit
one-based slots, returned zero-based indices, fixed-file data flow, nonblocking
behavior, exhaustion, boundary overflow, `O_CLOEXEC` rejection, bad output
memory, absent tables, exact post-failure slot state and resource cleanup.
Focused evidence is
`/tmp/linuxulator-gate-20260917/pipe-direct-focus-images3/amd64.img`; full
evidence is
`/tmp/linuxulator-gate-20260917/pipe-direct-full-run2/results.json`, with 338
Linux cases and 702 shared-option executions passing in an amd64 ZFS-root VM.


### Registered completion-wait clocks

Shared squeue implements `IORING_REGISTER_CLOCK` as per-ring state for absolute
`IORING_ENTER_EXT_ARG` waits. Linux clock-number translation remains in the
Linuxulator frontend; native squeue uses native `CLOCK_UPTIME` and
`CLOCK_MONOTONIC` IDs. The common engine converts each absolute deadline to its
uptime callout deadline when the wait begins. Relative waits and timeout SQEs
do not consume this registration.

The mandatory `register_clock_shared` group checks both accepted clocks, timed
absolute waits, replacement, disabled-ring use, all reserved words, invalid
clock IDs, count and pointer validation, guard-page and read-only inputs, ring
progress and cleanup through both APIs. Focused evidence is
`/tmp/linuxulator-gate-20260917/clock-focus-images1/amd64.img`; full evidence is
`/tmp/linuxulator-gate-20260917/clock-full-run1/results.json`, with 338 Linux
cases and 708 repeated shared-option executions passing in an amd64 ZFS-root
VM.


### Asynchronous eventfd registration

`IORING_REGISTER_EVENTFD_ASYNC` is shared squeue state because both frontends
use the same completion and worker machinery. Ordinary registration signals
when a CQE becomes visible. Async registration suppresses inline-CQE signals
and instead signals when a file-I/O worker moves resolved work to the ready
queue, matching Linux's io-wq/task-work boundary; the owner publishes the CQE
on its next enter. `IORING_CQ_EVENTFD_DISABLED` suppresses both modes.

The mandatory `eventfd_async_shared` group covers inline silence, worker
notification and CQE delivery, dynamic notification disable/enable, ordinary
mode, duplicate registration, exact argument/count validation, absent and
wrong descriptor types, guard-page and read-only inputs, malformed unregister
preservation, descriptor-close lifetime, disabled-ring registration, repeated
use and final ring health through both ABIs. Focused amd64 ZFS-root evidence is
`/tmp/linuxulator-gate-20260917/eventfd-focus-images1/amd64.img`. Full evidence
is `/tmp/linuxulator-gate-20260917/eventfd-full-run1/results.json`: 338 Linux
io_uring cases, 714 repeated shared-option executions, three native squeue
runs and four direct regressions passed with zero diagnostic findings, clean
resource counters, clean shutdown and a healthy ZFS pool. The change is
architecture-neutral, so no arm64 guest was run.


### Tagged registered-file generations

`IORING_REGISTER_FILES2` and `IORING_REGISTER_FILES_UPDATE2` are implemented in
the shared squeue engine. They provide exact 32-byte resource structures, sparse
file tables, optional 64-bit generation tags, sequential update progress and
Linux-compatible invalid-fd clearing. `IORING_FEAT_RSRC_TAGS` is advertised by
both frontends. A tag produces a zero-result auxiliary CQE only when the
detached generation's final reference retires; failed initial registration
produces no tag CQEs. Fixed-file `IOSQE_ASYNC` transfers now enter the shared
worker pool through a transient descriptor carrying the registration's captured
rights and keep the selected generation alive until completion.

The mandatory `files_v2_shared` group covers exact sizes, null and guard-page
pointers, read-only metadata, reserved fields, unknown flags, sparse and
oversized tables, ring and invalid descriptors, atomic initial failure, empty
slot tag rejection, duplicate registration, UPDATE2 overflow and bounds, bad
data and tag arrays, SKIP/clear tag rules, partial progress, invalid-fd slot
clearing, replacement/unregister CQEs, delayed tag release behind a blocked
fixed-file worker request, subsequent ring health and cleanup. Focused evidence
is `/tmp/linuxulator-gate-20260917/files2-focus-images4/amd64.console.log`. Full
evidence is `/tmp/linuxulator-gate-20260917/files2-full-run1/results.json`: all
338 Linux io_uring cases, 720 repeated shared-option executions, 78 repeated
tmpfs file-table executions, three native runs and four direct regressions
passed. Diagnostics were empty; request, registered-file and wired-page counters
returned to zero; shutdown was clean and the ZFS pool healthy. This shared
change is architecture-neutral, so no arm64 guest was run.

### Tagged registered-buffer generations

`IORING_REGISTER_BUFFERS2` and `IORING_REGISTER_BUFFERS_UPDATE` are implemented
in shared squeue. They provide sparse tables, optional 64-bit generation tags,
sequential update progress and immutable table snapshots. A tagged generation
produces a zero-result auxiliary CQE only when its final fixed-buffer request
retires; failed initial registration and ring teardown produce no tag CQEs.

The mandatory `buffers_v2_shared` group covers exact sizes, sparse rules,
tagged-empty rejection, null and inaccessible metadata, reserved and unknown
fields, count and arithmetic bounds, atomic initial failure, partial updates,
failing-slot preservation, immediate replacement/unregister CQEs, and delayed
release behind blocked worker I/O. Focused evidence is
`/tmp/linuxulator-gate-20260917/buffers2-focus-pass.console.log`. Full
evidence is `/tmp/linuxulator-gate-20260917/buffers2-full-run1/results.json`:
338 Linux io_uring cases, 726 shared-option executions, 96 tmpfs buffer
executions, 78 tmpfs file-table executions and four direct regressions passed,
with empty diagnostics, zero final resource counters, clean shutdown and a
healthy ZFS pool. The change is architecture-neutral, so no arm64 guest was
run.

### Registered ring descriptors and cloned buffers

`IORING_REGISTER_RING_FDS` and `IORING_UNREGISTER_RING_FDS` provide the Linux
16-slot task-local ring table in shared squeue. Registered indexes work with
`IORING_ENTER_REGISTERED_RING`, `IORING_REGISTER_USE_REGISTERED_RING` and
`IORING_REGISTER_SRC_REGISTERED`. Ordinary descriptor closure does not destroy
a registered ring, and task-exit cleanup defers file drops because OSD
destructors hold a non-sleepable lock.

`IORING_REGISTER_CLONE_BUFFERS` creates new untagged destination resource nodes
that share a refcounted pin/accounting backing with the source. Source tags
therefore retire independently of destination clones. Whole-table and sliced
clones, sparse entries, destination replacement, prefix preservation,
same-ring replacement and cross-ring concurrency use one global registration
transaction lock and one per-ring lock at a time.

The mandatory `clone_buffers_shared` group covers null, faulting, read-only and
reserved metadata; count, offset and arithmetic bounds; ordinary and registered
source lookup errors; empty and busy tables; automatic and explicit ring slots;
partial ring-fd operations and copyout rollback; registered enter/register;
closed-descriptor retention and self-unregister; full/sparse/sliced/self clones;
independent source/destination tags; replacement clearing; backing survival;
and concurrent opposite-direction cloning. Focused evidence is
`/tmp/linuxulator-gate-20260917/clone-focus-images3/amd64.console.log`. Full
evidence is `/tmp/linuxulator-gate-20260917/clone-full-run1/results.json`: 338
Linux io_uring cases, 732 shared-option executions, 102 tmpfs buffer executions,
78 tmpfs file-table executions, three native runs and four direct regressions
passed. Diagnostics were empty, every resource counter returned to zero,
shutdown was clean and the ZFS pool healthy. The implementation is
architecture-neutral, so no arm64 guest was run.

### Registered personalities

`IORING_REGISTER_PERSONALITY` and `IORING_UNREGISTER_PERSONALITY` are owned by
shared squeue because both native and Linux frontends submit into the same
request preparation, inline dispatch and worker paths. Registration captures a
held credential snapshot and returns a nonzero 16-bit identifier. Preparation
resolves that identifier and gives the request its own credential reference, so
a concurrent unregister cannot change already accepted work. Ring teardown and
process exit release remaining registrations.

The mandatory `personality_shared` group checks exact register/unregister
arguments, zero/unknown/out-of-range identifiers, distinct allocation, valid
and invalid SQE selection, unregister invalidation, a prepared blocked worker
request surviving unregister, repeated process exit with live registrations,
and a Linux privilege proof in which a root snapshot opens a mode-0600 file
after the submitter drops to uid 65534 while a direct open fails with EACCES.
Every case runs three times through native squeue and Linux io_uring. Full amd64
ZFS-root evidence is
`/tmp/linuxulator-gate-20260917/personality-full-run1/results.json`: 338 Linux
io_uring cases, 738 shared-option executions, 102 tmpfs buffer executions, 78
tmpfs file-table executions, three native runs and four direct regressions
passed. Diagnostics were empty, all tracked resource counters returned to zero,
shutdown was clean and the ZFS pool healthy. The implementation is
architecture-neutral, so no arm64 guest was run.


### Per-ring IOWQ policy

Shared squeue owns `IORING_REGISTER_IOWQ_AFF`,
`IORING_UNREGISTER_IOWQ_AFF` and `IORING_REGISTER_IOWQ_MAX_WORKERS` because
both frontends use the same worker pool. Each ring stores separate bounded and
unbounded admission limits. A zero input element queries that class without
changing it, and success copies the previous pair back, including Linux's
state-before-final-copyout behavior. The affinity command accepts a byte-sized
CPU bitmap, clamps oversized lengths to `cpuset_t`, and requires a nonempty
subset of the caller's allowed CPUs. Unregister is idempotent.

The global `kern.squeue.max_workers` tunable remains the hard pool-growth
ceiling. Per-ring limits control which queued request may enter an available
worker; they cannot create workers beyond the system-wide limit. Seekable file
work uses the bounded class, while pipes and sockets use the unbounded class.

The mandatory `iowq_controls_shared` group covers null, count, pointer,
read-only and cross-page faults; signed range and zero-element updates; prior
value copyout; copyout-fault state ordering; strict per-ring unbounded
serialization using two blocked pipes; empty, disallowed and oversized affinity
masks; constrained worker execution; repeated unregister; ring health and
resource cleanup. It runs three times through native squeue and Linux io_uring.
Focused evidence is
`/tmp/linuxulator-gate-20260917/iowq-focus-pass1.console.log`. Full amd64
ZFS-root evidence is
`/tmp/linuxulator-gate-20260917/iowq-full-run1/results.json`: 338 Linux
io_uring cases, 744 shared-option executions, 102 tmpfs buffer executions, 78
tmpfs file-table executions, three native runs and four direct regressions
passed. Diagnostics were empty, all tracked resource counters returned to zero,
shutdown was clean and the ZFS pool healthy. The implementation is
architecture-neutral, so no arm64 guest was run.


### Blind MSG_RING registration

Shared squeue implements `IORING_REGISTER_SEND_MSG_RING` before source-ring
lookup, matching Linux's blind `fd == -1` path. It accepts one flagless
`IORING_OP_MSG_RING` SQE and supports only `IORING_MSG_DATA`; SEND_FD still
requires an ordinary source ring. Target lookup, disabled-ring handling, CQE
flags and bounded overflow publication use the same shared machinery as the
submitted opcode.

The mandatory `register_msg_ring_shared` group covers null/count/pointer and
cross-page faults, read-only input, wrong opcode, SQE flags, personality, buffer
index, SEND_FD, source index, CQE_SKIP, target flag misuse, bad/regular/disabled
targets, the registered-ring opcode bit, ordinary data and FLAGS_PASS. It runs
three times through each frontend. Focused evidence is
`/tmp/linuxulator-gate-20260917/register-msg-focus-pass1.console.log`; full
amd64 ZFS-root evidence is
`/tmp/linuxulator-gate-20260917/register-msg-full-run1/results.json`: 338 Linux
io_uring cases, 750 shared-option executions, 102 buffer executions, 78
file-table executions, three native runs and four regressions passed with clean
resource counters, diagnostics, shutdown and ZFS health.


### NO_IOWAIT enter hint

Shared squeue accepts `IORING_ENTER_NO_IOWAIT`. The backend does not mark its
completion waits as Linux block-I/O waits, so accepting the hint gives the
requested accounting behavior without changing scheduling. SQ_WAKEUP and
SQ_WAIT remain rejected until SQPOLL exists. The mandatory
`enter_no_iowait_shared` group covers the hint alone, submission, GETEVENTS,
argument noninspection without a wait, composition with EXT_ARG and adjacent
unknown-bit rejection through both frontends. Focused evidence is
`/tmp/linuxulator-gate-20260917/noiowait-focus-pass1.console.log`; full amd64
ZFS-root evidence is `/tmp/linuxulator-gate-20260917/noiowait-full-run1/results.json`:
338 Linux io_uring cases and 756 shared-option executions passed with clean
resource counters, diagnostics, ZFS health and shutdown.


### Cooperative and deferred task running

Shared squeue admits `IORING_SETUP_COOP_TASKRUN`,
`IORING_SETUP_TASKRUN_FLAG` and `IORING_SETUP_DEFER_TASKRUN` with Linux's setup
dependencies. The existing ready list already defers worker-resolved work until
an entering owner runs it. TASKRUN_FLAG now publishes `IORING_SQ_TASKRUN` when
that list becomes nonempty and clears it only after the issuer drains it.

The expanded `setup_flags` group checks every valid combination, TASKRUN_FLAG
without COOP/DEFER, DEFER without SINGLE_ISSUER, exact returned flags, and a
deterministic blocked pipe worker that proves the flag's absent/present/cleared
transition. Focused evidence is
`/tmp/linuxulator-gate-20260917/taskrun-focus-pass1.console.log`; full amd64
ZFS-root evidence is `/tmp/linuxulator-gate-20260917/taskrun-full-run1/results.json`:
338 Linux cases and 756 shared-option executions passed with clean diagnostics,
resources, ZFS health and shutdown.


### Extended SQE and CQE layouts

Shared squeue supports `IORING_SETUP_SQE128` and `IORING_SETUP_CQE32` with
independent 128-byte submission and 32-byte completion strides. Standard
opcodes consume only the first SQE half. Ordinary CQEs explicitly zero their
extension, preventing stale kernel or prior-slot data disclosure. Allocation,
mmap bounds, wrap masks and wired-page accounting use the expanded sizes.

The mandatory `extended_layout_shared` group wraps 32 submissions through each
of SQE128, CQE32, their combination, and the combination with NO_SQARRAY. It
proves exact returned flags, preserved patterned SQE extensions, zero CQE
extensions, correct CQE contents, ring health and cleanup through both ABIs.
Focused evidence is `/tmp/linuxulator-gate-20260917/ext-layout-focus-pass1.console.log`;
final full evidence is `/tmp/linuxulator-gate-20260917/ext-layout-full-run2/results.json`:
338 Linux cases and 762 shared executions passed with clean diagnostics,
resources, ZFS health and shutdown.


### Mixed completion records

Shared squeue supports `IORING_SETUP_CQE_MIXED` with 16-byte ordinary records
and two-slot 32-byte records selected by `IORING_NOP_CQE32`. Mixed mode is
incompatible with fixed `CQE32` and requires at least two CQ slots. Large
records carry both 64-bit extension words, set `IORING_CQE_F_32`, and use a
zero `IORING_CQE_F_SKIP` padding record when the logical tail is the final
physical slot. Overflow retains the size and extension payload and publishes
the large record in order after userspace advances the head. Fixed `CQE32`
accepts the same NOP option without setting the mixed-width marker.

The mandatory `cqe_mixed_shared` group checks incompatible and undersized setup,
ordinary versus extended accounting, payload preservation, wrap padding,
overflow and recovery, fixed-CQE32 behavior, ring health and cleanup through
both frontends. Focused evidence is
`/tmp/linuxulator-gate-20260917/cqe-mixed-focus-pass3.console.log`; final full
evidence is `/tmp/linuxulator-gate-20260917/cqe-mixed-full-run4/results.json`:
338 Linux cases and 774 shared executions passed with clean diagnostics,
resources, ZFS health and shutdown. The later SQE_MIXED implementation and
its separate gate supersede this historical rejection.


### Submission-queue rewind mode

Shared squeue implements `IORING_SETUP_SQ_REWIND`, requiring NO_SQARRAY as on
Linux. Each enter consumes at most the ring capacity from SQE index zero, does
not inspect or publish SQ head/tail, and restarts at zero on the next enter.
Preparation-error stop and SUBMIT_ALL continuation retain their normal rules.

The mandatory `sq_rewind_shared` group checks the missing-NO_SQARRAY rejection,
exact returned flags, zero head/tail throughout, prefix submission, rewritten
prefix reuse, oversized-count clamping, ordinary preparation stop, SUBMIT_ALL
continuation, ring health and cleanup through both frontends. Focused evidence
is `/tmp/linuxulator-gate-20260917/rewind-focus-pass1.console.log`; full amd64
ZFS-root evidence is `/tmp/linuxulator-gate-20260917/rewind-full-run1/results.json`:
338 Linux cases and 768 shared-option executions passed with clean diagnostics,
resources, ZFS health and shutdown.

## Swap activation options after `swapoff` support

`swapon` now has a Linux wrapper that rejects unknown flag bits before path
lookup and privilege checks. `PREFER` and its priority field now feed the
shared swap pager's per-device priority and allocator, with Linux-reference,
focused native allocation and full amd64 ZFS-root VM gates. The remaining
semantic gap is `DISCARD`, `DISCARD_ONCE`, and `DISCARD_PAGES` on devices that
support trim: the wrapper currently accepts them but the native swap pager
does not apply the requested discard policy. Add native backend support and
negative/positive tests on a trim-capable disposable device before claiming
Linux-equivalent discard semantics.
See the [Linux swap flag definitions](https://github.com/torvalds/linux/blob/master/include/linux/swap.h)
and [swapon(2) contract](https://man7.org/linux/man-pages/man2/swapon.2.html).
A disposable second virtio disk now exists in the amd64 ZFS-root gate for
positive activation tests.

## io_uring WAITID remaining asynchronous contract (2026-09-19)

The direct Linuxulator `linux_waitid` path now has a VM-qualified exit/reap
lifecycle. The separate `waitid_pidfd` and `waitid_stop_continue` tests passed
the Linux 6.18.35 oracle and three focused ZFS/tmpfs candidate rounds; their full 348-case amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/waitid-both-full-gate/results.json`, with zero
diagnostics and final resource counts. These cases execute through the Linuxulator
front end and require no native squeue opcode.

This historical gap is closed by the asynchronous WAITID implementation and
377-case qualification recorded below. A living-child request is parked behind
a per-ring process-context pump; user-data/opcode/all cancellation, pidfd
identity, linked timeout, ring close and exit/cancel races resolve exactly once.
Shared squeue owns pending-request lifetime, CQE publication, cancellation and
teardown; Linuxulator owns Linux ID/options, pidfd resolution and siginfo ABI.

## io_uring EPOLL_WAIT readiness retry (2026-09-20)

`IORING_OP_EPOLL_WAIT` previously returned a zero CQE for an empty epoll set.
Linux keeps the request pending. The shared squeue fast-poll path now waits for
read readiness on the epoll fd and retries; Linuxulator returns an internal
EAGAIN on an empty zero-timeout probe and rejects reserved SQE fields. A Linux
6.18.35 oracle and 18 focused ZFS/tmpfs candidate executions passed for
deferred delivery, cancellation and four invalid fields. The 351-case full
amd64 ZFS-root gate passed with zero diagnostics and final resources. Fixed-file
readiness arming uses a held-file knote and passed the Linux oracle plus six
focused candidate runs. Ambient descriptor close/reuse snapshots the epoll
file and capability rights, then reissues against that file even after the
numeric descriptor is reused. It passed the Linux oracle plus six focused
ZFS/tmpfs candidate rounds. The 353-case full gate passed with zero diagnostics, final resources and a
clean shutdown. Cancellation after ambient descriptor
close/reuse passed the Linux oracle and six focused ZFS/tmpfs candidate runs,
and passed the 354-case full amd64 ZFS-root gate. A separate
16-iteration readiness/cancellation race case passed the Linux oracle and
96 focused candidate attempts across ZFS and tmpfs. It is now required in
the 355-case full amd64 ZFS-root gate, which passed with zero recognized
diagnostics and final resources.

## io_uring pending futex waits (2026-09-20)

`FUTEX_WAIT` and `FUTEX_WAITV` now use callback-backed umtx waiters and the
shared squeue external-request lifecycle. They leave the submitter and I/O
worker pool free while waiting. Linux 6.18.35 oracles covered wake,
cancellation, vector index, bitset selection, invalid preparation, external
wake, ring close, opcode/all cancellation, linked timeouts and races. The
369-case full amd64 ZFS-root gate passed with 918 squeue-option executions,
zero diagnostics/nonzero results and final resources of zero. Exact results
and hashes are in
`/tmp/linuxulator-gate-20260919/futex-async-final-gate/manifest.json`;
[the pending-futex gate](linuxulator-iouring-futex-pending.md) records the
contract.

## io_uring FUTEX/WAITID reserved SQE fields (2026-09-20)

Linux 6.18.35 rejects reserved fields in FUTEX_WAIT, FUTEX_WAKE, FUTEX_WAITV
and WAITID. The Linuxulator now validates them before delegating to the
existing syscall handlers. The WAITV EAGAIN test now uses Linux's required
zero `fd` field. Fifteen futex and four WAITID negative submissions passed
the Linux oracle and 42 focused ZFS/tmpfs candidate executions; the 357-case
full amd64 ZFS-root QEMU gate passed with zero recognized diagnostics and
final resources; its manifest is at
`/tmp/linuxulator-gate-20260919/futex-waitid-sqe-full-gate/manifest.json`.
This validates immediate errors. The later asynchronous futex and WAITID
sections qualify pending wake, cancellation and teardown behavior.


## io_uring asynchronous WAITID (2026-09-20)

Pending WAITID now uses one process-context pump per ring, started only when
a child wait actually remains pending. Shared squeue owns the lifecycle and
cancel/link result; Linuxulator owns waitid IDs, pidfds, options and siginfo.
The Linux 6.18.35 oracles and focused ZFS/tmpfs candidate runs cover exit,
user-data and opcode-wide cancellation, linked timeout, null siginfo, pidfd
close, ring close, and exit/cancel races, in addition to the existing
lifecycle/job-state negatives. The 377-case full amd64 ZFS-root gate passed
with 918 shared squeue-option, 39 NO_MMAP and 33 SQPOLL executions, zero
nonzero results or diagnostics, final resources of zero, healthy ZFS and
clean poweroff. Exact evidence and hashes are in
`/tmp/linuxulator-gate-20260919/waitid-race-full-gate/manifest.json` and
[the WAITID gate record](linuxulator-waitid-lifecycle.md).

## Remaining io_uring opcode scope

The local UAPI declares 65 concrete opcodes and source dispatch covers all 65.
`IORING_OP_RECV_ZC` has functional copied NODEV dispatch; socket `URING_CMD128`
uses the Linuxulator command path on SQE128 rings.
Opcode admission alone does not mean every flag or device command works.

`URING_CMD` now has a Linuxulator-only socket subset: queue queries for
IPv4/IPv6 sockets, `SETSOCKOPT` through the existing Linux socket translator,
and `GETSOCKOPT` for scalar `SOL_SOCKET` options. Unix sockets return
`EOPNOTSUPP` for queue queries, matching the Linux 6.18.35 oracle; unknown
socket commands and non-socket files also return `EOPNOTSUPP`. The shared
squeue engine supplies fixed-file resolution and normal CQE publication,
without a new native syscall. Its positive, negative, probe and negotiation
cases passed 54 focused ZFS/tmpfs executions, plus six dual-ABI probe
runs. The 383-case full amd64 ZFS-root gate passed with 918 shared option,
39 NO_MMAP and 33 SQPOLL executions, zero nonzero results or diagnostics,
zero final request/file/issuer counts and clean shutdown. Exact hashes and
results are in
`/tmp/linuxulator-gate-20260919/uring-cmd-full-gate383/manifest.json`.
Extend `GETSOCKOPT` to other translated `SOL_SOCKET` options; Linux's
socket command returns `EOPNOTSUPP` for other levels. `GETSOCKNAME`,
timestamps, fixed-buffer and multishot command semantics, and
individual device command ABIs only with matching Linux oracle and VM tests.
The Linux 6.18.35 oracle returns `EOPNOTSUPP` for socket `GETSOCKNAME`
and `EINVAL` for `URING_CMD128`. A separate Linux 7.1.5 QEMU oracle now
confirms socket `URING_CMD128` succeeds on an SQE128 ring, advertises in
PROBE, and rejects an ordinary SQE ring with `EINVAL`. The Linux 7.1.5
GETSOCKNAME oracle and its 393-case ZFS-root gate have since passed.

`RECV_ZC` hardware zero-copy depends on registered receive interface queues and packet
ownership. Linux v7.1 also defines a copied `ZCRX_REG_NODEV` fallback, which is
implemented and VM-qualified for the named first-phase contract; its ownership and mandatory oracle/VM matrix are
in [the ZCRX phase contract](linuxulator-iouring-zcrx.md). `SQE_MIXED` now consumes two contiguous 64-byte slots for NOP128 and
socket URING_CMD128. The Linux 7.1.5 oracle, including incomplete-pair,
physical-end, ordinary-ring and setup-conflict negatives, and the focused
ZFS/tmpfs native and Linux tests pass. The full amd64 ZFS-root
gate passed 394 io_uring and 924 shared-option executions with zero failures,
zero final resources, healthy ZFS and clean shutdown; see
`/tmp/linuxulator-gate-20260919/uring-cmd-full-gate396/manifest.json`.
The reference two-slot and physical-boundary rules are in
[Linux `io_init_req`](https://github.com/torvalds/linux/blob/master/io_uring/io_uring.c#L1615-L1654).

## io_uring socket URING_CMD structured options (2026-09-20)

`SO_LINGER` and `SO_RCVTIMEO_NEW`/`SO_SNDTIMEO_NEW` now use the same
Linux-to-native value translation as their direct socket calls, while
`URING_CMD` returns the copied byte count in the CQE. Linux 6.18.35 oracle
cases cover full and short result buffers, invalid user pointers and invalid
microseconds. The updated module and 385-case binary passed 66 focused
ZFS/tmpfs socket/probe executions plus six shared probe-scope executions.
The full 385-case amd64 ZFS-root gate passed with 918 shared squeue options,
39 NO_MMAP, 33 SQPOLL and 24 memory-region runs, zero nonzero results or
diagnostics, final resources zero and clean ZFS shutdown. Staged artifact
hashes are in `/tmp/linuxulator-gate-20260919/uring-cmd-full-gate385/manifest.json`.

The next socket command batch adds `TCP_NODELAY` through the existing generic
`SETSOCKOPT` path and a Linuxulator-only `SO_PASSCRED` getter for Unix
sockets. Linux 6.18.35 oracles and 78 focused ZFS/tmpfs socket/probe
executions plus six shared probe-scope executions passed, including wrong
level, truncated output and bad-pointer negatives. The full 387-case amd64 ZFS-root gate passed with 918 shared-option,
39 NO_MMAP, 33 SQPOLL and 24 memory-region runs; zero nonzero results,
diagnostics and final resources; healthy ZFS and clean shutdown. Its staged
artifact hashes are in `/tmp/linuxulator-gate-20260919/uring-cmd-full-gate387/manifest.json`.

`SO_PEERCRED` now translates the native Unix peer credentials for socket
`URING_CMD` GETSOCKOPT. The Linux 6.18.35 oracle confirms full and truncated
output, including the command-specific short-buffer behavior, plus a bad
pointer negative. The updated module passed 84 focused ZFS/tmpfs socket/probe
executions and six shared probe-scope executions. The 388-case full amd64 ZFS-root gate passed with 918 shared options,
39 NO_MMAP, 33 SQPOLL and 24 memory-region runs, zero nonzero results,
diagnostics and final resources, healthy ZFS and clean shutdown. Its staged
artifact hashes are in `/tmp/linuxulator-gate-20260919/uring-cmd-full-gate388/manifest.json`.

The next batch adds `SO_MAX_PACING_RATE` and four old/new timestamp
`GETSOCKOPT` variants through existing native socket options, plus the
Linuxulator-only socket `URING_CMD128` dispatch. Linux 6.18.35 pacing and
timestamp oracles, a Linux 7.1.5 command-128 oracle, 114 focused ZFS/tmpfs
io_uring executions and six dual-ABI probe runs passed. The full 392-case amd64 ZFS-root gate passed with 918 shared options,
39 NO_MMAP, 33 SQPOLL and 24 memory-region runs, zero nonzero results,
diagnostics and final resources, healthy ZFS and clean shutdown. Its
evidence is `/tmp/linuxulator-gate-20260919/uring-cmd-full-gate392/manifest.json`. `RECV_ZC` and its hardware-backed zcrx registration
remain outside this software-only socket command subset. The newer oracle uses
[Alpine's Linux 7.1.5 kernel package](https://dl-cdn.alpinelinux.org/alpine/edge/community/x86_64/linux-stable-7.1.5-r0.apk)
(SHA-256 `b541196292d50c94af213f24f9d6785547bb38941d6997c88e75b42b8fbf7fc3`)
with an isolated QEMU initramfs; its transcript is
`/tmp/linuxulator-gate-20260919/linux715/oracle-cmd128-final.console.log`.
The staged source and binary used for this oracle are pinned by the 392-case
gate manifest. No host kernel or module was loaded for this test.

## Newer socket GETSOCKNAME command (2026-09-20)

Linux 7.1.5 accepts socket command 5 with `sqe->addr` pointing to the
name buffer, `sqe->addr3` to its length, and `sqe->optlen` selecting local
(0) or peer (1). The Linuxulator dispatches to its existing sockaddr
translators. The Linux 7.1.5 QEMU oracle and 120 focused ZFS/tmpfs io_uring
executions plus six shared probe runs passed local and peer names,
truncation, bad length pointer, invalid peer selector, unexpected `ioprio`,
and unconnected peer negatives. The full 393-case ZFS-root gate passed with
918 shared-option executions, zero failures or diagnostics, healthy ZFS and
clean shutdown; see `uring-cmd-full-gate393/manifest.json`.

`SOCKET_URING_OP_TX_TIMESTAMP` remains unsupported: Linux requires a
multishot CQE32 timestamp stream backed by the socket's transmit error
queue; the native socket stack has no matching transmit timestamp queue.

## Provided-buffer ring receive bundles (2026-09-20)

Linux 7.1.5 consumed a 10-byte receive across three 4-byte registered
provided-buffer-ring entries in one `IORING_OP_RECV` bundle CQE, set the first
buffer ID, and advanced the ring head by three. The pinned oracle is
`/tmp/linuxulator-gate-20260919/linux715/oracle-recv-bundle-probe.console.log`.
[Linux 6.18 `io_recv`](https://github.com/torvalds/linux/blob/v6.18/io_uring/net.c)
selects an expandable buffer vector for bundled receives. The previous
Linuxulator helper limited receives to one descriptor even though shared
squeue could select and commit a batch. The Linuxulator now requests the
shared batch for both SEND and RECV; no native opcode or syscall ABI changed.

`pbuf_recv_bundle_multibuf` checks the exact data, first buffer ID, 10-byte
CQE result and head advancement. `pbuf_recv_bundle_empty_recover` checks
`ENOBUFS` with no buffer flag or head advance, preserves pending socket data,
then succeeds after a buffer is added. Both passed Linux 7.1.5, the latter at
`/tmp/linuxulator-gate-20260919/linux715/oracle-recv-bundle-empty-probe.console.log`.
The two new cases and three legacy bundle, length-bound and invalid-input
regressions passed three ZFS and three tmpfs rounds (30 executions) in the
disposable amd64 ZFS-root VM at
`/tmp/linuxulator-gate-20260919/recv-bundle-empty-focus.console.log`, with
zero tracked squeue resources, healthy ZFS and clean shutdown. A later multishot datagram probe exposed that a bundled multishot RECV must
keep one provided buffer per completion. Linux 7.1.5 passed that oracle at
`/tmp/linuxulator-gate-20260919/linux715/oracle-recv-bundle-mshot-probe.console.log`;
the 403-case snapshot expanded the batch only for single-shot receives; the
registered-ring follow-up below supersedes that policy.
The revised module passed seven cases across three ZFS and three tmpfs rounds
(42 focused executions), including multishot and cancellation/reuse, with
zero tracked resources, healthy ZFS and clean shutdown at
`/tmp/linuxulator-gate-20260919/recv-bundle-mshot-fix-focus.console.log`.
The 403-case full gate passed with 1086 shared-option, 39 NO_MMAP,
33 SQPOLL, 24 MEM_REGION and 57 AIO executions, zero failures or recognized
diagnostics, zero final tracked resources, healthy ZFS and clean shutdown;
see `recv-bundle-mshot-fix-final-full-gate/manifest.json`. This is a passed
historical snapshot; the current 404-case gate follows below.

The registered PBUF_RING multishot follow-up exposed a different Linux 7.1.5
contract from legacy provided buffers: two 6-byte datagrams each span two
4-byte ring entries, with first buffer IDs 820/822, a terminal second CQE and
head advance of four. The Linux-only helper now preserves multi-entry batches
for registered rings and returns surplus legacy buffers before each multishot
receive. The permanent `pbuf_recv_bundle_multishot` oracle passed at
`/tmp/linuxulator-gate-20260919/linux715/oracle-recv-bundle-pbuf-mshot4.console.log`.
The revised module passed 48 focused ZFS/tmpfs bundle executions with zero
tracked resources and clean shutdown at
`/tmp/linuxulator-gate-20260919/recv-bundle-pbuf-mshot-focus3.console.log`.
The first 404-case full gate was superseded during the shared-selector
concurrency review; its interrupted evidence is at
`/tmp/linuxulator-gate-20260919/recv-bundle-pbuf-mshot-final-full-gate/`.
The current 404-case gate is identified below.

Shared squeue now applies the one-descriptor legacy multishot limit during
batch selection under its group lock, avoiding a remove-and-return race with
another request. Linuxulator owns which limit to ask for. The rebuilt kernel
and matching modules passed the 48-case focused matrix at
`/tmp/linuxulator-gate-20260919/recv-bundle-atomic-focus.console.log`; the
404-case full gate passed with zero nonzero results, diagnostic failures,
tracked resources or ZFS faults; frozen evidence is in
`/tmp/linuxulator-gate-20260919/recv-bundle-atomic-final-full-gate/manifest.json`.


## Current io_uring timeout option

`IORING_TIMEOUT_IMMEDIATE_ARG` is implemented in shared squeue because both
native squeue and Linux io_uring use the same timer engine. Linuxulator keeps
the Linux SQE/errno ABI. Five positive/negative cases passed a Linux 7.1.5
oracle and a focused ZFS-root FreeBSD QEMU guest. The 408-case full gate also
passed with zero nonzero results, diagnostic failures or tracked resource
leaks, healthy ZFS and clean shutdown; see
`/tmp/linuxulator-gate-20260919/timeout-immediate-final-full-gate/manifest.json`.
The exact matrix and evidence are in
[linuxulator-implementation-gate.md](linuxulator-implementation-gate.md).


## Zero-copy send completion suppression

Linux 7.1.5 rejects `IOSQE_CQE_SKIP_SUCCESS` on SEND_ZC and SENDMSG_ZC.
The Linuxulator now rejects both before side effects; shared squeue needs no
change. Two oracle cases and 48 focused ZFS/tmpfs guest executions passed.
The full amd64 ZFS-root gate also passed all 410 general io_uring, 1,092
shared-option, 39 NO_MMAP, 33 SQPOLL, 24 MEM_REGION and 57 AIO executions,
with zero final resources, healthy ZFS and clean shutdown. The acceptance matrix is in
[linuxulator-implementation-gate.md](linuxulator-implementation-gate.md).


## io_uring read/write attribute validation (2026-09-21)

Linux 7.1 read/write attributes are no longer silently ignored. A zero mask
preserves Linux's ignored-pointer rule, unknown bits return `EINVAL`, and the
known protection-information request returns `EOPNOTSUPP` while
`IORING_FEAT_RW_ATTR` remains clear. All eight read/write opcodes share the
Linuxulator validation; native squeue remains unchanged until a real storage
metadata transport exists. The Linux 7.1.5 oracle and three-round amd64
ZFS-root focused gate passed the positive and negative matrix described in
[the RW-attribute audit](linuxulator-iouring-rw-attr.md).
The integrated 432-case amd64 ZFS-root full gate also passed with zero
failures, zero recognized diagnostics and zero final tracked resources.

## Read/write ioprio and write-stream batch (2026-09-21)

The read/write SQE audit found that Linux 7.1 validates block-I/O priority
before importing buffers. The Linuxulator now matches the NONE, realtime, BE,
IDLE and invalid-class rules across all eight read/write opcodes, including
the realtime privilege failure. Native squeue keeps valid priorities and
`write_stream` advisory because there is no native per-request block-priority
backend. Linux-only class numbering and privilege policy stay in
`linux_io_uring.c`.

The permanent positive, invalid-class opcode matrix and unprivileged cases
passed the Linux 7.1.5 oracle and the three-round amd64 ZFS-root focused gate.
They expand the mandatory io_uring inventory from 432 to 435 cases.

## Timeout reserved-field audit (completed 2026-09-21)

Linux 7.1 reserves `addr3` and the final padding word for `TIMEOUT`,
`TIMEOUT_REMOVE`/`TIMEOUT_UPDATE`, and `LINK_TIMEOUT`. The common preparation
mask now rejects them in shared squeue, before lookup or linked side effects.
Linux and native shared tests plus the Linux main test passed the Linux oracle,
focused VM, and the 436-case/1,098-option integrated amd64 ZFS-root gate.
Evidence is in `full6-run/manifest.json` under the current artifact directory.

## SEND_ZC notification `addr3` audit (completed 2026-09-21)

Linux 7.1 uses nonzero `sqe->addr3` as the notification CQE user data for
`SEND_ZC` and `SENDMSG_ZC`, falling back to primary user data when it is zero;
it reserves only the final padding word. The shared validation mask now
allows `addr3`, and Linuxulator selects the notification identity. Three new
positive/negative cases passed Linux 7.1.5 and a 27-execution focused amd64
ZFS-root matrix. The corrected native/Linux shared preparation case passed six
focused repetitions. The repeated integrated gate passed all 439 main and
1,098 shared-option executions with zero nonzero results, zero recognized
diagnostics, zero final tracked resources, healthy ZFS and clean shutdown.
Evidence is in `full8-run/manifest.json` under the current artifact directory.

## SEND_ZC execution-error pairing (completed 2026-09-21)

Linux 7.1 suppresses `SIGPIPE` internally and preserves the primary plus
notification CQE pair when a prepared zero-copy send returns `EPIPE`. The
Linuxulator now adds Linux `MSG_NOSIGNAL`, marks the negative primary CQE with
`F_MORE`, and posts the notification using the audited `addr3` identity.
A two-opcode Linux 7.1.5 oracle and 30-execution focused amd64 ZFS-root matrix
passed. The repeated integrated gate passed all 440 main and 1,098 shared-option
executions, every specialized suite at its expected count, zero nonzero results,
zero recognized diagnostics, zero final tracked resources, healthy ZFS and a
clean shutdown. Evidence is in `full9-run/manifest.json` under the current
artifact directory.


## SEND_ZC failed-send usage notification (completed 2026-09-21)

Linux 7.1.5 sets `IORING_NOTIF_USAGE_ZC_COPIED` in the notification CQE when
`REPORT_USAGE` is requested after either zero-copy send opcode reaches an
`EPIPE` execution failure. The Linuxulator already matches that policy. A new
two-opcode negative-path case passed the Linux oracle and a 51-execution
focused amd64 ZFS-root matrix. The repeated integrated gate passed all 441
main and 1,098 shared-option executions, every specialized suite, zero nonzero
results, zero diagnostics, zero final resources, healthy ZFS and clean
shutdown. Evidence is in `full10-run/manifest.json`. No shared squeue change
was needed.


## Vectorized fixed-buffer zero-copy sends (completed 2026-09-21)

Linux 7.1.5 supports `FIXED_BUF|VECTORIZED` for `SEND_ZC` and retains the
notification pair for fixed-buffer and fixed-SENDMSG import faults. Linuxulator
option decoding and the shared fixed-buffer adapter now implement that contract.
Three oracle cases and a 51-execution focused amd64 ZFS-root matrix passed.
The corrected integrated gate passed all 443 main and 1,098 shared-option
executions, every specialized suite, zero nonzero results, zero diagnostics,
zero final resources, healthy ZFS and clean shutdown. Evidence is in
`full11b-run/manifest.json`.


## Fixed SENDMSG_ZC iovec limit (completed 2026-09-21)

Linux 7.1.5 reports paired `EMSGSIZE` for fixed SENDMSG_ZC above `UIO_MAXIOV`;
the Linuxulator previously reported `EINVAL`. The errno is corrected, the
negative notification contract is permanent, and the fixed positive tests now
use TCP and cover SENDMSG's accepted vector flag. Oracle and focused gates
passed. The repeated integrated gate passed all 444 main and 1,098 shared-option
executions, every specialized suite, zero nonzero results, zero diagnostics,
zero final resources, healthy ZFS and clean shutdown. Evidence is in
`full12-run/manifest.json`.


## Fixed zero-vector zero-copy sends (completed 2026-09-22)

Linux 7.1.5 succeeds for empty fixed vectors once the registered table is valid,
for both zero-copy send opcodes. The Linux frontend now matches that completion
policy without weakening shared buffer-table validation. Linux oracle and 27
focused amd64 ZFS-root executions passed. The repeated integrated gate passed all 445 main and 1,098 shared-option
executions, every specialized suite, zero nonzero results, zero diagnostics,
zero final resources, healthy ZFS and clean shutdown. Evidence is in
`full13-run/manifest.json`.


## SENDMSG_ZC reserved destination/output fields (completed 2026-09-22)

Linux 7.1.5 rejects nonzero `addr2` or `file_index` on `SENDMSG_ZC` during
preparation. The Linux frontend now enforces both fields before message import
and socket execution; shared squeue needed no change. The Linux oracle,
pre-fix reproduction, three focused amd64 ZFS-root executions, and repeated
integrated gate passed. The final gate covered 446 main and 1,098 shared-option
executions plus every specialized suite, with zero nonzero results, zero
diagnostics, zero final resources, healthy ZFS, synced buffers and clean
shutdown. Evidence is in `full14b-run/manifest.json`.


## SEND_ZC address-length padding (completed 2026-09-22)

Linux 7.1.5 rejects the nonzero upper 16-bit padding beside `addr_len` for
`SEND_ZC`. The Linux frontend now enforces that preparation rule; shared
squeue needed no change. The Linux oracle, pre-fix reproduction, three focused
amd64 ZFS-root executions, and repeated integrated gate passed. The final gate
covered 447 main and 1,098 shared-option executions plus every specialized
suite, with zero nonzero results, zero diagnostics, zero final resources,
healthy ZFS, synced buffers and clean shutdown. Evidence is in
`full15-run/manifest.json`.

## Ordinary SEND/SENDMSG reserved fields (completed 2026-09-22)

Linux 7.1.5 rejects the upper `addr_len` padding word for ordinary `SEND` and
rejects `addr2` and `file_index` for ordinary `SENDMSG`. The Linux frontend now
enforces all three preparation rules; shared squeue needed no change. Two oracle
cases, six focused amd64 ZFS-root executions, and the repeated integrated gate
passed. The final gate covered 449 main and 1,098 shared-option executions plus
every specialized suite, with zero nonzero results, zero diagnostics, zero final
resources, healthy ZFS, synced buffers and clean shutdown. Evidence is in
`full16e-run/manifest.json` under the current artifact directory.

## RECV/RECVMSG reserved addr2 (completed 2026-09-22)

The Linux frontend now rejects reserved `addr2` on ordinary RECV and RECVMSG
before buffer import. Linux 7.1.5, six focused amd64 ZFS/tmpfs executions, and
the 450-case integrated ZFS-root gate passed with zero failures, diagnostics,
or leaked resources. Shared squeue needed no change. Evidence is in
`full17-run/manifest.json` under the current artifact directory.

## Direct network/open allocation and SEND_ZC test stabilization (completed 2026-09-22)

The Linux frontend now supports automatic fixed-file allocation for multishot
direct ACCEPT and enforces Linux CLOEXEC restrictions for direct SOCKET,
ACCEPT, OPENAT and OPENAT2 while preserving pathname and `open_how` error
precedence. Shared squeue needed no change. Linux 7.1.5 references, 12 focused
network executions, and six focused open executions passed across ZFS and
tmpfs.

The intermittent `ioprio_send_zc_fixed_vectorized` result was a test race:
candidate and baseline kernels each reproduced 11 immediate nonblocking
`EAGAIN` reads in 100 runs after both correct CQEs were already present. The
test now waits for peer readiness and keeps distinct CQE, readiness, length and
data failures. The exact final test passed 200/200 focused ZFS/tmpfs runs.

The integrated amd64 ZFS-root gate passed 453 main io_uring and 1,098
shared-option executions plus every specialized suite, with zero nonzero
results, diagnostics, or final tracked resources, healthy ZFS, synced buffers,
and clean poweroff. Evidence is in `full19b-run/manifest.json` under the current
artifact directory.

## Fixed-file CLOSE completed (2026-09-22)

`IORING_OP_CLOSE` now accepts Linux's one-based `file_index` direct-close form.
The implementation is in shared squeue because it operates on the shared
registered-file table, generation references, and tag completion mechanism.
Linux-specific errno and SQE-field behavior is covered by the Linux main test;
the larger lifetime and concurrency matrix runs through native and Linux entry
paths.

The final coverage includes missing, sparse, and out-of-range slots; every
reserved CLOSE field; invalid `fd` and `IOSQE_FIXED_FILE`; no-side-effect
rejection; double removal; ordinary close; immediate and delayed generation
tags; an in-flight fixed request; slot reuse; teardown; ZFS/tmpfs repetition;
and a Linux 6.18.35 oracle.  The full amd64 gate completed 454 main io_uring
cases and 1,104 shared-option executions with zero failures, leaks, or kernel
diagnostics.  The next option audit can proceed from the next incomplete
per-opcode option; fixed-file CLOSE is no longer backlog.

## io_uring `MADVISE` options completed (2026-09-22)

`IORING_OP_MADVISE` now matches Linux's 64-bit range contract: nonzero
`sqe->off` supplies the length and `sqe->len` remains the zero-`off` fallback.
Linux's no-file `IOSQE_FIXED_FILE` behavior is also implemented; the flag is
ignored without consulting the registered-file table.  Linux-only length
interpretation stays in the Linux frontend, while the fixed-file bypass uses
the shared dispatch mechanism under its Linux ABI condition.

The new cases cover observable multi-page length precedence and fallback,
arbitrary ignored descriptors, address alignment, advice validation, overflow,
reserved fields, ioprio, fixed-file handling, side-effect-free rejection, and
post-error recovery.  Linux 6.18.35 passed 50 oracle executions, the focused
candidate passed 100 ZFS/tmpfs executions, and the full amd64 ZFS-root gate
passed all 456 main and 1,104 shared-option executions with no failures, leaks,
or kernel diagnostics.  Continue with the next incomplete per-opcode option;
`MADVISE` SQE length and fixed-file semantics are no longer backlog.

## `SYNC_FILE_RANGE` options completed (2026-09-22)

Direct `sync_file_range` and `IORING_OP_SYNC_FILE_RANGE` now share Linux's
file-first errno precedence, signed range-overflow checks, valid flag matrix,
and `ESPIPE` file-type behavior. io_uring coverage includes all reserved SQE
fields, ioprio, normal and fixed files, missing/sparse/out-of-range slots, a
closed original descriptor, and recovery after failures. Shared squeue's
existing fixed-file and preparation machinery was already sufficient; the
Linux syscall handler owns the ABI policy. `kern_fsync_fp()` is the small shared
kernel primitive needed to keep the validated vnode reference stable.

Linux 6.18.35 passed 20 oracle executions, the focused candidate passed 100
ZFS/tmpfs executions, and the full amd64 ZFS-root gate passed 457 main and
1,104 shared-option executions plus every specialized suite. The backend uses
whole-vnode `VOP_FDATASYNC` because FreeBSD exposes no range-fsync VOP, so it is
conservative about the amount written while matching validation and results.
`FADVISE` was audited alongside this work: its advice values, 64-bit `addr`
length with `len` fallback, reserved fields, and descriptor handling already
match the Linux contract and required no implementation change.

The final test-only portability cleanup replaced amd64-only raw `open` and
`poll` calls with `openat` and `ppoll`. Both amd64 and arm64 freestanding test
binaries compile with warnings as errors. On the candidate kernel, all four
touched cases passed 25 repetitions on ZFS and 25 on tmpfs (200 executions),
with zero final squeue resources and clean ZFS shutdown. This cleanup does not
change the kernel implementation or reopen the completed `SYNC_FILE_RANGE`
option audit.

## io_uring xattr options completed (2026-09-22)

`FSETXATTR`, `SETXATTR`, `FGETXATTR`, and `GETXATTR` now have a direct and
io_uring option matrix. The Linux handler correctly checks CREATE existence
independent of the new value size, accepts CREATE|REPLACE with Linux's
existence-dependent result, and converts native short-buffer truncation into
Linux's side-effect-free `ERANGE`. The io_uring frontend owns flag-preparation
ordering; the shared squeue fixed-file machinery needed no change.

Linux 6.18.35 passed 20 oracle executions, the focused candidate passed 100
ZFS/tmpfs executions, and the formal amd64 ZFS-root gate passed all 458 main
io_uring cases and 1,104 shared-option executions with zero failures, leaked
resources, or kernel diagnostics. Continue the remaining per-opcode field and
option audit after the xattr family.

## io_uring `EPOLL_CTL` options completed (2026-09-22)

`IORING_OP_EPOLL_CTL` now follows Linux's no-request-file rule:
`IOSQE_FIXED_FILE` is ignored and the epoll descriptor remains an ambient fd.
The shared dispatch bypass is explicitly Linux-gated. Direct and io_uring
tests cover ADD/MOD/DEL, unknown operations, event-copy and descriptor error
ordering, all rejected preparation fields, accepted unused padding, ignored
fixed-file behavior, side-effect-free failures, and recovery.

Linux 6.18.35 passed 20 oracle executions, the focused candidate passed 100
ZFS/tmpfs executions, and the formal amd64 ZFS-root gate passed all 459 main
io_uring cases and 1,104 shared-option executions with zero failures, leaked
resources, or kernel diagnostics. Continue with the next incomplete
per-opcode field and option audit.

## io_uring `STATX` options completed (2026-09-22)

STATX now preserves Linux's preparation ordering: reserved `buf_index` and
`splice_fd_in` produce `EINVAL` before a simultaneous `IOSQE_FIXED_FILE`
produces `EBADF`. Positive operation, ignored tail fields, generic option
rejections, statx flags, pointer faults, side effects, and recovery are gated.
Linux 6.18.35 passed 20 oracle runs, the focused candidate passed 50 ZFS/tmpfs
runs, and the formal amd64 ZFS-root gate passed all 460 main and 1,104 shared
option executions without failures, diagnostics, or retained resources.


## io_uring pathname-operation options completed (2026-09-22)

`RENAMEAT`, `UNLINKAT`, `MKDIRAT`, `SYMLINKAT`, and `LINKAT` now preserve
Linux's preparation order. Each opcode validates its reserved union fields
before rejecting `IOSQE_FIXED_FILE`; the common squeue validator owns this
ordering because it owns both the per-opcode field masks and fixed-file
dispatch. No native syscall ABI changed.

The matrix covers every opcode's `buf_index` and `splice_fd_in` fields alone
and with fixed-file, fixed-file alone, each operation-specific reserved field,
invalid operation flags, side-effect-free failures, and a successful create,
link, rename, and cleanup sequence. Linux 6.18.35 passed the exact case 20
times. The focused amd64 candidate passed 50 ZFS/tmpfs executions, and the
formal amd64 ZFS-root gate passed all 461 main and 1,104 shared-option
executions plus every specialized suite. There were no nonzero results,
kernel diagnostics, or retained resources; ZFS was healthy, buffers synced,
and QEMU exited zero. Continue with the next incomplete per-opcode option
matrix.


## io_uring `TEE` options completed (2026-09-22)

`IORING_OP_TEE` now validates its splice flags during Linux request
preparation, before shared squeue resolves a registered output slot. This
matches Linux's opcode-preparation ordering for invalid flags combined with a
bad fixed output. The policy belongs in the Linux frontend; shared squeue's
zero-offset mask, output fixed-file translation, and registered-file table
already match the common contract. Direct Linux `tee(2)` remains outside this
io_uring-only phase.

The new matrix covers both forbidden offsets and their precedence, every
Linux `SPLICE_F` combination, nonblocking empty input, zero-length behavior,
ioprio and buffer selection, accepted unused SQE words, bad descriptors,
non-pipe and same-pipe errors, ordinary and registered input/output in every
combination, closed ambient descriptors, sparse and out-of-range slots,
unregister behavior, side effects, and recovery. Linux 6.18.35 passed the
exact case 20 times. The focused amd64 candidate passed 50 ZFS/tmpfs
executions, and the formal amd64 ZFS-root gate passed all 462 main and 1,104
shared-option executions plus every specialized suite, without failures,
diagnostics, or retained resources.

## io_uring `PIPE` option contract completed (2026-09-22)

`IORING_OP_PIPE` now ignores `IOSQE_FIXED_FILE`, as Linux does for this
descriptorless operation, while validating creation flags first. The
Linuxulator frontend owns Linux flag validation. Shared squeue only bypasses
registered-file translation for Linux rings; native squeue behavior is
unchanged. `O_CLOEXEC` and `O_NONBLOCK` work on both returned ends. Packet and
notification pipes remain explicitly rejected because the native pipe backend
does not provide their semantics.

The new matrix covers all four supported flag combinations, descriptor status
and close-on-exec flags, every reserved preparation field, nonzero ioprio,
buffer selection, accepted unused SQE words, ignored fixed-file behavior with
no table, invalid-flag ordering, bad result memory, rollback of both created
descriptors, side effects, and recovery. Linux 6.18.35 passed the exact case 20
times. The focused candidate passed 50 ZFS/tmpfs executions, and the formal
amd64 ZFS-root gate passed all 463 main and 1,104 shared-option executions plus
every specialized suite, without failures, diagnostics, or retained resources.

## io_uring `FTRUNCATE` option contract completed (2026-09-22)

`IORING_OP_FTRUNCATE` now preserves Linux request-file resolution order.
Linux pins the request file before execution validates a negative length, so an
invalid fd combined with a negative length returns `EBADF`; the direct syscall
validates length first. The Linux frontend owns this ordering and issues against
the pinned file. Native `ftruncate` and native squeue retain their existing
contract. The shared field mask already matched Linux and needed no change.

The matrix covers all six reserved union fields, accepted final SQE padding,
ioprio and buffer-selection rejection, negative lengths, invalid descriptors,
read-only files, directories, pipes, sockets, growth and shrink behavior,
ordinary and fixed files, lifetime after ambient close, sparse and
out-of-range slots, field-before-slot ordering, unregister behavior,
side-effect-free failures, asynchronous submission, and recovery. Linux
6.18.35 passed the exact case 20 times. The focused candidate passed 50
ZFS/tmpfs executions, and the formal amd64 ZFS-root gate passed all 464 main
and 1,104 shared-option executions plus every specialized suite, without
failures, diagnostics, or retained resources.

## io_uring `BIND` and `LISTEN` options completed (2026-09-22)

Linux imports BIND and CONNECT sockaddrs during opcode preparation, before
resolving the request file. The Linux frontend now validates the signed address
length and copies the complete sockaddr at that stage, preserving `EFAULT` or
`EINVAL` ahead of a bad registered-file slot. Shared squeue already had the
exact BIND and LISTEN field masks and fixed-file translation. Native socket
syscalls and native squeue are unchanged.

The matrix covers every reserved field for both opcodes, ioprio and buffer
selection, accepted unused SQE words, invalid pointer and oversized-address
ordering, absence of side effects, ordinary sockets, registered-socket lifetime
after ambient close, sparse and out-of-range slots, unregister behavior,
non-socket and datagram errors, asynchronous submission, and recovery. Linux
6.18.35 passed the exact case 20 times. The focused candidate passed 50
ZFS/tmpfs executions, and the formal amd64 ZFS-root gate passed all 465 main
and 1,104 shared-option executions plus every specialized suite, without
failures, diagnostics, or retained resources.

## io_uring `CONNECT` and `SHUTDOWN` options completed (2026-09-22)

`IORING_OP_CONNECT` now has a complete option matrix for the sockaddr
preparation rule introduced with BIND: Linux imports and validates the address
before resolving an ordinary or registered request file. `IORING_OP_SHUTDOWN`
uses the shared backend's existing exact field mask and registered-file
lifetime. No additional shared-backend or native ABI change was required for
this phase.

The matrix covers every reserved field, ioprio and buffer selection, accepted
unused SQE words, bad-pointer and oversized-address precedence, invalid
shutdown modes, ordinary and fixed sockets, lifetime after ambient close,
sparse and out-of-range slots, unregister behavior, non-socket errors,
`IOSQE_ASYNC`, observable peer EOF, side effects, and recovery. Linux 6.18.35
passed the exact case 20 times after the oracle guest's loopback interface was
brought up. The focused amd64 candidate passed 50 ZFS/tmpfs executions. The
formal amd64 ZFS-root gate passed all 466 main and 1,104 shared-option
executions plus every specialized suite, without failures, diagnostics, or
retained resources. Continue with the next incomplete per-opcode option
matrix.

## io_uring `SOCKET` and `ACCEPT` options completed (2026-09-22)

Linux ignores `IOSQE_FIXED_FILE` for descriptorless `IORING_OP_SOCKET`.
Shared squeue now bypasses request-file translation for that Linux opcode, as
it already does for PIPE and other descriptorless operations. The branch is
Linux-only; native squeue behavior is unchanged. The existing shared reserved
field masks and the Linux frontend's socket and accept flag translation remain
in place.

The matrix covers SOCKET's reserved fields, ioprio and buffer selection,
ignored fixed-file behavior without a table, accepted unused tail words,
ordinary and direct output, CLOEXEC/NONBLOCK status, invalid domains and type
flags, direct-slot rollback, and async execution. ACCEPT coverage includes its
reserved fields, unsupported selection, invalid flags without consuming a
peer, accepted tail words, returned descriptor flags, ordinary and registered
listeners, lifetime after ambient close, sparse and out-of-range slots,
unregister behavior, non-socket errors, async execution, side effects, and
recovery. Linux 6.18.35 passed 20/20 oracle runs. The corrected candidate
passed 50/50 focused ZFS/tmpfs runs and the formal amd64 ZFS-root gate passed
all 467 main and 1,104 shared-option executions without failures, diagnostics,
or retained resources. Continue with the next incomplete per-opcode option
matrix.

## io_uring `SPLICE` options completed (2026-09-23)

The SPLICE preparation and fixed-file ownership split already matched Linux:
the Linux frontend validates `SPLICE_F` bits before request-file lookup, while
shared squeue owns registered output translation and the frontend resolves the
independently fixed input. No kernel change was required.

The new combined matrix covers generic ioprio and buffer-selection rejection,
accepted unused buffer and SQE tail words, all 16 Linux splice-hint
combinations, flag validation before both fixed-slot lookups, ordinary and
registered input/output, lifetime after ambient close, sparse and out-of-range
slots, unregister behavior, invalid descriptors and file shapes, side effects,
`IOSQE_ASYNC`, and recovery. Linux 6.18.35 passed 20/20 oracle executions. The
candidate passed 50/50 focused ZFS/tmpfs runs and the formal amd64 ZFS-root
gate passed all 468 main and 1,104 shared-option executions without failures,
diagnostics, or retained resources. Continue with the next incomplete
per-opcode option matrix.

## FILES_UPDATE automatic allocation (2026-09-23)

IORING_OP_FILES_UPDATE now implements Linux's
off == IORING_FILE_INDEX_ALLOC mode in the shared squeue backend. Each input
descriptor is installed into the next free slot in the configured allocation
range, and its zero-based slot number is copied back over the input array.
The ordinary update and direct-close paths also maintain Linux-compatible
allocation hints when slots are cleared or replaced.

The permanent files_update_options case covers missing tables, every rejected
SQE option and reserved field, allocation ranges, full tables, returned slot
indexes, ambient-descriptor lifetime, asynchronous execution, partial prefixes,
and copyout rollback. A shared-backend case exercises the same allocation,
hint, lifetime, full-table and rollback behavior through both native squeue and
the Linux ABI.

## PROVIDE_BUFFERS / REMOVE_BUFFERS options completed (2026-09-23)

The shared squeue backend now preserves the identity of empty classic buffer
groups, matching Linux's distinction between a group that never existed and a
group whose last buffer was removed. PROVIDE publishes a preallocated batch
under one context lock, enforces both the 65,535-buffer per-group limit and the
shared global limit, and serializes correctly against provided-ring
registration. Registering a provided ring replaces an empty classic group,
rejects a classic group with live buffers, and prevents classic provide/remove
operations until that ring is unregistered.

Preparation now matches Linux 6.18 for count, element length, address
multiplication/addition and user-range checks, starting buffer ID and ID-range
bounds, and every reserved SQE field. A never-created group returns ENOENT,
an empty existing group returns zero, and mapped-ring conflicts return EINVAL.
Linux alone ignores IOSQE_FIXED_FILE for these descriptorless operations;
native squeue retains its registered-file interpretation.

The permanent `provided_buffer_options` case covers every positive and negative
preparation rule, asynchronous submission, accepted SQE tail words, fixed-file
handling, group creation/removal/reuse, empty-classic replacement, live-classic
registration conflicts, and mapped-ring conflicts. The shared suite repeats
that contract through native squeue and the Linux ABI and adds a 64-iteration
forked provide/register race that permits only the two serialized Linux
outcomes. Linux 6.18.35 passed the main and shared option cases 20/20 each and
the race case for 1,280 races. The expanded focused candidate passed 50 ZFS
and tmpfs iterations, 300 invocations total, with zero retained resources and
clean kernel diagnostics.

The formal amd64 ZFS-root gate passed all 470 main io_uring cases and 1,122
shared-option executions, plus 39 NO_MMAP, 33 SQPOLL, 24 registered-memory,
21 query, and 57 Linux AIO executions. All final request, file, issuer, and
wired-page counters were zero; QEMU exited zero after a healthy pool check and
synchronized shutdown, with no recognized kernel diagnostics. The exact
result is `/tmp/linuxulator-pbufoptions-20260923/full-run3/results.json`.

## OPENAT / OPENAT2 io_uring options completed (2026-09-23)

Linux io_uring now prepares OPENAT and OPENAT2 in Linux 6.18 order. Generic
ioprio and buffer-selection checks run first. OPENAT then rejects nonzero
buf_index, rejects IOSQE_FIXED_FILE, imports the pathname, and finally checks
direct-output O_CLOEXEC. OPENAT2 imports and extends open_how before the same
opcode checks. Shared squeue defers those two open-specific checks only for its
Linux frontend; native squeue retains its prior behavior.

The permanent open_options case covers 21 submissions: generic-option
precedence, every open-specific ordering boundary, short and inaccessible
open_how, nonzero extension bytes, invalid flags/mode/resolve, bad pathnames,
accepted SQE tail words, IOSQE_ASYNC, ordinary output, direct output,
failed-install rollback, and registered-slot health. Linux 6.18.35 passed
20/20 oracle runs. The candidate passed 50 ZFS/tmpfs focused rounds, 150
open-case executions total, with all resource pairs zero.

The formal amd64 ZFS-root gate at
/tmp/linuxulator-openoptions-20260923/full-run2/results.json passed 471 main
io_uring cases, 1,122 shared-option executions, 39 NO_MMAP, 33 SQPOLL, 24
memory-region, 21 query, and 57 Linux AIO executions. Final requests, files,
issuers, tokens, and wired pages were zero; the pool was healthy, diagnostics
were empty, and shutdown synchronized all buffers. An earlier identical run
is excluded because the host harness's 1,800-second limit expired after all
471 main cases had passed; the accepted rerun used a 3,000-second limit and
finished in about 2,063 seconds. Arm64 runtime was not repeated after the
architecture-specific phase; the arm64 freestanding binary compiles with
warnings as errors.

## CLOSE io_uring options completed (2026-09-23)

Linux io_uring CLOSE preparation now checks off, addr, len, rw_flags, and
buf_index before rejecting IOSQE_FIXED_FILE, then validates that a direct
file_index is not combined with a nonzero fd. Shared squeue defers these checks
only for Linux rings; native squeue retains its existing preparation behavior.

The permanent close_options case covers generic ioprio and buffer-selection
precedence, all five reserved fields combined with IOSQE_FIXED_FILE, fixed-file
rejection, the fd/direct-index conflict and its ordering, accepted SQE tail
words, ordinary and direct IOSQE_ASYNC close, observable ambient descriptor
closure, rejected-operation slot preservation, successful slot removal, and
post-close health. Linux 6.18.35 passed 20/20 oracle runs. The candidate passed
50 focused ZFS/tmpfs rounds, 150 close-case executions total, with all resource
pairs zero and clean debug diagnostics.

The formal amd64 ZFS-root result at
/tmp/linuxulator-closeoptions-20260923/full-run/results.json passed 472 main
io_uring cases, 1,122 shared-option executions, 39 NO_MMAP, 33 SQPOLL, 24
memory-region, 21 query, and 57 Linux AIO executions. Final requests, files,
issuers, tokens, and wired pages were zero; ZFS was healthy, diagnostics were
empty, and shutdown synchronized all buffers. Arm64 runtime remained waived
after the architecture-specific phase; the arm64 test binary compiles with
warnings as errors.

## FIXED_FD_INSTALL io_uring options completed (2026-09-23)

`IORING_OP_FIXED_FD_INSTALL` now follows Linux 6.18 preparation order in the
shared squeue backend. Generic ioprio and buffer-selection checks run before
personality lookup. The opcode then rejects all six reserved SQE fields,
including `addr3`, requires `IOSQE_FIXED_FILE`, validates
`install_fd_flags`, and rejects a registered personality with `EPERM` before
execution. Default installs retain close-on-exec and
`IORING_FIXED_FD_NO_CLOEXEC` clears it. These are common io_uring-compatible
semantics, so native squeue and the Linux frontend use the same backend; no
Linux-only syscall or native descriptor behavior changed.

The permanent main and shared cases cover invalid and sparse registered slots,
generic-option precedence, every reserved field, missing fixed-file state,
unknown install flags, personality ordering, CLOEXEC and NO_CLOEXEC,
`IOSQE_ASYNC`, accepted final SQE padding, source-slot lifetime, unregister,
and post-failure ring health. Linux 6.18.35 passed both cases 20/20. The
corrected candidate passed 50 ZFS/tmpfs focus rounds, 300 invocations total,
with all five before/after resource pairs zero. An earlier focus attempt and
an earlier combined oracle loop are excluded because their harnesses reused an
`O_EXCL` filename between otherwise independent invocations; separate working
directories removed the collision.

The formal amd64 ZFS-root result at
`/tmp/linuxulator-fixedinstall-20260923/full-run/results.json` passed 473 main
io_uring cases, 1,122 shared-option executions, 39 NO_MMAP, 33 SQPOLL, 24
memory-region, 21 query, and 57 Linux AIO executions, plus every other gate
matrix. Final requests, files, issuer references, issuer tokens, and wired
pages were zero; ZFS was healthy, diagnostics were empty, and shutdown
synchronized all buffers. The arm64 Linux and shared test binaries compile
with warnings as errors; arm64 runtime remains waived after the
architecture-specific phase.

## Linux `fadvise64` and io_uring `FADVISE` options completed (2026-09-23)

Linux `fadvise64` and `IORING_OP_FADVISE` now share one Linux frontend helper
that preserves Linux 6.18 descriptor and error ordering. The frontend resolves
and holds the file before validating the length and advice, reports `ESPIPE`
for pipes before those validation errors, accepts Linux's negative and wrapping
offset forms, and accepts valid advice for directories and sockets. Regular
files use a new held-file `kern_posix_fadvise_fp()` backend so a concurrent
close and descriptor reuse cannot redirect the operation. That helper contains
only common file-hint mechanics. Linux-only range, file-type, and errno policy
remains in the Linuxulator; native `posix_fadvise` and native squeue preserve
their existing validation and error ordering.

The permanent direct, main io_uring, and shared squeue cases cover all six
advice values, generic ioprio and buffer-selection rejection, reserved SQE
fields, personality ordering, `addr` and legacy `len` range forms, zero and
negative lengths, negative and wrapping offsets, invalid advice, descriptor
and pipe precedence, directories, sockets, ordinary and registered files,
sparse and out-of-range registered slots, ambient-descriptor lifetime,
unregister behavior, `IOSQE_ASYNC`, accepted SQE tail words, side effects, and
post-failure ring health. Linux 6.18.35 passed each exact case 20/20. Both
amd64 and arm64 freestanding test binaries compile with warnings as errors;
arm64 runtime remains waived after the architecture-specific phase.

The rebuilt WITNESS/INVARIANTS candidate passed 50 focused ZFS/tmpfs rounds,
300 invocations total, with all ten before/after resource values zero and clean
diagnostics. The formal amd64 ZFS-root gate at
`/tmp/linuxulator-fadvise-20260923/full-run/results.json` passed 48 direct ABI
executions, 474 main io_uring cases, 1,128 shared-option executions, three
native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, and 57
Linux AIO executions plus every other matrix. Final requests, registered files,
issuer references, issuer tokens, and wired pages were zero; ZFS was healthy,
no recognized kernel diagnostic occurred, and shutdown synchronized all
buffers. The accepted run took 2,121.09 seconds.

The first complete formal execution also had zero functional and diagnostic
failures, but the host validator still expected the previous 45 direct and
1,122 shared results. Its console passed a corrected-validator replay after
adding the two FADVISE inventories; it is retained under
`/tmp/linuxulator-fadvise-20260923/full-run-count-mismatch/` and is excluded
from the accepted result. The candidate kernel and modules were never
installed or loaded on the host.


## io_uring `FSYNC` range and option contract completed (2026-09-23)

`IORING_OP_FSYNC` now resolves and holds its request file before checking the
execution-time range. A negative offset returns `EINVAL`, while an invalid file
descriptor combined with a negative offset returns `EBADF`, matching Linux
6.18 ordering. The shared backend calls `kern_fsync_fp()` on that held file, so
a concurrent close and descriptor reuse cannot redirect writeback. It accepts
Linux's wrapping `off + len` form. FreeBSD has no range-fsync VOP, so a valid
range conservatively synchronizes the whole vnode; this is stronger writeback
than the requested range without changing the observable io_uring result.
The io_uring-compatible preparation policy is also shared: generic flags run
before personality lookup, FSYNC-reserved fields are rejected during common
preparation, and only `IORING_FSYNC_DATASYNC` is accepted. No direct Linux or
native fsync syscall semantics changed.

The expanded main case and new shared case cover generic ioprio and buffer
selection, personality lookup, every FSYNC-reserved field, unknown fsync flags,
full and data-only sync, nonzero ranges, negative and wrapping ranges,
bad-descriptor/range precedence, pipes, `IOSQE_ASYNC`, accepted SQE tail words,
registered-file lifetime after ambient close, sparse and out-of-range slots,
unregister behavior, and post-error health. Linux 6.18.35 passed both exact
cases 20/20. The amd64 and arm64 Linux test binaries and the native/shared test
binaries compile with warnings as errors; arm64 runtime remains waived for this
architecture-neutral phase.

The corrected WITNESS/INVARIANTS candidate passed 50 focused ZFS/tmpfs rounds,
200 invocations total, with all ten resource values zero and clean diagnostics.
The accepted formal amd64 ZFS-root gate at
`/tmp/linuxulator-fsync-20260923/full-run/results.json` passed 48 direct ABI
executions, 474 main io_uring cases, 1,134 shared-option executions, three
native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, and 57
Linux AIO executions plus every other matrix. All final resource counters were
zero, ZFS was healthy, no recognized kernel diagnostic occurred, and shutdown
synchronized all buffers. The run took 2,205.33 seconds. The candidate kernel
and modules were never installed or loaded on the host.


## Linux `fallocate` and io_uring `FALLOCATE` options completed (2026-09-23)

Linux `fallocate(2)` and `IORING_OP_FALLOCATE` now share a held-file Linux
policy helper. The direct syscall retains Linux's mode-before-descriptor error
ordering, while io_uring resolves and pins its request file before validating
the mode and range, matching Linux 6.18. Shared VFS helpers now perform
`posix_fallocate` and `fspacectl` mechanics on an already-held `struct file`,
which closes the descriptor-close/reuse race without moving Linux mode, type,
or errno policy into the native kernel interface. Native syscall argument
ordering and native squeue behavior remain unchanged.

The permanent main and shared cases cover generic ioprio and buffer-selection
precedence, personality lookup, `buf_index`, `rw_flags`, and `splice_fd_in`,
unknown and unsupported modes, zero, negative, and wrapping ranges,
bad-descriptor ordering, read-only files, pipes, directories, sockets,
`IOSQE_ASYNC`, accepted SQE tail words, mode-zero allocation, registered-file
lifetime after ambient close, sparse and out-of-range slots, unregister, and
post-error ring health. Linux 6.18.35 passed the exact main and shared cases
20/20 each. The amd64 and arm64 Linux binaries and native/shared binaries
compile with warnings as errors; arm64 runtime remains waived for this
architecture-neutral phase.

The corrected WITNESS/INVARIANTS candidate passed 50 focused rounds split
between ZFS and tmpfs, 275 actual invocations, with all ten resource values
zero, healthy ZFS, clean diagnostics, and synchronized shutdown. Reservation
success is exercised on tmpfs and Linux memfd because ZFS deliberately returns
`EOPNOTSUPP` for reservation allocation; filesystem-independent option,
ordering, lifetime, and negative tests run from the ZFS-root environment. The
first focus attempt, which incorrectly required mode-zero reservation on ZFS,
is excluded as a harness error.

The accepted formal amd64 ZFS-root gate at
`/tmp/linuxulator-fallocate-20260923/full-run/results.json` passed 48 direct ABI
executions, 475 main io_uring cases, 1,140 shared-option executions, three
native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, and 57
Linux AIO executions plus every other matrix. Final requests, registered files,
issuer references, issuer tokens, and wired pages were zero; no recognized
kernel diagnostic occurred, the pool was healthy, and shutdown synchronized
all buffers. The run took 2,119.19 seconds. Candidate kernel and module hashes
differ from the host's installed artifacts; they were staged and loaded only
inside the disposable VM.


## `IORING_SETUP_ATTACH_WQ` worker ownership completed (2026-09-24)

All attached rings now retain a canonical worker-control owner. Ordinary and
SQPOLL attachment chains therefore share `IORING_REGISTER_IOWQ_MAX_WORKERS`
and IOWQ affinity, while every ring keeps independent submission and completion
state. Closing the source or an intermediate attachment does not invalidate
the surviving chain. SQPOLL poller ownership remains separate, so a forked
process can use its own poller while sharing the worker policy safely.

The permanent `attach_wq_shared` case covers limit updates through both ends of
a chain, visibility after source close, canonical ownership across a chained
attachment, serialization of blocked asynchronous reads through a one-worker
limit, intermediate close, continued ring health, stale descriptors, invalid
descriptors, wrong descriptor types, and final teardown. The focused amd64
ZFS-root WITNESS/INVARIANTS VM passed 20 native and 20 Linux ABI executions.
The broader gate then passed all 191 option cases three times under each ABI,
1,146 executions total. All five request, registered-file, issuer-reference,
issuer-token, and wired-page counters returned to zero after every round; no
case was nonzero, no recognized kernel diagnostic occurred, ZFS was healthy,
buffers synchronized, and the VM powered off cleanly. Evidence is retained in
`/tmp/iouring-attach/evidence`. The candidate kernel and modules were used only
inside the disposable VM.

## BPF filter registration completed (2026-09-24)

`IORING_REGISTER_BPF_FILTER` is now the 36th handled ordinary registration
command. Shared squeue owns classic-BPF validation, immutable per-ring chains,
request-context construction and lockless execution. Linuxulator owns blind
per-task registration, privilege/`no_new_privs` policy, fork/exec inheritance,
and Linux preparation snapshots for CONNECT and OPENAT2. The permanent
positive, negative, payload, concurrency and lifetime case passed 20 focused
runs per ABI and the complete 192-case, three-round, dual-ABI amd64 ZFS-root
QEMU gate. NAPI and UNREGISTER_NAPI are the two remaining locally declared
ordinary registration commands; hardware/import/export ZCRX remains a backend
mode gap rather than a missing command dispatch.
