# Missing Linux syscalls: handoff for the next implementation stream

Follow-up: [peer names, mixed multicast deltas and process ptrace events](linuxulator-peer-events-options.md)
records the implemented amd64 subset and VM evidence. Earlier missing-option
entries below are superseded for that subset; full Linux thread tracing remains
unfinished. SO_COOKIE was already implemented before that follow-up.

The latest existing-handler work is [XSAVE writes and multicast filters](linuxulator-xstate-mcast-options.md).
It does not remove entries from the missing-syscall queue below.

This is the **non-io_uring syscall** work queue. The active io_uring/squeue
work has its own owner and gate in [linuxulator-implementation-gate.md](linuxulator-implementation-gate.md).
This inventory is based on the current `sys/amd64/linux/syscalls.master`,
`sys/compat/linux/linux_dummy.c`, `sys/amd64/linux/linux_dummy_machdep.c`,
and `sys/x86/linux/linux_dummy_x86.c` on 2026-09-21. It covers the Linux64
x86_64 ABI through local syscall 472. Linux v7.1's
[x86_64 syscall table](https://github.com/torvalds/linux/blob/v7.1/arch/x86/entry/syscalls/syscall_64.tbl)
ends its common sequence at 471; local 472 (`fchroot`) is already implemented.
Recheck upstream numbering when starting work against a newer Linux release.

`unshare` has a VM-qualified amd64 Linux64 `CLONE_FS` subset, documented in
[linuxulator-unshare.md](linuxulator-unshare.md). Its row remains because the
other namespace flags and non-amd64-Linux64 ABIs still need functional work.
A follow-up adds VM-tested concurrent path-state mutation and Linux reference
cases for descriptor-table lock ownership; it does not extend supported flags.
The queue now contains 36 `DUMMY()` calls, reject-only `seccomp`, and
partially implemented `unshare`, `quotactl`, `quotactl_fd`, and
`perf_event_open`. The initial software-counter subset is documented in
[linuxulator-perf-event.md](linuxulator-perf-event.md). The quota
subset has passed its named reference/focused cases and full amd64 VM gate. See
[the quota contract](linuxulator-quota.md).

The local table has 386 named slots: 334 functional handlers or native aliases
(which may support only part of their Linux options), **36 `DUMMY()` handlers**
that return `ENOSYS`, **one reject-only `seccomp` handler**, and 15 deliberately
unimplemented historical slots. The 37 calls without functional handlers and four partial calls
are all listed below (41 calls still needing work). These counts describe dispatch, not conformance of the
333 handlers. The separate [coverage inventory](linuxulator-syscall-coverage.md)
tracks partially implemented calls and options, including the six legacy AIO
calls; those are additional correctness work, not missing dispatch entries.

## 1. Namespaces, mounts, and filesystem control (14)

| x86_64 no. | Call | Current status | Main prerequisite / ownership question |
|---:|---|---|---|
| 155 | `pivot_root` | `DUMMY` | Mount-tree/root transition; cannot be represented by `chroot` alone. |
| 179 | `quotactl` | Partial: global quota sync | Legacy device-selected operations remain pending; use the fd variant for ZFS datasets. |
| 272 | `unshare` | Partial: amd64 single-threaded `CLONE_FS`; named ABI cases VM-tested | [Contract and reference tests](linuxulator-unshare.md); descriptor, thread-local and namespace ownership remain pending. |
| 308 | `setns` | `DUMMY` | Namespace-fd identity, permissions and lifetime. |
| 428 | `open_tree` | `DUMMY` | Detached mount-tree objects and mount-fd lifecycle. |
| 429 | `move_mount` | `DUMMY` | Atomic mount-tree movement and path/fd resolution. |
| 430 | `fsopen` | `DUMMY` | Filesystem context object and security checks. |
| 431 | `fsconfig` | `DUMMY` | Context command/parameter state machine. |
| 432 | `fsmount` | `DUMMY` | Mount-fd creation and attach semantics. |
| 433 | `fspick` | `DUMMY` | Existing-mount context selection. |
| 442 | `mount_setattr` | `DUMMY` | Recursive mount attributes and propagation. |
| 443 | `quotactl_fd` | Partial: amd64 ZFS user/group query, byte hard-limit update and sync | [Contract and tests](linuxulator-quota.md); other quota controls remain pending. |
| 467 | `open_tree_attr` | `DUMMY` | New mount-tree attribute ABI; depends on mount-fd model. |
| 470 | `listns` | `DUMMY` | Enumeratable namespace identity and visibility rules. |

Treat the namespace and new-mount calls as one design project, not aliases for
jails or ordinary `mount(2)`. Keep Linux structures, flags and errno conversion
in Linuxulator. Add reusable mount-tree and quota primitives to the native
kernel only when they preserve their invariants through native callers too.
Boot and acceptance guests use ZFS root; filesystem-sensitive success tests
must use ZFS. The first oracle matrix needs path/fd forms, unknown flags,
permissions, mount propagation, traversal races, rollback and close/exec/exit.

## 2. Security, tracing, and observability (17)

| x86_64 no. | Call | Current status | Main prerequisite / ownership question |
|---:|---|---|---|
| 212 | `lookup_dcookie` | `DUMMY` | Profiling cookie source and access policy. |
| 248 | `add_key` | `DUMMY` | Keyring object store, quotas and permissions. |
| 249 | `request_key` | `DUMMY` | Key lookup/upcall and negative-key semantics. |
| 250 | `keyctl` | `DUMMY` | Keyring commands, inheritance and revocation. |
| 298 | `perf_event_open` | Partial: current-thread software counters and event-fd lifecycle | [Implemented subset and tests](linuxulator-perf-event.md); PMU, sampling, mmap ring, groups and other targets remain. |
| 300 | `fanotify_init` | `DUMMY` | Filesystem notification group and queue. |
| 301 | `fanotify_mark` | `DUMMY` | Mark scope, permission events and teardown. |
| 317 | `seccomp` | reject-only handler | Filter verification and enforcement on *every* Linux syscall entry. |
| 321 | `bpf` | `DUMMY` | Verifier, maps/programs, attach targets and privilege. |
| 335 | `uretprobe` | `DUMMY` | User-return probe registration and lifecycle. |
| 336 | `uprobe` | `DUMMY` | User instruction probe backend and traps. |
| 444 | `landlock_create_ruleset` | `DUMMY` | Ruleset object and ABI-version query. |
| 445 | `landlock_add_rule` | `DUMMY` | Path/net rule validation and ownership. |
| 446 | `landlock_restrict_self` | `DUMMY` | Inherited, irreversible access enforcement. |
| 459 | `lsm_get_self_attr` | `DUMMY` | Defined LSM identity/attribute model. |
| 460 | `lsm_set_self_attr` | `DUMMY` | Attribute mutation policy. |
| 461 | `lsm_list_modules` | `DUMMY` | Advertised LSM inventory and versioning. |

Choose a real client for each subsystem before defining its supported subset.
A success return without the promised restriction, notification or event data
is not support. Security checks that protect native objects belong in shared
kernel code; Linux command formats and option translation stay in Linuxulator.
Tests must include denied privilege, invalid program/structure, cross-process
access, fork/exec inheritance, fd passing, object revocation and teardown.
For `seccomp`, include every syscall entry path and prove filtered operations
have no side effects. Avoid concurrent edits to io_uring/squeue while that
workstream is being qualified.

## 3. Module, boot, and administration (5)

| x86_64 no. | Call | Current status | Main prerequisite / ownership question |
|---:|---|---|---|
| 175 | `init_module` | `DUMMY` | Linux module image semantics versus native KLD format. |
| 176 | `delete_module` | `DUMMY` | Module identity, reference counts and unload policy. |
| 246 | `kexec_load` | `DUMMY` | Replacement-kernel loader and boot transition. |
| 313 | `finit_module` | `DUMMY` | fd-based module image validation and loading. |
| 320 | `kexec_file_load` | `DUMMY` | fd-based kernel/initrd verification and transition. |

These are not simple `kldload` or reboot wrappers. Record which Linux image
formats and signatures are actually supported, and distinguish a real subset
from a deliberate rejection. Test privilege, malformed images, fd type,
concurrent unload/load and rollback in disposable VMs only. Never load a
candidate module or kernel on the host.

## 4. Memory and process runtime (5)

| x86_64 no. | Call | Current status | Main prerequisite / ownership question |
|---:|---|---|---|
| 323 | `userfaultfd` | `DUMMY` | Fault delegation, address-space registration and wake/cancel races. |
| 447 | `memfd_secret` | `DUMMY`; design blocked | Requires pages excluded from the kernel direct map as well as dump paths. Ordinary shm or `MAP_NOCORE` is insufficient; add a real VM isolation primitive before a Linux wrapper. |
| 448 | `process_mrelease` | `DUMMY` | pidfd-validated exiting-process memory release. |
| 453 | `map_shadow_stack` | `DUMMY` | x86 CET shadow-stack mapping and enforcement. |
| 471 | `rseq_slice_yield` | `DUMMY` | Scheduler/rseq integration; amd64 `rseq` exists but this call does not. |

These need observable semantics, not a no-op that only satisfies feature
probes. VM/VFS enforcement, pidfd identity and scheduler hooks should be shared
where native access can bypass them. Linux syscall layouts and Linux-specific
policy belong in Linuxulator. Test faults, alignment/overflow, cross-process
permissions, fork/exec/exit and concurrent teardown. `map_shadow_stack` is
architecture-specific and therefore needs the relevant architecture VM gate.

## Historical slots deliberately outside the implementation queue (15)

`134 uselib`, `174 create_module`, `177 get_kernel_syms`,
`178 query_module`, `180 nfsservctl`, `181 getpmsg`, `182 putpmsg`,
`183 afs_syscall`, `184 tuxcall`, `185 security`, `205 set_thread_area`,
`211 get_thread_area`, `214 epoll_ctl_old`, `215 epoll_wait_old`, and
`236 vserver` are `UNIMPL` in the local x86_64 table. They are not counted in
the 41-call actionable queue. Reopen one only with a concrete Linux binary
requiring it and reference behavior that is meaningful on this platform.
Numeric holes 337–423 are not named syscalls.

## Architecture and partial-handler follow-up

The list covers 38 unresolved **Linux64 x86_64 dispatch** names plus
partially implemented `unshare`, `quotactl` and `quotactl_fd`.
Across the four local ABI tables there are 55 unique `DUMMY()` names, the
reject-only `seccomp` handler, and partial `unshare` and `perf_event_open`, or
58 names still requiring work. The
additional stubs and exceptions below make that cross-ABI inventory explicit;
ABI-specific syscall numbers must come from the corresponding master table.

| ABI | `DUMMY()` count | Additional stubs relative to the x86_64 list above | x86_64 stubs absent from this ABI's `DUMMY()` set |
|---|---:|---|---|
| arm64 Linux64 | 38 | `io_pgetevents` (292), `pkey_mprotect` (288), `pkey_alloc` (289), `pkey_free` (290) | `map_shadow_stack`, `quotactl`, `uprobe`, `uretprobe` |
| amd64 Linux32 | 48 | `stime` (25), `ptrace` (26), `olduname` (59), `uname` (109), `bdflush` (134), `sysfs` (135), `pkey_mprotect` (380), `pkey_alloc` (381), `pkey_free` (382), `arch_prctl` (384), `clock_adjtime64` (405), `io_pgetevents_time64` (416), `mq_timedsend_time64` (418), `mq_timedreceive_time64` (419) | `kexec_file_load`, `map_shadow_stack`, `uprobe`, `uretprobe` |
| i386 Linux32 | 50 | `stime` (25), `olduname` (59), `uname` (109), `vm86old` (113), `bdflush` (134), `sysfs` (135), `vm86` (166), `pkey_mprotect` (380), `pkey_alloc` (381), `pkey_free` (382), `arch_prctl` (384), `io_pgetevents` (385), `clock_adjtime64` (405), `io_pgetevents_time64` (416), `mq_timedsend_time64` (418), `mq_timedreceive_time64` (419) | `kexec_file_load`, `map_shadow_stack`, `uprobe`, `uretprobe` |

`unshare` is no longer a `DUMMY()` macro on any ABI. Its hand-written
non-amd64-Linux64 branch still returns ENOSYS; that is not functional support.

The quota rows above remain unresolved on the other ABIs; the shared
`quotactl_fd` stub is retained and amd64 uses a distinct handler. The cross-ABI
unique-stub count is therefore unchanged.

An entry in the last column may be absent, a native alias or a different
handler; do not infer support from this table. The Linux32 `ptrace` stub, for
example, differs from i386 Linux32. Recount against each `syscalls.master` and
its machine-dependent dummy file before changing an architecture-specific
ABI. Run arm64 QEMU only for arm64 ABI or machine-dependent changes, as the
current gate contract requires.

Already-dispatched but incomplete calls are a **separate option/correctness
queue**. At minimum, the six legacy AIO entries (`io_setup`, `io_destroy`,
`io_getevents`, `io_submit`, `io_cancel`, `io_pgetevents`) are partial; `rseq`
is qualified only for named amd64 contracts and still needs consumer/lifecycle
work; `openat2`, `fallocate`, futex, ptrace, sockets and many other handlers
have option gaps. Use [linuxulator-syscall-coverage.md](linuxulator-syscall-coverage.md)
and [linuxulator-next-phase-options.md](linuxulator-next-phase-options.md) for
those inventories. Do not count a handler as finished merely because it is
absent from the 41-call table.

## Definition of done for each handoff item

1. Pin the reference Linux version and record the syscall number, structures,
   flags, supported subset, return values and errno precedence. Assign
   shared-kernel versus Linuxulator ownership before code changes.
2. Add named positive and negative cases for every supported command/option:
   normal side effects, unknown/conflicting flags, reserved fields and size
   boundaries, bad pointers and descriptors, permissions and capmode where
   applicable, ZFS behavior, fork/exec/close, cancellation and concurrency.
   Give deliberately unsupported features negative tests too.
3. Run those cases against a disposable Linux-reference QEMU guest where
   semantics are uncertain, then against a **disposable amd64 ZFS-root BSD
   QEMU guest**. Run the existing full guest gate after the focused matrix.
   Require zero failures, zero recognized diagnostics and zero leaked tracked resources,
   healthy ZFS and clean shutdown. Record exact kernel, module, binary, source
   and result hashes; never install or load candidate artifacts on the host.
4. Update the syscall coverage row and the per-syscall matrix in
   [linuxulator-implementation-gate.md](linuxulator-implementation-gate.md).
   Only then mark the named contract QEMU validated. A fresh arm64 VM gate is
   required for an arm64 ABI or machine-dependent change, not for a
   purely architecture-neutral Linux64 change.
