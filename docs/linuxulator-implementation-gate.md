# Linux binary compatibility: implementation and correctness gate

This is the acceptance contract for the Linuxulator work requested on
2026-09-17. A syscall table entry, successful build, accepted flag, or passing
happy-path test is not evidence of complete Linux compatibility. Every supported syscall, including existing handlers, must have an explicit
coverage record; existing code is not grandfathered in. Every new or
changed syscall, command, flag and shared kernel primitive must pass the gate
below before its status becomes **QEMU validated**.

## Supported base-system configuration

The base system is supported only on ZFS. Acceptance requires an actual
ZFS-root QEMU guest, with filesystem-sensitive tests running on ZFS. UFS and
tmpfs results are supplemental and cannot substitute for ZFS qualification.
Earlier UFS-root results below remain historical evidence for their named
subsets, not acceptance of the supported base configuration. The named subsets
passed ZFS-root guests on both architectures in `zfs-run3/results.json`; see
the qualification record below. Other options and families retain their
separate pending or unvalidated statuses.

The platform-parity phase is complete. Beginning with architecture-neutral
squeue work after the registered provided-buffer-ring batch, the required VM
gate is the amd64 ZFS-root guest. Repeat arm64 only when a change touches an
arm64 ABI definition, syscall table, machine-dependent implementation, or
other architecture-specific path. The earlier dual-architecture evidence
remains part of the qualification record.

## Ownership decisions

Put reusable mechanisms in the native kernel; keep Linux numbering, layouts,
flag translation, errno translation and Linux-specific policy in Linuxulator.
Sharing code across Linux architectures is different from exposing a new
native ABI. Do not add native syscall numbers just to reuse an internal helper.
Native enforcement must cover every access path, including native callers,
descriptor passing, mmap, io_uring/squeue and fork/exec where applicable.

| Work item | Shared implementation | Linuxulator responsibility | Initial status |
|---|---|---|---|
| memfd flag validation | Existing native anonymous shared memory | Validate original flags before conversion; reject unsupported contracts | Pending |
| arm64 sync/readahead/umount2 | Existing sync, fadvise and unmount primitives | Common readahead wrapper; arm64 table wiring and generated files | Pending |
| modern memfd and seals | Native shared-memory execution permissions and seal enforcement in VFS/VM | MFD_EXEC, MFD_NOEXEC_SEAL, F_SEAL_EXEC, F_SEAL_FUTURE_WRITE conversion | Pending |
| OFD record locks | Description-owned byte-range locks in kern_lockf and descriptor lifetime integration | F_OFD_GETLK/SETLK/SETLKW and flock layout conversion | Pending |
| openat2 resolution | Per-lookup namei constraints: all-component symlink/magic-link restrictions, mount crossings, scoped root | RESOLVE_* validation and Linux error rules | Pending |
| legacy Linux AIO | Native AIO adapter plus held-file poll wait shared; context/ring translation in Linuxulator | Six amd64 handlers, scalar/vector I/O, eventfd, mmap ring and poll; remaining flags, races and lifecycle need individual gates | Partial; named poll cases QEMU validated |
| mremap | VM mapping relocation/resize preserving objects, offsets, protection and shared identity | Linux flags, zero-old-size duplication, DONTUNMAP contract | Pending |
| ptrace | Native tracing stop/event/register primitives | SEIZE, INTERRUPT, and LISTEN are amd64 Linux64 VM-qualified; seccomp requests remain | Partial |
| O_TMPFILE | VFS/filesystem anonymous inode creation and later linking | Open flag checks and linkat(AT_EMPTY_PATH) ABI | Pending |
| PI futex requeue | umtx PI ownership, wait queue transfer, cancellation and owner death | WAIT_REQUEUE_PI/CMP_REQUEUE_PI ABI and Linux waiter state | Pending |
| socket extensions | Native error queues, segmentation/coalescing and ancillary delivery where generally useful | Linux socket options, MSG_ERRQUEUE, sock_extended_err, SO_PASSPIDFD/SCM_PIDFD | Pending |
| `perf_event_open` software counting | Existing per-thread runtime and rusage counters; descriptor type only | Attribute ABI, supported selectors, event-fd state, ioctls, read layout and Linux errors | Partial; focused amd64 QEMU validated, full gate running |

Larger follow-on projects remain separately scoped: seccomp (Linux filter ABI
over kernel entry enforcement), rseq (Linux ABI over scheduler/signal/return
hooks), syscall user dispatch (Linux/Wine ABI with machine entry hooks), and
namespaces/new mount API (a resource isolation design, not aliases for jails).
No item above is implicitly completed by these design decisions.

## Required per-syscall record

Before implementation, record the exact ABI and supported subset, affected
architectures, existing behavior, intended behavior, shared/native changes,
and references to Linux source or maintained documentation. Name every public
entry point and command/flag affected, including aliases and indirect paths.
Version-dependent Linux behavior must name the reference kernel version.

For each item keep a matrix linking **each contract** to named test cases and
results. Related syscalls may share a suite but must have separate coverage
rows. A blanket statement such as "AIO tested" is insufficient. Rejected
features must have tests too. Explicitly distinguish required behavior from
optional hints and permissible filesystem/hardware-dependent rejection.

## Mandatory positive and negative coverage

For every syscall/option, enumerate applicable cases in all of these groups.
An omitted group needs a written reason; a large case count does not substitute
for coverage of the contract.

1. **Normal behavior:** observable output and side effects, return values,
   supported flag combinations, repeated operations and interoperability.
2. **Argument validation:** every unknown flag bit, conflicting flags, invalid
   enumerations, reserved fields, undersized/oversized/versioned structures,
   nonzero extension tails, zero/minimum/maximum lengths, signed boundaries,
   overflow, alignment, invalid descriptors and wrong descriptor types.
3. **User memory faults:** NULL, unmapped, read-only output, guard-page-crossing
   inputs/outputs and partial copy faults. Check error precedence only where
   established by the reference ABI; prove no unintended mutation or leak.
4. **Access and isolation:** unprivileged and privileged cases, credentials,
   Capsicum/jail restrictions where relevant, readonly mounts, immutable files,
   seals, path escape, symlink races and forbidden permission transitions.
5. **Lifetime:** dup and independently opened descriptions, close/last close,
   fd reuse, fork, exec, exit, descriptor passing, interrupted setup and cleanup.
6. **Concurrency:** deterministic waiter/worker handshakes; wake-before-sleep,
   wake-after-registration, cancellation races, close-versus-use, multiple
   waiters and repeated SMP stress. Use bounded waits, not sleeps as proof.
7. **Signals and deadlines:** EINTR/restart behavior, pending signals, relative
   and absolute deadlines, already expired deadlines, signal-mask restoration,
   timeout-versus-success ordering and progress after interruption.
8. **Resource limits and rollback:** exhaustion, allocation failure where
   injectable, short I/O, partial batches, full queues, cleanup after failure,
   child death and repeated create/destroy cycles.
9. **Shared mechanism regressions:** native callers and existing Linux paths
   exercise the same primitive. Verify changes do not silently weaken native
   locks, VM permissions, path constraints or descriptor rights.
10. **Real binaries:** a named workload appropriate to the feature, with version,
    invocation, expected output and a recorded result. A library's fallback
    must not be mistaken for successful use of the newly implemented feature.

Tests must assert semantics, not duplicate implementation branches. For
example, OFD tests must prove an unrelated close does not release the lock;
seal tests must actually attempt prohibited writes/mappings; lookup tests must
attempt escapes; AIO tests must observe independent progress and cancellation.

## QEMU is the correctness gate

The gate is mandatory for every implementation row and affected syscall.
All runtime tests, including native regressions and Linux reference cases,
run inside disposable QEMU guests. The host is used only to build artifacts
and run QEMU; do not install test kernels or modules on it or run syscall
regression binaries against its running kernel.

1. Build the changed kernel and matching modules from the recorded source
   revision **plus the exact working-tree patch**. Build the tests with warnings
   treated as errors. Regenerate syscall tables and verify reproducibility.
2. Stage an isolated **ZFS-root** guest image. Never replace the host kernel or unload its
   Linuxulator to run these tests. Do not reuse a running development VM or
   mutate someone else's image. Use a private disk or overlay and console log.
3. Boot the actual new kernel under QEMU. Record architecture, kernel identity,
   module hashes, QEMU version/arguments, CPU features, filesystem, memory and
   vCPU count. A build-only or user-mode-emulation run does not satisfy this.
4. Run named positive and negative tests separately with per-case timeouts and
   fresh processes/work directories. Preserve stdout, stderr, exit/signal
   status and guest console. Test infrastructure errors fail the gate.
5. Exercise concurrency on at least two guest vCPUs with a documented repeated
   run count. Use INVARIANTS/WITNESS and available memory diagnostics for shared
   kernel/lifetime changes; record which diagnostics were enabled.
6. Run native regressions for shared primitives and the relevant existing
   Linuxulator suites. Capture post-run kernel diagnostics and verify the guest
   remains responsive. Panics, unexpected warnings, lock-order reports, hangs,
   unexplained leaks or corrupted output fail the gate.
7. Run the same portable Linux ABI cases against a real Linux kernel (preferably
   a reference QEMU guest), recording its version/configuration. Account for
   documented filesystem/privilege differences individually. Do not weaken an
   assertion merely to match the emulator's current behavior.
8. Run each architecture being claimed. amd64 success does not validate arm64
   syscall wiring or linux32 layouts. An unavailable guest, missing feature,
   skipped required case or absent result leaves that portion **unvalidated**.
9. Archive a manifest with source/patch and artifact hashes, exact commands,
   expected test inventory, expected and actual counts, failures/skips, console
   logs, regression results and any deliberately unsupported behavior.

The runner must fail closed: nonzero test exits, timeouts, missing completion
markers, missing test results and guest crashes are failures. Tests must not
return success to encode a skip. Optional hardware cases may be recorded as
skipped, but the unexercised capability cannot be advertised as validated.
After a fix, rerun the failing case, its interacting cases and the affected
regression suite on the rebuilt image. Earlier binaries are not evidence for
later source changes.

## Feature-specific acceptance cases

| Item | Additional required tests |
|---|---|
| memfd | Every flag bit, conflicting EXEC/NOEXEC, name bounds/faults, exec permissions, seal round-trip, write/pwrite/writev/truncate, shared/private mmap, mprotect upgrades, existing writable mappings versus future mappings, fork/dup/SCM_RIGHTS |
| arm64 parity | Native arm64 Linux syscall numbers/layouts; sync positive behavior; readahead regular/read-only/write-only/pipe/socket/directory/bad fd, negative/overflowing offsets and zero length; umount flags/privilege/symlink/missing path and successful disposable mount lifecycle |
| OFD locks | Overlap and disjoint ranges, SEEK_* and signed ranges, l_pid rules, GETLK reporting, conflicts with POSIX locks, same-description reuse, independent opens, dup/fork/pass/last-close, interruptible SETLKW, waiter wakeups and owner teardown |
| openat2 | Each resolve flag and valid combination; intermediate/final symlinks, magic links, absolute paths/absolute symlinks/.., nested mounts, renamed ancestors, concurrent escape attempts, O_PATH exceptions and no side effects on failed O_CREAT |
| io_uring/squeue SQPOLL core | Seven Linux groups and one native/Linux shared group cover submission, wake/idle, full SQ wait, invalid setup, owner exit and teardown. Linux 6.18 oracle, focused three rounds and `sqpoll-full9-gate/results.json` passed for these contracts; 21 dedicated and 900 shared-option runs, zero diagnostics and final ring pages. Extended lifecycle combinations remain pending. |
| io_uring/squeue SQ_AFF | Require SQPOLL; validate online CPU and creator cpuset, including a CPU outside the caller thread affinity, invalid huge CPU and SQ_AFF without SQPOLL. Prove the poller has an exact one-CPU mask, submits work, and tears down in both native and Linux frontends. Include three focused rounds, Linux oracle and the full amd64 ZFS-root gate. CPU hotplug and cpuset restriction transitions remain separate cases. |
| io_uring/squeue ring resize | DEFER_TASKRUN prerequisite; exact pointer/count/flag/size rejection; grow/shrink and remap; pending SQ/CQ rollback; output copy fault; old mapping isolation and lifetime across descriptor close; repeated resize against concurrent mmap on two vCPUs; oversize rejection, CLAMP and inherited extended layouts; in-flight worker completion into the replacement CQ and post-resize submission/completion; wired-page baseline and full shared-engine regression gate |
| io_uring register query | Blind and ring-fd discovery; exact opcode counts and supported flag masks; linked headers and per-entry Linux errors; invalid counts/fds/types/reserved fields/sizes; short and oversized output with zero tail; NULL, unmapped, read-only and protected-page-crossing faults; cycle limit; shared-engine regressions |
| io_uring/squeue parameter memory region | Kernel-owned mmap and user-pinned pages; duplicate and invalid registration; disabled-ring wait prerequisite, indexed wait timeout and invalid offsets/flags; copyout rollback, read-only and guard-page faults; mapping lifetime after close, pinned-page lifetime after unmap; native/Linux shared regressions and resource baseline |
| AIO | Each syscall separately; context lifecycle/invalid handles, mixed valid-invalid submissions, short batches, completion contents/order constraints, eventfd, deadlines/signal masks, cancel/completion races, destroy with pending I/O, file types/O_DIRECT/alignment, exit and resource exhaustion |
| mremap | Anonymous/file-backed/shared/private, shrink/grow/move/fixed/duplicate/DONTUNMAP, content and object identity, offsets, heterogeneous protections, overlap/overflow, seals, wired pages, failure rollback and concurrent access |
| ptrace | Attach/seize distinctions, group/signal/syscall stops, INTERRUPT/LISTEN, fork/clone/exec/exit events and event messages, register round-trips/truncation, permissions, tracee/tracer exit and Linux debugger smoke test |
| O_TMPFILE | Filesystem support, access modes, invalid combinations, no directory entry before publication, linkat publication/permissions, O_EXCL no-link contract, failure cleanup, last-close deletion and readonly filesystem |
| PI requeue | Compare mismatch, source/destination validation, waiter transfer, PI boost/restore, timeout/signal races, owner death, competing lock owners, mixed waiter types and no lost wakeups |
| sockets | Each option plus getsockopt round-trip, cmsg layout/truncation, nonblocking readiness, error queue ordering/PMTU, UDP segment boundaries/checksums, fallback/rejection, pidfd identity/lifetime and credential checks |
| `perf_event_open` | Every advertised selector; disabled/enable/disable/reset and time fields; ID and CLOEXEC; size negotiation/extension tails; reserved fields; short/faulting reads and ioctls; dup/fork/exec/thread-exit/close races; explicit rejection for PMU, sampling, groups, mmap, CPU-wide and cross-target modes |

## Completion ledger

Allowed statuses: **pending**, **implemented / unvalidated**, **QEMU validated
(named architecture and subset)**. Document blockers and remaining contracts;
do not label a whole family complete when only a subset passed.

| Item/subset | Implementation | Positive/negative tests | QEMU evidence | Status |
|---|---|---|---|---|
| memfd original flags, name bounds and failure cleanup | Common Linux wrapper | `linux_abi_gate`: six memfd groups, including 1024-iteration churn | 2026-09-17: amd64 and arm64, three rounds each | QEMU validated for this subset |
| arm64 sync/readahead/umount2 parity and common error fixes | Shared Linux wrappers/native sync alias; regenerated arm64 tables | `linux_abi_gate`: six parity groups; existing amd64 regressions | 2026-09-17: amd64 and arm64, three rounds each | QEMU validated for this subset |
| OFD GETLK/SETLK/SETLKW on UFS and tmpfs | Native fcntl, kern_lockf, file lifetime, libthr; Linux64 translation | Shared native/Linux OFD suite and native rights/cancellation checks | 2026-09-17: amd64 and arm64, UFS/tmpfs, both APIs, three rounds | QEMU validated for this subset |
| F_SEAL_FUTURE_WRITE | Shared-memory writes, mappings, protection ceilings, deallocation and seal validation; Linux flag conversion | memfd_future native/Linux suites | 2026-09-17: amd64 and arm64, three rounds | QEMU validated for this subset |
| openat2 NO_SYMLINKS / NO_MAGICLINKS | Shared namei restrictions and proc/fdesc object-link identification; Linux flag conversion | linux_resolve: nine portable groups, one native-filesystem group and amd64 regression | 2026-09-17: amd64 and arm64, UFS/tmpfs, three rounds | QEMU validated for this subset |
| openat2 NO_XDEV | Shared namei mount-crossing rejection, absolute-link and fdesc handoff checks | Five additional linux_resolve groups, including nested/bind mounts and mount churn | 2026-09-17: amd64 and arm64, UFS/tmpfs and special mount paths, three rounds | QEMU validated for this subset |
| openat2 IN_ROOT | Shared per-lookup root and rename-lock tracking; Linux flag/errno policy | Eight additional linux_resolve groups, including concurrent ancestor rename and unprivileged access | 2026-09-17: amd64 and arm64, UFS/tmpfs, three rounds; Linux reference passed | QEMU validated for this subset |
| ZFS base configuration and OFD opt-in | Matching ZFS modules, ZFS-root images and strict filesystem/pool-health gate | Full ZFS/tmpfs matrix plus dataset boundaries, readonly rejection and clone isolation | 2026-09-17: zfs-run3, amd64 and arm64, 405 case runs each | QEMU validated for the named subsets |
| io_uring/squeue ring resize | Shared managed ring replacement and lifetime; Linux ABI output convention | Eleven native/Linux cases, five dedicated Linux oracle cases and full shared-engine matrix | 2026-09-19: amd64 ZFS-root, three rounds, 66 resize runs, zero diagnostics; `resize-full-gate13/results.json` | QEMU validated for the named contracts |
| io_uring register query | Linuxulator wire ABI and blind form; shared squeue admission masks and ring policy | Seven Linux 6.18.35 oracle cases; 21 candidate guest runs; complete shared-engine regression matrix | 2026-09-19: amd64 ZFS-root, `query-full-gate3/results.json`, zero diagnostics and clean shutdown | QEMU validated for the named contracts |
| io_uring/squeue parameter memory region | Shared managed and pinned-user backing, mmap lifetime and registered wait indices; Linux ABI/error translation | Eight Linux-specific and four dual-ABI Linux oracle groups; 48 focused runs; full shared matrix | 2026-09-19: amd64 ZFS-root, `mem-region-full-gate2/results.json`, 24 dedicated and 876 shared-option runs, zero diagnostics, clean shutdown | QEMU validated for named contracts; `min_wait_usec` pending |
| io_uring/squeue minimum wait interval | Shared two-stage CQ wait timer; Linux64 errno and signal-mask translation; direct and registered wait forms | Linux 6.18.35 oracle with positive, boundary and negative timer cases; nine focused candidate runs; complete shared and io_uring regression matrices | 2026-09-19: amd64 ZFS-root, `min-wait-full-gate/results.json`, 882 shared-option and 343 io_uring runs, zero diagnostics, clean shutdown | QEMU validated for named contracts; FEAT_MIN_TIMEOUT advertised |
| io_uring/squeue caller-owned rings and registered-fd-only setup | Shared pinned-user backing, replacement backing on resize, per-thread ring registry and copyout rollback; Linux64 setup translation | Eleven Linux oracle groups, two dual-ABI oracle groups, three focused rounds, complete shared and io_uring regression matrices | 2026-09-19: amd64 ZFS-root, `nommap-final-gate/results.json`, 894 shared-option and 33 dedicated runs, zero diagnostics, clean shutdown | QEMU validated for named contracts |
| io_uring/squeue SQ_AFF named contracts | Shared cpuset admission and poller CPU pin before setup completion; Linuxulator preserves Linux layout and thread state | Linux 6.18.35 oracle; valid pin and submission, invalid huge CPU, SQ_AFF without SQPOLL, caller thread mask independence, native poller mask inspection; three focused rounds and full shared matrix | 2026-09-19: amd64 ZFS-root, `sqaff-cpuset-full-gate/results.json`, 906 shared-option and 27 dedicated SQPOLL runs, zero diagnostics, final pages 0/0, healthy pool and clean shutdown | QEMU validated for named contracts; hotplug and post-setup cpuset transitions pending |
| io_uring/squeue SQPOLL task-run exclusion | Shared setup rejects SQPOLL with COOP_TASKRUN, TASKRUN_FLAG or DEFER_TASKRUN before ring allocation | Four invalid combinations repeated 16 times, followed by a valid SQPOLL ring; Linux 6.18.35 oracle, three focused Linux/native rounds, full shared matrix | 2026-09-19: amd64 ZFS-root, `taskrun-full-gate/results.json`, 912 shared-option and 30 dedicated SQPOLL runs, zero diagnostics, final pages 0/0, healthy pool and clean shutdown | QEMU validated for named contracts |
| io_uring/squeue SQPOLL layout combinations | Shared SQPOLL poller, issuer ownership, caller-owned backing and registered ring slots; Linux frontend preserves Linux setup/entry ABI | Linux 6.18.35 oracle; eight-ring `SINGLE_ISSUER` lifecycle stress, eight NOPs per caller-owned layout, wrong entry and mmap rejection, slot unregister/`EBADF`; three full rounds in native and Linux frontends | 2026-09-19: amd64 ZFS-root, `sqpoll-positive-full-gate4/results.json`, 918 shared-option, 39 `NO_MMAP`, 33 dedicated SQPOLL and 343 general io_uring runs; zero diagnostics, final pages and handles 0, healthy pool, clean shutdown | QEMU validated for named combinations; hotplug and post-setup cpuset changes pending |
| io_uring SPLICE explicit offsets | Linuxulator-only common splice path; direct syscall retains user-pointer offsets, io_uring supplies kernel-owned values | `splice_offsets`: explicit/current input and output positions, direct syscall baseline, pipe-offset `ESPIPE`, negative offsets, unknown flags, no-pipe descriptors, data and position preservation; Linux 6.18.35 oracle and three focused ZFS/tmpfs rounds | 2026-09-19: amd64 ZFS-root, `splice-full-gate/results.json`, 918 shared-option, 344 general io_uring, 39 `NO_MMAP` and 33 SQPOLL runs, zero diagnostics, final pages 0/0, healthy pool, clean shutdown | QEMU validated for named offset contracts; `SPLICE_F_FD_IN_FIXED` pending |
| io_uring SPLICE/TEE registered input | Shared registered-file lookup and temporary descriptor with captured rights; Linuxulator-only fixed-input flag translation | `splice_fixed_input`: closed original fd, explicit/current offsets, fixed output combination, registered pipe input, TEE source preservation, missing/empty/unregistered slots, bad flags and no side effects; Linux 6.18.35 oracle and three focused ZFS/tmpfs rounds | 2026-09-19: amd64 ZFS-root, `splice-fixed-full-gate5/results.json`, 918 shared-option, 345 general io_uring, 39 `NO_MMAP` and 33 SQPOLL runs, zero diagnostics and final pages/handles, healthy pool, clean shutdown | QEMU validated for named contracts; broader io_uring option matrix remains |
| io_uring WAITID child-exit lifecycle | Linuxulator `linux_common_wait` clears `si_signo` for a live child with `WNOHANG`; no native kernel ABI change | `waitid_lifecycle`: live child, invalid which/ID/options/SQE field, `WNOWAIT`, exit status, reaping and `ECHILD`; Linux 6.18.35 oracle and three focused ZFS/tmpfs rounds | 2026-09-19: amd64 ZFS-root, `waitid-full-gate/results.json`, 346 general io_uring, 918 shared-option, 39 `NO_MMAP` and 33 SQPOLL runs; zero failures/diagnostics, final pages/handles 0, healthy pool, clean shutdown; `manifest.json` pins hashes | QEMU validated for named lifecycle; pending-wait cancellation remains unimplemented and has a separate passing Linux oracle |
| io_uring WAITID pidfd and job-state options | Linuxulator P_PIDFD rejects negative IDs with EINVAL before lookup; shared squeue opcode forwards Linux id/options without a native ABI change | `waitid_pidfd`: live child, WNOHANG, WNOWAIT, reap, wrong/negative/closed descriptors, ECHILD; `waitid_stop_continue`: SIGSTOP/SIGCONT and CLD codes/status, final exit; Linux 6.18.35 oracles and three focused ZFS/tmpfs rounds each | 2026-09-19: amd64 ZFS-root, `waitid-both-full-gate/results.json`, 348 general io_uring, 918 shared-option, 39 `NO_MMAP` and 33 SQPOLL runs; zero failures/diagnostics and final resources, healthy pool, clean shutdown; `manifest.json` pins hashes | QEMU validated for named contracts; pending-wait cancellation remains unimplemented and opt-in oracle-only |
| io_uring socket `URING_CMD` subset | Linuxulator socket dispatch and existing sockopt translation; shared squeue retains fixed-file resolution and CQE lifecycle | Linux 6.18.35 oracles for Unix/TCP/UDP queue queries, scalar get/set options, nine-option matrix, fixed files, bad descriptors, unsupported targets, malformed flags/padding and pointer/length faults; 54 focused ZFS/tmpfs cases plus six dual-ABI probe runs | 2026-09-20: amd64 ZFS-root, `uring-cmd-full-gate383/results.json`, 383 io_uring, 918 shared-option, 39 NO_MMAP and 33 SQPOLL cases, zero diagnostics/nonzero results/final resources, healthy ZFS and clean shutdown; `manifest.json` pins hashes | QEMU validated for named socket subset; other `SOL_SOCKET` options, timestamps, driver commands and `URING_CMD128` remain |
| io_uring socket `URING_CMD` structured options | Linuxulator translates `SO_LINGER` and 64-bit receive/send timeouts and returns copied length in CQE | Linux 6.18.35 positive, truncation, pointer-fault and invalid-microsecond oracles; 66 focused ZFS/tmpfs socket/probe executions | 2026-09-20: amd64 ZFS-root `uring-cmd-full-gate385/results.json` passed 385 io_uring, 918 shared squeue, 39 NO_MMAP, 33 SQPOLL and 24 MEM_REGION runs; zero nonzero results, diagnostics and final resources; clean ZFS shutdown | QEMU validated for linger and 64-bit timeouts; other `SOL_SOCKET` options remain |
| io_uring socket `URING_CMD` TCP/Unix options | Linuxulator reuses generic `TCP_NODELAY` setter and translates Unix `SO_PASSCRED` get result; no shared-kernel change | Linux 6.18.35 positive, wrong-level, truncation and bad-pointer oracles; 78 focused ZFS/tmpfs socket/probe executions and six shared probe-scope runs | 2026-09-20: amd64 ZFS-root `uring-cmd-full-gate387/results.json` passed 387 io_uring, 918 shared, 39 NO_MMAP, 33 SQPOLL and 24 MEM_REGION runs; zero nonzero results, diagnostics and final resources; clean shutdown | QEMU validated for named TCP/Unix options |
| io_uring socket `SO_PEERCRED` command | Linuxulator translates native Unix peer credentials and returns truncated CQE length | Linux 6.18.35 full/short output and bad-pointer oracle; 84 focused ZFS/tmpfs socket/probe executions and six shared probe-scope runs | 2026-09-20: amd64 ZFS-root `uring-cmd-full-gate388/results.json` passed 388 io_uring, 918 shared, 39 NO_MMAP, 33 SQPOLL and 24 MEM_REGION runs; zero nonzero results, diagnostics and final resources; clean shutdown | QEMU validated for `SO_PEERCRED` |
| io_uring socket pacing, timestamps and `URING_CMD128` | Linuxulator handles pacing/timestamp get values and dispatches socket command 128 on SQE128 rings; shared squeue retains its existing 128-byte stride, file resolution and CQE path | Linux 6.18.35 pacing/timestamp oracles; Linux 7.1.5 SQE128 positive, probe and ordinary-ring negative oracles; 114 focused ZFS/tmpfs io_uring cases plus six shared probe-scope runs | 2026-09-20: amd64 ZFS-root `uring-cmd-full-gate392/results.json` passed 392 io_uring, 918 shared, 39 NO_MMAP, 33 SQPOLL and 24 MEM_REGION runs; zero nonzero results, diagnostics and final resources; clean shutdown | QEMU validated for pacing, timestamps and socket command 128 |
| io_uring socket `GETSOCKNAME` command | Linuxulator reuses direct local/peer name translation; shared squeue command completion is unchanged | Linux 7.1.5 local/peer, truncation, bad pointer, invalid selector, unexpected field and unconnected peer oracles; 120 focused ZFS/tmpfs io_uring executions plus six shared probe runs | 2026-09-20: `uring-cmd-full-gate393/results.json` passed 393 io_uring and 918 shared-option executions; zero diagnostics, nonzero results and final resources; healthy ZFS and clean shutdown | QEMU validated for named command |
| io_uring mixed 64/128-byte SQEs | Shared squeue consumes two contiguous 64-byte slots for NOP128 or socket URING_CMD128; Linuxulator validates the socket command on SQE_MIXED rings | Linux 7.1.5 oracle covers mixed 64/128/64, plain-ring rejection, incomplete pair, final physical slot, incompatible setup and one-entry overflow; focused ZFS-root VM ran native and Linux shared tests plus socket command on ZFS/tmpfs | 2026-09-20: `uring-cmd-full-gate396/results.json` passed 394 io_uring, 924 shared-option, 39 NO_MMAP, 33 SQPOLL and 24 MEM_REGION executions; zero failures, diagnostics and final resources; healthy ZFS and clean shutdown; `manifest.json` pins artifacts | QEMU validated for mixed NOP128 and socket URING_CMD128 contracts |
| `perf_event_open` current-thread software counters | Linuxulator event fd over native per-thread runtime/rusage; shared file-type identifier only | 13 named positive/negative/lifetime cases; five focused rounds on ZFS and tmpfs; Linux 7.1.5 reference matrix | 2026-09-24: focused amd64 WITNESS/INVARIANTS guest, 130/130; full gate pending | Implemented; focused QEMU validated, full gate pending |
| Remaining implementation rows | Pending | Pending | None | Pending |

## First batch evidence (2026-09-17)

The executed gate is `tools/test/linuxulator/qemu-gate.py`, with image setup
instructions in `tools/test/linuxulator/README.md`. Results were captured under
`/tmp/linuxulator-gate-20260917/run1/`: `results.json`,
`amd64.console.log`, and `arm64.console.log`. Both QEMU processes exited 0;
36/36 case runs passed on each architecture (12 named groups, three rounds).
The amd64 `linux_fileflags`, `linux_machdep2`, and `linux_openat2` regressions
also passed. QEMU was 11.1.1, TCG, two vCPUs, 2 GiB per FreeBSD guest, UFS plus
a disposable tmpfs mount, with INVARIANTS and WITNESS enabled. The arm64 CPU was
cortex-a72. Guest logs contain hashes of the kernel, both Linuxulator modules,
and the executed test binary. This is raw syscall evidence, not full runtime,
database or desktop-application qualification.

| Entry point | Positive cases | Negative cases and boundaries |
|---|---|---|
| memfd_create | All four existing CLOEXEC/ALLOW_SEALING combinations, empty name, 246–249-byte names, read/write, dup, seals and close | Unknown bits combined with supported flags, all 63 huge encodings without HUGETLB, NULL/unmapped/guard-page input, 250-byte/overlong names, flags-before-pointer ordering, repeated failure/create/close without descriptor growth |
| readahead | Readable regular file, zero count, beyond EOF, offset preservation, content preservation, negative offset behavior checked on Linux 6.18 | Invalid/closed, write-only, O_PATH, directory, pipe and socket descriptors; signed count boundary and offset-plus-length overflow |
| sync | Written file and repeated calls, including arbitrary argument registers (the call has no arguments) | No argument-validation contract; crash/power-loss durability was not simulated |
| umount2 | Create/mount/unmount/remove a disposable tmpfs mount | Missing path, NULL pointer, unknown flags, unsupported DETACH/EXPIRE, NOFOLLOW symlink, existing non-mountpoint, unprivileged root-mount attempt |

The first execution exposed a readahead signed-count mismatch and native
unmount's different missing-path errno. The previous amd64 regression expected
success for a count of SIZE_MAX; that expectation was corrected after the
Linux reference rejected it. Name-boundary review also corrected the memfd
buffer limit from 246 to 249 name bytes. All these changes are in the binaries
that passed both final FreeBSD guest runs.

The portable cases were additionally exercised on Alpine Linux 3.24,
Linux 6.18.35-0-virt, under amd64 QEMU. Known unsupported Linuxulator modes
are separately tested as rejection contracts. Reference semantics:
[Linux memfd implementation](https://github.com/torvalds/linux/blob/master/mm/memfd.c),
[Linux readahead implementation](https://github.com/torvalds/linux/blob/master/mm/readahead.c).
Negative-offset readahead behavior is version-dependent; the tests record the
6.18 reference behavior and do not claim it matches every later Linux release.

No native kernel mechanism was changed in this batch: readahead is shared
between the two Linux ABIs, sync reuses the native syscall, and memfd/unmount
validation stays in Linuxulator. OFD locks, new seals, additional openat2
resolution constraints and all other pending rows remain unimplemented by
this batch and must go through their own positive/negative QEMU gates.


## OFD implementation record

The entry points are native `fcntl(F_OFD_GETLK/F_OFD_SETLK/F_OFD_SETLKW)`
(commands 25–27) and Linux64 `fcntl` commands 36–38 on amd64 and arm64.
Before this change Linuxulator rejected all three commands. Native locks now
use a `struct file` owner distinct from both process locks and flock owners;
last-reference cleanup runs in the vnode file close path. POSIX record locks
conflict with OFD locks, including within one process. Flock remains a separate
namespace. OFD waits use existing wakeup edges but are excluded from the
process deadlock-detection graph. Query results combine contiguous internal
fragments belonging to the same OFD owner and lock type.

The native command interface, range handling, lifecycle, Capsicum checks,
filesystem opt-in and diagnostic lock type are shared. Linux numbering,
`struct flock` conversion and Linux no-conflict query output remain in
Linuxulator. Blocking native OFD requests use libthr cancellation handling.
UFS and tmpfs explicitly advertise support; other filesystems return
`EOPNOTSUPP` until their handlers have been audited and gated. Linux32 OFD
commands remain unsupported and are not covered by these 64-bit results.

`tests/sys/kern/ofd_lock.c` builds as either native FreeBSD or freestanding
Linux code. Fifteen groups cover ranges/conversions/negative lengths/EOF,
invalid command arguments and access modes, dup/unrelated-close ownership,
POSIX conflicts and owner reporting, flock independence, fork and exec
lifetime, blocking wakeups on unlock and last close, signal interruption,
killed waiters, 512 descriptor-reuse iterations, cyclic waits, guarded/read-only
memory, and SCM_RIGHTS ownership while queued and after receipt.
`ofd_native_extra.c` covers Capsicum, internal flag visibility, lock diagnostics,
and 16 cancellation/cleanup cycles. Both suites run on UFS and tmpfs in each
VM. Outer timeouts turn hangs into failures.

The oracle is Alpine Linux 3.24, kernel 6.18.35, using the portable Linux build.
References: [Linux lock implementation](https://github.com/torvalds/linux/blob/v6.18/fs/locks.c)
and [OFD locking contract](https://man7.org/linux/man-pages/man2/F_OFD_SETLK.2const.html).
The reference exposed that OFD GETLK accepts an unlock query; the first FreeBSD
VM run exposed contiguous-range reporting differences. Both are regression
assertions. Native cancellation additionally failed when accidentally linked
against the old library, demonstrating the check detects a missing libthr change.

Remaining qualification beyond this subset includes Linux32, memfd/shm-backed
OFD locks (these are not vnode-backed files), other filesystems,
forced-unmount races, systematic fault injection and full application workloads.
Those are not implied by the positive/negative and lifetime results above.


OFD final evidence: `/tmp/linuxulator-gate-20260917/ofd-run6/` contains the
complete passing gate on both architectures: 180 OFD case runs, six native
rights/introspection/cancellation runs, and the earlier 36 ABI runs per guest;
amd64 also passed the three existing regression binaries. Each native extra
run performs 16 cancellation cycles. No recognized panic/WITNESS diagnostic
was present, and both QEMU processes exited zero. All 15 portable OFD groups
passed the Linux oracle (`ofd-linux-reference4.console.log`). The preceding
`ofd-run5` is a failed run: its amd64 QEMU process received SIGKILL; its partial
results were not counted as a pass. Immutable OFD source evidence was saved as
`ofd-source.tar.gz`, `ofd-source.sha256`, `ofd-tracked.patch`, and
`ofd-build-provenance.json`, alongside kernel/module build logs and native
linker maps. Guest console logs contain hashes of all executed binaries.


## Future-write seal implementation record

Native and Linux `fcntl(F_ADD_SEALS/F_GET_SEALS)` now accept/report
`F_SEAL_FUTURE_WRITE` (0x10). The earlier Linux wrapper rejected it. Enforcement
is shared in `uipc_shm`: writes and deallocation fail, new shared mappings lose
maximum write protection, and old shared mappings retain their rights. New
shared writable mmap requests fail with EPERM; ordinary read-only-descriptor
permission failures remain EACCES. Private copies remain writable. Neither
size seal is implied. Native seal addition now also rejects unknown bits and
read-only descriptors before mutation. Kernel writable mapping creation is
serialized with seal changes and honors write seals; full write sealing counts
existing kernel mappings as writable references.

The public test matrix covers native and Linux fcntl, mmap, mprotect,
write/pwrite/writev, ftruncate and deallocation (native fspacectl versus Linux
fallocate PUNCH_HOLE|KEEP_SIZE). Failure checks assert the seal set and file
contents remain unchanged. Dup and fork retain the same sealed object;
closing the descriptor does not revoke an existing writable mapping. Linux
reference source: [memfd sealing and mapping checks](https://github.com/torvalds/linux/blob/v6.18/mm/memfd.c).
Execution flags and F_SEAL_EXEC remain pending. Large-page configurations,
non-default guest page sizes, direct in-kernel shm_map clients and systematic
concurrent seal/mmap fault injection are not yet qualified by this subset.


The new tests also identified Linux wrapper bugs in existing entry points:
`pread` performed a vnode-only check after a successful memfd read, and
`fallocate` rejected native shm descriptors before their supported operations.
The wrapper now preserves successful memfd pread results and permits shm
preallocation/hole punching. Signed offset-plus-length overflow is translated
to Linux EFBIG before entering native fspacectl, whose contract uses EINVAL.
`io_contract` covers successful reads, offsets, EOF, invalid pointers/fds,
negative offsets, pipes, zero/negative/overflowing hole ranges, a no-op punch
past EOF, and content preservation after denied writes/punches. The resize
group covers memfd preallocation and F_SEAL_GROW enforcement as well.


Future-write final evidence: `/tmp/linuxulator-gate-20260917/seal-run3/` passed
on amd64 and arm64. Each guest produced 39 seal/I/O cases, 180 OFD cases,
six native rights/cancellation cases and the earlier 36 ABI cases (261 total),
with the three additional amd64 regressions also passing. Both QEMU processes
exited zero and the diagnostic scan was clean. All six portable seal/I/O groups
passed Linux 6.18.35 (`seal-linux-reference4.console.log`). Intermediate failed
runs remain preserved. Source snapshot/hash, patch and build provenance are
saved as `seal-source.tar.gz`, `seal-source.sha256`, `seal-tracked.patch`, and
`seal-build-provenance.json` in the artifact directory. This validates the
named user-visible subsets, not the remaining execution-seal or path-resolution
backlog.


## Link-resolution implementation

`RESOLVE_NO_SYMLINKS` and `RESOLVE_NO_MAGICLINKS` use shared namei
constraints, passed through `kern_openat_resolve`. This introduces no native
syscall numbers or user-visible open flags. Constraints survive lookup
restarts; unsupported fast lookup modes fall back to locked namei. Pseudofs
marks process-object links, and fdescfs rejects descriptor-to-vnode handoffs
before they bypass ordinary symlink handling. Linuxulator retains flag and
errno translation. Native procfs object links carry the same classification.

`linux_resolve.c` exercises plain paths, final and intermediate links,
dangling and cyclic links, trailing slashes, O_PATH/O_NOFOLLOW exceptions,
failed create/truncate without side effects, proc object links, descriptor
links, renamed directories and unlinked link descriptors, BENEATH composition,
permission ordering, bad pointers and guarded structure boundaries, unknown
64-bit resolve flags, repeated cached lookups and concurrent atomic replacement
of a file by a symlink. Each group must pass three times on UFS and tmpfs on both architectures.
An additional group checks native procfs and default, rdlnk and nodup fdescfs
mounts. The nodup mode has no link vnode to retain and rejects constrained
opens even with O_PATH|O_NOFOLLOW.
The Linux reference uses the same freestanding binary; its nine groups passed
Linux 6.18.35 (`resolve-linux-reference2.console.log`). Semantics follow the
[Linux openat2 manual](https://www.man7.org/linux/man-pages/man2/openat2.2.html).
NO_XDEV and IN_ROOT were pending at this stage; their subsequent evidence is
recorded below. CACHED still requests fallback with EAGAIN.


Link-restriction evidence: `resolve-run3/results.json` reports both amd64 and
arm64 passing all 321 case runs per guest (60 link-resolution, 39 seal/I/O,
180 OFD, six native rights/cancellation and 36 initial ABI cases), plus three
amd64 regression binaries. Both QEMU processes exited zero, with no recognized
kernel fault diagnostics. All nine portable groups passed the final Linux
reference run. `resolve-run1` is preserved as a failed run: the raw test used
amd64 O_DIRECTORY/O_NOFOLLOW constants on arm64; correcting the architecture
constants made both guests pass. `resolve-run2` passed the UFS-only link matrix.
Snapshot and provenance: `resolve-source.tar.gz`, `resolve-source.sha256`,
`resolve-tracked.patch`, `resolve-build-provenance.json`. The saved document
predates the final result; kernel/test contents match the final run.


## Mount-crossing restriction implementation

`RESOLVE_NO_XDEV` uses a separate shared namei constraint. Native
`NOCROSSMOUNT` means to stop at the covered vnode, which does not implement
Linux's EXDEV rejection contract. The new constraint rejects downward mount
traversal, upward traversal from a mounted root, absolute symlink jumps to a
different mount, and fdesc descriptor/vnode jumps. Invalid flags and Linux
error translation remain in Linuxulator. Fast lookup falls back to locked
lookup for this constraint as well.

Five additional groups cover same-mount positive cases, nested tmpfs and
nullfs mounts (Linux bind mounts in the oracle), relative `..`, absolute
symlinks, link restriction composition, final-link exceptions, failed create
rollback, renamed directory descriptors, descriptor cleanup, and concurrent
mount/unmount replacement. The mount-race test synchronizes the first denied
lookup, then performs 10,000 constrained opens while another process installs
and removes 32 tmpfs mounts containing a distinct forbidden file. Successful
opens must always read the original underlying file. IN_ROOT was pending at
this stage; its subsequent evidence is recorded below.


NO_XDEV's initial dual-architecture run, `xdev-run1/results.json`, passed 351
case runs per guest plus all amd64 regressions, including 32 mount/unmount
cycles per mount-race case. Review then identified two additional native paths:
legacy MNT_UNION fallback and autofs lookup triggering. The former now rejects
crossing to its covered filesystem; the latter rejects before requesting an
automount. The native-filesystem group checks both paths. This extension must
pass a fresh dual-architecture gate before its status is updated.


NO_XDEV final evidence: `xdev-run2/results.json` passed 351 case runs on each
architecture, plus all three amd64 regression binaries. The native-filesystem
group passed its autofs and legacy union-fallback checks in every round.
Both QEMU processes exited zero; diagnostic scans were clean. The 14 portable
groups passed Linux 6.18.35 (`xdev-linux-reference2.console.log`). Final source
and build records are `xdev-final-source.tar.gz`, `xdev-final-source.sha256`,
`xdev-final-tracked.patch`, and `xdev-final-build-provenance.json`. The saved
source document precedes this result update. Filesystem topology is literal:
linprocfs's fd-directory redirection to fdescfs crosses native mounts, so callers
can open that directory first before applying NO_XDEV to its descriptor entries.


## Scoped-root implementation

`RESOLVE_IN_ROOT` supplies a reference-held, per-lookup root to namei. Initial
absolute paths use dirfd; absolute symlinks restart at that root; `..` clamps
there. Native rename-lock tracking keeps traversed local directory ancestry
stable. Root references and locks are released on success, failure and lookup
restart. The process root and cwd are unchanged. Pre-existing capability or
inherited BENEATH restrictions are never relaxed: these combinations reject.
Object-link traversal rejects with EXDEV unless an explicit link restriction
requires ELOOP; the final O_PATH|O_NOFOLLOW exception remains available.

This implementation rejects traversal on network filesystems with EOPNOTSUPP,
because local rename locks cannot exclude remote renames. It also rejects
legacy union fallback that could leave the scoped root. UFS/tmpfs and nullfs
are the initial test scope. Capsicum composition, remote filesystems, forced
unmount and ABI-root jail combinations require further dedicated qualification.

Eight groups add scoped relative/absolute paths, repeated `..`, slash-only
paths, absolute and relative symlink targets, failed-create rollback, flag and
pointer errors, magic-link precedence, nested/bind mounts, renamed roots,
fork lifetime and descriptor cleanup. The rename-race group performs 6,000
scoped opens while a child moves an ancestor out of and back into scope 1,000
times; every successful read must come from the protected tree. All 21 portable
resolution groups passed Linux 6.18.35 (`inroot-linux-reference1.console.log`).


`inroot-run1/results.json` passed the initial IN_ROOT matrix on both
architectures: 393 case runs per guest plus the amd64 regressions. A final
unprivileged-access group now verifies that a held directory descriptor and
scoped root do not bypass search, read, create or truncate permissions. The
native-filesystem group also asserts IN_ROOT's union-fallback rejection. These
additions are covered by the final rerun below; no broader family completion
is implied.


IN_ROOT final evidence: `inroot-run2/results.json` passed all 399 case runs
on each architecture: 138 resolution, 180 OFD, six native rights/cancellation,
39 seal/I/O and 36 initial ABI cases. All three additional amd64 regression
binaries passed. Both QEMU processes exited zero; there were no detected kernel
faults or lock-order reports. All 22 portable resolution groups passed Linux
6.18.35 (`inroot-linux-reference2.console.log`), including unprivileged access.
The native union-fallback checks passed on both FreeBSD guests. This validates
the named subset; the dedicated qualifications listed above remain outstanding.

Final source, hashes, patch, kernel configurations and build/result provenance
are saved under `/tmp/linuxulator-gate-20260917/` with the prefix
`inroot-final-`. The document and runner README were updated after the test to
record results and the VM-only policy; executable test and kernel sources were
unchanged. The running host kernel and its loaded modules were not replaced.


## ZFS base-system qualification

The supported base runs on ZFS. The initial ZFS-root run,
`zfs-run1/results.json`, passed 399 case runs on each architecture and the three
amd64 regressions. It used the same kernel changes as the preceding IN_ROOT
batch plus a rebuilt ZFS module advertising `VFCF_OFDLOCKS`: ZFS delegates
VOP_ADVLOCK to `vop_stdadvlock` and the shared lock manager. Linux layouts,
command numbers and error conversion remain in Linuxulator. `fcntl(2)` now
lists ZFS among the supported OFD filesystems.

The final matrix adds `linux_resolve:zfs_datasets`, repeated three times from
both ZFS and tmpfs. It exercises `openat2` across sibling ZFS datasets, allowed
reads and rejected NO_XDEV crossings, IN_ROOT clamping at dataset roots,
readonly-clone create/truncate rejection, absence of a file after denied
creation, unchanged contents after rejection, and clone isolation after writes
to the snapshot origin. Fixtures are created and destroyed inside each VM.
The 15 native and Linux OFD groups and the native cancellation/rights cases
all run on ZFS as well as tmpfs. Seals, initial ABI cases and existing amd64
regressions also execute from the ZFS-root guest.

`guest-gate.sh` verifies ZFS root and the primary test filesystem, records
pool/dataset status and module hashes, and requires successful final pool sync
and healthy pool status. `build-zfs-images.sh` uses makefs to create private
images without importing pools into the host. All runtime checks remain inside
disposable guests. The expanded matrix requires 405 case runs per architecture;
its acceptance result is recorded below.

The first expanded amd64 attempt (`zfs-run2`) was interrupted by SIGKILL of the
QEMU process. No syscall failure had been reported, but the incomplete run is
failed evidence and does not qualify amd64. Its console and results are retained.


Final ZFS evidence: `zfs-run3/results.json` passed **405 case runs on each
architecture**, plus the three additional amd64 regression binaries. Both
QEMU processes exited zero. Root and primary test storage were ZFS; the final
pool sync and healthy-status checks passed. There were no detected kernel
faults or lock-order reports. The current freestanding resolution binary also
passed all 22 portable groups on Linux 6.18.35
(`zfs-linux-reference.console.log`). `zfs-run2`'s arm64 result passed the same
405-case matrix; its interrupted amd64 result remains failed evidence.

Source, patch, kernel configurations, image/build/result hashes and logs are
preserved under `/tmp/linuxulator-gate-20260917/` with `zfs-final-` records and
`zfs-images3/` images. Historical UFS-root evidence remains intact. No test
kernel or module was installed into the running host.

## Next phase: option completeness

After this gate passed, the user requested a renewed option-level audit of
implemented syscalls, starting with io_uring. The source review and prioritized
work list are in [next-phase options](linuxulator-next-phase-options.md), with
an explicit admission inventory and source hashes. This adds to the existing
pending-syscall backlog. io_uring/squeue option correctness is not certified by
this 405-case batch; the next phase must bring those suites into the ZFS-root
amd64/arm64 gate and reproduce the listed semantic findings before expanding
accepted options.


## First shared squeue option batch (2026-09-17)

The shared BSD engine now implements `IORING_SETUP_NO_SQARRAY`, including
allocation/layout, zero array offset and direct masked-head SQE indexing.
The shared engine rejects unknown SQE bits and unregistered personalities
before issuing requests, and pairs acquire/release operations for SQ/CQ
publication and consumption. Linux's invalid mmap-offset ENOMEM policy is
selected by its front end; native BSD retains EINVAL. No new Linux-only copy
of the ring engine was introduced.

The gate now requires **738 case runs per architecture**: the preceding 405,
60 option runs (ten groups, both APIs, three rounds), three native squeue runs
and all 270 Linux io_uring groups. The older Linux test helper and suite are
ported to arm64, including syscall numbering/entry, *at/pipe2/clone use and
signal return. The three existing amd64 regression binaries are required too.
The native raw-mmap test helper uses the pointer-width `__syscall` result.

Nine portable option groups cover layouts/combinations, invalid setup and
mapping inputs, legacy index indirection, queue wrap, real I/O, malformed SQE
rejection without writes, linked cancellation, descriptor/fork lifetime, and
4096 submissions per layout with a separate concurrent producer. All nine
passed Linux 6.18.35 (`options-linux-reference7.console.log`). The tenth group
requires ZFS reservation-allocation rejection with unchanged size and contents;
the successful allocation case runs on tmpfs. This does not add ZFS
VOP_ALLOCATE support. The arm64 object code was also checked for the intended
LDAR/STLR operations; QEMU observations alone are not a weak-memory proof.

The preceding `options-run4/results.json` passed the initial 732-case matrix
on both architectures. The final memory-ordering/concurrency expansion,
`options-run5/results.json`, passed **738 case runs on each architecture**,
plus three amd64 regressions. Both QEMU processes exited zero with complete
markers, healthy ZFS pools, and no detected kernel faults or lock-order reports.
Final immutable source, hashes, patches and build provenance are
`options-final-*` under `/tmp/linuxulator-gate-20260917`; the tested images
are `options-images5/`. Matching guest kernel hashes were verified against
the staged artifacts. The provenance preserves kernel build-version files
as well as the repository HEAD, since unrelated userland commits occurred
during this work.

Earlier failed evidence is retained. `options-run1` exposed a truncated native
mmap return in the test helper and the old allocation test's assumption that
ZFS supports reservations. `options-run2` was aborted for a missing case-list
input redirection; it also recorded one 30-second timeout in the existing ZFS
pathname race. Subsequent complete runs passed that case in every repetition;
the isolated timeout has no confirmed root cause and must not be erased.
`options-run3` lost amd64 to another test script's broad QEMU process-name kill;
its arm64 run passed 732 cases. The gate now accepts distinct executable paths
and uses hash-identical private QEMU copies, without modifying the other VM.
Linux-reference attempts 4 and 6 were infrastructure failures (invalid FAT
image geometry and an interrupted guest respectively); attempts 5 and 7
passed their complete eight- and nine-group inventories.

These are named-subset results. Registered-buffer pinning, per-operation RWF
and ioprio semantics, link-timeout behavior, native PROBE accuracy, and the
remaining setup/enter/register options still require the next-phase work.
All runtime tests used disposable VMs; no test kernel or module was installed
or loaded into the running host.


## Front-end PROBE and input-validation batch (2026-09-17)

The shared PROBE implementation no longer advertises Linux-only dispatch
operations on native rings. Shared squeue advertises 27 core operations;
Linux's front end supplies a callback describing its 35 extension operations.
The shared wire-protocol validation rejects a null probe pointer, counts above
256, and any nonzero byte in the effective input buffer, including operation
entries. The output stays bounded by the requested count and known opcode
range. The comparison is pinned to
[Linux v6.18 io_uring/register.c](https://github.com/torvalds/linux/blob/v6.18/io_uring/register.c).

`probe-baseline-run/results.json` reproduced both defects in ZFS-root QEMU on
amd64 and arm64 before the fix: the native scope check failed, and both APIs
accepted nonzero input. The other four baseline groups passed. Those results
are regression evidence, not passing qualification.

Seven new dual-ABI groups cover all 65 local opcode slots, rejection of each
unsupported native opcode, actual Linux OPENAT execution versus native
no-create rejection, every nonzero input byte, header-only and short probes,
output canaries, oversized counts and error precedence, ordinary/invalid
file descriptors, unreadable input, unwritable output, page-boundary faults,
unmapped memory, dup/fork/close lifetime, concurrent queries with submissions,
and queries after dropping privileges. Native permission checks additionally
run after entering Capsicum. The opcode-inventory group is specific to these
BSD front ends; all six portable new groups plus the preceding nine portable
groups passed Linux 6.18.35 (`probe-linux-reference1.console.log`).

The executable gate now requires **780 case runs per architecture**, including
102 option runs (17 groups, two APIs, three rounds), plus the three existing
amd64 regressions. The complete `probe-run1/results.json` passed on **both amd64 and arm64**
with zero case failures, successful QEMU exits, healthy ZFS pools and no
detected kernel faults or lock-order reports. The three amd64 regressions
also passed. Guest kernel and linux64 hashes match the staged artifacts.
Final source/build records are `probe-final-*` and the tested images are
`probe-images1/` under
`/tmp/linuxulator-gate-20260917`.

This closes front-end dispatch-advertisement and PROBE input-validation gaps.
It does not certify every mode of an advertised operation: known linked-timeout,
registered-buffer, RWF/ioprio and other option semantics remain in the next
phase. All runtime testing remains inside disposable VMs; the running host
kernel and modules were not replaced.

## Per-I/O RWF batch (2026-09-17)

**Qualified:** `rwf-run7/results.json` passed all **930 case runs on each
architecture**, plus three amd64 regressions. Both QEMU guests used ZFS roots,
shut down successfully, reported healthy pools and had no detected kernel
faults or lock-order reports. `rwf-durability-run3/results.json` additionally
passed abrupt-termination/reboot verification of **28 synchronous-write files
per architecture**. Linux 6.18.35 passed all **25 portable option groups** in
`rwf-linux-reference5.console.log`. Exact source, configurations, build commands,
artifacts and evidence hashes are frozen as `rwf-final-*` under
`/tmp/linuxulator-gate-20260917`.

Changes in shared `file.h`, `sys_generic.c`, `vfs_vnops.c`, `uipc_shm.c` and
`sys_squeue.c` implement per-write sync and append policy. Linux-specific raw
flag decoding stays in `linux_file.c` and the Linux ring front end. The running
host kernel and its modules are not modified. The normal gate inventory is
930 case runs on each ZFS-root architecture, with native/Linux RWF matrices on
ZFS and tmpfs and six direct Linux RWF regression runs.

Before the fixes, `rwf-baseline-run/results.json` reproduced ignored flags,
incorrect append behavior, linked side effects and concurrent append failures
on both amd64 and arm64. `rwf-linux-reference1.console.log` exposed an overly
broad portable-rejection test: supported Linux policies must be distinguished
from currently unsupported BSD policies. Run 2 timed out during Linux boot.
Run 3 passed nine portable RWF groups but exposed a nonportable raw-fd reuse
assumption; the BSD worker reference-lifetime check remains strict and is
excluded from the portable inventory. Keep every failed attempt as evidence.

Synchronous-write qualification additionally requires
`tools/test/linuxulator/guest-rwf-durability.sh` and
`tools/test/linuxulator/qemu-rwf-durability.py`. Build separate images whose
`init_rc` points to that guest script. The controller requires a passed normal
gate, creates private qcow2 overlays, kills only its own QEMU child after the
write marker, and reboots the same overlay to verify all 28 files. Initial
file names/zero contents are pool-synced before the writes; no pool sync or
clean shutdown follows the writes before the cut. Increasing the guest TXG
timeout reduces incidental commits but does not rule out pressure-triggered
TXGs. The test cannot simulate loss of the host's or physical disk's caches.
Missing markers, wrong data, faults, unhealthy pools or unsuccessful reboots
fail qualification. The final qualified results above supersede the failed
attempts retained below.

The expanded amd64 run (`rwf-run2`) passed all 132 new ring RWF runs but
failed qualification: six direct regressions were omitted from the image
manifest, and tmpfs unmount returned EBUSY. The image builder now checks
mandatory payload entries before invoking makefs. A focused guest
(`rwf-debug-amd64.console.log`) isolated persistent EBUSY to registered-file
I/O for both native and Linux rings; all other groups unmounted successfully.
`finstall()` acquires its own descriptor reference, so the temporary reference
in `sq_fixed_install()` must be dropped on success as well as failure. This
pre-existing leak is fixed in shared squeue. Unmount remains mandatory, with
no forced unmount or retry masking the regression in the acceptance gate.
`rwf-run1` was superseded before completion by the expanded matrix; neither
that run nor `rwf-run2` qualifies any final source. Their interruption records
and consoles are preserved.

`rwf-run4` passed the 648 cases before the old io_uring suite, including all
new RWF tests and successful tmpfs unmount, but stopped on a harness typo:
its old-suite inventory expected 280 instead of 270. The corrected check now
runs before the long matrix. `rwf-run5` did not boot because the QEMU firmware
path in the launch command was mistyped. Both failures are retained; neither
is a qualified run. The replacement launcher derives firmware and executable
paths from the preceding successful PROBE gate commands.

`rwf-run6` completed both architectures cleanly with all new RWF cases passing,
but three older cases failed on each: `enter_fast_poll_zero`, `read_multishot`
and `fastpoll_read_sock`. Fast-poll retry had overwritten the SQE's rw_flags
union with a poll event mask, which the new validator correctly rejected.
Readiness now derives from the opcode without altering the original SQE.
A new native/Linux `rwf_retry` group checks flat and vectored nonblocking-pipe
reads with several valid flag combinations. This raises the normal gate to
930 cases per architecture; the original three regressions remain mandatory.

The first crash-image attempt (`rwf-durability-run`) booted the normal gate:
loader.conf.local overrode the init_rc set in loader.conf. It was stopped
without claiming a durability result. Both settings are now changed together;
the image builder rejects conflicting init_rc values, and the crash controller
rejects the normal-gate startup marker immediately.

The second crash-preparation attempt (`rwf-durability-run2`) entered the recovery
shell because the minimal image did not contain `touch`. Preparation now uses
shell redirection to create its marker, and the controller detects a recovery
shell immediately. The attempt was stopped and remains unqualified.


## Registered-buffer batch (2026-09-17, qualified named contracts)

The implementation is shared by native squeue and Linux io_uring. `sys_squeue.c`
owns immutable registered-buffer generations, kernel aliases of held pages,
per-request lifetime references, all-vector bounds validation and aggregate
real-uid MEMLOCK/system page charges. ABI-specific syscall dispatch and error
translation remain in the Linux front end.

Shared VM support in `vm_map.c` tracks externally writable pinned mappings.
Temporary system wiring stabilizes registration, after which munmap remains
permitted. Backing-object references prevent native anonymous-map coalescing
from reusing registered storage. Private mappings are eagerly copied for a
forked child, including mappings currently read-only or inaccessible. Mapping
identities survive clipping and prevent unregister from altering a replacement
mapping at the same address. Dirty-page handling locks the retained object and
accounts for invalidation. Kernel aliases and held pages outlive a detached
table until its last issued request is released.

The mandatory matrix now contains fifteen buffer groups: `register`, `faults`,
`ranges`, `vectors`, `remap`, `protect`, `retry`, `async`, `fork`, `cow`,
`mapped_file`, `vm_race`, `limits`, `links` and `churn` (each prefixed `buffers_`). Both APIs
run each group three times on ZFS and tmpfs in each ZFS-root architecture.
The complete gate requires 1110 runs per architecture plus three amd64
regressions, matching before/after wired-page counts, successful unmounts,
healthy pools, clean shutdown and no kernel fault diagnostics.

The Linux reference is pinned to [v6.18 resource handling](https://github.com/torvalds/linux/blob/v6.18/io_uring/rsrc.c)
and [registration dispatch](https://github.com/torvalds/linux/blob/v6.18/io_uring/register.c).
Missing/out-of-range fixed slots return EFAULT; ordinary registration rejects
a NULL array; individual `{NULL, 0}` entries are sparse. All fixed vectors
must fit the selected buffer and zero-length fixed-vector entries fail. Older
regressions that accepted an unregistered READV_FIXED destination or expected
EINVAL for a missing slot have been corrected.

Early failures are retained under `/tmp/linuxulator-gate-20260917`.
`buffers-run1` failed fixed readiness retries and native remap checks and did
not reach its page-release gate. `buffers-debug-run1` additionally reproduced
an INVARIANTS dirty-invalid-page panic during close/worker cleanup. These runs
are failure evidence, never passing qualification. Subsequent builds add fixed
read/write readiness handling and retained backing-object ownership.

The implementation currently retains the registration owner's vmspace until
the table retires, counts overlapping page references conservatively, limits
registration to 1024 slots, and applies an explicitly lowered MEMLOCK limit
even to privileged BSD callers. Buffer accounting is aggregate per real uid;
existing ring-backing accounting and RACCT integration are separate remaining
audit items. Buffer updates/tags, cloned registrations and newer resource
registration variants are not implemented by this batch.


`buffers-debug-run2` passed all fourteen initial buffer groups through both
APIs on both architectures, with zero residual wired pages after each group.
The broader `buffers-run2` then exposed a one-page reference leak per
`rwf_fixed_file` invocation (12 residual pages after its complete amd64 option
matrix). Fixed-file dispatch used a stack copy of the request and failed to
transfer newly acquired buffer references back to the tracked request. The
fix transfers ownership, and the regression now also covers fixed vectors.
`buffers-debug-run3` isolates that leak while exercising every option group;
its case successes do not override the residual-page failure.

Review also found a publication window between wiring and marking a mapping
pinned. Registration now retains the VM map lock from the return of
`vm_map_wire_locked` through page extraction and pin publication. The new
`buffers_vm_race` group runs concurrent mprotect/fork operations in a separate
stack sharing the VM, then verifies that subsequent fixed I/O still sees the
application's buffer. It runs through both APIs on both architectures.
The arm64 native race harness also needed a test-local rfork stack trampoline;
its libc fallback rejected the supplied child stack. `buffers-debug-run4`
passes that corrected harness and the expanded fixed-file regression through
both APIs on both architectures, with zero retained pages after each case.
Linux-reference run 6 passes all 39 portable option groups plus the three
corrected older fixed-buffer regressions, using the final expanded fixed-file
tests.

Final qualification: `buffers-run4/results.json` records **1110 passing case
runs on each architecture**, plus the three amd64 regressions. Both guests
report `GATE_BUFFER_PAGES 0 0`, healthy ZFS pools and clean shutdown, with no
detected kernel faults or lock-order reports. This includes every buffer group
through both APIs, three times each on ZFS and tmpfs. Both kernels use
INVARIANTS and WITNESS; all affected loadable modules were rebuilt against the
changed VM map layout.

`buffers-durability-run1/results.json` records abrupt termination and successful
reboot of both architectures, with all **28 synchronous-write files verified
per architecture**. Kernel, Linux module and native/Linux option-test hashes
match the normal gate and both crash/reboot boots. This checks the guest
persistence path; it does not simulate physical-device power loss or exclude
all incidental TXG commits.

The final Linux comparison is `buffers-linux-reference6.console.log`: **39
portable option groups and three corrected fixed-buffer regressions passed**.
`buffers_async` remains a mandatory BSD capture-before-submit-return invariant;
Linux can acquire forced-async buffer references later, so that assertion is
not presented as a portable Linux contract.

Exact accumulated source, build inputs, kernel configurations, compiler
versions, binary hashes, commands and retained failure evidence are frozen as
`buffers-final-*` under `/tmp/linuxulator-gate-20260917`. The tracked source
snapshot includes prior Linuxulator batches; the full-worktree patch also
preserves unrelated concurrent edits and does not qualify them. Testing used
private QEMU images only; the running host kernel and modules were not changed.
The limitations listed above remain open, as do linked deadlines/cancellation
and the remaining setup, enter and registration option backlog.


## Linked-deadline batch (2026-09-17, named contracts qualified)

This batch belongs to shared BSD squeue. Linux ABI dispatch and errno
translation remain in the front end. Linked deadlines are prepared before any
chain member executes, detached from ordinary successor execution, and armed
when their predecessor starts. Expiry cancels that request by identity; normal
completion disarms its deadline. Hard links preserve continuation after failure.
Cancellation retains worker ownership until execution and cleanup end, and
interrupts only interruptible sleeps. A canceled request must not release buffers,
files or its context while an executor still uses them.

The initial `links-baseline1` ZFS-root guests reproduced expiry, malformed
LINK_TIMEOUT, timeout-removal scope and cancel-all count failures through both
APIs on amd64 and arm64. The source review also found worker use-after-free
exposure in the old cancellation path and leaked unissued successors on close.
The new allocated-request counter and before/after gate checks supplement the
existing wired-page checks.

Readiness changes serialize kqueue creation and registration/deletion, retain
registrations needed by replacement requests, and fan out a descriptor/filter
event to all matching polls. Cancellation and last-close cleanup retire requests
without deleting a replacement poll's event or losing a linked successor.

The mandatory inventory now has 64 option groups and 1350 runs per architecture,
plus three amd64 regressions. Twenty `links_*` groups run through both APIs on
ZFS and tmpfs three times, with positive, negative, rollback, lifetime and race
assertions. Both INVARIANTS/WITNESS guests must report zero live requests before
and after the option matrix and after the older io_uring suite. Full-gate and
matching crash/reboot qualification are still pending.

Pinned implementation references are [Linux v6.18 timeouts](https://github.com/torvalds/linux/blob/v6.18/io_uring/timeout.c)
and [Linux v6.18 cancellation](https://github.com/torvalds/linux/blob/v6.18/io_uring/cancel.c).
The Linux reference confirms cancel-all returns a count (including zero),
ordinary timeout removal and asynchronous cancellation do not remove a linked
deadline by its own key, and two cancellation requests can both be accepted
before the target's single terminal CQE is delivered. Tests must permit those
races without permitting duplicate terminal completions or unintended I/O.

Remaining boundaries include cancellation FD/ANY/opcode matching modes,
synchronous cancellation and timeout updates. Completion results preserve
successful or partial I/O that wins cancellation; uninterruptible I/O must
finish before its resources can be released. Absolute realtime deadlines are
converted to a monotonic delay at arm time; clock changes after arming and
suspend/resume behavior are not qualified by this batch.

The batch's entry points are native `squeue_enter` and Linux
`io_uring_enter`, with setup/mmap/register/close as lifetime dependencies.
The following contracts are mandatory through both APIs on both guest
architectures; each `links_*` group repeats three times on ZFS and tmpfs.

| Contract | Positive and lifecycle coverage | Negative and competing outcomes |
|---|---|---|
| LINK_TIMEOUT preparation and arming | `links_success`, `links_deferred`, `links_absolute` | `links_invalid`: isolated/consecutive deadlines, lengths, reserved fields, clock conflicts, every unsupported timeout bit, negative/large times, NULL/unmapped/protected/guard-crossing timestamps; read-only input succeeds |
| Deadline expiry and link propagation | `links_expire`, `links_hardlink`, `links_io` | `links_rollback`: no writes before or after failed preparation; soft-linked successors cancel, hard-linked successors proceed |
| ASYNC_CANCEL by user_data | `links_cancel_target`, `links_duplicates`, `links_worker` | `links_remove_scope`, `links_cancel_timer`: missing key, unsupported matching flags, linked deadline not independently removable |
| ASYNC_CANCEL_ALL | `links_cancel_all`, `links_queued` | Count zero/multiple matches, exactly one terminal target CQE, canceled reads leave data untouched |
| Queued and active worker ownership | `links_queue_isolation`, `links_worker`, `links_io` | Queued cancellation bypasses unrelated blocked work; active cancellation retains buffers/file/vmspace until execution ends; subsequent data remains readable |
| Poll registration and retirement | `links_poll_reuse` | Duplicate fd subscribers, cancel newest without replacement, cancel and replace while preserving another subscriber |
| Completion/cancel/deadline races | `links_race`, `links_cancel_race` | Permissible Linux late-cancellation errors, no duplicate completions, continued ring progress |
| Last close and process death | `links_close`; registered-buffer alias cases in `buffers_async` | SIGKILL during pending polls/workers, unread CQEs, linked successors/drains; zero residual requests and wired pages |

No new pathname or credential bypass is introduced by linked timers: I/O still
uses the existing captured descriptor rights and operation checks. The full
gate retains its Capsicum, permission, seal, filesystem and VM coverage.
Permission matrices for additional future cancellation matching modes are not
certified by the user_data-only implementation.

Failure evidence is retained under `/tmp/linuxulator-gate-20260917`:
`links-run1` timed out in the older multishot-read regression, which incorrectly
used POLL_REMOVE to cancel data I/O, and left one live request. That regression
now uses ASYNC_CANCEL. The timeout also exposed a real process-exit leak:
the private kqueue watched its own ring file, forming a reference cycle when
the process exited without explicit close. `links-close-baseline` reproduces
16 residual requests and 16 wired pages per API on both old guest kernels.
The shared engine now uses a private EVFILT_USER wake event, triggered through
a drained task, without retaining the ring file. `links-debug4` passes the
focused matrix with zero residual requests/pages on both architectures.

Earlier Linux reference failures corrected test assumptions about accepted
LINK_TIMEOUT flags and racing cancellation results. Reference 13 also exposed
a fault-test setup error: creating ring mappings after unmapping the test
address could make that address valid again. Setup now creates the ring first.
`links-run2` was stopped before its option matrix to replace that harness;
it is incomplete evidence, not qualification. The eight-worker queue-isolation
assertion is BSD-specific and remains mandatory in both BSD front ends;
Linux's differently sized worker pool is not required to reproduce it.

A subsequent concurrency review found an event-consumption window between
knote registration and publishing its request. Registration now retains the
private queue lock through publication, and scanning takes that lock before
matching returned events. The extended `links_poll_reuse` test registers an
already-readable target while another process waits on the ring. `links-run3`
was stopped because its kernel predated this fix, not because it supplied
passing qualification. All interrupted runs retain logs and dispositions.


Final qualification: `links-run4/results.json` records **1350 passing case
runs on each architecture**, plus three amd64 regressions. Every one of the
20 linked-deadline/cancellation groups runs through both APIs, three times on
ZFS and three times on tmpfs, in ZFS-root guests. Both INVARIANTS/WITNESS kernels
report `GATE_REQUESTS options 0 0`, `GATE_REQUESTS final 0 0`,
`GATE_BUFFER_PAGES 0 0` and `GATE_FINAL_PAGES 0 0`. Both guests shut down cleanly
with healthy ZFS pools and no detected kernel faults or lock-order reports.

`links-durability-run1/results.json` records abrupt QEMU termination and
successful reboot on both architectures, verifying all **28 synchronous-write
files per architecture**. Kernel, Linux module and native/Linux test hashes
match the normal gate and both crash/reboot boots. This checks guest persistence;
it does not simulate physical-device power loss or rule out incidental TXGs.
The final Linux reference, `links-linux-reference15.console.log`, passes **58
portable option groups and eight older regressions** using the final test binary.

Evidence is frozen as `links-final-*` under
`/tmp/linuxulator-gate-20260917`, including exact accumulated source, build
inputs, configurations, commands, binary/image hashes and failed-run dispositions.
`links-since-buffers.patch` contains this batch's review changes; the concurrent
`vfs_lookup.c` edit is excluded from that patch and identified separately in
provenance. The full-worktree patch preserves unrelated work without claiming
that this batch authored or qualified it. Only disposable VM kernels/modules
were used; the running host was not changed. The cancellation modes and clock
behavior explicitly listed as remaining boundaries above are still pending.

## Setup, issuer and restriction batch: mandatory contracts

This batch adds SUBMIT_ALL, SINGLE_ISSUER and the R_DISABLED / RESTRICTIONS /
ENABLE_RINGS lifecycle to shared BSD squeue. Native and Linux setup, enter and
register entry points use the same policy and task-identity implementation.
Linuxulator alone translates invalid ring state to Linux EBADFD (77); native
callers receive EBADF. The shared KPI uses an internal sentinel, never a public
native errno. Restriction failures return EACCES; non-owner submissions and
registration return EEXIST. Zero-submission waits remain available to other
threads. Disabled rings cannot submit or wait, but allow resource registration.

Restrictions are installed transactionally and become immutable when enabled.
An empty, non-null policy denies all operations. Required SQE flags are also
allowed; repeated allowed/required rules use the last value. Unknown policy
flag bits and padding follow Linux's acceptance behavior, while common SQE
validation still rejects unknown SQE bits. Setup flags remain immutable;
disabled state is separate. Registration and enable operations serialize.
Single-issuer rings hold a reference-counted thread OSD identity, rather than
a reusable thread pointer or tid. The identity survives exec, remains owned
after issuer exit and releases after both ring and thread references retire.

| Contract | Positive and lifecycle coverage | Negative and competing outcomes |
|---|---|---|
| Setup combinations | `setup_flags`: all combinations of the three new flags and NO_SQARRAY | Unknown setup bit; existing unsupported-mode matrix retained |
| Disabled/enable lifecycle | `setup_disabled`: pre-registration, enable, ring progress | Enter with zero/nonzero submissions, no SQ/CQ consumption, bad arguments, duplicate enable |
| Opcode restrictions | `setup_restrict_ops`, `setup_restrict_empty` | Denied inline/async writes leave data unchanged; deny-all SQE/register policy |
| Flag policy | `setup_restrict_flags` | Missing required/disallowed flags; required-is-allowed, last rule wins, impossible flag policy, unknown common SQE bit |
| Register policy | `setup_restrict_register`, `setup_restrict_fixed` | Denied register calls, raw-fd I/O denied while fixed-file reference survives close |
| Installation rollback | `setup_restrict_invalid`, `setup_restrict_faults` | Invalid type/value/count, duplicate install, NULL/unmapped/protected/guard-crossing input, read-only input accepted, retry after fault |
| Restricted linked chains | `setup_restrict_links` | Soft/hard chain preparation failure produces no preceding or following writes |
| Single issuer | `setup_single`, `setup_single_enable`, `setup_single_threads` | Fork, dup, other process enables, same-process thread submission/register denied; zero-submit wait permitted |
| Identity lifetime | `setup_single_exit`, `setup_exec` | Owner exit followed by thread churn; owner and non-owner descriptors across exec |
| Concurrent transitions | `setup_enable_race`, `setup_restrict_race` | 32 competing parent/child attempts; exactly one installation or issuer wins |
| SUBMIT_ALL boundary | `setup_submit_all`, `setup_submit_links` | Bad opcode/common flag/personality/timeout pointer; exact consumed count, CQEs, poisoned chains and pending tail retry |
| Issue errors and bad indices | `setup_submit_errors`, `setup_submit_indices` | Execution EBADF continues submission; invalid SQ array slot drops without counting an SQE, with/without SUBMIT_ALL |
| Credentials | `setup_permissions` | Unprivileged disabled-ring and deny-all lifecycle; existing Capsicum and permission matrices retained |

All 22 new groups are mandatory through both APIs, three times on ZFS and
three times on tmpfs, in amd64 and arm64 ZFS-root/base QEMU guests. The option
inventory is 86 groups; the full gate requires 1614 runs per architecture plus
three amd64 regressions. Before/after option and final checks require zero
issuer ring references, task identity tokens, live requests and wired pages.
Thread OSD destruction may wait for the periodic thread reaper; the bounded
cleanup allowance is 15 seconds. INVARIANTS/WITNESS diagnostics, missing or
duplicate case markers, unhealthy pools and unclean exits fail qualification.
The matching abrupt-cut/reboot gate still requires all 28 durable files per
architecture and identical kernel/module/test hashes.

Reference behavior is checked against Linux 6.18.35 in QEMU and the pinned
[Linux v6.18 registration implementation](https://github.com/torvalds/linux/blob/v6.18/io_uring/register.c),
[submission implementation](https://github.com/torvalds/linux/blob/v6.18/io_uring/io_uring.c)
and [task context implementation](https://github.com/torvalds/linux/blob/v6.18/io_uring/tctx.c).
`setup-baseline/results.json` demonstrates that the preceding qualified BSD
kernels fail disabled-ring, single-issuer, deny-all and SUBMIT_ALL feature tests
through both APIs on both architectures. It is negative evidence, not a pass.

This batch qualifies the named submission-preparation boundaries. A complete
per-opcode reserved-field/ioprio, buffer-import and error-precedence audit is
still required: existing opcode-specific checks that run during issue have
not all been moved into preparation. Other setup/enter modes, registered ring
fds, resource tags/updates, personalities and newer restriction forms remain
separate work. Restrictions control ring operations, not arbitrary process
system calls. Final qualification results are recorded below.

The first full setup run exposed a third older SQ-index test with an incorrect
submission-count expectation: `sq_dropped_many` expected three invalid indices
to count as three submitted SQEs. The final Linux reference runs the preserved
old binary and reproduces its exit status 2, then passes the corrected test.
The correction checks one dropped slot and one head advance per enter, zero
submitted SQEs/CQEs, and subsequent successful NOP submission. The earlier
single-index regressions were corrected on the same basis. No engine behavior
was relaxed to satisfy the old expectation. `setup-run1` remains failed
evidence; only a complete run with the corrected suite can qualify this batch.


Final setup-batch qualification: `setup-run2/results.json` records **1614
passing cases per architecture**, plus three amd64 regressions, in ZFS-root/base
QEMU guests. Every new group passes both APIs on ZFS and tmpfs for three rounds.
Both INVARIANTS/WITNESS guests report zero issuer ring references, live identity
tokens, requests and wired pages at the option and final gates; both shut down
cleanly with healthy pools and no detected kernel faults or lock-order reports.

`setup-durability-run1/results.json` records abrupt termination (exit -9) and
successful reboot (exit 0) on each architecture, verifying **28 synchronous-write
files per architecture**. Kernel, Linux module and native/Linux option-test
hashes match the normal gate and both crash/reboot boots. This tests guest
persistence, with the physical-device and incidental-TXG limits stated earlier.
`setup-linux-reference3.console.log` passes **80 portable groups and 11 older
regressions** with the final binaries, and preserves the old SQ-drop test failure.

Evidence is frozen as `setup-final-*` under `/tmp/linuxulator-gate-20260917`:
exact accumulated source, build inputs, configurations, commands, artifact
hashes, logs and failed-attempt dispositions. `setup-since-links.patch` isolates
this batch relative to the preceding qualified source snapshot. The full-tree
patch preserves unrelated work without claiming it as this batch's changes.
The running host kernel and modules were not changed. Qualification covers the
named contracts above; per-opcode preparation/validation and the additional
modes explicitly listed as remaining work are not certified by these results.

## Registered-file lifetime and update batch: mandatory contracts

The shared squeue engine rejects ring descriptors in both initial registration
and updates, preventing self/cross-ring reference cycles. A dedicated sleepable
file-table lock serializes register calls and FILES_UPDATE SQEs with unregister,
and protects fixed-file reference and capability-template acquisition. It also
allows copying a Capsicum ioctl whitelist without sleeping under the ring mutex.
Descriptor ABI translation remains in Linuxulator; this batch changes the BSD
engine and its shared context, so both matching kernels/modules must be rebuilt.

Updates follow the pinned [Linux v6.18 resource implementation](https://github.com/torvalds/linux/blob/v6.18/io_uring/rsrc.c):
SKIP (-2) preserves a slot; -1 clears it. Each input descriptor commits separately.
An error after completed entries returns that prefix count. A failed descriptor
lookup clears its destination, while a user-memory fault leaves that slot
unchanged. Later slots are untouched. Initial registration is transactional:
any fault or rejected descriptor discards the entire unpublished table.
No registered table returns ENXIO; overflowing offset/count returns EOVERFLOW.
FILES_UPDATE reserved fields and prohibited SQE flags are checked before chain
side effects and obey SUBMIT_ALL stop/continue behavior. BUFFER_SELECT returns
EOPNOTSUPP before opcode-specific checks, as Linux common preparation does.

| Contract | Positive and lifecycle coverage | Negative and competing outcomes |
|---|---|---|
| No ring references in file tables | `files_cycles`, `files_update_cycles`: subsequent registration succeeds | Self, duplicate and other-ring descriptors rejected by initial registration and both update paths |
| Sparse entries and SKIP | `files_skip` | Empty-slot reads fail; skip preserves existing references; -2 is invalid for initial registration |
| Partial update semantics | `files_partial` | Valid prefix then invalid fd; failed destination becomes empty, later slot retains original file |
| Faults and rollback | `files_faults` | NULL/unmapped/protected/invalid and guard-crossing arrays; initial registration fully rolls back; updates preserve completed prefixes; read-only input succeeds |
| Validation and submission boundaries | `files_validation` | Missing table, zero count, reserved fields, invalid unregister arguments, range/overflow, prohibited SQE flags; default and SUBMIT_ALL counts/CQEs; rejected updates preserve original file |
| Descriptor lifetime | `files_lifetime` | Duplicate slots survive raw-fd close; replacement preserves other slots; unregister invalidates fixed indices |
| Update versus unregister | `files_race`: 512 multi-slot SQE updates against 512 unregister/register cycles | Only complete updates or ENXIO when no table exists; no access to retired table storage |
| Fixed lookup versus update | `files_read_race`: 512 reads against 512 replacements | Every read returns data from one held file, never an invalid or unrelated descriptor |
| Access rights | `files_permissions`, native `files_caps` | Read-only descriptors reject writes; captured Capsicum rights and ioctl whitelist survive original close without sleeping under a mutex |
| Process death | `files_exit`: repeated child exit with live file tables | All table references and ring memory released without explicit unregister/close |

Twelve new groups run through both APIs on ZFS and tmpfs, three rounds each,
in amd64 and arm64 ZFS-root/base INVARIANTS/WITNESS guests. The native-only
Capsicum assertions are replaced by descriptor access-mode checks in the Linux
front end and excluded from portable Linux-reference counts. The inventory is
98 option groups and 1758 total cases per architecture, plus three amd64
regressions. `GATE_FILES options 0 0` and `GATE_FILES final 0 0` are mandatory,
in addition to issuer, request and wired-page gates. The new counter includes
unpublished initial-registration references and counts duplicate slots separately.
Sleeping-allocation warnings mentioning non-sleepable locks now fail the gate,
even when the associated user test returned success.

Retained reproductions in `/tmp/linuxulator-gate-20260917` use the preceding
qualified setup kernels. `files-baseline` fails the new semantic tests through
both front ends on both architectures; ring self-registration leaves wired
pages behind. `files-hazard-baseline` produces Capsicum-copy WITNESS warnings
and a kernel panic during the update/unregister race on both architectures.
The controller terminates only its own hung guest after a bounded timeout.
These are failed/negative evidence, never qualification. Linux reference 1
exposed the BUFFER_SELECT errno expectation; reference 2 passes all 91 portable
groups and 11 retained regressions with the corrected expectation.

Final qualification: `files-run1/results.json` records **1758 passing cases per
architecture**, plus three amd64 regressions. Both INVARIANTS/WITNESS guests
report `GATE_FILES options 0 0` and `GATE_FILES final 0 0`, as well as zero
issuer references/tokens, requests and wired pages. Both ZFS-root guests shut
down cleanly with healthy pools and no detected kernel faults, lock-order
reports or allocation-under-non-sleepable-lock diagnostics.

`files-durability-run1/results.json` records abrupt QEMU termination (exit -9)
and successful reboot (exit 0) on both architectures, verifying all **28
synchronous-write files per architecture**. Kernel, Linux module and
native/Linux option-test hashes match the normal gate and both durability
boots. `files-linux-reference2.console.log` passes **91 portable groups and 11
retained regressions** with the final test binary.

Evidence is frozen as `files-final-*` under
`/tmp/linuxulator-gate-20260917`, including exact accumulated source, build
inputs, configurations, commands, binary/image hashes and failed-run
dispositions. `files-since-setup.patch` isolates this batch relative to the
preceding qualified snapshot. Only disposable VM kernels and modules were
used; the running host was unchanged.

This batch does not add v2/tag registration, automatic file-index allocation,
direct-file outputs or registered ring descriptors. The local 4096-entry limit
and existing resource-accounting boundaries remain; the broader per-opcode
preparation and reserved-field audit still needs its own qualified batches.

## Network ioprio and legacy provided-buffer bundle contract

Linuxulator preparation owns Linux ioprio masks, opcode combinations, Linux
message layout and errno translation. Shared squeue owns readiness parking,
intermediate-CQE accounting, fixed-buffer holds and the provided-buffer pool.
The pool's batch API atomically detaches contiguous buffer IDs, retains original
capacities for rollback, and restores unused buffers in order. Front ends add
their own feature bits: only Linux rings advertise
`IORING_FEAT_RECVSEND_BUNDLE`; native squeue shares the mechanism without
claiming Linux SEND/RECV policy.

The following cases are mandatory in addition to the earlier POLL_FIRST,
ACCEPT/RECV/RECVMSG multishot, SEND vector/fixed-buffer and SEND_ZC usage
notification cases. Each case needs a positive assertion and its applicable
negative, retry, cancellation and cleanup assertions.

| Contract | Required named coverage | Failure conditions |
|---|---|---|
| Feature scope | `setup_features` in Linux; native feature regression | Missing Linux feature bit or Linux-only bit advertised by native squeue |
| SEND bundle | `ioprio_send_bundle` | Wrong byte total/order, non-contiguous buffer IDs, missing or unterminated `F_MORE`, retained buffers/requests |
| RECV bundle | `ioprio_recv_bundle`, `ioprio_recv_bundle_limit` | Wrong payload prefix/result, wrong starting ID, ignored bounds, data loss |
| Bundle plus multishot | `ioprio_recv_bundle_multishot` | Datagram boundary/truncation mismatch, missing BUFFER/MORE flags, duplicate or terminal CQE errors |
| EAGAIN rollback and cancellation | `ioprio_bundle_retry_reuse` | Selected buffer not returned, capacity or ID changed, cancel duplicates, unread payload consumed |
| Invalid combinations | `ioprio_bundle_invalid` | Bundle without BUFFER_SELECT, SENDMSG/RECVMSG bundle, unknown bits, or invalid fields accepted; any side effect before rejection |

Correctness requires the complete inventory, not only these focused cases. The
301-case `linux_iouring` list must reconcile exactly with
`tools/test/linuxulator/iouring-cases.json`; every case must produce one named
zero result in each fresh amd64 and arm64 ZFS-root QEMU guest. The surrounding
native/Linux squeue matrix still repeats three times, and the gate must observe
zero live requests, registered files, issuer references/tokens and wired pages,
a healthy ZFS pool, clean shutdown and no panic, WITNESS or lock-order marker.
The matching private-overlay crash/reboot gate must then pass on both
architectures with the same kernel/module/test artifacts. A focused pass is
necessary debugging evidence but never substitutes for these two complete
gates.

Linux 6.18.35 positive bundle, limit, multishot and cancel/reuse cases are the
reference. That kernel accepts BUNDLE without BUFFER_SELECT and can repeatedly
send the same ordinary buffer; 5BSD deliberately returns EINVAL for this
malformed combination to prevent an unbounded operation. Preserve this as an
explicit reference difference and a mandatory BSD negative test.

Final bundle qualification is `/tmp/linuxulator-gate-20260917/bundle-full-run3/results.json`.
The fresh ZFS-root guests passed **1,846 named results on amd64** and **1,843 on
arm64**; the three-result difference is the existing amd64-only regression set.
Both results include all 301 Linux io_uring cases, 642 native/Linux squeue option
runs, three native squeue runs, the direct syscall and filesystem matrices, and
an assertion at every squeue setup that the bundle feature is present only for
the Linux frontend. Both guests reported zero final issuer references/tokens,
registered files, live requests and wired pages, zero diagnostic failures,
healthy ZFS pools and clean shutdowns.

`/tmp/linuxulator-gate-20260917/bundle-durability-run1/results.json` records
successful abrupt termination (exit -9) and reboot verification on both amd64
and arm64 using the final kernel, module and test artifacts. The earlier
`bundle-full-run1` is retained as non-qualification evidence: all observed cases
passed, but unrelated host build load exhausted its 2,400-second outer VM
allowance. `bundle-full-run2` was deliberately stopped before qualification to
add the missing native negative feature assertion. Neither interrupted run is
counted as passing evidence.


## Registered provided-buffer ring contract

Registered provided-buffer rings are a shared squeue resource contract. The
kernel owns registration, mmap or user-page pinning, producer-tail reads,
consumer-head commits, retry rollback, group exclusion, unregister and close
cleanup. Linux-specific SEND/RECV option combinations remain in the Linux
front end. `IOU_PBUF_RING_INC` is part of the shared contract: actual byte
counts update the active descriptor, `min_left` controls retirement, and
`IORING_CQE_F_BUF_MORE` reports that the same buffer ID remains active.

Every change to this contract must run positive and negative tests in a fresh
amd64 ZFS-root QEMU guest. The already-qualified implementation also has arm64
evidence; repeat that architecture only for a later platform-specific change.
At minimum, the gate must cover:

- kernel-allocated mmap registration, mapping, consumption, CQE buffer ID,
  payload integrity, status-head advancement, unregister, and repeated
  unregister;
- page-aligned user-ring registration, producer-tail publication, more than one
  complete ring wrap, unique IDs and payload integrity;
- invalid entry counts, reserved fields, unknown flags, invalid
  incremental/min-left combinations, conflicting addresses, duplicate group
  IDs,
  legacy `PROVIDE_BUFFERS` conflicts, and invalid unregister fields;
- EAGAIN retry, cancellation and concurrent unregister without advancing or
  duplicating a buffer; these are required additions for any future expansion
  of the registered-ring consumers;
- final request, registered-file, issuer and wired-page counters equal to their
  baselines, no panic/WITNESS/lock-order diagnostics, and a healthy ZFS pool.

The qualified focused evidence is
`/tmp/linuxulator-gate-20260917/pbuf-recover-focus-results1.json`. Final normal
evidence is `/tmp/linuxulator-gate-20260917/pbuf-full-run2/results.json`: amd64
and arm64 each pass 305 Linux io_uring cases and 642 repeated native/Linux
squeue option executions with zero diagnostic failures and clean counters. The
crash/reboot evidence is
`/tmp/linuxulator-gate-20260917/pbuf-durability-run2/results.json`; both
architectures record the deliberate cut as exit `-9`, reboot as exit `0`, and
successful ZFS verification. These VM results, including negative cases, are
the correctness gate; host kernel or module loading is not an accepted test.

The shared-front-end extension is separately recorded in
`/tmp/linuxulator-gate-20260917/pbuf-shared-results3.json`: the registered-ring
contract passes through native squeue and Linux io_uring on both previously
required architectures.  After adding that group to the complete inventory,
`/tmp/linuxulator-gate-20260917/pbuf-full-run4/results.json` records the final
amd64 gate passing 305 Linux io_uring cases and 648 repeated native/Linux
squeue option executions.  Its arm64 rerun was intentionally stopped under the
architecture-neutral gate policy above; no failure prompted the stop.

## Incremental provided-buffer qualification

Incremental rings are implemented in shared squeue rather than the Linux
front end. The engine serializes an outstanding registered-ring selection,
commits successful byte counts into the descriptor address and length, retains
the head and emits `IORING_CQE_F_BUF_MORE` while the remainder exceeds
`min_left`, and retires the descriptor exactly once otherwise. Cancellation
before data leaves it unchanged; cancellation after a multishot partial
completion preserves the already-committed offset for the next request.
Linux-specific opcode and ioprio validation remains in Linuxulator.

`pbuf_ring_incremental_shared` runs through both frontends. The Linux-specific
`pbuf_ring_incremental`, `pbuf_ring_incremental_user`,
`pbuf_ring_incremental_multishot`, and `pbuf_ring_incremental_bundle` cases cover
partial, threshold and zero-byte results, user-ring wrap, bundle byte
commits, repeated buffer IDs, descriptor
mutation, status head, EAGAIN parking, busy unregister, cancellation CQE flags,
remaining-range reuse and cleanup. The final amd64 ZFS-root evidence is
`/tmp/linuxulator-gate-20260917/pbuf-inc-full-run3/results.json`: 309 io_uring
cases and 654 repeated shared-option executions pass, along with three native
squeue runs and the complete surrounding gate. Request, registered-file, issuer
and wired-page counters return to zero; diagnostics are empty, QEMU exits zero,
and the ZFS pool is healthy.


## Extended asynchronous-cancellation qualification

`IORING_OP_ASYNC_CANCEL` matching is owned by the shared squeue engine because
pending, poll-armed and issuing request state is ABI-neutral.  The engine now
implements `IORING_ASYNC_CANCEL_FD`, `ANY`, `FD_FIXED`, `USERDATA` and `OP`, as
well as `ALL`.  Requests retain their open-file identity, so FD matching works
through `dup(2)` and after the submitted numeric descriptor is closed.  A fixed
cancel target can be selected with either `FD_FIXED` or `IOSQE_FIXED_FILE` and
is resolved against the ring's registered-file generation.  Flag-combination and opcode-bound validation is shared because both frontends
expose the same request contract; Linux errno translation remains in the Linux
frontend.

The required positive cases cover implicit and explicit user-data selection,
FD identity through a duplicate, FD plus user-data intersections, opcode-only
selection, ALL counts, ANY's cancel-all behavior, fixed slots, closed numeric
descriptors, unrelated-request preservation and zero matches.  Negative cases
cover unknown bits, ANY with FD, ANY with OP, an opcode at `IORING_OP_LAST`, bad
normal descriptors, bad fixed indices and proof that rejected cancellation
does not disturb an outstanding request.  `cancel_modes_shared` repeats the
core matcher through native squeue and Linux io_uring; the Linux-only cases
exercise the exact Linux SQE encodings.

The final amd64 ZFS-root QEMU evidence is
`/tmp/linuxulator-gate-20260917/cancel-full-run6/results.json`.  Qualification
requires 315 Linux io_uring cases, 660 repeated shared-option executions, three
native squeue runs, all surrounding syscall/filesystem regressions, zero final
request/file/issuer/wired-page counters, no diagnostic findings, a healthy ZFS
pool and clean shutdown.  This phase changes no syscall table or
machine-dependent ABI path, so the architecture-neutral policy does not require
another arm64 run.  No candidate kernel or module is installed or loaded on the
host.


### Poll and timeout option qualification

Poll and timeout updates are part of the shared squeue contract.  Each added
mode requires positive lifecycle tests, invalid flag and argument tests,
missing-target tests, target-preservation checks after rejected updates, exact
CQE result and `F_MORE` validation, cancellation cleanup, final zero request
and resource counters, and a healthy ZFS pool after sync.  The Linux suite must
also exercise the exact Linux SQE union encodings.  `poll_update_shared` and
`timeout_modes_shared` must pass three times through both native and Linux ABI;
the ten Linux encoding cases must each pass once.  The complete amd64 ZFS-root
QEMU gate requires 325 Linux io_uring cases and 672 shared-option executions.
Arm64 is required again only if this implementation later changes its syscall
table, ABI layout, or machine-dependent path.  Candidate kernels and modules
must never be installed or loaded on the host.


### Synchronous cancellation gate

`IORING_REGISTER_SYNC_CANCEL` must share the asynchronous cancellation matcher
and must be tested through native squeue and Linux io_uring.  Qualification
requires user-data, ALL/ANY, FD identity, fixed slots, opcode intersections,
match counts, missing targets, malformed sizes and pointers, reserved-field and
unknown-flag rejection, invalid normal and fixed descriptors, target
preservation after every negative call, completion cleanup, zero final resource
counters, and a healthy ZFS pool.  A running-request test must additionally
cover bounded wait expiration and interruption whenever a deterministic blocking
fixture is available.  The current mandatory amd64 inventory is 330 Linux cases
and 678 shared-option executions.
Final evidence is `/tmp/linuxulator-gate-20260917/synccancel-full-run1/results.json`; the full gate passed with zero diagnostic findings and zero final issuer, file, request, and wired-page counters.


## Shared squeue worker-pool control (2026-09-18)

The system-wide asynchronous file-I/O pool is controlled by the shared BSD
engine. `kern.squeue.max_workers` is a boot tunable and runtime sysctl with a
default of 8 and an accepted range of 1 through 256. Reducing the ceiling does
not terminate existing kernel workers; it prevents further growth until the
live count falls below the ceiling. `kern.squeue.workers` and
`kern.squeue.idle_workers` are read-only observability counters. This policy is
shared by native squeue and Linux io_uring.

The focused amd64 ZFS-root QEMU gate booted with a value of 3, rejected 0, -1,
257 and INT_MAX without changing the configured value, accepted both
boundaries and intermediate values, and rejected writes to both counters. A
16-request `IOSQE_ASYNC` burst created three workers, all three returned idle,
and reducing the ceiling to 1 preserved the existing workers while another
asynchronous write/read completed without pool growth. The guest powered off
cleanly with a healthy ZFS pool. Evidence image:
`/tmp/linuxulator-gate-20260917/worker-focus-images2/amd64.img`. The latest
full regression evidence is
`/tmp/linuxulator-gate-20260917/personality-full-run1/results.json`; it retained
the boot default of 8, accepted the runtime boundary/intermediate sequence,
rejected every invalid write and read-only counter write, observed eight live
and idle workers after the matrix, and passed all controller checks. This
architecture-neutral change does not require an arm64 rerun under the current
gate policy.


## Direct-descriptor allocation gate (2026-09-18)

The shared file-table implementation owns allocation ranges, slot scanning,
replacement, capability retention and transient-descriptor cleanup. The Linux
frontend owns the four Linux fd-producing opcode translations. Qualification
requires absent-table, pointer/count, overflow, reserved, bounds, zero-window,
wrap, full-table, explicit replacement, failed-operation rollback, fixed-fd
recovery, accepted-socket data transfer, invalid multishot composition and
post-failure listener health. The shared range group runs through both ABIs.

Focused evidence is `/tmp/linuxulator-gate-20260917/direct-focus-images3/amd64.img`:
five Linux cases and both shared-ABI runs passed, resource counters returned to
their baselines, QEMU exited zero, and the ZFS pool was healthy. The complete
gate must enumerate 336 Linux cases and 114 shared groups, yielding 684 repeated
shared executions. No arm64 rerun is required for this architecture-neutral
phase.

## Linux fallocate mode gate (2026-09-18)

`IORING_OP_FALLOCATE` now delegates Linux requests to the Linuxulator
front end so it shares the direct `fallocate(2)` mode validation, descriptor
classification and errno order. Native squeue retains mode-zero allocation in
the shared engine. Linux hole punching with
`FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE` uses
`kern_fspacectl(SPACECTL_DEALLOC)`; unsupported and unknown modes fail without
modifying the file.

The freestanding io_uring tests cover allocation, aligned and EOF-crossing hole
punches, preserved data and size, every known unsupported mode, an unknown
mode, zero length, negative and overflowing ranges, read-only and closed
descriptors, pipes, directories and sockets. The direct Linux syscall
regression performs 30 numbered checks, including unaligned holes and
validation precedence. The focused amd64 guest booted from ZFS and ran the
filesystem operations on a temporary tmpfs because the supported ZFS
implementation intentionally rejects reservation allocation. All four cases
passed, squeue resource counters returned to zero, and the ZFS pool remained
healthy. Evidence image:
`/tmp/linuxulator-gate-20260917/fallocate-focus-images4/amd64.img`.

The frontend calls an ABI-neutral Linuxulator kernel helper after the syscall
wrapper has decoded Linux32 or Linux64 arguments. Fresh `-Werror` builds of
both `linux64.ko` and the amd64 Linux32 `linux.ko` passed. This also corrected
the Linux32 io_uring frontend includes and its MADVISE and SYNC_FILE_RANGE
argument construction. Fallocate full-gate evidence is
`/tmp/linuxulator-gate-20260917/fallocate-full-run2/results.json`: 336 Linux
io_uring cases, 684 repeated shared-option executions, three native squeue
runs, four direct regressions, zero final issuer/file/request/page counts, no
diagnostic findings and a healthy ZFS pool.

## FSYNC flag gate (2026-09-18)

FSYNC option validation belongs to shared squeue. Preparation accepts zero or
`IORING_FSYNC_DATASYNC` and rejects every other flag bit with EINVAL before
descriptor lookup or linked side effects. Execution maps zero to full
`kern_fsync` and DATASYNC to data-only synchronization.

The Linux case `fsync_flags` covers low and high unknown bits, bad-descriptor
precedence, full and data sync, registered files and pipes. Existing
`fsync`, `fsync_badfd`, `fixed_fsync`, stress and shared reserved-field
cases remain mandatory. The focused amd64 ZFS-root gate passed three Linux
cases plus `prep_reserved_core` through both native and Linux frontends with
zero retained requests/files and a healthy pool. Evidence image:
`/tmp/linuxulator-gate-20260917/fsync-focus-images2/amd64.img`.

Final evidence is
`/tmp/linuxulator-gate-20260917/fsync-full-run2/results.json`: all 337 Linux
io_uring cases, 684 repeated shared-option executions, three native squeue
runs, four direct regressions, zero final issuer/file/request/page counts, no
diagnostic findings and a healthy ZFS pool. This shared, architecture-neutral
change does not require another arm64 run under the current gate policy.

## MSG_RING variants gate (2026-09-18)

Shared squeue owns target-ring completion publication and registered-file
reference/capability transfer. `IORING_MSG_DATA` supports same-ring and
cross-ring delivery plus `IORING_MSG_RING_FLAGS_PASS`.
`IORING_MSG_SEND_FD` copies a source registered file into an explicit one-based
target slot or the first slot in the target allocation range, leaves the source
registration intact, and honors `IORING_MSG_RING_CQE_SKIP`. Source and target
tables are never locked together, and ring descriptors remain ineligible for
registration, preventing reciprocal-transfer deadlocks and file-table-created
ring cycles. The Linux front end retains Linux errno translation, including
`EBADFD` for a non-ring or disabled target where native squeue reports `EBADF`.

The `msg_ring_shared` group covers DATA payloads, passed CQE flags, same-ring
ordering, disabled/non-ring/bad targets, invalid commands, source indices,
destination fields and unknown flags. SEND_FD coverage includes explicit
install and replacement, automatic allocation, full ranges, source retention,
closed-original-descriptor lifetime, target notification and CQE_SKIP,
FLAGS_PASS acceptance, absent tables and slots, self-transfer, invalid lengths
and destinations, rollback, target preservation, and final unregister cleanup.
Unknown preparation flags are checked before descriptor lookup or any side
effect.

Focused amd64 ZFS-root evidence is
`/tmp/linuxulator-gate-20260917/msg-ring-focus-images1/amd64.img`; both native
and Linux shared cases passed with zero retained files and requests. Full gate
evidence is
`/tmp/linuxulator-gate-20260917/msg-ring-full-run1/results.json`: 337 Linux
io_uring cases, 690 repeated shared-option executions, three native squeue
runs, four direct regressions, zero final issuer/file/request/page counts, no
diagnostic findings, clean shutdown and a healthy ZFS pool. This shared,
architecture-neutral phase does not require another arm64 run under the current
gate policy.

## NOP option gate (2026-09-18)

The shared engine implements the Linux 6.18 NOP option contract for native
squeue and Linux io_uring. INJECT_RESULT returns the signed 32-bit `len` value;
FILE validates a normal descriptor; FIXED_FILE switches that validation to a
registered-file slot and is ignored without FILE; FIXED_BUFFER validates a
registered buffer; and TW is accepted through the shared submission context.
CQE32 is rejected because the corresponding setup mode is not supported, and
unknown flags fail during preparation before file or buffer lookup.

`nop_flags_shared` covers positive and negative injected results, valid and bad
normal descriptors, valid, empty and missing fixed-file tables, fixed-file
lifetime after the original descriptor closes, valid, sparse, out-of-range and
missing registered buffers, TW, combined flags, ignored modifiers, unknown
low/high bits, CQE32 rejection, resource preservation and cleanup. Focused
amd64 ZFS-root evidence is
`/tmp/linuxulator-gate-20260917/nop-focus-images2/amd64.img`. Full evidence is
`/tmp/linuxulator-gate-20260917/nop-full-run2/results.json`: 337 Linux io_uring
cases, 696 repeated shared-option executions, three native squeue runs, four
direct regressions, zero final issuer/file/request/page counts, no diagnostic
findings, clean shutdown and a healthy ZFS pool. The phase is
architecture-neutral and does not require an arm64 rerun.

## FIXED_FD_INSTALL flag gate (2026-09-18)

Shared squeue now applies the Linux descriptor-flag contract when converting a
registered file into an ordinary descriptor. The installed descriptor defaults
to close-on-exec; `IORING_FIXED_FD_NO_CLOEXEC` clears it. Unknown install flags
fail in preparation before fixed-slot lookup. The operation retains the
capability rights captured when the source slot was registered, and the normal
transient fixed-file path continues to install without changing its descriptor
semantics.

`fixed_fd_install_flags_shared` verifies both close-on-exec states with
`F_GETFD`, readable content, source lifetime after the original descriptor is
closed, empty/out-of-range/absent tables, missing `IOSQE_FIXED_FILE`, unknown
low and high bits, 32 alternating installs, per-result close cleanup, table
preservation and final resource cleanup. Focused amd64 ZFS-root evidence is
`/tmp/linuxulator-gate-20260917/fixed-install-focus-images2/amd64.img`. Full
evidence is
`/tmp/linuxulator-gate-20260917/fixed-install-full-run1/results.json`: 337
Linux io_uring cases, 702 repeated shared-option executions, three native
squeue runs, four direct regressions, zero final issuer/file/request/page
counts, no diagnostic findings, clean shutdown and a healthy ZFS pool. This
shared, architecture-neutral phase does not require an arm64 rerun.


## PIPE direct-file gate (2026-09-18)

`IORING_OP_PIPE` now supports both ordinary descriptor output and direct output
into the shared registered-file table. Linux pipe flag and SQE validation remain
in the Linuxulator frontend. Shared squeue owns allocation-range scanning,
explicit one-based slot replacement, capability retention, transient-descriptor
cleanup and output of zero-based allocated indices. Explicit direct output
rejects `O_CLOEXEC`; `O_NONBLOCK` is preserved on both pipe ends.

Failure follows Linux 6.18's sequential install contract. If the second slot or
result copyout fails, each newly installed pipe end is removed and its affected
slot remains empty. A resource that was replaced before the failure is released;
it is not restored. This ordering is covered explicitly so a stronger-looking
transactional rollback cannot silently diverge from Linux.

The `pipe_direct` Linux case covers bounded automatic allocation, returned slot
indices, fixed-file write/read, explicit consecutive slots, replacement,
nonblocking pipes, last-slot overflow, allocation exhaustion, `O_CLOEXEC`, a
bad output pointer, table absence, post-failure slot state and final cleanup.
Focused amd64 ZFS-root evidence is
`/tmp/linuxulator-gate-20260917/pipe-direct-focus-images3/amd64.img`. Full
evidence is
`/tmp/linuxulator-gate-20260917/pipe-direct-full-run2/results.json`: all 338
Linux io_uring cases, 702 repeated shared-option executions, three native
squeue runs and four direct regressions passed. Final issuer, registered-file,
request and wired-page counts were zero; diagnostic findings were empty; the
guest shut down cleanly with a healthy ZFS pool. This phase is
architecture-neutral, so no arm64 rerun is required by the current gate policy.


## Registered completion-wait clock gate (2026-09-18)

`IORING_REGISTER_CLOCK` is implemented by shared squeue. Each ring stores the
clock used to interpret absolute `IORING_ENTER_EXT_ARG` completion waits; the
deadline is converted to the uptime callout domain when the wait begins.
Relative enter waits and timeout SQEs retain their existing independent clock
contracts. Native squeue accepts `CLOCK_UPTIME` and `CLOCK_MONOTONIC`. The
Linuxulator frontend alone translates Linux `CLOCK_MONOTONIC` and
`CLOCK_BOOTTIME` numbers into native clock domains.

`register_clock_shared` runs through both frontends and covers both accepted
clock domains, bounded future absolute waits, repeated replacement, use while a
ring is disabled, null arguments, wrong counts, bad pointers, every reserved
word, multiple invalid clock IDs, a guard-page-crossing structure, read-only
input, subsequent ring progress and final resource cleanup. Focused amd64
ZFS-root evidence is
`/tmp/linuxulator-gate-20260917/clock-focus-images1/amd64.img`; all six repeated
frontend runs passed. Full evidence is
`/tmp/linuxulator-gate-20260917/clock-full-run1/results.json`: 338 Linux
io_uring cases, 708 repeated shared-option executions, three native squeue
runs and four direct regressions passed. Final issuer, registered-file, request
and wired-page counts were zero, diagnostic findings were empty, and the guest
shut down cleanly with a healthy ZFS pool. The change is architecture-neutral,
so no arm64 guest was run.


## Asynchronous eventfd gate (2026-09-18)

Shared squeue owns `IORING_REGISTER_EVENTFD_ASYNC`, because worker dispatch,
ready-queue publication, CQ publication and eventfd lifetime are common to both
frontends. Ordinary eventfd registration signals only after a CQE is visible.
Async registration signals only at the file-I/O worker-to-ready transition;
inline completions remain silent and the owner publishes resolved CQEs on its
next enter. Both modes honor the userspace `IORING_CQ_EVENTFD_DISABLED` bit.
Registration retains the eventfd file, and ordinary and async modes compete for
the same single slot. Unregister requires a null argument and zero count and
reports `ENXIO` when the slot is empty.

`eventfd_async_shared` verifies exact pointer/count validation, bad and wrong
descriptor types, guard-page crossing, read-only input, duplicate-mode
preservation, inline silence, worker notification followed by exact CQE
delivery, disable/re-enable behavior, malformed-unregister preservation,
ordinary notification, original-descriptor closure, disabled-ring setup, ring
progress and cleanup. It passed three rounds through native squeue and three
through Linux io_uring in the focused amd64 ZFS-root VM. Full evidence is
`/tmp/linuxulator-gate-20260917/eventfd-full-run1/results.json`: all 338 Linux
io_uring cases, 714 repeated shared-option executions, three native runs and
four regressions passed. Diagnostic findings were empty; issuer, registered
file, request and wired-page counters returned to zero; the guest shut down
cleanly and the ZFS pool was healthy. This phase is architecture-neutral, so no
arm64 guest was run.


## Tagged registered-file gate (2026-09-18)

Shared squeue owns `IORING_REGISTER_FILES2`,
`IORING_REGISTER_FILES_UPDATE2`, sparse file tables, tag CQEs and generation
lifetime. Both frontends advertise `IORING_FEAT_RSRC_TAGS`. The Linuxulator
continues to own only ABI entry and errno translation. Fixed-file
`IOSQE_ASYNC` transfers resolve through a transient descriptor with the
registration's captured rights, while the request pins that exact generation
until the worker finishes. Replacement and unregister therefore emit the tag
CQE only after every in-flight owner retires.

Qualification requires exact structure-size checks, null, unmapped, protected,
guard-page and read-only inputs, reserved-field and unknown-flag rejection,
zero and oversized counts, sparse-table rules, ring/invalid descriptor
rejection, atomic initial failure without tag CQEs, duplicate registration,
UPDATE2 overflow and bounds, bad fd/tag arrays, SKIP and clear tag rules,
partial-prefix results and invalid-fd clearing, immediate replacement and
unregister CQEs, a delayed tag behind deterministic blocked fixed-file worker
I/O, post-failure ring health, and zero final resource counters. Every case must
run through native squeue and Linux io_uring in a disposable ZFS-root QEMU VM.

Focused amd64 evidence is
`/tmp/linuxulator-gate-20260917/files2-focus-images4/amd64.console.log`: three
native and three Linux rounds passed with zero request, registered-file and
wired-page residue. Full evidence is
`/tmp/linuxulator-gate-20260917/files2-full-run1/results.json`: 338 Linux
io_uring cases, 720 repeated shared-option executions, 78 repeated tmpfs
file-table executions, three native runs and four regressions passed. There
were no diagnostic findings; all resource counters returned to zero; the guest
shut down cleanly and the ZFS pool was healthy. The implementation is
architecture-neutral, so the current policy does not require an arm64 rerun.

## Tagged registered-buffer gate (2026-09-18)

Shared squeue owns `IORING_REGISTER_BUFFERS2` and
`IORING_REGISTER_BUFFERS_UPDATE`; both native squeue and Linux io_uring use the
same pinned-buffer tables, immutable per-slot generations, tags, accounting and
lifetime rules. `IORING_FEAT_RSRC_TAGS` is advertised by both frontends. A
replacement publishes a new table snapshot while submitted fixed-buffer work
retains its exact old generation. Its tag CQE is emitted only after the final
request releases the old pages. Ring teardown clears tags because no completion
consumer remains; explicit replacement and unregister continue to emit them.

The mandatory `buffers_v2_shared` group covers exact 32-byte structures; null,
unmapped, protected, guard-page and read-only inputs; reserved fields, unknown
flags, zero and oversized counts; sparse/data conflicts; tagged-empty rejection;
atomic initial failure without tag CQEs; UPDATE2 overflow and bounds; bad iovec
and tag arrays; partial-prefix progress with preservation of the failing slot;
immediate replacement and unregister CQEs; and delayed old-generation release
behind deterministic blocked `READ_FIXED` worker I/O. Every case runs through
both ABIs and checks subsequent ring health and zero final resource counters.

Focused evidence is
`/tmp/linuxulator-gate-20260917/buffers2-focus-pass.console.log`: three
native and three Linux rounds passed with zero request, registered-file and
wired-page residue. Full evidence is
`/tmp/linuxulator-gate-20260917/buffers2-full-run1/results.json`: all 338 Linux
io_uring cases, 726 repeated shared-option executions, 96 repeated tmpfs buffer
executions, 78 repeated tmpfs file-table executions and four direct regressions
passed. Diagnostics were empty; request, registered-file and wired-page counters
returned to zero; shutdown was clean and the ZFS pool healthy. This shared
change is architecture-neutral, so no arm64 guest was run.

## Registered-ring and cloned-buffer gate (2026-09-18)

Shared squeue owns task-local registered ring references and cloned registered
buffer storage. `IORING_REGISTER_RING_FDS`, `IORING_UNREGISTER_RING_FDS`,
`IORING_ENTER_REGISTERED_RING`, `IORING_REGISTER_USE_REGISTERED_RING` and
`IORING_REGISTER_SRC_REGISTERED` resolve through one 16-slot per-task registry.
Task exit schedules file drops outside the non-sleepable OSD destructor lock.
`IORING_REGISTER_CLONE_BUFFERS` creates separate untagged resource generations
that share a refcounted pinned backing and its single accounting charge.

Qualification requires malformed and inaccessible ring-fd arrays, explicit and
automatic slot allocation, duplicate/full/partial operations, copyout rollback,
wrong/closed/missing descriptors, registered enter/register and lifetime after
ordinary close. Clone coverage requires exact structure/count checks, unknown
flags and reserved fields, empty/busy tables, source and destination bounds,
overflow, sparse/full/sliced/self clones, independent tag retirement,
destination-prefix preservation and suffix clearing, source teardown with live
clones, and deterministic concurrent opposite-direction replacement without
lock-order diagnostics. Every case runs through native squeue and Linux
io_uring, with legacy buffer regressions and zero final resource counters.

The first focused image was rejected for a duplicate same-class two-ring lock
WITNESS report. The second was rejected for sleeping file teardown from the OSD
destructor lock. Both logs are retained as
`/tmp/linuxulator-gate-20260917/clone-focus-witness-failure1.console.log` and
`/tmp/linuxulator-gate-20260917/clone-focus-osd-failure2.console.log`.
The corrected focused evidence is
`/tmp/linuxulator-gate-20260917/clone-focus-images3/amd64.console.log`: three
native and three Linux clone rounds plus five buffer regression groups per ABI
passed with no diagnostics and zero residue. Full evidence is
`/tmp/linuxulator-gate-20260917/clone-full-run1/results.json`: 338 Linux
io_uring cases, 732 repeated shared-option executions, 102 repeated tmpfs
buffer executions, 78 repeated tmpfs file-table executions, three native runs
and four regressions passed. Diagnostics were empty, all tracked resources
returned to zero, shutdown was clean and the ZFS pool healthy. This phase is
architecture-neutral, so no arm64 guest was run.

## Registered-personality gate (2026-09-18)

Shared squeue owns `IORING_REGISTER_PERSONALITY`,
`IORING_UNREGISTER_PERSONALITY` and `SQE.personality`. Registration retains the
caller's current credential in a per-ring table and returns a nonzero 16-bit
identifier. Submission preparation takes an independent credential reference;
inline dispatch and asynchronous worker dispatch temporarily install it on the
executing thread. Unregister invalidates future submissions without changing
prepared requests. Ring teardown and process exit release registrations.

Qualification requires exact null/count validation, zero/unknown/out-of-range
unregister rejection, distinct identifiers, valid and stale SQE identifiers,
unregister during deterministically blocked `IOSQE_ASYNC` pipe I/O, repeated
process exit with live registrations and final ring health. The Linux ABI case
also proves credential effect: after registering as root and dropping to uid
65534, direct open of a mode-0600 file fails with EACCES while personality
`OPENAT` succeeds and reads the file. The matrix runs three times through both
frontends in a disposable amd64 ZFS-root guest.

Full evidence is
`/tmp/linuxulator-gate-20260917/personality-full-run1/results.json`: 338 Linux
io_uring cases, 738 shared-option executions, 102 repeated tmpfs buffer
executions, 78 repeated tmpfs file-table executions, three native runs and four
direct regressions passed. The controller found no WITNESS, INVARIANTS, panic,
lock-order or use-after-free diagnostics. Request, registered-file, wired-page
and issuer counters returned to zero; the guest shut down cleanly and the ZFS
pool was healthy. This architecture-neutral phase does not require an arm64
rerun.



## Per-ring IOWQ policy gate (2026-09-18)

Shared squeue implements `IORING_REGISTER_IOWQ_AFF`,
`IORING_UNREGISTER_IOWQ_AFF` and `IORING_REGISTER_IOWQ_MAX_WORKERS`. Rings have
separate bounded and unbounded active-work limits and an optional worker CPU
mask. Queue selection preserves FIFO order among eligible requests while
skipping a ring whose class is at its limit. The global
`kern.squeue.max_workers` boot/runtime tunable remains the hard system-wide
pool-growth ceiling; read-only `kern.squeue.workers` and
`kern.squeue.idle_workers` expose actual pool state.

Qualification requires exact pointer/count contracts, values above `INT_MAX`,
zero-element queries, partial updates, prior-value copyout, copyin atomicity and
Linux-compatible state retention after a final copyout fault. A deterministic
two-pipe case proves that an unbounded limit of one prevents the second request
from running ahead. Affinity coverage includes null, zero, inaccessible,
cross-page and read-only inputs; empty and disallowed masks; oversized byte
counts; constrained worker completion; restoration and idempotent unregister.
The sysctl gate separately rejects 0, -1, 257 and `INT_MAX`, accepts 1 and 256,
restores the original value and rejects writes to both counters.

The initial focused run exposed reversed `CPU_SUBSET` arguments and rejected a
valid single-CPU mask. Its log is retained as
`/tmp/linuxulator-gate-20260917/iowq-focus-subset-failure1.console.log`. The
corrected focused evidence is
`/tmp/linuxulator-gate-20260917/iowq-focus-pass1.console.log`: three native and
three Linux runs passed with zero retained resources and clean ZFS shutdown.
Full evidence is `/tmp/linuxulator-gate-20260917/iowq-full-run1/results.json`:
338 Linux io_uring cases, 744 repeated shared-option executions, 102 tmpfs
buffer executions, 78 tmpfs file-table executions, three native runs and four
direct regressions passed. The controller found no WITNESS, INVARIANTS, panic,
lock-order or use-after-free diagnostics. All tracked resource counters returned
to zero; shutdown was clean and the ZFS pool healthy. This phase is
architecture-neutral, so no arm64 guest was run.


## Blind MSG_RING registration gate (2026-09-18)

`IORING_REGISTER_SEND_MSG_RING` is handled by shared squeue before source-ring
lookup. The command requires `fd == -1`, one readable flagless MSG_RING SQE and
MSG_DATA; it resolves and holds only the target ring. SEND_FD remains invalid
because no source registered-file table exists. Linux EBADFD mapping remains in
the Linux frontend while native squeue maps the shared invalid-ring sentinel to
EBADF.

Qualification covers null, count, inaccessible, cross-page and read-only
arguments; opcode, SQE flag, buffer, personality, command, source index and
message-flag failures; bad, regular and disabled targets; FLAGS_PASS and the
registered-ring opcode bit. Every rejected call proves no target CQE was
published. The focused six-run log is
`/tmp/linuxulator-gate-20260917/register-msg-focus-pass1.console.log`. Full
evidence is `/tmp/linuxulator-gate-20260917/register-msg-full-run1/results.json`:
338 Linux io_uring cases, 750 repeated shared-option executions, 102 tmpfs
buffer executions, 78 tmpfs file-table executions, three native runs and four
direct regressions passed. Diagnostics were empty, all tracked resources
returned to zero, shutdown was clean and the ZFS pool healthy. The change is
architecture-neutral, so no arm64 run was required.


## NO_IOWAIT enter gate (2026-09-18)

`IORING_ENTER_NO_IOWAIT` is admitted by the shared enter path. Because squeue
does not classify its sleeps as Linux block-I/O waits, the flag is an exact
accounting hint with unchanged scheduling. Tests require success alone, during
submission and with GETEVENTS, prove that unused arguments remain uninspected,
and retain unknown-flag rejection. Focused evidence is
`/tmp/linuxulator-gate-20260917/noiowait-focus-pass1.console.log`. Full evidence
is `/tmp/linuxulator-gate-20260917/noiowait-full-run1/results.json`: 338 Linux
io_uring cases, 756 repeated shared-option executions, 102 buffer executions,
78 file-table executions, three native runs and four direct regressions passed.
Diagnostics and final resource counters were clean; shutdown and ZFS health
passed. This architecture-neutral change required no arm64 rerun.


## Taskrun setup-mode gate (2026-09-18)

Shared squeue implements COOP_TASKRUN, TASKRUN_FLAG and DEFER_TASKRUN. Admission
requires COOP or DEFER for TASKRUN_FLAG and SINGLE_ISSUER for DEFER. Worker,
cancellation and timeout ready-list publication sets `IORING_SQ_TASKRUN`; the
issuer clears it only after draining all resolved work. Focused testing uses a
blocked pipe worker to prove the complete flag transition through native and
Linux frontends three times each. Evidence is
`/tmp/linuxulator-gate-20260917/taskrun-focus-pass1.console.log` and the full
`/tmp/linuxulator-gate-20260917/taskrun-full-run1/results.json`, where 338 Linux
cases and 756 shared-option executions passed with no diagnostics or resource
residue and with healthy ZFS and clean shutdown. This architecture-neutral
phase required no arm64 rerun.


## Extended ring-layout gate (2026-09-18)

Shared squeue implements SQE128 and CQE32 with explicit per-context strides.
Ring allocation and mmap bounds charge the expanded storage, submission copies
only the standard SQE half, and completion publication zeros the added CQE half.
The focused matrix wraps all four relevant layout combinations three times per
frontend and checks extension isolation. Evidence is
`/tmp/linuxulator-gate-20260917/ext-layout-focus-pass1.console.log`. Final full
evidence is `/tmp/linuxulator-gate-20260917/ext-layout-full-run2/results.json`:
338 Linux io_uring cases, 762 shared-option executions, 102 buffer executions,
78 file-table executions, three native runs and four regressions passed. Every
ring initialization also asserts NO_IOWAIT feature advertisement. Diagnostics,
resource counters, ZFS health and shutdown were clean. No arm64 rerun was needed
for this architecture-neutral phase.


## SQ_REWIND setup gate (2026-09-18)

Shared squeue implements SQ_REWIND only with NO_SQARRAY. Submission uses the
requested prefix beginning at index zero, clamps to ring capacity and leaves the
shared head and tail untouched; each later enter rewinds again. Tests cover
dependency rejection, exact flags, rewritten entries, count bounds, ordinary
preparation stopping and SUBMIT_ALL continuation through both ABIs. Focused
evidence is `/tmp/linuxulator-gate-20260917/rewind-focus-pass1.console.log`.
Full evidence is `/tmp/linuxulator-gate-20260917/rewind-full-run1/results.json`:
338 Linux io_uring cases, 768 shared-option executions, 102 buffer executions,
78 file-table executions, three native runs and four regressions passed with no
diagnostics or resource residue and with healthy ZFS and clean shutdown. This
architecture-neutral phase required no arm64 rerun.

## Mixed CQE layout gate (2026-09-18)

Shared squeue implements CQE_MIXED as a logical 16-byte CQ with operation-selected
32-byte records. NOP_CQE32 preserves both extension words, sets F_32 only in
mixed mode, pads a last-slot wrap with SKIP, and retains size and payload while
backlogged on overflow. Setup rejects CQE32 combined with CQE_MIXED and mixed
completion queues smaller than two slots. SQE_MIXED was rejected in this
historical CQE_MIXED gate; the later NOP128 and socket URING_CMD128 support
provides the two-slot contract and has a separate acceptance row above.

The focused native/Linux matrix ran `cqe_mixed_shared` three times per frontend
and is recorded in
`/tmp/linuxulator-gate-20260917/cqe-mixed-focus-pass3.console.log`. The complete
amd64 ZFS-root gate is
`/tmp/linuxulator-gate-20260917/cqe-mixed-full-run4/results.json`: 338 Linux
io_uring cases, 774 shared-option executions, 102 buffer executions, 78
file-table executions, 72 read/write-flag executions, 120 linked-request
executions, 132 setup/ownership executions, three native runs and four direct
regressions passed. Issuer, file, request and wired-page counters returned to
zero; diagnostics, ZFS health and shutdown were clean. This architecture-neutral
phase required no arm64 rerun.



## `file_getattr` / `file_setattr` gate (2026-09-18)

Linux syscall slots 468 and 469 now use their five-argument ABI on amd64,
arm64, i386 and linux32.  The implementation is Linuxulator-owned and reuses
native VFS stat/chflags operations.  Immutable, append-only and nodump map to
native flags; unsupported mutable xflags and scalar allocation/project fields
return `EOPNOTSUPP`; read-only xflags and the get-only extent count are ignored
on set as Linux specifies.  The existing `FS_IOC_GETFLAGS`/`SETFLAGS` path now
uses the same ZFS-correct `SF_IMMUTABLE` and `SF_APPEND` representation.

The freestanding `linux_fileattr` test has 60 positive and negative assertions
covering structure sizes and extension bytes, bad pointers and flags, missing
paths and descriptors, the three supported flags through both syscall and
ioctl APIs, unsupported fields, relative dirfds, empty and null paths,
`O_PATH`, symlink following, directories, pipes and unprivileged mutation.  A
focused ZFS/tmpfs matrix passed three rounds per filesystem in
`/tmp/linuxulator-gate-20260917/fileattr-focus3.console.log`.  A Linux 6.18.35
oracle passed the matching stable-UAPI variant in
`/tmp/linuxulator-gate-20260917/fileattr-linux-final2.console.log`; the source
test additionally checks the newer read-only VERITY xflag.

The complete amd64 ZFS-root result is
`/tmp/linuxulator-gate-20260917/fileattr-full-run2/results.json`: 36 base ABI
cases, five direct regressions, 180 OFD-lock executions, 39 seal executions,
144 resolution executions, 774 shared-option executions, 72 tmpfs read/write
flag executions, 102 tmpfs buffer executions, 120 tmpfs link executions, 132
tmpfs setup executions, 78 tmpfs file-table executions, three native squeue
runs and 338 Linux io_uring cases passed.  Diagnostics were empty; issuer,
file, request and wired-page counters returned to zero; ZFS was healthy and
shutdown was clean.  The changes are architecture-neutral, so no arm64 guest
was run.


## `fchroot` gate (2026-09-18)

Linux syscall slot 472 uses its two-argument ABI on amd64, arm64, i386 and
linux32.  The Linuxulator rejects unknown flags before descriptor lookup,
rejects `O_PATH`, checks directory search access before chroot privilege, and
retains the checked vnode across the native `kern_chroot()` call.  That
reference prevents a concurrent descriptor close/reuse from switching the
selected root.  Native capability restrictions and chroot lifecycle still
apply.  This requires no new host syscall or ZFS implementation.

The freestanding amd64 regression has 16 positive and negative checks for
unknown flags, invalid/closed descriptors, non-directory file and pipe,
`O_PATH`, root change and cwd behavior, search permission and privilege.
Its focused ZFS-root QEMU run passed three times each on ZFS and tmpfs, with
healthy ZFS and clean shutdown:
`/tmp/linuxulator-gate-20260917/fchroot-focus.console.log`.  The full amd64
ZFS-root gate passed in
`/tmp/linuxulator-gate-20260917/fchroot-full-run/results.json`: 36 base ABI
runs, six direct regressions, 180 OFD runs, 39 seal runs, 144 path-resolution
runs, 774 shared-option runs, 72 tmpfs read/write-flag runs, 102 tmpfs
registered-buffer runs, 120 tmpfs linked-request runs, 132 tmpfs setup runs,
78 tmpfs file-table runs, three native squeue runs, and 338 io_uring cases.
There were no kernel diagnostics or resource leaks, the ZFS pool was healthy,
and shutdown was clean.  This is an architecture-neutral change; the
regenerated non-amd64 ABI tables have not been guest-tested in this phase.


## Legacy Linux AIO implementation contract (amd64 partial)

The freestanding amd64 regression source is
`tests/sys/kern/linux_aio.c`; its ATF wrapper remains staged until the
full contract below is qualified.  Its initial 52 numbered success/failure checkpoints across the six
calls passed Linux 6.18.35 in the disposable QEMU oracle at
`/tmp/linuxulator-gate-20260917/aio-linux-reference2.console.log` (binary
SHA-256 `4360338794b852774266c4780bebc497e9a8fbe1d1436d7b41d6883214c04a21`).
The added checks cover `io_submit` with a NULL IOCB array and with a NULL
IOCB element, both returning `EFAULT`.  An attempted negative-nanosecond
`io_getevents` test blocked on an empty context under that Linux kernel; do
not encode an assumed `EINVAL` for that case without a separately bounded
oracle probe.  This is initial reference evidence, not a BSD gate or full AIO
qualification.  The test is deliberately not registered in the ordinary ATF
Makefile while the six entries remain partial.

### Backend ownership and completion path

The kernel-source audit found that native POSIX AIO already owns a bounded
worker pool and queues completed `kaiocb` objects on its per-process
`kaio_done` list.  Its existing `aio_aqueue()` path can issue positioned scalar
and vectored I/O and fsync/fdatasync; `aio_complete()` can also run from a
bio completion context.  A Linux ABI adapter therefore needs an internal
native-AIO submission/cancellation hook and a completion callback that performs
no user-memory copy or sleep while the native `kaio_mtx` is held.  The callback
must publish into kernel-mapped ring pages, account one terminal result, and
wake waiters.  The caller can reap completed native jobs on `io_getevents`,
`io_submit`, and teardown; this preserves native job and file-reference
accounting without freeing an AIO job from a foreign worker process.

The ring mapping should follow the dual-mapped wired `OBJT_PHYS` pattern used
by `sys/kern/sys_squeue.c`: one shared VM object mapped into the Linux mm and
into kernel KVA.  `copyout()` from a bio completion callback is unsafe, and an
ordinary anonymous mapping would not give the callback a stable kernel
address.  The wired-page charge needs the same per-process `RLIMIT_MEMLOCK`
and system-wide bounds as squeue.  Linux AIO contexts belong to the mm, not a
file descriptor or a particular task.  Forked children with a new mm cannot
use a parent's context handle, while tasks made with `CLONE_VM` must share
contexts.  A process-only `linux_pemuldata` list is insufficient for that last
case; implementation must either attach to the shared `vmspace` lifetime or
maintain an explicit mm-keyed registry with balanced clone/exec/exit ownership.
The Linux-specific IOCB translation, context registry, ring layout, eventfd
and signal-mask semantics stay in the Linuxulator; the reusable native AIO
hook and any shared wired-ring allocator belong in the host kernel source.
The shared hook now exists in `sys/kern/vfs_aio.c` and `sys/sys/aio.h`:
`aio_compat_submit()` translates through an ABI callback into a native job,
`aio_compat_done_fn_t` runs under the native AIO lock, and
`aio_compat_cancel()`, `aio_compat_reap_done()` and `aio_compat_drain()`
retain native cancellation and teardown accounting.  The amd64 kernel build
passed, and the existing disposable amd64 ZFS-root QEMU regression gate passed
with this shared change: `/tmp/linuxulator-gate-20260918/aio-adapter-gate/run2/results.json`
reports 36 base cases, 6 regressions, 180 OFD cases, 39 seal cases, 144
resolution cases, 774 shared option cases and 338 io_uring cases, with zero
diagnostic failures and a clean shutdown.  The adapter now has an amd64 Linuxulator caller; the earlier adapter-only
gate remains regression evidence, not AIO behavior qualification.

The six amd64 entries `io_setup` (206), `io_destroy` (207), `io_getevents`
(208), `io_submit` (209), `io_cancel` (210) and `io_pgetevents` (333) now
have partial handlers.  Linux context ownership, the mmap completion ring,
eventfd signaling, errno conversion, and scalar/vectored file I/O live in
`sys/compat/linux/linux_aio.c`.  The small native-AIO submission, completion,
cancellation and reap adapter lives in `sys/kern/vfs_aio.c` and `sys/sys/aio.h`.
No host syscall numbers were added.  These are source and VM-gated working-tree
changes; they are not a fully qualified Linux AIO implementation.  Linux32
still returns `ENOSYS` for `io_pgetevents`; the amd64 path supports selected
per-write flags but not poll IOCBs or the full `rw_flags` contract.

The first integrated disposable amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260918/aio-six-gate2/run/results.json`.  Its script
ran the 52-check reference ABI regression three times each on ZFS and tmpfs,
plus context-only and I/O-only splits and the existing 36 base, 6 regression,
774 shared-option and 338 io_uring case runs.  All recorded cases and guest
shutdown passed with zero diagnostic failures.  A separate capacity test fills
the completion ring, drains it, consumes a mapped event directly, then submits
again.  It passed Linux 6.18.35 in
`/tmp/linuxulator-gate-20260918/aio-capacity-oracle.console.log` and passed
three times each on ZFS and tmpfs in the updated guest.  Its full
regression gate passed at
`/tmp/linuxulator-gate-20260918/aio-capacity-gate/run/results.json`.
The capacity bound now accounts for both active jobs and unconsumed
completions, so a fast producer cannot grow the overflow queue indefinitely
without consuming ring events.  Five additional `io_pgetevents` checks cover
temporary signal-mask restoration and bad mask pointers; these passed the
Linux oracle at `/tmp/linuxulator-gate-20260918/aio-mask-oracle.console.log`.
The latest module revision also handles a direct mmap consumer racing with
`io_getevents` copyout without an accounting assertion.  The repository gate
script now requires 33 AIO markers on amd64 (context, I/O, full ABI,
capacity, flags and cancellation), and the image builder requires the six
Linux AIO test payloads.  The earlier integrated
VM run passed at `/tmp/linuxulator-gate-20260918/aio-race-gate/run/results.json`:
21 AIO markers passed, together with 36 base cases, 774 shared-option cases,
338 io_uring cases, zero diagnostic failures and clean shutdown.  The four
AIO variants ran three times each on their specified ZFS/tmpfs paths.  This
qualifies the tested subset, not the unresolved per-call matrix below.

Per-write IOCB policy now translates `RWF_DSYNC`, `RWF_SYNC`, `RWF_APPEND`,
and `RWF_NOAPPEND` into shared native `FOF_*` flags on the AIO job.  The
Linux flag validation remains in `linux_aio.c`; the native AIO worker simply
passes the translated policy to its file operation.  The freestanding
`AIO_FLAGS_ONLY` test checks append placement, no-append override of an
`O_APPEND` descriptor, sync and datasync completion, and rejection of an
unknown flag.  It passed the Linux 6.18.35 oracle at
`/tmp/linuxulator-gate-20260918/aio-flags-oracle.console.log`, then three
ZFS and three tmpfs runs in the disposable amd64 guest.  The full updated
gate passed at `/tmp/linuxulator-gate-20260918/aio-rwf-gate/run/results.json`:
27 AIO markers, 36 base cases, 774 shared-option cases and 338 io_uring
cases passed, with zero diagnostic failures and clean shutdown.  A separate
static native POSIX AIO regression in `tests/sys/kern/aio_compat_native.c`
checks read, write, fsync and bad-descriptor rejection; it passed three ZFS
and three tmpfs runs in the disposable guest.  The native regression is now a
required gate payload and six-marker check.  Its full gate result is
`/tmp/linuxulator-gate-20260918/aio-native-gate/run/results.json` and
passed with zero diagnostics and clean shutdown.

Linux 6.18.35 also accepted `RWF_DSYNC`, `RWF_SYNC`, `RWF_APPEND` and
`RWF_NOAPPEND` on AIO reads, while rejecting the conflicting
`RWF_APPEND|RWF_NOAPPEND` pair.  The Linuxulator accepts these read-side hints
without passing write-only policy to the native read operation.  The first BSD
VM image for that correction accidentally contained an older
`linux_common.ko` from the full kernel object tree; its checkpoint 88 failure
exposed a staging error.  The exact rebuilt module passed the full gate at
`/tmp/linuxulator-gate-20260918/aio-readflags-final-gate/run/results.json`.
The separate `RWF_SYNC` read regression passed Linux at
`/tmp/linuxulator-gate-20260918/aio-sync-read-oracle.console.log` and the
full BSD VM at `/tmp/linuxulator-gate-20260918/aio-readsync-gate/run/results.json`.
The expanded append-hint read test passed Linux at
`/tmp/linuxulator-gate-20260918/aio-readappend-oracle.console.log` and the
full BSD VM at `/tmp/linuxulator-gate-20260918/aio-readappend-gate/run/results.json`:
27 AIO markers, 6 native AIO markers, 36 base cases, 774 shared-option
cases and 338 io_uring cases passed with zero diagnostics and clean shutdown.
A subsequent Linux-reference probe accepted `RWF_HIPRI` on a buffered AIO
read; its matching amd64 VM test passed three ZFS and three tmpfs runs in
`/tmp/linuxulator-gate-20260918/aio-hipri-gate/run/`.  The guest boot log
records `linux_common.ko` SHA-256
`57da758e0dc6cd8a7de3d6cbb7921406d5c67f42af4ed397ad3c8d91802d1f80`,
matching the staged module.  The full regression
gate for that image passed at
`/tmp/linuxulator-gate-20260918/aio-hipri-gate/run/results.json`: 27 Linux
AIO markers, 6 native AIO markers, 36 base cases, 774 shared-option cases,
338 io_uring cases, zero diagnostics and clean shutdown.  The current backend
treats HIPRI as a hint for this buffered case; direct-I/O priority behavior
is not qualified.
`NOWAIT`, atomic writes, `DONTCACHE`, and `NOSIGNAL` remain unsupported or
unqualified.  Poll IOCBs are qualified below.  The later `IOCB_FLAG_IOPRIO`
section records class validation and privilege enforcement; the native backend
does not apply accepted priorities to I/O scheduling.

The `AIO_CANCEL_ONLY` stress test submits up to 32 distinct writes, races
`io_cancel` against completion, and requires exactly one terminal event per
accepted IOCB with matching data, object pointer and result.  It passed the
Linux 6.18.35 oracle at
`/tmp/linuxulator-gate-20260918/aio-cancel-oracle.console.log` and three
ZFS plus three tmpfs rounds in the disposable amd64 guest.  The full gate passed at
`/tmp/linuxulator-gate-20260918/aio-cancel-gate/run/results.json`: 33 Linux
AIO markers, 6 native AIO markers, 36 base cases, 774 shared-option cases and
338 io_uring cases passed with zero diagnostic failures and clean shutdown.
This workload did not produce a guaranteed successful cancel on the Linux
oracle, so it does not qualify queued/active cancellation.  A separate
deterministically pending operation is still required for the positive
`EINPROGRESS` path and eventfd-once assertion.  Linux poll cancellation is a
distinct case: its queued completion has result zero, while a cancelled file-I/O
request may report `-ECANCELED`.  The `AIO_POLL_ONLY` test now covers pipe
readiness, exactly one eventfd signal, a deterministically pending poll cancel,
and rejection of nonzero length, offset, read/write flags and mask bits above
16. The extended oracle also requires two pending subscribers on one pipe to
complete once each with two eventfd increments; a poll must remain tied to its
original file after the fd closes and is reused for a different pipe. It checks
immediate writable readiness, peer-close `POLLHUP`, and bad-fd rejection
without clearing the IOCB key. The expanded test passed Linux 6.18.35 with a
clean shutdown at
`/tmp/linuxulator-gate-20260919/aio-poll-matrix-oracle.console.log`.
A shared `kern_poll_fps()` helper now waits on held `struct file` references
and a control wakeup; the Linuxulator owns a separate poll consumer, IOCB
validation, cancellation, Linux mask conversion, eventfd notification and AIO
ring publication. The first integrated disposable amd64 ZFS-root gate passed
at `/tmp/linuxulator-gate-20260919/aio-poll-first-gate/run/results.json`:
39 Linux AIO markers (including six poll rounds), six native AIO markers, 36
base cases, 144 pathname cases, 774 shared-option cases and 338 io_uring
cases, with zero diagnostic failures and a clean shutdown. A subsequent source
audit found eventfd could signal before the ring tail was published. The
publisher now orders the ring update before eventfd and keeps the context
pending until signaling finishes. The strengthened test first waits for eventfd
readability, then requires a published AIO ring entry before reaping it, for
both readiness and cancellation. It passed Linux 6.18.35 at
`/tmp/linuxulator-gate-20260919/aio-poll-publication-oracle.console.log` and
the second full disposable amd64 ZFS-root gate at
`/tmp/linuxulator-gate-20260919/aio-poll-publication-gate/run/results.json`: 39
Linux AIO markers, six native AIO markers, 36 base cases, 144 pathname cases,
774 shared-option cases and 338 io_uring cases, zero diagnostics and clean
shutdown. Poll readiness, cancellation, fd lifetime and eventfd publication
are qualified for these test cases. Pending-poll context destruction and
process-exit teardown passed the Linux 6.18.35 oracle and the next full
amd64 ZFS-root BSD gate at
`/tmp/linuxulator-gate-20260919/aio-poll-teardown-gate/run/results.json`: again
39 Linux AIO markers, six native AIO markers, 36 base cases, 144 pathname
cases, 774 shared-option cases and 338 io_uring cases, zero diagnostics and
clean shutdown. Those teardown cases are qualified for the tested paths.

The IOCB key and cancellation-result audit found two Linuxulator ABI
errors.  Linux writes zero to the user IOCB `key` during submission and reads
that key before resolving `io_cancel`'s context; the handler now does both,
including `EFAULT` for a read-only IOCB and bad cancel pointer.  The native
AIO callback had negated `bsd_to_linux_errno()` twice, turning a successful
queued cancellation's `-ECANCELED` into positive 125.  The ZFS VM diagnostic
recorded `AIO_RES 000000000000007d` for that case; the callback now uses the
negative value directly.  The expanded cancellation test passed the Linux
6.18.35 oracle at `/tmp/linuxulator-gate-20260918/aio-key-oracle.console.log`.
The first full amd64 ZFS attempt at
`/tmp/linuxulator-gate-20260919/aio-key-errno-gate/run/` passed all 33 AIO
markers and six native AIO markers, but two unrelated ZFS pathname race
rounds reached their 60-second per-case limit under host load. It was ended
after those failures; it is not qualification. The gate now allows that
1000-mutation/4000-lookup ZFS race 180 seconds while preserving the 60-second
limit for other pathname cases. The corrected full amd64 ZFS-root gate
passed at `/tmp/linuxulator-gate-20260919/aio-key-errno-retry/run/results.json`:
33 Linux AIO markers, six native AIO markers, 36 base cases, 144 pathname
cases, 774 shared-option cases and 338 io_uring cases passed, with zero
diagnostic failures and a clean shutdown. All three ZFS pathname race rounds
passed under the revised bound. This qualifies the tested IOCB-key and
cancellation-result behavior, not the remaining legacy AIO options below.
A subsequent `io_submit` audit found an additional ordering mismatch.
Linux rejects reserved fields and a bad target or eventfd descriptor before
writing `aio_key`, but writes zero before dispatching an unknown opcode. The
Linuxulator now follows that order. Four negative checks in `AIO_CANCEL_ONLY`
assert the returned errno and whether a sentinel key is preserved or reset.
They returned `ORACLE_AIO 0` on Linux 6.18.35 at
`/tmp/linuxulator-gate-20260919/aio-key-precedence-oracle.console.log`; the
oracle's poweroff exceeded its 60-second harness wait under host load after the
test result. The first BSD image accidentally staged a FreeBSD-branded copy of
the Linux raw-syscall test, so its SIGBUS result is a payload error, not AIO
evidence. The image builder now checks the Linux ELF brand for every AIO test.
The corrected full BSD ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/aio-key-precedence-final/run/results.json`:
33 Linux AIO markers, six native AIO markers, 36 base cases, 144 pathname
cases, 774 shared-option cases and 338 io_uring cases passed, with zero
diagnostic failures and a clean shutdown. This qualifies the tested key
ordering; poll IOCBs and the remaining legacy AIO options still need separate
implementation and gates.

Pin the ABI to [Linux's aio_abi.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/aio_abi.h)
and [the syscall implementation](https://github.com/torvalds/linux/blob/master/fs/aio.c).
The current upstream implementation accepts read, write, vectored read/write,
fsync, fdatasync and poll IOCB commands.  It accepts a zeroed context word
on setup, publishes the resulting handle into that word, ties the context to
the address space, and waits for in-flight user buffers before destroy
returns.  Submission accepts a partial batch and returns the number actually
queued.  Completion events carry the original IOCB address, user data, signed
result and second result.  Modern `io_cancel` delivers completion via the
normal ring and can return `EINPROGRESS`; its older comment about copying
the event into `result` is stale.  Linux's 32-byte AIO mmap ring header, head/tail
publication, capacity and mapping lifetime are observable to libaio and
therefore part of the required implementation, not an optional fast path.

| Entry point | Mandatory ZFS-root amd64 VM cases before qualification |
|---|---|
| `io_setup` | zero and extreme capacities, nonzero starting handle, NULL/read-only/cross-page output, multiple contexts, shared-mm threads, fork/exec/exit, mappings and charged-resource rollback |
| `io_submit` | scalar/vectored read/write, fsync/fdatasync, poll and eventfd, offsets and short I/O, reserved/unknown fields, rw flags, bad fd, pointer arrays/IOCB/buffer/iovec faults, partial batches, full rings, concurrent producers and fd close/reuse |
| `io_getevents` | min/max counts, zero/expired/infinite relative timeout, invalid timespec, NULL/guard/read-only event buffers, partial delivery, signal interruption, concurrent consumers and data/event visibility ordering |
| `io_pgetevents` | every `io_getevents` case plus invalid sigset size/pointer, blocked-versus-pending signal, temporary mask and restoration on normal, interrupted and fault paths |
| `io_cancel` | unknown/completed/active/queued IOCBs, key and pointer faults, cancellation race, exactly one terminal event, no premature buffer release, eventfd once, `EAGAIN`/`EINPROGRESS` as appropriate |
| `io_destroy` | invalid/double handle, requests in flight and full completion ring, waits for buffer users, concurrent submit/getevents/cancel, no handle reuse confusion, fork/exec/exit cleanup and repeated create/destroy with zero retained resources |

Poll IOCBs need a readiness subscription that completes once when the target fd
becomes ready and can be cancelled without losing or duplicating an event.
The current squeue kqueue polling path is private to `sys_squeue.c` and tied to
an squeue ring context; it cannot be called directly from a legacy AIO
context. Registering a kqueue note by the user's fd is insufficient: FreeBSD
removes that note on close, while the Linux oracle shows the AIO poll retains
the underlying file across close and fd reuse. A backend must subscribe using
a held `struct file` identity and have an independent wake path so eventfd is
signaled without a thread entering `io_getevents`. Linux poll-mask/IOCB
translation and event publication belong in the Linuxulator. A reusable
file-pointer-stable readiness subscription and cancellation primitive, if
factored from squeue or select, belongs in shared kernel code. The host's
`fo_poll(fp, ..., td)` already polls a held `struct file`, and `selrecord` plus
`selwakeup` can wake a selection thread; the coordinating `seltdinit`,
`seltdwait` and `seltdclear` helpers in `sys_generic.c` are private today.
A shared primitive must close the wake-versus-registration race and retain
file references through cancellation and completion. The Linuxulator should
own the IOCB list, key lookup, Linux mask conversion, eventfd-once behavior,
and ring publication. Do not occupy a
native AIO worker with a blocking `poll()` wait: that would allow idle poll
IOCBs to exhaust the bounded file-I/O worker pool.  Qualify fd close/reuse,
readiness at submission, readiness after arming, simultaneous readiness and
cancel, destroy, eventfd notification and exactly one terminal result in the
amd64 VM before removing `IOCB_CMD_POLL` from the backlog.

Run each named syscall's positive and negative suite three times on ZFS and
again on tmpfs while the base guest remains ZFS-root; run equivalent portable
cases under a Linux reference kernel and a real libaio database workload that
confirms it selected AIO.  Require the full existing squeue/io_uring and
filesystem regression gate, clean resource counters, diagnostics and shutdown.
An entry remains unimplemented until its entire supported contract is
qualified by this matrix.

## Shared squeue held-file POLL_ADD (2026-09-19)

Linux 6.18.35 retains a pending `POLL_ADD` request on its original file after
its descriptor is closed and reused. A new `poll_close_reuse` oracle at
`/tmp/linuxulator-gate-20260919/iouring-poll-lifetime-source-oracle.console.log`
passed, while the prior disposable amd64 ZFS-root guest timed out (exit 124)
at `/tmp/linuxulator-gate-20260919/iouring-poll-lifetime-bsd-diag/amd64.console.log`.
A separate `poll_cancel_closed` Linux oracle passed at
`/tmp/linuxulator-gate-20260919/iouring-poll-cancel-source-oracle.console.log`.
The `poll_lifetime_shared` test additionally checks readiness and cancellation
through both native squeue and Linux io_uring, with three repetitions each; it
passed the Linux oracle at
`/tmp/linuxulator-gate-20260919/squeue-poll-lifetime-oracle.console.log`.

The shared kqueue core now has an internal `kern_kevent_file()` registration:
it owns a reference to the target `struct file`, hashes the knote by a private
per-ring request key and keeps it out of `knote_fdclose()`'s fd list. Shared
squeue uses it for `POLL_ADD`, including multishot, update and cancellation;
fast-poll retries retain their separate descriptor-keyed path. The Linuxulator
keeps only ABI translation. The targeted amd64 ZFS-root guest passed all four
readiness/cancellation checks at
`/tmp/linuxulator-gate-20260919/held-kqueue-targeted/amd64.console.log`.
A native negative test also confirmed that a registered file without
`CAP_EVENT` rejects held-file poll at
`/tmp/linuxulator-gate-20260919/held-kqueue-cap-targeted/amd64.console.log`.
The full gate with the native capability negative test passed at
`/tmp/linuxulator-gate-20260919/held-kqueue-final-gate/run/results.json`:
39 Linux AIO markers, six native AIO markers, 36 base cases, 144 pathname
cases, 780 shared-option executions and 340 io_uring cases, with zero
diagnostics and clean shutdown. An additional ring-file cycle audit found
that self-ring `POLL_ADD` needs a descriptor-keyed exception. Linux accepted
self-ring close/cancel at
`/tmp/linuxulator-gate-20260919/iouring-ring-self-oracle.console.log`;
the amended kernel passed both at
`/tmp/linuxulator-gate-20260919/held-kqueue-ring-targeted/amd64.console.log`,
with `kern.squeue.live_requests` staying at zero. The 342-case full gate
for that amendment passed at
`/tmp/linuxulator-gate-20260919/held-kqueue-ring-safe-gate/run/results.json`:
39 Linux AIO and six native AIO markers, 36 base cases, 144 pathname cases,
780 shared-option executions and 342 io_uring cases, with zero diagnostics and
clean shutdown. A subsequent audit found that native capability-mode
`POLL_ADD` bypassed the raw-fd restriction by entering the asynchronous path.
The shared squeue arm path now rejects raw fds with `ENOTCAPABLE`; a native
positive fixed-file and negative raw-fd regression is in `files_caps`. Its
updated full gate passed at
`/tmp/linuxulator-gate-20260919/held-kqueue-capmode-gate/run/results.json`:
all three native `files_caps` rounds passed, alongside 39 Linux AIO and six
native AIO markers, 36 base cases, 144 pathname cases, 780 shared-option
executions and 342 io_uring cases. Diagnostics and final issuer, file and
request counters were zero, and the guest shut down cleanly. Ordinary-file
close/reuse is qualified; ring-target close/reuse remains a separate open case.
A focused two-ring reproduction confirms its contract: Linux 6.18.35 passed
`poll_ring_cross_reuse` at
`/tmp/linuxulator-gate-20260919/iouring-cross-ring-oracle.console.log`.
The disposable amd64 ZFS-root guest timed out (124) at
`/tmp/linuxulator-gate-20260919/iouring-cross-ring-bsd/amd64-final.console.log`.
The test polls ring B from ring A, closes and reuses B's original descriptor,
then submits a NOP through a duplicate B descriptor. The watched B completion
must wake A. A strong held-file reference solves this single direction but can
form a self- or mutual-ring reference cycle, so ring-target ownership needs a
separate design and tests for both cycle teardown and close/reuse before it
enters the mandatory inventory. The focused reproduction is retained in `tests/sys/kern/linux_iouring.c`
behind `LINUX_IORING_DIAGNOSTIC_RING_CROSS`, so the known-failing BSD case
does not enter the mandatory passing inventory before its fix. The complementary
`poll_ring_mutual_close` case passed a Linux oracle at
`/tmp/linuxulator-gate-20260919/iouring-mutual-ring-oracle.console.log` and
three focused BSD ZFS-root rounds at
`/tmp/linuxulator-gate-20260919/iouring-mutual-ring-bsd/amd64.console.log`
with `kern.squeue.live_requests` at zero. It is now mandatory in the 343-case
inventory. The full amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/iouring-mutual-mandatory-gate/run/results.json`:
39 Linux AIO and six native AIO markers, 36 base cases, 144 pathname cases,
780 shared-option executions and 343 io_uring cases; zero diagnostics, zero
final issuer/file/request counts and clean shutdown. Any held-ring fix must
preserve mutual teardown as well as cross-ring readiness after fd reuse.

## io_uring POLL_ADD_LEVEL boundary (2026-09-19)

The local UAPI declares `IORING_POLL_ADD_LEVEL`, but the pinned Linux 6.18
`io_poll_add_prep()` accepts only `IORING_POLL_ADD_MULTI` in `sqe->len`; the
flag and its `MULTI|LEVEL` combination complete with `-EINVAL`. The Linux
6.18.35 reference guest confirmed this at
`/tmp/linuxulator-gate-20260919/squeue-poll-level-rejected-oracle.console.log`.
The newer pinned Linux 7.1.5 guest also passed the same rejection matrix at
`/tmp/linuxulator-gate-20260919/linux715/oracle-poll-level-715.console.log`.
`poll_level_rejected_shared` tests the declared-but-rejected flag, its
combination with multishot, an unknown flag, a rejected poll-update flag,
and survival of an unrelated armed poll after the rejected update. It runs
through both native squeue and Linux io_uring. Retain this version-specific
boundary until a newer Linux reference is pinned and the shared engine
implements level-triggered multishot delivery and its update/cancel behavior.
The 131-group, 786-execution amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/poll-level-rejected-fixed-gate/run/results.json`:
39 Linux AIO and six native AIO markers, 36 base cases, 144 pathname cases,
786 shared-option executions and 343 io_uring cases, with zero diagnostics,
zero final issuer/file/request counts and clean shutdown. The earlier image
without the shared validation fix failed all six new option runs, confirming
that this test exercises the changed behavior.

## io_pgetevents signal interruption (2026-09-19)

`io_pgetevents` now converts the BSD internal `ERESTART` from an interrupted
AIO completion wait to `EINTR` at the Linuxulator boundary. Without that
conversion, a Linux `SA_RESTART` signal handler reran the syscall and the
second wait returned zero events. A pending signal observed at an otherwise
empty timeout also produces `EINTR` while the temporary mask is active. The
original mask is restored by the existing return-to-userspace AST.

The Linux 6.18.35 reference VM passed the freestanding amd64 signal probe at
`/tmp/linuxulator-gate-20260919/aio-pgetevents-signal-oracle.console.log`.
The new `linux_aio_signal.c` gate case verifies that a pending SIGUSR1 stays
blocked without a temporary mask, interrupts `io_pgetevents` even with
`SA_RESTART`, reaches the handler once, restores the original mask, and leaves
a subsequent zero-timeout wait successful. The same case checks an invalid timeout pointer after mask installation
returns `EFAULT` and restores the original mask. The existing full AIO suite
checks invalid sigset size and pointer and restoration after a normal
zero-event wait.
The initial BSD VM reproduced the wrong zero-event result after restart; the
instrumented VM confirmed `ERESTART` followed by a successful second wait.

The final amd64 ZFS-root QEMU gate passed at
`/tmp/linuxulator-gate-20260919/aio-pgetevents-signal-fault-gate/run/results.json`:
45 Linux AIO markers, including three new signal rounds each on ZFS and tmpfs;
six native AIO markers; 36 base cases; 144 pathname cases; 786 shared-option
executions; and 343 io_uring cases. It recorded zero diagnostics, zero final
issuer/file/request counts, healthy ZFS pool and a clean shutdown. This change
is confined to `linux_common`; the native AIO and squeue engines are unchanged.

A separate Linux-reference timeout probe at
`/tmp/linuxulator-gate-20260919/aio-timeout-oracle.console.log` observed that
`io_getevents` and `io_pgetevents` returned zero for a zero-minimum wait with
`tv_nsec == 1000000000` or `tv_sec == -1`; the local implementation rejects
those noncanonical values before waiting. The negative-second case with
`min_nr == 1` did not complete during the probe, so the probe was stopped.
That difference was not qualified by the signal gate; the bounded timeout
matrix and fix are recorded below.

## Legacy AIO timeout conversion (2026-09-19)

The Linux 6.18.35 timeout oracle accepted noncanonical `tv_nsec == 1e9` and
negative seconds/nanoseconds for both `io_getevents` and `io_pgetevents`. A
bounded SIGALRM oracle showed that a negative relative timeout with
`min_nr == 1` waits until interrupted, returning `EINTR`. The Linuxulator
now converts the raw timespec without a canonical-range rejection, treats
negative and saturated intervals as untimed waits, and uses unsigned tick
elapsed time to avoid a signed deadline wrap. Plain `io_getevents` now maps
BSD's internal `ERESTART` to `EINTR` as well. The freestanding
`linux_aio_timeout.c` test covers zero-minimum, noncanonical positive and
negative values, timed expiration, invalid pointers/counts and four
signal-interrupted negative waits. It passed the Linux reference at
`/tmp/linuxulator-gate-20260919/aio-timeout-final-oracle.console.log`.


The timeout-only amd64 ZFS-root QEMU gate passed at
`/tmp/linuxulator-gate-20260919/aio-timeout-only-gate/run/results.json`:
51 Linux AIO markers, six native AIO markers, 36 base cases, 144 pathname
cases, 786 shared-option executions and 343 io_uring cases. It reported zero
diagnostics, zero final issuer/file/request/page counts, a healthy ZFS pool
and clean shutdown. This batch changes Linuxulator AIO behavior only; the
native AIO and shared squeue engines are unchanged. No cap-mode syscall-table
flags are enabled by this batch.

## Legacy AIO request-count bounds (2026-09-19)

The Linux 6.18.35 reference VM accepts `io_getevents` and `io_pgetevents`
maximum counts above 65,536, including `LONG_MAX`, and returns only the
available events. It also accepts an `io_submit` batch count above 65,536:
an invalid first pointer returns `EFAULT`, while a valid first IOCB followed
by an invalid pointer returns the one submitted request. The bounded oracle
and permanent regression both passed on Linux at
`/tmp/linuxulator-gate-20260919/aio-count-oracle.console.log`.

Linuxulator now rejects negative or inconsistent counts but does not impose
its context-capacity limit on the caller's `nr` argument. Successful submits
are still bounded by the context's reserved slots, and completion reads by
actual events. `linux_aio_counts.c` covers invalid count relations, zero and
boundary counts through `LONG_MAX`, both completion calls, invalid submit
pointer arrays, a partial submit at a large count, and real poll completion
with a large read count. The gate runs it three times each on ZFS and tmpfs.

The final amd64 ZFS-root QEMU gate passed at
`/tmp/linuxulator-gate-20260919/aio-count-final-gate/run/results.json`:
57 Linux AIO markers (including six count-boundary runs), six native AIO
markers, 36 base cases, 144 pathname cases, 786 shared-option executions and
343 io_uring cases. It recorded zero diagnostics, zero final issuer/file/
request/page counts, a healthy ZFS pool and clean shutdown. Only Linuxulator
AIO count validation changed; native AIO and shared squeue are unchanged.

## x86 sysfs(2) filesystem-type enumeration (2026-09-19)

Linux `sysfs(2)` operations 1, 2 and 3 translate a filesystem name to an
index, an index to a name, and return the registered type count. The Linux
source implements this only with `CONFIG_SYSFS_SYSCALL`; the pinned Alpine
Linux 6.18.35 oracle has that option disabled and returned `ENOSYS` for all
three operations (`/tmp/linuxulator-gate-20260919/sysfs-oracle.console.log`).
The [upstream implementation](https://github.com/torvalds/linux/blob/master/fs/filesystems.c)
defines the enabled behavior and `EINVAL`/`EFAULT` boundaries.

The amd64 Linux64 module now exposes only registered FreeBSD filesystem types
under Linux-visible names, including ZFS, tmpfs and the Linux pseudo-filesystem
modules when present. The stable mapping yields a consistent count, index and
name round-trip. Unknown names and indexes return `EINVAL`; user-address faults
return `EFAULT`. `linux_sysfs.c` tests every enumerated name and index, ZFS and
tmpfs presence, all three operations, ignored arguments, invalid operation,
unknown name, bad pointer, bad index, bad buffer and overlong name. The gate
runs it three times on ZFS and tmpfs. This 5BSD kernel intentionally disables
`COMPAT_FREEBSD32`, so the Linux32 stub remains and only Linux64 is gated.

The final amd64 ZFS-root QEMU gate passed at
`/tmp/linuxulator-gate-20260919/sysfs64-gate/run/results.json`: six Linux64
`sysfs` runs, 57 Linux AIO markers, six native AIO markers, 36 base cases,
144 pathname cases, 786 shared-option executions and 343 io_uring cases.
Diagnostics and final issuer/file/request/page counts were zero; the ZFS pool
was healthy and shutdown was clean. The Linux32 module cannot load in this
5BSD VM because the kernel excludes 32-bit binary compatibility; no Linux32
behavior was changed or claimed as tested.

## Linux64 rseq implementation gate (2026-09-19)

Linux64 amd64 now registers per-thread rseq areas and repairs interrupted
critical sections through the scheduler callback, pre-signal AST and signal
frame path. The pinned Linux 6.18.35 amd64 oracle passed registration,
signal/migration, two-thread and exec-lifecycle reference probes. The full
disposable amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/rseq-expanded-gate/run/results.json`:
24 rseq runs (four groups, three rounds on ZFS and tmpfs), 343 io_uring cases,
786 shared squeue-option runs, 57 Linux AIO runs, 6 native AIO runs, 36 base
cases and 144 pathname cases. There were no recognized diagnostics; ZFS was
healthy and shutdown was clean. This gate included negative registration,
invalid descriptor, unmapped area, signal, migration, fork and exec cases.
The subsequent auxiliary-vector addition advertises feature size 28 and
alignment 32 for Linux64 amd64, with a fifth mandatory probe; its final gate
result is recorded separately below. Linux32 and arm64 rseq remain ENOSYS.
The remaining stress matrix is listed in
[the rseq implementation contract](linuxulator-rseq-implementation.md).

## Linux64 rseq auxiliary-vector gate (2026-09-19)

Linux64 amd64 now advertises `AT_RSEQ_FEATURE_SIZE=28` and
`AT_RSEQ_ALIGN=32`, matching the fields and allocation alignment it supports.
The freestanding `linux_rseq_auxv.c` probe reads the initial ELF auxiliary
vector, validates both entries, registers with the resulting allocation size,
checks CPU fields and unregisters. The pinned Linux 6.18.35 oracle passed at
`/tmp/linuxulator-gate-20260919/rseq-auxv-oracle.console.log` (the reference
probe accepts its actual feature size). The BSD gate passed at
`/tmp/linuxulator-gate-20260919/rseq-auxv-gate/run3/results.json`:
30 rseq executions over ZFS/tmpfs, the full 343-case io_uring and
786-execution squeue option matrix, 57 Linux AIO and 6 native AIO cases,
zero recognized diagnostics, healthy ZFS and clean shutdown. The first oracle
image attempt used an invalid 16 MiB FAT32 image and failed to mount; the
valid 64 MiB image passed. The first BSD runner attempt lacked local QEMU
libraries; the corrected invocation passed the complete gate.

## Linux64 rseq same-CPU preemption gate (2026-09-19)

The freestanding `linux_rseq_preempt.c` probe pins parent and busy child to
CPU 0, repeatedly yields from inside a registered critical section, and
requires at least one abort with no lost or duplicate completion. It passed
the pinned Linux 6.18.35 oracle at
`/tmp/linuxulator-gate-20260919/rseq-preempt-oracle.console.log` and the
full disposable amd64 ZFS-root BSD gate at
`/tmp/linuxulator-gate-20260919/rseq-preempt-gate/run/results.json`.
The BSD gate required 36 rseq executions (six groups, three rounds on ZFS and
tmpfs); all exited zero. It also passed 343 io_uring cases, 786 squeue-option
executions, 57 Linux AIO cases, 6 native AIO cases, 36 base cases and 144
pathname cases, with zero recognized diagnostics, healthy ZFS and clean
shutdown. This tests the shared scheduler callback against same-CPU
preemption as well as the previously qualified migration and signal paths.

## Linux64 rseq descriptor-boundary gate (2026-09-19)

The revised `linux_rseq_signal.c` adds fork-child fatal negatives for a
critical-section length that overflows, an abort IP outside userspace, and an
abort IP inside the critical section. The pinned Linux 6.18.35 oracle passed at
`/tmp/linuxulator-gate-20260919/rseq-bounds-oracle.console.log`.
The exact revised binary passed the full disposable amd64 ZFS-root gate at
`/tmp/linuxulator-gate-20260919/rseq-bounds-gate-final/run/results.json`:
36 rseq runs on ZFS/tmpfs, 343 io_uring cases, 786 squeue-option runs and the
other mandatory regressions, zero recognized diagnostics, healthy ZFS and
clean shutdown. The guest SHA-256 of `linux_rseq_signal` was
`770b8e9063a1f39cdd0c2f2ea72caa0b9351d06b64565b11e6ed19faef9f4cf4`,
matching the staged binary.

## Linux64 rseq active-process unload gate (2026-09-19)

`linux_rseq_hold.c` registers an rseq area, publishes a readiness marker and
waits while the guest attempts `kldunload linux64.ko`. The gate requires an
EBUSY rejection and checks that `linux64.ko` remains loaded, then terminates
the Linux process. All six attempts (three on ZFS and three on tmpfs) passed.
The full amd64 ZFS-root result is
`/tmp/linuxulator-gate-20260919/rseq-hold-gate-final/run/results.json`:
42 rseq executions, 343 io_uring cases, 786 squeue-option executions,
zero recognized diagnostics, healthy ZFS and clean shutdown. This verifies
active-process unload refusal; a separately synchronized pending-AST teardown
stress test remains to be done. The first hold-gate image exposed a missing
`grep` utility in the minimal guest and did not test the unload result; the
shell-only check in the final image did.

## Linux64 rseq pending-signal unregister gate (2026-09-19)

The signal probe now blocks SIGUSR1, creates a pending signal inside a
critical section, unregisters rseq while the signal is blocked, then unmasks
it. It requires exactly one handler invocation and unchanged reset CPU fields
after delivery. The pinned Linux 6.18.35 oracle passed at
`/tmp/linuxulator-gate-20260919/rseq-pending-unregister-oracle.console.log`.
The final combined disposable amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/rseq-lifetime-gate/run/results.json`:
42 rseq runs (seven groups, three rounds on ZFS and tmpfs), 343 io_uring
cases, 786 squeue-option executions, 57 Linux AIO cases, 6 native AIO cases,
36 base cases and 144 pathname cases, zero recognized diagnostics, healthy
ZFS and clean shutdown. The guest hashes matched staged `linux64.ko`
(`e7f8d04085c789c3092dc3456788a2a584cdf8b10319cf334f9a3ef8e65a4731`)
and `linux_rseq_signal`
(`9700c6cc85175511561cdf1f649ed65f9cb59dac3341ef61f101086bdcec1096`).
No candidate kernel or module was installed or loaded on the host.

## Linux64 remap_file_pages gate (2026-09-19)

The amd64 handler uses a shared VM-map object-offset replacement helper so a
shared mapping can be remapped after its creating file descriptor is closed.
The freestanding `linux_remap_file_pages.c` probe passed the pinned Linux
6.18.35 reference VM, including alias coherence, page rounding, ignored
flags, `MAP_NONBLOCK`, adjacent same-file VM areas, fork inheritance,
protection changes, different-object rejection, and invalid-argument cases. The exact branded ELF
(SHA-256
`9e7a5d4b5df97541e347cf38f76a93723130c2f28426e59b4fdc33e2891c9ac0`)
passed three runs each on ZFS and tmpfs in the disposable amd64 ZFS-root VM.
The full result is
`/tmp/linuxulator-gate-20260919/remap-edge-gate/results.json`: 42 rseq,
343 io_uring, 786 squeue-option, 57 Linux AIO, 6 native AIO, 36 base and
144 pathname cases; zero recognized diagnostics, healthy ZFS, clean shutdown.
The tested kernel and ZFS, linux64 and linux_common modules were built from
the current source; none was installed or loaded on the host.

The first execution of the branded probe exposed missing vnode write-mapping
accounting in the new VM helper and panicked at unlink. That accounting was
fixed, and the passing run used the corrected kernel. A subsequent full run
found that an older staged ZFS module lacked the current OFD-lock support
flag; the final run used the rebuilt module and passed the OFD checks.

## Linux64 ioperm gate (2026-09-19)

The amd64 wrapper now maps Linux `ioperm` onto the native I/O permission
bitmap, validating the 64-bit range before narrowing it. The native bitmap
helper allows unprivileged revocation but still requires privilege and an
acceptable securelevel when enabling ports. The freestanding Linux probe
passed the pinned Linux 6.18.35 oracle. It and a native `sysarch` regression
probe each passed three ZFS and three tmpfs runs in the disposable amd64
ZFS-root VM. The full result is
`/tmp/linuxulator-gate-20260919/ioperm-second-gate/results.json`: 42 rseq,
343 io_uring, 786 squeue-option, 57 Linux AIO, 6 native AIO, 36 base,
144 pathname and 6 remap cases; zero recognized diagnostics, healthy ZFS and
clean shutdown. The Linux and native probe SHA-256 hashes were
`973ada06d347750cc1aabafbac929293911936351f9ff7ce18a7849ec42ccb7d`
and `5c0ea7616c2e337cd1a7f050901dc870615acbec77e27efbc3feeaba32dcf195`
respectively. No candidate kernel or module was installed or loaded on the
host.

## Linux64 iopl privilege-transition gate (2026-09-19)

The amd64 handler now permits retaining or lowering the current IOPL level
without `PRIV_IO`; raising it still requires privilege and an acceptable
securelevel. The freestanding probe passed the pinned Linux 6.18.35 oracle
and three ZFS plus three tmpfs runs in the disposable amd64 ZFS-root VM. Its
SHA-256 was
`f66579b67dc38d6d9315700aa03ba49dcd6f1e93cb5c914f5a74316c97ec8de5`.
The full result is `/tmp/linuxulator-gate-20260919/iopl-full-gate/results.json`:
42 rseq, 343 io_uring, 786 squeue-option, 57 Linux AIO, 6 native AIO,
36 base, 144 pathname, 6 remap, 6 Linux ioperm and 6 native ioperm cases;
zero recognized diagnostics, healthy ZFS and clean shutdown. No candidate
module was installed or loaded on the host. Instruction-level `iopl`
emulation remains an option-level compatibility gap.

## Linux64 modify_ldt gate (2026-09-19)

The amd64 Linuxulator wrapper now implements all four Linux `modify_ldt`
commands through the native LDT backend. A shared helper snapshots raw
descriptor bytes for partial reads; the native LDT default is now 8192
entries. Linux64 gets a backend validation variant for non-present conforming
descriptors, leaving native `sysarch` behavior unchanged. The freestanding
probe passed the pinned Linux 6.18.35 oracle and three ZFS plus three tmpfs
runs in the disposable amd64 ZFS-root VM. Its SHA-256 was
`42b65be10bdb9db973899a7cba924cca029c41f6357c29d4172759da380e7339`.
The full result is
`/tmp/linuxulator-gate-20260919/ldt-conforming-gate/results.json`: 42 rseq,
343 io_uring, 786 squeue-option, 57 Linux AIO, 6 native AIO, 36 base,
144 pathname, 6 remap, 6 Linux ioperm, 6 native ioperm and 6 iopl cases;
zero recognized diagnostics, healthy ZFS and clean shutdown. No candidate
kernel or module was installed or loaded on the host.

## Linux64 swapon discard-policy gate (2026-09-19)

The Linuxulator maps `SWAP_FLAG_DISCARD`, `DISCARD_ONCE` and `DISCARD_PAGES`
into the shared GEOM swap pager. The native `swapon(2)` default remains
unchanged. The pager checks device delete capability, discards the usable
area in bounded requests on activation for ONCE, and holds freed swap blocks
unavailable until their asynchronous page deletion completes for PAGES.
Swapoff waits for those deletes before closing the device. Read-only kernel
counters expose successful once and page deletion and errors.

The freestanding Linux probe passed the pinned Linux 6.18.35 oracle. Its
negative cases check that PAGES does not cause activation-time deletion and
that subpolicy bits have no effect without the base DISCARD flag. The full
amd64 ZFS-root QEMU result is
`/tmp/linuxulator-gate-20260919/swap-discard-full-gate4/results.json`: six
discard-policy runs across ZFS and tmpfs, six priority runs, six flag runs,
six swapoff runs, 42 rseq, 343 io_uring, 786 squeue-option, 57 Linux AIO,
six native AIO, 36 base and 144 pathname cases. It reports zero recognized
diagnostics, healthy ZFS and clean shutdown. The candidate kernel SHA-256 is
`00cf6add9516e8a2ea5d7034ff834d386f3b4c47890abeebb92b6f73a40bc5cf`.
No candidate kernel or module was installed or loaded on the host. The exact
policy and test design are in [the discard gate](linuxulator-swapon-discard.md).

## Linux64 io_uring EPOLL_WAIT asynchronous gate (2026-09-20)

`IORING_OP_EPOLL_WAIT` now leaves an empty epoll set pending, arms shared
squeue readiness retry, and completes when an event arrives. Linuxulator
validates the reserved SQE fields. Shared squeue retains registered or ambient
epoll file identity and ambient capability rights across descriptor close and
reuse; its private held-file knote is cancelled by request identity. The
Linuxulator uses a rights-preserving temporary descriptor for each ambient
retry. No new native squeue opcode or syscall ABI was added.

The required Linux 6.18.35 oracle and focused candidate cases cover deferred
event delivery, cancellation with an untouched buffer, four invalid SQE
fields, invalid fixed-file slots, registered-file wait and cancellation,
ambient descriptor close/reuse with both completion and cancellation, and
16-iteration readiness/cancellation races. Each focused candidate case ran
three times on ZFS and three times on tmpfs in a disposable amd64 ZFS-root
QEMU VM. The final full result is
`/tmp/linuxulator-gate-20260919/epoll-race-full-gate/results.json`: 355
io_uring cases, 918 shared squeue-option, 39 NO_MMAP and 33 SQPOLL runs;
zero recognized diagnostics and nonzero results, zero final issuer/file/request
counts, healthy ZFS and clean shutdown. Exact image and binary hashes and
source evidence are in
`/tmp/linuxulator-gate-20260919/epoll-race-full-gate/manifest.json`.
The design and case matrix are in
[the EPOLL_WAIT audit](linuxulator-epoll-wait-async.md). No candidate kernel
or module was installed or loaded on the host.

Pending `IORING_OP_WAITID` cancellation and pending futex waits remain
unqualified. The Linux oracles and candidate failure evidence for futex waits
are in [the pending-futex gate](linuxulator-iouring-futex-pending.md); the
WAITID contract is in [the WAITID audit](linuxulator-waitid-lifecycle.md).

## io_uring FUTEX/WAITID reserved-SQE gate (2026-09-20)

Linux 6.18.35 oracles passed the FUTEX_WAIT, FUTEX_WAKE, FUTEX_WAITV and WAITID
reserved-field cases plus the corrected WAITV immediate-EAGAIN case. The
focused candidate amd64 ZFS-root VM passed 42 executions across ZFS and tmpfs.
The 357-case full amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/futex-waitid-sqe-full-gate/results.json`; its
`manifest.json` pins the image, module, test binary, oracle and focused logs.
The gate recorded 918 shared squeue-option cases, 39 NO_MMAP cases, 33 SQPOLL
cases, zero recognized diagnostics or nonzero results, zero final
issuer/file/request counts, healthy ZFS, and clean shutdown. Pending FUTEX_WAIT,
FUTEX_WAITV and WAITID wake/cancellation tests remain opt-in and unqualified;
they are not covered by this pass. No host kernel or module was installed.

## io_uring pending futex gate (2026-09-20)

The subsequent `FUTEX_WAIT` and `FUTEX_WAITV` implementation parks requests
on callback-backed umtx queues and completes them through shared squeue's
external-request lifecycle. Linuxulator retains Linux key, mask and vector
semantics. Linux 6.18.35 oracle cases, focused amd64 ZFS-root ZFS/tmpfs runs,
and the frozen 369-case full gate passed. The full gate recorded 918 shared
squeue-option, 39 NO_MMAP and 33 SQPOLL executions, zero diagnostics/nonzero
results, final request/file counts of zero, healthy ZFS and clean shutdown.
`/tmp/linuxulator-gate-20260919/futex-async-final-gate/manifest.json`
pins hashes and result provenance. The earlier 357-case record above is a
historical snapshot; its futex-pending limitation is superseded by this gate.
Pending `IORING_OP_WAITID` remains a separate gate.


## io_uring pending WAITID gate (2026-09-20)

`IORING_OP_WAITID` no longer blocks the submitter for a living child. The
shared squeue engine owns a process-context pump, pending-request lifetime,
CQE publication, links and cancellation. Linuxulator owns ID/option
translation, pidfd resolution and siginfo conversion. No native WAITID
syscall ABI was added. The Linux 6.18.35 oracles cover pending exit,
cancellation, pidfd close, ring close, opcode-wide cancellation, linked
timeout, null siginfo and child-exit/cancel races, alongside the existing
lifecycle/pidfd/job-state and reserved-field negatives. The focused amd64
ZFS-root VM passed 72 initial ZFS/tmpfs executions, 18 null-siginfo and
regression executions, and 48 race iterations across six runs, all with
healthy ZFS and clean shutdown.

The final full amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/waitid-race-full-gate/results.json`:
377 io_uring, 918 native/Linux squeue-option, 39 NO_MMAP and 33 SQPOLL
executions; zero nonzero results or recognized diagnostics; zero final
request/file/issuer counts; healthy ZFS and clean poweroff. Its
`manifest.json` pins exact image, kernel, module, Linux ELF, source, oracle,
focus and result hashes. The earlier WAITID-pending limitation in the
historical 357-case gate above is superseded. The candidate was never
installed or loaded on the host.

## io_uring SQPOLL ATTACH_WQ shared-poller gate (2026-09-20)

The shared squeue backend now lets same-frontend, same-process SQPOLL rings
share one poller while retaining separate SQ/CQ state and close paths. Invalid
or stale source descriptors, non-SQPOLL sources and native/Linux cross-frontend
attachments fail; a forked process gets its own poller. Linux 7.1.5 oracle
cases and focused ZFS/tmpfs VM runs cover simultaneous work, both close
orders, nested attachment, idle wake, SQ_WAIT, owner exit, failed exec,
worker-limit propagation and pending WAITID cancellation. The full amd64
ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-attach-repaired-full-gate3/results.json`:
1002 shared-option, 395 io_uring, 39 NO_MMAP, 33 dedicated SQPOLL and 24
MEM_REGION executions; zero failed cases, diagnostics and final request/file/
issuer counts; healthy ZFS and clean shutdown. The adjacent `manifest.json`
pins source, oracle, focused logs and candidate artifacts. Group idle-time
updates, concurrent close races and combination tests remain separate gates.

## io_uring SQPOLL shared idle-time gate (2026-09-20)

Shared squeue now recomputes the poller's idle interval as the maximum across
its live SQPOLL rings when a ring attaches or closes. A rejected attachment
leaves the source interval unchanged. The Linux 7.1.5 oracle passed the
negative attach, long-member spin, detach recalculation and source-first
close cases. The focused candidate VM passed 12 native/Linux runs on ZFS and
tmpfs, including NOP completion after each transition. The complete amd64
ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-idle-final-full-gate/results.json`:
1008 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; no failed cases or kernel diagnostics, zero
final request/file/issuer counts, healthy ZFS and clean shutdown. The
adjacent `manifest.json` pins the exact source and candidate artifacts.

## io_uring SQPOLL ATTACH_WQ caller-owned layout gate (2026-09-20)

A shared SQPOLL poller now has a VM-qualified `ATTACH_WQ|NO_MMAP` contract,
including `REGISTERED_FD_ONLY`. The Linux 7.1.5 oracle and focused amd64
ZFS-root candidate VM cover invalid source rejection with separate caller
memory, source-first close, eight NOP completions on each attached layout,
ordinary entry rejection on the registered-only slot, slot removal and stale
entry. The focused candidate matrix passed 12 native/Linux ZFS/tmpfs runs.
The full gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-nommap-attach-full-gate/results.json`:
1014 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; zero failures, diagnostics and final request/
file/issuer counts, healthy ZFS and clean shutdown. The adjacent
`manifest.json` pins source, test, oracle and VM artifact hashes.

## io_uring SQPOLL shared worker-affinity gate (2026-09-20)

`IOWQ_AFF` registration through an attached SQPOLL ring now has a
VM-qualified shared-poller contract. The permanent case checks malformed
registration and unregistration, pins actual native blocked workers to CPU 1,
submits pipe reads through source and attached rings, closes the source,
checks another attached read, and restores affinity. The Linux 7.1.5 oracle
passed its registration and I/O path. The candidate passed 12 focused
native/Linux ZFS/tmpfs runs. The complete amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-affinity-final-full-gate/results.json`:
1020 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; zero failed cases or kernel diagnostics, zero
final request/file/issuer counts, healthy ZFS and clean shutdown. The
adjacent `manifest.json` pins source, binaries, oracle and VM artifacts.

## io_uring SQPOLL shared CQ-overflow gate (2026-09-20)

The shared squeue backend now matches Linux's CQ-overflow accounting:
`IORING_SQ_CQ_OVERFLOW` marks recoverable backlogged completions, and the CQ
`overflow` counter advances only for completions actually dropped. The
permanent `sqpoll_attach_cq_overflow_shared` case fills each member's CQ,
checks the other ring's independent progress, recovers each CQE exactly once,
and closes an attached ring with a pending backlog. The Linux 7.1.5 reference
VM passed this case and the three corrected general overflow cases. The
candidate passed 30 focused native/Linux ZFS/tmpfs executions with zero
tracked resources and healthy ZFS. The complete amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-overflow-full-gate/results.json`:
1026 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; zero failed cases or recognized diagnostics,
zero final request/file/issuer counts, healthy ZFS and clean shutdown. The
adjacent `manifest.json` pins source, artifacts, Linux oracles and focused
logs. Concurrent source/attached close with cancellation remains a separate
gate.

## io_uring SQPOLL blocked-read and concurrent-close gate (2026-09-20)

Shared squeue now offloads potentially blocking SQPOLL file transfers to its
worker pool, so one source-ring pipe READ cannot stop attached-ring progress.
The SQPOLL poller drains worker-ready completions even when no new SQE is
present. The permanent native/Linux cases check a blocked READ with attached
NOP progress and recovery, simultaneous source/attached close with pending
polls and optional cancellation, stale descriptor rejection, and a fresh ring.
The dedicated `fd_context` case verifies CQ publication without another enter.
Linux 7.1.5 passed the attachment reference and 24 focused native/Linux
ZFS/tmpfs executions passed. The first complete candidate VM exposed the
empty-SQ ready-drain bug as three `fd_context` failures; the corrected kernel
passed that case in a focused ZFS-root VM and all three complete-gate rounds.
The final amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-close-repair-full-gate/results.json`:
1038 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; zero failing cases or recognized diagnostics,
zero final request/file/issuer counts, healthy ZFS and clean shutdown. The
adjacent `manifest.json` pins the exact source and candidate artifacts.

## io_uring SQPOLL and IOSQE_ASYNC selected-buffer worker gate (2026-09-20)

Shared squeue now selects a registered provided buffer before offloading
potentially blocking SQPOLL READ/READV or explicit `IOSQE_ASYNC` READ. Worker
completion consumes a successful selection or recycles a failed one before
publishing the CQE. The two permanent native/Linux cases check attached-ring
progress with a blocked selected-buffer read, no-buffer and bad-fd negatives,
exact buffer IDs and data, READV reuse after failure, independent NOP progress
for explicit async, and registered-ring head accounting. Linux 7.1.5 passed
both cases. The corrected candidate passed 24 focused ZFS/tmpfs native/Linux
runs, `fd_context`, zero tracked resources, healthy ZFS and clean shutdown.
An earlier focused candidate trapped on a recursive ring lock, which was fixed
before the full gate. The first full run had zero case failures but failed its
verifier because its expected-case set omitted the new names; the verifier
and strengthened test were corrected before the final run.

The final amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-pbuf-final-full-gate/results.json`:
1050 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; no failures or recognized diagnostics, zero
final request/file/issuer counts, healthy ZFS and clean shutdown. The
adjacent `manifest.json` pins the exact source, binaries, kernel, oracle and
focused-run artifacts.

## io_uring SQPOLL incremental-buffer and cancellation gate (2026-09-20)

Incremental provided-buffer reads through SQPOLL now preserve `BUF_MORE`,
advance the supplied descriptor address and length, and keep the ring head
unchanged until the buffer is consumed. The permanent
`sqpoll_pbuf_incremental_shared` case also checks attached-ring NOP progress
while the read is blocked and rejects a subsequent read with `ENOBUFS`.
`sqpoll_pbuf_cancel_shared` cancels a blocked selected-buffer read by user
data, checks `-ECANCELED` and a zero CQE buffer flag, then verifies that the
same buffer remains available for a later successful read. Linux 7.1.5 passed
both cases. An initial focused candidate exposed stale buffer flags and late
recycling on cancellation; the shared worker path now recycles a failed
selected buffer before CQE publication. The corrected candidate passed 48
focused native/Linux ZFS/tmpfs executions, `fd_context`, zero tracked
resources, healthy ZFS and clean shutdown.

The complete amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-pbuf-lifecycle-full-gate/results.json`:
1062 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; zero failed cases or recognized diagnostics,
zero final request/file/issuer counts, healthy ZFS and clean shutdown. The
adjacent `manifest.json` pins source, test binaries, kernel, Linux oracle,
focused run and VM artifact hashes. Ring-target `POLL_ADD` close/reuse remains
an open lifetime contract, as recorded above.

## io_uring SQPOLL incremental-buffer partial-cancellation gate (2026-09-20)

The permanent `sqpoll_pbuf_incremental_cancel_shared` case combines SQPOLL,
`IOU_PBUF_RING_INC`, and cancellation after a successful partial read. It
checks `BUF_MORE`, descriptor address/length advancement and unchanged head
after two bytes, `-ECANCELED` with no buffer flag for the next blocked read,
unchanged remaining range and head, successful reuse of that range and buffer
ID, head advancement on exhaustion, and subsequent `ENOBUFS`. Both native
squeue and Linux io_uring exercise the same shared path. The pinned Linux
7.1.5 reference passed at
`/tmp/linuxulator-gate-20260919/linux715/oracle-sqpoll-pbuf-inc-cancel.console.log`.
The candidate passed 12 focused native/Linux ZFS/tmpfs runs, `fd_context`,
zero tracked resources and healthy ZFS at
`/tmp/linuxulator-gate-20260919/sqpoll-pbuf-inc-cancel-focus2.console.log`.

The complete amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/sqpoll-pbuf-inc-cancel-full-gate/results.json`:
1068 shared-option, 395 general io_uring, 39 NO_MMAP, 33 dedicated SQPOLL
and 24 MEM_REGION executions; zero failed cases or recognized diagnostics,
zero final request/file/issuer counts, healthy ZFS and clean shutdown. The
adjacent `manifest.json` records hashes of the exact source and VM artifacts.
The previously qualified shared backend needed no change for this option
combination. Ring-target `POLL_ADD` close/reuse remains an open lifetime
contract.

## Ring-target POLL_ADD identity and close gate (2026-09-20)

A `POLL_ADD` on another io_uring/squeue ring must follow the original ring
across descriptor close and reuse, and a queued target completion must remain
observable after the target's last descriptor closes. Holding the target ring
*file* in the request creates a file-reference cycle for self and mutual
polls. Shared squeue instead gives each ring-target poll a private, uninstalled
readiness proxy that holds the target context and attaches to its knlist.
Linuxulator keeps Linux descriptor, cancellation, and CQE conventions; the
proxy and request lifetime are shared with native squeue.

The permanent Linux cases cover cross-ring descriptor reuse, last-close
completion, cancellation by the watched ring's duplicate descriptor versus a
fresh ring that reused its number, `POLL_UPDATE` of user data across target
fd reuse (including a missing-old-key negative), terminal behavior for a
MULTI poll on a ring target after descriptor reuse (including `F_MORE` and
`POLL_REMOVE` negatives), self close/cancel, mutual close, and ordinary file
close/reuse regressions. The shared native/Linux cases cover a target
completion after descriptor reuse and after last close, plus self-target polls
held behind soft and hard links, an `IOSQE_IO_DRAIN` barrier, and an active
asynchronous worker. Linux 7.1.5 passed the named oracles in
`/tmp/linuxulator-gate-20260919/linux715/oracle-poll-ring-last-close.console.log`,
`oracle-poll-ring-fd-cancel.console.log`, `oracle-poll-ring-shared.console.log`,
`oracle-poll-ring-deferred.console.log`,
`oracle-poll-ring-worker-probe.console.log`,
`oracle-poll-ring-update-probe.console.log`, and
`oracle-poll-ring-multishot-probe3.console.log` in the same directory. A
separate live-target oracle (`oracle-poll-ring-multishot-live-probe.console.log`)
confirmed that terminal behavior does not depend on closing the target fd.

The first focused candidate passed armed ring polls but the deferred-close
negative test retained 12 live requests and 12 wired pages. The first close
repair passed the deferred case, but an active worker linked to a self-poll
still retained four requests and four wired pages. The corrected shared close
path cancels unstarted chains and lets a worker resolving after last close
retire its linked successor. The corrected focused VM returned all tracked
resource counters to zero in
`/tmp/linuxulator-gate-20260919/ring-poll-worker-final-focus.console.log`.
The combined three-round native/Linux ZFS/tmpfs gate passed 24 shared and 24
dedicated Linux executions with zero tracked resources, healthy ZFS, and clean
shutdown at
`/tmp/linuxulator-gate-20260919/ring-poll-worker-final-combined.console.log`.
The `POLL_UPDATE` probe passed three focused VM runs with zero tracked
resources at
`/tmp/linuxulator-gate-20260919/ring-poll-update-final-focus.console.log`.
The earlier shared backend incorrectly posted `F_MORE` for a MULTI ring-target
poll; Linux 7.1.5 posted a terminal readiness CQE. Shared squeue now forces a
ring-target poll to single completion, including event updates that request
MULTI. The permanent `poll_ring_multishot_terminal_reuse` case passed three
focused VM runs with zero tracked resources at
`/tmp/linuxulator-gate-20260919/ring-poll-multishot-final-focus.console.log`.
The permanent `poll_ring_update_multi_terminal_reuse` case exercises the same
terminal rule after `POLL_UPDATE_EVENTS|MULTI` and target fd reuse. Linux 7.1.5
passed at `linux715/oracle-poll-ring-update-multi-probe.console.log`; both
permanent MULTI cases passed three focused runs each with zero tracked
resources and clean shutdown at
`/tmp/linuxulator-gate-20260919/ring-poll-update-multi-final-focus.console.log`.
The SQPOLL self-poll last-close case passed Linux 7.1.5 and six native/Linux
ZFS-root VM runs with zero tracked resources, healthy ZFS and clean shutdown
in `linux715/oracle-sqpoll-ring-self-probe.console.log` and
`/tmp/linuxulator-gate-20260919/sqpoll-ring-self-probe.console.log`. It is now
permanent as `poll_ring_sqpoll_self_close_shared`; the matching-module focused
VM passed six more native/Linux runs with zero tracked resources and clean
shutdown at `/tmp/linuxulator-gate-20260919/ring-poll-sqpoll-self-final-focus.console.log`.
The first 401-case full gate reached all 1080 then-current shared-option
executions, but trapped at `accept_parks`: process exit closed a ring with a
pending fast poll after `fdescfree()` had detached `p_fd`, and the fd-keyed
kqueue delete dereferenced that null table. Its preserved failure log is
`/tmp/linuxulator-gate-20260919/ring-poll-update-multi-final-full-gate/amd64.console.log`.
Shared squeue now leaves that fd-keyed note to its private kqueue teardown when
the caller's descriptor table is already gone. The rebuilt kernel passed six
focused `accept_parks` exit runs with zero tracked resources, healthy ZFS and
clean shutdown at
`/tmp/linuxulator-gate-20260919/ring-poll-fdtable-exit-focus2.console.log`.
The complete amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/ring-poll-fdtable-exit-final-full-gate/results.json`:
401 general io_uring cases, 1086 shared-option executions, 39 NO_MMAP,
33 dedicated SQPOLL and 24 MEM_REGION executions; zero failed cases or
recognized diagnostics, zero final request/file/issuer/page counts, healthy
ZFS and clean shutdown. The adjacent `manifest.json` pins the exact kernel,
matching Linux modules, source snapshot, focused and oracle logs and full
result hashes. The later 403-case receive-bundle gate below supersedes this
snapshot for current test-source coverage.

## io_uring registered receive-bundle gate (2026-09-20)

The Linux 7.1.5 reference returned one 10-byte `RECV` bundle CQE from three
4-byte registered provided buffers, with the first buffer ID and a ring head
advance of three. Its oracle log is
`/tmp/linuxulator-gate-20260919/linux715/oracle-recv-bundle-probe.console.log`.
Shared squeue already selects and commits ordered buffer batches; the Linux
socket helper now requests a batch for receive as well as send. The permanent
`pbuf_recv_bundle_multibuf` case checks result, flags, data and head. The
Linux 7.1.5 empty-buffer oracle passed at
`/tmp/linuxulator-gate-20260919/linux715/oracle-recv-bundle-empty-probe.console.log`;
`pbuf_recv_bundle_empty_recover` checks `ENOBUFS`, no premature consumption,
then successful reuse after registering a buffer. Those two cases plus legacy
bundle, length-bound and invalid-input regressions passed three ZFS and three
tmpfs rounds (30 executions) in the disposable amd64 ZFS-root VM at
`/tmp/linuxulator-gate-20260919/recv-bundle-empty-focus.console.log`, with
zero tracked resources, healthy ZFS and clean shutdown. A supplemental
multishot probe found that expanding the receive batch also changed the legacy
provided-buffer one-buffer-per-CQE multishot datagram contract. Linux 7.1.5
passed the original multishot case at
`/tmp/linuxulator-gate-20260919/linux715/oracle-recv-bundle-mshot-probe.console.log`.
At this 403-case snapshot, the Linux socket helper expanded only single-shot
receives; the registered-ring follow-up below supersedes that policy. The rebuilt
Linux64 module passed all seven bundle, multishot, cancellation/reuse and
invalid-input cases in three ZFS and three tmpfs rounds (42 executions), with
zero tracked resources, healthy ZFS and clean shutdown at
`/tmp/linuxulator-gate-20260919/recv-bundle-mshot-fix-focus.console.log`.
The 403-case amd64 ZFS-root full gate passed at
`/tmp/linuxulator-gate-20260919/recv-bundle-mshot-fix-final-full-gate/results.json`:
403 Linux io_uring, 1086 shared-option, 39 NO_MMAP, 33 SQPOLL, 24 MEM_REGION
and 57 AIO executions; zero failures, recognized diagnostics and final
tracked resources, healthy ZFS and clean shutdown. Its `manifest.json` pins
the passed historical source, image, module and result snapshot. The later
404-case gate is required for the current registered-ring behavior.

The registered PBUF_RING multishot oracle revealed a distinct rule: unlike
legacy provided buffers, one multishot `RECV|BUNDLE` CQE may span two ring
entries. With four 4-byte entries and two 6-byte datagrams, Linux 7.1.5
returned two 6-byte CQEs with starting IDs 820 and 822, `F_MORE` only on the
first, and ring head four. The permanent `pbuf_recv_bundle_multishot` case
checks those exact results, payloads, flags and terminal unregister; its
reference is
`/tmp/linuxulator-gate-20260919/linux715/oracle-recv-bundle-pbuf-mshot4.console.log`.
The first Linux-only helper revision used shared batch selection, returned
surplus legacy descriptors for multishot, and ended a multishot bundle when
its buffer group was exhausted. No native squeue ABI changed. The revised Linux64 module
passed eight bundle cases across three ZFS and three tmpfs rounds (48 focused
executions), with zero tracked resources, healthy ZFS and clean shutdown at
`/tmp/linuxulator-gate-20260919/recv-bundle-pbuf-mshot-focus3.console.log`.
The first 404-case gate was superseded during a shared-selector concurrency
review; its interrupted evidence remains at
`/tmp/linuxulator-gate-20260919/recv-bundle-pbuf-mshot-final-full-gate/`.
The 403-case result above is a passed historical snapshot; the current
404-case gate is identified below.

A follow-up concurrency review found that selecting a large legacy batch and
returning surplus descriptors after dropping the group lock could reorder them
against another request. Shared squeue's internal batch selector now accepts a
separate legacy limit and applies it under its existing lock. Linuxulator asks
for one legacy descriptor on multishot receive while permitting a full
registered-ring batch. This changes no native syscall ABI. The matching
rebuilt kernel, `linux_common` and `linux64` modules passed the same 48 focused
ZFS/tmpfs executions, zero resource counters, healthy ZFS and clean shutdown
at `/tmp/linuxulator-gate-20260919/recv-bundle-atomic-focus.console.log`.
The full 404-case gate for this final shared-selector implementation passed:
404 Linux io_uring cases, 1086 shared-option executions, 39 NO_MMAP,
33 SQPOLL, 24 MEM_REGION and 57 AIO executions, with zero nonzero results
or diagnostic failures, zero final tracked resources, healthy ZFS and clean
shutdown. The frozen inputs and results are in
`/tmp/linuxulator-gate-20260919/recv-bundle-atomic-final-full-gate/manifest.json`.
This is a qualified historical snapshot; the immediate-timeout change below
requires its own full gate.


### io_uring immediate timeout argument (QEMU qualified)

The Linux 7.1.5 reference accepts `IORING_TIMEOUT_IMMEDIATE_ARG` (bit 7) on
ordinary, linked and update timeouts. The SQE carries a signed-positive
nanosecond value in `addr` (or `addr2` for an update), instead of a userspace
`__kernel_timespec` pointer. Shared squeue decodes that representation before
its existing timer paths; Linuxulator retains Linux ABI layout and errno
translation. The shared decoder rejects values above `INT64_MAX` with
`EINVAL`, and the ordinary pointer form still faults on an invalid address.

This option's acceptance matrix is:

| Case | Positive behavior | Negative/edge behavior |
|---|---|---|
| `timeout_immediate_basic` | Relative 20 ms, absolute expired, absolute monotonic future deadline | Pointer form still returns `EFAULT` for address 1 |
| `timeout_immediate_invalid` | A live timer survives invalid update and can be removed | Sign bit, illegal flag combinations, immediate flag without UPDATE |
| `timeout_immediate_update` | Update a 30-second timer to 10 ms and retain original completion key | Original timer must not expire early |
| `timeout_immediate_link_multishot` | Linked poll is canceled by 20 ms timeout; three multishot expirations have two `MORE` CQEs | Completion ordering and terminal flag |
| `timeout_immediate_shared` | Native and Linux ABIs exercise relative, update, linked and multishot paths | Overflow update preserves live timer; sign-bit argument rejected |

All five cases passed against the disposable Linux 7.1.5 oracle at
`/tmp/linuxulator-gate-20260919/linux715/oracle-timeout-immediate-probe.console.log`.
The matching rebuilt kernel and modules passed 36 focused executions across
three ZFS and three tmpfs rounds, with zero failures, zero final tracked squeue
resources, healthy ZFS and clean shutdown at
`/tmp/linuxulator-gate-20260919/timeout-immediate-focus.console.log`.
The full amd64 ZFS-root gate passed: 408 Linux io_uring cases, 1092
shared-option executions, 39 NO_MMAP, 33 SQPOLL, 24 MEM_REGION and 57 AIO
executions, with zero nonzero results or diagnostic failures, zero final
tracked resources, healthy ZFS and clean shutdown. Frozen input, result and
console hashes are in
`/tmp/linuxulator-gate-20260919/timeout-immediate-final-full-gate/manifest.json`.
Concurrent `unshare` work changed the live gate scripts after this VM started;
the manifest identifies the pre-change driver and staged guest-script hashes
used for this result.

## unshare path-state subset (2026-09-20; named ABI cases VM-tested)

The amd64 Linux64 handler accepts zero and single-threaded `CLONE_FS` using
native `pdunshare()`. It rejects all other flags and multithreaded detachment
before changing state. Other ABIs retain ENOSYS. See
[the per-contract matrix](linuxulator-unshare.md); namespace and file-table
ownership remain separate, unresolved work.

The freestanding Linux 6.18.35 oracle passes 13 cases, including desired
future file-table and thread-local contracts. The focused amd64 BSD ZFS-root
VM passes 60 executions of ten supported/rejection cases across ZFS and
tmpfs, with healthy ZFS, no recognized diagnostics and clean shutdown.
Three separate native-tracer cases confirm that capability mode denies the
syscall with Linux EPERM. Both Linuxulator modules build against the guest
kernel's option headers. The complete amd64 ZFS-root gate passed in
`/tmp/linuxulator-unshare-20260920/full4-run/results.json`: 60 unshare
executions, 3 capability-mode checks, 1092 native/Linux ring-option executions
and 408 main io_uring cases, plus the existing syscall and lifecycle matrices.
There were zero recognized kernel diagnostics, zero leaked tracked ring
pages/files/requests/issuer resources, healthy ZFS and clean shutdown.
`manifest.json` in that directory's parent records the source commit, patch,
compiler/build commands, source and artifact SHA256 hashes, oracle version
and exact result hashes. The guest's kernel/module/probe hashes match it.
A Linux32 compile-only check of the fallback also passed; no new Linux32
runtime support is claimed.

This qualifies the named ABI cases, not complete unshare or container support.
External-application qualification, allocation-failure injection and broader
SMP stress remain listed in the contract. No namespace, CLONE_FILES or
thread-local path-state implementation is included.

The full-gate result applies to the recorded source snapshot. During the run,
the separate io_uring workstream changed `sys/compat/linux/linux_io_uring.c`
and `tests/sys/kern/linux_iouring.c`; those later edits are not qualified by
this result. The unshare implementation and probes remained unchanged, and
the earlier io_uring inputs are preserved in `source-snapshot/`.


### Zero-copy send and CQE_SKIP_SUCCESS (qualified 2026-09-20)

Linux 7.1.5 rejects `IOSQE_CQE_SKIP_SUCCESS` on both
`IORING_OP_SEND_ZC` and `IORING_OP_SENDMSG_ZC` with `-EINVAL`: these
operations require a primary completion and a notification completion.
The Linuxulator now rejects the combination during SQE preparation, before
sending data. This validation is Linuxulator-only; shared squeue's generic
completion-suppression behavior remains correct for other opcodes.

`send_zc_skip` and `sendmsg_zc_skip` each require one error CQE, no
notification CQE, no bytes readable from the peer socket, and a subsequent
successful NOP on the same ring. The Linux 7.1.5 oracle passed both at
`/tmp/linuxulator-gate-20260919/linux715/oracle-zc-skip-contract.console.log`.
The rebuilt `linux64` module passed these and six existing SEND_ZC
positive/negative regressions in three ZFS and three tmpfs rounds (48
executions), with zero tracked resource leaks, healthy ZFS and clean shutdown
at `/tmp/linuxulator-gate-20260919/zc-skip-focus.console.log`.

The full amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/zc-skip-final-full-gate/manifest.json`: 410
general io_uring cases, 1,092 shared-option executions, 39 NO_MMAP, 33
SQPOLL, 24 MEM_REGION and 57 legacy AIO executions all returned zero. It
reported no diagnostic failures or nonzero results, zero final
issuer/file/request/page resources, healthy ZFS, synced buffers and clean
ACPI shutdown. The frozen runner predates concurrent `unshare` script changes;
the candidate module includes the `unshare` implementation, while that
syscall's separate named matrix is qualified by its own full gate.


### unshare concurrent path-state mutation follow-up

The test-only expansion in [the unshare contract](linuxulator-unshare.md)
passes 15 Linux 6.18.35 reference cases. The focused two-vCPU amd64 ZFS-root
BSD guest passes 66 ZFS/tmpfs executions plus three capability-mode checks,
including 384 detachments concurrent with shared cwd/umask mutation. ZFS is
healthy, shutdown is clean and no recognized kernel diagnostics occur.
`/tmp/linuxulator-unshare-expansion-20260920/manifest.json` records inputs;
`results.json` records the exact named matrix. This reuses the kernel/modules
from the earlier full4 snapshot; no kernel code changed and no new full-gate
claim is made. Future full runs require eleven supported/rejection cases.
The added Linux record-lock PID/close-ownership case remains pending on BSD;
CLONE_FILES is still rejected.

### io_uring copied NODEV zero-copy receive (qualified 2026-09-21)

`IORING_OP_RECV_ZC` and `IORING_REGISTER_ZCRX_IFQ` now implement Linux v7.1
`ZCRX_REG_NODEV`: TCP receive copies into pinned registered chunks, publishes
CQE32/CQE_MIXED offsets, consumes validated refill entries, supports bounded
and multishot operation, fixed files, cancellation and teardown, and advertises
the opcode through PROBE. Linux ABI structures, flag and errno translation
remain in Linuxulator; shared squeue owns receive-area lifetime, refill queues,
chunk reuse and request completion. Hardware NIC queue binding, DMA-BUF,
import/export and cross-ring sharing remain rejected.

The Linux 7.1.5 oracle passed 22 named cases. The matching amd64 WITNESS
ZFS-root candidate passed those cases for three rounds (66 executions), then
passed the complete gate: 430 main io_uring, 1,092 shared-option, 39 NO_MMAP,
33 SQPOLL, 24 memory-region, 21 query, three native-squeue and 57 legacy-AIO
executions. There were no diagnostic failures or nonzero results. Final
page/file/request/issuer counters were zero, ZFS was healthy, buffers synced,
and ACPI shutdown was clean. The frozen evidence and SHA256 inventory are in
`/tmp/linuxulator-gate-20260919/zcrx-final-full-gate3/manifest.json`. No arm64
run was required after the user waived it for architecture-neutral work.


### amd64 quota control subset (VM-qualified named contract)

`quotactl_fd` now supports ZFS user/group quota queries, byte hard-limit
updates and accounting sync. `quotactl` supports global quota sync; legacy
block-device-selected updates remain unsupported. The Linux64 ABI uses a
small native kernel-buffer VFS interface. Native ZFS quota calls now share
its privilege checks, and quota sync waits for transaction-group accounting.
No Linux32 functionality is added. See [the contract](linuxulator-quota.md).

The Linux 6.18.35 ext4 oracle passes ten named cases. The final focused amd64
ZFS-root guest passes 33 Linux quota executions, six capability checks, three
native interoperability/permission groups and five filesystem checks (47 in
all), with healthy ZFS, no recognized kernel diagnostics and clean shutdown.
Evidence is `/tmp/linuxulator-quota-20260921/focused-results.json` and
`focus9.console.log`; the source/build/artifact manifest is in that directory.
The full amd64 ZFS-root gate passed with 47 quota checks, 1,092
native/Linux shared-ring option executions and 432 main io_uring cases, plus
the existing syscall and lifecycle matrices. The runner reported no recognized
kernel diagnostics or leaked tracked ring resources, healthy ZFS and clean
shutdown. Evidence is under `full4-run/` in the same artifact directory. The
earlier full
runs were superseded by native permission and read-only-pool sync corrections
and are not acceptance evidence.

### io_uring read/write attribute validation (qualified 2026-09-21)

All eight read/write opcodes now reject nonzero attribute masks explicitly.
A zero mask preserves Linux's ignored-pointer rule, unknown masks return
`EINVAL`, and the known protection-information mask returns `EOPNOTSUPP` while
`IORING_FEAT_RW_ATTR` remains clear. The Linux ABI policy stays in the
Linuxulator; shared squeue remains unchanged until a native storage-metadata
transport exists.

The Linux 7.1.5 QEMU oracle passed `rw_attr` and
`rw_attr_opcode_matrix`. The focused amd64 ZFS-root guest passed both for
three rounds with all tracked resources returning to zero, healthy ZFS and
clean poweroff. The integrated full gate then passed 432 main io_uring cases,
1,092 shared-option executions, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21
query, 57 Linux AIO and the complete quota/syscall regression matrices. Every
parsed result was zero, no recognized diagnostic was present, final tracked
resources were zero, ZFS was healthy, buffers synced and QEMU powered off
cleanly. Results and exact hashes are in
`/tmp/linuxulator-quota-20260921/full4-run/results.json` and
`full4-run/manifest.json` (manifest SHA-256
`f92e1e9a47dc9b895ce391ec2bcc9980a444655ea17626532967723a0d349b8e`).
No candidate kernel or module was installed or loaded on the host. Arm64 was
not repeated for this architecture-neutral Linux64 frontend change under the
current gate policy.

### io_uring read/write ioprio and write-stream validation (qualified 2026-09-21)

All eight read/write opcodes now apply Linux 7.1's block-I/O priority
validation during SQE preparation. Class NONE requires a zero low three-bit
level, BE and IDLE are accepted, realtime requires scheduling privilege, and
the remaining classes return EINVAL. Linux hint bits and the write_stream
byte remain valid advisory inputs. This class numbering and privilege policy
is Linuxulator-only; shared squeue accepts the common SQE fields but has no
native per-request block-priority or write-stream allocation backend.

The permanent matrix consists of rw_ioprio, which performs real BE, IDLE,
hinted, write-stream and privileged realtime writes;
rw_ioprio_opcode_matrix, which checks three malformed priorities across
READV, WRITEV, READ_FIXED, WRITE_FIXED, READ, WRITE, READV_FIXED and
WRITEV_FIXED; and rw_ioprio_privilege, which drops to uid 65534 and requires
EPERM for realtime priority. Linux 7.1.5 passed all three in the disposable
QEMU oracle recorded at /tmp/ioprio-oracle.console.log.

The matching Linux64 module passed all three cases for three rounds in the
focused amd64 ZFS-root guest. The integrated amd64 WITNESS/INVARIANTS
ZFS-root gate then passed 435 main io_uring cases, 1,092 shared-option
executions, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, 57 Linux AIO,
six native AIO, three native-squeue and all quota/syscall regression checks.
There were no nonzero parsed results or recognized diagnostics. Final
issuer, file, request and pinned-page counts were zero; ZFS was healthy,
buffers synced, and QEMU powered off cleanly. Results and exact source,
kernel, module, binary, oracle and console hashes are in
/tmp/linuxulator-quota-20260921/full5-run/manifest.json (SHA-256
2ce6135c8bd1097b573333ee7ce5fa0d585b70c6239891607fc51a726042ad3c).
No candidate kernel or module was installed or loaded on the host. Arm64 was
not repeated because the change is architecture-neutral Linux64 frontend
policy and the current project policy waives non-architecture-specific runs.

### Shared io_uring timeout reserved fields (qualified 2026-09-21)

Shared squeue now matches Linux 7.1 preparation rules for the timer family.
`TIMEOUT`, `TIMEOUT_REMOVE`/`TIMEOUT_UPDATE`, and `LINK_TIMEOUT` reject
nonzero `addr3` and the final SQE padding word before resolving a timeout or
executing an earlier linked request. This belongs in shared squeue because the
native and Linux frontends use the same SQE layout and timer engine.

The Linux `timeout_reserved_fields` case and dual-ABI
`timeout_reserved_shared` case cover eight malformed forms, update bad-pointer
precedence, predecessor cancellation, absence of unintended timer effects,
and ring health after each rejection. Both passed Linux 7.1.5. The focused
amd64 ZFS-root guest passed three Linux main, three Linux shared, and three
native shared repetitions. The integrated gate passed 436 main io_uring and
1,098 shared-option executions, plus the specialized and syscall matrices,
with no nonzero result or recognized diagnostic. Final issuer, file, request,
and page counts were zero; ZFS was healthy, buffers synced, and shutdown was
clean. Exact hashes are in
`/tmp/linuxulator-quota-20260921/full6-run/manifest.json` (SHA-256
`d7590648ad069d59e8180e09431594da3ba3147d89adedbfa40d41dda5dfedea`).
No candidate artifact was installed or loaded on the host. Arm64 was not
repeated under the architecture-neutral waiver.

### Zero-copy send notification user data (qualified 2026-09-21)

Linux 7.1 permits `SEND_ZC` and `SENDMSG_ZC` to place distinct notification
CQE user data in `sqe->addr3`; zero falls back to the primary SQE user data.
Only the final SQE padding word is reserved. Shared squeue owns the common
field-validation mask. The Linuxulator owns notification construction and now
uses `addr3` for the notification CQE while preserving primary CQE identity.

The permanent `send_zc_addr3` and `sendmsg_zc_addr3` cases use loopback TCP,
check primary result and `F_MORE`, distinct notification identity, notification
result (including report-usage), and exact received bytes. Existing tests pin
the zero fallback. `send_zc_reserved` covers both opcodes, requires `EINVAL`
before a socket side effect, forbids an extra notification, and verifies the
ring remains usable. All three passed Linux 7.1.5. The focused amd64 ZFS-root
guest passed these and six neighboring regressions for three rounds (27
executions), with zero tracked resources, healthy ZFS, synced buffers, and
clean poweroff. A stale shared preparation matrix was then corrected to stop
treating `addr3` as reserved; both native and Linux shared cases passed three
focused repetitions.

The repeated integrated amd64 ZFS-root gate passed 439 main io_uring, 1,098
shared-option, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, three native
squeue, 57 Linux AIO and six native AIO executions plus the syscall matrices.
There were no nonzero parsed results or recognized diagnostics. Final tracked
resources were zero, ZFS was healthy, buffers synced, and ACPI poweroff was
clean. Frozen evidence is in
`/tmp/linuxulator-quota-20260921/full8-run/manifest.json`. No candidate kernel
or module was installed or loaded on the host, and arm64 was not repeated under
the architecture-neutral waiver.

### Zero-copy send error notification pairing (qualified 2026-09-21)

Linux 7.1 adds `MSG_NOSIGNAL` internally to both zero-copy send opcodes and
retains the primary/notification CQE pair after a send fails during execution.
The Linuxulator copied fallback now does the same: a prepared `SEND_ZC` or
`SENDMSG_ZC` posts its negative primary result with `F_MORE`, then posts the
notification CQE using the `addr3` identity rule. Preparation failures still
produce only their preparation-error CQE.

`send_zc_error_notification` creates loopback TCP pairs, shuts down each sender,
and requires `EPIPE` without process `SIGPIPE` for both opcodes. It checks the
primary and notification identities and flags, the notification result, and a
subsequent NOP on the same ring. The case passed Linux 7.1.5. It and nine
neighboring zero-copy regressions passed three focused amd64 ZFS-root rounds
(30 executions), with zero tracked resources, healthy ZFS, synced buffers and
clean poweroff. The repeated integrated amd64 ZFS-root gate then passed all 440
main io_uring, 1,098 shared-option, 39 NO_MMAP, 33 SQPOLL, 24 memory-region,
21 query, three native squeue, 57 Linux AIO and six native AIO executions plus
the syscall matrices. It reported no nonzero results or recognized diagnostics;
all final tracked resources were zero, ZFS was healthy, buffers synced, and
ACPI poweroff was clean. Frozen evidence is in
`/tmp/linuxulator-quota-20260921/full9-run/manifest.json`. No candidate kernel
or module was installed or loaded on the host, and arm64 was not repeated under
the architecture-neutral waiver.


### Zero-copy failed-send usage notification (qualified 2026-09-21)

Linux 7.1.5 reports `IORING_NOTIF_USAGE_ZC_COPIED` when `REPORT_USAGE` is
requested even if a prepared `SEND_ZC` or `SENDMSG_ZC` later fails with
`EPIPE`. The Linuxulator already has that completion policy;
`send_zc_error_report_usage` now pins it together with `MSG_NOSIGNAL`, the
negative primary CQE, `F_MORE`, the notification CQE, and distinct `addr3`
identity for both opcodes. This is Linux frontend behavior and requires no
shared squeue change.

The case passed the Linux 7.1.5 oracle. It and 16 adjacent zero-copy option
cases passed three focused amd64 ZFS-root rounds (51 executions), with zero
tracked resources, healthy ZFS, synced buffers and clean poweroff. The
repeated integrated amd64 ZFS-root gate passed all 441 main io_uring, 1,098
shared-option, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, three native
squeue, 57 Linux AIO and six native AIO executions plus the syscall matrices.
It had no nonzero results or diagnostics, all final resources were zero, ZFS
was healthy, buffers synced, and poweroff was clean. Frozen evidence is in
`/tmp/linuxulator-quota-20260921/full10-run/manifest.json`.

### amd64 ptrace register access (VM-qualified named contracts)

[The register contract](linuxulator-ptrace-registers.md) covers legacy and
regset FP reads/writes, GPR regset writes, and XSAVE reads. A kernel-only
callback keeps native authorization and the target hold across the operation.
Twenty-one Linux-reference cases, 69 focused amd64 BSD checks, and separate
Linux/BSD no-XSAVE cases passed. GDB 16.3 starts but its target-run test
stalls during the separate EXITKILL capability probe; no complete debugger
claim is made. Evidence is under `/tmp/linuxulator-ptrace-20260921/`;
`full2-run/results.json` records the passing full amd64 ZFS-root gate.

The full amd64 ZFS-root regression gate passed with 69 ptrace checks, 1098 native/Linux shared-ring option executions and 441 main io_uring cases, plus the existing syscall and lifecycle matrices. It reported no recognized kernel diagnostics, zero final tracked ring resources, healthy ZFS and clean shutdown.


### Vectorized fixed-buffer zero-copy sends (qualified 2026-09-21)

Linux 7.1.5 treats `FIXED_BUF|VECTORIZED` on `SEND_ZC` as an iovec array whose
elements must lie inside the selected registered buffer. Fixed-buffer import
errors after zero-copy preparation retain the primary/notification CQE pair,
including `F_MORE`, `addr3`, and `REPORT_USAGE`; fixed `SENDMSG_ZC` metadata
faults follow the same rule. The Linux frontend now interprets those options
and preserves the pair. Shared `sq_prepare_fixed_buffer()` now honors its
vector argument for both zero-copy send opcodes.

Three positive/negative cases passed Linux 7.1.5. They and 14 neighboring
zero-copy cases passed three focused amd64 ZFS-root rounds (51 executions),
with zero tracked resources, healthy ZFS, synced buffers and clean poweroff.
The repeated integrated amd64 ZFS-root gate passed all 443 main io_uring,
1,098 shared-option, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, three
native squeue, 57 Linux AIO, six native AIO, 63 Linux ptrace, three native
ptrace and three ptrace-capmode executions plus the syscall matrices. It had
no nonzero results or diagnostics, all final resources were zero, ZFS was
healthy, buffers synced, and poweroff was clean. Frozen evidence is in
`/tmp/linuxulator-quota-20260921/full11b-run/manifest.json`. The first full11
image was discarded before io_uring because its staged root omitted the newly
required ptrace payloads.


### Fixed SENDMSG_ZC iovec limits (qualified 2026-09-21)

Linux 7.1.5 returns `EMSGSIZE`, not `EINVAL`, when a fixed `SENDMSG_ZC` header
exceeds `UIO_MAXIOV`, while retaining the primary/notification pair, `F_MORE`,
`addr3`, and `REPORT_USAGE`. The Linux frontend now translates that exact
errno. The fixed SEND_ZC and SENDMSG_ZC positives now use loopback TCP, and
the SENDMSG case also pins Linux's accepted `SEND_VECTORIZED` option. The new
negative case passed Linux 7.1.5 and a 54-execution focused matrix; the two
updated positives passed Linux and six focused FreeBSD executions. The
repeated integrated amd64 ZFS-root gate passed all 444 main io_uring, 1,098
shared-option, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, three native
squeue, 57 Linux AIO, six native AIO, 63 Linux ptrace, three native ptrace and
three ptrace-capmode executions plus the syscall matrices. It had no nonzero
results or diagnostics, all final resources were zero, ZFS was healthy,
buffers synced, and poweroff was clean. Frozen evidence is in
`/tmp/linuxulator-quota-20260921/full12-run/manifest.json`.


### Fixed zero-vector zero-copy sends (qualified 2026-09-22)

With a valid registered-buffer table, Linux 7.1.5 completes zero-vector fixed
`SEND_ZC|VECTORIZED` and fixed `SENDMSG_ZC` successfully and retains the
primary/notification CQE pair. Missing or invalid tables still fail before that
zero-length success. The Linux frontend now handles the valid empty vector after
shared registered-buffer validation. One two-opcode case checks result zero,
`F_MORE`, distinct `addr3`, `REPORT_USAGE`, and no payload. It passed Linux
7.1.5 and 27 focused amd64 ZFS-root executions with zero resources and clean
shutdown. The repeated integrated amd64 ZFS-root gate passed all 445 main io_uring,
1,098 shared-option, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, three
native squeue, 57 Linux AIO, six native AIO, 63 Linux ptrace, three native
ptrace and three ptrace-capmode executions plus the syscall matrices. It had
no nonzero results or diagnostics, all final resources were zero, ZFS was
healthy, buffers synced, and poweroff was clean. Frozen evidence is in
`/tmp/linuxulator-quota-20260921/full13-run/manifest.json`.


### SENDMSG_ZC reserved destination/output fields (qualified 2026-09-22)

Linux 7.1.5 reserves `sqe->addr2` and `sqe->file_index` for `SENDMSG_ZC`, even
though `SEND_ZC` uses the corresponding destination fields. The Linuxulator
previously ignored both fields and could issue the send. Linux-specific
preparation now rejects either field with `EINVAL` before message import or a
socket side effect. Shared squeue was not changed because this distinction is
part of the Linux opcode ABI, not backend request lifetime or I/O execution.

The new `sendmsg_zc_reserved_fields` case independently sets each field and
requires one unflagged primary `EINVAL` CQE, no notification CQE, no received
payload, and a usable ring afterward. Linux 7.1.5 passed the two-field oracle.
The unmodified full13 Linuxulator module reproduced the defect; the corrected
module passed three focused amd64 ZFS-root repetitions with healthy ZFS,
synced buffers, and clean shutdown.

The repeated integrated amd64 ZFS-root gate passed all 446 main io_uring,
1,098 shared-option, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, three
native squeue, 57 Linux AIO, six native AIO, 63 Linux ptrace, three native
ptrace and three ptrace-capmode executions plus the syscall matrices. It had
no nonzero results or diagnostics, all final resources were zero, ZFS was
healthy, buffers synced, and poweroff was clean. Frozen evidence is in
`/tmp/linuxulator-quota-20260921/full14b-run/manifest.json`. The first full14
attempt used 1 GiB and reached the runner timeout during SQPOLL without a test
failure; the unchanged image passed with the established 2 GiB allocation.


### SEND_ZC address-length padding (qualified 2026-09-22)

Linux 7.1.5 reserves the upper 16-bit padding word adjacent to `addr_len` for
`SEND_ZC`. The Linuxulator previously consumed the lower address length and
silently ignored a nonzero upper word. Linux-specific preparation now rejects
that word with `EINVAL`; shared squeue remains unchanged because the rule is a
Linux SQE layout contract.

The new `send_zc_addrlen_padding` case requires one unflagged primary `EINVAL`
CQE, no notification CQE, no socket payload, and a usable ring afterward. It
passed Linux 7.1.5. The full14 module reproduced the defect, and the corrected
module passed three focused amd64 ZFS-root repetitions with healthy ZFS,
synced buffers, and clean shutdown.

The repeated integrated amd64 ZFS-root gate passed all 447 main io_uring,
1,098 shared-option, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, three
native squeue, 57 Linux AIO, six native AIO, 63 Linux ptrace, three native
ptrace and three ptrace-capmode executions plus the syscall matrices. It had
no nonzero results or diagnostics, all final resources were zero, ZFS was
healthy, buffers synced, and poweroff was clean. Frozen evidence is in
`/tmp/linuxulator-quota-20260921/full15-run/manifest.json`.


### Linux64 debugger options (qualified 2026-09-22)

The [debugger follow-up](linuxulator-ptrace-debugger-options.md) fixes the
GDB stopped-tracee SIGKILL hang, USER writes and selector reporting, and
adds hardware watchpoints, ARCH_PRCTL, rseq configuration, IOPERM regset
reads, signal-mask access and process-leader task views. Linux 6.18.35
comparison suites and GDB 16.3 target execution/register editing pass.

The full amd64 ZFS-root gate passed all 90 ptrace checks, 449 main io_uring
cases and 1,098 shared-option checks, plus the existing syscall matrices.
No diagnostics or nonzero results occurred; final tracked resources were
zero, ZFS was healthy, buffers synced and poweroff was clean. Frozen source,
binaries, images, results and hashes are recorded in
`/tmp/linuxulator-options-20260922/manifest.json`. This adds no syscall
numbers or Linux32 support. Nonleader task views, broader ptrace events,
XSAVE writes and GDB's ret-to-NX SIGBUS warning remain outside this batch.


### Linux64 SO_COOKIE (qualified 2026-09-22)

The [socket-cookie batch](linuxulator-socket-cookie.md) adds stable 64-bit
socket identities to amd64 Linux getsockopt. Linux 6.18.35 reference cases,
three focused BSD rounds, native descriptor-right/capability-mode fixtures
and a Python 3.14.7 socket client pass. GDB 16.3 still runs its target and
edits registers successfully with the combined module.

The combined full amd64 ZFS-root gate passed all 24 cookie records, 90 ptrace
checks, 449 main io_uring cases and 1,098 shared-option checks, plus the
remaining syscall suites. No diagnostics or nonzero results occurred; final
tracked resources were zero, ZFS was healthy, buffers synced and poweroff was
clean. Frozen evidence is in
`/tmp/linuxulator-cookie-20260922/manifest.json`. No new native socket storage,
syscall number, Linux32 support or io_uring implementation is added.

### Ordinary SEND/SENDMSG reserved fields (qualified 2026-09-22)

Linux 7.1.5 rejects the nonzero upper 16-bit padding word beside `addr_len`
for ordinary `SEND`, and rejects nonzero `addr2` or `file_index` for ordinary
`SENDMSG`. The Linuxulator previously ignored those fields. Linux-specific
preparation now returns `EINVAL` before message import or socket execution.
Shared squeue remains unchanged because these are Linux SQE layout rules.

The two new cases exercise all three fields independently and require an exact
unflagged `EINVAL` completion, no socket side effect, and a usable ring after
each rejection. Both cases passed Linux 7.1.5, and the corrected module passed
six focused amd64 ZFS-root executions. The integrated amd64 gate passed all
449 main io_uring, 1,098 shared-option, 39 NO_MMAP, 33 SQPOLL, 24 memory-region,
21 query, three native squeue, 57 Linux AIO, six native AIO, 63 Linux ptrace,
three native ptrace and three ptrace-capmode executions plus the remaining
syscall matrices. It reported no nonzero test results or diagnostics; final
issuers, files, requests and pages were zero, ZFS was healthy, buffers synced,
and poweroff was clean. Frozen evidence is in
`/tmp/linuxulator-quota-20260921/full16e-run/manifest.json`.

The module was rebuilt against the candidate kernel build directory so its
RACCT options matched the kernel. Earlier full16 attempts used a standalone
module build whose generated options omitted RACCT; that build-context mismatch
caused the `linux_unshare` accounting assertion and is excluded. A completed
clean VM run was also rerun because its verifier snapshot had concurrently
picked up an unstaged ptrace expectation. The final run pins the last internally
consistent verifier and the 449-case inventory.

### RECV/RECVMSG reserved addr2 (qualified 2026-09-22)

Linux 7.1.5 rejects nonzero `addr2` for both ordinary receive opcodes before
importing the user buffer. The Linux frontend now enforces that preparation
rule; shared squeue remains unchanged. The new two-opcode negative case proves
exact unflagged `EINVAL` precedence over an invalid buffer, no socket-data
consumption, and ring reuse. It passed the Linux oracle and six focused amd64
ZFS/tmpfs executions. The integrated ZFS-root gate passed 450 main io_uring and
1,098 shared-option executions plus every specialized suite, with zero nonzero
results, diagnostics, or final resources, healthy ZFS, synced buffers, and
clean poweroff. Evidence is in
`/tmp/linuxulator-quota-20260921/full17-run/manifest.json`.

### Direct network/open allocation and SEND_ZC test stabilization (qualified 2026-09-22)

The Linux io_uring frontend now accepts `IORING_FILE_INDEX_ALLOC` for
multishot direct `ACCEPT`, rejects explicit fixed-file slots for that form, and
rejects `SOCK_CLOEXEC` for direct `SOCKET` and direct `ACCEPT`. Direct `OPENAT`
and `OPENAT2` likewise reject `O_CLOEXEC`; pathname and `open_how` import still
happen first so Linux fault and `E2BIG` precedence is preserved. These are
Linux SQE and direct-file-table contracts, so shared squeue was unchanged.

The focused network matrix ran `accept_direct_multishot` and
`socket_direct_cloexec` 12 times across ZFS and tmpfs. It checks automatic slot
allocation, two `F_MORE` completions, installed-file I/O, cancellation and its
terminal CQE, explicit-slot rejection without accepting a connection,
CLOEXEC rejection without consuming a connection, rollback, and valid slot
reuse. The direct-open case ran six times across ZFS and tmpfs and checks bad
path/how precedence, nonzero `open_how` extension handling, no file creation on
rejection, and reuse by valid direct opens and fixed-file writes. Linux 7.1.5
reference cases passed for all three contracts.

A separate full gate exposed an intermittent failure in
`ioprio_send_zc_fixed_vectorized`. Instrumented 100-run comparisons reproduced
11 failures on both the candidate and the earlier passing baseline. Every
failure had the correct primary and notification CQEs followed by an immediate
nonblocking peer `read` returning `EAGAIN`; no implementation delta caused it.
The test now retains exact CQE checks, waits up to one second for peer read
readiness, and reports missing CQEs, readiness, read length, and data mismatch
separately. The exact final binary passed 200 focused executions split between
ZFS and tmpfs with all tracked squeue resources returning to zero, healthy ZFS,
and clean shutdown.

The integrated amd64 ZFS-root WITNESS/INVARIANTS gate passed all 453 main
io_uring, 1,098 shared-option, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query,
three native squeue, 57 Linux AIO, six native AIO, 63 Linux ptrace, three native
ptrace and three ptrace-capmode executions plus the remaining syscall matrices.
It reported no nonzero results or diagnostics; final issuers, files, requests
and pages were zero, ZFS was healthy, buffers synced, and poweroff was clean.
Frozen evidence is in `/tmp/linuxulator-quota-20260921/full19b-run/manifest.json`.

## 2026-09-22: fixed-file `IORING_OP_CLOSE`

The shared squeue engine now implements Linux's direct-close form of
`IORING_OP_CLOSE`.  A nonzero `file_index` is a one-based registered-file slot:
a missing table returns `ENXIO`, an out-of-range index returns `EINVAL`, and an
empty slot returns `EBADF`.  Direct close requires `fd == 0`, rejects
`IOSQE_FIXED_FILE`, and retains the existing reserved-field validation.  Slot
removal is serialized by the registered-file lock.  The detached generation is
released through the existing node lifetime path, so its tag completes
immediately when unused or after the last in-flight request releases it.  The
slot can be reused while the old generation remains pinned.

This behavior belongs to `sys/kern/sys_squeue.c`: table synchronization, node
references, tags, and both native and Linux ring entry paths are shared
infrastructure.  No host kernel or module was installed or loaded.

`close_direct_shared` runs through both ABIs and covers no table, sparse and
out-of-range slots, nonzero `fd`, `IOSQE_FIXED_FILE`, all five reserved union
fields, side-effect-free rejection, same-batch double close, ordinary descriptor
close, immediate and delayed tags, pending fixed-read lifetime, immediate slot
reuse, unregister, and ring health.  The Linux-only `close_direct` case checks
the corresponding Linux errno and preparation contract.

Validation completed as follows:

- Both test binaries and the Linux main matrix compiled with `-Wall -Wextra
  -Werror`; `sys_squeue.c` compiled in the WITNESS/INVARIANTS GENERIC kernel
  with kernel `-Werror`.
- Linux 6.18.35-0-virt passed the exact Linux `close_direct` case 25/25.
- The first focused candidate run passed 150 executions: native shared, Linux
  shared, and Linux main tests, each 25 times on ZFS and 25 times on tmpfs.
  After adding an explicit immediate-tag assertion, the final focused binary
  passed another 60 executions, ten of each test on both filesystems.  Both
  runs ended with requests, wired pages, registered files, issuer references,
  and issuer tokens at zero, healthy ZFS, and a clean shutdown.
- The integrated amd64 ZFS-root VM completed 454 Linux io_uring cases, 1,104
  shared-option executions, three native squeue runs, 39 NOMMAP, 33 SQPOLL, 24
  memory-region, 21 query, 57 Linux AIO, 63 Linux ptrace, three native ptrace,
  and three ptrace-capmode executions.  It emitted no nonzero result or kernel
  diagnostic, returned all tracked resources to zero, reported healthy ZFS,
  synced all buffers, and powered off with QEMU status zero.

The first integrated image attempt used an older staging tree and stopped before
the ring matrix because three newer guest helper scripts were absent; it is not
qualification evidence.  The completed VM initially received a false host
verifier result because `close_direct_shared` had been added to the verifier's
extra tmpfs file-subset set but not to that guest loop.  The focused gate already
covers that case on tmpfs.  The verifier now lists it in the full option set and
not in the smaller emitted subset; replaying the unmodified preserved console
then passed with no missing or extra rows.

Evidence is under `/tmp/linuxulator-close-direct-20260922/`.  The completed VM
console SHA-256 is
`ca435bcc6b5b27d19baf36f255e60e905e4bc2d5f5d82c9cff08421360dc4acc`;
the corrected verifier result is
`66f4e454d5b670d89da2c71e034b9037c51f1ff854ead79d1ae46e64c8ca9b11`;
the qualified image is
`3cd4a9fb9a50c33b417bf61c88ea049a24cdd9438a361ea01e2a1fc68a6106ba`.

## 2026-09-22: io_uring `MADVISE` length and fixed-file semantics

Linux `IORING_OP_MADVISE` takes its 64-bit range length from `sqe->off` when
that field is nonzero and uses the legacy 32-bit `sqe->len` only as a fallback.
The Linux frontend previously ignored `off`, truncating or shortening requests
to `len`.  It now imports the same preferred/fallback length as Linux before
delegating to `linux_madvise()`.  This decoding is Linux ABI policy and remains
in `sys/compat/linux/linux_io_uring.c`.

The Linux 6.18.35 oracle also established that `IOSQE_FIXED_FILE` is ignored for
`MADVISE`: the opcode has no request file, so the flag neither looks up a
registered slot nor prevents the advice from running.  Shared squeue's fixed
file dispatch wrapper previously tried to resolve the meaningless `fd` field.
`MADVISE` now follows the existing Linux no-file bypass in
`sys/kern/sys_squeue.c`.  The bypass is Linux-gated; native descriptor-bearing
operations retain shared fixed-file resolution and native capmode policy.

Two new main-matrix cases provide positive and negative coverage.
`madvise_length` uses `MADV_DONTNEED` on a three-page anonymous mapping to prove
that a two-page `off` overrides a conflicting one-page `len`, that zero `off`
falls back to `len`, and that the third page remains unchanged.  It also proves
that arbitrary `fd` values are ignored.  `madvise_options` covers an unaligned
address, unknown advice, wrapping 64-bit length, reserved `buf_index` and
`splice_fd_in`, ignored `IOSQE_FIXED_FILE`, rejected nonzero `ioprio`,
side-effect-free preparation failures, and ring health after rejection.

The exact final binary passed both cases 25 times each on Linux 6.18.35-0-virt.
The focused amd64 WITNESS/INVARIANTS candidate then passed 100 executions: both
cases 25 times from ZFS-root working directories and 25 times from tmpfs.  All
tracked requests, wired pages, registered files, issuer references, and issuer
tokens returned to zero; ZFS was healthy and shutdown synced all buffers.

The complete disposable amd64 ZFS-root gate passed 456 Linux io_uring cases,
1,104 shared-option executions, three native squeue runs, 39 NO_MMAP, 33 SQPOLL,
24 memory-region, 21 query, 57 Linux AIO, 63 Linux ptrace, three native ptrace,
and three ptrace-capmode executions, plus the remaining syscall and filesystem
matrices.  It reported no nonzero result or kernel diagnostic, all final
resource counters were zero, ZFS was healthy, and QEMU exited zero after clean
poweroff.  Arm64 was not rerun because this is architecture-neutral option and
dispatch behavior, consistent with the post-platform-phase gate policy.

Two launches are excluded from qualification: one unbranded main Linux test
binary and one unbranded Linux shared-options binary stopped at exec before the
relevant matrix.  The final image contains Linux-branded copies and completed
the entire gate.  Evidence is under `/tmp/linuxulator-madvise-20260922/`.
The final image SHA-256 is
`2ab7a47d802fe5f8f5c5290f154eb47d2d304014b87bdb914c9de30e4244b1b3`;
the full console is
`967e56a861531cf6a6c73746314c3ae47e179a7d8b1a768d84453439c7117115`;
and the parsed result is
`a74f5686ed77c82ffac620e060c4c439d89af45daef90d5ba4a176fa27df66b4`.

## 2026-09-22: `sync_file_range` direct and io_uring option contract

The Linux `sync_file_range` handler now resolves and retains the descriptor
before validating flags or ranges, matching Linux error precedence. It rejects
negative offsets and lengths, detects signed `offset + nbytes` overflow, accepts
all combinations of `WAIT_BEFORE`, `WRITE`, and `WAIT_AFTER`, and returns
`ESPIPE` for pipes, sockets, and other unsupported file types. The same handler
serves the direct syscall and `IORING_OP_SYNC_FILE_RANGE`, so fixed-file io_uring
requests receive identical argument and type behavior after shared squeue
translates the registered slot to a transient descriptor.

A small shared kernel helper, `kern_fsync_fp()`, performs the existing vnode
sync against an already referenced file. This preserves the descriptor selected
by the Linux handler through validation and writeback, avoiding a close/reuse
window. It changes no native syscall ABI. Shared squeue needed no opcode change:
its reserved-field mask, ioprio rejection, and fixed-file dispatch already match
Linux. FreeBSD has no range-fsync VOP, so requests that reach writeback use a
conservative whole-vnode `VOP_FDATASYNC`; the range and flags are validated
exactly, but writeback may cover more data than Linux. This limitation is kept
visible rather than claiming range-writeback equivalence.

The direct case covers flag values 0 through 7, zero and boundary ranges,
negative offset and length, signed overflow, unknown flags, bad-fd precedence,
read-only descriptors, directories, pipes, and sockets. The io_uring case adds
missing, sparse, out-of-range, and closed-original fixed-file slots; all three
reserved SQE fields; nonzero ioprio; bad-fd precedence; pipe `ESPIPE`; recovery
after rejected preparations; and valid fixed-file lifetime.

Linux 6.18.35-0-virt passed the direct and io_uring cases ten times each. The
focused amd64 WITNESS/INVARIANTS candidate passed 100 executions split equally
between ZFS and tmpfs, with all tracked squeue resources returning to zero. The
formal disposable amd64 ZFS-root gate passed 39 direct ABI executions, 457 main
io_uring cases, 1,104 shared-option executions, three native squeue runs, 39
NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, 57 Linux AIO, 63 Linux ptrace,
three native ptrace, and three ptrace-capmode executions plus the remaining
matrices. It reported no nonzero results or kernel diagnostics, all final
resources were zero, ZFS was healthy, buffers synced, and QEMU exited zero.

The first full guest execution also passed every test and shut down cleanly,
but the host parser still required the former 36-case direct total. The parser
was corrected to 39 and the unchanged image then passed the complete formal
rerun. Arm64 was not rerun because this phase changes architecture-neutral
validation and vnode handling, under the post-platform-phase policy. Evidence
is under `/tmp/linuxulator-sync-range-20260922/`.

After the full gate, the freestanding io_uring test was made portable without
changing tested amd64 behavior: legacy direct `open` calls became `openat`, and
readiness waits use `ppoll`, which exists on both Linux amd64 and arm64. The
final source compiles cleanly with `-Wall -Wextra -Werror` for both targets.
The exact final amd64 binary then passed 200 focused candidate executions: the
four touched cases ran 25 times each from ZFS and 25 times each from tmpfs.
Every tracked squeue resource returned to zero, ZFS remained healthy, buffers
were synced, and QEMU powered off cleanly. Arm64 runtime was intentionally not
repeated under the post-platform-phase policy.

## 2026-09-22: direct and io_uring xattr option contract

The Linux xattr handler now matches three Linux VFS details that the native
extattr primitives do not provide directly. `XATTR_CREATE` checks existence
without using the proposed replacement length, so a shorter new value cannot
turn an existing large attribute into `ERANGE`. Linux permits CREATE and
REPLACE together: an existing attribute returns `EEXIST`, while a missing one
returns `ENODATA`. Finally, getxattr queries the complete native attribute size
before copying, returning `ERANGE` without exposing a truncated prefix and
preserving size-zero query behavior.

These rules remain Linuxulator policy in `linux_xattr.c`; no native syscall ABI
changed. The common Linux xattr flag constants moved to `linux_file.h` so the
io_uring frontend can validate fd-xattr flags during request preparation. That
preserves Linux ordering for invalid flags versus fixed-file slot lookup. Path
xattr operations continue to reject `IOSQE_FIXED_FILE` first. Shared squeue's
existing fixed-file translation and unused-field behavior were sufficient and
required no backend change.

The new direct case covers CREATE against a larger existing value, REPLACE on
present and absent attributes, both flag bits for present and absent names,
unknown flags, zero-size queries, short-buffer `ERANGE`, missing attributes,
data preservation, and cleanup. The io_uring case additionally covers all four
xattr opcodes, arbitrary ignored path-op fds, path-op fixed-file rejection,
fd-argument validation order, accepted unused SQE union fields, rejected
ioprio and buffer selection, registered-file lifetime after ambient close,
invalid fixed slots, and fixed-slot/flag error ordering.

Linux 6.18.35-0-virt passed the exact direct and io_uring cases ten times each.
The focused amd64 WITNESS/INVARIANTS candidate passed 100 executions split
between ZFS and tmpfs, with all tracked squeue resources returning to zero.
The complete amd64 ZFS-root gate passed 42 direct ABI executions, 458 main
io_uring cases, 1,104 shared-option executions, three native squeue runs, 39
NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, 57 Linux AIO, 63 Linux ptrace,
three native ptrace, and three ptrace-capmode executions plus every remaining
matrix. It reported no nonzero results or kernel diagnostics, final resources
were zero, ZFS was healthy, buffers synced, and QEMU exited zero. Both final
test sources compile for amd64 and arm64 with warnings as errors; arm64 runtime
was not repeated because the implementation is architecture-neutral.
Evidence is under `/tmp/linuxulator-xattr-20260922/`.

## 2026-09-22: direct and io_uring `EPOLL_CTL` option contract

The direct Linux `epoll_ctl` handler already matched Linux's event-copy rule:
every operation except `EPOLL_CTL_DEL` imports the event before descriptor
lookup, so an unknown operation with an invalid event pointer returns `EFAULT`.
`DEL` ignores the event pointer. No direct-handler change was needed.

Linux does not mark `IORING_OP_EPOLL_CTL` as a request-file opcode, so
`IOSQE_FIXED_FILE` is ignored and `sqe.fd` remains the ambient epoll descriptor.
Shared squeue previously translated that descriptor as a registered-file slot.
The fixed-file dispatch bypass now includes `EPOLL_CTL` only for Linux rings;
native descriptor handling and capmode policy are unchanged. The Linux
frontend's existing preparation rejects `buf_index` and `splice_fd_in`, while
the generic preparation path rejects nonzero ioprio and buffer selection.

The direct case covers ADD, duplicate ADD, MOD, DEL, repeated DEL, unknown
operations, bad event pointers, bad epoll and target descriptors, self-add,
and pointer-error precedence. The io_uring case adds every preparation field,
accepted unused padding, ignored fixed-file behavior without a registered
table, side-effect-free rejection, and successful recovery on a second target.

Linux 6.18.35-0-virt passed both exact cases ten times. The focused amd64
WITNESS/INVARIANTS candidate passed 100 executions split equally between ZFS
and tmpfs, with every tracked squeue resource returning to zero. The formal
amd64 ZFS-root gate passed 45 direct executions, 459 main io_uring cases, 1,104
shared-option executions, three native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24
memory-region, 21 query, 57 Linux AIO, 63 Linux ptrace, three native ptrace,
and three ptrace-capmode executions plus the remaining matrices. It reported
no nonzero results or kernel diagnostics, final resources were zero, ZFS was
healthy, buffers synced, and QEMU exited zero. Both test sources compile for
amd64 and arm64 with warnings as errors; arm64 runtime was not repeated because
the implementation is architecture-neutral. Evidence is under
`/tmp/linuxulator-epoll-20260922/`.

## 2026-09-22: io_uring `STATX` preparation ordering

Linux validates `STATX`'s reserved `buf_index` and `splice_fd_in` fields before
rejecting `IOSQE_FIXED_FILE`. Shared squeue previously performed those checks
in the reverse order. The common preparation path now defers only STATX's
fixed-file rejection until after its reserved-field mask; the operation remains
a Linux extension and native syscall ABI is unchanged.

The new case covers successful STATX, each reserved field alone and combined
with fixed-file, fixed-file alone, accepted unused tail words, nonzero ioprio,
buffer selection, unknown statx flags, invalid pathname and output pointers,
and recovery. Linux 6.18.35 passed the exact case 20 times. The focused amd64
WITNESS/INVARIANTS candidate passed 50 executions split across ZFS and tmpfs,
with all tracked resources returning to zero. The formal amd64 ZFS-root gate
passed 45 direct executions, 460 main io_uring cases, 1,104 shared-option
executions, three native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region,
21 query, 57 Linux AIO, and every remaining matrix. It reported no nonzero
results or diagnostics, final resources were zero, ZFS was healthy, buffers
synced, and QEMU exited zero. The test compiles for amd64 and arm64 with
warnings as errors; arm64 runtime was not repeated for this architecture-neutral
ordering change. Evidence is under `/tmp/linuxulator-epoll-20260922/`.


## 2026-09-22: io_uring pathname-operation preparation ordering

Linux validates opcode-specific reserved fields before rejecting
`IOSQE_FIXED_FILE` for `RENAMEAT`, `UNLINKAT`, `MKDIRAT`, `SYMLINKAT`, and
`LINKAT`. Shared squeue previously rejected fixed-file first. Its common
preparation path now defers fixed-file rejection for these five operations
until after their reserved-field masks, alongside the previously corrected
STATX rule. This belongs in the shared validator because that layer owns both
field-mask validation and registered-file selection; no native syscall ABI or
native pathname syscall behavior changed.

The new case checks `buf_index` and `splice_fd_in`, alone and combined with
fixed-file, for all five operations; fixed-file alone; UNLINK's reserved
`off`/`len`, MKDIR's `off`/`rw_flags`, SYMLINK's `len`/`rw_flags`; invalid
rename, unlink, and link flags; absence of filesystem side effects after every
rejection; and successful directory, symlink, hard-link, rename, unlink, and
cleanup operations after the negative matrix.

Linux 6.18.35 passed the exact case 20 times. The focused amd64
WITNESS/INVARIANTS candidate passed 50 executions split between ZFS and tmpfs,
with every tracked squeue resource returning to zero. The formal amd64
ZFS-root gate passed 45 direct executions, 461 main io_uring cases, 1,104
shared-option executions, three native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24
memory-region, 21 query, 57 Linux AIO, 63 Linux ptrace, three native ptrace,
and three ptrace-capmode executions plus all remaining matrices. It reported
no nonzero results or kernel diagnostics, final resources were zero, ZFS was
healthy, buffers synced, and QEMU exited zero. The test compiles for amd64 and
arm64 with warnings as errors; arm64 runtime was not repeated for this
architecture-neutral ordering change. Evidence is under
`/tmp/linuxulator-pathops-20260922/` and the source run artifacts under
`/tmp/linuxulator-epoll-20260922/`.


## 2026-09-22: io_uring `TEE` option and fixed-file contract

Linux performs `TEE`'s offset and splice-flag validation before looking up its
output file. Shared squeue already rejects nonzero input or output offsets
during common field-mask preparation. The Linux io_uring preparation hook now
validates `SPLICE_F_ALL | SPLICE_F_FD_IN_FIXED` before registered output-file
resolution, so an unknown flag combined with a missing fixed output returns
`EINVAL` rather than `EBADF`. Execution retains its defensive flag check. This
is Linux frontend policy; shared registered-file lookup and output descriptor
translation required no change.

The new case checks both offsets alone and together with bad flags; generic
ioprio and buffer-selection rejection; ignored buffer-index and tail words;
all 16 `SPLICE_F_ALL` combinations with observable duplicate-without-consume
behavior; nonblocking `EAGAIN`; zero-length behavior; bad descriptors; regular
and same-pipe rejection; ordinary, fixed-input, fixed-output, and both-fixed
operation; fixed-file lifetime after ambient close; sparse and out-of-range
slots in both directions; invalid-field precedence; unregister behavior; and
post-failure recovery. The same preparation rule also corrects invalid
splice-flag ordering for `IORING_OP_SPLICE` with a registered output.

Linux 6.18.35 passed the exact TEE case 20 times. The focused amd64
WITNESS/INVARIANTS candidate passed 50 executions split between ZFS and tmpfs,
with every tracked squeue resource returning to zero. The formal amd64
ZFS-root gate passed 45 direct executions, 462 main io_uring cases, 1,104
shared-option executions, three native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24
memory-region, 21 query, 57 Linux AIO, 63 Linux ptrace, three native ptrace,
and three ptrace-capmode executions plus all remaining matrices. It reported
no nonzero results or diagnostic failures; final resources were zero, ZFS was
healthy, buffers synced, and QEMU exited zero. Both freestanding test targets
compile with warnings as errors; arm64 runtime was not repeated for this
architecture-neutral preparation change. Evidence and the exact source
snapshot are under `/tmp/linuxulator-tee-20260922/`.

## 2026-09-22: io_uring `PIPE` option and fixed-file contract

Linux treats `IORING_OP_PIPE` as a descriptorless request. Its preparation
validates pipe creation flags before `IOSQE_FIXED_FILE` is ignored. The
Linuxulator preparation hook now accepts the Linux flag namespace and rejects
unknown bits in that order. Shared squeue bypasses registered-file translation
for PIPE only on Linux rings. The existing Linux pipe helper implements
`O_CLOEXEC` and `O_NONBLOCK`; `O_DIRECT` packet mode and
`O_NOTIFICATION_PIPE` remain rejected rather than silently losing semantics.

The exact case verifies flags 0, `O_CLOEXEC`, `O_NONBLOCK`, and their
combination on both returned descriptors; ignored fixed-file behavior without
a registered table; reserved fd, offset, addr3, ioprio, and buffer-selection
fields; accepted unused SQE words; invalid-flag precedence; `EFAULT` copyout
rollback with no leaked pipe ends; and successful recovery. Linux 6.18.35
passed it 20 times. The focused amd64 WITNESS/INVARIANTS candidate passed 50
executions split between ZFS and tmpfs, with all ten tracked resource counters
zero. The formal amd64 ZFS-root gate passed 45 direct executions, 463 main
io_uring cases, 1,104 shared-option executions, three native squeue runs, 39
NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, 57 Linux AIO, 63 Linux ptrace,
three native ptrace, and three ptrace-capmode executions plus every remaining
matrix. It reported no nonzero results or diagnostic failures; final resources
were zero, ZFS was healthy, buffers synced, and QEMU exited zero. Both
freestanding test targets compile with warnings as errors; arm64 runtime was
waived for this architecture-neutral change. Evidence and the exact source
snapshot are under `/tmp/linuxulator-pipe-20260922/`.

## 2026-09-22: io_uring `FTRUNCATE` file resolution and options

Linux prepares FTRUNCATE fields, resolves and pins the request file, then calls
`do_ftruncate`. This differs from the direct syscall for the combined invalid
fd and negative-length case: io_uring returns `EBADF`, while direct
`ftruncate` validates the length first. Shared squeue now delegates Linux
FTRUNCATE execution to the Linux frontend. That frontend resolves the file with
`CAP_FTRUNCATE`, keeps it pinned through `fo_truncate`, and preserves Linux
writable-regular-file checks. Native squeue still calls `kern_ftruncate`
directly. Shared reserved-field validation was already exact.

The exact matrix covers each rejected `addr`, `len`, `rw_flags`,
`buf_index`, `splice_fd_in`, and `addr3` field; accepted final SQE
padding; rejected ioprio and buffer selection; error ordering; unchanged size
after every failure; read-only regular files, directories, pipes, and sockets;
ordinary grow/shrink; fixed-file lifetime after ambient close; sparse and
out-of-range slots; preparation-before-slot ordering; unregister behavior;
`IOSQE_ASYNC`; and recovery. Linux 6.18.35 passed it 20 times. The focused
amd64 WITNESS/INVARIANTS candidate passed 50 executions split between ZFS and
tmpfs with all ten tracked counters zero.

The formal amd64 ZFS-root gate passed 45 direct executions, 464 main io_uring
cases, 1,104 shared-option executions, three native squeue runs, 39 NO_MMAP,
33 SQPOLL, 24 memory-region, 21 query, 57 Linux AIO, 63 Linux ptrace, three
native ptrace, and three ptrace-capmode executions plus every remaining
matrix. It reported no nonzero results or diagnostic failures; final resources
were zero, ZFS was healthy, buffers synced, and QEMU exited zero. Both
freestanding test targets compile with warnings as errors; arm64 runtime was
waived for this architecture-neutral change. Evidence and the exact source
snapshot are under `/tmp/linuxulator-ftruncate-20260922/`.

## 2026-09-22: io_uring `BIND` and `LISTEN` option contract

Linux BIND and CONNECT copy their sockaddr during request preparation, before
ordinary or registered request-file lookup. The Linux frontend now performs
the same signed-length bounds check and complete copyin at that point. This
makes an invalid sockaddr combined with a bad fixed slot return `EFAULT`, and
an oversized address return `EINVAL`, before `EBADF`. Execution continues
through the Linux socket handlers. Shared squeue already owns the correct
opcode field masks and registered-file lifetime; native behavior did not
change.

The exact matrix covers BIND's reserved `len`, `rw_flags`, `buf_index`,
and `splice_fd_in`; LISTEN's reserved `addr2`, `addr`, `rw_flags`,
`buf_index`, and `splice_fd_in`; generic ioprio and buffer-selection
rejection; accepted `addr3` and final SQE padding; sockaddr-fault and
oversize precedence; side-effect-free preparation failures; ordinary success;
registered socket lifetime after ambient close; sparse and out-of-range slots;
unregister behavior; regular-file `ENOTSOCK`; datagram LISTEN rejection;
`IOSQE_ASYNC`; and recovery. Linux 6.18.35 passed it 20 times. The focused
amd64 WITNESS/INVARIANTS candidate passed 50 executions split between ZFS and
tmpfs with all ten tracked counters zero.

The formal amd64 ZFS-root gate passed 45 direct executions, 465 main io_uring
cases, 1,104 shared-option executions, three native squeue runs, 39 NO_MMAP,
33 SQPOLL, 24 memory-region, 21 query, 57 Linux AIO, 63 Linux ptrace, three
native ptrace, and three ptrace-capmode executions plus every remaining
matrix. It reported no nonzero results or diagnostic failures; final resources
were zero, ZFS was healthy, buffers synced, and QEMU exited zero. Both
freestanding targets compile with warnings as errors; arm64 runtime was waived
for this architecture-neutral change. Evidence and the exact source snapshot
are under `/tmp/linuxulator-bindlisten-20260922/`.

## 2026-09-22: io_uring `CONNECT` and `SHUTDOWN` option contract

The permanent `connect_shutdown_options` case verifies CONNECT's four reserved
operation fields, ioprio, buffer selection, preparation-time sockaddr fault and
length ordering, accepted `addr3` and final padding, ordinary and registered
sockets, fixed-file lifetime, sparse and out-of-range slots, and unregister
behavior. It also verifies SHUTDOWN's five reserved fields, invalid `how`,
non-socket rejection, peer EOF, fixed-file lifetime, accepted unused tail,
`IOSQE_ASYNC`, side-effect-free failures, and recovery. The shared backend
already owns the exact SHUTDOWN mask. CONNECT uses the Linux frontend sockaddr
preparation helper added with BIND. Native socket syscalls and native squeue
remain unchanged.

Linux 6.18.35 passed 20 exact-case executions. The focused amd64
WITNESS/INVARIANTS candidate passed 50 executions split between ZFS and tmpfs,
with all ten before/after resource values zero. The formal amd64 ZFS-root gate
passed 45 direct executions, 466 main io_uring cases, 1,104 shared-option
executions, three native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region,
21 query, 57 Linux AIO, 63 Linux ptrace, three native ptrace, and three
ptrace-capmode executions plus every remaining matrix. It reported no nonzero
results or diagnostic failures; final resources were zero, ZFS was healthy,
buffers synced, and QEMU exited zero. The prior
`ioprio_send_zc_fixed_vectorized` one-off failure did not reproduce. Both
freestanding targets compile with warnings as errors; arm64 runtime was waived
for this architecture-neutral phase. Evidence and the exact source snapshot
are under `/tmp/linuxulator-connectshutdown-20260922/`.

## 2026-09-22: io_uring `SOCKET` and `ACCEPT` option contract

Linux ignores `IOSQE_FIXED_FILE` on SOCKET because the opcode creates a
descriptor and has no request file. Shared squeue now includes SOCKET in its
Linux-only descriptorless dispatch path. Native rings retain their existing
fixed-file handling. The frontend and shared field masks continue to validate
SOCKET address/flag/buffer fields and ACCEPT length/buffer fields before
execution.

The permanent `socket_accept_options` case verifies SOCKET reserved fields,
generic option rejection, ignored fixed-file operation, accepted SQE tail,
CLOEXEC/NONBLOCK, invalid domains and flags, direct output and rollback, and
async recovery. It verifies ACCEPT reserved fields, invalid flags without peer
consumption, accepted tail, returned descriptor flags, ordinary and fixed
listeners, lifetime after ambient close, sparse and out-of-range slots,
unregister behavior, non-socket errors, async execution, and recovery. Linux
6.18.35 passed 20 exact-case executions. The focused corrected candidate
passed 50 executions split between ZFS and tmpfs with all ten before/after
resource values zero.

The formal amd64 ZFS-root gate passed 45 direct executions, 467 main io_uring
cases, 1,104 shared-option executions, three native squeue runs, 39 NO_MMAP,
33 SQPOLL, 24 memory-region, 21 query, 57 Linux AIO, 63 Linux ptrace, three
native ptrace, and three ptrace-capmode executions plus every remaining
matrix. It reported no nonzero results or diagnostic failures; final resources
were zero, ZFS was healthy, buffers synced, and QEMU exited zero. Both
freestanding targets compile with warnings as errors; arm64 runtime was waived
for this architecture-neutral phase. Evidence and the exact source snapshot
are under `/tmp/linuxulator-socketaccept-20260922/`.

## 2026-09-23: io_uring `SPLICE` option contract

The permanent `splice_options` case verifies ioprio and buffer-selection
rejection, accepted unused `buf_index`, `addr3`, and final padding, every
combination of Linux's four `SPLICE_F` hints, invalid-flag precedence over bad
registered input and output slots, ordinary and fixed descriptors in both
directions, lifetime after ambient close, sparse and out-of-range slots,
unregister behavior, descriptor and file-shape errors, side effects,
`IOSQE_ASYNC`, and recovery. Linux flag validation remains in the Linux
frontend. Shared squeue continues to own output registered-file translation;
no native behavior changed and no kernel edit was needed for this phase.

Linux 6.18.35 passed 20 exact-case executions. The focused amd64 candidate
passed 50 executions split between ZFS and tmpfs with all ten before/after
resource values zero. The formal amd64 ZFS-root gate passed 45 direct
executions, 468 main io_uring cases, 1,104 shared-option executions, three
native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, 57 Linux
AIO, 63 Linux ptrace, three native ptrace, and three ptrace-capmode executions
plus every remaining matrix. It reported no nonzero results or diagnostic
failures; final resources were zero, ZFS was healthy, buffers synced, and QEMU
exited zero. Both freestanding targets compile with warnings as errors; arm64
runtime was waived for this architecture-neutral test phase. Evidence and the
exact source snapshot are under `/tmp/linuxulator-spliceoptions-20260922/`.

## FILES_UPDATE automatic-allocation gate (2026-09-23)

Changes to IORING_OP_FILES_UPDATE automatic slot allocation must test all of
the following before acceptance:

- Linux 6.18 oracle parity for preparation errors, slot numbering, allocation
  range and hint behavior;
- successful and full sparse tables, asynchronous execution, retained file
  lifetime, and partial-prefix results;
- invalid flags, ioprio, reserved fields, zero length, bad descriptors and bad
  user pointers;
- rollback when the kernel can read an input fd but cannot write its allocated
  slot index back;
- the same shared-backend behavior through native squeue and Linux io_uring;
- repeated amd64 ZFS-root QEMU execution on ZFS and tmpfs, with all squeue
  resource counters unchanged.

The permanent inventories are 469 Linux io_uring cases and 185 shared squeue
cases per ABI. The focused FILES_UPDATE gate passed 50/50 filesystem runs.

## FILES_UPDATE automatic-allocation result (2026-09-23)

The sealed amd64 ZFS-root QEMU gate passed with the 469-case io_uring
inventory and 185 shared squeue cases per ABI. The result includes 1,110
shared-option executions, 39 no-mmap, 33 SQPOLL, 24 memory-region, 21 query
and 57 AIO executions, plus the ptrace, capmode and native regressions. All
functional results were zero; final request, file, issuer and wired-page
counts were zero; ZFS remained healthy; shutdown synced all buffers.

One earlier unchanged-image run was excluded because unrelated
remap_file_pages stress emitted a nondeterministic vmobject/process-lock
WITNESS report. Its functional results were also all zero. The clean rerun
passed the same remap phase without a diagnostic and is the accepted result.

## io_uring legacy provided-buffer option gate (2026-09-23)

`IORING_OP_PROVIDE_BUFFERS` and `IORING_OP_REMOVE_BUFFERS` now use persistent
classic-group identity in shared squeue, enforce Linux 6.18 count, length,
address and buffer-ID bounds, and distinguish a missing group from an emptied
group. Provided-ring registration replaces an empty classic group, rejects a
live one, and serializes with batched classic publication. The Linux frontend
alone ignores `IOSQE_FIXED_FILE` for these descriptorless operations; native
squeue retains fixed-file semantics.

The main and shared option cases passed Linux 6.18.35 twenty times each. A
64-race provide-versus-register shared case passed twenty Linux runs (1,280
races). The focused candidate ran the main case, aggregate invalid case, and
both shared cases through native and Linux frontends for 50 ZFS/tmpfs rounds,
300 invocations total. The formal amd64 ZFS-root result at
`/tmp/linuxulator-pbufoptions-20260923/full-run3/results.json` passed 470 main
io_uring cases, 1,122 shared-option executions, and every specialized suite.
Final request, file, issuer, and wired-page counters were zero; the pool was
healthy, no kernel diagnostic was recognized, and shutdown synchronized all
buffers. Arm64 runtime was not repeated because the implementation and ABI
layout change are architecture-neutral; both freestanding arm64 test binaries
compile warning-clean.

## 2026-09-23: io_uring OPENAT / OPENAT2 option gate

Changes to open SQE preparation must preserve Linux 6.18 ordering: generic
ioprio and buffer-selection checks precede opcode preparation; OPENAT checks
buf_index, fixed-file use, pathname import, and direct O_CLOEXEC in that order;
OPENAT2 first copies and extends open_how, then applies those checks. Native
squeue semantics must remain unchanged when Linux-specific ordering is
implemented in the frontend.

Acceptance requires Linux-oracle comparison, malformed and inaccessible
open_how, invalid flags/mode/resolve, reserved-field and tail-word coverage,
ordinary and direct output, rollback with slot-health verification,
IOSQE_ASYNC, repeated ZFS/tmpfs focused execution, full ZFS-root QEMU, zero
final squeue resources, clean debug diagnostics, healthy pool status, and
synchronized shutdown. The accepted evidence is
/tmp/linuxulator-openoptions-20260923/full-run2/results.json: 471 main cases,
1,122 shared-option executions, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21
query, and 57 AIO executions passed. The first formal attempt is excluded only
because its 1,800-second host timeout expired after all main cases passed.

## 2026-09-23: io_uring CLOSE option gate

CLOSE preparation must reject generic unsupported options first, then its five
reserved SQE fields, then IOSQE_FIXED_FILE, and finally a nonzero fd combined
with a direct file_index. Rejected direct closes must preserve the registered
slot. Ordinary and direct asynchronous closes must prove descriptor and slot
removal, accepted tail words, and ring health.

Acceptance requires Linux 6.18 oracle parity, all precedence combinations,
focused ZFS/tmpfs repetition, a full amd64 ZFS-root QEMU gate, clean debug
kernel diagnostics, zero final squeue resources, healthy pool status, and a
synchronized shutdown. The accepted evidence is
/tmp/linuxulator-closeoptions-20260923/full-run/results.json: 472 main cases,
1,122 shared-option executions, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21
query, and 57 AIO executions passed.

## 2026-09-23: io_uring FIXED_FD_INSTALL option gate

FIXED_FD_INSTALL preparation must reject unsupported generic options before
personality lookup, reject nonzero `off`, `addr`, `len`, `buf_index`,
`splice_fd_in`, and `addr3`, require `IOSQE_FIXED_FILE`, validate the install
flags, and reject registered personalities with `EPERM`. Acceptance must
verify default CLOEXEC, NO_CLOEXEC, asynchronous execution, accepted final SQE
padding, invalid and sparse slots, source registration lifetime, unregister,
side-effect-free rejection, and ring recovery through both native squeue and
the Linux ABI.

The Linux 6.18.35 oracle passed the main and shared cases 20/20 each. The
focused WITNESS/INVARIANTS candidate passed 50 rounds split between ZFS and
tmpfs, 300 invocations total, with all ten resource-counter values zero and no
kernel diagnostic. Each test invocation used a separate directory after an
initial harness-only `O_EXCL` filename collision was identified and excluded.

The formal amd64 ZFS-root gate at
`/tmp/linuxulator-fixedinstall-20260923/full-run/results.json` passed 45 direct
ABI executions, 473 main io_uring cases, 1,122 shared-option executions, three
native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, and 57
Linux AIO executions plus every remaining matrix. It reported no nonzero
result or diagnostic failure. Final squeue resources were zero, the pool was
healthy, and shutdown synchronized all buffers. Both arm64 freestanding test
binaries compile warning-clean; runtime remains waived for this
architecture-neutral phase. The candidate kernel and modules were neither
installed nor loaded on the host.

## 2026-09-23: Linux `fadvise64` and io_uring `FADVISE` gate

Changes to Linux fadvise behavior must compare the direct syscall and io_uring
operation against the same pinned Linux kernel. Acceptance requires all advice
values; invalid advice; bad-descriptor, pipe, directory, socket, negative-length,
negative-offset, and wrapping-range precedence; generic io_uring options;
every opcode-reserved SQE field; personality ordering; ordinary and registered
file lifetime; sparse and invalid slots; async execution; accepted tail words;
side effects; unregister behavior; and post-error ring health. Shared mechanics
may accept a held `struct file`, but Linux-specific errno, type, and range rules
must remain in the Linux frontend. Native syscall and native squeue ordering
must be tested separately and remain unchanged.

Linux 6.18.35 passed the direct, main io_uring, and shared cases 20/20 each.
The rebuilt debug candidate passed 50 focused ZFS/tmpfs rounds and 300 total
invocations with zero retained resources and clean diagnostics. The accepted
formal amd64 ZFS-root gate at
`/tmp/linuxulator-fadvise-20260923/full-run/results.json` passed 48 direct ABI
executions, 474 main io_uring cases, 1,128 shared-option executions, three
native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, and 57
Linux AIO executions plus every remaining matrix. All final resource counters
were zero, the pool was healthy, no recognized kernel diagnostic occurred, and
shutdown synchronized all buffers. Both architecture test binaries compile
warning-clean; arm64 runtime remains waived for this architecture-neutral
phase. The host kernel and modules were not changed, installed, or loaded.

The first complete formal run was rejected only by stale host-validator
inventories of 45 direct and 1,122 shared executions. Its console passes the
corrected validator after adding `fadvise_options` and
`fadvise_options_shared`; the subsequent clean end-to-end run above is the
accepted artifact.


## 2026-09-23: io_uring `FSYNC` range and option gate

FSYNC acceptance requires Linux 6.18 parity for generic-option and personality
ordering, all reserved SQE fields, full and data-only modes, asynchronous
execution, valid nonzero and wrapping ranges, negative offsets, descriptor and
range-error precedence, non-vnode descriptors, accepted tail words, registered
file lifetime, sparse and invalid fixed slots, unregister, and ring recovery.
The shared implementation must hold the resolved file through writeback so
close/reuse cannot redirect the operation. Because the native VFS has no
range-fsync operation, successful ranges may conservatively sync the whole
vnode.

Linux 6.18.35 passed the main and shared cases 20/20 each. The corrected debug
candidate passed 50 focused rounds split between ZFS and tmpfs, 200 invocations
total, with zero retained resources and no recognized diagnostic. The accepted
formal amd64 ZFS-root evidence is
`/tmp/linuxulator-fsync-20260923/full-run/results.json`: 48 direct ABI
executions, 474 main io_uring cases, 1,134 shared-option executions, three
native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, and 57
AIO executions passed. Final requests, registered files, issuer references,
issuer tokens, and wired pages were zero; the pool was healthy and shutdown
synchronized all buffers. Both Linux arm64 test binaries compile warning-clean;
runtime remains waived for this architecture-neutral phase. The host kernel
and modules were not changed, installed, or loaded.


## 2026-09-23: Linux `fallocate` and io_uring `FALLOCATE` gate

FALLOCATE acceptance requires Linux 6.18 parity for direct-syscall and
io_uring error ordering, generic-option and personality precedence, every
opcode-reserved field, all declared modes, zero, negative, and overflowing
ranges, read-only and non-regular descriptors, asynchronous execution,
accepted SQE tail words, ordinary and registered-file lifetime, sparse and
invalid fixed slots, unregister, and ring recovery. The Linux frontend must
hold the resolved file through validation and allocation so descriptor reuse
cannot redirect the operation. Shared held-file VFS helpers may contain only
native allocation and deallocation mechanics; Linux mode/type/error policy
must remain in the Linuxulator, and native syscall ordering must remain
unchanged.

Linux 6.18.35 passed the exact main and shared option cases 20/20 each. Both
amd64 and arm64 test binaries compile warning-clean. The debug candidate passed
50 focused ZFS/tmpfs rounds and 275 actual invocations with zero retained
resources and no recognized diagnostic. Positive reservation is required on
tmpfs or memfd; ZFS's deliberate `EOPNOTSUPP` reservation result is tested as
a filesystem contract rather than treated as a backend failure.

The accepted formal amd64 ZFS-root evidence is
`/tmp/linuxulator-fallocate-20260923/full-run/results.json`: 48 direct ABI
executions, 475 main io_uring cases, 1,140 shared-option executions, three
native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, and 57
AIO executions passed. Final requests, files, issuer references, issuer tokens,
and wired pages were zero; ZFS was healthy, diagnostics were clean, and
shutdown synchronized all buffers. Arm64 runtime remains waived after the
architecture-specific phase. Candidate kernel and modules were not installed
or loaded on the host.

## 2026-09-23: legacy AIO `IOCB_FLAG_IOPRIO` gate

Legacy AIO read and write IOCBs now implement Linux 6.18's priority-field
contract.  `aio_reqprio` is interpreted only for scalar and vectored reads and
writes carrying `IOCB_FLAG_IOPRIO`.  Best-effort and idle classes are accepted;
real-time class requires `PRIV_SCHED_RTPRIO`; invalid classes and a NONE class
with a nonzero level return `EINVAL`.  A nonzero priority without the flag is
ignored.  Fsync and poll IOCBs ignore the priority field even when the flag is
present, and unknown `aio_flags` remain forward-compatible.  The native AIO
backend does not provide per-request I/O scheduling priority, so accepted
priorities are advisory.

The validator is in `linux_common`, because legacy AIO is compiled into
`linux_common.ko` while io_uring is compiled into `linux64.ko`; both Linux
frontends use the same Linux class and privilege rules.  This phase changes no
native syscall or shared host-kernel interface.  Submission preserves Linux's
observable ordering: target-file and eventfd lookup precede `aio_key`
publication, while priority validation follows publication.  A rejected
priority with a valid eventfd must not signal it.

The exact expanded flags and poll binaries passed Linux 6.18.35 twenty times
each.  Coverage includes scalar and vectored read/write, best-effort, idle and
privileged real-time classes, unprivileged real-time rejection, invalid class
and NONE-level rejection, ignored priorities and unknown flags, fsync and poll
behavior, key-write ordering, descriptor precedence, eventfd-once completion,
and no eventfd signal on rejected submission.  All seven build variants of
`tests/sys/kern/linux_aio.c` compile warning-clean.

The focused debug candidate passed 25 ZFS and 25 tmpfs rounds of both expanded
binaries: 100 process invocations, zero failures, unchanged zero Linux AIO
wired-page and squeue request counts, healthy ZFS, no recognized diagnostic,
and synchronized shutdown.  The accepted formal amd64 ZFS-root evidence is
`/tmp/linuxulator-aio-ioprio-20260923/candidate/full-run/results.json`: 48
direct ABI executions, 475 main io_uring cases, 1,140 shared-option executions,
three native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query,
and 57 legacy AIO executions passed.  All final request, file, issuer, token,
and wired-page counts were zero; ZFS was healthy, diagnostics were clean, and
shutdown synchronized all buffers.  Arm64 runtime remains waived; legacy AIO
is currently an amd64 Linuxulator implementation.  The candidate kernel and
modules were neither installed nor loaded on the host.

## 2026-09-23: legacy AIO FSYNC/FDSYNC field gate

Linux FSYNC and FDSYNC IOCBs require `aio_buf`, `aio_offset`, `aio_nbytes`, and
`aio_rw_flags` all to be zero.  The Linux AIO adapter now rejects any nonzero
operation-specific field with `EINVAL` after target-file and eventfd lookup and
after publishing a zero `aio_key`, matching Linux 6.18 ordering.  Invalid
target or eventfd descriptors therefore retain a sentinel key and return
`EBADF` before field validation.  A valid eventfd acquired for a rejected IOCB
is released without being signaled.  Unknown `aio_flags` and `aio_reqprio`
remain ignored for both sync opcodes, while a target without an fsync operation
returns `EINVAL` after key publication.  This validation is confined to the
Linux AIO adapter in `linux_common`; native POSIX AIO and shared kernel
interfaces are unchanged.

The expanded flags binary covers each of the four forbidden fields on both
opcodes, successful FSYNC/FDSYNC with an invalid priority and unknown flag,
bad target and resfd precedence, key-write ordering, eventfd rollback with a
zero-time readiness check, and a non-fsync target.  The exact binary passed
Linux 6.18.35 twenty times, and all seven AIO build variants compile with
`-Wall -Wextra -Werror`.

The debug candidate passed 25 ZFS and 25 tmpfs focused rounds with zero
failures, unchanged zero AIO wired-page and squeue request counts, healthy ZFS,
clean diagnostics, and synchronized shutdown.  The accepted formal amd64
ZFS-root evidence is
`/tmp/linuxulator-aio-fsync-20260923/full-run/results.json`: 48 direct ABI
executions, 475 main io_uring cases, 1,140 shared-option executions, three
native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, and 57
legacy AIO executions passed.  All final resource counters were zero; the pool
was healthy, no recognized diagnostic occurred, and shutdown synchronized all
buffers.  Arm64 runtime remains waived; legacy AIO is currently amd64-only.
The candidate kernel and modules were neither installed nor loaded on the host.

## 2026-09-23: legacy AIO `io_setup` capacity and precedence gate

`io_setup` now follows Linux 6.18's observable validation order and 32-bit
ring-size arithmetic.  It first reads the caller's context word, returns
`EFAULT` for an inaccessible word even when the event count is invalid, then
rejects a nonzero word or zero count with `EINVAL`.  Linux doubles the unsigned
32-bit requested ring size before checking its internal allocation ceiling;
ordinary requests above the fixed 65,536 request limit return `EAGAIN`, while
oversized and wrapped values retain Linux's exact `EINVAL`/`EAGAIN` split.  The
context word remains unchanged on every rejection.  This policy is confined to
the amd64 Linux AIO handler and adds no native syscall or shared interface.

The count regression covers 65,537, 4,194,304, 4,194,305, `0x80000000`,
`0x80000001`, and `UINT_MAX`, plus bad-pointer and nonzero-context precedence.
The exact binary compiled warning-clean and passed Linux 6.18.35 twenty times.
The debug candidate then passed 25 ZFS and 25 tmpfs focused rounds with zero
failures or retained resources, healthy ZFS, clean diagnostics, and synchronized
shutdown.

The accepted formal amd64 ZFS-root evidence is
`/tmp/linuxulator-aio-setup-20260923/full-run/results.json`: 48 direct ABI
executions, 475 main io_uring cases, 1,140 shared-option executions, three
native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, and 57
legacy AIO executions passed.  All final resource counters were zero; the pool
was healthy, no recognized diagnostic occurred, and shutdown synchronized all
buffers.  Arm64 runtime remains waived; legacy AIO is currently amd64-only.
The candidate kernel and modules were neither installed nor loaded on the host.

## 2026-09-23: cross-path `RWF_NOSIGNAL` gate

Linux `RWF_NOSIGNAL` is now supported consistently by `pwritev2`, io_uring,
and legacy AIO.  Direct writes and inline io_uring writes retain normal Linux
`SIGPIPE` delivery unless the flag is present.  io_uring worker writes suppress
the worker-thread signal in both modes, matching Linux.  Legacy AIO workers
also suppress their own signal, then deliver the default `SIGPIPE` to the Linux
submitter for an unflagged completion; flagged requests complete with `EPIPE`
without a signal.  Scalar and vectored writes cover pipes and sockets.  Read
operations accept the flag where Linux does, while unknown bits and the still
unsupported `NOWAIT`, `ATOMIC`, and `DONTCACHE` modes remain rejected.

The reusable `FOF_NOSIGPIPE` policy and socket/VFS plumbing live in the shared
kernel because native squeue needs the same file-operation contract.  Linux
flag decoding, legacy-AIO signal semantics, and Linux requests' forced generic
AIO dispatch remain in the compatibility layer.  Native POSIX AIO keeps its
global unsafe-AIO policy and specialized socket path.  Shared AIO teardown was
also corrected so a foreign completion callback runs during process rundown
and the final active-count transition wakes the waiting process.

Linux 6.18.35 and 7.1.5 oracle guests each passed twenty rounds of the four
exact direct, io_uring, shared-squeue, and legacy-AIO binaries: 160 oracle
process executions in total.  These establish the different inline, worker,
and legacy-AIO signal contracts.  A focused debug candidate then passed 25 ZFS
and 25 tmpfs rounds, 300 process invocations, with zero retained AIO or squeue
resources, healthy ZFS, clean diagnostics, and synchronized shutdown.

The accepted formal amd64 ZFS-root evidence is
`/tmp/linuxulator-nosignal-20260923/candidate/full-run8/results.json`: 48 direct
ABI executions, 78 dedicated shared-RWF executions, 1,146 shared-option
executions, 476 main io_uring cases, three native squeue runs, 39 NO_MMAP, 33
SQPOLL, 24 memory-region, 21 query, and 63 legacy-AIO executions all passed.
The previously intermittent `ioprio_send_zc_fixed_vectorized` case passed.  All
final request, file, issuer, token, and wired-page counts were zero; the ZFS
pool was healthy, diagnostics were clean, and shutdown synchronized all
buffers.  The staged image SHA-256 is
`f90315fb94a3f7214af87d6bafa9cb0458affda707efead0a60828d443d0f3f3`, the
kernel SHA-256 is
`c0e1e3eea76fb0ceca667bc946d2742684771bd4d5b17f08200d8d8f35c7db4d`, and
the result JSON SHA-256 is
`cc2c7ff28ba295968974653b192c71f222bc1500df9976a9311c2af9c8334c86`.
Arm64 runtime was waived for this architecture-neutral phase.  The candidate
kernel and modules were neither installed nor loaded on the host.


## 2026-09-23: amd64 Linux64 `PTRACE_SEIZE`

The [SEIZE contract](linuxulator-ptrace-seize.md) adds no-stop attachment and
atomic initial option installation. The native ptrace core owns only the
kernel-internal attach transaction and frontend validation/setup callbacks;
Linux argument, errno, emulation-state and option translation remain in the
Linuxulator. Native `PT_ATTACH` behavior is unchanged.

The exact freestanding binary passed 20 times on Linux 6.18.35 and 20 times on
Linux 7.1.5. A WITNESS/INVARIANTS candidate passed 25 ZFS and 25 tmpfs focused
iterations. The integrated amd64 ZFS-root gate then passed three SEIZE runs,
63 register-ptrace, 21 ptrace-option, three native-ptrace and three ptrace
capmode executions. It also passed all 476 main io_uring and 1,146 shared-option
executions, including `ioprio_send_zc_fixed_vectorized`. No result or resource
counter was nonzero, no recognized diagnostic occurred, ZFS was healthy,
buffers synced and QEMU exited zero. Frozen evidence is under
`/tmp/linuxulator-seize-20260923/candidate`; the accepted result is
`full-run1/results.json`. `PTRACE_INTERRUPT` is covered by the later interrupt phase; `PTRACE_LISTEN` remains the next
seized-tracee lifecycle work. Linux32 is unchanged, and arm64 runtime was
waived for this architecture-neutral phase. The host kernel and modules were
never installed or loaded.

## 2026-09-24: amd64 Linux64 `PTRACE_INTERRUPT`

The [INTERRUPT contract](linuxulator-ptrace-interrupt.md) adds signal-free
seized-tracee stops, exact `PTRACE_EVENT_STOP` status and siginfo translation,
and pending interrupt delivery across CONT, SYSCALL, and SINGLESTEP. A new
kernel-only ptrace operation owns relationship locking and the shared stop; the
Linuxulator owns seized state and Linux-visible translation. An oracle-derived
SINGLESTEP negative test exposed and then qualified cancellation of stale
single-step state after a synthetic stop.

The exact test passed 20 times on Linux 6.18.35, 20 times on Linux 7.1.5, and
25 times each from ZFS and tmpfs in the focused amd64 WITNESS/INVARIANTS VM.
The final full amd64 ZFS-root gate passed three INTERRUPT rows plus all existing
matrices: 48 ABI cases, 63 AIO, 78 shared RWF, 1,146 shared options, 476 main
io_uring, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, 63 register
ptrace, 21 ptrace-option, three SEIZE, three native ptrace, and three ptrace
capmode executions. `ioprio_send_zc_fixed_vectorized` passed. There were no
nonzero results or recognized kernel diagnostics, final tracked resources were
zero, ZFS was healthy, buffers synced, and QEMU exited zero. Evidence is under
`/tmp/linuxulator-interrupt-20260923/candidate/full-run3`.

## 2026-09-24: amd64 Linux64 `PTRACE_LISTEN`

The [LISTEN contract](linuxulator-ptrace-listen.md) adds the Linux two-stage
job-control stop, stopped-but-hidden listener state, and exact INTERRUPT and
SIGCONT retraps. The native core owns internal group-stop publication, wait
visibility, signal wakeups and teardown. The Linux64 frontend owns seized-state
validation and Linux event status/siginfo. No native userspace ptrace request
was added.

The exact permanent binary passed 20/20 runs on Linux 6.18.35 and 20/20 on
Linux 7.1.5. The amd64 WITNESS/INVARIANTS candidate passed 25 ZFS and 25 tmpfs
focused iterations. The full amd64 ZFS-root gate passed three LISTEN rows plus
48 ABI cases, 63 AIO, 78 shared RWF, 1,146 shared options, 476 main io_uring,
39 NO_MMAP, 33 SQPOLL, 24 memory-region, 21 query, 63 register ptrace, 21
ptrace-option, and three each of SEIZE, INTERRUPT, native ptrace and capmode
ptrace. No result or tracked resource was nonzero, no recognized diagnostic
occurred, ZFS was healthy, and shutdown synced all buffers. Evidence is under
`/tmp/linuxulator-listen-20260924/candidate/full-run1`.

Arm64 runtime was waived because the shared-core portion is architecture
neutral and the frontend changes are amd64 Linux64-specific. Linux32 is
unchanged. The candidate kernel and modules were never installed or loaded on
the host.

## 2026-09-24: io_uring fast-poll descriptor lifetime

The [fast-poll lifetime contract](linuxulator-fastpoll-lifetime.md) moves
ordinary-descriptor fast-poll ownership into shared squeue: requests retain the
submitted file and capability rights, arm kqueue by private held-file identity,
and retry through a transient descriptor. Fixed-file dispatch uses the
registered generation and suppresses a second ambient-file resolution in the
Linux EPOLL_WAIT extension. Linux ABI validation and translation remain in the
Linuxulator, and ring-file targets retain their cycle-safe path.

Linux 6.18.35 and 7.1.5 each passed the permanent `fastpoll_close_reuse` case
20 times. The pre-fix amd64 candidate timed out as required by the negative
oracle. The corrected WITNESS/INVARIANTS ZFS-root candidate passed 100
`epoll_wait_fixed` executions interleaved with 100 `fastpoll_close_reuse`
executions. The final full gate at
`/tmp/linuxulator-iouring-fastpoll-20260924/full2-run/results.json` passed 477
main io_uring cases, 1,146 shared options, 78 shared RWF, 78 registered-file
lifecycle executions, three native squeue runs, 39 NO_MMAP, 33 SQPOLL, 24
memory-region, and 21 query executions, plus the broader Linuxulator matrices.
All tracked resources were zero, diagnostics were clean, ZFS was healthy,
buffers synced, and QEMU exited zero. The result JSON SHA-256 is
`8900af6f20cec59f9333ae8cc50f8d16f56046a07a269d5c66702ed3bdff5dd2` and
the kernel SHA-256 is
`4c4e96bd450826643ec1458ab379d9fc849ba193f81f556657587dccf42daa16`.
Arm64 runtime was waived for this architecture-neutral phase. No candidate was
installed or loaded on the host.
## Linux64 rseq default-slice registration option gate (2026-09-24)

Linux 7.1.5 with `CONFIG_RSEQ=y` and
`CONFIG_RSEQ_SLICE_EXTENSION` disabled accepts
`RSEQ_FLAG_SLICE_EXT_DEFAULT_ON`, leaves the feature flags clear, and returns
`ENOSYS` from conditional syscall 471. The Linuxulator registration handler
now accepts that flag without advertising an extension. Unknown flags and
`DEFAULT_ON|UNREGISTER` remain `EINVAL`; the actual slice grant/revocation
mechanism and `rseq_slice_yield` remain unimplemented. The retained Linux
oracle is `/tmp/rseq-slice-phase/oracle-test.console.log`.

The focused WITNESS/INVARIANTS amd64 ZFS-root gate ran the revised registration
probe 20 times on ZFS and 20 times on tmpfs, then reran signal, preemption,
thread and exec lifecycle probes. It passed with zero squeue resource counters,
healthy ZFS and clean shutdown in
`/tmp/rseq-slice-phase/bsd-focus.console.log`. The full gate passed in
`/tmp/rseq-slice-phase/full-run2/results.json`: 42 rseq runs, 1,146 shared
squeue-option runs, 477 io_uring cases, all registered-resource matrices, no
recognized diagnostics, healthy ZFS and clean shutdown. The first full run
reached the post-matrix NO_MMAP cases with every emitted status zero but hit
the controller's 1,800-second wall clock limit; the unchanged image completed
under the corrected 3,600-second limit. Artifact hashes are in
`/tmp/rseq-slice-phase/evidence.sha256`. No candidate was installed or loaded
on the host.



## 2026-09-24: amd64 Linux64 `perf_event_open`

The [perf event contract](linuxulator-perf-event.md) implements current-thread
software counters, Linux read layouts, descriptor flags, enable/disable/reset
and ID ioctls, attribute-size negotiation, thread-exit lifetime, and explicit
errors for unsupported sampling, PMU, grouping, and CPU-wide forms. Linux64
and Linux32 register separate teardown handlers in the shared Linux common
module, so loading both ABIs cannot overwrite one ABI's callback. Module builds
use the matching GENERIC-DEBUG option headers; this is required to preserve
RACCT accounting in Linux thread teardown.

The focused amd64 WITNESS/INVARIANTS VM passed 13 cases five times on ZFS and
five times on tmpfs, for 130 executions. The final amd64 ZFS-root gate in
`/tmp/perf-phase/full-gate-final9` passed 78 perf executions, the native-exec
descriptor lifetime and unload guard, 477 main io_uring cases, 1,146 shared
squeue-option executions, 21 query, 39 NO_MMAP, 33 SQPOLL, and 24 memory-region
executions. It also passed three each of PTRACE_SEIZE, PTRACE_INTERRUPT, and
PTRACE_LISTEN and all six direct RWF rows. No result was nonzero, all tracked
issuer, file, and request counts reached zero, the configured worker limit and
observed peak were both eight, no recognized diagnostic occurred, ZFS was
healthy, buffers synced, and QEMU exited zero after 35 minutes 47 seconds.

The result JSON SHA-256 is
`d268a287c290f55391ed382e491a6ef910adb9018777d494cdb9cead809d41a6`;
the console SHA-256 is
`fae7e89dd243c0aa2dec7e1110cd9d28aac41ac5ccfd74ed4684c94e47fbc513`.
The tested kernel, `linux_common.ko`, and `linux64.ko` SHA-256 values are
`05ca1efb3ea1a56e5530df4a2c9db0375354368268d0b2bb75b9c11305835ceb`,
`27914bc0d6e4870a174c72f52cf98869599f8a8b3909f980c6e2916e001e2ddc`,
and `07ca6e2bcae03523eadcd9b89eba5947d97f021f9dc87531e46644d28f934a8e`.
No candidate kernel or module was installed or loaded on the host.


## 2026-09-24: io_uring `ATTACH_WQ` shared worker controls

`IORING_SETUP_ATTACH_WQ` now gives every attachment chain a retained canonical
owner for IOWQ worker limits and affinity. The focused amd64 ZFS-root
WITNESS/INVARIANTS gate passed the expanded lifetime, chaining, negative, and
one-worker serialization case 20 times through native squeue and 20 times
through Linux io_uring. The full shared-options regression then passed 191
cases three times through each ABI, for 1,146 zero-status executions. Resource
counters were zero after all six rounds and at shutdown, ZFS was healthy, no
recognized kernel diagnostic occurred, buffers synchronized, and QEMU powered
off cleanly. The full console SHA-256 is
`fcf59e1988a6b938f74b29e5b36691903584d83cf8df0d87224d4641c7cd44fb`;
artifact hashes and compact logs are in `/tmp/iouring-attach/evidence`. No
candidate kernel or module was installed or loaded on the host.

## io_uring BPF request filters (2026-09-24)

`IORING_REGISTER_BPF_FILTER` is implemented with the native classic-BPF
verifier and interpreter in shared squeue. Immutable filter chains are
published with release ordering and execute without the ring mutex after
frontend preparation and before descriptor lookup or operation side effects.
The shared context covers `user_data`, opcode and SQE flags plus the Linux
payloads for SOCKET, OPENAT, OPENAT2 and CONNECT. Per-ring registration works
for native squeue and Linux io_uring. Linux blind registration on fd `-1` is
stored per task, requires privilege or `no_new_privs`, is inherited by fork and
Linux exec, and is snapshotted into rings created later. Ring snapshots do not
change when the task subsequently stacks another filter.

The permanent `bpf_filter_shared` case in
`tests/sys/kern/squeue_options.c` covers metadata and reserved-field
validation, length and strict payload negotiation, copyin/copyout faults,
invalid and out-of-range programs, native-endian context loads, filter
stacking, `DENY_REST`, all four payload-bearing opcode families, ordering
before descriptor lookup, concurrent registration/submission, fork and exec
inheritance, privilege denial and `no_new_privs`, snapshot isolation, close and
thread teardown, and post-error ring health. The native and freestanding Linux
binaries compile with `-Wall -Wextra -Werror`.

The final amd64 WITNESS/INVARIANTS ZFS-root QEMU gate used source checkpoint
`392999caf15`. The focused gate passed 20 native and 20 Linux executions. The
full gate passed 192 cases three times through each ABI, 1,152 executions total,
with 192 unique names in every ABI/round slice. All five resource counters
returned to zero after every round, no recognized kernel diagnostic occurred,
ZFS was healthy, shutdown synchronized all buffers, and QEMU exited zero after
37 minutes 26 seconds. The accepted focused and full console SHA-256 values are
`7c65ecedfbd19513407d6d674efa3998da53177892680febcaff2d19e4b2b643` and
`223e3a07550cba81e9e2b0a855b4c7ee4076a235c984f002b5d9c9a24cdc2e1c`.
The tested guest kernel, `linux_common.ko`, and `linux64.ko` hashes are
`0844e94a14d42e983ae1b1fe08be3d20622e8842f6c68a462cbbd8ac339ef678`,
`42f348209d535b27240a3afa894936e5bc0f87cd46c88d61f8425f2fce124876`, and
`ace22c37ca1b1c7feda779a5643a6f20a02c88785dad0a0f9a42b19887f95ed2`.
The accepted native and Linux test binary hashes are
`9a4aac4d62f0298ce4e92c7ce1f5d888263d2e26de90ebef91ba376c05261011` and
`770a3d6623d82d49119c9954f5d1fc12742b458afd1b1c0128a35f93af0f33fc`.
Compact evidence is retained in `/tmp/iouring-bpf-20260924/evidence`. Arm64
runtime remains waived for this architecture-neutral phase. No candidate
kernel or module was installed or loaded on the host.

## 2026-09-24: io_uring NAPI registration ABI

Shared squeue implements `IORING_REGISTER_NAPI` and
`IORING_UNREGISTER_NAPI` as per-ring configuration state. It matches Linux's
previous-state copyout, 10 ms timeout cap, boolean preference, dynamic/static
tracking modes, static ID add/delete results, IOPOLL rejection, optional
unregister output and argument validation. FreeBSD network drivers have no
Linux NAPI ID or busy-poll callback interface, so the stored setting remains an
advisory latency hint and does not change ordinary socket readiness or
completion correctness.

The permanent `napi_register_shared` test covers both frontends, replacement
and query behavior, timeout clamping, static add/delete and duplicate/missing
IDs, repeated unregister, malformed counts, null and invalid pointers,
read-only output, reserved bytes, invalid operation and tracking values, failed
copyout state preservation, IOPOLL exclusion, ring close and repeated setup.
Both test binaries compile with `-Wall -Wextra -Werror`; the GENERIC-DEBUG
kernel and Linux modules build with `-Werror`. The focused amd64
WITNESS/INVARIANTS ZFS-root QEMU gate passed 20 native and 20 Linux executions,
reported a healthy pool, synchronized all buffers and exited zero. Arm64
runtime remains waived for this architecture-neutral phase. No candidate
kernel or module was installed or loaded on the host.
