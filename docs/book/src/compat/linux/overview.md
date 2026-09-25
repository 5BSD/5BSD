# Linux Emulation

The Linuxulator is the kernel's Linux ABI: a system-call translation layer that lets unmodified x86-64 Linux ELF binaries run as ordinary 5BSD processes. 5BSD ships it on by default, 64-bit only, and has extended it from the FreeBSD baseline of roughly 270 working x86-64 syscalls to 334 functional handlers over the full table through slot 472, plus a native completion-ring engine that Linux `io_uring` rides on. The reason 5BSD invests here is architectural rather than convenience: every Linux syscall is translated into native kernel operations before it executes, so the MAC framework, capability mode, coalitions and endpoint security police Linux code from beneath a boundary the Linux program cannot see. There are no Linux-specific security hooks to maintain and nothing for a Linux exploit to attack through.

This chapter says what is in scope, how the table is counted, which feature groups were added, how the ABI is switched on, what a Linux process sees on disk, and what the correctness bar is. The following chapters cover [the syscall surface](syscalls.md), [io_uring and squeue](io-uring.md), [the procfs and sysfs view](procfs-sysfs.md), [sandboxing and debugging](sandboxing.md) and [which applications actually run](running-apps.md).

## Scope: amd64 Linux64 only

5BSD is a 64-bit-only platform (`nooptions COMPAT_FREEBSD32`, no `LIB32`), and the Linux ABI follows suit. The `linux64` module is the only Linux image activator loaded; the 32-bit `linux` module is neither built into images nor loaded by `rc.d/linux`, and `rc.d/linux` skips the `kern.elf32.fallback_brand` sysctl because the node does not exist. The arm64 Linux64 tables are regenerated for parity so the build stays consistent, but every qualification claim in this Part is for amd64 Linux64 unless a document says otherwise; arm64 and the vestigial linux32 tables lag (rseq, for instance, returns `ENOSYS` there).

## The syscall table, counted honestly

`sys/amd64/linux/syscalls.master` names 386 slots between 0 and 472 (the range 337 to 423 is 87 unnamed holes, not syscalls). `docs/linuxulator-syscall-coverage.md` classifies each named slot with a fixed vocabulary, and the book uses the same words:

| Status | Meaning | Count |
|---|---|---:|
| STD-real | a handler or native alias exists; it may implement only part of the Linux contract | 334 |
| DUMMY | declared STD but backed by a `DUMMY()` stub that logs once per process and returns `ENOSYS` | 36 |
| STUB-reject | a hand-written handler that only rejects requests (`seccomp`) | 1 |
| UNIMPL-ancient | deliberately absent: removed from Linux long ago or x86-64 relics (`uselib`, `create_module`, `epoll_ctl_old`, ...) | 15 |

Slot 472 is `fchroot`, the last named entry. The option-level audit in `docs/linuxulator-option-review.md` is done against the Linux 7.3 uapi headers, and the reference guests used to check behaviour are Linux 6.18.35 and 7.1.5. Two cautions apply to every number in this Part. A handler being present is not evidence that every flag of that call works; the option review tracks flags individually with its own vocabulary (mapped, no-op-hint, rejected-correctly, rejected-unimplementable, BUG, GAP). And the counts describe dispatch, not conformance.

The 36 DUMMY stubs plus `seccomp` plus four partial handlers make the 41-call remaining-work queue in `docs/linuxulator-missing-syscalls-handoff.md`; [System Calls](syscalls.md) lists them.

## What was added

Each of the following groups has its own row in the divergence inventory (`docs/5bsd-inventory.md`, section 6) naming the files, the design document and the test programs that prove it.

| Group | One line |
|---|---|
| Process and pidfd | `pidfd_open`, `pidfd_send_signal`, `pidfd_getfd`, `CLONE_PIDFD`, `waitid(P_PIDFD)`, `SO_PEERPIDFD`; a new passive file type, not a FreeBSD process descriptor |
| futex and futex2 | `futex_wait`, `futex_wake`, `futex_requeue`, `futex_waitv` over per-address umtx entries; CMP_REQUEUE and CLOCK_REALTIME |
| Files and VFS | `openat2` with `RESOLVE_*`, `execveat`, `fchmodat2`, `*xattrat`, `statx` mount ids, `splice`/`tee`/`vmsplice`, `preadv2`/`pwritev2` with `RWF_*`, `cachestat`, `statmount`/`listmount`, `fallocate` hole punch, OFD locks, `mseal`, `fchroot`, `FS_IOC` flags, one-way pipes |
| Memory | `madvise` COLD/PAGEOUT/MERGEABLE mapping, `MAP_FIXED_NOREPLACE`/`MAP_POPULATE`/`MAP_LOCKED`, `mremap`, `mlock2`, `mlockall`, `remap_file_pages`, `process_madvise`, protection keys, single-node NUMA policy bookkeeping |
| Signals | `signalfd`/`signalfd4` as their own file type over `kern_sigtimedwait`, `rt_sigqueueinfo`, sigaction options |
| ptrace | `PTRACE_SEIZE`/`INTERRUPT`/`LISTEN`, GETREGSET/SETREGSET for GPR, x87/SSE, XSAVE, debug registers, `ARCH_PRCTL`, sigmask, rseq and ioperm regsets; fork and exec event messages |
| rseq | per-thread registration, auxv advertisement, critical-section abort on switch and signal via a new `sysentvec.sv_schedswitch` hook |
| x86 machdep | `modify_ldt`, `ioperm`, `iopl` privilege, `arch_prctl` XCOMP/LAM/shadow-stack answers, `readahead`, `restart_syscall` |
| Time, sched, misc | `adjtimex`/`clock_adjtime`, `sched_setattr`/`getattr`, `membarrier`, `vhangup`, `unshare` CLONE_FS subset, persistent `personality`, `prctl` GET_AUXV/MDWE/CAP_AMBIENT, `kcmp`, `getrandom` GRND_INSECURE |
| Swap and quota | `swapon` with priority and discard flags, `swapoff`, `quotactl`/`quotactl_fd` subset on ZFS |
| perf_event_open | event-fd backend for current-thread software counters; hardware, sampling and rings rejected |
| Legacy AIO | `io_setup`/`destroy`/`submit`/`getevents`/`cancel` with a Linux context and mmap ring over native AIO |
| Sockets | abstract `AF_UNIX` (binary names, autobind, VNET and prison isolated), `AF_VSOCK`, `SO_COOKIE`, `SOL_UDP`, peer names, multicast source filters, recvmsg flag translation |
| Netlink | `NETLINK_SOCK_DIAG` INET and UNIX dumps, `NETLINK_KOBJECT_UEVENT` with real interface add/remove events |
| linprocfs and linsysfs | cgroup, cpuset, fd, fdinfo, comm, mem, mountinfo, auxv, `task/<tid>`, `/proc/net/*`, CPU topology, net class and statistics, transparent-hugepage size |
| FUSE and inotify | per-open FUSE handles, remote flock, notify-store coherence; Linux inotify over native `vfs_inotify` with open-path identity |
| squeue and io_uring | the native completion-ring engine and its Linux front end: 65 opcodes and 38 register commands dispatched |

## How it is enabled

The defaults already turn everything on; the table shows the knobs so an operator can turn it off or tune it.

| Where | Setting | Default | Effect |
|---|---|---|---|
| `/boot/loader.conf` (`stand/defaults/loader.conf`) | `linux_common_load`, `linux64_load` | `YES` | load `linux_common.ko` and `linux64.ko` at boot |
| `/etc/rc.conf` (`libexec/rc/rc.conf`) | `linux_enable` | `YES` | run `rc.d/linux`: load `linux64` if needed, plus `pty`, `fdescfs`, `linprocfs`, `linsysfs`; set `kern.elf64.fallback_brand=3` so unbranded ELF files run as Linux |
| `/etc/rc.conf` | `linux_mounts_enable` | `YES` | mount the Linux pseudo-filesystems under the emulation root |
| sysctl | `compat.linux.emul_path` | `/compat/linux` | the emulation root used for path translation |
| sysctl, per jail | `compat.linux.osrelease`, `osname`, `oss_version` | `5.15.0`, `Linux` | the kernel identity reported to Linux programs; writable per prison for Linux jails |
| sysctl | `compat.linux.setid_allowed`, `preserve_vstatus`, `map_sched_prio`, `dummy_rlimits`, `ignore_ip_recverr`, `default_stacksize`, `default_openfiles`, `debug` | see linux(4) | behaviour knobs, all documented in linux(4) |
| sysctl | `compat.linux.aio.max_wired_pages` | see linux_aio.c | ceiling on wired legacy-AIO ring pages |
| sysctl | `kern.squeue.*` | see squeue(2) | worker-pool and wired-memory ceilings for io_uring and squeue rings |

`rc.d/linux` is a system unit like any other rc script under 5BSD; see [rc and service(8)](../rc-and-service.md) for how switchboard runs `/etc/rc`.

## The /compat/linux layout

Path translation makes a Linux process look under `compat.linux.emul_path` first and fall back to `/`: opening `/etc/passwd` tries `/compat/linux/etc/passwd`, then `/etc/passwd`. That is how a Linux program loads Linux shared libraries instead of the identically named native ones. With `linux_mounts_enable`, `rc.d/linux` populates the pseudo-filesystems (each with `nocover`):

| Path | Mount | Notes |
|---|---|---|
| `/compat/linux/proc` | linprocfs | the Linux process filesystem, see [procfs and sysfs](procfs-sysfs.md) |
| `/compat/linux/sys` | linsysfs | Linux kernel-object view |
| `/compat/linux/dev` | devfs | the native device tree |
| `/compat/linux/dev/fd` | fdescfs with `linrdlnk` | `/dev/fd/N` and `/proc/self/fd` readlink semantics |
| `/compat/linux/dev/shm` | tmpfs, mode 1777 | POSIX shared memory objects |

The userland itself (`/compat/linux/bin`, `/lib`, `/usr`) is not part of the base system. linux(4) points at the `emulators/linux_base-c7` package or a debootstrap; the reference userland the Linuxulator is developed against is a Rocky Linux 9 minimal root, and the test corpus uses Alpine's musl-linked busybox staged at `/compat/linux/bin/busybox` with its loader in `/compat/linux/lib`. Linux jails put a whole distribution root under a jail path and set `linux.osrelease` on the prison; see [Jails](../jails.md). Linux pseudo-filesystems are on the `mac_capability_mount` whitelist (`sys/dev/mac_capability/mac_capability_mount_proto.h`), so a supervised service can assemble a Linux jail root without ambient mount privilege.

## The correctness bar: the QEMU ZFS-root gate

No Linuxulator change counts as done because it compiles, or because a happy-path test passes on the development host. `docs/linuxulator-implementation-gate.md` is the acceptance contract: every syscall, option and shared kernel primitive must have a per-contract record linking it to named positive and negative cases, and those cases must pass inside a disposable amd64 ZFS-root QEMU guest running the exact candidate kernel and modules, with INVARIANTS and WITNESS, on at least two vCPUs, with the same portable cases run against a real Linux reference guest. UFS-root runs are supplemental evidence only; a UFS-root guest fails the gate. The runner (`tools/test/linuxulator/qemu-gate.py`) fails closed: a missing result, a timeout, a recognized kernel diagnostic in the console, a leaked tracked resource (`kern.squeue.live_requests`, wired pages, registered files, issuer tokens must all return to zero) or an unhealthy pool fails the run.

That discipline is why this Part distinguishes three evidence classes. **Gate-passed** means a named contract passed the full VM matrix and a Linux oracle. **Claimed** means source review or a host-side run only. **Not qualified** means the documents say so explicitly. [Running Real Applications](running-apps.md) sorts the workloads by those classes.

## What is explicitly not qualified

Electron and Chromium are the named gap. `docs/linuxulator-production-readiness.md` records that no Electron VM execution has been completed, that the Chromium sandbox installs seccomp filters which the committed `linux_seccomp` handler rejects, and that a launch with `--no-sandbox` is a testing switch, not a qualification. Native FreeBSD Electron from Ports is a separate track that does not exercise the Linuxulator. Docker, Steam, systemd and Wine have never been claimed; the namespace, new-mount-API, keyring, BPF and syscall-user-dispatch projects they would need are on the missing-syscalls queue or listed as separate future projects in the implementation gate.

Status: seccomp and Landlock exist as in-progress working-tree files and are not inventoried or described in this book as shipped; see [Sandboxing and Debugging](sandboxing.md).

## Where to look

| Question | Document |
|---|---|
| Is syscall N dispatched, and how | `docs/linuxulator-syscall-coverage.md` section 5 |
| Which flags of an implemented call work | `docs/linuxulator-option-review.md`, `docs/linuxulator-next-phase-options.md` |
| What is still missing, and who owns it | `docs/linuxulator-missing-syscalls-handoff.md` |
| The acceptance contract and every batch's evidence | `docs/linuxulator-implementation-gate.md` |
| Filesystem, procfs, FUSE and discovery batches | `docs/linuxulator-filesystems-handoff.md`, `-remaining-compat.md`, `-compat-next.md`, `-proc-extra.md` |
| Behaviour knobs | linux(4), linprocfs(4), linsysfs(4), squeue(2) |
