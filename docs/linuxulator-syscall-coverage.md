# Linuxulator syscall coverage (x86_64)

Status of the 5BSD Linux compatibility layer against the Linux 7.3 x86_64
syscall table, the option-level coverage of the syscalls that are
implemented, what the 2026-09-11 batch changed, and a ranked list of what is
left.  This is the document the next person starts from.

Sources: `sys/amd64/linux/syscalls.master` (the table), `sys/compat/linux/`
(machine-independent implementations), `sys/amd64/linux/linux_*machdep.c`
(amd64-only), `sys/compat/linux/linux_dummy.c` and
`sys/amd64/linux/linux_dummy_machdep.c` (stubs).  Upstream reference:
Linux 7.3 `arch/x86/entry/syscalls/syscall_64.tbl`,
`include/uapi/asm-generic/unistd.h`, `include/linux/syscalls.h`.

Status vocabulary used throughout:

| status | meaning |
|---|---|
| STD-real | declared STD in the table and backed by a real implementation |
| DUMMY | declared STD, but the implementation is a `DUMMY()` stub: logs "syscall X not implemented" once per process and returns ENOSYS |
| UNIMPL-ancient | declared UNIMPL on purpose: removed from Linux long ago (`uselib`, `create_module`, ...) or x86-64-only relics (`epoll_ctl_old`) |
| ABSENT | not in our table at all; falls to the unknown-syscall path |

## 1. Totals

| | before this batch | after this batch |
|---|---:|---:|
| upstream x86_64 syscalls (0..472, minus holes) | 386 | 386 |
| STD-real | 276 | 299 |
| DUMMY | 74 (+3 x86 `sysfs`/`quotactl`/`signalfd`) | 72 (incl. those 3) |
| UNIMPL-ancient | 15 | 15 |
| ABSENT | 21 | 0 |

The 21 previously absent numbers (335 `uretprobe`, 336 `uprobe`, 454-472)
now all have table entries on amd64, amd64/linux32, i386 and arm64 (the
`uprobe` pair is amd64-only, as upstream); 7 of them are implemented
(`futex_wake`, `futex_wait`, `futex_requeue`, `setxattrat`, `getxattrat`,
`listxattrat`, `removexattrat`) and 14 are clean named DUMMY stubs.

## 2. Empirical hit list (this box, since boot, before the batch)

Linux binaries here are mostly Claude Code's Bun runtime.

| hits | syscall / option | before | now |
|---:|---|---|---|
| 13 | `madvise(MADV_PAGEOUT=21)` | "unsupported madvise behav 21", EINVAL | mapped to FreeBSD `MADV_DONTNEED` (deactivate, contents preserved); `MADV_COLD` likewise |
| 4 | `pidfd_open` | DUMMY, ENOSYS | implemented (new pidfd file type), plus `pidfd_send_signal`, `pidfd_getfd`, `waitid(P_PIDFD)`, `CLONE_PIDFD` |
| 3/2 | `pwritev2`/`preadv2` | fixed 1024bbd7b6d (unflagged only) | unchanged |
| 6 | `prctl(PR_SET_VMA)` | quieted f84182f26a9 | unchanged |

## 3. What this batch implemented, with the semantics chosen

### 3.1 madvise (`sys/compat/linux/linux_mmap.c`)

| advice | before | now | why |
|---|---|---|---|
| MADV_COLD (20) | EINVAL + log | FreeBSD `MADV_DONTNEED` | FreeBSD DONTNEED deactivates clean pages and launders dirty ones without discarding anything, which is exactly a content-preserving reclaim hint. Linux MADV_DONTNEED (discard) is a different case and stays on `linux_madvise_dontneed()`. |
| MADV_PAGEOUT (21) | EINVAL + log | FreeBSD `MADV_DONTNEED` | same; the test writes a pattern, advises, and reads it back (fails against a discard mapping) |
| MADV_DONTNEED_LOCKED (24) | EINVAL + log | `linux_madvise_dontneed()` | identical to DONTNEED except allowed on locked pages; ours rejects wired ranges, i.e. merely stricter |
| MADV_MERGEABLE (12) | EINVAL + log | 0 | KSM hint; we never merge, so a no-op is a correct implementation of "advise" |
| MADV_UNMERGEABLE (13) | 0 | 0 | |
| MADV_HUGEPAGE (14) | 0 | 0 | superpages are always on |
| MADV_NOHUGEPAGE (15) | EINVAL | EINVAL (no log) | cannot stop superpage promotion per range; Linux without THP returns EINVAL too |
| MADV_COLLAPSE (25) | EINVAL + log | EINVAL | no synchronous collapse |
| MADV_POPULATE_READ/WRITE (22/23) | EINVAL + log | EINVAL | Linux guarantees the range is faulted in; WILLNEED is only a hint, so mapping would weaken |
| MADV_GUARD_INSTALL/REMOVE (102/103) | EINVAL + log | EINVAL | no guard-region facility |
| MADV_REMOVE (9) | EINVAL + log | EOPNOTSUPP | hole punch with guaranteed zero-fill; MADV_FREE does not guarantee zeros and madvise has no deallocation path for swap objects/tmpfs; EOPNOTSUPP is what Linux gives for an object that cannot do it |
| MADV_HWPOISON/SOFT_OFFLINE (100/101) | EINVAL + log | EPERM unprivileged, EINVAL privileged | Linux requires CAP_SYS_ADMIN; not supported at all |
| -1 (BoringSSL stub probe) | EINVAL | EINVAL | unchanged, still not logged |
| any advice, unaligned start or wrapping range | rounded down (kern_madvise) for the mapped advices | EINVAL | Linux do_madvise() checks this for every advice before looking at the mapping |

### 3.2 pidfd family (`sys/compat/linux/linux_pidfd.c`, new)

Design and its limits:

* **Not a FreeBSD process descriptor.** `procdesc(4)` is a capability that
  changes the described process: at most one per process, only creatable by
  `pdfork(2)`, the process becomes invisible to `waitpid(2)`, and the last
  close SIGKILLs it.  A Linux pidfd is a passive reference to an existing
  process that must not alter reaping, SIGCHLD or lifetime, so it is its own
  file type (`DTYPE_LINUXPIDFD`) holding only the identity of the process.
* **Identity / pid-reuse guard.** FreeBSD has no pid generation counter.  A
  pidfd records the `struct proc` pointer (comparison key only, never
  dereferenced without validation; `struct proc` is type-stable), the pid,
  and `p_stats->p_start` (microsecond uptime at fork).  All three must match
  on every lookup; a later process reusing the pid has a different start
  time, and a recycled proc slot in `PRS_NEW` is never accepted.
* **Exit readiness ordering.** Linux makes a pidfd readable exactly when the
  process is reapable.  The `process_exit` eventhandler fires early in
  `exit1()`, before the process is a zombie, so waking there would let a
  waiter's `wait4(WNOHANG)` return 0 (an edge-triggered epoll user would
  then miss the exit).  The eventhandler therefore only queues a task; the
  task `cv_wait`s on the process' `p_pwait`, which `exit1()` broadcasts with
  the process lock held immediately before setting `PRS_ZOMBIE`, and only
  then marks the pidfd readable (POLLIN|POLLRDNORM, kqueue EVFILT_READ so
  epoll works).  A waiter's subsequent `wait4()` always finds the zombie.
  Works for native FreeBSD children too (Bun spawns `/bin/sh` etc.).
* `pidfd_open(pid, flags)`: `PIDFD_NONBLOCK` honoured (visible via
  `F_GETFL`); `PIDFD_THREAD` and other bits EINVAL; pid <= 0 EINVAL; a
  non-leader thread id EINVAL (Linux: not a thread-group leader); unknown
  pid ESRCH; a zombie may be opened and is immediately readable; the fd is
  always close-on-exec; `read(2)` on it is EINVAL as on Linux.
* `pidfd_send_signal(fd, sig, info, flags)`: flags 0 or
  `PIDFD_SIGNAL_THREAD_GROUP` are the process case; `PIDFD_SIGNAL_PROCESS_GROUP`
  signals the group with that id via `kern_kill(-pid)` (queued siginfo cannot
  be carried on that path, SI_USER info is sent); `PIDFD_SIGNAL_THREAD` EINVAL
  (no thread pidfds).  `info`: si_signo must equal sig (EINVAL); si_code >= 0
  or SI_TKILL from another process EPERM.  Signalling a zombie succeeds (0),
  a reaped process is ESRCH.  Permission is `p_cansignal()`.
* `pidfd_getfd(fd, targetfd, flags)`: flags != 0 EINVAL; requires
  `p_candebug()` over the target (FreeBSD's PTRACE_MODE_ATTACH equivalent),
  EPERM otherwise; uses `fget_remote()` and installs the copy close-on-exec.
  ESRCH once the target has exited (its table is gone).
* `waitid(P_PIDFD, fd, ...)`: resolves the fd to its pid and waits as P_PID;
  EBADF if not a pidfd; ECHILD after the reap, as Linux.
* `clone(2)`/`clone3(2)` `CLONE_PIDFD`: the pidfd is installed and its number
  written (to `parent_tidptr` for legacy clone, `clone_args.pidfd` for
  clone3) while the child is still RFSTOPPED; `CLONE_PIDFD|CLONE_PARENT_SETTID`
  on legacy clone is EINVAL as on Linux; `CLONE_PIDFD|CLONE_THREAD` is EINVAL
  (thread pidfds not supported).
* `process_madvise(pidfd, ...)`: only the calling process; other targets get
  EPERM (cross-process madvise would need the remote vm_map plus a
  PTRACE_MODE_READ check).  See 3.5.
* Known limits: no `PIDFD_THREAD`; `fstat()` returns a synthetic anonymous
  inode; a pidfd passed over a unix socket to a native process keeps its
  semantics but `procstat` shows it as a process descriptor of that pid.

### 3.3 futex (`sys/compat/linux/linux_futex.c`)

* `FUTEX_CMP_REQUEUE` was already implemented on `umtxq_requeue()` (it moves
  waiters); the claim that it was unsupported was wrong.  `FUTEX_REQUEUE`
  was rejected for every brand but musl and logged; it is now the Linux
  definition (CMP_REQUEUE without the compare) for all brands.
* Bugs found and fixed in the process: `nr_requeue == 0` requeued every
  waiter (worked around above `umtxq_requeue()`, which cannot express
  "move none"); a same-chain double lock / ABBA between the two futex
  chains (now locked once or in address order); a VM object refcount skew
  when requeueing shared futexes (`umtxq_requeue()` copies the key without
  transferring the object reference); `FUTEX_WAIT_BITSET` with bitset 0
  slept forever instead of EINVAL; an absolute deadline of {0,0} became "no
  timeout"; `FUTEX_WAIT|FUTEX_CLOCK_REALTIME` (Linux >= 5.14) was ENOSYS.
* futex2: `futex_wait`(455)/`futex_wake`(454)/`futex_requeue`(456) for
  `FUTEX2_SIZE_U32` (+`FUTEX2_PRIVATE`), absolute timeouts on
  CLOCK_MONOTONIC/CLOCK_REALTIME; U8/U16/U64 EINVAL (as Linux today);
  `FUTEX2_NUMA`/`FUTEX2_MPOL` EINVAL (different word layout, logged once);
  val/mask that do not fit 32 bits EINVAL; `futex_wake` with nr <= 0 wakes
  nobody (strict, unlike legacy FUTEX_WAKE).  `futex_waitv`(449) is
  implemented since 2026-09-12 (see the option review, §7a).

### 3.4 Extended attributes (`sys/compat/linux/linux_xattr.c`)

`setxattrat`/`getxattrat`/`listxattrat`/`removexattrat` reuse the existing
namespace mapping (`user.`/`system.`/`trusted.`/`security.` ->
`EXTATTR_NAMESPACE_*`, ENOTSUP for others).  `struct xattr_args` follows
Linux `copy_struct_from_user` rules (size < 16 EINVAL, > PAGE_SIZE or a
nonzero tail E2BIG); `at_flags` only `AT_SYMLINK_NOFOLLOW`/`AT_EMPTY_PATH`
(EINVAL otherwise); `getxattrat` `args.flags != 0` EINVAL.  FreeBSD has no
dfd-relative `kern_extattr_*_path()`, so a dfd-relative path is opened
`O_PATH|O_CLOEXEC[|O_NOFOLLOW]` and the fd route is used; the VFS extattr
code applies the same `VOP_ACCESS` checks on both routes.

### 3.5 Tier-2 mappings

| syscall | semantics chosen |
|---|---|
| `readahead` (amd64) | `posix_fadvise(POSIX_FADV_WILLNEED)`; EBADF if not open for reading; EINVAL for anything that is not a regular file (ESPIPE/ENODEV translated); negative offset is a no-op 0 as on Linux |
| `setfsuid`/`setfsgid` | FreeBSD has no fsuid: return the current euid/egid and change nothing, which is exactly the "previous value" Linux returns both on success with the same value and on failure |
| `mlock2` | flags & ~MLOCK_ONFAULT EINVAL; ONFAULT is a strict subset of eager wiring, so `kern_mlock()` honours it |
| `fchmodat2` | `AT_SYMLINK_NOFOLLOW` and `AT_EMPTY_PATH` only; NOFOLLOW on a symlink target is EOPNOTSUPP (Linux symlinks have no mode) |
| `restart_syscall` (amd64) | EINTR (`do_no_restart_syscall`) |
| `execveat` | empty path + AT_EMPTY_PATH executes dfd (fexecve); absolute path or AT_FDCWD is plain execve; otherwise the file is opened `O_EXEC|O_CLOEXEC` relative to dfd (`O_NOFOLLOW` for AT_SYMLINK_NOFOLLOW, ELOOP) and executed by descriptor.  The fexecve script limitation (`#!` interpreter sees a closed /dev/fd/N -> ENOENT) is reproduced, not papered over; here it also applies to the dfd-relative case where Linux would pass /dev/fd/dfd/name |
| `openat2` | strict flag validation (unknown open or resolve bits EINVAL; mode rules; `O_TMPFILE` EOPNOTSUPP; size < 24 EINVAL, larger with nonzero tail E2BIG).  `RESOLVE_BENEATH` -> `O_RESOLVE_BENEATH` (same contract; escape reported as EXDEV like Linux).  `RESOLVE_IN_ROOT` (clamps `..`/absolute at dirfd), `RESOLVE_NO_SYMLINKS` (every component; `O_NOFOLLOW` covers only the last), `RESOLVE_NO_MAGICLINKS`, `RESOLVE_NO_XDEV`: EINVAL, never weakened.  `RESOLVE_CACHED`: EAGAIN (documented, callers retry without it) |
| `adjtimex`/`clock_adjtime` | `kern_ntp_adjtime()` with MOD_*/STA_* (same values, checked at compile time); returns the clock state; `ADJ_OFFSET_SINGLESHOT`/`SS_READ` via `kern_adjtime()`; `ADJ_TICK`/`ADJ_SETOFFSET` EINVAL (no native equivalent); non-root with modes != 0 EPERM; `clock_adjtime` only CLOCK_REALTIME, other known clocks EOPNOTSUPP, dynamic (fd) clocks EINVAL.  32-bit ABI uses the 32-bit `struct timex` layout |
| `sched_setattr`/`sched_getattr` | SCHED_OTHER/FIFO/RR with the same priority mapping as sched_setscheduler; SCHED_BATCH/IDLE/DEADLINE/EXT EINVAL (mapping them to OTHER would change semantics); size/E2BIG rules; getattr flags != 0 EINVAL; `SCHED_FLAG_KEEP_POLICY`/`KEEP_PARAMS` honoured; `RESET_ON_FORK`/`RECLAIM`/`DL_OVERRUN`/`UTIL_CLAMP_*` EINVAL (no per-thread reset bit; accepting would leave children real-time) |
| `process_madvise` | flags != 0 EINVAL; vlen <= UIO_MAXIOV; self only (any advice); another live process EPERM (or EINVAL for advice Linux would not allow remotely); returns bytes advised |
| `pkey_alloc`/`pkey_free`/`pkey_mprotect` (amd64) | FreeBSD exposes PKU through `pmap_pkru_*`/`sysarch(AMD64_PKRU_*)` but has no allocator, so the Linux per-mm allocation map lives in `linux_pemuldata.pkeys_map` (copied on fork, cleared on exec).  `pkey_alloc`: flags != 0 EINVAL, rights & ~3 EINVAL, keys 1..15, ENOSPC when exhausted or without PKU/OSPKE; initial rights written into the caller's PKRU (XSAVE area, or live WRPKRU when the thread does not own the FPU).  `pkey_free`: EINVAL if unallocated; like Linux it does not clear assignments.  `pkey_mprotect`: -1 is plain mprotect; unallocated key EINVAL; `kern_mprotect` then `pmap_pkru_set` non-persist (keys are a mapping property like a Linux VMA: munmap drops them).  Divergences: no execute-only key; new threads start with PKRU 0 rather than Linux's 0x55555554 default-deny |
| `arch_prctl` additions (amd64) | `ARCH_GET_XCOMP_SUPP/PERM/GUEST_PERM` return `xsave_mask`; `ARCH_REQ_XCOMP_PERM` only XTILEDATA (18) is requestable: 0 if the kernel saves both AMX tile components, else EOPNOTSUPP; every other known component EOPNOTSUPP (Linux has no permission entry for always-on features), EINVAL >= XFEATURE_MAX (glibc >= 2.39 probes 18 on AMX machines); `ARCH_GET_CPUID` 1, `ARCH_SET_CPUID` ENODEV; `ARCH_MAP_VDSO_*` EEXIST/EINVAL; LAM: untag mask ~0, max tag bits 0, enable ENODEV; shadow stack: status 0, enable/disable EOPNOTSUPP, unlock EINVAL |

## 4. Option-level coverage

A syscall being STD says nothing about which of its flags and commands are
honoured.  Every "unsupported ..." log site was worked through.  Status:
*mapped* (exact FreeBSD equivalent), *no-op-hint* (a pure hint, accepting it
is a correct implementation), *rejected-correctly* (the errno Linux itself
documents/returns), *rejected-unimplementable* (we cannot do it exactly, so
the honest errno rather than a silent weakening).

### 4.1 futex

| syscall | option/flag | status | reason |
|---|---|---|---|
| futex | FUTEX_REQUEUE | mapped | CMP_REQUEUE without compare, all brands |
| futex | FUTEX_CMP_REQUEUE | mapped | umtx requeue moves waiters; nr_requeue=0 fixed; EAGAIN on val3 mismatch |
| futex | FUTEX_WAIT + FUTEX_CLOCK_REALTIME | mapped | Linux >= 5.14 semantics |
| futex | FUTEX_WAIT_BITSET bitset=0 | rejected-correctly | EINVAL (was an infinite sleep) |
| futex | uaddr == uaddr2 in REQUEUE/WAKE_OP | rejected-correctly | EINVAL; a queue cannot be requeued onto itself |
| futex | FUTEX_WAIT_REQUEUE_PI / CMP_REQUEUE_PI | rejected-unimplementable | ENOSYS, unchanged |
| futex_wait | FUTEX2_SIZE_U32, FUTEX2_PRIVATE, absolute MONOTONIC/REALTIME timeout | mapped | WAIT_BITSET path |
| futex_wait/wake/requeue | FUTEX2_SIZE_U8/U16/U64 | rejected-correctly | EINVAL as Linux |
| futex_wait/wake/requeue | FUTEX2_NUMA, FUTEX2_MPOL | rejected-unimplementable | EINVAL; NUMA word layout |
| futex_wait | other clockid with a timeout | rejected-correctly | EINVAL |
| futex_wake | nr <= 0 | mapped | wakes nobody (strict futex2) |
| futex_requeue | 2-entry waitv, flags=0 | mapped | CMP_REQUEUE with waiters[0].val |
| futex_waitv | 1..128 U32 entries, absolute MONOTONIC/REALTIME timeouts | mapped (2026-09-12) | one umtx entry per address sharing a wait channel (`uq_wchan`) |

### 4.2 madvise

See section 3.1.

### 4.3 xattr, epoll, sigaction, clone3

| syscall | option/flag | status | reason |
|---|---|---|---|
| *xattrat | dfd + relative path | mapped | O_PATH open relative to dfd, then fd-based extattr; same VOP_ACCESS checks |
| *xattrat | AT_EMPTY_PATH | mapped | "" or NULL path operates on dfd |
| *xattrat | AT_SYMLINK_NOFOLLOW | mapped | NOFOLLOW lookup / O_PATH\|O_NOFOLLOW |
| *xattrat | other at_flags | rejected-correctly | EINVAL |
| setxattrat/getxattrat | struct size rules | rejected-correctly | EINVAL < 16, E2BIG > PAGE_SIZE or nonzero tail |
| getxattrat | args.flags != 0 | rejected-correctly | EINVAL |
| epoll_ctl | EPOLLEXCLUSIVE | no-op-hint | kqueue wakes every instance; "one or more" is conforming; Linux MOD/nested/OK_BITS rules enforced with EINVAL |
| epoll_ctl | EPOLLWAKEUP | no-op-hint | Linux drops it without CAP_BLOCK_SUSPEND |
| epoll_ctl | EPOLLET / EPOLLONESHOT | mapped | EV_CLEAR / EV_DISPATCH |
| epoll_ctl | EPOLLRDBAND/WRBAND/MSG, undefined bits | rejected-unimplementable | kqueue cannot deliver them; EINVAL + log |
| rt_sigaction | SA_RESTORER | mapped | accepted; not reported in oldact (no storage for Linux-only bits) |
| rt_sigaction | SA_UNSUPPORTED, SA_INTERRUPT, unknown bits | mapped | masked like Linux `UAPI_SA_FLAGS`, never reported back |
| rt_sigaction | SA_EXPOSE_TAGBITS | no-op-hint | no pointer tagging; not reported back |
| clone3 | CLONE_NEWTIME | rejected-unimplementable | EINVAL, as Linux without CONFIG_TIME_NS |
| clone3 | CLONE_INTO_CGROUP | rejected-unimplementable | EINVAL if usize < 88, else EBADF (no cgroup2 fd can exist) |
| clone3 | set_tid | rejected-unimplementable | Linux validation (EINVAL), EPERM unprivileged, ENOSYS privileged |
| clone3 | oversized struct with nonzero tail | rejected-correctly | E2BIG |
| clone/clone3 | CLONE_PIDFD | mapped | see 3.2 |
| clone | CLONE_PIDFD\|CLONE_PARENT_SETTID | rejected-correctly | EINVAL |

### 4.4 pkeys, readahead, restart_syscall, arch_prctl

| syscall | option/flag | status | reason |
|---|---|---|---|
| pkey_alloc | flags=0, rights in DISABLE_ACCESS\|DISABLE_WRITE | mapped | per-process map; caller's PKRU set |
| pkey_alloc | flags != 0 / rights & ~3 | rejected-correctly | EINVAL |
| pkey_alloc | no PKU/OSPKE | rejected-correctly | ENOSPC per pkey_alloc(2) |
| pkey_free | allocated key | mapped | releases the number only (Linux pitfall preserved) |
| pkey_free | unallocated / out of range | rejected-correctly | EINVAL |
| pkey_mprotect | pkey=-1 | mapped | plain mprotect path |
| pkey_mprotect | allocated key | mapped | kern_mprotect then pmap_pkru_set (non-persist) |
| pkey_mprotect | unallocated key / unaligned / no PKU | rejected-correctly | EINVAL |
| readahead | regular file | mapped | fadvise WILLNEED |
| readahead | pipe/socket/dir/device | rejected-correctly | EINVAL |
| readahead | not readable / bad fd | rejected-correctly | EBADF |
| restart_syscall | - | rejected-correctly | EINTR |
| arch_prctl | GET_XCOMP_SUPP/PERM/GUEST_PERM, REQ_XCOMP_PERM(18), GET_CPUID | mapped | see 3.5 |
| arch_prctl | REQ_XCOMP_PERM for x87/SSE/AVX/other known components | rejected-correctly | EOPNOTSUPP as Linux; >= XFEATURE_MAX EINVAL |
| arch_prctl | SET_CPUID | rejected-unimplementable | ENODEV |
| arch_prctl | MAP_VDSO_32/64, MAP_VDSO_X32 | rejected-correctly | EEXIST / EINVAL |
| arch_prctl | LAM ENABLE_TAGGED_ADDR | rejected-unimplementable | ENODEV |
| arch_prctl | SHSTK_ENABLE/DISABLE | rejected-unimplementable | EOPNOTSUPP |

### 4.5 file syscalls (openat2, fchmodat2, execveat, renameat2, fcntl, faccessat2, fchownat, copy_file_range, inotify)

| syscall | option/flag | status | reason |
|---|---|---|---|
| openat2 | O_CREAT mode, O_EXCL, O_PATH(+O_CLOEXEC/O_NOFOLLOW), O_DIRECTORY, O_NOFOLLOW | mapped | strict validation first (unknown open/resolve bits, high flag bits, mode without O_CREAT, mode & ~07777, O_PATH with non-O_PATH flags, O_DIRECTORY\|O_CREAT: EINVAL) |
| openat2 | struct open_how size rules | rejected-correctly | size < 24 or 0 EINVAL, > PAGE_SIZE or nonzero tail E2BIG, NULL EFAULT |
| openat2 | O_TMPFILE | rejected-unimplementable | EOPNOTSUPP (no unnamed files); without O_DIRECTORY or write access EINVAL as Linux |
| openat2 | RESOLVE_BENEATH | mapped | O_RESOLVE_BENEATH; ".." staying inside dirfd ok, escaping ".." / absolute path / absolute symlink target (any component) EXDEV |
| openat2 | RESOLVE_IN_ROOT, RESOLVE_NO_SYMLINKS, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_XDEV | rejected-unimplementable | EINVAL, never weakened (NO_SYMLINKS even on a symlink-free path); BENEATH\|IN_ROOT EINVAL (exclusive) |
| openat2 | RESOLVE_CACHED | rejected-correctly | EAGAIN, callers retry without it |
| fchmodat2 | flags 0 / AT_SYMLINK_NOFOLLOW / AT_EMPTY_PATH | mapped | NOFOLLOW on a symlink EOPNOTSUPP (Linux symlinks have no mode); other flags EINVAL |
| execveat | AT_EMPTY_PATH + dfd, absolute path, dfd-relative name, AT_SYMLINK_NOFOLLOW | mapped | fexecve / execve / O_EXEC open relative to dfd; NOFOLLOW on a symlink ELOOP; directory with AT_EMPTY_PATH EACCES; bad dfd EBADF only when it matters; script-via-fd limitation reproduced |
| renameat2 | RENAME_NOREPLACE | mapped | EEXIST on an existing target, names untouched; ENOENT for a missing source |
| renameat2 | RENAME_EXCHANGE, RENAME_WHITEOUT | rejected-unimplementable | EINVAL: VOP_RENAME has no atomic swap / whiteout; the exclusive-flag combinations and unknown bits are EINVAL as Linux |
| fcntl | F_OFD_GETLK/SETLK/SETLKW (36-38) | rejected-unimplementable | EINVAL + log once; POSIX locks unaffected (backlog #20) |
| fcntl | F_ADD_SEALS/F_GET_SEALS: SEAL_SEAL/SHRINK/GROW/WRITE | mapped | native memfd seals; EPERM on non-sealable memfd (reports SEAL_SEAL), EINVAL on a plain file |
| fcntl | F_SEAL_FUTURE_WRITE, F_SEAL_EXEC | rejected-unimplementable | EINVAL (no native bit; backlog #21); unknown seal bits EINVAL and nothing added |
| fcntl | F_GETPIPE_SZ/F_SETPIPE_SZ | mapped | reports the native capacity; requests are rounded up to a power of two, 0 means a page, > 2^31 EINVAL, non-pipe EBADF |
| fcntl | F_GETOWN_EX/F_SETOWN_EX | mapped | F_OWNER_PID/PGRP; pid 0 clears; ESRCH for missing pid/pgrp; F_OWNER_TID EINVAL (no per-thread owner); on a pipe EINVAL like the long form |
| fcntl | F_GETSIG/F_SETSIG | mapped-partial | 0 and SIGIO accepted; any other valid signal EINVAL (cannot be honoured), invalid signal EINVAL |
| fcntl | F_DUPFD_CLOEXEC | mapped | |
| faccessat2 | AT_EACCESS, AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH | mapped | unknown flags / invalid mode EINVAL; "" without AT_EMPTY_PATH ENOENT |
| fchownat | AT_EMPTY_PATH, -1/-1 | mapped | unknown flags EINVAL; "" without AT_EMPTY_PATH ENOENT |
| copy_file_range | flags | rejected-correctly | any nonzero flags EINVAL, validated before the descriptors |
| inotify_init1 | IN_NONBLOCK, IN_CLOEXEC | mapped | unknown flags EINVAL |
| inotify_add_watch | IN_ONLYDIR, IN_MASK_ADD, IN_MASK_CREATE, IN_ISDIR in mask | mapped | MASK_ADD\|MASK_CREATE EINVAL, MASK_CREATE on an existing watch EEXIST, mask 0 / flags-only mask / unknown bits EINVAL, ONLYDIR on a file ENOTDIR |

### 4.6 misc/time (sched_attr, prctl, syslog, adjtimex, clock_adjtime, setfsuid, mlock2, process_madvise, waitid)

| syscall | option/flag | status | reason |
|---|---|---|---|
| sched_getattr | full / VER0 / larger buffer, size rewrite | mapped | reports the VER1 size (56), min rule for VER0, flags != 0 / size < VER0 / > PAGE_SIZE / NULL EINVAL, bad pid ESRCH, negative pid EINVAL |
| sched_setattr | SCHED_OTHER/FIFO/RR, sched_nice (clamped to [-20,19]), priority validation | mapped | same priority mapping as sched_setscheduler; FIFO needs privilege (EPERM) |
| sched_setattr | SCHED_FLAG_KEEP_POLICY / KEEP_PARAMS | mapped | negative policy EINVAL even with KEEP_POLICY |
| sched_setattr | SCHED_BATCH/IDLE/DEADLINE/EXT | rejected-unimplementable | EINVAL (mapping to OTHER would change semantics) |
| sched_setattr | RESET_ON_FORK, RECLAIM, DL_OVERRUN, UTIL_CLAMP_* | rejected-unimplementable | EINVAL; size rules E2BIG with size rewritten to 56; size 0 = VER0 quirk accepted |
| prctl | PR_GET/SET_TIMING, PR_GET_TSC, PR_GET/SET_SECUREBITS (default 0, set needs CAP_SETPCAP), PR_GET_TID_ADDRESS | mapped | |
| prctl | PR_SET_TSC(SIGSEGV), timer slack, THP disable, speculation control, PR_SET_MM, PR_CAPBSET_DROP | rejected-unimplementable | EINVAL (speculation control ENODEV, as an arch without it) |
| syslog | OPEN/CLOSE, SIZE_BUFFER, READ_ALL (len rules) | mapped | READ_ALL len 0 reads nothing, NULL/negative EINVAL; unknown action EINVAL |
| syslog | CONSOLE_OFF/ON/LEVEL, READ, SIZE_UNREAD, CLEAR, READ_CLEAR | rejected-correctly | EPERM unprivileged; logged once |
| setfsuid/setfsgid | any | mapped | returns the current euid/egid, changes nothing (Linux "previous value" contract) |
| mlock2 | MLOCK_ONFAULT | mapped | strict subset of eager wiring; other flags EINVAL, unlock works |
| process_madvise | self, COLD/PAGEOUT/WILLNEED, empty vector | mapped | returns bytes advised; flags != 0 / vlen > UIO_MAXIOV / unaligned / bad advice EINVAL, NULL vector EFAULT, non-pidfd EBADF |
| process_madvise | another process | rejected-unimplementable | EPERM (EINVAL for advice Linux would not allow remotely) |
| waitid | P_PIDFD, WEXITED/WNOHANG, CLD_EXITED/CLD_KILLED siginfo | mapped | non-pidfd/closed fd EBADF, options without WEXITED/WSTOPPED/WCONTINUED EINVAL, invalid idtype EINVAL, second wait ECHILD |
| adjtimex/clock_adjtime | MOD_*/STA_*, ADJ_OFFSET_SINGLESHOT/SS_READ | mapped | returns the clock state; non-root with modes != 0 EPERM |
| adjtimex/clock_adjtime | ADJ_TICK, ADJ_SETOFFSET | rejected-unimplementable | EINVAL |
| clock_adjtime | clocks other than CLOCK_REALTIME | rejected-correctly | EOPNOTSUPP for known clocks, EINVAL for dynamic (fd) clocks |

### 4.7 socket options and TIOCGPTPEER

| level | option/flag | status | reason |
|---|---|---|---|
| SOL_SOCKET | SO_TYPE, SO_ERROR, SO_RCVBUF, SO_REUSEADDR, SO_KEEPALIVE, SO_BSDCOMPAT (no-op) | mapped | |
| SOL_SOCKET | SO_RCVTIMEO_NEW/SO_SNDTIMEO_NEW (66/67) | mapped | 64-bit timeval round trip; tv_usec out of range EDOM; short optlen EINVAL; negative tv_sec = no timeout |
| SOL_SOCKET | SO_NO_CHECK | mapped-partial | 0 ok, 1 EINVAL (checksums cannot be disabled) |
| SOL_SOCKET | SO_PASSRIGHTS | mapped-partial | cannot be turned off |
| SOL_SOCKET | SO_PRIORITY, SO_BINDTODEVICE, unknown options | rejected-correctly | ENOPROTOOPT (get and set); EBADF beats everything |
| IPPROTO_IP | IP_TTL, IP_MINTTL, IP_TOS, IP_RECVTOS, IP_RECVTTL, IP_PKTINFO (recv: ifindex + dst; send: ipi_spec_dst only), IP_PROTOCOL (get only) | mapped | per-datagram IP_TOS via sendmsg; TOS outside 0..255 EINVAL; forcing an interface via IP_PKTINFO on send EINVAL |
| IPPROTO_IP | MCAST_JOIN/LEAVE_GROUP (Linux 136-byte group_req), IP_ADD/DROP_SOURCE_MEMBERSHIP (Linux member order) | mapped | short struct EINVAL; leaving a group not joined EADDRNOTAVAIL |
| IPPROTO_IP | IP_MTU_DISCOVER DO/DONT | mapped | OMIT/INTERFACE EINVAL; out of range EINVAL |
| IPPROTO_IP | IP_MULTICAST_ALL | mapped-partial | only the FreeBSD behaviour (0) accepted |
| IPPROTO_IP | IP_FREEBIND | mapped | IP_BINDANY, root only (EPERM otherwise) |
| IPPROTO_IP | IP_RECVOPTS/IP_RETOPTS, IP_ROUTER_ALERT, IP_NODEFRAG | rejected-unimplementable | ENOPROTOOPT (logged once) |
| IPPROTO_TCP | TCP_NODELAY, TCP_MAXSEG, TCP_CORK (TCP_NOPUSH), TCP_KEEP*, TCP_INFO (translated, read-only), TCP_CONGESTION (name translation incl. reno<->newreno, optlen rules), TCP_USER_TIMEOUT (ms rounded up to s), TCP_FASTOPEN, TCP_MD5SIG | mapped | |
| IPPROTO_TCP | TCP_QUICKACK, TCP_NOTSENT_LOWAT, TCP_INQ, TCP_DEFER_ACCEPT | rejected-unimplementable | ENOPROTOOPT |
| IPPROTO_IPV6 | IPV6_V6ONLY, IPV6_UNICAST_HOPS, IPV6_RECVPKTINFO/RECVHOPLIMIT/RECVTCLASS, IPV6_TCLASS, IPV6_MTU_DISCOVER, IPV6_MULTICAST_ALL, IPV6_ADDR_PREFERENCES (TMP; COA / two source prefs EINVAL), IPV6_MTU (ENOTCONN unconnected) | mapped | |
| IPPROTO_IPV6 | RFC 2292 options (2292PKTINFO/HOPOPTS/DSTOPTS/RTHDR/PKTOPTIONS/HOPLIMIT), IPV6_ADDRFORM, IPV6_JOIN_ANYCAST | rejected-correctly | ENOPROTOOPT |
| cmsg | SCM_RIGHTS, IP_TTL, IP_TOS, IP_PKTINFO | mapped | unknown cmsg level/type EINVAL |
| ioctl | TIOCGPTPEER (0x5441) | mapped | opens the slave of a ptmx master with O_RDONLY/O_WRONLY/O_RDWR, O_NOCTTY, O_NONBLOCK, O_CLOEXEC honoured; other flag bits / access mode 3 EINVAL; on a non-master (pipe, slave) ENOTTY |

### 4.8 Deliberately not done in this batch

| site | what reaches it | reason |
|---|---|---|
| `linux_ptrace.c` (PTRACE_GETEVENTMSG, GETREGSET NT_PRFPREG/NT_X86_XSTATE, PTRACE_SEIZE, others) | gdb/strace | ptrace is its own project |
| `linux_socket.c:970` unsupported socket domain, `:2975` socket type | AF_NETLINK families other than route/uevent, AF_PACKET, AF_ALG, AF_VSOCK | each is a subsystem |
| `linux_ioctl.c:3864` generic "ioctl not implemented" | device-specific ioctls | per-driver work |
| `linux_ioctl.c:800` TCSBRK arg 0 | actual break generation | `TIOCSBRK`/`TIOCCBRK` with a timed pause; small |
| `linux_stats.c:641/663/757` fstatat/statx flags | `AT_STATX_*`, `AT_NO_AUTOMOUNT` | hints; statx sync flags could be accepted as no-ops (small) |
| `linux.c:583/585` POLLMSG/POLLREMOVE | obsolete | correct EINVAL |
| `linux_sysctl.c`, `linux_ipc.c` | obsolete `_sysctl`, `ipc()` sub-ops | obsolete |
| `linux_misc.c` PR_CAPBSET_READ/PR_SET_PTRACER | capability bounding set, Yama ptracer | no capability model |
| `linux_file.c:1296` umount2 flags | MNT_DETACH/MNT_EXPIRE | MNT_FORCE maps; DETACH needs lazy unmount |

## 5. Full upstream-vs-ours table (Linux 7.3 x86_64)

Generated from `syscalls.master` and the DUMMY/UNIMPLEMENTED lists at the
end of this batch.

| nr | syscall | status |
|---:|---|---|
| 0 | read | STD-real |
| 1 | write | STD-real |
| 2 | open | STD-real |
| 3 | close | STD-real |
| 4 | stat | STD-real |
| 5 | fstat | STD-real |
| 6 | lstat | STD-real |
| 7 | poll | STD-real |
| 8 | lseek | STD-real |
| 9 | mmap | STD-real |
| 10 | mprotect | STD-real |
| 11 | munmap | STD-real |
| 12 | brk | STD-real |
| 13 | rt_sigaction | STD-real |
| 14 | rt_sigprocmask | STD-real |
| 15 | rt_sigreturn | STD-real |
| 16 | ioctl | STD-real |
| 17 | pread64 | STD-real |
| 18 | pwrite64 | STD-real |
| 19 | readv | STD-real |
| 20 | writev | STD-real |
| 21 | access | STD-real |
| 22 | pipe | STD-real |
| 23 | select | STD-real |
| 24 | sched_yield | STD-real |
| 25 | mremap | STD-real |
| 26 | msync | STD-real |
| 27 | mincore | STD-real |
| 28 | madvise | STD-real |
| 29 | shmget | STD-real |
| 30 | shmat | STD-real |
| 31 | shmctl | STD-real |
| 32 | dup | STD-real |
| 33 | dup2 | STD-real |
| 34 | pause | STD-real |
| 35 | nanosleep | STD-real |
| 36 | getitimer | STD-real |
| 37 | alarm | STD-real |
| 38 | setitimer | STD-real |
| 39 | getpid | STD-real |
| 40 | sendfile | STD-real |
| 41 | socket | STD-real |
| 42 | connect | STD-real |
| 43 | accept | STD-real |
| 44 | sendto | STD-real |
| 45 | recvfrom | STD-real |
| 46 | sendmsg | STD-real |
| 47 | recvmsg | STD-real |
| 48 | shutdown | STD-real |
| 49 | bind | STD-real |
| 50 | listen | STD-real |
| 51 | getsockname | STD-real |
| 52 | getpeername | STD-real |
| 53 | socketpair | STD-real |
| 54 | setsockopt | STD-real |
| 55 | getsockopt | STD-real |
| 56 | clone | STD-real |
| 57 | fork | STD-real |
| 58 | vfork | STD-real |
| 59 | execve | STD-real |
| 60 | exit | STD-real |
| 61 | wait4 | STD-real |
| 62 | kill | STD-real |
| 63 | uname | STD-real |
| 64 | semget | STD-real |
| 65 | semop | STD-real |
| 66 | semctl | STD-real |
| 67 | shmdt | STD-real |
| 68 | msgget | STD-real |
| 69 | msgsnd | STD-real |
| 70 | msgrcv | STD-real |
| 71 | msgctl | STD-real |
| 72 | fcntl | STD-real |
| 73 | flock | STD-real |
| 74 | fsync | STD-real |
| 75 | fdatasync | STD-real |
| 76 | truncate | STD-real |
| 77 | ftruncate | STD-real |
| 78 | getdents | STD-real |
| 79 | getcwd | STD-real |
| 80 | chdir | STD-real |
| 81 | fchdir | STD-real |
| 82 | rename | STD-real |
| 83 | mkdir | STD-real |
| 84 | rmdir | STD-real |
| 85 | creat | STD-real |
| 86 | link | STD-real |
| 87 | unlink | STD-real |
| 88 | symlink | STD-real |
| 89 | readlink | STD-real |
| 90 | chmod | STD-real |
| 91 | fchmod | STD-real |
| 92 | chown | STD-real |
| 93 | fchown | STD-real |
| 94 | lchown | STD-real |
| 95 | umask | STD-real |
| 96 | gettimeofday | STD-real |
| 97 | getrlimit | STD-real |
| 98 | getrusage | STD-real |
| 99 | sysinfo | STD-real |
| 100 | times | STD-real |
| 101 | ptrace | STD-real |
| 102 | getuid | STD-real |
| 103 | syslog | STD-real |
| 104 | getgid | STD-real |
| 105 | setuid | STD-real |
| 106 | setgid | STD-real |
| 107 | geteuid | STD-real |
| 108 | getegid | STD-real |
| 109 | setpgid | STD-real |
| 110 | getppid | STD-real |
| 111 | getpgrp | STD-real |
| 112 | setsid | STD-real |
| 113 | setreuid | STD-real |
| 114 | setregid | STD-real |
| 115 | getgroups | STD-real |
| 116 | setgroups | STD-real |
| 117 | setresuid | STD-real |
| 118 | getresuid | STD-real |
| 119 | setresgid | STD-real |
| 120 | getresgid | STD-real |
| 121 | getpgid | STD-real |
| 122 | setfsuid | STD-real |
| 123 | setfsgid | STD-real |
| 124 | getsid | STD-real |
| 125 | capget | STD-real |
| 126 | capset | STD-real |
| 127 | rt_sigpending | STD-real |
| 128 | rt_sigtimedwait | STD-real |
| 129 | rt_sigqueueinfo | STD-real |
| 130 | rt_sigsuspend | STD-real |
| 131 | sigaltstack | STD-real |
| 132 | utime | STD-real |
| 133 | mknod | STD-real |
| 134 | uselib | UNIMPL-ancient |
| 135 | personality | STD-real |
| 136 | ustat | STD-real |
| 137 | statfs | STD-real |
| 138 | fstatfs | STD-real |
| 139 | sysfs | DUMMY |
| 140 | getpriority | STD-real |
| 141 | setpriority | STD-real |
| 142 | sched_setparam | STD-real |
| 143 | sched_getparam | STD-real |
| 144 | sched_setscheduler | STD-real |
| 145 | sched_getscheduler | STD-real |
| 146 | sched_get_priority_max | STD-real |
| 147 | sched_get_priority_min | STD-real |
| 148 | sched_rr_get_interval | STD-real |
| 149 | mlock | STD-real |
| 150 | munlock | STD-real |
| 151 | mlockall | STD-real |
| 152 | munlockall | STD-real |
| 153 | vhangup | STD-real |
| 154 | modify_ldt | DUMMY |
| 155 | pivot_root | DUMMY |
| 156 | _sysctl | STD-real |
| 157 | prctl | STD-real |
| 158 | arch_prctl | STD-real |
| 159 | adjtimex | STD-real |
| 160 | setrlimit | STD-real |
| 161 | chroot | STD-real |
| 162 | sync | STD-real |
| 163 | acct | STD-real |
| 164 | settimeofday | STD-real |
| 165 | mount | STD-real |
| 166 | umount2 | STD-real |
| 167 | swapon | STD-real |
| 168 | swapoff | DUMMY |
| 169 | reboot | STD-real |
| 170 | sethostname | STD-real |
| 171 | setdomainname | STD-real |
| 172 | iopl | STD-real |
| 173 | ioperm | DUMMY |
| 174 | create_module | UNIMPL-ancient |
| 175 | init_module | DUMMY |
| 176 | delete_module | DUMMY |
| 177 | get_kernel_syms | UNIMPL-ancient |
| 178 | query_module | UNIMPL-ancient |
| 179 | quotactl | DUMMY |
| 180 | nfsservctl | UNIMPL-ancient |
| 181 | getpmsg | UNIMPL-ancient |
| 182 | putpmsg | UNIMPL-ancient |
| 183 | afs_syscall | UNIMPL-ancient |
| 184 | tuxcall | UNIMPL-ancient |
| 185 | security | UNIMPL-ancient |
| 186 | gettid | STD-real |
| 187 | readahead | STD-real |
| 188 | setxattr | STD-real |
| 189 | lsetxattr | STD-real |
| 190 | fsetxattr | STD-real |
| 191 | getxattr | STD-real |
| 192 | lgetxattr | STD-real |
| 193 | fgetxattr | STD-real |
| 194 | listxattr | STD-real |
| 195 | llistxattr | STD-real |
| 196 | flistxattr | STD-real |
| 197 | removexattr | STD-real |
| 198 | lremovexattr | STD-real |
| 199 | fremovexattr | STD-real |
| 200 | tkill | STD-real |
| 201 | time | STD-real |
| 202 | futex | STD-real |
| 203 | sched_setaffinity | STD-real |
| 204 | sched_getaffinity | STD-real |
| 205 | set_thread_area | UNIMPL-ancient |
| 206 | io_setup | DUMMY |
| 207 | io_destroy | DUMMY |
| 208 | io_getevents | DUMMY |
| 209 | io_submit | DUMMY |
| 210 | io_cancel | DUMMY |
| 211 | get_thread_area | UNIMPL-ancient |
| 212 | lookup_dcookie | DUMMY |
| 213 | epoll_create | STD-real |
| 214 | epoll_ctl_old | UNIMPL-ancient |
| 215 | epoll_wait_old | UNIMPL-ancient |
| 216 | remap_file_pages | DUMMY |
| 217 | getdents64 | STD-real |
| 218 | set_tid_address | STD-real |
| 219 | restart_syscall | STD-real |
| 220 | semtimedop | STD-real |
| 221 | fadvise64 | STD-real |
| 222 | timer_create | STD-real |
| 223 | timer_settime | STD-real |
| 224 | timer_gettime | STD-real |
| 225 | timer_getoverrun | STD-real |
| 226 | timer_delete | STD-real |
| 227 | clock_settime | STD-real |
| 228 | clock_gettime | STD-real |
| 229 | clock_getres | STD-real |
| 230 | clock_nanosleep | STD-real |
| 231 | exit_group | STD-real |
| 232 | epoll_wait | STD-real |
| 233 | epoll_ctl | STD-real |
| 234 | tgkill | STD-real |
| 235 | utimes | STD-real |
| 236 | vserver | UNIMPL-ancient |
| 237 | mbind | DUMMY |
| 238 | set_mempolicy | DUMMY |
| 239 | get_mempolicy | DUMMY |
| 240 | mq_open | STD-real |
| 241 | mq_unlink | STD-real |
| 242 | mq_timedsend | STD-real |
| 243 | mq_timedreceive | STD-real |
| 244 | mq_notify | STD-real |
| 245 | mq_getsetattr | STD-real |
| 246 | kexec_load | DUMMY |
| 247 | waitid | STD-real |
| 248 | add_key | DUMMY |
| 249 | request_key | DUMMY |
| 250 | keyctl | DUMMY |
| 251 | ioprio_set | STD-real |
| 252 | ioprio_get | STD-real |
| 253 | inotify_init | STD-real |
| 254 | inotify_add_watch | STD-real |
| 255 | inotify_rm_watch | STD-real |
| 256 | migrate_pages | DUMMY |
| 257 | openat | STD-real |
| 258 | mkdirat | STD-real |
| 259 | mknodat | STD-real |
| 260 | fchownat | STD-real |
| 261 | futimesat | STD-real |
| 262 | newfstatat | STD-real |
| 263 | unlinkat | STD-real |
| 264 | renameat | STD-real |
| 265 | linkat | STD-real |
| 266 | symlinkat | STD-real |
| 267 | readlinkat | STD-real |
| 268 | fchmodat | STD-real |
| 269 | faccessat | STD-real |
| 270 | pselect6 | STD-real |
| 271 | ppoll | STD-real |
| 272 | unshare | DUMMY |
| 273 | set_robust_list | STD-real |
| 274 | get_robust_list | STD-real |
| 275 | splice | STD-real |
| 276 | tee | DUMMY |
| 277 | sync_file_range | STD-real |
| 278 | vmsplice | STD-real |
| 279 | move_pages | DUMMY |
| 280 | utimensat | STD-real |
| 281 | epoll_pwait | STD-real |
| 282 | signalfd | STD-real |
| 283 | timerfd_create | STD-real |
| 284 | eventfd | STD-real |
| 285 | fallocate | STD-real |
| 286 | timerfd_settime | STD-real |
| 287 | timerfd_gettime | STD-real |
| 288 | accept4 | STD-real |
| 289 | signalfd4 | STD-real |
| 290 | eventfd2 | STD-real |
| 291 | epoll_create1 | STD-real |
| 292 | dup3 | STD-real |
| 293 | pipe2 | STD-real |
| 294 | inotify_init1 | STD-real |
| 295 | preadv | STD-real |
| 296 | pwritev | STD-real |
| 297 | rt_tgsigqueueinfo | STD-real |
| 298 | perf_event_open | DUMMY |
| 299 | recvmmsg | STD-real |
| 300 | fanotify_init | DUMMY |
| 301 | fanotify_mark | DUMMY |
| 302 | prlimit64 | STD-real |
| 303 | name_to_handle_at | STD-real |
| 304 | open_by_handle_at | STD-real |
| 305 | clock_adjtime | STD-real |
| 306 | syncfs | STD-real |
| 307 | sendmmsg | STD-real |
| 308 | setns | DUMMY |
| 309 | getcpu | STD-real |
| 310 | process_vm_readv | STD-real |
| 311 | process_vm_writev | STD-real |
| 312 | kcmp | STD-real |
| 313 | finit_module | DUMMY |
| 314 | sched_setattr | STD-real |
| 315 | sched_getattr | STD-real |
| 316 | renameat2 | STD-real |
| 317 | seccomp | STD-real |
| 318 | getrandom | STD-real |
| 319 | memfd_create | STD-real |
| 320 | kexec_file_load | DUMMY |
| 321 | bpf | DUMMY |
| 322 | execveat | STD-real |
| 323 | userfaultfd | DUMMY |
| 324 | membarrier | STD-real |
| 325 | mlock2 | STD-real |
| 326 | copy_file_range | STD-real |
| 327 | preadv2 | STD-real |
| 328 | pwritev2 | STD-real |
| 329 | pkey_mprotect | STD-real |
| 330 | pkey_alloc | STD-real |
| 331 | pkey_free | STD-real |
| 332 | statx | STD-real |
| 333 | io_pgetevents | DUMMY |
| 334 | rseq | STD-real |
| 335 | uretprobe | DUMMY |
| 336 | uprobe | DUMMY |
| 424 | pidfd_send_signal | STD-real |
| 425 | io_uring_setup | DUMMY |
| 426 | io_uring_enter | DUMMY |
| 427 | io_uring_register | DUMMY |
| 428 | open_tree | DUMMY |
| 429 | move_mount | DUMMY |
| 430 | fsopen | DUMMY |
| 431 | fsconfig | DUMMY |
| 432 | fsmount | DUMMY |
| 433 | fspick | DUMMY |
| 434 | pidfd_open | STD-real |
| 435 | clone3 | STD-real |
| 436 | close_range | STD-real |
| 437 | openat2 | STD-real |
| 438 | pidfd_getfd | STD-real |
| 439 | faccessat2 | STD-real |
| 440 | process_madvise | STD-real |
| 441 | epoll_pwait2 | STD-real |
| 442 | mount_setattr | DUMMY |
| 443 | quotactl_fd | DUMMY |
| 444 | landlock_create_ruleset | DUMMY |
| 445 | landlock_add_rule | DUMMY |
| 446 | landlock_restrict_self | DUMMY |
| 447 | memfd_secret | DUMMY |
| 448 | process_mrelease | DUMMY |
| 449 | futex_waitv | STD-real |
| 450 | set_mempolicy_home_node | DUMMY |
| 451 | cachestat | DUMMY |
| 452 | fchmodat2 | STD-real |
| 453 | map_shadow_stack | DUMMY |
| 454 | futex_wake | STD-real |
| 455 | futex_wait | STD-real |
| 456 | futex_requeue | STD-real |
| 457 | statmount | DUMMY |
| 458 | listmount | DUMMY |
| 459 | lsm_get_self_attr | DUMMY |
| 460 | lsm_set_self_attr | DUMMY |
| 461 | lsm_list_modules | DUMMY |
| 462 | mseal | STD-real |
| 463 | setxattrat | STD-real |
| 464 | getxattrat | STD-real |
| 465 | listxattrat | STD-real |
| 466 | removexattrat | STD-real |
| 467 | open_tree_attr | DUMMY |
| 468 | file_getattr | DUMMY |
| 469 | file_setattr | DUMMY |
| 470 | listns | DUMMY |
| 471 | rseq_slice_yield | DUMMY |
| 472 | fchroot | DUMMY |

## 6. Ranked remaining work

Ranked by what real userland calls, not by ease.  Sizing: S < 1 day,
M 1-3 days, L a week or more.

| rank | syscall(s) | status | why it matters | sizing / approach |
|---:|---|---|---|---|
| 1 | signalfd, signalfd4 | DONE 2026-09-12 | glibc-free runtimes, systemd-style loops, Go (`os/signal` uses rt_sigaction, but many event loops use signalfd) | M: a file type over an in-kernel signal queue; `EVFILT_SIGNAL` only counts deliveries and does not consume the signal, so the file needs its own sigqueue drain in `postsig()`/`cursig()` (kernel change) or a per-process hook that steals blocked signals |
| 2 | futex_waitv | DONE 2026-09-12 | glibc 2.35+ `pthread_cond` on some builds, Wine/Proton fsync | M: per-entry wake indirection in `kern_umtx.c` + 128-entry parse |
| 3 | io_uring_setup/enter/register | DUMMY | modern Rust/C++ async runtimes probe it and fall back; returning ENOSYS is what they expect | L: not planned; keep ENOSYS (fallback path is well-trodden) |
| 4 | statmount, listmount | DUMMY | util-linux 2.40+, systemd | M: translate mount list (`getfsstat`) into the Linux `statmount` record |
| 5 | fsopen/fsconfig/fsmount/fspick/move_mount/open_tree/open_tree_attr/mount_setattr | DUMMY | systemd, containers | L: new mount API; needs a mount-context object |
| 6 | setns, unshare, pivot_root | DUMMY | containers | L: no namespaces; jails are not equivalent |
| 7 | userfaultfd | DUMMY | CRIU, some GC runtimes (probe and fall back) | L |
| 8 | memfd_secret, mseal, map_shadow_stack | DUMMY | glibc 2.41 probes mseal; Chrome sandbox | mseal: M (vm_map flag to reject munmap/mprotect); others L |
| 9 | cachestat | DUMMY | fincore-style tools | S: `mincore` on the file's object |
| 10 | fanotify_init/mark | DUMMY | AV/indexers | L; inotify covers most |
| 11 | landlock_* | DUMMY | sandboxes probe it, fall back | M-L: map onto Capsicum/mac_capability? design first |
| 12 | process_mrelease | DUMMY | Android/OOM killers | S: reap of a zombie's address space is implicit here; can return 0 for a dying process |
| 13 | tee, vmsplice | DUMMY | rare | M: pipe buffer access |
| 14 | add_key/request_key/keyctl | DUMMY | kerberos/ecryptfs | L |
| 15 | bpf, perf_event_open | DUMMY | tracing tools | L |
| 16 | io_setup..io_cancel, io_pgetevents (libaio) | DUMMY | old DB engines | M: map onto native aio |
| 17 | mbind/get_mempolicy/set_mempolicy/migrate_pages/move_pages/set_mempolicy_home_node | DUMMY | NUMA-aware daemons (probe) | M: domainset(2) |
| 18 | lsm_get_self_attr/lsm_set_self_attr/lsm_list_modules | DUMMY | systemd 256+ probes | S: report an empty module list |
| 19 | quotactl, quotactl_fd, sysfs, swapoff, init_module/finit_module/delete_module, kexec_*, ioperm, modify_ldt, lookup_dcookie, remap_file_pages, uretprobe, uprobe, listns, rseq_slice_yield, fchroot, file_getattr/setattr | DUMMY | admin tools / new | S each where mappable (`fchroot` -> `fchroot`? none native; `file_getattr` -> `chflags` subset); mostly leave ENOSYS |
| 20 | OFD locks (`fcntl F_OFD_*`) | option EINVAL | Rust `fs2`/`fd-lock`, PostgreSQL | M: native OFD lock support in `kern_lockf` (description-owned locks) |
| 21 | `F_SEAL_FUTURE_WRITE`, `F_SEAL_EXEC` | option EINVAL | Chromium, Wayland compositors | S-M: native seal bits |
| 22 | `RESOLVE_NO_SYMLINKS`, `RESOLVE_IN_ROOT` | option EINVAL | sandboxes (systemd, runc) | M: namei flags for "no symlink anywhere" and "clamp at root" |
| 23 | `PIDFD_THREAD`, `PIDFD_SIGNAL_THREAD` | option EINVAL | rare | S once thread identity is stored |

## 7. Tests

All tests are freestanding amd64 Linux binaries (no Linux libc), built by
their ATF sh wrapper with `clang --target=x86_64-linux-gnu -fuse-ld=lld
-nostdlib -static`, in `tests/sys/kern/`.  Each check asserts a Linux man
page / kernel behaviour; the exit status is the failing check number.

| test | covers | result (VM, this tree's modules, 2026-09-12) | notes |
|---|---|---|---|
| linux_pidfd | pidfd_open/send_signal/getfd, poll+epoll readiness, zombie, thread tid, PIDFD_NONBLOCK | passed |  |
| linux_madvise | COLD/PAGEOUT preserve contents (anon + file), KSM/THP hints, rejected advice, DONTNEED(_LOCKED) discard, unaligned start EINVAL | passed |  |
| linux_futex2 | futex_wait/wake/requeue, legacy REQUEUE/CMP_REQUEUE broadcast, WAIT_BITSET 0, CLOCK_REALTIME | passed |  |
| linux_xattrat | *xattrat validation + fs round trips (skips fs work if no extattr) | passed |  |
| linux_evsig | epoll EXCLUSIVE/WAKEUP/ONESHOT/MOD, sigaction flag read-back + delivery, clone3 validation, CLONE_PIDFD | passed |  |
| linux_pkey | pkey_alloc/free/mprotect incl. WRPKRU fault via SIGSEGV handler, fork inheritance, 15-key limit, munmap drops key; skips cleanly without PKU | passed | qemu TCG has no PKU: only the no-PKU checks (1-2) ran; the PKU path is still unverified on hardware |
| linux_machdep2 | readahead, restart_syscall, arch_prctl XCOMP/CPUID/VDSO/LAM/SHSTK | passed |  |
| linux_openat2 | openat2 size/flag/resolve rules, BENEATH escape EXDEV, NO_SYMLINKS EINVAL, fchmodat2, execveat | passed |  |
| linux_fileflags | renameat2 flags, fcntl OWN_EX/SIG/OFD/seals/pipe size, faccessat2, fchownat, copy_file_range | passed |  |
| linux_misc2 | setfsuid/gid, sched_getattr/setattr, waitid P_PIDFD, process_madvise, prctl, mlock2 | passed |  |
| linux_adjtime | adjtimex/clock_adjtime | passed |  |
| linux_sockopt | socket option mappings | passed |  |
| linux_pty | TIOCGPTPEER | passed |  |

Running them: `kyua test -k /usr/tests/sys/kern/Kyuafile linux_pidfd_test`
etc., or by hand: build with the clang line above and run the binary; the
exit status is the check number.  All of them need `linux64.ko` and
`linux_common.ko` from this tree loaded.  On the development box a reload
kills every Linux process, so they are run in the qemu VM rig
(`LINUX_TEST=1 CAPLANE_OFF=1 UFS_ROOT=1 sh ~/vm/build-image-authority.sh`,
which preloads `linux64` from loader.conf; stage the three `.ko`s into
`~/vm/guestroot/boot/kernel` and the `linux_*_test` wrappers -- with the
`#! /usr/libexec/atf-sh` line bsd.test.mk would add -- plus their `.c`
sources into `guestroot/usr/tests/sys/kern` first).

Result 2026-09-12: **13/13 passed** (kyua summary: `13/13 passed (0
broken, 0 failed, 0 skipped)`).  The first VM run found one kernel bug and
three test bugs, all fixed:

* **Boot panic when preloaded** (`panic: kthread_add called too soon` from
  `linux_pidfd_init`): the pidfd SYSINIT was at `SI_SUB_KLD`, which for a
  loader-preloaded module runs from `mi_startup()` before kthreads exist.
  Moved to `SI_SUB_TASKQ`.  Never seen on the dev box because there the
  module is `kldload`ed after boot.
* `ARCH_REQ_XCOMP_PERM` returned 0 for x87/SSE/AVX; Linux only has a
  permission entry for the dynamically enabled XTILEDATA (18) and returns
  EOPNOTSUPP for everything else, including always-on components.  Kernel,
  test and the tables above corrected.
* `madvise` with an unaligned start was accepted for the advices mapped
  onto `kern_madvise()` (which rounds down); Linux is EINVAL for every
  advice.  Now checked once in `linux_madvise_common()`.
* Test bugs: `linux_sockopt` used 2 (TCP_MAXSEG) for TCP_CORK (3);
  `linux_openat2` created a dirfd-relative symlink to a relative argv[0];
  `linux_pkey` wrote its "pku not available" notice to stderr, which the
  wrapper required empty.

**Later on 2026-09-12** the option-level review (`linuxulator-option-review.md`)
added 21 option tests and an adversarial suite; see that document §7a and
the `linux_*_test` list in `tests/sys/kern/Makefile`.  The runner is
`~/vm/run-linux-tests.sh` (stages kernel, modules, tests and the Alpine
busybox root, builds the UFS image, boots, runs kyua, prints the summary).

Not loaded in the VM: the 32-bit `linux.ko` fails to link against the VBSD
kernel (`elf32_register_note undefined`) -- pre-existing, unrelated to this
batch, and the kernel config has COMPAT_FREEBSD32 so it wants a look.

## 8. Build status

`bmake` in `sys/modules/linux64`, `sys/modules/linux_common` and
`sys/modules/linux` (32-bit compat) with
`KERNBUILDDIR=/usr/obj/usr/src/amd64.amd64/sys/VBSD`: all three link
warning-free with `-Werror`.  `make sysent` in all four `sys/*/linux*`
directories reproduces the checked-in generated files.  Header changes:
`sys/sys/file.h` gains `DTYPE_LINUXPIDFD` (a new constant only; no ABI
change).  `linux64.ko` + `linux_common.ko` boot preloaded and pass the
suite in the VM (section 7); nothing in the batch requires a kernel rebuild.

### 7.x Session 3 additions (2026-09-12 evening)

New syscall: `mseal` (462) STD-real. Tests added: `linux_mseal`, `linux_break_mseal`,
`linux_break_signalfd`, `linux_trace` (truss / ktrace+kdump / DTrace
`syscall:linux` / `linuxulator` SDT probes over a `linux_tracee` binary),
futex_waitv checks 22-24 (single-threading storm, wake-vs-deadline race,
duplicate addresses).  Tracing tools: libsysdecode/truss/kdump must be rebuilt
with the table (they include `linux_syscalls.c`); `systrace_linux.ko` embeds
`linux_systrace_args.c`.  See linuxulator-option-review.md §10 for the bug
list (B22-B28) fixed by the adversarial suite.

### 7.y tee(2) + process_vm test (session 3 follow-on)

tee (276) STD-real: non-consuming pipe->pipe duplication, sized to the sink
free space (reuses splice's room logic), source peeked without advancing the
read pointer.  New adversarial tests linux_tee (wrap/EOF/validation/splice
integration) and linux_break_procvm (process_vm_readv/writev cross-process
rw, scatter/gather, partial, EFAULT/ESRCH + readahead).

### 7.z cachestat(2)

cachestat (451) STD-real: page-cache residency over a file range via the
vnode VM object (resident pages -> nr_cache, dirty pages -> nr_dirty);
eviction counters stay 0 (FreeBSD does not track eviction history).  Test
linux_cachestat (residency, sub-range, beyond-EOF, validation, EFAULT).

### 7.aa statmount(2) + listmount(2)

statmount (457) / listmount (458) STD-real: mount enumeration and per-mount
query.  Linux mount IDs are mapped to FreeBSD fsids (packed 2x int32 -> u64);
listmount walks the mountlist (LSMT_ROOT = all, or children nested under a
given mount) with a param cursor and LISTMOUNT_REVERSE; statmount fills
fs_type/mnt_point/mnt_root/sb_source strings and the SB_BASIC/MNT_BASIC
fields (attrs from MNT_*, propagation MS_PRIVATE), EOVERFLOW on a short
buffer, ENOENT for an unknown id.  No mount-namespace tree (FreeBSD is flat):
parent id is the enclosing mount, peer-group/propagate_from are 0.  Test
linux_statmount.
