# System Calls

This chapter is the map of the Linux x86-64 syscall surface as 5BSD implements it: which families work, to what depth, what proves it, what is still missing, and how to find out what a particular binary needs. It is a summary of three living documents, `docs/linuxulator-syscall-coverage.md` (the table), `docs/book/src/compat/linux/syscalls.md` (the flags) and `docs/linuxulator-missing-syscalls-handoff.md` (the queue), and it inherits their rule: a handler is evidence of dispatch, not of every option working.

The counts from [the overview](overview.md) apply throughout: 386 named slots through 472, 334 STD-real, 36 DUMMY, one reject-only stub, 15 deliberately absent. All test programs named below live in `tests/sys/kern/` and are installed under `/usr/tests/sys/kern`; freestanding Linux probes are compiled with `clang --target=x86_64-linux-gnu -nostdlib -static` and branded with brandelf(1), so they need no Linux userland.

## The surface by family

| Family | What works | Status | Proof (test, man page) |
|---|---|---|---|
| Process, pidfd, clone, unshare | `pidfd_open`/`send_signal`/`getfd`, `CLONE_PIDFD`, `waitid(P_PIDFD)`, `SO_PEERPIDFD`; `__WALL` maps to native `WLINUXALL` (`sys/sys/wait.h`); `clone3`; `unshare(CLONE_FS)` for single-threaded amd64 processes | shipped; `unshare` namespace flags rejected; `setns`, `listns` DUMMY | `linux_pidfd`, `linux_break_pidfd`, `linux_peerpidfd`, `linux_cloneflags`, `linux_unshare`, `linux_unshare_capmode`; `docs/book/src/compat/linux/syscalls.md` |
| futex, futex2 | `futex` ops including CMP_REQUEUE and CLOCK_REALTIME; `futex_wait`/`wake`/`requeue`; `futex_waitv` with per-address umtx entries sharing one wait channel | shipped; `FUTEX_WAIT_REQUEUE_PI` and `CMP_REQUEUE_PI` return `ENOSYS`, `FUTEX2_NUMA` `EINVAL` | `linux_futex2`, `linux_futex_waitv`, `linux_break_futex` |
| Signals, signalfd | `signalfd`/`signalfd4` as an own file type over `kern_sigtimedwait`, fed by a `process_signal` eventhandler; `rt_sigqueueinfo`; sigaction flag translation | shipped; a blocked signalfd read captures the mask at call time (Linux re-evaluates) | `linux_signalfd`, `linux_break_signalfd`, `linux_break_signals`, `linux_evsig`; `docs/book/src/compat/linux/sandboxing.md` |
| Files | `openat2` with `RESOLVE_NO_SYMLINKS`/`NO_MAGICLINKS`/`NO_XDEV`/`IN_ROOT`/`BENEATH` (native namei flags in `vfs_lookup.c`), `execveat`, `fchmodat2`, `faccessat2`, `renameat2`, `*xattrat`, `statx` with mount ids, `statmount`/`listmount`, `cachestat`, `splice`/`tee`/`vmsplice` including `SPLICE_F_FD_IN_FIXED` and explicit offsets, `preadv2`/`pwritev2` with `RWF_*`, `fallocate` mode 0 and `PUNCH_HOLE\|KEEP_SIZE`, OFD locks (`F_OFD_*`, native in `kern_lockf.c`), `mseal`, `fchroot`, `FS_IOC_GETFLAGS`/`SETFLAGS`, `file_getattr`/`setattr`, `O_TMPFILE` rejected honestly | shipped; other `fallocate` modes `EOPNOTSUPP`; OFD advertised by ZFS, UFS and tmpfs only | `linux_openat2`, `linux_resolve`, `linux_splice`, `linux_tee`, `linux_cachestat`, `linux_statmount`, `linux_rwf`, `linux_mseal`, `linux_break_mseal`, `linux_fchroot`, `linux_xattrat`, `linux_fallocate`, `linux_fileflags`, `linux_fileattr`, `linux_openflags`, `linux_break_files`, `ofd_lock`; fcntl(2), inotify(2) |
| Memory | `madvise` COLD/PAGEOUT (content-preserving reclaim), MERGEABLE (no-op), HUGEPAGE (no-op), the rest rejected with Linux's errno; `mmap` `MAP_FIXED_NOREPLACE`/`POPULATE`/`LOCKED`/`SHARED_VALIDATE`; `mremap`; `mlock2`; `mlockall(MCL_ONFAULT)`; `remap_file_pages`; `process_madvise`; `pkey_alloc`/`free`/`mprotect` with a per-mm key map; `mbind`, `get_mempolicy`, `set_mempolicy`, `migrate_pages`, `move_pages` | shipped; NUMA is single-node policy bookkeeping; `MAP_HUGETLB` `ENOMEM`, `MAP_SYNC` `EOPNOTSUPP` | `linux_madvise`, `linux_mmapflags`, `linux_numa`, `linux_pkey`, `linux_remap_file_pages`, `linux_mlockall`, `linux_break_mmap`, `linux_break_procvm`; `docs/book/src/compat/linux/syscalls.md` |
| Time, adjtimex | `adjtimex`, `clock_adjtime`, `clock_*` with Linux clock ids, `timerfd` | shipped | `linux_adjtime` |
| Scheduling, rseq | `sched_setattr`/`getattr`, `sched_*` with `map_sched_prio`; `rseq` registration, auxv (feature size 28, alignment 32), abort-IP redirection on migration and signal, `mm_cid` | shipped amd64; `rseq_slice_yield` DUMMY; linux32 and arm64 `ENOSYS` | seven `linux_rseq_*` programs; `docs/book/src/compat/linux/syscalls.md` |
| ptrace | `SEIZE`, `INTERRUPT`, `LISTEN`, `GETREGSET`/`SETREGSET` for `NT_PRSTATUS`, `NT_PRFPREG`, `NT_X86_XSTATE`, `NT_386_IOPERM`; `PEEKUSER`/`POKEUSER` including DR0 to DR7; `ARCH_PRCTL`; `GET_RSEQ_CONFIGURATION`; `GETSIGMASK`/`SETSIGMASK`; `PEEKSIGINFO`; fork, exec and exit event messages | shipped; full multithreaded tracing not claimed; `PTRACE_O_SUSPEND_SECCOMP` `EINVAL` | 16 `linux_ptrace_*` programs, `linux_tracee`; ptrace(2) for the native `PTRACE_EXIT` event; see [Sandboxing and Debugging](sandboxing.md) |
| Sockets | abstract `AF_UNIX` names (binary, autobind, per VNET and prison; unbindable in capability mode), `AF_VSOCK` (46 in `sys/sys/socket.h`), `SO_COOKIE`, `SO_PEERPIDFD`, `SOL_UDP`, `getpeername` on every family, `MCAST_MSFILTER` and source filters, recvmsg output-flag translation, `IP_RECVERR` knob | shipped; `MSG_ERRQUEUE`, `SO_PASSPIDFD` pending | `linux_abstract`, `linux_abstract_caps`, `linux_vsock`, `linux_socket_cookie`, `linux_socket_peername`, `linux_mcast_filter`, `linux_sockopt`, `linux_recvmsg_flags`, `linux_break_sockets`; sockstat(1) `-V` |
| Netlink | `NETLINK_ROUTE` with per-interface Linux names; `NETLINK_SOCK_DIAG` INET and UNIX dumps (`sys/netlink/netlink_sock_diag.c`); `NETLINK_KOBJECT_UEVENT` (protocol 15) carrying real interface add, move and remove events | SOCK_DIAG shipped; uevent passes its focused tests, broad gates pending | `linux_sock_diag`, `linux_unix_diag`, `linux_kobject_uevent`, `linux_uevent_jail` |
| Swap, quota | `swapon` with `SWAP_FLAG_PREFER` priority and `DISCARD`/`DISCARD_ONCE`/`DISCARD_PAGES`; `swapoff`; `quotactl` sync; `quotactl_fd` ZFS user and group query, byte hard-limit update and sync | shipped; legacy device-selected `quotactl` pending | `linux_swapon_flags`, `linux_swapon_priority`, `linux_swapon_discard`, `linux_swapoff`, `linux_quota`, `linux_quota_capmode`; `docs/book/src/compat/linux/syscalls.md` |
| perf_event_open | task-clock, page-fault, context-switch and dummy software counters on the current thread; enable, disable, reset and ID ioctls; read formats; CLOEXEC, dup, fork, exit freezing | partial; hardware PMU, sampling, groups, mmap rings, CPU-wide and cross-task forms return an explicit error | `linux_perf_event`; `docs/book/src/compat/linux/syscalls.md` |
| x86: ioperm, iopl, modify_ldt | `ioperm` bitmap with self-revoke, `iopl` requiring `PRIV_IO` only when raising, `modify_ldt` read and write, `arch_prctl` sub-commands | shipped | `linux_ioperm`, `linux_iopl_options`, `linux_modify_ldt`, `linux_machdep2` |
| Legacy AIO | `io_setup`, `io_destroy`, `io_submit`, `io_getevents`, `io_cancel` over native AIO with a Linux mmap ring; `RWF_*` and `IOCB_FLAG_IOPRIO` on IOCBs; eventfd completion; poll IOCBs | partial; `io_pgetevents` DUMMY; direct-I/O priority unqualified | `linux_aio`, `linux_aio_counts`, `linux_aio_signal`, `linux_aio_timeout`, `aio_compat_native`; aio(4) |
| io_uring | `io_uring_setup`/`enter`/`register` over the native squeue engine | shipped; see [io_uring and squeue](io-uring.md) | `linux_iouring*`, `squeue_*` |

Every row above is the amd64 Linux64 ABI. Where the table says "pending", the missing-syscalls handoff or the option review has a named row for it.

## The 41 remaining calls

The queue in `docs/linuxulator-missing-syscalls-handoff.md` contains 37 calls without a functional handler (36 DUMMY stubs and the reject-only `seccomp`) plus four partial handlers. The handoff groups them by the design project each one needs, because none of them is a one-line alias for a native call.

| Group | Calls | Why they are not aliases |
|---|---|---|
| Namespaces, mounts and filesystem control (14) | `pivot_root`, `setns`, `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`, `open_tree_attr`, `listns` (DUMMY); `unshare`, `quotactl`, `quotactl_fd` (partial) | detached mount trees and namespace identities have no native object; jails and `mount(2)` are not substitutes |
| Security, tracing and observability (17) | `lookup_dcookie`, `add_key`, `request_key`, `keyctl`, `fanotify_init`, `fanotify_mark`, `bpf`, `uretprobe`, `uprobe`, `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`, `lsm_get_self_attr`, `lsm_set_self_attr`, `lsm_list_modules` (DUMMY); `seccomp` (reject-only); `perf_event_open` (partial) | each needs a real client, an object model and enforcement on every entry path; a success return without the promised restriction is not support |
| Module, boot and administration (5) | `init_module`, `delete_module`, `finit_module`, `kexec_load`, `kexec_file_load` | Linux module and kernel image formats differ from KLD; a deliberate rejection must be distinguishable from a subset |
| Memory and process runtime (5) | `userfaultfd`, `memfd_secret`, `process_mrelease`, `map_shadow_stack`, `rseq_slice_yield` | `memfd_secret` needs pages excluded from the direct map, which no native primitive provides; the others need scheduler or VM hooks with observable semantics |

The 15 UNIMPL-ancient slots (`uselib`, `create_module`, `get_kernel_syms`, `query_module`, `nfsservctl`, `getpmsg`, `putpmsg`, `afs_syscall`, `tuxcall`, `security`, `set_thread_area`, `get_thread_area`, `epoll_ctl_old`, `epoll_wait_old`, `vserver`) are outside the queue on purpose and are reopened only for a concrete binary that needs one.

The handoff's definition of done is the same gate every other change passes: pin the reference Linux version and the supported subset, write named positive and negative cases including the deliberately unsupported features, run them in a Linux reference guest and then in the disposable amd64 ZFS-root guest with the full existing matrix, and update the coverage row before calling the contract validated.

## Native facilities that arrived with the Linux work

Several Linux contracts were implemented as native kernel mechanisms so that native callers and descriptor passing cannot bypass them. A native program can use them directly: OFD locks (`F_OFD_GETLK`/`SETLK`/`SETLKW` in fcntl(2)), `F_SEAL_FUTURE_WRITE` on memfds, `WLINUXALL` in wait6(2), inotify open-path identity and `IN_EXCL_UNLINK` (inotify(2)), `NETLINK_KOBJECT_UEVENT` (`sys/netlink/netlink.h`), swap priority and discard, `futex_waitv`-style multi-address umtx waits, and the `PTRACE_EXIT` event in ptrace(2). The `SYF_CAPREQUIRED` syscall class and the per-syscall `mac_proc_check_syscall` hook, described in [The MAC Capability Framework](../../capability/mac-capability.md), fire on Linux dispatch exactly as they do on native dispatch.

## Finding out what a binary needs

The method the coverage document used to choose its first batch is the one to use for any new workload: run the binary under truss(1) and count. truss, kdump(1) and libsysdecode all include the kernel's `linux_syscalls.c`, so every named slot decodes; an `UNKNOWN Linux SYSCALL N` line means a stale truss, not a missing handler.

```sh
# census of every Linux syscall a run makes, most frequent first
truss -f -o /tmp/app.truss /compat/linux/usr/bin/app --version
sed -n 's/^\([0-9]*: \)*\(linux_[a-z0-9_]*\)(.*/\2/p' /tmp/app.truss | sort | uniq -c | sort -rn | head -40

# only the calls that failed with ENOSYS (a DUMMY slot) or EINVAL (an option gap)
grep -E "ERR#(78|22)" /tmp/app.truss | sort | uniq -c | sort -rn
```

A DUMMY slot also logs `linux: pid N (name): syscall X not implemented` once per process to the console, so `dmesg` after a run is a second census. For a running system, DTrace's `syscall:linux:*` provider (module `systrace_linux`) aggregates by name without restarting the program:

```sh
dtrace -n 'syscall:linux::entry { @[probefunc] = count(); }'
```

When the census turns up a failing call, look it up in section 5 of `docs/linuxulator-syscall-coverage.md` to see whether it is DUMMY (queue it under the right group in the handoff) or STD-real (find the flag in `docs/book/src/compat/linux/syscalls.md` and record whether the failure is a BUG, a GAP or a rejected-unimplementable option). The three real static binaries the coverage work trussed this way, jq, ripgrep and caddy, made zero unimplemented syscalls; their only gaps were missing procfs and sysfs files, which is why [the next chapter](procfs-sysfs.md) exists.
