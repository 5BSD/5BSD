# Linuxulator option-level review (x86_64, Linux 7.3 uapi)

Companion to `linuxulator-syscall-coverage.md` (which tracks the syscall
*table*).  This document is the option-level audit: for every implemented
syscall, which flags/commands/options are honoured, which are rejected and
with what errno, which are silently wrong, and what is left to build.
Reference: Linux master uapi headers as of 2026-09-12 (identical to 7.3 for
everything cited unless marked *post-7.3*).

Status vocabulary: **mapped** (exact FreeBSD equivalent), **no-op-hint**
(pure hint, accepting is correct), **rejected-correctly** (the errno Linux
itself returns in the equivalent configuration), **rejected-unimplementable**
(no facility; honest errno instead of a silent weakening), **BUG** (current
behaviour is silently wrong and must change), **GAP** (mappable onto a
FreeBSD facility but not done).

## 0. Findings that are bugs (silent misbehaviour today)

| # | syscall / option | today | correct | fix |
|---|---|---|---|---|
| B1 | `mmap(MAP_FIXED_NOREPLACE)` (0x100000) | flag ignored; address treated as a hint, falls back to *another* address on collision | EEXIST on collision, exact address otherwise | `MAP_FIXED\|MAP_EXCL` without the hint fallback |
| B2 | `mmap(MAP_POPULATE)` | ignored | pre-fault the range | `MAP_PREFAULT_READ` |
| B3 | `mmap(MAP_LOCKED)` | ignored | wire after mapping (Linux ignores mlock failure) | `kern_mlock()` after `kern_mmap()` |
| B4 | `mmap(MAP_HUGETLB)` | ignored: caller assumes 2 MB pages it did not get | ENOMEM (Linux with `vm.nr_hugepages=0`) | reject |
| B5 | `mmap(MAP_SYNC)` | ignored | EOPNOTSUPP (Linux for non-DAX) | reject |
| B6 | `clone/clone3(CLONE_NEWNS/NEWUTS/NEWIPC/NEWUSER/NEWPID/NEWNET/NEWCGROUP)` | ignored: a plain fork with no isolation "succeeds" | EINVAL (Linux without `CONFIG_*_NS`) | reject |
| B7 | `wait4/waitid(__WALL)` | mapped to "SIGCHLD children only"; clone children with another exit signal are never reaped | wait for both | new native `WLINUXALL` option (kern_exit.c XOR check) |
| B8 | `fallocate(FALLOC_FL_PUNCH_HOLE\|KEEP_SIZE)` | EOPNOTSUPP | deallocate | `kern_fspacectl(SPACECTL_DEALLOC)` |
| B9 | `personality(ADDR_NO_RANDOMIZE)` | stored, no effect: `setarch -R` and debuggers get a randomised image | disable ASLR for the next exec | `procctl(PROC_ASLR_CTL, FORCE_DISABLE/NOFORCE)` |
| B10 | `mlockall(MCL_ONFAULT)` (4) | native `mlockall` rejects the bit: EINVAL | accepted (eager wiring is a strict superset, as for `mlock2`) | STD wrapper |
| B11 | `getrandom(GRND_INSECURE)` (4) | EINVAL | never block; `GRND_INSECURE\|GRND_RANDOM` EINVAL | treat as non-blocking |
| B12 | `open(O_DSYNC)` | `LINUX_O_SYNC` is defined as Linux's `O_DSYNC` bit (010000); both become `O_SYNC` | O_DSYNC → `O_DSYNC`, O_SYNC (04010000) → `O_SYNC`; `F_GETFL` reports them back distinctly | split the defines |
| B13 | `prctl(PR_SET_PTRACER)`, `PR_CAPBSET_READ`, unknown `arch_prctl`, `fcntl` known-but-unsupported cmds | logged as "unsupported" | quiet EINVAL (Linux without Yama / the feature returns EINVAL too) | stop logging known numbers |
| B14 | `personality()` value after `execve` | reset to 0 on every exec | kept (only a set-id image clears PER_CLEAR_ON_SETID) | found by the personality test |
| B15 | `shmctl(SHM_STAT)` | treated the index as an id (IPC_STAT) | index → segment, id returned | found by the ipc test |
| B16 | `mmap(MAP_SHARED_VALIDATE)` (0x03) | EINVAL ("both SHARED and PRIVATE") | MAP_SHARED with strict flag check (EOPNOTSUPP on unknown bits, MAP_SYNC) | |
| B17 | `fcntl(F_SETFL)` | cleared O_SYNC/O_DSYNC (native semantics) | Linux keeps them; only APPEND/ASYNC/DIRECT/NOATIME/NONBLOCK change | found by the openflags test |
| B18 | `open(O_TMPFILE)` (not openat2) | opened the directory | EOPNOTSUPP (EINVAL without O_DIRECTORY/write access) | |
| B19 | `mount(NULL, dir, NULL, MS_PRIVATE\|…)` | EFAULT on the NULL type | NULL type/source are legal for bind/remount/propagation | found by the mount test |
| B20 | `setrlimit/prlimit64` on RLIMIT_NICE… | EINVAL (resource ≥ table size checked first) | dummy limits settable | found by the rlimit test |
| B21 | `ioctl(TCSBRK, 0)` on a pty | ENOTTY (no break_ctl) | 0, as Linux for a tty without break support | found by the tty test |

## 1. Memory

| syscall | option | status | notes |
|---|---|---|---|
| mmap | MAP_SHARED/PRIVATE/FIXED/ANONYMOUS/GROWSDOWN/32BIT | mapped | |
| mmap | MAP_FIXED_NOREPLACE, MAP_POPULATE, MAP_LOCKED | **BUG** B1-B3 | |
| mmap | MAP_NORESERVE, MAP_NONBLOCK, MAP_STACK, MAP_DENYWRITE, MAP_EXECUTABLE, MAP_FILE, MAP_UNINITIALIZED | no-op-hint | Linux itself ignores most of these |
| mmap | MAP_HUGETLB (+MAP_HUGE_2MB/1GB), MAP_SYNC | **BUG** B4/B5 | |
| mmap | MAP_SHARED_VALIDATE (0x03) | GAP | Linux: like MAP_SHARED but unknown flags are EOPNOTSUPP; treat as MAP_SHARED with strict flag check |
| mprotect | PROT_GROWSDOWN | mapped | PROT_GROWSUP ignored (x86 has no grows-up stacks: Linux EINVAL) — make it EINVAL |
| mprotect | PROT_SEM, PROT_SAO | rejected-correctly | EINVAL (x86 Linux ignores PROT_SEM; harmless either way) |
| madvise | all 0..25, 100..103 | see coverage doc §3.1 | complete after the alignment fix |
| mremap | MAYMOVE, FIXED | mapped | |
| mremap | MREMAP_DONTUNMAP | rejected-unimplementable | EINVAL; no VM_DONTUNMAP-like move |
| msync | MS_ASYNC/SYNC/INVALIDATE | mapped | |
| mlock2 | MLOCK_ONFAULT | mapped | |
| mlockall | MCL_CURRENT/FUTURE | mapped (native) | MCL_ONFAULT **BUG** B10 |
| mincore | - | mapped | |
| process_madvise | see coverage doc | | |
| pkey_* | see coverage doc | | PKU path still unverified on hardware |
| membarrier | all CMD_* incl. RSEQ, SYNC_CORE, GET_REGISTRATIONS | mapped | |
| rseq | register/unregister, RSEQ_FLAG_UNREGISTER, RSEQ_FLAG_SLICE_EXT_DEFAULT_ON | mapped | DEFAULT_ON is accepted without advertising the unavailable slice extension |
| memfd_create | MFD_CLOEXEC/ALLOW_SEALING/HUGETLB(+sizes) | mapped | MFD_NOEXEC_SEAL / MFD_EXEC (6.3) **GAP**: EINVAL today; NOEXEC_SEAL = create with F_SEAL_EXEC (we have no SEAL_EXEC) → keep EINVAL, quiet |
| mseal, memfd_secret, map_shadow_stack, userfaultfd, remap_file_pages, mbind/set_mempolicy/… | DUMMY | ENOSYS | mseal is the only one worth doing (M: vm_map flag) |

## 2. Process / signals / scheduling

| syscall | option | status | notes |
|---|---|---|---|
| clone/clone3 | VM, FS, FILES, SIGHAND, CLEAR_SIGHAND, THREAD, PARENT, VFORK, SETTLS, *_SETTID, CHILD_CLEARTID, PIDFD, DETACHED rules | mapped | |
| clone/clone3 | CLONE_SYSVSEM, CLONE_IO, CLONE_PTRACE, CLONE_UNTRACED | no-op-hint | SYSVSEM: semadj sharing not modelled (documented) |
| clone/clone3 | CLONE_NEW* (7 namespaces) | **BUG** B6 | |
| clone3 | NEWTIME, INTO_CGROUP, set_tid | rejected-correctly | |
| clone3 | *post-7.3* CLONE_AUTOREAP (1<<34), CLONE_NNP (1<<35), CLONE_PIDFD_AUTOKILL (1<<36), CLONE_EMPTY_MNTNS (1<<37) | rejected-correctly (EINVAL: unknown bit) | AUTOREAP and NNP are cheap to add later (NNP = procctl NO_NEW_PRIVS on the child) |
| wait4/waitid | WNOHANG/WUNTRACED/WCONTINUED/WEXITED/WSTOPPED/WNOWAIT, __WCLONE | mapped | __WNOTHREAD accepted as no-op (FreeBSD waits are per-process: superset) |
| wait4/waitid | __WALL | **BUG** B7 | |
| waitid | P_PIDFD | mapped | |
| exit_group, set_tid_address, set_robust_list/get_robust_list | mapped | |
| prctl | PDEATHSIG, DUMPABLE, KEEPCAPS, NAME, SECCOMP(get), CHILD_SUBREAPER, NO_NEW_PRIVS, TIMING, TSC(get), SECUREBITS, TID_ADDRESS | mapped | |
| prctl | SET_VMA, SET_TIMERSLACK/GET, THP_DISABLE, SPECULATION_CTRL, SET_MM, CAPBSET_DROP, SET_PTRACER, MPX_*, SET_TSC(SIGSEGV) | rejected-correctly | B13: stop logging |
| prctl | PR_GET_AUXV (0x41555856) | GAP-S | copy the process auxv (glibc `getauxval` fallback, sanitizers) |
| prctl | PR_CAP_AMBIENT (47) | GAP-S | IS_SET → 0, RAISE → EPERM (nothing is permitted+inheritable), LOWER/CLEAR_ALL → 0, bad cap EINVAL; systemd probes it |
| prctl | PR_CAPBSET_READ (23) | GAP-S | 1 for 0..CAP_LAST_CAP (40), EINVAL above — nothing is ever dropped from the bounding set here |
| prctl | PR_SET_MDWE / PR_GET_MDWE (65/66) | GAP-S | store per process (inherited on fork unless NO_INHERIT, kept over exec); enforce in mmap/mprotect: W+X or adding X to a non-X mapping → EACCES. systemd `MemoryDenyWriteExecute=` |
| prctl | PR_MCE_KILL / PR_MCE_KILL_GET (33/34) | GAP-S | store the policy (LATE/EARLY/DEFAULT), validate args as Linux; QEMU sets it |
| prctl | PR_SET_IO_FLUSHER / GET (57/58) | GAP-S | root-only bit, store; no scheduling effect |
| prctl | PR_TASK_PERF_EVENTS_ENABLE/DISABLE (31/32) | GAP-S | 0 (no perf events exist) |
| prctl | PR_SCHED_CORE (62), PR_SET/GET_MEMORY_MERGE (67/68), PR_SET_SYSCALL_USER_DISPATCH (59), PR_SET/GET_TAGGED_ADDR_CTRL (55/56), shadow-stack status (74-76), PR_TIMER_CREATE_RESTORE_IDS (77), PR_FUTEX_HASH (78), PR_RSEQ_SLICE_EXTENSION (79), PR_GET/SET_CFI (80/81) | rejected-correctly | EINVAL, quiet: Linux returns EINVAL without the respective CONFIG; SYSCALL_USER_DISPATCH is what Wine wants (L: needs a syscall-entry hook) |
| prctl | UNALIGN/FPEMU/FPEXC/ENDIAN, FP_MODE, SVE/SME/PAC, RISCV/PPC | rejected-correctly | EINVAL on x86 |
| arch_prctl | see coverage doc; SET_CPUID ENODEV, LAM ENODEV, SHSTK EOPNOTSUPP | | REQ_XCOMP_PERM fixed 2026-09-12 |
| seccomp | SET_MODE_STRICT/FILTER, GET_ACTION_AVAIL, GET_NOTIF_SIZES | rejected-correctly | EINVAL/EOPNOTSUPP as without CONFIG_SECCOMP; a filter engine would be L |
| personality | READ_IMPLIES_EXEC | mapped | ADDR_NO_RANDOMIZE **BUG** B9; UNAME26, ADDR_COMPAT_LAYOUT, MMAP_PAGE_ZERO, ADDR_LIMIT_3GB, STICKY_TIMEOUTS, WHOLE_SECONDS, SHORT_INODE no-op (Linux mostly ignores them on x86-64 too) |
| sched_setattr/getattr, sched_setscheduler, sched_[gs]etaffinity, sched_yield, getcpu, ioprio_* | mapped | SCHED_RESET_ON_FORK bit in sched_setscheduler policy: EINVAL (as setattr) |
| setpriority/getpriority, getrusage (RUSAGE_THREAD = 1 on both) | mapped (native) | |
| getrlimit/setrlimit/prlimit64 | CPU, FSIZE, DATA, STACK, CORE, RSS, NPROC, NOFILE, MEMLOCK, AS | mapped | |
| prlimit64 | RLIMIT_NICE, RTPRIO, RTTIME, SIGPENDING, MSGQUEUE, LOCKS | GAP-S | today EINVAL, which breaks `ulimit -i/-e/-r/-q` and systemd `Limit*=` units. NICE/RTPRIO = 0 (FreeBSD denies raising anyway, so 0 is exact), RTTIME/LOCKS = infinity, SIGPENDING = kern.sigqueue.max_pending, MSGQUEUE = 819200; store per process, validate soft ≤ hard, raising hard needs root |
| kill/tgkill/tkill, rt_sig*, sigaltstack (SS_AUTODISARM), rt_sigqueueinfo/rt_tgsigqueueinfo (SI_TKILL rule) | mapped | |
| signalfd/signalfd4 | mapped | `linux_signalfd.c`: own file type over `kern_sigtimedwait()` (read = dequeue for the reading thread, 128-byte records, several per read, NONBLOCK/CLOEXEC, mask replace, SIGKILL/SIGSTOP dropped), poll/epoll readiness via a new kernel `process_signal` eventhandler in `tdsendsignal()`; Linux-only ABI (the hook is generic) |
| capget/capset | v1/v2/v3 | mapped | |
| kcmp | FILE, FILES, SIGHAND, VM | mapped | FS, IO, SYSVSEM, EPOLL_TFD: EINVAL — Linux would compare; EOPNOTSUPP is the honest errno (change) |
| process_vm_readv/writev | mapped | |
| ptrace | PEEK/POKE, CONT, KILL, ATTACH/DETACH, TRACEME, SYSCALL, SINGLESTEP, register and regset access, GETSIGINFO, PEEKSIGINFO, SETOPTIONS, GETEVENTMSG, signal-mask and metadata requests, SEIZE, INTERRUPT, LISTEN | named amd64 Linux64 subsets are VM-qualified | seccomp filter requests remain; SEIZE, INTERRUPT, and LISTEN contracts are documented separately |

## 3. Files and descriptors

| syscall | option | status | notes |
|---|---|---|---|
| open/openat/creat | all O_* incl. O_PATH, O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, O_DIRECT, O_ASYNC, O_LARGEFILE, O_NOCTTY | mapped | O_NOATIME accepted and ignored (needs ownership on Linux; no per-open equivalent); O_DSYNC **BUG** B12; O_TMPFILE EOPNOTSUPP; *post-7.3* O_EMPTYPATH (0x4000000) → EINVAL until added (S: it is AT_EMPTY_PATH for open) |
| openat2 | see coverage doc §4.5 | | |
| fcntl | DUPFD, DUPFD_CLOEXEC, DUPFD_QUERY, GETFD/SETFD, GETFL/SETFL, GETLK/SETLK/SETLKW(64), GETOWN/SETOWN, GETOWN_EX/SETOWN_EX, GETSIG/SETSIG, ADD_SEALS/GET_SEALS, GETPIPE_SZ/SETPIPE_SZ | mapped | |
| fcntl | F_OFD_GETLK/SETLK/SETLKW | rejected-unimplementable | EINVAL + one log; needs description-owned locks in kern_lockf (M) |
| fcntl | F_SETLEASE/GETLEASE, F_NOTIFY, F_GETOWNER_UIDS, F_CREATED_QUERY, F_CANCELLK, F_GETDELEG/SETDELEG | rejected-correctly | EINVAL — make it quiet (B13) |
| fcntl | F_GET_RW_HINT / F_SET_RW_HINT | GAP-S | write-life hints: accept 0..5, report NOT_SET; F_*_FILE_RW_HINT are EINVAL on Linux ≥ 5.x too |
| fcntl | F_SEAL_FUTURE_WRITE, F_SEAL_EXEC | rejected-unimplementable | EINVAL (backlog) |
| read/write/pread/pwrite/readv/writev/preadv/pwritev | mapped | |
| preadv2/pwritev2 | RWF_HIPRI | mapped | Accepted as a direct-I/O hint; io_uring still requires IOPOLL support. |
| preadv2/pwritev2 | RWF_DSYNC, RWF_SYNC | mapped | Passed as per-operation native file-write policy. |
| preadv2/pwritev2 | RWF_NOSIGNAL | mapped | Suppresses SIGPIPE for pipe and socket writes; accepted as a read no-op. Direct, io_uring, shared squeue and legacy AIO paths are gated. |
| preadv2/pwritev2 | RWF_NOWAIT, RWF_ATOMIC, RWF_DONTCACHE | rejected-correctly | EOPNOTSUPP (Linux returns that on filesystems without support); RWF_NOAPPEND is mapped independently. |
| fallocate | mode 0 | mapped | KEEP_SIZE alone, ZERO_RANGE, COLLAPSE_RANGE, INSERT_RANGE, UNSHARE_RANGE, WRITE_ZEROES: EOPNOTSUPP (rejected-correctly); PUNCH_HOLE|KEEP_SIZE mapped through fspacectl; PUNCH_HOLE without KEEP_SIZE EOPNOTSUPP as Linux |
| sync_file_range | all 3 flags | mapped; Linux validation/order, conservative full-vnode fdatasync backend | |
| copy_file_range, sendfile, splice→EINVAL, tee/vmsplice DUMMY | | splice **GAP-M**: pipe↔file/socket/pipe with SPLICE_F_NONBLOCK (Rust `std::io::copy`, systemd-journal); direct tee/vmsplice stay ENOSYS; io_uring TEE flags, offsets, ordinary/fixed input and output, errors, and ordering are gated |
| fsync/fdatasync/syncfs/sync | mapped | |
| lseek SEEK_DATA/SEEK_HOLE | mapped (native) | |
| ftruncate/truncate | mapped | direct and io_uring FTRUNCATE field, fixed-file, file-type, length/error-ordering, side-effect, and recovery contracts are gated |
| dup/dup2/dup3(O_CLOEXEC) | mapped | |
| close_range | CLOSE_RANGE_CLOEXEC | mapped | CLOSE_RANGE_UNSHARE: EINVAL (needs fd-table unshare: M; documented) |
| pipe2 | O_CLOEXEC, O_NONBLOCK | mapped | O_DIRECT (packet mode) EINVAL rejected-unimplementable; O_NOTIFICATION_PIPE EINVAL rejected-correctly; io_uring PIPE creation flags, reserved fields, ignored FIXED_FILE, copyout rollback, and recovery are gated |
| eventfd2 | EFD_CLOEXEC/NONBLOCK/SEMAPHORE | mapped | |
| timerfd_create/settime/gettime | TFD_CLOEXEC/NONBLOCK, TFD_TIMER_ABSTIME, TFD_TIMER_CANCEL_ON_SET | mapped | |
| epoll_* | EPOLLIN/OUT/ERR/HUP/RDHUP/PRI, ET, ONESHOT, EXCLUSIVE, WAKEUP; epoll_pwait2 | mapped | EPOLLRDBAND/WRBAND/MSG EINVAL; direct and io_uring EPOLL_CTL operation, event-copy, reserved-field, error-ordering, and ignored fixed-file contracts are gated |
| inotify_* | all | mapped | |
| fanotify_* | DUMMY | ENOSYS | L |
| stat/fstat/lstat/newfstatat | AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH, AT_NO_AUTOMOUNT | mapped | AT_STATX_SYNC_AS_STAT/FORCE_SYNC/DONT_SYNC on fstatat: **GAP-S** accept (they are hints) |
| statx | mask (all basic + BTIME) | mapped; io_uring reserved-field/fixed-file ordering gated | **GAP-S**: STATX_MNT_ID (fill from st_dev / f_fsid and set the bit only when asked), STATX_ATTR_IMMUTABLE/APPEND/NODUMP from `st_flags` with `stx_attributes_mask`; STATX_MNT_ID_UNIQUE/DIOALIGN/SUBVOL/WRITE_ATOMIC/DIO_READ_ALIGN not reported (correct: bits absent from stx_mask) |
| statfs/fstatfs | f_type magics for ufs/zfs/cd9660/nfs/ext2fs/procfs/msdosfs/ntfs/devfs/tmpfs/sysfs | mapped | |
| getdents/getdents64, readlink(at), symlink(at), link(at) (AT_SYMLINK_FOLLOW, AT_EMPTY_PATH), unlink(at) (AT_REMOVEDIR), mkdir(at), rmdir, rename(at)(2), mknod(at), chmod/fchmod(at)(2), chown/fchown/lchown/fchownat, access/faccessat(2), utime*/utimensat (UTIME_NOW/OMIT), chdir/fchdir/chroot, umask, getcwd | mapped; io_uring rename/unlink/mkdir/symlink/link reserved-field and fixed-file ordering gated | |
| xattr family incl. *xattrat | mapped | CREATE/REPLACE (including both bits), full-size existence checks, zero-size queries, and ERANGE-without-prefix-copy are gated; io_uring path/fd and fixed-file forms share this policy |
| name_to_handle_at/open_by_handle_at | mapped | AT_HANDLE_FID / AT_HANDLE_MNT_ID_UNIQUE / AT_HANDLE_CONNECTABLE: check & add (S) |
| flock | LOCK_SH/EX/NB/UN | mapped (native) | LOCK_MAND EINVAL (Linux ≥ 5.14 too) |
| ioctl (generic) | FIONREAD/TIOCINQ, FIONBIO, FIOASYNC, FIOCLEX/FIONCLEX, FIOSETOWN/GETOWN | mapped | **GAP-S**: FIGETBSZ (st_blksize), FIOQSIZE (size for reg/dir/link, ENOTTY otherwise) |
| ioctl (fs) | FS_IOC_GETFLAGS / FS_IOC_SETFLAGS | **GAP-S** | ↔ `chflags`: IMMUTABLE_FL↔SF/UF_IMMUTABLE, APPEND_FL↔SF/UF_APPEND, NODUMP_FL↔UF_NODUMP; any other modifiable bit set → EOPNOTSUPP. `chattr`/`lsattr`, backup tools |
| ioctl (fs) | FS_IOC_FSGETXATTR/FSSETXATTR, FS_IOC_GETVERSION, FIEMAP, FICLONE(RANGE), FIDEDUPERANGE, FITRIM, FIFREEZE/FITHAW, FS_IOC_GETFSLABEL/UUID | rejected-correctly | ENOTSUP/ENOTTY as a filesystem without them |
| mount | MS_RDONLY, NOSUID, NOEXEC, REMOUNT; fstype ext2/proc/vfat/fuse renames | mapped | **GAP-M**: mask MS_MGC_VAL; MS_BIND → nullfs; MS_SYNCHRONOUS, MS_NOATIME, MS_NOSYMFOLLOW → MNT_*; MS_NODEV, RELATIME, STRICTATIME, LAZYTIME, NODIRATIME, DIRSYNC, SILENT, I_VERSION, POSIXACL → no-op; MS_PRIVATE/SHARED/SLAVE/UNBINDABLE(+MS_REC) → 0 (propagation is meaningless without mount namespaces); MS_MOVE → EINVAL; MS_MANDLOCK → EPERM |
| umount2 | MNT_FORCE | mapped | MNT_DETACH: EINVAL today — no lazy unmount exists; **decision needed** (keep EINVAL, or `compat.linux.umount_detach_force` knob); MNT_EXPIRE EINVAL; UMOUNT_NOFOLLOW **GAP-S** (refuse when the last component is a symlink) |
| fsopen/fsconfig/fsmount/fspick/move_mount/open_tree/mount_setattr/open_tree_attr | DUMMY | L |
| statmount/listmount | DUMMY | M (util-linux 2.40, systemd) |
| quotactl/quotactl_fd | DUMMY | S-M onto `quotactl(2)` if ever wanted |

## 4. Sockets

| level / area | option | status | notes |
|---|---|---|---|
| domains | UNIX, INET, INET6, NETLINK(route, uevent), AX25→CCITT, IPX, APPLETALK | mapped | **GAP-S: AF_VSOCK (40)** — `sockaddr_vm` is byte-identical after the family field, `SOL_VSOCK`(287)/AF_VSOCK-level options, `IOCTL_VM_SOCKETS_GET_LOCAL_CID` (0x7b9 → native _IOR('v',0xb9)); this fork has a full vsock stack, Linux guests/containers expect it |
| domains | AF_PACKET, AF_ALG, AF_KEY, AF_BLUETOOTH, AF_CAN, AF_XDP, … | rejected-correctly | EAFNOSUPPORT; each is a subsystem (AF_KEY → PF_KEY is S but nothing calls it) |
| socket type flags | SOCK_NONBLOCK, SOCK_CLOEXEC; accept4 same | mapped | io_uring BIND/LISTEN sockaddr preparation, reserved fields, fixed-file lifetime, file types, errors, side effects, and recovery are gated |
| SOL_SOCKET | DEBUG, REUSEADDR, TYPE, ERROR, DONTROUTE, BROADCAST, SNDBUF/RCVBUF(+FORCE→plain), KEEPALIVE, OOBINLINE, LINGER, REUSEPORT, PASSCRED(SCM_CREDENTIALS), PEERCRED, RCVLOWAT/SNDLOWAT, RCV/SNDTIMEO (old+new), ACCEPTCONN, TIMESTAMP/TIMESTAMPNS (old+new), PROTOCOL, DOMAIN, PEERGROUPS, PEERSEC, NO_CHECK(0), BSDCOMPAT, PASSRIGHTS(1) | mapped | |
| SOL_SOCKET | SO_PEERPIDFD (77) | **GAP-S** | LOCAL_PEERCRED `cr_pid` → a pidfd (our pidfd type); systemd/dbus-broker use it, fall back to PEERCRED |
| SOL_SOCKET | SO_PASSPIDFD (76) + SCM_PIDFD (0x04) | GAP-M | needs cmsg synthesis on receive |
| SOL_SOCKET | SO_TIMESTAMPING | rejected-unimplementable | ENOPROTOOPT (logged) |
| SOL_SOCKET | SO_PRIORITY, MARK, BINDTODEVICE/IFINDEX, ATTACH_*FILTER/BPF, INCOMING_CPU/NAPI_ID, COOKIE, ZEROCOPY, TXTIME, BUSY_POLL*, MEMINFO, PEEK_OFF, LOCK_FILTER, NOFCS, RXQ_OVFL, WIFI_STATUS, SELECT_ERR_QUEUE, CNX_ADVICE, NETNS_COOKIE, BUF_LOCK, RESERVE_MEM, TXREHASH, RCVMARK, RCVPRIORITY, INQ, DEVMEM_*, SECURITY_* | rejected-correctly | ENOPROTOOPT, quiet; *post-7.3* SO_RIGHTS_NOTRUNC (85) same |
| IPPROTO_IP | TOS, TTL, HDRINCL, OPTIONS, MINTTL, RECVTTL, RECVTOS, PKTINFO, MTU_DISCOVER (DO/DONT/WANT), MULTICAST_IF/TTL/LOOP, ADD/DROP_MEMBERSHIP, (UN)BLOCK_SOURCE, ADD/DROP_SOURCE_MEMBERSHIP, MCAST_JOIN/LEAVE(_SOURCE)_GROUP, MCAST_(UN)BLOCK_SOURCE, MULTICAST_ALL(0), FREEBIND(root), PROTOCOL(get), RECVERR(handled by name) | mapped | |
| IPPROTO_IP | IP_MTU (get) | rejected-unimplementable | logged; FreeBSD has no per-socket path MTU for IPv4 |
| IPPROTO_IP | RECVOPTS/RETOPTS, MSFILTER, MCAST_MSFILTER, ROUTER_ALERT, NODEFRAG, TRANSPARENT, ORIGDSTADDR, PASSSEC, CHECKSUM, BIND_ADDRESS_NO_PORT, RECVFRAGSIZE, UNICAST_IF, LOCAL_PORT_RANGE, PMTUDISC_PROBE/INTERFACE/OMIT | rejected-correctly | ENOPROTOOPT / EINVAL; IP_BIND_ADDRESS_NO_PORT is a plausible S (bind without port reservation ≈ `IP_BINDANY`? no — leave) |
| IPPROTO_IPV6 | V6ONLY, UNICAST_HOPS, MULTICAST_IF/HOPS/LOOP, JOIN/LEAVE_GROUP, RECVPKTINFO/PKTINFO, RECVHOPLIMIT/HOPLIMIT, RECVTCLASS/TCLASS, RECVPATHMTU/PATHMTU, DONTFRAG, MTU_DISCOVER, MTU(get), MULTICAST_ALL, ADDR_PREFERENCES(TMP/PUBLIC), CHECKSUM, RECVERR(by name), MCAST_* | mapped | |
| IPPROTO_IPV6 | RFC2292 options, ADDRFORM, JOIN/LEAVE_ANYCAST, FLOWINFO/FLOWLABEL_MGR/FLOWINFO_SEND, AUTOFLOWLABEL, MINHOPCOUNT, ORIGDSTADDR, TRANSPARENT, UNICAST_IF, RECVFRAGSIZE, FREEBIND, HDRINCL, ROUTER_ALERT(_ISOLATE), RECVHOPOPTS/HOPOPTS/RTHDR*/DSTOPTS | rejected-correctly | ENOPROTOOPT; IPV6_FREEBIND could mirror IP_FREEBIND (S) |
| IPPROTO_TCP | NODELAY, MAXSEG, CORK, KEEPIDLE/INTVL/CNT, INFO, CONGESTION, MD5SIG, USER_TIMEOUT, FASTOPEN | mapped | |
| IPPROTO_TCP | DEFER_ACCEPT | rejected-unimplementable | accf_data has no timeout; logged |
| IPPROTO_TCP | SYNCNT, LINGER2, WINDOW_CLAMP, QUICKACK, THIN_*, REPAIR*, QUEUE_SEQ, TIMESTAMP, NOTSENT_LOWAT, CC_INFO, SAVE(D)_SYN, FASTOPEN_CONNECT/KEY/NO_COOKIE, ULP, MD5SIG_EXT, ZEROCOPY_RECEIVE, INQ, TX_DELAY, AO_*, IS_MPTCP, RTO_MAX_MS, RTO_MIN_US, DELACK_MAX_US | rejected-correctly | ENOPROTOOPT; TCP_FASTOPEN_CONNECT is a plausible S (FreeBSD TCP_FASTOPEN on a client socket) |
| SOL_UDP (17) | UDP_CORK, UDP_SEGMENT, UDP_GRO, UDP_ENCAP, UDP_NO_CHECK6_* | **GAP-S** | today: "unsupported level" log; make the level known and return ENOPROTOOPT quietly |
| SOL_RAW, SOL_ICMPV6 | ICMP6_FILTER | mapped | |
| SOL_NETLINK, SOL_TLS, SOL_SCTP, SOL_MPTCP, SOL_ALG, SOL_PACKET, SOL_VSOCK | | ENOPROTOOPT / no socket can exist; SOL_VSOCK comes with the AF_VSOCK work |
| send/recv flags | OOB, PEEK, DONTROUTE, CTRUNC, TRUNC, DONTWAIT, EOR, WAITALL, NOSIGNAL, CMSG_CLOEXEC, WAITFORONE (recvmmsg) | mapped | |
| send/recv flags | MSG_MORE (0x8000) | check: must not be EINVAL — treat as no-op hint (Linux corks briefly) | |
| send/recv flags | MSG_FASTOPEN, MSG_ZEROCOPY, MSG_BATCH, MSG_ERRQUEUE, MSG_CONFIRM, MSG_PROBE, MSG_FIN/SYN/RST | rejected-correctly (logged for ERRQUEUE/CONFIRM/…) | MSG_FASTOPEN → plausible S via TCP_FASTOPEN + sendto |
| cmsg | SCM_RIGHTS, SCM_CREDENTIALS↔SCM_CREDS(2), SCM_TIMESTAMP(NS), IP_TTL/TOS/PKTINFO, IPV6_PKTINFO/HOPLIMIT/TCLASS | mapped | SCM_PIDFD, SCM_SECURITY: not produced |
| sockopt misc | SO_RCVBUF semantics (Linux doubles), getsockopt short buffers, optlen 0 rules | mapped | |
| netlink | NETLINK_ROUTE (RTM_GETLINK/GETADDR/GETROUTE …), NETLINK_KOBJECT_UEVENT | mapped | other families EPROTONOSUPPORT |
| socket ioctls | SIOCGIFCONF/COUNT/NAME/INDEX/FLAGS/ADDR/BRDADDR/DSTADDR/NETMASK/MTU/METRIC/HWADDR, SIOCSIFADDR/NETMASK/MTU/METRIC, SIOCADD/DELMULTI, SIOCATMARK, SIOCG/SPGRP, SIOCDEVPRIVATE | mapped | SIOCGSTAMP/SIOCGSTAMPNS, SIOCOUTQ(=TIOCOUTQ **GAP-S** → FIONWRITE), SIOCETHTOOL, SIOCBR*, SIOCGIFPFLAGS, TUNSETIFF: not implemented (ethtool/bridge/tun are subsystems) |

## 5. Time

| syscall | option | status | notes |
|---|---|---|---|
| clock_gettime/settime/getres/nanosleep | REALTIME, MONOTONIC(→UPTIME), PROCESS/THREAD_CPUTIME_ID, MONOTONIC_RAW, REALTIME/MONOTONIC_COARSE, BOOTTIME, per-process/thread cpu clocks (CPUCLOCK encoding) | mapped | REALTIME_ALARM/BOOTTIME_ALARM: EINVAL for timers, mapped for gettime? (verify); TAI → EINVAL (no TAI offset); SGI_CYCLE EINVAL; dynamic (fd) clocks ENOTSUP (Linux: EINVAL — align) |
| clock_nanosleep/nanosleep | TIMER_ABSTIME, EINTR remaining-time rules | mapped | |
| timer_create/settime/gettime/delete | SIGEV_SIGNAL/NONE/THREAD/THREAD_ID; TIMER_ABSTIME | mapped | |
| adjtimex/clock_adjtime | see coverage doc | | |
| gettimeofday/settimeofday/time/times | mapped | |
| getitimer/setitimer, alarm | mapped | |

## 6. IPC

| syscall | option | status | notes |
|---|---|---|---|
| shmget/shmat/shmdt/shmctl | IPC_STAT/SET/RMID/INFO, SHM_STAT(_ANY?), SHM_INFO, SHM_LOCK/UNLOCK | mapped | SHM_HUGETLB flag: check → EINVAL (no hugetlbfs) |
| semget/semop/semtimedop/semctl | GETALL/SETALL/GETVAL/SETVAL/GETPID/GETNCNT/GETZCNT/IPC_*/SEM_INFO/SEM_STAT | mapped | SEM_STAT_ANY (20) / MSG_STAT_ANY / SHM_STAT_ANY: verify, add (S) |
| msgget/msgsnd/msgrcv/msgctl | IPC_*, MSG_INFO/STAT, MSG_NOERROR/EXCEPT | mapped | MSG_COPY (CRIU) EINVAL rejected-correctly |
| mq_* | mapped (native mqueuefs) | mq_notify SIGEV_THREAD via helper | |
| futex | see coverage doc; PI ops LOCK_PI/LOCK_PI2/UNLOCK_PI/TRYLOCK_PI mapped; WAIT_REQUEUE_PI/CMP_REQUEUE_PI ENOSYS; FUTEX_FD ENOSYS (removed in 2.6.26) | | futex_waitv DUMMY (rank #2) |

## 7. Misc

| syscall | status | notes |
|---|---|---|
| uname (release = `compat.linux.osrelease`, default 5.15.0) | mapped | consider raising the default now that the table is 7.3-complete: programs gate on version for e.g. `close_range`, `openat2`, `pidfd_*`, `statx` — all real now |
| sysinfo, getrandom (NONBLOCK/RANDOM; INSECURE **BUG** B11), syslog (see coverage doc), sethostname/setdomainname, reboot (LINUX_REBOOT_CMD_*), vhangup, acct, swapon/swapoff, sync, umask, getpid…, setuid…, setfsuid/gid, getgroups/setgroups, capget/capset | mapped | swapon priority allocation, swapoff lifecycle, and discard policies passed Linux-reference and amd64 ZFS-root VM gates |
| ioperm, iopl | mapped on amd64 | `ioperm` range, privilege and revocation cases and `iopl` same/lower-level unprivileged cases have pinned-Linux oracles and mandatory amd64 ZFS-root VM probes; see gate doc |
| modify_ldt | mapped on amd64 | modern and legacy writes, reads, clears, high index, fork inheritance, descriptor errors and non-present conforming segment tested in pinned Linux and amd64 ZFS-root VM |
| kexec_*, init_module/finit_module/delete_module, lookup_dcookie, ustat, _sysctl, nfsservctl, uselib, personality-era leftovers | DUMMY / UNIMPL | see syscall coverage ranking |
| io_setup/io_submit/io_getevents/io_cancel/io_destroy/io_pgetevents (libaio) | partial amd64 handlers | Backed by native aio(4); see the tested subset and remaining lifecycle work in the syscall coverage document |
| io_uring_setup/enter/register | mapped on Linux64 through shared squeue | Core setup, submission, opcode, registration and lifetime matrices are VM-qualified; NAPI registration and hardware ZCRX remain explicit gaps. |
| landlock_*, keyctl/add_key/request_key, bpf, perf_event_open, userfaultfd, memfd_secret, cachestat, process_mrelease, lsm_*, mseal, set_mempolicy_home_node, listns, rseq_slice_yield, fchroot, file_getattr/setattr, uretprobe/uprobe, map_shadow_stack, kexec_file_load, pivot_root, setns, unshare | DUMMY | ranked in coverage doc §6 |

## 7a. Status 2026-09-12 (end of day)

Implemented and VM-tested (see coverage doc §7 for the run):

* **Wave A** complete: B1–B13 plus B14–B21 above.  Kernel side: new
  `WLINUXALL` wait option (`sys/wait.h`, `kern_exit.c`) so `__WALL` can
  wait for both SIGCHLD and non-SIGCHLD children.
* **Wave B** complete except `O_EMPTYPATH` (post-7.3) and `SO_PASSPIDFD`:
  prctl GET_AUXV / CAP_AMBIENT / CAPBSET_READ / MDWE (enforced in mmap and
  mprotect, inherited unless NO_INHERIT, kept across exec) / MCE_KILL /
  IO_FLUSHER / PERF_EVENTS, quiet EINVAL for the other-architecture and
  CONFIG-less options; fcntl RW hints and quiet unsupported commands; RWF_*
  (HIPRI/DONTCACHE accepted, DSYNC/SYNC via fsync, NOAPPEND, the rest
  EOPNOTSUPP); statx MNT_ID + ATTR_IMMUTABLE/APPEND/NODUMP + AT_STATX_*
  hints; dummy rlimits on by default and settable; kcmp EOPNOTSUPP types;
  FIGETBSZ, FIOQSIZE, FS_IOC_GETFLAGS/SETFLAGS ↔ chflags, RNDGETENTCNT,
  TIOCOUTQ, TCSBRK/TCSBRKP break generation, TIOCSTI=EIO; SEM/SHM_STAT_ANY;
  SO_PEERPIDFD; SOL_UDP level; umount2 UMOUNT_NOFOLLOW; mount MS_BIND (nullfs),
  MS_SYNCHRONOUS/NOATIME/NOSYMFOLLOW, no-op flags, propagation-only calls,
  MS_MGC_VAL masking.  Limitation found: nullfs cannot change flags on
  update, so `MS_REMOUNT|MS_BIND` returns EOPNOTSUPP (documented in the test).
* **Wave C**: AF_VSOCK (domain, sockaddr_vm, SOL_VSOCK/AF_VSOCK option
  levels, IOCTL_VM_SOCKETS_GET_LOCAL_CID) and `splice(2)` (pipe↔file/socket/
  pipe through a kernel buffer, sized by the sink's free space so pipe data
  is never consumed and then lost; offsets, NONBLOCK, hints) plus
  `vmsplice(2)` (readv/writev on the pipe).  `tee` stays ENOSYS (pipes
  cannot be peeked).
* **Wave D started**: `signalfd`/`signalfd4` implemented (kernel hook
  `process_signal` + `DTYPE_LINUXSIGNALFD`), 33-check test incl. storms and
  fork semantics.  Also from the break tests: Linux pipes are now one-way
  (FreeBSD's are full duplex; reading the write end blocked instead of
  EBADF), getdents64 with a tiny buffer no longer skips entries, an
  interrupted untimed/absolute FUTEX_WAIT restarts under SA_RESTART,
  EPOLLHUP is reported on pipes and fully-closed sockets, `mremap` can grow
  and move private anonymous memory (glibc realloc).
* `futex_waitv` implemented: one umtx queue entry per address, all sharing
  a wait channel (new `uq_wchan` field in `struct umtx_q`, honoured at the
  four wake sites in `kern_umtx.c`), sleepqueue-based sleep with absolute
  MONOTONIC/REALTIME deadlines, index of the woken entry returned, exact
  Linux validation (1..128 entries, U32 only, reserved 0, alignment,
  values fitting 32 bits, clock checked only with a timeout), EAGAIN unwind.
  Test: 21 checks incl. an 8x16 storm and cross-fork isolation.
* `mseal` implemented: sealed ranges per process (`linux_pemuldata`),
  inherited by fork, cleared by exec; enforced with EPERM in the emulated
  munmap (now a Linux wrapper, was NOPROTO), mprotect, mremap, MAP_FIXED
  mmap and destructive madvise; ENOMEM on gaps, merge of overlapping seals,
  4096-range cap.  glibc 2.41+ seals ld.so with it.
* Real-userland harness: Alpine musl busybox staged at `/compat/linux`,
  run by `linux_busybox_test` (shell, signals, tar/gzip round trip with
  checksums, text tools, sockets, 500-exec churn).

## 8. Implementation plan

Waves, each = code + option tests + VM run before the next.

(Waves A–C are done; see §7a.  Remaining: D and the deferred list.)

* **Wave A — bugs (B1–B13):** mmap flags, clone namespace flags, `WLINUXALL` + `__WALL`, fallocate PUNCH_HOLE, personality ASLR, mlockall ONFAULT, getrandom INSECURE, O_DSYNC split, quiet known-unsupported logs.
* **Wave B — cheap exactness (GAP-S):** prctl (GET_AUXV, CAP_AMBIENT, CAPBSET_READ, MDWE with enforcement, MCE_KILL, IO_FLUSHER, PERF_EVENTS), fcntl RW hints + quiet cmds, RWF flags, statx attributes/MNT_ID + AT_STATX_*, rlimit NICE/RTPRIO/RTTIME/SIGPENDING/MSGQUEUE/LOCKS, kcmp EOPNOTSUPP, FIGETBSZ/FIOQSIZE/TIOCOUTQ/TCSBRK(0)/RNDGETENTCNT/TIOCSTI(EIO), FS_IOC_GETFLAGS/SETFLAGS, SOL_UDP level, MSG_MORE, SEM/MSG/SHM_STAT_ANY, O_EMPTYPATH, SO_PEERPIDFD, umount2 UMOUNT_NOFOLLOW, mount flag mask + MS_BIND/SYNCHRONOUS/NOATIME/NOSYMFOLLOW/propagation.
* **Wave C — AF_VSOCK** (domain, sockaddr, SOL_VSOCK options, GET_LOCAL_CID ioctl) and **splice** (pipe↔file/socket/pipe).
* **Wave D — kernel-side:** signalfd (sigqueue drain hook), futex_waitv (multi-queue wake in kern_umtx), libaio, mseal, statmount/listmount, OFD locks.
* **Deferred / decisions:** MNT_DETACH policy; `compat.linux.osrelease` default; ptrace project; seccomp filter engine; syscall-user-dispatch (Wine); namespaces (never: jails are not namespaces).

## 9. Test program

The 13 wrappers in `tests/sys/kern/linux_*` are a smoke run.  The target
is a conformance suite where **every row above has at least one positive
and one negative check**, plus adversarial, stress and lifecycle coverage.
Layout stays the same (freestanding static Linux binaries, exit status =
check number, one ATF wrapper each) so it runs under kyua in the VM.

1. **Option matrices (one binary per subsystem, hundreds of checks each):**
   `linux_mmapflags`, `linux_cloneflags`, `linux_waitopts`, `linux_fallocate`,
   `linux_personality`, `linux_openflags` (every O_* incl. DSYNC/SYNC read-back
   via F_GETFL), `linux_prctl2`, `linux_fcntl2`, `linux_rwf`, `linux_statx2`,
   `linux_rlimit2`, `linux_ioctl2` (tty/file/random), `linux_chattr`,
   `linux_mount` (root: nullfs bind, flag no-ops, propagation, UMOUNT_NOFOLLOW),
   `linux_vsock` (loopback CID), `linux_peerpidfd`, `linux_splice`,
   `linux_sockopt2` (every SOL_SOCKET/IP/IPV6/TCP/UDP number × {set,get} ×
   {ok, short optlen, bad pointer, wrong socket type}), `linux_time2` (every
   clockid × every clock syscall), `linux_ipc2` (every *ctl command),
   `linux_signal2` (every SA_* flag, SS_AUTODISARM, sigqueueinfo codes).
2. **Adversarial, for every struct-taking syscall:** NULL/unmapped/partially
   mapped pointers (EFAULT, no crash), size 0 / huge / off-by-one sizes,
   negative and closed fds, fd of the wrong type (pipe, socket, dir, pidfd,
   epoll, memfd) for each fd-taking call, length overflow (`addr+len` wrap),
   unknown high bits in every flags word.
3. **Stress / concurrency:** futex ping-pong and requeue storms (8 threads ×
   100k), pidfd churn (10k spawn/poll/reap), epoll+timerfd+eventfd storm,
   clone3 thread create/join loops, openat2 RESOLVE_BENEATH with random
   path components (fuzz, must never escape), seals vs concurrent writers,
   madvise COLD/PAGEOUT on large ranges under fork, xattr with thousands of
   keys, pkey alloc/free cycling across threads.
4. **Lifecycle:** inheritance and clearing across fork / exec / clone3
   threads for pkeys, MDWE, personality, NO_NEW_PRIVS, subreaper, seals,
   close-on-exec of every new fd type; pidfd readiness ordering under load
   (wait4 after POLLIN must always find the zombie); process exit with
   pidfds held by other processes; unmount with open fds.
5. **Real userland in the VM:** Alpine's static busybox (from the ISO already
   in `~/vm`) run as a Linux binary under the new modules — its own applet
   tests plus scripted shell workloads; a musl Bun build (the actual consumer
   on this box) running its test subset; strace-style syscall census
   (`compat.linux` counters / dtrace `linuxulator` provider) to prove the
   options are exercised.
6. **Negative parity checks against Linux itself:** each test binary also
   runs on a real Linux (the Alpine guest in `~/vm`, `start-alpine.sh`) so
   the *expected* errnos are validated against the reference, not just
   against the man page.

## 10. Session 3 (2026-09-12 evening): hardening, tracing, deeper tests

Bugs found by the adversarial suite after the first commit (all fixed):

| # | Where | Bug | Fix |
|---|-------|-----|-----|
| B22 | linux_signal.c `linux_pksignal` | `pksignal()` return discarded: when the per-process pending cap (`kern.sigqueue.max_pending_per_proc`, 128) is hit an RT signal's value was **silently lost** (sender saw 0, reader saw `si_int` 0). Linux returns `EAGAIN` for a queued RT signal that does not fit. | propagate `EAGAIN` for RT signals with `si_code != SI_USER`; non-RT / `kill()` still coalesce silently (Linux semantics). Note: FreeBSD's cap (128) is far below Linux's default `RLIMIT_SIGPENDING`; apps queuing >128 RT signals see `EAGAIN` earlier than on Linux. |
| B23 | linux_futex.c `linux_futex_waitv` | (a) `sleepq_add()` followed by `sleepq_release()` on an already-passed deadline left the thread with `td_sleepqueue == NULL` → **panic** on its next sleep (in `wait4`). (b) Waker cleared the umtx entry under the chain lock but the sleep was on a different lock → lost wakeup (hang); process single-threading for sibling thread creation surfaced as spurious `ERESTART`. | rewritten around `msleep_sbt()` on a private mutex with a 20 ms re-poll bound, deadline checked before sleeping, `ERESTART` only honoured with a real pending signal; regression checks 22–24 in linux_futex_waitv (300 thread create/join cycles under a waiter, 300 wake-vs-deadline races, duplicate addresses). |
| B24 | linux_file.c `linux_splice` | in-kernel "wait for pipe room" loop deadlocked a single-threaded file→pipe→file pipeline against itself (FreeBSD pipes have no FIONWRITE; room computed on the wrong end). | one bounded chunk (≤64 KiB) per call, blocking left to the pipe's own read/write; short counts like Linux. |
| B25 | linux_mmap.c `linux_mprotect` | a hole anywhere in the range returned 0 (FreeBSD skips gaps); Linux is `ENOMEM`. | `linux_range_all_mapped()` walk (shared with mseal). |
| B26 | linux_event.c `linux_timerfd_create` | unknown clockid → `EOPNOTSUPP`; Linux `EINVAL`. Unknown flags accepted. | `EINVAL` both. |
| B27 | linux_mmap.c | unaligned file offset accepted for file mappings; msync/mprotect unaligned start accepted. | `EINVAL` (Linux). |
| B28 | linux_socket.c AF_VSOCK | unknown option → native `EOPNOTSUPP`; Linux `ENOPROTOOPT`. | mapped. |

New: `mseal(2)` (per-process sealed ranges, inherited by fork, dropped by exec; enforced in munmap/mprotect/mremap/MAP_FIXED/destructive madvise; emulator cap 4096 ranges → `ENOMEM`, re-sealing a sealed page still succeeds). Known deviation: a blocked `signalfd` read captures the mask at call time; Linux re-evaluates an updated mask for already-blocked readers.

### Tracing (all four paths verified by `linux_trace_test`)

* `libsysdecode`/`truss`/`kdump` include the kernel's `linux_syscalls.c`, so a rebuild of those three gives names for every new call (the guest had stale copies → "UNKNOWN Linux SYSCALL 454"). `truss` additionally got typed decoders for the new calls (usr.bin/truss/syscalls.c).
* DTrace `syscall:linux:*` comes from `linux_systrace_args.c` via `systrace_linux.ko` — that module must be rebuilt with the table (the runner stages it).
* SDT probes (provider `linuxulator`, `linuxulator32`) on the semantic events: `mmap:linux_mseal_common:sealed(addr,len)`, `mmap:linux_range_sealed:denied(addr,len)`, `futex:linux_futex_waitv:{wait(n),woken(idx,n),timeout(n)}`, `file:linux_splice:moved(fd_in,fd_out,bytes)`, `signalfd:linux_signalfd_common:create(fd,oldfd)`, `signalfd:linux_signalfd_signal:notify(sig)`, `signalfd:linux_signalfd_read:dequeued(sig)`, `pidfd:linux_pidfd_create:create(pid,fd)`, `pidfd:linux_pidfd_send_signal:send(pid,sig)`, `pidfd:linux_pidfd_getfd:getfd(fd)`, `pidfd:linux_pidfd_proc_exit:exit(pid)`.

* Rig gotchas found while writing `linux_trace_test`: `dtrace -c` cannot take
  control of a static Linux binary (libproc waits for an rtld breakpoint that
  never comes: "failed to control pid"), and a backgrounded `dtrace` in the
  guest is not reliably stopped by SIGINT (a `wait` on it hangs the console
  shell).  The test therefore runs the tracee *beside* dtrace and lets the D
  script terminate itself with `tick-12s { exit(0); }`.  FreeBSD `pipe_read`/
  `pipe_write` decide blocking from `fp->f_flag` only (not the ioflag), which
  is why splice checks buffered bytes / free space before touching a pipe.

### Tests added this session

`linux_break_mseal` (seal racing an mprotect flipper, NOREPLACE→EEXIST, mremap into/shrink/grow sealed, 8 concurrent sealers, hole→ENOMEM seals nothing, spanning munmap unmaps nothing, 4096-cap safety, fork storm, guard advice), `linux_break_signalfd` (4 readers × 4 senders exactly-once values, overflow=EAGAIN never loss, thread-directed isolation, dup sharing, fork does not inherit pending, EPOLLET edges, close under blocked readers), `linux_trace` (truss/kdump/DTrace syscall/SDT), futex_waitv 22–24. Runner now host-compiles tests (no in-guest clang under TCG), stages tracing tools, and self-diagnoses hangs with truss.

## 11. procfs/sysfs virtual-file gaps found by running real software (2026-09-13)

Ran jq (C/musl), ripgrep (Rust/musl, threaded) and caddy (Go) as real static
Linux binaries in the VBSD guest and trussed them: ZERO unimplemented syscalls
across all three (the syscall layer is complete for these).  The only gaps were
missing procfs/sysfs virtual files, now added:
- /proc/<pid>/cgroup  -> "0::/" (cgroup v2 unified root; Go/JVM/Node CPU-quota
  detection - caddy warned "failed to set GOMAXPROCS: open /proc/self/cgroup"
  before, silent after).
- /proc/<pid>/cpuset  -> "/".
- /sys/kernel/mm/transparent_hugepage/hpage_pmd_size -> pagesizes[1] (2 MiB),
  read by jemalloc/tcmalloc/Go.
Test: linux_procfs.  (The /etc/ssl/* and /etc/localtime ENOENTs those apps hit
are a bare test rootfs, not emulation bugs.)

## 12. io_uring completion waits and syscall inventory (2026-09-15)

Implemented legacy `io_uring_enter` signal masks and `IORING_ENTER_EXT_ARG`
completion waits in the shared squeue engine. Linux sigsets are translated at
the syscall boundary; native callers retain native sigset layout and numbering.
Relative timeouts and `IORING_ENTER_ABS_TIMER` use CLOCK_MONOTONIC deadlines that
survive repeated wakeups through both the condition-sleep and kqueue paths.
Setup now advertises `IORING_FEAT_EXT_ARG`.

Timeout is Linux ETIME/native ETIMEDOUT, with no fabricated CQE and no request
cancellation. A positive submission count takes precedence over wait errors;
a partial completion batch can also make an interrupted/expired wait succeed.
Signal-mask restoration uses the pselect AST pattern, including delivery of an
interrupting signal before restoring the original mask. The wait itself returns
EINTR even with a SA_RESTART handler. GETEVENTS gates argument inspection;
EXT_ARG structure and timespec pointers are checked even for a zero-event wait,
while a ready CQ avoids unnecessary signal-mask copying. `min_complete` is
clamped to CQ capacity. `min_wait_usec` was unsupported (EINVAL), with
FEAT_MIN_TIMEOUT clear at this audit point; the later
[minimum-wait phase](linuxulator-min-wait.md) implements the timer option.
SQPOLL remains separate work.

Validation on an isolated amd64 QEMU VM with a freshly built VBSD kernel and
linux64 module:
- All **259 Linux io_uring subtests** passed, run as separate processes with
  per-case timeouts. This includes 10 new cases for relative/absolute/expired
  deadlines, both wait paths, partial batches, asynchronous completion,
  invalid arguments, submission/error ordering, legacy/extended signal masks,
  SA_RESTART and restoration after interruption/timeout.
- The native squeue suite passed, including new deadline, native sigset,
  signal delivery and mask-restoration checks.
- The first regression pass had 256 passes and three network-case failures
  because the minimal boot had no loopback address. After configuring lo0,
  all three affected cases passed. No kernel change was needed.
- Kernel and linux64 module builds, freestanding Linux/native test compilation,
  shell syntax, man-page lint and `git diff --check` passed.
- The Linux ATF wrapper now explicitly brands its freestanding binary as Linux,
  so it does not depend on an ELF fallback-brand sysctl configured elsewhere.

Builds and VM disks were staged under `/tmp/iouring-work`; the host kernel was
not replaced. Runtime validation here is amd64 only. The reference semantics
were checked against Linux's `io_uring/io_uring.c`, `io_uring/wait.c` and the
[io_uring_enter manual](https://man7.org/linux/man-pages/man2/io_uring_enter.2.html).
This is raw-syscall and native-suite validation, not a claim of full liburing or
application compatibility.

The coverage document's totals, full table and remaining-work ranking were
refreshed from current source: 315 handlers/native aliases (partial support
included), 54 DUMMY stubs, two hand-written rejection stubs (`rseq`, `seccomp`),
and 15 historical UNIMPL entries. In particular, rseq always returns ENOSYS;
its STD declaration must not count as an implementation. The next recommended
project is OFD locks; ptrace, openat2 resolution, legacy AIO and rseq follow,
with target workload determining their relative priority.
This paragraph records the earlier review snapshot; the current inventory is
[linuxulator-syscall-coverage.md](linuxulator-syscall-coverage.md). Linux64 amd64
rseq is now implemented with a QEMU-gated core contract.

### Follow-up review: eleven passes (2026-09-15)

The initial 259-case run missed two combinations: an expired enter deadline
with a ready poll target, and an expired deadline with a signal pending under
the temporary mask. Both were reproduced in the isolated VM: the former
returned ETIME with an empty CQ, and the latter returned ETIME without delivering
the signal. The follow-up review covered these eleven separate aspects:

| Pass | Aspect | Finding / action |
|---|---|---|
| 1 | Deadline versus completion ordering | Fixed expired waits skipping queued poll readiness; scan once without sleeping, then recheck CQ. |
| 2 | Signal delivery and mask restoration | Fixed expired waits bypassing interrupt checks; use `sig_intr()` outside the ring mutex and preserve EINTR restoration ordering. |
| 3 | Partial batches and submission precedence | Checked that available CQEs and positive submission counts retain their existing precedence over wait errors; added an expired partial-poll regression. |
| 4 | Poll lifecycle and bounded progress | Added idle, single-shot, multishot and fast-poll zero-deadline regressions, including repeated calls and requests surviving expiry. |
| 5 | Time arithmetic and clock selection | Checked normalization, negative intervals, saturation and the Linux monotonic/native uptime mapping; added extreme-time tests with asynchronous completions. |
| 6 | Native/Linux ABI and kernel callers | Preserved the original seven-argument `kern_squeue_enter` symbol; added a separate callback-aware entry point, avoiding a calling-convention change. Extended native signal regressions. |
| 7 | User arguments and feature negotiation | Checked copyin ordering, GETEVENTS gating and mask size/layout; added unsupported min-wait and ready-CQ invalid-mask tests. |
| 8 | Locking, wakeups and ownership | Traced ready-list insertion, waiter registration, ring file references, timeout exits and AST cleanup; no additional issue found in the changed paths. |
| 9 | Test isolation and failure reporting | Fixed the ATF wrapper to invoke named cases as separate processes with per-case timeouts; the shared default harness does not isolate them. |
| 10 | Documentation and syscall inventory | Recounted 386 named slots with the same category totals; checked rseq/seccomp/OFD/openat2 classifications, corrected stale knote comments and removed an unverified upstream version label. |
| 11 | Runtime interruption of inline I/O | The first expanded run exposed a pre-existing panic when a blocking pipe read returned internal `ERESTART` to the Linux errno translator. Normalize it to EINTR before translation; add dedicated Linux/native interrupted-read regressions and make the fast-poll test use a nonblocking pipe. |

The resulting Linux suite has 270 named cases, including eleven new follow-up
cases and expanded argument checks. The native suite additionally checks
signal delivery and mask restoration for both zero relative and expired
absolute deadlines. These passes review the completion-wait change; they are
not a claim of exhaustive concurrency verification of the entire ring engine.

Final follow-up validation on the isolated amd64 QEMU guest:
- **270/270 Linux subtests passed**, each in a separate process with a timeout.
- The native suite passed, including expired signal waits and the interrupted
  inline read. The new read check uses a fresh ring: the earlier capability-mode
  child advances shared ring indices, so reusing the parent's cached indices
  produced a test framing failure until that fixture was corrected.
- Both original review probes passed unchanged: the ready-poll wait returned 0
  with one CQE; the expired signal wait returned EINTR with one handler call.
- The corrected-kernel run had no panic. Its kernel enables INVARIANTS and
  WITNESS. Guest kernel and Linux test hashes matched the staged build; the
  final native test was compiled from the corrected source inside the guest.
- Kernel/module builds, Linux/native compilation with warnings as errors,
  shell syntax, man-page lint and whitespace checks passed.

Runtime logs are `/tmp/iouring-review/console-fix.log` (the newly found panic)
and `/tmp/iouring-review/console-fix2.log` (the corrected-kernel run, including
the native fixture diagnosis and final passing result). The build remains
staged under `/tmp/iouring-work`; the host kernel was not replaced.

### amd64 XSAVE writes and multicast filters (2026-09-22)

[The XSAVE/multicast follow-up](linuxulator-xstate-mcast-options.md) adds
SETREGSET(NT_X86_XSTATE), IP_MSFILTER and IPv4/IPv6 MCAST_MSFILTER GET/SET
subsets. The 111 targeted full-gate executions, Linux references and GDB
checks pass. The broader gate completed with one separately documented,
preexisting io_uring test exception; see the linked record for exact limits. These are options on existing handlers,
so syscall-dispatch coverage counts do not change. No Linux32 support is added.

### io_uring CONNECT and SHUTDOWN option review (2026-09-22)

CONNECT and SHUTDOWN now have a dedicated exhaustive option case. CONNECT
reuses the Linux frontend's preparation-time sockaddr import, including
`EFAULT` and length-error precedence over registered-file lookup. SHUTDOWN's
shared mask and file handling already matched Linux. The case covers all
reserved fields, generic flags, ignored tail words, operation errors,
registered-file lifetime, asynchronous execution, side effects, and recovery.
Linux 6.18.35 passed 20/20 oracle executions; the candidate passed 50/50
focused ZFS/tmpfs executions and the complete 466-case amd64 ZFS-root gate.
The earlier `ioprio_send_zc_fixed_vectorized` exception passed in this clean
full run. Final resource counters were zero, ZFS was healthy, buffers synced,
and QEMU exited zero.

### io_uring SOCKET and ACCEPT option review (2026-09-22)

The option audit found that Linux treats SOCKET as descriptorless and ignores
`IOSQE_FIXED_FILE`, while shared squeue attempted registered-file lookup. A
Linux-only dispatch bypass now matches Linux without changing native squeue.
The dedicated case covers every reserved field, creation and accept flags,
ignored tail words, direct output, registered-listener lifetime, invalid-slot
and non-socket failures, asynchronous execution, side effects, and recovery.
Linux 6.18.35 passed 20/20; the corrected candidate passed 50/50 focused
ZFS/tmpfs runs and the complete 467-case amd64 ZFS-root gate. Final counters
were zero, ZFS was healthy, buffers synced, and QEMU exited zero.

### io_uring SPLICE option review (2026-09-23)

SPLICE's existing ownership is correct: Linux-only flag translation and input
fixed-slot selection stay in the Linux frontend, while shared squeue handles
the request output file. A new exhaustive case covers every accepted hint,
generic options, unused fields, validation ordering, both fixed directions,
lifetime, slot failures, operation errors, asynchronous recovery, and side
effects. Linux 6.18.35 passed 20/20, the candidate passed 50/50 focused
ZFS/tmpfs runs, and the complete 468-case amd64 ZFS-root gate passed with zero
final resources and no diagnostics.

## FILES_UPDATE allocation option review (2026-09-23)

The Linux 6.18 io_files_update_prep() and file-table implementation were
audited against squeue. Existing shared tests already covered the ordinary
update contract, preparation ordering, sparse entries, partial updates,
faults, lifetime and races. The missing option was
IORING_FILE_INDEX_ALLOC, including its writable input-array result and
allocation-hint side effects. That mode is now implemented in shared squeue;
Linux-only translation was unnecessary because the opcode and table are shared.

Linux 6.18.35 accepted the new Linux-facing and shared-backend matrices in
20/20 oracle repetitions each. The amd64 candidate passed 50 focused
ZFS/tmpfs repetitions with unchanged request, wired-page, registered-file,
issuer-reference and issuer-token counters.

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


### `perf_event_open` software-counter option review (2026-09-24)

The former ENOSYS stub is now a deliberately bounded event-fd backend. It
supports current-thread task time, faults, context switches, minor/major faults
and dummy events, including count/read-format and basic ioctl state. Sampling,
groups, mmap rings, PMU/hardware, CPU-wide and cross-target modes are rejected
explicitly and remain in the option queue. The 13-case suite includes structure
versioning, reserved fields, bad pointers/fds, ioctl errors, dup/fork and
thread-exit/close races. See [linuxulator-perf-event.md](linuxulator-perf-event.md).
