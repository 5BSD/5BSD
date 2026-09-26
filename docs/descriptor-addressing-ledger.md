# Descriptor addressing ledger

How every kernel control surface names its target, and which ambient forms
still lack a descriptor (capability) form. The plane's rule is that authority
is a held descriptor, never uid, path, pid or name; this ledger is the queue
for finishing that. Counts are from `sys/kern/syscalls.master` (593 slots,
424 live): FD 132, PATH-with-at 48, PATH-only 16, file-handle 5, pid/tid/id
64, NAME 24, global/ambient 135. Audited 2026-09-26.

## Descriptor types the kernel holds

| DTYPE | Capability for | Origin |
|---|---|---|
| PROCDESC | one process: pdkill, pdgetpid, pdwait, pdcmp, pdincapmode; target of the node, accounting, identity and capprotect services | stock + 5BSD ops |
| JAILDESC | one prison: `JAIL_USE_DESC` family, jail_attach_jd, jail_remove_jd, EVFILT_JAILDESC | stock |
| MAC_CAPABILITY | a service instance: CALL, SENDMSG, RECVMSG, MINT_INSTANCE, REVOKE; services `system`, `node`, `accounting`, `identity`, `coalition`, `capprotect`, `isolation`, `mount`, `channel` | 5BSD |
| ENVFD | a named, sealable environment value; EVFILT_ENVFD | 5BSD |
| ZFSHANDLE | a dataset or pool pinned by guid with a fixed rights mask; minted by name once, then `ZFD_*` by fd only | 5BSD |
| SQUEUE | a completion ring | 5BSD |
| EVENTFD, TIMERFD, INOTIFY, CRYPTO (+EVFILT_CRYPTODESC), KQUEUE, MQUEUE, SHM, SEM, PTS, DEV, SOCKET | stock objects | stock |

## A. Already descriptor-addressed

All file, socket, kqueue and aio I/O; every `*at()` form (open, chroot via
fchroot, execve via fexecve, `__acl_*_fd`, `extattr_*_fd`, `__mac_*_fd`,
getfhat, renameat2, inotify_add_watch_at); pdkill, pdgetpid, pdwait, pdcmp,
pdincapmode; jail_attach_jd, jail_remove_jd; the Capsicum limit family
including `cap_xfer_limit`, `cap_mmap_capmode`, `cap_lookup_capmode`;
squeue_enter and squeue_register; bindat and connectat; close_range.

Pid-addressed syscalls that already have a descriptor form through the
`node` service (target is an attached procdesc, self if none):

| NODE_OP | Replaces |
|---|---|
| STAT, CRED, RUSAGE | kern.proc sysctls, getrusage, `__mac_get_pid` (partly) |
| GET/SET_RLIMIT, GET_RACCT | setrlimit (self only), rctl_get_racct by process |
| GET/SET_NICE | setpriority by pid |
| GET/SET_AFFINITY | cpuset_setaffinity by pid |
| GET/SET_PROCCTL | procctl(P_PID) |
| SET_CRED | setuid family on a child |
| SET_SESSION, SET/GET_PGRP | setsid, setpgid, getpgid |
| GET/SET_UMASK, SET_LOGIN | umask, setlogin |
| GET/SET_RTPRIO | rtprio, sched_setscheduler by pid |
| SET/GET_PDEATHSIG, REAP_* | procctl PDEATHSIG and REAP |
| SIGNAL | kill and sigqueue (no value payload) |

`ACCT_OP_*` replaces rctl_add/remove/get_rules for the process subject;
`COALITION_OP_*` replaces killpg and process-group waiting with a lifecycle
descriptor; `CP_OP_PROTECT` shields a procdesc target; `IDENTITY_OP_QUERY`
reads a procdesc's nonce.

## B. Covered by a provider or kernel gate

| API | Kind | Replacement |
|---|---|---|
| kldload, kldunload | path/id | `SYS_GATE_KLDLOAD/UNLOAD` + `SYS_OP_KLDLOAD/UNLOAD`; BSDExtension ENSURE/STAT/LIST |
| sysctl writes | name | `SYS_GATE_SYSCTL` per-OID claims + `SYS_OP_SYSCTL`; BSDSysctl GET/SET/OIDFMT/DESCR/NEXT |
| settimeofday, clock_settime, adjtime | global | `SYS_GATE_SETTIME` + `SYS_OP_SETTIME/ADJTIME`; BSDTime SET/ADJUST |
| jail, jail_set, jail_get | name/jid | `SYS_GATE_JAIL` + `SYS_OP_JAIL_SET/GET` returning an owning jaildesc; BSDNamespace; consumer self-attach |
| prison operations by jid | jid | isolation `FI_OP_CLAIM_JAIL/MINT_JAIL` |
| mount, nmount, unmount | path | kernel `mount` service (whitelisted fstypes); storage mounts through zfshandle |
| `/dev/zfs` ioctls by dataset name | name | zfshandle: one name mint, then by fd |
| chroot | path | `CP_OP_CHROOT` with a dir fd; fchroot |
| device opens and ioctls (pf, bpf, kmem, acpi, crypto, dtrace) | path | BSDDevice OPEN under a delivered /dev dirfd with rights and ioctl whitelist; BSDPower, BSDCrypto, BSDTrace |
| socket create/bind/connect/listen, AF_VSOCK | global fd factory | isolation `FI_OP_CLAIM_NET/MINT_NET`, `CLAIM_VSOCK`; BSDNetwork RESOLVE/CONNECT/UDP/LISTEN; BSDVM vsock |
| vnode operations on a specific object, AF_UNIX connect | path | isolation `FI_OP_CLAIM/MINT` keyed by vnode |
| setuid family for a principal, sudo | global | BSDAuth MINT_SESSION/ELEVATE/MINT_AUTH |
| syslog, log files by path | path | BSDLog WRITE/FLUSH/QUERY |
| ptrace, kill, wait, sched, ktrace, core, fork, exec, IPC, SCM_RIGHTS, socket against a protected target | pid (target side) | capprotect `CP_SF_*` shields (protects the target; does not address the caller's authority) |

Gates that exist with **no perform op and no claimant**, so a capmode daemon
cannot exercise them at all: REBOOT, SWAPON/OFF, KENV, KENV_READ, ACCT, AUDIT.

## C. Still ambient with no descriptor form

Value: H removes a root-equivalent authority a plane daemon must otherwise
hold; M closes a launcher or supervisor gap; L is legacy surface.

| API | Kind | Descriptor form | Value |
|---|---|---|---|
| ptrace | pid | ptrace on a procdesc (PT_ATTACH by fd); debuggers and crash reporters hold the pd | H |
| ktrace | pid + path | ktrace(procdesc, tracefile fd) | H |
| ntp_adjtime, ffclock_setestimate | global, ungated | `SYS_OP_NTP_ADJTIME` under SETTIME; ntpd is the real clock writer | H |
| ifioctl (SIOCSIFADDR, FLAGS, MTU, ...) | ifname | interface descriptor: `if_open(name)` once, SIOC* on the fd, minted by BSDNetwork | H |
| routing socket, netlink writes | ambient socket | per-FIB route-table descriptor delivered by BSDNetwork | H |
| rctl rules naming jail:, user:, loginclass: | strings | rules bound to a coalition fd, a jaildesc, or a session capability | H |
| wait6/waitid, procctl, cpuset_* | pid | `P_PROCDESC` idtype and `CPU_WHICH_PROCDESC` on the native syscalls | M |
| reboot, kexec_load | global (deny gate only) | `SYS_OP_REBOOT`, kexec by image fd | M |
| swapon, swapoff | path (deny gate only) | perform op taking a device fd from BSDDevice | M |
| kenv | name (deny gate only) | perform ops, or kenv as an envfd | M |
| auditon, auditctl, setaudit, audit pipe preselection | global/path (deny gate only) | audit trail and audit session descriptors; audit-pipe preselect by coalition or jaildesc | M |
| mount/unmount beyond the whitelist | path | mount onto a directory fd; unmount(fd) | M |
| cpuset ids | ambient integers | cpuset descriptor, inheritable through pdfork | M |
| pf ioctls, bpf BIOCSETIF | whole device | pf anchor descriptor; bpf bound to an interface descriptor | M |
| devctl | device path | device-node descriptor as the target | M |
| thr_kill2 | pid + tid | thread descriptor or procdesc+tid | M |
| sched_* and rtprio by pid; kill, sigqueue; setpgid, getsid; `__mac_get_pid`; kcmp; getrusage children | pid | node-service forms exist; native forms stay pid | L |
| ksem_open/unlink; SysV sem/msg/shm ids; shm and mq unlink/rename by name | name/id | deny under a plane rather than build | L |
| quotactl, revoke, undelete, extattrctl, `__mac_execve`, setfib, sysarch, sync, nfssvc family, legacy jail(2), pid/jid kevent filters | path/global | deny or leave; legacy compatibility | L |

## Ranked queue

1. ntp_adjtime perform op under the time gate.
2. Interface descriptor for ifioctl.
3. ktrace on a procdesc with a tracefile fd.
4. ptrace on a procdesc.
5. rctl rules bound to coalition, jaildesc and session capabilities.
6. Route-table descriptor for rtsock and netlink.
7. `P_PROCDESC` and `CPU_WHICH_PROCDESC` on the native syscalls.
8. `SYS_OP_REBOOT` and kexec by fd.
9. swapon/swapoff by device fd.
10. kenv perform ops or kenv as envfd.
11. Audit trail, session and pipe descriptors.
12. General mount onto a directory fd; unmount(fd).
13. cpuset descriptor.
14. pf anchor and bpf-on-interface descriptors.
15. thread descriptor for thr_kill2.
