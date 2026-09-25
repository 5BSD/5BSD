# Descriptor and Process Protections

Capsicum rights say what a holder may do with a descriptor. They say
nothing about where the descriptor may go: any process can pass it with
`SCM_RIGHTS`, every fork inherits it, every exec keeps it unless
`FD_CLOEXEC` is set, and the holder can clear that flag at will. For a
system in which the descriptor is the authority, that is a hole. 5BSD
adds a set of per-descriptor states that only tighten, process descriptors
that are sufficient authority on their own, and kernel shields that a
launcher can put on a child before it runs. This chapter is the reference
for that surface; the framework that consumes it is in
[The MAC Capability Framework](mac-capability.md).

## The new system calls

All of these are `CAPENABLED` except `pdself`, which is `CAPREQUIRED`. The
numbers are from `sys/kern/syscalls.master`; the source of truth for
semantics is the man page in `lib/libsys` and the implementation in
`sys/kern/sys_capability.c`, `kern_descrip.c` and `sys_procdesc.c`.

| Call (number) | What it does | Who calls it in the tree | Man page |
|---|---|---|---|
| `cap_xfer_limit(fd, state)` (603) | sets transfer state `CAP_XFER_UNLIMITED`, `ONCE` or `NONE`; `ONCE` becomes `NONE` on the first successful send; tightening only | switchboard (channel ends, coalition, capprotect, bootstrap), capsule, BSDAuth (`ONCE` on a minted session channel), sshd monitor, libservice, libcapability `capability_confine_fd()`, every `lib*cmp` client | cap_xfer_limit(2) |
| `cap_xfer_rights_limit(fd, rights)` (606) | ceiling on the rights a receiver gets after a permitted transfer; the sender is unchanged | no plane component yet; tests only | cap_xfer_rights_limit(2) |
| `cap_xfer_ioctls_limit(fd, cmds, n)` (607) | the same ceiling for the ioctl allowlist (effective only if the rights ceiling keeps `CAP_IOCTL`) | tests only | cap_xfer_rights_limit(2) |
| `cap_xfer_fcntls_limit(fd, mask)` (608) | the same ceiling for `CAP_FCNTL_*` | tests only | cap_xfer_rights_limit(2) |
| `cap_cloexec_limit(fd, state)` (604) | `UNLOCKED`, `ONCE` (survive one exec, then locked) or `LOCKED` (closed on exec regardless of `FD_CLOEXEC`) | switchboard, capsule, libchannel (its private dup), libservice, client libraries, BSDBluetooth | cap_cloexec_limit(2) |
| `cap_clofork_limit(fd, state)` (605) | `UNLOCKED`, `ONCE` (one child inherits, then both entries locked) or `LOCKED` (skipped at fork regardless of `FD_CLOFORK`) | switchboard, capsule, libchannel, libservice, sshd session, client libraries | cap_clofork_limit(2) |
| `cap_mmap_capmode(fd)` (634) | monotone flag: the descriptor may be `mmap(2)`ed only from capability mode | `caph_mmap_capmode()` helper only | cap_mmap_capmode(2) |
| `cap_lookup_capmode(fd)` (635) | monotone flag: a directory descriptor may be a `*at(2)` `dirfd` only from capability mode | `caph_lookup_capmode()` helper only | cap_lookup_capmode(2) |
| `pdself(&fd, flags)` (630) | a process descriptor for the caller; `PDF_SELF` close semantics; `EBUSY` if one exists; capability mode only | tests only | pdself(2) |
| `pdcmp(fd1, fd2, &r)` (631) | do two process descriptors name the same process; needs `CAP_PDGETPID` | tests only | pdcmp(2) |
| `pdincapmode(fd)` (633) | is the described process in capability mode | switchboard (launch and supervision) | pdincapmode(2) |
| `envfd_create(name, opts)` | a descriptor holding one named value, with atomic replace, `ENVFD_WRITE_ONCE` sealing, `ENVFD_CAPMODE_ONLY`, and transfer and propagation states installed atomically | switchboard (the bootstrap descriptor); libservice reads it | envfd(2) |
| `mac_capability_channel_create(fds)` (dynamic number) | a self-owned connected endpoint pair with no service and no authority | libchannel, libservice (private lookup channel) | mac_capability_channel(4), libchannel(3) |

Transfer and propagation states are copied by `dup(2)`, follow the
descriptor through `fork(2)` and `SCM_RIGHTS` as their rules dictate, and
are reset only by closing and reopening the file. Widening any of them
fails with `ENOTCAPABLE`. They are invisible to `fcntl(F_GETFD)`: a process
can still set and clear `FD_CLOEXEC` and `FD_CLOFORK` without error, and the
lock overrides at exec or fork time. The kernel enforces transfer state on
both `SCM_RIGHTS` over unix(4) sockets and descriptors attached to
`mac_capability` messages; a `CAP_XFER_ONCE` descriptor is consumed by a
single hop, so a multi-hop delegation is expressed by each forwarder
re-attenuating to `ONCE` rather than by a kernel hop counter (the earlier
`CAP_XFER_TWICE` was removed for that reason).

A typical confinement, as libcapability's `capability_confine_fd()` does it:

```c
cap_xfer_limit(fd, CAP_XFER_NONE);
cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED);
cap_clofork_limit(fd, CAP_CLOFORK_LOCKED);
```

After that the descriptor cannot be sent, cannot survive an exec, and is
not inherited by children, whatever the holder does to its flags. The
inverse pattern, used by switchboard for the bootstrap envfd, is
`CAP_XFER_NONE` plus `CAP_CLOFORK_ONCE` plus `CAP_CLOEXEC_ONCE`: it crosses
exactly the one fork and the one exec of the launch and then locks.

## New rights and CAPENABLED marking

`sys/sys/capsicum.h` gained rights for objects FreeBSD's rights set did not
cover:

| Right | Allows |
|---|---|
| `CAP_JAIL_ATTACH`, `CAP_JAIL_REMOVE`, `CAP_JAIL_SET` | `jail_attach_jd(2)`, `jail_remove_jd(2)`, `jail_set(2)` with `JAIL_USE_DESC` on a jail descriptor |
| `CAP_TIMERFD_GETTIME`, `CAP_TIMERFD_SETTIME` | the timerfd(2) operations |
| `CAP_FCNTL_READAHEAD` | `fcntl(F_READAHEAD)` and `F_RDAHEAD` |
| `CAP_POSIX_FADVISE` | `posix_fadvise(2)` |

`CAP_ALL1` changed to include them, and `CAP_ACL_*` is now enforced. A
sandbox that limits a descriptor's rights explicitly and then calls
`posix_fadvise`, `timerfd_settime` or `F_READAHEAD` must add the new right or
it gets `ENOTCAPABLE`; the inventory flags this as a compatibility risk for
existing Capsicum programs. Tests are
`tests/sys/kern/{jaildesc,timerfd,fcntl_readahead,posix_fadvise}_cap_test.c`.
Separately, `reboot(2)`, `kldload(2)`, `kldunload(2)`, `kldfind(2)`,
`kldnext(2)`, `kldstat(2)`, `kldfirstmod(2)`, `kldunloadf(2)`, `auditon(2)`,
`jail_attach_jd(2)` and `jail_remove_jd(2)` are marked `CAPENABLED` so a
born-in-capability-mode daemon can reach them; whether they succeed is
decided by the `system` service ([System Gates](system-gates.md)).

## Process descriptors as capabilities

5BSD treats a process descriptor as sufficient authority. `pdkill(2)` and
`pdwait(2)` no longer perform the ambient credential, jail and MAC checks
that could override a held descriptor: a supervisor's `pdkill` of its own
child works after the child has execed and rotated its nonce, and after
the child has shielded itself. The descriptor's Capsicum rights
(`CAP_PDKILL`, `CAP_PDWAIT`, `CAP_PDGETPID`) are the only gate. Passing a
process descriptor to a coalition requires `CAP_PDKILL` for the same reason
(see [Coalitions and Accounting](coalitions-and-accounting.md)). An
`EINVAL` for a non-procdesc argument became `EBADF`.

`EVFILT_PROCDESC` reports the lifecycle a supervisor cares about:
`NOTE_FORK`, `NOTE_EXEC`, `NOTE_CAPMODE` (the child entered capability
mode), `NOTE_JAILED`, `NOTE_SETUID` and `NOTE_CHROOT`, in `sys/sys/event.h`.
switchboard promotes a unit to `RUNNING` on `NOTE_CAPMODE`. `pdfork(2)`,
procdesc(4) and kqueue(2) document them; `tests/sys/kern/procdesc.c`,
`pdwait.c` and `tests/sys/mac_capability/mac_capability_procdesc_test.c`
prove them. Where a supervisor needs to look inside or adjust a process it
holds a descriptor for, the `node` kernel service offers 29 operations
(credentials, rlimits, racct, nice, affinity, procctl, umask, rtprio,
pdeathsig, `SET_CRED` via `setcred(2)`, signal, and the reaper facility),
all authorized by holding the node instance rather than by the caller's
identity; see mac_capability_node(4).

## capprotect shields

The `capprotect` service (mac_capability_capprotect(4)) is a MAC policy
that makes a process opaque to processes that have no business with it. A
shield is keyed to a PID and a per-shield generation, not to a nonce: it
persists across `execve(2)` and across closing the instance that applied
it, and ends only when the process exits, so a reused PID never inherits
one. Forked children are not shielded.

| Operation | Effect |
|---|---|
| `CP_OP_SHIELD` | shield the caller with the given flags; the caller is its own protector |
| `CP_OP_PROTECT` | shield the process named by an attached (still transferable) process descriptor; the caller becomes its protector and keeps signal and wait access |
| `CP_OP_MINT` | mint an access token (a reply fd) conveying a subset of the shield's flags |
| `CP_OP_AUTHORIZE` | on a token fd: the caller may cross the shield for the token's flags, one accessor per token, until the token closes |
| `CP_OP_CAPMODE` | enter capability mode (idempotent) |
| `CP_OP_CHROOT` | change root to an attached directory descriptor |

Flags divide into protections, enforced against foreign processes, and
restrictions, enforced against the shielded process itself. `flags = 0`
means `CP_SF_ALL`.

| Flag | Manifest word | Hook and effect |
|---|---|---|
| `CP_SF_PTRACE` | `ptrace` | `proc_check_debug`: `EACCES` on attach |
| `CP_SF_SIGNAL`, `CP_SF_SIGKILL`, `CP_SF_SIGCONT` | `signal`, `sigkill`, `sigcont` | `proc_check_signal`, `proc_check_suspend`; `SIGKILL` and `SIGCONT` need their own flag |
| `CP_SF_WAIT` | `wait` | `proc_check_wait`; the real parent may always wait |
| `CP_SF_SCHED` | `sched` | `proc_check_sched`: priority and cpuset changes |
| `CP_SF_CORE` | `core` | `proc_check_core`: no dump |
| `CP_SF_KTRACE` | `ktrace` | `proc_check_ktrace` |
| `CP_SF_VISIBLE` | `visible` | accepted for wire compatibility; not enforced in the per-process model |
| `CP_SF_NOPRIVS` | `noprivs` | `priv_check`: every privilege fails |
| `CP_SF_NOFORK`, `CP_SF_NOEXEC`, `CP_SF_NOSOCK` | `nofork`, `noexec`, `nosock` | `proc_check_fork`, `vnode_check_exec`, `socket_check_create` |
| `CP_SF_NOIPC` | `noipc` | SysV and POSIX shm, sem and msq hooks |
| `CP_SF_NOFDRECV` | `nofdrecv` | `file_check_receive`: no ambient `SCM_RIGHTS`; attachments over a held channel are unaffected |
| `CP_SF_PROTECT`, `CP_SF_RESTRICT`, `CP_SF_ALL` | `protect`, `restrict`, `all` | the groups |

Three parties always pass: the process itself, its protector, and a
process that has activated a token for that shield. Same-nonce siblings
get nothing implicit. When no process is shielded every hook returns
without taking a lock. `kern.mac_capability_capprotect.max_auth` (loader
tunable) caps outstanding token authorizations; `.auth_count` reports them.
In the plane, capsule shields itself from `/etc/capsule.conf`
`integrity {}` (the signal flags are mandatory) and protects switchboard;
switchboard applies a unit's manifest `protect` list with `CP_OP_PROTECT`
before the child executes ([Bundles and
Manifests](../plane/bundles-and-manifests.md)); a provider may add to its
own shield with `service_worker_protect()`. Token minting has no plane user
yet.

## Sockets: capability-mode attestation

Three unix(4) socket options let sandboxed peers prove their state to each
other: `LOCAL_CAP_REQ` (this end may send or receive only from capability
mode), `LOCAL_CAP_CONNECT` (only capability-mode processes may connect to
this listener) and `LOCAL_CAPMODE_SERVER` (connect only to a listener
created from capability mode); each is monotone, and a failed check is
`ENOTCAPABLE`. `sockcred2` gained `sc_capmode`, which is why its
`SOCKCRED2_VERSION` changed. See unix(4) and socketpair(2).

## envfd

`DTYPE_ENVFD` is a descriptor that holds one named value. Writes replace
the whole value atomically; reads snapshot it; `ENVFD_WRITE_ONCE` seals it on
the first write for every holder; `ENVFD_CAPMODE_ONLY` makes it usable only
from capability mode; `EVFILT_ENVFD` reports writes and sealing;
`ENVFD_GETINFO` returns name, state, size and generation. Objects and bytes
are charged to the creating real uid under `kern.envfd.max_{objects,bytes,user_objects,user_bytes,value_size}`.
switchboard uses it as the capability-mode-safe carrier for a unit's
bootstrap record, and libservice(3) verifies the name, the `WRITE_ONCE`
flag, the sealed state and the exact size before trusting it. Tests:
`tests/sys/kern/envfd_test.c`; script: `share/dtrace/envfd-events`.

## Coalition membership

A coalition is the group form of the same discipline: enlisting a
descriptor requires the right its teardown would use, and closing the
coalition exercises all of them at once. It is covered in
[Coalitions and Accounting](coalitions-and-accounting.md).

## Tests and status

`tests/sys/kern/cap_xfer_test.c` (transfer states and ceilings across
`SCM_RIGHTS` and message hops), `cap_confinement_test.c` (exec and fork
locks, `cap_mmap_capmode`, `cap_lookup_capmode`), `tests/sys/capsicum/cap_pure_test.c`
(`SYF_CAPREQUIRED`), the procdesc and envfd programs above, and the
capprotect cases in `tests/sys/mac_capability/mac_capability_test.c` with
`shield_helper.c`. Everything in this chapter is shipped. Two things are
available but unused by the plane: the post-transfer ceilings
(`cap_xfer_{rights,ioctls,fcntls}_limit`) and capprotect tokens. The
`vnode_claim` per-descriptor identity ACL that an earlier draft of this
book described is not in the tree.
