# Descriptor Types

5BSD extends the FreeBSD file-descriptor table into a credential system:
for several descriptor types, **the fd is the authority**. This chapter
is a unified reference. The kernel type table in `sys/sys/file.h` adds
three entries beyond stock FreeBSD (17–19); `DTYPE_JAILDESC` (16) is
inherited from FreeBSD and extended by 5BSD with coalition enlistment:

```c
#define	DTYPE_JAILDESC		16	/* jail descriptor */
#define	DTYPE_MAC_CAPABILITY	17	/* mac_capability capability descriptor */
#define	DTYPE_ENVFD		18	/* environment value descriptor */
#define	DTYPE_ZFSHANDLE		19	/* TrustedZFS dataset handle */
```

## The shared substrate: per-descriptor transfer state

Every fd slot (`struct filedescent`, `sys/sys/filedesc.h`) carries an
`fde_xfer_state` and a `fde_xfer_caps` rights ceiling. Transfer states
(`sys/sys/capsicum.h`): `CAP_XFER_UNLIMITED` (default), `CAP_XFER_ONCE`
(one send, then exhausted), `CAP_XFER_NONE`. Companion `CAP_CLOEXEC_*`
and `CAP_CLOFORK_*` states
control survival across exec and fork, including `..._ONCE` variants
(survive one exec / inherit into one child, then lock).

Enforcement lives in `unp_internalize()` (`sys/kern/uipc_usrreq.c`):
every SCM_RIGHTS send checks `DFLAG_PASSABLE` (`EOPNOTSUPP`) and then
the xfer state (`ENOTCAPABLE` if `CAP_XFER_NONE`), emitting the
`fd:::pass__deny` / `fd:::xfer__deny` DTrace probes. An `ONCE` send is a
single hop: it leaves **both** the sender and the receiver at `NONE`, so
the receiver cannot forward it again. Rights are intersected with
`fde_xfer_caps` at transfer. The controlling syscalls are
`cap_xfer_limit(2)`, `cap_cloexec_limit(2)`, `cap_clofork_limit(2)`,
`cap_xfer_rights_limit(2)`, `cap_xfer_ioctls_limit(2)`, and
`cap_xfer_fcntls_limit(2)`.

All descriptor types below are `DFLAG_PASSABLE`; blocking transfer is
always per-descriptor and opt-in via `cap_xfer_limit()`.

## mac_capability fds (DTYPE_MAC_CAPABILITY)

**Represents:** a connection ("instance") to a named kernel service in
the mac_capability framework (`sys/dev/mac_capability/`), carrying a
service-assigned 64-bit badge. The fd is the credential: no ambient
check ever re-derives the authority.

**Obtained:** `open("/dev/mac_capability")` (mode 0600, root only) then
`ioctl(MAC_CAPABILITY_CONNECT)`, which returns the instance fd; or
`MAC_CAPABILITY_MINT_INSTANCE` on an existing instance of a mintable
service. Unprivileged processes receive instance fds from a broker via
SCM_RIGHTS. `read()`/`write()` are disabled; all traffic uses the
structured ioctls `MAC_CAPABILITY_SENDMSG`/`RECVMSG`/`CALL`/`GETINFO`,
plus `REVOKE_SEND`/`REVOKE_RECV`/`REVOKE_CALL`/`TERMINATE`
(`sys/dev/mac_capability/mac_capability_ioctl.h`).

**Lifecycle:** `dup()` shares the same instance and queues; fork
inherits; exec keeps the fd subject to close-on-exec and
`CAP_CLOEXEC_*` state. Last close is a full teardown: queues drain,
in-flight calls complete, the service's revoke hook fires exactly once,
and peers see `ECONNRESET` plus `EV_EOF` on kqueue. Messages may carry
up to 32 attached fds; the message path enforces the same
`CAP_XFER_*` budget as SCM_RIGHTS and propagates the transfer state
onto the fd installed in the receiver.

**Capsicum:** no per-service `CAP_*` rights exist; narrowing uses
`CAP_IOCTL` with `cap_ioctls_limit()` over specific `MAC_CAPABILITY_*`
commands, and `CAP_EVENT` for kqueue. Fully usable inside
`cap_enter()`; new connections cannot be opened from capability mode.
Process identity is a kernel nonce on the credential — inherited on
fork, rotated on exec, unforgeable.

## procdesc (DTYPE_PROCDESC)

**Represents:** a process, addressed without PIDs (`pdfork(2)`,
`pdkill(2)`, `pdgetpid(2)`; `sys/kern/sys_procdesc.c`). 5BSD adds
`pdrfork(2)`, `pdwait(2)`, `pdself(2)` (capability-mode-only:
CAPREQUIRED), `pdcmp(2)`, and `pdincapmode(2)`, plus EVFILT_PROCDESC
lifecycle notes `NOTE_FORK`, `NOTE_EXEC`, `NOTE_SETUID`, `NOTE_CHROOT`,
and `NOTE_CAPMODE`.

**Lifecycle:** last close SIGKILLs a still-running child and reparents
it to the reaper, unless `PD_DAEMON` was set at `pdfork`. A zombie is
reaped inline. 5BSD adds a third branch: when the described process
itself holds the last reference (the `pdself` case), close detaches
without killing. Inherited normally across fork; `PD_CLOEXEC` at
creation, otherwise standard exec rules. Passable via SCM_RIGHTS —
this is how supervisors delegate kill/wait authority.

**Capsicum:** `CAP_PDKILL`, `CAP_PDGETPID`, `CAP_PDWAIT` gate the
operations; `kcmp(2)`-style comparison via `pdcmp`.

## jaildesc (DTYPE_JAILDESC)

**Represents:** a jail, addressed without JIDs. Obtained from
`jail_set(2)`/`jail_get(2)` with the flags `JAIL_GET_DESC` or
`JAIL_OWN_DESC` (plus `JAIL_USE_DESC`/`JAIL_AT_DESC` for addressing);
consumed by `jail_attach_jd(2)` and `jail_remove_jd(2)`, both
capability-mode-enabled (`sys/kern/kern_jaildesc.c`).

**Lifecycle:** an **owning** descriptor (`JAIL_OWN_DESC`, opened
read-write) removes the jail on last close — the jail dies with the
fd. A non-owning descriptor (read-only) just drops its reference.
kqueue delivers `NOTE_JAIL_REMOVE` when the jail is removed. Standard
fork/exec inheritance; passable via SCM_RIGHTS, so jail ownership can
be handed to a supervisor.

**Capsicum:** lookups go through a rights-checked helper; enlisting a
jaildesc into a coalition requires `CAP_JAIL_REMOVE` on the fd.

## Coalition fds

There is no separate DTYPE: a coalition fd **is** a mac_capability
instance connected to the coalition service
(`sys/dev/mac_capability/mac_capability_coalition.c`). Operations are
`MAC_CAPABILITY_CALL` ops: enlist, terminate, stat, set_signal,
graceful, set_deadline, set_watchdog, heartbeat, set_leader, join,
rusage, enlist_set. Members are fds attached to the call — procdesc,
jaildesc, socket, shm, or other mac_capability instances.

**Capsicum:** enlisting requires that the caller already hold the
right to destroy the member: `CAP_PDKILL` for a procdesc,
`CAP_JAIL_REMOVE` for a jaildesc, `CAP_SHUTDOWN` for a socket,
`CAP_FTRUNCATE` for shm. Closing the coalition fd terminates all
members (signal, jail removal, instance revoke). Lifecycle events
(member added/removed, leader died, deadline/watchdog fired) arrive
via kqueue. Nesting is supported to depth 16.

**Resource descriptors as members.** The three resource-bearing
descriptor families below — TrustedZFS handles (`DTYPE_ZFSHANDLE`),
environment values (`DTYPE_ENVFD`), and crypto handles (`DTYPE_CRYPTO`)
— must be enlistable in a coalition so that terminating or closing the
coalition drops the last reference to each member and drives that
family's *own* last-close teardown, rather than leaking the backing
resource. Each already has a safe last-close path that a coalition
close simply triggers: a zfshandle force-unmounts its anon mount and
releases the dataset handle, an envfd `explicit_bzero`s the value and
returns its per-UID and global quotas, and a crypto handle revokes the
key or session. The enlistment right for these follows the same rule as
the other families — the caller must already hold the right that a last
close would exercise (dataset/mount authority, the envfd's write/seal
right, the crypto handle's revoke right) — so that coalition teardown
never performs a release the enlister could not have performed itself.
This bounds a resource's lifetime to its coalition: when the coalition
dies, its datasets unmount, its secrets are zeroed, and its crypto
state is revoked as one atomic teardown.

## envfd (DTYPE_ENVFD)

**Represents:** a named kernel-resident environment value — an
atomically published byte blob with a generation counter, invisible to
process inspection tools (`sys/kern/kern_envfd.c`, `envfd(2)`).
Created via `__specialfd(2)` type `SPECIALFD_ENVFD` (wrapper
`envfd_create(2)`). The name is metadata only; there is no
lookup-by-name — the descriptor is the sole reference.

**Lifecycle:** names are metadata-only identifiers drawn from
`[A-Za-z0-9._-]+`; there is no lookup-by-name. Creation always yields an
`O_RDWR` descriptor because a newly created, unwritten object must remain
writeable, and a holder can then make individual copies read- or write-only
with Capsicum rights. Creation options fix the
`CAP_XFER_*`/`CAP_CLOEXEC_*`/`CAP_CLOFORK_*` states at mint time, including
`CAP_XFER_ONCE` for an exact single-hop creator-to-consumer handoff.
`ENVFD_WRITE_ONCE` seals the shared object after the first successful
write — through `dup()`, `fork()`, and SCM_RIGHTS alike;
`ENVFD_CAPMODE_ONLY` makes data, info, stat, and kqueue operations fail with
`ECAPMODE` outside capability mode; close remains available. Reads before the
first write return
`ENOATTR`. Last close zeroes the value (`explicit_bzero`) and releases
per-real-UID and global object/byte quotas; `kern.envfd.max_value_size`
also caps one object. `procstat` renders the fd as `envfd:<name>` and
reports sizes, generation, flags, and state, but `kf_envfd_addr` is always
zero and neither the value nor a kernel address is exposed.

**Qualification:** `tests/sys/kern/envfd_test.c` covers creation and strict
options, name grammar, read/write and seek semantics, maximum value sizes,
write-once races across duplicated descriptors, kqueue write/seal events,
Capsicum rights and capmode-only use, initial transfer/exec/fork states,
creator→consumer `ONCE` exhaustion, stat/procstat disclosure, fd
exhaustion, global and per-real-UID quotas, cleanup, and malformed operations.
These tests run with the other descriptor families under the matching-kernel
`tools/test/capability-qemu/` guest.

## TrustedZFS capability fds (DTYPE_ZFSHANDLE)

**Represents:** a ZFS dataset or pool handle pinned by (pool guid,
dsobj, dataset guid) with a rights mask fixed at creation
(`sys/sys/zfshandle.h`, `docs/trustedzfs-design.md`). Minted by name
via `ZFS_IOC_DATASET_OPEN`/`ZFS_IOC_POOL_OPEN` on `/dev/zfs` — the
only name-based step; thereafter every operation is a verb ioctl on
the fd: `ZFD_DERIVE` (narrow), `ZFD_OPENAT` (descend, subtree handles
only), snapshot/rollback/send/recv/create/clone/mount/blkopen, and
pool verbs including `ZPD_ROOT_OPEN`, the one-way bridge down to a
dataset handle — a zfd can never climb to pool authority. Rights
(`ZH_SNAPSHOT`, `ZH_SEND`, `ZH_MOUNT`, …) sit beneath Capsicum's
`cap_ioctls_limit()` allowlist; `libtrustedzfs` wraps both layers.
Fd passing is the delegation mechanism, with standard fork/dup
semantics; the tzfsd broker mints and hands out handles.

The in-kernel fileops implementation, `zfshandle_ops`, and the
`finit(..., DTYPE_ZFSHANDLE, ...)` path live in
`sys/contrib/openzfs/module/os/freebsd/zfs/zfs_handle.c`, alongside the userland
(`lib/libtrustedzfs`, `usr.sbin/tzfsd`, `tzfsctl`) and tests. See
[TrustedZFS](../storage/trustedzfs.md) and the
[tzfsd broker](../storage/tzfsd.md).

## Crypto handles (DTYPE_CRYPTO)

`DTYPE_CRYPTO` (6, `sys/sys/file.h`) descriptors are minted by the
`[CRYPTO]` component (`sys/opencrypto/cryptodev.c` fileops): each fd
represents a key or crypto session whose rights only shrink
(monotonic reduction, revoke, TTL). See
[Cryptographic Services](crypto.md) for the full model.

## vnode_claim-bound descriptors

vnode_claim adds per-descriptor, identity-based ACLs: a descriptor
carries a list of allowed process identities, so possession alone is
no longer sufficient to use it. It blocks unauthorized SCM_RIGHTS
propagation, revokes access on exec, supports a lock mode denying all
operations, and targets anonymous descriptors (pipes, socketpairs,
shm) that cannot be re-opened by path (`5BSD.md`).

**Status:** developed as a standalone module (~2,000 lines, 20+
tests); not yet integrated into this tree, and its identity token is
slated to migrate to the mac_capability credential nonce. No syscall
or DTYPE exists in `/usr/src` today.
