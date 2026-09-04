# TrustedZFS

TrustedZFS makes ZFS storage a thing a program is handed, not a place it
goes. It adds first-class file descriptors — dataset handles (zfd) and pool
handles (zpd) — over the ZFS management plane, so a process can be granted
"this dataset, these operations, nothing else" as an unforgeable object.
TrustedZFS supports only 64-bit kernels and 64-bit user ABIs; every
returned descriptor is close-on-exec.

## Why the ZFS control plane needed this

Stock ZFS administration is ambient: every operation is an ioctl on
`/dev/zfs` addressed by a dataset name string, re-resolved per call and
authorized centrally (`zfs allow`, `zfs jail`, or root). That means no
unforgeable grants, no ZFS tooling under Capsicum (`cap_enter()` forbids
name lookups, and every `/dev/zfs` ioctl is one), rename races across
multi-step operations, and event delivery monopolized by a single
privileged zed process.

## Three planes, one handoff rule

The capability boundary follows ZFS's own internal structure:

- **Data plane** (bytes) — files via dirfd/`openat`/`mmap`, zvols via a
  block fd. Capsicum already governs this; TrustedZFS adds nothing here.
- **Management plane** (dataset handles) — create, destroy, snapshot,
  rollback, clone, send/recv, properties, mount. This is where TrustedZFS
  lives.
- **Storage plane** (pool handles) — health, capacity, scrub, `bootfs`.
  Thin by design.

Each plane hands down through exactly one door: `ZPD_ROOT_OPEN` (pool →
root dataset handle), and `ZFD_MOUNT` / `ZFD_BLKOPEN` (dataset handle →
dirfd of an anonymous mount, or zvol → block fd). Handles denote objects,
not addresses; doors go one direction; rights only shrink. The management
plane has no read verb, so it can never become a side channel around VFS
enforcement.

## The handle model

A dataset handle pins **(pool guid, dsobj, ds_guid)**. Operations hold the
dataset by object number and verify the guid still matches, so the handle
is rename-proof (it follows the dataset) and destroy-proof (recreate under
the same name yields a new guid; ops return `ENXIO`). After destroy, pool
export, or recv-rollback of the pinned object, everything but `close()`
and `ZFD_INFO` returns `ENXIO` and the handle's kqueue fires `INVALIDATED`.

Each handle carries a rights mask fixed at creation — `ZH_PROPS_READ`,
`ZH_PROPS_WRITE`, `ZH_SNAPSHOT`, `ZH_SNAP_DESTROY`, `ZH_ROLLBACK`,
`ZH_CLONE_SRC`, `ZH_CREATE`, `ZH_DESTROY`, `ZH_SEND`, `ZH_RECV`,
`ZH_MOUNT`, `ZH_HOLD`, `ZH_RELEASE`, `ZH_RENAME`, `ZH_PROMOTE`,
`ZH_BOOKMARK`, `ZH_EVENT` — plus a subtree flag covering
descendants. Two monotonic derivations narrow authority:

- `ZFD_DERIVE(mask)` — same object, fewer rights;
- `ZFD_OPENAT(relname, mask)` — open a child dataset or snapshot through a
  subtree handle. Relative names only; no `..`, no absolute names.

`ZFD_LIMIT` supplies a second monotonic kernel operation ceiling beneath the
immutable `ZH_*` rights. It follows derive/openat/create/clone/pool-root-open
results and survives duplication and SCM_RIGHTS, preventing a delegated child
from using an ioctl omitted by its grantor. `libtrustedzfs` can install the
corresponding Capsicum ioctl allowlist as a fast-path ceiling.

Minting (name → handle) is the only name-based step, done via
`ZFS_IOC_DATASET_OPEN` / `ZFS_IOC_POOL_OPEN` on `/dev/zfs`. It reuses the
existing authorization layers wholesale: root mints anything, an
unprivileged user mints exactly what `zfs allow` delegates, a jailed
process mints only within its visible datasets. Delegation is fd passing —
handles travel over unix sockets via `SCM_RIGHTS` and survive `fork`/`dup`.

## Verbs

Beyond derive/openat/info, dataset handles support properties (get/set/
inherit, single-prop get), listing (children, snapshots, holds, bookmarks),
snapshot/snap-destroy/rollback/promote, holds and bookmarks, `ZFD_SEND` /
`ZFD_RECV` (streams to/from a plain fd — pipe, socket, vsock), `ZFD_CREATE`
/ `ZFD_DESTROY` / `ZFD_RENAME` (all handle-relative), the two-handle
`ZFD_CLONE` (called on the destination parent with the origin passed as an
fd, so "CI can clone the template into its workspace and nowhere else"
falls out of the rights), and `ZFD_MOUNT` / `ZFD_BLKOPEN`.

Cursor-free enumeration is capped at `ZFSHANDLE_ENUM_MAX_ENTRIES` (16384);
the read-only boot tunable `vfs.zfs.trustedzfs.enum_max_entries` may lower but
cannot raise that ceiling, and oversized enumerations fail with `E2BIG`.
Send-once is enforced in kernel handle state, so it survives fd passing:
`ZHF_SEND_ONCE` refuses a second successful stream across the complete
derived/opened handle lineage (`EALREADY`);
`ZHF_SEND_CONSUME` additionally invalidates that lineage — an unforgeable
"one backup stream, then spent" grant.

Pool handles carry the thin delegable sliver: `ZPD_STAT`, property reads and
`bootfs`-only writes for boot-environment activation, `ZPD_SCRUB`, `ZPD_ROOT_OPEN`,
and kqueue events. Import/export, vdev topology changes, and upgrade are
deliberately not delegable — they reshape the pool and stay ambient-admin.

## Mounts without paths

`ZFD_MOUNT` returns a **dirfd of an anonymous mount**: the filesystem is
instantiated but never attached to the namespace (no `v_mountedhere`), so
it is unreachable by path yet fully functional through its root vnode. The
mount stays on `mountlist` for fsid lookup/sync/shutdown, is invisible to
jailed `getfsstat`, and its lifetime anchors on the handle — last close
triggers `dounmount`. The entire mechanism lives in the ZFS module using
already-exported VFS primitives; `zfs_domount` needed zero changes.

## Implementation shape

The kernel side is a shim, placed to keep OpenZFS merges cheap: a new file
`sys/contrib/openzfs/module/os/freebsd/zfs/zfs_handle.c` plus a ~3-line
mint intercept in `zfsdev_ioctl()`. Verbs resolve dsobj → verify guid →
drive the existing upstream ioctl dispatch in-kernel (`FKIOCTL`, kernel
nvlists) — upstream logic is reused, not reimplemented. The fd type is a
real `DTYPE_ZFSHANDLE` (19) with full fileops, `DFLAG_PASSABLE`, and
procstat/fstat integration: `procstat -f` shows
`zfshandle:tank/svc/pgsql [snapshot,mount] valid`.

Userland is `lib/libtrustedzfs` (`tzfs_*`, dependency-free, documented in
`trustedzfs.3`), including Capsicum profiles
(`tzfs_limit_dataset_ioctls()` / `tzfs_limit_pool_ioctls()`) applied per fd
before handles cross a trust boundary. The wrappers validate pointers,
flags, names, handle kinds, buffer lengths, and output ownership before
issuing an ioctl, and truncation is reported rather than silently accepted.

A `trustedzfs` SDT provider fires `mint`, `derive`, `handle-openat`,
`op-entry`/`op-return`, `denied`, and `invalidate`, with canned scripts in
`share/dtrace/` (`trustedzfs-handles`, `trustedzfs-denials`, and friends).
The whole surface is exercised by ATF suites under `tests/sys/zfshandle/`
and a disposable-VM harness.

## Consumers

A service self-mints storage at runtime by opening `system.Filesystem`
(the `tzfsd` broker, next section); `capsule` uses snapshot/rollback
handles plus a `bootfs`-only pool handle for boot-environment management;
WASPNest VMs get zvol checkpoint handles, golden-image `CLONE_SRC`
handles, and send-only migration handles; jails get subtree handles that
replace `zfs jail`.

Not provided: encryption-key verbs (`load-key`/`change-key`), `zfs diff`,
the `userspace`/`groupspace` accounting family, and rich per-dataset kqueue
notes — kqueue delivers `INVALIDATED` readiness only.

Sources: `sys/sys/zfshandle.h`, `lib/libtrustedzfs/`.

## The storage broker (tzfsd)

`tzfsd(8)` owns the storage plane of the capability plane. It is an ordinary
capability bundle, launched and supervised by `serviced` (`boot` activation
plus `ipc` activation for the name `system.Filesystem`), and it is a
socket-free `service_provider`: each client is served on its own
`mac_capability` channel. It retains TrustedZFS parent handles at startup,
creates or opens application datasets on request, attenuates each returned
handle to the requested rights, and delivers it over the channel. It never
proxies application I/O.

**Consumer self-service.** A unit does not declare storage in its manifest
(see [Capability bundle manifests](../system/manifests.md) for the manifest
view). It calls `service_storage_open(3)` at runtime; the library resolves
`system.Filesystem`, `tzfsd` mints a rights-limited `zfshandle`, and the
consumer mounts and drives the handle itself — the handle anchors the mount,
and nothing anywhere names a ZFS path. `service_storage_open_quota(3)` is the
same call with an explicit per-claim `refquota` ceiling in bytes (floor
1 MiB, below it `EINVAL`; 0 selects the daemon's configured
`default_refquota`, which defaults to 1 GiB), so no single claim can fill the
pool. `service_storage_destroy(3)` is the symmetric owner-scoped reclaim of a
persistent or cache claim — it frees the pool space and returns `ENOENT` if
the claim does not exist. `lib/libtzfsd` (`tzfsd_request`,
`tzfsd_request_quota`, `tzfsd_release`, `tzfsd_destroy`, `tzfsd_ping`,
`tzfsd_begin_session`) is the thin client beneath these.

**The label is the address.** `tzfsd` derives each client's dataset
namespace from the unforgeable channel label — a single dataset component
named by a hash of the label, which `serviced` stamped when it brokered the
channel and the client can never choose. Every claim is a single-component
child under that namespace, so a client can only ever create, open, or
destroy storage inside its own subtree; another service's storage cannot
even be named. At mint the claim root is `chown`ed to the requesting
process's uid/gid (base providers run under the unprivileged `capability`
sandbox account), so the consumer can write once it mounts the handle.

**Layout and invisibility.** Everything lives under
`<pool>/Capabilities/{persistent,ephemeral}`; ephemeral splits into
`boot-<boottime>` and per-connection `lease-<session>` generations. The base
dataset is set `mountpoint=none` and `canmount=off`, which propagates by
inheritance: the whole tree is invisible to the OS's boot-time
`zfs mount -a` and reachable only through anonymous handle-mounts.

**Lifetimes.** `persistent` survives everything; `cache` is persistent but
reclaimable by policy or `service_storage_destroy` (cache claims land in
the persistent tree and are never auto-reclaimed);
`boot` survives daemon restarts and is reclaimed a boot generation later;
`lease` is bound to the client's channel and reclaimed when the connection's
session ends. The wire protocol is small and strict — `REQUEST`, `OPEN`,
`RELEASE`, `BEGIN_SESSION`, `PING`, `DESTROY`, fixed-size messages that
reject unknown flags, non-zero reserved bytes, and unsafe dataset names.
`OPEN` delivers isolated *path* descriptors (files or devices) under a
per-label allowlist from the config file; it opens with
`O_NOFOLLOW | O_RESOLVE_BENEATH` so a granted leaf can never be
symlink-swapped out of its subtree, and device grants carry a Capsicum
ioctl allowlist.

**Recovery.** `tzfsd` never erases the ephemeral root at startup — that
would turn a storage-daemon crash into application data loss. Boot
generations are derived from `kern.boottime` and older ones reclaimed; each
live connection owns exactly one `lease-<session>` and orphaned leases from
prior boots are reaped; a client reconnecting after a `tzfsd` crash resumes
its session with `BEGIN_SESSION`. Datasets with retained snapshots make
reclamation fail visibly and leave the tree intact.

**The pool.** `tzfsd` never creates a pool; it requires exactly one to be
imported (default **`zroot`**, overridable in
`/Capabilities/Config/tzfsd.ucl` along with `default_refquota`) and
self-provisions `<pool>/Capabilities` on first start, exiting with
`layout provisioning failed (is pool <name> imported?)` otherwise. ZFS is
therefore a platform requirement: the pool must exist before the storage
plane comes up, which is why the installer's guided Root-on-ZFS path is the
standard 5BSD installation and a pool-less system is a degraded
configuration in which every storage-backed capability fails until an
operator creates a pool by hand.
