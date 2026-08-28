# TrustedZFS

TrustedZFS makes ZFS storage a thing a program is handed, not a place it
goes. It adds first-class file descriptors — dataset handles (zfd) and pool
handles (zpd) — over the ZFS management plane, so a process can be granted
"this dataset, these operations, nothing else" as an unforgeable object.
The dataset and pool handle API, extended verb set, library, broker consumers,
and qualification suites are implemented. TrustedZFS supports only 64-bit
kernels and 64-bit user ABIs; every returned descriptor is close-on-exec. Its
disposable QEMU qualification uses a matching WITNESS/INVARIANTS kernel and 82
cases across 13 ATF programs.

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

Cursor-free enumeration is capped at `ZFSHANDLE_ENUM_MAX_ENTRIES` (16384).
The read-only boot tunable `vfs.zfs.trustedzfs.enum_max_entries` may lower but
cannot raise that ceiling; oversized enumerations fail with `E2BIG` rather
than consuming unbounded kernel memory.

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

Userland is `lib/libtrustedzfs` (`tzfs_*`, ~44 dependency-free functions,
documented in `trustedzfs.3`), including Capsicum profiles
(`tzfs_limit_dataset_ioctls()` / `tzfs_limit_pool_ioctls()`) applied per fd
before handles cross a trust boundary.
The wrappers validate pointers, flags, names, handle kinds, buffer lengths,
and output ownership before issuing an ioctl; descriptor-returning calls
initialize their result to `-1`, variable-buffer calls initialize outputs,
and truncation is reported rather than silently accepted.

## Observability and tests

A `trustedzfs` SDT provider fires `mint`, `derive`, `handle-openat`,
`op-entry`/`op-return`, `denied`, and `invalidate`, with canned scripts in
`share/dtrace/` (`trustedzfs-handles`, `trustedzfs-denials`, and friends).
The ATF suites live in `tests/sys/zfshandle/` — rights matrix, derive
monotonicity and openat containment, guid pinning under rename/destroy
races, Capsicum behavior, mounts, pool handles, security negatives, and
the extended verbs — running against per-test file-vdev pools. Additional cases
also exercise malformed ioctl sizes and reserved fields, output contracts and
fd exhaustion, operation-ceiling inheritance, competing send-once users,
concurrent anonymous-mount singleton creation, unread SCM_RIGHTS teardown with
no calling thread, mount namespace identity races, delegation permission
matrices, and enumeration ceilings. `tools/test/trustedzfs-qemu/` installs the
kernel, ZFS module, libraries, broker, and tests as one payload, reboots into
that matched state, and aggregates every case in an isolated work directory.

## Consumers

serviced grants storage per manifest stanza the same way it grants files
and network (see [tzfsd](tzfsd.md)); authority-init uses snapshot/rollback
handles plus a `bootfs`-only pool handle for boot-environment management;
WASPNest VMs get zvol checkpoint handles, golden-image `CLONE_SRC`
handles, and send-only migration handles; jails get subtree handles that
replace `zfs jail`.

**Status.** Not yet implemented, in scope for a later batch: encryption-key
verbs (`load-key`/`change-key`, wants a dedicated `ZH_KEY` right),
`zfs diff`, the `userspace`/`groupspace` accounting family, and rich
per-dataset kqueue notes (`SNAP_CREATED`, `PROP_CHANGED`, …) — kqueue
today delivers `INVALIDATED` readiness only.

Sources: `docs/trustedzfs-design.md`, `sys/sys/zfshandle.h`,
`lib/libtrustedzfs/`, `tests/sys/zfshandle/`.
