# TrustedZFS

TrustedZFS makes ZFS storage a thing a program is handed, not a place it
goes. It adds first-class file descriptors — dataset handles and pool
handles — over the ZFS management plane, so a process can be granted "this
dataset, these operations, nothing else" as an unforgeable object.
TrustedZFS is 64-bit only, like the rest of the platform.

## Why the ZFS control plane needed this

Classic ZFS administration is ambient: every operation is an ioctl on
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
  clone, send/recv, properties, mount. This is where TrustedZFS lives.
- **Storage plane** (pool handles) — health, capacity, scrub, boot
  environment activation. Thin by design; operations that reshape the pool
  (import/export, vdev topology) are deliberately not delegable.

Each plane hands down through exactly one door: a pool handle can open its
root dataset handle, and a dataset handle can yield a dirfd of its mount or
a zvol block fd. Handles denote objects, not addresses; doors go one
direction; rights only shrink. The management plane has no read verb, so it
can never become a side channel around VFS enforcement.

## The handle model

A dataset handle pins the dataset's identity, not its name: it is
rename-proof (it follows the dataset) and destroy-proof (recreating under
the same name yields a different object; stale handles fail visibly and
signal invalidation via kqueue). Each handle carries an operation-rights
mask fixed at creation, plus an optional subtree flag covering descendants,
and every derivation — a weaker handle to the same object, or a handle to a
child dataset opened through a subtree grant — is monotonic: fewer rights,
never more. A second kernel-held operation ceiling follows derived handles
across duplication and descriptor passing, so a delegated child cannot use
an operation its grantor omitted.

Minting (name → handle) is the only name-based step, and it reuses ZFS's
existing authorization wholesale: root mints anything, an unprivileged user
mints exactly what `zfs allow` delegates, a jailed process mints only within
its visible datasets. Delegation after that is ordinary fd passing.

One design payoff worth naming: send authority can be minted **send-once** —
a grant that permits exactly one successful replication stream across its
entire derived lineage and can additionally spend itself afterward. That is
an unforgeable "one backup, then done" delegation.

## Mounts without paths

A dataset handle can be mounted as a **dirfd of an anonymous mount**: the
filesystem is instantiated but never attached to the namespace, so it is
unreachable by path yet fully functional through its root vnode, and its
lifetime anchors on the handle — last close unmounts. This is what lets a
sandboxed service hold and use storage no other process can even name.

Consumers across the system use these pieces: services self-mint storage at
runtime through the broker below; `capsule` uses snapshot/rollback handles
and a boot-environment pool grant; WASPNest VMs get checkpoint, clone-source,
and send-only migration handles; jails get subtree handles that replace
`zfs jail`.

Reference: `trustedzfs(3)`, `tzfsctl(8)`.

## The storage broker (tzfsd)

`tzfsd` owns the storage plane of the capability plane. It is an ordinary
socket-free provider publishing `system.Filesystem`, launched and supervised
by `serviced`: it retains TrustedZFS parent handles at startup, creates or
opens application datasets on request, attenuates each returned handle to
the requested rights, and delivers it over the client's channel. It never
proxies application I/O.

Storage is **consumer self-service**: a unit declares nothing in its
manifest and simply calls `service_storage_open(3)` at runtime; `tzfsd`
mints a rights-limited handle (optionally under a per-claim quota so no
single claim can fill the pool) and the consumer mounts and drives it
itself. **The label is the address**: each client's dataset namespace is
derived from its unforgeable channel label, which `serviced` stamped and the
client can never choose — so a client can only ever create, open, or destroy
storage inside its own subtree, and another service's storage cannot even be
named. Claims come in a few lifetimes — persistent, reclaimable cache,
per-boot, and per-session lease — and the whole tree is kept out of the
ordinary mount namespace, reachable only through anonymous handle-mounts.
Recovery is deliberately conservative: a broker crash or restart never
erases live data, and clients resume their sessions on reconnect.

`tzfsd` never creates a pool; it requires one imported pool and provisions
its layout on first start. ZFS is therefore a platform requirement: the
installer's guided Root-on-ZFS path is the standard 5BSD installation, and a
pool-less system runs degraded, with every storage-backed capability failing
until an operator creates a pool.

Reference: `tzfsd(8)`, `libtzfsd(3)`.
