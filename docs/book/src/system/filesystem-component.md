# Filesystem Component

`localfilesystem(8)` is the base provider for the
`system.Filesystem` 1.0.0 component. It gives each service an opaque,
handle-relative filesystem rather than a host pathname or vnode descriptor.
The provider is installed only inside
`/Capabilities/System/Filesystem.cap`; it is not an ambient `/usr/sbin`
daemon.

## Namespace flavors

Every private component worker exposes three isolated namespace flavors:

| Namespace | Lifetime and authority |
|-----------|------------------------|
| `scratch` | Quota-bounded in-memory tree destroyed with the worker |
| `persistent` | Quota-bounded disk tree scoped to the serviced identity and reconstructed across restarts |
| `bundle` | Read-only tree rooted at the consumer's verified `.cap` bundle |

The unit declares a named storage resource and binds it to the descriptor:

```ucl
storage = [{ name = "data"; scope = "unit"; lifetime = "persistent";
    rights = "mount"; }];
descriptors { filesystem { storage = "data"; } }
```

`serviced` asks `tzfsd` for the stable, bundle-scoped ZFS dataset, mounts it
anonymously, and delegates an attenuated directory fd plus the verified bundle
root to the provider. There is no label-derived `/var/db` backing path. The
consumer chooses neither a host path nor a dataset name and receives only the
private filesystem session. A jail remains an independent process-isolation
boundary.

The provider fixes initial limits at 64 MiB, 4096 objects, and 16 MiB per
file. Persistent restart accounting includes the namespace root and every
existing file and directory. Growth, creation, and reconstruction reserve
byte/object quota atomically so failures do not leave charged or partially
published state; rename preserves the existing accounting.

## Handle API and path contexts

`libfilesystemcmp(3)` exposes typed operations for negotiation, namespace/root
open, lookup, open, create, positional read/write, stat, unlink, rename, sync,
duplication, and close. Handles contain object and generation numbers; stale
handles fail closed after deletion and slot reuse. Names are one component and
reject empty, `.`, `..`, slash, embedded NUL, and lengths over 255 bytes.
Client validation also rejects unknown flags and oversized inline I/O before
transport.

The path-context layer provides Unix-like paths without ambient resolution.
Each context has a fixed delegated root and its own logical cwd. Absolute paths
start at that root, `..` cannot cross it, `chdir` commits only after the whole
path resolves to a directory, and concurrent contexts do not change the
provider process cwd or one another. Returned handles are explicitly owned by
the caller; `dup` creates an independently closeable handle without exposing
the root/cwd handles retained by the library.

The component session is process-wide and correlated for concurrent calls.
It is invalid after fork. A malformed typed reply permanently marks that
process's injected authority as `EPROTO`, including after close/reopen, rather
than continuing with a provider that violated the negotiated protocol. An
ambiguous disconnect is never permission to blindly replay a mutation.

## Disk and confinement rules

The worker enters Capsicum mode before accepting operations. Session and
readiness descriptors are non-transferable, survive only the single supervised
fork, and are locked against exec. All persistent and bundle traversal is
descriptor-relative, refuses symlinks and non-file/non-directory objects, and
reduces requested modes to owner-only permissions.

Writable persistent files must have exactly one link. Reconstruction rejects
hard-linked files and files exceeding the per-file ceiling; lookup, open,
write, truncate, rename, and unlink recheck the same invariants at the point of
use. Cross-namespace rename returns `EXDEV`; every bundle mutation returns
`EROFS`. The exclusive persistent lease prevents two workers from concurrently
owning one service store.

`filesystemcmp_sync()` is the explicit durability boundary. It fsyncs a
provider-owned persistent object; callers sync files after writes and affected
directories after create, rename, or unlink. Scratch sync succeeds as a no-op.

OpenBSM covers mutation, denied resolution, and rejected sessions. The
`localfilesystem_provider` and client `filesystemcmp` SDT providers expose
component and protocol activity without giving the consumer backing-store
authority.

## Storage delivery and mount lifetime

The persistent namespace is backed by a `tzfsd`-provisioned dataset. serviced
mounts the delivered `zfshandle` into an **anonymous mount** (reachable only
through the returned directory descriptor, never by path) and hands the provider
worker that directory descriptor as a session resource. The raw handle is never
exposed to the consumer, so a direct capability open of the backing store is
denied.

The anonymous mount is anchored by the handle: closing the last handle reference
force-unmounts it and revokes every descriptor beneath it. Because the worker
receives only the directory descriptor, **serviced retains a handle reference
for the lifetime of the service that uses the mount** and releases it during
service teardown. Dropping the handle at launch time instead — before the worker
is finished — force-unmounts the store out from under the running session and
turns the next descriptor-relative lookup into a spurious `ENOTDIR` against the
revoked mount root. The service manager records the handoff with a
`component=<name> phase=delegate` audit line when the resources are delegated to
the provider.

## Testing and qualification

Provider tests cover the complete object lifecycle, every request and error
shape, malformed channels, independent sessions, and concurrency. The scratch
model suite covers names, directories, sparse/bounded I/O, quota atomicity,
stale-handle ABA and generation churn, rename rules, session isolation, and
capability mode. Disk tests cover persistent lifecycle and restart accounting,
read-only bundle behavior, symlink and hard-link rejection, oversized restart
state, exclusive leases, quotas, rename bounds, and capability mode. Library
tests cover every request/reply ABI shape, reserved fields, output contracts,
shared open/close lifecycle, correlated calls, fork and peer death, terminal
protocol failure, logical cwd/parent traversal, transactional chdir, resource
lifecycle, and concurrent path contexts. `filesystemcmpctl` has success,
argument, unavailable-service, failure, and cleanup tests.

The complete provider/library/tool suite is included in the disposable amd64
`tools/test/capability-qemu/` matrix alongside Crypto, EnvFD, BSDNotify,
TrustedZFS, and TZFS flavor tooling.
