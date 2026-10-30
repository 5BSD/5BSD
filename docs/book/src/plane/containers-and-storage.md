# Containers and Storage

Capability storage uses per-bundle ZFS dataset subtrees under
`/Capabilities/Data`. Units claim storage through the filesystem provider and
receive directory descriptors. Package removal does not currently delete the
bundle's persistent container: automatic absence-based deletion is suspended
because retained generations and recovery records may still need that data.
Authenticated retention and explicit deletion authority remain unfinished.

This describes the provider interface, not completed protection against
compromised root. Anonymous mounts and descriptor rights do not establish the
mandatory persistent storage boundary required by BIP. See the
[security roadmap](../capability/system-security.md) for implementation and VM
qualification limits.

This chapter is the consumer's and operator's view. The kernel handle model
that makes it possible (TrustedZFS) and the broker's operation set belong to
[system.Filesystem (BSDFilesystem)](../providers/filesystem.md).

## The layout

```
/Capabilities/
  System/   installed base bundles        pkg, read-only, verified
  Apps/     installed non-system bundles  pkg, read-only
  Data/     runtime data                  retained, never pkg-owned
    <bundle>/<unit>/persistent/<name>     the unit's durable stores
    <bundle>/<unit>/cache/<name>          regenerable, explicit lifecycle needed
    <bundle>/shared/persistent/<name>     shared by the bundle's units
    Shared/<group>/persistent/<name>      a cross-bundle group container
  Config/   static operator configuration (bsdfilesystem.ucl, switchboard/boot-authority.ucl)
  Run/      tmpfs, prepared each boot
    live/<bundle>                         a marker per running bundle
    groups/<group>                        a marker per installed-claimed group
```

`System/` and `Apps/` are the installed set, the single source of truth for
what is installed; pkg owns them and switchboard scans them. `Data/` holds
everything a capability accumulates that pkg never touches. Each container
is a real dataset tree: with the default configuration the pool is `zroot`,
the base dataset is `zroot/Capabilities`, and `Data/<bundle>/<unit>/persistent/<name>`
is the dataset `zroot/Capabilities/Data/<bundle>/<unit>/persistent/<name>`
(`tzfs.conf(5)`, keys `pool`, `roots.base`, `roots.persistent`).

A bundle is the unit of installation. Its units share the bundle container;
removing the installation does not authorize deleting that container. A package must own its bundle directories
(`@dir` entries) so that removing it removes the directory, not only the
files; pkgbase's bundle packages do.

## Storage is claimed, not declared

A unit declares no storage in its manifest. At runtime it asks
`system.Filesystem` through libservice(3), and the broker derives the
container from the unforgeable identity switchboard stamped on the
connection: the bundle and unit label, plus the group memberships the
bundle's `Bundle.ucl` declares. A unit can only ever name storage under its
own bundle. The calls, from `lib/libservice/libservice.h`:

| Call | Claims |
|---|---|
| `service_storage_open(ctx, name, &fd)` | `Data/<bundle>/<unit>/persistent/<name>` |
| `service_storage_open_quota(ctx, name, bytes, &fd)` | the same, with an explicit refquota |
| `service_storage_open_cache(ctx, name, &fd)` | `Data/<bundle>/<unit>/cache/<name>` |
| `service_storage_open_shared(ctx, name, &fd)` | `Data/<bundle>/shared/persistent/<name>` |
| `service_storage_open_shared_readonly(ctx, name, &fd)` | the same store, delivered read-only |
| `service_storage_open_env(ctx, &fd)` | the read-only view of the shared store `env` |
| `service_storage_open_group(ctx, group, name, &fd)` | `Data/Shared/<group>/persistent/<name>`, members only |
| `service_open_config(ctx, &fd)` | the well-known `config` claim under the unit's home |

Each `open` has a symmetric `service_storage_destroy[_cache|_shared|_group]`
that frees the claim's pool space, a `service_storage_release[_cache|_shared|_group]`
that drops this process's mount anchor without destroying anything, and a
`service_storage_list[_shared|_group]` that pages the caller's own claims
(`SERVICE_STORAGE_LIST_MAX`, 32 per page) so a forgotten name can still be
found and destroyed. `service_storage_stat` returns one claim's `used`,
`refquota` and `available` bytes; `service_storage_set_quota` moves the
ceiling after the mint. The `ctx` is the unit's `struct service_context`
from `service_acquire`. One request to the broker is bounded by
`SERVICE_STORAGE_CALL_TIMEOUT_MS` (10 s); a request that gets no reply means
the worker serving the connection died, and the session is reopened on the
next claim.

```c
struct service_context *ctx;
int dirfd, fd;

if (service_acquire(&ctx) == -1)
        err(1, "service_acquire");
if (service_storage_open(ctx, "state", &dirfd) == -1)
        logcmp_log(LOG_WARNING, "no persistent store yet: %m"); /* fail soft */
else {
        fd = openat(dirfd, "counter", O_RDWR | O_CREAT, 0600);
        ...
}
```

For a confined consumer, access is through the delivered descriptor. This does
not prove exclusion of privileged backing-storage operations. The store is a dataset that
BSDFilesystem mounts on an anonymous anchor: it has no path in the global
namespace, `mount(8)` lists it as mounted on `[anon]`, and the consumer, born
in capability mode, reaches it only by `openat(2)` under the descriptor. A
store is mounted once and shared by every holder: several units of a bundle
over their shared store, or one unit's several claims over its one
connection. It is unmounted when the last anchor lets go, and the delivered
descriptor is itself an anchor, so a BSDFilesystem restart never unmounts a
store under a running unit. Provider death is soft for storage.

A read-only view narrows the descriptor with Capsicum rights so that nothing
derived under it can write, create, unlink or change attributes
(`ENOTCAPABLE`). That is how a bundle's units read the one environment a
designated unit writes: the writer calls `service_storage_open_shared(ctx,
"env")`, every other unit calls `service_storage_open_env`. Any shared store
can be opened that way, and a read-only claim never changes the store's
ownership.

## Shared and group containers

`Data/<bundle>/shared` is a scope of the bundle's own container: any unit of
the bundle reaches it, and it is retained when the bundle is removed. `Data/Shared/<group>` is
a container shared across bundles. Membership is declared in `Bundle.ucl`:

```ucl
groups = ["org.example.shared"];
```

Switchboard stamps that membership on the connection next to the container
identity, and BSDFilesystem refuses a group claim from a non-member with
`EPERM` (a group list from a non-member is an empty page). A group name is a
single safe path component everywhere it appears. Group membership absence is recorded by reconciliation, but automatic group
container deletion is suspended pending authenticated deletion authority.

## Quotas

Persistent claims support `refquota`. These quotas are configurable and can be
disabled; they are not an immutable capacity boundary. The default is `default_refquota` in
`/Capabilities/Config/bsdfilesystem.ucl` (1 GiB, UCL size suffixes accepted,
0 disables). A unit may pass its own ceiling to `service_storage_open_quota`;
a value below the daemon's floor is `EINVAL`, and `service_storage_set_quota`
with 0 removes the ceiling. The broker's compiled bounds
(`usr.sbin/BSDFilesystem/bsdfilesystem.h`) cap the rest:

| Bound | Value | Meaning |
|---|---|---|
| `BSDFILESYSTEM_CONN_MAX_CLAIMS` | 32 | claims held over one connection |
| `BSDFILESYSTEM_NS_MAX_CLAIMS` | 64 | datasets one namespace may hold, staging clones included |
| `BSDFILESYSTEM_MAX_SNAPSHOTS` | 256 | versions per claim |
| `BSDFILESYSTEM_MAX_OPEN_POLICY` | 32 | `open_paths` entries |
| `BSDFILESYSTEM_DESTROY_MAX_DEPTH` | 64 | recursion bound on a container destroy |

## Versions and transactions

A version is a snapshot of one of the caller's own persistent claims, named
by an opaque id of at most `SERVICE_STORAGE_VERSION_MAX` (64) bytes. All
version operations are owner-scoped; a caller can only ever version its own
storage.

| Call | Effect |
|---|---|
| `service_storage_snapshot(ctx, name, ver, sz)` | snapshot now; the assigned id is copied out |
| `service_storage_list_versions(ctx, name, vers, max, &n, &cursor)` | page the claim's version ids |
| `service_storage_open_version(ctx, name, ver, &fd)` | mount the version read-only and hand back its dirfd; non-destructive |
| `service_storage_rollback(ctx, name, ver)` | rewind the live claim; newer versions are discarded |
| `service_storage_txn_begin(ctx, name, txn, sz, &fd)` | hand back a writable staging clone of the claim plus a transaction id |
| `service_storage_txn_commit(ctx, name, txn)` | promote and rename the clone over the claim; crash-safe atomicity is unqualified |
| `service_storage_txn_abort(ctx, name, txn)` | discard the clone |

A transaction lets a caller prepare changes in a staging clone. Commit uses
promotion and multiple renames; it does not yet provide a durable journal or
proved atomic replacement and recovery. The staging clone records its base
claim, and abort checks that binding before deletion. That check is not a
complete authenticated GUID binding or protection against concurrent changes.
Both `txn_commit` and `rollback` replace
the live claim, and a mounted dataset cannot be renamed or rolled back, so
the caller must first close any delivered directory descriptor for the claim
and call `service_storage_release` on it; otherwise the operation fails
`EBUSY`. `open_version` needs an active session and its read-only clone is
reaped with the session.

Startup and idle staging sweeps currently preserve unresolved clones and
report `EBUSY`. Age or absence of a mount is insufficient deletion authority;
a clone can contain data needed after an interrupted commit. Authenticated
transaction ownership, durable recovery and bounded reclamation remain open.

## Reconciliation and retention

Switchboard observes installed bundle directories and running-unit markers.
`libcapreclaim` compares those observations with provider-owned resources.
BOOT can report absence immediately; TIMER confirms absence across consecutive
observations. Neither observation proves that retained generations or recovery
records have released persistent data. A grace interval cannot establish
upgrade safety.

BSDFilesystem's persistent bundle and group callbacks now refuse automatic
absence-based deletion with `EBUSY`. Six real-ZFS VM regressions cover startup
and repeated timer absence, including an empty group catalogue, and verify
retained dataset GUIDs and payload. These tests do not cover an actual provider
process restart or an authenticated system upgrade. The v9 candidate packages
predate this change. Evidence and packaging status are recorded in the
[security roadmap](../capability/system-security.md).

Retained state consumes space. Explicit deletion, references from retained
boot environments, recovery and capacity policy still need implementation and
qualification. Existing claim-level destroy APIs must also be evaluated against
those retention requirements; their existence does not qualify safe deletion.

Other providers have distinct cleanup operations. Source review found key
removal in BSDCrypto, jail removal in BSDNamespace, module attribution cleanup
and possible unload in BSDExtension, and log-owner retirement in BSDLog. The
filesystem regression does not qualify these operations. Their lifecycle and
upgrade/recovery behavior require separate positive and adversarial tests.

Reconcile lines go through the Log capability (`reclaim: boot pass reaped N
orphans (...)`), each provider fires a `reclaim-pass` USDT probe
(`BSDFilesystem:::reclaim-pass`, `BSDFilesystem:::reclaim-destroy`,
`BSDFilesystem:::reclaim-snapshot`), and a provider that publishes its
managed set to `/var/run/reclaim/<provider>` is readable with
`reclaimstat(8)`. BSDLog, which cannot log to itself, records its last pass
in a `reconcile.meta` file inside its store instead; see
[Logging, Audit and Trace](logging-audit-trace.md).

## /Capabilities/Run is tmpfs

`/Capabilities/Run` is mounted as tmpfs by the installer's fstab entry
(`tmpfs /Capabilities/Run tmpfs rw,mode=0700 0 0`, written by
`usr.sbin/bsdinstall/scripts/zfsboot`). It exists so that the running set is
expressed in the filesystem in a form that cannot survive a reboot: switchboard
creates `Run/live` before the first launch so it can be delivered as a
directory descriptor, rewrites one marker per running bundle at boot, after
every reload and after any change to the running set, and publishes
`Run/groups/<group>` for every group an installed bundle declares. A stale
marker from a previous boot would keep an orphan alive; tmpfs makes that
impossible. It also means nothing durable may live there: a reconciling
provider's map that must survive a reboot belongs in its container, and a map
that must not (BSDExtension's module-to-bundle map) belongs under `/var/run`.

## Isolated opens

The same broker answers the other question a sandboxed unit has: how to reach
a file, directory or device node that is not in any container.
`service_open_isolated(ctx, path, rights, is_dir, &fd)` returns a
rights-limited descriptor if, and only if, `bsdfilesystem.ucl` grants the
caller's label that path (`open_paths[]`, default-deny, `prefix` for device
unit families). This replaced manifest file delivery; the policy format is in
`tzfs.conf(5)` and the [provider chapter](../providers/filesystem.md).

## Operator recipes

The following inspection commands describe the current dataset layout. Direct
mutation is not an owner-authorized BIP recovery or deletion protocol; that
protocol remains unfinished.

| Task | Command |
|---|---|
| What does bundle `X` hold, and how much? | `zfs list -r -o name,used,refquota zroot/Capabilities/Data/X` |
| Which stores are held right now? | `mount \| grep '\[anon\]'` |
| Back up a container | `zfs snapshot -r zroot/Capabilities/Data/X@backup`, then `zfs send`; snapshot retention needs explicit lifecycle policy |
| What is each provider managing, and when did it last reconcile? | `reclaimstat` |
| Did the reaper run, and what did it do? | `grep 'reclaim:' /var/log/messages`; live: `dtrace -n 'BSDFilesystem:::reclaim-pass'` |
| Why is a bundle not loading? | `grep 'bundle_registry' /var/log/messages` |
| Force a rescan now | `switchboardctl reload` |
| Probe the broker by hand | `tzfsctl ping`, `tzfsctl request -l persistent -m name`, `tzfsctl release name` |

Never edit a live container by path: a mounted store has no path, and an
unmounted one may be claimed at any moment. Uninstall the bundle, or stop the
unit, first.

## Limits and status

ZFS is required for persistent capability storage. BSDFilesystem never
creates a pool; on installer media, or on a UFS root with no pool, it runs in
a degraded isolated-path-only mode and every dataset operation fails `ENXIO`.
The consumer API exposes the persistent and cache lifetimes; the
`roots.ephemeral` tree is used by the broker for transient clones such as
read-only version mounts. `tzfsctl(8)` has `ping`, `request` (lifetimes
`persistent`, `cache`, `boot` and `lease`, the last two not exposed through
libservice) and `release` only; there is no list, stat or version
subcommand, so those are reached from a program or by `zfs list`. The earlier flavors feature and the installation
ledger are gone and must not be relied on.

Reference: `BSDFilesystem(8)`, `tzfs.conf(5)`, `libservice(3)`,
`capreclaim(3)`, `reclaimstat(8)`, `tzfsctl(8)`. Design:
`docs/book/src/plane/containers-and-storage.md`, `docs/bsdfilesystem-design.md`.
