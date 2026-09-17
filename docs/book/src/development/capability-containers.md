# Capability Data and Cleanup

A capability's runtime data lives in a container keyed by its stable label,
and cleanup happens by deleting that container. There is no installation
registry, no generation, and no reclaim protocol: the filesystem is the
record. This is the iOS container model. The container is the capability's
whole world, and removing the capability removes it.

The full design is `docs/capability-container-model.md` in the source tree;
this chapter is the working summary.

## The layout

```
/Capabilities/
  System/   installed base bundles       pkg, read-only, verified
  Apps/     installed non-system bundles pkg, read-only
  Data/     runtime data                 reclaimable, never pkg-owned
    <bundle>/<unit>/persistent/<name>    the unit's durable stores
    <bundle>/<unit>/cache/<name>         regenerable, reaped with the unit
    <bundle>/shared/persistent/<name>    shared by the bundle's units
    Shared/<group>/persistent/<name>     a cross-bundle group container
  Config/   static operator configuration
  Run/      ephemeral, prepared each boot
    live/<bundle>                        a marker per running bundle
    groups/<group>                       a marker per installed-claimed group
```

`System/` and `Apps/` are the installed set, the single source of truth for
what is installed. `Data/` holds everything a capability accumulates that
pkg never touches. A bundle is the unit of install and of cleanup: its units
share the bundle container and are reaped together. A package must own its
bundle directories (`@dir` entries) so that removing it removes the directory,
not just the files.

## Storage is claimed, not declared

A unit declares no storage in its manifest. It asks `system.Filesystem`
(tzfsd) at runtime through libservice, and the provider derives the container
from the unforgeable identity switchboard stamped on the connection: a unit
can only ever name storage under its own bundle.

| Call | Claims |
|------|--------|
| `service_storage_open(ctx, name, &fd)` | `Data/<bundle>/<unit>/persistent/<name>` |
| `service_storage_open_cache(ctx, name, &fd)` | `Data/<bundle>/<unit>/cache/<name>` |
| `service_storage_open_shared(ctx, name, &fd)` | `Data/<bundle>/shared/persistent/<name>` |
| `service_storage_open_group(ctx, group, name, &fd)` | `Data/Shared/<group>/persistent/<name>`, only for a member |
| `service_storage_open_env(ctx, &fd)` | a read-only view of the shared store `env` |

The store is a ZFS dataset that tzfsd mounts on an anonymous anchor and
delivers as a directory descriptor: it has no path, so the consumer, born in
capability mode, reaches it only through that descriptor. A store is mounted
once and shared by every holder (several units of a bundle over their shared
store, or one unit's several claims over its one connection) and is unmounted
when the last holder lets go; the delivered descriptor is itself a holder, so
a tzfsd restart never unmounts a store under a running unit. A read-only view narrows the descriptor with
Capsicum rights, so nothing derived under it can write; that is how a bundle's
units read the one environment a designated unit writes.

Group membership is declared in `Bundle.ucl` (`groups = ["org.example.shared"]`),
stamped on the connection by switchboard, and enforced by tzfsd (`EPERM` for a
non-member).

## Install and remove

Install is a bundle directory appearing under `System/` or `Apps/`; remove is
it disappearing. Switchboard watches the install folders and each installed
bundle directory, settles a burst of changes into one rescan, and loads or
unloads units with no explicit reload. A bundle caught half extracted is
quarantined and the rescan retried a bounded number of times until it is whole;
a registered `System/` bundle caught mid-upgrade keeps running on the previous
registry until the upgrade completes. Reinstalling the same bundle within the
grace inherits its data, as an upgrade should; reinstalling after the removal
was confirmed and reaped starts fresh.

## Cleanup: the reconcile

Every provider that holds per-bundle state runs the same reconcile, from the
`libcapreclaim` library: read the **live set** (`System/` ∪ `Apps/` ∪
`Run/live`, installed or running) from delivered directory descriptors,
enumerate what it owns, and destroy the orphans.

- **At boot** one settled pass destroys orphans immediately.
- **On a timer** an orphan is destroyed only when seen gone on two consecutive
  passes, so the interval is the grace window and an upgrade's transient
  absence is never confirmed. The cadence is `reclaim_interval` in tzfsd's
  configuration, and `LOGD_RECLAIM_INTERVAL` / `CRYPTO_RECLAIM_INTERVAL` in the
  other providers' manifest environment.
- An empty live set destroys nothing (the sources are not published yet), a
  failed destroy is retried next pass, and a container whose snapshot is
  pinned by a clone outside it is left intact with the reason logged.

The clients today are tzfsd (destroys `Data/<bundle>`, snapshots included),
localcrypto (drops the bundle's kernel keys) and logd (seals the bundle's log
records through its owner-to-bundle map). Group containers are reaped by
membership: `Run/groups/<group>` exists while any installed bundle declares
the group.

## Observing it

`zfs list -r zroot/Capabilities/Data` shows the containers; `mount` lists a
held store as mounted on `[anon]`. The reconcile passes are logged
(`reclaim: boot pass reaped N orphans (...)`) and probed
(`tzfsd:::reclaim-pass`, `tzfsd:::reclaim-destroy`, `crypto:::reclaim-pass`,
`logd:::storage-reconcile`); shared mounts fire `trustedzfs:::anon-mount` and
`trustedzfs:::anon-release` with the anchor count.

## Operator recipes

Containers are ordinary datasets under `zroot/Capabilities/Data`, so the
operator's tools are ZFS's own; nothing here needs a daemon command.

| Task | Command |
|------|---------|
| What does bundle `X` hold, and how much? | `zfs list -r -o name,used,refquota zroot/Capabilities/Data/X` |
| Which stores are held right now (mounted)? | `mount \| grep '\[anon\]'` (one line per mounted store, named by dataset) |
| Drop a unit's cache without touching its state | stop the unit, then `zfs destroy -r zroot/Capabilities/Data/X/<unit>/cache` (it is re-created on the next claim) |
| Back up a container | `zfs snapshot -r zroot/Capabilities/Data/X@backup` then `zfs send`; delete the snapshot afterwards, or the reaper will sweep it with the container when the bundle goes |
| Did the reaper run, and what did it do? | `grep 'reclaim:' /var/log/messages`; live: `dtrace -n 'tzfsd:::reclaim-pass'` |
| Why is a bundle not loading? | `grep 'bundle_registry' /var/log/messages` (invalid, untrusted, quarantined, retried) |
| Force a rescan now instead of waiting for the settle | `switchboardctl reload` |

Never edit a live container by path: mounted stores have no path, and an
unmounted one may be claimed at any moment. Uninstall the bundle, or stop
the unit, first.

## What this replaced

The installation ledger and its reclaim protocol: a database of installs that
had to be seeded, kept consistent with the filesystem, and consulted by every
provider. The filesystem now is the record, and a provider becomes
reclaim-correct by supplying two callbacks.
