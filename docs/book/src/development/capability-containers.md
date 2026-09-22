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
(BSDFilesystem) at runtime through libservice, and the provider derives the container
from the unforgeable identity switchboard stamped on the connection: a unit
can only ever name storage under its own bundle.

| Call | Claims |
|------|--------|
| `service_storage_open(ctx, name, &fd)` | `Data/<bundle>/<unit>/persistent/<name>` |
| `service_storage_open_cache(ctx, name, &fd)` | `Data/<bundle>/<unit>/cache/<name>` |
| `service_storage_open_shared(ctx, name, &fd)` | `Data/<bundle>/shared/persistent/<name>` |
| `service_storage_open_group(ctx, group, name, &fd)` | `Data/Shared/<group>/persistent/<name>`, only for a member |
| `service_storage_open_env(ctx, &fd)` | a read-only view of the shared store `env` |

The store is a ZFS dataset that BSDFilesystem mounts on an anonymous anchor and
delivers as a directory descriptor: it has no path, so the consumer, born in
capability mode, reaches it only through that descriptor. A store is mounted
once and shared by every holder (several units of a bundle over their shared
store, or one unit's several claims over its one connection) and is unmounted
when the last holder lets go; the delivered descriptor is itself a holder, so
a BSDFilesystem restart never unmounts a store under a running unit. A read-only view narrows the descriptor with
Capsicum rights, so nothing derived under it can write; that is how a bundle's
units read the one environment a designated unit writes.

Group membership is declared in `Bundle.ucl` (`groups = ["org.example.shared"]`),
stamped on the connection by switchboard, and enforced by BSDFilesystem (`EPERM` for a
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
  absence is never confirmed. The cadence is `reclaim_interval` in BSDFilesystem's
  configuration, and `LOGD_RECLAIM_INTERVAL` / `CRYPTO_RECLAIM_INTERVAL` in the
  other providers' manifest environment.
- An empty live set destroys nothing (the sources are not published yet), a
  failed destroy is retried next pass, and a container whose snapshot is
  pinned by a clone outside it is left intact with the reason logged.

The clients today are BSDFilesystem (destroys `Data/<bundle>`, snapshots included),
BSDCrypto (drops the bundle's kernel keys), BSDLog (seals the bundle's log
records through its owner-to-bundle map), BSDNamespace (removes the bundle's
persistent jails through its jail-to-bundle map) and BSDExtension (unloads the
kernel modules it loaded for the bundle through its per-boot module-to-bundle
map, never one it merely found loaded, never one the kernel reports busy)
and BSDBluetooth (removes the local GATT services a bundle's units registered over
the plane, attributed per service in a sidecar beside its persisted GATT
artifact; a service registered over the socket path carries no identity and
is never reclaimed). Every other provider either holds nothing on a bundle's
behalf or holds only what dies with the connection. Group containers are reaped by
membership: `Run/groups/<group>` exists while any installed bundle declares
the group.

## Writing a reconcile client

A provider becomes reclaim-correct by filling one struct and supplying two
callbacks. The struct is **always** initialised with `CAPRECLAIM_INIT`:

```c
struct capreclaim r = CAPRECLAIM_INIT;   /* zeroes it, stamps struct_size */
r.sources[0].fd = sys_fd;  r.sources[0].strip_cap = true;   /* System/ */
r.sources[1].fd = apps_fd; r.sources[1].strip_cap = true;   /* Apps/   */
r.sources[2].fd = run_fd;  r.sources[2].strip_cap = false;  /* Run/    */
r.nsources = 3;
r.enumerate = my_enumerate;   /* emit(owner) for each owner I hold */
r.destroy   = my_destroy;     /* free one owner; return -1 to retry next pass */
r.arg       = ctx;
```

`CAPRECLAIM_INIT` stamps `struct_size` with the caller's own `sizeof`. That is
the **ABI-skew guard**: a provider built against one `libcapreclaim` and
dynamically linked against another reports the size of the struct it actually
allocated, so the library never reads an optional field past the end of an
older, smaller struct, and `capreclaim_run()` refuses a zero or out-of-range
size (which also catches a struct that was never initialised). Optional tail
fields (`stats`, `status_dirfd`, `status_name`) may be appended in future
versions without breaking an already-compiled caller. The soname carries this:
`libcapreclaim.so.3`.

The library owns the safety-critical parts so every provider gets them
identically: the empty-live floor (an empty live set reaps nothing — the
sources are not published yet; opt out with `allow_empty_live` **only** with an
independent readiness signal, as BSDFilesystem's group containers do), a truncated or
unreadable source failing the pass rather than looking like "everything is
gone", capability-mode-safe source reads (a `dup(2)` + `rewinddir(3)`, never an
`openat(".")` the plane refuses a sandboxed client), and exact owner-name
matching. The grace bookkeeping ("seen gone twice") is **library-owned and
opaque** — not caller fields to be desynced or double-freed — and released by
`capreclaim_fini()`.

**Logging.** A reconcile client must log through **`logcmp_log(3)`** (the Log
capability, `system.Log`), never `syslog(3)`: a capability-mode unit cannot
reach syslog's socket, so its reclaim lines would be lost. `logcmp_log` emits
to BSDLog and falls back to `syslog` before the plane is up, so it is a safe drop-in.
The one exception is BSDLog itself — it cannot log to `system.Log` (it *is*
`system.Log`), so it writes an fd-based `reconcile.meta` record instead.

**Born-in-capmode providers.** Providers run **sandboxed**: they `cap_enter(2)`
(switchboard execs them already in capability mode) and operate only on the
descriptors switchboard delivered. This includes the ones whose work needs
classic privilege — BSDFilesystem, BSDExtension, BSDNamespace, BSDSysctl,
BSDPower, BSDTime — which do NOT run as ambient root. Each holds a
`mac_capability` "system" **gate token** delivered by switchboard and performs
its privileged operation *through* that token in kernel context
(`kldload(2)`, `jail_set(2)`, `settimeofday(2)`, a gated `sysctl(2)`, a reboot),
so the raw privileged syscalls stay refused inside the cage and the sandbox is
never loosened. Some serve each client on a `pdfork(2)` worker; those holding a
close-on-fork gate token (BSDTime, BSDSysctl) instead serve inline in the
token-holding process, and BSDExtension/BSDNamespace serve on threads that share
the held token. Every request is still gated through per-label policy.

The lone remaining **ambient** provider is BSDVM (`ambient = true`): the vsock
VM broker's work is not yet expressible through a gate token. It still drops
inherited authority, caps its `pdfork(2)` workers, and gates every request
through per-label policy — the boundary is policy plus least-privilege rather
than a Capsicum cage. For any provider, open `capreclaim_status_dir()` (below)
*before* `cap_enter` when it is not already entered for you.

## Observing it

`zfs list -r zroot/Capabilities/Data` shows the containers; `mount` lists a
held store as mounted on `[anon]`. `reclaimstat(8)` reads
`/var/run/reclaim/` and prints, per provider, the set it is managing and its
last pass — a provider populates it by setting `status_dirfd`
(`capreclaim_status_dir()`, opened before `cap_enter`) and `status_name`. The
reconcile passes are also logged through the Log capability
(`reclaim: boot pass reaped N orphans (...)`, visible in `/var/log/messages`)
and probed: every reclaim client fires a `reclaim-pass` USDT probe carrying the
pass's counts — `BSDFilesystem:::reclaim-pass` (plus `BSDFilesystem:::reclaim-destroy`),
`crypto:::reclaim-pass`, `BSDExtension:::reclaim-pass`, `BSDNamespace:::reclaim-pass`,
`BSDBluetooth:::reclaim-pass`, and `BSDLog:::storage-reconcile`. (`libcapreclaim` itself
defines no probes — each provider fires one from the stats it fills in, so a new
provider is only observable once it does.)

## Operator recipes

Containers are ordinary datasets under `zroot/Capabilities/Data`, so the
operator's tools are ZFS's own; nothing here needs a daemon command.

| Task | Command |
|------|---------|
| What does bundle `X` hold, and how much? | `zfs list -r -o name,used,refquota zroot/Capabilities/Data/X` |
| Which stores are held right now (mounted)? | `mount \| grep '\[anon\]'` (one line per mounted store, named by dataset) |
| Drop a unit's cache without touching its state | stop the unit, then `zfs destroy -r zroot/Capabilities/Data/X/<unit>/cache` (it is re-created on the next claim) |
| Back up a container | `zfs snapshot -r zroot/Capabilities/Data/X@backup` then `zfs send`; delete the snapshot afterwards, or the reaper will sweep it with the container when the bundle goes |
| What is each provider managing, and when did it last reconcile? | `reclaimstat` |
| Did the reaper run, and what did it do? | `grep 'reclaim:' /var/log/messages`; live: `dtrace -n 'BSDFilesystem:::reclaim-pass'` |
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
