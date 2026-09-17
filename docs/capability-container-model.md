# The Capability Container Model

Status: design locked 2026-09-16. Supersedes the installation-authority
ledger. This document is the spec; the code is being driven to match it.

## Motivation

The installation ledger (`switchboard_lifecycle.c`, `sl_*`) grew from "free a
bundle's resources when it is removed" into a durable store with generations,
lifecycle phases, holdings, delivery records, replay, adoption, and a
**launch-admission gate**. On a freshly installed image the ledger is empty,
so launch, provider readiness, and session minting all failed and the plane
could not boot without hand-seeding the ledger from a recovery shell. That is
complexity — and boot fragility — far out of proportion to the job.

The job is small and the filesystem already does most of it: each capability's
data lives under a per-label path, so cleanup is "delete the path." This is the
Darwin/iOS container model: the container is the capability's whole world;
delete it and it is gone. We adopt that model wholesale and retire the ledger.

## Principles

1. **The filesystem is the source of truth.** No separate database can desync
   from it, because there is no separate database.
2. **Identity is the stable label.** The container path encodes ownership;
   nothing else records it. Reusing a label reuses its container (this is
   bundle-id-container semantics, and it is intended).
3. **Cleanup is reconcile, never react.** Cleanup compares durable state to the
   installed set at settled moments; it never fires off a raw filesystem event.
   This is what makes upgrades safe — a bundle briefly absent mid-upgrade is
   never observed as gone.
4. **Capability mode: directories are delivered, never opened by path.** A
   provider runs sandboxed; switchboard hands it descriptors for the
   directories it may use, and it only `openat`s under those.
5. **Decentralized via a shared primitive.** Each provider owns its own
   cleanup, using one shared reconcile library so the safety logic lives — and
   is tested — in exactly one place.

## Folder layout

```
/Capabilities/
├── System/                     installed base bundles      pkg, read-only, veriexec
│   └── <Name>.cap/                 Bundle.ucl, Units/<unit>.unit/{Unit.ucl,bin/}
├── Apps/                       installed non-system bundles pkg, read-only
│   └── <Name>.cap/
├── Data/                       runtime data                NOT pkg, reclaimable
│   ├── <bundle>/<unit>/            per-unit private container
│   │   ├── persistent/                 durable state (the reclaimable data)
│   │   ├── cache/                      regenerable
│   │   └── log/
│   ├── <bundle>/shared/            shared between a bundle's units
│   └── Shared/<group>/             cross-capability group container (App Groups)
├── Config/                     static admin config          tzfsd.ucl, principal-policy.ucl
└── Run/                        ephemeral, cleared each boot  sockets; running-unit markers
```

- **`System/` + `Apps/`** are the *installed set* — the single source of truth
  for "what is installed." pkg owns them; switchboard's registry scans them.
- **`Data/`** is the runtime half — everything pkg never touches, reaped on
  removal. Keyed by bundle (the unit of install/remove), subdivided per unit.
- **`Config/`**, **`Run/`** unchanged in role (static config; ephemeral
  per-boot). `Run/` additionally holds a marker per running unit (below).

## Storage and delivery (capability mode)

Providers are sandboxed, so they never open `/Capabilities/...` by path.
Switchboard delivers each unit the descriptors it needs and the unit `openat`s
under them:

- its **private container** `Data/<bundle>/<unit>/`,
- optionally the **bundle-shared** container `Data/<bundle>/shared/`,
- optionally a **group container** `Data/Shared/<group>/` it declares membership
  in,
- optionally a **shared environment** descriptor (a file/dir under the
  container, e.g. `Data/<bundle>/shared/env`) delivered read-only so a bundle's
  units read one on-disk environment through a passed descriptor.

The reconcile operates over the same delivered descriptors — nothing works by
global path.

## Lifecycle

- **Install:** pkg drops the bundle into `System/`/`Apps/`. Switchboard, which
  watches its install folders, notices and **loads** the units.
- **Run:** switchboard writes a marker under `Run/` for each running unit, so
  the running set is itself expressed in the filesystem.
- **Uninstall:** pkg removes the bundle. Switchboard notices the bundle is gone
  and **unloads** its units — the launchd move — then clears their `Run/`
  markers and **kicks a reconcile**. Only after the unload is the data an
  orphan the reconcile may reap.
- **Upgrade:** pkg replaces the bundle in place (or removes-then-reinstalls in
  a few seconds); the marker is present throughout, or back immediately. The
  data is never touched, and the units are reloaded. No cleanup fires.

## Cleanup: the reconcile

A shared library (`libcapreclaim`). A provider supplies two callbacks:

- **`enumerate()`** — the owner labels it currently holds resources for
  (tzfsd: the `Data/<bundle>/` containers; localcrypto: the kernel-key owners).
- **`destroy(label)`** — free that owner's resources (tzfsd: `zfs destroy`;
  localcrypto: drop the owner's keys).

The library owns everything hard and safety-critical:

- reading the **live set** from the delivered read-only views —
  `System/` ∪ `Apps/` ∪ `Run/`, i.e. **installed OR running** — all by
  `readdir`, no protocol;
- computing orphans (owned − live);
- the schedule and the grace:
  - **at boot:** one pass; destroy orphans immediately (a settled state, no
    concurrent pkg),
  - **on a timer:** destroy an orphan only if it was orphaned at the previous
    pass too — *seen-gone-twice*; the interval is the grace window, so an
    upgrade's transient absence is never confirmed,
  - **on switchboard's kick** (after an unload): a graced pass, so a kick during
    an upgrade is harmless.

Clients today:

- **tzfsd** — reaps `Data/<bundle>/` containers. It already reaps orphaned
  ephemeral leases this exact way; this extends it to persistent containers.
- **localcrypto** — drops kernel keys for owners no longer live (keys stay in
  the kernel key store, off disk; see "keys" below).

A new provider with per-capability state becomes a client by writing those two
callbacks and wiring the library into its event loop and boot — it inherits
correct, upgrade-safe cleanup for free.

**Shared and group containers** are reaped *by membership*: the container is an
orphan only when no installed capability still claims it. The same reconcile
handles it — the "live" test for a group is "any member installed."

## Keys (why localcrypto is option b)

localcrypto keys stay in the **kernel key store**, owner-scoped, never written
to disk. Storing them as files under the container would be simpler (tzfsd's
destroy would reap them) but would expose them on snapshots, backups, and
offline disks. Keeping them in kernel memory is worth one small reconcile:
localcrypto is a `libcapreclaim` client that drops keys for gone owners. It is
the single provider that holds state outside `Data/`; every other provider is
oblivious to cleanup.

## Darwin parallels

- Containers keyed by bundle id (`Data/<bundle>`), the app's whole world.
- launchd unloads a program on uninstall → switchboard unloads the unit.
- App Groups / Group Containers → `Data/Shared/<group>`.
- launchd tracks no runtime resource database → we track none either; the
  filesystem is the record. (macOS keeps pkg *receipts* of installed files,
  which is our `System/`/`Apps/` install set, not a runtime tracker.)

## Edge cases and implications

- **Running unit of a removed bundle (the important one).** Never reap data in
  use. Resolved by unload-first (switchboard stops the unit before its data is
  an orphan), the `Run/` marker in the live set, and the grace covering unload
  latency.
- **Label reuse inherits data.** Reinstalling the same bundle keeps its state
  (desirable). A *different* bundle claiming a taken label would inherit stale
  data, but labels are unique identities, so that is a namespace violation, not
  a normal case. We trade away the old generation field that distinguished
  installs; this is the accepted cost.
- **Delayed cleanup.** Resources linger until the next pass (boot, or a timer
  tick plus grace, or a kick). Fine for garbage collection.
- **Provider discipline.** Only per-owner-label, enumerable state is
  reclaimable. A provider that stores state unlabeled or unenumerable leaks.
  The library enforces the shape (you must supply the callbacks); writing a
  provider means following the convention.
- **Manual meddling** (`rm -rf` a live container) is not protected — operator
  error, same as today.
- **Granularity.** Data is per-bundle; ownership is per-unit. The reconcile
  keys on the installed `(bundle, unit)` pairs from the folder view.

## What is removed

- `lib/libcapsulert/switchboard_lifecycle.c` and the `sl_*` store — generations,
  phases (`SL_ACTIVE`/`PREPARED`/`RETIRED`/`COMPLETE`), holdings, delivery
  records, replay, adoption.
- `usr.sbin/switchboard/installation_query.c`, `reclaim_bridge.c`, and the
  ledger remnants of `lifecycle.c`.
- `switchboardctl lifecycle` and `reclaim`; `lib/libservice/service_reclaim.c`;
  `/usr/libexec/switchboard-pkg-reclaim`; the pkg lifecycle hook
  (`release/tools/lifecycle-package-labels.lua`).
- All ledger/reclaim tests (`installation_*`, `lifecycle_*`, `authority_*`).

## Build order

1. **Delete the dead machinery.** *(done — commit d0220802669.)* The ledger is
   off the runtime path (65ab30e43ce); the store, the pkg hook, the CLI reclaim,
   and their tests are removed.
2. **Folder reorg.** *(done for the storage path — VM-proven.)* Durable data
   lives in the container directory `Data/<bundle>/<unit>/persistent` (and
   `.../cache`): tzfsd roots each client's storage there, keyed by the container
   `<bundle>/<unit>` switchboard stamps on the connection (a new `container`
   field in the delivered identity; `resource_owner` stays the flat per-label key
   the other providers use). The install directories `System/`/`Apps/` and the
   ephemeral `Run/` are the live set; no `Data/`-side hashes remain. *(The
   `log/` sub-container and `Apps/` population are not exercised yet.)*
3. **The reconcile.** *(done for tzfsd — VM-proven.)* `libcapreclaim` owns the
   live-set read, orphan computation, grace, and schedule, plus an empty-live-set
   safety floor (reap nothing when the live set is empty). tzfsd is a client: it
   enumerates its `Data/<bundle>` containers, and a forked reconcile child reaps
   any whose bundle is not live — immediately on the first settled (boot) pass,
   seen-gone-twice on the timer. The live set is read straight from the install
   dirs (`System/`, `Apps/`, `strip_cap`) and switchboard's running-bundle markers
   (`Run/live/<bundle>`); `System/` existing is the readiness gate, so no sentinel
   is needed. Switchboard writes the running markers at boot and every reload and
   performs **unload-on-uninstall** (reload's Phase 1 graceful stop). tzfsd's
   destroy recurses per child, so a real four-level container
   (`Data/<bundle>/<unit>/persistent/<claim>`) reaps (e81335b7f6e). **localcrypto**
   is a client too: the kernel keystore is keyed by bundle and a forked reclaim
   child drops an uninstalled bundle's keys (9f3138f885d). **logd** is a client:
   records stay keyed by the flat `resource_owner` (it is the query-isolation
   scope, and sessions have no bundle), so the store keeps a durable best-effort
   owner→bundle map (`owners.meta`, fed by a fire-and-forget NOTE_OWNER on each
   accept) and the storage manager reconciles it in-process, sealing every owner
   of a gone bundle through the existing reclaim floor. The libservice no-op
   shims and tzfsd's ledger-era seam are gone (61c2ef9b4e0, fde768439db).
   **Born-in-capmode rule:** a reconciling provider MUST declare
   `directories = ["/Capabilities/System", "/Capabilities/Apps"]` in its unit
   manifest and take the live-set roots from `service_resource_dir(3)`. An
   `open(2)` by path fails ECAPMODE inside the sandbox and — because a missing
   `System/` is the readiness gate — *silently* disables reclaim (found on logd,
   latent on localcrypto). tzfsd is PID 1-spawned, not sandboxed, and reads by
   path.
4. **Shared and group containers.** `Data/<bundle>/shared/`, `Data/Shared/<group>/`,
   shared env — the same primitive, by-membership reaping. *(not started.)*
5. **Verify on the VM.** *(proven 2026-09-16.)* Fresh-from-scratch boot is clean;
   durable data lands at `Data/<bundle>/<unit>/persistent` (e.g. `Data/Log/logd/
   persistent/state`); the reaper runs and `Run/live/` holds one marker per
   running bundle. A planted orphan container `Data/OrphanBundle` is reaped by the
   boot pass (logged `reclaim: destroyed orphan persistent namespace …`) while the
   live `Data/Log/logd` container is preserved. Proven since with real test
   bundles on from-scratch images: **install→claim→remove→reap** (a boot unit
   claims `Data/Test/reclaimprobe/persistent/state`, its bundle is removed, the
   next boot reaps it while `Data/Log` survives); **upgrade→untouched** (bumping
   `version`/`sequence` under the same `bundle_id` and rebooting leaves the
   container intact); **logd remove→seal** (a unit that emits to `system.Log` is
   mapped to its bundle in `owners.meta`; after removal the next boot's reconcile
   seals it and drops the mapping). Still to cover: install/remove through pkg,
   label reuse→data inherited, group container reaped only when the last member
   goes.
