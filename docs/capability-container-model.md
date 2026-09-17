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

- its **private container** `Data/<bundle>/<unit>/` —
  `service_storage_open(3)` claims `persistent/<name>` there and
  `service_storage_open_cache(3)` claims `cache/<name>`,
- optionally the **bundle-shared** container `Data/<bundle>/shared/` —
  `service_storage_open_shared(3)`; any unit of the bundle reaches it, and it
  goes with the bundle's container,
- optionally a **group container** `Data/Shared/<group>/` it declares membership
  in — `service_storage_open_group(3)`; the bundle lists its groups in
  `Bundle.ucl` (`groups = ["org.example.shared"]`), switchboard stamps that
  membership on the connection next to the container identity, and tzfsd
  refuses (EPERM) a claim from a bundle that is not a member,
- optionally a **shared environment**: the bundle-shared store named `env`
  (`Data/<bundle>/shared/persistent/env`), which one designated unit writes
  through `service_storage_open_shared(ctx, "env")` and every other unit
  opens as a **read-only view** through `service_storage_open_env(3)` — the
  delivered directory carries read-only Capsicum rights, so nothing derived
  under it can write, create, unlink, or change attributes (`ENOTCAPABLE`).
  Any bundle-shared store can be opened that way
  (`service_storage_open_shared_readonly(3)`); a read-only claim never changes
  the store's ownership.

A store is **mounted once and shared**: the kernel keys anonymous mounts by
dataset, so every handle that claims an already-mounted store joins that mount
and the last anchoring handle to go unmounts it. That is what lets several
units hold one shared store at the same time, and one unit hold several
stores (its persistent store, its cache, a shared store) over its single
provider connection — tzfsd keeps one mount anchor per claim, not per
connection.

The reconcile operates over the same delivered descriptors — nothing works by
global path.

## Lifecycle

- **Install:** pkg drops the bundle into `System/`/`Apps/`. Switchboard
  **watches its install folders** (an edge-triggered vnode watch on each root
  *and on each installed bundle directory* with a short settle, so a multi-file
  install is scanned whole, never mid-copy). The files below `Units/` are two
  levels down and invisible to the watch, so a scan that catches a bundle still
  extracting is handled without waiting for another event: a bundle **not yet
  registered** (`System/` or `Apps/`) is *quarantined* — skipped and counted,
  never blocking the other bundles — while a **registered `System/` bundle**
  caught half written (an in-place upgrade) fails the rescan and the previous
  registry and its running units are retained; either way the watch rescans a
  bounded number of settled times and admits the bundle once it is whole. At
  boot a malformed `System/` bundle is still a convergence failure. Switchboard
  notices, and **loads** the units — no explicit reload. A package must own
  its bundle directories (`@dir` entries), so that removing it removes the
  directory and not just the files; pkgbase's bundle packages do (verified:
  the `logd` package's manifest lists `Log.cap`, `Units/`, `logd.unit/`,
  `Config/`, `bin/`). An `Apps/` bundle runs in the user
  domain, so the storage provider (`system.Filesystem`) is user-resolvable —
  safe by construction, since every durable claim is scoped by the stamped
  container identity, never by anything the caller supplies.
- **Run:** switchboard writes a marker under `Run/live/` for each running
  bundle, so the running set is itself expressed in the filesystem. The markers
  are rewritten at boot, after every reload, and after any asynchronous change
  to the running set (a restart, an on-demand launch, an exit) — once per
  event-loop iteration, so a burst is one rewrite.
- **Uninstall:** pkg removes the bundle. Switchboard notices the bundle is gone
  and **unloads** its units — the launchd move — then clears their `Run/`
  markers. Only after the unload is the data an orphan, and the providers'
  next reconcile pass (the timer, with its grace; or the next boot) reaps it.
  There is deliberately no event-driven "kick": the timer's grace already covers
  unload latency, and a sandboxed provider has no channel to be kicked on.
- **Upgrade:** pkg replaces the bundle in place (or removes-then-reinstalls in
  a few seconds); the marker is present throughout, or back immediately. The
  data is never touched, and the units are reloaded. No cleanup fires.

## Cleanup: the reconcile

A shared library (`libcapreclaim`). A provider supplies two callbacks:

- **`enumerate()`** — the bundles it currently holds resources for (tzfsd: the
  `Data/<bundle>/` containers; localcrypto: the kernel-keystore owners; logd:
  the distinct bundles in its owner→bundle map).
- **`destroy(bundle)`** — free that bundle's resources (tzfsd: `zfs destroy`
  the container, its snapshots included; localcrypto: drop the bundle's keys;
  logd: seal every owner of the bundle through its reclaim floor).

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
    upgrade's transient absence is never confirmed.
- optional per-pass **stats** (live, owned, orphans, destroyed, failed) that
  every client feeds to its DTrace probes (`tzfsd:::reclaim-pass`,
  `crypto:::reclaim-pass`, `logd:::storage-reconcile`) and its log line.

Clients today:

- **tzfsd** — reaps `Data/<bundle>/` containers. It already reaps orphaned
  ephemeral leases this exact way; this extends it to persistent containers.
- **localcrypto** — drops kernel keys for bundles no longer live (keys stay in
  the kernel key store, off disk; see "keys" below).
- **logd** — seals the log records of bundles no longer live (records live
  inside logd's own container, keyed by the flat per-unit owner; a durable
  owner→bundle map makes them reconcilable by bundle).

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
localcrypto is a `libcapreclaim` client that drops keys for gone bundles. It and
logd are the two providers whose per-bundle state is not itself a container
directory (kernel keys; records inside logd's own store), so both are clients;
every other provider keeps its state in its container and is oblivious to
cleanup — tzfsd reaps the container for it.

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
- **Label reuse inherits data — until the reap.** Reinstalling the same bundle
  within the grace (an upgrade, or a quick remove-and-reinstall) keeps its
  state (desirable); once a removal has been confirmed and reaped, a reinstall
  starts fresh, exactly as a deleted-then-reinstalled iOS app does. A
  *different* bundle claiming a taken label would inherit whatever has not yet
  been reaped, but labels are unique identities, so that is a namespace
  violation, not a normal case. We trade away the old generation field that
  distinguished installs; this is the accepted cost.
- **Delayed cleanup.** Resources linger until the next pass (boot, or a timer
  tick plus grace). Fine for garbage collection.
- **Provider discipline.** Only per-owner-label, enumerable state is
  reclaimable. A provider that stores state unlabeled or unenumerable leaks.
  The library enforces the shape (you must supply the callbacks); writing a
  provider means following the convention.
- **Manual meddling** (`rm -rf` a live container) is not protected — operator
  error, same as today.
- **Operator snapshots and clones.** A container's own snapshots are part of
  it and are swept by the reap (as `zfs destroy -r` would). A snapshot pinned
  by a clone that lives *outside* the container (an operator's backup clone)
  cannot be dropped: that reap fails soft (ZFS reports the branch point as
  `EEXIST`; logged with the reason, counted as failed) and is retried on every
  later pass until the clone is gone — data is never destroyed from under a
  clone.
- **Granularity.** Data is per-bundle; ownership is per-unit. The reconcile
  keys on the *bundle* (the unit of install and removal): a `Data/<bundle>/`
  container, a keystore owner, or a mapped log owner is live while its bundle
  is installed or running, whichever of its units that is.

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
   ephemeral `Run/` are the live set; no `Data/`-side hashes remain. The
   `cache/` sub-container is claimed through `service_storage_open_cache(3)`
   (regenerable data, reaped with the unit's container). `Apps/` is populated
   and exercised through pkg and the install-folder watch. The `log/`
   sub-container was superseded: a unit's logs live in logd's own store,
   keyed by the flat owner and reconciled by bundle through the owner map
   (item 3), so there is no per-unit log directory to deliver or reap.
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
   `directories = ["/Capabilities/System", "/Capabilities/Apps",
   "/Capabilities/Run/live"]` in its unit manifest and take the live-set roots
   from `service_resource_dir(3)` (switchboard creates `Run/live` before the
   first launch so it can be delivered). An
   `open(2)` by path fails ECAPMODE inside the sandbox and — because a missing
   `System/` is the readiness gate — *silently* disables reclaim (found on logd,
   latent on localcrypto). tzfsd is PID 1-spawned, not sandboxed, and reads by
   path.
4. **Shared and group containers.** *(built.)* `Data/<bundle>/shared/` is a
   scope of the bundle's own container (reaped with it, nothing extra).
   `Data/Shared/<group>/` is reaped **by membership**: switchboard publishes the
   installed-claimed groups as `Run/groups/<group>` markers (from every installed
   bundle's `groups`, at startup before any launch and on every reload), and
   tzfsd runs a second reconcile instance over `Data/Shared/` against that view
   — same library, own boot/timer state, gated on the marker directory existing
   so a pass before switchboard publishes reaps nothing. The claim protocol
   carries a scope (`unit`/`shared`/`group`) and the group name; a non-member
   is refused at the provider, and a group name is a single safe component
   everywhere it appears (manifest, identity, request, dataset). **Shared
   env** *(built.)*: the read-only view of the bundle-shared `env` store
   (`service_storage_open_env(3)`, tzfsd `DELIVER_MOUNTED_RO`), on top of
   shared anonymous mounts in the kernel and per-claim anchors in tzfsd.
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
   seals it and drops the mapping); **install-folder watch** (with no reload at
   all: `Apps/` created at runtime and the bundle moved into it relaunches its
   units under the new root, `rm -rf` unloads them, the `Run/live` marker
   appears and disappears with them, and the next boot reaps both the container
   and the log owner); **upgrade under `Apps/` through the watch** (a bundle
   removed and re-created with a bumped version relaunches at the new version
   with its container intact, through a reboot — the grace never confirms the
   transient absence); **kernel key reap** (a unit mints a named key under its
   bundle, the kernel owner list shows the bundle; after removal the next
   boot's localcrypto reconcile drops it and the owner list is empty);
   **install/remove through pkg itself** (a real package built with
   `pkg-static create` whose plist owns its bundle directories: `pkg add` →
   watch → unit runs and claims; `pkg delete` → directory gone → watch unloads
   it, marker gone → next boot reaps); **group container reaped only when the
   last member goes** (two members, a non-member refused at the provider,
   removing one member leaves `Data/Shared/<group>` intact, removing the last
   reaps it); **label reuse** (the same bundle removed and re-added within the
   grace inherits its container — a per-launch counter reads two — while a
   reinstall after the removal was confirmed and reaped starts fresh — it reads
   one; the unit's `cache/` sub-container is claimed on first launch and reaped
   with it); **snapshot sweep and clone fail-soft** (a container with an
   operator snapshot is reaped, snapshot included; one whose snapshot is pinned
   by a clone outside it is left intact with the reason logged, and reaped by
   the next pass once the clone is gone); **partial install admission** (a
   `System/` bundle re-created directory first and units six seconds later,
   below the watched level, is quarantined — not failing the scan — and admitted
   by the settled retry with no further event).
