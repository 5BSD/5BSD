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
│   │   └── cache/                      regenerable, reaped with the unit
│   ├── <bundle>/shared/            shared between a bundle's units (incl. env)
│   └── Shared/<group>/             cross-capability group container (App Groups)
├── Config/                     static admin config          bsdfilesystem.ucl, principal-policy.ucl
└── Run/                        ephemeral, cleared each boot  live/<bundle>, groups/<group> markers
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
  membership on the connection next to the container identity, and bsdfilesystem
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
provider connection — bsdfilesystem keeps one mount anchor per claim, not per
connection. The **delivered directory descriptor is itself an anchor**, so a
store lives as long as its holder keeps that descriptor: if bsdfilesystem dies and is
relaunched, running units keep their stores untouched and only new claims go
to the new instance (provider death is soft for storage).

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
  never blocking the other bundles — while a **registered bundle** caught half
  written (an in-place upgrade, `System/` or `Apps/` alike) keeps its previous
  registration, marked stale: its units are never stopped and its markers
  never dropped for a transient state. Either way the watch rescans a bounded
  number of settled times and admits the bundle once it is whole; a real
  change in a watched folder restarts that budget, exhaustion does not. A
  user bundle that conflicts with the registry (shadowing a system identity,
  a duplicate unit label or provided name, an unfillable manifest) is
  quarantined with the reason, never fatal; a `System/` root that vanishes at
  runtime retains the previous registry. At boot a malformed `System/` bundle
  is still a convergence failure. Switchboard notices, and **loads** the units
  — no explicit reload. A package must own
  its bundle directories (`@dir` entries), so that removing it removes the
  directory and not just the files; pkgbase's bundle packages do (verified:
  the `bsdlog` package's manifest lists `Log.cap`, `Units/`, `bsdlog.unit/`,
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

- **`enumerate()`** — the bundles it currently holds resources for (bsdfilesystem: the
  `Data/<bundle>/` containers; bsdcrypto: the kernel-keystore owners; bsdlog:
  the distinct bundles in its owner→bundle map).
- **`destroy(bundle)`** — free that bundle's resources (bsdfilesystem: `zfs destroy`
  the container, its snapshots included; bsdcrypto: drop the bundle's keys;
  bsdlog: seal every owner of the bundle through its reclaim floor).

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
  every client feeds to its DTrace `reclaim-pass` probe (`bsdfilesystem:::reclaim-pass`,
  `crypto:::reclaim-pass`, `bsdextension:::reclaim-pass`, `bsdnamespace:::reclaim-pass`,
  `blued:::reclaim-pass`, `bsdlog:::storage-reconcile`) and its log line.

The caller initialises the struct with `CAPRECLAIM_INIT`, which stamps a
`struct_size` field with the caller's own `sizeof` — an ABI-skew guard so a
provider built against one `libcapreclaim` and linked against another is never
read past the struct it allocated (optional fields are appended, never
reordered; `libcapreclaim.so.3`). The grace state ("seen gone twice") is
library-owned and opaque, not caller fields. Reclaim events are logged through
`logcmp_log(3)` — the Log capability — because a capability-mode provider
cannot reach `syslog(3)` (bsdlog, which cannot log to itself, keeps an fd-based
`reconcile.meta` record instead). Operability: a provider that sets
`status_dirfd`/`status_name` publishes its managed set to `/var/run/reclaim/`,
which `reclaimstat(8)` reads.

Clients today:

- **bsdfilesystem** — reaps `Data/<bundle>/` containers. It already reaps orphaned
  ephemeral leases this exact way; this extends it to persistent containers.
- **bsdcrypto** — drops kernel keys for bundles no longer live (keys stay in
  the kernel key store, off disk; see "keys" below).
- **bsdlog** — seals the log records of bundles no longer live (records live
  inside bsdlog's own container, keyed by the flat per-unit owner; a durable
  owner→bundle map makes them reconcilable by bundle).
- **bsdnamespace** — removes the persistent jails of bundles no longer live. A
  persistent jail outlives its unit by design (a relaunched consumer
  reattaches) but must not outlive the bundle; the jail name is a one-way
  hash of the unit's resource owner, so bsdnamespace keeps a jail→bundle map in its
  own container (written when a client connects, from the stamped container)
  and reconciles the `wj_` jails against it. A jail that predates the map is
  left alone and logged.
- **bsdextension** — unloads the kernel modules it loaded on behalf of bundles no
  longer live. Each ENSURE is attributed to the requesting unit's bundle
  (from the stamped container) in a per-boot module→bundle map; "bsdextension
  loaded it" is a property of the module for this boot, so the last bundle
  to claim a load is the one whose departure unloads it. A module found
  already loaded is attributed for the record and never unloaded (something
  else put it there); one the kernel reports busy stays loaded and is retried
  next pass. The map lives under `/var/run` rather than a storage container:
  modules do not survive a reboot (the map is stamped with the boot epoch and
  reset when it changes), and bsdfilesystem needs bsdextension to load `zfs` before it can
  serve any claim, so a storage claim there would be a boot cycle.
- **blued** — removes the local GATT services of bundles no longer live.
  Control clients historically arrive over a UNIX socket with no identity;
  a client may now open the exposed `system.Bluetooth` name instead
  (`ble_open_plane`), arriving with its stamped identity, and is handed one
  end of a socketpair carrying the same protocol. What such a client
  registers is attributed to its bundle per service handle range, in a
  sidecar beside the persisted GATT artifact (pinned to the declaration's
  uuid, since tail handles are reused; pending until the client's staged
  transaction commits), and an in-loop timer reconciles the records: an
  uninstalled bundle's services are removed from the live database. A
  service registered over the socket path carries no identity and is never
  reclaimed. A bundle-attributed plane client may edit its own bundle's
  services without the uid-0 tier, and nothing else.

**Every other provider was inventoried** (2026-09-17) for state held on a
bundle's behalf that outlives the bundle. Nine hold none or only state that
dies with the connection (netd, bsddevice, bsdsysctl, audit, traced,
notifyd, authagentd; waspnest's vsock window slots are process-lifetime and
reset with the daemon). No known gap remains.

A new provider with per-capability state becomes a client by writing those two
callbacks and wiring the library into its event loop and boot — it inherits
correct, upgrade-safe cleanup for free.

**Shared and group containers** are reaped *by membership*: the container is an
orphan only when no installed capability still claims it. The same reconcile
handles it — the "live" test for a group is "any member installed."

## Keys (why bsdcrypto is option b)

bsdcrypto keys stay in the **kernel key store**, owner-scoped, never written
to disk. Storing them as files under the container would be simpler (bsdfilesystem's
destroy would reap them) but would expose them on snapshots, backups, and
offline disks. Keeping them in kernel memory is worth one small reconcile:
bsdcrypto is a `libcapreclaim` client that drops keys for gone bundles.
Kernel keys, log records in bsdlog's own store, and bsdnamespace's jails are the
per-bundle state that is not itself a container directory, so those three
providers are clients; a provider whose only durable state is in its clients'
containers needs nothing — bsdfilesystem reaps the container for it. No provider
today stores client state in a client container; see the inventory above for
the two that hold it elsewhere without attribution.

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
- **Provider discipline.** Only state that is attributable to a bundle and
  enumerable is reclaimable. A provider that stores state unlabeled or
  unenumerable leaks — the library cannot help a provider that does not use
  it, so the convention has to be checked, not assumed: every provider that
  creates something on a client's behalf that outlives the connection
  (a dataset, a key, a record, a jail, a module, a VM) must either key it by
  the stamped container or keep an owner→bundle map, and supply the two
  callbacks. Kernel objects (jails, modules) count exactly as files do.
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
   `.../cache`): bsdfilesystem roots each client's storage there, keyed by the container
   `<bundle>/<unit>` switchboard stamps on the connection (a new `container`
   field in the delivered identity; `resource_owner` stays the flat per-label key
   the other providers use). The install directories `System/`/`Apps/` and the
   ephemeral `Run/` are the live set; no `Data/`-side hashes remain. The
   `cache/` sub-container is claimed through `service_storage_open_cache(3)`
   (regenerable data, reaped with the unit's container). `Apps/` is populated
   and exercised through pkg and the install-folder watch. The `log/`
   sub-container was superseded: a unit's logs live in bsdlog's own store,
   keyed by the flat owner and reconciled by bundle through the owner map
   (item 3), so there is no per-unit log directory to deliver or reap.
3. **The reconcile.** *(done for bsdfilesystem — VM-proven.)* `libcapreclaim` owns the
   live-set read, orphan computation, grace, and schedule, plus an empty-live-set
   safety floor (reap nothing when the live set is empty). bsdfilesystem is a client: it
   enumerates its `Data/<bundle>` containers, and a forked reconcile child reaps
   any whose bundle is not live — immediately on the first settled (boot) pass,
   seen-gone-twice on the timer. The live set is read straight from the install
   dirs (`System/`, `Apps/`, `strip_cap`) and switchboard's running-bundle markers
   (`Run/live/<bundle>`); `System/` existing is the readiness gate, so no sentinel
   is needed. Switchboard writes the running markers at boot and every reload and
   performs **unload-on-uninstall** (reload's Phase 1 graceful stop). bsdfilesystem's
   destroy recurses per child, so a real four-level container
   (`Data/<bundle>/<unit>/persistent/<claim>`) reaps (e81335b7f6e). **bsdcrypto**
   is a client too: the kernel keystore is keyed by bundle and a forked reclaim
   child drops an uninstalled bundle's keys (9f3138f885d). **bsdlog** is a client:
   records stay keyed by the flat `resource_owner` (it is the query-isolation
   scope, and sessions have no bundle), so the store keeps a durable best-effort
   owner→bundle map (`owners.meta`, fed by a fire-and-forget NOTE_OWNER on each
   accept) and the storage manager reconciles it in-process, sealing every owner
   of a gone bundle through the existing reclaim floor. The libservice no-op
   shims and bsdfilesystem's ledger-era seam are gone (61c2ef9b4e0, fde768439db).
   **Born-in-capmode rule:** a reconciling provider MUST declare
   `directories = ["/Capabilities/System", "/Capabilities/Apps",
   "/Capabilities/Run/live"]` in its unit manifest and take the live-set roots
   from `service_resource_dir(3)` (switchboard creates `Run/live` before the
   first launch so it can be delivered). An
   `open(2)` by path fails ECAPMODE inside the sandbox and — because a missing
   `System/` is the readiness gate — *silently* disables reclaim (found on bsdlog,
   latent on bsdcrypto). bsdfilesystem is PID 1-spawned, not sandboxed, and reads by
   path.
4. **Shared and group containers.** *(built.)* `Data/<bundle>/shared/` is a
   scope of the bundle's own container (reaped with it, nothing extra).
   `Data/Shared/<group>/` is reaped **by membership**: switchboard publishes the
   installed-claimed groups as `Run/groups/<group>` markers (from every installed
   bundle's `groups`, at startup before any launch and on every reload), and
   bsdfilesystem runs a second reconcile instance over `Data/Shared/` against that view
   — same library, own boot/timer state, gated on the marker directory existing
   so a pass before switchboard publishes reaps nothing. The claim protocol
   carries a scope (`unit`/`shared`/`group`) and the group name; a non-member
   is refused at the provider, and a group name is a single safe component
   everywhere it appears (manifest, identity, request, dataset). **Shared
   env** *(built.)*: the read-only view of the bundle-shared `env` store
   (`service_storage_open_env(3)`, bsdfilesystem `DELIVER_MOUNTED_RO`), on top of
   shared anonymous mounts in the kernel and per-claim anchors in bsdfilesystem.
5. **Verify on the VM.** *(proven 2026-09-16.)* Fresh-from-scratch boot is clean;
   durable data lands at `Data/<bundle>/<unit>/persistent` (e.g. `Data/Log/bsdlog/
   persistent/state`); the reaper runs and `Run/live/` holds one marker per
   running bundle. A planted orphan container `Data/OrphanBundle` is reaped by the
   boot pass (logged `reclaim: destroyed orphan persistent namespace …`) while the
   live `Data/Log/bsdlog` container is preserved. Proven since with real test
   bundles on from-scratch images: **install→claim→remove→reap** (a boot unit
   claims `Data/Test/reclaimprobe/persistent/state`, its bundle is removed, the
   next boot reaps it while `Data/Log` survives); **upgrade→untouched** (bumping
   `version`/`sequence` under the same `bundle_id` and rebooting leaves the
   container intact); **bsdlog remove→seal** (a unit that emits to `system.Log` is
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
   boot's bsdcrypto reconcile drops it and the owner list is empty);
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
   by the settled retry with no further event); **shared environment** (two
   units of one bundle hold the shared `env` store at once — the writer
   read-write, the reader through the read-only view — over one mount:
   the reader sees the writer's content, every mutation through the view is
   `ENOTCAPABLE`, the mount survives the writer's exit and goes with the last
   holder, a unit's persistent store stays mounted after it claims its cache,
   and the shared store is reaped with the bundle); **the timer path, live**
   (with short cadences and no reboot: a removal undone within one interval
   is never reaped, a confirmed removal of a container, a log owner and a
   kernel key is kept through one interval and reaped by the second pass in
   all three providers); **provider death** (bsdfilesystem killed under running
   units: their stores stay mounted and readable, switchboard relaunches it,
   a bundle installed afterwards claims from the new instance, no processes
   leak); **burst** (twelve bundles installed in one burst settle into one
   rescan and are all running, marked and claimed within seconds; removed in
   one burst they are all unloaded, and the next boot reaps all twelve in one
   pass); **jail reclaim** (two bundles enter persistent jails; uninstalling
   one has the timer pass remove its jail, attributed through bsdnamespace's owner
   map, while the live bundle's jail survives and the map is pruned);
   **module reclaim** (three bundles have bsdextension load modules; a bundle
   installed after a module was loaded by hand has it attributed but never
   unloaded; uninstalling a bundle unloads only the modules bsdextension loaded
   that no other bundle still claims; a module busy in the kernel is kept
   and retried once its user is gone; a reboot resets the map and the
   surviving bundle re-requests its module); **GATT service reclaim** (three
   bundles register local GATT services over the plane and each is
   attributed in blued's sidecar; a service registered over the socket path
   is not; uninstalling a bundle removes its services on the timer pass and
   leaves the others; a unit's death leaves its bundle's service in place;
   a restart restores the services with their records; a bundle removed
   while the daemon was down is reaped by the boot pass once it runs
   again). Every proof is a script under
   `tools/test/capability-containers/`
   (README there), runnable against a guest root with `run-all.sh`.
