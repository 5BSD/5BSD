# Capability-Plane API Expansion — Design Memo

Status: design proposal (2026-09-20). No code committed from this memo.
Audience: 5BSD capability-plane maintainers.

## Purpose

Every `system.*` capability daemon today exposes a deliberately small op set.
This memo asks, per daemon, **what applications actually want** — framed as
intents, not syscalls — and proposes capability-native API expansions that
satisfy those intents **without re-exposing the raw UNIX API** (no raw sockets,
`ifconfig`, BPF, `/dev` node names, raw OIDs, `kldload`, or `jail_set`).

### Design rules (apply to every proposal)

1. **Authority is the held channel label**, never a wire path/uid/pid.
2. **Return a narrower capability, not data.** An app asks for an *intent*
   ("wake me at a deadline", "give me a view of only my logs", "let me be
   reachable on this name") and receives a descriptor scoped to exactly that
   intent, which it can hold, delegate (one more SCM_RIGHTS hop), or drop.
3. **Compose capabilities across daemons.** A `system.Filesystem` zvol handle
   becomes a `system.VM` disk; a `system.Network` vport becomes a VM NIC; a
   `system.Crypto` key wraps a Filesystem cache. No daemon trusts a path.
4. **Owner-scoped enumerate + reclaim.** Every durable object gets a `LIST`
   and a reclaim op, or the namespace grows without bound.
5. **Fail soft, never `err(1)`/exit.** Revocation, eviction, and provider-down
   surface as recoverable events/empty-reopens (see the *no-hard-dependencies*
   principle).
6. **Kernel work is the exception.** Most proposals are daemon-side: policy
   catalogs, handle-binding, SHM rings, event fan-out. Kernel/bhyve items are
   called out explicitly.

Two existing libservice primitives are load-bearing for the expansions:
`service_provider_expose_sendable()` (re-sendable delivered descriptors — the
basis for capability handoff / connection brokering) and
`service_provider_expose_lazy()` (activation-on-demand — the hook for event
streams).

---

## system.Filesystem — the storage broker

Files: `lib/libcapsulert/bsdfilesystem_proto.h`, `usr.sbin/BSDFilesystem/request.c`,
`lib/libtrustedzfs/trustedzfs.h`, `docs/capability-container-model.md`.

### What apps want
- **Browser / package manager:** a scratch **cache** it can fill, that the
  system may reclaim under pressure, that can't blow up the pool, with usage
  accounting.
- **Build system:** stage an output tree and make it appear **all-at-once or
  not at all** — no half-written artifacts after a crash.
- **Database:** **snapshot** before a risky migration; open the point-in-time
  version read-only; roll back.
- **Media library / container registry:** store a blob **by content hash**,
  dedup identical objects, get a stable handle by digest.
- **Indexer / sync daemon:** be **woken on change**, not poll.
- **Multi-process app:** a **shared working set** one unit writes and others
  read.
- **Any sandboxed app:** a **mounted directory** delivered as an fd (it's in
  capmode and can't mount).

### Current API
`OP_REQUEST` (mint a TrustedZFS dataset: lifetime, ZH_* rights, refquota,
owner uid/gid, container scope UNIT/SHARED/GROUP, deliver HANDLE/MOUNTED/
MOUNTED_RO), `OP_RELEASE`, `OP_DESTROY`, `OP_LIST` (owner-scoped, folds `used`/
`refquota`), `OP_OPEN` (policy-gated isolated open of an existing path → rights-
limited fd), `OP_BEGIN_SESSION`, `OP_PING`. The kernel handle verbs
(snapshot/rollback/clone/promote/send/recv/mount/create/…) already exist in
`trustedzfs.h` — most proposals below just surface them as intents.

### Proposed expansions (ranked)
1. **First-class CACHE capability** *(daemon; optional kernel low-space kevent).*
   `OP_CACHE_REQUEST {soft_bytes, hard_bytes, priority}` (hard = refquota wall,
   soft = eviction target); `OP_CACHE_RECLAIM_POLICY` (WHOLE / LRU_SUBTREE /
   PINNED_UNTIL_RELEASE); daemon watches pool free space and evicts by
   priority+LRU using existing `tzfs_destroy`/`tzfs_snap_destroy`;
   `OP_CACHE_TOUCH` liveness renewal; eviction surfaces as an event (see #6),
   and a re-open of an evicted claim just finds it empty — never a crash.
   *Today `BSDFILESYSTEM_CACHE` is only a lifetime tag and is never actually
   reclaimed under pressure — this makes it a real cache.*
2. **Snapshots as app-visible time-travel** *(pure daemon; verbs exist).* **[IMPLEMENTED]**
   `BSDFILESYSTEM_OP_SNAPSHOT` → opaque `version_id`; `_LIST_VERSIONS` (paged);
   `_ROLLBACK`; `_OPEN_VERSION` (clone into an ephemeral lease dataset, mount
   read-only, deliver the dirfd). Client wrappers `service_storage_snapshot(3)`,
   `service_storage_list_versions(3)`, `service_storage_rollback(3)`,
   `service_storage_open_version(3)`. VM-validated: SNAPSHOT+LIST create/return a
   real ZFS snapshot end-to-end. (Retention policy keep-N/max-age still TODO;
   OPEN_VERSION's clone is reaped with its lease at reboot.)
3. **Atomic multi-file transaction** *(pure daemon; clone+promote).* **[IMPLEMENTED]**
   `BSDFILESYSTEM_OP_TXN_BEGIN` → writable mounted staging clone + txn id;
   `_TXN_COMMIT` → `tzfs_promote` then rename the clone over the claim (atomic
   whole-subtree swap; the caller must have released its own claim mount, EBUSY
   otherwise); `_TXN_ABORT` → destroy the clone + base snapshot. Client wrappers
   `service_storage_txn_begin/commit/abort(3)`. VM-validated: BEGIN creates a
   writable clone the caller edits, ABORT discards it leaving no leftover dataset.
4. **Content-addressed blob store** *(daemon; ZFS dedup).*
   `OP_BLOB_PUT` (hash + store by digest, dedup), `OP_BLOB_OPEN` (RO fd by
   digest), `OP_BLOB_RELEASE` (refcount, GC on sweep). The digest is a
   self-verifying capability name.
5. **Space accounting as intent** *(pure daemon; mostly exists).* **[IMPLEMENTED]**
   `BSDFILESYSTEM_OP_STAT_CLAIM` (one claim's live `{used, refquota, available}`)
   and `BSDFILESYSTEM_OP_SET_QUOTA` (raise/lower a claim's refquota post-mint,
   same floor as REQUEST) shipped: request.c handlers resolve the claim under the
   caller's own container (as DESTROY does), client wrappers
   `service_storage_stat(3)` / `service_storage_set_quota(3)`.
6. **Change notification / watch** *(daemon; delivered kevent-able fd).*
   `OP_WATCH` → a capability fd the client `kevent`s for create/write/delete/
   evicted/version events. Cheapest impl delivers a dirfd the client watches
   with `EVFILT_VNODE`; recursive/semantic events want the switchboard's
   existing edge-triggered vnode-watch machinery.
7. **Ad-hoc sharing** *(pure daemon; scope exists).*
   `OP_GRANT_SHARE`/`OP_ACQUIRE_SHARE` — the owner mints a narrowed (RO/RW)
   grant token a *named peer* redeems, beyond static bundle/group membership.
8. **Delivered-mount ergonomics** *(pure daemon).*
   `DELIVER_MOUNTED_SUBDIR` — mount then `openat` a named subdir, delivering
   only that subtree with narrowed rights.

---

## system.VM — the VM broker

Files: `lib/libcapsulert/vmd_proto.h`, `usr.sbin/BSDVM/bsdvm.c`. Today: **vsock
brokering only** (`VMD_OP_VSOCK_BIND/CONNECT/LIST`).

Model: a **VM is an owned object named by a `vm_id` scoped to the caller's
label**; its bhyve process is a pdfork'd child under the caller's coalition (so
coalition teardown reaps it); every I/O device is a *consumed* delivered
capability and every control surface a *returned* capability fd.

### What apps want
- **CI/build controller:** spin an ephemeral VM from a base image, give it a
  disk + NIC, run a job, snapshot the result, tear it down — all owned, no root,
  no `/dev/vmm` juggling.
- **Desktop virtualization:** persistent VM, ZFS-backed disk, bridged NIC,
  console, pause/resume, snapshots to roll back to.
- **Migration/HA:** suspend a VM to a stream, resume it on another host.
- Cross-cutting: **the VM's disk is a delivered storage capability, its NIC a
  delivered network capability** — owner-held, revocable, path-free.

### Proposed expansions (ranked)
1. **VM lifecycle as owned objects** *(daemon + existing `vmm.ko`).*
   `VMD_OP_CREATE {vcpus, mem, loader}` → `vm_id` + control-channel fd;
   `START`/`STOP`/`RESET`; `SUSPEND`/`RESUME`; `VMD_OP_PROCDESC` → a procdesc
   for the bhyve process (lifecycle is a held capability, not a pid).
2. **Disk = delivered TrustedZFS capability** *(daemon + one bhyve fd-backend hook).*
   `VMD_OP_ATTACH_DISK` consumes a TrustedZFS **volume handle fd** (from
   `system.Filesystem`) + `{RO/RW, virtio-blk/nvme/ahci}`, `tzfs_blkopen`s it,
   wires it as a guest block device; `DETACH_DISK` hot-detach. Snapshot/clone
   from the Filesystem apply to VM disks for free (golden-image clone-on-boot).
   *New integration point: bhyve must accept an already-open fd as a block
   backend.*
3. **NIC = delivered network capability** *(daemon + system.Network + tap/vmnet).*
   `VMD_OP_ATTACH_NIC` consumes a network vport capability (see Network #5);
   `VMD_OP_ATTACH_VSOCK` bridges the guest vsock to the caller's existing
   label-scoped window (reuses today's machinery — the natural first bridge).
4. **Console = delivered pty capability** *(pure daemon).*
   `VMD_OP_CONSOLE` → a pty master fd (or bound vsock) for the guest serial
   console; no `/dev/nmdm` path, works in capmode.
5. **Snapshot / checkpoint / migrate** *(daemon + bhyve snapshot + tzfs send).*
   `VMD_OP_SNAPSHOT` (bhyve device+vCPU checkpoint **plus** atomic
   `tzfs_snapshot` of every attached disk, under one `vm_version_id`);
   `RESTORE`; `MIGRATE_SEND`/`RECV` (disks via `tzfs_send`/`recv`, memory via
   bhyve live-migration over a delivered fd). Highest value, least-mature
   kernel dependency (vmm live migration).
6. **Device hot-plug + introspection** *(daemon).*
   `ATTACH_DEVICE`/`DETACH_DEVICE` (rng, balloon, framebuffer, PCI passthrough
   via a `system.Device` node fd); `VMD_OP_LIST` (owner-scoped VMs); `STAT`.

---

## system.Network

Files: `lib/libnetworkcmp/networkcmp_protocol.h`, `usr.sbin/BSDNetwork/`. Today:
a pure **outbound** connection broker (the header reserves the rest of the
opcode space for listeners/stacks/virtual interfaces).

### What apps want
- **Web/API server:** a capability to *be reached* on a name/port; each inbound
  connection delivered as a descriptor — never `bind`/`listen`/`accept` or a
  guessed port.
- **p2p app:** connect to a peer **by name/identity**, not IP; broker the
  rendezvous so neither side learns the other's address.
- **Multi-component app:** a **private overlay** just for its components, with a
  virtual port per component.
- **Any service:** register in discovery so peers find it by capability; bound/
  accounted bandwidth.

### Current API
`HELLO`, `RESOLVE` (policy-scoped bounded getaddrinfo), `CONNECT` (TCP: connected
transfer-limited fd — cannot bind/listen/accept/peel), `UDP` (connected datagram).
Policy: ipv4/ipv6/allow_connect/allow_udp/resolve/allow_internal, from label
rights.

### Proposed expansions (ranked)
1. **`LISTEN` — a listening endpoint as a capability** *(daemon).* Ask for a
   service name / port class; daemon owns the socket, delivers accepted
   connection fds as events (same narrowing as CONNECT). *The headline gap:
   apps cannot be servers today.* New `allow_listen` policy dim + per-label
   port/name window (mirror vmd's label-scoped windows).
2. **`ANNOUNCE`/`WITHDRAW` — service registration** *(daemon).* Register "this
   listener *is* `myapp.svc`"; `RESOLVE` is the read side. Network becomes a
   service directory, not just a DNS shim.
3. **`RENDEZVOUS` — broker two capabilities without either learning an address**
   *(daemon; `expose_sendable`).* Both hold a Network cap + a shared token;
   daemon hands each a connected fd (socketpair when co-resident, relay
   otherwise).
4. **`OVERLAY_CREATE`/`JOIN` — a private virtual network** *(kernel: vnet +
   epair/if_bridge; if_ovpn AEAD exists).* An L3 overlay capability the app's
   components join; nobody else sees the segment.
5. **`VPORT_ALLOC` — a virtual port bound into a VM/jail vnet** *(cross-daemon:
   Network mints, VM/Namespace consume).* Give a VM a NIC on the overlay.
6. **`BIND_DGRAM` — a bound UDP receive endpoint** *(daemon).* Inbound sibling
   of today's connected UDP (DNS/QUIC/discovery responders).
7. **`DISCOVER` — service discovery/browse** *(daemon).* Enumerate instances of
   a service type filtered by what the label may reach.
8. **`QOS_BUDGET` — bandwidth/QoS as a consumable capability** *(kernel:
   dummynet/ALTQ).* Rate/priority class + counters per listener/connection.

---

## system.Device

Files: `lib/libdevicecmp/devicecmp_protocol.h`, `usr.sbin/BSDDevice/`. Today: a
thin `/dev`-leaf broker (openat under a delivered `/dev` dirfd, cap_rights
narrowing, per-`(label,device)` ioctl whitelist). The gap: apps still think in
**node names and ioctl numbers** — the raw-UNIX leak.

### What apps want
- **Camera/device app:** "give me *a camera*" — not `/dev/video2` and the safe
  `VIDIOC_*` set; a typed **camera capability** with rights pre-narrowed.
- **Serial/GPIO tool (RPi5):** a typed UART/GPIO-line capability with
  `set_direction`/`read_line`, not raw ioctl passthrough.
- **Hotplug daemon:** device arrival/removal as **events**, not `/dev` polling.
- **Exclusive users (modem/burner/block):** an **exclusive** claim, reclaimed
  on death.
- **Storage stack:** a **block capability** (or sub-range) to hand to Filesystem,
  not a raw `/dev/da0`.

### Current API
`HELLO`, `OPEN` (leaf name + wanted `DEVICECMP_RIGHT_*` → rights-narrowed fd),
`LIST` (owner-scoped, openable leaves + policy-max rights).

### Proposed expansions (ranked)
1. **`OPEN_CLASS` — typed device-class capabilities** *(daemon).* Request by
   *class* (camera/serial/gpio/block/audio/input) + hints; daemon resolves the
   node and applies a class-standard ioctl profile + rights. Removes node-name/
   ioctl-number knowledge from apps. *Headline.*
2. **`SUBSCRIBE` — hotplug as an event stream** *(daemon; devctl/devd + lazy).*
   Arrival/removal for a class or match, label-filtered.
3. **`CLAIM` exclusive vs shared** *(daemon).* Track holders per node; refuse or
   queue conflicting claims — safe mutual exclusion without `O_EXCL` races.
4. **Named ioctl profiles per class** *(daemon).* Promote the raw ioctl
   whitelist into named operation sets ("camera.controls", "gpio.lines").
5. **`ATTENUATE_BLOCK` — sub-device/range capabilities** *(kernel: GEOM-style
   range gate).* A block capability restricted to an offset/length window.
6. **Leased claims with TTL / auto-reclaim** *(daemon).* Reclaim on holder death
   or expiry (mirrors crypto's `NAMED_LEASE`).
7. **`STAT`/`WATCH` a specific device** *(daemon).* Typed metadata + state-change
   watch (link up, media present).

---

## system.Crypto

Files: `lib/libcryptocmp/cryptocmp_protocol.h`, `sys/sys/cryptodesc.h`,
`sys/opencrypto/`. The **inverse** case: the kernel `cryptodesc` layer is already
rich (non-extractable descriptor caps with per-fd rights, attenuation, ed25519
sign/verify, x25519 ECDH, KDF, named keys) — the daemon surfaces a subset, so
most proposals are daemon-side plumbing over existing kernel verbs.

### What apps want
- **Password manager:** a key that can **never be extracted**; encrypt/decrypt
  against it; **seal** the vault so only *this app (label)* can unseal.
- **Signing service:** hold a signing key, export only the *public* key; give
  verifiers a verify-only capability.
- **Filesystem/cache:** **wrap** a per-file data key under a master key
  (envelope encryption — a stated goal).
- **p2p app:** ECDH with a peer's public key → a **session-key capability**,
  never seeing the raw secret.

### Current API
`HELLO`, `GENERATE` (symmetric session), `GENERATE_KEY` (asymmetric; returns
public key), `NAMED_CREATE/LEASE/ROTATE/DELETE/STAT/LIST`, `DIGEST`, `RANDOM`.
Descriptors carry attenuable `CRYPTODESC_RIGHT_*`.

### Proposed expansions (ranked)
1. **`WRAP`/`UNWRAP` — envelope encryption** *(daemon).* Wrap a data key under a
   named key → opaque blob; `UNWRAP` returns a fresh session descriptor, never
   plaintext key bytes. *Highest leverage — the Filesystem/cache use case.*
2. **`SEAL`/`UNSEAL` — sealed storage bound to a capability/label** *(daemon).*
   Encrypt so only the same owner label (± policy) can unseal.
3. **`SIGN`/`VERIFY` first-class named-key ops** *(daemon; kernel ed25519 exists).*
   Mint a sign-capable descriptor + a separate verify-only capability;
   `EXPORT_PUBLIC`. (Ties to IPC-anointment signing.)
4. **`EXCHANGE` — ECDH to a session-key capability** *(daemon; kernel x25519).*
   Raw shared secret never crosses the wire. Pairs with Network `RENDEZVOUS`.
5. **`DERIVE` — HKDF child-key capabilities** *(daemon; kernel KDF exists).*
   Per-purpose/per-tenant separation from one root.
6. **`ATTEST` — signed attestation/quote** *(daemon; HW root optional).*
7. **`MAC` / keyed-verify tokens** *(daemon).* Cheap authenticated capability
   tokens.
8. **`IMPORT_PUBLIC` / peer-key registration** *(daemon).* Pinning / TOFU for p2p.

---

## system.Namespace (jails)

Files: `lib/libcapsulert/bsdnamespace_proto.h`. Today: `ENTER_JAIL`/`DESTROY_JAIL`/
`LIST_JAILS`, one label-scoped jail, flags `F_EPHEMERAL`/`F_VNET`, returns a
`jd` the caller `jail_attach_jd`s into.

### What apps want
Confine *just this subtree*; a filesystem view composed of only the dirs I hold;
a network-isolated worker; snapshot a sandbox and fork N identical ones; cap
resources as part of confinement.

### Proposed expansions (ranked)
1. **`OP_COMPOSE_ROOT`** *(kernel: nmount/overlay under jail cred; heavy).* Build
   the jail root from held dir-capabilities (`{dirfd, mountpoint, ro/rw}` SCM
   fds) instead of a global path — a namespace as a pure function of what you
   hold. *Purest expression of the authority model.*
2. **`OP_CLONE_NAMESPACE`** *(daemon + tzfs clone).* Snapshot a jail definition
   (and ZFS root) → N identical child sandboxes cheaply.
3. **`OP_LIMIT` — limits as a capability** *(kernel rctl exists).* Attach a
   mem/pcpu/nfds/maxproc budget to the jail as a droppable limit descriptor.
4. **`OP_NEST`** *(daemon).* A confined caller creates a strictly-narrower
   sub-namespace (hierarchical jails), scoped `label + subtag`.
5. **`OP_DEVICE_VIEW`** *(daemon + devfs ruleset).* Seed the jail's devfs from
   `system.Device` capabilities, not the host devfs.

---

## system.SystemExtension (module loading)

Files: `lib/libcapsulert/sysext_proto.h`. Today: `ENSURE` (allow-listed module
name), `STAT`, `LIST`, `RELOAD`.

### What apps want
"I need USB-serial support" — not "kldload umodem". Query availability; load a
feature *for my session* and unload when I'm gone; know what a feature grants.

### Proposed expansions (ranked)
1. **`OP_ENSURE_FEATURE`** *(daemon).* Request an abstract feature
   ("usb-serial", "nfsv4-client") mapped to modules via a policy catalog —
   decouples apps from module names.
2. **`OP_PROVIDES`** *(daemon).* Query what a feature would light up (no load),
   so apps plan/soft-fail first.
3. **`OP_HOLD_FEATURE`** *(daemon refcount + gated kldunload).* Load and return
   an extension-hold descriptor; last hold dropped ⇒ eligible for autounload
   (mirrors the ephemeral-jail owning-descriptor pattern).
4. **`OP_WATCH`** *(via Notify).* Subscribe to load/unload transitions so a
   consumer re-establishes its device capability.

---

## system.Time

Files: `lib/libtimecmp/timecmp_protocol.h`. Today: `GET`, `SET` (privileged
step), `ADJUST` (privileged slew). Wall clock only; no timers.

### What apps want
Wake in 30s / at 09:00 / every minute; a trustworthy monotonic clock across
suspend; a deadline capability handed to a watchdog; calendar scheduling.

### Proposed expansions (ranked). *Split of concern:* Time owns clock semantics
(mint deadline capabilities); Notify owns delivery.
1. **`OP_GET_MONOTONIC`** *(daemon).* Unprivileged monotonic/uptime read.
2. **`OP_DEADLINE`** *(kernel: a pollable timer object / eventfd).* One-shot or
   periodic deadline capability, readable/pollable for expiry, delegable.
3. **`OP_SCHEDULE_CALENDAR`** *(daemon).* Crontab-semantics calendar deadline.
4. **`OP_LEASE_TIME_AUTHORITY`** *(daemon).* A bounded step/slew capability
   (e.g. ±100ms) for a subordinate NTP helper — least-privilege time discipline.

---

## system.Sysctl

Files: `lib/libsysctlcmp/sysctlcmp_protocol.h`. Today: `GET`/`SET` (raw value by
name), `OIDFMT`, `DESCR`, `NEXT`; per-label OID allow/deny; value is an opaque
byte blob.

### What apps want
A handle to *my* tunable I can get/set type-safely; `hw.ncpu` as an int, not a
raw blob; notify on change; set-with-clamp to a policy range.

### Proposed expansions (ranked)
1. **`OP_OPEN_TUNABLE`** *(daemon).* Resolve a name once → a typed tunable
   capability (kind + policy bounds); GET/SET on the handle with server-side
   marshalling. Kills the OIDFMT-then-format dance.
2. **`OP_WATCH`** *(kernel sysctl hook or daemon poll; via Notify).* Change
   notification for a permitted OID.
3. **`OP_BATCH_GET`** *(daemon).* One round-trip typed snapshot of a set.
4. **`OP_TYPED_SET` with policy clamp** *(daemon).* Enforce per-label min/max/enum.
5. **App-namespace tunables** *(daemon).* `app.<label>.*` typed config backed by
   the daemon, off the global MIB.

---

## system.Log

Files: `lib/liblogcmp/logcmp_protocol.h` (ABI 6 — already rich). Today: `WRITE`
(typed records, severity, typed attrs, privacy PUBLIC/PRIVATE/PRIVATE_HASH),
`QUERY` (cursor-paged, filtered, label-scoped), `ATTACH` (SHM ring w/ wake fds —
zero-copy ingest), `FLUSH`, `STATS`, `NOTIFY`, `DETACH`.

### What apps want
A live tail of *only my* logs; query my last N errors since a cursor; a
retention policy; scoped export to an OTel pipeline.

### Proposed expansions (ranked — mostly incremental given maturity)
1. **`OP_OPEN_STREAM`** *(daemon).* A scoped, tailable read handle (SHM ring for
   reads) bound to a filter, delegable to a viewer — "let my supervisor tail my
   errors" without the whole read surface.
2. **`OP_SUBSCRIBE`** *(daemon).* Push-tail via the existing wake-fd machinery.
3. **`OP_SET_RETENTION`** *(daemon).* Per-label size/time/severity retention as a
   settable capability.
4. **`OP_REDACTION_POLICY`** *(daemon).* Per-label field redaction enforced by
   policy, not per-call.
5. **`OP_EXPORT`** *(daemon).* A RO, filtered, time-bounded stream capability for
   an OTel exporter (libotelexport).

---

## system.Audit

Files: `lib/libauditcmp/auditcmp_protocol.h`. Today: `SUBMIT` (subject +
operation + errno into the BSM trail), `STATS`. **Write-only.**

### What apps want
Emit a security event into the trusted trail; read back *my own* records for a
compliance view; subscribe to events about my label for an in-app SIEM.

### Proposed expansions (ranked)
1. **`OP_OPEN_SCOPED_STREAM`** *(daemon).* A read capability over the audit trail
   filtered to the caller's own label/subtree — app-scoped audit without reading
   the global BSM trail (a TCB secret).
2. **`OP_SUBMIT_STRUCTURED`** *(daemon).* Typed attributes + category/outcome,
   aligned with Log's typed model.
3. **`OP_SUBSCRIBE`** *(via Notify).* Live delivery of new in-scope events.
4. **`OP_ATTEST`** *(daemon + Crypto).* A signed, tamper-evident excerpt of the
   caller's audit slice.

---

## system.Notify

Files: `lib/libnotify/notify_protocol.h`. Today (already broad): topic
`SUBSCRIBE`/`UNSUBSCRIBE`/`PUBLISH` (exact + prefix policy), `NEXT`,
`TIMER_ADD`/`CANCEL` (≤24h), `STATE_SET`/`GET`/`CLEAR` (shared presence state),
`LIST_*`, `STATS`.

### What apps want
Pub/sub on a topic; timer wakeups; small shared state (presence) others can read;
react to system events.

### Proposed expansions (ranked)
1. **`OP_OPEN_TOPIC`** *(daemon).* A topic capability (publish-only or
   subscribe-only) as a delegable descriptor — hand a child "publish on
   my.app.events" without your whole Notify label.
2. **`OP_WATCH_STATE`** *(daemon).* Subscribe to STATE key changes (presence)
   instead of polling.
3. **`OP_REQUEST_REPLY`** *(daemon).* Correlated request/reply over a topic
   (mint a reply-topic capability) — lightweight cross-app RPC on the channel.
4. **`OP_SYSTEM_EVENT_BRIDGE`** *(daemon + emitters).* Reserved topics fed by
   other daemons (`sys.network.up`, `sys.extension.loaded`, `sys.time.stepped`)
   — one subscription surface for all the cross-daemon `WATCH`es proposed above.
5. **Deadline-capability convergence** *(daemon + Time).* Accept a Time-minted
   deadline as a timer source; removes Notify's 24h cap.

---

## system.Trace

Files: `lib/libtracecmp/tracecmp_protocol.h`. Today: `OPEN` (a raw kernel DTrace
consumer fd), `STATS`; admin-only, whole-system. The least capability-native of
the set.

### What apps want
Trace *my own* process subtree (no root, no whole-system DTrace); counters/
metrics; a flight-recorder ring dumped on crash; enable a named probe set.

### Proposed expansions (ranked — biggest design gap)
1. **`OP_OPEN_SCOPED`** *(kernel: DTrace predicate/scoping by coalition id).* A
   trace capability bounded to the caller's coalition/subtree — the headline
   use case; the coalition model already provides the identity to scope by.
2. **`OP_COUNTERS`** *(daemon SHM).* Named counters/gauges/histograms as a
   metric-handle capability (feeds hwtlm/OTel).
3. **`OP_FLIGHT_RECORDER`** *(daemon ring + kernel scoped feed).* A fixed ring of
   the caller's own events, dumpable on crash.
4. **`OP_ENABLE_PROBE_SET`** *(daemon curates D; kernel unchanged).* Enable a
   named, policy-vetted probe set ("io-latency") → a streamed event capability,
   instead of a raw DTrace fd.
5. **`OP_USDT_REGISTER`** *(kernel USDT + daemon registry).* App-defined
   tracepoints in the capability model.

---

## Cross-cutting recommendations

- **Mint scoped handles, not data.** The single highest-leverage missing pattern
  across Sysctl/Log/Audit/Notify/Time/Trace is an `OP_OPEN_*` returning a
  narrowed, delegable descriptor (typed tunable, log stream, topic, deadline,
  scoped trace) — the capability-native replacement for "call with a name string
  each time," matching the owning/non-owning descriptor discipline already
  proven in Namespace and Extension.
- **Consolidate timers.** Time mints deadline capabilities; Notify delivers
  events. Removes Notify's 24h cap and duplicated clock logic.
- **One event bus.** The many proposed `WATCH`/`SUBSCRIBE` ops (Extension load,
  Sysctl change, Audit event, Namespace lifecycle, cache eviction) should all
  deliver through **Notify reserved system topics** reusing the edge-wakeup ring
  machinery already in `system.Log` — one subscription surface, not a bespoke
  push channel per daemon.
- **Capability composition is the point.** Filesystem zvol → VM disk; Network
  vport → VM/jail NIC; Crypto key → Filesystem/cache envelope; Device node →
  VM passthrough. Design every new handle to be *consumable* by another daemon.
- **Biggest single wins:** Filesystem CACHE + transactions/versioning; VM
  lifecycle + disk/NIC-as-capability; Network `LISTEN` + `RENDEZVOUS` (apps can
  finally *be reachable* and dial by identity); Device `OPEN_CLASS` +
  `SUBSCRIBE`; Crypto `WRAP/UNWRAP` + `SEAL/UNSEAL`; Trace `OPEN_SCOPED` +
  counters; Audit app-scoped read.
- **Kernel vs daemon:** the large majority is daemon-side (policy, catalogs,
  handle-binding, SHM rings, event fan-out). The genuine kernel/bhyve work:
  fd-backed bhyve block backend (VM disk), vmm live-migration (VM migrate),
  coalition-scoped DTrace + USDT (Trace), pollable timer objects (Time),
  per-jail rctl attach + overlay/devfs composition (Namespace), network overlay/
  vport/QoS (Network vnet/dummynet), block range-gate (Device), and an optional
  pool-low-space kevent + recursive vnode watch (Filesystem).
