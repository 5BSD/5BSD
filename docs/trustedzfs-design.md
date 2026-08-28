# TrustedZFS: a capability API over the ZFS storage API

Companion to `mac_capability-architecture.md` (the fd-type and SDT house
pattern this follows), `authority-control-abi-design.md` (the capability-token
grant model that consumes this), and `capability-components-roadmap.md`.
This records the design of dataset and pool *handles* — first-class file
descriptors that make ZFS storage a thing a program is handed, not a place
it goes — plus the code-grounded implementation, testing, and DTrace plan.

## 1. Problem

The ZFS control plane is ambient. Every operation is an ioctl on `/dev/zfs`
addressed by a dataset **name string**, re-resolved on every call, and
authorized by a central check (`zfs allow` delegation, `zfs jail`
visibility, or root). Consequences:

- **No unforgeable grants.** You cannot hand a process "this dataset and
  nothing else" as an object. Policy lives in tables (`zfs allow`) that any
  reachable process may attempt against.
- **No sandboxed tooling.** After `cap_enter()` a process cannot perform
  name lookups, and every `/dev/zfs` ioctl *is* a name lookup — so nothing
  built on libzfs can run under Capsicum.
- **Rename races.** Name-per-ioctl means multi-step operations (snapshot,
  hold, send) can land on a different dataset than the one they started on.
- **No delegable events.** Watching for snapshot/pool events means being
  zed, a single privileged process draining a global event ioctl.

Our fork's direction — Authority capability tokens, `mac_capability` fds,
Capsicum-aware zfs ioctls (commit 47195449a23) — makes storage the odd
subsystem out. TrustedZFS closes that gap.

## 2. Vision: three planes, one handoff rule

Filesystems sit on top of storage, and ZFS already has that split
internally: the pool (SPA/DMU) is an object store; datasets are views onto
it — ZPL filesystems, zvol block devices, snapshots. The capability
boundary follows that structure:

```
+----------------------------------------------------------+
| DATA PLANE -- bytes                                      |
|   files via dirfd/openat/mmap ; zvols via block fd       |
|   (Capsicum already governs this -- nothing new here)    |
+----------------------------------------------------------+
| MANAGEMENT PLANE -- dataset handles (zfd)                |
|   create/destroy/snapshot/rollback/clone/send/recv/      |
|   props/mount -- TrustedZFS lives here                   |
+----------------------------------------------------------+
| STORAGE PLANE -- pool handles (zpd)                      |
|   health, capacity, scrub, bootfs -- thin by design      |
+----------------------------------------------------------+
```

**TrustedZFS is a capability API over the management plane only.** The
data plane needs nothing (Capsicum solved file and block access); the
storage plane gets only a thin delegable sliver. Each plane hands down to
the one above through exactly one door:

- storage → management: `ZPD_ROOT_OPEN` (pool handle → root dataset handle)
- management → data: `ZFD_MOUNT` (dataset handle → dirfd of an anonymous
  mount) and `ZFD_BLKOPEN` (zvol handle → block-device fd)

Governing rules: **handles denote objects, not addresses; doors go one
direction; rights only shrink.** There is deliberately no mmap, offset, or
block addressing on the management plane — byte access always happens
after the handoff, through objects Capsicum and MAC already govern. The
management plane can therefore never become a side channel around VFS
enforcement: it has no read verb.

## 3. Handle model

### 3.1 Identity: GUID pinning

A dataset handle pins the triple **(pool guid, dsobj, ds_guid)**. Every
operation holds the dataset by object number (`dsl_dataset_hold_obj`,
O(1)) and verifies `ds_guid` still matches:

- **rename-proof**: object numbers survive renames; the handle follows the
  dataset, and the current name is re-derived only to call the existing
  name-based implementation paths;
- **destroy-proof**: destroy + recreate under the same name yields a new
  dsobj/guid; the check fails and the op returns `ENXIO`;
- **no new index needed**: there is no `dsl_dataset_hold_by_guid()` in the
  tree and we do not need one — the dsobj is the O(1) locator, the guid is
  the validity witness.

Invalidation contract: after destroy / pool export / recv-rollback of the
pinned object, every op returns `ENXIO` except `close()` and `ZFD_INFO`
(which reports invalid), and the handle's kqueue fires `INVALIDATED`.

### 3.2 Rights

A rights mask fixed at creation, checked in the handle's ioctl dispatch
(distinct from — and beneath — Capsicum's per-fd `cap_ioctls_limit`, which
allowlists command numbers before `fo_ioctl` is reached):

| Right            | Governs                                        |
|------------------|------------------------------------------------|
| `ZH_PROPS_READ`  | get props / stat / list (implicit, always on)  |
| `ZH_PROPS_WRITE` | set properties (optionally per-prop allowlist) |
| `ZH_SNAPSHOT`    | create snapshots                               |
| `ZH_SNAP_DESTROY`| destroy snapshots                              |
| `ZH_ROLLBACK`    | rollback to snapshot                           |
| `ZH_CLONE_SRC`   | act as clone origin                            |
| `ZH_CREATE`      | create child datasets / receive clones         |
| `ZH_DESTROY`     | destroy datasets in scope                      |
| `ZH_SEND`        | serialize as a stream (data-equivalent: this   |
|                  | right can read every byte, by design, visibly) |
| `ZH_RECV`        | receive streams into scope                     |
| `ZH_MOUNT`       | anonymous mount → dirfd; zvol → block fd       |
| `ZH_HOLD`        | create snapshot holds                          |
| `ZH_RELEASE`     | release snapshot holds                         |
| `ZH_RENAME`      | rename datasets                                |
| `ZH_PROMOTE`     | promote clones                                 |
| `ZH_BOOKMARK`    | create bookmarks                               |
| `ZH_EVENT`       | kqueue attachment (implicit, always on)        |

Plus a **subtree flag**: the handle covers descendants (list, openat,
create, recursive snapshot) rather than a single dataset.

Two derivation operations, both monotonic (result rights ⊆ source rights):

- `ZFD_DERIVE(mask)` — same object, narrower rights; the narrowing step a
  grantor performs before passing a handle on. May carry a per-property
  allowlist for `PROPS_WRITE`.
- `ZFD_OPENAT(relname, mask)` — open a child dataset or snapshot *through*
  a subtree handle; the openat() of the design. Relative names only; no
  `..`, no absolute names, no escaping the grant via rename.

`ZH_CREATE` does not imply destroy-what-you-created: grant `ZH_DESTROY`
explicitly when that lifecycle is required.

### 3.3 Pool handles and derivation topology

Dataset and pool handles are **peers**, both minted by name from
`/dev/zfs`; they are not parent and child:

- `/dev/zfs` → `ZFS_IOC_DATASET_OPEN` → zfd → derive/openat → narrower zfds
- `/dev/zfs` → `ZFS_IOC_POOL_OPEN` → zpd → `ZPD_ROOT_OPEN` → zfd

The bridge is one-directional. A zfd can never climb to pool authority
(no privilege amplification); a zpd can descend, rights-limited. We do
not root all zfds under zpds even though that mirrors the ZFS namespace:
it would put pool authority in every delegation chain, the two rights
vocabularies are disjoint (cross-type monotonicity has no clean answer),
and the only thing the coupling would express — handles die with the pool
— is already delivered unconditionally by guid verification.

Pool rights are the thin sliver the use cases actually demanded:
`ZPD_STAT` (health, capacity, scan progress, error counts), props
read/write with per-prop allowlist (sole motivating writer: `bootfs`, for
boot-environment activation by authority-init), `ZPD_SCRUB` behind its own
right, `ZPD_ROOT_OPEN`, and kqueue events (`STATE_CHANGED`,
`SCRUB_FINISHED`, `RESILVER_FINISHED`, `VDEV_FAULTED`, `INVALIDATED`).
Explicitly **not** delegable: import/export, vdev topology changes,
upgrade. Those reshape the pool and stay ambient-admin.

### 3.4 Minting and authorization

Minting (name → handle) is the only name-based step and requires ambient
access to `/dev/zfs`. Authorization at mint time reuses the existing
layers wholesale: each requested right maps to the corresponding
`zfs allow` permission and is checked via
`zfs_secpolicy_write_perms` / `dsl_deleg_access_impl`, and
`zone_dataset_visible` gates minting inside jails. Root mints anything;
an unprivileged user mints exactly what `zfs allow` delegates; a jailed
process mints only within its visible datasets. After minting, rights
travel with the handle and no further central checks apply — that is the
point.

Handles pass over unix sockets via SCM_RIGHTS (`DFLAG_PASSABLE`) — that
*is* the delegation mechanism — and survive fork and dup with standard fd
semantics.

## 4. Ioctl surface

### 4.1 Minting (on /dev/zfs)

- `ZFS_IOC_DATASET_OPEN(name, rights, flags)` → zfd (flags: SUBTREE)
- `ZFS_IOC_POOL_OPEN(name, rights)` → zpd

### 4.2 On any handle

- `ZFD_INFO()` — guid, current name, effective rights, subtree flag,
  validity. Always allowed.
- `ZFD_DERIVE(rights[, prop_allowlist])`
- `ZFD_OPENAT(relname, rights)`

### 4.3 Dataset handle verbs

| Verb | Right | Notes |
|------|-------|-------|
| `ZFD_GET_PROPS` / `ZFD_STAT` | `PROPS_READ` | STAT is the cheap fixed-size subset for monitors |
| `ZFD_GET_ONE_PROP(name)` | `PROPS_READ` | single property; native props resolve even at default value |
| `ZFD_LIST_CHILDREN` / `ZFD_LIST_SNAPS` | `PROPS_READ` | packed name-set nvlist; LIST_CHILDREN needs a subtree handle; kernel iterates so no userland cursor |
| `ZFD_SET_PROP(name, val)` | `PROPS_WRITE` | honors per-prop allowlist |
| `ZFD_INHERIT(name)` | `PROPS_WRITE` | clear a property to inherited/received source |
| `ZFD_SNAPSHOT(name)` | `SNAPSHOT` | atomic across a subtree handle (one txg, as `zfs snapshot -r`) |
| `ZFD_SNAP_DESTROY(name)` | `SNAP_DESTROY` | |
| `ZFD_ROLLBACK(snap)` | `ROLLBACK` | |
| `ZFD_PROMOTE` | `PROMOTE` | promote a clone above its origin; root-only at mint because origin authority is dynamic |
| `ZFD_HOLD(snap, tag)` / `ZFD_RELEASE` | `HOLD` / `RELEASE` | pins snapshots against concurrent pruners mid-send |
| `ZFD_HOLDS` | `PROPS_READ` | enumerate a snapshot's user holds |
| `ZFD_BOOKMARK(snap, book)` / `ZFD_DESTROY_BOOKMARK` | `BOOKMARK` / `SNAP_DESTROY` | persistent incremental-send anchors |
| `ZFD_LIST_BOOKMARKS` | `PROPS_READ` | packed name-set of full `fs#name` bookmarks |
| `ZFD_SEND(snap, from_snap, out_fd, flags)` | `SEND` | stream to a plain fd (pipe/socket/vsock); fd checked via access-aware `zfs_file_get`. `flags` includes send-once (see below) |
| `ZFD_RECV(in_fd, reltarget, flags)` | `RECV` | target relative to handle, never absolute |
| `ZFD_CREATE(relname, props)` | `CREATE` | returns new zfd for the child |
| `ZFD_DESTROY(relname)` | `DESTROY` | |
| `ZFD_RENAME(relfrom, relto)` | `RENAME` | both ends inside the subtree |
| `ZFD_CLONE(origin_fd, relname)` | `CREATE` here, `CLONE_SRC` on origin | the deliberately two-handle verb: called on the destination parent, origin passed as an fd. "CI can clone the template into its workspace and nowhere else" falls out of the rights with no policy code |
| `ZFD_MOUNT(flags)` / `ZFD_UNMOUNT` | `MOUNT` | returns a **dirfd of an anonymous mount** — see §5.3 |
| `ZFD_BLKOPEN(flags)` | `MOUNT` | zvol handles: returns a block-device fd |

**Send-once (immutable handle flags).** A survey of the send path confirmed the
kernel never closes the caller's output fd — it drops only its own
`zfs_file_get` reference — so "close after send" was only ever a userland
convention. The send-once semantics therefore govern the SEND *right on
the handle*, enforced in kernel handle state so they survive SCM_RIGHTS:
`ZHF_SEND_ONCE` makes the complete derived/opened lineage refuse further
sends after one successful stream (`EALREADY`); `ZHF_SEND_CONSUME`
additionally invalidates the lineage
(`ENXIO`). This gives serviced/tzfsd an unforgeable "one backup stream,
then spent" grant. The output fd's lifetime remains the caller's business.

Events: kqueue on the handle. v1 fires `INVALIDATED` (EVFILT_READ-style
readiness); richer notes (`SNAP_CREATED`, `CHILD_CREATED`, `PROP_CHANGED`,
`SPACE_THRESHOLD`) are Phase 4 and gated on acceptable hook cost in shared
code (§8).

### 4.4 Pool handle verbs

`ZPD_STAT`, `ZPD_GET_PROPS`/`ZPD_SET_PROP` (allowlist), `ZPD_SCRUB`,
`ZPD_ROOT_OPEN(rights)`, and kqueue events per §3.3.

### 4.5 Coverage against zfs(8)/zpool(8)

The handle verb set was checked against a full inventory of every
`zfs`/`zpool` subcommand.  Deliberately **out of scope** (they reshape
the pool or re-create the ambient policy the handle replaces):
`zpool import/export/upgrade/add/remove/attach/detach/replace/split/
online/offline/create/destroy/labelclear/checkpoint/reguid`,
`zfs allow`/`unallow` (the handle *is* the delegation), and
`zfs jail`/`unjail`/`zone` (replaced by passing handles into jails).
Not yet implemented but in-scope for a later batch: encryption keys
(`load-key`/`unload-key`/`change-key`, wants a dedicated `ZH_KEY`
right), `zfs diff`, and the `userspace`/`groupspace` accounting family.

## 5. Implementation (code-grounded)

Survey result up front: **this is mostly recombination.** The ZFS layer
needs no changes to upstream-shared logic; two pieces are genuinely new
(guid-pinned resolution — solved cheaply per §3.1 — and fd-anchored mount
lifecycle, §5.3).

### 5.1 The fd type

Follow the established pattern (procdesc/eventfd/timerfd; in-fork:
`mac_capability`, `envfd`):

- `DTYPE_ZFSHANDLE` (19) in `sys/sys/file.h`; `KF_TYPE_ZFSHANDLE` (19) in
  `sys/sys/user.h`.
- Creation inside the mint ioctl: `falloc_noinstall` →
  `finit(fp, FREAD|FWRITE, DTYPE_ZFSHANDLE, zh, &zfshandle_ops)` →
  `finstall` → copy fd out (the `kern_specialfd` idiom,
  `sys/kern/sys_generic.c:1010`).
- fileops: real `fo_ioctl`, `fo_close`, `fo_stat`, `fo_fill_kinfo`,
  `fo_cmp`, `fo_poll`/`fo_kqfilter`; `invfo_*` stubs for the rest;
  `fo_flags = DFLAG_PASSABLE`. Close neutralizes the fp
  (`f_ops = &badfileops`) before teardown, procdesc-style
  (`sys_procdesc.c:595`), and must be context-independent since SCM_RIGHTS
  means last close can happen anywhere (`unp_internalize` checks only
  `DFLAG_PASSABLE` — no per-type work).
- Handle struct: guid triple, rights mask + prop allowlist, subtree flag,
  mutex, refcount, `selinfo`/knlist.
- Capsicum: fds are born with full rights and narrowed by userland.
  `libtrustedzfs` exposes typed `TZFS_OP_*` masks through
  `tzfs_limit_dataset_ioctls()` / `tzfs_limit_pool_ioctls()`, plus complete
  rights-to-verbs profiles for brokers. These call `cap_ioctls_limit()` and
  reject unknown or cross-kind bits before changing the descriptor. The
  `tzfsd` grant path installs the corresponding profile before SCM_RIGHTS
  transfer. Capsicum ioctl lists are per-fd: every handle returned by
  derive/openat/create/clone/root-open must be limited separately; the
  library manual makes that rule explicit.
- **Not** cdevpriv: `/dev/zfs` already binds per-open state via
  `devfs_set_cdevpriv` (`kmod_core.c:195-218`), but cdevpriv fds share
  state under `dup()`, cannot carry custom fileops/kqfilter, and are
  indistinguishable to Capsicum. A real DTYPE is strictly better here.

### 5.2 Dispatch as a shim

New files only, placed to keep OpenZFS merges cheap:

- `sys/contrib/openzfs/module/os/freebsd/zfs/zfs_handle.c` (+ header) —
  new-file-only in vendor territory; vendor imports do not collide with
  files upstream doesn't have. Build wired via `sys/modules/zfs/Makefile`
  (FreeBSD-side).
- Mint ioctls intercepted with a ~10-line hook in `zfsdev_ioctl()`
  (`kmod_core.c:118-187`) before `zfsdev_ioctl_common` — the one small
  recurring merge cost.
- Handle verbs resolve dsobj → verify guid → obtain current name → call
  the **existing name-based implementation paths** (the same ones the
  `zfs_ioc_vec` table dispatches to, `zfs_ioctl.c:7722+`). Upstream logic
  is reused, not reimplemented; the shim's own authorization is the rights
  mask, the name-recheck races are closed by the guid witness.
- Stream fds for send/recv go through the access-aware
  `zfs_file_get(fd, access, ...)` established by commit 47195449a23.
- Userland: `libtrustedzfs` (outside `contrib/`, my lean) or FreeBSD-side
  `lzc_handle_*` additions next to
  `lib/libzfs_core/os/freebsd/libzfs_core_ioctl.c`; the nvlist
  marshalling choke point to mirror is `lzc_ioctl`
  (`libzfs_core.c:219-290`).

### 5.3 Anonymous mounts (the one new VFS mechanism)

`vfs_domount_first` (`sys/kern/vfs_mount.c:1118-1318`) separates cleanly
into *instantiate* (`vfs_mount_alloc` → `VFS_MOUNT` → `VFS_STATFS` →
`VFS_ROOT`) and *attach to namespace* (`v_mountedhere` +
`VIRF_MOUNTPOINT`, lines 1281-1286; `mountcheckdirs`). Lookup only
crosses mounts via `v_mountedhere` (`vfs_lookup.c:975-1037`), so skipping
the attach makes the mount unreachable by path yet fully functional
through its root vnode. Supporting facts from the tree:

- `mnt_vnodecovered == NULL` is already a supported state (the root
  mount; fullpath code NULL-guards it, see `vfs_cache.c:3579` comment;
  `dounmount` guards all uses).
- `zfs_domount` (`zfs_vfsops.c:1228`) needs only `(vfsp, osname)` — it
  never touches the covered vnode. **Zero ZFS changes.**
- The dirfd is manufactured by reusing `kern_fhopen`'s tail
  (`vfs_syscalls.c:4965-4997`): `falloc_noinstall` → `vn_open_vnode` →
  `finit_open` → `finstall` on the `VFS_ROOT` vnode.
- The mount **stays on `mountlist`** (insert as at `vfs_mount.c:1301`):
  `dounmount` does an unconditional `TAILQ_REMOVE` (line 2440), and
  fsid lookup/sync/shutdown want list membership. Path-invisibility comes
  from the missing `v_mountedhere`, not from hiding off-list.
- Jails: `prison_canseemount` filters by `f_mntonname` prefix
  (`kern_jail.c:4238`); anonymous mounts carry `"[anon]"` and are
  naturally invisible to jailed statfs. Nothing dereferences
  `f_mntonname` as a live path.

New code: `vfs_domount_anon(fstype, opts, &fd)` in `vfs_mount.c`
(FreeBSD-native, no vendor exposure) plus the lifecycle rule — the mount's
lifetime anchors on the returned fd(s) instead of a covered vnode; last
close triggers `dounmount`. This fd-anchored teardown has no existing
analogue and is the part that gets the most design and test attention.

zvols are easier: the backing object (`struct cdev *` dev-mode, GEOM
provider geom-mode; `zvol_os.c:1330-1401`) is already path-independent;
`ZFD_BLKOPEN` installs an fd from the cdev's devfs vnode via the same
fhopen tail. Dev-mode first; geom-mode via the provider's cdev.

## 6. Consumers (who holds what)

First consumers, which double as the proof the primitive earns its keep:

1. **serviced storage stanza** — manifest declares dataset + rights;
   serviced holds a subtree zfd on `tank/svc` (`CREATE|DESTROY|
   PROPS_WRITE|SNAPSHOT`), materializes the child, derives the service's
   handle (typically `MOUNT|SNAPSHOT|PROPS_READ`) and passes it over the
   control socket. serviced itself never holds `SEND`/`RECV`.
2. **authority-init boot-environment rollback** — `SNAPSHOT|SNAP_DESTROY|
   ROLLBACK` on the BE dataset (stamp last-known-good on successful
   converge; roll back after N failed boots) plus a `bootfs`-only pool
   handle for BE switching.
3. **WASPNest** — per-VM zvol zfd (`SNAPSHOT|SNAP_DESTROY|ROLLBACK`) for
   checkpoints coordinated with vmm snapshots; golden-image handle
   (`CLONE_SRC|PROPS_READ`); `SEND`-only derived handle to a sandboxed
   migration worker (stream over vsock); `ZFD_BLKOPEN` fd to bhyve.
4. **Jail self-service** — subtree zfd (`SNAPSHOT|ROLLBACK|CREATE|
   SNAP_DESTROY|MOUNT`), deliberately without `SEND` and `PROPS_WRITE`;
   replaces `zfs jail` for this pattern.
5. **Replication** — inbound: `RECV|CREATE|HOLD` + `cap_enter()`, no
   `MOUNT` (received data never becomes a filesystem in the receiver's
   world); outbound: `SEND|HOLD|PROPS_READ|EVENT`, wakes on kqueue.
6. **zed replacement** — `EVENT|PROPS_READ` watchers; pruners add
   `SNAP_DESTROY`; pool-health alerter on a `ZPD_STAT` handle. All
   ordinary supervised services.

Endgame: boot mounts only what config declares shared; services see
storage exclusively through granted dirfds; the global namespace becomes a
compatibility view rather than the security boundary — the same
trajectory as the rest of the Authority work.

## 6a. Storage integration: the `[TZFS]` grant path

**Status (2026-08-14): manifest → mint → exec-grant built and committed.**
- Manifest `capabilities.storage` stanza parses to `ort_storage_claim`
  (dataset, ZH_* rights, lifetime); libcapbundle test passes.
- `AUTHORITY_OP_MINT_STORAGE`: serviced `authority_mint_storage()` →
  authorityd `handle_mint_storage()` opens `/dev/zfs` and
  `ZFS_IOC_DATASET_OPEN`, passing the rights-limited handle fd back.
- serviced grants the handle at exec, in the token-bootstrap range,
  for datasets that already exist (persistent case).
- Ephemeral lifecycle (create-on-start, destroy-on-stop) built and
  committed; clean-VM validated 2026-08-14.
- **Remaining is now its own effort:** the `tzfsd` daemon takes storage
  ownership from authorityd and adds the flavor/image system (native /
  freebsd / linux=Rocky / empty). ZFS is a required subsystem for 5BSD
  (UFS still bootable). See **`docs/tzfsd-design.md`** — that supersedes
  the "optional broker" sketch below.

Original sketch (kept for context; see tzfsd-design.md for the built design):



The flagship consumer is the service manager granting storage the same
way it grants every other capability.  Grounded in a survey of the
serviced manifest and mint machinery, the design is:

**Naming.** Every system daemon carries a distinguishable bracket tag so
`ps`/`procstat`/capability inspectors can tell them apart: `[AUTHORITY]`
(authorityd / authority-init), `[SERVICE]` (serviced), `[TZFS]` (the storage
grant broker, `tzfsd`).  One tag each.

**Manifest stanza (UCL, matches the existing `capabilities {}` style).**
A service declares storage the way it declares `files`/`network`.  The
addressing is a logical `name` under tzfsd's `/Capabilities` plus an
optional `flavor` template (not an absolute pool path — tzfsd owns the
layout):
```ucl
capabilities {
    storage = [{
        name     = "mydata";
        flavor   = "linux";        # "" = bare dataset; else clone that flavor
        rights   = ["mount", "snapshot", "props_read"];
        lifetime = "persistent";   # or "ephemeral"
    }];
}
```
Parsed by `lib/libcapbundle/libcapbundle_parse.c` (add `storage` to the
`capkeys[]` allow-list + a `storagekeys[]`/`parse_storage_rights()`
mirror of `parse_file_actions`), landing in a POD `serviced_storage_claim`
(`cap_storage[N]`/`ncap_storage`) in `serviced_manifest.h` — embedded
`[N][NAME_MAX]`-style so `svc_manifest` stays memcpy-safe like the other
claim arrays.

**Grant delivery (push at exec, like every other token).** serviced mints
one handle per storage claim over its authority channel
(`AUTHORITY_OP_MINT_STORAGE`, new in `authorityd_svc_proto.h`; `handle_mint_
storage()` in authorityd calling `ZFS_IOC_DATASET_OPEN`), remaps the handle
fd into the child's `SVC_TOKEN_BASE` range, and describes it in the
existing `struct service_bootstrap` (`token_fds[]` already generic — no
transport ABI break).  `persistent` datasets are materialized once and
kept; `ephemeral` ones are cloned/created at start and destroyed at stop
(the handle's `DESTROY`/`SNAP_DESTROY` rights make teardown self-service).

**Who owns it.** Two viable shapes, both compatible with the manifest
above: (a) serviced holds the subtree handle on `tank/svc` and derives
per-service handles directly — least new machinery; or (b) a dedicated
`tzfsd` broker in the capability bundle holds `tank/svc`, and serviced (or
the service) asks it — decouples storage authority from the service
manager and gives storage its own `[TZFS]` audit identity.  Recommended:
design the config schema so (a) can become (b) without a manifest change.

**Getting storage before the capability world is up.** The one net-new
protocol piece: a `SVC_OP_STORAGE_REQUEST` on the service↔serviced
channel (`serviced_svc_proto.h`, modeled on the existing
`SVC_OP_WORKER_CHANNEL` reply-with-fds path), so a service that needs
storage it did not statically declare can obtain a handle at runtime as
`reply_fds[0]`.  This is what lets a service acquire a dataset handle
before — or independent of — its full capability grant being installed.

**Files this touches** (from the survey, for when it is built):
`lib/libcapbundle/{libcapbundle_parse.c,libcapbundle.c,
libcapbundle_internal.h}`, `lib/libcapbundle/serviced_manifest.h`,
`lib/libauthorityrt/{authorityrt.h,authorityd_svc_proto.h,serviced_svc_proto.h}`,
`usr.sbin/serviced/{authority_client.c,execute.c,svc_proto.c}`,
`usr.sbin/authorityd/{authority_proto.c,mac_capability_mint.c}`, and
optionally a new `usr.sbin/tzfsd/` + its `.cap` bundle.  Send-once
(`ZHF_SEND_ONCE`) is the natural grant shape for a backup service's
stanza.

## 7. Observability

House pattern per `mac_capability`: SDT providers + canned D scripts in
`share/dtrace/` + procstat/libprocstat integration.

### 7.1 SDT probes (`trustedzfs` provider; `trustedzfs_pool` mirror)

| Probe | Args | Fired |
|-------|------|-------|
| `mint` | name, guid, rights, cred | handle created from `/dev/zfs` |
| `derive` / `handle-openat` | parent guid, child guid/name, parent rights, child rights | lineage edges — every handle's ancestry is reconstructible back to an ambient mint |
| `op-entry` / `op-return` | guid, name, cmd, rights held, errno | every verb; pair gives latency |
| `denied` | guid, cmd, rights required, rights held | mask-check failure (distinct from `capsicum:::ioctl-deny`, which fires when `cap_ioctls_limit` blocks the command first) |
| `invalidate` | guid, reason (guid-miss / destroy / export / unmount) | the single most diagnostic probe: distinguishes "raced a destroy" from "pool went away" |
| `mount-anon` / `unmount-anon` / `blkopen` | guid, fd | data-plane bridges |
| `send-start` / `send-done` | snap guid, bytes | stream ops |

### 7.2 Canned scripts (`share/dtrace/`)

- `trustedzfs-handles` — live mint/derive/close feed with lineage.
- `trustedzfs-ops` — counts + latency quantized per dataset and cmd.
- `trustedzfs-denials` — aggregates `trustedzfs:::denied` +
  `capsicum:::ioctl-deny` + `mac_capability:::error`: one script answers
  "why did this service's storage op fail" across all three layers
  (same join style as `mac_capability-denials`).
- `trustedzfs-lineage` — delegation graph with rights narrowing per hop.
- `trustedzfs-invalidations` — invalidations with reason + surviving
  holder pids.
- Extend `serviced-capabilities` once storage stanzas land, so storage
  grants appear alongside the other capability grants.

### 7.3 Static visibility

`fo_fill_kinfo` reports `KF_TYPE_ZFSHANDLE` with the dataset name in
`kf_path` and rights/guid/validity in a new `kf_un` member; libprocstat
gets the type mapping (next to `KF_TYPE_MAC_CAPABILITY`,
`libprocstat.c:729`) and a describe function so `procstat -f`/`fstat`
show e.g. `zfshandle:tank/svc/pgsql [snapshot,mount] valid`. Fleet-wide
"who holds handles to what" with no DTrace required; also what the test
suite asserts against.

## 8. Testing

Primary suite: **ATF C tests** in `tests/sys/zfshandle/` (modeled on
`tests/sys/mac_capability/`), per-test file-vdev pools, kyua-runnable
(`ATF_TESTS_C` + `run_tests.sh`). Kernel-risk pieces run in the bhyve VM
rig, not the host.

1. `zfshandle_rights_test` — **the core matrix**: every verb x every
   rights mask, table-driven and exhaustive by construction; with the
   right → success, without → `EPERM`; forged fd types → `EBADF`.
2. `zfshandle_derive_test` — monotonicity (widening → `ENOTCAPABLE`),
   `OPENAT` containment (`..`, absolute names, rename-out escapes),
   `INFO` correctness, prop-allowlist narrowing.
3. `zfshandle_pin_test` — rename-follows-dataset; destroy+recreate →
   `ENXIO`; export → `ENXIO`; plus the race variant: rename/destroy loop
   in one thread vs ops in another, asserting no op ever lands on the
   wrong dataset.
4. `zfshandle_capsicum_test` — full verb set post-`cap_enter()`;
   `cap_ioctls_limit` narrowing; stream-fd rights (extends
   `zfs_send_capsicum.c`); the central asymmetry: minting fails in
   capability mode while handle ops succeed.
5. `zfshandle_fd_test` — dup/fork/SCM_RIGHTS to an unrelated process
   (crib `mac_capability_procdesc_test.c`,
   `tests/sys/capsicum/capability-fd-pair.cc`), close-on-last-ref,
   procstat/fstat output via libprocstat.
6. `zfshandle_jail_test` — handle passed into a jail works without
   `zfs jail`; jailed minting respects `zone_dataset_visible`;
   unprivileged mint via `zfs allow` grants exactly the delegated rights.
7. `zfshandle_mount_test` (Phase 3, most negative cases) — dirfd
   openat/getdirentries; path-unreachability; absence from jailed
   getfsstat; teardown on last close; in-use semantics; forced export
   under a live dirfd fails clean.
8. `zfshandle_zvol_test` — `BLKOPEN` read/write, dev and geom volmodes.
9. `bin/` stress tool — handle churn across processes + concurrent
   dataset lifecycle; catches refcount/teardown races.
10. `zfshandle_dtrace_test` — `dtrace -l` provider presence; scripted
    runs assert `mint`/`op-entry`/`denied`/`invalidate` fire with sane
    args, so the visibility tooling cannot silently rot.
11. STF end-to-end flows in `tests/sys/cddl/zfs/tests/handles/` —
    mint → send | recv pipeline between sandboxed processes; interop
    with the existing `delegate/` suite.

## 9. Phases

| Phase | Deliverables | ~Size |
|-------|--------------|-------|
| 1 | DTYPE + fileops; mint hook in `zfsdev_ioctl`; `INFO`/`DERIVE`/`OPENAT`; verbs: props/stat/snapshot/snap-destroy/rollback; tests 1-3, 9, 10; probes mint/op/denied/invalidate; scripts -handles/-denials; kinfo+libprocstat | 1,500 LoC kernel + 1,200 tests |
| 2 | send/recv/hold (access-aware `zfs_file_get`); create/destroy/rename; two-handle clone; prop allowlists; jail interop; userland lib; tests 4-6; -lineage/-ops scripts | 1,000 + 800 |
| 3 | `vfs_domount_anon` + `ZFD_MOUNT` dirfd + fd-anchored teardown; `ZFD_BLKOPEN`; tests 7-8; mount probes | 800 + 500 |
| 4 | Rich kqueue notes (needs hooks in shared DSL paths — the one place the merge-burden goal gets pressure; optional, last); thin pool handle (`ZPD_*`); `bootfs` sliver may be pulled forward for authority-init | 600 |

Phase 1 alone dogfoods the serviced storage stanza; authority-init BE
rollback needs Phase 1 + the `bootfs` sliver.

## 9a. Implementation status (2026-08-14)

All four phases plus the extended verb set are implemented.  The current
hardening suite covers rights and delegation matrices, derive/openat and
operation-ceiling propagation, guid pinning and namespace churn, lifecycle
and streams, send-once lineage races, anonymous-mount concurrency, pool
handles, Capsicum and SCM_RIGHTS, strict raw ABI negatives, MAC hook reach,
daemon protocol framing/concurrency, and bounded enumeration.

- `08539165` — phases 1-4 (handles, library, tests, DTrace, procstat).
- `f81f9f05` — extended verbs: enumeration (children/snaps/holds/
  bookmarks), single-property get, inherit, promote, bookmarks, and
  send-once (subsequently moved to immutable `ZHF_SEND_ONCE`/
  `ZHF_SEND_CONSUME` lineage flags).
- `05f99b2a` — the authorityd boot-health / shutdown-wedge fix this work
  surfaced (deferred signal shield, control-socket rebind, stale
  serviced.ready unlink, 30s self-heal, loud shutdown(8) failure).

All 7 SDT probes live.  Two latent VFS
contract details were found
by the Phase 3 tests and are load-bearing knowledge for anyone touching
mounts: `vfs_mount_alloc()` returns the mount BOTH busied (mnt_lockref)
and in vfs_ops mode (mnt_vfs_ops == 1); a mounter must release both
(`vfs_op_exit` + `vfs_unbusy`, as vfs_domount_first does at lines
~1315-16) — missing the first panics vfs_mount_destroy's MPASSERT at
unmount, missing the second deadlocks dounmount in an uninterruptible
busy-drain sleep.  Highlights beyond the plan above:

- **Phase 3 anonymous mounts** live entirely in the zfs module — every
  needed VFS primitive (`vfs_mount_alloc`, `vfs_buildopts`,
  `vfs_allocate_syncvnode`, `dounmount`, mountlist) is already exported,
  so no kernel rebuild is required.  `ZFD_MOUNT` instantiates the mount
  (no covered vnode, on mountlist, invisible to namei), opens the root
  vnode as a dirfd via the fhopen tail, and anchors the mount on the
  handle; `ZFD_UNMOUNT`/handle-close forcibly unmount (`dounmount`
  consumes the kern_unmount-style reference the handle holds).
- **Phase 4 pool handles** share the DTYPE with an internal ZHF_POOL
  flag: `ZPD_STAT` (spa/metaslab/scan direct reads), `ZPD_GET_PROPS`/
  `ZPD_SET_PROP` and `ZPD_SCRUB` via the FKIOCTL bridge, and
  `ZPD_ROOT_OPEN` minting a rights-limited dataset handle.  Pool minting
  beyond the implicit rights requires root (no zfs-allow analogue).
- The **shutdown-wedge and boot-health fixes** in authorityd that this work
  surfaced are documented in the git log: deferred CP_SF_SIGNAL shield,
  control-socket rebind after rc's /var/run cleanup, stale
  serviced.ready unlink, and a 30s self-heal retry in the PID 1 event
  loop.

Phase 2 details:

- Verbs `ZFD_CREATE`/`DESTROY`/`RENAME`/`CLONE` (two-handle)/`SEND`/
  `RECV`/`HOLD`/`RELEASE` are implemented by driving the upstream
  vectored ioctl dispatch in-kernel via `FKIOCTL` (kernel nvlists, no
  logic duplication), with the thread cred temporarily elevated —
  handle rights replace ambient secpolicy post-mint.  Jail dataset
  visibility remains ambient (checks curproc) until Phase 3.
- `ZFD_BLKOPEN` opens a zvol handle as a block-device fd (kernel-side
  devfs resolve + fhopen-style install; `fp->f_flag` must be set
  explicitly — omitting it both breaks I/O and leaks the zvol open
  count, wedging later pool destroys).  ECAPMODE inside capability
  mode for now; Phase 3 replaces the path walk.
- `lib/libtrustedzfs` exposes the complete surface (`tzfs_*`, 21
  functions, dependency-free; props returned as packed nvlists), with
  `trustedzfs.3` and full build-system wiring.
- Bare send streams do not carry user properties (`zfs send -p` is
  userland behavior) — stream tests verify snapshot guid equality.

Phase 1 status:

- Kernel: `sys/contrib/openzfs/module/os/freebsd/zfs/zfs_handle.c` (new
  file), `sys/sys/zfshandle.h` (UAPI), 3-line mint intercept in
  `kmod_core.c`, `DTYPE_ZFSHANDLE`/`KF_TYPE_ZFSHANDLE` (= 19), entries in
  `sys/modules/zfs/Makefile` and `sys/conf/files`.  `zfs.ko` links.
- Userland: libprocstat mapping + `procstat -f` ("Z") and `fstat`
  (`[zfshandle]`) rendering; dataset name appears via `kf_path`.
- Tests: `tests/sys/zfshandle/` — rights matrix, derive/openat, guid-pin
  suites (12 test cases), all compiling; hooked into `tests/sys/Makefile`
  and `BSD.tests.dist`.
- DTrace: `trustedzfs` SDT provider (mint/derive/handle-openat/op-entry/
  op-return/denied/invalidate) + `share/dtrace/trustedzfs-handles` and
  `trustedzfs-denials`.

Remaining deliberate constraints:
- Verbs that end in name-based DSL entry points are protected from
  resolve-to-call replacement by the FreeBSD namespace gate.
- Non-root minting of `ZH_PROPS_WRITE` is refused pending per-prop
  allowlists.
- Subtree `ZFD_SNAPSHOT` snapshots only the handle's own dataset
  (recursive one-txg variant pending).
- kqueue is EVFILT_READ readiness for INVALIDATED only, and invalidation
  detection is lazy (first failing op flips it).

## 10. Risks

- **Vendor merge cost**: confined by construction to the `kmod_core.c`
  intercept (~10 lines) and new-file-only additions; Phase 4 event hooks
  are the only threat to that and are optional.
- **Mount lifecycle**: fd-anchored teardown is novel; mitigated by
  keeping anonymous mounts on `mountlist`, reusing `dounmount`, and the
  Phase 3 negative-test load.
- **Second access path**: TrustedZFS adds a parallel authority route
  auditors must reason about. Mitigations: minting reuses the existing
  authorization layers (no new policy store), every handle is visible in
  procstat, and every mint/derive/op is a DTrace event.
- **Dead weight**: the primitive is only worth its surface if consumers
  land; Phase 1 ships with the serviced stanza as its acceptance test.
