# tzfsd — the `[TZFS]` storage daemon

Status: **built** (designed 2026-08-14; daemon, `tzfsctl`, `libtzfsd`,
and tests are in the tree — see commits `2cbcfd463c6`
through `80d8c2f99cc`; the boot-time ready gate remains design-only).
Supersedes the "optional broker" sketch in `trustedzfs-design.md §6a`; that
section now points here.

`tzfsd` is the system component that owns the **storage plane**. It takes the
storage-granting responsibility that authorityd carried inline
(`handle_mint_storage`) and turns it into a first-class daemon with its own
configuration, its own `[TZFS]` audit identity, and a zero-configuration
out-of-the-box experience: a service (or an interactive request) asks for a
storage claim by logical name and receives a rights-limited TrustedZFS handle
it can `mount` into a directory.

ZFS is now a **required** subsystem for 5BSD (you may still *boot* from UFS,
but the capability storage plane assumes a ZFS pool is present). tzfsd is not
optional; it comes up in the PID-1 boot chain before serviced hands out
storage.

---

## 1. What tzfsd owns

Two responsibilities, neither of which belongs in the service manager:

1. **The pool.** tzfsd holds the root-pool handle (`zpd`) for the pool that
   backs `/Capabilities`. All dataset creation/destruction flows
   through capability handles derived from it — tzfsd never shells out to
   `zfs(8)`/`zpool(8)`.
2. **The `/Capabilities` layout.** It auto-provisions (idempotently, on first
   boot) the persistent and ephemeral roots, so an
   installed system Just Works with zero operator configuration.

Everything a consumer does *after* receiving a handle is the existing
`libtrustedzfs` verb surface (snapshot, mount, props, send/recv, …). tzfsd
only mints and manages; it does not proxy I/O.

---

## 2. The `/Capabilities` layout

```
zroot/Capabilities                         (mountpoint = /Capabilities)
├─ persistent/<bundle-id>/<claim>          persistent per-app datasets
└─ ephemeral/<bundle-id>/<claim>           created on start, destroyed on stop

/Capabilities/
   persistent/…      mounted read-write, survive reboot
   ephemeral/…       mounted read-write, torn down at service stop
   .ephemeral mounts default to sync=disabled for throughput
```

- **Persistent** claims live under `persistent/<bundle-id>/…` and survive
  reboots; their datasets are materialized once and kept.
- **Ephemeral** claims live under `ephemeral/<bundle-id>/…`, are created at
  service start, and destroyed at stop. The
  handle's `DESTROY`/`SNAP_DESTROY` rights make teardown self-service.

Roots (pool, persistent parent, ephemeral parent) are all
configurable; the defaults above are the opinion.

---

## 3. Configuration — `/Capabilities/Config/tzfsd.ucl`

```ucl
pool = "zroot";                        # pool backing /Capabilities

roots {
    base        = "zroot/Capabilities";
    persistent  = "zroot/Capabilities/persistent";
    ephemeral   = "zroot/Capabilities/ephemeral";
    mountpoint  = "/Capabilities";
}

ephemeral {
    sync = "disabled";                 # throughput for scratch
}
```

Config is optional: with no file, tzfsd uses the defaults above against the
first imported pool. The schema is deliberately shaped so serviced-holds-it
(the old `handle_mint_storage`) and tzfsd-holds-it are the *same* grant
semantics — moving ownership needed no manifest change (as promised in §6a).

---

## 4. Protocol + `libtzfs` client

Two libraries, cleanly separated:

- **`libtrustedzfs`** (exists) — raw kernel handle verbs (ioctl/syscall
  wrappers), function prefix `tzfs_`. What you use *after* you hold a handle.
- **`libtzfsd`** (new) — the client to tzfsd, function prefix `tzfsd_`. What
  you use to *obtain* a handle. Distinct prefix because consumers link both
  libraries (`libtrustedzfs` already owns `tzfs_`); named parallel to how
  `libauthorityrt` hosts the `authority_*` client for authorityd.

### 4.1 `libtzfsd` API

```c
/* Connect the tzfsd socket (non-sandboxed callers); sandboxed callers pass
 * a channel fd delivered at bootstrap instead. Returns fd or -1. */
int tzfsd_connect(void);

/* Request a rights-limited handle for storage of a given lifetime.
 * Returns a TrustedZFS dataset fd (drive it with libtrustedzfs), or -1. */
int tzfsd_request(int chan, const struct tzfsd_req *req,
    struct tzfsd_grant *out);

struct tzfsd_req {
    char      name[64];        /* logical claim name within the bundle   */
    uint64_t  rights;          /* ZH_* mask requested                    */
    uint8_t   lifetime;        /* TZFSD_PERSISTENT | TZFSD_EPHEMERAL      */
};
struct tzfsd_grant {
    int       handle_fd;       /* the zfd (SCM_RIGHTS from tzfsd)         */
    char      dataset[256];    /* resolved dataset name (for audit)       */
};

int tzfsd_release(int chan, const char *name);   /* ephemeral teardown   */
int tzfsd_mount_dir(int handle_fd);              /* handle -> dirfd       */
```

A request is a claim on an existing (or created) plain dataset under the
bundle's layout.

### 4.2 Wire protocol (`tzfsd_proto.h`)

Modeled on the authorityd reply-with-fds RPC. Ops:

- `TZFS_OP_REQUEST` — `struct tzfs_req` → reply carries `handle_fd` via
  SCM_RIGHTS + resolved dataset name.
- `TZFS_OP_RELEASE` — logical name → destroy ephemeral dataset (idempotent).
- `TZFS_OP_PING` — liveness.

Socket: `/var/run/tzfsd.sock` (root-owned; peers are authorityd/serviced, and —
via a passed channel — sandboxed services). tzfsd `cap_enter()`s after opening
its pool handle and socket, so it runs the whole request loop in capability
mode, minting handles from its retained `zpd`.

---

## 5. Responsibility transfer from authorityd

Today: serviced `authority_mint_storage()` → authorityd `handle_mint_storage()`
opens `/dev/zfs` and mints. After the move:

- The `storage_open_handle` / `storage_create_ephemeral` / `storage_split`
  logic **moved into tzfsd**. **Built.**
- authorityd keeps `AUTHORITY_OP_MINT_STORAGE` as a thin **forwarder** to tzfsd via
  `libtzfsd` (`handle_mint_storage`/`handle_destroy_storage` in
  `authority_proto.c` now call `tzfsd_request`/`tzfsd_release`; authorityd no longer
  opens `/dev/zfs`). **Built.** This was chosen over serviced-talks-to-tzfsd-
  directly because `serviced` mints *every* capability class (path/file/net/
  jail/vsock/storage/system) uniformly over its one authority channel; making
  storage the sole exception would fracture that pattern for no real gain.
  authorityd forwarding relocates the full ZFS authority to tzfsd while keeping
  the mint path uniform. serviced-direct remains a possible later
  optimization (design unaffected — it is the same grant semantics).
- **Startup:** authorityd starts tzfsd on demand the first time a service needs
  storage (`posix_spawn` + `waitpid`; tzfsd provisions synchronously then
  daemonizes, so the wait returns once it is ready). A boot-time
  `tzfsd.ready` gate for services that need storage before first-mint is a
  Phase 4 refinement.

The manifest `capabilities.storage` stanza is unchanged; only *who mints* moves.

---

## 6. The out-of-the-box experience

What makes it zero-setup is the sum of two defaults, not either one:

1. **Auto-provisioned layout** — tzfsd lays down `/Capabilities` roots itself;
   the operator configures nothing to get started.
2. **One call** — `tzfs_request({.lifetime=TZFS_EPHEMERAL})`
   → `tzfs_mount_dir()` → **you have a directory** backed by a fresh dataset.
   The same one call, with `.lifetime=TZFS_PERSISTENT`, gets storage that
   survives reboot.

Boot 5BSD and capability storage is simply *there*.

---

## 7. Build / install / test plan

- **`usr.sbin/tzfsd/`** — daemon (config, pool handle, layout,
  request loop), `[TZFS]` tagged.
- **`lib/libtzfs/`** — client library + `tzfs.h` + `libtzfs.3`.
- **`lib/libauthorityrt/tzfsd_proto.h`** — wire protocol (lives with the other
  capability protocols).
- **`usr.sbin/tzfsctl/`** — inspector (`list`, `request`).
- **Man pages:** `tzfsd.8`, `tzfs.conf.5`, `libtzfs.3`, `tzfsctl.8`.
- **Tests:** ATF `tests/sys/tzfs/` — request/mount/release per claim,
  rights attenuation on granted handles, ephemeral teardown, negative paths;
  plus clean-VM validation of `request → mount → directory`.

---

## 8. Phases

1. **Protocol + `libtzfs`** — `tzfsd_proto.h`, client lib, plain-dataset path.
2. **Daemon core** — config, pool `zpd`, layout auto-provision, request loop,
   dataset create+mint, ephemeral teardown.
3. **Responsibility transfer** — serviced → tzfsd channel; authorityd out of the
   data path; boot-order + readiness handshake.
4. **Tooling, man pages, tests, clean-VM validation.**
