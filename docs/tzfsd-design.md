# tzfsd — the `[TZFS]` storage daemon

Status: **built** (designed 2026-08-14; daemon, `tzfsctl`, `libtzfsd`, the
tzfs-flavors package, and tests are in the tree — see commits `2cbcfd463c6`
through `80d8c2f99cc`; the boot-time ready gate remains design-only).
Supersedes the "optional broker" sketch in `trustedzfs-design.md §6a`; that
section now points here.

`tzfsd` is the system component that owns the **storage plane**. It takes the
storage-granting responsibility that authorityd carried inline
(`handle_mint_storage`) and turns it into a first-class daemon with its own
configuration, its own `[TZFS]` audit identity, and an opinionated
out-of-the-box experience: a service (or an interactive request) asks for a
root of a given **flavor** — `native`, `freebsd`, `linux` (Rocky), or
`empty` — and receives a rights-limited TrustedZFS handle it can `mount` into
a directory. Native and Linux storage are equal first-class citizens.

ZFS is now a **required** subsystem for 5BSD (you may still *boot* from UFS,
but the capability storage plane assumes a ZFS pool is present). tzfsd is not
optional; it comes up in the PID-1 boot chain before serviced hands out
storage.

---

## 1. What tzfsd owns

Three responsibilities, none of which belong in the service manager:

1. **The pool.** tzfsd holds the root-pool handle (`zpd`) for the pool that
   backs `/Capabilities`. All dataset creation/cloning/destruction flows
   through capability handles derived from it — tzfsd never shells out to
   `zfs(8)`/`zpool(8)`.
2. **The `/Capabilities` layout.** It auto-provisions (idempotently, on first
   boot) the persistent and ephemeral roots and the template registry, so an
   installed system Just Works with zero operator configuration.
3. **The flavors.** It maintains a small, curated set of template datasets and
   hands out cheap ZFS **clones** of them on request.

Everything a consumer does *after* receiving a handle is the existing
`libtrustedzfs` verb surface (snapshot, mount, props, send/recv, …). tzfsd
only mints and manages; it does not proxy I/O.

---

## 2. The `/Capabilities` layout

```
zroot/Capabilities                         (mountpoint = /Capabilities)
├─ persistent/<bundle-id>/<claim>          persistent per-app datasets
├─ ephemeral/<bundle-id>/<claim>           created on start, destroyed on stop
└─ .templates/                             flavor origins (not app-visible)
   ├─ empty@ready
   ├─ native@ready                         5BSD base (built live at install)
   ├─ freebsd@ready                        FreeBSD base rootfs
   └─ linux@ready                          Rocky 9 rootfs

/Capabilities/
   persistent/…      mounted read-write, survive reboot
   ephemeral/…       mounted read-write, torn down at service stop
   .ephemeral mounts default to sync=disabled for throughput
```

- **Persistent** claims live under `persistent/<bundle-id>/…` and survive
  reboots; their datasets are materialized once and kept.
- **Ephemeral** claims live under `ephemeral/<bundle-id>/…`, are cloned from a
  flavor (or created empty) at service start, and destroyed at stop. The
  handle's `DESTROY`/`SNAP_DESTROY` rights make teardown self-service.
- **`.templates/`** holds one origin dataset per flavor with a `@ready`
  snapshot. A request is `zfs clone <flavor>@ready` — instant, copy-on-write,
  near-zero space until the consumer writes.

Roots (pool, persistent parent, ephemeral parent, templates parent) are all
configurable; the defaults above are the opinion.

---

## 3. Flavors — the template/clone model

The insight that makes "ship ready-to-go images" cheap: **store one populated
template per flavor, clone per request.** Runtime is always instant regardless
of image size; the only question is how each template is *populated*.

| Flavor    | Contents                     | Populated by                         |
|-----------|------------------------------|--------------------------------------|
| `empty`   | bare skeleton dir tree       | built live (mkdir), ~free            |
| `native`  | 5BSD base userland           | built live from the running base     |
| `freebsd` | FreeBSD base rootfs          | baked send-stream (or live base.txz) |
| `linux`   | **Rocky Linux 9** rootfs     | baked send-stream                    |

**Why Rocky for `linux`:** 5BSD's Linuxulator is developed and tested against
the RHEL/Rocky userland (glibc, RHEL ABI), so a Rocky rootfs runs with the
least friction; and Rocky mirrors the RHEL library/ABI surface that regulated
software targets. `linux` is a **directory** (a dataset with a Linux rootfs),
handed out and mounted with the same handle API as `native` — not a foreign
block device.

### 3.1 Image artifacts and how they ship

Templates are shipped as **ZFS send streams** (zstd-compressed), not tarballs:
materializing a template is `zfs recv` (fast, preserves properties) rather than
untar. Sizes are small because we ship **base rootfs**, not installer ISOs:

| Template            | base rootfs on disk | as zstd send-stream |
|---------------------|---------------------|---------------------|
| Rocky 9 base        | ~180 MB             | ~70 MB              |
| FreeBSD base        | ~1 GB               | ~215 MB             |
| 5BSD base           | (built live)        | 0 on media          |
| empty               | trivial             | 0 on media          |

Curated set on the install media ≈ **~300 MB** → a ~1.2 GB install image
grows to ~1.5 GB (still under FreeBSD's own `dvd1.iso`). That buys a fully
**offline, zero-setup, first-class** Linux and FreeBSD out of the box.

**Materialization order of precedence** (first available wins), so a system is
never stuck:
1. **Baked** — send-stream present on install media / in `.templates.src/`;
   `zfs recv` at install or first boot.
2. **Live-built** — `native`/`empty` constructed from the running system.
3. **Sourced** — a configured URL/mirror path (`base.txz`, Rocky rootfs),
   fetched + unpacked on first request. Off by default (opt-in; not air-gapped).

A flavor with no available source is simply not offered; `tzfsd_request` on it
returns `ENOENT`.

### 3.2 Removability — on by default, slimmable

The `linux` (Rocky) flavor is **enabled by default** — the out-of-the-box
opinion is "Linux is first-class and present." But a deployment that doesn't
want a Red Hat userland on disk must be able to **shed it cleanly** and reclaim
the space. Three independent, supported levers, coarsest to finest:

1. **Build/package** — a `MK_TZFS_LINUX` (default `yes`) omits the Rocky
   send-stream from a slim release; equivalently the image is a removable
   package so `pkg delete tzfs-image-linux` drops it. The base + native +
   freebsd flavors are unaffected.
2. **Config** — `flavors { linux { enabled = false; } }` makes tzfsd not offer
   the flavor even if the artifact is present.
3. **Runtime reclaim** — `tzfsctl flavor destroy linux` (tzfsd removes the
   `.templates/linux` origin via its `ZH_DESTROY` handle). Existing clones are
   independent once promoted or already diverged.

"Off" is a designed state, not a failure mode: with `linux` gone,
`tzfsd_request({.flavor="linux"})` returns `ENOENT`, `tzfsctl list-flavors`
omits it, and nothing else changes. Turning it back on is re-adding the
artifact (or re-enabling in config) and letting tzfsd `zfs recv` it.

---

## 4. Configuration — `/etc/capability/tzfsd.ucl`

```ucl
pool = "zroot";                        # pool backing /Capabilities

roots {
    base        = "zroot/Capabilities";
    persistent  = "zroot/Capabilities/persistent";
    ephemeral   = "zroot/Capabilities/ephemeral";
    templates   = "zroot/Capabilities/.templates";
    mountpoint  = "/Capabilities";
}

ephemeral {
    sync = "disabled";                 # throughput for scratch
}

flavors {
    empty   { build = "live"; }
    native  { build = "live"; }
    freebsd { build = "baked"; source = "/usr/share/tzfs/freebsd.zfs.zst"; }
    linux   { build = "baked"; source = "/usr/share/tzfs/rocky9.zfs.zst";
              enabled = true;          # on by default; false to slim
              default = true; }        # the opinionated Linux default
}
```

Config is optional: with no file, tzfsd uses the defaults above against the
first imported pool. The schema is deliberately shaped so serviced-holds-it
(the old `handle_mint_storage`) and tzfsd-holds-it are the *same* grant
semantics — moving ownership needed no manifest change (as promised in §6a).

---

## 5. Protocol + `libtzfs` client

Two libraries, cleanly separated:

- **`libtrustedzfs`** (exists) — raw kernel handle verbs (ioctl/syscall
  wrappers), function prefix `tzfs_`. What you use *after* you hold a handle.
- **`libtzfsd`** (new) — the client to tzfsd, function prefix `tzfsd_`. What
  you use to *obtain* a handle. Distinct prefix because consumers link both
  libraries (`libtrustedzfs` already owns `tzfs_`); named parallel to how
  `libauthorityrt` hosts the `authority_*` client for authorityd.

### 5.1 `libtzfsd` API

```c
/* Connect the tzfsd socket (non-sandboxed callers); sandboxed callers pass
 * a channel fd delivered at bootstrap instead. Returns fd or -1. */
int tzfsd_connect(void);

/* Request a rights-limited handle for storage of a given flavor+lifetime.
 * Returns a TrustedZFS dataset fd (drive it with libtrustedzfs), or -1. */
int tzfsd_request(int chan, const struct tzfsd_req *req,
    struct tzfsd_grant *out);

struct tzfsd_req {
    char      flavor[32];      /* "native"|"freebsd"|"linux"|"empty"|"" */
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

`flavor=""` means "just a dataset" (the current behavior — a claim on an
existing/created dataset with no template). A non-empty flavor clones the
template.

### 5.2 Wire protocol (`tzfsd_proto.h`)

Modeled on the authorityd reply-with-fds RPC. Ops:

- `TZFS_OP_REQUEST` — `struct tzfs_req` → reply carries `handle_fd` via
  SCM_RIGHTS + resolved dataset name.
- `TZFS_OP_RELEASE` — logical name → destroy ephemeral clone (idempotent).
- `TZFS_OP_LIST_FLAVORS` — enumerate available flavors (for tooling/`tzfsctl`).
- `TZFS_OP_PING` — liveness.

Socket: `/var/run/tzfsd.sock` (root-owned; peers are authorityd/serviced, and —
via a passed channel — sandboxed services). tzfsd `cap_enter()`s after opening
its pool handle and socket, so it runs the whole request loop in capability
mode, minting handles from its retained `zpd`.

---

## 6. Responsibility transfer from authorityd

Today: serviced `authority_mint_storage()` → authorityd `handle_mint_storage()`
opens `/dev/zfs` and mints. After the move:

- The `storage_open_handle` / `storage_create_ephemeral` / `storage_split`
  logic **moved into tzfsd** (extended with clone-from-flavor). **Built.**
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
A `flavor` field is added to the stanza (optional; default `""` = today's
behavior) so a service can declare "give me a Rocky root, ephemeral":

```ucl
capabilities {
    storage = [{
        name     = "rootfs";
        flavor   = "linux";            # NEW: clone Rocky template
        rights   = ["mount", "snapshot"];
        lifetime = "ephemeral";
    }];
}
```

---

## 7. The out-of-the-box experience

What makes it *opinionated* is the sum of three defaults, not any one:

1. **Curated baked images** — `empty`, `native`, `freebsd`, `linux`(Rocky) are
   present from first boot, offline, no `pkg install`, no network.
2. **Auto-provisioned layout** — tzfsd lays down `/Capabilities` roots itself;
   the operator configures nothing to get started.
3. **One call** — `tzfs_request({.flavor="linux", .lifetime=TZFS_EPHEMERAL})`
   → clone → `tzfs_mount_dir()` → **you have a directory of Rocky Linux.**
   Same one call, flavor `native`/`freebsd`/`empty`, for the others.

Boot 5BSD and Linux storage is simply *there*, first-class beside native.

---

## 8. Build / install / test plan

- **`usr.sbin/tzfsd/`** — daemon (config, pool handle, layout, templates,
  request loop), `[TZFS]` tagged.
- **`lib/libtzfs/`** — client library + `tzfs.h` + `libtzfs.3`.
- **`lib/libauthorityrt/tzfsd_proto.h`** — wire protocol (lives with the other
  capability protocols).
- **`usr.sbin/tzfsctl/`** — inspector (`list-flavors`, `list`, `request`).
- **Man pages:** `tzfsd.8`, `tzfs.conf.5`, `libtzfs.3`, `tzfsctl.8`.
- **Image tooling:** a `tools/tzfs/mkflavor.sh`-style producer that turns a
  populated dataset into a `<flavor>.zfs.zst` send-stream; install glue that
  `zfs recv`s bundled streams into `.templates` (BSDInstall + first-boot).
- **Tests:** ATF `tests/sys/tzfs/` — request/clone/mount/release per flavor,
  rights attenuation on granted handles, ephemeral teardown, negative paths;
  plus clean-VM validation of `request → clone → mount → directory` for each
  flavor.

---

## 9. Phases

1. **Protocol + `libtzfs`** — `tzfsd_proto.h`, client lib, `flavor=""` path.
2. **Daemon core** — config, pool `zpd`, layout auto-provision, request loop,
   `empty`/`native` live-built flavors, clone+mint, ephemeral teardown.
3. **Responsibility transfer** — serviced → tzfsd channel; authorityd out of the
   data path; boot-order + readiness handshake; `flavor` in the manifest.
4. **Foreign flavors** — `freebsd`/`linux`(Rocky) send-stream artifacts,
   producer tooling, install-time recv, live-build/source fallbacks.
5. **Tooling, man pages, tests, clean-VM validation.**
