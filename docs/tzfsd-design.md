# tzfsd — the `[TZFS]` storage daemon

Status: **design** (2026-08-14). Supersedes the "optional broker" sketch in
`trustedzfs-design.md §6a`; that section now points here.

`tzfsd` is the system component that owns the **storage plane**. It takes the
storage-granting responsibility that oracled carried inline
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

A flavor with no available source is simply not offered; `tzfs_request` on it
returns `ENOENT`.

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
  wrappers). What you use *after* you hold a handle.
- **`libtzfs`** (new) — the client to tzfsd. What you use to *obtain* a handle.

### 5.1 `libtzfs` API

```c
/* Request a rights-limited handle for storage of a given flavor+lifetime.
 * Returns a TrustedZFS dataset fd (drive it with libtrustedzfs), or -1. */
int tzfs_request(const struct tzfs_req *req, struct tzfs_grant *out);

struct tzfs_req {
    char      flavor[32];      /* "native"|"freebsd"|"linux"|"empty"|"" */
    char      name[64];        /* logical claim name within the bundle   */
    uint64_t  rights;          /* ZH_* mask requested                    */
    uint8_t   lifetime;        /* TZFS_PERSISTENT | TZFS_EPHEMERAL        */
};
struct tzfs_grant {
    int       handle_fd;       /* the zfd (SCM_RIGHTS from tzfsd)         */
    char      dataset[256];    /* resolved dataset name (for audit)       */
};

int tzfs_release(const char *name);          /* ephemeral teardown       */
int tzfs_mount_dir(int handle_fd);           /* handle -> dirfd (convenience) */
```

`flavor=""` means "just a dataset" (the current behavior — a claim on an
existing/created dataset with no template). A non-empty flavor clones the
template.

### 5.2 Wire protocol (`tzfsd_proto.h`)

Modeled on the oracled reply-with-fds RPC. Ops:

- `TZFS_OP_REQUEST` — `struct tzfs_req` → reply carries `handle_fd` via
  SCM_RIGHTS + resolved dataset name.
- `TZFS_OP_RELEASE` — logical name → destroy ephemeral clone (idempotent).
- `TZFS_OP_LIST_FLAVORS` — enumerate available flavors (for tooling/`tzfsctl`).
- `TZFS_OP_PING` — liveness.

Socket: `/var/run/tzfsd.sock` (root-owned; peers are oracled/serviced, and —
via a passed channel — sandboxed services). tzfsd `cap_enter()`s after opening
its pool handle and socket, so it runs the whole request loop in capability
mode, minting handles from its retained `zpd`.

---

## 6. Responsibility transfer from oracled

Today: serviced `oracle_mint_storage()` → oracled `handle_mint_storage()`
opens `/dev/zfs` and mints. After the move:

- The `storage_open_handle` / `storage_create_ephemeral` / `storage_split`
  logic **moves into tzfsd** (extended with clone-from-flavor).
- oracled keeps `ORACLE_OP_MINT_STORAGE` as a thin **forwarder** to tzfsd (so
  the existing serviced→oracled path keeps working during transition), or
  serviced talks to tzfsd directly via a passed channel. Recommended:
  serviced holds a tzfsd channel fd (delivered by oracled at bootstrap, like
  the oracle channel) and calls tzfsd directly — oracled is out of the data
  path entirely.
- **Boot order:** `oracle-init` (oracled, PID 1) brings up tzfsd right after
  the pool is available and before serviced starts services that declare
  storage. tzfsd readiness gates serviced's storage grants (a `tzfsd.ready`
  handshake, mirroring `serviced.ready`).

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
- **`lib/liboraclert/tzfsd_proto.h`** — wire protocol (lives with the other
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
3. **Responsibility transfer** — serviced → tzfsd channel; oracled out of the
   data path; boot-order + readiness handshake; `flavor` in the manifest.
4. **Foreign flavors** — `freebsd`/`linux`(Rocky) send-stream artifacts,
   producer tooling, install-time recv, live-build/source fallbacks.
5. **Tooling, man pages, tests, clean-VM validation.**
