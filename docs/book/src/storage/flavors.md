# TZFS Flavor Catalog

A **flavor** is a pre-populated template dataset that `tzfsd(8)` clones,
copy-on-write, per storage request. The insight that makes ready-to-go
images cheap: store one populated template per flavor under
`.templates/<flavor>@ready`, and every grant is a `zfs clone` — instant
regardless of image size, near-zero space until the consumer writes. A
service asks for `flavor = "linux"` and one call later holds a mounted
directory of a Linux rootfs.

## Built-in flavors: empty and native

The broker itself ships exactly the two flavors that need no artifact,
built live on first start (`usr.sbin/tzfsd/config.c`, `layout.c`):

| Flavor   | Contents           | Built by                                  |
|----------|--------------------|-------------------------------------------|
| `empty`  | blank dataset      | `tzfs_create` under `.templates`, ~free   |
| `native` | 5BSD base userland | live clone of the running boot environment |

**Native is a live BE clone, not a baked image.** `tzfsd` resolves the
dataset mounted at `/` (via `statfs`), verifies it lives in the configured
pool, snapshots it once as `@tzfs-native` (idempotent — later starts take
the already-present path), and clones that snapshot into
`.templates/native` with an `@ready` snapshot on top. The template shares
blocks with the live root until a clone diverges, so the native flavor
costs essentially no image space and ships "for free" rather than as a
second copy of the system on media. The whole build runs through
TrustedZFS handles — `tzfsd` never shells out to `zfs(8)`.

## OS-image flavors: the tzfs-flavors package

The `freebsd` and `linux` (Rocky Linux 9) flavors are **not built into the
broker**. They ship as a separate `tzfs-flavors` package
(`usr.sbin/tzfs-flavors/`, `PACKAGE= tzfs-flavors`) consisting of:

- `/Capabilities/Config/tzfsd.d/flavors.ucl` — a config drop-in declaring each
  flavor and its baked artifact. `tzfsd` reads every `*.ucl` fragment in
  `/Capabilities/Config/tzfsd.d/` after its main configuration, so the catalog
  contributes flavors as data:

```ucl
flavors {
    linux {
        build = "baked"
        source = "/usr/share/tzfs/rocky9.zfs.zst"
        default = true
    }
    freebsd {
        build = "baked"
        source = "/usr/share/tzfs/freebsd.zfs.zst"
    }
}
```

- Producer tools in `/usr/libexec`: `tzfs-flavor-linux.sh` fetches the
  official Rocky Linux minimal container base rootfs and writes
  `rocky9.zfs.zst`; `tzfs-flavor-freebsd.sh` builds from an installed
  `DESTDIR` or an extracted `base.txz` and writes `freebsd.zfs.zst`. Both
  are thin wrappers around `tzfs-mkflavor(8)` (installed with the broker),
  which populates a scratch dataset and emits a zstd-compressed ZFS send
  stream. These are build-/admin-time tools needing network access and a
  live pool.

`tzfs-mkflavor` validates the pool, flavor, source directory, compression
level, and output location before touching ZFS. It creates a private work
directory and a uniquely named scratch dataset, refuses to reuse a preexisting
dataset, checks both producers in its tar and `zfs send` pipelines, writes to a
same-directory temporary file, and publishes the nonempty artifact atomically.
Cleanup destroys only the dataset whose unique name it created.

The Linux producer requires both the downloaded archive SHA-256 (`-s`) and the
exact OCI layer SHA-256 (`-l`) and permits only HTTPS mirrors. It verifies the
outer archive, extracts only the pinned `blobs/sha256/<digest>` member, verifies
that layer again, and lists both archives before extraction to reject absolute
or traversal paths. OCI whiteouts are rejected rather than misapplied as
ordinary files; no size-based “largest blob” guess is used. The FreeBSD
producer is a strict local-tree wrapper around the same builder.

Artifacts are send streams rather than tarballs because materializing a
template is then a `zfs recv` — fast and property-preserving. On first
start `tzfsd` receives each declared artifact into `.templates/` and
thereafter clones it per request.

**Why Rocky for `linux`:** the 5BSD Linuxulator is developed and tested
against the RHEL/Rocky userland (glibc, RHEL ABI), so a Rocky rootfs runs
with the least friction, and it mirrors the library/ABI surface most
enterprise Linux software targets. A `linux` grant is a directory — a
dataset holding a Linux rootfs, mounted with the same handle API as
`native` — not a foreign block device.

## Why the catalog is decoupled

`tzfsd` is a storage/capability broker and deliberately knows nothing
about any particular operating system; its own defaults name no
distribution. Curating an OS image (which release, which mirror, how big)
is distro-curation work with a different change cadence than the broker,
so it is contributed as data. Consequences that fall out of the split:

- **Independent lifecycle** — the catalog installs, upgrades, and removes
  on its own; `pkg delete tzfs-flavors` sheds the Red Hat userland from a
  host without touching the broker, `empty`, or `native`.
- **Graceful absence** — a validly configured flavor whose baked artifact
  cannot be materialized is simply not offered (`tzfsd` logs a notice;
  requests for it fail with `ENOENT`;
  `tzfsctl list-flavors` omits it). Installing the catalog before
  producing artifacts is harmless. "Off" is a designed state, not a
  failure mode.
- **Host override** — the operator can override any catalog entry in
  `tzfsd.ucl`, e.g. `flavors { linux { enabled = false; } }` keeps the
  artifact on disk but stops offering it.

## Using a flavor

```sh
tzfsctl list-flavors
# empty
# native
# freebsd
# linux  (default)

tzfsctl request -f linux -l lease -m scratch
# granted zroot/Capabilities/ephemeral/lease-.../... (flavor=linux, lease)
```

Or declaratively, in a service manifest:

```ucl
storage = [{ name = "rootfs"; scope = "unit"; flavor = "linux";
             rights = ["mount", "snapshot"]; lifetime = "lease"; }];
```

**Status.** The `source` build mode (fetch/unpack from a configured URL on
first request) is declared in the config schema but not implemented; such
flavors are offered only if their template was pre-seeded. OS-image
removability uses `pkg delete tzfs-flavors` and the `enabled` configuration
lever. Install-media integration (baked streams received at install/first boot
per `docs/tzfsd-design.md` §3.1) depends on producing the artifacts for the
release media.

## Qualification

Mock-driven shell suites cover invalid arguments, unsafe names, existing
scratch datasets, tar/send/compressor failures, empty output, cleanup, and
atomic publication without requiring a live pool. Linux-image tests cover
required digests, HTTPS enforcement, archive and layer mismatches, missing
pinned blobs, traversal, whiteouts, and exact layer selection. tzfsd tests
cover strict configuration overlays and baked-artifact ownership, type,
symlink, mode, decompressor, and receive failures. The complete flavor matrix
runs with Crypto, EnvFD, BSDNotify, and TrustedZFS in the disposable amd64
`tools/test/capability-qemu/` guest.

Sources: `usr.sbin/tzfs-flavors/`, `usr.sbin/tzfsd/tzfs-mkflavor.sh`,
`tzfs-flavors(7)`, `docs/tzfsd-design.md`.
