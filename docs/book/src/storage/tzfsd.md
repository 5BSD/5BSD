# tzfsd and capability storage

`tzfsd(8)` owns the storage plane. It retains TrustedZFS parent handles,
creates or opens application datasets, attenuates each returned handle to the
declared rights, and passes that handle with `SCM_RIGHTS`. It never proxies
application I/O.

`authorityd` starts it on demand and forwards storage requests. `serviced`
delivers mount-only storage as a rights-limited `zfshandle` named
`storage:<logical-name>`; the unit mounts it itself with `service_storage_open(3)`
and holds the handle for its lifetime (the handle anchors the mount). A
filesystem descriptor consumes its backing handle privately. The logical name
is not a dataset name.

## ZFS is a platform requirement

5BSD requires ZFS, and the installer must place the system on a ZFS pool. This
is not a preference — it is structural. The core capability daemons (`tzfsd`,
`serviced`, `logd`, and the descriptor factories) are the programs that expose
the system's storage, logging, and component APIs, and they run **confined in
capability mode**: after startup they hold only the descriptors they were
handed and can no longer reach the global namespace, run `zpool(8)`, or create
a pool. A daemon cannot bootstrap the very storage plane it confines itself
inside. The pool must therefore exist **before** the storage plane comes up —
which in practice means it must be created at install time.

Consequently `bsdinstall` provisions a ZFS pool by default (the guided
"Auto (ZFS)" path is the standard 5BSD installation), and ZFS is the default
root filesystem on every platform that can boot from it. A UFS-only or
pool-less install is a degraded configuration: the daemons still start, but
every storage-backed capability (persistent unit state, the log store, the
filesystem component's namespaces) is unavailable until an operator creates a
pool by hand as described below. Treat "no ZFS pool" as an installation error
to correct, not a supported mode.

> Platform status: amd64 installs onto a ZFS root out of the box. Bringing the
> same ZFS-root default to the arm64 board images (Raspberry Pi in particular)
> is in progress; see "ZFS root on ARM board images" at the end of this chapter.

## The backing pool at first boot

`tzfsd` never creates a ZFS pool. It requires exactly one pool to already be
imported and, inside it, provisions the whole capability layout itself: on
first start it opens the pool root and creates
`<pool>/Capabilities/{persistent,ephemeral,.templates}` if they do not exist
(`tzfsd_ensure_path`). Everything below `/Capabilities` is therefore
self-installing; the only prerequisite the operator owns is the pool.

The pool name defaults to **`zroot`** and is the single knob most systems ever
touch. Configuration lives in `/etc/capability/tzfsd.ucl`
(with flavor-catalog drop-ins under `/etc/capability/tzfsd.d/`); every key is
optional and the commented defaults in the shipped file are authoritative.

**ZFS-rooted install (the streamlined path).** A stock ZFS-on-root system
already has `zroot` imported at boot, so there is nothing to do: the first time
a unit requests storage, `authorityd` starts `tzfsd`, which provisions
`zroot/Capabilities` and begins minting handles. The `native` flavor — a
copy-on-write clone of the running boot environment — is available only on such
a system, because it clones the live root dataset.

**No suitable pool (UFS root, or a dedicated capability pool).** If `zroot`
does not exist, `tzfsd` exits at startup with
`layout provisioning failed (is pool <name> imported?)`. Provide a pool and
point the daemon at it:

```sh
# One-time: create (or import) a pool for capability storage.
zpool create capability /dev/<disk-or-file>   # or: zpool import capability

# Tell tzfsd to use it.
printf 'pool = "capability";\n' >> /etc/capability/tzfsd.ucl
```

`tzfsd` provisions `capability/Capabilities/...` on its next start. Only the
`empty` flavor (a blank dataset) works on a system whose root is not ZFS; the
`native` flavor and OS-image flavors from the `tzfs-flavors` package need a
ZFS-rooted host and are simply not offered otherwise.

Storage is delivered to providers that run under the unprivileged **`capability`
sandbox account** (uid/gid 976, `Capability service sandbox`, `nologin`), which
ships in the base `master.passwd`. `tzfsd` sets the dataset root's owner to
that account at mint (the uid is threaded `serviced` → `authorityd` → `tzfsd`),
so the unit can write once it mounts the handle; no operator setup of the
account is required.

## Installer integration (bsdinstall)

Two `bsdinstall` behaviors follow from ZFS being mandatory and from the
capability component model.

**ZFS is the default, UFS is the labeled fallback.** On every arch that can boot
ZFS (`amd64`, `arm64`, `i386`, `riscv`) the guided installer lists **Auto (ZFS)
— Guided Root-on-ZFS** first and pre-selects it (`--default-item`), so the
operator who presses Enter gets a pool. "Auto (UFS)" remains, but as an
explicitly chosen, second-class option — consistent with the "no ZFS pool is a
degraded configuration" rule above. Automated installs get the same default:
the unattended `bsdinstall` path uses the ZFS layout unless a script overrides
it. (Board images are the exception until the ARM ZFS-root work below lands.)

**A capability-selection step.** Because the capability daemons broker a menu of
independent components — logging, notifications, tracing, the filesystem and
network components, crypto, audit — the installer offers a checklist for which
ones start at first boot, modeled on the existing `services` and `hardening`
screens and slotted into the same post-extract sequence
(`… → services → capabilities → hardening → …`). The core plane
(`authorityd`/`serviced`/`tzfsd`) is always on and not listed; the checklist covers
the optional providers. A selected component has its capability bundle marked
active (boot activation or on-demand); an unselected one is still installed but
inactive, so it can be enabled later with `servicectl` without a reinstall. The
defaults enable the commonly expected providers and leave specialized ones off,
matching how `services` seeds `sshd` on and the rest off. See
[serviced](../system/serviced.md) and
[Service Manifests](../system/manifests.md) for what "active" means at the
bundle level.

## Dataset layout

```text
<pool>/Capabilities/
├── persistent/
│   ├── u-<192-bit-key>          unit persistent/cache storage
│   └── s-<192-bit-key>          shared persistent/cache storage
├── ephemeral/
│   ├── boot-<kern.boottime>/
│   │   └── <stable-key>         current-boot storage
│   └── lease-<manager-session>/
│       └── <stable-key>         last-holder lease storage
└── .templates/
    └── <flavor>@ready
```

The key is the first 192 bits of a domain-separated SHA-256 digest over bundle
id, scope, unit id when applicable, and descriptor name. It is stable for
persistent identity and has 192-bit collision resistance. Scope prefixes make
unit and shared keys visibly disjoint.

## Lifetimes

| Lifetime | Stop | `serviced` restart | `tzfsd` restart | Reboot |
|---|---|---|---|---|
| `persistent` | keep | keep | keep | keep |
| `cache` | keep | keep | keep | keep, but reclaimable by policy |
| `boot` | keep | keep | keep | reclaim old boot generation |
| `lease` | delete after last holder | reclaim abandoned session | resume current session | reclaim old session |

Shared lease accounting occurs in `serviced`: every successful mint adds a
holder and all failure/stop paths release exactly the subset actually minted.
Only the transition from one holder to zero sends a destroy request.

`tzfsd` does not erase the ephemeral root when it starts. Doing so would turn a
storage-daemon crash into application data loss. Instead, boot generations are
derived from `kern.boottime`; lease generations are selected by `authorityd` for
each new `serviced` instance. Reconnecting after a `tzfsd` crash resumes the
same lease session. A new manager instance selects a new session after the old
supervised process tree is gone and reclaims older ordinary lease trees.
Retained snapshots make reconciliation fail visibly and leave the tree intact.

## Bundle declarations

Shared definition in `Bundle.ucl`:

```ucl
shared {
    storage = [{
        name = "database";
        flavor = "native";
        lifetime = "persistent";
    }];
}
```

Per-unit grants in `Unit.ucl`:

```ucl
storage = [
    {
        name = "database";
        scope = "shared";
        rights = ["mount", "props_read", "snapshot"];
    },
    {
        name = "scratch";
        scope = "unit";
        lifetime = "lease";
        rights = ["mount", "props_read", "props_write"];
    }
];
```

A shared reference cannot override the bundle declaration's lifetime or
flavor. Rights remain per unit. Accepted rights include property read/write,
snapshot lifecycle, rollback, clone source, child create/destroy, send/receive,
mount, hold, and release operations.

## Confinement and protocol

Before `cap_enter()`, `tzfsd` loads its UCL configuration and flavor drop-ins,
ensures ZFS is available, provisions roots, reconciles stale boot generations,
and retains subtree handles. After that point every operation derives from
those handles.

The versioned `SOCK_SEQPACKET` protocol has request, release, flavor-list,
ping, and begin-session operations. Messages are fixed-size and reject unknown
flags, non-zero reserved bytes, unterminated fields, unsafe dataset components,
wrong descriptor counts, truncation, and descriptor smuggling. Release is
idempotent and applies only to the selected lease generation.

Tests under `tests/sys/tzfs` exercise all lifetimes, daemon restart, session
rollover, last-holder behavior, malformed sessions/messages, rights
attenuation, clone/mount behavior, and conservative retained-snapshot failure
in a disposable ZFS VM.

## Boot environments (ZFS multiboot)

Because ZFS is mandatory (above), every 5BSD root install uses the boot
environment layout — `zroot/ROOT/<be>` with `canmount=noauto`, and the pool's
`bootfs` naming the active one (`zroot/ROOT/default` by default). The
`makefs -t zfs` image build and `bsdinstall`'s `zfsboot` script both lay the
pool out this way, so multiboot is present by construction rather than as an
opt-in.

Three layers make it usable, and all three ship in base:

- **Selection (loader).** The Lua loader enumerates bootable environments from
  the pool (`stand/lua/core.lua`: `bootenvList`, `zfs_be_active`) and offers the
  boot-environment menu, so a different BE can be booted without touching disk.
  On arm64 this is the same EFI `loader.efi` used by the board images, so the
  menu works on Raspberry Pi exactly as on amd64.
- **Management (tool + API).** `bectl(8)` creates, activates, mounts, renames,
  and destroys environments; `libbe(3)` is the C API beneath it. Use these —
  not raw `zfs(8)` — to add or promote an environment, so `bootfs` and the
  `canmount`/`mountpoint` invariants the loader relies on stay correct.
- **Capability storage (native flavor).** `tzfsd`'s `native` flavor is itself a
  boot-environment clone: `build_native_live()` snapshots the running BE
  (`f_mntfromname`, e.g. `zroot/ROOT/default`) as `@tzfs-native` and clones the
  template from it. A unit that requests `flavor = "native"` therefore boots
  into a copy-on-write image of the exact environment the system is currently
  running, and it costs nothing until written. This is why `native` is offered
  only on a ZFS root: without a boot environment there is nothing to clone.

The upshot for the capability platform: an operator can `bectl create` a new
environment, install or upgrade into it, and activate it for the next boot,
while `tzfsd` keeps handing units `native` clones of whichever environment is
live — the two mechanisms share one substrate.

## ZFS root on ARM board images

amd64 and the arm64 *VM* images already build a ZFS root: `release/tools/
vmimage.subr` builds the pool image offline with `makefs -t zfs` (the
`zroot/ROOT/default` layout above) and lets `mkimg` place it as a
`freebsd-zfs` partition behind an EFI System Partition, and the
`arm64:aarch64` case already carries the ESP path. Nothing on that path needs a
live `zpool create`, so it works inside the release chroot.

The **embedded board images** (`release/arm64/RPI.conf` and friends, assembled
by `release/tools/arm.subr`) are the remaining gap: `arm_create_disk()` still
partitions a `freebsd-ufs` root and `newfs`es it, and writes an `/etc/fstab`
that mounts `/dev/ufs/rootfs`. Those images boot UFS today.

The boot chain that has to be satisfied for a ZFS root on Raspberry Pi is:

```text
SoC ROM → GPU firmware (start*.elf on the FAT) → u-boot.bin → EFI →
loader.efi (MK_LOADER_ZFS, reads zroot) → kernel + zfs.ko → zfs:zroot/ROOT/default
```

The FAT partition keeps its current role (GPU firmware, `config.txt`, U-Boot,
DTBs, and now `loader.efi`); only the root partition changes from UFS to a
`freebsd-zfs` pool. Concretely, converting `arm.subr` means:

1. Build the root as a pool image with the same `makefs -t zfs …
   -o poolname=zroot -o bootfs=zroot/ROOT/default …` invocation the VM path
   uses, instead of `newfs` on a mounted partition, and `dd`/`mkimg` it into the
   `freebsd-zfs` root partition.
2. Replace the UFS `fstab` root line with none (ZFS mounts the root) and set
   `zfs_load="YES"` plus `vfs.root.mountfrom="zfs:zroot/ROOT/default"` in the
   FAT-side `loader.conf`, keeping the existing EFI/DTB entries.
3. Ensure `zfs.ko` matching the `VBSD` kernel is stored where `loader.efi` can
   load it (in the pool, alongside the kernel), and that the arm64 `loader.efi`
   with ZFS is the one copied to the FAT partition.

A software audit of the boot chain found no blocker: `makefs -t zfs` builds the
pool image on any host (it is userland and needs no kernel ZFS), the arm64
`loader_lua.efi` is built with `-DLOADER_ZFS_SUPPORT` and carries the
arch-common `efi_zfs_probe` that enumerates EFI block devices for pools,
`stand/common/disk.c` traverses MBR and `bsddisklabel` partitions, and
`rc.d/growfs` already grows a ZFS root (`zpool online -e`). The remaining work
is build wiring in `arm.subr` plus a hardware boot test.

Milestones, in order:

1. **Buildable Pi 4 ZFS image.** Add a `ROOTFS=zfs` path to `arm.subr` that
   stages the tree, images the root with the `makefs -t zfs` invocation above,
   and stages DTBs/loader from the tree rather than from a live mount (a
   `makefs` ZFS image is not mountable on a non-ZFS build host). The Pi 4 is the
   first target because its U-Boot EFI + SD/USB block path is the most mature.
   Keep UFS the default so existing board images do not regress.
2. **Hardware boot validation (Pi 4).** Confirm GPU-firmware → U-Boot →
   `loader_lua.efi` ZFS discovery on real hardware, and the pool
   `ashift`/feature flags the arm64 loader accepts.
3. **Pi 5 and the other boards.** Extend the same path once Pi 4 boots, and
   decide whether the RPi firmware's first-FAT-partition requirement coexists
   with `mkimg`'s ESP or the two-partition (firmware-FAT + ZFS) `arm.subr`
   layout is retained.

Until milestone 2 passes, board images remain UFS and the "no ZFS pool"
fallback in this chapter applies to them; see `docs/rpi5-bringup-plan.md` for
the wider Raspberry Pi bring-up.
