# Installing

The 5BSD installer is bsdinstall(8), adapted to install base packages and
configure the ZFS pool used by the storage provider. The media boots with
the capability plane off, installs `5BSD-*` packages from its offline
repository, and writes the selected pool name into `/Capabilities/Config`.
Software attributes arrive with the installed bundles; account creation does
not assign capability privileges. Partitioning, networking and other standard
screens are documented in bsdinstall(8) and the FreeBSD Handbook.

## The media

Installer media come from `make -C release memstick` or `cdrom` (see
[Building](building.md)). On the media, `/boot/loader.conf` carries
`capability_plane="NO"`, so `/sbin/capsule` still starts as PID 1 (it is
first in `init_path`) and hands off to stock `/sbin/init` at once; the loader
brand is `5bsd-install`. `/usr/5bsd-packages/offline` holds the repository,
and `/usr/5bsd-packages/repos/5BSD-base-offline.conf` points `5BSD-base` at
it. `/tmp`, `/var` and `/Capabilities/Run` are tmpfs because the media is
read-only.

## The guided install

`bsdinstall auto` runs the steps below in order. Steps that 5BSD added or
changed are marked; the rest are upstream.

| Step | What it does | 5BSD change |
|---|---|---|
| `keymap`, `hostname` | Keyboard and host name | Host name validated by `hostname.subr` |
| offline prompt | If `5BSD-base-offline.conf` exists, asks whether to configure networking for firmware and extra packages; either way `BSDINSTALL_PKG_REPOS_DIR` points at the media repo | new |
| `zfsboot` | Guided root-on-ZFS | The only guided path; UFS guided install is gone. Manual and shell partitioning remain |
| `pkgbase` | Selects components and installs packages into `/mnt` | replaces dist-set extraction |
| `tzfspool` | Records the pool in the storage broker's config | new |
| `rootpass`, `netconfig`, `time`, `services`, `hardening`, `firmware`, `adduser` | Post-install configuration | `firmware` uses fwget(8); `firmware-fetch` installs matching drivers and firmware from the offline `5BSD-hardware` repository or a configured 5BSD hardware service |
| `finalconfig`, manual shell | Last chance to edit `/mnt` | unchanged |

### Storage: ZFS only

`zfsboot` creates the usual boot-environment layout (`zroot/ROOT/default`,
`/home`, `/tmp`, `/var/*`) plus a `/usr/local` dataset so ports and locally
built software live outside the base generation, and it appends one line to
the new system's fstab:

```
tmpfs /Capabilities/Run tmpfs rw,mode=0700 0 0
```

`/Capabilities/Run` holds the launch containers switchboard creates for
every unit: ephemeral descriptors and process-scoped state that must not
survive a reboot or a boot-environment rollback. Putting it on tmpfs is what
keeps the installed system consistent with the live media.

The ZFS requirement is real but not absolute. bsdinstall(8) says it plainly:
OpenZFS is the required filesystem for a fully functional installation;
BSDFilesystem provides capability-based access to it for persistent service
data, and a pool-less system runs in a degraded mode with no persistent
capability storage. Manual partitioning on UFS produces a bootable system
whose providers have no durable containers. See
[Containers and Storage](../plane/containers-and-storage.md).

### Packages: the `pkgbase` step

`usr.sbin/bsdinstall/scripts/pkgbase.in` queries the repository for
`5BSD-set-*` metapackages and offers them as components. `base` (the complete
system) is on by default; `kernel-dbg`, `src`, `tests` and `debug` are
explicit choices; `minimal`, `pkg` and `kernel` are always installed
(`5BSD-kernel-generic`, the only kernel the script knows). With `--jail`
(used by `bsdinstall jail`) the `-jail` variants are selected and no kernel is
installed. A scripted install sets `COMPONENTS` in the environment; the
`script` target forces it to `base kernel`.

Installation is a plain `pkg install` into `/mnt`. Nothing runs the service
manager afterwards: switchboard discovers bundles on its first boot scan and
through its install-folder watch, so there is no post-install step to
register them. Two things do happen inside `pkg`: the `runtime` package's
scripts create the `capability` user and group (uid and gid 976, the
identity every sandboxed unit runs as by default), regenerate `pwd.db`, and
verify with `pw -V` that the database resolves the name, failing the install
loudly if it does not; and `/Capabilities/{Config,Run,State/switchboard,System}`
are created from `etc/mtree/BSD.root.dist`.

### The `tzfspool` step

`bsdinstall tzfspool` runs right after `pkgbase` so that it edits the packaged
policy in place. `zfsboot` leaves the chosen pool name in
`/tmp/bsdinstall_etc/bsdfilesystem.pool`; `tzfspool` validates it against the
identifier grammar BSDFilesystem accepts (a letter, then letters, digits,
`_ . : -`) and rewrites the `pool =` line of
`/mnt/Capabilities/Config/bsdfilesystem.ucl`:

```
pool = "zroot";
```

A manual or UFS layout produces no state file and the step is a no-op. The
file is the single place the storage broker learns which pool to bind; if
you rename the pool later, edit this line. See
[system.Filesystem](../providers/filesystem.md) and tzfs.conf(5).

### Software authority

There is no per-user capability policy dialog. Installed bundle manifests
identify approved executables and their attributes. The inherited discovery
channel supplies a route to SwitchBoard; it does not give a shell the
attributes of its parent or of an administrator.

Ordinary UNIX permissions determine who may execute a program. In V1, anyone
permitted to execute an attributed program can use the operations that program
exposes. System builders must choose those programs and their execution
permissions accordingly. UID 0 alone does not grant endpoint access. CORE
services cannot be stopped, restarted, unloaded or disabled through runtime
management commands.

See [Software Attributes](../plane/attributes.md) and
[The Management Model](../plane/management-model.md). The packaged
`switchboard/boot-authority.ucl` separately bounds temporary boot-script
authority; it is not a user or login policy.

## Scripted and jail installs

The package installation environment variables are:

| Variable | Effect |
|---|---|
| `BSDINSTALL_PKG_REPOS_DIR` | Directory of pkg repository files for the `pkgbase` step; unset, the template `/usr/share/bsdinstall/5BSD-base.conf` is used, which points at the standard local build repository; the installer explicitly selects `5BSD-base`, even with its disabled default |
| `COMPONENTS` | Component list for a non-interactive `pkgbase` |

A `bsdinstall script` file uses the same preamble variables as upstream
(`ZFSBOOT_*`, `nonInteractive`, and so on). `bsdinstall jail <dir>` runs
`pkgbase --jail` and skips partitioning, networking and the kernel; the
result is a chroot suitable for jail(8). How a jail relates to the plane on
the host is in [Jails](../compat/jails.md).

## What `/Capabilities` looks like after install

```
/Capabilities/
    Config/
        switchboard/
            boot-authority.ucl   packaged boot-script limits
        bsdfilesystem.ucl        pool= written by tzfspool
    Run/                         tmpfs, mode 0700, per-unit launch containers
    State/
        switchboard/             mode 0700, switchboard's persistent state
    System/
        <Name>.cap/              one bundle per system capability
            Units/<unit>.unit/
                Unit.ucl, bin/, Config/, lib/
```

`/Capabilities/System` is populated by the packages that carry bundles
(`runtime`, `bsdlog`, `bsdtrace-provider` and the rest). `/Capabilities/Apps`
is not created by the installer; switchboard watches for it to appear and
starts scanning it when it does. The full layout contract is in
[Bundles and Manifests](../plane/bundles-and-manifests.md).

Other first-boot facts fixed by the packages rather than the installer: the
`capability:976` identity; `zfs_enable="YES"`, `auditd_enable="YES"` and
`linux_enable="YES"` in the default `rc.conf` (see
[Boot Knobs](boot-knobs.md)); `/etc/os-release` with `ID=5bsd` and
`ID_LIKE=freebsd`; and `uname` still reporting `FreeBSD` so that ports
packages keep installing.

## First boot

The loader's `init_path` starts `/sbin/capsule`. Capsule claims
`/dev/mac_capability`, starts switchboard, and switchboard launches the
native boot units in parallel with `/etc/rc` (which still mounts the root
read-write, imports pools, and starts every `rc.d` service you enabled).
Expect these lines on the console or in `/var/log/messages`:

```
switchboard[..]: registry: watching install folder /Capabilities/System
switchboard[..]: startup: service: system.Log
...
switchboard[..]: startup: launched 13 native services
```

followed by the ordinary getty banner. `ps -p 1 -o comm=` prints `capsule`;
`switchboardctl services` lists the running units. A unit that is missing
from that list has its reason in `/var/log/messages` (switchboard's own
lines) and `/var/log/capability.log` (the unit's stdout and stderr);
[Troubleshooting](troubleshooting.md) covers the common ones. The full boot
sequence is in [From Power-On to Login](../orientation/boot-to-login.md).

## The plane-off escape hatch

If the installed system does not come up, the loader knob that the media
itself uses is available to you. At the loader prompt:

```
set capability_plane="NO"
boot
```

or persistently, `capability_plane="NO"` in `/boot/loader.conf`. Capsule
still starts, reads the kenv, logs `capability_plane=NO: handing PID 1 to
/sbin/init (plane-free boot)` and execs stock init; `-s` is forwarded so
single-user still works. The kernel is unchanged and the plane's code is
still compiled in, but nothing claims the control device, no unit is
launched, and you have a plain FreeBSD-style system to repair from. The same
boot is what the kernel capability test suites need
([Testing](../develop/testing.md)). Remove the knob and reboot to return to
the plane.

## Limits

The installer is amd64-first; the arm64 and Raspberry Pi profiles under
`release/tools/` are experimental. There is no public package server, so a
freshly installed system has a disabled `5BSD-base` repository entry until
you give it a local one ([Upgrading](upgrading.md)). The installer knows one
kernel package. Software attributes control capability access; they do not
by themselves protect every UNIX resource or seal the installed software
against modification. See [The Management Model](../plane/management-model.md).

## Hardware support

The firmware menu includes the graphics driver when GPU firmware is selected,
and includes PCI/USB Wi-Fi and Intel/Realtek Bluetooth firmware detected by
fwget. Packages come from
`5BSD-hardware`, with kernel modules built for the exact installed kernel and data-only
firmware supplied separately. Full release media keeps
an offline copy in `/usr/5bsd-packages/hardware` on the target, so networking is
not required for this step. Wi-Fi firmware is also available to the live installer.

The firmware step reuses the release's embedded `pkg-static` when the live
system has no installed package manager, extracting it into a private temporary
directory. It must not prompt to bootstrap pkg from the network behind the
installer dialog. Failed installation displays the helper's stderr and retains
the complete output in a temporary log as well as the installer debug log.
Media built with `WITHOUT_HARDWARE_PACKAGES=yes` has no offline hardware
repository; a configured 5BSD hardware service is then required.

Firmware detection is not a driver-support check. For example, the MediaTek
MT7925 (`14c3:7925`) is detected by fwget, but the imported mt76 driver is
not enabled in the base module build. It has unresolved LinuxKPI build and
page-pool implementation requirements. Its firmware package alone cannot
create a Wi-Fi interface; do not report this chipset as supported until the
driver is implemented, built and tested on hardware.

Missing or incompatible packages are reported; the installer does not fall
back to FreeBSD's binary module repository. For network installation or updates,
configure a signed 5BSD hardware repository matching the base release. The
shared fwget installer validates the target kernel and the complete package
dependency closure before installing. GPU module startup is written to the
installer's rc.conf fragments after successful installation.

The release build and update contract is described in
[Release hardware packages](../develop/packaging.md#release-hardware-packages).
