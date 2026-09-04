# Building, Packaging, and Releasing

5BSD builds like FreeBSD: `buildworld` and `buildkernel` from `/usr/src`,
pkgbase packages from the same tree, and release media from `release/`.
This chapter is where the **5BSD kernel** referred to throughout this Epic
is defined and built.

## Requirements

- A FreeBSD or 5BSD build host
- `/usr/ports` containing at least `ports-mgmt/pkg` (the release targets
  build `pkg` for the installer media); a sparse checkout is enough:

```sh
doas git clone --depth 1 --sparse https://git.FreeBSD.org/ports.git /usr/ports
cd /usr/ports
doas git sparse-checkout set ports-mgmt/pkg Mk Templates Keywords
```

- About 30 GB free under `/usr/obj`, and a USB drive for installer media

## World and the 5BSD kernel

```sh
cd /usr/src
doas make -j$(sysctl -n hw.ncpu) buildworld
doas make -j$(sysctl -n hw.ncpu) buildkernel        # KERNCONF=VBSD is the default
```

The 5BSD kernel is built from the `VBSD` configuration, and ships as the
pkgbase package `5BSD-kernel-vbsd`. `VBSD` is `include GENERIC` plus
`ident VBSD` plus `nooptions COMPAT_FREEBSD32`: every 5BSD kernel option —
`HWT_HOOKS` for hardware tracing, `BHYVE_SNAPSHOT` for WASPNest
checkpoint/restore, and the rest — lives in `GENERIC` itself, so custom
configurations that include `GENERIC` inherit the full 5BSD feature set,
and `VBSD` adds only identity and the 64-bit-only stance.

That stance is tree-wide: **5BSD is 64-bit only**. TrustedZFS capability
descriptors require a 64-bit kernel and user ABI, so `MK_LIB32` is
unconditionally broken (`share/mk/src.opts.mk`) — there is no 32-bit shim
userland and no `COMPAT_FREEBSD32` in the kernel.

Build orchestration follows standard `Makefile.inc1` conventions. One 5BSD
addition worth knowing: with `MK_DTRACE` enabled, `cddl/lib/drti` and
`cddl/lib/libdtrace` are staged as startup/prebuild libraries so USDT
provider objects link against the target-ABI `drti.o` during cross builds.
The in-tree toolchain is LLVM/Clang 21.1.8 (a curated import — MLIR, Flang,
BOLT, Polly, and most of clang-tools-extra are not included).

## Pkgbase packaging

5BSD distributes its base system as pkgbase packages named `5BSD-*`
(upstream uses `FreeBSD-*`). Every base component — libraries, daemons, the
kernel, tests, debug symbols — is a package, so upgrades, partial installs,
and rollbacks all go through `pkg(8)` and boot environments.

Source Makefiles tag installed files with `PACKAGE=<name>`;
`packages/<name>/Makefile` defines the package (`PKG_SETS`, `SUBPACKAGES`,
commonly `dbg man`, dependencies, licenses) and
`release/packages/ucl/<name>-all.ucl` carries the human-facing description.
The master list is `packages/Makefile`; build-option-conditional packages
are added there (e.g. `SUBDIR.${MK_DTRACE}+= bsdinstruments ctf dtrace
dwatch`). Packages install in sets — `5BSD-set-base`, `5BSD-set-kernels`,
`5BSD-set-tests` — with `-dbg` variants carrying debug files and kernel
symbols. Two notable cases: the **bhyve** package ships the transitional
`waspnest -> bhyve` symlink and man link (part of the gradual hypervisor
rename), and the ObservableBSD tools are individually packaged
(see [ObservableBSD](../observability/observablebsd.md)).

### Building the repository

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld buildkernel KERNCONF=VBSD \
    packages PKG_CMD=/usr/local/sbin/pkg-static
```

The result is a signed repository under
`/usr/obj/usr/src/repo/${ABI}/<version>` (`${ABI}` is e.g.
`FreeBSD:16:amd64`) with the `latest` symlink updated.

`PKG_CMD=/usr/local/sbin/pkg-static` is not optional. The default dynamic
`pkg(8)` from ports tracks the newest FreeBSD `__FreeBSD_version` and may be
linked against libc symbol versions the 5BSD tree has not adopted (the
concrete case: `fts_*@FBSD_1.9` vs the tree's `FBSD_1.5`), which kills
packaging with an `Undefined symbol` error at signing time. `pkg-static`
carries its own libc and is immune to the skew. **Do not** patch base libc
to satisfy the dynamic pkg — every base binary is internally consistent;
the mismatch is a property of the foreign tool. If you intend to move the
tree to the newer ABI, bump `__FreeBSD_version` deliberately.

### Repository configuration

Base updates must come from a local 5BSD repo so `pkg upgrade` never
replaces 5BSD packages with upstream FreeBSD ones. Sample configurations
ship in the tree: `docs/pkg/5BSD.conf.sample` (install to
`/usr/local/etc/pkg/repos/5BSD.conf`; `priority: 100` prefers local
packages) and `docs/pkg/FreeBSD.conf.sample` (disables `FreeBSD-base`).
The FreeBSD-ports repos remain enabled for third-party software.

### Installing, migrating, upgrading

Fresh installs use the USB installer, which carries an offline `5BSD-*`
repo. Migrating a
FreeBSD 16-CURRENT pkgbase system is a one-time operation because the
package names differ:

```sh
bectl create pre-5bsd-migration
pkg update
pkg delete -fa
pkg install -r 5BSD-base 5BSD-set-base 5BSD-kernel-vbsd
reboot
```

5BSD-to-5BSD upgrades are the repository build above followed by
`bectl create pre-upgrade; pkg update -f; pkg upgrade; reboot`. Verify
after reboot: `uname -i` shows `VBSD` and `pkg query '%n' | head` shows
`5BSD-*` names. Roll back with `bectl activate` if anything goes wrong.

## Release engineering

Release artifacts are built from `/usr/src/release` using FreeBSD's release
framework, adapted so every image installs from 5BSD pkgbase packages and
carries 5BSD branding throughout — the boot chain, loader menus, volume
labels, installer scripts, and boot logo.

```sh
cd /usr/src/release
doas make obj
doas make cdrom          # disc1.iso
doas make memstick       # memstick.img (also mini-memstick)
doas make release        # real-release + vm-release + cloudware-release + oci-release
```

Cloud and container variants live alongside (`Makefile.vm`, `Makefile.ec2`,
`Makefile.azure`, `Makefile.gce`, `Makefile.oci`, `Makefile.firecracker`,
`Makefile.vagrant`); per-target media scripts sit in `release/<arch>/`, and
helper scripts under `release/scripts/`, notably `pkgbase-stage.lua` (which
must list `5BSD-kernel-vbsd`).

### Installer media

The memstick and disc1 images stage a fresh system, build an offline
pkgbase repository of `5BSD-*` packages, and install `pkg` on the media, so
`bsdinstall` performs a network-free pkgbase install. The media uses the
UFS label `5BSD_Install`, pins `vfs.root.mountfrom` to it, and puts
`boot_policy=strict` in the ESP loader environment so the EFI loader does
not fall back into a resident FreeBSD boot pool. Write the image with
`dd if=.../memstick.img of=/dev/daX bs=1m status=progress`. For a VM,
prefer `make cdrom` and attach the ISO; the memstick image also works
attached as a raw boot disk (not as a CD-ROM).

### VM images

`release/tools/vmimage.subr` builds VM disk images from pkgbase rather than
`installworld`: `vm_base_packages_list` selects `5BSD-set-base`,
`5BSD-set-kernels`, `5BSD-set-tests` (plus `-dbg` variants unless disabled)
and `5BSD-pkg-bootstrap`, so images can upgrade themselves without the
ports-built pkg. `vm_install_base` installs from the build repo and writes
`/usr/local/etc/pkg/repos/5BSD.conf` so the image keeps pulling base
updates from a 5BSD repo; `NOPKGBASE` falls back to the classic
`installworld` path, and a `vm_extra_filter_base_packages` hook lets
per-image configurations filter the package list.

VM images boot on the serial console: `console="comconsole"` is appended to
`/boot/loader.conf` so images are drivable over a `bhyve -l com1` line for
automated boot verification (headless bhyve has no framebuffer; pairing
`vidconsole` yields "no valid consoles!").

## Troubleshooting

- Boot drops to `mountroot`: check that `release/amd64/make-memstick.sh`
  uses `5BSD_Install` for both `/etc/fstab` and the UFS label.
- `pkg update` fails while building the installer repo: confirm
  `/usr/ports` contains `ports-mgmt/pkg`, then rebuild the release target.
- pkgbase staging cannot find a kernel package: `5BSD-kernel-vbsd` must be
  listed in both `release/scripts/pkgbase-stage.lua` and
  `usr.sbin/bsdinstall/scripts/pkgbase.in`.
- Packaging dies with `Undefined symbol "fts_open@FBSD_1.9"` (or a bus
  error): you packaged with the dynamic ports pkg — use
  `PKG_CMD=/usr/local/sbin/pkg-static` as above.
- A machine boots into an installed system instead of the installer: at the
  loader prompt inspect `show currdev`, `show rootdev`,
  `show vfs.root.mountfrom`, `show loader_brand`, and `lsdev`.
