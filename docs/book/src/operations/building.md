# Building 5BSD

5BSD builds like FreeBSD: `buildworld` and `buildkernel` from `/usr/src`,
then release targets under `release/`. The canonical short-form document is
`/usr/src/docs/building-5bsd.md`; this chapter expands it for operators.

## Requirements

- A FreeBSD or 5BSD build host
- `/usr/ports` containing at least `ports-mgmt/pkg` (the release targets
  build `pkg` for the installer media)
- About 30 GB free under `/usr/obj`
- A USB drive if you are producing installer media

A sparse ports checkout is enough:

```sh
doas git clone --depth 1 --sparse https://git.FreeBSD.org/ports.git /usr/ports
cd /usr/ports
doas git sparse-checkout set ports-mgmt/pkg Mk Templates Keywords
```

## World and kernel

```sh
cd /usr/src
doas make -j$(sysctl -n hw.ncpu) buildworld
doas make -j$(sysctl -n hw.ncpu) buildkernel
```

The default 5BSD kernel configuration is `VBSD` (the pkgbase kernel package
is `5BSD-kernel-vbsd`). `VBSD` is purely an identity wrapper — it is
`include GENERIC` plus `ident VBSD`, and every 5BSD kernel option
(including `BHYVE_SNAPSHOT`, required by the WASPNest
checkpoint/suspend-and-restore implementation) lives in `GENERIC` itself,
so custom configurations that include `GENERIC` inherit the full 5BSD
feature set. Build orchestration follows standard
`Makefile.inc1` conventions: cross builds bootstrap a toolchain, stage
startup and prebuild libraries, then build everything in parallel. 5BSD
adds one convention worth knowing: with `MK_DTRACE` enabled,
`cddl/lib/drti` and `cddl/lib/libdtrace` are staged as startup/prebuild
libraries so USDT provider objects link against the target-ABI `drti.o`
during cross builds.

The in-tree toolchain is LLVM/Clang 21.1.8 (a curated import — MLIR,
Flang, BOLT, Polly, and most of clang-tools-extra are not included).

## Installer media (memstick)

```sh
cd /usr/src/release
doas make obj
doas make memstick
```

The image lands at:

```sh
/usr/obj/usr/src/amd64.amd64/release/memstick.img
```

The release target stages a fresh system, adds the installer environment,
builds an offline pkgbase repository of `5BSD-*` packages, installs `pkg`
on the media, and creates a bootable memstick image. No external installer
script is required. Write it with:

```sh
geom disk list                       # find the target device
doas dd if=/usr/obj/usr/src/amd64.amd64/release/memstick.img \
    of=/dev/daX bs=1m status=progress
```

The USB boots into 5BSD-branded loader menus and starts `bsdinstall`. The
media uses the UFS label `5BSD_Install`, sets `vfs.root.mountfrom` to that
label, and puts `boot_policy=strict` in the ESP loader environment so the
EFI loader does not fall back to an internal FreeBSD boot pool.

## VM installs

For a VM, use an ISO instead of a deploy script:

```sh
cd /usr/src/release
doas make cdrom
# attach /usr/obj/usr/src/amd64.amd64/release/disc1.iso as install media
```

The memstick image also works in a VM, but attach it as a raw boot disk,
not as a CD-ROM ISO.

## Base packages

To produce the pkgbase repository used for installs and upgrades:

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) packages
pkg repo /usr/obj/<srcdir>/repo/${ABI}/<version>
ln -snf <version> /usr/obj/<srcdir>/repo/${ABI}/latest
```

See the [Packaging](packaging.md) chapter for repository configuration and
migration from FreeBSD pkgbase.

## Troubleshooting

- Boot drops to `mountroot`: check that
  `release/amd64/make-memstick.sh` uses `5BSD_Install` for both
  `/etc/fstab` and the UFS label.
- `pkg update` fails while building the installer repo: confirm
  `/usr/ports` contains `ports-mgmt/pkg`, then rebuild the release target.
- pkgbase staging cannot find a kernel package: `5BSD-kernel-vbsd` must be
  listed in both `release/scripts/pkgbase-stage.lua` and
  `usr.sbin/bsdinstall/scripts/pkgbase.in`.
- A machine boots into an installed system instead of the installer: at
  the loader prompt inspect `show currdev`, `show rootdev`,
  `show vfs.root.mountfrom`, `show loader_brand`, and `lsdev` to confirm
  the USB entry was actually booted.
