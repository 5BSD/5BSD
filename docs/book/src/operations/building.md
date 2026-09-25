# Building

5BSD is built from one source tree with the FreeBSD build system: `buildworld`
and `buildkernel` produce the system, `make packages` turns it into a pkgbase
repository, and `release/` turns that repository into installer media and VM
images. 5BSD keeps the FreeBSD build because it keeps the FreeBSD ABI; what
changes is the kernel that is built, the package names that come out, and a
handful of defaults chosen for a system whose trusted computing base is
compiled in rather than loaded. This chapter covers the loop from checkout to
repository; [Installing](installing.md) and [Upgrading](upgrading.md) cover
what happens on the target.

For anything the FreeBSD Handbook already explains, such as `make.conf`,
`src.conf` mechanics, cross-building or `installworld`, read build(7) and the
Handbook. Only the 5BSD differences are here.

## Requirements

A build host running 5BSD or FreeBSD 16-CURRENT with the same major libc
version, about 30 GB free under `/usr/obj`, and a static `pkg`:
`/usr/local/sbin/pkg-static` from the `ports-mgmt/pkg` port. Release media
also needs a ports checkout containing at least `ports-mgmt/pkg`; a sparse
clone is enough:

```sh
git clone --depth 1 --sparse https://git.FreeBSD.org/ports.git /usr/ports
cd /usr/ports && git sparse-checkout set ports-mgmt/pkg Mk Templates Keywords
```

## World and the GENERIC kernel

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld
make -j$(sysctl -n hw.ncpu) buildkernel        # KERNCONF=GENERIC is the default
```

`GENERIC` is the 5BSD kernel. There is no overlay configuration: the 5BSD
block at the end of `sys/amd64/conf/GENERIC` sets `nooptions
COMPAT_FREEBSD32` and compiles in `OES`, `MAC_ABAC`, `MAC_VERIEXEC` (with
`MAC_VERIEXEC_SHA256` and `device mac_veriexec_parser`) and `device
cryptodev`; the upstream part of the file already carries `HWT_HOOKS`,
`RACCT`, `BHYVE_SNAPSHOT`, `device vsock` and `device virtio_vsock`. The
mac_capability plane itself is not an option at all: every
`sys/dev/mac_capability/*.c` file is listed as `standard` in
`sys/conf/files`, so a kernel that boots is a kernel with the plane. Any
custom configuration that starts with `include GENERIC` inherits the whole
set. `GENERIC-DEBUG` adds `INVARIANTS`, `WITNESS` and `WITNESS_SKIPSPIN` for
test kernels; `GENERIC-KASAN`, `-KCSAN` and `-KMSAN` remain as upstream ships
them.

The kernel ships as the package `5BSD-kernel-generic` (`-dbg` carries the
symbols). Kernel modules that belong to a tool travel with that tool's
package: a module Makefile that sets `PACKAGE=` is tagged through
`sys/conf/kmod.mk` and materialised into the world stage by
`Makefile.inc1`, so `bhyve`, `linux` and similar packages carry their own
`.ko` files.

Two tree-wide stances follow from the kernel. 5BSD is 64-bit only:
`share/mk/src.opts.mk` puts `LIB32` in `BROKEN_OPTIONS`, and there is no
32-bit compatibility layer to build. And with `MK_DTRACE` on, `Makefile.inc1`
stages `cddl/lib/drti` and `cddl/lib/libdtrace` early so the USDT provider
objects that most base daemons now carry link against the target-ABI
`drti.o`, including in cross builds.

## Build knobs that matter

| Knob | Default | Where | Effect |
|---|---|---|---|
| `BIND_NOW` | on | `share/mk/bsd.opts.mk` | Every binary is linked `DF_BIND_NOW`; with `RELRO` this is full RELRO. `WITHOUT_BIND_NOW` restores lazy binding. |
| `BHYVE_SNAPSHOT` | on (amd64 only) | `share/mk/src.opts.mk` | Save and restore support in bhyve(8) and bhyvectl(8). `WITHOUT_BHYVE_SNAPSHOT` disables it. |
| `LIB32` | broken | `share/mk/src.opts.mk` | Cannot be enabled. |
| `DTRACE` | on | src.conf(5) | Also controls libdtrace staging, `bsdinstruments`, `dtrace`, `dwatch` and every USDT provider in base. |
| `PMC` | on | src.conf(5) | Gates `libipt` and therefore the `bsdtrace` Intel PT tool (amd64). |
| `KERNCONF` | `GENERIC` | build(7) | Kernel configuration(s) to build. |

The two 5BSD options are documented in `tools/build/options/WITHOUT_BIND_NOW`
and `WITHOUT_BHYVE_SNAPSHOT`, which is where src.conf(5) is generated from.

## Packages

5BSD is pkgbase-native. `share/mk/bsd.pkg.pre.mk` sets
`PKG_NAME_PREFIX=5BSD`, so every package is `5BSD-<name>`. A file's package
is decided by the `PACKAGE=` variable in the Makefile that installs it (or a
`tags=package=` entry in `etc/mtree`); the package itself is defined in
`packages/<name>/Makefile` (`PKG_SETS`, dependencies, subpackages) with its
description in `release/packages/ucl/<name>-all.ucl`. `packages/Makefile` is
the master list, and option-conditional packages are added there with
`SUBDIR.${MK_xxx}`. The 5BSD daemons that live in the `runtime` package
(BSDFilesystem, BSDPower, BSDTime, BSDExtension, BSDNamespace, BSDVM) have
no package of their own; the others (`capsule`, `switchboard`, `bsdlog`,
`bsdtrace-provider`, `oes`, `mac-abac` and so on) do, and each library and
daemon has a matching `<name>-tests` package. `release/packages/create-sets.sh`
generates the metapackages `5BSD-set-base`, `5BSD-set-kernels` and
`5BSD-set-tests` (plus `-dbg` variants); there is no `set-lib32`.

### Building the repository

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld buildkernel
make packages PKG_CMD=/usr/local/sbin/pkg-static
```

`packages` stages world and kernel into `${OBJTOP}/worldstage` and
`${OBJTOP}/kernelstage`, creates one package per plist, and signs the
repository if `PKG_REPO_SIGNING_KEY` is set. The result lands in
`${REPODIR}/${PKG_ABI}/${PKG_VERSION}` with a `latest` symlink, which with the
defaults is:

```
/usr/obj/usr/src/repo/FreeBSD:16:amd64/<version>/
/usr/obj/usr/src/repo/FreeBSD:16:amd64/latest -> <version>
```

The ABI string stays `FreeBSD:16:amd64` on purpose: ports packages from the
FreeBSD repositories must keep installing (see
[Packages and Ports](../compat/packages.md)). `amd64.amd64/packages/` under
`/usr/obj` is staging, not the repository.

Two rules keep this step from failing in ways that are hard to diagnose:

*Always `buildkernel` before `make packages`.* The kernel package and every
module package are cut from the kernel stage, which `buildworld` never
touches. Packaging after a kernel or module change without rebuilding the
kernel ships stale modules, and the symptom appears at boot on the target,
not in the build. If a `git checkout` reset source mtimes so the incremental
build skipped a module, `touch` the sources and rebuild.

*Use `pkg-static`.* The dynamic `pkg` from ports tracks the newest ports ABI
and may reference libc symbol versions the tree has not adopted; the failure
is an `Undefined symbol "fts_open@FBSD_1.9"` (or similar) at signing time.
`pkg-static` carries its own libc. Do not patch base libc to satisfy the
dynamic tool; a libc symbol-version bump is a deliberate ABI change, never a
side effect of packaging. `release/Makefile` picks `/usr/local/sbin/pkg-static`
on its own when it exists; `Makefile.inc1` does not, so pass `PKG_CMD`.

### The stage-directory gotcha

`WSTAGEDIR` and `KSTAGEDIR` default to `${OBJTOP}/worldstage` and
`${OBJTOP}/kernelstage`. A previous root-owned run leaves those directories
owned by root; an unprivileged rebuild in the same object tree then fails
partway through staging with permission errors rather than at the start.
Either remove the leftovers as root or point the stage directories somewhere
you own:

```sh
make packages PKG_CMD=/usr/local/sbin/pkg-static \
    WSTAGEDIR=/usr/obj/stage/world KSTAGEDIR=/usr/obj/stage/kernel
```

The plists and the repository are unaffected by where staging happens.

### Repository configuration

There is no public 5BSD package service, so the base repository is a local
`file://` one. `usr.sbin/pkg/5BSD.conf.in` installs `/etc/pkg/5BSD.conf` with
a disabled `5BSD-base` entry pointing at
`file:///usr/obj/usr/src/repo/${ABI}/latest`; `docs/pkg/5BSD.conf.sample` is
the enabled form (`priority: 100`) to copy to
`/usr/local/etc/pkg/repos/5BSD.conf`, and `docs/pkg/FreeBSD.conf.sample`
disables `FreeBSD-base`. [Upgrading](upgrading.md) walks through both.

## Release media

```sh
cd /usr/src/release
make obj
make memstick       # memstick.img (and mini-memstick)
make cdrom          # disc1.iso
make release        # real-release + vm-release + cloudware-release + oci-release
```

Every image is pkgbase-native. `release/Makefile` defaults `NODISTSETS=yes`
whenever pkgbase is in use, builds the world's repository with the same
`packages` target, and copies it onto the media as
`/usr/5bsd-packages/offline` together with
`release/scripts/5BSD-base-offline.conf`, so the installer never needs a
network for the base system. `release/scripts/pkgbase-stage.lua` selects the
packages and must list `5BSD-kernel-generic`, as must
`usr.sbin/bsdinstall/scripts/pkgbase.in`. The knobs:

| Variable | Meaning |
|---|---|
| `NOPKGBASE` | Put dist tarballs on the media instead of packages (the classic `installworld` path). |
| `NODISTSETS` | Omit dist sets and `MANIFEST`; defaults on with pkgbase. |
| `PKGBASE_PKG_PACKAGE`, `PKGBASE_PKG_SHA256` | A prebuilt target-architecture `pkg` package to embed instead of building it from `/usr/ports`; the checksum, name and ABI are verified. |
| `PKG_CMD` | Defaults to `/usr/local/sbin/pkg-static` when present. |
| `VOLUME_LABEL` | `5BSD_Install`; the media's `loader.conf` pins `vfs.root.mountfrom` to it. |

The installer environment written onto the media sets `capability_plane="NO"`
in `/boot/loader.conf` (the media has no installed-program ledger for a
service manager to run), `hostname="5bsd-installer"`, and an fstab from
`write_installer_fstab` in `release/scripts/tools.subr` that mounts tmpfs on
`/Capabilities/Run`, `/tmp` and `/var`. The ESP loader environment carries
`boot_policy=strict` so the EFI loader never falls into a boot pool already
on the machine. Write a memstick with `dd if=memstick.img of=/dev/daX bs=1m
status=progress`; for a VM prefer `disc1.iso`, or attach the memstick image
as a raw disk rather than a CD.

### VM and cloud images

`release/Makefile.vm` builds from packages (`release/tools/vmimage.subr`),
selects `5BSD-set-base`, `5BSD-set-kernels`, `5BSD-set-tests` and the
`5BSD-pkg-bootstrap` package so images can update themselves without the
ports `pkg`, and defaults `VMFS=zfs` with `VMFSLIST=zfs ufs`. Images get a
`zroot/usr/local` dataset, a serial console (`console="comconsole"`) so
`bhyve -l com1` can drive them, and `/etc/waspnest-build-id`. The cloud
profiles (ec2, gce, azure, oci, vagrant) draw from the `5BSD-base`
repository name, and there are Raspberry Pi profiles under `release/tools/`
that are experimental.

### Integrity baseline

`release/packages/base-integrity.sh create|check|veriexec <root> <manifest>`
records an mtree baseline of an installed root, checks a root against it,
or exports a veriexec manifest from it. It is unsigned and opt-in; see
[Verified Execution](../capability/veriexec.md) for what the kernel does
with the manifest.

## Tests

`make buildworld` builds the test suites when `MK_TESTS` is on, and they
ship as the `*-tests` packages collected in `5BSD-set-tests`. Which suites
run on a build host, which need a VM with the plane up, and which need a
plane-off boot is the subject of [Testing](../develop/testing.md); the
short version is that anything opening `/dev/mac_capability` directly needs
`capability_plane="NO"`.

## Continuous integration

The only workflow in the tree is `.github/workflows/handbook.yml`: on a push
to `main` that touches `docs/book/**` it installs mdBook 0.4.40, runs
`mdbook build docs/book`, and deploys the result to GitHub Pages. There is
no CI build of world, kernel or packages; the QEMU and bhyve gates described
in [Testing](../develop/testing.md) are run by hand.

## Status and limits

Everything above is committed. Known rough edges: src.conf(5) still prints
i386 and armv7 defaults that the 64-bit-only universe never uses; the
repository is unsigned unless you set `PKG_REPO_SIGNING_KEY`; and while
`make packages` cuts one `5BSD-kernel-<name>` package per configuration in
`KERNCONF` (`Makefile.inc1`, `create-kernel-packages`), the installer and
`release/scripts/pkgbase-stage.lua` only know `5BSD-kernel-generic`, so a
custom kernel is installable with `pkg` but not selectable in `bsdinstall`.
