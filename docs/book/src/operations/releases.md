# Release Engineering

Release artifacts are built from `/usr/src/release`. The tooling is
FreeBSD's release framework, adapted so every image installs from 5BSD
pkgbase packages and carries 5BSD branding.

## Targets

`release/Makefile` provides the standard media and image targets:

```sh
cd /usr/src/release
doas make obj
doas make cdrom          # disc1.iso
doas make memstick       # memstick.img (also mini-memstick)
doas make release        # real-release + vm-release + cloudware-release + oci-release
```

Cloud and container variants live alongside: `Makefile.vm` (generic VM
disks), `Makefile.ec2`, `Makefile.azure`, `Makefile.gce`, `Makefile.oci`
(container images), `Makefile.firecracker`, and `Makefile.vagrant`.
Per-target media scripts sit in `release/<arch>/` (e.g.
`amd64/make-memstick.sh`, which labels installer media `5BSD_Install`).
Helper scripts are under `release/scripts/`, notably `pkgbase-stage.lua`
(stages base packages onto media — it must list `5BSD-kernel-vbsd`) and
`5BSD-base-offline.conf` (the offline installer repo definition).

## VM image construction: vmimage.subr

`release/tools/vmimage.subr` builds VM disk images from pkgbase rather
than `installworld`. `vm_base_packages_list` selects the package sets that
make up a full system:

- `5BSD-set-base` (plus `5BSD-set-base-dbg` unless `WITHOUT_DEBUG_FILES`)
- `5BSD-set-kernels` (plus `-dbg` kernel symbols unless
  `WITHOUT_KERNEL_SYMBOLS`)
- `5BSD-set-lib32` on amd64/aarch64/powerpc64
- `5BSD-set-tests`, and `pkg` itself so images can upgrade themselves

`vm_install_base` runs `pkg install -r 5BSD-base` against the build repo
into the image root and writes `/usr/local/etc/pkg/repos/5BSD.conf`
(`5BSD-base: { enabled: yes }`) so the installed image keeps pulling base
updates from a 5BSD repo. Setting `NOPKGBASE` falls back to the classic
`installworld installkernel distribution` path. A
`vm_extra_filter_base_packages` hook lets per-image configurations
(`release/tools/*.conf`, e.g. `ec2-base.conf`, `basic-cloudinit.conf`)
filter the package list.

VM images boot on the serial console: `vm_install_base` appends
`console="comconsole"` to `/boot/loader.conf` so images are drivable over
a `bhyve -l com1` serial line for automated boot verification (headless
bhyve has no framebuffer, so `vidconsole` must not be listed — pairing it
yields "no valid consoles!"). This was added in commit `bb9f5be0208`.

## Branding

Commit `7214cc04ece` ("release: brand 5BSD boot and image artifacts")
rebrands the boot chain and media: loader menus and `newvers.sh`, EFI
`boot1`, the i386/powerpc boot blocks, ISO/memstick volume labels across
all architectures, OCI image configurations, the AMI builder, and the
`bsdinstall` partedit/bootconfig/hostname scripts. Commit `bb9f5be0208`
adds the boot logo itself, `stand/images/5bsd-logo.png`, installed to
`/boot/images`.

## Observability tools in release builds

Commit `bb9f5be0208` ("release: package observability tools and refresh
VM branding") wires the ObservableBSD tools into package production:
`packages/hwtlm` joins the unconditional package list and
`packages/bsdinstruments` is added under `MK_DTRACE` in
`packages/Makefile`, so release package sets and media repos ship
`5BSD-bsdinstruments` and `5BSD-hwtlm` (each with `dbg` and `man`
subpackages). `bsdtrace` has its own package metadata
(`release/packages/ucl/bsdtrace-all.ucl`) and is amd64-only.

## Release media contents

The installer media (memstick and disc1) carry an offline pkgbase
repository built during the release, plus `pkg(8)` itself, so
`bsdinstall` performs a network-free pkgbase install. The installer
environment uses the UFS label `5BSD_Install` and pins
`vfs.root.mountfrom` to it, with `boot_policy=strict` in the ESP loader
environment to prevent EFI fallback into a resident FreeBSD boot pool.
See the [Building](building.md) chapter for the exact build steps and
troubleshooting.

## Boot verification

Release work is validated by booting the produced images. The serial
console default above exists for this purpose, and the tree carries
capsule VM boot tests exercised against release-built images
(commits `9b148611045` "release: extend Capsule VM boot testing" and
`495541ff50d` "release: make Capsule PID 1 VM test reproducible"). Related
hardening: `b6fff311996` makes source-tree VM images fail safely and
`80f46b38aeb` avoids duplicate EFI fstab entries.

## Status

The working tree currently carries uncommitted modifications to
`release/tools/vmimage.subr` (and other release/test files) on the `dev`
branch; this chapter describes the committed state as of `bb9f5be0208`.
