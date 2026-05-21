# Building 5BSD

This builds 5BSD from source and creates a USB installer that boots
directly into `bsdinstall`.

## Requirements

- FreeBSD or 5BSD build host
- `/usr/ports` with at least `ports-mgmt/pkg`
- About 30 GB free under `/usr/obj`
- USB drive for the installer image

For a small ports checkout:

```sh
doas git clone --depth 1 --sparse https://git.FreeBSD.org/ports.git /usr/ports
cd /usr/ports
doas git sparse-checkout set ports-mgmt/pkg Mk Templates Keywords
```

## Build

```sh
cd /home/koryheard/Projects/5BSD
doas make -j$(sysctl -n hw.ncpu) buildworld
doas make -j$(sysctl -n hw.ncpu) buildkernel

cd release
doas make obj
doas make memstick
```

The image is written to:

```sh
/usr/obj/home/koryheard/Projects/5BSD/amd64.amd64/release/memstick.img
```

The release target stages a fresh system, adds the installer
environment, builds an offline pkgbase repo, installs `pkg` on the
media, and creates the bootable memstick image. No external installer
script is required.

## Write To USB

Find the target device:

```sh
geom disk list
```

Write the image, replacing `daX` with the USB device:

```sh
doas dd if=/usr/obj/home/koryheard/Projects/5BSD/amd64.amd64/release/memstick.img of=/dev/daX bs=1m status=progress
```

## Expected Boot

The USB should show the 5BSD installer loader branding and then start
`bsdinstall`. If a machine lands in an installed system instead, first
confirm it booted the USB entry you intended. On the loader prompt,
use:

```sh
show currdev
show rootdev
show vfs.root.mountfrom
show loader_brand
lsdev
```

The installer media uses the UFS label `5BSD_Install`, sets
`vfs.root.mountfrom` to that label, and puts `boot_policy=strict`
in the ESP loader environment so EFI loader does not fall back to an
internal FreeBSD boot pool.

## VM Installs

For a VM, use release media instead of a custom deploy script. The
cleanest path is usually an ISO:

```sh
cd /home/koryheard/Projects/5BSD/release
doas make cdrom
```

Then attach:

```sh
/usr/obj/home/koryheard/Projects/5BSD/amd64.amd64/release/disc1.iso
```

as the VM install media and run `bsdinstall` normally against the VM
disk.

The memstick image is also usable in a VM, but attach it as a raw boot
disk, not as a CD-ROM ISO:

```sh
/usr/obj/home/koryheard/Projects/5BSD/amd64.amd64/release/memstick.img
```

## Troubleshooting

If the image drops to `mountroot`, check that
`release/amd64/make-memstick.sh` uses `5BSD_Install` for both
`/etc/fstab` and the UFS label.

If `pkg update` fails while building the installer repo, check that
`/usr/ports` contains `ports-mgmt/pkg`, then rebuild the release
target.

If pkgbase staging cannot find a kernel package, make sure
`FreeBSD-kernel-5bsd` is listed in both
`release/scripts/pkgbase-stage.lua` and
`usr.sbin/bsdinstall/scripts/pkgbase.in`.
