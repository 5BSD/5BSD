# Graphics

5BSD installs graphics drivers from its own hardware repository, built against
the exact kernel on the media. `fwget` selects them automatically. What it will
never do is install a kernel module built by somebody else.

## How it is supposed to work

A release is built with a matching hardware repository: every driver and
firmware package compiled against that release's kernel and stamped with its
SHA256. The whole repository ships on the install media.

At install time `fwget` inspects the machine over PCI and USB and installs only
what is present — on an Intel laptop, the Intel firmware and `drm-kmod`; on an
AMD desktop, the AMD set. The repository is then copied to
`/usr/5bsd-packages/hardware` and enabled in `/etc/pkg`, so `fwget` keeps
working after reboot with no network.

Before installing anything, the packaged kernel hash is compared against the
running `/boot/kernel/kernel`. A mismatch stops the install. There is
deliberately no fallback to the FreeBSD module repository.

## Why there is no fallback

A kernel module is compiled against kernel internals — structure layouts,
inline functions, the linuxkpi layer — not a stable interface. It must come
from the tree that built the kernel it loads into.

FreeBSD stamps each build with `__FreeBSD_version`, and the loader refuses a
module built for a different one:

```
KLD i915kms.ko: depends on kernel - not available or version mismatch
```

5BSD is a fork, so its version never matches upstream's and upstream's
`drm-kmod` never loads. Refusing outright is better than the alternative: a
module built against a *nearly* right tree can load and then misbehave.

This applies to every port containing a kernel module — `nvidia-driver`,
`virtualbox-ose-kmod`, `wireguard-kmod`. Firmware packages are different:
`gpu-firmware-*` holds blobs behind the stable `firmware(9)` interface, carries
no kernel code, and is not kernel-bound.

## Current limitations

**This beta ships without a hardware repository.** None was built for it, so
there is nothing on the media for `fwget` to install and graphics will not come
up. See the interim workaround below. This is a missing build step, not a
missing mechanism.

**Detection is amd64, PCI and USB only.** `fwget` recognises AMD and Intel
graphics; Intel, MediaTek, Qualcomm and Realtek wireless; and Bluetooth and
Ralink devices over USB. There is no device-tree provider, so on aarch64 and
riscv boards — where hardware is described by an FDT rather than enumerated on
PCI — it finds nothing. No port profile exists for those architectures either.

## Interim workaround: build drm-kmod yourself

Until a hardware repository is built for your kernel, build the driver from
ports against your own source.

```sh
# 1. Confirm what you are running
uname -a
sysctl kern.osreldate

# 2. Get ports
git clone --depth 1 https://git.FreeBSD.org/ports.git /usr/ports

# 3. Build against your kernel source
cd /usr/ports/graphics/drm-kmod
make install clean
```

If `/usr/src` no longer matches the running kernel, build against the revision
it came from:

```sh
cd /usr/src
git worktree add /var/tmp/kernsrc <revision-from-uname>
cd /usr/ports/graphics/drm-kmod
make SYSDIR=/var/tmp/kernsrc/sys install clean
```

Then load it:

```sh
kldload i915kms        # or amdgpu, radeonkms
sysrc kld_list+="i915kms"
```

Rebuild after every kernel install. Treat it as part of the kernel, not as an
independent package. This is exactly the burden the hardware repository exists
to remove, which is why it is a workaround and not the documented path.

## X without acceleration

Independent of any driver, X.Org can drive the firmware framebuffer with no
kernel module at all:

```sh
pkg install xorg xf86-video-scfb
```

and in `/usr/local/etc/X11/xorg.conf.d/driver-scfb.conf`:

```
Section "Device"
    Identifier "card0"
    Driver     "scfb"
EndSection
```

`vesa` is an alternative where `scfb` does not attach. Nothing is accelerated:
comfortable for terminals and editors, poor for video, 3D or heavy compositing.
It survives kernel updates untouched.

For appliances, do nothing at all. `vt(4)` gives a console on an attached
display with no driver and nothing to rebuild when the kernel changes.

## Building a hardware repository

Release engineers build one with `release/scripts/hardware-packages.py`, driven
by a port profile such as `release/tools/hardware-ports.amd64`. The profile
lists umbrella ports that expand to every supported device, so it stays short.
Extend it whenever a provider is added to `fwget`.

The build requires a disposable root, a pinned ports tree, and a kernel build
directory hashing to the release kernel. It refuses to run if ports are already
installed there, so no upstream-built dependency can slip into the result.

`release/Makefile` will not produce media without a hardware repository unless
`WITHOUT_HARDWARE_PACKAGES=yes` is set explicitly.
