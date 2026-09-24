# Linux swapoff implementation and VM gate

The Linux `swapoff(2)` ABI takes a single pathname and no flags. The shared
Linuxulator handler in `linux_misc.c` passes that pathname to the existing
native `sys_swapoff` backend with flags zero. This uses the native swap-device
lifecycle, privilege check and serialized deactivation. The Linux wrapper
translates the native `EINVAL` for an inactive directory path to Linux's
`EISDIR`; it leaves native callers unchanged. The handler is wired into the
amd64 Linux64, amd64 Linux32, i386 Linux and arm64 Linux syscall tables. The
amd64 Linux64 runtime behavior is qualified below; the other ABI entries need
runtime qualification before claiming equal coverage.

The freestanding `tests/sys/kern/linux_swapoff.c` probe uses a dedicated
64 MiB virtio disk. It checks missing path (`ENOENT`), directory (`EISDIR`),
invalid and NULL pointers (`EFAULT`), empty path (`ENOENT`), inactive swap area
(`EINVAL`), successful `swapon` then `swapoff`, repeated `swapoff` (`EINVAL`),
symlink deactivation and removal, and privilege rejection (`EPERM`)
for both an existing and a missing path after dropping UID. The unbranded probe (SHA-256 `c2d5f85edf91b474f3b57b1603279f64c57ba4ed8a6e8d1e9d1aee2dc559d8ad`)
passed the pinned Linux 6.18.35 amd64 reference guest; the console evidence is
`/tmp/linuxulator-gate-20260919/swap-oracle.console.log`. No swap is activated
on the build host. QEMU uses a private snapshot of the swap disk, and the
FreeBSD guest boots its base system from ZFS.

| Contract | Probe checks | Linux 6.18.35 | FreeBSD amd64 VM |
| --- | --- | --- | --- |
| Path lookup and errno | Missing/empty paths, directory, invalid and NULL pointers, inactive device | Pass | Six repetitions pass |
| Activation lifecycle | Native-alias `swapon`, Linux `swapoff`, second `swapoff`, symlink to active device and removal | Pass | Six repetitions pass |
| Privilege precedence | Unprivileged existing and missing paths return `EPERM` | Pass | Six repetitions pass |
| Isolation | Dedicated 64 MiB virtio disk; root filesystem stays ZFS | Pass | Six repetitions pass |

The gate executes the probe three times from ZFS and three times from tmpfs.
Each run activates and deactivates the disposable disk and requires clean
post-deactivation state. The strict parser requires all six result rows and
also checks the full Linuxulator regression suite and a clean guest shutdown.
The branded probe (SHA-256 `066a05961080afd80e0462fd7c06fc0896856529596cf617984eab1065bb3a6d`)
passed the full amd64 ZFS-root gate at
`/tmp/linuxulator-gate-20260919/swapoff-gate4/results.json`: six swapoff,
42 rseq, 343 io_uring, 786 squeue-option, 57 Linux AIO, six native AIO,
36 base and 144 pathname cases, zero recognized diagnostics, healthy ZFS
and clean shutdown. The guest module SHA-256 was
`b6913f6b719f71c5d74ac65d3e29f0485c76940c3411720e6193eaf770b4f056`.
No candidate kernel or module was installed or loaded on the host. The
expanded swapoff probe also passed the later combined swapon/swapoff gate at
`/tmp/linuxulator-gate-20260919/swapon-flags-gate/results.json`, with the
current Linux64 module and six swapoff rows.

Remaining swapoff-specific qualification: races with device removal or
concurrent swapon/swapoff, swap exhaustion and interrupted
migration, and Linux32/arm64 runtime tests. Those must have pinned Linux
reference results and VM cases before claiming full Linux equivalence.
