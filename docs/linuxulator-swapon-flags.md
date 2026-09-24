# Linux swapon flag validation and gate

Linux's `swapon(2)` ABI includes a second `swap_flags` argument. The prior
Linuxulator table pointed directly at native `sys_swapon`, which ignored it.
The shared Linux compatibility handler now validates bits outside Linux's
currently defined flag mask (`0x7ffff`) before calling native `sys_swapon`.
This matches Linux's ordering: an unknown bit yields `EINVAL` even with a
missing pathname or insufficient privilege. Zero flags retain native
activation behavior. No shared native syscall or kernel backend changed.
The handler is wired into the amd64 Linux64, amd64 Linux32, i386 Linux and
arm64 Linux syscall tables; only amd64 Linux64 has runtime qualification here.

| Contract | Probe checks | Linux 6.18.35 | FreeBSD amd64 VM |
| --- | --- | --- | --- |
| Unknown bits | `0x80000`, high sign bit, mixed known and unknown bits | Pass | Six repetitions pass |
| Error precedence | Unknown bit with missing/NULL path; unknown bit after dropping UID | Pass | Six repetitions pass |
| Zero-flag lifecycle | Missing and invalid path, activate disk, repeated activation (`EBUSY`), deactivate | Pass | Six repetitions pass |
| Privilege | Zero flags with existing and missing paths return `EPERM` after UID drop | Pass | Six repetitions pass |

The freestanding `tests/sys/kern/linux_swapon_flags.c` probe
(SHA-256 `64bcd452d258f359f87e4f45acba6f559eb19df929ed3805300aed432c3a99d4`)
passed a pinned Linux 6.18.35 amd64 reference VM using a dedicated 64 MiB virtio disk. The
Linux oracle console is
`/tmp/linuxulator-gate-20260919/swapon-oracle.console.log`.
The same disk is attached to the disposable FreeBSD ZFS-root QEMU guest in
snapshot mode. The branded guest probe SHA-256 is
`6b12847493f07790232966a905298f8e751b43f2f4f6c586d4d276eb377c5f2c`;
the guest Linux64 module SHA-256 is
`de3f936140dda4323a2bfbc94cf9b15d20fa7b03372d7a6c91b8107aaad996d6`. The full amd64 VM result is
`/tmp/linuxulator-gate-20260919/swapon-flags-gate/results.json`: PASS, with
six swapon, six swapoff, 42 rseq, 343 io_uring, 786 squeue-option,
57 Linux AIO, six native AIO, 36 base and 144 pathname results, zero
recognized diagnostics, healthy ZFS and clean shutdown. No candidate
kernel or module was installed or loaded on the host.

The priority fields are now backed by a shared swap-pager implementation and
qualified separately in [the swap priority gate](linuxulator-swapon-priority.md).
Discard policies on trim-capable devices are described in
[the swap discard gate](linuxulator-swapon-discard.md). Linux32 and arm64
syscall-table entries still need runtime tests.
