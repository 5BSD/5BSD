# Linux swapon priority and shared swap-pager allocation

Linux `swapon(2)` assigns an explicit nonnegative priority only when
`SWAP_FLAG_PREFER` is present; the low 15 bits then hold the priority.
Without `PREFER`, those bits do not request explicit priority. The Linux
wrapper now passes either the requested priority or the default `-1` to a
shared kernel helper. Native `sys_swapon` also uses default `-1`, preserving
equal-priority round-robin behavior for native devices. No new public native
syscall number or public `xswdev` ABI is required.

The shared swap pager stores priority per device and scans active devices from
highest to lowest priority when reserving blocks. Within one priority it starts
after the last successful device, preserving round robin. It lowers the
requested allocation size only after all priority levels fail. Linprocfs now
reports the stored value in `/proc/swaps`, reading it under the same lock as
the device metadata.

| Contract | Test | Pinned Linux 6.18.35 | Disposable amd64 ZFS-root VM |
| --- | --- | --- | --- |
| Flag interpretation | Priority bits `7` without `PREFER`; `PREFER|100`; `PREFER|0` | Pass | Pass |
| Metadata | `/proc/swaps` shows default negative, explicit 100 and 0 | Pass | Pass |
| Allocation order | Two swap disks; reserve 4 MiB via native swap-backed `mdconfig` | Linux reference confirms priority metadata | All 4096 KiB on priority-100 disk, zero on default disk |
| Native regression | Two native default devices, two 4 MiB reservations | Not applicable | One reservation on each device |
| Exhaustion fallback | Reserve a further 64 MiB after the first 4 MiB | Not in oracle | Preferred disk fills; 4104 KiB spills to default disk |
| Lifecycle | Repeated activation, device cleanup and clean shutdown | Pass | Pass |

The freestanding `tests/sys/kern/linux_swapon_priority.c` probe has activation
and `-DSWAP_CLEANUP` builds. Both passed the pinned Linux reference; see
`/tmp/linuxulator-gate-20260919/priority-oracle.console.log`. The focused
FreeBSD VM with both allocation and native regression checks passed at
`/tmp/linuxulator-gate-20260919/priority-focus4.console.log`. The
additional exhaustion and fallback VM passed at
`/tmp/linuxulator-gate-20260919/priority-fallback.console.log`; its preferred
disk reached 65528 KiB used while 4104 KiB moved to the lower-priority disk.
The full regression gate at
`/tmp/linuxulator-gate-20260919/swap-priority-full-gate/results.json` passed:
six priority runs, six swapon-flag runs, six swapoff runs, 42 rseq,
343 io_uring, 786 squeue-option, 57 Linux AIO, six native AIO,
36 base and 144 pathname results, zero recognized diagnostics,
healthy ZFS and clean shutdown. The candidate kernel SHA-256 was
`146a6b16ce2116ccb5f8b07bbcabad675a299cdb8eaa0b3a53b56930e50ae90f`;
the Linux64 module SHA-256 was
`da28a4bfe8c3b9781986d34e68ba54b988f2d2bb5c19f9c49ea79cff14462637`;
and the linprocfs module SHA-256 was
`7eddda51d0cbb29dc1eae1932026416d67e97b735a7ec8a5f9eccccabfdd701a`.
The amd64 Linux32 module also compiled successfully; it was not run in the VM.

Discard flags still need native pager behavior on devices that support trim.
The current QEMU virtio disks do not exercise discard. Linux32 and arm64
syscall-table entries require architecture-specific runtime qualification if
their ABI behavior is changed further; the shared allocator itself was tested
on amd64. No candidate kernel or module was loaded on the host.
