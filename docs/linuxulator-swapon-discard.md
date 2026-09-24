# Linux swap discard policies

Linux `swapon(2)` accepts `SWAP_FLAG_DISCARD` (`0x10000`), with optional
`SWAP_FLAG_DISCARD_ONCE` (`0x20000`) and `SWAP_FLAG_DISCARD_PAGES` (`0x40000`).
The Linuxulator maps these to the shared swap pager. Without the base discard
bit, the subpolicy bits have no effect. With no subpolicy, both once and page
trim are requested. When both subpolicy bits are present, ONCE takes
precedence, as on Linux.

The shared GEOM swap backend checks `GEOM::candelete`. For ONCE it discards
usable swap space during activation in bounded 16 MiB requests, skipping the
reserved header. For PAGES
it submits BIO_DELETE as pages are freed. A freed range stays unavailable
until deletion completes, so a concurrent swap allocation cannot reuse it
before the device finishes the trim. Swapoff waits for outstanding deletes
before closing the GEOM consumer. A delete error still releases the range;
`vm.stats.swap.discard_errors` records the failure. The backend ignores discard
on providers that do not advertise it, and avoids page trim when the sector
size cannot divide the VM page size. Native `swapon(2)` keeps its existing
zero-trim default.

`tests/sys/kern/linux_swapon_discard.c` covers five flag combinations and
readback preservation where no trim should occur. A separate
`-DDISCARD_PAGES_ONLY` build leaves swap active for the guest to reserve and
release 4 MiB through `mdconfig`, then deactivate. The guest checks the
`vm.stats.swap.discard_once`, `discard_pages`, and `discard_errors` counters
for each of three ZFS and three tmpfs repetitions on a disposable
trim-capable virtio disk. The QEMU runner attaches that disk with
`discard=unmap` and requires all six `GATE_SWAP_DISCARD` rows.

The revised probe passed a pinned Linux 6.18.35 VM oracle at
`/tmp/linuxulator-gate-20260919/discard-oracle3.console.log`: exit 0 and
three completed block discard operations covering 393192 sectors. Reads after
discard are deliberately not asserted to return zero; the device does not
promise that. The final bounded-request kernel passed the full amd64 ZFS-root QEMU gate at
`/tmp/linuxulator-gate-20260919/swap-discard-full-gate4/results.json`:
six discard rows, six swap-priority rows, six swapon-flag rows, six swapoff
rows, 343 io_uring cases, 786 squeue-option cases, 57 Linux AIO cases,
36 base cases, and 144 pathname cases. There were zero recognized kernel
diagnostics, ZFS was healthy and the guest shut down cleanly. The staged
kernel SHA-256 is `00cf6add9516e8a2ea5d7034ff834d386f3b4c47890abeebb92b6f73a40bc5cf`;
Linux64 module SHA-256 is
`b383c9e95d750a8f7059c216065c340dba94b385d0444da6a6c199718e7bb3c5`.
No candidate kernel or module was loaded on the host.
