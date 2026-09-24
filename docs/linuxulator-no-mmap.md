# Caller-owned io_uring rings and registered-fd-only setup

`IORING_SETUP_NO_MMAP` uses two page-aligned caller buffers: `cq_off.user_addr`
is the shared SQ/CQ ring, and `sq_off.user_addr` is the SQE array. Shared
squeue pins both buffers for ring lifetime and maps those pages into the kernel
for submission, completion, and worker access. It owns the pin and memory
accounting, while the caller owns the mappings. Mapping the ring fd again is
rejected. The Linuxulator continues to translate the setup syscall and errno.
Native squeue uses the same backing implementation.

`IORING_SETUP_REGISTERED_FD_ONLY` requires `NO_MMAP` and returns an index in
the calling thread's ring registry. `IORING_ENTER_REGISTERED_RING` and the
registered-ring register flag use that index. Setup rolls the slot back if
writing parameters to userspace fails. A full registry returns EBUSY. Slot
unregistration releases the ring reference; thread cleanup releases any
remaining slots.

The contract follows Linux v6.18
[`io_allocate_scq_urings`](https://github.com/torvalds/linux/blob/v6.18/io_uring/io_uring.c)
and [`io_create_region`](https://github.com/torvalds/linux/blob/v6.18/io_uring/memmap.c).
The pinned Linux 6.18.35 amd64 QEMU oracle passed eleven dedicated groups:
basic NOP submission, NO_SQARRAY/SQE128/CQE32 layout combinations, read-only
and malformed addresses, continued access through a shared alias after the
original mappings are removed, registered-only setup, registered submission
and unregistration, all 16 slots filling, copyout rollback, and successful and
invalid resize with replacement caller-owned buffers. One dual-ABI
NO_MMAP group and one dual-ABI registered-only group also passed the Linux
oracle. Logs:
`/tmp/linuxulator-gate-20260919/nommap-oracle5.console.log`,
`nommap-shared-oracle.console.log`, and
`nommap-fdonly-shared-oracle.console.log`.

The candidate amd64 ZFS-root QEMU focus passed three rounds of all eleven
dedicated groups and both native/Linux shared groups in
`/tmp/linuxulator-gate-20260919/nommap-resize-focus.console.log`.
The full gate passed in
`/tmp/linuxulator-gate-20260919/nommap-final-gate/results.json`:
894 shared-option runs, 33 dedicated NO_MMAP runs, 343 io_uring runs, 24
memory-region runs, 21 query runs, and 57 Linux AIO runs, with zero diagnostic
failures and clean guest shutdown. The guest kernel SHA256 was
`b4ce0cc1b779e648a6886b407e0695970f4ef86e73d3b5a8d4b5fb0aad1caf65`;
the linux64 module SHA256 was
`47b672a9e1d8ce1ff510911ab44b3c1777d07cfadf17fec068f005b94c8d16ad`.
Arm64 is reserved for architecture-specific changes in this phase.
