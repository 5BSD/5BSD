# io_uring parameter memory regions: shared backing and VM gate

`IORING_REGISTER_MEM_REGION` (opcode 34) registers one page-aligned region.
With a kernel-owned region, registration returns mmap offset `0x20000000` and
the ring fd maps zeroed pages. With `IORING_MEM_REGION_TYPE_USER`, the kernel
pins the supplied pages and the returned mmap offset stays zero. The optional
`IORING_MEM_REGION_REG_WAIT_ARG` flag exposes the region to
`IORING_ENTER_EXT_ARG_REG`; Linux requires the ring to remain disabled until
that wait region is registered. An enter call then treats its argument as an
aligned byte offset into the pinned region rather than a userspace pointer.

The region backing, mapping lock, pinned-page lifetime, memory charging and
registered-wait reader are in shared squeue, so native squeue and Linux
io_uring use the same mechanism. Linuxulator retains syscall numbering and
Linux errno translation. The wire structures live in the shared io_uring ABI
header because native squeue uses the same registration command and enter
flag; no new native syscall number was added.

The ABI comparison is pinned to [Linux v6.18 UAPI](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/io_uring.h),
[registration](https://github.com/torvalds/linux/blob/v6.18/io_uring/register.c),
[region memory handling](https://github.com/torvalds/linux/blob/v6.18/io_uring/memmap.c),
and [registered wait handling](https://github.com/torvalds/linux/blob/v6.18/io_uring/io_uring.c).
`tests/sys/kern/linux_iouring_mem_region.c` passed all eight named cases on
the pinned Linux 6.18.35 oracle at
`/tmp/linuxulator-gate-20260919/mem-region-oracle6.console.log`.
`tests/sys/kern/squeue_options.c` passed its four new shared cases against
that oracle at
`/tmp/linuxulator-gate-20260919/mem-region-shared-oracle.console.log`.

| Linux-specific test | Contract |
|---|---|
| `basic_mapping` | Kernel-owned region returns a usable mmap offset, maps writable pages and rejects duplicate registration. |
| `wait_region` | A disabled ring accepts a registered wait region; an indexed timeout works after enabling. |
| `invalid_registration` | Wrong count, null/invalid pointer, reserved fields, unsupported flags, wrong setup state, bad size/alignment and inconsistent user backing return the reference errors without consuming the registration slot. |
| `user_backing` | Page-aligned user memory is pinned, retains a zero mmap offset and supports registered waits. |
| `copyout_rollback` | Read-only descriptor output fails with `EFAULT`; a writable retry succeeds. |
| `wait_invalid` | Unknown wait flags, wrong structure size, misaligned index and out-of-bounds index fail before blocking. |
| `user_unmap_lifetime` | Registered wait still works after unmapping the original pinned user pages. |
| `protected_inputs` | A registration header or region descriptor crossing into a protected page returns `EFAULT`. |

| Shared test | Contract |
|---|---|
| `param_region_mmap_shared` | Native/Linux mmap offset, duplicate rejection, submit/complete health and mapping lifetime past ring close. |
| `param_region_invalid_shared` | Counts, pointers, flags, sizes and output-fault rollback followed by successful retry. |
| `param_region_wait_shared` | Registered timeout and invalid wait flags/offsets through both ABIs. |
| `param_region_user_shared` | Pinned user memory supports a registered wait and rejects ring-fd remapping. |

The focused amd64 ZFS-root guest passed all 48 runs (four shared cases in
both ABIs and eight Linux cases, each for three rounds) at
`/tmp/linuxulator-gate-20260919/mem-region-shared-focus2.console.log`.
The full amd64 ZFS-root QEMU gate passed at
`/tmp/linuxulator-gate-20260919/mem-region-full-gate2/results.json`:
24 dedicated memory-region runs, 876 shared squeue-option runs (including the
new native/Linux cases), 343 io_uring cases, 21 query runs, 57 Linux AIO cases,
six swap-discard cases, zero recognized kernel diagnostics, healthy ZFS and
clean shutdown. The guest used QEMU 11.1.1 with two virtual CPUs and a
WITNESS/INVARIANTS kernel. No candidate kernel or module was loaded on the
host. `min_wait_usec` in registered waits was rejected because the shared
backend did not advertise `IORING_FEAT_MIN_TIMEOUT` at that gate. The later
[minimum-wait phase](linuxulator-min-wait.md) added this option to shared
squeue and tested both front ends.

| Guest artifact | SHA-256 |
|---|---|
| kernel | `7f4488418d2694132de54384d7a36dcae3b41b591185b308b19510b32ec818c4` |
| linux64.ko | `c12792858f393a13365d5a244223cf5444a2821d084da652f75da13c1bb92fa1` |
| Linux memory-region test | `66ffcfecb71409874b2ad957b03422827f721fabf8e9f460c6df052439b792b1` |
| native shared-option test | `17ebf7b60c39d602dacb087f00e01810f67b3b08356dfe484ea784f0dc37f35b` |
| Linux shared-option test | `c61017e3e48e91031de7a177361fd42450c05a3f1834875f4580abf9dadd76bf` |
