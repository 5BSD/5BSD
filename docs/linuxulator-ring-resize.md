# io_uring ring resize: shared squeue implementation and gate

`IORING_REGISTER_RESIZE_RINGS` (opcode 33) replaces the SQ, CQ and SQE
backing store. The operation belongs in shared squeue because it changes
memory mapping, submission and completion state for native and Linux rings.
The Linuxulator passes Linux's registration opcode and handles only ABI
translation; native squeue uses the same engine.

The pinned [Linux 6.18 register implementation](https://github.com/torvalds/linux/blob/v6.18/io_uring/register.c)
requires `IORING_SETUP_DEFER_TASKRUN`, a non-null parameter pointer and
`nr_args == 1`. New parameter flags may contain only `CQSIZE` and `CLAMP`;
layout flags are inherited from the original ring. A shrink that cannot
hold pending SQEs or CQEs fails with `EOVERFLOW` and preserves the old ring.
The Linux implementation preserves the caller's `sq_off.array` field in the
resize output, so legacy-array clients must calculate the new array offset
from the returned CQ size. The shared engine retains that Linux wire behavior
while native registration returns the computed offset.

`tests/sys/kern/linux_iouring_resize.c` passed five pinned Linux 6.18.35
oracle cases, including invalid arguments and occupied SQ/CQ rollback, at
`/tmp/linuxulator-gate-20260919/resize-oracle2.console.log`. Eleven parallel
native/Linux cases in `tests/sys/kern/squeue_options.c` passed the Linux
reference VM at
`/tmp/linuxulator-gate-20260919/resize-shared-oracle13.console.log`.
They check required setup mode, invalid pointers/counts/flags/sizes, empty
grow and shrink, detached old mappings, pending SQ/CQ rollback,
copyout-fault rollback, mapping lifetime across descriptor close, and repeated
resize while another process maps the ring, oversize rejection and clamping,
inherited NO_SQARRAY/SQE128/CQE32 layouts, and a worker completion
published into the replacement CQ. They also submit and reap after resizing, so success-only registration cannot pass.

| Shared test case | Contract checked |
|---|---|
| `resize_requires_defer_shared` | Reject resize without `DEFER_TASKRUN`; old ring state is unchanged. |
| `resize_invalid_shared` | Reject null/bad pointers, wrong counts, unknown flags and invalid sizes. |
| `resize_empty_shared` | Grow, shrink, remap, submit and reap; old SQ/SQE mappings remain readable. |
| `resize_pending_sq_shared`, `resize_pending_cq_shared` | Return `EOVERFLOW` for occupied shrink; preserve work and allow later resize. |
| `resize_fault_rollback_shared` | Read-only output pointer returns `EFAULT` without replacing the ring. |
| `resize_mapping_lifetime_shared` | Forked old mapping survives resize and final descriptor close. |
| `resize_mmap_race_shared` | 64 resizes against 512 concurrent ring/SQE mappings, then submit and reap. |
| `resize_clamp_shared` | Reject oversize without `CLAMP`; clamp SQ/CQ to 32768/65536 with it. |
| `resize_layout_shared` | Preserve `NO_SQARRAY`, `SQE128` and `CQE32` layouts and complete a request. |
| `resize_worker_completion_shared` | An in-flight asynchronous read completes in the new CQ after resize. |

The shared backend allocates a replacement object before taking the ring
mutex, then copies pending SQEs/CQEs and swaps the backing under the mutex.
An mmap lock prevents new mappings from binding to the retired object during
replacement. The old mappings remain readable and detached from the new ring,
matching the pinned Linux oracle. Ring teardown unwires every page and releases
its wired-page charge; mappings that outlive descriptor close remain pageable.
The old object is freed after its last user mapping is removed.

The focused amd64 ZFS-root QEMU run passed all eleven native and eleven Linux
resize cases and returned `kern.squeue.wired_pages` to baseline:
`/tmp/linuxulator-gate-20260919/resize-focus14.console.log`.

The full amd64 ZFS-root QEMU gate passed in
`/tmp/linuxulator-gate-20260919/resize-full-gate13/results.json` with clean
shutdown, healthy ZFS, zero kernel diagnostics, 66 resize runs (eleven cases,
three rounds, both ABIs), 852 squeue-option runs overall, 343 io_uring cases,
57 AIO cases and six swap-discard runs. The kernel had INVARIANTS and WITNESS
enabled. QEMU was 11.1.1 with two virtual CPUs. No candidate kernel or module
was loaded on the host.

| Guest artifact | SHA-256 |
|---|---|
| kernel | `f7fef3efc0af7aba60d8be34a548297fbe21f6a29c7bed5f2059ff2c2b6641e9` |
| linux64.ko | `b383c9e95d750a8f7059c216065c340dba94b385d0444da6a6c199718e7bb3c5` |
| native squeue option test | `b38276c7ebf1024f7eb4a59455f675cd4ec44627c5ed2e1092399bd5da201c6e` |
| Linux squeue option test | `02a6a8b9bb33788eb38dbbd3b875ae982f84143f84156566371c1b43fde46e54` |
