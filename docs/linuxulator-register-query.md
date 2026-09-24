# io_uring register query: Linux ABI and VM gate

`IORING_REGISTER_QUERY` (opcode 35) is a Linuxulator-only discovery command. It
returns the supported request/register opcode counts and feature, setup, enter,
and SQE flag masks. The shared squeue engine supplies the masks it actually
admits and routes a query on an existing Linux ring through its normal ring
ownership and registration-restriction checks. The Linuxulator implements the
Linux header/data layout, linked-list traversal, blind `fd == -1` form,
per-entry Linux errors, and zero-filled output extensions. Native squeue has
no query ABI callback and continues to reject this opcode.

The ABI and behavior are pinned to [Linux v6.18 query.h](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/io_uring/query.h),
[Linux v6.18 query.c](https://github.com/torvalds/linux/blob/v6.18/io_uring/query.c),
and a Linux 6.18.35 amd64 reference guest. The reference oracle is
`/tmp/linuxulator-gate-20260919/query-oracle5.console.log`; every named case
passed there. The query returns counts describing the UAPI inventory, while
the bitmasks describe modes the backend accepts. Request opcode support still
requires `IORING_REGISTER_PROBE` for the per-opcode answer.

| Named test | Positive and negative contract |
|---|---|
| `blind_basic` | Blind query succeeds; returned data has valid counts, nonempty masks, one query opcode, and zero padding. |
| `fd_and_count` | Ring-fd form succeeds; NULL blind list is empty; nonzero `nr_args`, invalid fd, and wrong fd type return their Linux errors. |
| `linked_headers` | Two linked headers are independently populated and agree on the inventory. |
| `invalid_entries` | Unsupported query opcode, reserved bits, nonzero input result, and zero data size each produce the correct per-entry failure with zero size and output. |
| `sizes_and_faults` | Invalid header/data pointers fail; short output is truncated to the declared size; larger output is zero-filled, including a 4097-byte request. |
| `cycle_limit` | A self-linked header returns `ERANGE` at the 1000-entry limit after writing the last successful entry. |
| `protected_pages` | Read-only header/data outputs and inputs crossing a protected page fail with `EFAULT`. |

`tests/sys/kern/linux_iouring_query.c` is a freestanding Linux binary. Its
ATF wrapper and the disposable guest gate compile or stage it as a Linux ELF.
The VM gate runs every named case three times on a ZFS-root amd64 guest and
requires exact zero status per case. The shared squeue regression suite also
runs both native and Linux front ends after the mask refactor.

The focused candidate guest passed the first six groups three times at
`/tmp/linuxulator-gate-20260919/query-focus2.console.log`; the added
protected-page group passed three times at
`/tmp/linuxulator-gate-20260919/query-protected-focus.console.log`.
The full amd64 ZFS-root guest passed at
`/tmp/linuxulator-gate-20260919/query-full-gate3/results.json`: 21 query
runs, 852 shared squeue-option runs, 343 io_uring cases, 57 Linux AIO cases,
six swap-discard cases, zero recognized kernel diagnostics, healthy ZFS and
clean shutdown. It used QEMU 11.1.1, two virtual CPUs, and a WITNESS/
INVARIANTS kernel. No candidate kernel or module was loaded on the host.

| Guest artifact | SHA-256 |
|---|---|
| kernel | `a5b8909e3da76c0c993e29d18b7756f6dd5091fc3125c6262391e711c8c47b06` |
| linux64.ko | `7b39dd28967de5e3c9a69890e522edbef29a27fdc317bd026065aeb7f7299d4d` |
| Linux query test | `b30db774be03b07c8a1936ea9dfd0fa4f6f17d335ebb2e54d0f668930d80bdd3` |
