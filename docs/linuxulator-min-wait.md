# io_uring minimum wait interval

`io_uring_enter(GETEVENTS|EXT_ARG)` accepts `min_wait_usec` in
`io_uring_getevents_arg`. The same field works in an
`IORING_ENTER_EXT_ARG_REG` record after `IORING_REGISTER_MEM_REGION`.
Both ABIs use the shared squeue wait implementation; Linux64 only translates
the syscall and errno. Setup advertises `IORING_FEAT_MIN_TIMEOUT` because
that implementation is available through both paths.

The first completion threshold is still `min_complete`. If it is reached,
the wait returns immediately. Otherwise the minimum interval starts when
the wait begins. At its end, any partial CQ batch makes the wait succeed.
With an empty CQ and no ordinary timeout, the call returns ETIME on Linux
(ETIMEDOUT natively). With an ordinary timeout, an empty wait continues
toward that deadline. Linux 6.18 arms the minimum timer first even when the
ordinary timeout is shorter, so the ordinary timeout is checked after the
minimum interval. Pending poll targets get one nonblocking scan at expiry;
signals and partial completions keep the established wait precedence.

The reference is Linux v6.18
[`io_cqring_wait`](https://github.com/torvalds/linux/blob/v6.18/io_uring/io_uring.c)
and [`io_should_wake`](https://github.com/torvalds/linux/blob/v6.18/io_uring/io_uring.h).
The Linux 6.18.35 amd64 QEMU oracle passed `min_wait_shared`, including
minimum-only expiration, a longer ordinary timeout, a shorter ordinary
timeout, partial CQ batches, registered arguments, invalid flags, and
invalid signal-mask pointers. The oracle log is
`/tmp/linuxulator-gate-20260919/min-wait-oracle3.console.log`.

The candidate amd64 ZFS-root QEMU focus passed three rounds each of
native squeue `min_wait_shared`, Linux64 `min_wait_shared`, and Linux64
`enter_args`. The log is
`/tmp/linuxulator-gate-20260919/min-wait-focus4.console.log`.
The full amd64 ZFS-root [implementation gate](linuxulator-implementation-gate.md)
passed at `/tmp/linuxulator-gate-20260919/min-wait-full-gate/results.json`:
882 shared-option runs, 343 io_uring runs, 24 dedicated memory-region runs,
21 query runs, 57 Linux AIO runs, zero recognized kernel diagnostics, healthy
ZFS, and a clean shutdown. The guest used QEMU 11.1.1, two virtual CPUs,
and a WITNESS/INVARIANTS kernel. Kernel SHA-256 was
`ea2bfbafaa901eec5f557e554dc13c4a39116e10d16ed628e705608071bad821`;
linux64.ko SHA-256 was
`ea7d30d8452da10fdf9d7ca0ee5b126d17d842dca950bfd75b0b4394c2d08763`.
No candidate kernel or module was loaded on the host. Arm64 is reserved for
architecture-specific work in this phase.
