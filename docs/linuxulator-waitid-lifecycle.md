# io_uring WAITID lifecycle and pending requests

The WAITID SQE places `which` in `len`, the child ID in `fd`, options in
`file_index`, and the siginfo pointer in `addr2`. `addr`, `buf_index`,
`addr3`, and `waitid_flags` must be zero. Linuxulator validates and resolves
Linux IDs and options, including resolution of a pidfd at submission, then uses
the same wait and siginfo conversion as direct Linux `waitid`. The shared
squeue engine owns pending request lifetime, CQEs, links, cancellation and
ring teardown. It starts at most one process-context pump per ring when a
WAITID actually has to wait. That pump checks child state without blocking
the submitter or occupying a general I/O worker; it wakes promptly for
submission/cancellation and otherwise probes at a bounded ten-millisecond
interval. No native squeue WAITID opcode or new host syscall ABI was added.

The required Linux 6.18.35 oracle and amd64 ZFS-root guest matrix includes:

| Case | Positive or negative contract |
|---|---|
| `waitid_lifecycle` | Live child with `WNOHANG`, invalid which/ID/options, `WNOWAIT`, exit siginfo/status, consumption and `ECHILD` |
| `waitid_pidfd` | Live pidfd, `WNOWAIT`, reaping, wrong/negative/closed descriptors and post-reap `ECHILD` |
| `waitid_stop_continue` | `SIGSTOP`/`SIGCONT` child-state codes and status, then exit |
| `waitid_sqe_badfields` | Four reserved-field rejections without touching the siginfo buffer |
| `waitid_pending_exit` | Submission returns while the child is alive; no premature siginfo write; completion reaps the child |
| `waitid_null_info` | A null siginfo pointer succeeds both for a live child with `WNOHANG` and for the eventual exit |
| `waitid_exit_cancel_race` | Exit versus cancellation resolves without losing a consumed child event, over eight iterations per invocation |
| `waitid_cancel_pending` | Same-ring user-data cancellation gives wait `-ECANCELED`, cancel result `1`, clears `si_signo`, and leaves the child waitable |
| `waitid_pending_pidfd_close` | Closing the pidfd after submission does not retarget or fail the pending wait |
| `waitid_close_pending` | Closing the ring cancels a pending wait without consuming the child |
| `waitid_cancel_op_all` | Opcode-wide cancellation resolves two waits once, returns Linux's result `1`, clears both `si_signo` fields, and preserves both children |
| `waitid_link_timeout` | A linked deadline cancels the wait, reports timeout result `1`, clears `si_signo`, and leaves the child waitable |

The original direct-WAITID lifecycle/pidfd/stop cases passed their Linux
oracles and earlier full ZFS-root gates. The six new pending cases passed the
Linux 6.18.35 oracle in
`/tmp/linuxulator-gate-20260919/waitid-pending-oracle.console.log`,
`waitid-extra-oracle.console.log`, and `waitid-more-oracle.console.log`.
The additional null-siginfo case passed the Linux oracle at
`/tmp/linuxulator-gate-20260919/waitid-null-case-oracle.console.log`.
A 32-iteration Linux exit/cancel oracle and the exact eight-iteration
production case passed at
`/tmp/linuxulator-gate-20260919/waitid-race-oracle.console.log` and
`waitid-race-case-oracle.console.log`. All eight are in the mandatory
377-case inventory. The focused candidate run
covers all ten named cases plus `waitid_echild` and a pending-futex regression
in three ZFS and three tmpfs rounds at
`/tmp/linuxulator-gate-20260919/waitid-async-focus-v4.console.log`.
All 72 focused executions returned zero; the ZFS pool was healthy and the
guest shut down cleanly. The null-siginfo case and two pending-wait regressions also run three
ZFS and three tmpfs rounds at
`/tmp/linuxulator-gate-20260919/waitid-null-focus.console.log`; all 18
executions passed with clean shutdown. The exit/cancel race passed three ZFS and
three tmpfs rounds (48 iterations total) at
`/tmp/linuxulator-gate-20260919/waitid-race-final.console.log`, with a
healthy pool and clean shutdown. The complete amd64 ZFS-root gate passed at
`/tmp/linuxulator-gate-20260919/waitid-race-full-gate/results.json` in
1041.2 seconds. It recorded 377 io_uring cases, 918 shared squeue-option
executions, 39 NO_MMAP and 33 SQPOLL executions, zero nonzero results or
recognized diagnostics, zero final request/file/issuer counts, healthy ZFS
and clean shutdown. `manifest.json` beside the result pins the frozen image,
module, kernel, test binary, oracle/focus logs and source hashes. The
candidate kernel and linux64 module ran only in disposable QEMU guests.

The Linux source reference is
[io_uring WAITID](https://github.com/torvalds/linux/blob/v6.18/io_uring/waitid.c).
Any further WAITID option must add a Linux-oracle positive case, a negative
case that verifies errno and side effects, ZFS and tmpfs guest executions,
and a passing full amd64 ZFS-root gate before promotion.
