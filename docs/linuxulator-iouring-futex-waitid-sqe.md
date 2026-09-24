# io_uring FUTEX and WAITID SQE validation

Linux requires zero in the unused `len`, `futex_flags`, `buf_index`, and
`file_index` fields of `IORING_OP_FUTEX_WAIT` and `IORING_OP_FUTEX_WAKE`.
`IORING_OP_FUTEX_WAITV` also requires zero in `fd`, `addr2`, and `addr3`;
its `len` holds the vector size. The Linuxulator front end now enforces those
fields before calling the shared futex syscall backend. The existing
`futex_waitv_eagain` production test incorrectly set `fd = -1`; it now uses
zero, as Linux requires.

Linux `IORING_OP_WAITID` rejects nonzero `addr`, `buf_index`, `addr3`, and
`waitid_flags`. The Linuxulator front end now validates those fields before
calling `linux_waitid`. These are Linux SQE ABI rules; no native squeue opcode
or syscall ABI was changed.

The `futex_sqe_badfields` case checks 15 separate negative submissions across
WAIT, WAKE, and WAITV. `waitid_sqe_badfields` checks four negative submissions
and verifies that rejected operations leave the siginfo buffer untouched.
The corrected WAITV `EAGAIN` case, FUTEX_WAIT `EAGAIN`, FUTEX_WAKE, WAITID
`ECHILD`, and WAITID child lifecycle provide positive and immediate-error
regressions. All passed a Linux 6.18.35 oracle at
`/tmp/linuxulator-gate-20260919/futex-sqe-oracle.console.log` and
`/tmp/linuxulator-gate-20260919/waitid-sqe-oracle.console.log`. The focused
candidate ZFS-root QEMU VM passed 24 futex and 18 WAITID executions, each
case three times on ZFS and three times on tmpfs, at
`/tmp/linuxulator-gate-20260919/futex-sqe-focus.console.log` and
`/tmp/linuxulator-gate-20260919/waitid-sqe-focus.console.log`.

The 357-case production image passed the full amd64 ZFS-root QEMU gate at
`/tmp/linuxulator-gate-20260919/futex-waitid-sqe-full-gate/results.json` (manifest
in the same directory). The gate also passed 918 shared squeue-option cases, 39
NO_MMAP cases, and 33 SQPOLL cases, with zero recognized diagnostics, zero
nonzero results, zero final issuer/file/request counts, a healthy ZFS pool, and
a clean shutdown. The full VM run took 881 seconds. This result was the reserved-field gate;
later [pending-futex](linuxulator-iouring-futex-pending.md) and
[WAITID lifecycle](linuxulator-waitid-lifecycle.md) gates qualify asynchronous
wake, cancellation and teardown and include them in the production inventory.
