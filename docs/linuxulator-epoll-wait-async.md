# io_uring EPOLL_WAIT readiness and cancellation

The Linux v6.18 `IORING_OP_EPOLL_WAIT` path validates that `off`, `rw_flags`,
`buf_index` and `splice_fd_in` are zero. It sends available events immediately;
when the epoll set is empty, it leaves the request pending until the epoll fd
becomes readable. The prior Linuxulator path used a zero-timeout
`linux_epoll_pwait` call and completed with result zero on an empty set.

The shared squeue readiness-retry path now treats EPOLL_WAIT as a read-ready
operation. The Linuxulator front end returns its internal `EAGAIN` when the
zero-timeout check finds no events. Squeue arms the existing kqueue wait on the
epoll fd, reissues the original SQE when ready, and uses its existing request
cancellation and teardown machinery. The Linuxulator alone validates the
Linux-specific reserved SQE fields and translates the epoll result. No native
squeue opcode or syscall ABI was added.

`epoll_wait_deferred` checks that an empty set produces no CQE and that a later
eventfd write delivers the event and user data. `epoll_wait_cancel` cancels a
pending wait and checks both CQEs and the untouched event buffer.
`epoll_wait_badfields` checks four reserved fields, each with a separate
negative submission. All three cases passed a Linux 6.18.35 oracle at
`/tmp/linuxulator-gate-20260919/epoll-wait-oracle.console.log` and three ZFS
plus three tmpfs rounds each at
`/tmp/linuxulator-gate-20260919/epoll-focus.console.log`.

A registered epoll descriptor is armed through a held-file knote in shared
squeue. `epoll_wait_fixed` closes the original descriptor, checks an invalid
registered slot, waits for a later event, and cancels a second wait. The Linux
6.18.35 oracle passed at
`/tmp/linuxulator-gate-20260919/epoll-fixed-oracle.console.log`; three ZFS
and three tmpfs focused rounds passed at
`/tmp/linuxulator-gate-20260919/epoll-fixed-focus.console.log`.

An ambient epoll descriptor is now captured at submission with its file
identity and original capability rights. Each issue installs a temporary
rights-preserving descriptor, so a parked request still targets its original
epoll instance after the submitting process closes and reuses the numeric fd.
The same held-file knote arms readiness and request cancellation deletes it by
request identity. `epoll_wait_close_reuse` validates the original event data
after closing the epoll fd and allocating a replacement with the same number.
The Linux 6.18.35 oracle passed at
`/tmp/linuxulator-gate-20260919/epoll-reuse-oracle.console.log`; three ZFS
and three tmpfs focused rounds of close/reuse, deferred delivery, cancellation
and fixed-file wait passed at
`/tmp/linuxulator-gate-20260919/epoll-reuse-focus.console.log`.

`epoll_wait_close_reuse_cancel` checks that a cancelled wait still targets
its original epoll instance after the numeric fd has been reused, that the
wait CQE is `-ECANCELED`, and that the event buffer remains untouched. It
passed the Linux oracle at
`/tmp/linuxulator-gate-20260919/epoll-reuse-cancel-oracle.console.log`
and three ZFS plus three tmpfs focused candidate rounds at
`/tmp/linuxulator-gate-20260919/epoll-reuse-cancel-focus.console.log`.

`epoll_wait_ready_cancel_race` forks an eventfd writer and races readiness
against `ASYNC_CANCEL` over 16 iterations. It requires exactly one wait CQE:
either one event with `-ENOENT` from cancellation or `-ECANCELED` with an
untouched buffer. Linux 6.18.35 passed at
`/tmp/linuxulator-gate-20260919/epoll-race-oracle.console.log`; three ZFS
and three tmpfs candidate rounds (96 race attempts) passed at
`/tmp/linuxulator-gate-20260919/epoll-race-focus.console.log`.

The first 351-case full gate passed at
`/tmp/linuxulator-gate-20260919/epoll-full-gate/results.json`: 351 io_uring,
918 shared squeue-option, 39 NO_MMAP and 33 SQPOLL executions, zero recognized
diagnostics, zero nonzero results, zero final request/file counters, healthy
ZFS and clean shutdown. The 353-case full gate containing fixed-file and
ambient close/reuse passed at
`/tmp/linuxulator-gate-20260919/epoll-reuse-full-gate2/results.json` with the
same clean resource and shutdown results. The 354-case gate including cancellation after descriptor reuse passed at
`/tmp/linuxulator-gate-20260919/epoll-reuse-cancel-full-gate/results.json`:
354 io_uring, 918 shared squeue-option, 39 NO_MMAP and 33 SQPOLL
executions, zero recognized diagnostics and nonzero results, healthy ZFS and
clean shutdown. The final 355-case full gate including the readiness/cancellation race
passed at `/tmp/linuxulator-gate-20260919/epoll-race-full-gate/results.json`:
355 io_uring, 918 shared squeue-option, 39 NO_MMAP and 33 SQPOLL
executions, zero recognized diagnostics and nonzero results, zero final
issuer/file/request counts, healthy ZFS and clean shutdown. Its artifact
hashes and oracle/focused evidence are recorded in
`/tmp/linuxulator-gate-20260919/epoll-race-full-gate/manifest.json`.
