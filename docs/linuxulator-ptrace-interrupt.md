# Linux64 `PTRACE_INTERRUPT`

Status: amd64 Linux64 `PTRACE_INTERRUPT` is implemented. Its Linux-oracle and
focused amd64 ZFS-root VM gates pass. Integrated full-gate evidence is recorded
below only after a complete run. No host kernel or module is installed or
loaded by this work.

## Contract

`PTRACE_INTERRUPT` applies only to a relationship created by `PTRACE_SEIZE`.
A running tracee enters a signal-free `PTRACE_EVENT_STOP`; the request ignores
its `addr` and `data` arguments. `PTRACE_GETSIGINFO` reports `SIGTRAP` with an
event-stop code. A request made while the tracee is already in a ptrace stop is
remembered and creates another event stop after `PTRACE_CONT`,
`PTRACE_SINGLESTEP`, or `PTRACE_SYSCALL`. Restarting with CONT or SYSCALL also
cancels a single-step mode that was interrupted before it executed. An ordinary
`PTRACE_ATTACH`
relationship rejects INTERRUPT with `EIO`. A missing or inaccessible trace
relationship reports `ESRCH`.

The behavior follows Linux's generic ptrace implementation and UAPI constants:
[ptrace.c](https://github.com/torvalds/linux/blob/master/kernel/ptrace.c) and
[ptrace.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/ptrace.h).

`PTRACE_LISTEN` is qualified by the later [LISTEN follow-up](linuxulator-ptrace-listen.md). LISTEN requires a distinct group-stop
listening state whose wait visibility and `SIGCONT` behavior cannot be
represented by resuming the process. It must not be implemented as an alias for
CONTINUE.

## Ownership

The native ptrace core owns the kernel-only `PT_KERN_INTERRUPT` operation. It
checks and serializes the trace relationship under the process-tree and process
locks, lets the emulation frontend validate the relationship, and creates a
ptrace stop without queueing or delivering a signal. The helper is not exposed
as a FreeBSD userspace ptrace request.

The Linuxulator owns seized-state tracking, Linux errno selection,
`PTRACE_EVENT_STOP` wait-status and siginfo translation, and the pending-stop
rule across Linux restart requests, including cancellation of stale single-step
state after a synthetic stop. Native `PT_ATTACH`, native stop reporting,
and Linux32 behavior are unchanged.

## Tests

`linux_ptrace_interrupt` is a freestanding Linux64 test. Each invocation checks:

- missing-target `ESRCH`;
- the ordinary ATTACH initial `SIGSTOP` and INTERRUPT rejection with `EIO`;
- a running seized target, ignored `addr` and `data`, exact event-stop status,
  and exact `PTRACE_GETSIGINFO` signal and code;
- a queued INTERRUPT while stopped followed by CONT and a later event stop;
- a queued INTERRUPT followed by SYSCALL and a later event stop;
- a queued INTERRUPT followed by SINGLESTEP, accepting Linux's permitted
  step/event ordering while requiring the promised event stop and a clean later
  CONT;
- preservation of an existing `SIGUSR1` signal stop, followed by the promised
  event stop;
- detach, continued execution, and the tracee's exact normal exit status.

The test is registered with ATF and requires the disposable ZFS-root VM. The
expanded test binary passed 20 iterations on Linux 6.18.35 and 20 on Linux
7.1.5. It then passed 25 iterations from ZFS and 25 from tmpfs under the
WITNESS/INVARIANTS candidate. ZFS remained healthy, shutdown synced all
buffers, QEMU exited zero, and the console contained no recognized kernel
diagnostic. Evidence is under
`/tmp/linuxulator-interrupt-20260923`; the test binary SHA-256 is
`71d60c3bb71a17b58098eaf55f2565ed964f6bf3f78f88ee0a14de13a0e1a958`.

## Integrated gate

The accepted amd64 ZFS-root gate is
`/tmp/linuxulator-interrupt-20260923/candidate/full-run3/results.json`. It
passed three INTERRUPT executions, three SEIZE executions, 63 register-ptrace
executions, 21 ptrace-option executions, three native-ptrace executions, and
three ptrace-capmode executions. The surrounding gate passed 48 direct ABI
cases, 63 Linux AIO executions, 78 dedicated shared-RWF executions, 1,146
shared-option executions, 476 main io_uring cases, three native-squeue
executions, 39 NO_MMAP cases, 33 SQPOLL cases, 24 memory-region cases, and 21
query cases. `ioprio_send_zc_fixed_vectorized` passed. No result was nonzero,
no recognized kernel diagnostic occurred, all final resource counters were
zero, ZFS was healthy, shutdown synced all buffers, and QEMU exited zero.

The result JSON SHA-256 is
`d7b46b457389c95c06e7d6ffc18f60852de65ccfcfca25f23ffba7346a697abf`.
The image SHA-256 is
`ede69718a9e495af74d5a17e259b7c3a0545351409886c7a4d30c984ef526f8c`;
the kernel SHA-256 is
`4d2ee5f99223dc13883d80472a73fb0e7c96053bbbbb5509b977562e6b59c0dd`;
and the Linux64 module SHA-256 is
`89934b308f302bb603bc664f74fb98ec1632d26a86b7b35d18667292f08a433a`.
Arm64 runtime is waived for this phase because the shared ptrace changes are
architecture-neutral and the frontend support is amd64 Linux64; no
arm64-specific code changed.
