# Linux64 `PTRACE_LISTEN` design and oracle

Status: implemented and VM-qualified for amd64 Linux64. The exact Linux
6.18.35 and Linux 7.1.5 oracle behavior, focused runs, full-gate results, and
frozen artifacts are under `/tmp/linuxulator-listen-20260924`. No candidate
kernel or module was installed or loaded on the host.

## Linux contract

LISTEN is valid only for a seized tracee whose current siginfo is a
`PTRACE_EVENT_STOP`. It leaves the tracee stopped, removes ordinary ptrace
request/wait visibility, and waits for a group-stop state change or INTERRUPT.
It is not equivalent to CONTINUE.

The oracle performs the complete stop sequence rather than treating the first
SIGSTOP interception as a group stop:

1. SEIZE a running tracee.
2. Send SIGSTOP and observe the signal-delivery stop `0x137f`.
3. Continue with SIGSTOP and observe group `PTRACE_EVENT_STOP` `0x80137f`.
4. LISTEN, require WNOHANG to report nothing, and prove the tracee executes no
   userspace instructions.
5. In one tracee, INTERRUPT and observe the retained group-stop status
   `0x80137f`.
6. In another tracee, send SIGCONT and observe a new event stop
   `0x80057f` (`PTRACE_EVENT_STOP` with SIGTRAP).

Both kernels produced the same statuses and completed the probe successfully.
The behavior matches Linux's generic
[ptrace implementation](https://github.com/torvalds/linux/blob/master/kernel/ptrace.c)
and [signal state machine](https://github.com/torvalds/linux/blob/master/kernel/signal.c).

## Required ownership

The native ptrace core must own the stopped-but-listening state because normal
ptrace authorization, wait visibility, SIGCONT processing, detach, tracer exit,
and concurrent INTERRUPT all cross the Linux frontend boundary. A kernel-only
LISTEN request may expose frontend validation/setup callbacks, as SEIZE and
INTERRUPT do, but no new FreeBSD userspace ptrace request is required.

The Linuxulator must own seized-state validation, recognition of the two-stage
SIGSTOP transition, Linux event-status/siginfo translation, and Linux errno
selection. Linux32 remains outside this phase.

A correct backend must prove all of these transitions:

- ordinary ATTACH and a non-event signal stop reject LISTEN with EIO;
- the first seized SIGSTOP stop rejects LISTEN; the later group event accepts;
- while listening, WNOHANG is empty, the tracee remains stopped, and ordinary
  ptrace requests see no actionable ptrace stop;
- INTERRUPT clears listening and retraps without changing `0x80137f`;
- SIGCONT clears the group stop and retraps as `0x80057f`;
- detach, SIGKILL, tracer exit, exec and tracee exit cannot retain listening
  state or suspended threads;
- repeated LISTEN/INTERRUPT/SIGCONT and concurrent signal races do not duplicate
  wait records or lose wakeups.

The current FreeBSD signal path deliberately ignores SIGCONT for an ordinary
traced stop. LISTEN therefore needs explicit shared state and wait notification;
a Linuxulator-only CONT approximation would violate the oracle and is rejected.

## Implementation

The native ptrace core owns the stopped-but-listening flag, hides listeners
from ordinary stopped-target requests, handles INTERRUPT and SIGCONT wakeups,
and publishes a kernel-only group-stop transition without allowing the target
to execute userspace. Detach, kill, and trace teardown clear that shared state.
No new native userspace ptrace operation is exposed.

The amd64 Linux64 frontend owns seized/event validation and Linux status and
siginfo translation. It distinguishes the initial `SIGSTOP` signal-delivery
stop (`0x137f`) from the group event (`0x80137f`), preserves that status across
LISTEN/INTERRUPT, and translates LISTEN/SIGCONT to `0x80057f`. Group-stop
`GETSIGINFO` reports `SIGSTOP/0x8013`; the SIGCONT event reports
`SIGTRAP/0x8005`. A zero-result `wait4(WNOHANG)` leaves the caller's status
word untouched, matching both oracle kernels.

## Tests and acceptance evidence

`linux_ptrace_listen` has five independent groups covering missing/running and
traditional-attach errors, rejection of the first signal-delivery stop,
ignored LISTEN arguments, exact group/SIGCONT statuses and siginfo, WNOHANG
visibility, stopped execution, ordinary-request rejection while listening,
16 repeated LISTEN/INTERRUPT cycles, SIGKILL cleanup, detach, and normal exit.

- The exact permanent binary passed 20/20 runs on Linux 6.18.35 and 20/20 on
  Linux 7.1.5.
- It passed 25/25 runs from the amd64 disposable ZFS root and 25/25 from a
  tmpfs working directory with WITNESS/INVARIANTS enabled.
- The integrated amd64 ZFS-root gate passed 48 syscall cases, 63 AIO rows,
  1,146 squeue-option rows, 476 main io_uring cases, 39 no-mmap, 33 SQPOLL,
  24 memory-region, 21 query, 63 ptrace-register, 21 ptrace-option, and three
  each of SEIZE, INTERRUPT, LISTEN, native ptrace, and capmode ptrace rows.
  It reported no nonzero results or recognized diagnostics, all final ring
  resources were zero, ZFS was healthy, and shutdown synced all buffers.

The implementation is architecture-neutral in the shared ptrace/signal core
and amd64-specific in the Linux64 frontend. This phase changes no arm64 code,
so the established architecture-specific runtime rule does not require an
arm64 VM rerun. Linux32 remains unchanged.
