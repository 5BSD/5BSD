# Linux64 pending signals, tracing relationships and multicast modes

Scope: amd64 Linux64. No Linux32, io_uring or squeue implementation/tests.
This batch adds options and lifecycle behavior to existing calls, not syscall
numbers. The named contracts passed the Linux reference and BSD VM checks below.

## Contracts

* `ptrace(PTRACE_PEEKSIGINFO)`: a 16-byte argument contains a 64-bit queue
  offset, 32-bit flags and signed 32-bit count. Flag 1 selects the process
  queue; zero selects the target thread queue. Copy queued signal records
  without consuming them. Return the number copied; preserve a positive
  partial count on later output faults. Reject unknown flags and negative
  counts. Empty/out-of-range queries return zero. Native tracing ownership,
  target-stop and credential checks remain mandatory before user-memory access.
* Explicit tracing attach/TRACEME and successful detach reset Linux options
  under the native tracing locks. Failed requests leave the relationship
  intact. The reattach stop reports a zero event message instead of the old exec
  message; cached event classification and message fields are cleared. Options must not leak TRACESYSGOOD,
  TRACEEXEC or TRACEEXIT into a new tracing relationship.
* IPv4 and IPv6 source joins can change an empty EXCLUDE membership into
  INCLUDE when no source list is retained. A list emptied by incremental
  unblocks still fixes its mode, as on Linux; full empty replacement clears
  that restriction. Last-source INCLUDE removal leaves the membership.
  Both the legacy IPv4 and RFC 3678 interfaces are covered.

## Implementation ownership

Linuxulator translates signal records and implements PEEKSIGINFO using the
existing held-target ptrace callback and native signal queues. It releases the
process lock for copyout, checks for pending tracer signals and yields between
records. It retains no queue pointers across lock release and never dequeues.

The generic `process_ptrace` event runs at native relationship changes while
proc/proctree locks are held; handlers must not sleep. The Linux64 module uses
it to reset Linux option state atomically, including native debugger attach.
Fork-follow option inheritance still occurs after child emulation state is
created. Module unload unregisters the callback.

Native IPv4/IPv6 multicast permits the mode transition during its existing
membership transaction. It changes the pending mode only after source graft
allocation succeeds; existing merge rollback restores the old state.

## Tests and evidence

Artifacts: `/tmp/linuxulator-signal-modes-20260922/`.
Linux reference is Alpine 3.24.1 with Linux 6.18.35-0-virt, in disposable QEMU.
BSD runtime tests use a disposable amd64 ZFS-root image with INVARIANTS/WITNESS
and two vCPUs. Host activity is limited to building and running QEMU.

`linux_ptrace_pending` covers shared and thread-private queues, ordering,
offsets, repeated non-consuming reads, metadata, unknown flags, negative/zero
counts, dead targets, input/output faults, read-only and guard-page buffers,
partial-copy counts, repeated lifecycle and detach/reattach with exec/syscall/
exit options. Tests run as root and unprivileged after exec.

`linux_mcast_filter transitions` covers all three address/option forms and
32 membership cycles per form. Native multicast probes exercise the same
transition and preserve negative-mode checks. Existing native/Linux tracing,
XSAVE, peer-name and multicast suites are retained for regressions.

Reference contracts: Linux v6.18
[ptrace](https://github.com/torvalds/linux/blob/v6.18/kernel/ptrace.c),
[IPv4 multicast](https://github.com/torvalds/linux/blob/v6.18/net/ipv4/igmp.c),
and [IPv6 multicast](https://github.com/torvalds/linux/blob/v6.18/net/ipv6/mcast.c).

## Qualification results (2026-09-22)

* `oracle5.console.log`: all 18 named root/unprivileged executions passed on
  Linux 6.18.35-0-virt, including ordinary queued signals, the reattach message
  reset and packet delivery after filter-mode transitions.
* `regression1-run/results.json`: **405/405 passed**, exactly matching the
  expected inventory, with no missing/extra records or recognized kernel
  diagnostics. This includes 42 pending-signal/lifecycle executions, 12 mode
  transition executions, and 351 preceding tracing/register/XSAVE/socket/
  multicast/native regression executions. The pool was healthy and the guest
  synced and powered off cleanly.
* `client1.console.log`: Linux GDB 16.3 followed fork/exec through exit status 7.
  Embedded Python used libc ptrace to inspect a queued signal twice without
  consuming it (`PYTHON_PEEK_PASS`) and verified real UDP delivery following
  empty-EXCLUDE to INCLUDE conversion (`PYTHON_TRANSITION_PASS`). Existing
  peer-name and multicast client checks also passed. GDB emitted the existing
  return-to-NX signal and unavailable proc-memory/symbol-path warnings; those
  broader debugger limitations are unchanged.
* `module1.console.log`: three unload/reload cycles passed, with native ptrace
  exercised while Linux64 was unloaded and Linux reattach/peek checks before
  and after. No stale callback diagnostics occurred; the VM powered off cleanly.
* Kernel and Linux64 builds completed with warnings treated as errors. New
  Linux and native test binaries compiled with `-Wall -Wextra -Werror`.
  The Python runner compiles and the guest shell script passes syntax checks.

The gate is `tools/test/linuxulator/qemu-signal-modes.py`, a dedicated runner
which does not invoke io_uring/squeue tests. It fails on missing or duplicate
case records, nonzero exits, missing completion/health/shutdown markers,
timeouts and recognized kernel diagnostics. Exact VM commands, source
snapshots, artifact hashes and retained earlier failures are recorded in the
artifact manifest. No host kernel or module was installed or loaded.

Earlier Linux exploration incorrectly expected a retained exec message at the
reattach stop; the reference returns zero. The first BSD focused run also found
that invalid detach signals returned EINVAL instead of Linux EIO. Both issues
were corrected, and the final reference and full affected-suite runs use the
corrected assertions and implementation.

## Remaining limits

This does not implement SEIZE/INTERRUPT/LISTEN or complete Linux per-thread
tracing. The thread-private queue tests target the process leader; nonleader
queue lookup is not separately qualified. Signal generation, ordinary-signal
coalescing and native fallback pending bits without stored siginfo retain
existing native behavior; the new request walks actual queued records and
never fabricates missing metadata. Tracer-signal interruption is implemented
but a deterministic interruption during a long peek was not injected.
No allocation-failure injection or namespace/jail matrix was added. Existing
ptrace permission/Capsicum regressions pass; this batch adds no namespace or
Linux32 support. The multicast restrictions unrelated to these transitions
remain as recorded in the preceding batch.
