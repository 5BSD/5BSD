# amd64 Linux ptrace register access

The later [XSAVE-write and multicast batch](linuxulator-xstate-mcast-options.md)
extends the XSAVE-read-only contract recorded below.

Status: named Linux-reference cases, focused FreeBSD VM matrices and the full
amd64 ZFS-root regression gate pass. No host installation has been performed.

The implementation covers legacy GETFPREGS/SETFPREGS and GETREGSET/SETREGSET
for NT_PRFPREG; SETREGSET for NT_PRSTATUS; and GETREGSET for NT_X86_XSTATE.
Legacy GETREGS/SETREGS and GETREGSET/NT_PRSTATUS share the amd64 transaction
so target FS/GS bases and rax are handled consistently. No Linux32 or arm64
support is added. XSAVE writes and additional ptrace event operations remain
outside this batch. No io_uring/squeue implementation changes are part of it.

Reference: Linux 6.18 x86/kernel/ptrace.c and kernel/ptrace.c, with runtime
comparison against the existing Linux 6.18.35 disposable oracle guest.
The ABI is a 216-byte general register record, a 512-byte FXSAVE record,
and a hardware-sized standard XSAVE image with the supported feature mask
at byte 464. Regsets use the Linux64 iovec layout. Lengths must be multiples of eight, and larger requests are clamped to the
regset size. FP writes require a complete 512-byte record (zero and partial
writes fail EINVAL); GPR writes accept prefixes and commit words in order,
including progress before a later user-memory fault. Unknown notes return
EINVAL. XSAVE reads without native XSAVE return ENODEV. Reserved output bytes
are initialized, and invalid MXCSR writes fail before changing FP state.

The native addition is a kernel-only ptrace callback request. It uses existing
p_candebug/proc_can_ptrace checks, target selection, process hold and
P2_PTRACEREQ serialization. Native userspace cannot invoke the internal request.
Callbacks enter/return with PROC_LOCK held and can drop it for user copies
while the ptrace request hold prevents a concurrent continue operation.
Linux formats and policy remain in the amd64 Linuxulator helper. Register
writes use native proc_write_* privilege checks and mark debugger mutation.

Tests: tests/sys/kern/linux_ptrace_registers.c. Named cases cover
legacy/regset FP reads, FP writes with resumed execution, partial FP writes,
invalid MXCSR, target TLS bases, full/partial GPR writes with resumed execution,
rax preservation, invalid TLS bases, lengths, memory faults, unknown notes,
XSAVE/AVX layout, protected memory, output bounds, permission rejection,
unprivileged tracing after exec, partial-fault progress, TLS writes,
thread-specific target selection and repeated child lifetimes. The focused
final matrix passed 63 Linux case executions, three native FP roundtrips /
internal-request denials and three capmode checks. Separate Linux and BSD
no-XSAVE runs passed. Guests used two vCPUs; the BSD kernel enables INVARIANTS
and WITNESS. These are named register contracts, not complete ptrace conformance.

The tests validate GPR reads/writes at ordinary breakpoint stops. They do not
qualify all syscall-entry rax/orig_rax rewriting, signal/exec stop combinations,
32-bit code segments, or every selector/CPU-feature combination. Existing
ptrace event, SEIZE and EXITKILL semantics remain a separate workstream.
XSAVE writes remain rejected; this batch implements extended-state reads.

The GDB 16.3 binary from Alpine 3.24 passes version and batch-startup tests.
Its target-run smoke test timed out while probing PTRACE_O_EXITKILL, before
it reached the requested register inspection. Full GDB compatibility is not
claimed. The corresponding console and native ktrace excerpt are in
focus8.console.log. The pre-change quota-qualified kernel reproduces the same target-run timeout
in `gdb-baseline.console.log`; its kernel and module hashes are printed in
that log. This establishes an existing debugger limitation, not a regression
from the register additions. A test-only interposer rejecting EXITKILL also
failed to complete the target run (`gdb-workaround.console.log`); that
experiment is not acceptance evidence.

The full regression image deliberately excludes the optional debugger's
/compat/linux userland, because that prefix changes root pathname lookup and
would invalidate existing pathname-test assumptions. The initial full1
setup failure is retained, and full2-run is the acceptance candidate.

Artifacts: /tmp/linuxulator-ptrace-20260921. The host only compiles artifacts
and runs QEMU; candidate kernels/modules and probes execute in disposable guests.


## Evidence

- Linux 6.18.35, XSAVE/AVX: `oracle8.console.log` (21 named cases).
- Linux without XSAVE: `oracle-no-xsave2.console.log`.
- Final BSD focused matrix: `focus7.console.log` (69 checks, healthy ZFS,
  no recognized kernel diagnostics and clean shutdown).
- BSD without XSAVE: `focus6.console.log`.
- Source/build/artifact hashes: `manifest.json` and `source-snapshot/`.
- Full gate: `full2-run/results.json` (passed).

All paths are relative to `/tmp/linuxulator-ptrace-20260921`.

## Full-gate result

The full amd64 ZFS-root regression gate passed with 69 ptrace checks, 1098 native/Linux shared-ring option executions and 441 main io_uring cases, plus the existing syscall and lifecycle matrices. It reported no recognized kernel diagnostics, zero final tracked ring resources, healthy ZFS and clean shutdown.

Qualification applies to the recorded source and artifact hashes. Later
concurrent workspace edits are outside this recorded build. The debugger
limitation above remains; this is qualification of the named register
contracts, not all ptrace behavior.

## Debugger follow-up (2026-09-22)

The subsequent [debugger-options batch](linuxulator-ptrace-debugger-options.md)
fixes the stopped-tracee SIGKILL hang and the later USER-area/proc task-path
failures. GDB 16.3 now completes the original target-run smoke test. The
historical failures above remain evidence for the earlier build.
