# Linux64 debugger options, 2026-09-22

The later [XSAVE-write and multicast batch](linuxulator-xstate-mcast-options.md)
extends the XSAVE-read-only contract recorded below.

Status: Linux-reference suites, all 90 focused FreeBSD checks and the GDB
16.3 client smoke test pass. The full amd64 ZFS-root regression gate also
passes. No host kernel or modules have been installed.

## Scope and contracts

This extends amd64 Linux64 ptrace, syscall 101. It adds no syscall numbers,
Linux32 support, arm64 register support, or io_uring implementation changes.
References are Linux v6.18 [x86 ptrace](https://github.com/torvalds/linux/blob/v6.18/arch/x86/kernel/ptrace.c),
[generic ptrace](https://github.com/torvalds/linux/blob/v6.18/kernel/ptrace.c),
and [the USER layout](https://github.com/torvalds/linux/blob/v6.18/arch/x86/include/asm/user_64.h).
Runtime comparison uses the Linux 6.18.35 QEMU oracle.

| Contract | Change | Test |
|---|---|---|
| SIGKILL of a traced Linux64 process | Terminate without requiring the debugger to resume it; defer resume until an active ptrace request releases its hold | `linux_ptrace_lifecycle`: TRACEME/ATTACH, tracer/third-party sender, with/without EXITKILL, 16 concurrent register-read/kill lifetimes |
| Native SIGKILL behavior | Keep the existing stopped-tracee behavior for native processes | `linux_ptrace_kill_native`: SIGKILL, WNOHANG, explicit PT_KILL and reaping |
| PEEKUSER/POKEUSER general registers | Use the held register transaction; actually apply writes; translate native 64-bit CS/SS to Linux selector values | `linux_ptrace_user`: compare all 27 words, modify r12 and verify resumed execution, alignment/bounds/faults |
| USER debug registers | Read/write DR0–3/6/7; reserved DR4/5 writes reject; validate user addresses, watchpoint type, length and alignment before mutation | `linux_ptrace_user`: initial values, 64-bit DR6 roundtrip, invalid address/control rollback, live 8-byte hardware write watchpoint |
| Hardware breakpoint lifecycle | New Linux64 children/threads start without inherited hardware breakpoints; exec clears virtual register bookkeeping | `linux_ptrace_user`: fork with an active watchpoint and observe the grandchild's normal exit; thread/exec hardware lifecycle is not independently qualified |
| PTRACE_ARCH_PRCTL | Get/set the stopped target's FS/GS bases; invalid commands/pointers and kernel bases reject | `linux_ptrace_user`: roundtrips through both this request and PEEKUSER |
| PTRACE_GET_RSEQ_CONFIGURATION | Return a zero-initialized 24-byte configuration, support truncated copies, report full structure size | `linux_ptrace_metadata`: absent/registered/unregistered state, prefix, zero-length and bad pointer |
| GETREGSET NT_386_IOPERM (0x201) | Read the target's 8,192-byte I/O permission bitmap; no active permissions gives ENXIO; no writes | `linux_ptrace_metadata`: enable one port, verify every byte, size clamping/alignment, revoke and query again |
| PTRACE_GETSIGMASK/SETSIGMASK | Convert target masks, preserve Linux signal numbering and remove unmaskable SIGKILL/SIGSTOP; handle saved sigsuspend mask | `linux_ptrace_sigmask`: lengths, bad pointers, ordinary-stop roundtrip, realtime bit and resumed execution; sigsuspend-stop combinations remain unqualified |
| /proc/pid/task/pid views | Expose the process leader's mem/maps/status/stat using existing process permission checks | `linux_proc_task`: memory read/write, directory enumeration, parent traversal, unrelated ID rejection and denied cross-credential access |
| Real debugger | GDB 16.3 starts a freestanding target, reads r12/x87/SSE, changes r12 and continues to normal exit | `focus6.console.log` and later focused runs, using the original `gdb.cmd` without the earlier interposer |

The USER layout includes the two trailing Linux fault-information words;
non-register reads return zero and writes reject. Hardware DR7 receives only
validated breakpoint controls. Linux-visible control bits and upper DR6 bits
are kept separately from the physical registers. Native register-write
privilege checks still apply.

## Shared implementation and limits

A sysent-vector flag selects Linux64 SIGKILL behavior. The signal path marks
the target killed; the native ptrace release path resumes a deferred kill
after P2_PTRACEREQ ends. This keeps target threads alive while callbacks drop
PROC_LOCK for user copies. Linux register, signal and metadata requests use
the existing kernel-only held callback; its userland invocation remains denied.

Pseudofs gains a PID-named node that retains its parent's process identity.
Lookup, directory enumeration and reverse path lookup agree on that name.
Linprocfs uses it for the leader's task directory. This is not enumeration of
all nonleader threads; full multithreaded GDB compatibility remains outside
this qualification. `PTRACE_SEIZE` is qualified by the later [SEIZE follow-up](linuxulator-ptrace-seize.md).
`PTRACE_INTERRUPT` is qualified by the later [interrupt follow-up](linuxulator-ptrace-interrupt.md), and `PTRACE_LISTEN` by the later [LISTEN follow-up](linuxulator-ptrace-listen.md). XSAVE writes remain unsupported. GDB still reports a SIGBUS warning in its
ret-to-NX capability probe; translating that fault to Linux SIGSEGV is not
part of this change. The target smoke test nevertheless exits normally.

Unprivileged register/watchpoint tests drop credentials and exec before
tracing. The native post-setuid, pre-exec debug restriction remains: the initial
unprivileged test without exec failed in `focus7.console.log`. That result is
retained and is not claimed as Linux-equivalent behavior.

## Evidence

Artifacts are under `/tmp/linuxulator-options-20260922`. All execution is in
disposable QEMU guests, with two vCPUs. FreeBSD uses ZFS root, GENERIC with
INVARIANTS/WITNESS, and `-cpu max` for XSAVE/AVX.

- `oracle9.console.log`: latest Linux reference suites, including unprivileged
  tracing after exec and forked-child breakpoint isolation.
- `focus6.console.log`: first successful GDB target run, native SIGKILL
  regression and initial Linux lifecycle, USER and metadata checks.
- `focus9.console.log`: final frozen kernel/module, all 90 checks and GDB
  target execution/register modification, healthy ZFS and clean shutdown.
- `full1-run/results.json`: full gate passes, including 90 ptrace checks,
  449 main io_uring cases and 1,098 shared-option checks, plus the complete
  syscall matrices. No diagnostics/nonzero results, zero final tracked
  resources, healthy ZFS, synced buffers and clean poweroff.
- `manifest.json`, `focused-results.json`, `task.patch`: hashes, results and
  isolated changes.
- `source-inputs.json`, `source-snapshot/`: recorded build inputs.
- Build logs retain failed attempts as well as subsequent corrections.

The initial metadata oracle VM (`oracle5`) was externally terminated before
login; `oracle5b` reran and passed. Earlier USER oracle failures exposed the
928-byte Linux USER structure boundary and were corrected against the pinned
source. Earlier debugger images lacked leader task memory paths; these runs
are diagnostic evidence, not acceptance runs.
