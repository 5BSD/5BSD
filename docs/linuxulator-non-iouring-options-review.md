# Remaining non-io_uring options: amd64 review, 2026-09-21

Follow-up: [pending signals, tracing reattach and multicast mode transitions](linuxulator-signal-modes-options.md)
records the next amd64 batch. Its named contracts supersede the corresponding
remaining-option entries below.

Follow-up: [peer names, mixed multicast deltas and process ptrace events](linuxulator-peer-events-options.md)
records the implemented amd64 subset and VM evidence. Earlier missing-option
entries below are superseded for that subset; full Linux thread tracing remains
unfinished. SO_COOKIE was already implemented before that follow-up.

Scope: source review for relatively small additions to amd64 Linux64.
No Linux32 work, no io_uring/squeue changes, and no implementation or new
runtime qualification in this review. Effort estimates are engineering
judgments, not promises of application compatibility.

## Recommended sequence

| Priority | Addition | Current source | Native support / estimated scope |
|---|---|---|---|
| 1 | `ptrace(PTRACE_GETFPREGS)` and `PTRACE_GETREGSET, NT_PRFPREG` | GETFPREGS has a number but no dispatch case; the regset request explicitly returns EINVAL | `kern_ptrace(PT_GETFPREGS)` exists. Relatively small amd64 ABI conversion/readout batch; verify x87/SSE layout, reserved bytes and iovec sizing. |
| 2 | `PTRACE_SETFPREGS` and `PTRACE_SETREGSET, NT_PRFPREG` | Neither has a dispatch case | Native PT_SETFPREGS exists. Small-to-medium follow-up: partial input, MXCSR validity, preserved state and side-effect/error behavior need oracle tests. |
| 3 | `PTRACE_SETREGSET, NT_PRSTATUS` | GETREGSET/PRSTATUS and legacy SETREGS exist; SETREGSET does not | Existing register converters and PT_SETREGS offer a starting point. Small-to-medium, but audit original-syscall register handling, FS/GS bases and partial writes before reusing the legacy setter. |
| 4 | `PTRACE_GETREGSET, NT_X86_XSTATE` | Explicit EINVAL | Native PT_GETXSTATE_INFO/PT_GETXSTATE exist. Medium: Linux XSAVE headers, feature masks, layout, variable lengths and CPU-dependent tests prevent a blind structure copy. Begin with read access. |

The first batch would let Linux debuggers inspect x87/SSE state. It does not
by itself establish full GDB/strace compatibility. These operations should
primarily need Linuxulator ABI work rather than new VM/VFS facilities;
confirm this during implementation and keep native ptrace security checks.

Source: [Linux ptrace dispatcher](../sys/compat/linux/linux_ptrace.c),
[amd64 conversions](../sys/amd64/linux/linux_machdep.c),
[native ptrace](../sys/kern/sys_process.c),
[native XSAVE access](../sys/amd64/amd64/ptrace_machdep.c).
Pinned comparison: [Linux 6.18 x86 ptrace](https://github.com/torvalds/linux/blob/v6.18/arch/x86/kernel/ptrace.c)
and [generic ptrace](https://github.com/torvalds/linux/blob/v6.18/kernel/ptrace.c).

Acceptance needs a stopped Linux child with known register patterns, zero/
short/full/oversized and misaligned regset lengths, bad pointers, unrelated
and non-stopped targets, multithread target selection, and continued execution
after writes. Compare against Linux in a disposable VM, then use the required
amd64 ZFS-root guest and regression gate. A real debugger smoke test should
supplement the syscall matrix.

## Other confirmed gaps that are larger

- `PTRACE_GETEVENTMSG` is still a rejecting function. Native PT_LWPINFO
  provides event information, but Linux event classification and payloads
  must agree across fork/vfork/clone/exec/exit. Existing option code maps
  TRACECLONE and TRACEVFORKDONE to PTRACE_VFORK, so this is more than filling
  in a getter. PTRACE_SEIZE also remains a rejecting function.
- `fcntl(F_SEAL_EXEC)` needs shared execution-mode/seal enforcement;
  Linux translation alone is insufficient.
- `openat2(O_TMPFILE)` still rejects: unnamed creation and subsequent linking
  need filesystem support. RESOLVE_CACHED always returns EAGAIN; an actual
  cache-only success path needs pathname-resolution work.
- `renameat2(RENAME_EXCHANGE/RENAME_WHITEOUT)` and extra `fallocate` modes need
  atomic/native VFS/filesystem operations. Multi-step userspace-style
  emulation would not preserve their semantics.
- `F_SETOWN_EX/F_OWNER_TID` and non-SIGIO `F_SETSIG` need native signal-owner
  and delivery changes.
- TCP_DEFER_ACCEPT needs timeout behavior beyond the native data accept
  filter. TCP_NOTSENT_LOWAT and TCP_INQ lack matching general backends;
  TCP_QUICKACK has stack-specific behavior rather than a universal mapping.
- IP_RECVOPTS/IP_RETOPTS have native option constants, but the receive control
  message generation in ip_input.c is inside `#ifdef notyet`. They are not
  simple socket-option translations.
- Legacy AIO rejects NOWAIT/ATOMIC/DONTCACHE/NOSIGNAL; plain vectored I/O also
  rejects several of these. Do not assume the existing flag names provide
  the required native completion/storage/signal semantics.
- PI futex requeue, scheduler policies/flags, lazy unmount, remote
  process_madvise and enforced NUMA policies require deeper kernel work.

## Stale backlog entries excluded from recommendations

The older option tables still mark these as missing, but current source has
implementations:

- openat2 IN_ROOT, NO_XDEV, NO_SYMLINKS and NO_MAGICLINKS.
- OFD GETLK/SETLK/SETLKW and F_SEAL_FUTURE_WRITE (also have recorded VM gates).
- TCSBRK with zero argument, and TCSBRKP duration handling.

Source presence is not a new correctness certification. In particular, the
terminal-break code still merits duration-overflow and interruption review.

## Implementation follow-up

The four register additions now have an [implementation and focused VM
matrix](linuxulator-ptrace-registers.md); the full amd64 gate passed. The
source-review table above records the starting state.


### Debugger and socket follow-up, 2026-09-22

The next implemented batches are [debugger options](linuxulator-ptrace-debugger-options.md)
and [SO_COOKIE](linuxulator-socket-cookie.md). Focused Linux/FreeBSD matrices
and real GDB/Python client checks pass. Both full amd64 ZFS-root regression
gates pass; see those pages for frozen evidence and remaining limits.
The additions cover USER general/debug registers and hardware watchpoints,
ARCH_PRCTL, signal masks, rseq configuration, IOPERM regset reads, traced
SIGKILL lifecycle, process-leader task views and stable socket identities.
They add options to existing syscall handlers, not new syscall numbers.

The next debugger batch should address event classification and per-tracee
option state together before claiming GETEVENTMSG or full strace support.
Nonleader task enumeration and the ret-to-NX SIGBUS/SIGSEGV difference remain
separate work. [XSAVE writes and multicast full-state filters](linuxulator-xstate-mcast-options.md)
have passed their targeted full-gate, reference and client tests. The linked
record notes the broader gate’s one preexisting io_uring test exception. SO_NETNS_COOKIE would require a stable
namespace/VNET identity with defined lifetime; a process ID or constant
would not provide that contract. The remaining standalone missing-dispatch
queue still needs the subsystems listed in the
[handoff](linuxulator-missing-syscalls-handoff.md); no new small standalone
syscall is claimed by these batches.
