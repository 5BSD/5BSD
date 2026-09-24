# Linux64 `PTRACE_SEIZE`

Status: amd64 Linux64 `PTRACE_SEIZE` is implemented and its focused VM gate
passes. The integrated gate evidence is recorded below after a complete run.
No host kernel or module is installed or loaded by this work.

## Contract

`PTRACE_SEIZE` creates the normal ptrace relationship without stopping the
target and without creating an initial wait status. The Linux `addr` argument
must be zero. Unknown option bits return `EIO`; the unsupported
`PTRACE_O_SUSPEND_SECCOMP` mode returns `EINVAL`. Options supplied with SEIZE
are installed as part of the attach transaction, before the target can expose
a traced event. A later signal creates an ordinary ptrace stop, and detach can
suppress that signal and let the target continue. `PTRACE_O_TRACEEXIT` supplied
at attach therefore reports the exit event even when the target exits
immediately after SEIZE returns.

The behavior follows Linux's generic ptrace implementation and UAPI constants:
[ptrace.c](https://github.com/torvalds/linux/blob/master/kernel/ptrace.c) and
[ptrace.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/ptrace.h).

`PTRACE_INTERRUPT` is implemented and qualified by the later
[interrupt follow-up](linuxulator-ptrace-interrupt.md) and the later
[LISTEN follow-up](linuxulator-ptrace-listen.md). Seccomp filter support remains absent, so
`PTRACE_O_SUSPEND_SECCOMP` cannot be enabled.

## Ownership

The native ptrace core owns a new kernel-only `PT_KERN_SEIZE` operation because
ptrace authorization, request serialization, traced-state changes, reparenting,
and wait visibility are shared process semantics. It is not exposed as a new
FreeBSD userspace request. A frontend validation callback runs with the process
and process tree locked before any relationship change, so an incompatible
target cannot leave a partial attachment. A setup callback then initializes
frontend state under the same transaction after the common ptrace reset.

The Linuxulator owns Linux argument and option validation, Linux errno choices,
emulation-data validation, and option-to-native-event translation. Existing
native `PT_ATTACH` continues to stop its target. Linux32 is unchanged.

## Tests

`linux_ptrace_seize` is a freestanding Linux64 test. Each invocation checks:

- missing-target `ESRCH`, self-target `EPERM`, nonzero `addr` `EIO`, and unknown
  option `EIO`, all before a trace relationship is created;
- proof that the target executes before and after SEIZE, plus absence of an
  initial wait status;
- rejection of a stopped-only request while the seized target is running;
- signal interception, `PTRACE_GETSIGINFO`, signal-suppressing detach, continued
  execution, and normal exit;
- atomic `PTRACE_O_TRACEEXIT` activation, Linux exit-event status, resume, and
  final exit status.

The test is registered with ATF and requires the disposable ZFS-root VM. The
focused WITNESS/INVARIANTS candidate ran 25 iterations from ZFS and 25 from
tmpfs. All 50 passed, ZFS remained healthy, shutdown synced its buffers, and
the console contained no recognized kernel diagnostic. The kernel SHA-256 was
`beb0e28f61d78c142f0883f7f0e26cdb1112637c94e05125931f158d8209e295`, the
`linux64.ko` SHA-256 was
`10547e8762c4482e3af0ca9186352b21defffd2efe92874ca6fe85201107f8ce`, and the
test binary SHA-256 was
`af93960d3631d817d34082fbbef8af5af577cd618f998aa33af3a3a8ae56fa97`.
Evidence is under `/tmp/linuxulator-seize-20260923/candidate`.

The exact binary also passed 20 iterations on Linux 6.18.35 and 20 on
Linux 7.1.5. The captured console hashes are
`cc0ea0e9a0fdfef503662ed8274d872f5dfb31e548533a2d548adee3fb3ef9c9` and
`16d025dc8eb99e857eb4ba1b83312a98fe03036a275ff401d9cfef823ed3d277`.

The accepted integrated amd64 ZFS-root gate is
`/tmp/linuxulator-seize-20260923/candidate/full-run1/results.json`. It passed
three SEIZE executions, 63 register ptrace executions, 21 ptrace option
executions, three native ptrace and three capmode executions. The surrounding
gate passed 48 direct ABI cases, 63 Linux AIO executions, 78 dedicated shared
RWF executions, 1,146 shared-option executions, 476 main io_uring cases, three
native squeue executions, 39 NO_MMAP, 33 SQPOLL, 24 memory-region, and 21 query
executions. `ioprio_send_zc_fixed_vectorized` passed. No result was nonzero, no
recognized kernel diagnostic occurred, all final resource counters were zero,
ZFS was healthy, shutdown synced all buffers, and QEMU exited zero. The image
SHA-256 is
`3d30eb8379f6cc983def1282cb31869adee28f57310e6bb4336ed00556ee697a` and the
result JSON SHA-256 is
`f5e232797df0de000c2d2e802ed256336cc65a8791a7d17eebdd33a78b531673`.
Arm64 runtime was waived because this phase adds architecture-neutral ptrace
core behavior and amd64 Linux64 frontend coverage; no arm64-specific code was
changed.
