# Linuxulator restartable-sequences implementation contract

Status: Linux64 amd64 registration, scheduler and signal abort handling is
implemented. Linux32 and arm64 still return `ENOSYS`. The native scheduler
exposes an optional `sysentvec.sv_schedswitch` callback; only Linux64 uses it.
The shared callback is needed because a context switch must abort a registered
critical section before that thread executes in userspace again.

## Implemented contract

Registration is per Linux thread in `linux_emuldata`. The handler accepts a
32-byte-aligned userspace area of at least 32 bytes, initializes the CPU,
node and `mm_cid` fields, and validates unknown flags, pointer faults,
duplicates and unregister mismatches. Registration resets on fork and exec;
failed `execve` preserves it. `mm_cid` currently equals the CPU number: this
provides distinct IDs for threads running concurrently on different CPUs,
but does not provide Linux's dense per-memory-map allocation policy.

The scheduler calls `sv_schedswitch` after `mi_switch()` resumes a thread.
Linux64 marks a pending switch and schedules a pre-signal AST. That AST
updates IDs, clears `rseq_cs`, validates the descriptor and abort signature,
and redirects RIP to `abort_ip` when the interrupted instruction lies inside
the critical section. Linux signal delivery performs the same fixup before
saving the interrupted RIP in its signal frame. Invalid descriptors and
unmapped registered memory terminate the process with SIGSEGV. The auxiliary
vector advertises `AT_RSEQ_FEATURE_SIZE=28` (through `mm_cid`) and
`AT_RSEQ_ALIGN=32` only for Linux64 amd64. The slice extension is not
advertised or implemented; `rseq_slice_yield` remains a DUMMY syscall.
Linux's rseq-specific `membarrier` commands remain unsupported and rejected.

The Linux reference is [kernel/rseq.c](https://github.com/torvalds/linux/blob/master/kernel/rseq.c),
[the rseq UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/rseq.h),
[auxiliary-vector UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/auxvec.h),
and [the userspace API](https://docs.kernel.org/userspace-api/rseq.html).

## Qualified behavior

The freestanding registration test `tests/sys/kern/linux_rseq.c` checks the
Linux 6.18.35 reference results: lengths 31 (EINVAL), 32/33/64 (success),
misalignment and unknown flags (EINVAL), bad pointer (EFAULT), duplicate
registration (EBUSY), mismatched signature (EPERM), mismatched area or length
(EINVAL), matching unregister and reset fields, and repeated unregister
(EINVAL). It also checks CPU fields against `getcpu()`.

`linux_rseq_signal.c` checks 32 synchronous signal aborts, forced CPU 0 to
CPU 1 migration, alternate signal stack, `SA_RESTART`, masked/pending signal,
seven bad descriptor cases killed with SIGSEGV, unmapped registered memory and
fork reset. `linux_rseq_threads.c` starts two raw clone threads pinned to
separate CPUs and checks distinct `mm_cid`; `linux_rseq_lifecycle.c` checks
failed and successful `execve`. All four passed the pinned Linux oracle and
three rounds on ZFS and tmpfs in the disposable amd64 BSD VM. The complete
BSD gate result is
`/tmp/linuxulator-gate-20260919/rseq-expanded-gate/run/results.json`:
24 rseq executions, 343 io_uring cases, 786 squeue-option executions,
57 Linux AIO and 6 native AIO cases, 36 base cases and 144 pathname cases,
zero recognized diagnostics, healthy ZFS and clean shutdown.

`linux_rseq_auxv.c` checks the advertised feature size/alignment, registers
with the resulting allocation size and verifies CPU fields and unregister.
`linux_rseq_preempt.c` forces same-CPU scheduling with a busy peer and checks
that interrupted critical sections abort before commit.
`linux_rseq_hold.c` keeps an active registration while the guest attempts to
unload `linux64.ko`; the module must reject the unload with EBUSY and remain
loaded. The signal probe also checks delivery of a pending signal after
unregister, with the rseq area left in its reset state.
The auxiliary-vector and same-CPU preemption oracles and mandatory BSD gates
passed; see `docs/linuxulator-implementation-gate.md` for the complete
results. The final seven-group BSD gate is
`/tmp/linuxulator-gate-20260919/rseq-lifetime-gate/run/results.json`.

## Remaining qualification

Do not claim full Linux rseq compatibility until the following receive
positive and negative reference tests and the full disposable amd64 ZFS-root
QEMU gate:

1. Longer-running preemption and migration under CPU contention, including
   a real per-CPU data update workload; prove no stale-CPU commit.
2. Additional descriptor start-address overflow and unmapped copyin
   boundaries. Length overflow and invalid abort IPs are now VM-tested.
3. Stress unregister and thread exit with scheduler callbacks pending.
   The active-process module-unload rejection and pending-signal-after-
   unregister cases are now gated, but concurrent teardown still needs stress.
4. A real librseq-based Linux application under signals, migration and load.
5. Any future slice extension or rseq-specific membarrier command must have
   its own implementation and Linux-reference positive/negative gate before
   advertisement.

Never install or load the candidate kernel on the host. Guest root must be
ZFS; run filesystem-sensitive tests on ZFS and tmpfs. The original shared
callback no-registration regression result is
`/tmp/linuxulator-gate-20260919/rseq-hook-gate/run/results.json`.
