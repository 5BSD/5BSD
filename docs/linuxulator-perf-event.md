# Linux `perf_event_open` software-counting subset

## Scope and ownership

The first supported `perf_event_open(2)` slice is an event-file implementation
inside the Linuxulator. Linux event numbers, `perf_event_attr`, flag and ioctl
translation, Linux errno choices, and event-fd state live in
`sys/compat/linux/linux_perf.c`. It reads existing per-thread runtime and
resource counters; it does not add a native syscall, scheduler hook, PMU
interface, sampling engine, mmap ring, or squeue operation.

The only shared-kernel surface is `DTYPE_LINUXPERF` in `sys/sys/file.h`, used to
identify the descriptor safely. Linux thread detach calls freeze open counters
before Linux emulation data is destroyed, so a duplicated or inherited event
fd remains readable after its target thread exits. The fd is passable and its
file state is shared by `dup(2)` and `fork(2)` as on Linux.

## Supported contract

The handler accepts a software event for the calling Linux thread (`pid == 0`
or the caller's Linux TID), `cpu == -1`, and no group. These event selectors
are implemented:

- `PERF_COUNT_SW_TASK_CLOCK`
- `PERF_COUNT_SW_PAGE_FAULTS`
- `PERF_COUNT_SW_CONTEXT_SWITCHES`
- `PERF_COUNT_SW_PAGE_FAULTS_MIN`
- `PERF_COUNT_SW_PAGE_FAULTS_MAJ`
- `PERF_COUNT_SW_DUMMY`

A read returns the count and optionally
`PERF_FORMAT_TOTAL_TIME_ENABLED`, `PERF_FORMAT_TOTAL_TIME_RUNNING`, and
`PERF_FORMAT_ID`. `PERF_EVENT_IOC_ENABLE`, `DISABLE`, `RESET`, and `ID` are
supported. The enable, disable, and reset ioctls accept the group flag for the
single event. `PERF_FLAG_FD_CLOEXEC` is supported. Attribute size zero uses the
Linux version-zero layout; undersized structures return `E2BIG` and publish the
current size, and unknown nonzero extension bytes return `E2BIG`.

This initial slice explicitly returns an error for hardware/PMU events,
CPU-wide events, cross-thread/process targets, event groups, cgroup/output
redirection, inheritance, sampling, overflow notifications, group/lost read
formats, breakpoints, clock selection, branch/register sampling, AUX data,
BPF/filter operations, refresh/period updates, and mmap metadata/data rings.
`PERF_COUNT_SW_CPU_CLOCK` and `PERF_COUNT_SW_CPU_MIGRATIONS` are not advertised
because the current backend cannot provide their Linux semantics. These gaps
remain option-level work; the syscall is partial rather than complete.

The Linux syscall table does not mark this entry capability-mode enabled, which
matches the general Linuxulator syscall-table policy. Calls after
`cap_enter(2)` are therefore rejected by the syscall entry layer.

## Reference behavior

The ABI and errno matrix was checked in a disposable Linux 7.1.5 amd64 QEMU
guest. The reference probe covers task-clock counting, disabled state, read
layout and ID, all software selectors, syscall flags, target/cpu/group forms,
unknown type/config values, attribute sizes 0/63/144, nonzero newer fields,
sampling/group formats, short reads, and ioctl argument handling. The raw
reference log is `/tmp/perf-phase/oracle.console.log` in the development
evidence directory.

Some reference-supported forms are deliberately outside this subset. Their
negative tests require `EOPNOTSUPP`, preventing a false success that would make
a caller believe sampling, grouping, or CPU-wide counting is active.

## Test matrix and gate

`tests/sys/kern/linux_perf_event.c` is a freestanding Linux amd64 binary with
13 named cases:

| Case | Contracts |
|---|---|
| `basic_task_clock` | live monotonic task-runtime counting |
| `disabled_transitions` | disabled open, enable/disable/reset, group ioctl flag |
| `read_formats` | enabled/running/ID layout, ID fault, short read |
| `software_counters` | page faults, minor/major faults, context switches, dummy |
| `attribute_sizes` | size 0, undersize negotiation, current size, newer field, bad pointer |
| `attribute_options` | sampling, group/lost format, inheritance, reserved bits and fields |
| `target_and_flags` | unknown/unsupported flags, cpu/process/group fd, type and selector errors |
| `fd_contract` | dup/last close, read/write/stat/poll and stale fd behavior |
| `ioctl_validation` | invalid flags, unsupported/unknown commands and closed fd |
| `cloexec_flag` | `PERF_FLAG_FD_CLOEXEC` descriptor state |
| `thread_exit_lifetime` | frozen value after target-thread teardown |
| `thread_close_race` | 32 repeated close-versus-thread-exit races per invocation |
| `fork_inheritance` | inherited descriptor and shared readable state |

The ATF wrapper builds with `-Wall -Wextra -Werror`, requires exactly 13 cases,
and fails on any nonzero result. The focused WITNESS/INVARIANTS QEMU run passed
all 13 cases five times on ZFS and five times on tmpfs: 130 executions, zero
failures and no recognized kernel diagnostic. The permanent full gate runs
three rounds on each filesystem and requires all 78 `GATE_PERF` records. The
final amd64 ZFS-root full gate passed all 78 records and its native-to-FreeBSD
exec lifetime check. While the native process retained the perf descriptor,
`kldunload linux64.ko` was rejected; the process then released the descriptor
and exited normally. The same run passed the complete 477-case io_uring matrix,
1,146 shared squeue-option executions, and the query, NO_MMAP, SQPOLL, and
memory-region matrices. All tracked resources reached zero, the ZFS pool was
healthy, no recognized kernel diagnostic occurred, buffers synced, and QEMU
exited zero. Evidence is in `/tmp/perf-phase/full-gate-final9`; the result JSON
SHA-256 is `d268a287c290f55391ed382e491a6ef910adb9018777d494cdb9cead809d41a6`.

The implementation is built into both `linux64.ko` and the amd64 Linux32
`linux.ko`; both module builds pass with `-Werror`. Runtime qualification in
this phase is amd64 Linux64. No candidate kernel or module is installed or
loaded on the host.
