# Linux unshare implementation contract

Status: first subset implemented; named ABI cases and the full amd64 ZFS-root
regression gate pass. Broader acceptance and expansion work remains below.

## First supported contract

The first implementation targets amd64 Linux64 syscall 272, with one
`unsigned long` flags argument (`l_ulong`, 64 bits). It supports flags zero
and `CLONE_FS` (0x200) for a process with one live thread. Zero leaves all
sharing unchanged. `CLONE_FS` detaches the root/current-directory references
and umask, while preserving descriptor-table sharing. Repeated detachment is
idempotent. No privilege is required and detachment grants no new authority.

Nonzero flags other than `CLONE_FS`, including namespace flags and
`CLONE_FILES`, are rejected with EINVAL before mutation. `CLONE_FS` in a
multithreaded process is deliberately rejected with EINVAL: the current
kernel stores its path descriptor in the process, not the thread. This is a
partial implementation, not Linux namespace support or complete unshare.
Other architectures retain ENOSYS. No namespace or mount feature is advertised.

Linuxulator owns the syscall argument, flag validation, subset restriction
and errno policy. The existing native `pdunshare()` primitive owns copying
and lifetime of path state; no new native syscall or shared-kernel change is
needed for this first contract. The process lock protects the live-thread
count check. With exactly one live thread, no sibling can create another
thread while the path state is copied. This restriction must remain until
per-thread resource ownership is implemented.

## Reference and prerequisites for expansion

The runtime oracle is Alpine Linux 6.18.35-0-virt, amd64, booted in a disposable
QEMU guest. Source references are Linux
[`kernel/fork.c`](https://github.com/torvalds/linux/blob/v6.18/kernel/fork.c)
and [`fs/locks.c`](https://github.com/torvalds/linux/blob/v6.18/fs/locks.c).
The first contract uses established flags shared by these versions; newer
namespace flags need a separate, newer oracle before implementation.

1. Linux threads may independently detach file tables and filesystem state.
   Native `p_fd` and `p_pd` are process-owned. Stopping sibling threads and
   replacing those pointers would still change the siblings' state.
2. Linux POSIX record locks use the file table as owner. Detaching a table
   leaves existing locks associated with the old shared table. The detached
   caller observes them as conflicting locks until the old table releases
   them. Native `fdunshare()` calls `fdescfree()`, whose `fdclearlocks()` path
   releases the process leader's locks. Simply suppressing that unlock would
   not provide the correct new ownership model either.
3. Native `fdcopy()` also handles native fork-only descriptor restrictions
   and `DFLAG_FORK` callbacks. Descriptor-table detachment needs its own
   reviewed policy, including Capsicum rights, epoll/kqueue and ring lifetime.
4. Namespace flags need namespace objects, permissions and lifetime, plus
   transactional preparation/rollback when combined with resource detachment.
   Neither `chroot` nor `rfork` supplies that contract.

## Reference matrix

`tests/sys/kern/linux_unshare.c` is a freestanding amd64 oracle suite.
Run it only in a disposable VM with a private writable cwd other than `/`,
and an outer timeout. All cases must pass on the Linux oracle; only the
named supported subset can pass on BSD until later implementation phases.

| Case | Contract | First BSD subset |
|---|---|---|
| zero_preserves_sharing | Zero flags preserve descriptor, cwd and umask sharing | Required |
| fs_detaches_only_paths_and_umask | CLONE_FS isolates cwd/umask but leaves descriptors shared | Required |
| files_detaches_only_descriptors | CLONE_FILES isolates descriptors but preserves cwd/umask sharing | Pending |
| fs_files_detach_both | Combined flags detach both objects | Pending |
| invalid_flags | Reserved high bits and invalid combinations return EINVAL | Required |
| fs_unprivileged | An unprivileged caller can detach shared path state | Required |
| fs_repeated | Repeated detachment and zero flags remain successful | Required |
| fs_concurrent_shared_mutation | 64 detachments while another process changes the shared cwd/umask; private state remains stable | Required |
| fs_fork_exec_lifetime | Detached cwd/umask survive failed and successful exec; parent stays unchanged | Required |
| fs_root_lifetime | Child root changes do not alter the sharing parent after detachment | Required |
| bsd_rejected_flags | Every unsupported bit, alone and with CLONE_FS, returns EINVAL | BSD-only negative contract |
| bsd_thread_rejection | Multithreaded CLONE_FS fails; zero succeeds and sharing survives | BSD-only negative contract |
| native capability tracer | Dispatcher returns Linux EPERM before unshare in capmode | BSD-only negative contract |
| rejection_preserves_sharing | Failed combined request changes neither object | Required |
| files_preserves_open_description | Offsets remain shared after table detachment | Pending |
| files_preserves_old_table_lock_ownership | Existing POSIX locks retain old-table ownership and lifetime | Pending |
| files_lock_pids_and_close_ownership | Ranges report their acquiring PID; closing a duplicate releases only its table’s locks | Pending |
| thread_detaches_without_affecting_sibling | Thread-local detachment leaves sibling state intact | Pending |

Additional first-subset cases cover `fs_unprivileged`, `fs_repeated`,
`fs_fork_exec_lifetime`, `fs_root_lifetime`, `bsd_rejected_flags` (every
unsupported bit individually and combined with CLONE_FS), and
`bsd_thread_rejection` (including zero flags and unchanged umask sharing).
`linux_unshare_capmode.c` uses a native tracer and a freestanding Linux probe
to check that the dispatcher denies the syscall in capability mode with
Linux EPERM. The syscall is not marked capability-enabled.
Pointer/size-boundary cases do not apply to this scalar ABI. Filesystem-sensitive success cases must run on ZFS. Full namespace,
CLONE_FILES and thread-local support remain explicitly outside this subset.

## Building the probe

```sh
clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static \
    -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror \
    -o linux_unshare tests/sys/kern/linux_unshare.c
```

The optional argument selects one named case; `-l` lists the cases.
Do not run candidate kernel code or these probes on the host.

Build the BSD subset binary with `-DUNSHARE_BSD_SUBSET`. Its inventory includes
future reference cases too; the guest gate selects only the eleven supported or
rejected-contract cases. Build `tests/sys/kern/linux_unshare_capmode.c` twice:
once with native `clang -static -O2 -Wall -Wextra -Werror` as `unshare_capmode`,
and once with the Linux freestanding flags and `-DLINUX_PROBE` as
`unshare_capmode_probe`. Brand both Linux binaries with `brandelf -t Linux`.
The native tracer is invoked inside the guest as
`timeout 30 /root/unshare_capmode /root/unshare_capmode_probe`.

Initial reference result: all 13 cases passed on Linux 6.18.35-0-virt.
Focused BSD result: all 60 supported/rejection executions pass; three
capability-mode executions also pass. The complete amd64 ZFS-root gate passes
with the same 63 checks, 1092 native/Linux ring-option executions and 408 main
io_uring cases, zero recognized kernel diagnostics or leaked tracked resources,
healthy ZFS and clean shutdown. See
`/tmp/linuxulator-unshare-20260920/full4-run/results.json` and the adjacent
console log. The parent directory's `manifest.json` records exact source,
kernel, module, binary, oracle and result hashes plus build commands; its
`source-snapshot/` preserves the module and test inputs. A Linux32 compile-only
check passed with the ENOSYS fallback; no Linux32 runtime claim is made.

## Remaining acceptance and expansion work

The freestanding tests are direct ABI consumers, not evidence that a complete
container runtime works. A named external application using this narrow
single-threaded path-state contract still needs qualification. Namespace
clients, CLONE_FILES consumers, and multithreaded callers are not supported
by this batch. Allocation-failure injection and broader SMP stress remain
follow-ups; the bounded two-vCPU shared-path mutation test below now passes; the implementation delegates those native lifetime operations to
`pdunshare()` without changing them. There are no descriptors created, user
buffers imported, cancellable waits, deadlines or new native enforcement
mechanisms in the first supported syscall contract.

The full-gate result applies to the recorded source snapshot. During the run,
the separate io_uring workstream changed `sys/compat/linux/linux_io_uring.c`
and `tests/sys/kern/linux_iouring.c`; those later edits are not qualified by
this result. The unshare implementation and probes remained unchanged, and
the earlier io_uring inputs are preserved in `source-snapshot/`.

## Concurrency and lock-ownership follow-up

The expanded reference matrix passes all 15 cases on Linux 6.18.35-0-virt.
The two-vCPU amd64 BSD focused VM passes 66 executions (eleven cases, three
rounds on each of ZFS and tmpfs), plus three capability-mode checks. The new
`fs_concurrent_shared_mutation` case performs 64 process detachments per
execution while a separate process changes the old shared cwd and umask.
Each detached process verifies its private state stays stable while the
mutator makes observable progress. Across six executions this covers 384
detachments. This is bounded contention coverage, not exhaustive race proof.
The VM reports healthy ZFS, no recognized kernel diagnostics and clean
shutdown. Evidence and exact input hashes are in
`/tmp/linuxulator-unshare-expansion-20260920/{manifest.json,results.json}`.

This follow-up changes tests and gate inventories only. It reuses the exact
kernel and Linuxulator modules from the earlier full-gate snapshot. The
expanded matrix passed a focused gate; the earlier full-gate result remains
for its original matrix. The full runner now requires the new concurrency
case in subsequent runs.

The new Linux-only `files_lock_pids_and_close_ownership` case confirms that
two processes sharing one file table can acquire nonadjacent record locks
which report different PIDs. After detachment, closing a duplicate in the
new table preserves both old-table locks. Closing that duplicate in the old
table releases both locks while its process remains alive. Together with
`files_preserves_old_table_lock_ownership`, these are acceptance requirements
for future `CLONE_FILES` support, not BSD success claims.

Implementation review found the following additional prerequisites:

- `kern_fcntl()` passes the native process leader as the POSIX lock owner;
  `kern_lockf.c` stores the reporting PID on that owner. Linux table ownership
  needs a separate reporting PID per range, including split/merge and lock
  enumeration behavior. OFD locking cannot substitute for this: it uses an
  open file description and reports PID -1.
- Close cleanup must know which table was closed. In particular,
  `fdescfree()` clears `p_fd` before closing the last table's descriptors, so
  looking only at the caller's current table is insufficient. Close, dup
  replacement, exec, exit and blocking-lock races all need the same rule.
- Native-to-Linux and Linux-to-native exec must preserve existing POSIX
  locks. Changing only Linux fcntl's owner key would make a process conflict
  with its own inherited locks. Ownership transition and lifetime rules
  must be resolved before wiring table-owned locking into Linux fcntl.
- A descriptor-copy primitive must preserve file objects, both capability
  sets and descriptor flags. Reusing `fdcopy(..., false)` would still apply
  fork callbacks and fork-only restrictions in this tree.

`CLONE_FILES` therefore remains rejected. No new native locking or descriptor
copy interface has been introduced by this test-only follow-up.
