# 5BSD

A BSD kernel that implements the Linux API with a security layer
underneath it.

Traditional UNIX compatibility means running old UNIX programs.
5BSD takes a different approach: the Linux syscall interface is a
first-class target, and every Linux syscall passes through a BSD
security stack that Linux itself cannot provide -- because the
enforcement lives below the API, not inside it.

---

## Why This Matters

Linux security (seccomp-bpf, SELinux, AppArmor, namespaces) runs
inside the kernel it's protecting.  A kernel exploit owns the
security framework too.  The enforcement and the attack surface
are the same code.

5BSD separates them.  Linux programs call `clone()`, `mmap()`,
`open()`, `sendmsg()` -- and those calls are translated into BSD
kernel operations before they execute.  Security policy is enforced
at the translation boundary by a MAC framework the Linux code never
touches, on a kernel the Linux code doesn't know about.

This is the same architecture that made microkernels appealing for
security, except it actually runs Linux software at native speed.

### What Linux Gets on 5BSD

| Layer | What It Does |
|-------|-------------|
| **MACF** | 38+ mandatory access control hooks gate every Linux syscall -- fork, exec, mmap, open, socket, signal, mount.  Policy modules are loadable.  No Linux code can bypass or disable them. |
| **Capsicum** | Capability mode for process sandboxing.  Enter capability mode and lose the ability to open new resources.  Works on Linux binaries. |
| **CAP_RT** | Capability-based IPC.  Kernel message passing where the file descriptor IS the credential.  Services are loadable modules.  No new syscalls required. |
| **capprotect** | Per-process integrity shields.  Make a process invisible to ps, immune to ptrace, immune to kill -- enforced by MACF, controlled by capability. |
| **CACL** | Per-descriptor access control.  Bind a file descriptor to a process identity.  Passing it to the wrong process makes it useless.  Exec into a different program revokes access. |
| **Coalition** | Capability-based resource groups.  Supervisor creates a coalition, enlists processes/jails/sockets/devices, and closing the fd kills everything.  Deadlines, watchdogs, leader death triggers, nested coalitions. |
| **HWT/PT** | Hardware instruction tracing (Intel PT).  See exactly what a Linux process executed, at the CPU level, without modifying the process. |

### What Linux Gets on Linux

seccomp-bpf, a BPF program that filters syscall numbers.
Namespaces that isolate the view but not the kernel.
LSMs that run in the same privilege domain as the code they police.

---

## Architecture

```
 Linux programs
      |
      | Linux syscalls (clone, open, sendmsg, ...)
      v
 Linuxulator (syscall translation)
      |
      | FreeBSD syscalls (fork1, VOP_*, sosend, ...)
      v
 MACF enforcement ── policy modules (capprotect, mac_biba, ...)
      |
 Capsicum / CACL ── descriptor-level access control
      |
 Coalition ── coordinated termination (supervisor pattern)
      |
 CAP_RT nonce ── single process identity across all layers
      |
 BSD kernel (VFS, network stack, VM, scheduler)
```

Linux programs don't adapt to this.  They don't know it's there.
They call Linux syscalls and either succeed or get EACCES/EPERM
from a security layer they can't see, can't map, and can't attack
through the Linux API.

---

## Components

### MACF -- Mandatory Access Control Framework

38 new hooks beyond stock FreeBSD, covering:
- Process lifecycle (fork, exec, core dump, thread creation, syscall gating)
- Memory protection (anonymous mmap, mprotect -- W^X enforcement)
- File descriptor layer (dup, inherit, receive, ioctl, mmap, close)
- Vnode operations (create, open, rename, unlink, link, truncate, chmod, chown)
- Mount operations (mount, unmount, remount, snapshot)
- System information (kernel ASLR info disclosure)

All hooks fire on Linux syscalls because the linuxulator translates
to native FreeBSD operations before the kernel executes them.

**Design doc:** [docs/macf-new-hooks.md](docs/macf-new-hooks.md)
**Source:** `sys/security/mac_test_hooks/`

### CAP_RT -- Capability Runtime

Kernel message-passing framework.  One base system change
(`DTYPE_CAP_RT`, two Capsicum rights, one device node) enables
unlimited kernel services as loadable modules.

- Async (taskqueue) and sync (caller-thread) models
- File descriptor passing with Capsicum rights
- Cryptographic program nonce (rotates on exec, inherits on fork)
- capprotect: MACF-backed process integrity shields
- KernelStore: shared capability-based key-value store

See [CAPABILITY_ARCHITECTURE.md](CAPABILITY_ARCHITECTURE.md).

**Source:** `sys/dev/cap_rt/`
**Tests:** `tests/sys/cap_rt/` (116 ATF tests)

### CACL -- Capability Access Control List

Per-descriptor, identity-based access control.  Descriptors carry
an ACL of allowed process identities.  Possession of an fd is no
longer sufficient to use it -- you must be in the ACL.

- Blocks unauthorized fd propagation via SCM_RIGHTS
- Revokes access on exec (new identity, no access)
- Lock mode: deny all operations on a descriptor
- Batch operations across multiple fds and processes
- Best suited for anonymous descriptors (pipes, socketpairs, shm)
  where there is no path to re-open

**Status:** Standalone module (2,045 lines, 20+ tests), targeting
integration.  Will be migrated to use CAP_RT nonce as identity
(currently uses its own independent token).

### Coalition -- Capability-Based Resource Groups

Supervisor pattern for coordinated resource lifecycle.  A coalition
groups processes, jails, sockets, shared memory, devices, and nested
coalitions.  Closing the coalition fd terminates all members.

- Enlist any fd-representable resource (procdesc, jaildesc, socket, shm, cdev)
- Graceful termination (SIGTERM → grace period → SIGKILL)
- Deadline termination (auto-kill after timeout)
- Watchdog/heartbeat (supervisor liveness check)
- Leader death trigger (if leader dies, coalition terminates)
- Nested coalitions (hierarchical supervision, cascade termination)
- Aggregate resource usage monitoring (CPU, memory, faults)
- kqueue event notifications for all lifecycle events
- DTrace SDT probes and audit subsystem integration
- Third-party cdev integration via `vbsd_terminate_ops`

**Status:** Standalone module (2,935 lines, 90+ tests), targeting
integration.

### HWT/PT -- Hardware Trace

Intel Processor Trace support with fixes over stock FreeBSD:
- Race condition fixes in teardown (PMI, SWI, switch-in)
- Correct buffer position from XSAVE save area (not MSR)
- Multi-thread trace fix (TAILQ_FIRST removal)
- PSB/MTC/CYC timing packet support
- TOCTOU fix in context hash removal

**Source:** `sys/dev/hwt/`, `sys/amd64/pt/`

---

## Building

```sh
export MAKEOBJDIRPREFIX=/path/to/5BSD-obj
make buildkernel KERNCONF=GENERIC
```

## Testing

```sh
cd tests/sys/cap_rt && kyua test
cd tests/sys/mac && kyua test
```

## Deployment

```sh
sh deploy-5bsd-vm.sh      # kernel + modules + tests to VM
sh macf-hooks.sh           # MACF hook deployment
```

---

## Roadmap

### Done

- MACF: 38 hooks across process, fd, vnode, mount, memory, system
- CAP_RT: async/sync services, fd passing, kqueue, nonce identity
- capprotect: ptrace/signal/visibility/core shields via MACF
- KernelStore: shared capability store
- HWT/PT: race fixes, buffer fix, timing support
- Linuxulator basics: clone3, close_range, statx, epoll_pwait2,
  memfd_create, copy_file_range, getrandom

### In Progress

- CACL integration from standalone repo
- Coalition integration from standalone repo
- Migrate CACL identity to CAP_RT nonce
- bsdtrace userspace tool for hardware trace decode

### Linuxulator Roadmap

Verified against Linux v7.1-rc1 syscall table (`arch/x86/entry/
syscalls/syscall_64.tbl`, 472 entries through `rseq_slice_yield`)
and Linux kernel source at `/home/koryheard/Projects/linux/`.
The linuxulator has table entries for ~350 syscall numbers, but
~80 of those are DUMMY stubs returning ENOSYS.  Roughly 270 are
truly functional.  The following are prioritized by what real
Linux software requires and ordered by implementation feasibility.

Line counts and implementation details below are from reading
the actual Linux kernel source, not estimates.

#### Step 1: membarrier -- deferred

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 324 | `membarrier` | `kern_membarrier()` in `sys/kern/kern_membarrier.c` |

FreeBSD has the base kernel primitive, but the linuxulator wiring is
deferred until the exposed command set and validation rules line up
cleanly with Linux, especially around the newer RSEQ-specific command
paths.

**Unlocks:** glibc >= 2.32 dlopen/dlclose performance.
Go >= 1.21 GC write barriers.  QEMU TCG code cache invalidation.

**Ref:** `sys/kern/kern_membarrier.c:118` (kern_membarrier),
`sys/kern/kern_membarrier.c:140-229` (all CMD_* handlers)

#### Step 2: pidfd_send_signal -- pdkill wrapper (~50 lines)

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 424 | `pidfd_send_signal` | `pdkill(2)` in `sys/kern/kern_sig.c` |

Linux's implementation (`kernel/signal.c:4066-4117`) resolves
the pidfd via `pidfd_to_pid()`, then calls `kill_pid_info_type()`.
Also supports `PIDFD_SELF_THREAD` and `PIDFD_SELF_THREAD_GROUP`
magic fd values for self-signaling.  Pidfds in Linux are NOT
`/proc/PID` fds — they're backed by a dedicated `pidfs`
pseudo-filesystem (`fs/pidfs.c`, 1182 lines) with custom
`file_operations` including poll (for process exit notification).

FreeBSD's `pdkill()` already takes (fd, signum), resolves the
process descriptor via `procdesc_find()`, and calls
`kern_psignal()`.  The wrapper translates Linux's extra
`siginfo_t *` parameter and calls the existing path.

**Unlocks:** systemd >= 243 targeted signal delivery.

**Ref:** `sys/kern/kern_sig.c:1957` (pdkill implementation),
`sys/kern/sys_procdesc.c:267` (procdesc_find),
Linux: `kernel/signal.c:4066` (pidfd_send_signal),
Linux: `fs/pidfs.c` (pidfs filesystem, 1182 lines)

#### Step 3: signalfd4 -- custom fileops (medium, ~500 lines)

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 289 | `signalfd4` | EVFILT_SIGNAL + new file type |

The kernel has `EVFILT_SIGNAL` (fires via `NOTE_SIGNAL` in
`kern_sig.c`) and the linuxulator already translates epoll to
kqueue in `linux_event.c`.  But signalfd semantics differ:

- `read()` must dequeue pending signals and format them as
  `struct signalfd_siginfo` (128 bytes per signal)
- Signals must be blocked with `sigprocmask` first
- kqueue's EVFILT_SIGNAL only notifies, it doesn't dequeue

Linux implementation is 351 lines (`fs/signalfd.c`).  The context
struct is minimal: just `sigset_t sigmask` (inverted at creation
with `signotset()` — stores "monitor these" not "block these").
SIGKILL/SIGSTOP are always stripped.

The `fo_read` handler calls `dequeue_signal()` under `siglock`,
dequeuing from both `current->pending` (per-thread) and
`current->signal->shared_pending` (process-wide).  Each read
returns one or more 128-byte `signalfd_siginfo` structs (minimum
read size 128 bytes; first read blocks, subsequent in same call
are non-blocking).  Poll registers on a dedicated wait queue
(`current->sighand->signalfd_wqh`), separate from normal signal
delivery.

Implementation: new file object type following the eventfd/timerfd
pattern (`sys/kern/sys_eventfd.c`).  FreeBSD's `fo_read` handler
calls the equivalent signal dequeue path in `kern_sig.c`.  The
128-byte `signalfd_siginfo` struct needs format translation from
BSD `siginfo_t`.  Poll uses `EVFILT_SIGNAL` for kqueue/epoll
integration.

**Unlocks:** systemd sd-event loop.  This is the single biggest
blocker for systemd boot.

**Ref:** `sys/kern/kern_sig.c:113-128` (sig_filtops),
`sys/compat/linux/linux_event.c:79-107` (epoll-to-kqueue pattern),
`sys/kern/sys_eventfd.c` (eventfd fileops template),
Linux: `fs/signalfd.c` (351 lines, full implementation)

#### Step 4: pidfd_open -- extend procdesc (medium-large, ~400 lines)

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 434 | `pidfd_open` | procdesc in `sys/kern/sys_procdesc.c` |

FreeBSD's process descriptors are created only at `pdfork()` time.
The source has an open question at the top of `sys_procdesc.c`:
*"Will we want to add a pidtoprocdesc(2)?"* -- never implemented.

Implementation: new `procdesc_open(pid)` function that:
1. Looks up `struct proc *` via `pfind(pid)`
2. Allocates a new `struct procdesc` via `procdesc_new()`
3. Attaches to the existing proc (handling the case where
   `p->p_procdesc` may already exist from a prior pdfork)
4. Returns the fd via `finstall()`

Needs careful locking: `PROC_LOCK` around the proc lookup,
and the procdesc currently assumes at most one per process
(may need to allow multiple procdesc references or refcount).

**Unlocks:** systemd >= 243 reliable process tracking without
PID recycling races.

**Ref:** `sys/kern/sys_procdesc.c:210` (procdesc_new, fork path),
`sys/kern/sys_procdesc.c:61` (the pidtoprocdesc question),
`sys/kern/sys_procdesc.c:267` (procdesc_find, fd-to-proc lookup)

#### Step 5: futex_waitv + futex2 -- multi-wait on umtxq (medium, ~500 lines)

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 449 | `futex_waitv` | umtxq in `sys/kern/kern_umtx.c` |
| 454 | `futex_wake` | umtxq (new futex2 API, Linux 6.7) |
| 455 | `futex_wait` | umtxq (new futex2 API, Linux 6.7) |
| 456 | `futex_requeue` | umtxq (new futex2 API, Linux 6.7) |

Linux implementation is ~6,000 lines across `kernel/futex/`
(core.c 2015, waitwake.c 755, pi.c 1304, requeue.c 913,
syscalls.c 526).

The multi-wait algorithm (`waitwake.c:402-572`) uses a
**two-phase enqueue**:

Phase 1: resolve all futex keys via `get_futex_key()` (can
sleep for page faults — done before changing task state).

Set `TASK_INTERRUPTIBLE` atomically.

Phase 2: for each futex in sequence: lock hash bucket → re-read
userspace value → if match, `futex_queue()` into bucket's plist
→ unlock bucket.  If any value doesn't match, bail `EWOULDBLOCK`.

Wakeup detection: each `futex_q` has a `lock_ptr` pointing to
its hash bucket spinlock.  When a waker removes a waiter, it
sets `lock_ptr = NULL` via `smp_store_release()`.  The sleeping
thread checks `!READ_ONCE(vs[i].q.lock_ptr)` — if any entry is
NULL, that futex was woken.  `futex_unqueue_multiple()` then
removes from all remaining buckets and returns the woken index.

Memory ordering: the waiters-increment/value-read pair on the
waiter side is paired against the value-write/waiters-check pair
on the waker side via full memory barriers at
`futex_hb_waiters_inc()` and `futex_hb_waiters_pending()`.  This
guarantees the system can never both miss a value change and miss
an enqueue.

FreeBSD mapping: `umtx_key` = `union futex_key`, `umtxq_chain` =
`futex_hash_bucket`.  The existing linuxulator futex code already
calls `umtx_key_get()`/`umtxq_insert()`/`umtxq_sleep()`/
`umtxq_remove()` directly.  The multi-wait extension: insert one
thread into N `umtxq_chain` buckets, sleep, check which bucket
fired via a flag word (analogous to lock_ptr), unqueue from all
others.

The futex2 syscalls (454-456) are thin wrappers in
`kernel/futex/syscalls.c:366-475`.  They call the same core
`futex_wake()`/`__futex_wait()`/`futex_requeue()` functions.
Only real difference: separate parameters instead of multiplexed
`op`, explicit `clockid`, `FLAGS_STRICT` flag.  Size field
supports 8/16/32/64-bit in theory but **only 32-bit is
implemented** — `futex_flags_valid()` rejects all others.

**Unlocks:** Wine/Proton WaitForMultipleObjects (futex_waitv).
Future glibc locking (futex2).  Rust std::sync on newer
toolchains.

**Ref:** `sys/compat/linux/linux_futex.c:738-783` (futex_wait,
shows direct umtxq usage), `sys/kern/kern_umtx.c:4003-4054`
(UMTX_OP_NWAKE_PRIVATE, multi-address wake pattern),
`sys/kern/kern_umtx.c:160-200` (umtxq_insert/remove)

#### Step 6: pidfd_getfd -- cross-process fd extraction (~300 lines)

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 438 | `pidfd_getfd` | None -- new mechanism needed |

No BSD equivalent for grabbing an fd from another process
(SCM_RIGHTS is cooperative/sender-initiated only).

Linux implementation (`kernel/pid.c:917-972`): resolves pidfd
to `struct task_struct` via `get_pid_task()`, calls
`__pidfd_fget(task, fd)` which requires **ptrace permission**
(`ptrace_may_access()`), then `receive_fd()` to install into
the caller's table.

FreeBSD implementation: given a process descriptor fd and a
target fd number, look up the target process's `struct filedesc`,
call `fget()` on the target fd, and `finstall()` into the
caller's table.  Permission check via `p_candebug()` (FreeBSD's
ptrace permission equivalent, matches Linux's `ptrace_may_access`
gate).

Locking: `FILEDESC_SLOCK(targetp->p_fd)` around the lookup,
`fhold()` to bump the refcount before releasing, then
`finstall()` in the caller.

**Ref:** `sys/kern/kern_descrip.c:2116` (fget implementation),
`sys/kern/kern_descrip.c:1847` (finstall),
`sys/sys/filedesc.h` (struct filedesc, locking protocol),
Linux: `kernel/pid.c:917-972` (pidfd_getfd, ptrace gate)

#### Step 7: unshare/setns -- partial namespace support (large)

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 272 | `unshare` | jails + VNET (partial) |
| 308 | `setns` | jail_attach(2) (partial) |

Linux namespaces total ~13,900 lines across 8 types.  The core
is `struct nsproxy` (`kernel/nsproxy.c`, 613 lines) — a
refcounted container of pointers to each namespace instance.
Tasks sharing identical namespaces share one nsproxy.

`unshare()` (`kernel/fork.c:3193`) creates a new nsproxy with
fresh namespaces for each `CLONE_NEW*` flag, then atomically
swaps it under `task_lock()`.  `setns()` (`kernel/nsproxy.c:569`)
accepts `/proc/PID/ns/*` files or pidfds, validates via each
namespace's `install()` op, then commits atomically.

**Per-type complexity from Linux source:**

| Type | Linux LOC | FreeBSD mapping | Feasibility |
|------|-----------|----------------|-------------|
| UTS | 164 | jail hostname | Trivial |
| Cgroup | 144 | rctl(8) | Stub OK |
| Time | 358 | None (vDSO changes) | Medium |
| IPC | 257 | jail SysV isolation | Medium |
| PID | 473 | No PID remapping | Hard |
| User | 1,415 | No UID mapping | Very hard |
| Network | 1,555 | **VNET jails** | Good |
| Mount | 6,531 | No per-process mounts | Extremely hard |

**What maps well:**
- `CLONE_NEWNET` → dynamic VNET jail creation.  FreeBSD's VNET
  provides per-jail network stacks (`PR_VNET` flag, `struct
  vnet *pr_vnet` in `struct prison`).  Linux's `struct net`
  (1,555 lines) and FreeBSD's VNET are architecturally similar.
- `setns(fd, CLONE_NEWNET)` → `jail_attach()` to a jail with VNET.
- `CLONE_NEWUTS` → jail hostname isolation (164 lines in Linux,
  ~50 on FreeBSD — just `strlcpy` of hostname/domainname).
- `CLONE_NEWIPC` → jails already isolate SysV IPC objects.

**What doesn't map (confirmed by reading Linux source):**
- `CLONE_NEWNS` (mount namespace) -- Linux's `fs/namespace.c` is
  6,531 lines built on per-process mount trees (`struct
  mnt_namespace` with rb-tree of mounts).  FreeBSD's VFS has no
  per-process mount table.  Would require major VFS changes.
- `CLONE_NEWPID` (PID namespace) -- Linux uses hierarchical PID
  namespaces (max 32 levels, `kernel/pid_namespace.c`) with per-
  namespace PID allocators (IDR).  FreeBSD PIDs are globally unique.
- `CLONE_NEWUSER` (user namespace) -- Linux's `kernel/user_namespace.c`
  (1,415 lines) implements UID/GID mapping tables (`struct
  uid_gid_map`, up to 340 extents).  No FreeBSD equivalent.
- `CLONE_NEWCGROUP` -- FreeBSD uses rctl(8), not cgroups.

**Recommended approach:** implement `CLONE_NEWNET` only via
dynamic jail+VNET creation.  Return ENOSYS for other namespace
types.  This unblocks Chrome/Firefox (which primarily need
network namespace isolation) and `ip netns`.  Document the
remaining gaps.

**Ref:** `sys/kern/kern_jail.c` (jail infrastructure),
`sys/net/vnet.h` (VNET interface),
`sys/sys/jail.h:196` (pr_vnet in struct prison),
`sys/sys/jail.h:237` (PR_VNET flag),
`sys/sys/jail.h:462` (prison_owns_vnet)

#### Step 8: io_uring -- new subsystem (very large)

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 425-427 | `io_uring_*` | AIO + kqueue + new ring infrastructure |

Linux implementation is **26,553 lines across 86 files** in
`io_uring/`.  62 distinct opcodes.  This is not a syscall to
shim — it's a subsystem.

**Core data structures** (from `io_uring/io_uring_types.h`):
- `io_ring_ctx` (~200 fields): per-instance state, holds rings,
  SQ/CQ arrays, worker pools, 4 allocation caches, cancel hash
  table, file/buffer tables, locks
- `io_kiocb` (~30 fields): per-request struct, opcode, file,
  CQE result, async data, linked request chain, creds snapshot
- `io_uring_sqe` (64 bytes): userspace submission entry
- `io_uring_cqe` (16 bytes): userspace completion entry
- `io_rings`: mmap'd shared struct with SQ/CQ head/tail indices

**Ring protocol** (lock-free, barrier-only):
- SQ: app writes SQEs, bumps tail with `smp_wmb()`.  Kernel
  reads tail with `smp_load_acquire()`, consumes SQEs, writes
  head with `smp_store_release()`.
- CQ: kernel writes CQEs, bumps tail with `smp_store_release()`.
  App reads tail with `smp_load_acquire()`.
- In single-issuer mode (`DEFER_TASKRUN`), CQ posting needs no
  lock at all.  Otherwise uses `completion_lock` spinlock.

**Worker model** (`io-wq.c`, 1,047 lines):
- Two pools: BOUND (hashed by inode, for file I/O, limit
  `min(ncpus * 4, 128)`) and UNBOUND (for network, limit 128)
- Workers run in submitter's MM context
- Work dispatched via `io_wq_enqueue()`, completion posted back
  via `io_req_task_work_add()`

**Fixed resources** (`rsrc.c`, 1,020 lines):
- `IORING_REGISTER_BUFFERS`: pin user pages with
  `get_user_pages_fast`, create bio_vec arrays, charge
  RLIMIT_MEMLOCK.  Eliminates per-op buffer mapping.
- `IORING_REGISTER_FILES`: store file pointers in direct table.
  Eliminates per-op `fget()`.

**SQPOLL mode** (`sqpoll.c`): dedicated kernel thread polls
SQ ring continuously.  Userspace submits by writing to shared
memory — **zero syscalls** for submission.

**Phased approach:**
1. Ring infrastructure: mmap-able SQ/CQ, lock-free producer/
   consumer protocol, kernel worker thread pool backed by
   FreeBSD's `taskqueue`.
2. Basic ops: IORING_OP_READ, IORING_OP_WRITE, IORING_OP_FSYNC
   backed by `kern_readv()`/`kern_writev()`/`kern_fsync()`.
3. Network ops: IORING_OP_ACCEPT, IORING_OP_CONNECT,
   IORING_OP_SEND/RECV backed by `soaccept()`/`soconnect()`/
   `sosend()`/`soreceive()`.
4. Fixed resources: pinned buffers via
   `vm_fault_quick_hold_pages()`, registered files via
   `fget_locked()`.
5. SQPOLL: dedicated kthread.
6. Advanced: multishot accept, linked SQEs, cancel,
   IORING_OP_SPLICE, IORING_OP_POLL_ADD.

**Scale:** 26,553 lines in Linux.  A minimal compatibility layer
(ring + read/write/poll, ~3,000 lines) gets basic programs
running without io_uring's performance benefits.  A real
implementation (~15,000+ lines) is a multi-month project but
delivers the zero-copy, zero-syscall I/O path.

**Ref:** `sys/kern/vfs_aio.c` (async I/O worker infrastructure),
`sys/kern/kern_event.c` (kqueue notification patterns),
`sys/sys/buf_ring.h` (lock-free ring buffer algorithm),
Linux: `io_uring/io_uring.c` (3,259 lines, main entry),
Linux: `io_uring/io-wq.c` (1,047 lines, worker threads),
Linux: `io_uring/rw.c` (475 lines, read/write ops),
Linux: `io_uring/net.c` (1,265 lines, network ops)

#### Step 9: userfaultfd -- user-space page fault handling (large, ~800 lines)

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 323 | `userfaultfd` | `vm_fault()` + new file type |

Linux implementation is 2,231 lines (`fs/userfaultfd.c`) plus
`mm/userfaultfd.c` for page table manipulation.

The context struct (`userfaultfd_ctx`) is substantial: 4
separate wait queues (`fault_pending_wqh`, `fault_wqh`,
`fd_wqh`, `event_wqh`), a `rw_semaphore`, `atomic_t
mmap_changing`, and a reference to `mm_struct`.

**Fault interception** (`handle_userfault()`, lines 381-558):
called from `mm/memory.c` fault paths.  The faulting thread
registers in `fault_pending_wqh`, then validates PTEs **after**
registering (prevents race where page is filled between check
and sleep).  Calls `schedule()` to block.  Woken by
`UFFDIO_COPY`/`UFFDIO_ZEROPAGE`/`UFFDIO_WAKE` ioctls.

**10 ioctl commands:** `UFFDIO_API` (feature negotiation),
`REGISTER`/`UNREGISTER` (set `VM_UFFD_MISSING`/`WP`/`MINOR`
flags on VMAs), `WAKE`, `COPY` (copies pages from userspace
src to faulted dst), `ZEROPAGE`, `WRITEPROTECT`, `CONTINUE`
(minor faults — use existing pagecache page), `POISON`, `MOVE`.

**Event system:** non-cooperative events (fork, remap, unmap)
block the kernel operation until the userspace handler
acknowledges via the event wait queue.

FreeBSD implementation: hook into `vm_fault()` in
`sys/vm/vm_fault.c`.  Registered `vm_map_entry` ranges get a
uffd context pointer.  The `fo_read` handler dequeues fault
events (32-byte `uffd_msg` structs).  The `UFFDIO_COPY` path
manipulates page tables via `pmap_enter()`.  The VMA integration
maps to `vm_map_entry` flags rather than Linux's `vm_area_struct`
flags.

**Unlocks:** CRIU (checkpoint/restore).  QEMU postcopy live
migration.  Garbage collectors with concurrent compaction.

**Ref:** `sys/vm/vm_fault.c` (fault handling path),
`sys/vm/vm_map.h` (vm_map_entry, flag candidates),
Linux: `fs/userfaultfd.c` (2,231 lines),
Linux: `mm/userfaultfd.c` (page fill operations)

#### Phase 10: quality of life (callers have fallbacks)

| # | Syscall | BSD Mapping | Effort |
|---|---------|------------|--------|
| 437 | `openat2` | `kern_openat()` + `RESOLVE_BENEATH` → FreeBSD's `O_RESOLVE_BENEATH` (already exists).  Linux has 6 RESOLVE flags (`fs/open.c:1163-1302`); `RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS` cover 95% of callers.  `RESOLVE_IN_ROOT` needs namei changes. | Small |
| 322 | `execveat` | `kern_execve()` with `AT_EMPTY_PATH` fd resolution.  Linux (`fs/exec.c:1778-1971`) routes through same `do_execveat_common()` as execve.  FreeBSD has `fexecve(2)` natively. | Small |
| 310-311 | `process_vm_readv/writev` | `proc_rwmem()` in `sys/kern/sys_process.c`.  Linux (`mm/process_vm_access.c`, 306 lines) pins pages with `pin_user_pages_remote()`, copies with `copy_page_to_iter()`, gates on ptrace permission.  FreeBSD: resolve PID → proc, `p_candebug()` check, `proc_rwmem()` per iovec. | Medium |
| 327-328 | `preadv2/pwritev2` | `kern_preadv()/kern_pwritev()` plus `pos=-1` and `RWF_*` compatibility work | Small |
| 325 | `mlock2` | `kern_mlock()` + `MLOCK_ONFAULT` flag (populate-on-fault via `VM_MAP_WIRE_NOHOLE`) | Small |
| 452 | `fchmodat2` | `kern_fchmodat()` + `AT_SYMLINK_NOFOLLOW` flag (FreeBSD `lchmod` path) | Small |
| 305 | `clock_adjtime` | `kern_ntp_adjtime()` / `ntp_adjtime(2)` -- direct wrapper | Small |
| 314-315 | `sched_setattr/getattr` | `kern_sched_setparam()` / `kern_sched_getparam()` + SCHED_DEADLINE stub | Small |
| 313 | `finit_module` | Linux-style module loading entrypoint; needs fd-backed loader compatibility work | Medium |
| 451 | `cachestat` | `mincore()` for basic page-resident info; no direct equivalent for dirty/writeback counts | Small |
| 428-433 | New mount API | `kern_nmount()` (legacy mount covers all cases) | Medium |
| 442 | `mount_setattr` | `kern_nmount()` with MS_REMOUNT | Small |
| 457-458 | `statmount/listmount` | `getfsstat(2)` + `statfs(2)` (different shape, same data) | Medium |

#### Deliberately not implemented (superseded by 5BSD)

These Linux security features are replaced by the BSD security
stack.  The linuxulator returns ENOSYS; 5BSD provides the equivalent
enforcement from below the API where Linux code cannot bypass it.

| Linux Feature | # | 5BSD Replacement |
|---------------|---|-----------------|
| seccomp | 317 | MACF `mac_proc_check_syscall` -- same per-syscall gating, enforced below the Linux API |
| Landlock | 444-446 | MACF vnode/mount/process hooks + CACL for descriptor-level control |
| LSM query API | 459-461 | MACF policy modules -- loaded below the Linux API boundary |
| perf_event_open | 298 | HWT/PT -- hardware instruction tracing at the CPU level |
| bpf (eBPF) | 321 | Not now.  HWT/PT covers observability.  DTrace covers kernel tracing.  eBPF may come later for networking use cases. |

### Security Stack Roadmap

#### Unified nonce identity

CAP_RT already assigns a cryptographic nonce per credential
(rotates on exec, inherits on fork).  Currently capprotect uses
it; CACL has its own independent token.

1. **Migrate CACL to CAP_RT nonce** -- one identity across all
   enforcement layers.  CACL keeps its refcount tracking for lazy
   cleanup but reads the nonce from the CAP_RT credential label
   instead of generating its own.

2. **Coalition nonce-based enlistment** -- convenience operation
   to enlist all processes sharing a nonce (fork family) into a
   coalition, rather than requiring individual procdesc fds.

3. **Nonce-based resource accounting** -- extend `rctl(8)` or
   build a new accounting layer keyed by nonce.  Track CPU, memory,
   I/O, and network usage per program identity, not just per-pid
   or per-jail.  This is the BSD answer to Linux cgroups: identity-
   based accounting that survives fork and resets on exec, enforced
   below the Linux API.  Coalition already has aggregate rusage
   (`VBSD_COALITION_RUSAGE`) -- extend this to work by nonce across
   the system, not just within a single coalition.

Once unified, the nonce becomes 5BSD's single answer to "who is
this process" across four layers:

| Layer | Nonce Question |
|-------|---------------|
| capprotect | Can this nonce ptrace/signal/see that nonce? |
| CACL | Is this nonce in this descriptor's ACL? |
| Coalition | Enlist/track all processes with this nonce |
| Resource accounting | How much CPU/memory/IO has this nonce used? |

#### Module integration

- Integrate CACL into 5BSD tree from standalone repo
- Integrate Coalition into 5BSD tree from standalone repo
- Wire coalition terminate ops into CAP_RT services
  (coalition close revokes CAP_RT instances)

#### Planned

- Kernel-to-kernel capability communication design
- Second IP range for library-level PT filtering
- PT profiling mode + bsdtrace integration

---

## Upstream Strategy

Structured for FreeBSD contribution:

- All custom work is in loadable modules
- MACF hooks follow existing MAC framework patterns
- HWT/PT fixes are pure bug fixes applicable to upstream
- File names chosen to avoid merge conflicts

Base system touches are minimal: `DTYPE_CAP_RT` in `sys/sys/file.h`,
two Capsicum rights in `sys/sys/capsicum.h`.

```sh
git fetch freebsd main
git merge freebsd/main
```
