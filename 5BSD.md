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

Per-descriptor, identity-based access control.  Each process has a
random token (refreshed on exec).  Descriptors carry an ACL of
allowed tokens.  Possession of an fd is no longer sufficient to use
it -- you must be in the ACL.

- Blocks unauthorized fd propagation via SCM_RIGHTS
- Revokes access on exec (new program, new token, no access)
- Lock mode: deny all operations on a descriptor
- Batch operations across multiple fds and processes

**Status:** Standalone module, targeting integration.

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
- bsdtrace userspace tool for hardware trace decode

### Linuxulator Roadmap

Verified against Linux 7.0-rc7 syscall table (`arch/x86/entry/
syscalls/syscall_64.tbl`).  The linuxulator currently implements
~310 of 472 syscalls.  The following are prioritized by what real
Linux software requires and ordered by implementation feasibility.

#### Step 1: membarrier -- direct wrapper (~30 lines)

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 324 | `membarrier` | `kern_membarrier()` in `sys/kern/kern_membarrier.c` |

FreeBSD already has a **complete implementation** of membarrier
with all the commands glibc and Go need: `CMD_PRIVATE_EXPEDITED`,
`CMD_PRIVATE_EXPEDITED_SYNC_CORE`, `CMD_GLOBAL_EXPEDITED`, and
`CMD_GET_REGISTRATIONS`.  Uses `pmap_active_cpus()` +
`smp_rendezvous_cpus()` internally.

The linuxulator just needs a thin wrapper that translates Linux
command constants and calls `kern_membarrier()`.

**Unlocks:** glibc >= 2.32 dlopen/dlclose performance.
Go >= 1.21 GC write barriers.  QEMU TCG code cache invalidation.

**Ref:** `sys/kern/kern_membarrier.c:118` (kern_membarrier),
`sys/kern/kern_membarrier.c:140-229` (all CMD_* handlers)

#### Step 2: pidfd_send_signal -- pdkill wrapper (~50 lines)

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 424 | `pidfd_send_signal` | `pdkill(2)` in `sys/kern/kern_sig.c` |

`pdkill()` already takes (fd, signum), resolves the process
descriptor via `procdesc_find()`, and calls `kern_psignal()`.
The wrapper translates Linux's extra `siginfo_t *` parameter
and calls the existing path.

**Unlocks:** systemd >= 243 targeted signal delivery.

**Ref:** `sys/kern/kern_sig.c:1957` (pdkill implementation),
`sys/kern/sys_procdesc.c:267` (procdesc_find)

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

Implementation: new file object type following the eventfd/timerfd
pattern (`sys/kern/specialfd.h`).  The `fo_read` handler dequeues
signals from the thread's pending set using the existing
`sig_freenote()`/`sigqueue_take()` infrastructure in `kern_sig.c`
and formats them as Linux siginfo structs.  The `fo_poll`/`fo_kqfilter`
side uses EVFILT_SIGNAL for epoll integration.

**Unlocks:** systemd sd-event loop.  This is the single biggest
blocker for systemd boot.

**Ref:** `sys/kern/kern_sig.c:113-128` (sig_filtops),
`sys/compat/linux/linux_event.c:79-107` (epoll-to-kqueue pattern),
`sys/kern/sys_eventfd.c` (eventfd fileops template)

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

#### Step 5: futex_waitv -- multi-wait on umtxq (medium, ~300 lines)

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 449 | `futex_waitv` | umtxq in `sys/kern/kern_umtx.c` |

The linuxulator's existing futex code (`linux_futex.c`) already
calls umtxq primitives directly -- `umtx_key_get()`,
`umtxq_insert()`, `umtxq_sleep()`, `umtxq_remove()`.  FreeBSD
has multi-wake (`UMTX_OP_NWAKE_PRIVATE` at `kern_umtx.c:4003`)
but no multi-wait.

Implementation: insert one thread into N umtxq hash chains
simultaneously, sleep until any one fires, then remove from
all chains.  Conceptually identical to how `poll()` registers
across multiple fds.  Each `struct futex_waitv` entry maps to
one umtx_key + queue insertion.

Main challenge: the wakeup path must find and wake a thread
that's sleeping across multiple queues.  Use a shared `struct
umtx_q` with a single `sleepq` entry and cross-link all the
queue positions.

**Unlocks:** Wine/Proton WaitForMultipleObjects.  This was
the specific syscall added to Linux for Wine's use case.

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

Implementation: given a process descriptor fd and a target fd
number, look up the target process's `struct filedesc`, call
`fget()` on the target fd number, and `finstall()` into the
caller's table.

Locking: `FILEDESC_SLOCK(targetp->p_fd)` around the lookup,
`fhold()` to bump the refcount before releasing, then
`finstall()` in the caller.  Must verify the caller has
appropriate privilege (root, or same UID, or procdesc owner).

**Ref:** `sys/kern/kern_descrip.c:2116` (fget implementation),
`sys/kern/kern_descrip.c:1847` (finstall),
`sys/sys/filedesc.h` (struct filedesc, locking protocol)

#### Step 7: unshare/setns -- partial namespace support (large)

| # | Syscall | BSD Primitive |
|---|---------|--------------|
| 272 | `unshare` | jails + VNET (partial) |
| 308 | `setns` | jail_attach(2) (partial) |

This is the hardest mapping.  Linux namespaces are per-process
and fine-grained (mount, PID, net, user, UTS, cgroup -- each
independent).  FreeBSD jails bundle everything and are
jail-scoped, not process-scoped.

**What maps:**
- `CLONE_NEWNET` → dynamic VNET jail creation.  FreeBSD's VNET
  provides per-jail network stacks (`PR_VNET` flag, `struct
  vnet *pr_vnet` in `struct prison`).  Creating a new jail with
  VNET gives an isolated network namespace.
- `setns(fd, CLONE_NEWNET)` → `jail_attach()` to a jail with VNET.
- `CLONE_NEWUTS` → jail hostname isolation (trivial).

**What doesn't map (significant gaps):**
- `CLONE_NEWNS` (mount namespace) -- no per-process mount table.
  Would require major VFS changes.
- `CLONE_NEWPID` (PID namespace) -- no PID remapping.  Jails
  restrict visibility but PIDs are globally unique.
- `CLONE_NEWUSER` (user namespace) -- no per-namespace UID mapping.
- `CLONE_NEWCGROUP` -- no cgroups at all (FreeBSD uses rctl(8)).

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

No shared-memory ring buffer exists in FreeBSD's kernel.
`buf_ring` (`sys/sys/buf_ring.h`) is kernel-internal only (for
NIC TX queues).  AIO (`sys/kern/vfs_aio.c`) provides per-request
async I/O but no batching.  kqueue handles notification but not
I/O submission.

**Architecture:** io_uring requires mmap-able submission (SQ) and
completion (CQ) queues shared between userspace and the kernel.
The zero-syscall submission path is the entire performance value.

**Phased approach:**
1. Ring infrastructure: mmap-able SQ/CQ, lock-free producer/
   consumer protocol, kernel worker thread pool.
2. Basic ops: IORING_OP_READ, IORING_OP_WRITE, IORING_OP_FSYNC
   backed by existing VFS read/write/fsync paths.
3. Network ops: IORING_OP_ACCEPT, IORING_OP_CONNECT,
   IORING_OP_SEND/RECV backed by existing socket layer.
4. Advanced: fixed buffers, multishot accept, linked SQEs,
   IORING_OP_SPLICE, registered files.

**Scale:** Linux's io_uring is ~15K+ lines.  A minimal
compatibility layer translating to AIO would lose the zero-copy
benefit.  A proper implementation is a multi-month project.

**Ref:** `sys/kern/vfs_aio.c` (async I/O worker infrastructure),
`sys/kern/kern_event.c` (kqueue notification patterns),
`sys/sys/buf_ring.h` (lock-free ring buffer algorithm),
Linux source: `io_uring/` directory in kernel tree

#### Phase 9: quality of life (callers have fallbacks)

| # | Syscall | BSD Mapping | Effort |
|---|---------|------------|--------|
| 437 | `openat2` | `kern_openat()` + RESOLVE_BENEATH via `VN_OPEN_BENEATH` (FreeBSD already has `O_BENEATH` in VFS) | Small |
| 322 | `execveat` | `kern_execve()` with `AT_EMPTY_PATH` fd resolution | Small |
| 310-311 | `process_vm_readv/writev` | `ptrace(PT_IO)` or direct `proc_rwmem()` | Medium |
| 327-328 | `preadv2/pwritev2` | `kern_preadv()` + per-flag handling (RWF_NOWAIT → O_NONBLOCK, RWF_DSYNC → fdatasync) | Small |
| 314-315 | `sched_setattr/getattr` | `kern_sched_setparam()` / `kern_sched_getparam()` + SCHED_DEADLINE stub | Small |
| 428-433 | New mount API | `kern_nmount()` (legacy mount covers all cases) | Medium |
| 442 | `mount_setattr` | `kern_nmount()` with MS_REMOUNT | Small |

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

### Planned (security and tracing)

- CACL integration into 5BSD tree
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
