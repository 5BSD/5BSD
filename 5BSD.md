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
| **vnode_claim** | Per-descriptor access control.  Bind a file descriptor to a process identity.  Passing it to the wrong process makes it useless.  Exec into a different program revokes access. |
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
 Capsicum / vnode_claim ── descriptor-level access control
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

### vnode_claim -- Capability Access Control List

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

CAP_RT sync service for coordinated resource lifecycle.  A coalition
groups cap_rt instances, processes, jails, sockets, shared memory,
and nested coalitions.  Closing the coalition fd revokes all members.

- Enlist any fd: cap_rt capabilities, procdesc, jaildesc, socket, shm
- Cap_rt members terminated via `cap_rt_instance_revoke()`
- Graceful termination (SIGTERM → grace period → SIGKILL)
- Deadline termination (auto-kill after timeout)
- Watchdog/heartbeat (supervisor liveness check)
- Leader death trigger (process exit, jail destroy, cap_rt instance revoke)
- Nested coalitions (cycle detection, cascade termination)
- Aggregate resource usage monitoring (CPU, memory, faults)
- Service name tracking for cap_rt member types
- DTrace SDT probes

**Source:** `sys/dev/cap_rt/cap_rt_coalition.c` (CAP_RT service)
**Tests:** `tests/sys/cap_rt/cap_rt_coalition_test.c` (40+ ATF tests)

### HWT/PT -- Hardware Trace

Intel Processor Trace support with fixes over stock FreeBSD:
- Race condition fixes in teardown (PMI, SWI, switch-in)
- Correct buffer position from XSAVE save area (not MSR)
- Multi-thread trace fix (TAILQ_FIRST removal)
- PSB/MTC/CYC timing packet support
- TOCTOU fix in context hash removal

**Source:** `sys/dev/hwt/`, `sys/amd64/pt/`

---

## Installing

5BSD installs over FreeBSD 16-CURRENT via pkgbase.  Build packages
from source, disable the upstream base repo, and `pkg upgrade`.
ZFS boot environments provide rollback.

See [docs/pkgbase-install.md](docs/pkgbase-install.md) for the
full procedure.

```sh
make -j$(sysctl -n hw.ncpu) buildworld KERNCONF=5BSD
make -j$(sysctl -n hw.ncpu) buildkernel KERNCONF=5BSD
make stage-packages KERNCONF=5BSD
make create-packages KERNCONF=5BSD

bectl create pre-upgrade-$(date +%Y%m%d)
pkg update && pkg upgrade
reboot
```

The kernel ident is `VBSD` (config(8) does not allow leading digits).
Cap_rt modules load automatically via `stand/defaults/loader.conf`.

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
- Coalition: CAP_RT sync service with cap_rt member revocation,
  process/jail/socket termination, nested coalitions, graceful
  shutdown, deadline/watchdog timers, leader death monitoring
- HWT/PT: race fixes, buffer fix, timing support
- bsdtrace: userspace tool for hardware trace decode
- Linuxulator basics: clone3, close_range, statx, epoll_pwait2,
  memfd_create, copy_file_range, getrandom

### In Progress

- vnode_claim integration
- Migrate vnode_claim identity to CAP_RT nonce

### Security Stack Roadmap

#### Unified nonce identity

CAP_RT already assigns a cryptographic nonce per credential
(rotates on exec, inherits on fork).  Currently capprotect uses
it; vnode_claim has its own independent token.

1. **Migrate vnode_claim to CAP_RT nonce** -- one identity across all
   enforcement layers.  vnode_claim keeps its refcount tracking for lazy
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
| vnode_claim | Is this nonce in this descriptor's ACL? |
| Coalition | Enlist/track all processes with this nonce |
| Resource accounting | How much CPU/memory/IO has this nonce used? |

#### Module integration

- Integrate vnode_claim into 5BSD tree from standalone repo
- ~~Integrate Coalition into 5BSD tree from standalone repo~~
  **Done** -- coalition is now a CAP_RT sync service
  (`sys/dev/cap_rt/cap_rt_coalition.c`)
- ~~Wire coalition terminate ops into CAP_RT services~~
  **Done** -- coalition uses `cap_rt_instance_revoke()` for
  cap_rt members, no separate terminate_ops registry needed

#### Planned

- Kernel-to-kernel capability communication design
- HWT/PT ARM support (requires ARM hardware with tracing)

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
