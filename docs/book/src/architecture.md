# Architecture Overview

5BSD is a FreeBSD 16-CURRENT derivative (kernel ident `VBSD`) in which the
Linuxulator is treated as the primary application binary interface and a
capability-oriented security stack enforces policy beneath it.

## Design principles

The shape of 5BSD follows from a handful of deliberate decisions. Read these
first; the rest of the Epic is their consequences.

- **Authority is a held capability, not a uid.** A uid, PID, path, or socket
  peer-credential grants nothing; what a process can do is exactly what it holds
  an unforgeable descriptor for. See [The Authority
  Model](security/authority-model.md).
- **A hybrid by design — the secure realm sits beside UNIX.** The
  capability-authority plane runs *alongside* the traditional BSD system, not as
  a replacement, so adoption is incremental and the machine stays working at
  every step. `authority-init` can hand off to stock `init`
  (`capability_plane="NO"`), `serviced` coexists with `rc(8)`, and
  `reboot`/`halt`/signals stay standard. FreeBSD 16 is the last base adopted
  wholesale; the secure realm subsumes the old model over time rather than on a
  flag day.
- **One mint boundary.** Authority is created in one explicit place —
  `authority-init` at boot, and the [auth-agent](security/session-mint.md) for
  login sessions — and flows everywhere else by delegation. `login`/`su`/`sshd`
  do not classify principals or mint; they *ask*.
- **Domains scope reach.** Every lookup channel carries a domain — **SYSTEM**
  (admin, resolves everything), **USER** (per-uid, a small allow-list), or
  **CONTROL** (the admin control plane) — and domains only ever narrow. The
  policy that assigns a principal its domain lives in one file,
  `/Capabilities/Config/principal-policy.ucl`.
- **Reached through a library, never a raw protocol.** Programs use typed
  libraries (`libservice`, `libcapbundle`, …), not hand-rolled sockets or
  `getpeereid(3)`; operator and system policy lives in manifests, not code.
- **`/Capabilities`, not an FHS clone.** The capability plane's files are laid
  out per-capability, not as a `/etc`+`/var` mirror. See [Capability Filesystem
  Hierarchy](system/capability-hier.md).
- **Security below the API, not inside it.** Enforcement lives beneath the
  Linux syscall boundary, on a kernel the Linux code cannot see or attack
  through the API.
- **64-bit only** (below), and **structured for clean upstream tracking** —
  custom kernel work is loadable modules with minimal base-system touches.

## 64-bit only

5BSD is a **64-bit-only** operating system — there is no 32-bit support of any
kind: no 32-bit libraries (`lib32`), no 32-bit userland, no 32-bit binary
compatibility (`COMPAT_FREEBSD32`), no 32-bit build targets (i386, armv7), and
no 32-bit installer options. This is structural, not merely a default:
TrustedZFS capability descriptors — the foundation of the storage plane —
`#error` at compile time on any non-64-bit kernel or user ABI, so the capability
daemons cannot be built 32-bit at all. Supported architectures are the 64-bit
ones: `amd64`, `arm64` (aarch64), `powerpc64`/`powerpc64le`, and `riscv64`.
`MK_LIB32` is unconditionally off and cannot be enabled.

## The enforcement stack

```
 Linux programs
      |
      | Linux syscalls (clone, open, sendmsg, ...)
      v
 Linuxulator (syscall translation)
      |
      | FreeBSD syscalls (fork1, VOP_*, sosend, ...)
      v
 MACF enforcement ── policy modules (capprotect, mac_abac, mac_biba, ...)
      |
 Capsicum / vnode_claim ── descriptor-level access control
      |
 Coalition ── coordinated termination (supervisor pattern)
      |
 MAC_CAPABILITY nonce ── single process identity across all layers
      |
 BSD kernel (VFS, network stack, VM, scheduler)
```

Every layer below the Linuxulator is invisible to Linux code. Policy
decisions surface only as `EACCES`/`EPERM` on ordinary syscalls.

## Core kernel components

### MACF — Mandatory Access Control Framework

38+ new hooks beyond stock FreeBSD, covering process lifecycle (fork, exec,
core dump, thread creation, syscall gating), memory protection (anonymous
`mmap`, `mprotect` — W^X enforcement), the file-descriptor layer (dup,
inherit, receive, ioctl, mmap, close), vnode operations, mount operations,
and system-information disclosure (kernel ASLR). All hooks fire on Linux
syscalls because the Linuxulator translates to native operations before the
kernel executes them. The design mapping that scoped the hook set is in
the source tree at `docs/macf-new-hooks.md` (an XNU-comparison document —
later commits added hooks beyond it, such as `mac_vnode_check_close`).

### MAC_CAPABILITY — the capability framework

The kernel message-passing framework. One base-system change —
`DTYPE_MAC_CAPABILITY`, standard Capsicum rights with ioctl limits, one
device node —
enables unlimited kernel services as loadable modules:

- Async (taskqueue) and sync (caller-thread) service models
- File-descriptor passing governed by Capsicum rights
- A cryptographic per-process nonce that rotates on `exec` and is inherited
  on `fork` — the single process identity used across all layers
- capprotect: MACF-backed process integrity shields
- KernelStore: a shared, capability-gated key-value store

Source: `sys/dev/mac_capability/`; ~490 ATF test cases across 15 test
programs under
`tests/sys/mac_capability/`. Details in the
[MAC Capability Framework](security/mac-capability.md) chapter.

### Descriptor-level access control

**Capsicum** capability mode works on Linux binaries. **vnode_claim** adds
per-descriptor ACLs of allowed process identities — possession of an fd is
no longer sufficient to use it (see
[Process Protections](security/process-protections.md) and
[Descriptor Types](security/descriptors.md)).

### Coalition — resource groups

A MAC_CAPABILITY sync service grouping capabilities, processes, jails,
sockets, shared memory, and nested coalitions. Closing the coalition fd
revokes all members; graceful termination, deadlines, watchdogs, and
leader-death triggers are built in.

### HWT/PT — hardware trace

The machine-independent HWT framework (`sys/dev/hwt/`) with
per-architecture backends — Intel PT on amd64 (`sys/amd64/pt/`, Intel
CPUs only) and ARM SPE on arm64 (`sys/arm64/spe/`) — with correctness
fixes over stock FreeBSD, feeding the
[Observability](observability/dtrace.md) stack.

## New system calls

5BSD adds the following system calls (`sys/kern/syscalls.master`), all
Capsicum-enabled:

| # | Syscall | Purpose |
|---|---------|---------|
| 600 | `pdrfork(2)` | `rfork` returning a process descriptor |
| 601 | `pdwait(2)` | wait on a process descriptor |
| 602 | `renameat2(2)` | Linux-compatible rename with flags |
| 603 | `cap_xfer_limit(2)` | per-fd transfer state (`CAP_XFER_*`) |
| 604 | `cap_cloexec_limit(2)` | one-way close-on-exec propagation lock |
| 605 | `cap_clofork_limit(2)` | one-way close-on-fork propagation lock |
| 606 | `cap_xfer_rights_limit(2)` | rights ceiling applied after transfer |
| 607 | `cap_xfer_ioctls_limit(2)` | ioctl allowlist applied after transfer |
| 608 | `cap_xfer_fcntls_limit(2)` | fcntl allowlist applied after transfer |
| 630 | `pdself(2)` | process descriptor for the calling process |
| 631 | `pdcmp(2)` | compare two process descriptors |
| 633 | `pdincapmode(2)` | query a target's capability mode via procdesc |
| 634 | `cap_mmap_capmode(2)` | monotonic flag: fd may only be mmapped from capability mode |
| 635 | `cap_lookup_capmode(2)` | monotonic flag: fd usable as `*at` dirfd only from capability mode |

The transfer family is covered in
[Capability Transfer](security/capability-transfer.md); the procdesc
family in [Process Protections](security/process-protections.md).
Everything else 5BSD adds to the kernel is reachable without new
syscalls — capability services are ioctls on `/dev/mac_capability`
descriptors, and envfd creation goes through the specialfd path
(`envfd(2)`).

## Userland stacks

Above the kernel core, 5BSD adds capability-brokered system daemons and
product stacks, each covered in its own section:

| Stack | Components | Section |
|-------|-----------|---------|
| Init & services | `authorityd` (PID 1 capable), `serviced`, `authorityctl` | [System Services](system/authority-init.md) |
| Virtualization | WASPNest (bhyve), VirtIO models, vsock, migration | [Virtualization](virtualization/overview.md) |
| Bluetooth | `blued`, `meshd`, `bluedctl`/`meshctl` (skyblue rename pending) | [Bluetooth](bluetooth/overview.md) |
| Storage | TrustedZFS, `tzfsd`, `tzfsctl`, tzfs-flavors | [Storage](storage/trustedzfs.md) |
| Endpoint security | OES clients over MACF | [Endpoint Security](security/endpoint-security.md) |
| Observability | libotelexport, bsdinstruments, hwtlm, DTrace | [Observability](observability/observablebsd.md) |

Daemons log with subsystem tags (`[AUTHORITY]`, `[SERVICE]`, `[TZFS]`) into the
unified logging design. Services declare their needs via manifest files and
capability bundles (see [Service Manifests](system/manifests.md) and
[Capability Bundles](security/capability-bundles.md)).

## Installing

For a fresh machine or VM, build the release memstick and boot the
installer ([Building 5BSD](operations/building.md)). For an existing
FreeBSD 16-CURRENT pkgbase system, build local 5BSD packages, disable the
upstream `FreeBSD-base` repository, and upgrade through `pkg`
([Packaging](operations/packaging.md)). MAC capability modules load
automatically via `stand/defaults/loader.conf`.
