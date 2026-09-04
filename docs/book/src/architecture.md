# Architecture Overview

5BSD is a capability-oriented operating system that runs its own kernel —
the **5BSD kernel**. 5BSD descends from FreeBSD but is charting its own
course; this book documents 5BSD as it is, in its own terms. The system is
a hybrid: the capability plane —
authority as held, unforgeable descriptors, brokered by named services — runs
beside the traditional BSD system, and the kernel's MAC/capability security
stack enforces policy beneath every application ABI, the Linuxulator included.
The kernel modifications (the MAC_CAPABILITY framework, the new MACF hooks and
system calls, the hardware-trace backends) are detailed below; the kernel
configuration itself is covered in [Building 5BSD](operations/building.md).

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
  every step. `capsule` can hand off to the classic `init(8)`
  (`capability_plane="NO"`), `serviced` coexists with `rc(8)`, and
  `reboot`/`halt`/signals stay standard. The secure realm subsumes the old
  model over time rather than on a flag day.
- **One mint boundary.** Authority is created in one explicit place —
  `capsule` at boot, and the [auth-agent](security/authority-model.md) for
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
  out per-capability, not as a `/etc`+`/var` mirror. See [the `/Capabilities`
  hierarchy](system/serviced.md#the-capabilities-hierarchy).
- **Security below the API, not inside it.** Enforcement lives beneath the
  Linux syscall boundary, on a kernel the Linux code cannot see or attack
  through the API.
- **64-bit only** (below), and **structured as loadable modules** —
  custom kernel work ships as modules with minimal base-kernel touches.

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
      | native kernel operations (fork1, VOP_*, sosend, ...)
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

## Running Linux software

The Linuxulator translates Linux syscalls into native
kernel operations *before* they execute, so the whole enforcement stack above
polices Linux binaries with no separate "Linux hooks" to maintain.
Enforcement below the translation boundary is the point: Linux's own
mechanisms — seccomp-bpf, SELinux, AppArmor, namespaces — run *inside* the
kernel they protect, so a kernel exploit owns the security framework too.
5BSD enforces beneath the boundary, by a MAC and capability layer the Linux
code never touches; a Linux program does not adapt to it and cannot attack
through it — it simply succeeds, or receives `EACCES`/`EPERM` from a layer
it cannot see. How 5BSD ships the Linux ABI:

- **Enabled by default.** `linux_common.ko` and `linux64.ko` load from
  `stand/defaults/loader.conf`, and `linux_enable`/`linux_mounts_enable`
  default to `YES` in `libexec/rc/rc.conf`, so Linux jails work out of the
  box. 64-bit Linux only, consistent with the platform.
- **ABI target: RHEL/Rocky.** The Linuxulator is developed and tested against
  a **Rocky Linux 9** userland — an official minimal container base unpacked
  into a jail root — because Rocky mirrors the ABI surface enterprise
  environments certify against. The reported kernel version defaults to
  5.15.0 (`compat.linux.osrelease`, per-prison writable), which satisfies the
  glibc floor checks of that generation.
- **Coverage.** The syscall surface that generation of userland exercises
  is functional, and additions follow the enforcement discipline — Linux
  debugging and tty-revocation paths pass through the same MAC policy as
  native code.
- **Capability-mediated Linux filesystems.** The Linux compatibility
  filesystems are on the mac_capability mount whitelist, so Linux jails can
  be assembled by supervised services without ambient mount privilege.

## Core kernel components

### MACF — Mandatory Access Control Framework

5BSD extends MACF with new hooks covering process lifecycle, memory
protection (W^X enforcement), the file-descriptor layer, vnode and mount
operations, and system-information disclosure. All hooks fire on Linux
syscalls because the Linuxulator translates to native operations before the
kernel executes them.

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

Details in the [MAC Capability Framework](security/mac-capability.md)
chapter.

### Descriptor-level access control

**Capsicum** capability mode works on Linux binaries. **vnode_claim** adds
per-descriptor ACLs of allowed process identities — possession of an fd is
no longer sufficient to use it (see
[Process Protections](security/process-protections.md) and
[Descriptor Types](security/mac-capability.md)).

### Coalition — resource groups

A MAC_CAPABILITY sync service grouping capabilities, processes, jails,
sockets, shared memory, and nested coalitions. Closing the coalition fd
revokes all members; graceful termination, deadlines, watchdogs, and
leader-death triggers are built in.

### HWT/PT — hardware trace

The machine-independent HWT framework with per-architecture backends —
Intel PT on amd64 (Intel CPUs only) and ARM SPE on arm64 — feeding the
[Observability](observability/observablebsd.md) stack.

## New system calls

5BSD adds a small, Capsicum-enabled syscall surface in three families: the
process-descriptor family (`pdrfork(2)`, `pdwait(2)`, `pdself(2)`, and
friends — see [Process Protections](security/process-protections.md)), the
capability transfer and propagation family (`cap_xfer_limit(2)` and
friends — see
[Transfer and propagation](security/mac-capability.md#transfer-and-propagation)),
and a Linux-compatible `renameat2(2)`. Everything else 5BSD adds to the
kernel is reachable without new syscalls — capability services are ioctls
on `/dev/mac_capability` descriptors, and envfd creation goes through the
specialfd path (`envfd(2)`).

## Userland stacks

Above the kernel core, 5BSD adds capability-brokered system daemons and
product stacks, each covered in its own section:

| Stack | Components | Section |
|-------|-----------|---------|
| Init & services | `capsule` (PID 1), `authorityd`, `serviced` (launcher), `authorityctl`, and the capability providers `tzfsd` (Filesystem), `warden` (Namespace), `sysextd` (SystemExtension), `vmd` (VM), `authagentd` (AuthAgent), `logd` (Log), `localnetwork` (Network), `traced` (Trace), `auditbrokerd` (Audit), `localcrypto` (Crypto), `bsdnotify` (Notify) | [System Services](system/capsule.md) |
| Virtualization | WASPNest (bhyve), VirtIO models, vsock, migration | [Virtualization](virtualization/overview.md) |
| Bluetooth | `blued`, `meshd`, `bluedctl`/`meshctl` | [Bluetooth](bluetooth/overview.md) |
| Storage | TrustedZFS, `tzfsd`, `tzfsctl` | [Storage](storage/trustedzfs.md) |
| Endpoint security | OES clients over MACF | [Endpoint Security](security/endpoint-security.md) |
| Observability | libotelexport, bsdinstruments, hwtlm, DTrace | [Observability](observability/observablebsd.md) |

Daemons log with subsystem tags (`[AUTHORITY]`, `[SERVICE]`, `[TZFS]`) into the
unified logging design. Services ship as capability bundles whose manifests
declare only how to launch a program; a unit acquires whatever capabilities it
needs at runtime, by name, scoped to its unforgeable channel label (see
[Capability bundle manifests](system/manifests.md) and
[Capability Bundles](security/capability-bundles.md)).

## Installing

For a fresh machine or VM, build the release memstick and boot the
installer; an existing pkgbase system can migrate to the `5BSD-*` package
sets through `pkg` — [Building 5BSD](operations/building.md) covers both.
MAC capability modules load automatically via
`stand/defaults/loader.conf`.
