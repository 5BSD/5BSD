# Introduction

5BSD is a BSD kernel that implements the Linux API with a security layer
underneath it.

Traditional UNIX compatibility means running old UNIX programs. 5BSD takes a
different approach: the Linux syscall interface is a first-class target, and
every Linux syscall passes through a BSD security stack that Linux itself
cannot provide — because the enforcement lives below the API, not inside it.

## Why this matters

Linux security mechanisms (seccomp-bpf, SELinux, AppArmor, namespaces) run
inside the kernel they are protecting. A kernel exploit owns the security
framework too: the enforcement and the attack surface are the same code.

5BSD separates them. Linux programs call `clone()`, `mmap()`, `open()`,
`sendmsg()` — and those calls are translated into BSD kernel operations
before they execute. Security policy is enforced at the translation boundary
by a MAC framework the Linux code never touches, on a kernel the Linux code
does not know about. Linux programs do not adapt to this and do not know it
is there; they either succeed or receive `EACCES`/`EPERM` from a layer they
cannot see, map, or attack through the Linux API.

## What the platform provides

| Layer | What it does |
|-------|--------------|
| **MACF** | 38+ mandatory access control hooks gate every Linux syscall — fork, exec, mmap, open, socket, signal, mount. Policy modules are loadable. No Linux code can bypass or disable them. |
| **Capsicum** | Capability mode for process sandboxing. Enter capability mode and lose the ability to open new resources. Works on Linux binaries. |
| **MAC_CAPABILITY** | Capability-based IPC. Kernel message passing where the file descriptor *is* the credential. Services are loadable modules; no new syscalls required. |
| **mac_abac** | Attribute-based access control policy module. |
| **capprotect** | Per-process integrity shields — invisible to `ps`, immune to `ptrace` and `kill`, enforced by MACF, controlled by capability. |
| **vnode_claim** | Per-descriptor access control. Bind a file descriptor to a process identity; passing it to the wrong process makes it useless. |
| **Coalition** | Capability-based resource groups with coordinated termination, deadlines, watchdogs, and nesting. |
| **HWT/PT** | Hardware instruction tracing — observe exactly what a Linux process executed at the CPU level without modifying it. The HWT framework is cross-platform (Intel PT on amd64, ARM SPE on arm64); the Intel PT backend requires Intel CPUs. |

Beyond the security core, 5BSD ships:

- **WASPNest** — the virtualization stack (bhyve lineage) with modern VirtIO
  device models, vsock, live migration, and nested VMX
  ([Virtualization](virtualization/overview.md)).
- **Bluetooth** — a Bluetooth host and BLE mesh stack, `blued` and `meshd`
  ([Bluetooth](bluetooth/overview.md)).
- **TrustedZFS** — a capability-fd API over ZFS with a storage broker daemon
  ([Storage](storage/trustedzfs.md)).
- **Authority / serviced** — a capability-brokered init and service-management
  stack that coexists with `rc(8)` ([System Services](system/authority-init.md)).
- **ObservableBSD** — OpenTelemetry export, instruments, and hardware
  telemetry in base ([Observability](observability/observablebsd.md)).

## Relationship to FreeBSD

5BSD is derived from FreeBSD 16-CURRENT, and the inherited base system —
ZFS, jails, the network stack, `rc(8)`, ports and packages, standard
userland — behaves as documented in the
[FreeBSD Handbook](https://docs.freebsd.org/en/books/handbook/) and the
FreeBSD manual pages. The Epic deliberately does not reiterate that
material; consult the FreeBSD documentation for the underlying operating
system.

That said, **5BSD is a separate project, not a FreeBSD distribution**.
5BSD plans to eject and modify significant portions of the inherited
system over time, and **FreeBSD 16 is the last version 5BSD adopts
wholesale** — future FreeBSD releases will be sources of selectively
merged improvements, not a base to track. The divergence is already
underway: init duties have moved to `authorityd`/`serviced`, and bhyve is
becoming WASPNest. Wherever 5BSD has
diverged from FreeBSD — whether by adding, changing, or removing a
subsystem — **the Epic is the source of truth**, and the FreeBSD
documentation no longer applies to that subsystem.

## How to read this Epic

- **Security architects**: start with [Architecture](architecture.md), then
  the [Security](security/mac-capability.md) section.
- **Virtualization operators**: the [WASPNest](virtualization/overview.md)
  section is self-contained.
- **Builders and release engineers**: see
  [Operations](operations/building.md).

Chapters marked with a *Status* note describe components that are designed
or partially delivered; everything else describes committed, tested code in
the source tree.
