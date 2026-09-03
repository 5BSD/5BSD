# Introduction

5BSD is a capability-oriented operating system with its own kernel — the
**5BSD kernel**, descended from FreeBSD but no longer stock. It is a BSD you
already know how to drive: `sh`, `cc`, ZFS, jails, `rc(8)`, ports and
packages, every man page in muscle memory. And beside that familiar system
runs a second one — a **capability plane**, in which authority is a held,
unforgeable descriptor rather than a uid, a path, or a peer credential.

That pairing is the whole idea. The traditional BSD system stays fully
intact, so nothing you know stops working; the capability plane sits
alongside it, so a service adopts the stronger model when it is ready, one
service at a time.

## Two systems, one machine

In the traditional system, a process's power comes from who it is: its uid,
the paths it can reach, the peer credentials on its sockets. In the
capability plane, power comes from what a process *holds*. A capability is a
typed service with a name — `system.Filesystem`, `system.Log`,
`system.Network` — and a program reaches one by resolving the name over a
`libservice` channel whose identity the kernel stamps and nothing can forge.
What the program may then do is exactly what it holds descriptors for,
never what its uid implies. The name is the contract: swap the binary behind
a capability and its consumers never notice.

Writing for the plane feels less exotic than that sounds, because 5BSD ships
an **SDK** — `libservice`, `libcapbundle` — that does the heavy lifting. A
few fixed calls turn a program into a *capability provider*: reached by
name, launched on demand, sandboxed by construction, each client served in
its own isolated worker. The program ships as a **capability bundle**, a
`.cap` directory whose manifest says only how to launch it — the program
acquires whatever authority it needs at runtime, by name, each grant scoped
to its own unforgeable channel label. [The Hybrid Model: BSD plus a
Capability SDK](development/hybrid-model.md) builds one end to end.

None of this asks the rest of the machine to change. `capsule` — the
capability plane's PID 1 — can hand off to stock `init`; `serviced` coexists
with `rc(8)`; `reboot`, `halt`, and signals stay standard. Underneath both
systems, the 5BSD kernel's mandatory-access-control and capability framework
does the enforcing: an application sees policy only as `EACCES`/`EPERM`,
from a layer it cannot see, map, or disable. The full set of design
principles behind this shape is enumerated in
[Architecture](architecture.md); the authority model itself has
[its own chapter](security/authority-model.md).

## What the platform provides

The security and capability core lives in the 5BSD kernel, structured as
loadable modules over a small set of base-kernel changes — adding a
capability *service* needs no new syscall — and exercised by ~490 ATF test
cases under `tests/sys/mac_capability/`:

| Layer | What it does |
|-------|--------------|
| **MAC_CAPABILITY** | Capability-based IPC: kernel message passing where the file descriptor *is* the credential. Carries a cryptographic per-process nonce that rotates on `exec` and is inherited on `fork` — one process identity across every layer. Services are loadable modules. |
| **MACF** | 38+ mandatory access-control hooks gating process lifecycle, memory (W^X), the descriptor layer, vnodes, mounts, and info disclosure. Policy modules are loadable; no application code can bypass them. |
| **mac_abac** | Attribute-based access control: a loadable MACF policy module expressing policy over process and object attributes. |
| **Capsicum** | Capability mode for process sandboxing — enter it and lose the ability to open new global resources. |
| **vnode_claim** | Per-descriptor access control: bind an fd to a process identity so possessing it is not enough to use it. |
| **capprotect** | Per-process integrity shields — invisible to `ps`, immune to `ptrace`/`kill`, enforced by MACF, controlled by capability. |
| **Coalition** | Capability-based resource groups with coordinated termination, deadlines, watchdogs, and nesting. |
| **HWT/PT** | Hardware instruction tracing (Intel PT on amd64, ARM SPE on arm64) feeding the observability stack. |

On top of that core, 5BSD ships its own userland stacks, each covered in its
own section of this Epic:

- **Capsule / serviced** — a capability-brokered init and service manager, and
  the capability providers built on the SDK: `tzfsd` (Filesystem), `warden`
  (Namespace), `sysextd` (SystemExtension), `vmd` (VM), `authagentd`
  (AuthAgent), `logd` (Log), `localnetwork` (Network), `traced` (Trace),
  `auditbrokerd` (Audit), `localcrypto` (Crypto), `bsdnotify` (Notify)
  ([System Services](system/capsule.md)).
- **TrustedZFS** — a capability-descriptor API over ZFS, brokered by `tzfsd`
  ([Storage](storage/trustedzfs.md)).
- **OpenEndpointSecurity (OES)** — an endpoint-security event framework over
  MACF: clients subscribe to authoritative kernel events (exec, open, close,
  signal, …) for detection and response
  ([Endpoint Security](security/endpoint-security.md)).
- **WASPNest** — the virtualization stack (bhyve lineage) with modern VirtIO
  models, vsock, live migration, and nested VMX
  ([Virtualization](virtualization/overview.md)).
- **Bluetooth** — a Bluetooth host and BLE mesh stack, `blued` and `meshd`
  ([Bluetooth](bluetooth/overview.md)).
- **ObservableBSD** — OpenTelemetry export, instruments, and hardware
  telemetry in base ([Observability](observability/observablebsd.md)).

## Running Linux and BSD software

5BSD runs the full inherited BSD userland unchanged, and it treats the
**Linux syscall interface as a first-class execution target** — not a
legacy-emulation afterthought. Linux binaries call `clone()`, `mmap()`,
`open()`, `sendmsg()`, and the Linuxulator translates each into a native BSD
kernel operation before it executes.

The point is where enforcement sits. Linux's own mechanisms — seccomp-bpf,
SELinux, AppArmor, namespaces — run *inside* the kernel they protect, so a
kernel exploit owns the security framework too. 5BSD enforces beneath the
translation boundary, by the MAC and capability framework the Linux code
never touches, on a kernel it does not know is there. A Linux program does
not adapt to this and cannot attack through it; it simply succeeds, or
receives `EACCES`/`EPERM` from a layer it cannot see. The same is true of
native BSD binaries: the capability plane sits under *every* application,
whichever ABI it was compiled for.

## Relationship to FreeBSD

5BSD is derived from FreeBSD 16-CURRENT, but it boots the 5BSD kernel, not a
stock FreeBSD kernel. The inherited base — ZFS, jails, the network stack,
`rc(8)`, ports and packages, standard userland — behaves as documented in the
[FreeBSD Handbook](https://docs.freebsd.org/en/books/handbook/) and the
FreeBSD manual pages. The Epic deliberately does not reiterate that material.

That said, **5BSD is a separate project, not a FreeBSD distribution.** It
plans to eject and modify significant portions of the inherited system over
time, and **FreeBSD 16 is the last version 5BSD adopts wholesale** — later
FreeBSD releases are sources of selectively merged improvements, not a base
to track. The divergence is already underway: init duties have moved to
`capsule`/`serviced`, storage is growing a capability API, and bhyve is
becoming WASPNest. Wherever 5BSD has diverged — by adding, changing, or
removing a subsystem — **the Epic is the source of truth**, and the FreeBSD
documentation no longer applies to that subsystem.

## How to read this Epic

- **Developers** extending the system: start with [The Hybrid Model: BSD plus
  a Capability SDK](development/hybrid-model.md), then the rest of the
  [Developer Guide](development/writing-components.md).
- **Security architects**: start with [Architecture](architecture.md), then
  the [Security](security/mac-capability.md) section.
- **Virtualization operators**: the [WASPNest](virtualization/overview.md)
  section is self-contained.
- **Builders and release engineers**: see
  [Operations](operations/building.md).

Chapters marked with a *Status* note describe components that are designed or
partially delivered; everything else describes committed, tested code in the
source tree.
