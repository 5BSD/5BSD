# Introduction

5BSD is a capability-oriented operating system with its own kernel — the
**5BSD kernel**. It is a BSD you
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
capability plane's PID 1 — can hand off to the classic `init(8)`; `serviced` coexists
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
capability *service* needs no new syscall. Its layers — the MAC_CAPABILITY
message-passing framework where the file descriptor *is* the credential,
the mandatory-access-control hooks, Capsicum sandboxing, per-descriptor
and per-process protections, coalitions, and hardware tracing — are each
described in [Architecture](architecture.md).

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
- **WASPNest** — the virtualization stack, with modern VirtIO
  models, vsock, live migration, and nested VMX
  ([Virtualization](virtualization/overview.md)).
- **Bluetooth** — a Bluetooth host and BLE mesh stack, `blued` and `meshd`
  ([Bluetooth](bluetooth/overview.md)).
- **ObservableBSD** — OpenTelemetry export, instruments, and hardware
  telemetry in base ([Observability](observability/observablebsd.md)).

## Running Linux and BSD software

5BSD runs its complete BSD userland natively, and it treats the **Linux
syscall interface as a first-class execution target** — not a
legacy-emulation afterthought. Linux binaries run unmodified, translated
into native kernel operations before they execute, with the security stack
enforcing beneath the translation boundary — a layer the Linux code cannot
see, adapt to, or attack. The mechanism and the reasoning live in
[Architecture](architecture.md#running-linux-software).

## How to read this Epic

The Epic is the authoritative reference for 5BSD: wherever it and any other
documentation disagree, the Epic is the source of truth.

- **Developers** extending the system: start with [The Hybrid Model: BSD plus
  a Capability SDK](development/hybrid-model.md), then the rest of the
  [Developer Guide](development/writing-components.md).
- **Security architects**: start with [Architecture](architecture.md), then
  the [Security](security/mac-capability.md) section.
- **Virtualization operators**: the [WASPNest](virtualization/overview.md)
  section is self-contained.
- **Builders and release engineers**: see
  [Operations](operations/building.md).
