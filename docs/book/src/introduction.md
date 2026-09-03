# Introduction

5BSD is a capability-oriented operating system with its own kernel — the
**5BSD kernel**, descended from FreeBSD but no longer stock. It is a BSD you
already know how to drive: `sh`, `cc`, ZFS, jails, `rc(8)`, ports and
packages, every man page in muscle memory. And beside that familiar system
runs a second one — a **capability plane**, in which authority is a held,
unforgeable descriptor rather than a uid, a path, or a peer credential.

That pairing is the whole idea. The traditional BSD system stays fully
intact, so nothing you know stops working. The capability plane sits
alongside it, so a service adopts the stronger model when it is ready, one
service at a time. And 5BSD ships an **SDK** — `libservice`,
`libcapbundle` — for writing a *capability*: a program reached by name,
launched on demand, sandboxed by construction, and served to each client in
its own isolated worker. [The Hybrid Model: BSD plus a Capability
SDK](development/hybrid-model.md) shows what that looks like in code.

## What 5BSD is

A handful of decisions define the platform; the rest of this Epic is their
consequences (laid out in full in [Architecture](architecture.md)).

- **Authority is a held capability, not a uid.** What a process may do is
  exactly what it holds an unforgeable descriptor for — never what its uid,
  path, or socket peer-credential implies. See [The Authority
  Model](security/authority-model.md).
- **A hybrid by design.** The capability plane runs *beside* the traditional
  BSD system, not instead of it. `capsule` can hand PID 1 back to stock
  `init`, `serviced` coexists with `rc(8)`, and `reboot`/`halt`/signals stay
  standard — so adoption is incremental and the machine works at every step.
- **Reached by name, through a library.** Capabilities are typed services
  (`system.Filesystem`, `system.Log`, `system.Network`, …) resolved by name
  over a `libservice` channel. The name is the contract: replace the binary
  behind a capability and its consumers never notice. No hand-rolled sockets,
  no `getpeereid(3)`.
- **Policy in manifests, not code.** A service ships as a **capability
  bundle** whose manifest declares only how to launch a program; the program
  acquires whatever authority it needs at runtime, by name, each grant scoped
  to its own unforgeable channel label.
- **Enforcement in the kernel, below the API.** The 5BSD kernel's
  mandatory-access-control and capability framework gates every operation; an
  application sees policy only as `EACCES`/`EPERM` and cannot see, map, or
  disable the layer that produced it.

## What the platform provides

The security and capability core lives in the 5BSD kernel, structured as
loadable modules over a small set of base-kernel changes — adding a
capability *service* needs no new syscall — and exercised by ~490 ATF test
cases under `tests/sys/mac_capability/`:

| Layer | What it does |
|-------|--------------|
| **MAC_CAPABILITY** | Capability-based IPC: kernel message passing where the file descriptor *is* the credential. Carries a cryptographic per-process nonce that rotates on `exec` and is inherited on `fork` — one process identity across every layer. Services are loadable modules. |
| **MACF** | 38+ mandatory access-control hooks gating process lifecycle, memory (W^X), the descriptor layer, vnodes, mounts, and info disclosure. Policy modules are loadable; no application code can bypass them. |
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
