# 5BSD

**A capability-authority operating system built on a FreeBSD 16 fork — that
also runs Linux binaries under a security stack enforced below the API.**

5BSD is derived from FreeBSD 16-CURRENT (kernel ident `VBSD`) but it is a
separate project, not a distribution. Two ideas define it:

1. **Authority is a held capability, not a uid.** Who you are — your uid, your
   PID, the path you opened, the peer credentials on your socket — grants
   nothing. What you can do is exactly what you hold a capability descriptor
   for. Init, service management, login sessions, storage, and IPC are all
   brokered through unforgeable kernel-backed capability channels.

2. **Security lives below the Linux API.** The Linux syscall interface is a
   first-class ABI. Every Linux syscall is translated into native BSD
   operations, and policy is enforced at that translation boundary by a MAC
   framework the Linux code never touches — on a kernel it does not know is
   there. Linux programs do not adapt; they succeed or get `EACCES`/`EPERM`
   from a layer they cannot see, map, or attack through the Linux API.

Full documentation lives in **The 5BSD Epic**, the book under
[`docs/book/`](docs/book/) — it is the source of truth wherever 5BSD has
diverged from FreeBSD. This README is the map; the Epic is the territory.

---

## A hybrid by design — the secure realm sits beside UNIX

This is a deliberate architectural decision, not a transitional accident:
**5BSD does not replace UNIX — the capability-authority realm runs *beside* the
traditional BSD/UNIX system, and you migrate onto it over time.** The two
coexist by design so that adoption is incremental and the machine stays working
at every step, instead of betting everything on a single big-bang rewrite:

- `authority-init` runs as PID 1, but the capability plane is a loader knob
  (`capability_plane="NO"`) — with it off, `authority-init` hands off to stock
  `init` and you get an ordinary FreeBSD system. The OS boots and runs either
  way.
- `serviced` coexists with `rc(8)`; services move under capability management
  **progressively**, one subsystem at a time, not all at once.
- Stock UNIX mechanisms are kept where they belong: `reboot`/`halt`/signals stay
  standard (they signal `authority-init` as init), and the system-lifecycle
  control socket deliberately keeps `getpeereid(3)`.
- Ambient uid checks are being replaced by held capabilities **in phases** —
  during the migration a capability path may still carry a uid fallback behind
  it.

The payoff is a gradual path: an operator — and the project itself, as it
diverges from FreeBSD — grows the secure realm next to UNIX and lets it subsume
the old model over time, rather than requiring a flag day. The
capability-authority migration described throughout this document is exactly
that process, and it is meant to be run incrementally.

---

## Reached through a library, never a raw protocol

A second deliberate decision: **nothing speaks the capability wire protocols by
hand.** A program reaches a capability service through a *typed library* —
`libservice` (`service_open`, `service_connect`, `service_acquire`) plus
per-service client libraries (`libcapbundle`, `libnetworkcmp`, `liblogcmp`, …) —
which hands back a capability channel and performs the request/reply. There are
no client-side sockets, no `getpeereid(3)` credential checks, and no ad-hoc
framing on the consumer side. The library *is* the API surface; the wire format
is an implementation detail behind it. Correspondingly, **operator and system
policy lives in manifests, not in code** — only the client↔server protocol
contract and a service's own self-hardening belong in the library.

---

## The capability-authority model

Traditional Unix authority is *ambient*: a process carries a uid, and code all
over the kernel and userland re-derives "is this allowed?" from it. 5BSD removes
that. Authority is created at one explicit **mint boundary** and flows by
delegation:

```
 Authority Init (PID 1)  -- holds the root capability at boot
        |  delegates
        v
 serviced -- launches services with fail-closed capability bundles
        |  each unit gets exactly its declared authority, or does not launch
        v
 auth-agent (system.authagent) -- the ONE place a login becomes a capability
        |  login/su/sshd authenticate, then ask the agent to mint a session
        v
 your session -- holds a scoped lookup channel; the shell inherits it
```

- **[Authority Init](docs/book/src/system/authority-init.md)** (`authorityd`
  running as PID 1) owns `/dev/mac_capability`, holds the root authority, and
  supervises `serviced`. `rc(8)` still runs beside it.
- **[serviced](docs/book/src/system/serviced.md)** is the service manager.
  Services declare their needs in **[capability
  bundles](docs/book/src/security/capability-bundles.md)** and **[service
  manifests](docs/book/src/system/manifests.md)**; `serviced` mints and delivers
  exactly those capabilities (including opening declared files/dirs and handing
  over rights-limited descriptors) or refuses to launch — never a
  half-provisioned service.
- **[The auth-agent](docs/book/src/security/session-mint.md)**
  (`authagentd` / `system.authagent`) is the single identity→capability mint
  boundary. `login`, `su`, and `sshd` no longer classify principals or hold mint
  authority; they authenticate and then ask the agent, which resolves the
  principal authoritatively (via Casper) and mints a scoped **SYSTEM** (admin) or
  **USER** (per-uid) session channel. Direct session minting has been retired.
- Everything a capability service needs lives under
  **[`/Capabilities`](docs/book/src/system/capability-hier.md)**, not a Unix FHS
  clone.

**Domains scope reach.** Every capability lookup channel carries a *domain*, and
`serviced` decides which service names it may resolve: a **SYSTEM** channel
(admin) resolves every registered service; a **USER** channel (per-uid,
non-admin) resolves only a small allow-list; a **CONTROL** channel reaches the
admin control plane and nothing else. Domains only ever *narrow* — a USER
channel can never widen itself to SYSTEM. This is what gives the auth-agent's
SYSTEM-vs-USER decision teeth: the agent picks the domain, and `serviced`
enforces the reach at every lookup.

The authoritative, code-level spec is
[`docs/capability-authority-model.md`](docs/capability-authority-model.md).

---

## Security beneath the Linux API

```
 Linux programs -> Linuxulator (syscall translation) -> native FreeBSD syscalls
      -> MACF enforcement (policy modules)
      -> Capsicum / vnode_claim (descriptor-level access control)
      -> Coalition (coordinated termination)
      -> mac_capability nonce (one process identity across all layers)
      -> BSD kernel (VFS, network, VM, scheduler)
```

| Layer | What it does |
|-------|--------------|
| **MACF** | 38+ mandatory access-control hooks gate every Linux syscall — fork, exec, mmap (W^X), open, socket, signal, mount. Loadable policy modules; no Linux code can bypass them. |
| **mac_capability** | Capability-based IPC: kernel message-passing where the file descriptor *is* the credential. Unlimited kernel services as loadable modules, no new syscalls. A cryptographic per-process **nonce** (rotates on `exec`, inherits on `fork`) is the single identity used across every layer. |
| **capprotect** | Per-process integrity shields — invisible to `ps`, immune to `ptrace`/`kill` — enforced by MACF, controlled by capability. |
| **vnode_claim** | Per-descriptor ACLs of allowed process identities: holding an fd is no longer sufficient to use it. |
| **Coalition** | Capability-based resource groups with coordinated termination, deadlines, watchdogs, leader-death triggers, and nesting. |
| **Capsicum** | Capability mode for sandboxing, working on Linux binaries — plus 5BSD's per-fd transfer controls (`cap_xfer_*`). |
| **mac_abac** | Attribute-based access-control policy module. |
| **HWT/PT** | Hardware instruction tracing (Intel PT on amd64, ARM SPE on arm64) — see exactly what a process executed, at the CPU level, unmodified. |

Details: the **[Security](docs/book/src/security/mac-capability.md)** section of
the Epic. New Capsicum-enabled syscalls (`pdrfork`, `pdwait`, `cap_xfer_limit`
family, `pdself`/`pdcmp`, `cap_mmap_capmode`, …) are tabulated in
**[Architecture](docs/book/src/architecture.md)**.

---

## The stacks

Beyond the security core and the authority plane, 5BSD ships:

- **[WASPNest](docs/book/src/virtualization/overview.md)** — the virtualization
  stack (bhyve lineage) with modern VirtIO device models, vsock, live migration,
  and nested VMX.
- **[Bluetooth](docs/book/src/bluetooth/overview.md)** — a Bluetooth host and BLE
  mesh stack, the `blued` and `meshd` daemons.
- **[TrustedZFS](docs/book/src/storage/trustedzfs.md)** — a capability-fd API
  over ZFS with the `tzfsd` storage broker; the capability plane's storage
  substrate.
- **[ObservableBSD](docs/book/src/observability/observablebsd.md)** —
  OpenTelemetry export, instruments, and hardware telemetry in base.
- **[OpenEndpointSecurity](docs/book/src/security/endpoint-security.md)** — an
  endpoint-security event framework over MACF.

---

## Relationship to FreeBSD

5BSD inherits FreeBSD's base — ZFS, jails, the network stack, `rc(8)`, ports and
packages, standard userland — and that inherited material behaves as documented
in the [FreeBSD Handbook](https://docs.freebsd.org/en/books/handbook/) and man
pages. **But 5BSD is a separate project, not a FreeBSD distribution.** FreeBSD 16
is the last version adopted wholesale; later releases are sources of selectively
merged improvements, not a base to track. Divergence is already underway — init
duties moved to `authorityd`/`serviced`, session authority moved to the
auth-agent, and bhyve is becoming WASPNest. Wherever 5BSD has added, changed, or
removed a subsystem, **the Epic is the source of truth** and FreeBSD's
documentation no longer applies to that subsystem.

Custom kernel work is structured for clean upstream tracking: it lives in
loadable modules, MACF hooks follow existing framework patterns, and base-system
touches are minimal (`DTYPE_MAC_CAPABILITY` in `sys/sys/file.h`, the `CAP_XFER_*`
transfer states in `sys/sys/capsicum.h`).

---

## 64-bit only

There is no 32-bit support of any kind — no `lib32`, no `COMPAT_FREEBSD32`, no
i386/armv7 targets. This is structural: TrustedZFS capability descriptors
`#error` at compile time on any non-64-bit ABI, so the capability daemons cannot
be built 32-bit at all. Supported: `amd64`, `arm64`, `powerpc64`/`le`, `riscv64`.

---

## Building

5BSD builds like FreeBSD. The kernel config is `VBSD` (`config(8)` disallows a
leading digit); it is `include GENERIC` plus `ident VBSD`, so every 5BSD option
lives in `GENERIC`.

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld
make -j$(sysctl -n hw.ncpu) buildkernel KERNCONF=VBSD
make packages KERNCONF=VBSD          # pkgbase 5BSD-* packages, kernel included
```

`make packages` writes a complete pkg repo (world + `5BSD-kernel-vbsd` +
sets, with a catalog) under `${OBJTOP}/repo/`. Installer media
(`make -C release memstick`) and the full build/packaging details are in
**[Operations](docs/book/src/operations/building.md)**.

### Installing / upgrading

- **Fresh machine or VM:** build the release memstick and boot the installer.
- **Existing FreeBSD 16-CURRENT pkgbase host:** build local 5BSD packages,
  disable the upstream `FreeBSD-base` repository, and upgrade through `pkg(8)` on
  a boot environment. See
  [`docs/pkgbase-install.md`](docs/pkgbase-install.md) and
  **[Packaging](docs/book/src/operations/packaging.md)**.

MAC capability modules load automatically via `stand/defaults/loader.conf`;
`authority-init` becomes PID 1 through the `init_path` loader knob.

---

## Testing

```sh
cd tests/sys/mac_capability && kyua test     # ~490 ATF cases, the capability core
cd tests/sys/mac            && kyua test
```

Userland capability daemons and libraries carry their own ATF suites
(`serviced`, `libcapbundle`, `libservice`, `authagentd`, …), packaged as
`5BSD-*-tests`.

---

## Where things live

| Area | Path |
|------|------|
| Capability kernel framework | `sys/dev/mac_capability/` |
| MACF hooks | `sys/security/` |
| Hardware trace | `sys/dev/hwt/`, `sys/amd64/pt/`, `sys/arm64/spe/` |
| Authority / services | `usr.sbin/{authorityd,serviced,authagentd,authorityctl,servicectl}` |
| Capability libraries | `lib/{libcapability,libcapbundle,libservice,libchannel,libauthorityrt}` |
| Storage plane | `lib/libtrustedzfs`, `lib/libtzfsd`, `usr.sbin/tzfsd` |
| The book (source of truth) | `docs/book/` |
| Code-level model spec | `docs/capability-authority-model.md` |

---

## Status

The capability core (MACF, `mac_capability`, capprotect, coalition, HWT/PT), the
authority plane (`authority-init`, `serviced`, the auth-agent, capability
bundles, TrustedZFS), and the product stacks (WASPNest, Bluetooth, ObservableBSD)
are committed and tested; the from-scratch build packages cleanly and boots. The
capability-authority migration — moving every authority decision off ambient
uid/socket checks and onto held capabilities — is the ongoing throughline;
chapters in the Epic marked with a *Status* note describe designed or partially
delivered pieces, everything else describes committed, tested code.
