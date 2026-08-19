# Architecture Overview

5BSD is a FreeBSD 16-CURRENT derivative (kernel ident `VBSD`) in which the
Linuxulator is treated as the primary application binary interface and a
capability-oriented security stack enforces policy beneath it.

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

The kernel message-passing framework, formerly known as **CMI** and then
**cap_rt** (both names appear in older commit history). One base-system
change — `DTYPE_MAC_CAPABILITY`, standard Capsicum rights with ioctl
limits, one device node —
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

## Userland stacks

Above the kernel core, 5BSD adds capability-brokered system daemons and
product stacks, each covered in its own section:

| Stack | Components | Section |
|-------|-----------|---------|
| Init & services | `oracled` (PID 1 capable), `serviced`, `oraclectl` | [System Services](system/oracle-init.md) |
| Virtualization | WASPNest (bhyve), VirtIO models, vsock, migration | [Virtualization](virtualization/overview.md) |
| Bluetooth | `blued`, `meshd`, `bluedctl`/`meshctl` (skyblue rename pending) | [Bluetooth](bluetooth/overview.md) |
| Storage | TrustedZFS, `tzfsd`, `tzfsctl`, tzfs-flavors | [Storage](storage/trustedzfs.md) |
| Endpoint security | OES clients over MACF | [Endpoint Security](security/endpoint-security.md) |
| Observability | libotelexport, bsdinstruments, hwtlm, DTrace | [Observability](observability/observablebsd.md) |

Daemons log with subsystem tags (`[ORACLE]`, `[SERVICE]`, `[TZFS]`) into the
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
