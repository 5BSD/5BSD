# 5BSD

5BSD is an operating system of the BSD lineage in which authority is a
held capability, not a user id. The classic BSD system is kept whole.
Beside it runs a capability plane: a PID 1 called capsule, a service
manager called switchboard, and sixteen system capabilities that broker
storage, logging, networking, devices, crypto, time, tracing and more to
programs that start in capability mode and hold nothing they were not
given. Linux binaries run on the same kernel under the same policy.

This file is the map. The book, **The 5BSD Epic** under
[`docs/book/`](docs/book/), is the territory: seventy-two chapters written
from this tree, and the source of truth wherever 5BSD differs from the BSD
base it inherits. For inherited behaviour the
[FreeBSD Handbook](https://docs.freebsd.org/en/books/handbook/) still
applies and the book does not repeat it.

## What is different

| Area | What 5BSD adds | Read |
|---|---|---|
| Kernel | The MAC_CAPABILITY framework: unforgeable process identity, capability channels, coalitions, system gates, capprotect shields, all compiled into GENERIC | [The Capability System](docs/book/src/capability/mac-capability.md) |
| Policy | 62 new MAC hooks, mac_abac, OpenEndpointSecurity, verified execution, and a single map of every place policy is decided | [Policy Points](docs/book/src/capability/policy-points.md) |
| Runtime | capsule as PID 1, switchboard as launcher and name switchboard, bundles with manifests as policy, per-app containers on TrustedZFS, anointments in place of sudo | [The Plane](docs/book/src/plane/capsule.md) |
| Services | Sixteen system capabilities, each a born-in-capability-mode daemon with a typed client library, a ctl tool and tests | [Reference](docs/book/src/providers/overview.md) |
| Compatibility | rc and service(8) run alongside the plane; login, su and ssh mint sessions through the plane; jails, pkgbase, bhyve virtual machines, and a Linux emulation layer at Linux 7.3 syscall parity with a native io_uring engine | [Backward Compatibility](docs/book/src/compat/bsd-side.md) |
| Development | How to write a provider, a consumer, a per-user agent, a Linux application, a driver bundle or a kernel extension, with examples that compile | [Writing Software](docs/book/src/develop/choosing.md) |
| Operations | Building, installing, upgrading from a local repository, boot knobs, observability, troubleshooting | [Operations](docs/book/src/operations/building.md) |

The full account of what changed relative to the inherited base, subsystem by
subsystem with file paths, man pages and tests, is
[`docs/5bsd-inventory.md`](docs/5bsd-inventory.md).

## The idea in one page

A traditional UNIX process carries a uid, and code all over the kernel and
userland re-derives "is this allowed" from it. 5BSD moves that decision to
one place. Authority is minted at a single boundary and flows by
delegation:

```
capsule (PID 1)      claims the plane at boot, supervises switchboard
   |
switchboard          launches units from their manifests, born in capability mode,
   |                 and answers every name lookup over a per-process channel
   |
BSDAuth              the mint boundary: login, su and sshd authenticate, then
   |                 ask it for a session channel scoped by the principal policy
   |
your session         holds a lookup channel; every capability it reaches is a
                     descriptor it was handed, never a path or a uid it has
```

A unit's manifest says how to launch it and what it is allowed to hold.
It does not grant resources. The unit acquires what it needs at run time,
by name, over its lookup channel, and fails soft when a provider is down.
Storage is a per-application namespace on TrustedZFS, so removing an
application is one revoke. Everything a plane program does is a DTrace
probe.

The plane is optional at boot. With `capability_plane="NO"` in loader.conf,
capsule hands off to stock init and the machine is an ordinary BSD
system. The book's [From Power-On to Login](docs/book/src/orientation/boot-to-login.md)
narrates the whole sequence with the real log lines.

## The sixteen system capabilities

| Wire name | Provider | What it brokers |
|---|---|---|
| system.Filesystem | BSDFilesystem | Per-application storage on TrustedZFS: containers, quota, snapshots, versions, transactions |
| system.Log | BSDLog | Structured logging, storage, retention and query |
| system.Audit | BSDAudit | BSM audit records from capability-mode units |
| system.Auth | BSDAuth | Session minting and elevation, the mint boundary |
| system.Crypto | BSDCrypto | Kernel crypto descriptors, named keys, digests, randomness |
| system.Network | BSDNetwork | Connected, listening and UDP sockets and name resolution, per-label policy |
| system.Device | BSDDevice | Rights-narrowed `/dev` descriptors with ioctl allow-lists |
| system.Notify | BSDNotify | Publish and subscribe, state cells, timers |
| system.Sysctl | BSDSysctl | sysctl reads and writes through a gate, isolated OIDs |
| system.Time | BSDTime | Clock step and slew through a gate |
| system.Power | BSDPower | ACPI sleep states |
| system.SystemExtension | BSDExtension | Kernel module loading from an allow-list |
| system.Namespace | BSDNamespace | Label-scoped jails |
| system.Trace | BSDTrace | Rights-limited DTrace descriptors for anointed callers |
| system.VM | BSDVM | vsock endpoint brokering for virtual machines |
| system.Bluetooth | BSDBluetooth | The BLE host, GAP through HOGP, as a service |

Each has a chapter in the book on a fixed template: what it brokers, its
unit, every wire operation, the client library, the tool, the policy, the
tests, and an honest status.

## Building

5BSD builds like any BSD. GENERIC is the 5BSD kernel; every 5BSD option is
compiled in and there is no separate configuration.

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld
make -j$(sysctl -n hw.ncpu) buildkernel
make -j$(sysctl -n hw.ncpu) packages PKG_CMD=/usr/local/sbin/pkg-static
```

The last step writes a complete pkgbase repository, 5BSD-prefixed packages
with sets and a catalogue, under `/usr/obj/usr/src/repo/`. The static pkg
is required because the ports pkg tracks a newer libc ABI. Installer media
come from `make -C release memstick`. Details and the knobs that matter are
in [Building](docs/book/src/operations/building.md).

There is no public package service. Base updates come from a repository
you built, configured as `5BSD` in `pkg.conf`, and third-party software
comes from the FreeBSD ports repositories. See
[Upgrading](docs/book/src/operations/upgrading.md) and
[Installing](docs/book/src/operations/installing.md).

## Testing

Every capability daemon and library ships an ATF suite, packaged as
`5BSD-<name>-tests`. On an installed system:

```sh
kyua test -k /usr/tests/usr.sbin/BSDLog/Kyuafile
kyua test -k /usr/tests/sys/mac_capability/Kyuafile   # needs the plane off
```

Tests that open the capability device directly need a boot with
`capability_plane="NO"`, because a live plane owns it. Tests that need a
live plane, the Linux QEMU gate and the virtualization harnesses are
described in [Testing](docs/book/src/develop/testing.md).

## Where things live

| Area | Path |
|---|---|
| Capability kernel framework | `sys/dev/mac_capability/` |
| Policy modules | `sys/security/mac_abac/`, `sys/security/oes/`, `sys/security/mac/` |
| Native io_uring engine | `sys/kern/sys_squeue.c`, `lib/libsqueue/` |
| TrustedZFS | `sys/contrib/openzfs/module/os/freebsd/zfs/zfs_handle.c`, `lib/libtrustedzfs/` |
| capsule, switchboard and their tools | `usr.sbin/{capsule,capsulectl,switchboard,switchboardctl}` |
| System capabilities | `usr.sbin/BSD*/`, `usr.sbin/bluetooth/BSDBluetooth/` |
| Plane libraries | `lib/{libservice,libcapbundle,libchannel,libcapability,libcapsulert}` |
| Client libraries | `lib/lib*cmp/`, `lib/libnotify/`, `lib/libbsdfilesystem/` |
| Linux emulation | `sys/compat/linux/`, `sys/amd64/linux/`, `tools/test/linuxulator/` |
| Virtualization | `usr.sbin/bhyve/`, `sys/amd64/vmm/`, `sys/dev/virtio/`, `usr.sbin/BSDVM/` |
| Packages | `packages/`, `release/packages/ucl/` |
| The book | `docs/book/` |
| Design documents | `docs/`, indexed in the book's [Design Document Index](docs/book/src/appendix/design-docs.md) |

## Lineage

5BSD descends from the BSD family and inherits its base, ZFS, jails, the
network stack, rc(8) and the standard userland, from the FreeBSD tree at
one point in time; later upstream work is merged selectively, not
tracked. 5BSD is 64-bit only: no 32-bit compatibility layer, no lib32, no
i386 or armv7 targets. ZFS is required. Where 5BSD has added, changed or
removed a subsystem, the book applies and upstream documentation does
not; the [BSD Side](docs/book/src/compat/bsd-side.md) chapter lists what
a developer coming from another BSD will notice.

## Status

The capability core, the plane, the sixteen providers, TrustedZFS, the
Linux emulation layer, the virtualization stack and the Bluetooth host are
committed and tested, and a from-scratch build packages and boots. The
migration of every authority decision off ambient uid checks and onto held
capabilities is the ongoing throughline; where a chapter describes designed
or partially delivered work it says so in a Status paragraph. Verified
execution is present but not yet enforcing. Linux seccomp and Landlock are
in progress.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: pull requests
against `dev`, current names only, every claim in a document checked
against the tree, and tests for anything that touches the trusted
computing base.
