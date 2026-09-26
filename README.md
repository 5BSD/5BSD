# 5BSD

5BSD is a hybrid. It is a capability operating system and a UNIX system
sharing one kernel. The UNIX side is BSD, kept whole, and it runs Linux
binaries too. The capability side has no root. Authority lives in
processes, as capabilities the kernel makes unforgeable, and the
capability system protects itself from root instead of trusting it.

The rule is simple. A program may do what it holds a capability for, and
nothing else. Being root, owning a file, knowing a path, or being on the
other end of a socket does not count. Beside the familiar system runs a
capability plane: capsule as PID 1, switchboard to launch and connect
services, and sixteen system capabilities that hand out storage, logs,
sockets, devices, keys, time and traces to programs that start sandboxed
and hold only what they were given.

This is early work. The plane is real, boots, and is tested, but today
it runs beside a UNIX system that still has root, still has mode bits,
and still answers many questions by uid. The direction is fixed: over
time more interfaces become capabilities, root is removed, and 5BSD moves
further from the BSDs it forked from. The [Where this is going](#where-this-is-going)
section says what that means.

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

## What kind of capability system this is

In UNIX, a process carries an identity, and code all over the kernel and
userland re-derives "is this allowed" from that identity: the uid against
the file's owner and mode bits, root against everything. Authority is
ambient. Any code running as you has all of your power, and a program
cannot be given less than its user has.

In 5BSD, authority is an object the program holds. The building block is
the file descriptor, made unforgeable and rights-limited by the kernel:
Capsicum's capability mode, where a process can reach nothing by path or
by global name and can only use descriptors it already holds, plus a
kernel framework, MAC_CAPABILITY, that adds what Capsicum lacks. That
framework gives every process a cryptographic identity the kernel stamps
on every message, capability channels over which requests and descriptors
travel, labels that name services without a filesystem path, coalitions
that group processes for accounting and teardown, and system gates that
let a sandboxed daemon ask the kernel to perform one privileged operation
on its behalf without holding the privilege.

On that base runs a plane of brokers. A program does not open `/dev/x`,
a socket, a log file or a dataset. It asks a named capability for one and
receives a descriptor narrowed to exactly the rights it was granted,
under a policy keyed by the program's label rather than its uid. Authority
is minted at a single boundary and flows by delegation:

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

What this buys you, concretely:

| Property | How 5BSD provides it |
|---|---|
| Least authority | A program starts in capability mode holding only the descriptors switchboard delivered; everything else it must be handed by name, narrowed to the rights the policy allows |
| No confused deputy | A provider acts on the caller's label, which the kernel stamps and nothing can forge; it never acts on a uid the caller claims |
| Delegation without escalation | Capabilities are descriptors, so passing one on is an ordinary descriptor transfer, and the receiver can only narrow it, never widen it |
| Revocation | An application's storage, logs, keys and jails hang off one namespace; removing the bundle revokes them all |
| Attribution | Audit records, logs and traces carry the label and the unforgeable identity, so every action has a provenance |
| Containment of privilege | The privileged operations the system still needs (load a module, set the clock, make a jail, write a sysctl) are performed by the kernel through a gate a specific daemon holds, not by a process running as root |
| A single mint boundary | Sessions become capabilities in one place, BSDAuth, under one policy file, whether the user arrived through login, su or ssh |

This is not a microkernel and not typed memory in the seL4 sense. It is
a monolithic BSD kernel whose authority model has been rebuilt around
unforgeable descriptors and a broker plane. The trade is deliberate: the
whole of BSD and its software keep working, and the capability model is
adopted one interface at a time.

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
committed and tested, and a from-scratch build packages and boots. Where
a book chapter describes designed or partially delivered work it says so
in a Status paragraph. Verified execution is present but not yet
enforcing. Linux seccomp and Landlock are in progress.

What is still UNIX today, stated plainly: root exists and can do most of
what root does elsewhere; file access outside the plane is mode bits and
ACLs; a number of kernel checks are still uid checks with a capability
path beside them; six of the sixteen providers run as root because the
operation they broker has no gate yet; and the manifest still carries a
system-gate declaration that will one day be a held capability like
everything else.

## Where this is going

The throughline of the project is moving every authority decision off
ambient identity and onto held capabilities, and it runs in phases so
the machine works at every step. The order is roughly:

1. Every privileged operation the plane needs becomes a system gate a
   sandboxed daemon holds, until no provider runs as root.
2. The remaining uid checks in the kernel's capability paths are replaced
   by a process flag, set only through a held capability, that makes the
   kernel accept capabilities as authority in place of `priv_check`.
3. Resource authority follows: memory, CPU and object budgets become
   derivable, revocable grants rather than limits attached to a uid.
4. More of the classic system is reached through the plane: the daemons
   that still run under rc migrate to units, and the interfaces they
   expose become capabilities.
5. Root is removed. An administrator is a principal with anointments and
   a session channel, not uid 0, and there is nothing left for uid 0 to
   mean.

Each step moves 5BSD further from the BSDs it forked from. The plane-off
boot knob, the rc coexistence and the uid fallbacks are scaffolding for
the migration, not the destination. The book's
[Authority Model](docs/book/src/capability/authority-model.md) chapter
tracks where each phase stands.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: pull requests
against `dev`, current names only, every claim in a document checked
against the tree, and tests for anything that touches the trusted
computing base.
