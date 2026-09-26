# Introduction

The 5BSD Epic is the reference for 5BSD: what it adds to FreeBSD, why those
additions exist, and how to run the system, write software for it, and extend
it. It is written for three readers. An operator who installs and runs 5BSD
needs to know which of their FreeBSD habits still apply and which have moved.
A developer who writes software for 5BSD needs the programming model and the
libraries that carry it. A kernel or platform engineer who extends 5BSD needs
the framework, the policy points and the trusted computing base laid out
honestly, including what is design-only and what is not yet enforced.

The Epic does not repeat the FreeBSD Handbook. Where 5BSD behaves as FreeBSD
does, a chapter says so and links to the Handbook or to a man page. Where 5BSD
diverges, the Epic is the source of truth, and it is written from the source
tree, not from memory: every command, path, manifest key and function named
here exists at the tree's head.

## Why 5BSD exists

No open source operating system on the market gives you the security posture
of iOS or QNX behind an API that an ordinary developer with UNIX experience
can pick up quickly. The systems that have that posture are closed, or are
microkernels with a programming model of their own, or attach a policy
language to UNIX that only its author understands. The systems developers
know are UNIX, and on UNIX a program's power is whoever it runs as: root can
do anything, and any code running as you has all of your power.

5BSD closes that gap with one BSD kernel that runs two systems side by side:
classic UNIX, kept whole so that everything you already run keeps running,
and a capability system with no root, in which a program's authority is the
set of unforgeable descriptors it holds. The API for the second system is
file descriptors, `openat(2)`, kqueue and a small C library, the things a
UNIX developer already knows.

A modern application environment also needs a modern hypervisor, binary
compatibility and containers, and 5BSD treats each as a first-class target.
The hypervisor is bhyve, extended with a modern VirtIO transport, new device
models, vsock, checkpointing and nested VMX
([Virtual Machines](compat/virtual-machines.md)). The compatible UNIX of
choice for application software is Linux, so 5BSD invests heavily in running
unmodified Linux binaries, and every Linux system call is translated into a
native operation before it executes, so the whole 5BSD security stack polices
Linux code from beneath a boundary it cannot see
([Linux Emulation](compat/linux/overview.md)). Containers are jails, classic
and self-service, plus per-application storage namespaces that are revoked in
one operation ([Jails](compat/jails.md),
[Containers and Storage](plane/containers-and-storage.md)).

On top of that sits a secure software API through which a program protects
itself and declares its resources to the system: it says what it may hold,
starts already inside a sandbox, and receives each resource as a
rights-limited descriptor from a service that decided by the program's
identity rather than its uid. System policy becomes per-application policy,
set by the application author instead of root. The repository
[README](../../../README.md) walks the technologies in order; this book is
the full account.

## Two systems, one machine

5BSD is a FreeBSD derivative that runs two systems side by side.

The first is the BSD you already know. `sh`, `cc`, ZFS, jails, rc(8), ports and
packages, every man page in muscle memory: all of it is present and works as it
does upstream. In this system a process's power comes from who it is. Its uid
decides what it may open, its paths decide what it may reach, the peer
credentials on its sockets decide whom it will serve.

The second is the capability plane. Here power comes from what a process
holds. A capability is an unforgeable kernel descriptor bound to one thing,
and a program may act only through the capabilities it was given, each one
narrowable and revocable. The plane has a PID 1 of its own, capsule, which
claims the kernel's capability device and hands the machine to a service
manager, switchboard. Switchboard launches every plane program already inside
capability mode, with the descriptors it needs delivered before its first
instruction, and answers name lookups over a private channel whose identity the
kernel stamps. Sixteen system capabilities, `system.Filesystem`,
`system.Log`, `system.Network` and their siblings, each broker exactly one
facility and hand back rights-limited descriptors to whoever holds a channel
to them.

The two systems share one kernel and one filesystem, and the boundary between
them is deliberately porous in one direction. Switchboard runs `/etc/rc`
alongside its own units, so an rc daemon keeps working untouched. A login
session receives a lookup channel at the getty hop, so a shell on the BSD side
can reach plane services by name. A plane program cannot open a path, bind a
port or read a uid-protected file by itself; it asks a provider, and the
provider decides by the caller's label. Nothing on the BSD side had to change
for that to be true, and nothing on the BSD side can forge its way in.

That pairing is the whole idea. The classic system stays intact so nothing
stops working. The capability plane sits beside it so a service adopts the
stronger model when it is ready, one service at a time.
[What 5BSD Is](orientation/what-5bsd-is.md) states the principles behind this
shape; [From Power-On to Login](orientation/boot-to-login.md) shows both
systems coming up on one machine.

## The map

The Epic has seven parts and a set of appendices.

**Part I, Orientation**, says what 5BSD is and is not, narrates one boot from
the loader to a login prompt, and gives each kind of reader a path through the
rest of the book.

**Part II, The Capability System**, covers the kernel: the mac_capability
framework and its services, coalitions and accounting, capability mode and the
born-sandboxed launch, descriptor and process protections, the authority
model, the policy points, the system gates, and the three security modules
(mac_abac, OES and verified execution) that sit beside the plane.

**Part III, The Plane**, covers the userland runtime that turns those kernel
primitives into a running system: capsule, switchboard, bundles and manifests,
discovery over the lookup channel, containers and storage, anointments and
principal policy, the management model, and logging, audit and trace.

**Part IV, System Capabilities Reference**, is one chapter per provider, all
sixteen on a fixed template: the wire name, the operations, the client
library, the policy file, the control tool and the tests that prove it.

**Part V, Backward Compatibility**, is for the BSD side: what rc and
service(8) do under switchboard, how login, su, ssh and cron carry a session's
capabilities, jails, packages and ports, virtual machines, and the Linux
emulation layer with its system calls, io_uring, procfs and sandboxing.

**Part VI, Writing Software for 5BSD**, walks through each kind of program you
might write, a provider, a consumer application, a per-user agent, a migrated
rc daemon, a Linux application, a device driver bundle, a kernel extension, and
then testing, packaging and shipping it.

**Part VII, Operations**, covers building from source, installing, upgrading,
the boot knobs, observability, troubleshooting, and a reference to every 5BSD
tool.

The **Appendices** hold a glossary of names, an index of the 5BSD manual
pages, the list of new system calls and sysctls, and an index of the design
documents under `docs/` that the chapters cite.

## How the chapters are written

Each chapter opens by saying what the thing is and why 5BSD has it, then
explains the mechanism, then shows how to use it with something you can act
on: a command with its real output shape, a manifest, a code fragment, a table
of options. Each closes with its limits and gaps. Where a feature is shipped,
in progress or design-only, the chapter says which, and a paragraph headed
**Status** carries the date that verdict was checked against the tree.
[How to Read This Book](orientation/how-to-read.md) lists the conventions and
the reading order for each role.
