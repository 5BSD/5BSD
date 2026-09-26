# 5BSD

## Why 5BSD exists

No open source operating system on the market gives you the security
posture of iOS or QNX behind an API that an ordinary developer with UNIX
experience can pick up in an afternoon. The systems that have that
posture are closed, or are microkernels with their own programming
model, or bolt a policy language onto UNIX that nobody but the policy
author understands. The systems developers actually know are UNIX, and
on UNIX a program's power is whoever it runs as: root can do anything,
and any code running as you has all of your power.

5BSD is the attempt to close that gap. It is one BSD kernel that runs
two systems side by side. The first is classic UNIX, kept whole, so that
everything you already run keeps running. The second is a capability
system with no root, in which a program's authority is the set of
unforgeable descriptors it holds and nothing else. The API for the
second system is file descriptors, `openat(2)`, kqueue, and a small C
library, because those are the things a UNIX developer already
understands.

A modern application environment needs three more things, and 5BSD
treats each as a first-class target rather than an add-on:

- **A modern hypervisor.** bhyve, extended with a modern VirtIO
  transport, packed rings, multiqueue, ten new device models, vsock end
  to end, checkpoint and live migration, and nested VMX.
  See [Virtual Machines](docs/book/src/compat/virtual-machines.md).
- **Binary compatibility with Linux.** The compatible UNIX of choice for
  application software is Linux, so 5BSD invests heavily in running
  unmodified Linux binaries: the 64-bit Linux system call table is
  covered to Linux 7.3 numbering, with a native io_uring engine, pidfd,
  futex2, openat2, signalfd, rseq, netlink, and a full procfs and sysfs
  view. Every Linux call is translated into a native kernel operation
  before it executes, so the whole 5BSD security stack polices Linux
  programs from beneath a boundary they cannot see.
  See [Linux Emulation](docs/book/src/compat/linux/overview.md).
- **Containers.** Jails, both the classic kind and the kind a sandboxed
  program asks for at run time, plus per-application storage namespaces
  on ZFS that are created by the program that owns them and revoked in
  one operation when it is removed.
  See [Jails](docs/book/src/compat/jails.md) and
  [Containers and Storage](docs/book/src/plane/containers-and-storage.md).

On top of that sits the thing no other open source UNIX offers: a secure
software API through which a program protects itself and declares its
resources to the system. A program says what it is allowed to hold, is
started already inside a sandbox, and receives each resource as a
rights-limited descriptor from a service that decided by the program's
identity, not by its uid. System policy becomes per-application policy
instead of per-machine policy, and the person who sets it is the
application author, not root.

The rest of this file walks through the technologies in the order they
stack up. Each section ends with the book chapter that explains the
interface with code. The book, **The 5BSD Epic** under
[`docs/book/`](docs/book/), is the full account, written from this tree.

## Part one: classic UNIX, hardened

The UNIX side of 5BSD is BSD as you know it: `sh`, `cc`, ZFS, jails,
rc(8), ports and packages, the man pages you have in muscle memory.
Where 5BSD behaves as FreeBSD does, the
[FreeBSD Handbook](https://docs.freebsd.org/en/books/handbook/) still
applies and 5BSD's own documentation does not repeat it.

What 5BSD adds on this side is a set of kernel policy hooks and two
policy modules that use them.

### The kernel hooks

The TrustedBSD MAC framework is the kernel's policy backbone: every
loaded policy sees an operation and any one of them can deny it. 5BSD
keeps the upstream hook set and adds over sixty new entry points at
places FreeBSD never had them: process fork, core dump, ktrace, anonymous
mmap, mprotect, syscall dispatch, descriptor dup, inherit, ioctl and
`SCM_RIGHTS` receive, vnode close and truncate, AF_UNIX bind and connect
by path, exec relabel, bhyve VM lifecycle and guest memory, ZFS dataset
and pool destruction and key operations, snapshot lifecycle, vsock
attach, kernel module unload, rctl rules and pseudo-terminal open. Each
hook is documented with its call site, lock context and whether it may
sleep. A hook is only a place where a policy can look; the modules
below are what look.

Read: [Policy Points](docs/book/src/capability/policy-points.md) for the
map of every hook and which module implements it, and
[`docs/macf-new-hooks.md`](docs/macf-new-hooks.md) for the reference.

### mac_abac: attribute-based access control

`mac_abac` is a label-based mandatory access control policy compiled
into every 5BSD kernel. Files and processes carry sets of `key=value`
attributes, and an ordered rule table decides, per operation, whether a
subject label may act on an object label. It answers the questions the
capability side does not ask: which labeled file a labeled process may
read, which process it may signal, whether an executable of one type
may run at all. It is type enforcement in the SELinux style without a
compile-time policy, with rules that hot-swap in sets, a permissive mode
for rollout, and context constraints such as "only from a terminal" or
"only when sandboxed".

```
mode = "enforcing";
default_policy = "deny";
rules = [
    { action = "transition"; operations = ["exec"];
      object = "type=entrypoint,app=nginx";
      newlabel = "domain=web,app=nginx,restricted=true"; },
    { action = "allow"; operations = ["all"];
      subject = { domain = "web"; }; object = { domain = "web"; }; },
    { action = "deny"; operations = ["debug"]; obj_ctx = { sandboxed = true; }; }
];
```

Read: [Attribute-Based Access Control](docs/book/src/capability/mac-abac.md)
for labels, the thirty operations, the rule syntax, the tools and the
DTrace provider.

### OpenEndpointSecurity

OES turns the same hooks into an event stream for userland. A program
opens `/dev/oes`, subscribes to a set of events, and either observes them
or authorizes them: each exec, open, unlink, rename, mount, module load,
signal or credential change becomes a message, and for the thirty-six
authorization events the originating thread waits for the subscriber's
verdict. It follows the client model of Apple's Endpoint Security API,
with per-client muting, deadlines, a decision cache, and a
descendants-scoped mode in which a process supervises only its own
subtree. A privileged opener hands rights-limited passive views to third
parties, so an unprivileged consumer never touches the device.

```c
client = oes_client_create();
oes_set_mode(client, OES_MODE_AUTH, 0, 0);
oes_subscribe_all(client, true, true);
oes_mute_self(client);
while (oes_read_event(client, &msg, false) == 0)
        if (oes_is_auth_event(msg))
                oes_respond_allow(client, msg);
```

Read: [Endpoint Security](docs/book/src/capability/oes.md) for the
event table, the library, and a complete subscriber.

## Part two: the capability system

The capability side rests on three kernel ideas: Capsicum extended until
a descriptor is the authority, transfer semantics that make delegation
safe, and a message framework that gives every process an identity and a
channel.

### Extended Capsicum

Capsicum is FreeBSD's sandbox: after `cap_enter(2)` a process can use
only the descriptors it holds and can never again name anything in a
global namespace, and each descriptor is bounded by a rights mask. 5BSD
extends it in four directions so that holding a descriptor is
sufficient authority and nothing else counts.

- **Descriptors that cannot leak.** Capsicum rights say what a holder
  may do with a descriptor but nothing about where it may go. 5BSD adds
  per-descriptor states that only tighten: close-on-exec and
  close-on-fork that the kernel enforces regardless of what the process
  sets, a flag that permits `mmap(2)` of the descriptor only from
  capability mode, and a flag that permits a directory descriptor as a
  `*at(2)` base only from capability mode.
- **Process descriptors as capabilities.** `pdkill(2)` and `pdwait(2)`
  no longer consult uid, jail or MAC; the descriptor's rights are the
  only gate. Process descriptors report the child entering capability
  mode, being jailed, changing uid or root, so a supervisor observes
  readiness rather than trusting a report.
- **Shields.** A launcher puts a kernel shield on a child before it runs.
  A shielded process cannot be traced, signalled, suspended, waited for,
  rescheduled or core-dumped by any process not holding a token for it,
  root included, and can restrict itself from forking, executing, opening
  sockets, receiving descriptors or exercising any privilege.
- **Dynamic binaries in the sandbox.** The kernel permits exactly one
  path lookup from capability mode: the ELF brand's own interpreter. The
  linker then finds libraries through directory descriptors. A
  dynamically linked daemon therefore has no un-sandboxed instant.

```c
/* confine a descriptor: cannot be sent, cannot survive exec or fork */
cap_xfer_limit(fd, CAP_XFER_NONE);
cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED);
cap_clofork_limit(fd, CAP_CLOFORK_LOCKED);
```

Read: [Descriptor and Process Protections](docs/book/src/capability/descriptor-protections.md)
for every new system call with its number and man page, and
[Capability Mode and the Born-Sandboxed Launch](docs/book/src/capability/capability-mode-and-launch.md).

### Transfer semantics: what 5BSD took from Mach

A capability that can be copied without limit is not a capability. Mach
solved this with send-once rights: a port right that is consumed by the
message that carries it. 5BSD puts the same idea on the file descriptor.
Every descriptor carries a transfer state, `CAP_XFER_UNLIMITED`,
`CAP_XFER_ONCE` or `CAP_XFER_NONE`, and the state is monotonic: it can
be tightened by `cap_xfer_limit(2)`, never loosened, and it follows the
descriptor through `dup(2)`, `fork(2)`, `SCM_RIGHTS` and capability
messages alike. A `CAP_XFER_ONCE` descriptor is exhausted by a single
send: after it both the sender's and the receiver's copies are
`CAP_XFER_NONE`. A multi-hop delegation therefore exists only if every
forwarder deliberately re-grants it, which is how a login session's
channel arrives non-transferable and how a launcher hands a child a
bootstrap channel that survives exactly one exec.

The sender can also cap what the receiver gets. `cap_xfer_rights_limit(2)`
and its ioctl and fcntl forms set a ceiling that is intersected with the
descriptor's rights on a permitted transfer, so a process can pass on a
read-and-write descriptor and know the receiver holds it read-only, while
its own copy is unchanged.

Read: [Descriptor and Process Protections](docs/book/src/capability/descriptor-protections.md)
under "The new system calls", and the tests in
`tests/sys/kern/cap_xfer_test.c`.

### The MAC capability framework

`mac_capability` is the kernel substrate that turns those descriptors
into a system. Every kernel service and every process-to-process channel
is reached through one descriptor type, and holding it is holding the
authority.

- **Identity.** Every credential carries a 64-bit nonce the kernel
  generates, inherits on fork and rotates on exec. Userspace cannot set
  it. Every message a process sends arrives with a kernel-stamped
  trailer naming the sender's nonce, uid, gid and jail, so a service
  decides by who is actually speaking and never by what the message
  claims.
- **Channels.** A connected endpoint pair over which requests,
  replies and attached descriptors travel, with kqueue readiness and
  backpressure. Descriptors ride inside messages under the same rights
  and transfer discipline as anywhere else.
- **Coalitions.** Resource groups that are accounted and torn down
  together, so killing an application kills everything it spawned.
- **System gates.** A kernel-held claim on one privileged operation:
  load a module, step the clock, create a jail, write a protected
  sysctl. A sandboxed daemon holds a gate token and asks the kernel to
  perform the operation in kernel context. Root is not exempt from a
  claimed gate.

```c
/* provider side: the kernel says who sent this, not the message */
const struct channel_sender *who = channel_message_sender(request);
if (!policy_allows(who->badge, who->nonce))
        answer.status = EPERM;
channel_send_reply(request, &rep);
```

Read: [The MAC Capability Framework](docs/book/src/capability/mac-capability.md)
for the nine kernel services, the ioctl surface, a synchronous call and
a channel round trip in code;
[System Gates](docs/book/src/capability/system-gates.md);
[Coalitions and Accounting](docs/book/src/capability/coalitions-and-accounting.md);
and [The Authority Model](docs/book/src/capability/authority-model.md)
for the rule underneath all of it.

## Part three: the process model

Three kinds of program run on a 5BSD machine, and each is supported as
it is.

**Linux programs** run through the emulation layer as ordinary
processes with a different system call table. They keep their own
userland under `/compat/linux` or a Linux jail, and they are confined by
capability mode, coalitions, MAC policy and OES exactly as native
programs are, because the enforcement sits beneath the translation.
Read: [A Linux Application](docs/book/src/develop/linux-application.md)
and [Sandboxing and Debugging](docs/book/src/compat/linux/sandboxing.md).

**BSD programs under rc** keep working. `/etc/rc`, `/etc/rc.d`, rc.conf(5)
and service(8) are the FreeBSD ones, and every rc.d daemon starts as it
does on FreeBSD. What changed is who runs `/etc/rc`: the plane's service
manager, which launches its own units in parallel with rc and can adopt
chosen rc.d services into its supervision from a one-line-per-service
list. Read: [rc and service(8)](docs/book/src/compat/rc-and-service.md)
and [Migrating an rc Daemon](docs/book/src/develop/migrating-an-rc-daemon.md).

**Capability bundles** are the third kind, and the reason 5BSD exists.

### Bundles, manifests and declared isolation

A bundle is a `.cap` directory: one `Bundle.ucl` naming the bundle and
its units, and one `Unit.ucl` per unit saying how to run a program. The
manifest is the secure software API from the top of this file. It
describes the program, its user, its activation, its resource ceilings,
its shield, and its visibility. It grants nothing. Everything the program
needs at run time it acquires by name, and it starts already sandboxed.

```ucl
activation { boot = true; ipc = ["system.Time"]; }
control = "core";                      # nobody stops it at runtime, not root
protect = ["ptrace", "signal", "wait", "sigkill", "sigcont",
           "sched", "core", "ktrace"]; # kernel shield before the first instruction
program = "BSDTime";
user = "capability";                   # unprivileged; the token is the authority
capabilities { system = ["settime"]; } # one gate token, delivered at fd 6
limits { nofile = 256; nproc = 64; core = 0; }
umask = "0077";
```

That is the whole manifest of the daemon that sets the system clock. It
runs as an unprivileged user in capability mode; the one line under
`capabilities` is what lets it step the clock, and the kernel refuses
the same operation to root while the claim stands. A manifest can also
declare `directories` to be delivered as descriptors, a `Config/`
directory delivered read-only, a `watchdog` interval, a `domain` that
bounds which names the unit may resolve, `visible` to say who may reach
it, and `holds` for the anointments it presents.

Read: [Bundles and Manifests](docs/book/src/plane/bundles-and-manifests.md)
for the closed key set, every activation trigger, and two complete
manifests.

### Switchboard: the launcher and the switchboard

Capsule is PID 1. It claims the capability device, claims the gates it is
configured to hold, shields itself, and starts one child: switchboard,
the service manager. Switchboard does two jobs. As a launcher it turns
bundles into supervised processes that are born in capability mode: it
places the unit's channel at fd 3, a shield at fd 4, a sealed bootstrap
record at fd 5, gate tokens from fd 6, opens the library and config
directories as descriptors, drops to the manifest's user, applies its
limits, enters capability mode itself, and only then executes the
program. As a switchboard it resolves reverse-domain names to live
channels, launching the provider on demand when nothing is listening.

```
capsule (PID 1)      claims the plane at boot, supervises switchboard
   |
switchboard          launches units born in capability mode and answers
   |                 every name lookup over a per-process channel
   |
BSDAuth              the mint boundary: login, su and sshd authenticate,
   |                 then ask it for a session channel scoped by policy
   |
your program         holds a lookup channel; every capability it reaches
                     is a descriptor it was handed, never a path or a uid
```

A unit that needs storage, a socket, a log, a key, a device or a jail
asks the provider for it by name over its channel. The lookup yields a
fresh direct channel between the two parties, stamped by the kernel with
the caller's label; switchboard is then out of the path. The provider
decides from its own configuration what that label may have and hands
back a descriptor narrowed to exactly those rights. A provider being
down is a delay, not a crash: the client libraries acquire lazily and
retry.

```c
/* a consumer: ask system.Network for a connected socket, by name */
networkcmp_client_open(&net);
networkcmp_getaddrinfo(net, host, port, &hints, &res);
networkcmp_connect_ex(net, res->ai_addr, res->ai_addrlen, 5000, &fd);
write(fd, request, len);          /* an ordinary socket, rights-limited */

/* the same program: its own storage, as a directory descriptor */
service_acquire(&ctx);
service_storage_open(ctx, "spool", &dirfd);
openat(dirfd, "last-reply", O_WRONLY | O_CREAT | O_TRUNC, 0600);
```

Read: [Switchboard](docs/book/src/plane/switchboard.md) for the launch
path step by step and the lifecycle;
[Capsule, PID 1](docs/book/src/plane/capsule.md);
[Discovery and the Lookup Channel](docs/book/src/plane/discovery-and-lookup.md);
and [A Consumer Application](docs/book/src/develop/consumer-app.md),
which builds a complete program that runs both as a sealed unit and from
a shell.

### The sixteen system capabilities

Each facility a program might need is brokered by one provider under one
wire name, and each provider is itself a born-in-capability-mode unit
with its own config file, client library, control tool and tests.

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

Read: [How to Read a Provider Chapter](docs/book/src/providers/overview.md),
then any provider, for its wire operations, client library, policy file
and tool. To write one, read
[A Capability Provider](docs/book/src/develop/provider.md), which builds
an echo service end to end.

### Nesting, visibility and who may manage what

Programs nest, and each level sees less than the one above it.

- **Domains.** A unit from `/Capabilities/System` resolves every name.
  A unit from `/Capabilities/Apps` resolves only names whose provider
  declares itself visible to users. A refusal is `ENOENT`,
  indistinguishable from an unregistered name.
- **Per-user agents.** A user drops a bundle under their own agent root
  and switchboard launches, supervises and restarts it with no operator
  involved. Whatever the manifest declares, the agent is forced to the
  user domain and the user management class, cannot be ambient, cannot
  hold gates and cannot mint sessions. A user's unverified code is
  confined by construction.
- **Private helpers.** A unit marked `helper` publishes no name and is
  reachable only by a sibling unit in the same bundle.
- **Sessions.** login, su and sshd authenticate, then ask BSDAuth for a
  session channel scoped by the principal policy. A shell holds the
  channel and reaches plane services by name; what it may reach is fixed
  at mint. Nobody becomes root to run the machine; an administrator holds
  an anointment for the one thing they need, and `anoint(1)` replaces
  sudo.
- **Management.** A unit's `control` class says who may stop, restart or
  unload it. `core` refuses everyone, root included.

Read: [A Per-User Agent](docs/book/src/develop/per-user-agent.md);
[Anointments and Principal Policy](docs/book/src/plane/anointments.md);
[The Management Model](docs/book/src/plane/management-model.md);
[Sessions: login, su, ssh and cron](docs/book/src/compat/sessions.md).

## Where to go next

| I want to | Read |
|---|---|
| See a whole boot, both systems, with the real log lines | [From Power-On to Login](docs/book/src/orientation/boot-to-login.md) |
| Write a program that uses the plane | [A Consumer Application](docs/book/src/develop/consumer-app.md) |
| Offer a service to other programs | [A Capability Provider](docs/book/src/develop/provider.md) |
| Run a Linux binary, and know what it cannot do | [A Linux Application](docs/book/src/develop/linux-application.md) |
| Move an rc daemon into the plane | [Migrating an rc Daemon](docs/book/src/develop/migrating-an-rc-daemon.md) |
| Ship a driver or a kernel service | [A Device Driver Bundle](docs/book/src/develop/device-driver-bundle.md), [A Kernel Extension](docs/book/src/develop/kernel-extension.md) |
| Find every place policy is decided | [Policy Points](docs/book/src/capability/policy-points.md) |
| Look up a name | [Glossary of Names](docs/book/src/appendix/glossary.md), [Manual Page Index](docs/book/src/appendix/man-index.md) |
| See every divergence from the BSD base, with paths and tests | [`docs/5bsd-inventory.md`](docs/5bsd-inventory.md) |

## Building

5BSD builds like any BSD. GENERIC is the 5BSD kernel; every 5BSD option is
compiled in and there is no separate configuration.

```sh
cd /usr/src
make -j$(sysctl -n hw.ncpu) buildworld
make -j$(sysctl -n hw.ncpu) buildkernel
make -j$(sysctl -n hw.ncpu) packages PKG_CMD=/usr/local/sbin/pkg-static
```

The last step writes a complete pkgbase repository under
`/usr/obj/usr/src/repo/`. The static pkg is required because the ports
pkg tracks a newer libc ABI. Installer media come from
`make -C release memstick`. There is no public package service; base
updates come from a repository you built, and third-party software from
the FreeBSD ports repositories. See
[Building](docs/book/src/operations/building.md),
[Installing](docs/book/src/operations/installing.md) and
[Upgrading](docs/book/src/operations/upgrading.md).

Every capability daemon and library ships an ATF suite:

```sh
kyua test -k /usr/tests/usr.sbin/BSDLog/Kyuafile
kyua test -k /usr/tests/sys/mac_capability/Kyuafile   # needs the plane off
```

Tests that open the capability device directly need a boot with
`capability_plane="NO"`, because a live plane owns it. See
[Testing](docs/book/src/develop/testing.md).

## Where things live

| Area | Path |
|---|---|
| Capability kernel framework | `sys/dev/mac_capability/` |
| Policy modules | `sys/security/mac_abac/`, `sys/security/oes/`, `sys/security/mac/` |
| Capsicum extensions | `sys/kern/sys_capability.c`, `sys/sys/capsicum.h` |
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
| Specifications and ledgers | `docs/`, indexed in [Design Document Index](docs/book/src/appendix/design-docs.md) |

## Lineage and status

5BSD descends from the BSD family and inherits its base from the FreeBSD
tree at one point in time; later upstream work is merged selectively,
not tracked. 5BSD is 64-bit only: no 32-bit compatibility layer, no
lib32, no i386 or armv7 targets. ZFS is required. The
[BSD Side](docs/book/src/compat/bsd-side.md) chapter lists what a
developer coming from another BSD will notice.

The capability core, the plane, the sixteen providers, TrustedZFS, the
Linux emulation layer, the virtualization stack and the Bluetooth host
are committed and tested, and a from-scratch build packages and boots.
Where a book chapter describes designed or partially delivered work it
says so in a Status paragraph.

What is still UNIX today, stated plainly: on the UNIX side root exists
and can do what root does elsewhere, though not inside the plane; file
access outside the plane is mode bits and ACLs unless `mac_abac` is
enforcing; a number of kernel checks are still uid checks with a
capability path beside them; some providers still run as root because
the operation they broker has no gate yet; verified execution is present
but not yet enforcing; and Linux seccomp and Landlock are in progress.
The direction is fixed: every privileged operation becomes a gate,
remaining uid checks become a held-capability flag, resource authority
follows, the rc daemons migrate to units, and root is removed. The
[Authority Model](docs/book/src/capability/authority-model.md) chapter
tracks where each phase stands. The plane is optional at boot: with
`capability_plane="NO"` in loader.conf, capsule hands off to stock init
and the machine is an ordinary BSD system.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: pull requests
against `dev`, current names only, every claim in a document checked
against the tree, and tests for anything that touches the trusted
computing base.
