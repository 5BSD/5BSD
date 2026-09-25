# Choosing What to Write

5BSD runs two kinds of software side by side: the ordinary BSD programs that
FreeBSD runs, and programs that live in the capability plane, where authority
is a held descriptor rather than a uid or a path. Before you write a line, decide
which kind you are writing, because the choice fixes how the program gets its
authority, who launches it, how it ships, and which chapter of this part you
should read next. This chapter is the decision table, followed by the three
rules that every kind obeys.

## The kinds

| Kind | Choose it when | Authority it holds | Launched by | Ships as | Chapter |
|---|---|---|---|---|---|
| Capability provider | You offer a facility to other programs under a name | Its own channel; anything it acquires by name; a system gate only if it is a base bundle | switchboard, on first lookup of its `ipc` name or at boot | A `.cap` bundle under `/Capabilities/Apps` (site) or `/Capabilities/System` (base, pkgbase) | [A Capability Provider](provider.md) |
| Consumer application | You need system facilities (network, log, storage) and publish nothing | Sessions to `system.*` providers, opened lazily; a per-unit storage container | switchboard (boot, timer, schedule, socket, path) or a shell | A `.cap` bundle, or a plain package binary run from a session | [A Consumer Application](consumer-app.md) |
| Per-user agent | One user wants a long-running program of their own | The same as a consumer, confined to the user's domain | switchboard, from `/Capabilities/Users/<uid>/Agents` | A `.cap` owned by that uid | [A Per-User Agent](per-user-agent.md) |
| Migrated rc daemon | A daemon you already have, moving in steps | Starts with the uid's ambient authority, ends with a channel and delivered descriptors | rc.d first (adopted from `rc_adopt.conf`), then switchboard | An rc.d script first, a `.cap` at the end | [Migrating an rc Daemon](migrating-an-rc-daemon.md) |
| Linux application | The program exists only as a Linux binary | The ambient authority of the uid, through the Linuxulator | A shell, rc.d, or a container runtime | A Linux package tree | [A Linux Application](linux-application.md) |
| Device driver bundle | Hardware needs a kernel module plus the userland that drives it | The module: the kernel; the userland: a `system.Device` session | BSDExtension loads the module on request; switchboard launches the unit | A bundle carrying both | [A Device Driver Bundle](device-driver-bundle.md) |
| Kernel extension | You extend the kernel itself | Everything, once loaded | `service_ensure_extension(3)` through BSDExtension, gated by its allow-list | A kernel module under `/boot` | [A Kernel Extension](kernel-extension.md) |
| Plain BSD program | None of the above applies | The ambient authority of the uid, as on FreeBSD | Anything | A package | The FreeBSD Handbook |

The last row is not a consolation prize. Most software on a 5BSD machine is
plain BSD software: the compiler, the shell, ports, most of base. The plane
exists beside them, not instead of them, and a plain program can reach any
provider whose name its session may resolve (see
[Discovery and the Lookup Channel](../plane/discovery-and-lookup.md)).

## Reading the columns

**Authority.** A plane program never holds authority because of who it is.
It holds descriptors: the bootstrap channel switchboard delivered at launch,
sessions it opened by name, directory descriptors for storage it claimed,
device nodes a broker opened for it. Nothing in its manifest grants a resource;
`switchboard(5)` rejects the eager grant keys of earlier designs. The one
exception is the `capabilities { system = [...] }` block, which names the
`mac_capability(4)` system gates a base provider such as BSDTime holds. It is
stripped from any bundle loaded from a per-user agent directory, and for every
other bundle the declaration is the grant: switchboard mints exactly what the
`O_VERIFY`-opened manifest declares, so under `mac_veriexec` a gate can only
come from a bundle in the verified set. `switchboard(5)` reserves it for the
base providers; an application never needs it (see
[System Gates](../capability/system-gates.md)).

**Launch.** switchboard launches every bundle unit born in capability mode:
it `cap_enter(2)`s in the child and then `fexecve(2)`s the verified program
from the bundle, so the image runs its first instruction already sealed. Its
libraries arrive by descriptor (`LD_LIBRARY_PATH_FDS`), its bundled `Config/`
directory by descriptor (`CAPABILITY_CONFIG_FD`), and any `directories` the
manifest names by descriptor (`CAPABILITY_DIR_FDS`). Standard output and error
go to `/var/log/capability.log`. An `ambient = true` unit skips the seal, and
only a base-system bundle may say so; switchboard ignores the key elsewhere and
logs that it did. The mechanism is in
[Capability Mode and the Born-Sandboxed Launch](../capability/capability-mode-and-launch.md).

**Shipping.** A bundle is a directory:

```text
Name.cap/
  Bundle.ucl                identity: bundle_id, version, sequence, units
  Units/<unit>.unit/
    Unit.ucl                how to launch: activation, restart, control, ...
    bin/<unit>              the program (or `program = "name"` below bin/)
    Config/                 optional, delivered read-only as a descriptor
    lib/                    optional private shared libraries
```

The tree must be root-owned under `/Capabilities/System` and
`/Capabilities/Apps`, and owned by the user under `/Capabilities/Users/<uid>/Agents`.
`switchboardctl verify Name.cap` checks all of it offline. Packaging into the
pkgbase sets is in [Packaging and Shipping](packaging.md).

## Which domain can see you

Two manifest keys decide reach, and they are easy to confuse. `visible` says
which session kinds may resolve the names a unit publishes; a name with no
`visible` is resolvable only by SYSTEM-domain sessions (an admin login, a base
unit). `domain` says which names the unit itself may resolve; when absent, a
`/Capabilities/System` bundle resolves everything and an `/Capabilities/Apps`
bundle resolves only user-visible names. Of the base providers, only
`system.Auth`, `system.Log`, `system.Filesystem` and `system.Notify` are
`visible = ["user"]`; `system.Network`, for instance, is SYSTEM-only. An
application that needs it declares `domain = "system"`, which an Apps bundle
may do; a per-user agent may not, because switchboard forces `domain = "user"`
on every unit loaded from an agent directory. The full model is in
[The Management Model](../plane/management-model.md).

## The three rules

Whatever row you chose, three rules apply, and the chapters that follow return
to them again and again.

### Fail soft

A provider may be down. It may not have started yet at boot; it may have been
restarted by its watchdog; its bundle may have been disabled by an operator.
None of that is your program's failure. Acquire lazily, on first use; when the
acquire fails, log it and try again later; never `err(1)` because a name did not
resolve. The libraries are built this way: `logcmp_log(3)` falls back to
`syslog(3)` when `system.Log` is unreachable and never fails the caller;
`networkcmp_client_open(3)` returns -1 with an errno you can retry on;
`service_storage_open(3)` marks a dead session so the next claim reopens it.
Your code has to keep the same promise one level up. The
[consumer chapter](consumer-app.md) shows the retry loop.

### Acquire on demand, by name

There is no manifest key for "give me the network" or "give me this file". A
program that needs a socket opens `system.Network` and asks for one; a program
that needs a file it does not ship opens `system.Filesystem` through
`service_open_isolated(3)` and receives a rights-limited descriptor if the
per-label policy in `tzfs.conf(5)` grants it; a program that needs storage
calls `service_storage_open(3)` and receives a directory descriptor for its own
container. Every grant is scoped by the caller's channel label, which the
kernel stamps and the caller cannot forge. The manifest describes how to
launch the program, nothing more. See
[Bundles and Manifests](../plane/bundles-and-manifests.md).

### No uid checks

A plane program never asks `getpeereid(3)` and never compares a uid to zero.
On the provider side, `service_listener_accept(3)` fills a `struct
service_identity` whose `client_label` is the caller's bundle label
(`bundle_id/unit`, for instance `system.Auth/bsdauth`) and whose `rights` is
the rights mask switchboard granted that session. Policy keys on the label.
The one cross-service right is `SERVICE_RIGHTS_ADMIN`, granted only to an
admin login session's connections, and it bypasses a provider's per-object
policy the way "root may do anything" used to. On the consumer side, a program
does not become powerful by running as root; it becomes powerful by holding a
session to the right name, which a root login may or may not be able to
resolve. The reasoning is in
[The Authority Model](../capability/authority-model.md).

## Status

Everything in the table is shipped except the rows that point at the Linux,
device-driver and kernel-extension chapters, which describe programs the plane
hosts rather than programs written against it. Two details are worth knowing
before you start: the per-user agent root is scanned at boot and on reload,
not on login (see [A Per-User Agent](per-user-agent.md)), and the manifest
`capabilities` block is the only remaining declaration of anything but launch
policy, reserved for base brokers.
