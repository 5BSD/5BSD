# How to Read This Book

The 5BSD Epic is organised by subject, not by reader, because the same
mechanism matters to an operator debugging a boot and to a developer choosing
an API. This chapter gives each kind of reader an ordered path through the
chapters and explains the conventions every chapter follows, so that a reader
can tell at a glance what is shipped, what is a path on disk, and what is a
man page to open next.

Whoever you are, read Part I first. [What 5BSD Is](what-5bsd-is.md) states
the principles and lists the sixteen system capabilities;
[From Power-On to Login](boot-to-login.md) shows the whole machine in motion
once. Everything after that assumes both.

## Reading paths

### The operator

You install, upgrade and run 5BSD machines and you want to know where your
FreeBSD habits still hold.

1. [The BSD Side](../compat/bsd-side.md), because most of what you do every
   day is unchanged and this chapter says exactly what is not.
2. [Installing](../operations/installing.md) and
   [Boot Knobs](../operations/boot-knobs.md), for the ZFS-root requirement,
   `init_path`, `capability_plane` and the loader defaults.
3. [rc and service(8)](../compat/rc-and-service.md), because switchboard now
   runs `/etc/rc` and adopts cron, and `service(8)` behaves accordingly.
4. [Sessions: login, su, ssh and cron](../compat/sessions.md) and
   [Anointments and Principal Policy](../plane/anointments.md), because
   `/Capabilities/Config/principal-policy.ucl` decides what a login holds and
   anoint(1) replaces sudo.
5. [The Management Model](../plane/management-model.md), for what root can
   and cannot stop, and why a CORE unit resists it.
6. [Observability](../operations/observability.md) and
   [Troubleshooting](../operations/troubleshooting.md), for
   `/var/log/capability.log`, logctl(8), the DTrace scripts and the shape of
   a stalled boot.
7. [Tool Reference](../operations/tools.md), to keep open.
8. [Upgrading](../operations/upgrading.md) and
   [Packages and Ports](../compat/packages.md), for pkgbase, the `5BSD-`
   package sets and the local repository.

Dip into Part IV when a specific provider misbehaves; each chapter ends with
its policy file and its control tool.

### The application developer

You write programs that run on 5BSD and want the plane's services without
becoming a plane expert.

1. [Choosing What to Write](../develop/choosing.md), which decides whether
   your program is a consumer, an agent, a provider or an rc daemon, and
   what each costs.
2. [The Authority Model](../capability/authority-model.md), because
   everything the client libraries do follows from its one rule.
3. [Discovery and the Lookup Channel](../plane/discovery-and-lookup.md), for
   `service_open(3)`, lazy acquisition and fail-soft behaviour.
4. [A Consumer Application](../develop/consumer-app.md), the worked example.
5. [Bundles and Manifests](../plane/bundles-and-manifests.md) and
   [Containers and Storage](../plane/containers-and-storage.md), for the
   `.cap` you ship and the `/Capabilities/Data` home you get.
6. The Part IV chapters for the providers you call, most often
   [system.Filesystem](../providers/filesystem.md),
   [system.Log](../providers/log.md), [system.Network](../providers/network.md)
   and [system.Notify](../providers/notify.md).
7. [A Per-User Agent](../develop/per-user-agent.md) if your program runs on
   a user's behalf, then [Testing](../develop/testing.md) and
   [Packaging and Shipping](../develop/packaging.md).

If your program is a Linux binary, read
[A Linux Application](../develop/linux-application.md) and
[Running Real Applications](../compat/linux/running-apps.md) instead of
steps 4 to 6.

### The provider author

You are adding a new system capability or a facility broker, and your code
will be part of the trusted computing base.

1. [The MAC Capability Framework](../capability/mac-capability.md), for
   CALL versus SENDMSG/RECVMSG, the credential trailer, badges and revocation.
2. [Capability Mode and the Born-Sandboxed Launch](../capability/capability-mode-and-launch.md),
   because your daemon will start inside capability mode with only the
   descriptors switchboard delivers.
3. [System Gates](../capability/system-gates.md) if the facility needs a
   privileged kernel operation, and
   [Policy Points](../capability/policy-points.md) for where the knobs live.
4. [Switchboard](../plane/switchboard.md) and
   [Bundles and Manifests](../plane/bundles-and-manifests.md), for the
   launch contract, `visible`, `requires`, `directories` and `protect`.
5. [How to Read a Provider Chapter](../providers/overview.md), then two
   existing providers as models: [system.Time](../providers/time.md) for
   the smallest gate daemon and [system.Log](../providers/log.md) for one
   with storage.
6. [A Capability Provider](../develop/provider.md), the worked example, and
   [Logging, Audit and Trace](../plane/logging-audit-trace.md) for the
   probes, logs and audit events every provider must carry.
7. [Testing](../develop/testing.md), with particular attention to the
   real-plane VM runner; provider code is not done until it has run there.

### The kernel engineer

You extend the kernel, add a MAC policy, a mac_capability service or a
driver, and you need the framework and its rules.

1. [The MAC Capability Framework](../capability/mac-capability.md),
   [Coalitions and Accounting](../capability/coalitions-and-accounting.md) and
   [Descriptor and Process Protections](../capability/descriptor-protections.md),
   the kernel core in order.
2. [Policy Points](../capability/policy-points.md) and
   [System Gates](../capability/system-gates.md), for every sysctl, gate and
   hook the plane exposes.
3. [Attribute-Based Access Control](../capability/mac-abac.md),
   [Endpoint Security (OES)](../capability/oes.md) and
   [Verified Execution](../capability/veriexec.md), the modules beside the
   plane and how deny-wins composition works across them.
4. [Capsule, PID 1](../plane/capsule.md), because PID 1 owns the device your
   service will be reached through.
5. [A Kernel Extension](../develop/kernel-extension.md) and
   [A Device Driver Bundle](../develop/device-driver-bundle.md), for how
   modules are loaded through `system.SystemExtension` and how a driver
   ships with its userland.
6. [Building](../operations/building.md), for GENERIC as the 5BSD kernel,
   GENERIC-DEBUG and the pkgbase build.
7. The appendix [System Calls and Sysctls](../appendix/syscalls-and-sysctls.md).

Engineers working on the Linux ABI or virtualization should add
[Linux Emulation](../compat/linux/overview.md) with its sub-chapters, or
[Virtual Machines](../compat/virtual-machines.md) and
[system.VM](../providers/vm.md), after step 3.

### Porting from FreeBSD or Linux

You have software that runs elsewhere and want it running here with the
least change.

1. [The BSD Side](../compat/bsd-side.md), to confirm how little changes for
   a FreeBSD program that stays on the BSD side.
2. [Migrating an rc Daemon](../develop/migrating-an-rc-daemon.md), the
   incremental path from an rc.d script to a bundle, one capability at a
   time.
3. [Sessions: login, su, ssh and cron](../compat/sessions.md), because a
   daemon that spawns user sessions must carry the lookup channel correctly.
4. For Linux software, [Linux Emulation](../compat/linux/overview.md),
   [System Calls](../compat/linux/syscalls.md),
   [procfs, sysfs and the Filesystem View](../compat/linux/procfs-sysfs.md),
   and [Sandboxing and Debugging](../compat/linux/sandboxing.md), which also
   explains why seccomp and namespaces are not the sandbox here.
5. [Jails](../compat/jails.md), for a Linux userland in a jail, and
   [Packages and Ports](../compat/packages.md).

## Conventions

**Names.** Every component has exactly one name in this book, the current
one. PID 1 is capsule; the service manager is switchboard; providers are the
BSD\* programs and their wire names are `system.X`. The
[Glossary of Names](../appendix/glossary.md) lists each with the names it
replaced, so a reader who meets an old name in a commit message or a design
document can map it. A chapter never uses a superseded name in prose.

**Paths.** A path in backticks, such as `usr.sbin/switchboard/startup.c`, is
relative to the top of the source tree unless it begins with `/`, in which
case it is a path on an installed system, such as
`/Capabilities/Config/principal-policy.ucl`. When a chapter cites a source
file it is inviting you to read it; the book does not paraphrase what a
header states.

**Man pages.** A reference of the form switchboard(8) or libservice(3) names
a manual page installed on 5BSD, in section 8 or 3. The
[Manual Page Index](../appendix/man-index.md) lists the 104 pages 5BSD adds.
Where a FreeBSD page describes 5BSD behaviour correctly the book cites it
rather than restating it.

**Wire names, manifest keys and code.** Wire names appear in backticks
(`system.Filesystem`). Manifest keys appear in backticks with their UCL
spelling (`activation { boot = true }`). Function names carry their section
(`service_open(3)`); wire operations and constants are in backticks
(`SVC_OP_READY`, `SERVICE_LOOKUP_FIXED_FD`). Anything you would type is in a
code block, with `$` for a command an ordinary user may run and `#` for one
that needs a privileged session.

**Tables and lists.** Option sets, op sets and policy keys are tables, so
they can be scanned and compared. A table's columns are the same across a
part: Part IV chapters share one template, described in
[How to Read a Provider Chapter](../providers/overview.md).

**Shipped, in progress, design-only.** Each chapter describes what is in the
tree and says so where a piece is missing. Three words are used
consistently: *shipped* means built, tested and committed on `dev`;
*in progress* means code exists but is incomplete or uncommitted;
*design-only* means a design document exists under `docs/` and no code. A
feature that is present but not enforced (verified execution today) is
described as exactly that.

**Status paragraphs.** Every chapter ends with a paragraph headed **Status**
carrying the date its claims were checked against the tree and the commit
or validation that backs them. It is the one place a date appears in prose.
If a Status paragraph is older than the tree you are running, treat the
chapter as possibly stale and check the cited files before relying on it.

**Links.** Chapters link to one another by relative path. A link to a design
document under `docs/` points at the design, which may describe intent
beyond what is built; the chapter text, not the design document, is the
statement of what exists. The
[Design Document Index](../appendix/design-docs.md) annotates each document
with its status.

**Status.** Conventions and reading paths reflect the chapter plan for the
Epic as of 2026-09-25; the linked chapters are being written to that plan.
