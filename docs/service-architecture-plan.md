# Demand-driven service management plan

Status: authoritative pre-v1 design plan.  This replaces the earlier proposal
for a dependency-graph service manager.  The format may change freely until
v1; no compatibility parser or migration shim is required.

The objective is a small, dependable service manager with the useful behavior
of launchd and systemd activation, while preserving 5BSD's descriptor-based
authority model.  It deliberately does **not** reproduce systemd's dependency
language, launchd's plist layout, or SMF's central database.

## 1. Decisions

These decisions are part of the design, not open questions:

1. There are no manifest `requires`, `wants`, `before`, `after`, target, or
   ordering edges.
2. Registration is cheap; running is demand-driven.  Installing or enabling a
   unit does not normally start it.
3. IPC and manager-owned listeners are the primary demand sources.  Timers,
   filesystem events, explicit administrative requests, and a bounded boot
   event are additional demand sources.
4. A provider obtains other services by using their IPC interfaces.  The
   lookup activates them and queues the request until they are ready.  IPC is
   the availability relationship.
5. Storage, identities, kernel gates, and local descriptors are provisioned
   directly for a launch.  They are resources, not service dependencies.
6. There is no operator-facing bundle rollback system.  Upgrade publication
   is transactional so a rejected replacement never displaces the active
   registry, but serviced does not select arbitrary historical versions.
7. One system network broker supplies DNS and connected sockets.  A general
   userspace network stack, virtual network topology, and per-bundle network
   namespace are deferred.
8. Bundle definitions remain literal, strict UCL.  Mutable manager state is a
   small collection of atomically replaced UCL files, not an opaque database.
9. The existing `/etc/rc` boot remains one transitional compatibility job.
   Native capability units do not acquire hard edges to rc services.

Apple's launchd is the closest precedent: its manual explicitly has no
dependency model and expects IPC services and manager-owned sockets to solve
availability.  systemd's named socket descriptors are useful, but its unit
dependency graph is not part of this design.  FreeBSD Casper's `system.net`
service demonstrates that DNS, bind, and connect operations can be attenuated
without giving a capability-mode client ambient networking authority.

Primary references:

- <https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5>
- <https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html>
- `lib/libcasper/services/cap_net/cap_net.3` in this source tree

## 2. Responsibility boundaries

### authority-init / authorityd

PID 1 owns only authority and recovery mechanisms that must survive a service
manager failure:

- process reaping and final machine lifecycle;
- the recovery console and single-user transition;
- the root mac_capability handles and authority ceilings;
- supervision and bounded restart of serviced;
- privileged operations such as kernel-module loading that cannot safely be
  delegated as ordinary ambient privilege.

PID 1 does not interpret application bundles, choose versions, schedule jobs,
or manage application readiness.

### serviced

One system-wide serviced instance owns:

- bundle discovery and transactional registry replacement;
- the IPC namespace and pending lookup queues;
- trigger registration and demand accounting;
- process launch, readiness, restart/backoff, idle exit, and shutdown;
- storage leases and crash reconciliation;
- manager-owned activation listeners;
- enable/disable state and the administrative control socket.

### provider daemons

Notification, logging, tracing, audit, filesystem, crypto, and networking are
ordinary supervised providers.  They are not compiled into serviced.  A
provider may be replaced without expanding the authority of serviced.

## 3. The demand model

A unit is normally loaded but stopped.  A demand record names the unit, the
trigger, a deadline, and any queued authority such as an IPC request or
listener descriptor.

Demand sources are:

| Trigger | Meaning |
| --- | --- |
| `ipc` | A client looked up a reserved service name. |
| `socket` | A manager-owned listener became readable. |
| `timer` | A monotonic or calendar schedule fired. |
| `path` | A kqueue filesystem condition changed. |
| `admin` | `servicectl start` requested one activation. |
| `boot` | The one boot-generation event requested an early or compatibility job. |

`boot` is a demand event, not a dependency tier and not an implicit keepalive.
A boot-triggered provider may become idle and exit after it has completed its
work.  Only the small PID 1 / serviced spine is unconditionally resident.

Multiple simultaneous demands coalesce into one launch.  Pending IPC and
socket work remains held by the manager while the provider starts.  Each
request retains its own deadline and cancellation state; one abandoned client
does not cancel another client's demand.

The manager maintains a demand reference count per unit:

```text
zero demand + stopped       -> remain stopped
first demand + stopped      -> start once
more demand + starting      -> queue/coalesce
ready                       -> deliver queued work
zero demand + idle timeout  -> request clean exit, then stop
crash + pending demand      -> bounded restart/backoff
crash + no demand           -> remain stopped
```

An explicit `resident = true` policy is reserved for a very small set of
audited base services.  Application bundles cannot use it by default.  This
is clearer than overloading `restart = always` as a keepalive declaration.

## 4. Bundle and unit contract

The existing two-level structure remains:

```text
Example.cap/
├── Bundle.ucl
├── Shared/
│   ├── Config/
│   ├── Resources/
│   └── Libraries/
└── Units/
    ├── api.unit/
    │   ├── Unit.ucl
    │   ├── bin/api
    │   ├── Config/
    │   └── Resources/
    └── worker.unit/
        ├── Unit.ucl
        └── bin/worker
```

`Bundle.ucl` owns identity, display version, monotonic install sequence, unit
inventory, and genuinely shared immutable resources or storage declarations.
Each `Unit.ucl` owns one process's program, credentials, triggers, restart
behavior, storage access, and capability ceiling.

No dependency keys are accepted.  In particular, these remain errors:

```ucl
requires = [];
wants = [];
before = [];
after = [];
```

A fully loaded demand-driven unit looks like:

```ucl
arguments = ["--foreground"];
environment = { MODE = "production"; };
user = "capability";
group = "capability";

activation {
    ipc = ["org.example.mail.smtp"];
    idle_timeout = 30;
}

restart = "on-failure";
stop_timeout = 10;
max_failures = 10;

capabilities {
    ipc = ["system.Log"];
    system = [];
}
```

The `capabilities.ipc` entries are authority to look up those global names; they
are not startup edges.  The first actual lookup creates demand for the provider.
Reachability is otherwise governed entirely by the discovery domain (SYSTEM/USER)
— a unit needs no manifest declaration to use a capability service.  (The former
per-unit `capabilities.services` allow-list has been removed.)

Packaged configuration and static resources stay in the immutable bundle.
Before entering capability mode, serviced passes rights-limited descriptors
for the bundle, shared, unit Config, and unit Resources directories.  A path
environment variable may be supplied for diagnostics, but it is not the
authority mechanism.  Executables should ultimately be pinned and launched
with `fexecve(2)` from the verified tree.

Machine-local configuration and secrets live in named persistent storage and
are passed separately from immutable defaults.  They do not mutate the
installed `.cap` directory and do not return to a general `/etc` namespace.

## 5. IPC activation and readiness

At registry publication serviced reserves every declared IPC name.  Lookup is
always against this reservation, never against a provider-created pathname.

The sequence is:

1. client requests `org.example.service`;
2. serviced authenticates the requester and verifies its lookup authority;
3. serviced queues the request and records demand;
4. the provider is launched if it is not already starting or ready;
5. the provider checks in with its complete declared name set;
6. serviced independently observes the provider entering capability mode;
7. serviced transfers the queued channel endpoints;
8. demand is released when the session closes or the request is cancelled.

Readiness requires both check-in and confinement.  Merely forking, opening a
socket, writing a pidfile, or surviving for a delay is not readiness.

Provider failure before readiness fails queued requests with one stable error
and participates in bounded restart/backoff.  A circuit-open provider remains
registered: new lookups receive an immediate diagnostic error containing the
retry time instead of hanging.

## 6. Socket activation

Listening endpoints are resources held by the manager, not proof that another
unit started first.  A future `activation.socket` entry declares a named
listener:

```ucl
activation {
    socket = [{
        name = "https";
        family = "inet6";
        type = "stream";
        address = "::";
        port = 443;
        accept = false;
    }];
    idle_timeout = 60;
}
```

serviced asks the network broker to create and hold the listener while the
unit is stopped.  Readability creates demand.  After readiness, the listener
is delivered under the declared descriptor name.  `accept = true` may later
launch one isolated instance per accepted connection, but it is not required
for the first implementation.

Named descriptors are delivered in the service bootstrap table, not through
fixed fd numbers or a count-only environment variable.  A unit asks for
`listener:https` and receives exactly that descriptor.

Unix-domain application IPC should normally use the serviced IPC namespace.
Filesystem socket paths are supported only for compatibility jobs and must not
be the native discovery mechanism.

## 7. No dependency graph

Removing hard dependencies is intentional, but it transfers responsibility to
clear runtime behavior:

- Logging a message activates the log service or uses a bounded local fallback.
- Resolving or connecting activates the network broker.
- Requesting a filesystem descriptor activates its provider.
- A service unavailable before network configuration receives a retryable
  network error or waits within its own request deadline.
- A provider that needs another provider performs an ordinary authorized
  lookup after launch.

serviced detects activation recursion at runtime.  If A's startup waits on B
and B's startup waits on A, the second lookup fails with `EDEADLK`, logs the
complete activation chain, and does not consume the global pending-request
budget.  This is not a hidden dependency graph; it is bounded deadlock
protection for actual IPC calls.

Boot convergence is likewise not a topological sort.  PID 1 emits the boot
event, serviced runs the transitional rc job and the small explicit set of
boot-triggered native jobs, and convergence completes when those finite
demands complete or reach a terminal failure.  Ordinary IPC providers remain
stopped until used.

## 8. Network broker: simple now, extensible later

The current network design mixes direct network claims, private proxy workers,
handle-based socket emulation, and inline data transfer.  That is too much
mechanism for the initial goal.

The replacement is one system-wide provider, provisionally `socketbrokerd`,
published as `system.Network`.  It follows the Casper model but returns
usable, rights-limited sockets rather than proxying application data.

Initial operations are deliberately small:

```text
hello       return version and hard limits
resolve     bounded getaddrinfo-style lookup
connect     create and connect TCP socket; return connected fd
udp         create connected UDP socket; return connected fd
```

The caller never supplies policy.  serviced mints the session from the
caller's effective unit manifest and administrative ceiling.  The broker
validates family, protocol, destination address/name, and port against that
immutable session policy.

Returned connected sockets have only the rights needed for data transfer and
event notification.  They cannot bind, listen, accept, reconnect, or change
security-relevant socket options.  The broker applies allowed options before
transfer and locks descriptor inheritance/transfer state as tightly as the
consumer API permits.

Inbound listeners are not created through the client `connect` API.  They are
declared under `activation.socket`, created for serviced by the same broker,
and held by serviced across provider restarts.

The first policy format should express only what the broker implements:

```ucl
network = [{
    operation = "connect";
    family = "inet";
    protocol = "tcp";
    destination = "192.0.2.0/24";
    ports = [443];
}];
```

Name-based policy must pin a resolution result to the connect operation so a
second lookup or DNS rebinding cannot broaden authority.  An unrestricted
`network {}` descriptor is not accepted.  Bind/listen policy is represented
only by activation listeners.

The broker source and manual must contain an explicit scope note: future work
may add userspace protocol stacks, per-bundle virtual interfaces, traffic
accounting, and richer network isolation, but none of those semantics are
implied by protocol version 1.  New behavior requires a negotiated protocol
version and new tests.

## 9. Restart, idleness, and process ownership

Every launch uses `pdfork(2)` and a coalition.  serviced owns the complete
process group even if the initial process forks within its granted policy.

Restart policy describes failure while demanded:

- `never`: fail current demand and remain stopped;
- `on-failure`: restart while demand remains, subject to backoff;
- `always`: reserved synonym for restart after any exit while demand remains;
- `resident`: separate audited policy for an unconditional base service.

Rapid failures use exponential bounded backoff, a rolling failure window, and
a circuit breaker.  Successful readiness resets only the rapid-start portion;
it does not erase the last failure diagnostic.

When demand reaches zero, an idle-capable provider receives an idle event.
After `idle_timeout`, serviced asks it to stop and then applies its ordinary
stop deadline.  Providers may report a bounded internal busy count, but they
cannot keep themselves alive forever without an active manager-visible lease.

## 10. Installation and update without rollback machinery

`servicectl install` performs a transactional publication:

1. copy to a non-scanned staging directory without following symlinks;
2. normalize owner and writable bits;
3. fsync files, directories, and staging parent;
4. validate structure, UCL, binaries, resources, and authority bounds;
5. atomically publish the canonical sequence directory;
6. ask serviced to build and validate a replacement registry;
7. commit the replacement only when every reservation succeeds.

If replacement validation fails, the currently loaded registry continues to
serve requests.  This is failed-update atomicity, not a version rollback
feature.  serviced always selects the highest valid installed sequence and has
no `select-version` or `rollback` command.

Package removal cannot delete mutable storage.  `uninstall` disables new
demand, drains or force-stops the unit under an explicit deadline, removes the
immutable bundle, and records orphaned storage.  `purge` is a separate command
that names the exact bundle and storage roles to destroy.

Superseded immutable versions and abandoned staging directories are eligible
for bounded garbage collection once no running process or pinned descriptor
references them.  pkg and serviced must agree on ownership; neither silently
removes files owned by the other.

## 11. Mutable state without a database

The bundle tree is the source of service definitions.  Initial mutable state
is stored below `/Capabilities/State/serviced` as strict, versioned UCL using
write-fsync-rename-directory-fsync replacement:

- enabled/disabled unit state;
- circuit-breaker and last-failure diagnostics;
- persistent timer cursors;
- storage cleanup generations and orphan records;
- incomplete install/uninstall transaction markers.

Runtime state is reconstructed from bundles, process descriptors, kernel boot
generation, and TrustedZFS properties.  State files are hints or durable
operator choices; corruption cannot grant authority.  Invalid mutable state is
quarantined and reported, then replaced with safe defaults.

A database is justified only by measured scale or multi-record transaction
requirements.  If introduced later, it must remain rebuildable from bundles
and independently exportable state.

## 12. Control surface

The initial administrative interface is intentionally smaller than systemctl:

```text
servicectl status [unit]
servicectl services
servicectl bundles
servicectl enable UNIT
servicectl disable UNIT
servicectl start UNIT
servicectl stop UNIT
servicectl reload
servicectl verify PATH.cap
servicectl install PATH.cap
servicectl uninstall BUNDLE-ID
servicectl purge BUNDLE-ID STORAGE...
servicectl reset-failure UNIT
```

There is no rollback or dependency command.  `start` creates one explicit
administrative demand; it does not make the unit resident.  `enable` permits
declared triggers to create demand; `disable` rejects new demand and may drain
existing sessions according to policy.

Status exposes the effective selected bundle, state, demand count and sources,
PID/coalition/jail, readiness and capability-mode observations, published IPC
names, held listeners, restart/backoff state, last exit, storage leases, and
quarantine errors.

All mutating operations are root-only initially.  A later user domain gets a
separate authority ceiling and namespace, not ambient access to the system
control socket.

## 13. Timers and path triggers

Timers are activation sources, not dependency units.  A timer declaration
names one unit in its own bundle and creates one demand when it fires.  The
first version supports monotonic intervals.  Calendar expressions, persistent
catch-up, and user schedules follow only after clock-change, suspend/resume,
duplicate-fire, and crash persistence semantics are specified.

Path activation uses native kqueue vnode events.  inotify compatibility may be
an implementation adapter, but it is not the public manifest ABI.  Path
events are hints: after activation, the consumer must inspect current state and
handle rename, deletion, replacement, overflow, and coalescing.  The manifest
must never imply that observing one event proves a path remains unchanged.

This eventually replaces cron and ad-hoc watcher daemons without adding
dependency ordering.

## 14. rc transition

For now `/etc/rc autoboot` is one boot-triggered compatibility job.  It retains
stock rcorder behavior internally.  Native providers coexist with it but are
not ordered through it.

Migration is service-by-service:

1. identify the external event or IPC operation that actually needs the
   service;
2. give serviced ownership of that IPC name, listener, timer, or path trigger;
3. package the daemon as a `.cap` unit with its authority ceiling;
4. prove demand launch, readiness, idle exit, restart, shutdown, and recovery;
5. remove the rc-owned instance so there is exactly one owner.

Per-script rc ingestion is unnecessary unless a real migration cannot be
expressed as demand activation.  We should not build an rc dependency graph
inside serviced merely to reproduce rcorder.

## 15. Recovery and availability

Registry reload is transactional.  An invalid local bundle is quarantined and
cannot reserve names, but does not remove the valid active registry.  An
invalid base-system bundle is a boot convergence failure because continuing
could silently omit required system authority.

If serviced crashes, PID 1 stops the old supervised process tree before
starting a new manager session.  The new instance reconstructs registrations,
listeners, boot/storage generations, and durable operator choices before
accepting requests.  Pending client operations fail deterministically rather
than being silently replayed across manager generations.

If serviced repeatedly fails before convergence, PID 1 opens the independent
single-user recovery console.  Recovery never depends on a working bundle
parser, network broker, or mutable state store.

## 16. Implementation phases

### Phase 0: finish and qualify the current base

- Complete the active clean-VM Kyua run and fix every failure.
- Pin bundle/resource directories by descriptor and executable by fd.
- Finish ctl visibility for current launch/readiness/storage state.
- Verify pkg output and boot a staged pkg world.

### Phase 1: remove dependency semantics

- Delete internal startup-edge and cycle-graph code.
- Reject dependency keys in all schemas and fixtures.
- Replace eager local factories with ordinary IPC demand activation.
- Add demand counts, coalescing, cancellation, deadlines, and recursion
  detection.

### Phase 2: complete IPC lifecycle

- Hold reservations before providers start.
- Queue requests across startup and release them only after real readiness.
- Implement idle notification and bounded idle shutdown.  Idle is
  provider-driven: serviced brokers a direct client->provider descriptor and
  cannot observe disconnects, so a provider declares idle intent through a
  client API (`service_idle_shutdown(ctx, seconds)`).  serviced arms a timer;
  new demand cancels it; on expiry the provider is gracefully stopped but its
  name reservations are kept, so the next lookup relaunches it on demand.
- Persist enable/disable state (done).  **Do NOT persist circuit-breaker
  state:** the in-memory breaker stops a crash-looping service at runtime, but
  carrying a tripped breaker across reboot would silently mask a real bug — a
  service that should be fixed would stay parked with no signal.  Operator
  enable/disable already covers deliberate parking.

### Phase 3: replace NetworkCmp proxying

- Add one system socket broker and the version-1 hello/resolve/connect/udp API.
- Return connected, rights-limited descriptors; remove inline send/receive and
  emulated socket handles.
- Make policy session-derived and immutable.
- Remove empty `descriptors.network {}` syntax.
- Retain explicit comments and protocol space for future userspace networking,
  but implement none of it now.

### Phase 4: manager-owned listeners

- Add strict `activation.socket` parsing.
- Have the network broker create listeners for serviced.
- Preserve listeners across provider restart and deliver them by logical name.
- Test backlog pressure, simultaneous demand, cancellation, descriptor
  exhaustion, address conflicts, and restart without connection loss.

### Phase 5: timers and path events

- Add monotonic timer demand, then calendar/persistent behavior.
- Add kqueue path hints with explicit coalescing and overflow semantics.
- Migrate one cron task and one watcher as reference bundles.

### Phase 6: user domains

- Add per-uid namespaces, storage roots, control authorization, quotas, and
  authorityd-enforced authority ceilings.
- Realise the lookup domains of §22 (System/User, optionally Session/Instance)
  and the ambient/narrowed lookup channel of §21, so a login session is handed a
  user-domain channel that its descendants inherit.
- Do not add a second manager process until isolation or scale demonstrates a
  need.
- Retire the `descriptors.network {}` manifest block (deferred from Phase 3): it
  is currently the NetworkCmp broker-session delivery trigger and is distinct
  from a `capabilities.network` kernel socket-authority gate.  Once §21/§22
  ambient-IPC lookup delivers the broker session, remove the descriptor block
  and switch delivery to the lookup channel.

## 17. Required tests and review gates

Every phase requires unit, integration, fault-injection, and clean-VM tests.
At minimum the suite must cover:

- hundreds of concurrent lookups coalescing to one process;
- client cancellation before, during, and after readiness;
- provider crash at every launch transition;
- activation recursion and longer A -> B -> C -> A chains;
- circuit breaker, reset, idle timeout, and demand arriving during stop;
- manager crash with pending IPC and held listeners;
- descriptor exhaustion and partial bootstrap rollback;
- malformed, duplicated, over-limit, and unauthorized trigger declarations;
- install interruption at every fsync/rename boundary;
- disabled and quarantined units never starting from any trigger;
- socket policy denial, DNS rebinding, address-family confusion, port bounds,
  fd-rights checks, peer death, and descriptor leak accounting;
- listener backlog, accepted connection survival, provider restart, and port
  conflict behavior;
- storage lease cleanup after process, manager, and machine crashes;
- the SCM_RIGHTS orphan-close kernel regression;
- package installation paths and modes in an empty staged root;
- a clean QEMU boot with the exact staged kernel, libraries, bundles, and
  managers followed by the complete Kyua suite.

No phase is complete with skipped root/kernel cases, ad-hoc ATF invocation in
place of Kyua, or a VM using libraries from a different source revision.

## 18. Non-goals before v1

- No hard or soft dependency language.
- No bundle rollback/version-selection UI.
- No central configuration database.
- No general container runtime.
- No userspace TCP/IP stack or virtual network topology.
- No arbitrary manifest-selected provider implementations.
- No compatibility parser for superseded manifests.
- No promise that registration means residency.

The resulting model is deliberately compact: bundles declare authority and
events; serviced holds namespaces and events; actual requests create demand;
providers check in and enter confinement; descriptors carry all useful
authority.

## 19. Process protection model

Self-protection through the mac_capability capprotect service is being reworked.
The original model let a process apply a shield to *itself* after it was already
running, keyed to the mac_capability **nonce** (inherited across fork, rotated on
exec).  Three problems follow from that shape:

1. **Unshielded window.** Protection can only be self-applied after `execve`, so
   the new image runs unprotected until it voluntarily shields itself.  There is
   no way to launch an image already protected the way `cap_enter` or a jail is
   entered atomically.
2. **Exec-identity coupling.** The shield is meaningful only relative to the
   nonce established by the exec, so it cannot be prepared before the code
   exists, and every protected program must cooperate.
3. **Fork inheritance forces descriptor gymnastics.** Because the whole nonce
   family shares the shield and a worker must self-shield after `pdfork`, the
   capprotect descriptor has to survive that fork.  That fights descriptor
   confinement (`CAP_CLOFORK_ONCE` latches to `LOCKED` after the launch fork and
   is dropped in the next fork), and was the direct cause of session workers
   losing their shield.

### 19.1 New model: launcher-applied, per-process, dropped on exit

- **Identity is the process, not the nonce.**  A shield is recorded against a
  specific process (`p_pid`, guarded against reuse by dropping the entry when the
  process exits) rather than against a nonce.
- **Protection is applied by a launcher to a target.**  A holder of the
  capprotect service descriptor applies flags to a target process identified by
  an **attached process descriptor** (`pdfork(2)` handle).  Holding the target's
  procdesc is the authority to protect it; no ambient privilege is required and
  the target need not cooperate.
- **Forks are born unprotected.**  Because the key is the process, a forked child
  is not a member of the shield table and inherits no protection.  Its launcher
  protects it explicitly (or does not).  This removes fork inheritance and, with
  it, the need for the capprotect descriptor to cross any fork.
- **Protection is dropped when the process exits.**  A process-exit event handler
  removes the shield entry before the PID can be reused, so a later process that
  happens to reuse the PID is never falsely protected.
- **The self case remains available.**  A process may still shield itself
  (`CP_OP_SHIELD` on its own PID) for programs that have no launcher, but it is
  now per-process and non-inheritable like every other entry.

### 19.2 Closing the startup window

The launcher protects the target while the target waits at its readiness
barrier, before the target performs any sensitive operation:

1. serviced/provider `pdfork`s the target; the target initialises and blocks on
   its sync barrier.
2. The launcher applies protection to the target's procdesc with the intended
   flags.
3. The launcher releases the barrier; the target enters capability mode and
   begins serving, already protected.

For component providers this means a factory protects each per-session **worker**
by the worker's procdesc using the factory's own capprotect descriptor.  The
descriptor never leaves the factory, so no clofork relaxation is required and the
`prepare_child_descriptor_forkable` interim in serviced is removed once the
rework lands.

### 19.3 Flags and authorisation

Protection flags (`CP_SF_*`) are unchanged in meaning: outward guards
(PTRACE/SIGNAL/VISIBLE/WAIT/SIGKILL/SIGCONT/SCHED/CORE/KTRACE) and self
restrictions (NOPRIVS/NOFORK/NOIPC/NOFDRECV/NOEXEC/NOSOCK).  Cross-process access
to a protected process (for lifecycle control) continues to use the mint/authorise
token path, re-keyed to the per-process identity; the launcher that applied a
shield may act on the target it protected.

### 19.4 Declaring protection in the manifest

A service declares the protection it wants applied at launch with a top-level
`protect` array in its unit manifest.  Each entry is a flag name; the group
aliases `protect` (all outward guards), `restrict` (all self restrictions), and
`all` (both) expand to their sets.  Unknown names are ignored with a warning so a
newer manifest degrades safely on an older parser.

```
protect = ["ptrace", "signal", "visible", "wait", "noprivs", "nofork"];
```

serviced installs the resulting `CP_SF_*` mask on the child **by its process
descriptor immediately after `pdfork(2)`**, before the child's program image
runs and while the descriptor is still transferable — so the protection is in
force from the moment the process exists, independent of anything the image
does.  A manifest with no `protect` stanza leaves the process to shield itself
(or not).  `servicectl verify` reports the parsed policy as `protect: 0x<mask>`.

The policy is per-service because it must be: a component **factory** that
`pdfork`s workers cannot itself carry `nofork`, while each worker it launches
can.  Because the launcher (serviced for services, the factory for its workers)
holds the target's procdesc, it applies exactly the policy the target should
have without the target needing its own capprotect descriptor.

## 20. Runtime container directories

Every launched process is given a private **runtime container directory**,
created at launch and destroyed when the instance stops.

- **Location.**  Containers live under the capability tree, in a serviced-owned
  subtree — `/Capabilities/Run/<unit-instance>/` — with directory permissions
  that deny access to any process other than serviced.  The path is never a
  usable capability by itself.
- **Access is by descriptor, not path.**  The launched program cannot open the
  container by pathname (it is confined and the directory is not world-reachable).
  Instead serviced opens the container directory and passes an **`O_DIRECTORY`
  descriptor** into the child as part of the bootstrap, alongside the other
  launch descriptors.  The program uses `*at(2)` calls relative to that directory
  descriptor for all private runtime files.  This keeps the container reachable
  only through delegated authority and consistent with capability mode.
- **Lifecycle.**  serviced creates the directory before fork with restrictive
  ownership/mode, hands the child the directory descriptor, and removes the
  subtree on instance stop and during crash reconciliation.  The directory is
  runtime state, not durable state; it is never a source of authority and is
  safe to delete and recreate.
- **Relationship to storage.**  This is distinct from provisioned storage leases
  and component scratch (which are minted TrustedZFS datasets delivered as
  descriptors).  The container directory is a lightweight, always-present private
  scratch area for the instance itself; storage resources remain the mechanism
  for larger or persistent data.

### 20.1 Default on-disk layout and installation

The capability tree and its subtree layout are **installed by default** as part
of the base system — created by the distribution `mtree` with correct ownership
and mode, so the directories exist on a fresh install before serviced first runs
and are verified by `mtree`/pkgbase.  serviced creates only per-instance leaves
at runtime; the fixed skeleton is shipped, not synthesised.

```
/Capabilities/               0755 root:wheel   capability tree root
  System/                    0755 root:wheel   system capability bundles (*.cap)
  State/                     0700 root:wheel   durable mutable state
    serviced/                0700 root:wheel   serviced registry/state (UCL)
  Run/                       0700 root:wheel   per-instance runtime containers
                                               (serviced-owned; instances are
                                               created and removed at runtime)
```

`Run/` is mode `0700 root:wheel` so no process other than serviced (running with
that authority) can traverse it; launched programs reach their own container
only through the directory descriptor serviced passes in.  Additional fixed
subtrees (for example a future `User/` domain root) are added to the shipped
`mtree` in the same way rather than being created ad hoc at runtime.

## 21. Ambient serviced channel (bootstrap lookup)

Every process reaches serviced through an inherited **lookup channel**, so
service discovery needs no socket and no filesystem path.  This is the same
shape as the Mach bootstrap port: one inherited "ask serviced" channel per
process, through which a lookup mints a fresh, per-connection capability channel
to the target service.  serviced-launched units already receive this channel in
their bootstrap descriptors; this section extends it to *all* processes,
including interactive sessions.

### 21.1 Inheritance

The lookup channel is an **ambient descriptor**: `CAP_CLOFORK_UNLOCKED` (survives
every fork), not close-on-exec (survives exec), and usable inside capability
mode.  A process therefore inherits it exactly the way it inherits standard I/O.

When a user reaches a terminal, the session-establishing program — `getty`/
`login`, `sshd`, or `su` — carries the lookup channel into the session leader,
and **that session and every descendant it forks or execs holds it**.  Any
program in the session can then look up and connect to services without opening
`/var/run/…`.  The chain of custody is authority-init (PID 1) → serviced → the
login path → the user's shell → its children.

### 21.2 Discovery is not authority

The lookup channel is a **discovery** capability only.  A lookup (`SVC_OP_LOOKUP`)
is still brokered by serviced's naming layer, which authorises the request and
mints a per-connection channel to the provider; the provider still decides who it
answers.  Universal reachability of the *broker* does not grant universal access
to *services*.

### 21.3 Narrowing per session

Like a replaceable bootstrap port, a session may be handed a **narrowed** lookup
channel that exposes only a subset of names (for example, a user session that can
see user-domain services but not system-only providers).  Narrowing composes with
the per-process protection model (§19) and the per-instance container (§20): a
session is defined by the lookup channel it can see, the protection applied to its
processes, and the container directory it is given.

### 21.4 Consequence

Providers stop binding private sockets under `/var/run`; discovery is uniform,
capability-typed, and identical for a boot daemon and a login shell.  The one
piece of new plumbing is teaching the login/session path to carry the ambient
channel; the broker, the lookup RPC, and the per-connection channel minting
already exist.

## 22. Lookup domains

A **domain** is a scoped view over the naming layer: it defines *which names a
lookup resolves*.  The narrowed lookup channel of §21.3 is a channel bound to a
domain.  This is the same shape as launchd's bootstrap domains (system, per-user,
per-login-session, per-process), and it is the concrete form of Phase 6's "user
domains" (§16).

A domain is not a new namespace database.  serviced already holds one naming
namespace and authorises each `SVC_OP_LOOKUP` per name; a domain adds a scope —
"this lookup channel resolves only names in set `S`, and activates only those" —
layered over the existing broker.  A lookup outside the channel's domain returns
`ENOENT` exactly as an unregistered name does.

### 22.1 Domain kinds

- **System domain** — the root scope: every system provider (`org.5bsd.*`).  This
  is the channel serviced and system daemons hold.  Broadest; only the trusted
  system tree runs here.
- **User domain** (per uid) — the scope a user's session is handed at login.  It
  resolves user-scoped services **plus an explicit allow-list of system names**
  (for example logging and notifications) and nothing else — privileged
  system-only providers (storage broker, module management, identity minting) are
  not visible.  This is the Phase 6 domain.
- **Session domain** (optional, per login/terminal) — a user with several
  terminals may receive per-session narrowing, so each session tree sees an
  independently scoped view (matching launchd's per-login-session domain).
- **Instance domain** (optional, per process/instance) — the tightest scope: a
  single service instance is given a channel exposing only the names it needs,
  like an XPC per-process domain.  This composes most directly with the per-PID
  protection of §19.

### 22.2 Selection and inheritance

The domain is selected where the session is established.  The login path
(`getty`/`login`, `sshd`, `su`) requests a **user-domain** lookup channel for the
authenticated uid from serviced and installs it as the session leader's ambient
channel (§21).  Because that channel is inherited across fork and exec, **every
descendant of the session shares the same domain** without any further action.
A privileged supervisor may hand a child a *narrower* domain than its own, never
a broader one; domains only reduce.

### 22.3 Composition

A running context is fully described by three delegated things, each of which
only ever narrows:

> **session = domain (which names it can look up, §22) + protection (what its
> processes may do and who may act on them, §19) + container (its private
> runtime directory, §20).**

System services run in the system domain, unprotected-by-default or
self-protected, with system containers; user sessions run in a user domain, with
the login-selected protection profile and a per-session container.  There is no
central policy database — the domain, protection, and container a process has are
exactly the ones delegated to it through descriptors.
