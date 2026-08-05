# Capability services and components

This is a clean-break design. There is no compatibility contract with the
earlier generic component resolver.

## The model

There are three mechanisms, and a typed library chooses exactly one.

1. A local component replaces ambient authority removed from a supervised
   process. The base system currently has only `filesystem` and `network`.
   serviced constructs the session before exec, enlists the provider worker in
   the consumer coalition, and injects a confined channel as `FILESYSTEMCMP`
   or `NETWORKCMP`. The variable contains a descriptor number, not a service
   name. Local components are not globally discoverable.
2. A global service provides functionality under one or more agreed
   reverse-domain names. Its bundle declares `provides`; its process calls
   `service_provider_expose()` once per name. Every name has a separate
   listener and accept queue. `service_connect()` launches the provider on
   demand and returns a fresh connection.
3. A capability is kernel authority delegated directly as a descriptor or
   activation token. It is neither a component nor a named service.

Applications use typed libraries. Typed libraries own service or interface
names, connection setup, locking, protocol validation, fork behavior, and
descriptor ownership. libservice alone maps stable local interfaces to
bootstrap environment entries.

## Layering contract

The dependency direction is fixed:

```text
Application
    |
    v
Typed service library
    |
    +----> libservice ----> libchannel
    |           |
    |           +----> libcapability (bootstrap/token/protection kernel ABI)
    |
    +----> libshmring        (only for bulk data)

serviced / servicectl ----> libcapbundle
kernel capability wrapper -> libcapability -> specialized kernel ABI
```

- `libchannel` transports bytes, ordered descriptors, reply tokens, sender
  metadata, backpressure, and peer death. It is asynchronous and
  kqueue-native. It has no names, typed headers, activation policy, blocking
  convenience calls, internal thread, or `MAC_CAPABILITY_CALL`.
- `libservice` owns serviced's private control protocol, global name
  resolution, listeners, local component descriptor discovery, per-name
  activation, and supervised lifecycle. Its managed-client helper is an
  optional blocking adapter over `libchannel`; it does not expose tokens.
  Raw inherited-bootstrap and local-component wire structures are private;
  component authors receive opaque objects, a typed membership enum, and
  attachment-slot accessors. Component bootstrap has no scope, sharing,
  required/optional, or arbitrary-options fields.
- A typed library owns magic/version/opcode/status, payload and attachment-slot
  schemas, and a fixed choice of local component or global service. The
  application cannot select discovery policy. Its ordinary `<name>.h` header
  exposes only the client API; wire construction and validation live in the
  separately installed `<name>_server.h` provider-author header. AuditCmp's
  pre-capability bootstrap/adoption helpers are provider-only for the same
  reason.
- `libshmring` is independent of `libservice`; any typed library may combine
  them without reversing dependencies. Opened mappings use `INHERIT_NONE`
  and process ownership checks, so a forked child cannot retain ring authority
  after close-on-fork descriptors disappear.
- `libcapbundle` validates declarations for serviced and servicectl.
- `libcapability` wraps only synchronous kernel capability-service ABIs.
  `libservice` uses that narrow layer to authenticate inherited bootstrap
  descriptors, activate kernel capability tokens, and apply capprotect. It is
  never used for userspace service messaging and has no serviced lifecycle,
  name lookup, userspace channel transport, daemon framework, allow-list
  policy, or payload dispatch.

A third-party provider may use `libservice` to expose and accept each declared
name, then use `libchannel` directly for its own typed protocol. This is the
intended extension point, not a compatibility escape hatch.

## Manifest contract

Public services:

```ucl
program = "indexd";
provides = [
    "org.example.index.query",
    "org.example.index.admin"
];
```

Local authority:

```ucl
components = ["filesystem", "network"];
```

There is no `implements`, `on_demand`, component provider selection, semantic
version selection, lifetime, sharing, optional component, component options,
or local-to-global fallback. Runtime identity is private and is derived from
the bundle identity and program; it is not the first `provides` name.

## libservice routing

`service_provider_expose(provider, name, &listener)` creates one opaque
listener and synchronously claims that exact manifest-reserved name with
serviced. Providers expose all declared names and may route each listener to a
different protocol, thread pool, kqueue, or process.

Initial check-in is staged. `service_provider_ready()` succeeds only after
every declared name has been claimed and only after the provider explicitly
calls `service_provider_enter_capability_mode()`. serviced verifies
capability-mode entry independently. The complete listener set therefore
exists before process readiness, while publication remains independently lazy
per name. No partially initialized sibling is made connectable merely because
another name activated.

serviced includes both the requested service name and authenticated client
identity in every NEW_CLIENT notification. libservice is the only reader of
the shared control channel. It demultiplexes notifications to the exact
listener, bounds each queue, closes unmatched or excess endpoints, and
provides a pollable readiness descriptor.

`service_connect(context, name, &fd)` always asks for a global service. It
never reads a component environment variable.

The bundle registry reserves every name in `provides` and maps it to the same
bundle/service record before the provider exists. A request for any name starts
that record. The starting-runtime check matches the complete `provides` set,
so simultaneous requests for different names cannot create duplicate
processes. The provider claims each listener with `NAME_CLAIM`; serviced
rejects READY until the complete set is present. Process readiness is reported
once, then serviced sends `ACTIVATE_NAME` only for requested names. Each name
has an independent activation callback and `NAME_RESULT`; success drains only
that name and failure leaves siblings available for later activation.
`NAME_WITHDRAW` removes a claim without disturbing existing direct sessions;
new lookups remain queued against the reservation until a replacement claim.
Restart resets every claim and activation state, so no endpoint state crosses
process incarnations.

`service_local_component_open(context, interface, version, &fd)` always
acquires a local component. It accepts only a stable interface identifier,
validates the kernel descriptor type, duplicates it close-on-exec, and
consumes the private deployment entry. It never consults serviced's global
registry.

`service_supervisor_fd(context)` is a pollable, process-local death indication
for the inherited serviced control connection, and
`service_supervisor_status(context)` returns its terminal error. Dispatcher
failure also wakes every listener and blocked accept. These signals describe
naming-supervisor availability; an already-established client/provider
channel is direct and has its own peer lifetime.

Direct channels are also the peer-crash indication: closing either endpoint
revokes the other; receive reports `ECONNRESET` and send reports `EPIPE` or
`ECONNRESET`. If a provider exits before publication,
serviced cancels the activation timers and immediately fails every pending
lookup for all names in that provider's `provides` set. Serviced does not proxy
the data plane. A successful send means kernel queue acceptance; typed protocol
replies acknowledge processing. Automatic retry is limited to operations the
typed protocol marks idempotent, and exactly-once effects across crashes require
durable provider-side request deduplication.

## Protocol contract

libchannel is the userspace transport layer over mac_capability channel
framing. Channels already provide atomic
messages, actual payload length, ordered descriptor attachments, a 64-bit
reply token, authenticated badge/credential metadata, bounded queues,
backpressure, and peer-death signaling. Neither libchannel nor libservice
layers a
byte-stream frame protocol, XPC-style object graph, or generic serialization
format over them.

`channel_send_request()`, `channel_send_reply()`, and
`channel_send_event()` expose those properties asynchronously. Requests use a
fresh nonzero token, replies echo it, and unsolicited events or explicitly
fire-and-forget messages use token zero.
Both halves of the private serviced control channel use libchannel. Serviced
retains the actual incoming request object while an on-demand lookup is
pending, then responds through that object; it never copies a reply token into
a second waiter protocol. Control replies and descriptor-bearing activation
events use bounded libchannel queues and kqueue write readiness, so `EAGAIN`
cannot silently lose a publication acknowledgement. The acknowledgement is
queued before any `NEW_CLIENT` event for that name, preserving provider-visible
activation order.
libservice's optional blocking adapter is the sole receiver for a managed client channel and
routes reordered replies by token, preventing concurrent callers from
consuming one another's replies. Token-zero events use a separate bounded
queue. Timed-out and unknown-token replies are discarded with their attached
descriptors, peer death wakes every waiter, and inherited clients fail closed
after fork. No second transport envelope is carried in the typed payload.

A typed service header contains meaning only: service protocol magic,
protocol version, opcode, application status, and explicitly declared
service-specific flags. Typed validators remain responsible for exact payload
shape, field policy, and opcode semantics. Payload length, request identity,
reply role, sender identity, and descriptor count come from channel metadata
and must not be duplicated in the typed header.

Descriptors are identified by zero-based attachment slot, not by sender fd
number. The receiver gets newly installed descriptor numbers in the original
attachment order. Each opcode specifies its exact or permitted attachment
count and, for every slot, the semantic role, required descriptor type, and
minimum rights. Variable descriptor collections may define a compact role
table in their typed payload; libservice does not impose a generic object
schema. Rights and extended transfer/exec/fork/capmode state survive transfer.
An undersized receive buffer returns `EMSGSIZE` without dequeuing. Failed
multi-descriptor installation closes partial installs.

Completion has three explicit levels:

1. a successful send means kernel queue acceptance;
2. a typed reply means provider processing to that protocol's documented
   boundary;
3. durable completion exists only for an explicit sync, flush, transaction, or
   durable acknowledgement operation.

Reply tokens correlate one live channel and do not provide crash-stable
idempotency. After an ambiguous disconnect, mutating operations are not
automatically retried. Exactly-once effects require durable operation IDs,
provider-side deduplication, and stable transaction state.

Pending naming requests and their retained channel messages are owned by exact
requester and provider incarnations: stable label, PID, and serviced launch
sequence, rather than a reusable label or PID alone. Serviced frees requester
work when that incarnation exits and only lets the matching provider
incarnation complete, fail, time out, or cancel its waiters. A replacement
process therefore cannot consume or destroy its predecessor's requests.
Failure to register a pending-request timer is immediately terminal.
Runtime-array compaction and reload explicitly rebind libchannel callbacks to
the moved runtime record.

## FileSystem component

The FileSystem component supplies three namespaces:

- scratch storage with UNIX-like temporary semantics;
- persistent per-service storage reconstructed across provider restart;
- read-only access to the consumer's verified `.cap` bundle.

Object and byte quotas are durable properties of the namespace, not merely
open-handle limits. Creation must reserve accounting before mutation or roll
back completely. Directories count as objects. Restart scans reconstruct both
byte and object totals and reject corrupt or over-quota stores. Writable files
must have exactly one link: reconstruction rejects hard links, and every
lookup or mutation path revalidates link count and the per-file size ceiling
so an injected alias cannot carry writes outside the delegated tree.
The initial interface uses provider-owned fixed limits (64 MiB total, 4096
objects, and 16 MiB per file); manifests cannot inject parser input or weaken
them. A future administrator policy source can narrow those limits without
changing the application-facing component declaration.

The typed library serializes the shared component channel and caches the
injected process session. Repeated opens return owned duplicates associated
with the same lock domain. Forked children cannot reuse the parent's authority.
Replies acknowledge provider processing. `filesystemcmp_sync()` is the
explicit stable-storage boundary: sync a regular file after writes and every
affected directory after create, unlink, or rename. Scratch sync is a no-op.

`libfilesystemcmp` also supplies an opaque, per-caller path context. Each
context starts at one delegated namespace root and maintains its own logical
current directory over opaque directory handles. Absolute paths start at that
delegated root, relative paths start at the context cwd, `.` is ignored, and
`..` clamps at the root. `chdir` is transactional and never changes the
provider process cwd. Independent contexts avoid process-global cwd races.
The provider's handle-duplication operation ensures that resolving `/`, `.`,
or an ancestor returns a caller-owned handle rather than leaking a context's
retained authority. Path contexts remain process-bound across `fork`.
`getcwd` reports the context's logical spelling; an ancestor rename performed
through another context can make that spelling stale, while retained handles
continue to provide correct relative-resolution authority.
Logical cwd changes are client-local and do not generate audit records;
provider-side resolution denials and namespace mutations remain audited, and
their underlying typed requests remain visible through DTrace.
The cwd is not the namespace root: `chdir` can only move within the fixed
delegation.  Programs set an initial logical cwd before resolving startup
configuration that contains relative paths.  If root narrowing is added
later, it will construct a new path context from an already-authorized
directory handle; it will never replace a context root from a host pathname
or widen the original delegation.

## Network component

The Network component supplies the normal kernel TCP/UDP stack through a
provider-owned socket table. netmap and userspace packet I/O are future bearer
work, not part of the current contract.
Its initial provider-owned policy enables IPv4, IPv6, DNS, and outbound
connects, denies bind/listen authority, and bounds result and socket tables.
Manifests cannot supply policy JSON or arbitrary component options.

All provider sockets are nonblocking. Connect and accept expose bounded
asynchronous state, deadlines, status, and cancellation rather than blocking
the provider RPC loop. Inline receive deadlines are implemented by the typed
library as bounded nonblocking requests, so a waiting client thread cannot
head-of-line block other session calls. DNS resolution is part of the
typed library/provider
protocol; applications do not discover a separate DNS component.
The base provider performs DNS on one worker thread per private session using
a distinct attenuated Casper channel. Socket RPC dispatch therefore remains
responsive while resolution is pending. One resolution may be active per
session; overlap returns `EBUSY`, and token matching safely discards late
replies after a caller timeout.

The typed library maps all duplicates of one injected session to the same RPC
lock domain. Version 1 uses bounded inline data only. A future bulk-data
protocol may compose `libshmring`, but it must be introduced as a negotiated,
fully implemented protocol version rather than a placeholder ABI.

## Global base services

- `org.5bsd.log` is a global structured logging service. Every serviced
  connection is an independent provider session. Shared-memory ring wakeups
  are coalesced and draining is batched; flush remains explicit. Flush
  confirms provider drain, submission of the redacted syslog copy, draining
  of the bounded worker-to-storage ring, and synchronization of the private
  LogCmp store. It does not claim durability for syslogd's separate copy.
  Retained queries are cursor-driven, contain only privacy-redacted records,
  and are restricted to the immutable serviced identity on that session.
  Searches are sliced by record, byte, and segment budgets so a no-match scan
  cannot monopolize the storage event loop; the typed client hides internal
  continuations under one total deadline. Private fields use a fixed marker.
  Private-hash fields use a keyed 128-bit digest with a random, non-persisted
  storage-manager epoch key, permitting within-epoch correlation without
  stable cross-restart identifiers or a store-resident dictionary oracle.
  Logging policy includes a per-session burst limiter, an
  administrator-selected minimum ingested severity, and explicit filtered
  and rate-limited counters.  A producer session that exceeds its budget must not
  monopolize storage or terminate unrelated sessions; sequence accounting must
  continue across deliberate drops.  These controls follow the useful parts of
  modern journal designs while retaining LogCmp's identity-scoped store and
  typed privacy model.  Live following and richer subsystem/category/time
  predicates belong in the query protocol, not in libservice or libchannel.
  An eventual all-system administrative reader must be a separately declared
  service with explicit identity policy, never a request flag.
- `org.5bsd.notify` is a global event service. The current safe default denies
  publish, subscribe, and timer authority until an identity-bound ACL is
  supplied. Every open has an independent channel and lock. Topics are not
  security boundaries by themselves. Publish replies confirm router
  processing, while bounded subscriber queues remain volatile, lossy under
  pressure, and non-replayable. A relay keeps at most one private-router
  operation outstanding but continues dispatching its public channel, so
  concurrent calls receive `EBUSY` and client death tears down an infinite
  event wait without retaining the router session. Finite client waits use
  saturating grace deadlines and cannot wrap near `UINT32_MAX`.
- `org.5bsd.trace` is a global tracing service. Raw descriptor delegation is
  available only to explicit serviced-authenticated labels in
  `/etc/traced.allow`; wildcard grants are invalid. The delivered descriptor
  has the complete libdtrace ioctl allowlist plus one-time transfer and locked
  fork/exec propagation. It remains administrator-only because those limits
  cannot constrain D programs, probe targets, actions, or buffer allocation.
  A provider-owned constrained query and aggregation API is still required
  for ordinary clients.
  The friendly `tracecmp_dtrace_open()` constructor applies RAM- and
  CPU-aware defaults: per-CPU principal and aggregation buffers are bounded
  between the kernel-safe computed value and 32 MiB, dynamic variables are
  bounded at 64 MiB, buffer resize remains automatic, and switching occurs
  every 250 ms. Callers may override these libdtrace options before enabling
  probes. The raw descriptor API intentionally applies no policy.
- `org.5bsd.audit` is a global structured-audit service. It accepts only the
  typed record schema implemented by `libauditcmp`, authenticates the serviced
  client label, applies label policy and rate limits before submission, and
  emits records through OpenBSM. It does not delegate the audit descriptor or
  arbitrary BSM construction authority to clients.

## Security invariants

- Packrat, Roadrunner, Ledger, and Beacon run as the pkgbase
  `capability` account. Their parents open only their predeclared resources,
  apply external-process protection plus `NOPRIVS`, then enter capability
  mode. Packrat workers reject incoming descriptor transfer. Beacon's fixed
  router rejects ambient `SCM_RIGHTS` receipt. Its only admission path is a
  pre-created unnamed capability channel from the provider. Serviced gives a
  provider endpoint a two-hop linear transfer budget; receipt by the provider
  leaves one hop, and admission to the router consumes it so the installed
  endpoint is non-transferable. Descriptor-bearing client protocol requests
  are rejected and closed. Roadrunner and Ledger retain descriptor receipt
  only for their typed attachment phases.
- Sentinel, Bloodhound, Armory, and Sundown run as root deliberately. DTrace device
  access, traditional kernel-module/reboot privilege checks, and custom BSM
  audit submission still require root even after the MAC system gate
  authorizes the nonce. Their parents enter capability mode and their
  per-client workers prohibit fork, IPC, incoming descriptor transfer, exec,
  and new sockets. Root removal requires a separately reviewed kernel
  privilege-grant design; `SERVICE_PROTECT_NOPRIVS` must not be set while
  these providers depend on traditional privilege checks.
- Component channels are non-transferable and locked against fork/exec
  propagation except for the one supervised exec performed by serviced.
- Shared-memory endpoint mappings are explicitly non-inheritable; descriptor
  propagation controls alone are not treated as revocation of an existing
  mapping.
- Provider workers enter capability mode, shed inherited libservice authority,
  and join the consumer coalition before the consumer starts.
- Global providers remain in their own coalitions.
- A provider may expose only exact names in its `provides` declaration.
- Reserved component-factory names cannot be connected to by applications.
- DTrace probes and BSM audit records cover registration, routing, component
  construction, policy denial, quota failure, and session teardown.
- Unknown manifest and protocol fields fail closed.

## Required verification

The release gate includes:

- manifest schema positive and negative cases, duplicate component rejection,
  and removal of all obsolete keys;
- multi-name routing, wrong-listener isolation, concurrent connects, reply
  reordering, listener close while accept is blocked, close/reopen, fork, queue
  overflow, and provider death;
- FileSystem namespace, read-only bundle, persistence, durable object and byte
  quotas, hard-link confinement, per-file restart bounds, rollback at every
  allocation failure, restart reconstruction,
  relative and absolute path resolution, independent cwd contexts, root-clamped
  parent traversal, atomic failed `chdir`, handle duplication, concurrent
  clients, malformed frames, and coalition teardown;
- Network TCP and UDP over IPv4 and IPv6, DNS, nonblocking connect/accept,
  deadlines, cancellation, descriptor and socket-table exhaustion, concurrent
  sessions, malformed frames, and coalition teardown;
- Log ring wrap, batching, wakeup coalescing, high-water behavior, loss
  accounting, flush, fork, close/reopen, sink failure, keyed privacy
  expansion boundaries, bounded retained scans, and peer-death recovery
  without ambiguous replay;
- Notify default-deny and identity ACL tests before publish/subscribe is
  enabled, plus independent clients, concurrent calls, close/reopen, fork,
  malformed replies, subscription restoration, peer death during every
  operation family, loss/reset events, timers, state, and payload limits;
- Trace default-deny policy, explicit-label delegation, ioctl, one-time
  transfer, fork/exec, duplicate-open, and unavailable-device tests;
- DTrace probe argument tests, build-time DOF presence/absence checks for both
  `MK_DTRACE=yes` and `MK_DTRACE=no`, live probe-firing tests, audit
  success/failure tests, pkgbase package
  contents, PIE links against fresh typed static archives, suffix builds, and
  upgrade/removal tests;
- each typed client library must independently cover discovery, session
  ownership, concurrent opens and calls, timeouts, malformed and reordered
  replies, unexpected descriptors, peer death, close/reopen, and fork; each
  configurable global service must ship a strict config-test/diagnostic tool
  with argument, parser, unavailable-service, success, and operation-failure
  tests. Local FileSystem and Network policy remains cap-bundle configuration
  validated by servicectl rather than a second daemon configuration format;
- root-only live tests for Capsicum, mac_capability propagation, coalition
  teardown, jails, auditd, DTrace, and real network sockets.

Root-only or live-environment tests that cannot run in an unprivileged object
tree must be recorded explicitly in the handoff rather than treated as
passing.  The current results and privileged rerun obligations are recorded in
`docs/capability-components-validation.md`.

## Operational provider names

Provider process names are an operator-facing identity, not a protocol or API.
The provider executables, cap bundles, packages, manuals, DTrace providers,
and operator-visible paths use one western/animal naming set.  No compatibility
binaries or aliases are installed:

| Interface or subsystem | Executable | Role mnemonic |
|---|---|---|
| boot authority | `oracled` | top-level boot and policy supervisor |
| service manager | `serviced` | service reservation, activation, and lifecycle |
| FileSystemCmp | `localfilesystem` | private durable and scratch object store |
| NetworkCmp | `localnetwork` | local network authority and socket operations |
| logging | `logd` | structured persistent system record |
| notifications | `bsdnotify` | global state and event notification |
| tracing | `traced` | privileged tracing and diagnosis |
| auditing | `auditbrokerd` | security audit policy and submission |
| reboot coordination | `rebootd` | coordinated shutdown and reboot |
| kernel modules | `kldmgrd` | controlled kernel-module inventory |

The two local component executables retain the mandatory `cmp` suffix; global
providers retain daemon names.  Typed library names, C symbols, manifest
component selectors, and reverse-DNS interface identifiers remain functional
and descriptive.  The completed rename covers executable and manual names, source
directories, cap-bundle program entries and paths, pkgbase package metadata,
DTrace provider names where they identify the process, test fixtures, control
tool diagnostics, and operator documentation.  Repository-wide old-name scans
and package content tests enforce the boundary.
