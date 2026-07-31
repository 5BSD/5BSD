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
  application cannot select discovery policy.
- `libshmring` is independent of `libservice`; any typed library may combine
  them without reversing dependencies.
- `libcapbundle` validates declarations for serviced and servicectl.
- `libcapability` wraps only synchronous kernel capability-service ABIs. It has
  no serviced lifecycle, name lookup, userspace channel transport, daemon
  framework, allow-list policy, or payload dispatch.

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
byte and object totals and reject corrupt or over-quota stores.
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

The typed library maps all duplicates of one injected session to the same RPC
lock domain. Shared-memory rings use `libshmring`.

## Global base services

- `org.5bsd.log` is a global structured logging service. Every serviced
  connection is an independent provider session. Shared-memory ring wakeups
  are coalesced and draining is batched; flush remains explicit. Flush
  confirms provider drain and sink submission, not syslog disk durability.
- `org.5bsd.notify` is a global event service. The current safe default denies
  publish, subscribe, and timer authority until an identity-bound ACL is
  supplied. Every open has an independent channel and lock. Topics are not
  security boundaries by themselves. Publish replies confirm router
  processing, while bounded subscriber queues remain volatile, lossy under
  pressure, and non-replayable.
- `org.5bsd.trace` is a global tracing service. The safe default does not
  delegate a raw DTrace descriptor. A provider-owned constrained query and
  aggregation API is required for ordinary clients. Any future raw consumer
  path must remain an explicit administrator-only grant.

## Security invariants

- Component channels are non-transferable and locked against fork/exec
  propagation except for the one supervised exec performed by serviced.
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
  quotas, rollback at every allocation failure, restart reconstruction,
  relative and absolute path resolution, independent cwd contexts, root-clamped
  parent traversal, atomic failed `chdir`, handle duplication, concurrent
  clients, malformed frames, and coalition teardown;
- Network TCP and UDP over IPv4 and IPv6, DNS, nonblocking connect/accept,
  deadlines, cancellation, descriptor and socket-table exhaustion, concurrent
  sessions, malformed frames, and coalition teardown;
- Log ring wrap, batching, wakeup coalescing, high-water behavior, loss
  accounting, flush, fork, close/reopen, and sink failure;
- Notify default-deny and identity ACL tests before publish/subscribe is
  enabled;
- Trace proof that raw descriptor delegation is unavailable by default;
- DTrace probe argument tests, audit success/failure tests, pkgbase package
  contents, suffix builds, and upgrade/removal tests;
- root-only live tests for Capsicum, mac_capability propagation, coalition
  teardown, jails, auditd, DTrace, and real network sockets.

Root-only or live-environment tests that cannot run in an unprivileged object
tree must be recorded explicitly in the handoff rather than treated as
passing.  The current results and privileged rerun obligations are recorded in
`docs/capability-components-validation.md`.
