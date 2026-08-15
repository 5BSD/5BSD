# bhyve non-DAX VirtIO filesystem design

Status: rootless-tested modern PCI composition and transactional idle or
active-object backend state transfer; live Linux qualification remains
pending.

## References and scope

The normative contract is VirtIO 1.4 CS01 section 5.11 and the FUSE protocol
referenced by that section.  The pinned Linux `fs/fuse/virtio_fs.c` is the
guest-driver behavior reference.  Pinned QEMU `hw/virtio/vhost-user-fs.c` and
its vhost-user core are device/backend architecture references only; GPL code
is not copied.

The default release configuration is modern PCI and non-DAX.  It exposes one
high-priority queue and one or more request queues, but no shared-memory
region.  The explicit `notifications=true` configuration additionally offers
`VIRTIO_FS_F_NOTIFICATION`, queue 1, and the feature-gated 44-byte device
configuration only after the authenticated backend has negotiated the matching
VFSB notification capability.  DAX remains a separate Linux/FUSE extension
dependent on shared-memory mapping and coherency work.

## Isolation boundary

Filesystem pathname, credential, inode, file-handle, and cache state belongs
in a separately sandboxed backend process.  bhyve owns the VirtIO transport,
validates descriptor direction and bounded aggregate lengths, and mediates
requests to that backend.  The backend must never receive a bhyve pointer,
guest physical address, queue structure, or unrestricted descriptor for the
VM process.

The first backend contract is message-mediated rather than direct guest-memory
mapping.  This costs copies, but keeps the trust boundary enforceable and
makes queue reset, disconnect recovery, resource limits, and checkpoint
ownership explicit.  A future vhost-user fast path must be a separate mode
with an equally explicit guest-memory and migration security contract; it
must not silently replace the mediated path.

## Session boundary already implemented

`virtio_fs_host.c` is the common, device-independent FUSE transport validator.
It currently:

- detects little- or big-endian FUSE sessions from every `FUSE_INIT`;
- permits a later `FUSE_INIT` to terminate the old session and change byte
  order;
- requires exact, bounded input lengths and nonzero request identifiers;
- enforces that `FUSE_INTERRUPT`, `FUSE_FORGET`, and `FUSE_BATCH_FORGET`
  appear only on the high-priority queue and normal requests do not;
- validates the exact fixed bodies of `FUSE_INTERRUPT` and `FUSE_FORGET`, and
  the count-derived array length of `FUSE_BATCH_FORGET`, before forwarding;
- prevents any non-INIT request before successful initialization;
- does not forward reply-bearing requests unless the guest supplied space for
  the common output header;
- validates output length, signed error convention, and request identifier;
- handles the no-reply FORGET operations; and
- splits request acceptance from asynchronous response validation, carries an
  incarnation token between them, terminates the old session immediately on
  an accepted replacement INIT, and rejects stale completions; and
- marks the new session initialized only after a structurally valid
  successful INIT result.

Independent ATF and sanitizer tests cover both byte orders, replacement INIT,
queue-class separation, no-reply requests, malformed lengths and identifiers,
truncated or versionless INIT bodies, short output buffers, backend
disconnect, invalid output, replacement INIT
ordering, stale asynchronous completion, and generation overflow.

The validator is now used by the modern-only `virtio-fs` PCI device.  The
device exposes one high-priority queue plus 1 through 64 request queues,
retains guest-chain ownership across asynchronous backend I/O, and uses the
same validator for split and packed rings.

## Versioned backend protocol foundation

`virtio_fs_backend.c` defines the transport-independent `VFSB` protocol codec
and lifecycle state machine used over the authenticated local backend socket.
Every 40-byte header uses explicit little-endian fixed-width fields:
magic, protocol version, message type, header size, flags, payload length,
request identifier, backend incarnation, signed status, and a zero reserved
field.  Variable message data is bounded to 16 MiB.
Successful `HELLO_REPLY` records carry the negotiated 20-byte selection;
failed replies carry no payload.  A negative `RESPONSE` status likewise
carries no FUSE bytes because it reports a backend-transport failure rather
than a FUSE operation result.  The dispatcher converts that condition to the
portable FUSE `EIO` value before completing the guest request.

The 20-byte `HELLO` payload negotiates one protocol version, cancellation and
freeze capabilities, maximum message size, maximum in-flight requests, and a
maximum aggregate pending-byte budget.  The selected values must be nonzero
subsets of the caller's offer, and the aggregate budget must hold at least one
maximum-sized message.  The lifecycle permits only:

```
disconnected -> negotiating -> active
active -> quiescing -> quiesced -> thawing -> active
active|quiesced -> shutting-down -> closed
```

A failed quiesce, thaw, or shutdown returns to its exact prior stable state.
Disconnect invalidates the pending control operation and advances a
saturating incarnation so stale replies cannot be accepted after reconnect.
Once the counter reaches its terminal value, reconnect fails rather than
reusing a generation.
The owner must serialize state-machine calls with its connection lock.

Independent tests use literal `VFSB` document values and cover byte layout,
reserved fields, invalid flags/status/type/length combinations, limit and
feature negotiation, reconnect incarnation, failed control operations, and
shutdown from both active and quiesced states.

The Unix-domain transport layer now requires a connected local
`SOCK_SEQPACKET` endpoint, verifies its effective peer UID/GID, sends and
receives exactly one bounded `VFSB` frame per record with nonblocking
`sendmsg`/`recvmsg`, rejects truncation, and rejects and closes passed file
descriptors.  The owning event loop handles `EAGAIN`; no worker hides a sleep
or polling interval.  The codec alone does not establish peer identity, so
authentication remains mandatory before sending `HELLO`.
Connection setup accepts only an absolute, bounded pathname and creates a
nonblocking close-on-exec socket.  Immediate and in-progress connections use
the same `SO_ERROR` and peer-credential completion check, so a future event
loop does not need a polling fallback or a less strict asynchronous path.
The backend-client owner now drives that connection and `HELLO` exchange as a
serialized readiness state machine.  It reports only the read or write event
currently required, treats `EAGAIN` as retained ownership, closes and records
every terminal connection or protocol error, and transfers the descriptor
only after a bounded selection has made the session active.  It has no sleep,
timer, polling interval, native pointer on the wire, or Intel-specific state.
`virtio_fs_connection.c` composes that handshake with the retained queue
engine.  Once negotiation succeeds it allocates exactly the negotiated receive
bound, exposes socket readiness to the owner, flushes at most one priority-
ordered record per writable callback, consumes one response per readable
callback, and turns a terminal framing or ownership error into an atomic
pending-chain failure.  This keeps fairness in the caller's event loop and
prevents an internal drain loop from monopolizing bhyve.  Both configured-path
connection and already-connected descriptor adoption use the same
authentication and handshake path; failed adoption leaves descriptor
ownership with the caller, while every owned descriptor is close-on-exec.
All non-DAX filesystem foundation objects and the modern PCI composition are
compiled into bhyve with its normal warning policy.  The configured backend
must negotiate cancellation; otherwise activation fails closed.  This makes
the advertised `VIRTIO_F_RING_RESET` contract unconditional.  A queue reset
removes unsent ownership atomically and cancels sent requests one at a time.
Backend failure during cancellation discards every owner from each resetting
queue and reports exactly one failed reset completion per queue, so no queue
can remain permanently resetting.

The pending-request layer allocates a fixed-capacity hash table at negotiated
startup.  It rejects duplicate identifiers and saturation, fences completion
and cancellation by backend incarnation, records cancellation idempotently,
and can atomically drain all ownership on disconnect into caller-provided
storage.  Both request count and aggregate pending bytes are enforced, so the
product of individually valid limits cannot pin unbounded memory.  Its
internal mutex permits request and high-priority workers to operate
concurrently.  The owner must stop those workers before destroying the table.
Each entry may carry an opaque runtime owner cookie for locating the retained
VirtIO chain.  The cookie is never placed in `VFS1`; checkpoint still requires
the table to be empty, so native addresses cannot enter portable state.

`virtio_fs_dispatch.c` composes session validation and pending ownership into
the queue/backend boundary.  Submission assigns a monotonic backend request
identifier and reserves ownership before publishing any FUSE session change.
A replacement `FUSE_INIT` is deferred while requests from the old
incarnation remain outstanding, preventing stale completions and ownership
leaks.  Backend replies are structurally validated before ownership is
retired, malformed replies and short guest buffers remain recoverable, and
backend transport failures become a fixed FUSE `EIO` value rather than
leaking host errno numbering into the guest ABI.  No-reply requests have an
explicit send-completion path.  If the backend negotiated cancellation, a
pending request can be marked and retried through an idempotent
`CANCEL`/`CANCEL_REPLY` exchange; a successful cancellation retires the guest
chain with FUSE `EIO`, while a failed cancellation preserves ownership.
Late duplicate cancellation replies are harmless because request identifiers
are never reused within the backend incarnation.  Pause stops new submissions
without polling; disconnect atomically drains caller-visible ownership and
fences the FUSE session.

`virtio_fs_chain.c` is the layout-neutral split/packed queue boundary.  It
requires the device-readable descriptors to precede all device-writable
descriptors, rejects missing request data, null guest mappings, count
mismatches, and length overflow, and bounds each direction before gathering
or scattering bytes.  Fragmented request and response chains therefore use
the same checked path regardless of ring format.

`virtio_fs_outbox.c` provides the event-loop-facing send boundary.  It owns
copied frames in bounded FIFO lanes, always drains hiprio before normal
traffic, and reserves enough aggregate byte capacity for one maximum-sized
hiprio request even when normal traffic is saturated.  A nonblocking send
failure leaves the frame owned and retryable; successful removal returns the
header so no-reply ownership can be retired only after the record was
actually accepted by the socket.

`virtio_fs_queue.c` composes the chain validator, transactional dispatcher,
and priority outbox into retained guest-chain ownership.  It copies descriptor
metadata and request bytes before returning from notification, keeps the
guest completion cookie only in runtime memory, scatters validated responses
before invoking the completion callback, and discards retained ownership
without publishing stale used entries during reset.  Outbox publication is
part of the dispatch transaction: allocation or saturation failure removes
the pending entry and does not publish a candidate `FUSE_INIT` session.
Backend failure atomically fences new submission, drains both outbox lanes,
and completes every reply-bearing chain with a byte-order-correct FUSE `EIO`;
no-reply chains retire with zero used bytes.  Completion callbacks run after
the queue lock is released and must not destroy the queue from inside the
callback.
Each retained request and queued backend frame now carries an immutable
32-bit VirtIO queue identifier.  Reset can atomically discard one queue's
pending ownership and unsent frames while preserving the FUSE session and
requests belonging to other queues.  A request already accepted by the
backend is deliberately not forgotten: selective reset returns
`EINPROGRESS`, cancels sent requests one at a time, and reports asynchronous
completion to the transport only after the last cancelled owner and any
unsent owner from that queue have been discarded.  The bounded tombstone
window accepts a late response or duplicate cancellation acknowledgement
without touching a new queue incarnation.  This prevents a late valid
response from being misclassified as a connection-wide protocol violation
or publishing into a reset used ring.

The portable `VFS1` state codec accepts state only after a freeze-capable
backend is exactly quiesced, no control operation is pending, and the
outstanding-request table is empty.  Its fixed little-endian header records
the immutable tag and request-queue count, negotiated VirtIO features, FUSE
session byte order and incarnation, backend protocol version/incarnation,
backend features and negotiated limits, backend identity, and a bounded
opaque state blob produced by that backend.  Restore validates the current
tag, queue topology, identity, all lengths, reserved fields, saved VirtIO
features against destination availability, and an exact quiesced destination
backend capability/limit contract before publishing decoded state.  The
opaque bytes alias the input buffer and never contain a bhyve-owned pointer or
descriptor.

## Checkpoint boundary and remaining implementation sequence

The PCI device now wires the `VFS1` codec to authenticated backend
quiesce/export/import/thaw operations.  Active FUSE inode and file-handle state
is reconstructed rather than guessed.  Idle and active sessions both use the
sole current bounded version-2 envelope; obsolete version-1 records are
rejected.  A daemon with live objects includes separate `EXPT` node and `HNDL`
handle tables.  Those tables preserve the exact opaque guest node and handle
identifiers, lookup counts, type, regular-file size, and a relative path
beneath the pre-opened export.  They never serialize a pointer, descriptor,
lock, native structure, host byte order, host page size, or Intel-specific
state.

Restore validates every header, reserved field, aggregate length, slot and
generation, relative path, type, and regular-file size, then reopens all
objects beneath the destination export before publishing either table.  A
handle owner must be a syntactically valid historical FUSE node ID; the root
handle is bound only to node 1, and a handle whose node remains in the
restored lookup table must name that node's exact path and type.  A
handle retains its own relative identity, so Linux's open-handle-after-FORGET
behavior survives checkpoint even when its node lookup no longer exists.
Failed preparation leaves the live source tables unchanged; repeated restore
replaces rather than accumulates state.  The outer checkpoint generation
checksum protects the opaque backend bytes against accidental mutation, while
the stable configured backend identity and export-root identity remain the
external-resource compatibility contract.  File contents are intentionally
not copied into device state: the administrator must provide the same shared
or separately replicated read-only export at the destination.

`DESTROY` reclaims every non-root node and handle, including lookup references
for which the guest sent no `FORGET`.

1. Extend the existing DTrace request, completion, backend-lifecycle, and
   queue-reset probes with cancellation and quiesce phase detail plus
   rate-limited diagnostics.  Per-request latency and bounded pending/outgoing
   pressure are now observable without adding hot-path polling.
2. Run the scheduled unmodified Linux mount/read/metadata/reset, active split
   and packed checkpoint, repeated-restore, backend-fault, and soak lanes.
   Add a 5BSD lane only when an unmodified guest driver exists.

## Portability and Intel host

The active development host is Intel amd64.  No filesystem wire field,
backend frame, queue state, or snapshot record may use VMX state, a native
pointer, native `long`, host byte order, or host page size.  Intel-specific CPU
save-state remains behind the later nested-VMX architecture interface and is
not part of the filesystem design.
