# BSDNotify

BSDNotify is the system-wide notification service, exposed as `system.Notify`
by `bsdnotify(8)` and consumed through `libnotify(3)`. It gives
capability-mode services bounded exact-topic publish/subscribe, retained
64-bit state, and monotonic timers. One broker routes sessions for the host,
but it is not a global broadcast API: every session is identified by its
unforgeable channel label (see
[The Authority Model](../security/authority-model.md)) and gets an independent, default-deny policy,
subscription set, queue, and timer namespace. The provider lives in
`usr.sbin/bsdnotify/`, the client library in `lib/libnotify/`, and the
operator tool in `usr.sbin/notifyctl/`.

## Using it

```c
notify_client_open(&client);
notify_subscribe(client, "service.ready");
notify_publish(client, "service.ready", payload, payload_len);
notify_state_set(client, "service.health", value);      /* retained 64-bit */
notify_state_get(client, "service.health", &state);
notify_state_clear(client, "service.health");           /* owner-only */
notify_timer_add(client, timer_id, interval_ms, flags);
notify_next(client, event, capacity, timeout_ms);
```

Limits: 128-byte dot-separated topics, 2048-byte opaque payloads, 64
subscriptions, a 256-event queue, and 64 timers per session; 4096 retained
state topics broker-wide. Retained state is **owner-scoped**: only the label
that set a state topic may clear it (`EACCES` otherwise), and when a label's
last session disconnects, its retained states are evicted — a client cannot
exhaust the global state table by setting topics and walking away.

## Delivery semantics

Events carry the authenticated publisher label (stamped from bootstrap data —
it can never be supplied in a request), a random per-start router epoch, a
router-wide sequence, and a monotonic timestamp. Queues are volatile and
fanout never blocks a publisher: if a subscriber's queue is full, its newest
event is dropped and its next read receives an explicit **GAP** event with the
loss count. If the provider connection dies, `notify_next()` reconnects,
restores subscriptions, and returns a **RESET** event for the new epoch rather
than pretending the stream was continuous; ambiguous operations are never
replayed. Clients inherited across `fork()` are invalid. Payloads are hints —
they must not contain secrets or the only copy of application state.

## Authorization and confinement

Policy ships inside the bundle — the daemon loads
`$CAPABILITY_UNIT_DIR/Config/bsdnotify.conf` (installed under
`/Capabilities/System/Notify.cap/Units/bsdnotify.unit/Config/`) — mapping
channel labels to exact publish/subscribe topic lists and a separate timer
grant. Undeclared clients and operations are denied; `*` grants one operation
class. The loader is fail-closed (ownership, mode, `O_NOFOLLOW`, size, and
strict-UCL checks) and completes before sandbox entry.

The router runs in capability mode with no ambient filesystem, socket, fork,
exec, or `SCM_RIGHTS` authority; consumer channels are non-transferable
(`CAP_XFER_ONCE`, see
[Capability Transfer](../security/mac-capability.md)). OpenBSM records
and a `bsdnotify` DTrace provider expose admission, publish, deliver, and
rejection decisions — metadata only, never payload bytes.

`notifyctl` validates policy files, publishes, reads/writes state, watches an
event stream, and reports statistics. The stack is exercised by test suites
beside their sources and the disposable harness in
`tools/test/capability-qemu/`.
