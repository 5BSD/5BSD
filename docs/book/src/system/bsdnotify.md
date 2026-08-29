# BSDNotify

BSDNotify is the system-wide notification component exposed as
`system.Notify` by `bsdnotify(8)`. It gives capability-mode services
bounded exact-topic publish/subscribe, retained 64-bit state, and monotonic
timers through `libnotify(3)`. It is system-wide in deployment—one broker
routes sessions for the host—but it is not an unrestricted global broadcast
API. Every session has an authenticated serviced label and an independent,
default-deny policy, subscription set, queue, request stream, and timer
namespace.

| Component | Location |
|-----------|----------|
| Provider, router, policy, and transport | `usr.sbin/bsdnotify/` |
| Client library and protocol | `lib/libnotify/` |
| Operator tool | `usr.sbin/notifyctl/` |
| Service bundle and policy | `usr.sbin/bsdnotify/capbundle/` |
| Tests | `usr.sbin/bsdnotify/tests/`, `lib/libnotify/tests/`, `usr.sbin/notifyctl/tests/` |

## Router and session model

The provider admits each authenticated component connection to one shared,
event-driven router worker over a private unnamed capability channel. The
router owns the topic index, retained state table, kqueue timers, and bounded
per-session queues. It does not fork or allocate a process or private ring for
each client. One client can have one outstanding long poll; a second concurrent
request receives `EBUSY`, while unrelated sessions continue to dispatch.
Client death closes its endpoint immediately and removes its subscriptions,
timers, and queued events without affecting other services.

The interface is `system.Notify` 2.0.0 with wire ABI 2. The public limits are
128-byte topics, 2048-byte opaque payloads, 64 subscriptions, a 256-event
default queue, 64 timers per session, and 4096 retained state topics. Topics
are validated dot-separated identifiers: empty segments, path syntax,
controls, and embedded NULs are rejected.

The client surface is:

```c
notify_client_open(&client);
notify_subscribe(client, "service.ready");
notify_publish(client, "service.ready", payload, payload_len);
notify_state_set(client, "service.health", value);
notify_state_get(client, "service.health", &state);
notify_timer_add(client, timer_id, interval_ms, flags);
notify_next(client, event, capacity, timeout_ms);
notify_stats(client, &stats);
```

State publications retain one 64-bit value and advance a broker generation.
One-shot and periodic timers are owner-scoped and use monotonic time. Finite
wait deadlines use saturating arithmetic; `NOTIFY_TIMEOUT_INFINITE` cannot
wrap into a short wait.

## Delivery semantics

Publication, state, and timer events carry the authenticated publisher label,
random router epoch, router-wide sequence, monotonic timestamp, topic, and
event-specific fields. GAP and RESET are synthetic control events carrying
loss or epoch discontinuity instead. Opaque payloads are hints whose schema
belongs in a typed topic library; they must not contain secrets or the only
copy of application state.

Queues are volatile and fanout never blocks a publisher. If one subscriber's
queue is full, the newest event for that subscriber is dropped and its
saturating loss counter advances. Its next read receives an explicit GAP event
with the loss count. A successful publish means the router evaluated the
request and attempted fanout, not that every subscriber durably received it.

Each router start chooses a nonzero random epoch. If a provider connection
dies, `notify_next()` reconnects, restores exact-topic subscriptions, and
returns a RESET event for the new epoch rather than pretending the stream was
continuous. Other operations report the transport failure because acceptance
is unknown and are never replayed; their next call opens a clean session.
Clients inherited across `fork()` are invalid and the child must open its own
session.

## Authorization and confinement

`/etc/bsdnotify.conf` maps immutable serviced client labels to exact publish
and subscribe topic lists and a separate timer grant. `*` can grant all topics
within one operation class; undeclared clients and undeclared operations are
denied. Publisher identity always comes from authenticated bootstrap data and
cannot be supplied in a publish request. Subscribers should still authorize
the publisher field when the topic's application policy depends on identity.

The policy loader opens the file with `O_NOFOLLOW`, accepts only a regular file
owned by root or the daemon's effective user, rejects group/world-writable
files, embedded NULs, unknown keys, duplicate grants, invalid labels/topics,
and files over 64 KiB, and completes parsing before sandbox entry.

Consumer channels and installed router endpoints are non-transferable and
locked against fork and exec. serviced gives the provider a
`CAP_XFER_ONCE` endpoint: the single admitted hop consumes it, so the router
sees a non-transferable session. The router enters capability mode with no ambient
filesystem, socket-creation, fork, exec, or SCM_RIGHTS authority. Provider and
router share their own coalition, separate from every consumer.

OpenBSM records and the `bsdnotify` SDT provider expose session admission,
subscribe, publish, deliver, timer, and rejection decisions. Probes include
bounded metadata such as labels, topics, lengths, operation, and result, never
payload bytes.

## Tooling and testing

`notifyctl` validates policy, publishes, reads and writes state, watches an
event stream, and reports service statistics:

```sh
notifyctl configtest /etc/bsdnotify.conf
notifyctl publish service.ready 'online'
notifyctl state-set service.health 1
notifyctl watch service.ready
notifyctl stats
```

Broker tests cover exact fanout, binary/max payloads, queue pressure and GAP
events, state generations and ceilings, subscription limits, timers, and
sequence saturation. Dispatcher and transport tests cover concurrent clients,
pending long polls, disconnect cleanup, timer identifier wrap/collision,
label bounds, truncated/oversized messages, and fd ownership. Policy tests
exercise strict UCL, ownership/mode/no-follow checks, default deny, wildcard
rules, duplicates, and all bounds. The client fake-service suite covers every
request, malformed replies and descriptor counts, multi-client concurrency,
fork rejection, disconnect/reconnect, subscription restoration, RESET
semantics, and non-replay of ambiguous operations. Bundle tests verify the
Capsicum, coalition, and linear-transfer confinement contract.

BSDNotify, `libnotify`, `notifyctl`, Crypto, EnvFD, flavors, and TrustedZFS
are also exercised together under a matching WITNESS/INVARIANTS kernel by the
disposable amd64 harness in `tools/test/capability-qemu/`.
