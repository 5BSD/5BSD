# system.Notify (BSDNotify)

## What it brokers

BSDNotify is the host-wide notification service: bounded exact-topic publish and subscribe, retained 64-bit state cells, and monotonic timers, delivered to capability-mode units that cannot open sockets or files of their own. It is exposed as two endpoints, or tiers, served by one broker. `system.Notify` is the open tier, resolvable by every session including a login shell; `system.Notify.System` is the gated tier, which switchboard resolves only for software carrying `system.notify.system` (everyone else gets `ENOENT` before the provider is reached). Which tier a session is on is decided by the endpoint it was accepted on, cross-checked against the name switchboard resolved, never by anything the client sends.

Every session is identified by its unforgeable channel label and gets its own policy, subscriptions, bounded queue and timer namespace. Events carry the authenticated publisher label, stamped by the router and impossible to supply in a request. Retained state is owner-scoped: only the label that set a value may clear it. Delivery is honest rather than pretend-reliable: fanout never blocks a publisher, a subscriber that falls behind loses its newest events and reads an explicit `NOTIFY_EVENT_GAP` with the loss count, and a broker restart surfaces as `NOTIFY_EVENT_RESET` under a new random router epoch. Payloads (at most `NOTIFY_MAX_PAYLOAD`, 2048 bytes) are hints, never secrets or the only copy of application state.

The provider admits each connection to one event-driven router worker (a `pdfork(2)` child) over an unnamed capability channel; nothing is allocated per client beyond its queue. The router cannot create sockets, fork, exec, receive ambient `SCM_RIGHTS` descriptors or use ambient filesystem authority. Client death closes the router endpoint at once, even during an infinite `NEXT` wait, and the session's subscriptions and timers go with it.

The two-name split is the worked example of gating dangerous operations behind an attribute-gated endpoint instead of growing a policy file; see [Software attributes](../plane/attributes.md).

## Unit

Source: `usr.sbin/BSDNotify/capbundle/bsdnotify.ucl` and `Bundle.ucl`.

| Field | Value |
|---|---|
| Wire names | `system.Notify` (open tier); `system.Notify.System` with `requires = ["system.notify.system"]` (gated tier). |
| Bundle | `/Capabilities/System/Notify.cap` (`bundle_id = "system.Notify"`) |
| Program | `/Capabilities/System/Notify.cap/Units/bsdnotify.unit/bin/BSDNotify` |
| Unit | `bsdnotify` |
| User | `capability` |
| Launch | born in capability mode; `activation { boot = true; ipc = [...] }` |
| Control | `system` |
| Visible | `["user"]` (a login session must reach the open tier) |
| Gates | none |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 1024; nproc = 64; core = 0`; `umask = "0077"` |
| Config | `Units/bsdnotify.unit/Config/bsdnotify.conf` |

## Wire operations

Both endpoints serve the FIDL protocol `Notify` in `lib/libnotify/notify.fidl`
(library `bsd.notify.v1`, installed as `/usr/share/fidl/notify.fidl`; see
[FIDL and Capability IPC](../develop/fidl.md)). A session calls
`GetProtocolInfo` first. `Hello` returns the feature bits (`PUBSUB`, `TIMERS`,
`BOUNDED_QUEUE`, `STATE`, `LOSS_REPORTING`, and `STATE_WATCH` when asked
for), the limits (`max_topic` 128, `max_payload` 2048, `max_subscriptions` 64,
`queue_depth` 256, `max_timers` 64, `max_states` 4096) and the `router_epoch`.
Any operation the tier's policy does not permit fails with `EACCES` and is
audited; any request while a long-poll `Next` or `StateWatch` is outstanding
fails with `EBUSY`. All errors are errno values; the historical opcodes
remain the DTrace probe arguments.

The router rebuilds each request as the historical record
(`notify_protocol.h`) and applies the same record rules, so a request before
negotiation, a topic outside the topic grammar, an unknown feature or flag
bit, a zero timer id or an interval outside 1 ms to 24 h ends the session as a
protocol violation (`malformed-message` audit), as do an unknown method, a
malformed frame, a pre-FIDL record and an attached descriptor (previously
audited separately as `descriptor-attachment`).

| Method (probe opcode) | Request | Reply | Errors |
|---|---|---|---|
| `Hello` (1) | requested features | limits | `EBUSY` |
| `Subscribe` (2) | topic | empty | `EACCES`; `EEXIST` already subscribed; `ENOSPC` at 64 |
| `Unsubscribe` (3) | topic | empty | `ENOENT` not subscribed |
| `Publish` (4) | topic, payload (≤ 2048 bytes) | empty (router processed, not durable delivery) | `EACCES`; `EOVERFLOW` sequence exhausted |
| `Next` (5) | `timeout_ms` (0 polls, `NOTIFY_TIMEOUT_INFINITE` waits) | one event | `EAGAIN` nothing queued in time; `EBUSY` |
| `TimerAdd` (6) | `timer_id`, `interval_ms`, `flags` | empty | `EACCES` timers off; `EEXIST` id in use; `ENOSPC` at 64 |
| `TimerCancel` (7) | `timer_id` | empty | `ENOENT` |
| `GetStats` (8) | empty | published, delivered, dropped, rejected, timer_events | |
| `StateSet` (9) | topic, state | `router_epoch`, `generation`, `state` | `EACCES` (publish policy); `ENOSPC` at 4096 states; `EOVERFLOW` |
| `StateGet` (10) | topic | `router_epoch`, `generation`, `state` | `EACCES` (subscribe policy); `ENOENT` |
| `StateClear` (11) | topic | empty | `ENOENT`; `EACCES` not the owner |
| `ListSubscriptions` (12) | `cursor` | up to 24 topics, `next_cursor`, `total` | |
| `ListTimers` (13) | `cursor` | up to 24 (id, interval, flags, `next_fire_ms`), `next_cursor`, `total` | |
| `StateWatch` (14) | topic, `timeout_ms` | `watch_epoch`, `generation`, `state`, `present` | `EACCES` (subscribe policy); `EAGAIN`; `EBUSY` |

`usr.sbin/BSDNotify/tests/evolution/notify_next.fidl` is the schema at `bsd:1`
plus a method at `bsd:2` for the pairing test. The main process still hands
sessions to the router over its own internal control channel; that private
record is not a provider protocol.

Event types are `PUBLISH`, `TIMER`, `STATE`, `GAP` and `RESET`; a `notify_event` carries epoch, sequence, timestamp, timer id, generation, state, lost count, then the publisher, topic and payload bytes.

## Client library

Header `<notify.h>` (installs `notify.h`, `notify_protocol.h`, `notify_server.h`); link with `-lnotify` (`SHLIB_MAJOR 1`, depends on libservice, pthread and the FIDL runtime). Manual: libnotify(3). The record structures in `notify_protocol.h` remain the API's event, state and statistics types; its `NTFC` framing and the `notify_server.h` validators describe the pre-FIDL wire format and are kept for compatibility.

| Group | Functions |
|---|---|
| Session | `notify_client_open` (open tier), `notify_client_open_system` (gated tier), `notify_client_adopt` (wrap an already-delivered fd), `notify_client_close` |
| Pub/sub | `notify_subscribe`, `notify_unsubscribe`, `notify_publish`, `notify_next` |
| State | `notify_state_set`, `notify_state_get`, `notify_state_clear` |
| Timers | `notify_timer_add` (flag `NOTIFY_TIMER_F_PERIODIC`), `notify_timer_cancel` |
| Introspection | `notify_stats`, `notify_list_subscriptions`, `notify_list_timers` |

A client is bound to one tier for life, across transparent reconnects. If the provider dies inside `notify_next()`, the library reconnects, restores subscriptions and returns one `NOTIFY_EVENT_RESET`; any other operation that sees peer death returns the transport error because its acceptance is unknown. `notify_list_*` walk every page and return the session's total, which may exceed `capacity` to signal truncation. An inherited client is invalid after `fork(2)`. Calls on one client are serialized; each is bounded by 30 seconds (long polls by their own timeout plus one second), shortened by an active `service_budget_begin()`, and a timeout cancels that call and keeps the session (a timed-out `notify_state_watch()` drops it, so no watch stays pending). A malformed reply or a lost provider drops the session; the next call reconnects.

```c
#include <notify.h>
#include <err.h>
#include <stdio.h>

void
watch_user_topic(void)
{
	struct notify_client *nc;
	unsigned char buf[sizeof(struct notify_event) + NOTIFY_MAX_PAYLOAD +
	    NOTIFY_MAX_PUBLISHER + NOTIFY_MAX_TOPIC];
	struct notify_event *ev = (struct notify_event *)buf;
	ssize_t n;

	if (notify_client_open(&nc) == -1)
		err(1, "system.Notify");
	if (notify_subscribe(nc, "user.example.ready") == -1)
		err(1, "subscribe");
	n = notify_next(nc, ev, sizeof(buf), 5000);
	if (n > 0)
		printf("type=%u seq=%llu from %.*s\n", ev->type,
		    (unsigned long long)ev->sequence,
		    ev->publisher_length, (const char *)ev->data);
	notify_client_close(nc);
}
```

## Command-line tool

notifyctl(8) uses libnotify for every live operation. It receives no implicit
administrative bypass from the invoking UNIX user. `-s` selects the gated tier
and fails with `ENOENT` unless the software has `system.notify.system` in its
attributes. No per-command elevation or login-principal policy is involved.

| Verb | Example | Output shape |
|---|---|---|
| `configtest [file]` | `notifyctl configtest /Capabilities/System/Notify.cap/Units/bsdnotify.unit/Config/bsdnotify.conf` | `<file>: valid (0 clients, default explicit, system_default explicit)` or the parser's error |
| `publish topic [payload]` | `notifyctl publish user.build.done ok` | exit 0 on router acceptance |
| `state-get topic` | `notifyctl -s state-get system.power.ac` | `epoch=... generation=... state=...` |
| `state-set topic value` | `notifyctl -s state-set system.power.ac 1` | exit status |
| `timer id interval-ms [count [timeout-ms]]` | `notifyctl -s timer 7 1000 3` | one `type=2 flags=0x00000000 epoch=... sequence=... ...` metadata line per event, payload bytes after it |
| `watch topic [timeout-ms]` | `notifyctl watch user.build.done 10000` | one event metadata line, then unsubscribes |
| `stats` | `notifyctl stats` | `published=N delivered=N dropped=N rejected=N timer_events=N` |

`configtest` uses the daemon's own strict parser; its default path `/etc/bsdnotify.conf` is not where the plane installs the file, so pass the bundle path.

## Policy

`/Capabilities/System/Notify.cap/Units/bsdnotify.unit/Config/bsdnotify.conf` is loaded before sandbox entry from the switchboard-delivered descriptor. It must be a regular file owned by root or the daemon's user, not group- or world-writable, opened without following symlinks, at most 64 KiB with no embedded NUL. It has three optional top-level blocks; any other key is a hard error and the daemon refuses to start. A missing block takes the compiled-in default, which the shipped file states explicitly.

| Block | Governs | Compiled default |
|---|---|---|
| `default` | every session on `system.Notify` | `subscribe = ["*"]; publish = ["user.*"]; timers = false` |
| `system_default` | a `system.Notify.System` session whose label has no `clients` entry | `publish = ["*"]; subscribe = ["*"]; timers = true` |
| `clients { "<label>" {...} }` | replaces `system_default` for that label on the gated tier only; never consulted on the open tier | empty |

Each block holds `publish` and `subscribe` topic lists and a `timers` boolean. A missing list or a missing `timers` denies, so an empty block denies everything. `subscribe` also governs state reads; `publish` also governs state writes and clears. Entries are an exact topic, a prefix pattern such as `user.*` (matches `user.x` and `user.x.y`, not `user` or `users.x`), or a bare `*`, which must be the only entry in its list. Patterns like `*.x`, `user.*.y` and `user*` are rejected.

```ucl
clients {
	"com.example/publisher" {
		publish = [ "system.shutdown.*" ];
		subscribe = [ "*" ];
		timers = true;
	}
}
```

A session holding `SERVICE_RIGHTS_ADMIN`, which switchboard mints only onto an ambient root login session, bypasses the tier policy on either tier (the authorization source is recorded as `admin`). Every policy refusal is an OpenBSM `AUE_BSDNOTIFY_POLICY` record, and a connection whose resolved endpoint disagrees with the listener it arrived on is refused with `EPROTO` and recorded as `admit-tier-mismatch-*`.

## Tests

| Where | Programs | What they prove |
|---|---|---|
| `usr.sbin/BSDNotify/tests` (package `bsdnotify-tests`, `/usr/tests/usr.sbin/BSDNotify`) | `session_test` (6), `dispatcher_test` (21 cases), `policy_test` (28), `broker_test` (12), `transport_test` (1), `bundle_test.sh` (9) | session_test runs the router's session code with the real libnotify client over capability channels: round trip with open-tier `EACCES` refusals, admin bypass and a timer, the exclusive long poll (`EBUSY`, `EAGAIN`), protocol violations ending only their session, and the `bsd:1`/`bsd:2` pairing both ways. dispatcher_test drives the router's record dispatch through an internal socket: HELLO/STATS/errors, pub/sub/state/next, timers and the pending long-poll, the open-tier default (`user.*` only), the gated default and `clients` narrowing, admin bypass on both tiers, admission-control tier validation and failure classes, timer id wrap, every opcode on the open tier, explicit empty lists denying, one label on both tiers at once, a user session label being nothing special, and a NULL policy failing closed. policy_test covers the parser; broker_test covers queues, gap accounting and state ownership; bundle_test.sh checks the manifest, shipped policy, tier, security, router lifecycle, observability and tier-mismatch audit contracts. |
| `lib/libnotify/tests` (`libnotify-tests`) | `notify_test` (8), `client_lifecycle_test` (13) | retained record rules and argument checks; against a scripted `bsd.notify.v1` provider over real channels: reconnect and RESET semantics, malformed and timed-out replies, tiers, list truncation reporting, post-fork invalidation |
| `usr.sbin/notifyctl/tests` | `notifyctl_test.sh` (10) | configtest on `valid.conf`/`invalid.conf`, argument and payload limits, `-s` tier option and its usage errors, operation failures, `--` handling |

Run with `kyua test -k /usr/tests/usr.sbin/BSDNotify/Kyuafile` on a booted plane ([Testing](../develop/testing.md)). The inventory counts 62 daemon cases. The `BSDNotify` DTrace provider exports `session-start`, `session-end`, `session-admit`, `tier-policy`, `subscribe`, `publish`, `deliver`, `timer`, `list` and `reject`; payload bytes are never probe arguments.

## Status and gaps

Status: shipped; capmode; user `capability`; `visible = ["user"]`; gated tier `requires = ["system.notify.system"]`; 14 operations; FIDL `bsd.notify.v1` since October 2026 (endpoints, tiers, policy and limits unchanged; the provider and libnotify ship together).

Known gaps and drift:

- notifyctl(8) `configtest` defaults to `/etc/bsdnotify.conf`, a path the plane does not install; the man page and tool predate the bundle Config layout.
- BSDNotify(8) names the file `Config/BSDNotify.conf`; the Makefile installs `bsdnotify.conf`. Use the lowercase name.
- Delivery is at-most-once with explicit loss reporting by design; there is no durable queue, replay or acknowledgement, and state cells (one `uint64_t` per topic) do not survive a broker restart or the owning label's last session.
- Subscriptions are exact-topic only; wildcards exist in policy lists, not in the subscribe op.
