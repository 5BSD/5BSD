# system.Notify (BSDNotify)

## What it brokers

BSDNotify is the host-wide notification service: bounded exact-topic publish and subscribe, retained 64-bit state cells, and monotonic timers, delivered to capability-mode units that cannot open sockets or files of their own. It is exposed as two endpoints, or tiers, served by one broker. `system.Notify` is the open tier, resolvable by every session including a login shell; `system.Notify.System` is the gated tier, which switchboard resolves only for callers anointed with `system.notify.system` (everyone else gets `ENOENT` before the provider is reached). Which tier a session is on is decided by the endpoint it was accepted on, cross-checked against the name switchboard resolved, never by anything the client sends.

Every session is identified by its unforgeable channel label and gets its own policy, subscriptions, bounded queue and timer namespace. Events carry the authenticated publisher label, stamped by the router and impossible to supply in a request. Retained state is owner-scoped: only the label that set a value may clear it. Delivery is honest rather than pretend-reliable: fanout never blocks a publisher, a subscriber that falls behind loses its newest events and reads an explicit `NOTIFY_EVENT_GAP` with the loss count, and a broker restart surfaces as `NOTIFY_EVENT_RESET` under a new random router epoch. Payloads (at most `NOTIFY_MAX_PAYLOAD`, 2048 bytes) are hints, never secrets or the only copy of application state.

The provider admits each connection to one event-driven router worker (a `pdfork(2)` child) over an unnamed capability channel; nothing is allocated per client beyond its queue. The router cannot create sockets, fork, exec, receive ambient `SCM_RIGHTS` descriptors or use ambient filesystem authority. Client death closes the router endpoint at once, even during an infinite `NEXT` wait, and the session's subscriptions and timers go with it.

The two-name split is the worked example of gating dangerous operations behind an anointed endpoint instead of growing a policy file; see [Anointments and Principal Policy](../plane/anointments.md).

## Unit

Source: `usr.sbin/BSDNotify/capbundle/bsdnotify.ucl` and `Bundle.ucl`.

| Field | Value |
|---|---|
| Wire names | `system.Notify` (open tier); `system.Notify.System` with `requires = ["system.notify.system"]` (gated tier). Interface version `2.0.0`, ABI 2 |
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

Defined in `lib/libnotify/notify_protocol.h`. Header `struct notify_msg` (magic `NTFC`, `version`, `opcode`, `flags`, `status`). HELLO returns `notify_hello_reply` with the ABI version, feature bits (`PUBSUB`, `TIMERS`, `BOUNDED_QUEUE`, `STATE`, `LOSS_REPORTING`), the limits (`max_topic` 128, `max_payload` 2048, `max_subscriptions` 64, `queue_depth` 256, `max_timers` 64, `max_states` 4096) and the `router_epoch`. Any operation the tier's policy does not permit fails with `EACCES` and is audited; a second request while a long-poll `NEXT` is outstanding fails with `EBUSY`; a malformed message is `EPROTO`.

| Op | Request | Reply | Errors |
|---|---|---|---|
| `HELLO` (1) | header | `notify_hello_reply` | `EPROTO` |
| `SUBSCRIBE` (2) | `notify_topic_request` | header | `EACCES`; `EEXIST` already subscribed; `ENOSPC` at 64 |
| `UNSUBSCRIBE` (3) | `notify_topic_request` | header | `ENOENT` not subscribed |
| `PUBLISH` (4) | `notify_publish_request` + payload | header (router processed, not durable delivery) | `EACCES`; `EOVERFLOW` sequence exhausted |
| `NEXT` (5) | `notify_next_request { timeout_ms }` (0 polls, `NOTIFY_TIMEOUT_INFINITE` waits) | one `notify_event` | `EAGAIN` nothing queued in time; `EBUSY` |
| `TIMER_ADD` (6) | `notify_timer_request { timer_id, interval_ms, flags }` | header | `EACCES` timers off; `EEXIST` id in use; `ENOSPC` at 64; `EINVAL` id 0 or interval outside 1 ms to 24 h |
| `TIMER_CANCEL` (7) | `notify_timer_cancel_request` | header | `ENOENT` |
| `STATS` (8) | header | `notify_stats` (published, delivered, dropped, rejected, timer_events) | |
| `STATE_SET` (9) | `notify_state_set_request { state, topic }` | `notify_state_reply` | `EACCES` (publish policy); `ENOSPC` at 4096 states; `EOVERFLOW` |
| `STATE_GET` (10) | `notify_topic_request` | `notify_state_reply { router_epoch, generation, state }` | `EACCES` (subscribe policy); `ENOENT` |
| `STATE_CLEAR` (11) | `notify_topic_request` | header | `ENOENT`; `EACCES` not the owner |
| `LIST_SUBSCRIPTIONS` (12) | `notify_list_request { cursor }` | `notify_list_reply` + `notify_subscription_entry[]`, at most 24 per page | |
| `LIST_TIMERS` (13) | `notify_list_request` | `notify_list_reply` + `notify_timer_entry[]` (id, interval, flags, `next_fire_ms`) | |

Event types are `PUBLISH`, `TIMER`, `STATE`, `GAP` and `RESET`; a `notify_event` carries epoch, sequence, timestamp, timer id, generation, state, lost count, then the publisher, topic and payload bytes.

## Client library

Header `<notify.h>` (installs `notify.h`, `notify_protocol.h`, `notify_server.h`); link with `-lnotify` (`SHLIB_MAJOR 1`, depends on libservice and pthread). Manual: libnotify(3).

| Group | Functions |
|---|---|
| Session | `notify_client_open` (open tier), `notify_client_open_system` (gated tier), `notify_client_adopt` (wrap an already-delivered fd), `notify_client_close` |
| Pub/sub | `notify_subscribe`, `notify_unsubscribe`, `notify_publish`, `notify_next` |
| State | `notify_state_set`, `notify_state_get`, `notify_state_clear` |
| Timers | `notify_timer_add` (flag `NOTIFY_TIMER_F_PERIODIC`), `notify_timer_cancel` |
| Introspection | `notify_stats`, `notify_list_subscriptions`, `notify_list_timers` |

A client is bound to one tier for life, across transparent reconnects. If the provider dies inside `notify_next()`, the library reconnects, restores subscriptions and returns one `NOTIFY_EVENT_RESET`; any other operation that sees peer death returns the transport error because its acceptance is unknown. `notify_list_*` walk every page and return the session's total, which may exceed `capacity` to signal truncation. An inherited client is invalid after `fork(2)`.

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

notifyctl(8) uses libnotify for every live operation and receives no implicit administrative bypass; it is subject to the invoking session's policy. `-s` selects the gated tier and fails with `ENOENT` without the anointment (`anoint(1)` can elevate a command when `principal-policy.ucl` lists `system.notify.system` under `may_elevate`).

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
| `usr.sbin/BSDNotify/tests` (package `bsdnotify-tests`, `/usr/tests/usr.sbin/BSDNotify`) | `dispatcher_test` (21 cases), `policy_test` (28), `broker_test` (12), `transport_test` (1), `bundle_test.sh` (9) | dispatcher_test drives the router over real channels: HELLO/STATS/errors, pub/sub/state/next, timers and the pending long-poll, the open-tier default (`user.*` only), the gated default and `clients` narrowing, admin bypass on both tiers, admission-control tier validation and failure classes, timer id wrap, every opcode on the open tier, explicit empty lists denying, one label on both tiers at once, a user session label being nothing special, and a NULL policy failing closed. policy_test covers the parser; broker_test covers queues, gap accounting and state ownership; bundle_test.sh checks the manifest, shipped policy, tier, security, router lifecycle, observability and tier-mismatch audit contracts. |
| `lib/libnotify/tests` (`libnotify-tests`) | `notify_test` (8), `client_lifecycle_test` (13, fake service) | encoding, reconnect and RESET semantics, list truncation reporting, post-fork invalidation |
| `usr.sbin/notifyctl/tests` | `notifyctl_test.sh` (10) | configtest on `valid.conf`/`invalid.conf`, argument and payload limits, `-s` tier option and its usage errors, operation failures, `--` handling |

Run with `kyua test -k /usr/tests/usr.sbin/BSDNotify/Kyuafile` on a booted plane ([Testing](../develop/testing.md)). The inventory counts 62 daemon cases. The `BSDNotify` DTrace provider exports `session-start`, `session-end`, `session-admit`, `tier-policy`, `subscribe`, `publish`, `deliver`, `timer`, `list` and `reject`; payload bytes are never probe arguments.

## Status and gaps

Status: shipped; capmode; user `capability`; `visible = ["user"]`; gated tier `requires = ["system.notify.system"]`; 13 ops (inventory section 4).

Known gaps and drift:

- notifyctl(8) `configtest` defaults to `/etc/bsdnotify.conf`, a path the plane does not install; the man page and tool predate the bundle Config layout.
- BSDNotify(8) names the file `Config/BSDNotify.conf`; the Makefile installs `bsdnotify.conf`. Use the lowercase name.
- Delivery is at-most-once with explicit loss reporting by design; there is no durable queue, replay or acknowledgement, and state cells (one `uint64_t` per topic) do not survive a broker restart or the owning label's last session.
- Subscriptions are exact-topic only; wildcards exist in policy lists, not in the subscribe op.
