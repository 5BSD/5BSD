# Endpoint Security (OES)

OpenEndpointSecurity (`oes(4)`) is 5BSD's endpoint monitoring and
authorization framework. It follows the client and event model of Apple's
Endpoint Security API while using the 5BSD MAC framework for enforcement and
Capsicum descriptors for delegation. EDR agents, integrity monitors, and audit
collectors subscribe through `/dev/oes`; AUTH clients decide whether selected
operations proceed, while NOTIFY clients observe without blocking them. The
kernel policy and public ABI live in `sys/security/oes/`, the client library is
`liboes(3)`, and `oeslogger(8)` is the installed passive inspection tool. OES
is an LP64-only, version-1 ABI; 32-bit clients are rejected.

## Relationship to Apple's API

OES preserves the concepts that make Endpoint Security clients familiar:
opaque per-client state, AUTH and NOTIFY subscriptions, auth and flags
responses, client caches, process/path/target-path muting, sequence counters,
copied-message ownership, and descendants-scoped clients with deadline
controls. This is behavioral alignment, not source or event-catalog
compatibility: OES events are FreeBSD vnode, credential, jail, Capsicum,
audit, socket, pipe, mount, kernel-module, sysctl, and kenv operations, and
5BSD has no equivalent of Apple's code-signing entitlement — opening `/dev/oes`
is privileged instead. Clients must use the versioned `oes_*` ABI and test
metadata-availability flags rather than assuming an `es_*` layout.

## Event and client model

MAC check hooks and process, mount, and module event handlers produce two
kinds of event:

- **AUTH** events originate in sleepable checks. Every applicable AUTH client
  must respond before its deadline; the effective result combines all client
  decisions, and per-client/per-event deadline policy selects fail-open or
  fail-closed behavior when an event cannot be queued or answered in time.
- **NOTIFY** events are informational and never block the originating
  operation. A NOTIFY derived from an AUTH event records the applied
  authorization decision, not the later success of the system call. Hooks that
  cannot sleep have NOTIFY-only coverage; `oes(4)` identifies them.

Each `open("/dev/oes")` creates an independent client, up to
`security.oes.max_clients`. A client owns its subscription bitmap, mutes,
operating mode, queue, timeouts, deadline overrides, and decision cache;
events fan out only to clients whose scope, subscription, and mute state admit
them. `oes_client_create_descendants()` restricts a client to its own
descendant tree — the opener stays visible for NOTIFY, descendants for AUTH
and NOTIFY, unrelated processes are hidden — and the restriction can never be
widened.

## Message and metadata contract

Every `oes_message_t` is self-describing and versioned: reads return as many
aligned complete messages as fit, and a message that does not fit remains
queued — it is never truncated into the caller's buffer. Messages carry the
event and applied AUTH result, timestamps and deadlines, per-client global and
per-event sequence numbers (advanced for attempted delivery, so a
discontinuity exposes a drop), a rich process snapshot (token, lineage,
credentials, jail/Capsicum/Linuxulator state, cached executable path), vnode
identity and attributes where applicable, and event-specific objects such as
exec argv/envp or source and target paths. Metadata is a snapshot, not a
promise: flag bits distinguish missing, truncated, requested, and proposed
data.

## Delivery and close safety

NOTIFY events raised where sleeping is forbidden go to a dedicated deferred
queue that module unload drains, and kqueue notes are cleared before client
destruction so a late filter detach cannot reach freed state. OES adds
`mac_vnode_check_close(cred, vp)` to MACF so close observation occurs before
`VOP_CLOSE()`; close remains NOTIFY-only because a close cannot be rejected,
and VFS supplies a valid credential even on deferred descriptor disposal (an
unread `SCM_RIGHTS` descriptor discarded while a Unix socket closes).

## Client API and noise policy

`liboes(3)` wraps subscriptions, reads, responses, caches, deadline policy,
scope, and muting:

```c
oes_client_t *client = oes_client_create();
oes_subscribe_all(client, false, true);   /* passive NOTIFY collector */
oes_mute_self(client);
oes_mute_path(client, "/var/log", OES_MUTE_PATH_PREFIX);
```

New ordinary clients self-mute by default, and administrators can configure
default path mutes via `security.oes.default_muted_paths*` sysctls; these
defaults are ordinary mutable client state that mute-query APIs report and
`oes_unmute_all_*()` removes. AUTH callbacks must not perform work that
recursively requires their own authorization — `oes(4)` documents this
self-deadlock constraint.

`oeslogger(8)` subscribes only to NOTIFY events and emits newline-delimited
JSON; with no arguments it selects all NOTIFY events, and names such as `exec`
and `open` narrow the stream (`oeslogger exec open | jq .`).

## Observability

The `oes` SDT provider exposes authorization results, timeouts, queue and
cache activity; denials also carry OpenBSM audit context. The framework is
exercised by an extensive ATF suite, with a disposable QEMU harness
(`tools/test/oes-qemu/`) that runs it against a matching kernel without host
root access.

Process tokens contain PID plus an OES generation counter, not the
`mac_capability` per-credential nonce.
