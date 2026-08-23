# Endpoint Security (OES)

OpenEndpointSecurity (`oes(4)`) is 5BSD's endpoint monitoring and
authorization framework. It follows the client and event model of Apple's
Endpoint Security API while using the 5BSD MAC framework for enforcement and
Capsicum descriptors for delegation. EDR agents, integrity monitors, and audit
collectors subscribe through `/dev/oes`; AUTH clients decide whether selected
operations proceed, while NOTIFY clients observe without blocking them.

| Component | Location |
|-----------|----------|
| Kernel MAC policy and public ABI | `sys/security/oes/` |
| Client library `liboes(3)` | `lib/liboes/` |
| Event logger `oeslogger(8)` | `usr.sbin/oeslogger/`, `share/examples/oes/oeslogger.c` |
| Kernel and userspace tests | `tests/sys/security/oes/` |
| VM qualification harness | `tools/test/oes-qemu/` |
| Man pages and examples | `share/man/man4/oes.4`, `lib/liboes/liboes.3`, `share/examples/oes/` |

OES is an LP64-only interface. The public header rejects ILP32 builds and the
device rejects 32-bit clients; no compatibility ABI is provided. The pre-1.0
API and message ABI are both version 1.

## Relationship to Apple's API

OES preserves the concepts needed to make Endpoint Security clients familiar:
opaque per-client state, AUTH and NOTIFY subscriptions, auth and flags
responses, client caches, process/path/target-path muting and inversion,
per-event and global sequence counters, copied-message ownership, and
event-specific unions. Its descendants scope and per-event minimum/maximum
deadline plus miss-mode controls correspond to Apple's current beta
[`es_new_descendants_client`](https://developer.apple.com/documentation/endpointsecurity/es_new_descendants_client%28_%3A_%3A%29),
[`es_message_t`](https://developer.apple.com/documentation/endpointsecurity/es_message_t),
and deadline APIs.

This is behavioral alignment, not source or event-catalog compatibility.
OES uses FreeBSD vnode, credential, jail, Capsicum, audit, socket, pipe, mount,
kernel-module, sysctl, and kenv objects and events. Apple uses an
[Endpoint Security entitlement](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.developer.endpoint-security.client),
TCC, code-signing identity, and macOS-specific event families; 5BSD currently
has no equivalent code-signing or entitlement metadata. OES clients must use
the versioned `oes_*` ABI and test metadata-availability flags instead of
assuming an `es_*` structure layout.

## Event and client model

MAC check hooks and process, mount, and module event handlers produce two
kinds of event:

- **AUTH** events originate in sleepable checks. Every applicable AUTH client
  must respond before its deadline; the effective result combines all client
  decisions. Per-client and per-event deadline policy selects fail-open or
  fail-closed behavior if an event cannot be queued or answered in time.
- **NOTIFY** events are informational and never block the originating
  operation. A NOTIFY derived from an AUTH event records the applied
  authorization decision, not the later success of the system call.

Event identifiers are generated from
`sys/security/oes/oes_event_table.h`: AUTH occupies `0x0001`–`0x0fff` and
NOTIFY occupies `0x1001`–`0x1fff`. Some hooks cannot sleep and therefore have
NOTIFY-only coverage; the public header and `oes(4)` identify those cases.

Each `open("/dev/oes")` creates an independent client in `cdevpriv`, up to
`security.oes.max_clients` (64 by default). A client owns its subscription
bitmap, process/path/target-path mutes, operating mode, queue, timeouts,
deadline overrides, and decision cache. Events fan out only to clients whose
scope, subscription, and mute state admit them.

## Descendants clients

`oes_client_create_descendants()` provides the nested-client behavior of
Apple's `es_new_descendants_client()`. The opener remains visible for NOTIFY
events, its descendants are visible for AUTH and NOTIFY events, and unrelated
processes are hidden. The same restriction can be selected with
`oes_set_descendants_scope()` before mode and subscription configuration and
queried with `oes_get_scope()`; it cannot later be widened.

Descendants clients may set both minimum and maximum AUTH deadlines. Ordinary
clients set a maximum only. Per-event overrides use zero to return to the
client default. Opening `/dev/oes` remains privileged because 5BSD does not yet
have a code-signing entitlement authority equivalent to Apple's.

## Message and metadata contract

Every `oes_message_t` is self-describing. `em_size` covers the fixed structure
and trailing string table, `em_struct_size` identifies the fixed portion, and
reads return as many aligned complete messages as fit. A message that does not
fit remains queued; it is never truncated into the caller's buffer. The
pointer returned by `oes_read_event()` remains valid until the next read;
`oes_message_copy()` and `oes_message_free()` provide owned storage.

Messages include:

- message ID, event and action, applied AUTH result, monotonic deadline, and
  monotonic and wall-clock event timestamps;
- per-client global and per-event sequence numbers, advanced for attempted
  delivery so a discontinuity exposes a drop;
- triggering thread ID and name;
- process token and exec ID, PID and parent lineage, process/session/group and
  reaper IDs, state, ABI, flags (including Capsicum, jail, Linuxulator, and
  active-OES-client state), scheduling data, start time, credentials and the
  first 16 groups, login/TTY/jail data, and OpenBSM audit identity;
- the executable path cached on successful exec and inherited across fork,
  plus the current working directory when safely available;
- vnode identity, path, type, filesystem type, owner, mode, size and allocated
  bytes, device and special-device IDs, link count, flags, generation,
  revision, block information, and nanosecond atime/mtime/ctime/birthtime;
- event-specific objects such as exec argv/envp, source and target paths,
  sockets, mounts, credentials, access masks, and proposed vnode attributes.

Metadata is a snapshot, not a promise that every field is available in every
hook. `ep_meta_flags`, `ef_meta_flags`, and message flags distinguish missing,
truncated, requested, and proposed data. Processes that predate OES activation
can lack a cached executable path until their next successful exec.

## Delivery and close safety

NOTIFY events raised where sleeping is forbidden go to the dedicated
single-thread `oes_deferq`; module unload drains that queue. Poll and kqueue
state is tied to the client mutex and knotes are cleared before client
destruction, preventing a late filter detach from reaching freed state.

OES adds `mac_vnode_check_close(cred, vp)` to MACF so close observation occurs
before `VOP_CLOSE()`. Close remains NOTIFY-only because a close cannot be
rejected. VFS supplies a valid credential even on deferred descriptor disposal,
where there is no calling thread—for example an unread `SCM_RIGHTS` descriptor
discarded while a Unix socket closes. The stock stream and datagram
`unix_passfd_*:devfs_orphan` regressions are part of OES VM qualification.

## Client API and default noise policy

`liboes(3)` wraps subscriptions, reads, responses, caches, deadline policy,
scope, and muting:

```c
oes_client_t *client = oes_client_create();
oes_subscribe_all(client, false, true);   /* passive NOTIFY collector */
oes_mute_self(client);
oes_mute_path(client, "/var/log", OES_MUTE_PATH_PREFIX);
```

`oes_client_create_from_fd()` adopts a pre-opened or delegated descriptor.
AUTH callbacks must not perform work which recursively requires their own
authorization; `oes(4)` documents this self-deadlock constraint.

New ordinary clients self-mute by default. Administrators can configure
colon-separated prefix and literal path defaults with
`security.oes.default_muted_paths` and
`security.oes.default_muted_paths_literal`; `security.oes.default_self_mute`
controls self-muting. These defaults are mutable client state, deliberately
visible to mute-query APIs, and clients can remove them with the
`oes_unmute_all_*()` calls. A descendants client keeps its root process visible
because that visibility is part of its scope contract.

## ESLogger

`oeslogger(8)` is the installed passive OES inspection tool. It subscribes
only to NOTIFY events and emits newline-delimited JSON containing the message,
sequence, time, authorization, process, thread, path, and event-specific
metadata described above. With no event names it selects all NOTIFY events;
names such as `exec`, `open`, `create`, and `unlink` narrow the stream.

```sh
oeslogger                            # all NOTIFY events as compact NDJSON
oeslogger exec open | jq .          # selected events
oeslogger -d -n exec open           # this descendant tree, no noise mutes
oeslogger -m /var/log -o events.ndjson
```

`-d` selects descendants scope, `-l` lists names, repeated `-m` adds prefix
mutes, `-n` clears the normal self and `/dev/` noise mutes, `-o` appends to a
file, and `-p` pretty-prints JSON. JSON string generation validates UTF-8 and
escapes arbitrary kernel-supplied bytes.

## Observability and qualification

The `oes` SDT provider exposes authorization results and timeouts, enqueue and
drop activity, and cache hits/misses; scripts live under
`share/examples/oes/dtrace/`. OES denials also carry OpenBSM audit context.

The ATF suite covers ABI validation, malformed ioctls and messages, every hook
class, metadata and path availability, AUTH combination and deadlines,
passive mode, descendants and nested descendants, muting and defaults, caches,
multi-client/process delivery, kqueue/fd lifecycle, memory pressure, stress,
audit/DTrace integration, ESLogger JSON, and explicit 32-bit rejection. The
disposable amd64 QEMU harness installs the matching kernel/module, public
header, `liboes`, and logger, runs the complete Kyua suite, and then runs both
deferred-close Unix-domain regression cases. TCG is the default accelerator,
so host root access and `/dev/vmm` are not required.

**Status:** process tokens contain PID plus an OES generation counter. Moving
them to the mac_capability per-credential nonce remains planned.
