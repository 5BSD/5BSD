# Endpoint Security (OES)

OpenEndpointSecurity is the kernel event framework that lets a userland
program watch, and for a chosen set of operations veto, what every process
on the machine does: each exec, open, unlink, mount, module load, signal or
credential change becomes a message on `/dev/oes`. 5BSD has it because
endpoint-detection agents, integrity monitors and audit collectors need a
supported, structured, close-safe event stream rather than a patchwork of
ktrace, audit pipes and DTrace, and because the MAC framework already sees
every one of those operations. OES follows the client and event model of
Apple's Endpoint Security API; the resemblance is behavioural, not a
compatibility claim, and the events are native FreeBSD operations.

Reference: oes(4), liboes(3), oeslogger(8), `docs/security/oes-endpoint-security.md`.
Source: `sys/security/oes/` (seven files, the hook table in `oes_mac.c`),
`lib/liboes/`, `usr.sbin/oeslogger/`, examples in `share/examples/oes/`.

## The event model

OES is a MAC policy. Its hooks, plus a few event handlers for fork, exit,
mount and kld, turn kernel operations into events of two kinds.

| Kind | Delivered from | Blocking | Client's role |
|---|---|---|---|
| AUTH | sleepable MAC check hooks, before the operation | the originating thread sleeps in the hook until every subscribed AUTH client answers or the deadline passes | allow or deny |
| NOTIFY | check hooks, event handlers and the framework's close hook, after the decision | never blocks the originating thread | observe |

There are 100 event types, generated from the X-macro table in
`sys/security/oes/oes_event_table.h`: 36 AUTH events in the range
`0x0001` to `0x0FFF` and 64 NOTIFY events in `0x1001` to `0x1FFF`. The
`0x1000` bit tells them apart (`OES_EVENT_IS_AUTH`). Most AUTH events have
a NOTIFY counterpart; when they do, the NOTIFY is queued only after the
combined authorization decision and carries that decision in `em_result`
with `OES_MSG_FLAG_AUTH_RESULT` set. Such a message reports the
authorization outcome before the MAC check returns; it is not proof that
the system call later succeeded.

| Family | AUTH events | NOTIFY-only events |
|---|---|---|
| process | `EXEC`, `PTRACE` | `EXIT`, `FORK`, `SIGNAL`, `SETUID`, `SETGID`, `PROC_SCHED`, `PRIV_CHECK` |
| file lifecycle | `OPEN`, `CREATE`, `UNLINK`, `RENAME`, `LINK`, `READ`, `WRITE`, `LOOKUP`, `ACCESS`, `STAT`, `POLL`, `REVOKE`, `READDIR`, `READLINK`, `CHDIR`, `CHROOT` | `CLOSE` |
| attributes | `SETMODE`, `SETOWNER`, `SETFLAGS`, `SETUTIMES`, `SETEXTATTR`, `GETEXTATTR`, `DELETEEXTATTR`, `LISTEXTATTR`, `GETACL`, `SETACL`, `DELETEACL`, `RELABEL` | |
| memory | `MMAP`, `MPROTECT` | |
| system | `MOUNT`, `KLDLOAD`, `SWAPON`, `SWAPOFF` | `UNMOUNT`, `KLDUNLOAD`, `REBOOT`, `SYSCTL`, `KENV`, `MOUNT_STAT` |
| sockets and pipes | | `SOCKET_CREATE`, `_CONNECT`, `_BIND`, `_LISTEN`, `_ACCEPT`, `_SEND`, `_RECEIVE`, `_STAT`, `_POLL`, `PIPE_READ`, `_WRITE`, `_STAT`, `_POLL`, `_IOCTL` |

`CLOSE` is the one event 5BSD had to add a hook for: FreeBSD's MAC
framework had no close hook, so OES brought `mac_vnode_check_close`, called
as `(void)` from `vn_close1()` because a close cannot be denied. The
executable path is captured once at a successful exec and carried in the
credential label, so later hooks never perform a vnode path lookup under a
held lock; a process older than OES activation reports
`OES_PROC_META_PATH_UNAVAILABLE` until its next exec.

## Clients

Each `open(2)` of `/dev/oes` creates an independent client with its own
subscription bitmap, mute state, mode, queue, deadline policy and decision
cache; events fan out to every subscribed client, bounded by
`security.oes.max_clients`. A client runs in one of three modes:

| Mode | Meaning |
|---|---|
| `OES_MODE_NOTIFY` | receive NOTIFY events only; never blocks the kernel |
| `OES_MODE_AUTH` | receive AUTH events and answer them; the process that opened the client is never sent its own AUTH requests, so a handler cannot recurse on itself |
| `OES_MODE_PASSIVE` | receive AUTH subscriptions as NOTIFY messages without blocking; the shape a broker hands to a third party |

A client may become *descendants-scoped* before setting its mode or
subscriptions (`oes_client_create_descendants`). It then sees NOTIFY for
its own process and AUTH plus NOTIFY for the whole descendant subtree,
including descendants that existed before the scope was chosen; every other
process is invisible and process mutes outside the subtree are rejected.
This is the sandbox-supervisor shape, and the scope can never be widened.

Muting is per client and is ordinary mutable state: by process token, by
uid or gid, by path prefix or literal path on the primary object, by target
path on the secondary object of a rename or link, per event type, and with
inversion (deliver only the muted set). New clients self-mute by default so
a logger does not log itself.

Deadlines bound how long an AUTH decision may take. The client-wide
deadline in `oes_mode_args` is the default; `OES_IOC_SET_DEADLINE_MAX` caps
one event type, and a descendants client may also set a floor with
`OES_IOC_SET_DEADLINE_MIN`. `OES_IOC_SET_DEADLINE_MISS_MODE` chooses what a
missed deadline, or an AUTH message that cannot be queued because the
client's queue is full, means: `OES_DEADLINE_MISS_FAIL_OPEN` (allow) or
`OES_DEADLINE_MISS_FAIL_CLOSED` (deny). The decision cache lets a client
pre-answer repeats of an event whose security-relevant parameters are in
the cache key; the kernel invalidates entries on content and metadata
changes and clears every cache on namespace changes.

## The device and its ioctls

The kernel interface is `sys/security/oes/oes.h`: 38 `OES_IOC_*` ioctls,
`read(2)` returning one or more `oes_message_t` records, and `write(2)` of
an `oes_response_t` or `oes_response_flags_t` to answer an AUTH event.
Readiness is reported through `poll(2)`, `select(2)` and `kqueue(2)`.

| Ioctl group | Ioctls |
|---|---|
| subscription | `SUBSCRIBE`, `SUBSCRIBE_BITMAP`, `GET_SUBSCRIPTIONS` |
| scope and mode | `SET_SCOPE`, `GET_SCOPE`, `SET_MODE`, `GET_MODE` |
| deadlines | `SET_DEADLINE_MAX`, `GET_DEADLINE_MAX`, `SET_DEADLINE_MIN`, `GET_DEADLINE_MIN`, `SET_DEADLINE_MISS_MODE`, `GET_DEADLINE_MISS_MODE` |
| muting | `MUTE_PROCESS`, `UNMUTE_PROCESS`, `MUTE_PATH`, `UNMUTE_PATH`, `MUTE_UID`, `UNMUTE_UID`, `MUTE_GID`, `UNMUTE_GID`, `MUTE_PROCESS_EVENTS`, `UNMUTE_PROCESS_EVENTS`, `MUTE_PATH_EVENTS`, `UNMUTE_PATH_EVENTS`, `SET_MUTE_INVERT`, `GET_MUTE_INVERT`, `GET_MUTED_PROCESSES`, `GET_MUTED_PATHS`, `UNMUTE_ALL_PROCESSES`, `UNMUTE_ALL_PATHS`, `UNMUTE_ALL_TARGET_PATHS`, `UNMUTE_ALL_UIDS`, `UNMUTE_ALL_GIDS` |
| decision cache | `CACHE_ADD`, `CACHE_REMOVE`, `CACHE_CLEAR` |
| statistics | `GET_STATS` |

Every message carries per-client global and per-event sequence numbers, so
a gap means a drop happened and is visible; monotonic and wall-clock
timestamps; the triggering thread; and a snapshot of the source process
(pid and real parent, reaper, process group and session, credentials and
supplementary groups, audit session, jail, login class, ABI, start time,
routing FIB and the `EP_FLAG_OES_CLIENT` bit). File objects carry vnode
identity, ownership, mode, flags, sizes, generation and nanosecond
timestamps, with `OES_FILE_META_*` bits marking attributes that were
unavailable, truncated or proposed for an object that does not exist yet.
Consumers must read `ep_meta_flags` and `ef_meta_flags` rather than assume
every field is populated. The message format is version 1 of a pre-1.0 ABI
(`OES_API_VERSION`), fixed-width and additive.

## liboes(3)

`liboes` wraps the device. Its 44 functions group as:

| Group | Functions |
|---|---|
| lifecycle | `oes_client_create`, `oes_client_create_descendants`, `oes_client_create_from_fd`, `oes_client_destroy`, `oes_client_fd` |
| configuration | `oes_set_mode`, `oes_get_mode`, `oes_set_descendants_scope`, `oes_get_scope`, `oes_set_deadline_max/min`, `oes_get_deadline_max/min`, `oes_set_deadline_miss_mode`, `oes_get_deadline_miss_mode` |
| subscription | `oes_subscribe`, `oes_unsubscribe`, `oes_unsubscribe_all`, `oes_subscribe_all`, `oes_subscribe_bitmap`, `oes_get_subscriptions` |
| muting | `oes_mute_self`, `oes_mute_process`, `oes_mute_path`, `oes_mute_target_path` and their unmute and unmute-all forms, `oes_set_mute_invert`, `oes_get_mute_invert` |
| events | `oes_read_event`, `oes_message_copy`, `oes_message_free`, `oes_respond`, `oes_respond_flags`, `oes_respond_allow`, `oes_respond_deny`, `oes_dispatch` |
| helpers | `oes_process_path`, `oes_file_path`, `oes_event_name`, `oes_is_auth_event`, `oes_cache_add/remove/clear`, `oes_get_stats` |

`oes_read_event` returns a pointer valid only until the next read on that
client; `oes_message_copy` makes an owned copy. `oes_dispatch` runs a
handler loop on the caller's thread; OES owns no asynchronous callback
queue, which is why it does not offer an `es_sync_client` analogue.

## Writing a subscriber

The reference broker `share/examples/oes/oesd.c` shows the shape. The
fragment below is the core of it: open a client, enter AUTH mode, subscribe,
mute yourself, then drain events off a kqueue and answer the AUTH ones.

```c
#include <sys/event.h>
#include <err.h>
#include <liboes.h>

static void
handle(oes_client_t *client, const oes_message_t *msg)
{
	if (oes_is_auth_event(msg)) {
		/* decide; here every operation is allowed */
		oes_respond_allow(client, msg);
	}
}

int
main(void)
{
	oes_client_t *client;
	struct kevent kev;
	int kq, fd;

	client = oes_client_create();
	if (client == NULL)
		err(1, "oes_client_create");
	fd = oes_client_fd(client);

	if (oes_set_mode(client, OES_MODE_AUTH, 0, 0) < 0)
		err(1, "oes_set_mode");
	if (oes_subscribe_all(client, true, true) < 0)
		err(1, "oes_subscribe_all");
	if (oes_mute_self(client) < 0)
		err(1, "oes_mute_self");

	kq = kqueue();
	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) < 0)
		err(1, "kevent");

	for (;;) {
		const oes_message_t *msg;

		if (kevent(kq, NULL, 0, &kev, 1, NULL) < 0)
			continue;
		/* read(2) batches messages; drain until EAGAIN */
		while (oes_read_event(client, &msg, false) == 0)
			handle(client, msg);
	}
}
```

A real handler subscribes to a chosen set with `oes_subscribe` rather than
everything, keeps AUTH work short (the originating thread sleeps in a MAC
hook, sometimes with the target vnode locked, until the answer arrives),
and mutes any helper process it forks, because a helper is a separate
identity and can deadlock on a vnode held by the operation it is helping to
authorize. The `oesd` example goes on to hand third parties a passive
descriptor: it opens a second client in `OES_MODE_PASSIVE`, narrows it with
`cap_ioctls_limit(2)` to `OES_IOCTLS_THIRD_PARTY_INIT` and
`cap_rights_limit(2)` to `CAP_READ`, `CAP_EVENT` and `CAP_IOCTL`, and
passes it over a root-only Unix socket after checking peer credentials.
`share/examples/oes/vendor_client.c` is the receiving side. That is the
5BSD idiom: the one privileged opener of `/dev/oes` delegates rights-limited
views, and an unprivileged consumer never touches the device.

## oeslogger(8)

`oeslogger` is the installed passive client. It subscribes in NOTIFY mode,
never authorizes anything, and writes one JSON object per event to standard
output or a file:

```
oeslogger exec open create unlink          # selected events, NDJSON
oeslogger -o /var/log/oes.ndjson           # everything, appended to a file
oeslogger -d -n exec open                  # own subtree only, no noise mutes
oeslogger -m /var/log -m /tmp exec         # mute two path prefixes
oeslogger -l                               # list accepted event names
```

Each record carries the message id and sequence numbers, both timestamps,
the authorization result and deadline where applicable, source process,
thread and path metadata (including `is_oes_client`), and the
event-specific objects. By default it mutes itself and `/dev/`; `-n` clears
those and the kernel's configured default mutes, `-p` pretty-prints.

## Sysctls

| Sysctl | Meaning | Default |
|---|---|---|
| `security.oes.max_clients` | concurrent clients | 64 |
| `security.oes.require_auth_clients` | deny any operation that would raise an AUTH event when no AUTH client is subscribed to it; the fail-closed switch | 0 |
| `security.oes.auth_fail_closed` | deny when the kernel cannot allocate or deliver the state an AUTH event needs | 0 |
| `security.oes.default_deadline_ms` | client-wide AUTH deadline | 30000 |
| `security.oes.default_deadline_miss_mode` | 0 fail open, 1 fail closed, for clients that do not set their own | 0 |
| `security.oes.default_queue_size` | events queued per client | 1024 |
| `security.oes.cache_max_entries` | decision-cache entries per client | 1024 |
| `security.oes.default_self_mute` | self-mute new clients; not applied to descendants-scoped clients | 1 |
| `security.oes.default_muted_paths`, `.default_muted_paths_literal` | colon-separated prefix or literal paths muted for new clients when they set their mode | empty |
| `security.oes.debug` | kernel debug output | 0 |

`require_auth_clients` is the knob that turns OES from an observer into a
mandatory control: with it set, an exec with no AUTH subscriber for
`OES_EVENT_AUTH_EXEC` is refused. Set it only once the agent is known to
start before anything that matters.

## Boot-only, LP64-only

OES is compiled into GENERIC (`options OES`) and registers its policy at
boot with no unload path, because its credential labels live on every
process. The kernel interface is LP64 only: the public header refuses
32-bit builds, and the ioctl structures carry native pointers and `size_t`
counts with no compat32 translation. 5BSD ships no 32-bit userland, so
this costs nothing in practice, and `tests/sys/security/oes/test_unsupported_32bit.sh`
pins it.

## The DTrace provider

The `oes` SDT provider carries seven probes: `auth-allow`, `auth-deny` and
`auth-timeout` for authorization outcomes, `event-enqueue` and `event-drop`
for queue flow, `cache-hit` and `cache-miss` for the decision cache. Eleven
ready-made scripts live in `share/examples/oes/dtrace/`. Together with
`mac_framework:::policy-decision` they answer "did OES, or another policy,
deny this?".

## What is qualified and what is open

Qualified: the message ABI, metadata helpers and batched reads are covered
by unit tests that need no module; 47 plain C integration tests plus an ATF
contract matrix and two shell tests under `tests/sys/security/oes/` exercise
deadline transitions, invalid and late responses, queue-saturation
fail-closed behaviour, multi-client AUTH and NOTIFY fan-out, descendants
visibility across separate outside, root and child processes, mute
inversion, uid and gid mutes, signal, socket, mmap, extattr, chdir, chroot,
unmount and kldunload events, memory pressure and stress. `liboes` and the
batch-reader tests build clean under AddressSanitizer and
UndefinedBehaviorSanitizer. The test harness exits non-zero on any failed
assertion (an earlier version did not, and that was fixed).

Open: a live kyua qualification of the whole suite on a VM, together with
KASAN and KUBSAN runs and the DTrace scripts, is recorded as pending in
`docs/security/oes-endpoint-security.md`. Apple's `KILL` deadline-miss mode,
exec entitlements and code-signing fields are not implemented; 5BSD has no
signing authority yet, and opening `/dev/oes` is gated by device permission
rather than an entitlement. Bootstrap, XPC and TCC events have no truthful
FreeBSD equivalent and are not published as placeholders. The API is pre-1.0
and may change shape before it is frozen.

## Where OES sits among the policies

OES is a MAC policy beside the plane, like [mac_abac](mac-abac.md). It
neither grants nor consumes capabilities; a deny from an AUTH client is one
more deny-wins vote in the MAC composition and cannot re-allow what
`mac_capability`, capprotect or Capsicum refused. The plane's own units are
visible to it like any other process, which makes `oeslogger -d` under a
provider a useful debugging view, and a descendants-scoped AUTH client is a
reasonable way for a per-user agent to police its own children without any
system-wide authority. See [Policy Points](policy-points.md) for how OES
relates to the other six decision layers.
