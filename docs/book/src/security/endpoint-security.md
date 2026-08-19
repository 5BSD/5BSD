# Endpoint Security (OES)

OpenEndpointSecurity — `oes(4)` — is 5BSD's endpoint-security event
monitoring and authorization framework, inspired by Apple's Endpoint
Security API but built on the 5BSD MAC framework and the Capsicum
capability model. An EDR agent, integrity monitor, or audit collector
subscribes to kernel events through `/dev/oes` and, for authorization
events, decides whether the operation proceeds.

| Component | Location |
|-----------|----------|
| Kernel MAC policy | `sys/security/oes/` |
| Client library `liboes(3)` | `lib/liboes/` |
| Tests | `tests/sys/security/oes/` |
| Man pages | `share/man/man4/oes.4`, `lib/liboes/liboes.3` |
| Example clients and DTrace scripts | `share/examples/oes/` |

## Event model

The kernel module registers a MAC policy (manually rather than via
`MAC_POLICY_SET`, so it controls cdev/eventhandler ordering across
dynamic load). MAC check hooks plus a few `EVENTHANDLER`s (process
fork/exit, mount, kld) generate events of two kinds:

- **AUTH** events come from sleepable check hooks. A subscribed client
  may allow or deny; the operation blocks until the client responds or
  the per-client timeout fires (with a configurable timeout action).
- **NOTIFY** events are informational and never block the operation.

The ABI is versioned (`OES_API_VERSION`, currently 4) and the event types
are generated from an X-macro table (`sys/security/oes/oes_event_table.h`):
AUTH types occupy `0x0001`–`0x0FFF`, NOTIFY types `0x1001`–`0x1FFF`.

Each `open("/dev/oes")` creates an independent client (stored in
`cdevpriv`), so clients are per-open and per-process; up to
`security.oes.max_clients` (default 64) may be active, and every event
fans out to all subscribed clients. Each client carries its own
subscription bitmap, mute state (self, process, path, target path),
mode, timeout, and decision cache.

## Read batching via em_size

Events are read from `/dev/oes` as self-describing messages: each
`oes_message_t` header records `em_size`, the total message size
including its string table. A single `read(2)` returns as many complete
messages as fit in the buffer, and userspace iterates:

```c
for (off = 0; off < n; off += msg->em_size)
        msg = (oes_message_t *)(buf + off);
```

A message that does not fit in the remaining buffer stays queued (the
client's queue-byte accounting is credited back), so no event is
truncated or lost by a short read. This batching keeps syscall overhead
low for high-rate notify streams.

## Deferred delivery (oes_deferq)

Some MAC hooks fire in contexts that cannot sleep. NOTIFY events raised
there are placed on a deferred queue and delivered by a **dedicated
single-thread taskqueue, `oes_deferq`**, created at module init. Earlier
designs dropped such events on lock contention (trylock) or handed them
to the shared `taskqueue_thread`, where unrelated kernel work was
observed to stall delivery long enough for observers to miss events
under load. The private thread keeps deferred-delivery latency low and
bounded; module unload drains the task and releases anything still
queued.

## kqueue-free safety

Clients can wait for events with `poll(2)`/`kqueue(2)`. The knote list is
initialized against the client mutex (`knlist_init_mtx`), and
`oes_client_free()` performs `knlist_clear()` before `knlist_destroy()`,
so an EVFILT registration that outlives the fd-close knote drop cannot
leave a dangling `kn_knlist` and fault in `oes_kqdetach()` when the
client is freed underneath it. Detach takes the lock itself because
`knote_drop` calls `f_detach` without the knlist lock held.

## MAC framework integration

OES consumes existing MACF hooks and motivated one new one:
`mac_vnode_check_close(cred, vp)`, added across
`sys/security/mac/mac_policy.h`, `mac_framework.h`, `mac_vfs.c`, and the
call site in `vn_close1()` (`sys/kern/vfs_vnops.c`) before `VOP_CLOSE()`.
A close cannot fail, so the call site invokes the hook as `(void)` and
OES treats `NOTIFY_CLOSE` as notify-only. Three hooks OES's upstream
documentation listed as missing already existed in 5BSD
(`mac_kld_check_unload`, `mac_vnode_check_truncate`,
`mac_mount_check_unmount`); see `docs/macf-new-hooks.md` for the full
hook catalog.

## Client API

`liboes(3)` wraps the device protocol:

```c
oes_client_t *c = oes_client_create();
oes_subscribe_all(c, /*auth*/ false, /*notify*/ true);
/* or: oes_subscribe(), oes_subscribe_bitmap(), oes_subscribe_bitmap_ex() */
oes_set_timeout(c, 500);                 /* AUTH response deadline, ms */
oes_set_timeout_action(c, OES_AUTH_RESULT_ALLOW);
oes_mute_self(c);                        /* don't observe yourself */
oes_mute_path(c, "/var/log", type);      /* path and target-path mutes */
oes_cache_add(c, &entry);                /* per-client decision cache */
```

Handlers receive `const oes_message_t *` callbacks;
`oes_client_create_from_fd()` supports pre-opened (e.g. delegated)
descriptors. The module also ships an `oes` DTrace SDT provider
(`auth-allow`, `auth-deny`, `auth-timeout`, `event-enqueue`,
`event-drop`, `cache-hit`, `cache-miss`) with scripts under
`share/examples/oes/dtrace/`, and an `oeslogger` event tool. AUTH
handlers must not perform operations that would generate events they
themselves must authorize; `oes.4` documents this self-deadlock hazard.
Recent hardening makes the policy fail closed and isolates delegated
clients.

## Packaging and testing

The module builds as `sys/modules/oes` (option `OES`); pkgbase ships
`oes` (library) and `oes-tests` packages. Tests are C integration tests
requiring root and the loaded module; the shared harness exits non-zero
on any failed assertion, and `liboes` builds clean under
`-fsanitize=address,undefined`. Event delivery has been validated in a
VM, including a vnode-event smoke test passing 95/95 consecutive runs.

**Status:** OES currently identifies processes by raw PID in process
tokens; migrating to the MAC_CAPABILITY per-credential nonce (stable
across PID reuse) is planned but not yet implemented.
