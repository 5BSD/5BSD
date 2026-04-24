# CAP_RT -- Capability Message Interface

CAP_RT is a generic messaging interface for building capabilities on
FreeBSD.  It supports async and sync messaging to kernel services
(via loadable modules) and userspace-to-userspace IPC (via capability
pairs).  All communication flows through file descriptors that are
Capsicum-aware, kqueue-integrated, and delegable via fork, dup, or
SCM_RIGHTS.

## The problem CAP_RT solves

Adding a new Capsicum-aware kernel service to FreeBSD today requires
touching the base system in multiple places:

1. **New capability rights** in `sys/sys/capsicum.h` -- every new
   operation needs a `CAP_*` constant allocated from a finite bitspace.
   There are only 57 bits per index, and rights must be planned
   carefully to avoid collisions.

2. **New descriptor type** in `sys/sys/file.h` -- a new `DTYPE_*`
   constant, a new `struct fileops`, and all the boilerplate that
   comes with it (read, write, close, stat, kqueue, fill_kinfo, cmp).

3. **New syscall** (often) -- entry in `syscalls.master`, handler
   in `sys/kern/`, userspace wrapper in libc.  Syscall numbers are
   a limited namespace with ABI stability requirements.

4. **procstat support** in `usr.bin/procstat` and `lib/libprocstat`
   -- so the new descriptor type shows up in `procstat -f`.

5. **Manual queue/lock/lifecycle code** -- every service reinvents
   message queuing, reference counting, teardown ordering, and
   credential handling.

Each of these changes requires review, risks merge conflicts, and
ships with a base system release.  There is no uniformity across
services -- each one has its own fileops, its own ioctl definitions,
its own error conventions, and its own Capsicum rights.

**CAP_RT replaces all of this with one base system change** (`DTYPE_CAP_RT`,
two reserved Capsicum rights, one device node) that enables unlimited
kernel services as loadable modules.  No new syscalls, no new DTYPEs,
no new `CAP_*` bits per service.  A service author writes message
handlers in a kernel module, loads it, and userspace connects via
`/dev/cap_rt`.

For userspace-to-userspace IPC, the `cap_rt_pair` module provides
bidirectional capability channels -- similar to `socketpair(2)` but
as capability descriptors that can be restricted with
`cap_ioctls_limit()` and revoked by closing one end.

CAP_RT coexists with the socket API.  Like Apple (Mach ports + BSD
sockets) and Android (Binder + sockets), FreeBSD gets both: sockets
for network and traditional IPC, CAP_RT for structured capability-based
messaging.

---

## Design rules

1. **A service is async OR sync, never both.**  Pick `co_handler`
   (async, taskqueue dispatch) or `co_call` (sync, caller's thread).
   The framework rejects services that set both.

2. **Messages are the interface.**  Every operation goes through
   `CAP_RT_SENDMSG`/`CAP_RT_RECVMSG` (async) or `CAP_RT_CALL` (sync).
   No direct struct access from userspace.  Kernel-to-kernel
   messaging uses CAP_RT_CALL or CAP_RT_SENDMSG.

3. **The framework owns the descriptor.**  Services never touch
   `falloc`, `finit`, `finstall`, `fileops`, or `DTYPE_*`.

---

## How it works

A capability is a file descriptor connected to a kernel service.
Userspace sends messages through the fd.  The kernel dispatches
them to the service's handler.  The handler processes the message
and optionally sends a reply.  Userspace receives replies and
notifications through the same fd.

### Async model (co_handler)

```
userspace                    kernel
---------                    ------
CAP_RT_SENDMSG  ------>  RX queue  ------>  taskqueue  ----->  co_handler()
                                                                  |
CAP_RT_RECVMSG  <------  TX queue  <------  cap_rt_reply()  <--------+
```

Two queues per instance (like Mach ports, like NIC ring buffers):
- **RX queue**: userspace → kernel.  `CAP_RT_SENDMSG` enqueues, returns immediately.
- **TX queue**: kernel → userspace.  `CAP_RT_RECVMSG` dequeues, blocks if empty.

### Sync model (co_call)

```
userspace                    kernel
---------                    ------
CAP_RT_CALL  -------->  co_call() runs in caller's thread  -------->  return
```

No queues.  The handler runs as the calling process -- it can
`jail_attach`, `cap_enter`, modify credentials.

---

# Kernel Developer Guide

## Writing a service

A CAP_RT service is a kernel module with one callback -- `co_handler`
(async) or `co_call` (sync), never both:

```c
#include "cap_rt.h"
MODULE_DEPEND(echo, cap_rt, 1, 1, 1);

static int
echo_handler(struct cap_rt_instance *s, const struct cap_rt_msg *msg,
    void *arg)
{
    return (cap_rt_reply(s, cap_rt_msg_token(msg),
        cap_rt_msg_data(msg), cap_rt_msg_datalen(msg),
        NULL, NULL, 0));
}

static const struct cap_rt_ops echo_ops = {
    .co_handler = echo_handler,
};

static struct cap_rt_service *svc;

static int
echo_modevent(module_t mod, int type, void *arg)
{
    switch (type) {
    case MOD_LOAD: {
        struct cap_rt_service_params p = {
            .name = "echo",
            .ops  = &echo_ops,
        };
        return (cap_rt_service_create(&p, &svc));
    }
    case MOD_UNLOAD:
        cap_rt_service_destroy(svc);
        return (0);
    }
    return (EOPNOTSUPP);
}
```

That's a complete echo service.  Load it, connect from userspace,
send a message, get it back.

## Lifecycle callbacks

| Callback | When | Thread | Can fail? |
|---|---|---|---|
| `co_connect` | `CAP_RT_CONNECT`, before instance exists | Caller | Yes |
| `co_init` | After creation, before fd visible | Caller | Yes |
| `co_handler` | Async message dispatch | Taskqueue | Yes (auto-error-reply) |
| `co_call` | Sync call in caller's context | Caller | Yes |
| `co_revoke` | Instance dying, after all work drains | Varies | No (void) |
| `co_fdclose` | Specific fd closed, instance may survive | Caller | No (void) |

All are optional except one of `co_handler` or `co_call`.

### Revocation reasons

| Reason | Meaning |
|---|---|
| `CAP_RT_REVOKE_PEER_CLOSED` | Userspace called `close()` |
| `CAP_RT_REVOKE_BY_SERVICE` | Service called `cap_rt_instance_revoke()` or userspace sent `CAP_RT_TERMINATE` |
| `CAP_RT_REVOKE_UNLOAD` | Module unload via `cap_rt_service_destroy()` |

## The async handler

`co_handler` is called from a per-service taskqueue.  One message
at a time per instance (never concurrent).  May sleep.  No framework
locks held.

Access the message through accessors -- the struct is opaque:

```c
cap_rt_msg_data(msg)      /* payload bytes */
cap_rt_msg_datalen(msg)   /* payload length */
cap_rt_msg_token(msg)     /* correlation token set by sender */
cap_rt_msg_fds(msg)       /* attached file pointers */
cap_rt_msg_fcaps(msg)     /* Capsicum rights on attached fds */
cap_rt_msg_nfds(msg)      /* number of attached fds */
cap_rt_msg_badge(msg)     /* this instance's badge */
cap_rt_msg_cred(msg)      /* sender credentials at send time */
```

**Return 0** after calling `cap_rt_reply()` to send a response.
**Return 0** without replying for fire-and-forget messages.
**Return nonzero** to have the framework send an error reply.

The message is valid only during the call.  Copy what you need.

## Replying

```c
cap_rt_reply(s, cap_rt_msg_token(msg), data, len, fds, fcaps, nfds);
```

- `fds`: file pointers to attach.  NULL if none.
- `fcaps`: Capsicum rights to preserve on those fds.  NULL = full rights.
- `cap_rt_msg_token(msg)`: pass the sender's token back for correlation.

## Notifications

Push an unsolicited message to userspace (async services only):

```c
cap_rt_notify(s, data, len, fds, fcaps, nfds);
```

Returns EAGAIN above the soft limit.  No reply token.

## Badges

The badge is a uint64_t assigned by `co_connect` at instance creation.
It's stamped on every inbound message.  The handler sees it via
`cap_rt_msg_badge(msg)`.  Use it to identify which client sent a
message.  Typical values: monotonic counter, hash key, user ID.

## Instance private data

```c
cap_rt_instance_set_priv(s, my_state);
struct my_state *st = cap_rt_instance_get_priv(s);
```

Set in `co_init`, freed in `co_revoke`.

## Revocation

Tear down an instance from the service side:

```c
cap_rt_instance_revoke(s);
```

The peer's next RECVMSG returns ECONNRESET.  `co_revoke` fires.
Safe to call from inside `co_handler` (self-revoke).
Do NOT call from inside `co_call`.

Userspace can terminate the instance for all holders:

```c
ioctl(fd, CAP_RT_TERMINATE, NULL);
```

The instance dies, all handles get ECONNRESET.  `co_revoke`
fires.  Works regardless of any CAP_RT_REVOKE_* restrictions.

## Granular revoke

Strip individual operations from a capability without killing
the instance.  One-way latch -- once revoked, can't be restored.
Affects the instance (all handles/dups).

```c
ioctl(fd, CAP_RT_REVOKE_SEND, NULL);   /* SENDMSG → EACCES */
ioctl(fd, CAP_RT_REVOKE_RECV, NULL);   /* RECVMSG → EACCES */
ioctl(fd, CAP_RT_REVOKE_CALL, NULL);   /* CALL → EACCES */
```

GETINFO always works.  `CAP_RT_TERMINATE` always works (it's
a control operation, not a message).

Use case: pass a capability to a process but restrict it to
receive-only (revoke send + call before passing).

## Preventing delegation (CAP_RT_LOCK)

Permanently prevent a capability fd from being passed via
SCM_RIGHTS.  One-way latch.

```c
ioctl(fd, CAP_RT_LOCK, NULL);
/* sendmsg(SCM_RIGHTS) now fails for this fd */
/* fork still inherits, dup still works */
```

Services can also set `CAP_RT_SVC_NOXFER` at creation time to
make all instances non-transferable from birth.

## Minting new capabilities

Create an instance and return it as an attached fd in a reply:

```c
struct file *fp;
cap_rt_mint_fp(svc, badge, &fp);
cap_rt_reply(s, token, NULL, 0, &fp, NULL, 1);
fdrop(fp, curthread);
```

This is how services return new capabilities to clients.  The
cap_rt_pair sample demonstrates this pattern.

## Service parameters

```c
struct cap_rt_service_params p = {
    .name          = "myservice",
    .ops           = &ops,
    .queue_depth   = 64,         /* 0 = 256, max 4096 */
    .tx_limit      = 128,        /* 0 = 256, max 4096 */
    .instance_limit = 512,       /* 0 = 1024, max 1M */
    .flags         = CAP_RT_SVC_NOXFER, /* non-transferable */
};
```

### Tunables

| Parameter | Default | Max | Description |
|---|---|---|---|
| `msg_size` | 16384 | 16384 | Fixed message size (4 pages) |
| `queue_depth` | 256 | 4096 | RX queue depth (async only) |
| `tx_limit` | 256 | 4096 | TX soft limit for notifications |
| `instance_limit` | 1024 | 1M | Max concurrent instances |
| `CAP_RT_MAX_FDS` | 16 | 16 | Max fds per message (compile-time) |
| TX hard limit | 4x queue_depth | -- | TX hard limit, prevents unbounded growth |

### Service flags

| Flag | Effect |
|---|---|
| `CAP_RT_SVC_NOXFER` | Instances cannot be passed via SCM_RIGHTS |

## Advanced: deferred replies

Most handlers reply inline and return.  If the handler needs to
defer work (long crypto, disk I/O), it can reply later:

```c
static int
myservice_handler(struct cap_rt_instance *s, const struct cap_rt_msg *msg,
    void *arg)
{
    struct work *w = alloc_work();
    w->instance = s;
    w->token = cap_rt_msg_token(msg);
    memcpy(w->data, cap_rt_msg_data(msg), cap_rt_msg_datalen(msg));

    /* Hold the instance so close doesn't free it. */
    cap_rt_instance_hold(s);
    taskqueue_enqueue(my_tq, &w->task);
    return (0);
}

/* Later, on a different thread: */
static void
deferred_task(void *ctx, int pending)
{
    struct work *w = ctx;
    uint32_t result = compute(w->data, w->datalen);
    cap_rt_reply(w->instance, w->token,
        &result, sizeof(result), NULL, NULL, 0);
    cap_rt_instance_rele(w->instance);
    free_work(w);
}
```

`cap_rt_instance_hold()` prevents close from freeing the instance.
`cap_rt_instance_rele()` releases the hold.  `co_revoke` fires
only after all holds are released.

Most services don't need this.

## Headers

- **cap_rt.h** -- public API for service modules (opaque types, accessors)
- **cap_rt_ioctl.h** -- shared kernel/userspace ioctl definitions
- **cap_rt_label.h** -- program nonce accessor (`cap_rt_proc_nonce`)
- **cap_rt_internal.h** -- framework internals (not for service modules)
- **cap_rt_capprotect_proto.h** -- capability protection wire protocol
- **cap_rt_test_kernelstore_proto.h** -- test fixture: kernelstore wire protocol
- **cap_rt_test_keystore_proto.h** -- test fixture: keystore wire protocol

---

# System Developer Guide

## Connecting

```c
#include "cap_rt_ioctl.h"

int ctl = open("/dev/cap_rt", O_RDWR);
struct cap_rt_connect_args ca = {0};
strlcpy(ca.name, "myservice", sizeof(ca.name));
ioctl(ctl, CAP_RT_CONNECT, &ca);
close(ctl);

int cap = ca.fd;   /* this is your capability */
```

After connecting, you never need /dev/cap_rt again.  The capability
fd can be passed via SCM_RIGHTS (unless `CAP_RT_SVC_NOXFER`), inherited
across fork, or restricted via Capsicum.

## Sending a message (async services)

```c
struct cap_rt_sendmsg_args sa = {0};
sa.payload = &request;
sa.payload_len = sizeof(request);
sa.reply_token = my_request_id;   /* optional correlation */
ioctl(cap, CAP_RT_SENDMSG, &sa);
```

Returns immediately.  EAGAIN if the queue is full -- use
kqueue(EVFILT_WRITE) to wait.  EOPNOTSUPP if the service is
sync-only.

## Receiving a message (async services)

```c
char buf[4096];
struct cap_rt_recvmsg_args ra = {0};
ra.payload = buf;
ra.payload_len = sizeof(buf);
ioctl(cap, CAP_RT_RECVMSG, &ra);
/* ra.payload_len = actual bytes received */
/* ra.reply_token = correlation token from request */
/* ra.badge = sender's badge */
/* ra.trailer = sender credentials */
```

Blocks until a message is available.  EAGAIN with O_NONBLOCK.
EMSGSIZE if the payload buffer is too small (message stays queued
for retry).

## Synchronous call (sync services)

```c
struct ns_request req = { .op = NS_OP_INFO };
char reply_buf[512];
int recv_fds[4];
struct cap_rt_call_args ca = {0};
ca.req = &req;
ca.req_len = sizeof(req);
ca.reply = reply_buf;
ca.reply_len = sizeof(reply_buf);
ca.reply_fds = recv_fds;     /* optional: receive fds from handler */
ca.reply_nfds = 4;           /* max fds to receive */
ioctl(cap, CAP_RT_CALL, &ca);
/* ca.reply_len = actual reply size */
/* ca.reply_nfds = actual fds received */
/* ca.trailer = caller's kernel-attested credentials */
```

CALL returns directly -- no separate RECVMSG needed.  Returns
EOPNOTSUPP if the service is async-only.  Returns EMSGSIZE
(with `ca.reply_len` set to the required size) if the reply
buffer is too small -- same contract as RECVMSG.

## Revoking a capability

From userspace, either close the fd or terminate the instance:

```c
/* Option 1: close — instance dies when last handle closes */
close(cap);

/* Option 2: terminate — instance dies immediately for all holders */
ioctl(cap, CAP_RT_TERMINATE, NULL);
```

`CAP_RT_TERMINATE` kills the instance regardless of how many handles
exist.  All holders get ECONNRESET.  Works on both async and sync
services, and works even if CAP_RT_REVOKE_* restrictions are set.

## Attaching file descriptors

```c
int shm_fd = shm_open(SHM_ANON, O_RDWR, 0);
struct cap_rt_sendmsg_args sa = {0};
sa.payload = &request;
sa.payload_len = sizeof(request);
sa.fds = &shm_fd;
sa.nfds = 1;
ioctl(cap, CAP_RT_SENDMSG, &sa);
```

Attached fds preserve Capsicum rights.  Non-passable descriptor
types are rejected.  Up to `CAP_RT_MAX_FDS` (16) per message.

## Querying service info

```c
struct cap_rt_info_args info;
ioctl(cap, CAP_RT_GETINFO, &info);
/* info.name      -- service name */
/* info.badge     -- this instance's badge */
/* info.msg_limit -- max payload bytes */
/* info.features  -- CAP_RT_INFO_F_* bitmask */
```

Feature bits:

| Bit | Meaning |
|---|---|
| `CAP_RT_INFO_F_SENDMSG` | Async messaging supported |
| `CAP_RT_INFO_F_CALL` | Synchronous call supported |
| `CAP_RT_INFO_F_KQUEUE` | EVFILT_READ/WRITE supported |

A service has either `SENDMSG+KQUEUE` (async) or `CALL` (sync),
never both.

## Event loop integration

```c
EV_SET(&kev, cap, EVFILT_READ, EV_ADD, 0, 0, NULL);   /* msg ready */
EV_SET(&kev, cap, EVFILT_WRITE, EV_ADD, 0, 0, NULL);   /* can send */
```

EV_EOF fires via kqueue when the capability is revoked.
Only meaningful for async services.

## Capsicum

Restrict which operations a capability fd can perform:

```c
unsigned long send_only[] = { CAP_RT_SENDMSG };
cap_ioctls_limit(cap, send_only, 1);
```

## Delegation

- **fork** -- child inherits the fd
- **dup** -- shares the same capability (same queues)
- **SCM_RIGHTS** -- pass to any process (unless `CAP_RT_SVC_NOXFER`)

## Error summary

| Error | Context | Meaning |
|---|---|---|
| EAGAIN | SENDMSG | RX queue full |
| EAGAIN | RECVMSG + O_NONBLOCK | No message |
| EMSGSIZE | SENDMSG | Payload too large |
| EMSGSIZE | RECVMSG | Buffer too small (reply_len = required) |
| EMSGSIZE | CALL | Reply buffer too small (reply_len = required) |
| EPIPE | SENDMSG | Instance dead |
| ECONNRESET | RECVMSG / CALL | Instance revoked |
| EOPNOTSUPP | SENDMSG on sync service | Wrong API |
| EOPNOTSUPP | CALL on async service | Wrong API |
| ENOENT | CONNECT | Service not registered |
| ECONNABORTED | CONNECT | Service unloading |
| ENOBUFS | (internal) | TX queue hard limit reached |
| EACCES | SENDMSG / RECVMSG / CALL | Operation restricted via CAP_RT_REVOKE_* |

## Security

`/dev/cap_rt` is mode 0600 (root only).  Unprivileged processes cannot
connect to services directly.  A broker daemon connects on their
behalf and passes capability fds via SCM_RIGHTS.

Capabilities can be attenuated before delegation:
- `CAP_RT_LOCK` prevents further SCM_RIGHTS passing
- `CAP_RT_REVOKE_SEND` / `CAP_RT_REVOKE_RECV` / `CAP_RT_REVOKE_CALL` strip operations
- `cap_ioctls_limit` restricts which ioctls the holder can perform

These compose: lock the capability, strip send, restrict to RECVMSG+GETINFO
only, then pass it.  The recipient can receive notifications but nothing else.

---

## Source layout

```
sys/dev/cap_rt/
    cap_rt.h              public kernel API
    cap_rt_internal.h     framework internals
    cap_rt_ioctl.h        shared ioctl definitions
    cap_rt_core.c         module lifecycle, capability creation
    cap_rt_dev.c          capability operations (ioctls, kqueue, close)
    cap_rt_kern.c         KPI: dispatch, reply/notify/revoke
    cap_rt_capprotect.c          capability protection (ptrace/signal/visibility via MACF)
    cap_rt_label.h               public header: cap_rt_proc_nonce() accessor
    cap_rt_pair.c                bidirectional capability pair
    cap_rt_test_kernelstore.c    test fixture: sync key-value store
    cap_rt_test_keystore.c       test fixture: async key-value store

sys/modules/cap_rt/                 core module
sys/modules/cap_rt_capprotect/      capability protection
sys/modules/cap_rt_pair/            capability pair
sys/modules/cap_rt_test_kernelstore/ test fixture: sync key-value store
sys/modules/cap_rt_test_keystore/   test fixture: async key-value store

tests/sys/cap_rt/             116 ATF tests via kyua
```

## Base system changes

- `DTYPE_CAP_RT` (17) in sys/sys/file.h
- `KF_TYPE_CAP_RT` (17) in sys/sys/user.h
- `CAP_CAP_RT_SEND` / `CAP_CAP_RT_RECV` in sys/sys/capsicum.h (reserved)

## Exported kernel API

### Service lifecycle
- `cap_rt_service_create(params, &svc)` -- register a service
- `cap_rt_service_destroy(svc)` -- unregister and drain

### Messaging (from co_handler or sleeping context)
- `cap_rt_reply(s, token, data, len, fds, fcaps, nfds)` -- reply to a message
- `cap_rt_notify(s, data, len, fds, fcaps, nfds)` -- push notification

### Instance management
- `cap_rt_instance_revoke(s)` -- tear down instance
- `cap_rt_instance_hold(s)` / `cap_rt_instance_rele(s)` -- deferred work refcount
- `cap_rt_instance_set_priv(s, priv)` / `cap_rt_instance_get_priv(s)` -- per-instance data
- `cap_rt_instance_get_badge(s)` -- service-assigned badge

### Program identity (built into cap_rt core)
- `cap_rt_proc_nonce(cred)` -- return 8-byte cryptographic nonce for a credential

The nonce identifies the program image.  It is kernel-assigned,
not settable by userspace.  Inherited across fork (same program),
rotated on exec (new program).  Services use it instead of pid.
The nonce rides in the credential trailer on every async message
(`trailer.nonce`).  Zero is reserved as "not available" and is
never generated.

The nonce is implemented as a MACF credential label inside the
cap_rt core module.  The internal struct is hidden behind the
accessor — fields may be added without changing consumers.

### Minting
- `cap_rt_mint_fp(svc, badge, &fp)` -- create new capability from handler

### Message accessors
- `cap_rt_msg_data(msg)`, `cap_rt_msg_datalen(msg)`
- `cap_rt_msg_fds(msg)`, `cap_rt_msg_fcaps(msg)`, `cap_rt_msg_nfds(msg)`
- `cap_rt_msg_badge(msg)`, `cap_rt_msg_token(msg)`
- `cap_rt_msg_cred(msg)`

## DTrace probes

Provider: `cap_rt`

| Probe | Args |
|---|---|
| `connect` | service name, badge, pid |
| `send` | service name, badge, payload len |
| `recv` | service name, badge, payload len |
| `dispatch` | service name, badge |
| `reply` | service name, badge, payload len |
| `notify` | service name, badge, payload len |
| `call` | service name, badge, req len |
| `revoke` | service name, badge, reason |
| `close` | service name, badge |

## Sysctls

| Sysctl | Type | Description |
|---|---|---|
| `kern.cap_rt.services` | counter | Number of registered services |
| `kern.cap_rt.instances` | counter | Number of active instances |

---

## Roadmap

### Phase 1: Capability Protection (DONE)

CAP_RT sync service (`cap_rt_capprotect`) backed by MACF.  Selective
process integrity protection via flags: ptrace, signals, SIGKILL,
SIGCONT, visibility, wait.  Same-nonce (fork family) freely
interacts; foreign programs (different nonce) are blocked.  Access
tokens grant foreign programs authorized access through the shield.
Close removes protection.

### Phase 2: Namespace service (REMOVED)

The `cap_rt_namespace` service was removed.  Namespace management is
better handled by `jaildesc` which provides direct jail descriptor
support without duplicating jail configuration in a CAP_RT protocol.

### Phase 3: Token capability (REMOVED)

The `cap_rt_token` service was removed.  Any CAP_RT capability fd already
proves kernel-granted authorization; a dedicated token service
added no value beyond what the fd itself provides.

### Phase 4: Program identity — nonce (DONE)

Built into the cap_rt core module as a MACF credential label.
8-byte cryptographic nonce (`arc4random_buf`, zero excluded).
Identifies the program image: inherited across fork, rotated
on exec.  Accessible via `cap_rt_proc_nonce(cred)`.

Removed pid from the framework:
- `cm_pid` removed from internal message struct
- `cap_rt_msg_pid()` removed from kernel API
- `pid` removed from credential trailer (replaced by `nonce`)
- `issuer_pid` removed from token validate reply
- `cap_rt_capprotect` shield/auth tables keyed by nonce, not pid
- Instance `id` removed (badge is the only per-instance identifier)

### Phase 5: KernelStore — shared capability store (DONE)

Added `cap_rt_kernelstore` — sync CAP_RT service.  Shared key-value
store where the capability fd IS the credential.  Connect
creates a new empty store.  Owner can MINT member fds to share
access.  All holders PUT/GET/DELETE on the same backing store.
Last close destroys the data.  Revoke via CAP_RT_TERMINATE on the
member fd.  256 keys max, 4096 bytes per value, string keys.

### 3. Kernel-to-kernel capability communication

We removed `cap_rt_send` because services shouldn't talk to
each other directly — the holder composes.  But there are
real cases where a service needs to operate on a capability
it was given:

- A proxy service forwards messages on a passed-in capability
- A supervisor service terminates capabilities in a coalition
- A broker mints capabilities on behalf of the caller

The question: should this be message-based (reintroduce
`cap_rt_send` with clear constraints) or should it be a
different mechanism (direct instance-to-instance calls)?
Or should the holder always mediate — pass the results
back through the holder's thread?

This needs design before code.  The wrong answer creates
a capability system where services bypass the holder's
authority.
