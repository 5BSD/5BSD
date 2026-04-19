# CMI -- Capability Message Interface

CMI is a generic messaging interface for building capabilities on
FreeBSD.  It supports async and sync messaging to kernel services
(via loadable modules) and userspace-to-userspace IPC (via capability
pairs).  All communication flows through file descriptors that are
Capsicum-aware, kqueue-integrated, and delegable via fork, dup, or
SCM_RIGHTS.

## The problem CMI solves

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

**CMI replaces all of this with one base system change** (`DTYPE_CMI`,
two reserved Capsicum rights, one device node) that enables unlimited
kernel services as loadable modules.  No new syscalls, no new DTYPEs,
no new `CAP_*` bits per service.  A service author writes message
handlers in a kernel module, loads it, and userspace connects via
`/dev/cmi`.

For userspace-to-userspace IPC, the `cmi_pair` module provides
bidirectional capability channels -- similar to `socketpair(2)` but
as capability descriptors that can be restricted with
`cap_ioctls_limit()` and revoked by closing one end.

CMI coexists with the socket API.  Like Apple (Mach ports + BSD
sockets) and Android (Binder + sockets), FreeBSD gets both: sockets
for network and traditional IPC, CMI for structured capability-based
messaging.

---

## Design rules

1. **A service is async OR sync, never both.**  Pick `co_handler`
   (async, taskqueue dispatch) or `co_call` (sync, caller's thread).
   The framework rejects services that set both.

2. **Messages are the interface.**  Every operation goes through
   `CMI_SENDMSG`/`CMI_RECVMSG` (async) or `CMI_CALL` (sync).
   No direct struct access from userspace.  Kernel-to-kernel
   messaging uses `cmi_send()`.

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
CMI_SENDMSG  ------>  RX queue  ------>  taskqueue  ----->  co_handler()
                                                                  |
CMI_RECVMSG  <------  TX queue  <------  cmi_reply()  <--------+
```

Two queues per instance (like Mach ports, like NIC ring buffers):
- **RX queue**: userspace → kernel.  `CMI_SENDMSG` enqueues, returns immediately.
- **TX queue**: kernel → userspace.  `CMI_RECVMSG` dequeues, blocks if empty.

### Sync model (co_call)

```
userspace                    kernel
---------                    ------
CMI_CALL  -------->  co_call() runs in caller's thread  -------->  return
```

No queues.  The handler runs as the calling process -- it can
`jail_attach`, `cap_enter`, modify credentials.

---

# Kernel Developer Guide

## Writing a service

A CMI service is a kernel module with one callback -- `co_handler`
(async) or `co_call` (sync), never both:

```c
#include "cmi.h"
MODULE_DEPEND(echo, cmi, 1, 1, 1);

static int
echo_handler(struct cmi_instance *s, const struct cmi_msg *msg,
    void *arg)
{
    return (cmi_reply(s, cmi_msg_token(msg),
        cmi_msg_data(msg), cmi_msg_datalen(msg),
        NULL, NULL, 0));
}

static const struct cmi_ops echo_ops = {
    .co_handler = echo_handler,
};

static struct cmi_service *svc;

static int
echo_modevent(module_t mod, int type, void *arg)
{
    switch (type) {
    case MOD_LOAD: {
        struct cmi_service_params p = {
            .name = "echo",
            .ops  = &echo_ops,
        };
        return (cmi_service_create(&p, &svc));
    }
    case MOD_UNLOAD:
        cmi_service_destroy(svc);
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
| `co_connect` | `CMI_CONNECT`, before instance exists | Caller | Yes |
| `co_init` | After creation, before fd visible | Caller | Yes |
| `co_handler` | Async message dispatch | Taskqueue | Yes (auto-error-reply) |
| `co_call` | Sync call in caller's context | Caller | Yes |
| `co_revoke` | Instance dying, after all work drains | Varies | No (void) |
| `co_fdclose` | Specific fd closed, instance may survive | Caller | No (void) |

All are optional except one of `co_handler` or `co_call`.

### Revocation reasons

| Reason | Meaning |
|---|---|
| `CMI_REVOKE_PEER_CLOSED` | Userspace called `close()` |
| `CMI_REVOKE_BY_SERVICE` | Service called `cmi_instance_revoke()` or userspace sent `CMI_TERMINATE` |
| `CMI_REVOKE_UNLOAD` | Module unload via `cmi_service_destroy()` |

## The async handler

`co_handler` is called from a per-service taskqueue.  One message
at a time per instance (never concurrent).  May sleep.  No framework
locks held.

Access the message through accessors -- the struct is opaque:

```c
cmi_msg_data(msg)      /* payload bytes */
cmi_msg_datalen(msg)   /* payload length */
cmi_msg_token(msg)     /* correlation token set by sender */
cmi_msg_fds(msg)       /* attached file pointers */
cmi_msg_fcaps(msg)     /* Capsicum rights on attached fds */
cmi_msg_nfds(msg)      /* number of attached fds */
cmi_msg_badge(msg)     /* this instance's badge */
cmi_msg_cred(msg)      /* sender credentials at send time */
cmi_msg_pid(msg)       /* sender PID at send time */
```

**Return 0** after calling `cmi_reply()` to send a response.
**Return 0** without replying for fire-and-forget messages.
**Return nonzero** to have the framework send an error reply.

The message is valid only during the call.  Copy what you need.

## Replying

```c
cmi_reply(s, cmi_msg_token(msg), data, len, fds, fcaps, nfds);
```

- `fds`: file pointers to attach.  NULL if none.
- `fcaps`: Capsicum rights to preserve on those fds.  NULL = full rights.
- `cmi_msg_token(msg)`: pass the sender's token back for correlation.

## Notifications

Push an unsolicited message to userspace (async services only):

```c
cmi_notify(s, data, len, fds, fcaps, nfds);
```

Returns EAGAIN above the soft limit.  No reply token.

## Badges

The badge is a uint64_t assigned by `co_connect` at instance creation.
It's stamped on every inbound message.  The handler sees it via
`cmi_msg_badge(msg)`.  Use it to identify which client sent a
message.  Typical values: monotonic counter, hash key, user ID.

## Instance private data

```c
cmi_instance_set_priv(s, my_state);
struct my_state *st = cmi_instance_get_priv(s);
```

Set in `co_init`, freed in `co_revoke`.

## Revocation

Tear down an instance from the service side:

```c
cmi_instance_revoke(s);
```

The peer's next RECVMSG returns ECONNRESET.  `co_revoke` fires.
Safe to call from inside `co_handler` (self-revoke).
Do NOT call from inside `co_call`.

Userspace can terminate the instance for all holders:

```c
ioctl(fd, CMI_TERMINATE, NULL);
```

The instance dies, all handles get ECONNRESET.  `co_revoke`
fires.  Works regardless of any CMI_REVOKE_* restrictions.

## Granular revoke

Strip individual operations from a capability without killing
the instance.  One-way latch -- once revoked, can't be restored.
Affects the instance (all handles/dups).

```c
ioctl(fd, CMI_REVOKE_SEND, NULL);   /* SENDMSG → EACCES */
ioctl(fd, CMI_REVOKE_RECV, NULL);   /* RECVMSG → EACCES */
ioctl(fd, CMI_REVOKE_CALL, NULL);   /* CALL → EACCES */
```

GETINFO always works.  `CMI_TERMINATE` always works (it's
a control operation, not a message).

Use case: pass a capability to a process but restrict it to
receive-only (revoke send + call before passing).

## Preventing delegation (CMI_LOCK)

Permanently prevent a capability fd from being passed via
SCM_RIGHTS.  One-way latch.

```c
ioctl(fd, CMI_LOCK, NULL);
/* sendmsg(SCM_RIGHTS) now fails for this fd */
/* fork still inherits, dup still works */
```

Services can also set `CMI_SVC_NOXFER` at creation time to
make all instances non-transferable from birth.

## Minting new capabilities

Create an instance and return it as an attached fd in a reply:

```c
struct file *fp;
cmi_mint_fp(svc, badge, &fp);
cmi_reply(s, token, NULL, 0, &fp, NULL, 1);
fdrop(fp, curthread);
```

This is how services return new capabilities to clients.  The
cmi_pair sample demonstrates this pattern.

## Kernel-to-kernel messaging

Kernel modules can send messages to capabilities they hold:

```c
int cmi_send(struct file *fp, const void *data, size_t datalen,
    struct file **fds, struct filecaps *fcaps, int nfds,
    uint64_t reply_token);
```

`fp` must be a `DTYPE_CMI` file.  The message enqueues on the
target's RX queue and flows through the normal dispatch path.
No copyin -- data is already in kernel memory.  Credentials
are stamped as `curthread`'s ucred.

This is how kernel modules talk to each other through capabilities
instead of direct function calls.  The target service doesn't need
to know whether the sender is userspace or kernel.

## Service parameters

```c
struct cmi_service_params p = {
    .name          = "myservice",
    .ops           = &ops,
    .msg_size      = 16384,      /* 0 = 8192, max 64MB */
    .queue_depth   = 64,         /* 0 = 256, max 4096 */
    .tx_limit      = 128,        /* 0 = 256, max 4096 */
    .instance_limit = 512,       /* 0 = 1024, max 1M */
    .flags         = CMI_SVC_NOXFER, /* non-transferable */
};
```

### Tunables

| Parameter | Default | Max | Description |
|---|---|---|---|
| `msg_size` | 8192 | 64 MB | Max payload per message |
| `queue_depth` | 256 | 4096 | RX queue depth (async only) |
| `tx_limit` | 256 | 4096 | TX soft limit for notifications |
| `instance_limit` | 1024 | 1M | Max concurrent instances |
| `CMI_MAX_FDS` | 16 | 16 | Max fds per message (compile-time) |
| TX hard limit | 4x queue_depth | -- | TX hard limit, prevents unbounded growth |

### Service flags

| Flag | Effect |
|---|---|
| `CMI_SVC_NOXFER` | Instances cannot be passed via SCM_RIGHTS |

## Advanced: deferred replies

Most handlers reply inline and return.  If the handler needs to
defer work (long crypto, disk I/O), it can reply later:

```c
static int
myservice_handler(struct cmi_instance *s, const struct cmi_msg *msg,
    void *arg)
{
    struct work *w = alloc_work();
    w->instance = s;
    w->token = cmi_msg_token(msg);
    memcpy(w->data, cmi_msg_data(msg), cmi_msg_datalen(msg));

    /* Hold the instance so close doesn't free it. */
    cmi_instance_hold(s);
    taskqueue_enqueue(my_tq, &w->task);
    return (0);
}

/* Later, on a different thread: */
static void
deferred_task(void *ctx, int pending)
{
    struct work *w = ctx;
    uint32_t result = compute(w->data, w->datalen);
    cmi_reply(w->instance, w->token,
        &result, sizeof(result), NULL, NULL, 0);
    cmi_instance_rele(w->instance);
    free_work(w);
}
```

`cmi_instance_hold()` prevents close from freeing the instance.
`cmi_instance_rele()` releases the hold.  `co_revoke` fires
only after all holds are released.

Most services don't need this.

## Headers

- **cmi.h** -- public API for service modules (opaque types, accessors)
- **cmi_ioctl.h** -- shared kernel/userspace ioctl definitions
- **cmi_internal.h** -- framework internals (not for service modules)

---

# System Developer Guide

## Connecting

```c
#include "cmi_ioctl.h"

int ctl = open("/dev/cmi", O_RDWR);
struct cmi_connect_args ca = {0};
strlcpy(ca.name, "myservice", sizeof(ca.name));
ioctl(ctl, CMI_CONNECT, &ca);
close(ctl);

int cap = ca.fd;   /* this is your capability */
```

After connecting, you never need /dev/cmi again.  The capability
fd can be passed via SCM_RIGHTS (unless `CMI_SVC_NOXFER`), inherited
across fork, or restricted via Capsicum.

## Sending a message (async services)

```c
struct cmi_sendmsg_args sa = {0};
sa.payload = &request;
sa.payload_len = sizeof(request);
sa.reply_token = my_request_id;   /* optional correlation */
ioctl(cap, CMI_SENDMSG, &sa);
```

Returns immediately.  EAGAIN if the queue is full -- use
kqueue(EVFILT_WRITE) to wait.  EOPNOTSUPP if the service is
sync-only.

## Receiving a message (async services)

```c
char buf[4096];
struct cmi_recvmsg_args ra = {0};
ra.payload = buf;
ra.payload_len = sizeof(buf);
ioctl(cap, CMI_RECVMSG, &ra);
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
struct my_request req = { .op = JAIL_ATTACH, .jid = 42 };
int recv_fds[4];
struct cmi_call_args ca = {0};
ca.req = &req;
ca.req_len = sizeof(req);
ca.reply = reply_buf;
ca.reply_len = sizeof(reply_buf);
ca.reply_fds = recv_fds;     /* optional: receive fds from handler */
ca.reply_nfds = 4;           /* max fds to receive */
ioctl(cap, CMI_CALL, &ca);
/* ca.reply_nfds = actual fds received */
```

CALL returns directly -- no separate RECVMSG needed.  Returns
EOPNOTSUPP if the service is async-only.

## Revoking a capability

From userspace, either close the fd or terminate the instance:

```c
/* Option 1: close — instance dies when last handle closes */
close(cap);

/* Option 2: terminate — instance dies immediately for all holders */
ioctl(cap, CMI_TERMINATE, NULL);
```

`CMI_TERMINATE` kills the instance regardless of how many handles
exist.  All holders get ECONNRESET.  Works on both async and sync
services, and works even if CMI_REVOKE_* restrictions are set.

## Attaching file descriptors

```c
int shm_fd = shm_open(SHM_ANON, O_RDWR, 0);
struct cmi_sendmsg_args sa = {0};
sa.payload = &request;
sa.payload_len = sizeof(request);
sa.fds = &shm_fd;
sa.nfds = 1;
ioctl(cap, CMI_SENDMSG, &sa);
```

Attached fds preserve Capsicum rights.  Non-passable descriptor
types are rejected.  Up to `CMI_MAX_FDS` (16) per message.

## Querying service info

```c
struct cmi_info_args info;
ioctl(cap, CMI_GETINFO, &info);
/* info.name      -- service name */
/* info.badge     -- this instance's badge */
/* info.id        -- unique instance ID */
/* info.msg_limit -- max payload bytes */
/* info.features  -- CMI_INFO_F_* bitmask */
```

Feature bits:

| Bit | Meaning |
|---|---|
| `CMI_INFO_F_SENDMSG` | Async messaging supported |
| `CMI_INFO_F_CALL` | Synchronous call supported |
| `CMI_INFO_F_KQUEUE` | EVFILT_READ/WRITE supported |

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
unsigned long send_only[] = { CMI_SENDMSG };
cap_ioctls_limit(cap, send_only, 1);
```

## Delegation

- **fork** -- child inherits the fd
- **dup** -- shares the same capability (same queues)
- **SCM_RIGHTS** -- pass to any process (unless `CMI_SVC_NOXFER`)

## Error summary

| Error | Context | Meaning |
|---|---|---|
| EAGAIN | SENDMSG | RX queue full |
| EAGAIN | RECVMSG + O_NONBLOCK | No message |
| EMSGSIZE | SENDMSG | Payload too large |
| EMSGSIZE | RECVMSG | Buffer too small |
| EPIPE | SENDMSG | Instance dead |
| ECONNRESET | RECVMSG / CALL | Instance revoked |
| EOPNOTSUPP | SENDMSG on sync service | Wrong API |
| EOPNOTSUPP | CALL on async service | Wrong API |
| ENOENT | CONNECT | Service not registered |
| ECONNABORTED | CONNECT | Service unloading |
| ENOBUFS | (internal) | TX queue hard limit reached |
| EACCES | SENDMSG / RECVMSG / CALL | Operation restricted via CMI_REVOKE_* |

## Security

`/dev/cmi` is mode 0600 (root only).  Unprivileged processes cannot
connect to services directly.  A broker daemon connects on their
behalf and passes capability fds via SCM_RIGHTS.

Capabilities can be attenuated before delegation:
- `CMI_LOCK` prevents further SCM_RIGHTS passing
- `CMI_REVOKE_SEND` / `CMI_REVOKE_RECV` / `CMI_REVOKE_CALL` strip operations
- `cap_ioctls_limit` restricts which ioctls the holder can perform

These compose: lock the capability, strip send, restrict to RECVMSG+GETINFO
only, then pass it.  The recipient can receive notifications but nothing else.

---

## Source layout

```
sys/dev/cmi/
    cmi.h              public kernel API
    cmi_internal.h     framework internals
    cmi_ioctl.h        shared ioctl definitions
    cmi_core.c         module lifecycle, capability creation
    cmi_dev.c          capability operations (ioctls, kqueue, close)
    cmi_kern.c         KPI: dispatch, reply/notify/revoke, cmi_send
    cmi_debug.c        cap_debug: process protection via MACF
    cmi_keystore.c     async test fixture: key-value store
    cmi_namespace.c    namespace management (create, nest, remove)
    cmi_pair.c         bidirectional capability pair
    cmi_token.c        kernel-gated authorization tokens

sys/modules/cmi/           core module
sys/modules/cmi_debug/     debug shield
sys/modules/cmi_keystore/  keystore test fixture
sys/modules/cmi_namespace/ namespace management
sys/modules/cmi_pair/      capability pair
sys/modules/cmi_token/     authorization token

tests/sys/cmi/             116 ATF tests via kyua
```

## Base system changes

- `DTYPE_CMI` (17) in sys/sys/file.h
- `KF_TYPE_CMI` (17) in sys/sys/user.h
- `CAP_CMI_SEND` / `CAP_CMI_RECV` in sys/sys/capsicum.h (reserved)

## Exported kernel API

### Service lifecycle
- `cmi_service_create(params, &svc)` -- register a service
- `cmi_service_destroy(svc)` -- unregister and drain

### Messaging (from co_handler or sleeping context)
- `cmi_reply(s, token, data, len, fds, fcaps, nfds)` -- reply to a message
- `cmi_notify(s, data, len, fds, fcaps, nfds)` -- push notification
- `cmi_send(fp, data, len, fds, fcaps, nfds, token)` -- kernel-side send

### Instance management
- `cmi_instance_revoke(s)` -- tear down instance
- `cmi_instance_hold(s)` / `cmi_instance_rele(s)` -- deferred work refcount
- `cmi_instance_set_priv(s, priv)` / `cmi_instance_get_priv(s)` -- per-instance data
- `cmi_instance_get_badge(s)` / `cmi_instance_get_id(s)` -- identity

### Minting
- `cmi_mint_fp(svc, badge, &fp)` -- create new capability from handler

### Message accessors
- `cmi_msg_data(msg)`, `cmi_msg_datalen(msg)`
- `cmi_msg_fds(msg)`, `cmi_msg_fcaps(msg)`, `cmi_msg_nfds(msg)`
- `cmi_msg_badge(msg)`, `cmi_msg_token(msg)`
- `cmi_msg_cred(msg)`, `cmi_msg_pid(msg)`

## DTrace probes

Provider: `cmi`

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
| `kern.cmi.services` | counter | Number of registered services |
| `kern.cmi.instances` | counter | Number of active instances |

---

## Roadmap

### Phase 1: cap_debug — process debug protection (DONE)

CMI sync service (`cmi_debug`) backed by MACF.  Shield protects
from ptrace/signals.  Debug tokens authorize specific debuggers.
Close removes protection.  Per-instance mutex for safety.

### Phase 2: Rename jail → namespace (DONE)

Renamed `cmi_jail` to `cmi_namespace`.  Service name is now
"namespace" instead of "jail".

### Phase 3: Token capability (DONE)

Added `cmi_token` — kernel-gated authorization tokens.  Issuers
create labeled tokens that prove authorization.  Tokens can be
validated, revoked, and passed.  dup shares the same instance.

### Phase 4: Kernel-to-kernel messaging tests

Add a test service (`cmi_proxy`) that receives a capability fd
in a message and uses `cmi_send()` to send a message on it.
Proves kernel modules can talk to each other through capabilities.

### Phase 5: Migrate Keyvault to CMI

Migrate the Keyvault kernel module (~/Projects/Keyvault) to use
CMI as its transport.  Sync service — key operations are
request-reply in caller context.  Capability fd = authority to
use a key.  Eliminates custom /dev/ and ioctl boilerplate.
