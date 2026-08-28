# MAC_CAPABILITY -- Capability Message Interface

## Design Stance

mac_capability is a **capability transport, supervision, and policy substrate**
for BSD sandboxes.  It is a generic messaging interface for building
capabilities on FreeBSD, supporting async and sync messaging to kernel
services (via loadable modules) and userspace-to-userspace IPC (via
capability pairs).

All communication flows through file descriptors that are
Capsicum-aware, kqueue-integrated, and delegable via fork, dup, or
SCM_RIGHTS.

mac_capability is **not** intended to be a microkernel IPC substrate, a
remote-object runtime, or a Binder/Mach clone.  It centers on:

- Capability file descriptors as the unit of authority
- Explicit delegation and narrowing
- Kernel-stamped identity and credential metadata
- Revocation, supervision, and policy enforcement

The runtime does **not** currently aim to provide general remote
object references, port-right algebra, VM-integrated message passing,
or IDL-generated RPC machinery.

## The Problem MAC_CAPABILITY Solves

Adding a new Capsicum-aware kernel service to FreeBSD today requires
touching the base system in multiple places:

1. **New capability rights** in `sys/sys/capsicum.h` -- every new
   operation needs a `CAP_*` constant from a finite bitspace (57 bits
   per index).
2. **New descriptor type** in `sys/sys/file.h` -- a new `DTYPE_*`,
   new `struct fileops`, and all the boilerplate.
3. **New syscall** (often) -- entry in `syscalls.master`, handler,
   userspace wrapper.
4. **procstat support** in `usr.bin/procstat` and `lib/libprocstat`.
5. **Manual queue/lock/lifecycle code** -- every service reinvents
   message queuing, reference counting, teardown ordering, and
   credential handling.

**MAC_CAPABILITY replaces all of this with one base system change** (`DTYPE_MAC_CAPABILITY`,
standard Capsicum rights with ioctl limits, one device node) that enables unlimited
kernel services as loadable modules.  No new syscalls, no new DTYPEs,
no new `CAP_*` bits per service.

MAC_CAPABILITY coexists with the socket API.  Like Apple (Mach ports + BSD
sockets) and Android (Binder + sockets), FreeBSD gets both: sockets
for network and traditional IPC, MAC_CAPABILITY for structured capability-based
messaging.

---

## Design Rules

1. **A service implements `co_handler`, `co_call`, or both.**
   `co_handler` handles async messages (taskqueue dispatch).
   `co_call` handles sync calls (caller's thread).  Most services
   use one or the other, but both can be provided when a service
   needs sync operations alongside async messaging.
2. **Messages are the interface.**  Every operation goes through
   `MAC_CAPABILITY_SENDMSG`/`MAC_CAPABILITY_RECVMSG` (async) or `MAC_CAPABILITY_CALL` (sync).
   No direct struct access from userspace.
3. **The framework owns the descriptor.**  Services never touch
   `falloc`, `finit`, `finstall`, `fileops`, or `DTYPE_*`.

---

## How It Works

A capability is a file descriptor connected to a kernel service.
Userspace sends messages through the fd.  The kernel dispatches
them to the service's handler.

### Async model (co_handler)

```
userspace                    kernel
---------                    ------
MAC_CAPABILITY_SENDMSG  ------>  RX queue  ------>  taskqueue  ----->  co_handler()
                                                                  |
MAC_CAPABILITY_RECVMSG  <------  TX queue  <------  mac_capability_reply()  <--------+
```

Two queues per instance: RX (userspace to kernel) and TX (kernel to
userspace).

### Sync model (co_call)

```
userspace                    kernel
---------                    ------
MAC_CAPABILITY_CALL  -------->  co_call() runs in caller's thread  -------->  return
```

No queues.  The handler runs as the calling process.

---

## Identity

Every credential carries a 64-bit **nonce** (program identity):
- Inherited across fork (same program)
- Rotated on exec (new program)
- Kernel-assigned; userspace cannot set or forge it

The nonce is implemented as a MACF credential label inside the
mac_capability core module.  Accessible via `mac_capability_proc_nonce(cred)`.
Zero is reserved as "not available" and is never generated.

### How a process learns nonces

| Source | Mechanism |
|--------|-----------|
| Peer's nonce | `mac_capability_cred_trailer.nonce` on every RECVMSG and CALL |
| Own nonce | `identity` service: `IDENTITY_OP_SELF` via MAC_CAPABILITY_CALL |
| Child's nonce (procdesc) | `identity` service: `IDENTITY_OP_QUERY` with attached procdesc fd |

---

## File Descriptors and Capabilities

The unit of authority is the **instance fd** returned by MAC_CAPABILITY_CONNECT.

### Operations on an instance fd

| Operation | Ioctl allowlist entry | Effect |
|-----------|-----------------------|--------|
| Send async message | MAC_CAPABILITY_SENDMSG | Enqueue on service RX queue |
| Receive async message | MAC_CAPABILITY_RECVMSG | Dequeue from TX queue (blocks) |
| Synchronous call | MAC_CAPABILITY_CALL | Run service handler in caller thread |
| Query metadata | MAC_CAPABILITY_GETINFO | Read service name, badge, limits, features |
| Strip send | MAC_CAPABILITY_REVOKE_SEND | Block future SENDMSG (one-way) |
| Strip recv | MAC_CAPABILITY_REVOKE_RECV | Block future RECVMSG (one-way) |
| Strip call | MAC_CAPABILITY_REVOKE_CALL | Block future CALL (one-way) |
| Strip mint | MAC_CAPABILITY_REVOKE_MINT | Block future MINT_INSTANCE (one-way) |
| Mint instance | MAC_CAPABILITY_MINT_INSTANCE | Create new instance from mintable service |
| Destroy instance | MAC_CAPABILITY_TERMINATE | Kill the instance for all holders |
| kqueue readiness | CAP_EVENT (not an ioctl) | TX has data / RX has space |
| Prevent delegation | cap_xfer_limit(fd, CAP_XFER_NONE) | Disable fd transfer (one-way) |
| Permit one exec boundary | cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE) | Survive one exec, then lock |
| Permit one fork boundary | cap_clofork_limit(fd, CAP_CLOFORK_ONCE) | Inherit once, then lock both entries |

### Capability narrowing

Rights can only be reduced, never re-escalated:

1. **cap_rights_limit()** -- retain `CAP_IOCTL` and any non-ioctl rights the fd needs.
2. **cap_ioctls_limit()** -- irreversibly whitelist specific ioctl commands.
3. **MAC_CAPABILITY_REVOKE_SEND/RECV/CALL/MINT** -- instance-level one-way latch.
4. **cap_xfer_limit()** -- bound fd transfer via SCM_RIGHTS and mac_capability messages.
5. **cap_cloexec_limit() / cap_clofork_limit()** -- bound propagation across image and child-process boundaries.

All five compose.  A process can hand a child a send-only,
non-transferable handle by combining them.

### fd passing in messages

Messages (SENDMSG, CALL) can carry up to `MAC_CAPABILITY_MAX_FDS` (32)
file descriptors.  Attached fds preserve their complete Capsicum restrictions,
including rights, ioctl allowlists, and xfer/cloexec/clofork propagation states.
The DFLAG_PASSABLE check and per-fd CAP_XFER state prevent passing
non-transferable fds.

### Delegation

- **fork** -- child inherits the fd
- **dup** -- shares the same capability (same queues)
- **SCM_RIGHTS** -- pass to any process unless CAP_XFER state blocks it

`CAP_CLOFORK_ONCE` allows one child to inherit an fd and then locks both
the parent and child entries against further fork propagation.
`CAP_CLOEXEC_ONCE` allows the fd to survive one exec and then locks it
against the next exec.

---

## Capsicum Sandbox Compatibility

mac_capability is fully usable inside `cap_enter()`:

| Operation | Available in Capsicum mode? |
|-----------|---------------------------|
| MAC_CAPABILITY_CONNECT (on /dev/mac_capability) | Yes, if fd opened before cap_enter |
| SENDMSG, RECVMSG, CALL | Yes, with CAP_IOCTL and the command allowlisted |
| GETINFO, LOCK, REVOKE_*, TERMINATE | Yes |
| MINT_INSTANCE | Yes, with CAP_IOCTL and MINT_INSTANCE allowlisted |
| kqueue on instance fd | Yes |
| __mac_get_proc / __mac_set_proc | Yes (CAPENABLED) |
| mac_syscall | **No** (not CAPENABLED) |

### What a sandboxed process CANNOT do

1. **Open new /dev/mac_capability connections** -- must open before cap_enter
   or receive the fd from a supervisor.
2. **Forge credentials** -- nonce, uid, gid, prison_id are
   kernel-stamped.
3. **Re-escalate rights** -- all narrowing is one-way.
4. **Call mac_syscall()** -- use MAC_CAPABILITY_CALL instead.
5. **Bypass service access control** -- co_connect checks credentials.
6. **Send on a recv-only fd** -- enforced by Capsicum rights and
   instance restriction flags.

---

# Kernel Developer Guide

## Writing a Service

A MAC_CAPABILITY service is a kernel module that implements `co_handler`
(async), `co_call` (sync), or both:

```c
#include "mac_capability.h"
MODULE_DEPEND(echo, mac_capability, 1, 1, 1);

static int
echo_handler(struct mac_capability_instance *s, const struct mac_capability_msg *msg,
    void *arg)
{
    return (mac_capability_reply(s, mac_capability_msg_token(msg),
        mac_capability_msg_data(msg), mac_capability_msg_datalen(msg),
        NULL, NULL, 0));
}

static const struct mac_capability_ops echo_ops = {
    .co_handler = echo_handler,
};

static struct mac_capability_service *svc;

static int
echo_modevent(module_t mod, int type, void *arg)
{
    switch (type) {
    case MOD_LOAD: {
        struct mac_capability_service_params p = {
            .name = "echo",
            .ops  = &echo_ops,
        };
        return (mac_capability_service_create(&p, &svc));
    }
    case MOD_UNLOAD:
        mac_capability_service_destroy(svc);
        return (0);
    }
    return (EOPNOTSUPP);
}
```

## Lifecycle Callbacks

| Callback | When | Thread | Can fail? |
|---|---|---|---|
| `co_connect` | `MAC_CAPABILITY_CONNECT`, before instance exists | Caller | Yes |
| `co_init` | After creation, before fd visible | Caller | Yes |
| `co_handler` | Async message dispatch | Taskqueue | Yes (auto-error-reply) |
| `co_call` | Sync call in caller's context | Caller | Yes |
| `co_revoke` | Instance dying, after all work drains | Varies | No (void) |
| `co_fdclose` | Specific fd closed, instance may survive | Caller | No (void) |

All are optional except at least one of `co_handler` or `co_call`
(both may be provided).

### Revocation reasons

| Reason | Meaning |
|---|---|
| `MAC_CAPABILITY_REVOKE_PEER_CLOSED` | Userspace called `close()` |
| `MAC_CAPABILITY_REVOKE_BY_SERVICE` | Service called `mac_capability_instance_revoke()` or userspace sent `MAC_CAPABILITY_TERMINATE` |
| `MAC_CAPABILITY_REVOKE_UNLOAD` | Module unload via `mac_capability_service_destroy()` |

## The Async Handler

`co_handler` is called from a per-service taskqueue.  One message
at a time per instance (never concurrent).  May sleep.  No framework
locks held.

Access the message through accessors -- the struct is opaque:

```c
mac_capability_msg_data(msg)      /* payload bytes */
mac_capability_msg_datalen(msg)   /* payload length */
mac_capability_msg_token(msg)     /* correlation token set by sender */
mac_capability_msg_fds(msg)       /* attached file pointers */
mac_capability_msg_fcaps(msg)     /* Capsicum rights on attached fds */
mac_capability_msg_nfds(msg)      /* number of attached fds */
mac_capability_msg_badge(msg)     /* this instance's badge */
mac_capability_msg_cred(msg)      /* sender credentials at send time */
```

**Return 0** after calling `mac_capability_reply()` to send a response.
**Return 0** without replying for fire-and-forget messages.
**Return nonzero** to have the framework send an error reply.

The message is valid only during the call.  Copy what you need.

## Replying

```c
mac_capability_reply(s, mac_capability_msg_token(msg), data, len, fds, fcaps, nfds);
```

- `fds`: file pointers to attach.  NULL if none.
- `fcaps`: per-descriptor Capsicum restrictions to preserve, including rights
  and ioctl allowlists.  NULL means full rights.
- `mac_capability_msg_token(msg)`: pass the sender's token back for correlation.

## Notifications

Push an unsolicited message to userspace (async services only):

```c
mac_capability_notify(s, data, len, fds, fcaps, nfds);
```

Returns EAGAIN above the soft limit.  No reply token.

## Forwarding

Forward a received message to another instance:

```c
mac_capability_forward(s, msg);
```

Transfers the message (including attached fds) to the target instance's
RX queue.  Useful for proxy and routing services.

## Badges

The badge is a uint64_t assigned by `co_connect` at instance creation.
It's stamped on every inbound message.  The handler sees it via
`mac_capability_msg_badge(msg)`.  Typical values: monotonic counter, hash key,
user ID.

## Instance Private Data

```c
mac_capability_instance_set_priv(s, my_state);
struct my_state *st = mac_capability_instance_get_priv(s);
```

Set in `co_init`, freed in `co_revoke`.

## Revocation

Tear down an instance from the service side:

```c
mac_capability_instance_revoke(s);
```

The peer's next RECVMSG returns ECONNRESET.  `co_revoke` fires.
Safe to call from inside `co_handler` (self-revoke).
Do NOT call from inside `co_call`.

## Minting New Capabilities

Create an instance and return it as an attached fd in a reply:

```c
struct file *fp;
mac_capability_mint_fp(svc, badge, &fp);
mac_capability_reply(s, token, NULL, 0, &fp, NULL, 1);
fdrop(fp, curthread);
```

## Process Resolution

Resolve a procdesc from message fds:

```c
struct proc *p;
mac_capability_resolve_proc(mac_capability_msg_fds(msg), mac_capability_msg_nfds(msg), &p);
```

Searches the attached fds for a procdesc and returns the referenced
process.  Used by services that operate on a target process (node,
accounting, identity).

## Service Parameters

```c
struct mac_capability_service_params p = {
    .name          = "myservice",
    .ops           = &ops,
    .queue_depth   = 64,         /* 0 = 256, max 4096 */
    .tx_limit      = 128,        /* 0 = 256, max 4096 */
    .instance_limit = 512,       /* 0 = 1024, max 1M */
    .flags         = MAC_CAPABILITY_SVC_NOTIFY,
};
```

### Tunables

| Parameter | Default | Max | Description |
|---|---|---|---|
| `msg_size` | 16384 | 16384 | Fixed message size (4 pages) |
| `queue_depth` | 256 | 4096 | RX queue depth (async only) |
| `tx_limit` | 256 | 4096 | TX soft limit for notifications |
| `instance_limit` | 1024 | 1M | Max concurrent instances |
| `MAC_CAPABILITY_MAX_FDS` | 32 | 32 | Max fds per message (compile-time) |
| TX hard limit | 4x queue_depth | -- | Prevents unbounded growth |

## Advanced: Deferred Replies

If the handler needs to defer work (long crypto, disk I/O):

```c
static int
myservice_handler(struct mac_capability_instance *s, const struct mac_capability_msg *msg,
    void *arg)
{
    struct work *w = alloc_work();
    w->instance = s;
    w->token = mac_capability_msg_token(msg);
    memcpy(w->data, mac_capability_msg_data(msg), mac_capability_msg_datalen(msg));

    mac_capability_instance_hold(s);
    taskqueue_enqueue(my_tq, &w->task);
    return (0);
}

static void
deferred_task(void *ctx, int pending)
{
    struct work *w = ctx;
    uint32_t result = compute(w->data, w->datalen);
    mac_capability_reply(w->instance, w->token,
        &result, sizeof(result), NULL, NULL, 0);
    mac_capability_instance_rele(w->instance);
    free_work(w);
}
```

`mac_capability_instance_hold()` prevents close from freeing the instance.
`mac_capability_instance_rele()` releases the hold.

---

# Userspace Developer Guide

## Connecting

```c
#include "mac_capability_ioctl.h"

int ctl = open("/dev/mac_capability", O_RDWR);
struct mac_capability_connect_args ca = {0};
strlcpy(ca.name, "myservice", sizeof(ca.name));
ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca);
close(ctl);

int cap = ca.fd;   /* this is your capability */
```

After connecting, you never need /dev/mac_capability again.  The capability
fd can be passed via SCM_RIGHTS unless CAP_XFER state blocks it,
inherited across fork, or restricted via Capsicum.

## Sending a Message (async)

```c
struct mac_capability_sendmsg_args sa = {0};
sa.payload = &request;
sa.payload_len = sizeof(request);
sa.reply_token = my_request_id;
ioctl(cap, MAC_CAPABILITY_SENDMSG, &sa);
```

Returns immediately.  EAGAIN if the queue is full -- use
kqueue(EVFILT_WRITE) to wait.

## Receiving a Message (async)

```c
char buf[4096];
struct mac_capability_recvmsg_args ra = {0};
ra.payload = buf;
ra.payload_len = sizeof(buf);
ioctl(cap, MAC_CAPABILITY_RECVMSG, &ra);
/* ra.payload_len = actual bytes received */
/* ra.reply_token = correlation token */
```

Blocks until a message is available.  EAGAIN with O_NONBLOCK.
EMSGSIZE if buffer too small (message stays queued for retry).

## Synchronous Call

```c
struct ns_request req = { .op = NS_OP_INFO };
char reply_buf[512];
int recv_fds[4];
struct mac_capability_call_args ca = {0};
ca.req = &req;
ca.req_len = sizeof(req);
ca.reply = reply_buf;
ca.reply_len = sizeof(reply_buf);
ca.reply_fds = recv_fds;
ca.reply_nfds = 4;
ioctl(cap, MAC_CAPABILITY_CALL, &ca);
```

## Attaching File Descriptors

```c
int shm_fd = shm_open(SHM_ANON, O_RDWR, 0);
struct mac_capability_sendmsg_args sa = {0};
sa.payload = &request;
sa.payload_len = sizeof(request);
sa.fds = &shm_fd;
sa.nfds = 1;
ioctl(cap, MAC_CAPABILITY_SENDMSG, &sa);
```

## Querying Service Info

```c
struct mac_capability_info_args info;
ioctl(cap, MAC_CAPABILITY_GETINFO, &info);
```

Feature bits:

| Bit | Meaning |
|---|---|
| `MAC_CAPABILITY_INFO_F_SENDMSG` | Async messaging supported |
| `MAC_CAPABILITY_INFO_F_CALL` | Synchronous call supported |
| `MAC_CAPABILITY_INFO_F_KQUEUE` | EVFILT_READ/WRITE supported |

## Event Loop Integration

```c
EV_SET(&kev, cap, EVFILT_READ, EV_ADD, 0, 0, NULL);   /* msg ready */
EV_SET(&kev, cap, EVFILT_WRITE, EV_ADD, 0, 0, NULL);   /* can send */
```

EV_EOF fires when the capability is revoked.

## Error Summary

| Error | Context | Meaning |
|---|---|---|
| EAGAIN | SENDMSG | RX queue full |
| EAGAIN | RECVMSG + O_NONBLOCK | No message |
| EMSGSIZE | SENDMSG | Payload too large |
| EMSGSIZE | RECVMSG / CALL | Buffer too small (reply_len = required) |
| EPIPE | SENDMSG | Instance dead |
| ECONNRESET | RECVMSG / CALL | Instance revoked |
| EOPNOTSUPP | SENDMSG on sync / CALL on async | Wrong API |
| ENOENT | CONNECT | Service not registered |
| ECONNABORTED | CONNECT | Service unloading |
| ENOBUFS | (internal) | TX queue hard limit reached |
| EACCES | SENDMSG / RECVMSG / CALL | Operation restricted via MAC_CAPABILITY_REVOKE_* |
| EBADF | SENDMSG / CALL | fd hold failed during message construction |

## Security

`/dev/mac_capability` is mode 0600 (root only).  Unprivileged processes cannot
connect directly.  A broker daemon connects on their behalf and passes
capability fds via SCM_RIGHTS.

Capabilities can be attenuated before delegation:
- `cap_xfer_limit(fd, CAP_XFER_NONE)` prevents further SCM_RIGHTS and mac_capability fd passing
- `cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE)` permits one exec boundary and then forces close-on-exec
- `cap_clofork_limit(fd, CAP_CLOFORK_ONCE)` permits one fork boundary and then forces close-on-fork in both branches
- `MAC_CAPABILITY_REVOKE_SEND` / `MAC_CAPABILITY_REVOKE_RECV` / `MAC_CAPABILITY_REVOKE_CALL` / `MAC_CAPABILITY_REVOKE_MINT` strip operations
- `cap_ioctls_limit` restricts which ioctls the holder can perform

---

## Services Available Today

### identity (sync, MAC_CAPABILITY_CALL)

Program identity queries.

| Operation | What it does |
|-----------|-------------|
| IDENTITY_OP_SELF | Returns caller's own nonce |
| IDENTITY_OP_QUERY | Returns nonce of process via attached procdesc fd |

### capprotect (sync, MAC_CAPABILITY_CALL)

Program shielding -- protects a process (by nonce) from external
interference.

| Operation | What it does |
|-----------|-------------|
| CP_OP_SHIELD | Set protection flags on a nonce |
| CP_OP_MINT | Create an access token granting cross-nonce access |
| CP_OP_AUTHORIZE | Present a token to gain access to a shielded process |
| CP_OP_CAPMODE | Force Capsicum capability mode on a process |
| CP_OP_CHROOT | Set a chroot for a process |

Shield flags:

| Flag | Value | Meaning |
|------|-------|---------|
| CP_SF_PTRACE | 0x001 | Block ptrace |
| CP_SF_SIGNAL | 0x002 | Block signals |
| CP_SF_VISIBLE | 0x004 | Hide from process listing |
| CP_SF_WAIT | 0x008 | Block wait4 |
| CP_SF_SIGKILL | 0x010 | Block SIGKILL |
| CP_SF_SIGCONT | 0x020 | Block SIGCONT |
| CP_SF_SCHED | 0x040 | Block scheduler manipulation |
| CP_SF_CORE | 0x080 | Block core dumps |
| CP_SF_KTRACE | 0x100 | Block ktrace |
| CP_SF_NOPRIVS | 0x200 | Drop extra privileges |
| CP_SF_NOFORK | 0x400 | Prevent fork |
| CP_SF_NOIPC | 0x800 | Block SysV IPC |
| CP_SF_NOFDRECV | 0x1000 | Block fd receive via SCM_RIGHTS |
| CP_SF_ALL | 0x1fff | All flags combined |

### system (sync, MAC_CAPABILITY_CALL)

Privileged system operations gated through capability tokens.
Allows sandboxed processes to perform controlled system calls
(kldload, reboot, sysctl, etc.) via narrowed gate tokens.

| Operation | What it does |
|-----------|-------------|
| SYS_OP_CLAIM | Claim system gate authority for a nonce |
| SYS_OP_RELEASE | Release system gate authority |
| SYS_OP_MINT | Create a gate token with restricted gates |
| SYS_OP_AUTHORIZE | Activate a gate token for the caller's nonce |

System gates:

| Gate | Value | Controls |
|------|-------|----------|
| SYS_GATE_KLDLOAD | 0x001 | Module loading |
| SYS_GATE_KLDUNLOAD | 0x002 | Module unloading |
| SYS_GATE_KLDSTAT | 0x004 | Module status query |
| SYS_GATE_REBOOT | 0x008 | System reboot |
| SYS_GATE_SWAPON | 0x010 | Enable swap |
| SYS_GATE_SWAPOFF | 0x020 | Disable swap |
| SYS_GATE_SYSCTL | 0x040 | sysctl writes |
| SYS_GATE_KENV | 0x080 | Kernel environment writes |
| SYS_GATE_ACCT | 0x100 | Process accounting |
| SYS_GATE_AUDIT | 0x200 | Audit control |
| SYS_GATE_KENV_READ | 0x400 | Kernel environment reads |
| SYS_GATE_ALL | 0x7ff | All gates |

### isolation (sync, MAC_CAPABILITY_CALL)

File, directory, Unix-socket, network, vsock, and jail isolation by nonce.
Claims establish broad ownership; tokens delegate narrowed access.

**File/directory operations:**

| Operation | What it does |
|-----------|-------------|
| CLAIM | Isolate a file/directory to caller's nonce (by vnode, not path) |
| RELEASE | Release a vnode claim |
| QUERY | Check claim status and authorization |
| MINT | Create an access token with FI_FS_* action mask |
| AUTHORIZE | Activate a token for the caller's nonce |

File action masks for token narrowing:

| Action | Meaning |
|--------|---------|
| LOOKUP | Traverse a directory during path resolution |
| STAT | Inspect metadata |
| READ | Read file data or symlink target |
| WRITE | Write existing file data |
| APPEND | Append-only write |
| CREATE | Create a directory entry |
| DELETE | Unlink a file or remove a directory |
| RENAME_FROM / RENAME_TO | Move names between directories |
| LINK | Create a hard link |
| EXEC | Execute a file |
| SETATTR | chmod, chown, chflags, utimes |
| TRUNCATE | Truncate file content |
| UIPC_CONNECT | Connect to a Unix domain socket |

**Network operations:**

| Operation | What it does |
|-----------|-------------|
| CLAIM_NET | Isolate a network endpoint (domain, protocol, port range, direction, CIDR address) |
| RELEASE_NET | Release a network claim |
| QUERY_NET | Check network claim status |
| MINT_NET | Create a network access token scoped to an endpoint |

Network claims support port ranges (min..max), CIDR address prefixes
(e.g., 10.0.0.0/8), protocol wildcards, and direction (bind/connect/any).

**Vsock operations:**

| Operation | What it does |
|-----------|-------------|
| CLAIM_VSOCK | Claim a CID, 32-bit port range, and bind/connect direction |
| RELEASE_VSOCK | Release an exact vsock claim |
| QUERY_VSOCK | Check vsock ownership and authorization |
| MINT_VSOCK | Create a token narrowed to a covered vsock tuple |

Vsock claims are owned by program nonce and live as long as their isolation
instance fd.  Bind claims identify local endpoints; connect claims identify
destinations.  `VSOCK_CID_ANY` and port ranges provide controlled wildcards.
Socket type is intentionally outside the key, so a claim covers both stream
and sequenced-packet sockets.  Wildcard and ephemeral binds are checked for
overlap with exact claims rather than being allowed to bypass them.

The endpoint policy applies to the AF_VSOCK socket API.  The current native
host transport allows only one privileged `/dev/vsock` provider; access to
that device can be delegated using vnode isolation.  Supporting multiple
simultaneous providers is an explicit integration boundary: transport attach
must then acquire a provider-CID claim, with its own allow/deny probes and
attach/detach/race tests.

**Jail operations:**

| Operation | What it does |
|-----------|-------------|
| CLAIM_JAIL | Claim a jail by JID, name, or both |
| RELEASE_JAIL | Release a jail claim |
| QUERY_JAIL | Check jail claim status |
| MINT_JAIL | Create a jail access token with FI_JAIL_* action mask |

Jail action masks: CREATE, GET, SET, REMOVE, ATTACH.

**MACF enforcement:** Claims are enforced via MAC policy hooks on
vnode operations, socket bind/connect, and jail create/get/set/remove/attach.
Owner nonce always passes.  Foreign nonces are denied unless authorized
via a token whose action mask covers the requested operation.

### coalition (sync, MAC_CAPABILITY_CALL)

Resource group management.

| Operation | What it does |
|-----------|-------------|
| ENLIST | Add process, jail, socket, or fd to a coalition |
| JOIN | Join an existing coalition |
| ENLIST_SET | Enlist multiple members in one call |
| TERMINATE | Kill all members |
| STAT | Query membership and state |
| SET_SIGNAL | Set signal for coalition-wide delivery |
| GRACEFUL | Graceful shutdown with signal and timeout |
| SET_DEADLINE | Set a time-bounded lifetime |
| SET_WATCHDOG | Require periodic checkins |
| HEARTBEAT | Watchdog checkin |
| SET_LEADER | Designate a leader process |
| RUSAGE | Aggregate resource usage |

### node (sync, MAC_CAPABILITY_CALL)

Per-process inspection and control via attached procdesc.

| Operation | What it does | Remote? |
|-----------|-------------|---------|
| STAT | Get pid, state, name, thread count | yes |
| CRED | Get uid, gid, groups, nonce, jail identity | yes |
| RUSAGE | Get live resource usage | yes |
| GET/SET_RLIMIT | Read or update one rlimit | yes |
| GET_RACCT | Read one racct counter | yes |
| GET/SET_NICE | Read or update priority | yes |
| GET/SET_AFFINITY | Read or update CPU affinity | yes |
| GET/SET_PROCCTL | Read or update procctl state | yes |
| SET_CRED | Set uid/gid/groups (via setcred) | yes |
| GET/SET_UMASK | Read or update file creation mask | yes |
| SET_LOGIN | Set session login name | yes |
| GET_PGRP | Get process group id | yes |
| SET_PGRP | Set process group (setpgid) | **self only** |
| SET_SESSION | Create new session (setsid) | **self only** |
| SIGNAL | Send signal to target process | yes |
| REAP_GETPIDS | List reaped descendant PIDs | **self only** |

### accounting (sync, MAC_CAPABILITY_CALL)

Per-process racct and rctl operations via attached procdesc.

| Operation | What it does |
|-----------|-------------|
| CHARGE | Debit one racct resource |
| RELEASE | Credit one racct resource |
| SET | Set one racct resource absolutely |
| ADD_RULE / REMOVE_RULE | Add or remove rctl enforcement rules |
| GET_RULES | Query active rctl rules |

### channel (async, SENDMSG/RECVMSG)

Bidirectional process-to-process messaging.  `CHANNEL_OP_CREATE` creates
a connected channel; returns two fds.  Revoking one end delivers
ECONNRESET to the peer.

### mount (sync, MAC_CAPABILITY_CALL)

Capability-based filesystem mounting for sandboxed and jailed processes.

| Operation | What it does |
|-----------|-------------|
| MOUNT_OP_MOUNT | Mount a filesystem (fstype, path, flags) |
| MOUNT_OP_UNMOUNT | Unmount a filesystem path |

Whitelisted fstypes: tmpfs, devfs, fdescfs, nullfs, procfs,
linprocfs, linsysfs, fusefs.  Path validation rejects relative
paths and `..` traversal.  Enforcement is layered: mac_capability_mount
constrains request shape, jail `allow.mount.*` decides filesystem
policy, the filesystem handler validates fs-specific options.

---

## Service Model: Future Direction

Today, `MAC_CAPABILITY_CONNECT` resolves named kernel services.  The intended
direction is:

- Service names resolved through a registrar (not a flat global
  kernel namespace)
- Namespaces scoped per supervisor, per jail, or per policy domain
- Services may be kernel-backed or userspace-hosted
- Bind/open operations can be brokered for policy, launch, and audit

In that model, mac_capability remains the transport and authority layer,
while the registrar and supervisor provide naming, lifecycle, and
policy.

---

## Source Layout

```
sys/dev/mac_capability/
    mac_capability.h              public kernel API
    mac_capability_internal.h     framework internals
    mac_capability_ioctl.h        shared ioctl definitions
    mac_capability_core.c         module lifecycle, capability creation
    mac_capability_dev.c          capability operations (ioctls, kqueue, close)
    mac_capability_kern.c         KPI: dispatch, reply/notify/revoke
    mac_capability_label.c/h      program nonce (identity) MACF label
    mac_capability_identity.c     identity service (SELF, QUERY)
    mac_capability_isolation.c    file/net/vsock/jail isolation (claims, tokens, MACF)
    mac_capability_capprotect.c   capability protection (ptrace/signal/visibility via MACF)
    mac_capability_system.c       system gate enforcement via MACF
    mac_capability_coalition.c    resource group management (enlist, terminate, timers)
    mac_capability_node.c         per-process inspection/control via procdesc
    mac_capability_accounting.c   per-process racct/rctl operations
    mac_capability_mount.c        capability-based filesystem mounting
    mac_capability_channel.c      bidirectional capability channel
    mac_capability_test_kernelstore.c  test fixture: sync key-value store
    mac_capability_test_keystore.c     test fixture: async key-value store

usr.sbin/authorityd/         authority authority daemon
usr.sbin/serviced/        service manager daemon

share/dtrace/mac_capability-*     DTrace scripts (14 mac_capability scripts)
share/dtrace/authorityd-*    DTrace scripts (8 authorityd)
share/dtrace/serviced-*   DTrace scripts (10 serviced)

tests/sys/mac_capability/         ATF kernel tests via kyua
```

## Base System Changes

- `DTYPE_MAC_CAPABILITY` (17) in sys/sys/file.h
- `KF_TYPE_MAC_CAPABILITY` (17) in sys/sys/user.h

## Exported Kernel API

### Service lifecycle
- `mac_capability_service_create(params, &svc)` -- register a service
- `mac_capability_service_destroy(svc)` -- unregister and drain

### Messaging (from co_handler or sleeping context)
- `mac_capability_reply(s, token, data, len, fds, fcaps, nfds)` -- reply
- `mac_capability_notify(s, data, len, fds, fcaps, nfds)` -- push notification
- `mac_capability_forward(s, msg)` -- forward message to another instance

### Instance management
- `mac_capability_instance_revoke(s)` -- tear down instance
- `mac_capability_instance_hold(s)` / `mac_capability_instance_rele(s)` -- deferred work refcount
- `mac_capability_instance_set_priv(s, priv)` / `mac_capability_instance_get_priv(s)` -- per-instance data
- `mac_capability_instance_get_badge(s)` -- service-assigned badge

### Program identity
- `mac_capability_proc_nonce(cred)` -- return 8-byte cryptographic nonce

### Minting
- `mac_capability_mint_fp(svc, badge, &fp)` -- create new capability from handler

### Process resolution
- `mac_capability_resolve_proc(fds, nfds, &proc)` -- resolve procdesc from message fds

### Message accessors
- `mac_capability_msg_data(msg)`, `mac_capability_msg_datalen(msg)`
- `mac_capability_msg_fds(msg)`, `mac_capability_msg_fcaps(msg)`, `mac_capability_msg_nfds(msg)`
- `mac_capability_msg_badge(msg)`, `mac_capability_msg_token(msg)`
- `mac_capability_msg_cred(msg)`

## Headers

- **mac_capability.h** -- public API for service modules
- **mac_capability_ioctl.h** -- shared kernel/userspace ioctl definitions
- **mac_capability_label.h** -- program nonce accessor
- **mac_capability_internal.h** -- framework internals (not for service modules)
- **mac_capability_isolation_proto.h** -- file/net/vsock/jail isolation wire protocol
- **mac_capability_capprotect_proto.h** -- capability protection wire protocol
- **mac_capability_system_proto.h** -- system gate wire protocol
- **mac_capability_coalition_proto.h** -- coalition wire protocol
- **mac_capability_channel_proto.h** -- capability channel wire protocol
- **mac_capability_identity_proto.h** -- identity service wire protocol
- **mac_capability_node_proto.h** -- node service wire protocol
- **mac_capability_accounting_proto.h** -- accounting service wire protocol
- **mac_capability_mount_proto.h** -- mount service wire protocol

## DTrace Probes

Provider: `mac_capability` (core messaging)

| Probe | Args |
|---|---|
| `connect` / `connect-done` | service name, badge, pid [, error, time] |
| `send` / `send-done` | service name, badge, payload len [, nfds, error, time] |
| `recv` / `recv-done` | service name, badge, payload len [, nfds, error, time] |
| `dispatch` / `dispatch-done` | service name, badge [, error, time] |
| `reply` / `reply-done` | service name, badge, payload len [, error, time] |
| `notify` / `notify-done` | service name, badge, payload len [, error, time] |
| `call` / `call-done` | service name, badge, req len [, reply len, error, time] |
| `forward` / `forward-done` | service name, badge, payload len [, error, time] |
| `revoke` / `revoke-done` | service name, badge, reason [, time] |
| `close` | service name, badge |
| `fd-install` / `fd-close` / `fd-receive` | service name, badge, fd, pid, cred, nonce |
| `fd-mint` | service name, badge, pid, cred, nonce, svc flags |
| `instance-create` / `instance-finalize` / `instance-lastclose` | service name, badge, ... |
| `service-create` / `service-destroy` | service name, flags, ... |
| `control` / `rights-change` | service name, badge, cmd, pid, cred, nonce |
| `queue-pressure` | service name, badge, reason, current, limit |
| `error` | service name, badge, cmd, pid, nonce, errno |

Provider: `mac_capability_isolation` (file/net/vsock/jail enforcement)

| Probe | Args |
|---|---|
| `deny` | name, owner nonce, caller nonce |
| `deny-action` | name, owner nonce, caller nonce, claim id, actions |
| `deny-net` | owner nonce, caller nonce, claim id, domain, proto\|dir, port |
| `deny-vsock` | owner nonce, caller nonce, claim id, CID, port, direction |
| `deny-jail` | owner nonce, caller nonce, claim id, jid, name, actions |
| `allow-action` | name, owner nonce, caller nonce, claim id, actions |
| `allow-net` | owner nonce, caller nonce, claim id, domain, proto\|dir, port |
| `allow-vsock` | owner nonce, caller nonce, claim id, CID, port, direction |
| `allow-jail` | owner nonce, caller nonce, claim id, jid, name, actions |
| `token-narrow` | type, owner nonce, claim id, actions, 0 |
| `query` | type, caller nonce, 0, 0, reply flags |
| `state` | name, nonce, nonce, claim id, op, errno |

Provider: `mac_capability_capprotect` (shield enforcement)

| Probe | Args |
|---|---|
| `deny` | hook name, target nonce, caller nonce |
| `allow` | hook name, target nonce, caller nonce |
| `state` | op name, target nonce, caller nonce, flags, pid, error |

Provider: `mac_capability_system` (gate enforcement)

| Probe | Args |
|---|---|
| `deny` | gate name, owner nonce, caller nonce |
| `allow` | gate name, owner nonce, caller nonce |
| `state` | op name, owner nonce, caller nonce, gates, pid, error |

Provider: `mac_capability_coalition` (resource groups)

| Probe | Args |
|---|---|
| `create` | badge |
| `enlist` | dtype, error |
| `join` | pid, error |
| `terminate` | member count, error |
| `close` | member count |
| `member-exit` / `leader-exit` | pid |
| `fork-inherit` | parent pid, child pid |
| `signal-set` | signal, 0 |
| `deadline-set` | timeout ms, signal, grace ms, 0 |
| `watchdog-set` | timeout ms, 0 |
| `heartbeat` | timeout ms |
| `deadline-expire` | phase, signal |
| `watchdog-expire` | signal |
| `graceful` | signal, timeout ms, 0 |
| `call-done` | op, error, time |
| `deny` | reason, errno, pid |

Provider: `mac_capability_channel` (bidirectional messaging)

| Probe | Args |
|---|---|
| `create` | badge A, badge B, 0 |
| `forward` | src badge, dst badge, data len |
| `handler-done` | op, badge, error, time |
| `state` | name, op, badge, error, 0 |

## Sysctls

| Sysctl | Type | Description |
|---|---|---|
| `kern.mac_capability.services` | counter | Number of registered services |
| `kern.mac_capability.instances` | counter | Number of active instances |
| `kern.mac_capability.service_names` | string | Newline-separated service list |
| `kern.mac_capability.service_details` | string | Service details (flags, limits, counts) |

---

## Roadmap

Phases 1-7 are complete: program identity (nonces), capability
protection (MACF shields), file/network/jail isolation (claims and
tokens), resource groups (coalitions), per-process control (node),
accounting (racct/rctl), capability pairs, filesystem mounting,
system gate enforcement, and the two-daemon architecture (authorityd +
serviced).

### Kernel-to-kernel capability communication

Needs design before code.  The wrong answer creates a capability
system where services bypass the holder's authority.

---

## Explicit Non-Goals

Unless concrete requirements force them, the runtime does not need:
- Remote object references
- Complex RPC stub generation
- Mach-style port-right algebra
- VM-integrated zero-copy IPC
- A general distributed-object model
