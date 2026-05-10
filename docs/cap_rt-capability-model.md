# cap_rt Capability Model

What a sandboxed process can do through the cap_rt runtime,
what the runtime is meant to provide, and what is intentionally
out of scope.

## Design stance

cap_rt is a **capability transport, supervision, and policy substrate**
for BSD sandboxes.

It is **not** intended to be:
- a microkernel IPC substrate
- a remote-object runtime
- a Binder or Mach clone

The runtime centers on:
- capability file descriptors as the unit of authority
- explicit delegation and narrowing
- kernel-stamped identity and credential metadata
- revocation, supervision, and policy enforcement

The runtime does **not** currently aim to provide:
- general remote object references
- port-right algebra
- VM-integrated message passing
- IDL-generated RPC machinery

## Identity

Every credential carries a 64-bit **nonce** (program identity):
- Inherited across fork (same program)
- Rotated on exec (new program)
- Kernel-assigned; userspace cannot set or forge it

### How a process learns nonces

| Source | Mechanism |
|--------|-----------|
| Peer's nonce | `cap_rt_cred_trailer.nonce` on every RECVMSG and CALL |
| Own nonce | `identity` service: `IDENTITY_OP_SELF` via CAP_RT_CALL |
| Child's nonce (procdesc) | `identity` service: `IDENTITY_OP_QUERY` with attached procdesc fd |

The **identity** service is a capability — connect once, pass the fd
to sandboxed children so they can discover their own nonce without
needing `/dev/cap_rt`.

## File descriptors and capabilities

The unit of authority is the **instance fd** returned by CAP_RT_CONNECT.
All operations go through ioctls on this fd.

### Operations on an instance fd

| Operation | Ioctl | Capsicum Right | Effect |
|-----------|-------|----------------|--------|
| Send async message | CAP_RT_SENDMSG | CAP_CAP_RT_SEND | Enqueue on service RX queue |
| Receive async message | CAP_RT_RECVMSG | CAP_CAP_RT_RECV | Dequeue from TX queue (blocks) |
| Synchronous call | CAP_RT_CALL | CAP_CAP_RT_SEND + CAP_CAP_RT_RECV | Run service handler in caller thread |
| Query metadata | CAP_RT_GETINFO | (none) | Read service name, badge, limits, features |
| Prevent delegation | CAP_RT_LOCK | (none) | Disable SCM_RIGHTS transfer (one-way) |
| Strip send | CAP_RT_REVOKE_SEND | (none) | Block future SENDMSG (one-way) |
| Strip recv | CAP_RT_REVOKE_RECV | (none) | Block future RECVMSG (one-way) |
| Strip call | CAP_RT_REVOKE_CALL | (none) | Block future CALL (one-way) |
| Destroy instance | CAP_RT_TERMINATE | (none) | Kill for all holders |
| kqueue readiness | EVFILT_READ / EVFILT_WRITE | (none) | TX has data / RX has space |

### Capability narrowing

Rights can only be reduced, never re-escalated:

1. **Capsicum cap_rights_limit()** — restrict which Capsicum rights
   the fd carries (CAP_IOCTL, CAP_CAP_RT_SEND, CAP_CAP_RT_RECV).
2. **Capsicum cap_ioctls_limit()** — whitelist specific ioctl commands.
3. **CAP_RT_REVOKE_SEND/RECV/CALL** — instance-level one-way latch.
4. **CAP_RT_LOCK** — prevent fd transfer via SCM_RIGHTS.

All four mechanisms compose.  A process can hand a child a
send-only, non-transferable handle by combining cap_rights_limit,
cap_ioctls_limit, REVOKE_RECV, REVOKE_CALL, and LOCK.

### fd passing in messages

Messages (SENDMSG, CALL) can carry up to 32 file descriptors.
Capsicum rights on attached fds are preserved through transfer.
The DFLAG_PASSABLE check prevents passing non-transferable fds.

For some services, an attached fd is part of the authority model. For
others, it is only a target designator. In particular:
- `coalition` interprets attached fd rights as part of delegation policy
- `node` and `accounting` treat an attached procdesc as naming the target
  process; authority comes from possession of the service capability plus
  possession of the procdesc itself, not from the procdesc's narrowed
  `CAP_PD*` rights

That difference is intentional. The runtime does not require every
service to project attached-fd Capsicum rights into its own policy.

## Service model

Today, `CAP_RT_CONNECT` resolves a named **kernel** service and returns
an instance fd for that service.

That is sufficient for the current model, but it is not the long-term
shape of the runtime.  The next major runtime layer should be a
**general service registrar** paired with a **supervisor / launcher**
model.

The intended direction is:
- service names are resolved through a registrar rather than a flat,
  global kernel namespace
- namespaces can be scoped per supervisor, per jail, or per policy domain
- registration policy is explicit: who may publish, replace, hide, or
  delegate a service
- services may be kernel-backed or userspace-hosted
- bind/open operations can be brokered for policy, launch, and audit

In that model, cap_rt remains the transport and authority layer, while
the registrar and supervisor provide naming, lifecycle, and policy.

## Capsicum sandbox compatibility

cap_rt is fully usable inside `cap_enter()`:

| Operation | Available in Capsicum mode? |
|-----------|---------------------------|
| CAP_RT_CONNECT (on /dev/cap_rt) | Yes, if fd to /dev/cap_rt was opened before cap_enter |
| SENDMSG, RECVMSG, CALL | Yes, with appropriate rights on the instance fd |
| GETINFO, LOCK, REVOKE_*, TERMINATE | Yes |
| kqueue on instance fd | Yes |
| __mac_get_proc / __mac_set_proc | Yes (CAPENABLED) |
| mac_syscall | **No** (not CAPENABLED) |

Since cap_rt services (capprotect, isolation, coalition) use
CAP_RT_CALL, not mac_syscall, they are fully accessible inside a
Capsicum sandbox.  The MAC syscall restriction does not matter.

## Services available today

### identity (sync, CAP_RT_CALL)

Program identity queries.

| Operation | What it does |
|-----------|-------------|
| IDENTITY_OP_SELF | Returns caller's own nonce |
| IDENTITY_OP_QUERY | Returns nonce of process via attached procdesc fd |

The identity fd is meant to be passed to sandboxed children so they
can discover their own nonce without needing `/dev/cap_rt`.

### capprotect (sync, CAP_RT_CALL)

Program shielding — protects a process (by nonce) from external
interference.

| Operation | What it does |
|-----------|-------------|
| SHIELD | Set protection flags for caller's nonce (ptrace, signals, visibility, wait, unkillable, unstoppable, sched, coredump, ktrace) |
| MINT | Create an access token granting cross-nonce access |
| AUTHORIZE | Present a token to gain access to a shielded process |

Access tokens are capability fds — they can be passed via messages,
narrowed, and revoked.

### isolation (sync, CAP_RT_CALL)

File, directory, Unix-socket, and network isolation by nonce.

| Operation | What it does |
|-----------|-------------|
| CLAIM_VNODE | Isolate a file/directory to caller's nonce |
| RELEASE_VNODE | Release a vnode claim |
| CLAIM_NETWORK | Isolate a port/address/protocol/direction tuple |
| RELEASE_NETWORK | Release a network claim |
| QUERY | Check claim status of a resource |

Claims are bound to the instance fd — revoking the fd releases all
claims made through it.

### coalition (sync, CAP_RT_CALL)

Resource group management.

| Operation | What it does |
|-----------|-------------|
| ENLIST | Add process, jail, socket, or fd to a coalition |
| TERMINATE | Kill all members |
| STAT | Query membership and state |
| SIGNAL | Send signal to all process members |
| DEADLINE | Set a time-bounded lifetime |
| WATCHDOG | Require periodic checkins |
| LEADER | Designate a leader process |
| RUSAGE | Aggregate resource usage across members |

Nested coalitions are supported with cycle detection.

### node (sync, CAP_RT_CALL)

Per-process inspection and control.

| Operation | What it does | Remote? |
|-----------|-------------|---------|
| STAT | Get pid, state, name, and thread count | yes |
| CRED | Get uid, gid, groups, nonce, and jail identity | yes |
| RUSAGE | Get live resource usage | yes |
| GET_RLIMIT / SET_RLIMIT | Read or update one rlimit | yes |
| GET_RACCT | Read one racct counter | yes |
| GET_NICE / SET_NICE | Read or update process priority | yes |
| GET_AFFINITY / SET_AFFINITY | Read or update CPU affinity | yes |
| GET_PROCCTL / SET_PROCCTL | Read or update procctl state | yes |
| SET_CRED | Set uid/gid/groups (via setcred) | yes |
| GET_UMASK / SET_UMASK | Read or update file creation mask | yes |
| SET_LOGIN | Set session login name | yes |
| SET_SESSION | Create new session (setsid) | **self only** |
| SET_PGRP | Set process group (setpgid) | **self only** |

SET_SESSION and SET_PGRP are self-only because the kernel's
`enterpgrp()` asserts `p == curproc` for session creation.  Remote
targets get EOPNOTSUPP.  An init daemon should have the child call
these on itself before exec.

For `node`, an attached procdesc identifies the target process. Its
`CAP_PD*` rights are not treated as an independent authority filter.
The authority model is: possession of the `node` capability plus
possession of the procdesc.

### accounting (sync, CAP_RT_CALL)

Per-process racct and rctl operations.

| Operation | What it does |
|-----------|-------------|
| CHARGE | Debit one racct resource |
| RELEASE | Credit one racct resource |
| SET | Set one racct resource absolutely |
| ADD_RULE | Add one rctl enforcement rule |
| REMOVE_RULE | Remove one rctl enforcement rule |
| GET_RULES | Query active rctl rules |

Like `node`, `accounting` uses an attached procdesc as a target
designator. The effective authority is the `accounting` capability
combined with possession of the procdesc, not the procdesc's narrowed
`CAP_PD*` rights.

### pair (async, SENDMSG/RECVMSG)

Bidirectional process-to-process messaging.

| Operation | What it does |
|-----------|-------------|
| PAIR_OP_CREATE | Create a connected pair; returns two fds |

Messages sent to one end appear on the other.  Revoking one end
delivers ECONNRESET to the peer.

### mount (sync, CAP_RT_CALL)

Capability-based filesystem mounting for sandboxed init daemons.

| Operation | What it does |
|-----------|-------------|
| MOUNT_OP_MOUNT | Mount a filesystem (fstype, path, flags) |
| MOUNT_OP_UNMOUNT | Unmount a filesystem path |

Whitelisted fstypes: tmpfs, devfs, fdescfs, nullfs, procfs,
linprocfs, linsysfs, fusefs.

Generic flags: RDONLY, NOEXEC, NOSUID, NOATIME, NOSYMFOLLOW.
Fs-specific options via comma-separated key=value string:
tmpfs `size=128M,mode=1777`, devfs `ruleset=4`, fdescfs `linrdlnk`.

Path validation rejects relative paths and `..` traversal components.
Runs in the caller's thread context, so mounts are scoped to the
caller's jail namespace.  The jail's `allow.mount.*` parameters
provide a second layer of enforcement.  Invalid fs-specific options
are rejected by the filesystem's own mount handler.

## What a sandboxed process CANNOT do

1. **Open new /dev/cap_rt connections** — must open before cap_enter,
   or receive the /dev/cap_rt fd from a supervisor.
2. **Forge credentials** — nonce, uid, gid, prison_id are
   kernel-stamped on every message.
3. **Re-escalate rights** — all narrowing operations are one-way.
4. **Call mac_syscall()** — blocked by Capsicum.  Use CAP_RT_CALL instead.
5. **Bypass service access control** — co_connect checks credentials
   before granting an instance fd.
6. **Send on a recv-only fd** — enforced by both Capsicum rights and
   instance restriction flags.

## Near-term runtime work

The main missing runtime piece is not Mach- or Binder-style object
machinery.  It is a **general service registrar** and the supervision
model around it.

Priority order:

1. **Registrar / bootstrap namespace**
   Resolve service names to capabilities.
   Support per-supervisor, per-jail, or per-policy namespaces instead
   of a single flat registry.

2. **Userspace service hosting**
   Allow supervisors to publish userspace-backed services in addition
   to kernel-backed services.

3. **Activation and lifecycle**
   Support on-demand launch, explicit shutdown, revoke/restart, and
   clear "service went away" semantics.

4. **Metadata and versioning**
   Expose ABI version, feature bits, limits, and expected rights so
   callers can bind safely.

5. **Delegation policy**
   Make service-cap passing rules explicit and enforceable, since
   delegation is a core part of the model.

6. **Audit and accounting**
   Add audit(4) integration for connect/call/revoke/fd transfer and
   per-sender or per-service accounting via racct integration.

## Explicit non-goals for now

Unless concrete requirements force them, the runtime does not need:
- remote object references
- complex RPC stub generation
- Mach-style port-right algebra
- VM-integrated zero-copy IPC
- a general distributed-object model

Those solve a different class of problem than the one cap_rt is meant
to solve.
