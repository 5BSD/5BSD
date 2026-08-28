# The MAC Capability Framework

`mac_capability` is 5BSD's kernel capability-based IPC substrate: a
transport, supervision, and policy layer where **the file descriptor is
the credential**. A capability is an fd connected to a kernel service;
holding the fd is holding the authority, and every attenuation of that
authority is a one-way operation on the fd itself.

Earlier internal names for this subsystem appear in older commit
messages; `mac_capability` is the name, and the only name used in this
documentation.

## The problem it solves

Adding a Capsicum-aware kernel service to stock FreeBSD means new
`CAP_*` rights bits, a new `DTYPE_*` and `struct fileops`, usually a new
syscall, procstat support, and hand-rolled queue/lifecycle code.
`mac_capability` collapses this to one base-system change — one
descriptor type (`DTYPE_MAC_CAPABILITY`), standard Capsicum rights with
ioctl limits (commit `efa4872a3df`), and the `/dev/mac_capability`
device node — after which any
number of kernel services can be added as **loadable modules** with no
new syscalls or rights bits. It coexists with sockets, the way Mach
ports and Binder coexist with BSD sockets on other systems.

## Core model

A process opens `/dev/mac_capability` (mode 0600, root only — a broker
connects on behalf of unprivileged processes and passes the fd via
`SCM_RIGHTS`), issues `MAC_CAPABILITY_CONNECT` with a service name, and
receives an instance fd. All further traffic is ioctls on that fd:

- **Async**: `MAC_CAPABILITY_SENDMSG` / `MAC_CAPABILITY_RECVMSG` through
  bounded per-instance RX/TX queues, dispatched to the service's
  `co_handler` on a taskqueue.
- **Sync**: `MAC_CAPABILITY_CALL` runs the service's `co_call` in the
  caller's thread.

Messages carry up to 32 attached fds; attached descriptors keep their
full Capsicum rights, ioctl allowlists, and transfer/exec/fork
propagation state. Instance fds are kqueue-integrated (`EVFILT_READ`,
`EVFILT_WRITE`, `EV_EOF` on revocation) and delegable via fork, dup, and
`SCM_RIGHTS`.

## Process nonces

Every credential carries a kernel-assigned 64-bit **nonce** identifying
the running program: inherited across `fork`, rotated on `exec`, never
settable from userspace (zero is reserved). It is implemented as a MACF
credential label in the core module and exposed to kernel code as
`mac_capability_proc_nonce(cred)`. Every received message and call
carries the peer's nonce in a kernel-stamped credential trailer; the
`identity` service answers `IDENTITY_OP_SELF` and, given a procdesc,
`IDENTITY_OP_QUERY`. Nonces are the subject identity for all
capability policy (shields, isolation claims, system gates).

## Capability narrowing

Rights only ever shrink. Five composable mechanisms:

1. `cap_rights_limit()` / `cap_ioctls_limit()` — standard Capsicum.
2. `MAC_CAPABILITY_REVOKE_SEND/RECV/CALL/MINT` — one-way instance
   latches (a stripped operation later returns `EACCES`).
3. `cap_xfer_limit(fd, CAP_XFER_NONE)` — block fd transfer.
4. `cap_cloexec_limit(fd, CAP_CLOEXEC_ONCE)` — survive one exec, then lock.
5. `cap_clofork_limit(fd, CAP_CLOFORK_ONCE)` — inherit into one child, then
   lock both entries.

Combined, a supervisor can hand a child a send-only, non-transferable,
single-generation handle. See the [Capability Transfer](capability-transfer.md) chapter for the
`cap_xfer` mechanics.

## Channels

The `channel` service (async) provides bidirectional
userspace-to-userspace messaging: `CHANNEL_OP_CREATE` returns two
connected fds; revoking or closing one end delivers `ECONNRESET` to the
peer. Channels were originally called **pairs**; the rename landed in
commit `a388482383b` and userspace builds on them through `libchannel`.
Channels give atomic messages, ordered descriptor attachments, 64-bit
reply tokens, authenticated badge/credential metadata, bounded queues,
and peer-death signaling.

## Kernelstore and test fixtures

Two in-tree services exist purely as test fixtures for the framework:
`mac_capability_test_kernelstore.c` (a synchronous key-value store
exercising `co_call`) and `mac_capability_test_keystore.c` (the async
equivalent). They back the ATF suite in `/usr/src/tests/sys/mac_capability/`
and are built as separate modules (`sys/modules/mac_capability_test_*`).

## Loadable service modules

A service implements `co_handler` (async), `co_call` (sync), or both,
plus optional lifecycle callbacks (`co_connect`, `co_init`, `co_revoke`,
`co_fdclose`), and registers with `mac_capability_service_create()`.
The framework owns descriptor creation, queuing, credential stamping,
and teardown. Services shipped today, each its own module under
`/usr/src/sys/dev/mac_capability/`:

| Service | Mode | Purpose |
|---|---|---|
| `identity` | sync | nonce queries (self, procdesc target) |
| `capprotect` | sync | per-nonce process shields (ptrace, signals, visibility, fork, ...) |
| `system` | sync | gate tokens for kldload, reboot, sysctl, kenv, audit, ... |
| `isolation` | sync | file/dir, Unix-socket, network, vsock, and jail claims + tokens |
| `coalition` | sync | resource groups: enlist, terminate, deadlines, watchdogs, rusage |
| `node` | sync | per-process inspection/control via procdesc |
| `accounting` | sync | racct/rctl charge, release, rules |
| `channel` | async | bidirectional process-to-process messaging |
| `mount` | sync | whitelisted filesystem mounting for sandboxed/jailed processes |

## Authorization limits

The token-activation modules (isolation, capprotect, system) enforce
per-nonce authorization-entry limits so a process minting and activating
tokens in a loop cannot exhaust kernel memory: `ENOSPC` past
`kern.mac_capability_isolation.max_auth`-style sysctls (default 4096,
0 = unlimited), with deduplication of matching entries and read-only
`auth_count` counters (added in commit `112faea6e8f`, pre-rename).
Service-level limits bound queue depth (max 4096), notification TX
(soft limit plus a 4x hard limit), instances (default 1024), and
message size (16 KiB fixed).

## MACF hook integration

Enforcement — not just transport — happens through the MAC framework.
The core module registers the nonce credential label; `isolation`
enforces claims via MAC hooks on vnode operations, socket bind/connect,
and jail create/get/set/remove/attach (owner nonce always passes,
foreign nonces need a covering token); `capprotect` shields via
ptrace/signal/visibility hooks; `system` gates privileged syscalls.
Denials and allows fire DTrace probes under the `mac_capability_*`
providers, and `kern.mac_capability.*` sysctls expose service and
instance counts.

## Relationship to Capsicum

`mac_capability` builds on Capsicum rather than replacing it. Instance
fds are fully usable inside `cap_enter()` (given `CAP_IOCTL` and an
allowlisted command); a sandboxed process cannot open new
`/dev/mac_capability` connections, forge kernel-stamped credentials,
re-escalate narrowed rights, or call `mac_syscall()` (not `CAPENABLED` —
`MAC_CAPABILITY_CALL` is the sanctioned path). Where Capsicum answers
"what operations may this fd perform", mac_capability adds who is
speaking (nonces), to whom (services), revocation, and delegation policy.

## Source layout

```
/usr/src/sys/dev/mac_capability/     core, dev node, KPI, per-service modules
/usr/src/sys/modules/mac_capability* module builds
/usr/src/tests/sys/mac_capability/   ATF kernel tests (kyua)
/usr/src/share/dtrace/mac_capability-*  DTrace scripts
/usr/src/usr.sbin/authorityd/           authority authority daemon
/usr/src/usr.sbin/serviced/          service manager daemon
```

**Status.** Design phases 1–7 (identity, shields, isolation, coalitions,
node, accounting, channels, mount, system gates, two-daemon
architecture) are complete. Kernel-to-kernel capability communication
and registrar-based (per-supervisor/per-jail) service naming are
designed direction only, not yet built. Full architecture reference:
`/usr/src/docs/mac_capability-architecture.md`.
