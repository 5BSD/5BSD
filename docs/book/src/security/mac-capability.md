# The MAC Capability Framework

`mac_capability` is 5BSD's kernel capability-based IPC substrate: a
transport, supervision, and policy layer where **the file descriptor is
the credential**. A capability is an fd connected to a kernel service;
holding the fd is holding the authority, and every attenuation of that
authority is a one-way operation on the fd itself. This chapter covers
the framework, the per-descriptor transfer controls built on it, and the
descriptor types that make up the capability plane. For *why* authority
is a held descriptor at all, see [The Authority
Model](authority-model.md).

## The problem it solves

Without this framework, adding a Capsicum-aware kernel service means new
`CAP_*` rights bits, a new `DTYPE_*` and `struct fileops`, usually a new
syscall, and hand-rolled queue/lifecycle code. `mac_capability`
collapses this to one base-system change — one descriptor type
(`DTYPE_MAC_CAPABILITY`), standard Capsicum rights with ioctl limits,
and the `/dev/mac_capability` device node — after which any number of
kernel services can be added as **loadable modules** with no new
syscalls or rights bits. It coexists with sockets, the way Mach ports
and Binder coexist with BSD sockets on other systems.

## Core model

A process opens `/dev/mac_capability` (mode 0600, root only — a broker
connects on behalf of unprivileged processes and passes the fd via
`SCM_RIGHTS`), issues `MAC_CAPABILITY_CONNECT` with a service name, and
receives an instance fd. All further traffic is ioctls on that fd:
async send/receive through bounded per-instance queues, or a synchronous
call run in the caller's thread. Messages carry up to 32 attached fds;
attached descriptors keep their full Capsicum rights, ioctl allowlists,
and transfer/exec/fork propagation state. Instance fds are
kqueue-integrated (`EV_EOF` on revocation) and delegable via fork, dup,
and `SCM_RIGHTS`. Last close is a full teardown: queues drain, the
service's revoke hook fires exactly once, and peers see `ECONNRESET`.

## Process nonces

Every credential carries a kernel-assigned 64-bit **nonce** identifying
the running program: inherited across `fork`, rotated on `exec`, never
settable from userspace. It is implemented as a MACF credential label
and exposed to kernel code as `mac_capability_proc_nonce(cred)`. Every
received message and call carries the peer's nonce in a kernel-stamped
credential trailer; the `identity` service answers self and
procdesc-targeted queries. Nonces are the subject identity for all
capability policy — shields, isolation claims, system gates.

## Channels

The `channel` service provides bidirectional userspace-to-userspace
messaging: `CHANNEL_OP_CREATE` returns two connected fds; revoking or
closing one end delivers `ECONNRESET` to the peer. Channels give atomic
messages, ordered descriptor attachments, reply tokens, authenticated
credential metadata, bounded queues, and peer-death signaling; userspace
builds on them through `libchannel`, and the **unforgeable channel
label** stamped on each endpoint is the client identity every capability
service keys on.

## Capability narrowing

Rights only ever shrink. The composable mechanisms:

1. `cap_rights_limit()` / `cap_ioctls_limit()` — standard Capsicum.
2. `MAC_CAPABILITY_REVOKE_SEND/RECV/CALL/MINT` — one-way instance
   latches (a stripped operation later returns `EACCES`).
3. The `cap_xfer` transfer, exec, and fork limits below.

Combined, a supervisor can hand a child a send-only, non-transferable,
single-generation handle.

## Capability transfer (cap_xfer)

Classic descriptor passing has no limits: `SCM_RIGHTS` to
any process, inherited by every fork, surviving every exec. For a
capability system that is a hole — a supervisor cannot hand a worker a
credential and be sure it stays there. `cap_xfer` closes it with
per-descriptor, monotonically tightening limits, kept deliberately
orthogonal to `cap_rights_t` so no `cap_rights_*` API can see or change
them. The syscall family (600–635 in `sys/kern/syscalls.master`, all
usable in capability mode):

- **Transfer states** — `cap_xfer_limit(2)`: `CAP_XFER_UNLIMITED`
  (default), `CAP_XFER_ONCE`, `CAP_XFER_NONE`. An `ONCE` send is a
  single hop that leaves **both** the sender and the receiver at `NONE`,
  so the receiver cannot forward it again; longer chains are built by
  re-attenuating each hop explicitly. A blocked send fails
  `ENOTCAPABLE`.
- **Post-transfer ceilings** — `cap_xfer_rights_limit(2)`,
  `cap_xfer_ioctls_limit(2)`, `cap_xfer_fcntls_limit(2)`: on a
  permitted send the receiver's rights are intersected with these
  ceilings, so a delegate gets attenuated authority while the sender
  keeps its own.
- **Locked exec/fork survival** — `cap_cloexec_limit(2)` /
  `cap_clofork_limit(2)`: classic `FD_CLOEXEC`/`FD_CLOFORK` are
  process-settable, so a compromised program can clear them; these add
  `LOCKED` (forced, unclearable) and `ONCE` (survive exactly one
  exec / inherit into exactly one child, then lock). This is how
  `serviced` injects bootstrap channels that survive its one supervised
  exec and nothing after.

Every state only tightens — widening fails — and every
descriptor-creating path yields `UNLIMITED`, so legacy software behaves
identically. Enforcement lives in the `SCM_RIGHTS` path and in the
`mac_capability` message path, which honors the same states for fds
attached to capability messages.

## Descriptor types

5BSD extends the descriptor table into a credential system. The types
it adds (`sys/sys/file.h`), all passable and all subject to
the `cap_xfer` controls above:

| Type | Represents | Key semantics |
|---|---|---|
| `DTYPE_MAC_CAPABILITY` | a connection to a named kernel service | the framework fd described above; narrowing via `CAP_IOCTL` allowlists |
| `DTYPE_PROCDESC` | a process, without PIDs | 5BSD adds `pdrfork(2)`, `pdwait(2)`, `pdself(2)`, `pdcmp(2)`, `pdincapmode(2)`; holding it is sufficient authority — no ambient identity checks override capability-granted `pdkill` |
| `DTYPE_JAILDESC` | a jail, without JIDs | an owning descriptor removes the jail on last close; delegable jail ownership |
| `DTYPE_ENVFD` | a named kernel-resident secret value | invisible to inspection tools; write-once sealing, capmode-only option, `explicit_bzero` on last close; can be minted `CAP_XFER_ONCE` for an exact one-hop handoff |
| `DTYPE_ZFSHANDLE` | a TrustedZFS dataset/pool handle | rights fixed at mint; verb ioctls only narrow; see [TrustedZFS](../storage/trustedzfs.md) |
| `DTYPE_CRYPTO` | a key or crypto session | monotonic rights, revoke, TTL; see [Cryptographic Services](crypto.md) |

A **coalition fd** is not a separate type: it is a `mac_capability`
instance connected to the coalition service, and enlisting a member
requires already holding the right a teardown would exercise
(`CAP_PDKILL` for a procdesc, `CAP_JAIL_REMOVE` for a jaildesc, and so
on) — closing the coalition terminates every member. See [Per-Process
Protections](process-protections.md).

## Loadable service modules

A service implements an async handler, a sync call, or both, plus
optional lifecycle callbacks, and registers with
`mac_capability_service_create()`; the framework owns descriptor
creation, queuing, credential stamping, and teardown. Services shipped
today, each its own module under `/usr/src/sys/dev/mac_capability/`:

| Service | Purpose |
|---|---|
| `identity` | nonce queries (self, procdesc target) |
| `capprotect` | per-nonce process shields (ptrace, signals, visibility, ...) |
| `system` | gate tokens for kldload, reboot, sysctl, kenv, audit, ... |
| `isolation` | file/dir, socket, network, vsock, and jail claims + tokens |
| `coalition` | resource groups: enlist, terminate, deadlines, watchdogs |
| `node` | per-process inspection/control via procdesc |
| `accounting` | racct/rctl charge, release, rules |
| `channel` | bidirectional process-to-process messaging |
| `mount` | whitelisted filesystem mounting for sandboxed processes |

Per-nonce authorization-entry limits, bounded queues, and fixed message
sizes prevent a process from exhausting kernel memory by minting in a
loop.

## MACF hook integration

Enforcement — not just transport — happens through the MAC framework:
`isolation` enforces claims via hooks on vnode operations, socket
bind/connect, and the jail lifecycle (owner nonce always passes, foreign
nonces need a covering token); `capprotect` shields via
ptrace/signal/visibility hooks; `system` gates privileged syscalls.
Denials and allows fire DTrace probes under the `mac_capability_*`
providers.

## Relationship to Capsicum

`mac_capability` builds on Capsicum rather than replacing it. Instance
fds are fully usable inside `cap_enter()`; a sandboxed process cannot
open new `/dev/mac_capability` connections, forge kernel-stamped
credentials, or re-escalate narrowed rights. Where Capsicum answers
"what operations may this fd perform", `mac_capability` adds who is
speaking (nonces), to whom (services), revocation, and delegation
policy.

The framework is exercised by an extensive ATF suite under
`tests/sys/mac_capability/`. Kernel-to-kernel capability communication
and registrar-based service naming are not provided.
