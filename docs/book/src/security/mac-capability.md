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

A process opens `/dev/mac_capability` (root only — a broker connects on
behalf of unprivileged processes and passes the fd via `SCM_RIGHTS`),
issues `MAC_CAPABILITY_CONNECT` with a service name, and receives an
instance fd. All further traffic is ioctls on that fd: async send/receive
through bounded per-instance queues, or a synchronous call run in the
caller's thread. Messages can carry attached fds; attached descriptors
keep their full Capsicum rights, ioctl allowlists,
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

## Fork and exec

The two process transitions treat identity differently, and deliberately
so. Across `fork()` the nonce is **inherited**: a child is the same
principal, because fork is how a program structures itself — a provider's
workers share their program's identity and the shields and claims keyed to
it. Across `exec()` the nonce **rotates**: a new program image is a new
principal, so authority keyed to the old identity never silently follows
into foreign code. Exec is a trust boundary; fork is not.

Held descriptors follow ordinary Unix inheritance across both transitions
unless the propagation locks below say otherwise: a clofork-locked
descriptor never reaches a child, and a cloexec-locked descriptor never
survives into a new image. Identity policy and descriptor policy compose —
a supervisor can let exactly one bootstrap channel cross exactly one exec,
into a program that runs under a fresh identity.

## Channels

The `channel` service is the communication primitive of the plane:
bidirectional kernel message passing between two processes over a connected
descriptor pair. Messages are atomic, queues are bounded, and peer death is
signaled rather than hidden — closing or revoking one end delivers
`ECONNRESET` to the other. Userspace drives channels through
`libchannel(3)`.

Two properties make channels a security substrate and not just a pipe.
First, every message carries **kernel-stamped sender identity** — the
peer's credentials and the unforgeable channel label — so a receiver never
trusts wire data for who is speaking. Second, descriptors ride along inside
messages under exactly the rights and transfer discipline described in this
chapter, so delegation over a channel is as controlled as delegation
anywhere else.

Channels are also how services are reached: a named-service lookup hands
back a channel endpoint, and every typed service protocol in this book runs
over one. The channel is why "reached by name, scoped by label" works —
the name gets you an endpoint, and the endpoint's kernel-stamped label is
the identity every provider keys its policy on.

## Capability narrowing

Rights only ever shrink. The composable mechanisms:

1. `cap_rights_limit()` / `cap_ioctls_limit()` — standard Capsicum.
2. `MAC_CAPABILITY_REVOKE_SEND/RECV/CALL/MINT` — one-way instance
   latches (a stripped operation later returns `EACCES`).
3. The `cap_xfer` transfer, exec, and fork limits below.

Combined, a supervisor can hand a child a send-only, non-transferable,
single-generation handle.

## Transfer and propagation

Descriptors are the capabilities, and capabilities **move**: over channels
between processes, into children across `fork()`, into new program images
across `exec()`. Delegation is how authority flows through the system, so
controlling that movement is part of the security model itself. Classic
descriptor passing has no controls at all — `SCM_RIGHTS` to any process,
inherited by every fork, surviving every exec — and for a capability system
that is a hole: a supervisor could not hand a worker a credential and be
sure it stayed there. The `cap_xfer` family closes it with per-descriptor,
one-way-tightening limits, kept deliberately orthogonal to Capsicum rights
so no rights API can see or loosen them.

**Transfer states** bound re-delegation. A sender can leave a descriptor
freely transferable (the default), limit it to **one** more hop, or make it
non-transferable. A one-hop send is consumed by the transfer itself: after
it, both the sender's and the receiver's copies are non-transferable, so the
recipient cannot forward what it was given — longer chains exist only if
each hop deliberately re-grants them. The canonical use is the minted login
session channel: the auth-agent attenuates it to one transfer, its single
reply delivers it, and it lands at the session non-transferable.

**Propagation locks** bound inheritance. Classic close-on-exec and
close-on-fork are process-settable, so a compromised program can simply
clear them; 5BSD adds locked variants that can never be cleared, plus a
survive-exactly-once mode — inherit into one child, or across one exec, then
lock. This is how `serviced` injects bootstrap channels that survive its one
supervised exec and nothing after.

**Post-transfer ceilings** narrow what arrives. A sender can stamp rights,
ioctl, and fcntl ceilings that take effect on the descriptor *after* it
transfers: the receiver's authority is intersected with the ceiling while
the sender keeps its own, so a delegate always gets a weaker capability than
its grantor held.

Every one of these states only tightens — widening fails — and every
descriptor-creating path starts unrestricted, so legacy software behaves
identically. Together they are what makes "authority is a held descriptor"
safe: delegation is always available, and attenuation-on-delegation is
always enforceable. Reference: `cap_xfer_limit(2)` and its family.

## Descriptor types

5BSD extends the descriptor table into a credential system. The types
it adds, all passable and all subject to the `cap_xfer` controls above:

| Type | Represents | Key semantics |
|---|---|---|
| `DTYPE_MAC_CAPABILITY` | a connection to a named kernel service | the framework fd described above; narrowing via `CAP_IOCTL` allowlists |
| `DTYPE_PROCDESC` | a process, without PIDs | holding it is sufficient authority — no ambient identity checks override capability-granted `pdkill`; a family of `pd*(2)` syscalls rounds out the model |
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
optional lifecycle callbacks, and registers with the framework, which
owns descriptor creation, queuing, credential stamping, and teardown.
The services shipped today each ship as their own module: `identity`
(nonce queries), `capprotect` (process shields), `system` (gate tokens
for privileged operations), `isolation` (resource claims and tokens),
`coalition` (resource groups), `node` (per-process inspection),
`accounting` (resource accounting), `channel` (process-to-process
messaging), and `mount` (whitelisted mounting for sandboxed processes).
Per-nonce limits, bounded queues, and fixed message sizes prevent a
process from exhausting kernel memory by minting in a loop.

## MACF hook integration

Enforcement — not just transport — happens through the MAC framework:
`isolation` enforces claims via hooks on vnode operations, socket
bind/connect, and the jail lifecycle (owner nonce always passes, foreign
nonces need a covering token); `capprotect` shields via
ptrace/signal/visibility hooks; `system` gates privileged syscalls.
Denials and allows fire DTrace probes under the `mac_capability_*`
providers.

## mac_abac — attribute-based access control

Beside the capability services sits `mac_abac`, 5BSD's label-based
mandatory access control policy — a loadable MACF module. Security labels
are sets of `key=value` attributes on credentials and files, and kernel
decisions come from an ordered, first-match rule table matching subject and
object attributes; rule sets can be prepared inactive and swapped
atomically, so policy is replaced without an enforcement gap. Composition
is deny-wins: `mac_abac` can further restrict Capsicum, `mac_capability`,
and capprotect, but can never re-grant an operation another policy denied.

Reference: `mac_abac(4)`, `mac_abacd(8)`, `mac_abac_ctl(8)`.

## Relationship to Capsicum

`mac_capability` builds on Capsicum rather than replacing it. Instance
fds are fully usable inside `cap_enter()`; a sandboxed process cannot
open new `/dev/mac_capability` connections, forge kernel-stamped
credentials, or re-escalate narrowed rights. Where Capsicum answers
"what operations may this fd perform", `mac_capability` adds who is
speaking (nonces), to whom (services), revocation, and delegation
policy.

Kernel-to-kernel capability communication and registrar-based service
naming are not provided.
