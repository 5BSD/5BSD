# Per-Process Protections

5BSD layers several per-process enforcement mechanisms beneath every
application ABI — native and Linux alike: **capprotect** integrity shields,
**coalitions** for coordinated resource lifecycle, and **vnode_claim**
descriptor binding. All three key off the `mac_capability` program nonce
(see [the framework chapter](mac-capability.md)) — a per-credential identity
that rotates on `exec` and is inherited on `fork` — so a program is governed
by an identity it cannot read or forge. The label-based `mac_abac` policy,
which composes with these mechanisms, is covered with the
[MAC Capability Framework](mac-capability.md).

## capprotect — integrity shields

capprotect is a `mac_capability` service that lets a process shield itself,
enforced by MACF hooks the shielded process — and every other process —
cannot bypass. A shield is requested over the capability channel and is
**nonce-scoped**: it protects the calling program identity, not a bare PID.
Shield flags divide into outward protections — blocking debugger attach,
signals, visibility in process listings, and similar outside interference —
and self restrictions — dropping privileges and giving up fork, exec, new
sockets, and IPC. Shields are refcounted per flag, so independent shield
descriptors compose and each close removes only its own contribution.

Shields interact with normal supervision: `serviced` applies its shield
last, after readiness signalling, and omits the flags that would block its
own supervision paths. A unit manifest can request a shield declaratively
via its `protect` field — see [Capability Bundles](capability-bundles.md).

## Coalitions — capability-based resource groups

A coalition is a `mac_capability` service that groups kernel resources under
a single file descriptor held by a supervisor. **Closing the coalition fd
terminates every member.** Members are enlisted by fd — processes, jails,
sockets, capability instances, resource handles, and nested coalitions — and
enlisting always requires already holding the right a teardown would
exercise, so coalition teardown never performs a release the enlister could
not have performed itself. Beyond enlist and terminate, the service provides
graceful termination, lifetime deadlines, supervisor watchdogs, leader-death
triggers, and aggregate resource reporting.

## Process descriptor semantics

5BSD treats a process descriptor as a true capability: holding it is
sufficient authority. `pdkill(2)` and `pdwait(2)` apply no ambient identity
checks that could override capability-granted authority — a parent's
`pdkill` of its own capprotect-shielded child works even after `exec`
rotates the nonce. Capsicum rights on the descriptor are the sole gate. The
per-descriptor transfer, exec, and fork locks that keep such descriptors
from leaking are covered in the
[MAC Capability Framework](mac-capability.md).

## vnode_claim — per-descriptor identity binding

vnode_claim attaches an ACL of allowed process identities to a file
descriptor, so possession alone is no longer sufficient authority: fds
propagated to a process outside the ACL are useless, `exec` produces a new
identity and revokes access, and a lock mode denies all operations. It is
best suited to anonymous descriptors (pipes, socketpairs, shared memory)
that have no path to re-open.

vnode_claim is a standalone module not yet integrated into the 5BSD tree.
