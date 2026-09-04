# Per-Process Protections

5BSD layers several per-process enforcement mechanisms beneath every
application ABI — native and Linux alike: **capprotect** integrity
shields, **coalitions** for coordinated resource lifecycle,
**vnode_claim** descriptor binding, and the **mac_abac** attribute
policy. The first three key off the `mac_capability` program nonce (see
[the framework chapter](mac-capability.md)) — a per-credential identity
that rotates on `exec` and is inherited on `fork` — so a program is
governed by an identity it cannot read or forge.

## capprotect — integrity shields

capprotect is a `mac_capability` service that lets a process shield
itself, enforced by MACF hooks the shielded process — and every other
process — cannot bypass. A shield is requested over the capability
channel and is **nonce-scoped**: it protects the calling program
identity, not a bare PID.

Shield flags divide into outward protections — block ptrace attach,
signals (except SIGKILL/SIGCONT), visibility in `ps`/`top`/procfs,
non-parent `wait4`, scheduling manipulation, core dumps, and ktrace —
and self restrictions — strip all privileges, and block fork, exec, new
sockets, IPC, and incoming `SCM_RIGHTS`. Group aliases (`protect`,
`restrict`, `all`) expand to their sets. Shields are **refcounted per
flag**: additional shield descriptors for the same nonce add their own
flags, and closing a shield fd removes only the flags that descriptor
contributed.

Shields interact with normal supervision: `serviced` applies its shield
last, after readiness signalling, and omits the visibility flag (which
blocks syslog delivery) and the signal flag (which blocks `pdkill` from
its supervisor). A unit manifest can request a shield declaratively via
its `protect` field — see [Capability Bundles](capability-bundles.md).

## Coalitions — capability-based resource groups

A coalition is a `mac_capability` service that groups kernel resources
under a single file descriptor held by a supervisor. **Closing the
coalition fd terminates every member.** Members are enlisted by fd:
process descriptors, jail descriptors, sockets, POSIX shared memory,
`mac_capability` instances (revoked on teardown), resource descriptors
(TrustedZFS handles, envfds, crypto handles — teardown drives each
family's own safe last-close path), and other coalitions (nesting, with
cycle detection). Enlisting always requires already holding the right a
teardown would exercise, so coalition teardown never performs a release
the enlister could not have performed itself.

Beyond enlist/terminate, the service provides graceful termination
(SIGTERM, grace period, SIGKILL), deadlines that bound a workload's
lifetime, watchdogs that terminate the coalition if the supervisor stops
sending heartbeats, a designated leader whose death triggers group
termination, and aggregate rusage reporting.

## Process descriptor semantics

5BSD treats a process descriptor as a true capability: holding it is
sufficient authority. `pdkill(2)` and `pdwait(2)` apply no ambient
identity checks (`p_cansignal()`, jail and P_SUGID restrictions) that
could override capability-granted authority — a parent's `pdkill` of its
own capprotect-shielded child works even after `exec` rotates the nonce.
Capsicum rights on the descriptor are the sole gate.
The per-descriptor transfer, exec, and fork locks that keep such
descriptors from leaking are covered in the [MAC Capability
Framework](mac-capability.md).

## mac_abac — attribute-based access control

`mac_abac(4)` is 5BSD's label-based mandatory access control policy, a
loadable MACF module under `sys/security/mac_abac/`. Security labels are
sets of `key=value` attributes — on credentials, and on vnodes via a
system extended attribute — and kernel decisions use an ordered,
first-match rule table: `allow`/`deny` actions over an operation mask
(vnode, process, socket, IPC, kenv, system), subject/object attribute
patterns, and optional context constraints (uid, gid, jail, TTY,
Capsicum mode). Rules are grouped into sets that can be prepared
inactive and atomically swapped, so policy is replaced without an
enforcement gap; any load failure restores the previous table whole.

`mac_abacd(8)` compiles and loads `/etc/mac_abac.conf` (UCL/JSON or a
compact line format); `mac_abac_ctl(8)` manages rules and sets, applies
labels (including atomic and recursive labeling), and offers a kernel
dry-run decision test. Enforcement modes are `disabled`, `permissive`
(log only), and `enforcing`, with a one-way lock latch that freezes the
policy until reboot. Composition is deny-wins: `mac_abac` can further
restrict Capsicum, `mac_capability`, and capprotect, but can never
re-grant an operation another policy denied. The module ships in the
`mac-abac` pkgbase package.

## vnode_claim — per-descriptor identity binding

vnode_claim attaches an ACL of allowed process identities to a file
descriptor, so possession alone is no longer sufficient authority: fds
propagated to a process outside the ACL are useless, `exec` produces a
new identity and revokes access, and a lock mode denies all operations.
It is best suited to anonymous descriptors (pipes, socketpairs, shared
memory) that have no path to re-open.

vnode_claim is a standalone module not yet integrated into the 5BSD
tree.
