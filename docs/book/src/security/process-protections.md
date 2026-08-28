# Per-Process Protections

5BSD layers several per-process enforcement mechanisms below the Linux
API: **capprotect** integrity shields, **vnode_claim** descriptor
binding, **coalitions** for coordinated resource lifecycle, and a set of
Capsicum and process-descriptor enhancements. All of them key off the
MAC_CAPABILITY cryptographic program nonce — a per-credential identity
that rotates on `exec` and is inherited on `fork` — so a Linux binary is
governed by an identity it cannot read or forge.

## capprotect — integrity shields

capprotect is a MAC_CAPABILITY service
(`sys/dev/mac_capability/mac_capability_capprotect.c`) that lets a
process shield itself, enforced by MACF hooks the shielded process — and
every other process — cannot bypass. A shield is requested over the
capability channel with `CP_OP_SHIELD` and is **nonce-scoped**: it
protects the calling program identity, not a bare PID.

Shield flags (`sys/dev/mac_capability/mac_capability_capprotect_proto.h`)
divide into protections and restrictions:

| Flag | Effect |
|------|--------|
| `CP_SF_PTRACE` | block ptrace attach |
| `CP_SF_SIGNAL` | block signals (except SIGKILL/SIGCONT) |
| `CP_SF_VISIBLE` | hide from ps/top/procfs |
| `CP_SF_WAIT` | block wait4 from non-parent |
| `CP_SF_SIGKILL` / `CP_SF_SIGCONT` | unkillable / unstoppable |
| `CP_SF_SCHED` | block setpriority/cpuset manipulation |
| `CP_SF_CORE` | suppress core dumps (prevent secret leakage) |
| `CP_SF_KTRACE` | block ktrace (passive information disclosure) |
| `CP_SF_NOPRIVS` | strip all privileges (`priv_check` returns EPERM) |
| `CP_SF_NOFORK` / `CP_SF_NOEXEC` / `CP_SF_NOSOCK` | block fork, execve, new sockets |
| `CP_SF_NOIPC` / `CP_SF_NOFDRECV` | block SysV/POSIX IPC, incoming SCM_RIGHTS |

`CP_SF_PROTECT` and `CP_SF_RESTRICT` group these; `CP_SF_ALL` is both.
Shields are **refcounted per flag**: additional shield descriptors for
the same nonce add their own flags, and closing a shield fd removes only
the flags that descriptor contributed. The service also exposes token
minting and authorization (`CP_OP_MINT`, `CP_OP_AUTHORIZE`) and
confinement operations (`CP_OP_CAPMODE` enters Capsicum capability mode,
`CP_OP_CHROOT` changes the filesystem root via an attached directory fd).

Shields interact with normal supervision: 5BSD's own `serviced` applies
its shield last, after readiness signalling, and omits `CP_SF_VISIBLE`
(which blocks syslog delivery) and `CP_SF_SIGNAL` (which blocks `pdkill`
from its supervisor). System daemons such as `authorityd` run shielded, with
init-integrity tests covering the configuration.

## vnode_claim — per-descriptor identity binding

vnode_claim attaches an ACL of allowed process identities to a file
descriptor. Possession of the fd is no longer sufficient authority:

- fds propagated via `SCM_RIGHTS` to a process outside the ACL are useless;
- `exec` produces a new identity, revoking access;
- a lock mode denies all operations on a descriptor;
- batch operations cover multiple fds and processes.

It is best suited to anonymous descriptors (pipes, socketpairs, shared
memory) that have no path to re-open.

**Status:** vnode_claim is a standalone module (about 2,000 lines, 20+
tests) that is not yet integrated into the 5BSD tree. The roadmap
migrates its private identity token to the MAC_CAPABILITY nonce so one
identity answers capprotect, vnode_claim, and coalition questions.

## Coalitions — capability-based resource groups

A coalition (`sys/dev/mac_capability/mac_capability_coalition.c`) is a
MAC_CAPABILITY sync service that groups kernel resources under a single
file descriptor held by a supervisor. **Closing the coalition fd
terminates every member.** Members are enlisted by fd type: process
descriptors, jail descriptors, sockets, POSIX shared memory,
MAC_CAPABILITY instances (revoked via `mac_capability_instance_revoke()`),
and other coalitions (nesting, with cycle detection at enlist time and
cascade termination).

The operation set (`mac_capability_coalition_proto.h`):

```c
COALITION_OP_ENLIST        /* add a member fd */
COALITION_OP_ENLIST_SET    /* batch enlist; stops on first error */
COALITION_OP_TERMINATE     /* kill all members now */
COALITION_OP_GRACEFUL      /* SIGTERM -> grace period -> SIGKILL */
COALITION_OP_SET_SIGNAL    /* choose the termination signal */
COALITION_OP_SET_DEADLINE  /* auto-terminate after timeout_ms (0 cancels) */
COALITION_OP_SET_WATCHDOG  /* require heartbeats; 0 disables */
COALITION_OP_HEARTBEAT     /* supervisor liveness ping */
COALITION_OP_SET_LEADER    /* leader death triggers termination */
COALITION_OP_JOIN / _STAT / _RUSAGE
```

Deadlines bound a workload's lifetime; watchdogs terminate the coalition
if the supervisor stops sending heartbeats; a designated leader (process
exit, jail destruction, or capability revocation) triggers group
termination. `COALITION_OP_RUSAGE` reports aggregate CPU, memory, and
fault usage across members. DTrace SDT probes cover the lifecycle.
Tests: `tests/sys/mac_capability/mac_capability_coalition_test.c`
(40+ ATF tests).

## Capsicum enhancements

Beyond stock Capsicum, 5BSD adds descriptor-lifecycle limits in
`sys/kern/sys_capability.c`, exported from libc at `FBSD_1.9`:

- `cap_xfer_limit(fd, state)` — restrict how many times an fd may be
  passed over `SCM_RIGHTS`: `CAP_XFER_UNLIMITED`, `_TWICE`, `_ONCE`, or
  `_NONE`.
- `cap_cloexec_limit(fd, state)` / `cap_clofork_limit(fd, state)` — force
  and optionally lock close-on-exec / close-on-fork behavior
  (`UNLOCKED` → `ONCE` → `LOCKED`, monotonically increasing rank).
- `cap_xfer_fcntls_limit(fd, rights)` — bound the fcntl rights an fd
  carries after transfer.

Supervision code uses these to pin inherited descriptors: `authorityd` locks
its channel end with `cap_xfer_limit(fd, CAP_XFER_NONE)` so the fd cannot
leak to a third process.

## Process descriptor semantics

5BSD treats a process descriptor as a true capability: holding it is
sufficient authority. `pdkill(2)` and `pdwait` no longer apply ambient
identity checks (`p_cansignal()`, `p_canwait()`, MAC hooks, jail and
P_SUGID restrictions) that could override capability-granted authority —
previously a parent could not `pdkill` its own capprotect-shielded child
after `exec` rotated the nonce. Capsicum rights on the descriptor remain
the sole gate, matching `procdesc_close()`, which has always delivered
SIGKILL unconditionally.

## One identity across layers

The roadmap converges all of the above on the MAC_CAPABILITY nonce:
capprotect asks "can this nonce signal/trace/see that nonce?",
vnode_claim asks "is this nonce in this descriptor's ACL?", coalitions
enlist all processes sharing a nonce, and nonce-keyed resource accounting
extends `COALITION_OP_RUSAGE` system-wide. **Status:** capprotect uses
the nonce today; nonce-based coalition enlistment and nonce accounting
are designed but not yet built.
