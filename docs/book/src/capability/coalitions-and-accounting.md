# Coalitions and Accounting

A coalition is a group of kernel resources, processes first among them,
held under one `mac_capability` instance so that they live and die
together. 5BSD has it because a supervisor that launches a sandboxed unit
needs a handle that outlives PIDs, survives the unit forking helpers, and
cannot be argued with: closing the coalition kills everything in it. The
accounting service beside it exposes racct(4) and rctl(8) through the same
descriptor discipline. This chapter covers both, the manifest `limits`
block that switchboard applies at launch, and what those limits do and do
not promise.

## What a coalition is

A coalition is not a new descriptor type. It is an instance of the
`coalition` kernel service ([the framework chapter](mac-capability.md)),
reached by `MAC_CAPABILITY_CALL` or asynchronously by `MAC_CAPABILITY_SENDMSG`,
with state-change notifications on `MAC_CAPABILITY_RECVMSG`. Members are
enlisted by attaching their descriptors to the request, never by number,
and enlisting requires already holding the right that a teardown would
exercise, so the coalition can never perform a release its enlister could
not have performed alone:

| Member type | Right required to enlist | What termination does |
|---|---|---|
| `DTYPE_PROCDESC` | `CAP_PDKILL` | delivers the coalition's signal (default `SIGKILL`) |
| `DTYPE_JAILDESC` | `CAP_JAIL_REMOVE` | `prison_remove()` |
| `DTYPE_MAC_CAPABILITY` | (instance held) | revokes the instance; a coalition-backed instance is a nested coalition |
| `DTYPE_SOCKET` | `CAP_SHUTDOWN` | `soshutdown(SHUT_RDWR)` |
| `DTYPE_SHM` | `CAP_FTRUNCATE` | (member released) |

Nesting is bounded at sixteen levels (`COALITION_MAX_NESTING`) and cycles
are rejected at enlist time with `ELOOP`. A process may belong to one
coalition; `COALITION_OP_JOIN` lets the caller enlist itself without a
descriptor, and because it needs the caller's process context it is
call-only.

The operations, from `sys/dev/mac_capability/mac_capability_coalition_proto.h`:

| Operation | Effect |
|---|---|
| `ENLIST`, `ENLIST_SET` | add one member, or several in one call (stops at the first error) |
| `JOIN` | the caller joins |
| `TERMINATE` | signal every process, remove every jail, shut down every socket, revoke every instance |
| `GRACEFUL` | deliver a signal, wait `timeout_ms`, then `SIGKILL` survivors |
| `SET_SIGNAL` | choose the termination signal |
| `SET_DEADLINE` | time-bounded lifetime: signal at `timeout_ms`, optional grace, then `SIGKILL` |
| `SET_WATCHDOG`, `HEARTBEAT` | dead-man switch: terminate unless a heartbeat arrives within `timeout_ms` |
| `SET_LEADER` | name a process whose exit terminates the whole coalition |
| `STAT` | member counts by type, flags (`COF_*`), signal, nesting depth |
| `RUSAGE` | aggregate RSS, VSZ, CPU time, faults and block I/O across process members |

Notifications carry a `COALITION_NOTE_*` bitmask: `MEMBER_ADDED`,
`MEMBER_REMOVED`, `TERMINATING`, `TERMINATED`, `LEADER_DIED`,
`DEADLINE_FIRED`, `WATCHDOG_FIRED`, `GRACE_STARTED`. While a coalition is
terminating or in a grace period (`COF_TERMINATING`, `COF_GRACE_ACTIVE`) new
members are refused with `EBUSY`. Errors come back as raw errno values in
the reply's `status` field; the man page lists them.

## Fork, pdfork and jails

Membership follows the process family. The service registers a
`process_fork` event handler: an ordinary `fork(2)` child of a member is
enlisted automatically (the `fork-inherit` probe fires), so a unit that
forks workers keeps them under its supervisor's handle without any
cooperation. A `pdfork(2)` child is deliberately not inherited: a process
created with a descriptor is an independently launched process, and
whoever holds its procdesc enlists it into the right coalition explicitly.
Auto-enlisting it would bind it to its creator's group and make the
intended enlist fail, since a process joins only one coalition.

A jail is held while it is a member: enlisting a jail descriptor takes a
`prison_hold()` and refuses a prison that is no longer valid. On
termination the service takes `allprison_lock` and calls `prison_remove()`
only if the prison is still alive. When a jail dies on its own, a per-prison
OSD slot points back at the membership and a deferred task removes the
member outside the prison locks, fires `MEMBER_REMOVED`, and, if the jail
was the leader, terminates the coalition. That deferral is what keeps
jail death and coalition teardown from freeing under each other; the
inventory records the one use-after-free found in this path as fixed in
44fb4ada4b0b, and the churn and jail-death-race tests in
`tests/sys/mac_capability/mac_capability_coalition_test.c` exercise it.

## Limits

Two sysctls bound the whole facility, and both are soft:
`kern.mac_capability_coalition.max` (default 1024 coalitions) and
`kern.mac_capability_coalition.max_members` (default 8192 members across all
coalitions); zero disables either. Concurrent connect, enlist and fork can
overshoot by the number of racing callers, which is why they are documented
as best effort. An explicit enlist over the limit fails; a `fork(2)` by a
member over the limit still succeeds, but the child is left outside the
coalition, a warning is logged and the `deny` probe fires with reason
`fork-limit`. `kern.mac_capability_coalition.count` and `.members` report
the live totals.

## How the plane uses coalitions

switchboard creates one coalition per native unit before it forks the
unit. It mints the instance on the coalition service descriptor capsule
delegated to it at startup, or asks capsule for one
(`CAPSULE_OP_CREATE_COALITION`) when it holds none
(`usr.sbin/switchboard/mac_capability_direct.c`), and immediately confines
the descriptor to itself with `cap_xfer_limit(CAP_XFER_NONE)`,
`cap_clofork_limit(CAP_CLOFORK_LOCKED)` and
`cap_cloexec_limit(CAP_CLOEXEC_LOCKED)` (`usr.sbin/switchboard/execute.c`).
After `pdfork(2)` it enlists the unit's process descriptor and names it the
leader, so the unit's death tears down whatever it forked. Stopping a unit
is `pdkill(SIGTERM)` on the leader plus `COALITION_OP_GRACEFUL` with
`SIGTERM` and the manifest's `stop_timeout`, then `TERMINATE` for anything
that ignored it (`usr.sbin/switchboard/supervisor.c`). capsule's own wrappers in
`usr.sbin/capsule/mac_capability_coal.c` cover enlist, set-leader,
set-deadline and terminate.

The kernel watchdog is not what the manifest `watchdog { interval }` key
uses. That feature is implemented by switchboard over the unit's service
channel with `service_heartbeat(3)`; no shipped component calls
`COALITION_OP_SET_WATCHDOG` or `COALITION_OP_HEARTBEAT`. Both remain
available to a supervisor that wants a kernel-enforced dead-man switch.

## The accounting service

The `accounting` service (`mac_capability_accounting(4)`) is a
capability-shaped front end to racct and rctl. Connecting requires
`PRIV_ACCT`, which under the stock priv(9) rules means root; this is one
of the transitional uid gates listed in
[The Authority Model](authority-model.md). Every operation targets the
process named by an attached process descriptor, or the caller when none
is attached.

| Operation | Kernel primitive | Notes |
|---|---|---|
| `ACCT_OP_CHARGE` | `racct_add()` | any `RACCT_*` resource up to `RACCT_MAX`; `ACCT_STATUS_DENIED` when a limit would be exceeded |
| `ACCT_OP_RELEASE` | `racct_sub()` | refused for resources that are not droppable (`RACCT_CAN_DROP`); the amount is clamped to current usage so a delegated holder cannot drive the counter negative |
| `ACCT_OP_SET` | `racct_set()` | absolute value |
| `ACCT_OP_ADD_RULE`, `ACCT_OP_REMOVE_RULE` | `rctl_rule_add()` / `_remove()` | actions `ACCT_RULE_DENY`, `LOG`, `THROTTLE`, `SIGNAL` (with a signal number), on a `RACCT_*` resource and a threshold |
| `ACCT_OP_GET_RULES` | rule walk | up to `ACCT_MAX_RULES` (16) entries |

The resources it charges are therefore whatever racct(4) counts: CPU
time, RSS, swap, memory locked, file descriptors, processes, and the rest
of the `RACCT_*` set. A kernel built without `RACCT` or `RCTL` answers
`ACCT_STATUS_ERR`; 5BSD kernels build with both on by default (the
`RACCT_DEFAULT_TO_DISABLED` option is gone, so rctl rules are effective
without a loader knob). Related read-only views live in the `node`
service: `NODE_OP_GET_RACCT` reads one counter with its limit and headroom,
`NODE_OP_GET_RLIMIT`/`SET_RLIMIT` read and set one rlimit, and
`NODE_OP_RUSAGE` reads live usage, all through an attached process
descriptor.

No shipped daemon drives the accounting service today. libservice(3)
recognises `accounting` as a capability name a launcher may deliver, and
the ATF program `mac_capability_accounting_test.c` proves the operations,
but neither switchboard nor any provider charges or sets rules through it.
Its DTrace provider is `mac_capability_acct` (`state`, `deny`).

## Manifest limits

Resource ceilings for a unit are declared in its `Unit.ucl`
(`switchboard(5)`, [Bundles and Manifests](../plane/bundles-and-manifests.md)):

```ucl
limits {
    memory = "512M";    # RLIMIT_AS, bytes; K/M/G/T suffixes are powers of 1024
    cpu    = 3600;      # RLIMIT_CPU, seconds
    nproc  = 64;        # RLIMIT_NPROC
    nofile = 1024;      # RLIMIT_NOFILE
    stack  = "8M";      # RLIMIT_STACK
    fsize  = "1G";      # RLIMIT_FSIZE
    core   = 0;         # RLIMIT_CORE; the default even when limits {} is absent
}
umask = "0077";         # default
level = "standard";     # background | standard | interactive
```

`lib/libcapbundle/libcapbundle_parse.c` accepts an integer or a size string
per key, rejects negatives, unknown suffixes and trailing text, and stores
`SVC_LIMIT_UNSET` for anything omitted. switchboard applies the block in
the child after `pdfork(2)` and before the credential drop and `fexecve(2)`
(`execute.c`): each present value becomes both the soft and the hard limit
through `setrlimit(2)`, `core` is always set (zero unless overridden),
`level` maps to `nice` +10 for `background` and -5 for `interactive`, and
`umask` defaults to 0077. A failure to apply any of them is fatal to the
launch: a unit that asked to be contained is never run uncontained. The
`interactive` boost is honoured only for a base-system bundle; application
and per-user-agent units are clamped to `standard`
([The Management Model](../plane/management-model.md)).

## Memory is a limit, not a grant

`limits.memory` is `RLIMIT_AS`: a ceiling on one process's address space.
It does not reserve memory, it does not measure resident set size, it is
not shared across the processes of a coalition, and nothing enforces it
against the unit's forked children beyond their inheriting the same
per-process rlimit. The same is true of every key in the block: they are
the classic setrlimit(2) ceilings, applied early and made unraisable. A
unit that wants an aggregate view can read `COALITION_OP_RUSAGE`, which
reports summed RSS and VSZ across its process members, but that is
observation, not enforcement. Group-wide enforcement is what rctl(8) rules
are for, and the plane does not create any from the manifest; an operator
who needs a per-unit memory cap that survives forking must add an rctl
rule, or a supervisor must use the accounting service, today.

## Tests and status

`tests/sys/mac_capability/mac_capability_coalition_test.c` covers enlist by
type, nesting and cycle rejection, deadline, watchdog, leader death,
graceful termination, fork inheritance, jail members and limit exhaustion;
`mac_capability_accounting_test.c` covers charge, release, set and rules;
`lib/libcapbundle/tests` pins the `limits` parser. The coalition and
accounting services are shipped and static. Open items: the coalition
watchdog has no plane user, the accounting service has no plane user, and
manifest limits remain per-process rlimits with no racct-backed group cap.
