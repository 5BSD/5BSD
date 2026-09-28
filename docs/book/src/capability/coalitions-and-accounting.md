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
| `SET_RESPONSIBLE` | record, once, the coalition this one exists on behalf of (see below) |
| `STAT` | member counts by type, flags (`COF_*`), signal, nesting depth, the permanent id, the responsible id, both leader pids |
| `RUSAGE` | aggregate RSS, VSZ, CPU time, faults and block I/O across process members |

Notifications carry a `COALITION_NOTE_*` bitmask: `MEMBER_ADDED`,
`MEMBER_REMOVED`, `TERMINATING`, `TERMINATED`, `LEADER_DIED`,
`DEADLINE_FIRED`, `WATCHDOG_FIRED`, `GRACE_STARTED`. While a coalition is
terminating or in a grace period (`COF_TERMINATING`, `COF_GRACE_ACTIVE`) new
members are refused with `EBUSY`. Errors come back as raw errno values in
the reply's `status` field; the man page lists them.

## Fork, pdfork and jails

Membership follows the process family. The service registers a
`process_fork` event handler: every child of a member, `fork(2)` and
`pdfork(2)` alike, is enlisted automatically (the `fork-inherit` probe
fires), so a unit that forks or pdforks helpers keeps them under its
supervisor's handle and its identity without any cooperation. A membership
that was only inherited (or taken with `JOIN`) is not pinned: whoever holds
the process's descriptor may re-home it by enlisting the procdesc into
another coalition, which is how a factory hands a worker it created to a
consumer's coalition. An explicit procdesc enlist is pinned and a second
enlist fails with `EBUSY`. The launcher itself is in no coalition, so the
units it pdforks start unbound and are enlisted into their fresh coalition.

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

## Identity and responsibility

Every coalition carries a permanent 64-bit id, assigned when it is created
and never reused while the kernel runs. Across boots the id restarts, so
the switchboard pairs it with the kernel's boot id (`kern.boot_id`) in its
start audit record and in the tree header; a durable name for the thing
behind a coalition is the unit label or the session's uid, not the number. It is the stable name for a unit:
pids recycle and the unit's own process may fork helpers, but the coalition
id names the whole launch. `STAT` reports it, and the kernel exports it for
every member process as `ki_coalition` in `kinfo_proc`, so `ps -o coal`
and `procstat coalition` print it without any plane call.

A coalition may also record, once, its responsible parent: the coalition
on whose behalf it exists (`SET_RESPONSIBLE`, attaching the parent's
coalition or process descriptor, or naming the caller's own coalition, or
itself). This is the answer to "who caused this?", which the process tree
cannot give because switchboard is the fork parent of everything it
launches. The edge is attribution only. It never changes membership,
signals, nesting or lifetime; it cannot be changed after it is set; a chain
cannot loop and is bounded in length; and it survives the parent's
termination, pinning only the parent's record, so a chain can be walked
from any live process to its origin long after the origin exited. macOS
has the same concept as launchd's responsible process, which its endpoint
security and consent subsystems attribute to rather than to launchd.

switchboard decides the parent from the launch context, following the
[management model](../plane/management-model.md):

| Launched how | Responsible parent |
|---|---|
| a private helper opened by a unit | the requesting unit |
| a per-user unit requested by a unit with the same owner | the requesting unit |
| a per-user unit activated from its owner's login session | the session |
| a shared `system`/`core` provider activated on demand by any client | itself (a client that touched `system.Crypto` first does not own it) |
| boot, an operator `start`, or an adopted rc service | switchboard's own root coalition |

The root coalition is a member-less, self-rooted coalition switchboard
mints at startup, so every chain that does not end in a session or a
self-rooted provider ends at the system. A login session is a coalition
too: every session mint (USER or SYSTEM kind; the boot ambient carry is
not a session) creates one with the release signal (0), and the session
leader joins it over
`SVC_OP_SESSION_COALITION` (`service_session_join_coalition(3)`, called by
login, su, and the sshd session child before they exec the shell), so the
shell and everything it starts carry the session id. Because the
signal is 0, closing the session record when the channel goes away never
kills a detached process that outlived the login.

What consumes it: `switchboardctl services` prints `coal=` and `resp=` per
unit and `switchboardctl tree` draws the chains; `ps -o coal,rcoal,rpid`
and `procstat coalition` read the kinfo export; every switchboard launch
audit record carries `coalition=` and `responsible=`; and OES stamps
`ep_coalition`, `ep_responsible_coalition` and `ep_responsible_pid` into
each event's process record, the analogue of EndpointSecurity's
responsible audit token. rc-adopted and oneshot units have no coalition
today, so they show no identity.

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
unit that wants an exact aggregate for right now can read
`COALITION_OP_RUSAGE`, which walks the process members and sums them, but that
is observation, not enforcement.

## Ceilings for the whole unit

Enforcement for a unit rather than a process is a separate mechanism, and
it does not go through rlimits at all. A coalition is a container in the
kernel's own accounting framework, charged beside the process, user, login
class and jail containers a process already belongs to, so its figures are
maintained by racct(9) rather than by anything this driver samples. A
holder declares ceilings on that container with `COALITION_OP_SET_LIMIT`:

| figure | unit | how the counter behaves |
| --- | --- | --- |
| `memory_bytes` | resident bytes | refreshed by the page daemon's pass |
| `vmem_bytes` | address space in bytes | charged at the mapping path, exact |
| `cpu_percent` | percentage of one processor | a rate, measured over a window |

Because every ceiling is judged from the container, a kernel booted without
resource accounting (`kern.racct.enable=0`) has nothing to judge, and
`COALITION_OP_SET_LIMIT` answers `EOPNOTSUPP` rather than accepting a figure
nothing would act on.

Zero removes any of them and they are independent. A breach always
notifies through `COALITION_NOTE_LIMIT`; with `COALITION_LIMIT_KILL` it
also terminates the coalition, regardless of band, because a unit over a
figure declared for it is over budget whether or not the machine is short.

The CPU ceiling is a rate rather than a total, since a total only grows and
a unit running for a week breaches any figure worth setting. What is judged
is `RACCT_PCTCPU` on the coalition's container — the decaying average the
accounting framework already keeps beside every other figure, clamped there
to the number of processors on the machine. Nothing in the driver measures
it. It covers CPU spent by members that have since left, and that falls out
of the framework rather than being arranged: CPU is neither reclaimable nor
decaying, so it is never taken back out of a container when a member leaves.
A unit therefore cannot stay under its ceiling by working in short-lived
children. Darwin has no equivalent: its CPU limits are per-task and report
through an exception port rather than describing a unit.

Nothing in the plane declares these from a manifest yet: they are a kernel
interface a supervisor calls, and switchboard does not call it.

## One source per figure

The container arrived after the module had already built several of these
figures by hand, and keeping both would have been the worst of the two. Each
number now has one owner:

- The **ceilings**, the **ledger** (`COALITION_OP_LEDGER`) and the **kill
  report** read the container. None of them walks a member list, so they cost
  the same whatever a coalition is made of, and adding a fourth resource needs
  no code in the module at all.
- The **victim rankings** — memory pressure choosing what to hand down, and the
  out-of-memory policy choosing what to give up — still sample the member list
  at the moment of the decision. This is the one deliberate exception: a
  ranking made on a figure that is a page-daemon pass old picks the wrong
  coalition, and picking the wrong one is the whole failure.
- **CPU** is kept entirely by the container, as `RACCT_PCTCPU`. The driver
  once maintained its own rate and its own tally of departed members' CPU;
  both were removed. `racct_sub_racct()` only gives back resources that are
  reclaimable or decaying, and CPU is neither, so a container already keeps
  what its departed members spent — the second tally counted it twice.

A coalition may also hold a jail, and then it accounts for what runs inside
it. Only a process carries a container pointer, so the jail's processes are
charged individually — on attach, on fork inside the jail, and, for work
already running, by one walk when the jail is enlisted. They do not become
members: a jail's processes are accounted, not enlisted, so the member count,
the member limit and what a termination signals are unchanged. A process
enlisted in its own right is never displaced by a jail it happens to be in,
and where jails nest, the innermost held one wins — in both cases because the
more specific statement about whose work a process is should stand.

Ceilings are held in one array indexed by the framework's own resource
numbers rather than a field per figure, because every one is judged the same
way: read the counter, compare. Limiting a resource the driver has never
heard of needs no code in it, only a caller willing to name it — the wire
carries three today. Breaches are reported with rctl's names for resources
rather than a second table that could drift from the first.

The natural end state is for these to be `rctl(8)` rules against a coalition
subject, which would bring operator tooling and persistence with them. That
is not a cleanup but a project, and it has a real conflict to settle first:
rctl's actions are per-process, and this model's whole point is that the unit
dies together. Until that is decided, the array keeps the driver honest and
makes the migration a mapping rather than a rewrite.

Consequences worth knowing. `age_ms` in the ledger reply is always zero —
nothing is sampled, so nothing goes stale — and `COALITION_LEDGER_REFRESH` no
longer refreshes anything; it now means "judge the ceilings before replying"
rather than waiting for the next sweep. Resident memory in the ledger is zero
for a process too young for the page daemon to have looked at, which is the
difference `COALITION_OP_RUSAGE` exists to span.

## Tests and status

`tests/sys/mac_capability/mac_capability_coalition_test.c` covers enlist by
type, nesting and cycle rejection, deadline, watchdog, leader death,
graceful termination, fork inheritance, jail members, limit exhaustion,
permanent ids, the responsible edge (set-once, self-root, caller and
procdesc naming, cycle and depth refusal, survival of the parent's close),
the kinfo export, the release signal, the resident, address-space and CPU
ceilings, idle exit, the periodic sweep and the out-of-memory ranking;
`usr.sbin/switchboard/tests/responsibility_test.c` pins the parent decision
against the management model;
`mac_capability_accounting_test.c` covers charge, release, set and rules;
`lib/libcapbundle/tests` pins the `limits` parser. The coalition and
accounting services are shipped and static. Open items: the coalition
watchdog has no plane user, the accounting service has no plane user, and
the unit-wide ceilings have no manifest field, so a supervisor must set
them through `COALITION_OP_SET_LIMIT` itself.
