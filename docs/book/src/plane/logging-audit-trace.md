# Logging, Audit and Trace

A 5BSD system produces three kinds of record, and they are kept apart on
purpose. Diagnostic and telemetry records go to unified logging (BSDLog,
`system.Log`); security decisions go to the BSM audit trail, which
capability-mode providers reach through BSDAudit (`system.Audit`) or, when
they run as root, through the capability-enabled audit(2) directly; and
dynamic instrumentation stays DTrace, with BSDTrace (`system.Trace`)
deciding who may open a consumer. 5BSD needs its own answer for each because
a unit born in capability mode cannot reach `/var/run/log`, cannot call
auditon(2), and cannot open `/dev/dtrace`. This chapter is the mental model;
the operation sets and policy files of the three providers are in Part IV.

| Record | Provider and wire name | Client entry point | Tool | For |
|---|---|---|---|---|
| log | BSDLog, `system.Log` | `logcmp_log(3)`, `logcmp_emit(3)` | logctl(8) | what happened, for diagnosis |
| audit | BSDAudit, `system.Audit`; or audit(2) for root providers | `auditcmp_submit(3)`, `audit_submit(3)` | praudit(1), auditreduce(1) | who was allowed or refused to do what |
| trace | BSDTrace, `system.Trace` | `tracecmp_dtrace_open(3)`, `dtrace_fdopen(3)` | dtrace(1), bsdinstruments(8) | what the kernel and processes are doing right now |

## Unified logging

### Why a capability-mode unit cannot syslog

syslog(3) writes to the UNIX socket `/var/run/log`. Connecting to a socket
by path is a global-namespace operation and fails `ECAPMODE` after
cap_enter(2), so every line a sandboxed daemon tried to syslog would be
lost silently. Fifteen of the sixteen providers are born in capability mode,
and so is every application unit. The replacement is one call:

```c
#include <logcmp.h>

logcmp_log(LOG_WARNING, "claim %s refused: %m", name);
```

`logcmp_log` and `logcmp_vlog` (liblogcmp(3), `lib/liblogcmp/logcmp.h`) are
a fire-and-forget printf(3)-style sink at a syslog priority. They lazily open
a process-lifetime `system.Log` client on first use, named after
getprogname() with category `log`, emit one record, and fall back to
syslog(3) whenever `system.Log` is unreachable: before the plane is up, in a
pre-capability-mode launch, or when BSDLog is down. They never block, never
fail the caller and preserve errno, so a trailing `%m` still reports the
caller's error. This is the one sink every unit should use after
cap_enter(2), and the reconcile library, every provider and the capability
plane's own daemons use it.

### The record and the store

`system.Log` is open (no anointment) and `visible = ["user"]`, because every
login session emits records. A record carries an OpenTelemetry severity
number (1 through 24; `LOGCMP_SEVERITY_TRACE` is 1 and `LOGCMP_SEVERITY_FATAL`
21), a subsystem and category, an optional event name, a kind (log, event or
signpost), optional activity, trace and span ids, a UTF-8 message and
bounded typed attributes, each dynamic value classified public, private or
private-hash. A `logcmp_logger_create` handle names the subsystem and
category; `logcmp_emit` sends a full record; `logcmp_flush` is the explicit
durability boundary. The provider stamps the trusted service label,
component instance, provider sequence and receive timestamps at the sink, so
a client cannot forge ordering or origin, and private values are never
written to the ordinary store.

Low-rate clients send a record per message. High-rate clients attach a
bounded single-producer shared-memory ring and send an edge-coalesced wakeup
when it goes from empty to non-empty; the worker drains the burst through
kqueue(2). Logging is non-blocking and lossy under pressure: the API returns
`EAGAIN`, counts the drop per severity, and later emits one synthetic loss
record. Those counters are what `logctl stats` prints.

BSDLog keeps the durable copy itself, in its own persistent container claim
(`Data/Log/bsdlog/persistent/state`, obtained with `service_storage_open`
like any other unit), as a sequence of append-only checksummed segments. It
is the sink of record; validated records are never mirrored to a separate
sink. A query is always scoped to the authenticated label of the session
that asks; the protocol has no identity override and no all-system view.

### logctl and retention

```sh
$ logctl emit myapp startup info "listening"
$ logctl flush
$ logctl stats
$ logctl show warn
$ logctl configtest
```

`emit` writes and flushes one public record; `show` prints the retained
records that belong to the caller's own switchboard identity, optionally
from a minimum severity (`trace`, `debug`, `info`, `warn`, `error`,
`fatal`); `configtest` validates `bsdlog.conf` with exactly the daemon's
strict parser. logctl(8) has no private endpoint and no administrative
bypass: it sees what its own identity may see. An operator reading another
unit's records reads them from the store on disk. `/var/log/messages` holds
only what fell back to syslog(3) because `system.Log` was unreachable at the
time; BSDLog never mirrors records there.

The configuration is `/Capabilities/System/Log.cap/Units/bsdlog.unit/Config/bsdlog.conf`:

| Key | Default | Meaning |
|---|---|---|
| `ring_size` | 262144 | bytes per client ring |
| `fallback_drain_ms` | 1000 | lost-wakeup fallback timer |
| `segment_size` | 16777216 | rotation threshold (64 KiB to 1 GiB) |
| `max_segments` | 64 | completed segments kept beside the active one |
| `retention_max_age` | 0 | prune a completed segment older than this many seconds; 0 disables |
| `retention_max_bytes` | 0 | prune oldest completed segments while the store exceeds this; 0 disables |
| `minimum_severity` | `trace` | records below it are filtered and counted |
| `rate_limit_interval_ms`, `rate_limit_burst` | 30000, 10000 | per-session fixed-window budget; both zero disables |
| `ingress_shards`, `max_sessions`, `drain_batch` | 4, 65536, 256 | worker pool shape |

Pruning removes whole completed segments only, never the active one, so no
partial record is dropped; the count is exported through the
`bsdlog:::retention-prune` probe.

### The reconcile.meta exception

Every provider that reaps state for uninstalled bundles logs its reconcile
passes through `logcmp_log`. BSDLog cannot: it is `system.Log`, and its
storage manager is born in capability mode with no syslog socket, and a
plane may run without DTrace. So it writes the outcome of its latest pass,
or the reason none can run, as one line to `reconcile.meta` in its store
directory (`usr.sbin/BSDLog/storage.c`, `record_reconcile`), atomically via a
temporary file and rename. An operator, or a proof, reads it through a
snapshot of the store. It is best-effort and never fails a pass. Nothing
else gets this exception; a new provider that reconciles logs through the
Log capability.

## Audit from capability mode

BSM audit is the security trail and stays what it is on FreeBSD: kernel
records under `/var/audit`, read with praudit(1). What 5BSD changes is who
can write a userland record and how a sandboxed daemon does it.

### Two ways to commit a record

`audit(2)` is marked `CAPENABLED` in `sys/kern/syscalls.master`, so a
process in capability mode may submit a fully formed record, but it keeps
its root privilege check (`PRIV_AUDIT_SUBMIT`) and jail prohibition. A
provider that runs as root and is born in capability mode, such as BSDTrace,
therefore calls `audit_submit(3)` directly (`AUE_TRACECMP_POLICY`, 43332).
Switchboard, which is not sandboxed, does the same for its own events
(43320 through 43328).

A provider that runs as the `capability` user cannot. For it there is
BSDAudit, the submit-only broker at `system.Audit`: `auditcmp_client_open`,
then `auditcmp_submit(client, subject, operation, error)` from
libauditcmp(3). The broker accepts submissions only from a compiled-in
identity table (`usr.sbin/BSDAudit/auditcmp_policy.c`): `system.Log`,
`system.Network`, `system.Notify`, `system.Crypto` and `system.Auth`, each
mapped to a fixed event class, with `system.Auth` split by operation into
`AUE_AUTHAGENT_ELEVATE` (43335) and `AUE_AUTHAGENT_MINT` (43336). The wire
message carries only the record's variable content; its event class and
origin are facts the broker derives from the unforgeable channel label. A
submitter cannot pick an event number, an audit uid or another provider's
identity, and each session is rate-limited (a burst of 200, 100 per second)
in the long-lived parent so a cycled session cannot recover its allowance.
There is no query operation; the broker writes the trail and never reads it.

### Three things that had to be true first

The trail was silent from capability mode until three fixes landed, and
they are worth knowing because they recur in any new provider.

1. **The timezone and NLS preflight.** Several libc facilities open files
   by path on first use: the timezone database for any local timestamp,
   and the locale message catalog for strerror(3) and `%m`. After
   cap_enter(2) those opens fail with `ECAPMODE`, and any provider that
   timestamps or formats an error in the sandbox hit it. libservice now
   primes both immediately before entering capability mode
   (`service_capmode_preflight` in `lib/libservice/libservice.c`:
   `tzset()`, one `localtime()`, one `strerror()`), at the chokepoints every
   provider passes through: `service_enter_capability_mode`,
   `service_worker_enter_capability_mode` and `service_worker_protect`.
   pdfork(2) workers forked after the main process primed inherit the warm
   caches; workers that sandbox independently prime their own. A facility that still cannot be primed degrades to a UTC
   timestamp or a built-in English string, never a failure.
2. **libbsm tolerates `ECAPMODE` from auditon(2).** `au_assemble` calls
   `auditon(A_GETKAUDIT)` only to size an extended header, and
   `audit_submit` calls `auditon(A_GETCOND)` only to learn whether auditing
   is on. auditon(2) administers system-wide policy and is deliberately not
   capability-enabled, so both calls return `ECAPMODE` in the sandbox.
   `contrib/openbsm/libbsm/bsm_audit.c` and `bsm_wrappers.c` now treat that
   like `ENOSYS`/`EPERM`: fall back to the plain header, assume auditing is
   on, and let the capability-enabled audit(2) report `ENOTSUP` if it is
   not.
3. **auditd is on by default.** `libexec/rc/rc.conf` ships
   `auditd_enable="YES"` and audit(4) is compiled into GENERIC, so the
   kernel accepts records from first boot. Without a running auditd a
   submission is a no-op; `praudit /var/audit/current` is the test.

### What the plane records

| Event | Number | Source |
|---|---|---|
| `AUE_SWITCHBOARD_CTL` | 43321 | every control operation, allowed or refused |
| `AUE_SWITCHBOARD_COMPONENT` | 43327 | every session mint |
| `AUE_SWITCHBOARD_ANOINT` | 43328 | every anointment refusal |
| `AUE_TRACECMP_POLICY` | 43332 | BSDTrace delegation, denial and session bootstrap |
| `AUE_BSDNOTIFY_POLICY` | 43333 | BSDNotify refusals and tier mismatches |
| `AUE_AUTHAGENT_ELEVATE`, `AUE_AUTHAGENT_MINT` | 43335, 43336 | every anoint(1) and mint outcome |

The complete list is in `sys/bsm/audit_kevents.h`. BSDLog submits a record
for a refused request (`AUE_LOGCMP_POLICY`), never for each ordinary log
record. Passwords, hashes and capability material never
appear in a record. A submission carries a caller-asserted operation string
that the broker validates for form only; the authenticated facts are the
event class and the originating provider.

## Tracing authorization

DTrace on FreeBSD is all or nothing: opening `/dev/dtrace` requires root
and grants kernel-wide introspection. 5BSD keeps DTrace as the
instrumentation layer (about 65 new kernel SDT providers and 64 userland
USDT providers, catalogued in [Observability](../operations/observability.md))
and changes only how a consumer is obtained.

BSDTrace is the only program that opens `/dev/dtrace`, through the `/dev`
directory descriptor switchboard delivers. It publishes `system.Trace`
gated on the `system.trace.client` anointment, so a session that does not
hold it gets `ENOENT` at lookup and never reaches the daemon. A session that
does is then checked against the daemon's own allow-list, `bsdtrace.allow`
in the unit's delivered `Config` directory
(`/Capabilities/System/Trace.cap/Units/bsdtrace.unit/Config/bsdtrace.allow`,
opened with `service_config_open`, never by path): one switchboard label per
line, no wildcards, root-owned and not group- or world-writable, at most
64 KiB. An absent file is an empty, default-deny policy; an unsafe file is a
fatal configuration error. `/etc/bsdtrace.allow` is not read by the daemon;
it is only the default input of `tracectl configtest`, which validates a
file with the daemon's parser.

Two gates, then, with different owners: the operator's principal policy
decides which people may trace (grant `system.trace.client`, or let them
`may_elevate` to it, without making them administrators), and the daemon's
allow-list decides which programs may. The shipped policy grants the
anointment to the admin principal through `*`.

An admitted client receives one independently opened DTrace consumer
descriptor: close-on-fork, close-on-exec, transferable once, and limited to
the ioctl set libdtrace needs. `tracecmp_dtrace_open(flags, &err)` in
libtracecmp(3) asks for it and hands back a `dtrace_hdl_t` by way of
`dtrace_fdopen(fd, version, flags, &err)`, the libdtrace entry point 5BSD
added for building a handle from a delegated descriptor with no device open,
no module load and no fasttrap. Unmodified D programs then run as the
unprivileged user; `tracecmp_dtrace_open` also applies RAM- and CPU-scaled
buffer defaults that `dtrace_setopt` may override. Each client is served by
its own capability-mode worker (at most 256), an idle pre-delegation
session is closed after 30 seconds, and every delegation and denial is both
an `AUE_TRACECMP_POLICY` record and a `bsdtrace:::delegate` or
`bsdtrace:::reject` probe.

The honest limit: policy is coarse. An ioctl allow-list cannot constrain D
programs, probes, actions or buffer sizes within the kernel's limits, so an
allow-listed label has the full introspection power DTrace has. BSDTrace
narrows who may trace and how the consumer is obtained, not how much an
authorized tracer can see. A provider-owned query and aggregation protocol
for untrusted consumers is not built.

## Choosing the record

| You want to record | Use |
|---|---|
| a diagnostic line from a daemon after cap_enter(2) | `logcmp_log(3)` |
| a structured event with attributes, or a signpost | `logcmp_logger_create` + `logcmp_emit` |
| that a request was refused, or a privilege was exercised | `auditcmp_submit(3)` from a `capability`-uid provider, `audit_submit(3)` from a root one; both need a fixed event class |
| a decision worth watching live without persisting it | a USDT probe in the daemon's `*_provider.d` |
| a one-off look at what is happening now | `dtrace -s /usr/share/dtrace/<script>` or `bsdinstruments watch <profile>`, over `system.Trace` |

Never syslog(3) from a sandboxed unit, never audit every ordinary log
record, and never hand a raw DTrace descriptor to a program that only needs
an aggregate.

## Limits and status

OTLP export of log records is deferred; only bsdinstruments and hwtlm
export OTLP today. BSDLog's query is label-scoped with severity, subsystem,
category and time filters, and a separately authorized administrative query
is not built; an operator reads other units' records from the store. BSDAudit
has no query and a fixed identity table, so a new provider that needs its
own event class is a source change to `auditcmp_policy.c` and
`audit_kevents.h`. BSDTrace's allow-list is by label only.

Reference: BSDLog(8), liblogcmp(3), logctl(8), BSDAudit(8),
libauditcmp(3), BSDTrace(8), libtracecmp(3), tracectl(8),
dtrace_fdopen(3), audit(4), praudit(1). Design:
`docs/book/src/providers/log.md`. Related: [system.Log](../providers/log.md),
[system.Audit](../providers/audit.md), [system.Trace](../providers/trace.md),
[Containers and Storage](containers-and-storage.md).
