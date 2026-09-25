# system.Audit (BSDAudit)

BSDAudit is the submit-only BSM audit broker of the capability plane. It
accepts audit submissions from a closed set of system providers, fixes each
record's event class from the caller's channel label, and commits the
record to the kernel audit trail on the caller's behalf. 5BSD has it
because audit(2) requires `PRIV_AUDIT_SUBMIT`, and a provider that could
call it directly could write any record it liked, including one that
impersonates another provider. With the broker, a capability-mode daemon
produces trusted audit records without root and without the power to forge
them.

## What it brokers

The resource is the audit trail's write side. audit(2) is
`CAPENABLED` in `sys/kern/syscalls.master`, so a capability-mode process
can call it, but the privilege check and the jail prohibition stay: only a
root, unjailed caller may submit. BSDAudit is that caller. It runs as root,
cannot run in a jail, and hands every client a `pdfork(2)` worker that
prohibits fork, IPC, incoming descriptor transfer, exec and new sockets.
The supervisor keeps each worker's process descriptor, watches it with
`EVFILT_PROCDESC`, and admits at most 4096 workers. On a managed quiesce it
stops admission, terminates and reaps every worker, and only then
acknowledges shutdown to switchboard.

What a client sends is deliberately thin: an errno-style `error` and two
short strings, `subject` and `operation`, each bounded (64 bytes) and drawn
from a restricted character set. What the broker adds is the part that
matters. The switchboard-authenticated provider identity on the channel
selects a fixed BSM event number; a request cannot choose an event, an
audit user id or a provider identity. Only the built-in identities are
accepted, and an unknown identity is refused before a worker is created.
Each session is rate-limited by a token bucket held in the long-lived
parent and keyed by label (100 records per second, burst 200,
`AUDITCMP_RATE_PER_SECOND` and `AUDITCMP_RATE_BURST` in
`usr.sbin/BSDAudit/auditcmp.c`), so a compromised submitter cannot recover
its burst by cycling sessions. There is no query API. The broker writes the
trail and never reads it back; auditreduce(1) and praudit(1) remain the
readers.

The one caveat worth stating: `subject` and `operation` are caller-asserted
text. The broker validates their form, and it authenticates the event
class and originating provider, but the operation string is a descriptive
hint, not an authenticated assertion. The chapter [Logging, Audit and
Trace](../plane/logging-audit-trace.md) shows how these records read in
the trail beside switchboard's own.

## Unit

| Field | Value |
|---|---|
| Wire name | `system.Audit` |
| Bundle | `/Capabilities/System/Audit.cap` (`bundle_id = "system.Audit"`) |
| Program | `Units/bsdaudit.unit/bin/BSDAudit` |
| Unit name | `bsdaudit` |
| Activation | `boot = true`, `ipc = ["system.Audit"]` |
| User | `root` (audit(2) requires `PRIV_AUDIT_SUBMIT`) |
| Launch mode | born in capability mode; no `directories` |
| Declared gates | none |
| Visible | default (system-domain lookups only) |
| Control | `core` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 2048`, `nproc = 64`, `core = 0`; `umask = "0077"` |

Records reach the trail only when auditd(8) is running; the plane's
`rc.conf` default is `auditd_enable="YES"`.

## Wire operations

The protocol is `lib/libauditcmp/auditcmp_protocol.h`: magic `AUDC`,
`AUDITCMP_ABI_VERSION` 1, interface version `1.0.0`. Every message starts
with a 16-byte `auditcmp_msg` (magic, version, opcode, flags, status).

| Op | Request | Reply | Errors |
|---|---|---|---|
| 1 HELLO | header | `auditcmp_hello_reply` (version) | version mismatch |
| 2 SUBMIT | `auditcmp_submit_request` (140 bytes: `error`, `subject_length`, `operation_length`, `subject[64]`, `operation[64]`) | header with `status` | `EINVAL` (length or character set), `EAGAIN` (rate bucket empty), the errno from audit(2) |
| 3 STATS | header | `auditcmp_stats` (`submitted`, `rejected`) | none |

The event number is not on the wire in either direction. The daemon's
compiled table (`usr.sbin/BSDAudit/auditcmp_policy.c`) maps the bundle-id
part of the caller's label to one event, refined for BSDAuth by the first
path component of `operation`:

| Caller | Operation prefix | Event |
|---|---|---|
| `system.Log` | any | `AUE_LOGCMP_POLICY` (43331) |
| `system.Network` | any | `AUE_NETWORKCMP_POLICY` (43329) |
| `system.Notify` | any | `AUE_BSDNOTIFY_POLICY` (43333) |
| `system.Crypto` | any | `AUE_CRYPTOCMP_POLICY` (43334) |
| `system.Auth` | `elevate/` | `AUE_AUTHAGENT_ELEVATE` (43335) |
| `system.Auth` | `mint/` | `AUE_AUTHAGENT_MINT` (43336) |

A per-operation provider whose operation matches no prefix keeps its
admission event, so a record is never dropped for its operation text.

## Client library

libauditcmp(3) (`<auditcmp.h>`, `-lauditcmp`) has four functions:

| Function | Purpose |
|---|---|
| `auditcmp_client_open(struct auditcmp_client **)` | resolve `system.Audit` with `service_open(3)` and complete HELLO |
| `auditcmp_submit(client, subject, operation, error)` | one SUBMIT; `error` is 0 for success or the errno the audited decision produced |
| `auditcmp_stats(client, struct auditcmp_stats *)` | the session's counters |
| `auditcmp_client_close(client)` | drop the channel |

A provider that audits a policy refusal, opening its session lazily and
failing soft when the broker is not yet up:

```c
#include <errno.h>
#include <auditcmp.h>

static struct auditcmp_client *audit;

static void
audit_decision(const char *client_label, const char *op, int error)
{
        int saved = errno;

        if (audit == NULL && auditcmp_client_open(&audit) != 0) {
                errno = saved;
                return;         /* system.Audit not reachable: keep going */
        }
        if (auditcmp_submit(audit, client_label, op, error) != 0) {
                auditcmp_client_close(audit);
                audit = NULL;   /* reopen on the next decision */
        }
        errno = saved;
}
```

The pattern is the one BSDAuth uses: it opens its audit session on the
first record, commits each record after the reply it describes has been
sent, and drops records with a warning while `system.Audit` is unreachable.
An audit failure never widens a grant and never fails the caller's own
request.

## Command-line tool

There is no ctl tool. The reader side is the stock OpenBSM tooling: `praudit
/var/audit/current` shows the committed records, and `auditreduce -m
43335` selects one event class. A submitter's own counters are available
through `auditcmp_stats(3)`; nothing on the command line submits a record
by hand, which is the point.

## Policy

Policy is compiled in, not configured. The identity-to-event table above is
the whole allow-list: a unit whose bundle id is not in it is refused at
admission, before a worker exists, and a login session cannot reach the
name at all because the unit does not opt into `visible = ["user"]`. There
is no admin bypass: `SERVICE_RIGHTS_ADMIN` does not add an identity to the
table. Field bounds (`AUDITCMP_MAX_SUBJECT` and `AUDITCMP_MAX_OPERATION`,
64 each) and the character-set check are applied in
`usr.sbin/BSDAudit/auditcmp_submit.c` before any record is assembled, and
the rate bucket is checked before that. Adding a provider to the table is a
code change to `auditcmp_policy.c` plus a new `AUE_*` number in
`sys/bsm/audit_kevents.h` and the OpenBSM `audit_event` file.

## Tests

| Suite | Location | Installed under | What it proves |
|---|---|---|---|
| `policy_test` (10), `rate_test` (10), `submit_test` (12), `session_test` (11), `bundle_test.sh` | `usr.sbin/BSDAudit/tests` | `/usr/tests/usr.sbin/BSDAudit` | label-to-event mapping including the `elevate/` and `mint/` split, token-bucket timing and burst recovery across sessions, field validation, worker admission and quiesce under `AUDITCMP_TESTING`, the installed bundle layout |
| `auditcmp_test` (8), `client_lifecycle_test` (12) | `lib/libauditcmp/tests` | `/usr/tests/lib/libauditcmp` | HELLO, SUBMIT and STATS encoding against `fake_service`, and reopen after a dead worker |

Run with `kyua test -k /usr/tests/usr.sbin/BSDAudit/Kyuafile`; the packages
are `5BSD-bsdaudit-tests` and `5BSD-libauditcmp-tests`. End-to-end proof
that a record from a capability-mode provider reaches the trail needs a
booted plane with auditd(8) enabled; the VM runner in
[Testing](../develop/testing.md) is where that was established. The DTrace
provider `bsdaudit` exports session, submit and reject probes carrying the
provider label, the selected event, the submitted error and the result,
never an arbitrary record.

## Status and gaps

Shipped. Commit from capability-mode providers works end to end: the
blockers the inventory records as fixed were libservice pre-loading the
timezone and NLS data before `cap_enter(2)`, and libbsm tolerating
`ECAPMODE` from `auditon(A_GETKAUDIT)` when assembling a record. BSDAudit
runs as root, which the inventory lists among the providers that have not
yet moved to a gate-based launch as user `capability`. The BSDAudit(8)
manual page names four accepted identities (CryptoCmp, NetworkCmp, LogCmp,
Notify); the compiled table also carries the two `system.Auth` entries.
Whether BSM audit is enabled by default in a shipped installation, as
opposed to the test rig, is recorded as a product decision still to be
taken. There is no ctl tool and no plan for one.
