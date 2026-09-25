# system.Log (BSDLog)

BSDLog is the structured-logging authority of the capability plane. It
accepts records from units and sessions, stamps each with the metadata a
client cannot forge, keeps them in a private segmented store, and answers
queries scoped to the caller's own label. 5BSD has it because a unit born in
capability mode cannot reach `/var/run/log`, and because a log a component
can write for another component is not evidence.

## What it brokers

The resource is the log itself. A client never holds a file, a socket, or a
syslog path; it holds a channel to `system.Log`, and everything it writes
arrives at the sink with the trusted service label, component instance,
provider sequence, and both a realtime and a monotonic receive timestamp
added by the provider. The client supplies only what it legitimately knows:
subsystem, category, severity, privacy class, message text, an optional
event timestamp, and up to 32 typed attributes. The provider overwrites the
receive clocks before a record reaches storage, so ingestion order cannot be
forged.

Ingestion has two paths. A low-rate emitter sends each record inline in a
`WRITE`. A high-rate emitter `ATTACH`es a bounded single-producer
shared-memory ring, built with libshmring(3), by passing five descriptors
(config, data, head, tail, and a wakeup pipe) and then sends one
edge-coalesced `NOTIFY` whenever the ring goes from empty to nonempty; the
worker drains the burst through `kqueue(2)` and a periodic timer
(`fallback_drain_ms`) exists only to cover a lost wakeup. Sessions are
sharded across a fixed pool of capability-mode ingress workers
(`ingress_shards`); a worker cannot open files, sockets or sinks, cannot
fork or exec, and cannot transfer a ring consumer descriptor back to a
client. Validated records cross from the workers to a storage manager over
a second single-producer ring, and the manager drains active rings in
bounded round-robin batches so one busy producer cannot starve the rest.

The store is the unit's persistent `state` claim from
[system.Filesystem](filesystem.md), obtained with `service_storage_open(3)`
(on installer media without a pool, an ephemeral runtime container with a
logged warning). Records append to one active segment that rotates into a
completed segment at `segment_size`; `max_segments` bounds the ring of
completed segments, and the optional `retention_max_age` and
`retention_max_bytes` prune whole completed segments oldest-first. The
active segment is never pruned and no partial record is dropped. Private
fields are stored as the literal `<private>`; private-hash fields as a
128-bit digest keyed with a random per-epoch key that never touches disk,
so equal values correlate within one storage epoch and not across restarts.
The storage manager also runs the owner reconcile: every
`BSDLOG_RECLAIM_INTERVAL` seconds (default 30) it seals the records of
bundles that are no longer installed or running.

## Unit

| Field | Value |
|---|---|
| Wire name | `system.Log` |
| Bundle | `/Capabilities/System/Log.cap` (`bundle_id = "system.Log"`) |
| Program | `Units/bsdlog.unit/bin/BSDLog` |
| Unit name | `bsdlog` |
| Activation | `boot = true`, `ipc = ["system.Log"]` |
| User | `capability` |
| Launch mode | born in capability mode; `directories = ["/Capabilities/System", "/Capabilities/Apps", "/Capabilities/Run/live"]` (for the owner reconcile) |
| Declared gates | none |
| Visible | `["user"]` (login sessions log too) |
| Control | `core` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 2048`, `nproc = 72`, `core = 0`; `umask = "0077"` |

## Wire operations

The protocol is `lib/liblogcmp/logcmp_protocol.h`: magic `LOGC`,
`LOGCMP_ABI_VERSION` 6, interface version `6.0.0`. Every message begins
with a 16-byte `logcmp_msg` (magic, version, opcode, flags, status). A
session opens with HELLO carrying `min_version`, `max_version` and a
feature bitmap (`LOGCMP_FEATURE_INLINE`, `SHM_RING`, `TYPED_RECORDS`,
`PRIVACY`, `TRACE_CONTEXT`, `EDGE_WAKEUP`, `SCOPED_QUERY`); the reply fixes
the version and reports `ring_size`, `max_record` (4096), `max_text`
(2048) and `max_fields`.

| Op | Request | Reply | Errors |
|---|---|---|---|
| 1 HELLO | `logcmp_hello` | `logcmp_hello_reply` | version outside the accepted range |
| 2 ATTACH | `logcmp_attach_request` (generation, `ring_size`, `max_record`) + 5 fds in `logcmp_attach_fd_slot` order | header | `EINVAL` (ring shape or `max_record` over the session's limit), `EBUSY` (a ring is already attached) |
| 3 NOTIFY | header | none (event; the worker drains) | none |
| 4 WRITE | `logcmp_record` followed by subsystem, category, event name, message and `logcmp_attribute_wire` entries | header | `EINVAL` (malformed; counted as rejected), `EMSGSIZE` (over the session's `max_record`) |
| 5 FLUSH | header | header, after every earlier record is durable | none |
| 6 STATS | header | `logcmp_stats` (accepted, rejected, `client_dropped`, `provider_filtered`, `provider_rate_limited`, `last_sequence`, per-severity drop arrays) | none |
| 7 DETACH | header | header | none |
| 8 QUERY | `logcmp_query_request` (cursor, `minimum_severity`, `match_flags`, `from_ns`, `to_ns`, subsystem and category fragments) | `logcmp_query_reply` (cursor, result, `record_length`) followed by one record | `EINVAL` (inverted time range); end of scan signalled by result |

Severities are `TRACE` 1, `DEBUG` 5, `INFO` 9, `WARN` 13, `ERROR` 17,
`FATAL` 21 on a 1 to 24 scale; record kinds are `LOG`, `EVENT` and three
signpost kinds; privacy classes are `PUBLIC`, `PRIVATE` and
`PRIVATE_HASH`. A QUERY is bounded to the caller's label on the server side
and the filters only narrow within it; a zeroed request is the whole
label-scoped history. Long scans return in slices and the client library
follows the cursor.

## Client library

liblogcmp(3) (`<logcmp.h>`, `-llogcmp`):

| Group | Functions |
|---|---|
| Session | `logcmp_client_open`, `logcmp_client_close` |
| Loggers | `logcmp_logger_create(client, subsystem, category, &logger)`, `logcmp_logger_destroy` |
| Emit | `logcmp_emit(logger, const struct logcmp_emit_options *)`, `logcmp_flush(client)` |
| syslog replacement | `logcmp_log(priority, fmt, ...)`, `logcmp_vlog` |
| Observe | `logcmp_stats`, `logcmp_query_next(client, min_severity, cursor, buf, len, &outlen)`, `logcmp_query_ex(client, const struct logcmp_query_options *, cursor, buf, len, &outlen)` |

`logcmp_log(3)` is the one call every capability daemon should use after
`cap_enter(2)`. It takes a syslog(3) priority, opens a process-lifetime
logger lazily on first use (subsystem `getprogname()`, category `log`),
falls back to syslog(3) whenever `system.Log` is unreachable, never blocks,
never fails the caller, and preserves errno so a trailing `%m` still works.
A unit that needs typed attributes or privacy classes uses the explicit
path:

```c
#include <string.h>
#include <logcmp.h>

static void
log_login(const char *user)
{
        struct logcmp_client *client;
        struct logcmp_logger *logger;
        struct logcmp_attribute attr = {
                .size = sizeof(attr), .key = "user",
                .type = LOGCMP_ATTR_STRING,
                .privacy = LOGCMP_PRIVACY_PRIVATE_HASH,
                .value = user, .value_length = strlen(user),
        };
        struct logcmp_emit_options opts = {
                .size = sizeof(opts), .severity = LOGCMP_SEVERITY_INFO,
                .kind = LOGCMP_KIND_EVENT,
                .message_privacy = LOGCMP_PRIVACY_PUBLIC,
                .event_name = "session.start", .message = "login",
                .attributes = &attr, .nattributes = 1,
        };

        if (logcmp_client_open(&client) != 0)
                return;                 /* fail soft: no log, no crash */
        if (logcmp_logger_create(client, "auth", "session", &logger) == 0) {
                (void)logcmp_emit(logger, &opts);
                logcmp_logger_destroy(logger);
        }
        (void)logcmp_flush(client);
        logcmp_client_close(client);
}
```

## Command-line tool

logctl(8) uses liblogcmp for every live verb and has no private endpoint or
administrative bypass; `show` sees only the caller's own label.

```
# logctl configtest
/Capabilities/System/Log.cap/Units/bsdlog.unit/Config/bsdlog.conf: valid (ring_size=262144 fallback_drain_ms=1000 ...)
# logctl emit demo startup info "hello from the shell"
# logctl stats
accepted=1 rejected=0 client_dropped=0 provider_filtered=0 provider_rate_limited=0 last_sequence=1
# logctl show warn
timestamp_ns=... receive_timestamp_ns=... severity=13 subsystem=... message=...
```

`stats` also prints one `client_dropped.severity.N=` and
`provider_rate_limited.severity.N=` line per severity level that saw a
drop.

`configtest [file]` runs the daemon's strict parser on a file (default: the
installed `bsdlog.conf`). `emit subsystem category severity message` writes
and flushes one public record; the severity is `trace`, `debug`, `info`,
`warn`, `error` or `fatal`. `flush` establishes the processing boundary,
`stats` prints the counters of the command's own isolated session, and
`show [minimum-severity]` prints retained records for the caller's
switchboard identity.

## Policy

BSDLog has no per-label allow-list: any unit or session that can resolve
`system.Log` may write, and each sees exactly its own records back. The
policy surface is the ingestion configuration in
`/Capabilities/System/Log.cap/Units/bsdlog.unit/Config/bsdlog.conf`, a
strict UCL file that must be a regular, non-symlink file owned by root or
the daemon's user, not group- or world-writable, and under 64 KiB. Unknown
keys, wrong types and out-of-range values prevent startup.

| Key | Range | Shipped default |
|---|---|---|
| `ring_size` | power of two, 64 KiB to 64 MiB | 262144 |
| `fallback_drain_ms` | 1 to 1000 | 1000 |
| `segment_size` | 64 KiB to 1 GiB | 16777216 |
| `max_segments` | 1 to 1024 completed segments | 64 |
| `retention_max_age` | seconds, 0 disables | 0 |
| `retention_max_bytes` | bytes, 0 disables | 0 |
| `minimum_severity` | 1 to 24 or a severity name | `trace` |
| `rate_limit_interval_ms`, `rate_limit_burst` | at most one hour and one million; both zero disables, one zero is rejected | 30000, 10000 |
| `ingress_shards`, `max_sessions`, `drain_batch` | pool sizing | 4, 65536, 256 |

Records below `minimum_severity` and records beyond a session's fixed-window
budget advance the sequence but never reach the store, and they are counted
as filtered and rate-limited respectively, distinct from malformed records
and client-ring loss. Ring exhaustion never overwrites an unread record.
Session creation and rejected records are audited through
[system.Audit](audit.md) as `AUE_LOGCMP_POLICY` (43331). Admin sessions
have no bypass: `SERVICE_RIGHTS_ADMIN` does not widen a query to another
label.

## Tests

| Suite | Location | Installed under | What it proves |
|---|---|---|---|
| `config_test`, `session_test`, `store_test`, `store_limit_test`, `storage_test`, `provider_test`, `bundle_test.sh` (88 cases) | `usr.sbin/BSDLog/tests` | `/usr/tests/usr.sbin/BSDLog` | parser bounds, ring attach and drain, segment format and crash recovery, retention pruning, reclaim limits, the provider against `LOGCMP_TESTING` seams, and the installed bundle |
| `logcmp_test`, `client_lifecycle_test` | `lib/liblogcmp/tests` | `/usr/tests/lib/liblogcmp` | wire encoding, the fake-service handshake, lazy open and fallback of `logcmp_log` |
| `logctl_test.sh` | `usr.sbin/logctl/tests` | `/usr/tests/usr.sbin/logctl` | every verb against `fake_logcmp`, `valid.conf` and `invalid.conf` |

Run with `kyua test -k /usr/tests/usr.sbin/BSDLog/Kyuafile`; the suites are
in the `5BSD-bsdlog-tests` and `5BSD-liblogcmp-tests` packages. The DTrace
provider `bsdlog` exports `session-start`, `record-write`, `record-drop`,
`wakeup-receive`, `batch-drain`, `flush-complete`, `storage-persist`,
`storage-rotate`, `storage-corruption`, `storage-quarantine`,
`query-complete`, `query-filter`, `retention-prune`, `storage-reclaim` and
`storage-reconcile`; payloads and private values are never arguments.

## Status and gaps

Shipped and VM-proven: inline and ring ingestion, the segmented store with
rotation, retention and crash recovery, scoped queries with subsystem,
category and time filters, privacy classes, the owner reconcile, and the
`logcmp_log` fallback path. The BSDLog(8) manual page still describes the
interface as version `5.0.0` while the header ships ABI 6 and
`LOGCMP_INTERFACE_VERSION` `6.0.0`. The inventory lists further query
filters (beyond subsystem, category and time) as deferred. A capability-mode
unit that calls syslog(3) directly writes nothing, and `LOG_INFO` lines do
not appear in `/var/log/messages`; use `logcmp_log(3)`.
