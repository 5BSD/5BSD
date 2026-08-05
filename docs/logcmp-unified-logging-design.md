# LogCmp unified logging design

## Status and scope

LogCmp is the global, serviced-registered logging service.  Applications use
only `liblogcmp`; they do not discover endpoints, attach shared memory, choose
sinks, or open log files.  This design upgrades the existing bounded
shared-memory ingestion path into a unified structured log without turning
`libchannel` or `libservice` into a logging protocol.

The system is for diagnostics and telemetry.  OpenBSM remains the security
audit trail, DTrace remains dynamic instrumentation, and TraceCmp remains the
administrator-only tracing broker.  LogCmp may correlate with those systems,
but does not replace their integrity or privilege boundaries.

## Selected model

The useful properties of Apple unified logging are subsystem/category log
handles, severity-controlled persistence, activity and signpost correlation,
centralized memory/disk storage, filtering, and privacy-aware dynamic values.
The useful properties of the systemd journal are authenticated source
metadata, structured fields, append-oriented corruption recovery, bounded
storage/rotation, indexed queries, and a stable export boundary.  The useful
OpenTelemetry properties are normalized severity numbers, event names,
trace/span correlation, typed bounded attributes, batching, and explicit drop
accounting.

Primary references:

- <https://developer.apple.com/documentation/os/logging>
- <https://developer.apple.com/documentation/os/generating-log-messages-from-your-code>
- <https://systemd.io/JOURNAL_FILE_FORMAT/>
- <https://opentelemetry.io/docs/specs/otel/logs/data-model/>
- <https://opentelemetry.io/docs/specs/otel/logs/sdk/>

LogCmp deliberately does not copy Apple's private storage format, journald's
full indexing format, an XPC object model, or OTLP into its ingestion ABI.

## Layers

`liblogcmp` owns logger handles, typed records, privacy classification,
nonblocking shared-ring publication, reconnect, local drop counters, and
explicit flush.  `libshmring` owns only bounded bulk transport.  `libservice`
owns discovery and service death.  The LogCmp provider authenticates the
serviced client label, adds trusted process/coalition/receive metadata,
redacts private values, batches records, persists them, and serves authorized
queries.  Exporters consume a stable record/export stream and cannot change
the ingestion protocol.

## Record model

Every record has:

- authenticated service label and provider instance (provider supplied);
- client and observed realtime plus monotonic ordering timestamps;
- provider epoch and sequence;
- normalized OpenTelemetry severity number (1 through 24);
- subsystem, category, and optional event name;
- record kind: log, event, signpost begin, signpost end, or signpost point;
- optional activity ID, trace ID, span ID, and signpost ID;
- a UTF-8 message body and bounded typed attributes;
- explicit public, private, or private-hash classification on each dynamic
  value.

Private values are never written to the ordinary persistent store or syslog.
Private-hash values use a boot-scoped keyed hash so records can be correlated
without creating a stable cross-boot identifier.  Reserved trusted field
names cannot be supplied by clients.  Records and every nested value have
hard byte/count limits.

## Fast path and delivery contract

Each process shares one reference-counted producer and one independent
provider session.  Producers write complete validated records to a bounded
single-producer shared-memory ring.  A coalesced edge wakeup descriptor, not
one RPC per record, wakes the provider.  The provider drains bounded batches
on its kqueue and also uses a short fallback timer so a lost wakeup cannot
strand records.

Normal logging is nonblocking and lossy under pressure.  The API returns
`EAGAIN`, increments per-severity drop counters, and later emits one synthetic
loss record when space returns.  `flush` is the implemented explicit
durability boundary and reports provider death and storage failure.  A
separate emergency path for error/fatal records and caller-selected deadlines
is deferred; the current API must not be documented or operated as though it
exists.

Publication commits at the transport boundary.  Once a complete record is
published into a shared ring, failure of the coalesced wakeup does not make
that record retryable: the provider may already have consumed it or may do so
on its fallback timer.  The client abandons the damaged session and reports
the committed publication as successful.  Callers needing a reported storage
outcome use `flush`; they must not retry a successfully published record merely
because the following flush reports provider death.

After provider death, `liblogcmp` reconnects and reattaches a fresh ring.  It
does not replay records whose acceptance is unknown, which prevents duplicate
diagnostics.  The implemented synthetic event reports records dropped by
local `EAGAIN` backpressure.  A distinct provider-restart event and a public
provider-epoch field are deferred.

## Storage and query

The provider owns pre-opened storage capabilities and runs the storage writer
in a separate sandbox from untrusted client sessions.  Files are versioned,
append-only segments with checksummed length-delimited records.  Startup
validates every length/checksum and truncates only an incomplete active tail.
The target administrative recovery path quarantines corrupt complete segments
before continuing.  Rotation is bounded by
segment size, total bytes, age, and free-space reserve.  Severity determines
default retention.  An explicit durable flush synchronizes retained storage.

The implemented query operation uses the same typed LogCmp session.  The
provider fixes the service-label scope from the authenticated serviced
identity; callers can supply only a minimum severity and an opaque cursor.
They cannot select another identity or request an all-system view.  A
separately authorized administrative query name, time/subsystem/category/event
indexes, trace/activity lookup, and stable length-delimited or JSON-lines
export are deferred.  Any future indexes remain rebuildable accelerators,
never the only copy of data.

The implemented baseline fails closed on complete-record corruption rather
than silently discarding evidence.  It reconstructs generation state after a
crash between the durable rename of an active segment and creation of its
successor, and synchronizes both file and directory updates.  Automated
quarantine with an independently auditable administrative recovery path
remains a later storage-format phase; until then the daemon does not rename or
discard a corrupt complete segment on its own.

## Security and observability

The session sandbox cannot open storage or arbitrary sinks.  The storage
worker cannot receive client descriptors or connect to services.  Descriptor
rights are transfer-locked after bootstrap, all inherited authority is
dropped, and provider workers remain outside client coalitions.  Query and
configuration endpoints are independently authorized.

DTrace probes cover enqueue, drop, wake, batch drain, persist, rotate,
corruption, query, reconnect, and flush latency.  OpenBSM records policy
changes, query authorization, storage corruption/quarantine, and durable
flush failures; it does not audit every normal log record.

## Delivery phases

Phases describe the target architecture, not an assertion that every item is
already a release guarantee.  The validation record is authoritative for
implemented and qualified status.

1. Replace the text-field ABI with versioned typed records, privacy classes,
   normalized severity, subsystem/category logger handles, trace/activity and
   signpost fields, exhaustive validation, and syslog redaction.
2. Replace timer-only draining with coalesced edge wakeups plus fallback
   draining, add reconnect and per-severity loss records, and stress the fast
   path under fork/thread/crash/overflow conditions.
3. Add the isolated append store, recovery, rotation, retention, checksums,
   durable flush, and fault-injection tests.
4. Add the separately authorized query/export service, cursor semantics,
   rebuildable indexes, command-line tooling, and privacy tests.
5. Complete pkgbase, DTrace, OpenBSM, upgrade/removal, performance, and live
   root validation.
