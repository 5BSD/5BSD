# logd: the log authority

`logd` exposes `system.Log` and is the capability plane's structured-logging
authority: it accepts records from components, adds the trusted metadata a
component cannot forge, and retains them in its own private store. It is
`resolvable_by` the `user` domain as well as `system`, because a login session
emits records — every authenticated session gets an independent, label-scoped
view.

## Born in capability mode

`logd` persists to its own store — a directory delivered by
[`tzfsd`](../storage/trustedzfs.md) and opened through
`service_storage_open()`, never a global path — and it *is* the sink of record.
Earlier designs forwarded validated records through a Casper `system.syslog`
channel; that zygote is retired. `logd` now owns the durable copy directly and
consumers read it back by querying the store. Ingress workers run in capability
mode with no ability to open files, sockets, or other sinks, no fork or exec,
and no way to transfer the store or ring descriptors back to a client;
connections are sharded across a pool of `pdfork(2)`'d workers, and durable
records cross to the storage manager over a single-producer shared-memory ring.

## Emitting records

There are two emit paths, chosen by the client's rate:

- **Inline `WRITE`** — a record is carried in a single channel message. Simple,
  and adequate for low-rate emitters.
- **The shared-memory ring** — the client `ATTACH`es a bounded
  single-producer ring (its config, data, head, and tail descriptors plus a
  wakeup descriptor) and then sends an edge-coalesced `NOTIFY` when the ring
  goes from empty to nonempty. The worker drains the burst through `kqueue(2)`;
  a bounded periodic timer is retained only as a lost-wakeup fallback. This
  gives high-rate publication without a control message per record or polling
  latency.

Whichever path is used, the provider stamps each record with the trusted
service label, component instance, provider sequence, and both realtime and
monotonic receive timestamps at the sink — overwriting any client-supplied
receive clocks — so a client cannot forge ingestion ordering. Clients supply
only the subsystem, category, severity, privacy class, message text, an
optional event timestamp, and bounded typed attributes.

## Flush, stats, and drop accounting

An explicit **`FLUSH`** drains every record published before the request and
synchronizes the store before replying. **`STATS`** returns the session's
counters, including *per-severity* drop accounting: ring exhaustion is explicit
and observable rather than silent, and records dropped because they fall below
the configured `minimum_severity` or exceed the session's fixed-window
ingestion budget are counted separately (filtered vs. rate-limited) from
malformed records and client-ring overflow. Ring exhaustion never overwrites an
unread record.

## Scoped queries

A **`QUERY`** reads retained records back from the private store. It is always
restricted to the authenticated `serviced` client label of the session — the
protocol has no identity-override flag and no all-system view — and it takes an
opaque cursor plus a set of filters that narrow *within* that label:

- a `minimum_severity` floor;
- a **subsystem** and/or **category** fragment, each matched either as a
  substring (the default) or as an exact match selected per field through the
  request's match flags — an empty fragment is "no constraint";
- a **time range** given as `from`/`to` receive-timestamp bounds, either of
  which may be left open (zero) for a one-sided or unbounded window.

A zeroed request behaves exactly as the pre-filter protocol did — the whole
label-scoped history, severity floor only — so the filters are strictly
subtractive and never widen the scope. Long scans are divided into bounded
slices and resumed through the returned cursor, so one query cannot monopolize
the storage-manager event loop; the client library hides those continuations
behind a single overall deadline.

## Retention

The store is a sequence of fixed-size segments: records append to a single
*active* segment that rotates to a *completed* segment when it fills, capped by
a `max_segments` ring. Two optional configuration keys layer age- and
size-bounded retention on top of that ring:

- **`retention_max_age`** — a completed segment whose newest record is older
  than this many seconds is pruned.
- **`retention_max_bytes`** — while the whole store (the active segment
  included in the accounting) exceeds this size, the oldest completed segments
  are pruned until it fits.

Either key is `0` to disable that dimension, and the `0`/`0` default keeps every
segment within the ring. Pruning only ever removes whole completed segments —
**never the active segment** — so no partial record is dropped, and the count of
pruned segments and records is exported through the retention DTrace probe.

Reference: `logd(8)`, `liblogcmp(3)`.
