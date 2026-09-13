# Installation authority

The authority records installation facts. It answers which installation a label
belongs to, which package or bundle sources keep it installed, and which changes
are pending or finished. It does not infer removal from a missing executable,
a stopped service, a failed scan, or a veriexec result.

Use the existing switchboard ledger and control channel; no additional daemon or
provider database is required. Installers write durable intent before changing
files, then record completion. A failed operation remains pending for recovery.
Each installation has a random 128-bit ID. Upgrades and additional live bundle
versions retain that ID. Reinstallation after removal receives a new ID.

The book chapter [Installation Identity and Lifecycle](../book/src/development/installation-authority.md)
provides the developer integration guide and package-hook examples.

## Registration and upgrades

Runtime startup and client connection handling only read installation identities.
An unknown label is rejected with ENOENT; a removed identity is rejected with
ESTALE; an unfinished installation/removal blocks new runtime use with EBUSY.
Runtime discovery never creates an installation record. Removal preparation also
refuses an unknown label instead of implicitly adopting it.

The bundle installer obtains labels from verified bundle manifests. Managed
package hooks explicitly supply their labels and package source. The runtime
package also registers the platform principal `org.5bsd.user-session`, used for
ambient login-session connections. That principal must exist before such
connections can succeed.

Managed upgrades preserve active installation IDs, source references, and resource
ownership keys. Upgrade hooks explicitly use begin-adopt so older package slots
can acquire provenance while preserving legacy ownership. Pending upgrades block
new starts/connections until finished or correctly cancelled; existing delegated
channels are not revoked by this check.

Before switching an older system to strict runtime lookup, inspect existing
package/bundle state and register any unrecorded installations with
`switchboardctl lifecycle adopt ROOT SOURCE LABEL ...`. Supply the actual
package slot or bundle version, including `pkg:runtime/runtime` for
`org.5bsd.user-session`. Adoption is an installer/operator migration action,
not evidence inferred from a service starting or a pathname existing. Do not
adopt a removed or pending installation to bypass its recovery procedure.

Bootstrap matching installer tools/helper first, register or migrate the installed
sources, then restart with matching switchboard and libraries. Updating binaries
alone on an unregistered system will leave affected services unable to start.
A version-3 database remains readable; no identity reset is needed.

## Queries

```
switchboardctl lifecycle query / org.example.App/main
switchboardctl lifecycle query / org.example.App/main INSTALLATION_ID
switchboardctl lifecycle status /
```

`query` returns the label, installation ID, state, and live/staged source counts.
Omitting the ID selects the latest recorded installation, for operator inspection.
Providers use the exact ID delivered with the client session:

```c
enum service_installation_state state;
if (service_installation_query(label, installation_id, &state) == -1) {
        /* Authority unavailable: retain state and retry later. */
}
```

The authenticated service control channel returns only installation state, without
exposing package history to ordinary services. Root can inspect source names,
operation IDs, references, and historical installation IDs with `status`.
Queries attempt a shared lock without waiting and never create files, adopt
labels, or commit records. A writer holding the lock produces `EWOULDBLOCK`;
callers retain state and retry. The default lifecycle timer also avoids waiting
for an installer.

| State | Meaning |
| --- | --- |
| unknown | No record for this exact identity; no removal conclusion is possible. |
| installed | Recorded installation is active. |
| installing | Publication or upgrade has an unfinished installation operation. |
| removing | A source removal is unfinished; other live sources may remain. |
| removed | This installation ended, or its initial publication was cancelled. |

An unreadable, missing, or corrupt store is an error, not `unknown` or `removed`.
Query errors leave the public API output `UNKNOWN`. Retained historical IDs remain
queryable after replacement; expired identities return unknown. A removal record does not claim
that files or provider data were erased. If publication was cancelled, its
operation history distinguishes that case from a completed uninstall.

## Records and boundaries

Root-owned installer entry points record the label, installation ID, stable
source reference, readable source name, operation ID, and pending/committed/
cancelled outcome. Package sources name a package slot; bundle sources include
bundle ID and sequence. Source names are bounded to 255 bytes and cannot contain
control characters. Hash references remain internal identifiers, not the only
explanation of provenance. Historical records from runtime adoption in the earlier
prototype can lack a known source; explicit installer adoption records one.

This is operational history, not a tamper-proof audit log. Records are atomically
published, synced, checksummed, and protected by filesystem ownership. Root can
replace them. History is pruned automatically to a recent window of 256 issued transactions
(in creation order, not elapsed time). Unused tickets are collected when their
count exceeds 512. Pending operations and all labels of their transactions are
always retained, along with live source references and the installation records
needed to explain retained operations. One last-known installation per label
remains even after removal, preventing implicit re-adoption of an expired label.
This bounds repeated-operation history, not the number of distinct labels or
unfinished operations. Experimental provider records have a separate retention
policy and are not discarded here. The store still has a fixed 262144-record
limit and fails writes at capacity.

Operators can prune earlier with
`switchboardctl lifecycle prune ROOT [KEEP]` (1 through 256, default 256).
KEEP applies to that invocation; it does not change the automatic limit.
After pruning, unknown operation IDs are rejected with ESTALE. New transactions
must use IDs persisted by `lifecycle issue ROOT` or supplied by `lifecycle run`.
The normal bundle installer and immediate install/adopt commands issue these
automatically. Exact retained retries still work; a discarded operation cannot
become a new removal against a replacement installation. The rejection policy
and discarded history are published in one atomic store image.

There is no provider-resolution command or permanent audit archive. Use system
snapshots or a separate audit facility when longer historical retention is needed.

The current development format is version 4. Version 3 records are read without
resetting identities and written as version 4 on the next changed commit.
Versions 1 and 2 remain unsupported and need an explicit migration before upgrade.
Before first pruning, legacy caller-generated operation IDs remain accepted;
after pruning, new IDs require authority issuance. Downgrading the binary to a
version-3-only reader requires restoring its matching system snapshot.
The added service query uses control protocol version 12; manager and service
libraries must be built and rolled out together.

Provider cleanup is now a separate experimental consumer of these facts.
Installation transactions never call the reclamation module or create delivery
records. The authority has a test executable linked directly against its source,
without reclamation code. The production query handler also stands alone from
provider dispatch and is exercised over real capability channels.

Automatic provider cleanup is disabled by default, including replay of deliveries
left by the earlier prototype. In an isolated qualification environment only,
`SWITCHBOARD_EXPERIMENTAL_RECLAIM=1` in switchboard's environment enables that
consumer. Default operation still stops a removed installation's process, but
does not issue provider data-deletion requests or collect new holder records.
Data may therefore remain after uninstall; resource retention is not yet a
qualified policy. Existing resource ownership keys continue to distinguish a
replacement from the old installation.

The experimental consumer shares the existing record file for compatibility;
this is a code and execution boundary, not a separately secured database. Enabling
it later cannot reconstruct holdings that were never recorded. It must not be
treated as a general cleanup or migration command.

This change does not
add polling to every provider or decide the lifetime of user documents, shared
storage, credentials, or audit records. The earlier cleanup/replay prototype remains
under review and has not been requalified end to end with the corrected fixture. It is not a
prerequisite for querying the authority and is not qualified for deployment.
Veriexec continues to answer executable-integrity questions independently.

## Validation

Focused validation on 2026-09-12 passed 37 distinct test cases:

- 2 authority-only cases, linked without the reclamation module: historical
  queries and source records, read-only access, and prompt failure on writer locks.
- 9 existing ledger transaction and experimental receipt cases.
- 3 manager lifecycle cases, including the default-off cleanup boundary,
  nonblocking default timer, and explicit opt-in replay compatibility.
- 9 package-helper cases.
- 3 root CLI cases, including old-ID queries during replacement and atomic failure.
- 2 service query cases, covering local errors and protocol reply validation.
- 1 production query-handler case over real capability channels, exercising all
  five states, querying an old ID after replacement, corrupt and missing state,
  and an active writer lock. This uses the actual handler and durable store,
  without starting the whole switchboard daemon or any cleanup provider.
- 1 existing service idle RPC case to check the shared reply handling.
- 1 real pkg install/upgrade/uninstall interruption and recovery case.
- 6 bundle publication/recovery cases, including unsafe paths and size limits.

Root and capability-channel checks ran in a disposable VM snapshot. The libraries,
switchboard, switchboardctl, and affected tests built successfully; man-page lint
and whitespace checks passed. The authority object has no reclamation references.
The follow-up qualification below extends these component checks. Versions 1/2 migration, if deployed,
and deployment qualification remain outstanding. No host installation
or rollout was performed.

### Additional qualification

A follow-up added nine tests: eight authority/concurrency/model/fault tests and a
live-daemon query/restart test. The expanded host run passed all 22 authority,
crash, ledger, and manager-lifecycle cases. The live-daemon case passed after
correcting the staged fixture from static to dynamic linking, using matching
libraries inside a disposable VM. It checks an installed ID and old/replacement
IDs after restarting the actual daemon stack.

The added tests cover eight simultaneous writers, death while holding a lock,
160 modeled source transitions with reopen boundaries, and 28 SIGKILL/EIO
publication scenarios. They found a real malformed-record bug: the reader accepted
an unterminated reference field with a valid checksum. The fixed reader now checks
termination of every fixed-size string field, and the regression test passes.

These are not hardware power-loss tests or large-history load tests. See the
[qualification record and release gaps](installation-authority-qualification.md).
The current assessment is a better-tested development feature, not a mature
production facility.

### Retention qualification

The bounded-history follow-up passed 38 focused cases: 27 host authority,
publication-fault, ledger, and manager cases; four root CLI cases; one real
package interruption/recovery case; and six bundle publication/recovery cases.
Root tests ran in a disposable VM using snapshot=on, with no host installation.

New coverage includes automatic collection across 288 upgrades, expired retries
against a replacement, pending multi-label transactions, version-3 preservation,
and six SIGKILL boundaries during pruning. The CLI test checks that an expired
uninstall fails without changing the replacement and a newly issued ID succeeds.
The full live-daemon test described above predates this retention change; it was
not rerun for this follow-up. Release-image snapshot/restore and capacity/load
qualification remain outstanding.

### Explicit registration qualification

The stricter registration follow-up passed 47 distinct focused cases: 29 host
authority/ledger/manager/fault cases, nine package-helper cases, five root CLI
cases, one real package upgrade/interruption/recovery case, and three live-daemon
cases. The live cases verify refusal of an unregistered service followed by
successful explicit adoption, historical queries after replacement/restart, and
ordinary crash recovery. The CLI migration case preserves both the installation
ID and legacy resource owner through an upgrade and records its package source.
These tests ran without deploying to the host.


### Validated query snapshots

The manager uses a single-threaded `sl_query_cache` from libcapsulert for service
queries. It retains a compact, sorted index of owner facts and its state-file
descriptor, plus a private close-on-exec kqueue. The retirement timer uses the
same cache implementation for owner phases that require stopping an incarnation. It does not retain the lifecycle lock.
Every request reopens and checks the trusted directory, lock, state file, and
header and obtains the same nonblocking shared lock as an uncached read. A
writer therefore continues to receive exclusive access between requests.

Reuse requires matching device/inode/generation, size, ownership, mode, flags,
link count, and modification/change/birth timestamps, with no pending watched
vnode event. The retained descriptor prevents inode reuse while cached. Writes,
extension, attribute/link changes, rename, deletion, and revocation invalidate
the snapshot. Path replacement and snapshot restoration are checked against the
newly opened state file. Corruption, missing files, untrusted paths, and failed
reads produce errors with UNKNOWN state, never an earlier cached answer.

On a miss, the reader watches the file before reading its record array and
validates the checksum and record structure. It checks metadata and events again
before retaining the derived index. The temporary read buffer uses anonymous
memory that is unmapped when validation finishes. A change during validation discards the read and
allows at most three validation attempts. This handles deferred UFS metadata
updates without accepting a potentially inconsistent read. Writer contention
and other failures return immediately. This optimizes reads;
there is no new durable format, installation identity, or cleanup authority.

Each cache is bounded by the store capacity, `SL_MAX_RECORDS`, rather than
by the number of callers or queried identities. Exact-identity queries use a
binary search of the index. Latest-owner queries search the label range for
the last ledger position; duplicate owner rows retain the uncached query
semantics. Source counts are aggregated during validation. Cold or changed-store
reads still validate the whole ledger and rebuild the index. The retirement
timer visits indexed owner phases, so pending removal of one of several sources
does not stop the live installation. Callers must handle
errors and synchronous latency, and deployments must measure their workload.
