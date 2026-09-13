# Installation authority qualification

Passing component tests is not sufficient to declare this feature mature. The
scope of the dated runs below is the installation registry and its query
interface; automatic provider cleanup was disabled during those runs. See the
[automatic cleanup qualification](installation-cleanup-qualification.md) for the
subsequent enabled-cleanup implementation and its evidence.

## Authority-only qualification (2026-09-13 UTC)

The development-build gates pass: 41 core cases on the host and in QEMU, three
API fixture cases, six normal-plane administrative cases repeated 50 times,
maximum-capacity performance within the recorded budgets, and a 201-round,
ten-reboot soak over 102 minutes. The administrative run includes the regression
for preserving adopted cron across bundle reload. A coherent supported release
image/package qualification is still required. The sections below retain the
qualification history, including failures that led to fixes.

Final evidence: `/tmp/authority-final-gates/REPORT.md`, `normal-evidence.tgz`,
and `soak-evidence.tgz`. The archives are 1,021,313 and 2,022,473 bytes respectively;
their SHA256 hashes are
`bf635dac7ff0dea6634adbf21a4430a995864488593798eac00a316d3641c5d5` and
`076f008f12577b771ceafe21cf37f989faffb067463c7a47c5f7a1e0b67a06f9`.
Both VMs powered off cleanly with all buffers synced.

## Covered boundaries

The authority-only tests link the production store code without reclamation code.
They cover concurrent writer serialization (eight processes sharing one label),
loss of a writer holding the lock, preservation of its committed pending intent,
exact recovery, historical identities, read-only behavior, and a deterministic
160-operation model of five sources with installs, removals, upgrades, and
cancellations. Each model operation crosses a close/reopen boundary.

`installation_crash_test` uses test-only linker wrappers around `fsync` and
`renameat`. It kills a child with SIGKILL or returns EIO immediately before/after
file sync, rename, directory sync, and initial marker sync. The four cases cover
28 fault scenarios for first publication and replacement of an existing store.
An additional case kills the pruning writer at six publication boundaries and
checks that history expiry and rejection of old IDs become visible together.
A new process verifies the surviving state and retries the exact transaction.
There are no production environment variables or fault-injection hooks.

These tests model process death and syscall failure. They do **not** simulate
loss of the operating system's page cache, storage-controller caches, or actual
power failure. They cannot establish hardware-level durability.

A malformed-record regression uses a valid checksum and an unterminated reference
field. This initially failed and exposed a reader-validation gap. The reader now
checks termination of every fixed-size string field before accepting a record.

The existing capability-channel tests exercise the actual query handler, all five
states, an old ID after replacement, corrupt/missing stores, busy writers, and
malformed replies. They do not replace a launched-service test.

## Live-daemon test

`switchboard_integration_test:installation_authority_live_query` launches a real
service through capsule and switchboard, queries an installed identity, removes
and replaces it, then restarts the daemon stack. Relaunched services must report
the old identity as removed and the new identity as installed.

The first qualification attempt staged a static fixture. Ordinary switchboard
services launch through rtld's descriptor mode and require a dynamic executable;
the static fixture exited before readiness. The harness now rejects that mismatch
with a direct error. Qualification must stage a dynamic fixture with libraries
built from the same source revision. This packaging failure must not be counted
as either a successful query or proof of a registry defect.

The dynamic-fixture rerun passed on the disposable 5BSD VM: the initial query
returned installed, and after a real daemon-stack restart the old ID returned
removed while the replacement returned installed. This is a passing live query
and restart result on the tested image, not qualification of every deployment.

## Release gaps

The dated runs below cover version-3 migration, ZFS recovery, maximum-capacity
concurrent queries, and the six administrative cases on a normal capability
plane. A development overlay on a fresh installation still does not qualify a
supported release package set.

- Build a coherent release image and repository with protocol 12 and libservice
  ABI 3 throughout. Repeat installation, upgrade, live query/restart, and normal
  administrative qualification on that exact artifact; retain its hashes and
  package inventory.
- Inventory deployed database formats. Version-3 migration is covered; versions
  1/2 fail closed and require an explicit migration if they were deployed.
- Qualify ZFS snapshot/restore and interrupted rollout with the supported release
  procedure and consistent installation database. Device durability belongs to
  platform qualification; preserve the fsync and atomic-publication contract.
- Set deployment-specific latency and memory budgets. The maximum-capacity TCG
  run passes its provisional budgets, with limited peak-memory headroom. Cache
  misses still synchronously validate and index the full bounded store.

Provider data retention and cleanup qualification are not prerequisites for a
registry-only release, but no registry-only test authorizes enabling that separate
consumer.

## Bounded retention

Authority tests cover automatic collection after 288 same-source upgrades,
expired install/removal retries against a replacement, preservation of all labels
in a pending transaction, read-only rejection, source provenance, last-known
removed state, and version-3 upgrade without identity loss. The history window
does not cap live installations, distinct-label tombstones, pending transactions,
or experimental cleanup metadata.

## ZFS recovery contract

The authority does not implement filesystem rollback. ZFS supplies snapshots
and rollback; the authority supplies atomic records and recoverable pending
intent. Snapshots preserve a filesystem point in time, which can still fall
between steps of an installer transaction.

Before a planned recovery point, establish issued-operation enforcement with
`switchboardctl lifecycle prune ROOT`, including on legacy stores. Then stop
package and bundle writers, inspect pending
operations, and finish or explicitly cancel them after checking the files. Take
a consistent snapshot set containing the installed programs, package database,
and /Capabilities/Config/switchboard/lifecycle. Include application/provider data
when that data is part of the rollback. Do not assume all these paths belong to
the same dataset or boot environment. Restore the same set together with matching
binaries/libraries and restart services before accepting new writes.

OpenZFS documents atomic snapshots, including recursive snapshots at the same
point in time: [zfs-snapshot(8)](https://openzfs.github.io/openzfs-docs/man/master/8/zfs-snapshot.8.html).
An interrupted snapshot with pending intent requires the same package/file
inspection and exact-operation recovery as an interrupted live installation.
Restoring only the registry can report facts about the wrong filesystem state;
restoring only program files can leave the registry describing a later install.
Snapshots are recovery points, not a substitute for correct fsync behavior.

## Explicit registration follow-up

Runtime identity and session paths now consume existing installation records.
They never adopt an unknown label. Tests verify missing-store/unknown-label
rejection without record creation, explicit adoption, ambient-session registration,
and preservation of identity through completed and cancelled upgrades. The
removal helper also rejects missing ownership.

The live-daemon qualification now includes an unregistered boot service: startup
fails with the expected diagnostic, query remains unknown, and explicit adoption
allows it to start after daemon restart. The existing live installation query
and crash/restart cases passed with this stricter manager.

Legacy systems need installer/operator migration before restarting the stricter
manager. Managed package upgrades explicitly adopt older package slots and retain
active identities. The runtime package owns the built-in login-session principal.
This is a tested migration mechanism and documented rollout order, not a claim
that all previously deployed images have been inventoried.

## Tracing a test deployment

Set `SWITCHBOARD_TRACE_INSTALLATION=1` in the manager environment to emit
installation trace records through syslog (and its existing diagnostic stderr).
Tracing is off by default. Each record includes action (start/session/query),
label, exact installation ID where available, state, and numeric errno. A failed
runtime lookup uses state 0; its error distinguishes unavailable, busy, and stale
identities. State 0 is not permission to remove data. Package source names and
capability contents are not logged.

DTrace builds also expose `switchboard*:::installation`, with arguments action,
label, ID, state, and errno. For a running manager, the string arguments are
userspace pointers; use `copyinstr(arg0)`, `copyinstr(arg1)`, and
`copyinstr(arg2)` when formatting them.

For test artifact retention, set `CAPD_TEST_ARTIFACTS` to a directory outside the
ATF work directory. The switchboard integration harness preserves logs, selected
ledger output, and fixture result files there before cleanup. This does not
change the production installation-history retention policy.

### Traced deployment result

The traced build was installed at the normal executable/library paths in a
disposable VM, and installed hashes matched the staged build. Final validation
passed 49 distinct checks: 29 host cases, 11 daemon integration cases, six CLI/
real-package cases, and three capability-channel cases. In that run, four broader integration
checks skipped: audit capture and three checks requiring an ambient control
channel unavailable to the test shell. The follow-up below closes those skips on the development VM.

Trace assertions found that Capsule's minimal child environment omitted the
new setting. The launcher now explicitly forwards the enabled setting, and the
default-mode suite passed after redeployment. Direct-bootstrap API tests must run
without a competing live Capsule; both affected cases passed in isolation.

Direct DTrace attachment was denied by the manager's process protection. The
verified trace path on this image is the opt-in syslog/stderr output; no protection
was relaxed to make tracing work. Tracing must be enabled in Capsule's environment
so it reaches the manager. Reviewed error records matched deliberate crash and
unknown-registration scenarios; no unexpected authority failure was found.

## Development VM follow-up: 2026-09-12

The four previously skipped checks now have passing results on the disposable
VM, using its normal installed Capsule/switchboard paths:

- Malformed reload retains the running service and its PID.
- An untrusted bundle cannot execute.
- The obsolete `kmod_requires` manifest key is rejected and the previous registry
  remains intact. This replaces a stale test expecting Capsule module loading;
  the supported module broker is sysextd. It does not qualify that broker's
  positive module-loading path.
- The configured BSM trail contains the execution event for the fixture's exact
  service label and PID. The harness now reopens the original trail after
  rotation instead of reading the new empty trail or reusing an exhausted file
  descriptor. Capture filters the BSM event number as well, so audited grep
  arguments cannot be mistaken for the actual service event. The VM selected `ad,pc` events in addition to its original classes.
  Missing audit prerequisites can still skip on other hosts; configured missing
  events fail.

The maximum-record regression passed on the host and VM. It fills the store with
262144 historical owners, verifies ENOSPC leaves durable state intact, prunes,
reopens to verify the last-known identity, and successfully installs afterward.
This found and fixed a capacity bug: adding the expiry-policy record before
compaction prevented pruning a full legacy store. Compaction now precedes adding
that record, with both published in the same atomic commit. The focused host
suite passed all 30 authority, crash, ledger, and manager cases without skips.

A table-driven CRC32C implementation preserves the record format and checksum
while reducing whole-file validation work. The qualification helper performs
three independent reopen/query/close samples against synthetic active-owner
stores. In the 2-vCPU, 3-GiB QEMU TCG guest:

| Active-owner records | Record bytes | Query time, three samples (ms) | Sampled resident KiB |
| --- | --- | --- | --- |
| 1000 | 472000 | 10.295 / 7.590 / 7.423 | 1672 |
| 10000 | 4720000 | 62.900 / 61.791 / 61.703 | 6308 |
| 50000 | 23600000 | 330.960 / 338.149 / 314.783 | 25892 |

Reproduce with `authority_qualification scale NEW_DIRECTORY RECORD_COUNT` from
the installed switchboard test directory. These measure direct store queries in
emulation, not end-to-end RPC throughput or a production latency guarantee.
The reader still validates the entire file. Representative mixed pending/history
stores and concurrent RPC latency remain performance qualification work.

A file-backed ZFS test pool in the disposable VM held the package database,
payload, and registry in one dataset. Real pkg hooks installed version 1,
upgraded to version 2 without changing identity, and completed a prepared
uninstall. Restoring the pending snapshot restored version-2 files/package state
and the pending removal; cancelling it was valid because those files were intact.
After uninstall/reinstall produced a different ID, restoring the original
snapshot restored version 1 and its original ID. The future ID queried unknown,
and retrying a future removal operation failed without affecting the restored
installation. Issued-operation enforcement was established before the snapshots.
This is consistent filesystem recovery coverage, not simulated hardware power
loss or qualification of every release boot-environment layout.

A separate live-stack migration started a service using the earlier version-3
manager, adopted its actual bundle source with current installer tools, and
restarted using the version-4 manager. The service started with the same
installation ID and readable source provenance. This covers the selected legacy
fixture and rollout order, not an inventory of all deployed packages.

After a full guest reboot, the restored ZFS payload, package database and original
installation ID still agreed. The upgraded service also ran after reboot with
its original ID. The initial test-only rc.local hook left the service in the
boot shell's process group and it received SIGHUP; using daemon(8) to detach the
hook fixed that harness issue. The second reboot reached login and the service
remained running, but shutdown reported a syncer timeout. Both shutdowns also
reported signal-11 exits in base services (including devd/getty). These platform
failures remain unresolved and prevent claiming clean release-image reboot
qualification. No kernel or process protections were weakened for these tests.

Artifacts for this follow-up are retained at
`/tmp/installation-authority-review/final-qualification/` in the development
workspace: host results, guest test databases and logs, audit capture, scale
samples, migration and ZFS scripts, boot output, and post-reboot assertions.
The VM used QEMU snapshot mode throughout; its base image was not modified.
The developer book now includes installation integration examples; mdBook builds
successfully and the C query example passes a syntax check against this tree.


## Extended QEMU maturity run: 2026-09-12

A second disposable QEMU run exercises concurrent managed-service queries,
persistent history churn, repeated real-package failures/recovery, the shipped
runtime scripts, and publication faults on ZFS. Its full record is maintained in
`/tmp/authority-maturity-review/`. This remains development-image qualification:
no immutable supported release artifact was supplied, and the available image
boots without the capability plane and has no base installation registry.

The shipped runtime completion hook omitted `org.5bsd.user-session` after its
removal had been prepared. The corrected hook completes all six principals.
The package coverage test now checks every transition, rather than merely
finding a label somewhere in a manifest. It failed before the fix and passed
afterward. A new real-pkg test executes the actual runtime scripts, upgrades
without changing identities, and verifies complete removal with no pending
operations. This qualifies the scripts with a fixture payload, not a complete
release runtime package or every possible existing account database.

The explicit load harness launches eight separate managed services, each with
an authenticated control channel. It seeds 300 upgrades/cancellations and eight
pending installations before adding synthetic active owners. It tests read-only
traffic, concurrent durable upgrades/cancellations, and successful reads after
the writer finishes. Contention errors must leave the output unknown; no wrong
installation states are accepted. Some short query bursts receive only busy
responses while the writer runs. Post-writer recovery is tested separately.

At 50000 synthetic owners plus history, eight saturated clients experienced
roughly three-second successful query latency in TCG. The current whole-file
reader serializes that work in the manager. This identifies a scaling limit;
it is not a production latency promise or proof of adequate responsiveness for
large deployments. Optimization and an agreed workload/latency target remain
necessary before claiming that scale. The run shared host CPU resources with
another QEMU process.

A 3000-cycle persistent-store run retained eight pending operations, preserved
the active identity, and stabilized at 547 records with approximately 2040 KiB
sampled resident memory. Twenty subsequent rounds each exercised real-package
interruption/recovery, the shipped runtime hooks, and installation queries across
live daemon restarts. This is a bounded qualification run, not a multi-day soak.

Unsupported header versions 0, 1, 2, and 5 are rejected for both reading and
writing without modifying stored bytes or deleting the initialized marker.
This tests safe rejection; it does not implement migration from versions 1/2.
All five publication fault cases and the maximum-record recovery case also
passed with their working directories on ZFS.

The baseline reboot reproduced syslogd/getty SIGSEGV reports before deployment.
Source inspection found the capability-unavailable reboot fallback invokes
reboot(2) directly, bypassing userspace shutdown. This narrows the shutdown issue
to the platform path rather than installation transaction state.
The shared base image's mtime changed externally during this run; before the
final reboot, block streaming completed and removed the private overlay's backing
dependency. These results do not qualify an immutable release image. QEMU snapshot
mode also ignores host flushes: no host-crash or hardware power-loss durability
claim follows from these guest process/syscall tests.

Final extended-run results: 31 core cases, 15 default-mode daemon cases, three
capability-channel cases, and six ZFS fault/capacity cases passed without skips.
The package soak completed all twenty rounds (two real-pkg cases and one live
identity/restart case per round). Nine host package-hook cases passed. The
broader CLI rerun passed its reply-validation case; six general admin-command
cases skipped because no ambient login discovery channel is available. Those
six are not installation-query cases and remain unqualified in this environment.

Across the retained load matrix, 4960 requests produced 3128 valid successes
and 1832 expected busy errors, with no unexpected errors or states. Per-client
median successful latency under eight-client read-only saturation was about
116 ms with 1000 synthetic owners, 625 ms with 10000, and 3030 ms with 50000,
plus retained history in each store. Post-writer reads all succeeded at the
10000- and 50000-owner sizes. These are deliberately saturated TCG workloads.

For the final comparison, the test stack was stopped, the file-backed ZFS pool
was exported, and legacy init received its normal reboot signal. Userspace shut
down, the syncer completed without timeout, and no SIGSEGV reports occurred.
After reboot, the migrated service remained running with its original ID, and
importing the test pool restored the expected version-1 payload, package database,
and installation identity. The stock capability-unavailable reboot fallback was
not changed; correcting and qualifying that platform path remains separate work.
The supported recovery procedure passed on this development image. Release-image
qualification still needs an immutable image with its normal capability-plane
boot and package inventory.

Final review found that the first daemon-memory sampler used a BSD ps format
that printed only PIDs. Those files are not memory evidence. The sampler now
uses separate `-o` arguments. A focused rerun on a private read-only copy of the
development image sampled RSS every 0.2 seconds while eight clients each made
ten queries per store size. All 240 queries succeeded. Sampled manager RSS was
21836 KiB (1000 synthetic owners, seven samples), 25528 KiB (10000 owners,
24 samples), and 28580–28628 KiB (50000 owners, 109 samples), plus history and
pending work in each store. These short measurements describe observed resident
memory; they do not establish absence of leaks over a multi-day deployment.
The helper's independent sysctl RSS measurement during the 3000-cycle run was
unaffected by the sampler mistake.


### Reboot fallback follow-up (2026-09-12 local / 2026-09-13 UTC)

Fixed `sbin/reboot/reboot.c`: a failed Capsule request now returns to the
existing SIGTERM, grace period, sync, and SIGKILL sequence before `reboot(2)`.
If the catatonia request also fails, SIGTSTP quiesces legacy init. Protected
Capsule still rejects that signal; no MAC protection was relaxed. The degraded
path does not run ordered service shutdown or `/etc/rc.shutdown`.

Six new ATF cases run the real command with intercepted destructive calls:
accepted Capsule request, legacy-init fallback, protected-init fallback, fast
mode, quick mode, and syncing. All six pass on the host and inside QEMU without
skips. Compiling the legacy-fallback regression against the previous source
reproduced the defect: direct kernel reboot without process termination.

A disposable QEMU TCG guest (two CPUs, 3072 MiB) used a private read-only copy of
`/home/koryheard/vm/bsd-guest-test.img` with a snapshot overlay. The guest booted
`capability_plane=NO` and legacy init. The patched reboot executable's SHA256 was
`57eb0261acb7001655b0f482f06415a6f67fb7fdf39f6536d9853f38acbb03e1`, matching
host and guest before and after reboot. Ordinary reboot completed with all
buffers synced, zero SIGSEGV reports, and no syncer timeout. Syslog and auditd
received SIGTERM. A dedicated process wrote and fsynced a termination marker
on SIGTERM; the marker was present after reboot, proving it could save state
before kernel teardown.

Evidence is retained in `/tmp/authority-next-review`, including the pre-fix
regression, build logs, host Kyua results, reboot console, and post-reboot probe
verification. This closes the observed plane-free direct-reboot defect on the
development image. Live capability-plane shutdown qualification on an immutable
supported release image, large-store query performance, and longer operational
soak remain open. Snapshot-mode testing does not establish hardware power-loss
behavior. Automatic provider cleanup remains disabled.

The patched `reboot -p` also synced all buffers and powered off the guest
without SIGSEGV reports or a syncer timeout. QEMU exited successfully, and
the private test base copy was removed after shutdown.


### Query snapshot cache qualification (2026-09-12 local / 2026-09-13 UTC)

Switchboard now retains one validated read-only snapshot for installation
queries. Each request rechecks trusted paths, the shared nonblocking lock,
state header, file identity/metadata and vnode events. Atomic publication,
restoration of an old inode, ordinary in-place writes, permissions, removal and
revocation invalidate the cached snapshot. No transaction lock is retained.
The durable format, installer operations, and provider cleanup policy did not
change. Cold queries still validate the whole store; warm queries scan records.

QEMU initially exposed a validation race absent from the first host run: on UFS,
the state file's ctime changed between the two fstat calls while its contents
and mtime were unchanged. The pre-fix trace and failed test results are retained.
The reader now discards such a read and retries full validation at most three
times. Writer contention returns immediately. A test injects continuous edits
to verify the retry bound and UNKNOWN error result.

Final checks, all passing with no skips:

- 39 core cases on the host and in QEMU, including eight cache cases.
- Three real authenticated-channel API cases in QEMU.
- Thirteen cache/publication-fault cases with test directories on ZFS.
- Twenty repeated runs of all eight cache cases: 160 passing invocations,
  including 2,000 repeated switches between independent stores.
- Actual ZFS rollback while the same cache remains open: the original ID becomes
  installed and the future replacement ID becomes unknown.
- A strengthened live-daemon integration case verifies that uninstall/reinstall
  refreshes cached old and new IDs before restart, and then verifies both again
  after restart. Structured query tracing confirms successful removed/installed
  replies. The guest test script hash matches the locally built script.

The eight-client matrix contains 5,760 requests: 3,911 correct successes,
1,849 expected EWOULDBLOCK responses with UNKNOWN state, and zero unexpected
states/errors. All read-only and post-writer recovery queries succeeded.
The workload retains 300 prior upgrade/cancellation cycles and eight pending
installations, then adds the stated synthetic active-owner population. Each
mixed phase performs 32 further upgrade/cancellation cycles. Final retention
checks passed at all three sizes.

| Active owners | Prior read-only per-client median | Cached per-client median | Cached maximum | Peak sampled manager RSS |
| --- | --- | --- | --- | --- |
| 1,000 | 115.9–116.7 ms | 23.3–24.2 ms | 78.9 ms | 22,556 KiB |
| 10,000 | 624.3–626.2 ms | 30.0–31.2 ms | 153.7 ms | 30,680 KiB |
| 50,000 | 3,026.8–3,035.3 ms | 59.6–62.1 ms | 548.0 ms | 53,268 KiB |

These are per-client percentile ranges from eight concurrent authenticated
services in a two-vCPU, 3072-MiB QEMU TCG development guest. The 50,000-owner
read-only p95 remains approximately 405–410 ms because full validation is still
needed on a miss. They establish a substantial improvement, not a native
production latency SLO. Retaining the array increases steady memory use; one
snapshot is bounded by SL_MAX_RECORDS, independent of client count.

Evidence: `/tmp/authority-next-review/cache-evidence.tgz` (197,378 bytes),
extracted `cache-evidence/`, `cache-load-summary.txt`, host Kyua databases and
build logs. The book builds successfully at `/tmp/authority-cache-book`.
The deployed switchboard SHA256 is
`53e37815c9a6ec85d8f2e7116a02c3e3dc3c0e0b9cf7f4d124dc13d663bcdcb5`;
libcapsulert.so.2 is
`e7b630601924d0cccdca7fe7e7c71223ffc478f98924a99fc033548ac3689f9b`.
Both match the staged artifacts.

The guest used a private read-only copy of the development base with a snapshot
overlay; no shared-base or host installation was changed. The available image
still boots capability_plane=NO with legacy init. Supported-release qualification
with the normal capability plane/admin channels, a deployment latency target
(including cold/maximum-size reads), and a longer operational soak remain open.
Automatic provider cleanup remains disabled. This run does not qualify hardware
power loss.

The test ZFS pool was exported and legacy init powered off the guest with all
buffers synced. QEMU exited successfully; the private base copy was removed.

### Maximum-capacity qualification (2026-09-13 UTC)

The 262,144-record screen found two remaining full-ledger scans: the query itself
and the one-second retirement timer. At eight clients the original cached reader
had a roughly 1.99-second median and exceeded the provisional memory budget.
Indexing queries alone did not fix timer saturation. The corrected reader builds
a compact owner index, uses binary search for exact IDs, and visits indexed
retirement phases. Read-only validation buffers are unmapped after use, and
normal runtime initialization no longer opens a writable ledger.

The corrected two-vCPU, 3072-MiB TCG guest completed all 800 authenticated requests
at full capacity with no busy or unexpected responses. Per-client medians were
30.5–32.7 ms and p95 values were 62.9–69.9 ms. The first cold requests reached
3.52 seconds. Sampled manager RSS peaked at 192,712 KiB and settled at 71,644 KiB.
Twenty direct cold-cache samples had p95 4,038.6 ms; 100 primed warm queries had
p95 2.19 ms. Cold here means a new userspace cache, not flushed ARC/disk caches.
A separate installation VM also ran on the host; this is development-emulator
qualification, not a dedicated hardware benchmark.

These pass the budgets recorded before the screen: warm p95 below 500 ms, cold
p95 below 5,000 ms, and manager RSS below 196,608 KiB. The RSS margin is small;
production deployments still need workload and hardware budgets. A cache miss
remains a synchronous full-store validation and index rebuild.

All 41 core cases passed on the host and in QEMU without skips. Added tests
compare indexed and uncached facts for duplicate IDs, multiple generations,
latest-owner selection, source counts, and missing owners. A retirement-visitor
test distinguishes partial-source removal from retiring the last source.
The existing explicit-registration test additionally checks that runtime
initialization does not create a missing ledger or lock file.

Evidence is retained under `/tmp/authority-final-gates/`. The completed
normal-plane and longer-soak results follow.

### Normal-plane administrative qualification (2026-09-13 UTC)

A private copy of the locally built amd64 release ISO installed 333 packages onto
a fresh ZFS disk. The original package set uses libservice ABI 2 and contains no
installation ledger. The authority work already uses ABI 3. After checking the
installed package inventory, explicit adoption registered the actual package
sources and ambient-session principal. A development overlay supplied matching
managed providers, component libraries, login/su, Capsule, switchboard and tools.
After reboot, all 12 expected services were running and the root login's normal
discovery channel provided administrative access.

The six previously unqualified administrative cases now pass with no skips:
status, service listing, reload, non-root reload denial, restart with an actual
PID change, and oversized control-payload rejection. The tests no longer start
an unrelated isolated manager and then send requests through the login's ambient
channel. They require explicit `live_admin=yes`, use a registered managed-service
fixture, and clean up through installation transactions. A restart assertion now
accepts the expected `No such process` diagnostic when checking the old PID.

Run these cases only in a disposable normal-plane VM, for example with the
installed FreeBSD test-suite name (substitute a custom Kyuafile's suite name):

```sh
kyua -v test_suites.FreeBSD.live_admin=yes \
    -v test_suites.FreeBSD.preserve_rc_service=cron \
    -v test_suites.FreeBSD.service_fixture=/usr/tests/lib/libservice/capd_service_fixture \
    test -k /usr/tests/usr.sbin/switchboardctl/Kyuafile \
    switchboardctl_test:switchboardctl_status \
    switchboardctl_test:switchboardctl_services_lists \
    switchboardctl_test:switchboardctl_reload \
    switchboardctl_test:switchboardctl_reload_nonroot \
    switchboardctl_test:switchboardctl_restart \
    switchboardctl_test:sctl_oversized_payload
```

The same VM passed all 41 core authority cases on ZFS. Mock-channel API cases
that directly open the minting device require the separate plane-free fixture
environment; Capsule correctly denies that access in a normal boot. External
`procstat -f` inspection of the protected manager is also denied. These controls
were not weakened for qualification.

The ISO is a pre-fix local artifact, and the overlay does not update its package
metadata. These results qualify the normal capability-plane behavior of the
development build, not a supported immutable release or package repository.
The release image/package gate remains open. The repetition and collateral-state
results follow.

The initial 50 repetitions passed all 300 selected administrative cases, kept the
ambient installation ID stable, and left exactly 256 operation records. Reviewing
the final service inventory nevertheless exposed a reload regression: adopted
rc.d units have no capability bundle, so the bundle rescan stopped cron. The
administrative assertions alone had missed this collateral effect. Reload now
excludes adopted RC units from bundle removal and manifest replacement. A live
`preserve_rc_service=cron` assertion failed against the previous manager with cron
in STOPPING state. The corrected manager passed that regression and then all
300 checks in a fresh 50-round administrative run without skips. All 12
services remained running, cron retained its original PID, the ambient-session
installation ID stayed stable, and the ledger retained exactly 256 operation
records. Descriptor-budget denials and control shedding remained zero.
The status `conns` field is a cumulative brokered-connection count, not an open
file-descriptor count; its increase during repeated authentication is expected.

### Extended reboot soak (2026-09-13 UTC)

The disposable development guest completed 201 rounds over 6,118 seconds
(102 minutes), including 20,100 durable upgrade/cancellation cycles, 402 real-pkg
lifecycle cases, and 201 live installation-query/restart cases. Every selected
case passed without skips. Ten actual reboots produced 11 distinct boot records;
each resume verified the original installation ID and eight long-lived pending
transactions. The steady ledger stayed at 547 records while completed history
was pruned. This exceeds the predeclared minimum of one hour, 200 rounds, and
ten reboots; it is not a multi-day soak or a hardware power-loss test.

The normal-plane administrative build additionally fixes the RC reload boundary
found during qualification. Its installation cache/query code matches the
performance and soak build; the two manager hashes are recorded separately.
The maximum-capacity and soak VM uses legacy init, while the administrative VM
uses Capsule as PID 1 with the normal protected discovery/control channels.
Neither test environment substitutes for a coherent supported release package
set. Automatic provider cleanup remains disabled and unqualified.
