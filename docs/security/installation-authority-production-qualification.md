# Installation authority production qualification

Status: blocked on a kernel memory-corruption failure. The coherent build,
installation, upgrade, regression, capacity and recovery gates passed. The
corrected final-runtime sustained run completed 149 cycles and ten reboots,
then panicked while ZFS allocated a previously freed buffer during dataset
destruction. Production qualification is not complete. Process protection
correctness and hardening changes are separate and were not deployed in this VM.

## Candidate and provenance

The candidate uses an isolated source tree based on
`85424c01c9237a33668d2e459a042831415fdf18` plus the recorded authority changes.
Full world and VBSD kernel builds completed. No old kernel objects or runtime
binary overlays were substituted. A missing umtx wait-channel helper and missing
reclamation test include were fixed when those complete builds exposed them.
Log storage admission limits and drain scheduling were corrected and rebuilt
with the candidate world. Test corrections were rebuilt with that world's
sysroot or compiled by the installed Linux test harness and incorporated into
packages.

The selected base and test packages use version `16.snap20260913160000`.
Separate debug-file packages are omitted from this candidate profile. The final
ISO SHA256 is
`ed21afdae0ee27ba0a5bca81f9e8b2711cae905d5369d24e8139bdba232347e1`.
Its offline repository contains the corrected log-storage, worker and futex test packages.

Both fresh and upgraded systems' capsule, switchboard, switchboardctl and kernel
hashes match their package payloads. Live installation media boots with the
capability plane disabled because it has no installed authority ledger; the
installed system boots with the normal capability plane enabled.

The unprivileged media build emitted 1,539 duplicate METALOG definition warnings;
makefs reported zero errors. These warnings are retained in the build log rather
than counted as a warning-free build.

## Installation and upgrade

An automatic ZFS installation using the actual bsdinstall Lua/pkg path committed
all six expected principal records without manual adoption, left no unfinished
operations, and booted with 12 healthy services. The media containing the final
runtime also installed successfully and booted
with all five runtime hashes matching the package payloads. Its first automated
login preceded provider readiness and therefore received no administrator
discovery channel. A subsequent login after startup had that channel and all
12 services were healthy. This follows login's existing best-effort discovery
policy: an early shell remains usable but requires a new login for capability
administration. The test does not establish administrator-channel availability
at the first boot prompt.

The upgrade baseline is a private copy of an earlier development installation:
333 packages plus an authority development overlay. It is not an unmodified
supported release. The upgrade replaced 315 packages, installed the selected
base/tests sets, and removed 19 old debug packages after updating their
metapackage dependencies. All 15 previously active installation IDs and opaque
resource-owner keys survived, as did persistent ZFS dataset GUIDs and mountpoints.
Those checks also passed after a normal reboot.

The baseline carried a same-version pkg 2.8.4 binary built for a different libc
symbol version. Replacing it with the candidate media's pkg resolved the package
repository test failure. The recorded upgrade procedure explicitly installs the
candidate's compatible package manager even when its version number is unchanged.

The upgraded system activated two cleanup providers on demand and had 14 healthy
services. A retained `@before-authority` snapshot prevented destruction of its old
ephemeral boot dataset; the snapshot was preserved and authority cleanup had no
pending receipts. Normal upgraded shutdown exited the manager successfully and
synced all buffers.

## Final Log package update

After the supporting soak, the same VM installed the final Log and test packages
through `switchboardctl lifecycle run / pkg add -f`. Log's installation identity
and every active owner record matched before installation, afterward and after a
normal reboot. All five runtime hashes matched the final candidate. The updated
system passed 54 Log tests and seven worker tests without skips or expected
failures, then passed 20 cleanup cycles and one further reboot over 753 seconds.
Independent archive checks verified 60 distinct identities, all 300 provider
receipts, a stable 1,390-row ledger and sampled manager RSS of 93,348–96,116 KiB.
The per-round process count stayed at 72. The VM then shut down normally.

## Regression results

An independent audit of the saved Kyua databases confirms 157 passing authority
cases with no skips, unexpected failures, or expected failures in that set:

| Area | Passing cases |
| --- | ---: |
| Core authority, replay, crash, cache | 46 |
| Reclamation worker | 7 |
| Lifecycle CLI | 7 |
| Normal administrative channel | 6 |
| Real package lifecycle | 3 |
| Actual Lua installer | 2 |
| Privileged service API | 15 |
| Jail descriptors | 4 |
| Five provider cleanup/reuse paths | 8 |
| Log storage and retention | 54 |
| Live manager integration | 5 |

A fresh-image repeat exposed a timing assumption in the worker fixture: receipt
arrival can precede the send callback returning and releasing its busy fence.
The corrected case holds the sender across admission handoff, verifies that the
fence remains, then releases it and checks eventual collection. It passed 100
repetitions. No worker runtime change was needed.

The package regression now uses an actual repository upgrade to test adoption of
pre-authority installations. `pkg add -f` does not provide the same upgrade-hook
context. The log-storage fixture now explicitly persists the delivery batch before
acknowledging provider completion, matching the manager's actual sequence.

Supplemental kernel validation produced 34 native threading passes and two
historical expected failures in priority-ceiling attribute tests (PR 211802).
They are reported separately and are not counted as authority passes. Linux
futex break, futex2 and wait-vector checks passed. The vector stress fixture had
its own result-publication race: its waking thread overwrote a result that could
already have been written by the waiter. Initialization now precedes thread
creation, with atomic result exchange. Five additional full stress runs passed.

## Capacity and recovery

At 262,144 records, eight clients completed 800 queries with no busy or unexpected
results. Manager startup took approximately 8 seconds under the original
15-second fixture deadline. Sampled peak manager RSS was 168,908 KiB, below the
196,608 KiB budget. Cold-query p95 was 4,552.153 ms over 20 trials, below the
5,000 ms budget; warm p95 was 2.452 ms over 100 trials, below 500 ms.
These are QEMU TCG measurements, not hardware performance guarantees or an
allocator high-water mark.

A real five-provider fixture verified upgrade preservation, last-source cleanup,
replacement isolation, and interrupted provider recovery. Three acknowledgements
and two pending providers survived a normal reboot while a retained snapshot and
disabled Waspnest blocked completion. Explicit removal of the test snapshot and
reenabling Waspnest yielded five receipts. The replacement retained its identity,
private storage and live use of all five providers. Software crypto was enabled
only for the TCG fixture and restored afterwards.

The coherent isolated-mode shutdown also synced all buffers and did not reproduce
the earlier overlay pilot's quiesce/getty failures.

The retention review found that log retirement metadata could exceed the
loader's maximum accepted entry count. Admission now rejects new fences with
`ENOSPC` at that boundary before writing an unreadable image; updates and retries
for existing fences still work. A dedicated reduced-limit build of the actual
store verifies rejection without metadata changes and reopening at capacity.
The new boundary case and all 53 existing storage cases passed.

The fresh-image storage repeat exposed long record-count-only drain batches on
TCG. Log now also yields after a 10 ms drain quantum, checked between writes;
explicit flush and query barriers still drain their caller's queued records.
This is a scheduling bound, not a guarantee on an individual blocking disk I/O.
The original one-second fairness fixture failed repeatedly during package builds
and intermittently after the build. With time-bounded draining, 98 of 100 runs
passed that original deadline. The regression now uses the storage API's normal
five-second timeout and additionally verifies continued flood-writer progress.
The one-second failures remain performance evidence rather than being relabeled
as passing functional results. All 100 repetitions of the revised contract case
and all 54 storage cases
passed. The final image then passed its normal and isolated regression phases.
The final runtime sustained qualification failed as described below.

## Sustained run

A 20-cycle, 551-second pilot completed successfully before a final runtime
correction. It is not the sustained qualification.

The host ran out of disk space during the sustained run, causing QEMU to pause
on a `nospace` I/O error. After host space became available, the VM resumed.
Guest time initially stopped while paused, then caught up with host time at
reboot. The required duration was therefore extended to 7,800 seconds, adding
ten minutes to cover the interruption. Retained host events document the pause.
This is not a power-loss test.

The supporting run uses the Log runtime before the scheduling refinement and
completed 213 cycles over 7,815 guest seconds with ten normal reboots. Independent
archive checks verified 639 distinct installation identities, all 3,195 expected
provider receipts and bounded ledger history (1,079–1,402 rows). Sampled manager
RSS ranged from 95,188 to 104,952 KiB; per-round process counts ranged from 69 to
75. This supporting evidence does not replace the final-runtime run.

The final image's initial run started at 19:06:33 UTC and stopped after 60
completed cycles because of the fixture deadline described below. The corrected
run started at 20:01:48 UTC using the same final runtime and the rebuilt diagnostic
fixture. It requests a reboot after each of its first ten cycles and requires at least
7,200 seconds, 200 full real-provider cleanup cycles and ten normal reboots, with
bounded ledger history, complete receipts, no private
storage or jail leaks, and retained per-round process/log samples.

This qualifies process failure and normal reboot behavior. Physical power-loss
durability is not established by these tests. ZFS rollback must restore registry,
package, program and provider state together as documented in the recovery
contract; cleanup does not remove retained user snapshots.

## Evidence

- `final-update.tgz`: 3,819,088 bytes, SHA256
  `22015819ed3182a529cb0ec176de9a81c6622bbcaae1a258423ad0f47c717406`.

- `supporting-soak.tgz`: 11,850,110 bytes, SHA256
  `c99b5f88b3439648d4a9293f344b3211c326f5125cf4c000b66296d294df3184`.

Evidence is retained under `/tmp/authority-production/evidence`:

- `pre-soak.tgz`: 912,202 bytes, SHA256
  `2679132530335955b18a0c8577ea3da9046f10468421834bb1a12ca9b01a8736`.
- Upgrade archive at `../upgrade/evidence/upgrade.tgz`: 14,721,760 bytes, SHA256
  `3db5065ba1b102cac2f19e77bc3b9f29d1f2af3aca0fed806bc6779434e8b739`.
- Source revision, per-file hashes, source patch, world/kernel/package/media logs,
  package and installed-binary hashes, serial logs and driver event records.

- Fresh-image and corrective stress archive at
  `../upgrade/evidence/fresh-storage-fixes.tgz`: 435,654 bytes, SHA256
  `e8f292971063f1bd7d1e83493fa4bbc46853f28e404d2a2748613caf78ecca5a`.

Superseded failures and pilot results remain in the evidence. Final sustained and
final-media archives will be recorded when their checks finish. Preserve these
artifacts with release evidence before discarding the temporary workspace.

## Filesystem fixture deadline correction

The initial final-media run completed 60 cycles before both first Filesystem
requests in round 61 timed out at the fixture's 10-second deadline. QEMU remained
running with no reported host I/O error. The failed run is preserved as
`release-failed.tgz`, SHA256
`4ff2588a161430990c4c40dc07c46bfb3a3af6b8d06338af64715f006962e4f1`.

Request-stage timing reproduced the failure on the same boot: connection setup
succeeded and the session call timed out. Process samples taken during fresh
allocation showed the two Filesystem workers alternating between ZFS transaction
sync (`tx->tx_s`) and the TrustedZFS namespace lock (`TrustedZ`). They completed
after the callers' deadline; subsequent opens of those existing claims succeeded.
The samples do not support the initial suspicion of a provider dispatch deadlock.

The production `service_storage_open()` API uses the default session wait for
ZFS allocation. The fixture now follows that behavior for Filesystem, retains
its 10-second bound for its other raw provider requests, and records request
stage, result, errno and elapsed time. The external readiness harness retains
its bounded polling loop. No production timeout was increased. With the corrected
fixture, two fresh allocations completed in 16,907 and 16,748 milliseconds, and
the full five-provider cleanup qualification passed. Existing-claim update took
1,350 milliseconds; replacement allocation took 8,607 milliseconds.

The diagnosis archive is `fs-diagnosis.tgz`, 247,604 bytes, SHA256
`9c7fc31c019e34a97f87346026f249d38f24e79985c26a53d985201aad4d9ad2`.
It retains the failing attempts, process samples and successful corrected run.
The corrected fixture was built with the candidate world and sysroot; its SHA256
is `eb4047e777e68174d752228e9d0de20777aab5e59898258d428bb3235b1a68f1`.
It is a test-only addition to the installed media; production binary hashes are
unchanged. The sustained rerun must finish before this qualification is complete.

## Final-runtime kernel panic

The corrected sustained run completed 149 cycles over 5,453 guest seconds with
ten normal reboots. During the next cycle, the kernel detected a modified freed
16,384-byte `zio_buf_16384` allocation at offset 8,192. The detection stack runs
through `trash_ctor`, `zio_buf_alloc`, `arc_read`, `traverse_dataset_destroyed`
and `dsl_scan_sync`. This identifies the detection path, not the modifying
operation. The changed word was `deadc0de80000000`.

The host driver stopped after 300 seconds without a completed cycle. The QEMU
memory dump and debugger traces were preserved before reboot. The compressed
memory dump SHA256 is
`856b23c3c068206af5671a4298acc70fa60d84eae2ca94ad4e631b128419c925`.
No protection patch was installed in this guest. This failure must be diagnosed
and the sustained gate rerun successfully before production signoff.

## Work-in-progress checkpoint

The process-lifetime patch rejects exited process descriptors, associates tokens
with a shield generation, removes an exiting process's authorization roles, and
limits token activation to its original accessor. Its kernel translation unit
compiles with warnings treated as errors. It has not been deployed or verified
in QEMU. The baseline VM reproduced stale-handle and PID-reuse failures before
these edits.

Additional source edits reject malformed protection declarations, add explicit
factory policies, and apply worker protection before inherited authority is
dropped. These userspace changes still need build and regression validation.
The launcher startup gate and Bluetooth socket-broker changes remain unfinished.
No production-readiness claim applies to this checkpoint.

The interrupted authority run was recovered as `corrected-panic.tgz`, 6,831,452
bytes, SHA256
`7b81e7a542018f42a77cc752001e458e8d29c79efbd0cc074ef245abd400fbc5`.
