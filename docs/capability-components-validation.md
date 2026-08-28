# Capability components validation record

This record separates tests that have actually run from tests that require a
privileged or live system.  A skipped privileged test is not a pass.

## Manifest-format qualification

On August 23, 2026, the serviced capability-bundle format was reviewed and
qualified in a root QEMU guest built from the current tree. The focused guest
run passed 50 of 50 checks with no failures or skips: all 36 libcapbundle
parser cases, three launch-limit cases, and source-built verification of all
11 tracked shipped and example manifests. The parser cases include the exact
1 MiB file-size boundary, every minimum and maximum numeric value, maximum and
maximum-plus-one cardinalities for every bounded collection, duplicate keys
and entries, schema identity and version, literal-only parsing, executable and
reverse-domain name validation, reserved environment names, and every
capability group. The launch cases prove that a maximum valid manifest fits
the bootstrap token table and that storage claims occupy token slots.

On the host, the same 36 parser and three launch-limit cases passed. The
servicectl suite passed all 11 unprivileged cases and skipped its seven
root-only cases. Its dependency inspection now covers filesystem, network,
and crypto local components. The historical whole-component results below
remain dated August 1 and are not silently combined with this focused rerun.

## Unprivileged object-tree validation

Validation was last updated on August 1, 2026 from
`/usr/obj/usr/src/amd64.amd64`.  Every affected library, provider, serviced,
servicectl, and test program built with the normal FreeBSD warning policy
(`-Werror`).  The channel and every DTrace-instrumented provider also built
with both `MK_DTRACE=yes` and `MK_DTRACE=no`, catching probe-only unused
state.  The reviewed Kyua accounting records 493 passed, zero failed, zero
broken, and 178 root-only tests skipped across 34 suites:

- `libcapability`, `libchannel`, `libservice`, `libcapbundle`, `libshmring`,
  `libauthorityctl`, and `libauthorityrt`;
- `libfilesystemcmp`, `libnetworkcmp`, `liblogcmp`, `libnotify`,
  `libtracecmp`, `libauditcmp`, `libkldmgr`, and `librebootctl`;
- `localfilesystem`, `localnetwork`, `logd`, `bsdnotify`, `traced`,
  `auditbrokerd`, `kldmgrd`, and `rebootd`;
- `authorityd` and `serviced`; and
- all nine control-tool suites.

The per-suite result counts were:

| Suite | Passed | Skipped |
| --- | ---: | ---: |
| libcapability | 3 | 1 |
| libchannel | 2 | 8 |
| libservice | 2 | 14 |
| libshmring | 14 | 0 |
| libcapbundle | 30 | 0 |
| libauthorityctl | 6 | 0 |
| libauthorityrt | 6 | 0 |
| libfilesystemcmp | 20 | 0 |
| libnetworkcmp | 13 | 0 |
| liblogcmp | 29 | 0 |
| libnotify | 15 | 0 |
| libtracecmp | 9 | 0 |
| libauditcmp | 10 | 0 |
| libkldmgr | 12 | 0 |
| librebootctl | 12 | 0 |
| localfilesystem | 28 | 2 |
| localnetwork | 19 | 5 |
| logd | 56 | 3 |
| bsdnotify | 25 | 0 |
| traced | 15 | 3 |
| auditbrokerd | 14 | 3 |
| kldmgrd | 22 | 9 |
| rebootd | 30 | 7 |
| authorityd | 26 | 42 |
| serviced | 16 | 71 |
| nine control suites | 59 | 10 |

All component bundle manifests passed source-built `servicectl verify`.
The pkgbase metadata, package dependency, package suffix, typed-discovery,
audit-event, and DTrace-provider source contracts passed in
`component_examples_test`; its final focused rerun passed all seven cases.
The added operational-name contract ties daemon `PROG` and `PACKAGE` values,
rc.d hook names and rc variables, pkgbase metadata, and `.cap` bundle paths to
the reviewed public naming table.

The eight typed client libraries passed 120 of 120 unprivileged tests.  The
tests cover transparent local or global discovery as appropriate, request and
reply validation, attachment ownership, timeouts, close/reopen, fork
rejection, concurrent use, malformed provider replies, and provider death.
The FileSystemCmp and NetworkCmp configuration/diagnostic tools are included
with their providers.  Together with `logctl`, `notifyctl`, `tracectl`,
`kldmgrctl`, `rebootctl`, `servicectl`, and `authorityctl`, the nine command-line
suites passed 59 unprivileged tests and skipped ten root-only cases.

A clean `MK_DTRACE=no` matrix for the five DTrace-aware typed libraries and
all eight providers passed 255 tests and skipped 30 privileged cases.  After
restoring `MK_DTRACE=yes`, 26 DTrace/provider, bundle, observability, and
security contract tests passed.  This checks both compilations rather than
allowing probe-only state or stale non-PIC archives to hide build defects.

AuditCmp, kldmgrd, and rebootd have injected production-backend tests.
They prove that policy denial and malformed input cannot reach the privileged
backend, exercise success and errno mapping, and cover AuditCmp rate limits,
kldmgrd unload ordering and atomicity, and rebootd pending-state rollback.
Source-contract tests also enforce that privileged workers apply capprotect
before dropping inherited service authority, so the protection lease cannot
be closed before use.

The kldmgrd backend boundary includes module enumeration. Policy denial
does not call `kldnext` or `kldstat`, capacity is bounded, and enumeration or
status errors produce an error reply instead of a successful partial list.
Rebootd holds pending state in an anonymous shared atomic mapping created
before capability entry. Unit and fork tests prove that one worker's request
is visible to other sessions, competing mutations fail with `EALREADY`
without a backend call, and backend failure rolls the state back.

The BsdNotify UCL policy loader and the Kldmgrd, Traced, and Rebootd
privileged allow-list loaders now open configuration with `O_NOFOLLOW`,
require a regular file with trusted ownership and no group/world write bit,
and impose a 64 KiB input ceiling.  The line-oriented loaders also reject
embedded NUL bytes instead of accepting a parser-dependent prefix.  Focused
tests cover symlinks, directories, unsafe modes, oversized files, oversized
lines, embedded NULs, malformed identities, duplicates, and wildcard denial.

### Production-readiness follow-up

NetworkCmp now resolves on a dedicated per-session thread with a separately
attenuated Casper channel. A deterministic blocked-resolver provider case
proves that another RPC remains dispatchable, overlap returns `EBUSY`, and the
original reply remains token-correlated. That case is compiled but root-only
on this host.
The unused `liblwipcmp` scaffold was removed: it was not in the build graph,
still carried the obsolete `networkcmp` package identity, and represented an
unqualified second networking architecture. Roadrunner remains the single
supported provider and uses bounded nonblocking kernel sockets; netmap or a
userspace TCP/IP stack remains explicitly future work.

LogCmp added tests for both persistent rotation crash windows: a missing
successor after the completed-segment rename and an empty successor before its
header commit. Startup reconstructs the next generation from retained segment
names, and rotation synchronizes both file contents and directory namespace
changes. Configuration loading now rejects symlinks, non-regular files,
untrusted ownership, group/world write permission, embedded NUL input, and
files above 64 KiB. It reads the already-open descriptor through EOF with a
bounded overflow byte, so concurrent growth cannot be silently ignored. The
client saturation test also proves that recovery emits one typed synthetic
loss record while preserving cumulative per-severity drop counters.

`libcapability` remains the kernel-only `GETINFO`/`CALL` wrapper needed by
serviced, authorityd, and libservice. Its former runtime-compiled shell fixture was
replaced with normal build-time ATF cases covering invalid capacities, reply
slot cleanup, wrong-type descriptors, borrowed request-descriptor ownership,
and a root-only live kernel metadata query. `libchannel` remains exclusively
on `SENDMSG`/`RECVMSG` and does not link or expose `MAC_CAPABILITY_CALL`.

The Authorityd control client now uses `MSG_NOSIGNAL`, applies a bounded send
timeout as well as its receive timeout, rejects summary lengths above the wire
protocol maximum, and reports daemon and transport failures consistently.
Six direct library tests cover dead peers, truncated and oversized replies,
safe caller-buffer truncation, path bounds, and daemon error propagation. Its
test package has an explicit `-tests` suffix and installed Kyua mtree root.
`servicectl` no longer links this Authorityd-specific library merely for raw
socket loops; it owns bounded `MSG_NOSIGNAL` control I/O, validates request and
reply protocol limits, and has three isolated valid/truncated/oversized reply
tests.

`libshmring` marks all four endpoint mappings `INHERIT_NONE` and rejects an
inherited ring object with `ECHILD`. Its fork test proves the child API cannot
write while the original process retains a working endpoint. All typed static
libraries are built with `${PICFLAG}`; all eight PIE providers were then
clean-built against fresh DTrace-enabled object-tree archives. This prevents
pkgbase builds from accidentally succeeding only because an older installed
archive lacked probe relocations.

Notify no longer blocks a relay inside a private router receive while a
`NEXT` request is pending. The relay polls and dispatches both endpoints,
retains the exact channel request until the router replies, rejects a second
in-flight router operation with `EBUSY`, and releases the retained request and
router endpoint on client death. A source-contract regression test proves the
request callback cannot reintroduce the blocking receive. The client library
also has boundary tests for saturating finite timeout grace near
`UINT32_MAX`, including the distinct infinite-wait value.  Broker and
wire-dispatch tests additionally cover exact maximum-size binary payloads
(including NUL and high bytes), oversize rejection, queue saturation,
subscriber isolation, exact GAP/loss reporting, publisher identity, and a
complete publish-to-next round trip.  Client tests prove concurrent calls on
one handle are serialized and invalid inputs do not reach the provider.

The FileSystem path-context suite passed 15 of 15 cases, covering independent
logical current directories, absolute and relative resolution, root-clamped
`..`, transactional failed `chdir`, caller-owned duplicate handles, concurrent
contexts, path-only handle I/O and release, exact root/cwd-handle cleanup,
length limits, and rejection after `fork`.
The provider's persistent-disk suite passed 9 of 9 cases. Restart
reconstruction rejects files with multiple links and files above the per-file
ceiling. A live-mutation test adds a hard link after a handle is opened and
proves that write, truncate, existing-file create, rename, and unlink all fail
without changing the aliased inode.

The serviced on-demand state suite passed 4 of 4 focused cases.  It verifies
that pending work is bound to the exact provider label, PID, and launch
sequence; same-name waiters remain isolated across replacement providers;
timer identifiers wrap without leaving their reserved range or colliding with
a live timer; and failure to register a timeout on the kqueue is immediately
terminal rather than leaving a retained request without a deadline.

Kyua's local database is a diagnostic artifact, not release evidence that
should be packaged.  The root-only client-death, supervisor-death, and
inherited-channel tests, plus the strict component-bootstrap wire rejection
matrix, were enumerated and skipped, not counted as passes.

## Full-world build status

A normal `buildworld` reached unrelated existing VSOCK test code and stopped
because `tests/sys/kern/vsock_rx_harness/virtio_vsock.c` includes the absent
`dev/virtio/vsock/virtio_vsock_var.h`.  A second build with tests disabled
reached unrelated VMM/sysdecode code and stopped because `VM_GET_CPU_COMPAT`
uses an incomplete `struct vm_cpu_compat`.

The logs are:

- `/tmp/capability-buildworld.log`
- `/tmp/capability-buildworld-notests.log`

These failures do not validate or invalidate the component changes.  A clean
full-world and pkgbase artifact build remains a release gate after the
independent base-tree failures are repaired.

Focused pkgbase staging was completed in a fresh DESTDIR with METALOG
generation.  It verified runtime, development, debug, test, and provider
package suffixes; typed-library dependencies; provider/tool grouping; `.cap`
bundle ownership; root-owned configuration files; and LogCmp's private store
directory.  Both `filesystemcmpctl` and `networkcmpctl` were staged with their
providers, while each typed client library remained independently packaged.
This validates package metadata and layout, but is not a substitute for
building archives and exercising package install, upgrade, and removal.

## Privileged and live release gate

Run the following on a disposable test host built from the same source and
object trees:

```sh
cd /usr/src
doas kyua test -k /usr/obj/usr/src/amd64.amd64/lib/libchannel/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/lib/libcapability/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/lib/libservice/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/tests/sys/mac_capability/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/localfilesystem/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/localnetwork/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/logd/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/bsdnotify/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/traced/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/auditbrokerd/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/kldmgrd/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/rebootd/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/authorityd/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/serviced/tests/Kyuafile
doas kyua test -k /usr/obj/usr/src/amd64.amd64/usr.sbin/servicectl/tests/Kyuafile
```

This host has no `doas` executable, so these privileged cases were not run
here and remain release obligations.

### Final review carry-forward checklist

The July 31 shared-ring and logging review leaves the following tests as
mandatory release work.  None is implied by a successful unprivileged build,
and none may be converted from skipped to passed without retaining its Kyua
results or the indicated qualification evidence.

| Gate | Current evidence | Required completion evidence |
| --- | --- | --- |
| Ledger root provider dispatch | 56/59 passed; `provider_backend_failures`, `provider_dispatch_and_ring_lifecycle`, and `provider_malformed_descriptor_is_terminal` root-skipped | Run the Ledger Kyuafile as root and obtain 59/59. Repeat after clean `MK_DTRACE=yes` and `MK_DTRACE=no` builds. |
| Roadrunner root provider dispatch | 19/24 passed; `provider_all_dispatch_opcodes`, `provider_malformed_channel`, `provider_resolver_deadline_terminates_session`, `provider_resolver_does_not_block_session`, and `provider_socket_lifecycle` root-skipped | Run the Roadrunner Kyuafile as root and obtain 24/24, including local IPv4 and IPv6 peers and a deliberately stalled resolver. |
| LogCmp allocation and wakeup faults | Transport, attach, promotion-flush, promotion peer-death, ambiguous-detach, broken-wakeup-after-commit, descriptor-baseline, and corrupt-ring failures are automated | Complete `RNG-004`: inject compact and bulk memfd, sealing, and mmap failures plus final explicit-flush failure; prove exact commit status and descriptor/mapping baselines. |
| LogCmp process lifecycle | Concurrent open, shared handles, close/reopen, fork rejection, final drain, and reconnect are automated | Complete `RNG-005`: race final close against emit and flush at each inline, compact, and bulk state under the documented ownership contract. |
| Ledger crash and durability | Torn-tail and both interrupted-rotation reconstruction paths are deterministic unit tests | Complete `LDG-002`, `LDG-005`, and the `reboot-vm` power-cut matrix at every record-commit, sync, rename, rotation, quiesce, and restart boundary. |
| Logging load, fairness, and loss | Bounded queues, batching, hot-session fairness, and per-severity loss accounting have focused tests | Complete `LDG-001`, `LDG-003`, and `LDG-004` under sustained shard, disk, query, privacy, and sink pressure; retain throughput, p50/p95/p99/p99.9 latency, memory, and loss-counter evidence. |
| 50,000-client scale | Lazy rings and compact/bulk policy are unit-tested | Complete `RNG-006`: 90% idle, no more than 10% active, with descriptor, VM-object, resident/wired-memory, promotion, fairness, and teardown measurements. |
| Installed and pkgbase behavior | Source contracts and METALOG staging pass | Build package archives and test fresh install, upgrade, rollback where supported, dependency-safe removal, suffix identities, installed tests, service activation, and retained Ledger store compatibility. |

Root commands may use another site-approved privilege wrapper in place of
`doas`.  At minimum, preserve `kyua report --verbose` output, the source and
object-tree revisions, kernel/world versions, build options, and the host role
(`root-vm`, `reboot-vm`, or `scale-host`) with every result.

Also run the installed component suites under `/usr/tests/lib` and
`/usr/tests/usr.sbin` so packaging and installed-path assumptions are tested,
not only object-tree paths.  The live run must demonstrate:

- Capsicum entry and descriptor-right confinement;
- mac_capability transfer, close-on-fork, close-on-exec, peer-death, and
  coalition teardown behavior, including
  `cap_pro_nofdrecv_channel_attachment`;
- multiple provided names, lazy per-name activation, provider crashes,
  requester crashes, stale-reply rejection, and serviced death;
- FileSystem scratch, persistent, and read-only bundle namespaces across
  restart, including quota reconstruction and durable sync;
- Network TCP and UDP over IPv4 and IPv6, DNS, nonblocking connect and accept,
  deadlines, cancellation, socket exhaustion, and the blocked-resolver
  concurrency/overlap case;
- Log batching, ring pressure, loss accounting, flush, close/reopen, fork, and
  sink failure, plus restart after each durable segment-rotation boundary;
- Notify default-deny enforcement plus successful identity-bound publish,
  subscribe, state, and timer grants loaded from `/etc/bsdnotify.conf`.
  Confirm that labels cannot impersonate another policy identity, publishers
  cannot forge the event identity, slow subscribers do not block healthy
  subscribers, and GAP counts remain exact under live queue pressure;
- the serviced `private_worker_channel` case, including the provider/worker
  fork boundary, endpoint non-transferability, payload exchange, and
  supervisor-created channel path;
- Trace raw-descriptor denial by default;
- successful and denied OpenBSM audit records and live DTrace probe arguments;
- jail-scoped startup and component coalition membership.

Finally build pkgbase packages with the project’s normal suffix matrix and test
fresh install, upgrade, and removal in a disposable boot environment.  Confirm
that removing a provider does not remove a typed client library needed by
another package, and that removing a library is rejected while a dependent
provider or application remains installed.

## Outstanding production qualification plan

The following cases are required in addition to the presently compiled Kyua
tests. They are intentionally identified separately from the 487 passing
unprivileged cases. A case is not complete until it exists as an automated
test, runs in its designated lane, and retains the evidence listed below.

Status terminology:

- **compiled/root-skipped** means the test exists but has not passed on this
  host;
- **new test** means implementation and execution are both outstanding;
- **qualification run** means an existing test must be repeated under the
  specified load, fault, or hardware conditions.

### Required test hosts

| Host | Required properties | Permitted destructive operations |
| --- | --- | --- |
| `root-vm` | Current kernel/world, auditd, DTrace, test KLDs, IPv4/IPv6 loopback, disposable ZFS dataset | Jail creation, service crashes, audit rotation, module load/unload |
| `reboot-vm` | Boot environment with serial console and automatic post-boot evidence collection | Real delayed reboot, crash during durable-state transitions, power cut |
| `scale-host` | At least 64 GiB RAM, high `kern.maxfiles`, many CPUs, isolated test network | 50,000 concurrent service sessions and coalition/jail churn |
| `pkg-vm` | Clean base install and disposable boot environments | Package install, upgrade, downgrade, removal, rollback |

Record the exact source revision, kernel build ID, world build ID, package
repository digest, loader tunables, sysctls, CPU/RAM topology, and test command
for every host.

Use these locations for new automation so ownership remains clear:

| Area | Test location |
| --- | --- |
| mac_capability attachment and transfer semantics | `tests/sys/mac_capability` |
| libservice worker-channel ownership and malformed replies | `lib/libservice/tests` |
| Serviced activation, descriptor budget, and coalition lifecycle | `usr.sbin/serviced/tests` |
| Beacon admission, routing, policy, timers, and scale | `usr.sbin/bsdnotify/tests` |
| Sundown scheduling, durable recovery, and notifications | `usr.sbin/rebootd/tests` |
| Ledger storage, privacy, loss, and crash recovery | `usr.sbin/logd/tests` |
| Local filesystem and network end-to-end behavior | provider tests plus `usr.sbin/serviced/tests/component_integration_test.sh` |
| Package install, upgrade, removal, and installed suites | release qualification scripts under `tools/regression/capability-components` |

The last directory is a planned test home and must be added with the first
package lifecycle script; this document does not imply that it exists today.

### Private worker channel and descriptor authority

| ID | Status | Test and pass criteria |
| --- | --- | --- |
| `WCH-001` | compiled/root-skipped | Run `serviced_svc_test:private_worker_channel`; provider endpoint must be closed in the child, worker endpoint must survive exactly the intended fork, payload exchange must succeed, and neither endpoint may be made transferable. |
| `WCH-002` | compiled/root-skipped | Run `mac_capability_test:cap_pro_nofdrecv_channel_attachment`; `SCM_RIGHTS` must fail with `EACCES` under `NOFDRECV`, while an attachment on an already-held capability channel succeeds and arrives with `CAP_XFER_NONE`. |
| `WCH-003` | new test | Request worker channels until serviced's descriptor reserve denies admission. Existing services and control clients must remain usable, denial must be `EMFILE` or `ENFILE` as specified, and the DTrace/audit result must match. No endpoint may leak after all clients close. |
| `WCH-004` | new test | Kill the provider before it receives the worker-channel reply, while the reply is queued, and immediately after receipt. Serviced's descriptor count must return to baseline in every case. |
| `WCH-005` | new test | Inject malformed worker-channel replies with zero, one, three, and wrong-type attachments. Libservice must close every unclaimed descriptor and fail without exposing a partial channel. |
| `WCH-006` | new test | Repeat create/fork/exchange/destroy 100,000 times under `INVARIANTS`, `WITNESS`, and a descriptor-leak monitor. Final open-fd and mac_capability object counts must equal baseline. |

### BsdNotify routing and notification semantics

| ID | Status | Test and pass criteria |
| --- | --- | --- |
| `BCN-001` | new root test | Exercise the complete serviced-to-BsdNotify admission path. The parent and router must both retain `NOFDRECV`; the session must reach the router only through the private capability channel and must arrive non-transferable. |
| `BCN-002` | new fault test | Force admission timeout after the router accepts but before its reply is delivered. The parent must classify the result as fatal, destroy that router generation, fail queued clients, and restart without a duplicated live session. |
| `BCN-003` | new fault test | Return truncated, oversized, descriptor-bearing, negative-status, `EINVAL`, and `EPROTO` control replies. Each is fatal. `ENOSPC` and `ENOMEM` are per-client rejections and must not corrupt other sessions. |
| `BCN-004` | qualification run | Open 50,000 sessions on the scale host, split across publishers, subscribers, state users, and timers. Verify the fixed router process count, bounded memory per session, descriptor budget, fair dispatch, and clean reclamation after simultaneous disconnect. |
| `BCN-005` | new stress test | Saturate every subscriber queue while healthy subscribers continue consuming. Publishers must not block on slow subscribers; GAP counts must be exact and monotonic, and one subscriber's death must not affect another. |
| `BCN-006` | new identity test | Run Rebootd with runtime identity `org.5bsd.system.reboot/rebootd`. All four authorized topics must publish successfully; the former `/rebootd` identity and forged payload identities must be denied and audited. |
| `BCN-007` | new lifecycle test | Quiesce BsdNotify with active timers, pending infinite `NEXT` requests, queued publications, and half-closed clients. It must stop admission, resolve or cancel retained requests, reclaim timers, acknowledge quiesce before deadline, and leave no worker. |
| `BCN-008` | new restart test | Crash and restart BsdNotify during publish, state update, subscription change, and timer firing. Volatile state may disappear, but clients must receive peer death, reconnect cleanly, and never receive an event attributed to the wrong router epoch. |

Notification messages remain data-only. Add a permanent negative case that
attempts to attach descriptors to publish, state, timer, and event messages;
the session must fail closed and the received descriptors must be closed.
Capability delegation requires a separate named service protocol and must not
be added to broadcast notification operations.

### Rebootd reboot lifecycle

| ID | Status | Test and pass criteria |
| --- | --- | --- |
| `SDN-001` | new end-to-end test | Request the default delayed reboot and verify `requested`, `scheduled`, and `imminent` notifications contain the correct authenticated publisher, request ID, reason, flags, and remaining deadline. The default delay must be exactly ten seconds. |
| `SDN-002` | new race test | Race cancellation against timer expiry at every millisecond around the deadline. Exactly one terminal outcome is allowed: `cancelled`, or durable disarm followed by reboot. |
| `SDN-003` | reboot-vm qualification | Power-cut after temporary-state sync, rename, directory sync, notification publication, durable disarm, and immediately before reboot. On boot, Rebootd must reconstruct one valid state and must never replay a completed reboot request. |
| `SDN-004` | new dependency test | Stop or crash BsdNotify before each notification. Reboot policy must state whether notification failure aborts or merely records degraded observability; the implementation and tests must enforce that choice without an unbounded wait. |
| `SDN-005` | new quiesce test | Shutdown serviced while Rebootd has a pending request. Durable state, notification outcome, cancellation policy, and quiesce status must agree after restart. |

### Logd logging qualification

| ID | Status | Test and pass criteria |
| --- | --- | --- |
| `LDG-001` | qualification run | Drive all storage shards concurrently to ring and disk high-water marks. Record throughput and p50/p95/p99/p99.9 enqueue latency; prove one hot client cannot starve another. |
| `LDG-002` | new crash matrix | Crash before and after every active-record commit, segment rename, successor creation, header sync, and directory sync. Recovery must retain every committed record once, reject corrupt committed segments, and truncate only an uncommitted torn tail. |
| `LDG-003` | new privacy test | Exercise public, private, and sensitive fields through retained storage, syslog projection, queries, DTrace, core suppression, and diagnostics. Raw private values must never appear outside the authorized projection. |
| `LDG-004` | new loss test | Exhaust every ring, internal queue, disk quota, and sink path independently. Synthetic loss records and cumulative per-severity counters must be exact across recovery and restart. |
| `LDG-005` | new lifecycle test | Quiesce with active writers, blocked queries, rotation in progress, and a failed sink. Flush must use one total deadline, return an accurate error, and leave a restartable store. |
| `LDG-006` | new compatibility test | Install an older retained store, upgrade Logd, query old and new segments, downgrade when supported, and verify explicit rejection when the on-disk version is not compatible. |
| `LDG-007` | naming qualification | Confirm syslog records use the `logd` tag from both manager and storage worker; no operational record may use the obsolete `logcmp` daemon tag. |

### Shared-memory shape and logging activation qualification

The typed library, not the application, owns ring policy.  `libshmring`
currently implements compact and bulk SPSC rings with immutable watermarks.
The trusted multiplexed shape is reserved and returns `ENOTSUP`; it is not a
release feature until its reservation/commit algorithm can recover from a
stalled or dead producer without exposing writable storage to unrelated
clients.

| ID | Status | Test and pass criteria |
| --- | --- | --- |
| `RNG-001` | implemented | `shmring_test:shapes_and_watermarks`, `forged_objects`, `forged_aliases`, `forged_metadata`, `counter_overflow`, and `corrupt_positions` cover compact/bulk boundaries, immutable shape discovery, ordered watermarks, versioned options, reserved fields, explicit `ENOTSUP` for trusted MPSC, exact role rights, distinct object identity, sealed malicious geometry, counter wrap, and observable invariant failure. |
| `RNG-002` | implemented | `client_lifecycle_test:ring_is_lazy_and_policy_selected` proves an idle LogCmp session allocates no ring, the first seven records remain inline, and the eighth causes exactly one 16 KiB compact attachment selected inside `liblogcmp`. |
| `RNG-003` | implemented | `shared_memory_burst_is_asynchronous_and_batched` proves compact pressure drains in a batch, performs one detach, promotes to the negotiated bulk ring, and a final flush accounts for every record. `final_close_drains_attached_ring` proves best-effort final close drains before detach. |
| `RNG-004` | partial | Lazy attach failure, bulk promotion failure, promotion-flush failure, promotion peer-death, ambiguous detach failure, broken wakeup after ring commit, repeated attach descriptor cleanup, and corrupt-ring terminal recovery are deterministic.  Add injected compact and bulk memfd/sealing/mmap failures and final explicit-flush failure.  A committed record must never become retryable; an uncommitted record must return an exact error; all descriptors and mappings must return to baseline. |
| `RNG-005` | new process test | Open and close many LogCmp handles in one process before and after promotion, race final close with emit/flush under the documented ownership rules, fork at each ring state, and prove one process session and ring are shared without child authority reuse. |
| `RNG-006` | scale qualification | Connect 50,000 clients with 90% idle and at most 10% active on 8--16 KiB compact rings.  Measure resident/wired memory, VM objects, descriptors, promotion rate, and teardown.  After the `RNG-008` metadata optimization, the target is approximately 60 MiB of shared ring memory for 5,000 active 8 KiB clients plus one control page each, not multi-gigabyte eager allocation. |
| `RNG-007` | future implementation | Implement trusted internal multiplexed rings only for fixed Ledger worker shards, with source/session IDs, bounded producer slots, reservation/commit recovery, producer-death tests, and no writable mapping in unrelated clients. |
| `RNG-008` | future optimization | Copy and unmap sealed configuration after validation and combine producer-owned head metadata with the producer-writable data object while preserving a separately protected consumer tail.  Prove page and VM-object reductions with `procstat` and reject every forged geometry/permission combination. |

Focused object-tree validation on July 31, 2026 passed all 14 libshmring
cases, all 29 liblogcmp cases, and 56 of 59 Ledger cases; the remaining three
Ledger cases were root-skipped.  These focused counts supplement rather than
replace the complete-suite release matrix below.
The root-only Ledger and Roadrunner provider cases were attempted during the
final review, but this qualification host has neither `doas` nor `sudo`;
they remain required runs and are not counted as passes.

### LocalFilesystem filesystem qualification

- Create, close, and persist objects up to every byte, object, path, depth, and
  open-handle boundary; the first over-limit operation must fail atomically.
- Crash at create, mkdir, rename, unlink, truncate, write, file sync, directory
  sync, and accounting-update boundaries. Restart reconstruction must agree
  with durable namespace state and remain bounded in time and memory.
- Inject symlinks, hard links before and after open, mount crossings, device
  nodes, FIFOs, sockets, sparse files, overlong names, invalid UTF-8 bytes, and
  rename cycles. No operation may escape the namespace or mutate an aliased
  inode.
- Run independent logical current directories concurrently. Failed `chdir`
  and root changes must be transactional; `..` must remain clamped at the
  assigned root.
- Restart the consumer coalition and provider independently and verify scratch
  loss, persistent retention, and read-only bundle immutability match the
  documented contract.
- Run 50,000 namespace instances on the scale host and measure startup scan,
  open descriptors, wired memory, teardown latency, and jail/coalition object
  reclamation.

### LocalNetwork network qualification

- Cover TCP and UDP over IPv4 and IPv6, DNS success/failure/truncation,
  nonblocking connect, accept, listen, shutdown, half-close, cancellation, and
  deadline expiry using deterministic local peers.
- Stall DNS, connect, accept, send, and receive independently. Unrelated
  sessions must continue, a second operation on the same channel must receive
  the documented busy result, and no global client-library mutex may span the
  wait.
- Exhaust sockets, mbufs, descriptors, resolver workers, and policy entries.
  Admission must remain bounded and recover after resources return.
- Verify destination policy after DNS resolution and for every returned
  address, including rebinding, IPv4-mapped IPv6, link-local scope IDs,
  broadcast, multicast, wildcard bind, and privileged ports.
- Kill caller, worker, resolver, peer, and serviced at every asynchronous
  state. Pending operations must complete once with cancellation or peer-death
  status and all sockets must close.
- Run at least 50,000 concurrent idle channels and a mixed connection workload
  on the scale host; record throughput, tail latency, memory, descriptors, and
  fairness. Netmap and a userspace TCP/IP stack are not part of this release.

### Remaining global-service qualification

- **Traced:** prove default denial, administrator-only enablement,
  per-identity policy, bounded DTrace buffers on the target machine, ioctl
  rights, worker death, quiesce, and absence of raw descriptor transfer to
  ordinary applications. Treat raw DTrace delegation as restricted production
  functionality, not general application tracing.
- **AuditBrokerd:** test auditd stopped, suspended, rotating, full filesystem,
  backpressured pipe, malformed record, per-identity rate exhaustion, and
  restart. Audit submission failure must not deadlock the calling daemon.
- **Kldmgrd:** use a dedicated signed test module to cover load, duplicate load,
  dependency ordering, unload refusal, rollback, worker crash, and concurrent
  requests. Confirm that policy denial never calls the kernel backend.
- **Authorityd:** exercise every capability service with wrong versions,
  malformed attachment counts, descriptor pressure, revocation, authority
  restart, and 50,000 concurrent capability objects. Audit and DTrace must
  agree on result and identity.
- **Serviced:** repeat activation, multiple provides, provider replacement,
  requester death, circuit breaking, descriptor shedding, coalition teardown,
  and quiesce under concurrent load. Kill serviced at every transition and
  prove clients observe supervisor death without consuming another session's
  reply.

### Packaging, upgrade, and installed-system tests

The pkg-vm lane must build actual archives, not only a DESTDIR/METALOG stage:

1. Install each typed library without its provider and verify headers, shared
   library links, manual pages, and the expected discovery error.
2. Install each provider and tool, verify `.cap` ownership/modes, root-owned
   policy, private state directories, service discovery, DTrace providers, and
   audit-event registration.
3. Upgrade from the immediately preceding package revision while Ledger and
   Packrat retain data and Sundown has no pending reboot.
4. Attempt provider removal while clients remain, and library removal while a
   dependent provider/application remains. Dependency handling must reject the
   unsafe operation.
5. Remove and reinstall providers. Persistent data and administrator-edited
   configuration must follow the declared package policy; no obsolete daemon,
   rc variable, syslog tag, object path, or compatibility alias may return.
6. Run the installed Kyua suites using only installed binaries, libraries,
   fixtures, and data files.

### Stress, repetition, and evidence requirements

- Run the complete root stack 100 consecutive times and the unprivileged
  34-suite matrix 1,000 times in the nightly lane with zero broken or failed
  cases and no growth in descriptors, processes, jails, coalitions, shared
  mappings, or mac_capability objects.
- Repeat the concurrency suites under `INVARIANTS`, `WITNESS`, KASAN, userspace
  ASan/UBSan, and ThreadSanitizer where supported. Run protocol parsers and
  retained-store readers under coverage-guided fuzzing with the checked-in
  corpus and a zero-crash release window.
- Capture Kyua result databases, serial consoles, audit excerpts, DTrace
  aggregations, daemon logs, core metadata, `procstat -f`, `procstat -r`, jail
  and coalition inventories, package manifests, and before/after resource
  counts. Payloads marked private or sensitive must be redacted from retained
  evidence.
- A timing test passes only when it waits on an observable state transition;
  fixed sleeps are not evidence. A crash test passes only after the guardian
  proves all descendants and protected objects were reclaimed.

Release sign-off requires every ID above to have an owner, an automated test
location, a passing result URL or artifact digest, and an explicit disposition
for every supported architecture. Any waived case must identify the approving
reviewer, affected release, risk, and removal date.

Implement and execute the backlog in this order:

1. `WCH-001` through `WCH-006`, then `BCN-001` through `BCN-003`; these prove
   the authority-transfer foundation used by the fixed workers.
2. `BCN-006` and `SDN-001` through `SDN-005`; these close the reboot
   notification and durable terminal-outcome boundary.
3. `LDG-002` through `LDG-005` and the Packrat crash matrix; these protect
   persistent state before scale testing can produce useful evidence.
4. Network cancellation/policy tests and the remaining privileged global
   services.
5. Scale, repetition, sanitizer, fuzz, package lifecycle, and architecture
   coverage.

A later phase may not be used to waive a failure in an earlier phase.
