# Capability Daemon Test Suite Architecture

## Status

This document defines the target test architecture for the capability stack.
It supersedes the current practice of growing independent ATF shell programs
with private daemon lifecycle code and C programs compiled from heredocs.

The scope is:

- the `mac_capability` kernel framework and its capability services;
- `libauthorityrt`, `libcapability`, `libchannel`, `libservice`, `libshmring`,
  `libcapbundle`, and every typed service library;
- `authorityd`, `serviced`, `authorityctl`, and `servicectl`;
- FileSystemCmp, NetworkCmp, LogCmp, Notify, TraceCmp, and AuditCmp;
- privileged managed services such as `kldmgrd` and `rebootd`;
- capability-managed device brokers such as `blued`.

The objective is not merely a green suite.  The suite must demonstrate that
authority is created, confined, transferred, used, revoked, and recovered
correctly under success, denial, concurrency, crash, and timeout conditions.

The first infrastructure migration is implemented:

- `capd_test_guardian` gives every stack test exact procdesc-based recovery,
  including recovery when Kyua or the invoking shell disappears;
- `capd_test_harness.sh` is the single stack lifecycle implementation used by
  the daemon and library integration suites;
- `capd_service_fixture`, `capd_protocol_fixture`, and
  `capd_bootstrap_fixture` are normal build-time programs replacing generated
  C and object-tree-specific runtime compilation;
- `libservice_api_test` and `req_validate_test` move pure validation below the
  full-stack layer; and
- the focused runner stages the same fixtures and harness used by installed
  tests.

The L0-L2 coverage matrices below remain the definition of done, not a claim
that every row is already implemented.  New cases should land at the lowest
layer able to prove the contract; L3 should remain a deliberately small set of
cross-boundary invariants.

## Non-negotiable properties

Every test must satisfy these rules.

1. **The test owns every process it starts.**  Ownership means retaining a
   legitimate termination mechanism, not remembering a PID.
2. **A passing test has already stopped its stack.**  ATF cleanup is an
   idempotent failure fallback, never the primary lifecycle path.
3. **Timeouts are recoverable.**  A timed-out test must not leave a protected
   daemon that requires a reboot.
4. **No broad process matching is allowed.**  `pkill -f`, `killall`, and PID
   guesses are forbidden.  Process descriptors or another exact authority
   identify test processes.
5. **Synchronization is event-driven.**  Fixed sleeps do not establish
   readiness, ordering, or termination.  Every wait has a monotonic deadline
   and emits diagnostics on expiry.
6. **Fixtures are built with the tree.**  Tests do not compile C heredocs at
   runtime.  A fixture's source, warnings, dependencies, and installed-test
   behavior are reviewed and built normally.
7. **Denials verify the reason.**  A nonzero exit is insufficient.  Tests
   check the protocol status or exact `errno` and confirm that no forbidden
   side effect occurred.
8. **Security assertions use an independent observer where possible.**  A
   service must not be the sole source of evidence that its own descriptors
   or credentials were confined.
9. **Development and installed tests have the same semantics.**  Object-tree
   selection may change binary paths, but not topology, fixtures, or cases.
10. **Global-state tests are explicitly exclusive.**  Module, audit, DTrace,
    mount, jail, network, and hardware mutations declare and restore their
    state.

## Test pyramid

### L0: pure protocol, schema, and parser tests

These run unprivileged, do not load modules, and do not start daemons.

Coverage includes:

- every request and reply type, size, version, flag mask, and reserved field;
- bundle schema, normalization, duplicate handling, path traversal, symlinks,
  arguments, environment, capability families, and dependency declarations;
- claim parsing and canonical round trips for path, network, jail, system,
  Bluetooth, kmod, service, and future claim types;
- overflow, truncation, unterminated strings, invalid UTF-8 where applicable,
  and unknown enum values;
- public library null, range, state-machine, descriptor-type, and environment
  validation.

Parser and validator logic must be callable from C tests without launching the
daemon that consumes it.  Table-driven C tests replace shell cases that start a
daemon solely to discover whether a configuration value parses.

### L1: kernel capability-service contract tests

These test one kernel service at a time through `/dev/mac_capability`.  They
are root-only and exclusive only when they mutate shared kernel state.

Each capability service receives the same conformance matrix:

| Contract | Required checks |
| --- | --- |
| Discovery | known service, unknown service, duplicate connection |
| Wire validation | short/long request, bad version/op/flags/reserved fields |
| Authority | no claim, wrong claim, wrong nonce, stale token, valid token |
| Descriptor confinement | type, rights, transfer count, close-on-exec/fork |
| Identity | fork, exec, credential change, jail boundary, process exit |
| Revocation | explicit release, owner exit, reload replacement, duplicate release |
| Concurrency | simultaneous mint/use/release and interrupted callers |
| Accounting | limits, exhaustion, rollback, leak-free failure paths |

The existing `tests/sys/mac_capability` suite is the base for this layer.  Its
large generic test file should be split by service contract and share a small C
conformance library rather than duplicating setup code.

### L2: daemon component tests

These run daemon subsystems with injected backends and socketpairs, without a
live protected Authorityd stack. Production logic must expose narrow interfaces;
tests must not copy implementations.

`authorityd` component coverage:

- configuration defaults, overrides, validation, and reload diff planning;
- control protocol framing, authorization, slow/early-closing clients, and
  bounded connection handling;
- claim transaction planning, commit, rollback, and status snapshots;
- bootstrap state machine, backoff, circuit breaker, and watchdog decisions;
- all request validators and reply construction.

`serviced` component coverage:

- bundle registry and dependency graph algorithms;
- startup tiering, on-demand state transitions, restart policy, and backoff;
- transactional reload planning and rollback;
- naming ownership, authorization, auto-unregister, and waiter cancellation;
- environment and descriptor layout construction;
- audit event selection and DTrace state-transition probes;
- supervisor reactions to every wait status and procdesc event.

Audit and DTrace cases protect an observability interface.  They belong in the
normal daemon/component suite, but they are not gates for the focused
capability-correctness runner: instrumentation failure does not imply that a
claim, token lease, confinement boundary, or lifecycle invariant is broken.

`kldmgrd` and `rebootd` component coverage:

- complete request-validation and client-label authorization matrices;
- backend success and every relevant backend `errno` through injected syscall
  adapters;
- proof that denied or malformed requests never call the dangerous backend;
- response behavior after client disconnect and partial messages.

`blued` component coverage remains in its dedicated suite, using the virtual
HCI backend for controller behavior.  Capability activation, descriptor
confinement, and serviced lifecycle use the common fixtures and harness.

## Library contract suites

The pyramid describes where tests run; it does not replace a contract suite for
each public library.  Every exported function must appear in that library's
API coverage table with success, invalid-input, resource-failure, and relevant
state-transition cases.

### `libauthorityrt`

- encode/decode round trips for every Authorityd request and reply;
- exact wire size, alignment, byte order, version, operation, flag, and reserved
  field validation;
- descriptor count/type/order validation and cleanup after partial receipt;
- fragmented transport, peer close, interruption, retry, and oversized message
  behavior;
- claim canonicalization and stable text/binary round trips;
- forward-compatibility behavior for unknown versions, operations, and flags;
- fuzz targets seeded by one valid and representative invalid message for every
  operation.

### `libcapability`

- kernel-service metadata and synchronous-call APIs across their complete
  state machines;
- exact behavior for missing, malformed, stale, closed, and wrong-type kernel
  capability descriptors;
- descriptor ownership on every success and failure path, including proof that
  caller-owned descriptors are not accidentally consumed;
- attachment-slot order, zero-capacity replies, oversized kernel results,
  interruption, and concurrent calls on shared and separate handles;
- leak checks under deterministic allocation and syscall failures.

### `libchannel`

- asynchronous request, reply, and event dispatch using the kernel channel
  token as the sole correlation identifier;
- ordered attachment ownership, take/borrow semantics, automatic cleanup of
  unclaimed descriptors, and duplicate-response rejection;
- queue and byte/fd limits, backpressure, flush readiness, cancellation, late
  replies, unknown tokens, and peer death;
- concurrent outstanding requests, intentionally reordered replies, fork, and
  channel destruction with queued attachments; and
- proof that the library uses only `SENDMSG`/`RECVMSG` and contains no service
  discovery, blocking adapter, internal thread, or `MAC_CAPABILITY_CALL` path.

### `libcapbundle`

- one table-driven case for every manifest field and allowed type;
- defaults, normalization, duplicate keys, unknown keys, limits, and conflicting
  declarations;
- path traversal, symlink, ownership, permissions, replacement races, and file
  mutation between validation and use;
- dependency/provides consistency and every capability-family schema;
- argument and environment preservation, rejection, and size accounting;
- parse/serialize/parse stability where serialization is supported;
- corpus fuzzing plus differential checks between parse and verify entry points;
- fixtures for every shipped example bundle and package manifest.

### `libservice`

- every public call before initialization, after initialization, after channel
  loss, and after relevant one-shot operations;
- ready, expose, withdraw, lookup, accept, protection, capability activation,
  component bootstrap, managed call/event, and descriptor access
  success/denial paths;
- declared-name authorization, duplicate registration, self-lookup, provider
  exit, waiter cancellation, and reconnect policy;
- payload boundary values, null/zero combinations, descriptor passing, reply
  reordering, cancellation, peer closure, interruption, and protocol mismatch;
- descriptor type and confinement verified by an independent observer;
- fork and exec behavior and an explicitly documented thread-safety contract;
- static and shared linking against both object-tree and installed libraries.

### `libshmring` and typed service libraries

- `libshmring` independently covers wraparound, full/empty transitions,
  malformed sealed metadata, exact endpoint rights, object aliasing, position
  corruption and overflow, producer/consumer ordering, ownership, and cleanup;
  availability queries must distinguish corruption from empty/full state, and
  the library must not depend on `libservice`;
- each typed library covers its exact magic/version/opcode/status schema,
  attachment-slot meanings, malformed replies, descriptor cleanup, and its
  statically selected local or global discovery path;
- `libfilesystemcmp` covers namespaces and cwd contexts;
  `libnetworkcmp` covers socket, DNS, deadline, and cancellation calls;
  `liblogcmp` covers shared process lifecycle, lazy ring activation and
  promotion, coalesced wakeups, bounded drain-before-detach, ambiguous RPC
  failure, descriptor baselines, corrupt-ring recovery, flush, and fork;
  `libnotify` covers independent sessions, events, default denial, and
  saturating timeout boundaries;
  `libtracecmp` covers raw ownership and tuned libdtrace construction;
  `libauditcmp`, `libkldmgr`, and `librebootctl` cover typed global requests;
  and
- no application-facing typed API exposes environment-variable names,
  service-discovery strategy, channel tokens, or serviced control messages.

### Common library quality gates

- Public headers compile alone as C and C++ where supported.
- Symbol lists and ABI versions are checked against reviewed baselines.
- Static and shared variants pass the same contract suite.
- Sanitizer builds cover all unprivileged tests and fixture parsers.
- Each library has deterministic allocation/syscall failure injection.
- Examples from manual pages and shipped manifests are compiled or validated in
  CI rather than treated as untested documentation.
- Installed-package tests prove that headers, libraries, runtime linker names,
  and package dependencies are sufficient without a source or object tree.

## Program contract suites

Each program has a component matrix independent of the ten cross-stack cases.

| Program | Required component contracts |
| --- | --- |
| `authorityd` | CLI/config, startup phases, claims, reload transactions, control authorization/framing, bootstrap supervision, watchdog, status, shutdown |
| `serviced` | registry, graph, startup/on-demand, naming, token delivery, descriptor layout, reload, restart/backoff, coalition cleanup, audit |
| `authorityctl` | CLI grammar, exact request encoding, all reply statuses, incompatible version, partial/closed socket, exit-status contract |
| `servicectl` | CLI grammar, status/list/reload/start/stop, malformed-wire rejection, verification and installation safety, authorization, exact exit-status contract |
| `localfilesystem` | scratch/persistent/bundle namespaces, durable byte/object quotas, reconstruction, rollback, cwd/path contexts, malformed frames, worker confinement |
| `localnetwork` | TCP/UDP, IPv4/IPv6, DNS, nonblocking deadlines/cancellation, socket limits, malformed frames, worker confinement |
| `logd` | independent sessions, shared-ring lifecycle, batching/coalescing, loss accounting, flush and sink failures, close/reopen/fork |
| `bsdnotify` | independent sessions, default-deny policy, subscriptions/timers, queue pressure, event ordering, close/reopen/fork |
| `traced` | explicit-label policy, DTrace descriptor rights/propagation, tuned buffer defaults, unavailable device, worker confinement |
| `auditbrokerd` | identity/rate policy, typed validation, injected audit backend, response mapping, no backend call on denial, worker confinement |
| `kldmgrd` | label policy, request validation, injected kld backend, response mapping, no backend call on denial |
| `rebootd` | label policy, request validation, injected reboot backend, response mapping, no backend call on denial |
| `blued` | config/persistence/control protocols, virtual-HCI behavior, serviced activation, Bluetooth claim confinement and revocation |

For every daemon state machine, the suite must cover every state and transition,
including invalid events in each state.  A generated transition-coverage report
is preferable to inferring coverage from shell case names.

For every CLI, stdout, stderr, and exit status are public contracts.  Tests use
symbolic expected statuses from a shared test header rather than accepting any
nonzero result.

### L3: full-stack security contract tests

These run the real kernel services, Authorityd, Serviced, libraries, and
managed fixture processes.  They are root-only, exclusive, deliberately few,
and each proves a cross-boundary invariant that cannot be established below.

Required full-stack cases:

1. Authorityd boots serviced with a confined channel and sole procdesc supervision
   authority, reaches ready, and performs a clean authenticated shutdown.
2. A managed service receives exactly its declared tokens and capability
   service descriptors, with correct type and transfer/fork/exec restrictions.
3. A provider registers a declared name; an authorized client performs a
   bidirectional descriptor-confined exchange; an undeclared name and an
   unauthorized client are denied.
4. On-demand activation has one launch under concurrent lookup, propagates
   success to all waiters, and cancels all waiters on timeout/crash.
5. Reload is transactional across manifests and Authorityd claims: success changes
   the effective set, and every injected failure leaves the old set intact.
6. Service exit and bundle removal release dynamic claims exactly once while
   policy claims remain intact.
7. Direct ambient signal, trace, visibility, descriptor transfer, and `/dev`
   access attacks fail; the retained procdesc and authenticated control paths
   still work.
8. Serviced crash closes or revokes subordinate authority and follows the
   declared Authorityd restart policy without preserving stale registrations or
   claims.
9. A real privileged broker (`kldmgrd` or a non-destructive `rebootd` status
   path) authenticates its client label end to end.  Dangerous operations stay
   in L2 with injected backends.
10. A virtual-HCI `blued` instance activates through serviced, receives only
    its Bluetooth claims, reaches ready, and loses controller authority after
    termination.

The full-stack suite must not repeat every parser or restart-policy permutation.
Those belong in L0-L2, where failures are faster and easier to diagnose.

### L4: stress, fault injection, and hardware qualification

This lane is not part of every commit run.

- repeated concurrent mint/register/lookup/reload/exit loops;
- deterministic allocation, ioctl, send, receive, fork, exec, and audit failure
  injection at each transaction boundary;
- daemon crash at each persisted or externally visible state transition;
- resource-exhaustion runs for descriptors, processes, connections, claims,
  and message queues;
- sanitizer and coverage builds for userland parsers and protocol handlers;
- protocol fuzz targets seeded from the L0 wire corpus;
- physical Bluetooth controller qualification in addition to virtual HCI.

Every discovered regression receives a deterministic lower-layer case before
the stress reproducer is considered fixed.

## Process-safe test harness

### `capd_test_guardian`

A compiled guardian is the only supported way for shell tests to launch a
protected Authorityd.

The guardian:

1. creates a lease socketpair with the test;
2. starts Authorityd with `pdfork(2)` and retains the process descriptor;
3. records the exact Authorityd PID only for diagnostics;
4. reports startup and exit events over a small versioned protocol;
5. accepts `shutdown`, `kill`, `status`, and `wait` commands;
6. attempts authenticated control-socket shutdown first;
7. uses `pdkill(2)` as the bounded recovery authority;
8. kills and reaps Authorityd if the test's lease closes unexpectedly;
9. does not exit until Authorityd and its supervised subtree are gone.

The guardian must be outside the protected subtree it supervises.  Its own
unexpected death is covered by a runner-level guardian census and is treated
as infrastructure failure.  The protocol and failure behavior receive normal
ATF-C tests.

This design matches the production security model: termination uses retained
authority rather than an ambient PID signal.  `kill -0` is never a liveness
probe for shielded processes.

### Shell harness

One canonical `capd_test_harness.sh` supplies:

- guarded stack start, status, reload, stop, and bounded wait;
- unique work, bundle, socket, PID, log, and result paths;
- bundle construction from explicit fields;
- event waits with a monotonic deadline;
- exact process and descriptor diagnostics on timeout;
- preflight and postflight daemon census;
- idempotent cleanup that preserves diagnostics on failure;
- coherent object-tree and installed-test binary discovery.

Component-specific shell helpers may build on it, but cannot redefine process
ownership or stack lifecycle.  The same source is installed beside every test
program that imports it and is staged unchanged by focused runners.

## Compiled fixtures

Runtime C compilation is replaced by three reviewed programs installed in the
relevant test directory.

### `capd_service_fixture`

A libservice client selected by command-line scenario.  Scenarios include:

- ready and hold;
- register/provider exchange;
- lookup/client exchange and expected lookup denial;
- descriptor and environment inventory;
- token activation and capability-service activation;
- protection and identity report;
- controlled clean exit, error exit, crash, signal ignore, and child tree;
- explicit unregister and channel-close behavior.

The fixture emits versioned key/value records to a supplied result descriptor
or FIFO.  It sends a ready record only after the operation being observed has
completed.  It never uses a sleep to establish ordering.

### `capd_wire_fixture`

A raw client for Authorityd, serviced, service, kld, and reboot protocols. It can
send exact byte sequences and descriptor sets, fragment writes, close early,
delay a protocol phase under harness control, and report exact replies.  This
replaces one-off raw clients embedded in shell tests.

### `capd_lifecycle_fixture`

A process-behavior fixture for supervisor tests: clean/error exit, crash,
ignore selected signals, fork a reported tree, wait on a control descriptor,
and record received environment/credentials/descriptors.  It contains no
libservice dependency when the test is specifically about pre-activation
behavior.

Fixtures must have unit tests for argument parsing and record format.  Scenario
names are stable test interfaces; adding a scenario requires documentation.

## Synchronization and diagnostics

All fixture and harness events use a versioned record such as:

```text
CAPD-TEST/1 event=registered label=org.test.provider pid=1234
```

Records use escaped values or a length-delimited binary form when arbitrary
data is required.  A test waits for a named event, not for a guessed duration.

Every deadline failure prints:

- the expected event and elapsed deadline;
- guardian status and exact owned process tree;
- Authorityd and serviced status replies when available;
- the tail of each relevant log;
- fixture records received so far;
- open control/result endpoints and retained process descriptors.

Successful tests may discard routine artifacts.  Failed tests preserve the
complete work directory and print its location.

## Test naming and traceability

Case names describe the invariant and expected outcome, for example:

- `lookup_undeclared_provider_returns_enoent`
- `reload_claim_failure_preserves_previous_generation`
- `test_lease_loss_procdesc_kills_protected_stack`

Each public protocol operation, manifest field, capability family, and daemon
state transition has a row in a machine-readable coverage manifest.  Rows name
their L0-L4 cases.  CI rejects a new enum value, operation, or manifest field
without a coverage-manifest disposition.

## CI lanes

| Lane | Contents | Target |
| --- | --- | --- |
| `quick` | L0 and non-global L2 | every change, unprivileged where possible |
| `kernel` | L1 by capability service | every kernel/capability change |
| `stack` | the ten L3 contracts | every capability-stack change |
| `installed` | quick plus stack from installed packages | package/release CI |
| `stress` | L4 concurrency and fault injection | nightly |
| `hardware` | physical controller/device qualification | scheduled/release |

The focused capability runner selects cases by lane metadata instead of a
hand-maintained shell list.  It still stops after contamination, but guardian
recovery should make contamination an infrastructure defect rather than a
normal test outcome.

## Migration plan

### Phase 0: freeze lifecycle duplication

- Do not add another private `start_stack` or `stop_stack` implementation.
- Make existing full-stack bodies stop their stack before returning success.
- Replace shield-incompatible `kill -0` checks with exact observation until the
  guardian is available.

Exit gate: no newly modified test can report pass while its stack is alive.

### Phase 1: guardian and canonical harness

- Implement and unit-test `capd_test_guardian`.
- Implement `capd_test_harness.sh` and its self-tests.
- Migrate `libservice_test:libservice_naming` first because it exercises the
  leaked-daemon failure mode.
- Migrate Authorityd bootstrap, serviced integration, servicectl, authorityctl,
  kldmgrd, and rebootd suites.
- Delete superseded lifecycle functions after the final caller migrates.

Exit gate: killing or timing out a test body leaves no Authorityd, serviced, or
managed fixture process in 100 consecutive fault-injected runs.

### Phase 2: compiled fixtures

- Add the three fixtures to normal test builds and packages.
- Migrate libservice cases, then serviced naming/lifecycle/capability cases,
  then privileged brokers.
- Remove `cc_with_libservice`, generated `.c` cleanup, and fixed readiness
  sleeps.

Exit gate: capability daemon tests perform no runtime C compilation and use no
fixed sleep for correctness.

### Phase 3: restore the pyramid

- Move pure config/protocol/graph/reload cases from shell integration tests to
  table-driven L0/L2 C tests.
- Keep only the cross-boundary L3 contracts listed above.
- Add backend injection to privileged brokers before expanding mutating tests.

Exit gate: each L3 case documents why a lower layer cannot prove its invariant.

### Phase 4: coverage and fault injection

- Add the coverage manifest and CI validation.
- Add deterministic failure points and transaction-boundary crash tests.
- Establish nightly repetition, sanitizer, fuzz, and resource-exhaustion lanes.

Exit gate: every security-relevant state transition has success, denial, and
rollback/recovery coverage.

## Definition of done

The redesign is complete when:

- an interrupted test cannot strand a protected process;
- no daemon test compiles source at runtime;
- no test uses a fixed sleep as evidence of state;
- all process cleanup uses exact retained authority;
- installed and object-tree suites run identical cases and fixtures;
- full-stack cases are few, explicit, and independently diagnosable;
- denial tests verify both error identity and absence of side effects;
- protocol/schema additions cannot land without a coverage disposition;
- 100 repeated stack runs and forced test-body deaths produce zero leaks;
- failures retain enough structured evidence to diagnose without rerunning.
- every exported library symbol and daemon/CLI protocol operation is mapped to
  success, denial, boundary, and failure-injection coverage;
- public ABI, standalone headers, static/shared linking, examples, and installed
  package operation are continuously verified;
- every daemon state and transition appears in a reviewed transition-coverage
  report.

## Current validation status

The latest July 31, 2026 object-tree results cover 34 suites and report 472
passed, zero failed, zero broken, and 178 root-only cases skipped. The eight
typed component/service client libraries account for 120 passes. Nine
configuration and diagnostic tool suites, including `filesystemcmpctl` and
`networkcmpctl`, passed 59 unprivileged tests and skipped ten root-only cases.
The direct `libauthorityctl` suite adds six transport and framing passes. Clean
`MK_DTRACE=yes` and `MK_DTRACE=no` builds passed for the affected libraries
and providers; the non-DTrace matrix ran 255 passing unprivileged tests with
30 privileged skips. AuditCmp, kldmgrd, and rebootd use injected production
backend interfaces to
prove denial-without-side-effect, success, error mapping, and rollback without
performing a privileged audit, module, reboot, or shutdown operation.
The module backend now covers enumeration failure and bounded ordering as well
as mutation. Reboot tests cover atomic pending-state serialization and
visibility across forked workers.

`libshmring` additionally proves that opened mappings are `INHERIT_NONE`, an
inherited object returns `ECHILD`, and the parent endpoint remains usable.
The clean-build gate links every PIE provider against freshly built
position-independent typed static archives in both DTrace configurations,
eliminating reliance on stale installed libraries.

Beacon tests require a pending event wait to remain asynchronous with respect
to client dispatch and peer death. The event-driven router retains the exact
channel request for the response, bounds each session to one pending `NEXT`,
and rejects overlap with `EBUSY`; client timeout tests cover saturation
immediately below the reserved infinite value.

FileSystemCmp persistent-store tests also reject hard-linked files during
restart reconstruction and after live link injection. The latter exercises
write, truncate, existing-file create, rename, and unlink through an already
open handle. Restart reconstruction independently enforces the per-file size
ceiling as well as aggregate byte and object limits.

The skipped cases are not passes. They require a disposable root test host for
the real Capsicum, mac_capability, coalition, jail, network, auditd, DTrace,
kernel-module, and non-destructive reboot-status boundaries. This host has no
`doas` executable, so that live gate was not run. Focused pkgbase DESTDIR and
METALOG staging has verified suffixes, ownership, configuration, dependency,
and provider/tool grouping. A full package archive install/upgrade/removal run
remains pending because unrelated base-tree buildworld failures prevent
producing the complete package set.

Notify is default-deny for publish, subscribe, state, and timers. Beacon's
runtime policy is loaded before sandbox entry from `/etc/bsdnotify.conf`,
keyed by the immutable serviced client label, and enforced in each relay
before forwarding to the shared router. Unit and dispatcher tests cover
policy parsing, unknown-label denial, identity-specific grants, exact bounded
binary payloads, publisher identity, queue isolation, loss reporting, and a
publish-to-next wire round trip. Successful live ACL paths and label
authentication remain part of the root release gate. Exact commands,
per-suite counts, pkgbase staging evidence, and the live release checklist are
maintained in `docs/capability-components-validation.md`.

The July 31 production-readiness follow-up added deterministic NetworkCmp
resolver isolation, LogCmp interrupted-rotation reconstruction and strict
configuration loading, normal build-time `libcapability` ATF cases, and direct
Authorityd-control-library failure tests. It also added an operational-name
contract covering every daemon `PROG`/`PACKAGE`, rc.d hook and variable,
pkgbase definition, and `.cap` bundle path. The `libcapability` suite no longer
compiles a C heredoc at runtime. Privileged resolver, kernel metadata, and live
capability cases remain release gates because this host has no privilege
wrapper.

The public operational names are `authorityd`, `serviced`, `localfilesystem`,
`localnetwork`, `logd`, `bsdnotify`, `traced`, `auditbrokerd`, `rebootd`,
and `kldmgrd`. Component and typed-library names remain descriptive API names.
The final source contract specifically prevents the rc-variable/hook mismatch
found during the rename from recurring.

The library-boundary review removed raw socket-loop symbols from the public
Authorityd control library and removed `servicectl`'s accidental link to that
protocol-specific library. Six `libauthorityctl` tests and three isolated
`servicectl` transport tests cover dead peers, valid replies, truncation,
oversized lengths, bounded buffers, and error propagation. Root-only Armory,
Sundown, and servicectl fixtures now generate the current
`serviced_control_socket` key and current `.cap`/program names. The unused
`liblwipcmp` scaffold was deleted so only Roadrunner's reviewed kernel-socket
architecture ships; userspace packet networking remains future work.

These results do not yet constitute a release sign-off. The Beacon descriptor
admission conflict is resolved without weakening `SERVICE_PROTECT_NOFDRECV`:
the provider and fixed router now use an unnamed mac_capability channel created
through `service_provider_worker_channel()`. Provider session endpoints start
with `CAP_XFER_ONCE` (a single hop); the router handoff consumes that hop and
installs `CAP_XFER_NONE`. The private pair is itself
non-transferable and has one-fork propagation bounds. The obsolete UNIX-domain
`SCM_RIGHTS` helpers and tests were removed, while malformed attachment counts,
bounded replies, peer death, and descriptor-bearing client requests continue
to fail closed. A root-only end-to-end worker-channel test verifies fork
propagation, non-transferability, payload exchange, and supervisor creation.
The kernel suite also verifies that `NOFDRECV` rejects `SCM_RIGHTS` while an
attachment on an already-held capability channel remains usable and arrives
non-transferable.
Production sign-off still requires that live test, the other root-only cases,
and the full build/pkgbase artifact gates on a clean tree.

## Final naming and production-readiness review

The operational names deliberately describe roles without exposing protocol
or implementation names. The Texas/animal vocabulary is confined to program,
package, bundle, and manual-page identity; stable typed C libraries retain
descriptive names so application code remains obvious.

| Program | Role | Readiness disposition |
| --- | --- | --- |
| `authorityd` | capability authority and root bootstrap | Code-complete; live kernel, audit, and DTrace gates remain. |
| `serviced` | service activation, naming, coalitions, and lifecycle | Code-complete; root crash/restart, descriptor-pressure, and private-worker-channel gates remain. |
| `localfilesystem` | coalition-local filesystem authority | Code-complete; live jail, mount, persistence, and hard-link defenses remain to be qualified. |
| `localnetwork` | coalition-local socket and resolver authority | Code-complete; live network-policy, resolver-stall, and cancellation gates remain. |
| `logd` | bounded, persistent structured log service | Code-complete; crash/power-loss, sustained-load, retention, and package-upgrade qualification remain. |
| `bsdnotify` | bounded publish/subscribe, state, and timer service | Code-complete; live identity-policy and capability-channel attachment qualification remain. |
| `traced` | administrator-only DTrace capability broker | Restricted-production only; raw DTrace delegation must remain explicitly privileged until a provider-owned query API replaces it. |
| `auditbrokerd` | rate-limited OpenBSM submission service | Code-complete; live auditd backpressure, rotation, and failure qualification remain. |
| `rebootd` | durable reboot scheduling and Beacon publication | Code-complete; only non-destructive status paths are eligible for routine CI; real reboot recovery requires a disposable host. |
| `kldmgrd` | policy-controlled kernel-module management | Code-complete; live load/unload rollback requires a disposable host and dedicated test module. |

“Code-complete” is not a release sign-off. It means the reviewed architecture,
bounded resource model, typed API, sandbox transition, managed quiesce path,
audit/DTrace surface, pkgbase metadata, configuration or diagnostic surface
where applicable, and deterministic
unprivileged tests are present. None of these programs should be called
production-ready until the skipped root/live matrix, repeated stress and
forced-crash lanes, clean full-world build, and package archive
install/upgrade/removal gates pass on release-equivalent systems.

The naming contract rejects stale daemon manual-page references and ties every
public name to its `PROG`, package, bundle path, and rc boundary. Internal wire
identifiers and typed library names such as `notify` and `logcmp` are not
daemon aliases and remain intentionally descriptive.
The final audit also corrected Rebootd's authenticated Beacon policy identity,
Ledger's syslog tag, and every root-only provider object path; those are now
covered by the same operational-name contract.

The authoritative outstanding qualification backlog is the
“Outstanding production qualification plan” in
`docs/capability-components-validation.md`. It assigns stable test IDs and
pass criteria to private worker channels, Beacon admission ambiguity,
Sundown-to-Beacon delivery, Ledger crash/privacy/loss behavior, filesystem and
network scale, the remaining privileged global services, pkgbase lifecycle,
sanitizers, fuzzing, repetition, and retained release evidence. Those cases
are requirements, not claims of completed coverage.
