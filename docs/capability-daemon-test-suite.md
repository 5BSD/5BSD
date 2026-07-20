# Capability Daemon Test Suite Architecture

## Status

This document defines the target test architecture for the capability stack.
It supersedes the current practice of growing independent ATF shell programs
with private daemon lifecycle code and C programs compiled from heredocs.

The scope is:

- the `mac_capability` kernel framework and its capability services;
- `liboraclert`, `libcapability`, `libcapbundle`, and `libservice`;
- `oracled`, `serviced`, `oraclectl`, and `servicectl`;
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
live protected Oracle stack.  Production logic must expose narrow interfaces;
tests must not copy implementations.

`oracled` component coverage:

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

### `liboraclert`

- encode/decode round trips for every Oracle request and reply;
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

- connect, call, mint, authorize, release, and descriptor-access APIs across
  their complete state machines;
- exact behavior for missing, malformed, duplicate, stale, closed, and wrong-
  type descriptors;
- descriptor ownership on every success and failure path, including proof that
  caller-owned descriptors are not accidentally consumed;
- transfer, fork, exec, close-on-exec, close-on-fork, and multithreaded use;
- environment parsing without mutation on failure and idempotent activation;
- cancellation/interruption and concurrent calls on shared and separate
  handles;
- leak checks under deterministic allocation and syscall failures.

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
- ready, register, unregister, lookup, accept, send, receive, protection,
  capability activation, and descriptor access success/denial paths;
- declared-name authorization, duplicate registration, self-lookup, provider
  exit, waiter cancellation, and reconnect policy;
- payload boundary values, null/zero combinations, descriptor passing, peer
  closure, interruption, and protocol mismatch;
- descriptor type and confinement verified by an independent observer;
- fork and exec behavior and an explicitly documented thread-safety contract;
- static and shared linking against both object-tree and installed libraries.

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
| `oracled` | CLI/config, startup phases, claims, reload transactions, control authorization/framing, bootstrap supervision, watchdog, status, shutdown |
| `serviced` | registry, graph, startup/on-demand, naming, token delivery, descriptor layout, reload, restart/backoff, coalition cleanup, audit |
| `oraclectl` | CLI grammar, exact request encoding, all reply statuses, incompatible version, partial/closed socket, exit-status contract |
| `servicectl` | CLI grammar, status/list/reload/stop, verification and installation safety, authorization, exact exit-status contract |
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

These run the real kernel services, Oracle, service manager, libraries, and
managed fixture processes.  They are root-only, exclusive, deliberately few,
and each proves a cross-boundary invariant that cannot be established below.

Required full-stack cases:

1. Oracle boots serviced with a confined channel and sole procdesc supervision
   authority, reaches ready, and performs a clean authenticated shutdown.
2. A managed service receives exactly its declared tokens and capability
   service descriptors, with correct type and transfer/fork/exec restrictions.
3. A provider registers a declared name; an authorized client performs a
   bidirectional descriptor-confined exchange; an undeclared name and an
   unauthorized client are denied.
4. On-demand activation has one launch under concurrent lookup, propagates
   success to all waiters, and cancels all waiters on timeout/crash.
5. Reload is transactional across manifests and Oracle claims: success changes
   the effective set, and every injected failure leaves the old set intact.
6. Service exit and bundle removal release dynamic claims exactly once while
   policy claims remain intact.
7. Direct ambient signal, trace, visibility, descriptor transfer, and `/dev`
   access attacks fail; the retained procdesc and authenticated control paths
   still work.
8. Serviced crash closes/revokes subordinate authority and follows the declared
   Oracle restart policy without preserving stale registrations or claims.
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
protected Oracle.

The guardian:

1. creates a lease socketpair with the test;
2. starts Oracle with `pdfork(2)` and retains the process descriptor;
3. records the exact Oracle PID only for diagnostics;
4. reports startup and exit events over a small versioned protocol;
5. accepts `shutdown`, `kill`, `status`, and `wait` commands;
6. attempts authenticated control-socket shutdown first;
7. uses `pdkill(2)` as the bounded recovery authority;
8. kills and reaps Oracle if the test's lease closes unexpectedly;
9. does not exit until Oracle and its supervised subtree are gone.

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

A raw client for Oracle, serviced, service, kld, and reboot protocols.  It can
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
- Oracle and serviced status replies when available;
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
- Migrate Oracle bootstrap, serviced integration, servicectl, oraclectl,
  kldmgrd, and rebootd suites.
- Delete superseded lifecycle functions after the final caller migrates.

Exit gate: killing or timing out a test body leaves no Oracle, serviced, or
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
