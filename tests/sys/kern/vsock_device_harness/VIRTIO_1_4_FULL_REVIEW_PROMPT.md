# bhyve VirtIO 1.4 and AF_VSOCK correctness review

Review the complete implementation range
`362c33ab220^..HEAD` plus the current worktree.  Do not assume that a commit,
an earlier review, a successful build, or a happy-path guest run establishes
correctness.  Review the final composed source and use individual commits only
to understand intent and regression risk.

The local VirtIO 1.4 specification is `/tmp/virtio-v1.4.html`.  The local Linux
reference tree is `/tmp/linux-virtio-reference`.  The specification is normative.
Linux is an interoperability and mature-lifecycle reference, not a replacement
for the specification.  When Linux differs from the specification, identify
the difference and decide explicitly whether bhyve should implement the
normative rule, a safe compatible superset, or a documented Linux-compatible
restriction.

## Scope

Review the implementation and all directly affected callers, not just changed
lines:

* `usr.sbin/bhyve/virtio.[ch]`
* `usr.sbin/bhyve/virtio_pci_modern.c`
* all changed `usr.sbin/bhyve/pci_virtio_*.c` device models
* `usr.sbin/bhyve/block_if.c`
* `sys/dev/virtio/pci/virtio_pci_modern*`
* `sys/dev/virtio/mmio/virtio_mmio.c`
* all of `sys/dev/virtio/vsock/virtio_vsock.c`, including unchanged attach,
  RX/TX, reset, detach, and failure paths
* all of `sys/kern/uipc_vsock.c`, `sys/kern/uipc_vsock_user.c`, and
  `sys/kern/uipc_vsock.h`, including unchanged functions and not merely the
  current diff
* `sys/sys/vsock.h`, the AF_VSOCK protocol-switch/domain declarations, and
  every caller of `vsock_transport_*()` and `vsock_rx_packet()`
* the complete `/dev/vsock` provider ABI and implementation: provider
  registration, CID indexing, feature epochs, read/write, poll/kqueue,
  cdevpriv destruction, stable transport callbacks, sysctls, DTrace probes,
  and every unchanged error and teardown path in the files above
* all of `usr.sbin/bhyve/pci_virtio_vsock.c`, including both the userspace
  relay backend and kernel `/dev/vsock` backend, plus
  `usr.sbin/bhyve/vsock_provider.d` and
  `usr.sbin/bhyve/vsock_virtio_transport_notes.md`
* the requirement catalog, direct harnesses, RX harness, kernel tests, Alpine
  matrix, multi-VM tests, soak scripts, manuals, DTrace metadata, and roadmap
* the common bhyve save-state lifecycle, portable wire encodings, atomic
  checkpoint publication, backend reconstruction contracts, feature and
  destination compatibility manifests, and every VirtIO device snapshot,
  pause, resume, rollback, and repeated-restore callback
* the complete Intel nested-VMX implementation under `sys/amd64/vmm/intel/`,
  its public VMM and libvmmapi boundaries, bhyve guest-exposure policy,
  versioned architectural checkpoint state, requirements ledger, independent
  model tests, Linux/KVM-L1 live harness, and retained hardware evidence
* `sys/dev/mac_capability/mac_capability_isolation.c`,
  `sys/dev/mac_capability/mac_capability_isolation_proto.h`,
  `sys/dev/mac_capability/mac_capability_internal.h`, the claim/token lifetime
  code they call, `sys/security/mac/mac_framework.h`,
  `sys/security/mac/mac_policy.h`, `sys/security/mac/mac_socket.c`, and every
  MAC Framework hook or provider-ownership test used by vsock

This vsock list is a closed review requirement, not an example list.  Every
review cycle must inspect the final composed source of every listed layer,
including unchanged code, and must include existing behavior predating the
VirtIO 1.4 work.  A pass over only `git diff`, only bhyve, only the kernel
transport, or only newly added multi-provider code is incomplete.

Pay particular attention to the composed interactions among:

* modern status and feature negotiation;
* split-ring descriptor ownership and publication ordering;
* EVENT_IDX notification suppression and re-enabling;
* queue enable, queue reset, full reset, detach, rebind, and snapshot;
* virtio-net multiqueue, RSS, HASH_REPORT, Linux control commands, and TX/RX
  scheduling;
* virtio-blk and virtio-scsi multiqueue worker lifecycle;
* virtio-9p asynchronous requests and generation fencing;
* userspace and kernel-backed bhyve vsock;
* multiple simultaneous `/dev/vsock` providers keyed by guest CID;
* STREAM credit accounting and SEQPACKET record guarantees.
* capability claims and delegated tokens governing AF_VSOCK bind/connect and
  whole-CID `/dev/vsock` provider ownership.

Unrelated dirty-tree changes must not be modified or included in a proposed
patch.

## Required method

Start by listing the invariants for each subsystem.  At minimum include:

* which lock or atomic operation owns every mutable field;
* descriptor and guest-memory ownership before, during, and after callbacks;
* when a driver may reclaim a queue or its buffers;
* what status is visible while a backend reset drains work;
* feature staging versus feature application;
* queue notification enable/disable transitions;
* worker selection, pause, wakeup, and shutdown conditions;
* packet, byte-credit, record, and provider ownership;
* provider lifetime across lock-dropping copy operations and sleeps;
* snapshot state that must agree with negotiated transport state.

For every advertised optional feature, audit
`virtio-feature-activation.tsv` as a separate live-proof obligation.  Do not
accept feature-bit negotiation, a configured queue count, driver attachment,
or unrelated device I/O as activation.  Require an unmodified guest to select
the feature, a workload that can reach its distinct data/control path, and
host evidence that the path ran.  Review Linux and 5BSD independently:
`driver-gap` is an honest unsupported test environment, while `pending` is an
unfinished gate; neither status counts as coverage or release qualification.
Where both stock guest drivers implement a feature, both operating systems
must reach `exercised`.  Where a stock guest driver lacks the feature, record
the driver gap and add guest-driver implementation and activation testing to
the roadmap rather than weakening the device test.  In particular,
multiqueue must show the guest's active queue count and traffic on every
active queue, with host notifications/completions on those same queues.
Packed cases must show an enabled packed queue plus device data,
NOTIFICATION_DATA must show the feature-selected doorbell width and payload,
and RING_RESET must show a selective queue reset rather than a full
detach/rebind reset.

The proof must be a first-class case in the qualification profile, not an
ad-hoc command that happens to have passed once.  Each exercised ledger entry
must identify its exact `linux_case` and/or `fivebsd_case` from
`virtio-lab.yaml`, the assertion made inside the unmodified guest, and the
host-side probe or bounded trace assertion.  A cross-device claim must list
every applicable device case; one representative packed or translated-DMA
case is not evidence for the other devices.  A
source evidence label must resolve to an explicit
`VIRTIO_ACTIVATION_ASSERTION` marker beside the executable check it describes;
report stale, fabricated, or remotely placed markers.  A
case must fail when the feature is declined, when fewer queues become active
than requested, when the distinguishing operation is routed through the
fallback path, or when the expected host event is absent.  Review the
orchestrator manifest as part of every feature review and reject orphaned
helpers, unscheduled live tests, and release cases that only inspect
negotiated feature bits.

Apply that proof shape to every feature, not only ring features.  For example,
block discard/write-zeroes must verify changed backing-store semantics,
read-only must prove rejected writes and successful reads, RSS/HASH_REPORT
must prove the selected control and packet paths, ACCESS_PLATFORM must prove
translated DMA for the tested endpoint, suspend/save-state must retain active
work and device state across restore, and device-specific protocols must
produce an observable guest result correlated with the exact host command.
Reject tests that can pass when the feature is disabled, negotiated but
unused, serviced by a different queue, or emulated entirely by the test
helper.

For multiqueue specifically, run concurrent work that can remain outstanding
on every active queue, report the guest driver's actual active queue count,
and correlate a nonzero notification and completion count for every queue on
the host.  Run that proof independently in Linux and 5BSD.  CPU affinity or
flow steering may be used to make queue selection deterministic, but merely
creating multiple vCPUs, advertising a maximum queue count, or observing one
busy queue is not multiqueue activation evidence.

For every potential issue, construct a concrete operation sequence or
concurrency schedule.  Do not report a race without naming both operations,
the shared state, and the missing or incorrect ordering.  Do not dismiss an
issue merely because the guest is expected to be well behaved when the
specification requires the device to validate or safely reject the input.

Trace every error from origin to final recovery.  Include allocation failure,
short I/O, zero progress, `EAGAIN`, `EINTR`, hard errors, malformed descriptor
chains, unavailable backend, failed feature application, queue saturation,
reset timeout, callback cancellation, and snapshot validation failure.
Determine whether each error:

1. consumes guest input or descriptors;
2. preserves byte and record order;
3. wakes every blocked participant;
4. leaves bounded and internally consistent resource state;
5. sets or clears `FEATURES_OK`, `DRIVER_OK`, `NEEDS_RESET`, and interrupts
   correctly;
6. permits a documented recovery path.

## Review passes

Complete every pass.  If a pass produces fixes, apply narrowly scoped fixes
and deterministic regression tests, then restart with a different pass order.

Do not repeat the same reading order and call it an independent review.
Rotate the emphasis on successive cycles:

1. **Document-first:** derive obligations and boundary values from VirtIO 1.4,
   then locate the code and tests that satisfy them.
2. **Code-first:** start at each guest-controlled entry point and follow
   ownership, waits, errors, and cleanup outward without consulting the
   catalog until the trace is complete.
3. **Test-first:** assume each claimed test could pass a broken implementation;
   inspect its oracle and assertions, perform a temporary mutation, and then
   map the demonstrated behavior back to the document.
4. **Lifecycle-first:** begin with reset, detach, failed initialization,
   backend loss, and snapshot restore, then work backward to steady-state
   setup and feature negotiation.
5. **Progress-first:** begin with every blocking point and guest-controlled
   loop, prove its wakeup or continuation, and only then inspect data-path
   correctness.

After a fix, choose a different starting emphasis and reverse the subsystem
order.  Record which emphasis found each issue so repeated cycles provide
different evidence instead of repeatedly confirming the same happy paths.

### Pass 0: constants, generated values, and hardcoding

Inventory every numeric literal, size, offset, mask, queue number, timeout,
limit, feature bit, PCI identity, operation code, status value, and endian
conversion added or used by the reviewed implementation and tests.  Classify
each as:

* directly normative and traced to a VirtIO 1.4 clause;
* ABI/API-defined by FreeBSD, PCI, socket, CTL, lib9p, or another named source;
* an implementation policy limit with a named rationale and boundary tests;
* derived safely from a type or runtime capability; or
* unexplained hardcoding requiring removal, a named constant, documentation,
  or a test.

Search decimal as well as hexadecimal literals.  Do not accept a comment that
merely repeats the number.  Verify normative numbers against the local
standard and interoperability numbers against Linux.  Tests must use the
independent document oracle rather than copying the production constant.

### Pass 1: normative VirtIO 1.4 conformance

Build a clause-to-code map for every mandatory rule and every advertised
optional feature.  Check field sizes, offsets, endian conversion, reserved
bits, feature dependencies, status transitions, configuration generation,
capability ranges, queue topology, reset completion, used lengths, interrupt
rules, and device-specific configuration.

Flag any advertised feature whose full operational and error semantics are not
implemented.  Distinguish unsupported optional features from violations of
advertised behavior.

Reconcile the complete release-closure inventory in
`usr.sbin/bhyve/VIRTIO_1_4_ROADMAP.md`.  For every common-infrastructure,
existing-device, provisional-device, and conditional-device bullet, locate a
normative requirement row and an honest live disposition.  Report an item
that exists only in prose, an advertised feature missing from the activation
ledger, a broad row that hides per-device gaps, or an “exercised” status that
cannot be traced to exact scheduled Linux/5BSD cases and the corresponding
host path.

### Pass 2: Linux interoperability

Compare the relevant Linux driver and transport paths line by line:

* `drivers/virtio/virtio_pci_modern*.c`
* `drivers/virtio/virtio_ring.c`
* `drivers/net/virtio_net.c`
* the Linux virtio block, SCSI, console, RNG, 9P, and vsock drivers
* `net/vmw_vsock/virtio_transport*.c`
* `drivers/vhost/vsock.c`

Check the exact scatter-gather shape, natural structure padding, queue IDs,
feature validation, retry behavior, reset waits, callback rearming, and
control-command completion expected by an unmodified Linux guest.  Record
where Linux is stricter, more permissive, or merely one possible
implementation.

### Pass 3: concurrency and memory ordering

Examine host threads, vCPU callbacks, backend callbacks, reset callbacks,
snapshot callbacks, kernel provider operations, and socket-domain operations.
Validate lock order and every atomic memory order.  Construct schedules for:

* notification racing with EVENT_IDX re-enable;
* queue reset racing a worker that has selected that queue;
* full reset racing a fatal worker error and `NEEDS_RESET`;
* RSS/MQ reconfiguration racing TX and staged RX;
* backend callback racing queue unmap;
* snapshot pause racing queue work;
* provider reset/detach racing blocked read, write, poll, and kqueue;
* same-CID and different-CID provider attach;
* feature changes on one provider while another carries traffic;
* last-provider detach and immediate CID reuse.

Timed sleeps are not synchronization.  A wait is acceptable only when its
predicate, owner, wakeup, and failure behavior are explicit.

### Pass 4: descriptor and packet validation

Exercise zero, minimum, maximum, and maximum-plus-one sizes; integer
wraparound; indirect chains; too many descriptors; loops; mixed
device-readable/device-writable ordering; split headers; unmapped ranges;
short response buffers; stale queues; invalid queue selectors; unknown
operations; unsupported socket types; reserved flags; wrong CIDs and ports;
credit wraparound; fragmented and zero-length SEQPACKET records.

Verify that malformed work cannot produce an unbounded callback loop, consume
an uninitialized request index, publish an incorrect used length, access an
unmapped guest range, or strand notifications.

### Pass 5: failure recovery and resource lifetime

Follow initialization, partial initialization failure, feature rejection,
normal reset, queue reset, failed queue reset, full reset, detach, reconnect,
and process exit.  Account for every mutex, condition variable, thread,
mevent, fd, mapping, resource, packet, mbuf, request object, and guest
descriptor.

For SEQPACKET, prove that no complete record is silently dropped after being
credited.  For STREAM, prove that partial sends retain correct order and
credit.  For multiqueue devices, prove that one queue's reset or failure does
not disable unrelated queues or devices.

### Pass 6: snapshot and long-run state

Validate serialized representations independently of in-memory structure
layout.  Reject inconsistent restored feature, queue, header, hash, request,
and staged-packet state.  Confirm pause waits without polling and resume cannot
lose already-published work.

Design an error-inclusive soak that reuses a single bhyve process, repeatedly
changes load and queue pressure, resets/rebinds devices, abruptly closes
endpoints, and measures fd, memory, thread, connection, queue, and provider
counts after warmup.  A successful echo loop alone is insufficient.

### Pass 7: test validity

Treat tests as code under review:

* wire values must be transcribed from the specification into an independent
  oracle, not included from or calculated using the implementation;
* Linux compatibility fixtures must reproduce Linux's actual descriptor and
  byte layout;
* mocks must support short I/O, zero progress, hard errors, asynchronous
  completion, reset races, and allocation failure where relevant;
* tests must assert both endpoints, used-ring publication, status, wakeups,
  and final resource state;
* no fixed sleep may stand in for a readiness or lifecycle condition;
* skips must name a genuine unavailable prerequisite and must not conceal an
  untested advertised feature.

Perform mutation checks on load-bearing tests: temporarily break one behavior
per subsystem and confirm the intended test fails, then restore the source.
Do not leave mutations in the worktree.

### Pass 8: observability and documentation

Check that DTrace, rate-limited logs, audit records, sysctls, manuals, and test
diagnostics identify the device/backend/CID/queue and resulting state without
exposing packet payloads.  Ensure observability code obeys the same lifetime
and locking rules as the functional path.  Documentation must distinguish
implemented-and-tested, implemented-but-awaiting live validation, and planned
features.

### Pass 9: waits, polling, and progress

Inventory every `sleep`, `usleep`, `nanosleep`, `DELAY`, spin loop, retry loop,
timer, `poll`, condition wait, and open-ended descriptor drain.  For each,
record the predicate, predicate owner, wakeup source, timeout policy, caller
lock state, and behavior when progress never occurs.

Prefer condition variables, kqueue/mevent readiness, task scheduling, or
device interrupts when the producer can signal progress.  Do not replace a
non-sleepable kernel wait with a sleeping primitive while a child-driver mutex
may be held.  Conversely, do not retain periodic polling merely because it is
easy.  Bound guest-controlled loops or provide a fair continuation mechanism.
Compare reset and control-queue progress with the normative requirement and
Linux, explicitly separating a required wait from Linux's implementation

### Pass 10: complete vsock subsystem review

Review the final composed implementation, not only the multi-provider diff:

* AF_VSOCK PCB lookup, bind/connect, accept, shutdown, close, credit accounting,
  STREAM partial progress, and SEQPACKET assembly;
* mbuf allocation, packet-header ownership, fragmentation, limits, malformed
  packets, and every RST path;
* the FreeBSD virtio-vsock guest driver attach, feature negotiation, RX/TX
  queues, event queue, queue reset, detach, and a second-device attach failure;
* bhyve's userspace relay and kernel `/dev/vsock` backend, including packet
  validation, negotiated feature epochs, reset/rebind/reboot, and backend
  selection;
* every `/dev/vsock` provider operation and stable-transport callback with
  zero, one, and many providers;
* CID hash collision, duplicate attachment, last-provider removal, immediate
  CID reuse, feature aggregation, unrelated-CID traffic during reset, blocked
  read/write wakeup, copyin/copyout failure, poll/kqueue teardown, fd passing,
  exec/credential change, and process exit;
* MAC capability claim overlap, full-CID provider ownership, narrowed
  delegation, token close/revoke, claim release, descriptor passing, and the
  rule for an unclaimed CID.

Before completing this pass, produce a function-level inventory for all of
`pci_virtio_vsock.c`, `uipc_vsock.c`, `uipc_vsock_user.c`,
`virtio_vsock.c`, and the vsock-facing MAC capability code.  Mark every
function as reviewed for steady-state behavior, malformed input, reset,
teardown, and concurrency, or state why a category is inapplicable.  Search
callers and callbacks from the final tree rather than relying on a handwritten
list, so unchanged and newly connected code cannot be omitted.

Compare the transport behavior with both
`net/vmw_vsock/virtio_transport*.c` and `drivers/vhost/vsock.c` in the Linux
reference.  Verify the VirtIO 1.4 socket clauses directly, especially implicit
STREAM support, unsupported socket-type RST, packet length versus descriptor
capacity, credit modulo arithmetic, shutdown flags, and SEQPACKET EOM/EOR.

Treat provider authorization as a lifetime property.  A successful attach-time
check alone is insufficient if token revocation, credential change, or
descriptor transfer can continue to exchange packets.  Conversely, do not
make the optional MAC policy a mandatory runtime dependency when it is absent
or when the CID is deliberately unclaimed.  Tests must prove both enforcement
and the unclaimed-policy behavior.

### Pass 11: dead code, review residue, and design drift

Search for unused fields and functions, redundant assignments, impossible
branches, duplicate state caches, temporary tracing, payload dumps, stale
comments, compatibility workarounds that outlived their cause, and helpers
whose abstraction hides rather than enforces an invariant.  Compile with
warnings-as-errors and run the narrow Clang static analyzer.  Check whether
debug-only code is rate limited, disabled by default, free of guest payloads,
and documented when it is intentionally retained.

Compare each subsystem's shape with established bhyve, FreeBSD VirtIO, and
Linux patterns.  Do not mechanically copy Linux, but require a reason for a
new private polling loop, duplicate feature cache, custom queue scheduler, or
nonstandard lifetime rule.

### Pass 12: coverage accounting

Do not use “100%” without stating the denominator.  Report separate coverage
for:

* mandatory rules applicable to the implemented PCI/MMIO transports;
* every optional feature actually advertised;
* every implemented device type;
* all VirtIO 1.4 chapters, including unsupported devices and optional
  facilities;
* positive, malformed-input, boundary, failure-injection, reset, concurrency,
  interoperability, and soak evidence.

Every advertised behavior needs positive evidence and at least one meaningful
negative or boundary test.  High-risk stateful behavior additionally needs
reset and concurrency evidence.  Verify catalog references are declared,
registered, and executed.  Identify semantic blind spots that line or
requirement counts conceal.  Unsupported optional features must be explicitly
listed and must not be advertised.

### Pass 13: common save-state and migration review

Treat save and restore as a transaction spanning the common lifecycle, the
device model, every external backend, PCI and interrupt state, queue/DMA
ownership, and the checkpoint manifest.  Review the final composed code for
all supported devices, including devices whose steady-state data path did not
change in the current worktree.

Build a field-level state ledger.  Every persisted field must have a stable
wire type, byte order, version-introduction rule, validation rule, destination
compatibility rule, and independent negative test.  Reject native structure
serialization, padding, pointers, mutexes, condition variables, host virtual
addresses, file descriptors, backend-private identifiers without a
reconstruction contract, and architecture-specific CPU state in portable
device records.  Verify unknown versions, unknown optional fields, truncation,
oversized counts, duplicate records, arithmetic overflow, cross-field
inconsistency, changed destination features, and changed backend identity.

Trace pause, quiesce, snapshot, publication, restore staging, commit, rollback,
resume, and destroy in both success and failure order.  Prove that a failed
checkpoint leaves the source runnable, a failed restore leaves the destination
unpublished and retryable, and repeated restore cannot consume or mutate the
manifest.  Active requests, packed/split cursor state, interrupt suppression,
configuration generation, queue reset, translated-DMA mappings, external
backend ownership, and device-specific protocol objects must either be
reconstructed exactly or rejected before commit.  Compare the architecture
and observable guarantees with the pinned QEMU VMState implementation, while
using VirtIO and bhyve's declared checkpoint ABI as the controlling contracts.

Require focused unit and mutation tests plus scheduled Linux and 5BSD live
cases for every supported device.  A marker file surviving reboot is not
active-I/O checkpoint evidence.  The live workload must hold the relevant
device object or request across the checkpoint, restore the same immutable
image at least twice, and correlate guest-visible continuity with host
lifecycle evidence.

### Pass 14: Intel nested-VMX architecture and execution review

Use the pinned Intel SDM VMX chapters and capability-MSR definitions as the
normative guest ABI.  Use the pinned Linux KVM nested implementation and
nested-state ABI as an execution, lifecycle, and interoperability reference,
not as source to copy.  Review every nested-VMX source file and all callers;
do not limit this pass to changed lines, VMCS field helpers, or the model
library.

Trace VMXON/VMXOFF, VMPTRLD/VMCLEAR/VMPTRST, VMREAD/VMWRITE, VMLAUNCH/VMRESUME,
VM-entry validation and failure publication, VMCS01/VMCS12/VMCS02 ownership,
control composition, MSR and I/O bitmaps, entry/exit MSR lists, nested exit
reflection, event arbitration, APIC and timer state, TSC offset/scaling, EPT02
composition and invalidation, VPID ownership, teardown, and active-L2
checkpoint/restore.  For every Intel-defined failure path verify the exact
instruction result, VM-instruction error, flags, state mutation boundary, and
whether the failure is an L0 exit, reflected L1 exit, failed VM entry, or
ordinary L2 continuation.

Keep hardware VMCS objects, physical mappings, CPU-local VPIDs, and host
capabilities out of portable state.  Restore a versioned architectural VMCS12
and explicit execution/pending state, validate destination capabilities before
publication, rebuild hardware-local resources transactionally, and preserve a
runnable source or retryable destination on every error.  Common VMM,
save-state, DMA, interrupt, and lifecycle code must remain architecture-neutral;
Intel-specific structures and checks stay behind explicit amd64/VMX operations.

Model and warnings-as-errors builds are necessary but not release evidence.
Every pending hardware requirement must map exactly once to a scheduled live
feature group.  Final qualification requires nested VMX enabled explicitly on
this Intel host, an unmodified Linux/KVM L1, both Linux and 5BSD L2 guests,
real instruction and VM-entry failures, interrupt/APIC/timer behavior,
EPT/VPID and invalidation, exit reflection, save/restore while L2 is running,
repeated create/destroy, concurrency, injected failures, and soak.  Evidence
must record host capabilities, kernel and bhyve identities, pinned guest
artifacts, exact commands, and bounded traces; absence of hardware evidence is
reported as a gate, never converted into a pass or skip.

### Pass 15: second independent kernel implementation review

Repeat the kernel review after all earlier conformance, interoperability,
lifecycle, state, and test fixes have been composed.  This is a new review,
not a summary of Passes 1 through 14 and not an assertion that previously
reviewed code stayed correct.  Make this the forward lifetime traversal:
start from production entry points and follow allocation, initialization,
publication, active use, revocation, and destruction.  Reverse the subsystem
order used by the first kernel reading.

For every kernel object, identify allocation, initialization, publication,
reference acquisition, lock or epoch ownership, callback entry, sleep and
lock-drop boundaries, revocation, rollback, detach, and final destruction.
Trace interrupt, taskqueue, callout, poll/kqueue, cdevpriv, sysctl, MAC hook,
snapshot, suspend/resume, DMA, and virtqueue callbacks through concurrent
reset and unload.  Check that a callback cannot retain a stale softc,
transport, provider, prison, credential, mbuf, mapping, queue, or guest-memory
pointer after its owning generation ends.  Recheck memory ordering on every
architecture, not only amd64, and distinguish compiler ordering, CPU ordering,
and bus-DMA synchronization.

Audit failure paths independently from success paths.  Partial attach,
publication failure, interrupted waits, timeout, copyin/copyout failure,
allocation failure, queue corruption, backend loss, failed restore, and
module unload must leave an unpublished or recoverable object and wake all
waiters exactly once.  Inventory hot-path allocation, unbounded work,
unbounded logs, lock contention, and repeated translation or copying.  A
clean earlier kernel pass is invalidated by any subsequent functional fix;
after such a fix, rerun this pass from a different entry point and with a new
concurrency schedule.  Capture fresh warnings-as-errors diagnostics from the
final source.  Re-reading the same diff in the same direction is not an
independent second kernel review.

### Pass 16: non-standard interfaces and operational policy review

Inventory every behavior not defined by the controlling VirtIO, Intel, PCI,
ACPI, socket, or other named normative specification.  Do not silently treat
Linux, QEMU, an existing bhyve behavior, or a locally convenient wire value as
a standard.  Classify each item as a private implementation detail, a
documented compatibility contract, a versioned private ABI, an experimental
guest ABI, or operator policy.  Keep these values out of independent standard
fixtures and give each interface direct compatibility and negative tests.

Run five separately recorded subphases:

1. **Compatibility identities.**  Audit transitional PCI IDs, historical
   aliases, legacy layouts, and compatibility fallbacks.  Their oracle must be
   separate from the VirtIO 1.4 oracle, with explicit selection and no
   accidental advertisement on a modern-only device.
2. **Host and provider ABIs.**  Audit `/dev/vsock`, VMM ioctls, backend control
   messages, DTrace argument layouts, MAC authorization boundaries, and
   management commands.  Require versions or reserved-zero expansion fields,
   complete input validation, bounded waits, authorization revalidation after
   sleep, transactional publication, and stable error meanings.  ABI layout
   tests built from the source tree must include the source ABI headers rather
   than silently validating an older installed world.
3. **Checkpoint ABIs.**  Audit every private state envelope and manifest
   field for fixed-width endian-defined encoding, count and allocation bounds,
   exact consumption, unknown-version handling, historical decoding,
   destination compatibility, preflight without mutation, and commit/rollback
   ordering.  Native structs, pointers, descriptors, mutex state, and
   hardware-local objects must not become persistent ABI.
4. **Experimental guest ABIs.**  Audit nested VMX, administration queues and
   device groups, provisional devices, accelerations, and incomplete optional
   features.  They remain default-off or unadvertised until their declared
   qualification gates pass, and unsupported commands fail closed without
   corrupting standard state.
5. **Operational policy.**  Audit sysctl limits, timeout defaults, retry and
   rate limits, tracing, audit records, debug knobs, and resource ceilings for
   synchronization, privilege, information exposure, denial-of-service
   behavior, rollback, and boundary tests.  Policy defaults are documented as
   implementation choices rather than normative requirements.

In every subphase enumerate compile-time queue counts, maximum descriptors,
objects and transfers, memory caps, timeouts, retry counts, polling cadences,
rate limits, sysctls, tunables, and guest-driver resource ceilings.  For each
value record exactly one disposition: standard-derived with the controlling
section and an independent oracle, or private policy with owner, units,
default, mutability, authorization, version/compatibility promise, rollback,
and a boundary or negative test.  A copied Linux/QEMU default, unexplained
literal, or prose-only justification is unresolved.

Compare observable behavior with the pinned Linux and QEMU revisions, but do
not use either as the normative authority and do not copy or mechanically
translate their GPL implementation.  Any fix found in one subphase requires
all five subphases to be rerun because compatibility, state, and policy
contracts can overlap.

The first composed Pass 15/16 follow-up retraced the CTL LUN-event cdevpriv
lifetime, packed-ring publication and consumption barriers, VMM CPU
compatibility ioctls, and `/dev/vsock` provider teardown from their kernel
entry points.  A suspected CTL unload lifetime problem was rejected after
following `destroy_dev()` into the common cdev implementation: it synchronously
invokes and drains every cdevpriv destructor before returning, so subscribers
are removed while the CTL softc and mutex remain valid.  The actual finding
was in qualification evidence.  Version 2 allowed one group-level label to
accompany several requirement assertions without proving each behavior ran.
Version 3 requires one role-typed, positive-count proof per requirement and
rejects missing, duplicate, zero-count, and cross-role proofs.  The evidence,
two-boot policy-pair, host-tools, nested sanitizer/model, and VirtIO
requirements gates pass; the Intel L1/L2 hardware run remains pending.

The next composed Pass 15/16 application retraced the common guest queue from
enqueue publication through notification, completion, interrupt rearm,
drain, reset, and transport failure.  It found that malformed-ring failure
could race interrupt rearm: rearm could publish ENABLE after failure had
published DISABLE.  The final queue uses an atomic one-time failure latch,
rechecks it after event publication, disables a racing rearm, and rechecks
before notification.  The private `virtio_bus_fail` method is classified as
an internal implementation of the standard FAILED status, not as a guest or
userspace ABI; PCI legacy, PCI modern, and MMIO all implement it.  Independent
failure/rearm/reset models, focused packed contracts, the FIRECRACKER MMIO
object, and every VirtIO guest module build with `-Werror`.  Rebuilt-guest
live malformed-device and ordered-batch execution remain explicit privileged
gates.

The following Pass 13/15/16 rotation began at private device checkpoint
callbacks and followed every decode error to the coordinator.  It found that
the console callback validated magic, version, booleans, port lifecycle,
truncation, and backend identity but its common exit discarded the resulting
error.  The callback now returns the codec result, and the production-source
harness corrupts the private `CON1` magic and requires `ENOTSUP` without state
publication.  A second scan found no other VirtIO device snapshot callback
with a `done` path returning unconditional success.  The complete console
ATF program and its focused snapshot case pass rootlessly.  This is a private
checkpoint-ABI correction; it does not alter the standard VirtIO console wire
protocol or feature advertisement.

The subsequent independent-kernel/private-interface pass expanded the
non-standard ledger to cover AF_VSOCK buffer policy, SEQPACKET fragment
policy, PCB observability, and global/per-CID connection admission.  The
source-level kernel harness already proves the connection ceilings in all
three directions, including loopback's two-PCB reservation and immediate
slot reclamation; the ledger validator now resolves tests in sibling harness
directories so that claim cannot silently become prose-only.  Running that
harness under ASan and UBSan then exposed a build-contract drift rather than
a runtime defect: the transport half did not stage the new private
`virtio_vsock_var.h` dependency or mock `virtio_teardown_intr()`.  The
standalone runner now includes the kernel header root, the mock records the
teardown boundary, and the detach lifecycle test requires exactly one
interrupt teardown.  Both halves pass with 370 and 1348 checks respectively.
These are host policy, observability, and test-harness contracts; none is a
new VirtIO guest ABI.

The following driver-ownership pass compared every successful attach step
with both the normal detach path and each later failure edge.  It found that
the guest VirtIO-vsock driver could successfully install MPSAFE interrupts,
then fail while populating its event or receive queues and return without
tearing those interrupts down.  Attach now records interrupt ownership and
calls `virtio_teardown_intr()` on precisely those post-setup failures; failures
before setup do not issue a spurious teardown.  The source-level transport
harness proves both boundaries and normal detach's exactly-once teardown.
ASan/UBSan reports 370 core checks and 1351 transport checks passing, and the
`virtio_vsock.ko` module rebuilds with kernel `-Werror` flags.  This is a
FreeBSD driver-lifetime correction below the VirtIO guest-visible protocol.
The same test-quality pass found an error branch in the root provider ATF
case which could close an uninitialized kqueue descriptor when ATTACH was
rejected before the kqueue existed.  The descriptor now has an explicit
invalid initial state and guarded cleanup; `vsock_test` rebuilds with the
tree's `-Werror` test flags.

The completed second kernel/private-interface cycle initially validated 39 explicitly
inventoried non-standard contracts and 223 VirtIO requirements.  The complete
rootless device suite passes under ASan/UBSan and in a separate ThreadSanitizer
build, including the independent wire oracle, negative descriptor and state
fixtures, snapshot portability, private-DMA boundary checks, and every
supported device model.  A separate
nested-VMX anti-drift gate then found one remaining entry-runtime copy of the
VMCS02 identity comparison.  It now delegates to the common identity helper;
the 206-entry nested ledger and its 148-case ASan/UBSan model pass again.
All bhyve translation units compile under the tree's `-Werror` flags.  A
standalone final link against the running host's installed `libvmmapi` is not
a valid gate because that library predates the new memory-domain and automatic
device-memory interfaces; the release build must use a matching buildworld.

A subsequent save-state/private-ABI rotation made the checkpoint trust
boundary explicit.  Version-3 SHA-256 member values are unkeyed corruption
and post-publication mutation detection, not authentication; version-2
imports intentionally have no member digests.  The installed manual now
requires the manifest, members, and containing directory to remain inside the
trusted operator boundary, and the private-interface validator requires that
warning plus the existing member-mutation regression test.  This changes no
wire field and does not turn an integrity digest into a security credential.

The next reverse kernel/private-policy replay inventoried the bounded packet
queues on both FreeBSD vsock host paths.  The guest virtio-vsock driver's
256-packet reply FIFO and 240-packet RX high-water mark, plus the userspace
provider's 128-packet total and 64-packet data ceilings, are implementation
resource policy rather than VirtIO queue or credit constants.  Two new
private-interface rows now state their ownership, rollback, and isolation
contracts.  The same replay found that the driver's last-resort drop count
was trapped in an otherwise unreadable softc field.  Drops now increment the
read-only `kern.vsock.tx_drops` counter and fire a metadata-only
`vsock:::pkt-tx-drop` probe carrying the operation, destination, payload
length, error, and queue depth.  A direct production-driver harness fills the reply FIFO to the
exact high-water boundary, proves that a completed RX buffer remains on the
virtqueue without delivery or loss, fills the reserved margin, proves one
additional control packet is dropped and counted, then proves TX progress
resumes RX and delivers it exactly once.  The existing live kernel-provider test continues
to prove exact userspace-provider saturation, control-slot reservation, and
per-CID isolation.  The private-interface validator pins both production
bounds and both tests, and the ASan/UBSan transport harness passes.  Because
this adds material kernel test evidence, the final post-private kernel replay
continues from the resulting source rather than inheriting an earlier clean
result.

The following non-standard resource-policy inventory added four production
limits which were already enforced but not separately classified: the
userspace bhyve vsock device's 256 connection and 16 control-client ceilings,
virtio-fs's 64 request-queue and 4096 in-flight ceilings, virtio-IOMMU's 256
endpoint, 256 domain, 8192 mapping, and 256 fault-table ceilings, and the
input device's 4096-event staged-frame ceiling.  Their focused tests now pin
the intended private values with independent literals as well as exercising
overflow rollback.  The machine-readable inventory therefore contains 45
private contracts; none of these host resource policies is presented as a
VirtIO architectural maximum.

A second inventory sweep added four more policies that had been implicit in
production constants: the RNG device's 65,536-byte service budget, the net
device's 256-descriptor processing ceiling, the block backend's 1024-slot plus
eight-worker request pool, and the checkpoint format's eight-domain NUMA cap.
Independent literal assertions distinguish each policy from standard wire or
guest-architecture limits.  The inventory now contains 49 private contracts.

The restarted second kernel pass then found a boundary defect in the arm64
SCMI VirtIO consumer's required non-sleeping poll path.  Positive timeouts
shorter than the private two-millisecond cadence performed no probe, and a
matching response on the final permitted iteration was reported as timed out
because success was inferred from a post-decremented loop counter.  Production
now rounds positive timeouts up, returns immediately for the target response,
and derives the terminal result from the acquire-loaded completion state.  A
small architecture-independent policy helper has focused boundary tests and
the arm64 production object builds warning-clean.  The cadence is catalogued
as private contract 50 rather than as a VirtIO requirement.  This production
correction restarts Passes 17 and 18 again.

Continuing the same destructor-first pass found that synchronous SCMI callback
unregistration still did not revoke device DMA ownership.  The firmware
consumer freed its P2A pool while receive descriptors referring to that pool
could remain posted in the transport virtqueue.  The private transport
boundary now closes enqueue admission, resets the device, drains every queue,
and only then permits consumer memory to be freed; a later consumer start
reinitializes the stopped transport.  Callback installation precedes P2A
buffer publication, partial publication errors use the same reset/drain
rollback, and the arm64 consumer and transport objects compile with `-Werror`.
The private-interface validator now verifies both callback lifetime and the
DMA-revocation/free ordering.  Because this is another production lifetime
fix, neither of the restarted kernel/private passes is yet clean.

The accompanying test-quality replay found that private-ledger references to
shell validators proved only that the script file existed; the named semantic
anchor could be stale or fictitious.  Shell-backed claims now require an
explicit `TEST-ANCHOR` marker, and all three current DTrace, interrupt-teardown,
and SCMI lifetime claims resolve to real anchors.  The complete requirements
validator, private-interface validator, and DTrace wrapper validator pass with
that stricter evidence rule.

### Pass 17: final post-private kernel replay

After Pass 16 is clean, review the production kernel a second time because a
private-ABI or policy correction can change publication, locking, sleep, and
teardown behavior that Pass 15 never saw.  Make this the reverse lifetime
traversal and start from the opposite side of
each boundary: begin at destructors, interrupt teardown, wakeups, restore
rollback, and policy writes, then trace backward to allocation and attach.
Compile the complete affected kernel modules with warnings as errors and
review every diagnostic rather than casting around a type, alignment, or
ownership mismatch.  Separately identify diagnostics caused by a documented
FreeBSD kernel format extension or tool limitation.  A fix in this pass
invalidates both Passes 15 and 17.
The compiler evidence must be newly produced for the post-private final source;
Pass 15 diagnostics and conclusions cannot be reused.

### Pass 18: non-standard boundary composition

Compose the Pass 16 inventories rather than reviewing each private interface
in isolation.  Check collisions and confused-deputy paths between historical
PCI identities, provider ioctls, MAC policy, sysctls, checkpoint envelopes,
backend identity records, experimental features, and management tools.
Require cross-version, cross-owner, wrong-credential, wrong-device,
wrong-generation, and standard-versus-private namespace tests.  Prove that a
private value cannot leak into a normative VirtIO fixture or be accepted by a
standard parser, and that Linux/QEMU comparisons are labelled explanatory.
Any new contract or test discovered here must be added to the machine-readable
private-interface ledger before this pass can be clean.

### Pass 19: second independent non-standard inventory replay

Discard the Pass 16 inventory conclusions and rediscover private contracts
from their consumers rather than their definitions.  Start at userspace
decoders, guest-visible feature selection, restore dispatch, management tools,
installed manuals, tracing consumers, audit readers, MAC authorization hooks,
and compatibility fallbacks, then trace each accepted value backward to its
producer and owner.  Review the final composed source, including unchanged
callers, and reconcile every discovered contract with exactly one private
ledger row and a direct positive and rejection test.

Specifically look for private values that bypass the declared decoder, old
encodings accepted without an explicit selection rule, implementation enums
serialized as integers, native layout or endian leakage, unknown critical
state treated as optional, source-tree tests accidentally using installed
headers, operator limits presented as architectural maxima, and Linux/QEMU
behavior presented as normative.  Re-run the five Pass 16 categories in a
different order and with fresh boundary examples.  Pass 18 composition does
not satisfy this replay: it tests interactions among known contracts, while
this pass searches independently for contracts omitted from the inventory.

Any finding or production/test correction invalidates Passes 15 through 21.
Record a separate clean result for this pass; it cannot inherit the Pass 16
or Pass 18 result.

### Pass 20: kernel/private adapter failure-atomicity replay

Review every boundary where normative VirtIO or VMM state crosses a private
kernel adapter: transport methods, backend callbacks, DMA translators,
interrupt delivery, cdevpriv/provider operations, checkpoint codecs, suspend
coordinators, and architecture-specific VMM operations.  For each call, mark
the last fallible operation, the first mutation of every retained owner, the
rollback owner, and the exact retry identity.  Replay failures in reverse
order, including a successful callback followed by caller-side validation or
publication failure.  Prove that failure preserves live state, caller output,
queue cursors, generation ownership, wakeup obligations, and backend resource
ownership, or explicitly transitions to a documented fail-stop state.

This pass is separate from Passes 15 and 17.  A lifetime can be correct in the
steady state while a multi-owner adapter transaction is not atomic.  Require
focused failure injection at every fallible stage and byte-for-byte unchanged
state assertions where rollback is promised.  A production correction
restarts Passes 15 through 20.

### Pass 21: withheld, unsupported, and implementation-defined behavior review

Inventory every parsed, modelled, restored, logged, or partially implemented
facility which is not advertised or is deliberately unsupported.  Verify the
same feature is withheld at every transport and capability surface, rejected
consistently by restore and runtime paths, and cannot be activated through a
legacy identity, private ioctl, stale checkpoint, backend option, or host
hardware capability leak.  For implementation-defined behavior, record the
owner, stable observable contract, default, bounds, error result, rollback,
and direct negative test.

Review compatibility fallbacks, provisional devices, debug paths, manual
waits, polling and retry policy, fixed resource ceilings, old checkpoint
decoders, and unknown-command handling.  Compare with the controlling
specification first, then the pinned Linux and QEMU revisions as explanatory
references.  Do not turn their defaults into bhyve policy without an explicit
private contract.  Distinguish `not implemented`, `implemented but withheld`,
`implemented and model-tested`, and `live-qualified`; none may imply another.
Any new contract enters the private ledger, and any production correction
restarts Passes 15 through 21.

### Pass 22: second final-source kernel implementation review

After Pass 21, discard the Pass 15, 17, and 20 kernel traces and review the
final composed kernel again from machine-independent lifetime boundaries.
Start independently at VM and device destruction, module unload, interrupt
and taskqueue publication, DMA revocation, queue reset, suspend, restore
commit, backend failure, and blocked-operation cancellation.  Trace each path
backward until it meets allocation and publication.  For every retained
object record its pointer-stability owner, admission gate, lock order,
sleepability, cancellation and drain condition, rollback owner, and final
release.  Review release-kernel behavior separately from diagnostic-only
assertions and require externally reachable exhaustion, malformed input,
version skew, and backend failure to return without partial publication.

Before reading, build a sorted manifest containing every tracked modification
and every untracked production, header, test, fixture, ledger, script, and
manual file in scope.  Hash each member before this pass and again after Pass
23.  `git diff --name-only` is insufficient because it omits newly created
untracked files.  If membership or any hash changes, discard the result and
restart Passes 15 through 23.  Require fresh warnings-as-errors builds and
focused failure tests from this exact source.  Earlier kernel passes cannot
satisfy this final replay.

### Pass 23: second final-source non-standard and private-policy review

After Pass 22, discard the Pass 16, 18, 19, and 21 inventories and rediscover
every non-standard behavior from its final consumers: ioctl and backend
decoders, legacy selectors, checkpoint import, management manifests, sysctl
and tunable handlers, DTrace and audit consumers, manuals, compatibility
fallbacks, provisional devices, and withheld-feature paths.  Trace each value
back to exactly one owner and classify it as transient implementation detail,
compatibility ABI, versioned private ABI, experimental interface, or operator
policy.  Record units, default, authorization, namespace, versioning,
reserved fields, rollback, observability, and direct rejection evidence.

Compose valid values with the wrong VM, device, queue, vCPU, generation,
backend, credential, jail, architecture, transport, version, and
legacy/current selector.  Prove that kernel pointers, locks, credentials,
tickets, cookies, file descriptors, host DMA identities, and interrupt
residency never enter portable state.  Reconcile every discovered contract
with exactly one machine-readable ledger row, and prove standard fixtures do
not derive expectations from a private value.  Linux and QEMU remain
explanatory comparisons, not normative sources.  Any finding or correction
restarts Passes 15 through 25 and the earlier affected conformance or lifecycle
phase.

### Pass 24: repeated common-kernel primitive lifecycle review

Discard the device-centric kernel traces and start underneath every changed
device and bhyve adapter. Independently review VMM freeze and wakeup,
sleepqueue and callout use, interrupt publication, DMA pinning and revocation,
cdevpriv lifetime, taskqueue drain, VMX/SVM runtime ownership, and snapshot
publication. Trace each primitive through allocation, admission, rollback,
reset, detach, restore, and destruction. Record execution context, lock order,
pointer-stability owner, cancellation, wakeup, and release-kernel behavior.
Recheck non-amd64 callers and forbid an architecture-specific assumption from
becoming a common success contract.

### Pass 25: repeated private and non-standard activation review

Discard every earlier private inventory and reconstruct it from final
consumers and decoders. Include legacy identities, provider and ioctl ABIs,
backend/checkpoint envelopes, feature-policy switches, provisional options,
resource ceilings, DTrace/audit records, and withheld architecture adapters.
Bind each contract to an owner, generation, lifetime, authorization domain,
architecture, default, units, rollback, and independent rejection test.
Compose it with the common primitives from Pass 24 and prove no private
success can bypass their admission, lifetime, or failure rules. Model-tested,
compiled, installed, and live-qualified remain distinct states.

Passes 24 and 25 use the byte-identical complete source manifest from Passes
22 and 23. Any correction invalidates all four final-source passes; neither
repeated pass may reuse findings or build evidence from its predecessor.

### Pass 26: terminal production-kernel source review

After Passes 24 and 25 are clean, discard every earlier kernel trace and read
the final composed kernel source from public entry points into the shared
implementation.  This is a second review, not a summary of the first: start
at syscall, ioctl, socket, VMM, device attach, interrupt, taskqueue, callout,
and snapshot entry points; independently trace publication, lock acquisition,
guest-memory access, wakeup, cancellation, reset, detach, and destruction.
Then repeat the traversal in reverse from each release, asynchronous callback,
and error return.  Reconcile common code with all architecture adapters so an
amd64, Intel, Linux-driver, or bhyve-only assumption never becomes a portable
kernel invariant.  Every discovered implementation choice must have a named
owner, an error policy, and deterministic source-level or model evidence.

### Pass 27: terminal non-standard and private-contract review

Independently reconstruct every behavior outside the VirtIO, AF_VSOCK, and
architectural specifications from final consumers, decoders, installed
operators, diagnostics, and test runners.  Cover private ioctls and records,
checkpoint envelopes and manifests, backend identities, feature gates,
defaults, timeouts, retry or polling policy, resource limits, compatibility
selectors, DTrace/audit metadata, MAC policy, and provisional interfaces.
For each contract, verify versioning, authorization, namespace, generation,
architecture scope, rollback, observability, and an independent rejection
test.  Compose valid values with the wrong owner, VM, device, queue, backend,
architecture, credential, version, and restore destination.  A private
success must not weaken a standard or common-kernel admission, lifetime, or
failure rule.

Passes 26 and 27 run on a newly generated complete source manifest after
Passes 24 and 25.  Any production, test, ledger, documentation, or manifest
change restarts Passes 24 through 27 and the earlier affected conformance or
lifecycle phase.  Neither terminal pass may reuse a prior pass's source trace,
inventory, compiler output, or test conclusion.

### Pass 28: independent common-production-kernel contract replay

After Pass 27, review the final production kernel a third time, starting from
the common VMM, socket, PCI, DMA, interrupt, taskqueue, callout, sleepqueue,
credential, prison/VNET, MAC, snapshot, and module interfaces rather than
from a device implementation.  For each interface, prove retained ownership
across lock drops, execution context, admission closure, cancellation,
wakeup, rollback, and failure-atomic caller state.  Then verify that every
device adapter preserves rather than silently redefines that common contract.

This must expose any Intel, pointer, native-endian, page-size, process, or
bhyve-specific assumption that is not isolated behind an explicit adapter.
Use fresh Werror and deterministic fault evidence.  A correction restarts
Passes 24 through 31 and every affected earlier phase.

### Pass 29: independent non-standard decoder and policy replay

After Pass 28, reconstruct private behavior from final accepted decoder and
operator inputs, not producers or ledgers: ioctls, checkpoint envelopes and
manifests, backend identity, feature gates, compatibility selectors, limits,
timeouts, retries, polling, DTrace/audit metadata, MAC policy, and provisional
interfaces.  For each accepted value prove validation, owner, authorization,
namespace, generation, architecture scope, reserved-field rule, rollback, and
direct positive and rejection evidence.  Compose it with wrong VM, device,
queue, backend, provider, credential, jail, VNET, architecture, version, and
restore destination.

Linux and QEMU can describe compatibility but cannot define FreeBSD-private
policy.  A private success must not bypass the common contract from Pass 28 or
a normative wire rule.  A correction restarts Passes 24 through 31 and the
affected earlier phase.

## Pass 30: second kernel-source replay

Perform a second, independently planned kernel-source review after the normal
conformance and lifecycle passes.  Start from actual production entry points,
including PCI configuration and queue writes, DMA mapping, interrupt delivery,
taskqueue/callout callbacks, socket protocol hooks, VMM ioctls, snapshot
dispatch, module attach/detach, and MAC hooks.  Then separately start from
their teardown, error, reset, suspend, restore, and cancellation paths and
trace back to admission.  Do not reuse the first review's call graph, examples,
or finding list.

For each mutable object, prove the owner, lock/atomic ordering, lifetime,
failure cleanup, guest-visible status, and cross-architecture assumptions.
Inspect unchanged paths as carefully as changed ones.  Treat a compiler-clean
build, an earlier commit, or a passing happy-path VM as evidence only of the
specific path it exercised.

## Pass 31: non-standard behavior and seam inventory

Independently inventory behavior not defined by VirtIO, PCI, the socket ABI,
or the Intel SDM.  This includes bhyve-specific configuration, private
ioctls, snapshot envelopes, backend/provider handshakes, checkpoint manifests,
limits, timeouts, polling, retries, logging, DTrace/audit, MAC policy,
emulator-only fallbacks, compatibility decisions, test-only hooks, and dormant
interfaces.

For every item, record its source and consumer, authority/authorization,
namespace, version/generation, architecture scope, endianness and alignment,
failure and rollback rule, observability, and independent positive and
negative test.  Verify that a non-standard seam cannot weaken a normative
wire, lifecycle, DMA, or kernel invariant.  Compare Linux and QEMU only where
they expose an observable compatibility expectation; they do not define this
private policy.  Rebuild the inventory once from definitions and once from
consumers.  Any correction restarts Passes 24 through 31.

## Pass 32: kernel callback identity and recycle-boundary review

Perform a second, kernel-source-only traversal of every asynchronous VirtIO
callback: interrupt, taskqueue, callout, provider callback, detach path, and
snapshot completion.  Begin at each queue dequeue and follow the exact
buffer, descriptor, softc, backend, and provider identity through recycle,
notification re-enable, and wakeup.  A callback must either prove that its
original owner is still current at every post-unlock or indirect boundary, or
stop without touching the retired object.  Checking merely for a non-NULL
global owner is not sufficient where a replacement owner is possible.

Repeat the inventory independently from destruction and replacement paths.
For each private identity contract, require a direct test that replaces or
withdraws the owner at the boundary and proves no stale queue is recycled,
notified, re-armed, or dereferenced.  Distinguish a normal lifetime lock from
an atomic publication convenience; do not assume the former makes the latter
safe after future refactoring.  Reconcile the results with the private
interface ledger; any correction restarts Passes 24 through 32.

## Pass 33: independent common-kernel contract replay

Perform a clean-room review of the production kernel contracts used by VirtIO
and VMM code.  Start at shared primitives, not the device models: DMA and
busdma ownership, guest-memory mappings, interrupt handlers, taskqueues and
callouts, sleep/wakeup predicates, reference counts, credentials,
prison/VNET boundaries, module attach/detach, and snapshot dispatch.  For
each primitive, trace every production consumer in the complete source
manifest and verify acquire, publication, error, reset, suspend, restore, and
release rules.

Treat host pointer width, host endianness, page size, Intel interrupt behavior,
and process lifetime as untrusted assumptions unless the common interface
expressly guarantees them.  Verify every adapter preserves the standard queue,
DMA, status, and notification contracts.  Reconstruct the review from source
and consumers, not prior call graphs, ledgers, or test names.  A correction
restarts Passes 24 through 33 and all affected earlier passes.

## Pass 34: independent non-standard policy and decoder replay

Repeat the non-standard review from externally accepted values and operator
surfaces.  Inventory command-line options, private PCI configuration, ioctls,
socket/provider/backend records, snapshot envelopes and manifests,
compatibility selectors, resource limits, timeouts, retries, polling,
DTrace/audit/MAC hooks, provisional gates, and test-only controls.  Follow
each input through validation, authorization, namespace and generation
binding, architecture scope, byte order and alignment, persistence, failure
cleanup, and observability.

For every private contract, require independent positive and rejection or
withdrawal evidence.  Verify that a compatibility convenience or backend
policy cannot override a normative VirtIO, PCI, socket, DMA, or checkpoint
rule.  Linux and QEMU may identify observable interoperability expectations,
but do not define FreeBSD-private policy.  Rebuild the inventory from
consumers and accepted inputs.  A correction restarts Passes 24 through 34;
the final synthesis follows only after Passes 33 and 34 are separately clean.

## Validation after each fix cycle

At minimum run:

```sh
git diff --check
SANITIZERS=address,undefined \
    sh tests/sys/kern/vsock_device_harness/run.sh
SANITIZERS=thread \
    sh tests/sys/kern/vsock_device_harness/run.sh
make -C usr.sbin/bhyve -j2
# A direct snapshot bhyve build must use a matching snapshot-built libvmmapi.
# Use a private fresh object root so objects compiled without BHYVE_SNAPSHOT
# cannot be reused accidentally.
snapshot_objdir=$(mktemp -d /tmp/bhyve-snapshot-review.XXXXXX)
env MAKEOBJDIRPREFIX="$snapshot_objdir" MK_BHYVE_SNAPSHOT=yes \
    make -C lib/libvmmapi -j2
env MAKEOBJDIRPREFIX="$snapshot_objdir" MK_BHYVE_SNAPSHOT=yes \
    make -C usr.sbin/bhyve -j2
make -C sys/modules/vsock -j2
make -C sys/modules/virtio/pci -j2
make -C sys/modules/virtio/vsock -j2
```

When root and `/dev/vmm` are available, also require:

* the installed kernel vsock suite with interfering services such as
  `oracled` stopped;
* modern Alpine per-device and combined matrices;
* virtio-net with one and multiple queue pairs, RSS and HASH_REPORT, MSI-X and
  MSI fallback, reset/rebind, and monitor reboot;
* simultaneous userspace and kernel vsock backend matrices;
* at least two concurrent kernel-backed guests with distinct CIDs;
* the error-inclusive soak with recorded duration and resource deltas.

Do not merge a runtime workaround into a conformance assertion.  Preserve
failure logs and the exact bhyve binary path used for every live run.

## Finding format

Report confirmed findings first, ordered by severity:

```text
[severity] file:function — concise defect
Reachability:
Violated invariant or clause:
Linux comparison:
Consequence:
Minimal fix:
Regression test:
Verification:
```

Then report:

1. coverage gaps;
2. deliberate and justified design restrictions;
3. unsupported optional features;
4. verification completed;
5. verification still requiring root, a rebuilt kernel, or live guests.

Do not say “no bugs” or “fully compliant.”  A clean cycle means only that the
specified review and evidence found no additional actionable issue.

## Termination condition

Continue until one complete Pass 0 through Pass 44 cycle over the final
composed source
finds no new confirmed defect or material test gap, all non-privileged
validation above passes, and every remaining live or privileged gate is
listed with an exact command and expected evidence.  If a fix is made during
the nominal clean cycle, restart the cycle.  The clean cycle is invalid unless
Pass 10 covered the whole existing vsock subsystem manifest above, Pass 13
covered the common save-state transaction and every supported device, Pass 14
covered the complete nested-VMX implementation and its exact remaining Intel
live gates, Pass 15 independently retraced the final kernel source, and all
five Pass 16 non-standard-interface subphases have separate recorded results.
Pass 17 must then retrace the post-private final kernel, and Pass 18 must prove
that the composed private boundaries remain distinct from normative VirtIO.
Pass 19 must independently rediscover the final non-standard inventory from
its consumers and reconcile it with the ledger and direct tests.  Pass 20
must independently prove failure atomicity across every kernel/private adapter
transaction, and Pass 21 must reconcile every withheld, unsupported, and
implementation-defined behavior with feature exposure, runtime, restore,
private-ledger, and direct negative-test evidence.  Pass 22 must then repeat
the final kernel review from the immutable complete source manifest, and Pass
23 must independently rediscover and compose the final non-standard inventory
from consumers.  Neither may reuse an earlier pass's trace or inventory.
Pass 24 must then repeat the common-kernel primitive lifecycle traversal from
the final manifest, and Pass 25 must independently reconstruct every private
and non-standard activation boundary and compose it with those primitives.
Neither new phase may reuse Pass 22/23 evidence.  A correction in either
restarts both phases and every earlier affected review.  Pass 26 must then
independently retrace the terminal production kernel from public entries and
from asynchronous teardown back to those entries.  Pass 27 must independently
reconstruct the terminal private-contract inventory from consumers and
operators, compose every contract across ownership and restore boundaries,
and verify that none weakens a standard or common-kernel invariant.  A change
in either terminal phase restarts Passes 24 through 27 and every earlier
affected review.
Pass 28 must independently reconstruct the common production-kernel contract
from final consumers and prove every device adapter preserves it.  Pass 29
must independently rediscover private decoder and operator policy from
accepted values and compose each contract with Pass 28.  Pass 30 must then
repeat the production-kernel source traversal, and Pass 31 must reconstruct
the non-standard seam inventory from consumers and accepted inputs rather than
from its ledger.  Neither pass may inherit an earlier callback, queue, or
provider inventory.

Pass 32 must finally repeat the kernel-only callback identity and replacement
traversal without reusing a prior queue or provider inventory.  Each retained
or recycled object needs direct withdrawal/replacement evidence before it can
be re-enqueued, notified, re-armed, woken, or published.  A correction in any
of Passes 28 through 32 restarts Passes 24 through 32 and every earlier
affected normative, lifecycle, portability, Linux/QEMU-comparison, and
test-quality review.  The cycle closes only after a final synthesis compares
the independently reconstructed common contract, private seam inventory, and
callback-owner evidence against the requirements and activation ledgers; it
must list every remaining root-only gate instead of treating a rootless model
result as live qualification.

Pass 33 must independently replay the common production-kernel contracts from
shared primitives through every final VirtIO and VMM consumer.  Pass 34 must
independently reconstruct every non-standard decoder and operator policy from
accepted values and consumers.  Neither may reuse the previous common or
private inventory.  A correction in either restarts Passes 24 through 34 and
all affected earlier reviews.  Only then may the final synthesis call this
review cycle clean; it must still distinguish rootless evidence from root-only
live qualification.

## Pass 35: doubled final kernel-code and device-lifecycle replay

Review the final composed kernel and device-model source a second time without
using the prior defect list.  Start once from public entry points (PCI/MMIO
transport accesses, queue notification, interrupt delivery, backend I/O,
AF_VSOCK ingress, snapshot hooks, reset, detach, and module unload) and once
from cleanup, timeout, callback, wakeup, and destroy paths.  Cover common
VirtIO transport code and every enabled device, including all unchanged
vsock, MAC capability, VMM, and save-state layers that can affect a device
operation.  For every feature, prove the complete path from negotiated bit to
guest activation, device work, completion/interrupt, reset/detach, and
snapshot/restore; do not allow a feature to be considered covered merely
because it is advertised or a guest attached.

Check locking, ownership, memory ordering, integer/length conversion,
descriptor traversal, queue cursor/wrap state, backend identity, and failure
atomicity.  Separate normative VirtIO behavior from host policy and record
every architecture-private assumption.  Compare observable behavior with the
pinned Linux driver and QEMU device model only as reference behavior.  Any
correction restarts Passes 24 through 35 and all affected device, save-state,
Linux/5BSD activation, and root-only live gates.

## Pass 36: doubled non-standard policy, operator, and test replay

Independently reconstruct every behavior not defined by the VirtIO
specification or public kernel ABI from its accepted inputs and consumers:
host CLI options, sysctls, ioctls, backend selection, CID allocation,
checkpoint manifests, compatibility rejection, resource limits, timeouts,
fault injection, tracing, DTrace/audit/MAC checks, test-only toggles, and
unsupported-feature responses.  Trace each through validation, authorization,
namespace/generation binding, persistence, error recovery, cancellation,
teardown, and observability.  Do not consult the prior policy inventory until
the consumer-derived inventory is complete.

For each private behavior require a direct positive and negative test, and
prove it cannot silently weaken a normative device rule, activate an
unimplemented feature, leak host-private state into a portable image, or turn
a model-only test into a live qualification claim.  Reconcile feature-ledger
activation with stock Linux and 5BSD guest-driver evidence: a driver gap stays
a gap, and a pending live path stays pending.  Any correction restarts Passes 24 through 36 and all affected review, qualification, and soak gates.

The review cycle cannot close until one complete Pass 0 through Pass 44 cycle
has completed, with Passes 35 and 36 using fresh source and consumer
inventories.  Their findings must be resolved or recorded as explicit
unsupported gaps, and the final synthesis must rerun the applicable independent
tests. Passes 39 and 40 then independently close the withheld-feature and
test-oracle boundaries. Rootless builds and models remain distinct from the
retained root-only Linux, 5BSD, checkpoint, and soak commands.

## Pass 37: terminal kernel mutation and rollback review

Review the final composed kernel source from mutations rather than feature
lists.  For each change to queue cursors, used rings, interrupt state, device
configuration, backend ownership, DMA translation, checkpoint staging, VMM
registry state, or AF_VSOCK connection state, prove the admission condition,
last fallible operation, rollback or derived-cache invalidation rule, and
independent negative test.  Follow partial loops, callback failure, reset,
detach, restore cancellation, allocation failure, and stale identity paths.

Separate guest-visible architectural/device state from derived host caches.
Derived cache retirement may precede publication only if it is quiescent,
rebuildable from retained state, and cannot expose a half-published device on
a later error.  Do not use comments, test-only models, or a successful guest
attach as proof of transactional behavior.

Any correction restarts Passes 24 through 37 and every affected device,
save-state, nested-VMX, Linux/5BSD activation, and root-only live gate.

## Pass 38: terminal implementation-defined behavior replay

Build a fresh consumer-derived inventory of all behavior that is not set by
the VirtIO specification or a public kernel ABI: host options, defaults,
limits, timeouts, retries, NOWAIT policy, back-end/provider selection,
diagnostic logging, DTrace/audit/MAC hooks, test-lab controls, checkpoint
compatibility policy, and unsupported-feature errors.  For every entry prove
the authority, input validation, namespace/generation binding, resource
ownership, teardown, observability, persistence treatment, fail-closed path,
and direct positive and negative test.

Confirm private policy cannot change a negotiated VirtIO rule, serialize a
host pointer/native layout, make a model-only test appear live-qualified, or
weaken an architecture-neutral VMM contract.  Reconcile the fresh inventory
only after it is complete with the private ledgers and documented root-only
Linux, 5BSD, checkpoint, and soak gates.

Any correction restarts Passes 24 through 38 and the final synthesis.  A
clean rootless replay still does not claim privileged hardware qualification.

## Pass 39: withheld-feature and host-policy boundary replay

Independently enumerate each feature omitted from negotiation, every explicit
unsupported response, and every host-only policy used by transport, device,
DMA/IOMMU, snapshot, or vsock code.  Trace from guest-visible negotiation or
management input to the rejection, cleanup, observability, and restore
behavior.  Do not conflate a normative VirtIO device response with a
host-management errno or a test-lab policy.  For each withheld feature prove
that it cannot allocate, publish, retain, or restore partial live state, and
record its prerequisite for later activation.

Linux and QEMU are interoperability references only.  Require independent
positive and negative evidence for every non-standard gate, including proof
that a disabled gate did not make the test skip the path it claims to check.
Any correction restarts Passes 24 through 39 and all affected device,
save-state, Linux/5BSD activation, and root-only qualification gates.

## Pass 40: independent feature-activation and oracle replay

Review every static model, userspace harness, and live guest test against an
independent specification fixture.  Expected VirtIO constants and wire
results may not be imported from the bhyve implementation under test.  A
feature is qualified only when the Linux or 5BSD driver negotiated it and
performed the associated work on every applicable queue, not when the device
advertised it or a guest attached.

Prove negative, boundary, reset, checkpoint, and restore cases could fail if
the target feature were absent or wrong.  Retain the distinction among
rootless source/model evidence, installed-kernel validation, and live Linux,
5BSD, migration, and soak artifacts.  Any correction restarts Passes 24
through 40 and the final synthesis.

## Pass 41: independent production-kernel implementation replay

Perform a second line-by-line review of the final production kernel and
device-model code, independently of the prior feature and requirements
inventory.  Start at common-kernel primitives and externally reachable
entries: DMA and guest-memory mappings, interrupt delivery, taskqueues and
callouts, sleep/wakeup, credentials, prison/VNET, module lifetime, snapshot
dispatch, PCI transport, and queue callbacks.  Follow every affected VirtIO,
vsock, VMM, VMX, and SVM path through success, failure, reset, suspend,
resume, detach, checkpoint, restore, and teardown.

For each live-state mutation, establish the serialization owner, last
fallible operation, rollback or derived-cache retirement rule, and an
independent negative test.  Treat host pointer width, endianness, page size,
file descriptors, process lifetime, and Intel-specific execution state as
non-portable facts unless a public common interface explicitly owns them.  A
comment, mock, attach-only test, or successful guest boot is not proof that a
kernel lifetime or failure-atomicity contract holds.

This is intentionally separate from Pass 37: Pass 37 is mutation-first across
the scoped implementation; Pass 41 is entry- and common-primitive-first
across the final production call graph.  Any finding restarts Passes 24
through 42 and all affected rootless, installed-kernel, Linux, 5BSD,
checkpoint, and soak evidence.

## Pass 42: independent implementation-defined contract replay

Without consulting any earlier private-interface inventory, reconstruct every
behavior not prescribed by the VirtIO specification, a processor manual, or a
public kernel ABI.  Begin at accepted configuration and operator surfaces,
emitted diagnostic/audit/DTrace records, and explicit unsupported results.
Include backend and provider choices, snapshot envelopes and compatibility
manifests, resource ceilings, allocation and retry policy, timeouts and
polling bounds, feature withholding, test-lab controls, CID and identity
allocation, MAC policy, and architecture-specific gates.

Each private contract must state its authority, validation, authorization,
namespace and generation binding, version/reserved-field handling, resource
owner, rollback or fail-closed behavior, observability, persistence exclusion
or explicit portable encoding, and both a positive and a rejection test.
Prove it cannot alter negotiated VirtIO semantics, a guest VMX/SVM outcome, a
common DMA/interrupt/snapshot invariant, or a test's evidence class.
Reconcile the resulting inventory with the documented private ledger only
after the consumer-derived reconstruction is complete.

Pass 42 is distinct from Passes 38 and 39: it checks the complete final
operator and non-standard contract graph, including intentionally unavailable
paths, rather than only individual policy or withheld-feature boundaries.
Any correction restarts Passes 24 through 44 and the complete final synthesis.

## Pass 43: clean-room kernel invariant replay

Repeat the final production-kernel review without using the preceding finding
lists, requirements ledger, or implementation-defined catalog as its starting
point.  Begin at externally reachable kernel and device-model entries, then
derive the state invariants from actual readers and writers: guest-memory and
DMA mappings, ring ownership, interrupt delivery, taskqueue/callout work,
sleep/wakeup, credentials and namespaces, module lifetime, PCI configuration,
snapshot dispatch, and VM-entry/exit boundaries.  Follow each invariant across
normal execution, allocation failure, malformed input, reset, suspend,
restore, detach, and cancellation.

For every mutation, identify the publication point, the last fallible action,
the rollback or rebuild rule, and an independent test that would fail if the
invariant were violated.  Explicitly search for stale callbacks, unchecked
return values, partial output aliases, native-layout persistence, host-page or
pointer assumptions, manual polling, unbounded waits, and feature-dependent
paths that can be reached after the feature is withheld.  Compare observable
guest behavior with the pinned VirtIO specification first; Linux and QEMU may
identify interoperability cases but cannot define the rule.  Any correction
restarts Passes 24 through 44 and all affected rootless and retained
privileged qualification gates.

## Pass 44: clean-room non-standard contract replay

Independently rebuild the implementation-defined inventory from production
callers, operators, diagnostics, and unsupported results.  Do not begin from
the prior private ledger.  Cover every host option and default, provider or
backend selection, resource cap, timeout/retry/polling policy, checkpoint
compatibility choice, test-lab control, audit/DTrace/MAC decision, CID or
identity allocator, and `ENOTSUP`/`EOPNOTSUPP` path.  For each, require an
explicit owner, input and authorization boundary, namespace/generation scope,
resource lifetime, no-publication failure path, observability, portable-state
treatment, and independently derived positive and rejection evidence.

Prove none of these private choices changes negotiated VirtIO semantics,
Intel/AMD guest architectural behavior, common VMM/DMA/interrupt/snapshot
contracts, or a test's evidence class.  Classify a difference from Linux or
QEMU as specification-required, compatibility-required, intentional and
documented, or defective; do not import their implementation.  A correction
restarts Passes 24 through 44 and the final synthesis.  A clean Pass 44 is
still source/model evidence only, not a substitute for installed-kernel,
Linux, 5BSD, checkpoint, or soak qualification.
