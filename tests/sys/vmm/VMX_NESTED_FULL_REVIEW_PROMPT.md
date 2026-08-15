# Intel nested-VMX conformance and qualification review

Review the scoped nested-VMX change as an Intel architectural implementation,
not as a collection of helper files.  Intel SDM revision 092 is normative.
The pinned Linux 7.2-rc4 KVM tree is a behavior and architecture comparison;
do not copy or mechanically translate GPL code.

Use these ledgers as the review boundary:

- `vmx-nested-requirements.tsv`
- `vmx-nested-live-qualification.tsv`
- `vmx_nested_state_test.c`

For every finding, identify the Intel requirement, production symbol, exact
operation sequence, observable failure, and missing or insufficient test.
Do not count a compiled path, CPUID bit, module attachment, L2 boot, or a
value-only model as live execution evidence.

## Mandatory doubled final-source review phases

Every production or test correction restarts these four phases on the new
byte-identical scope.  They are separate review results and may not reuse one
another's traversal, findings, ownership graph, private-interface inventory,
or compiler output:

1. Forward kernel review: start at allocation, initialization, admission, and
   publication; follow every owner through execution, rollback, reset, and
   destruction.
2. Definition-first non-standard review: inventory every FreeBSD/bhyve-only
   ABI, KPI, record, policy, limit, timeout, diagnostic, compatibility rule,
   and experimental control from its definition and producer.
3. Reverse kernel review: start at teardown, cancellation, failed restore,
   event consumption, interrupt/DMA revocation, and capacity exhaustion; walk
   backward to admission and allocation using fresh warnings-as-errors builds.
4. Consumer-first non-standard review: reconstruct accepted private values
   from decoders, ioctls, management tools, DTrace/audit/log consumers,
   checkpoint restore, compatibility fallbacks, and negative paths, then
   reconcile the result exactly with the definition-first inventory.

The two kernel phases must independently cover common VMM code and Intel
adapters.  The two non-standard phases must independently prove version,
owner, generation, architecture, backend, authorization, reserved-field,
rollback, fallback, and stable-error behavior.  A clean normative Intel
review cannot substitute for either private-interface phase.

Before any staged path is activated, repeat the same four directions at the
actual activation edge.  Compiled callbacks, model coverage, and teardown
assertions do not prove that production can reach the path in the required
execution context.  The activation replay must prove where the dispatcher is
called, which vCPU state and locks it owns, how it returns to the run loop, and
which public or private selector can enable it.  If no such caller exists, the
feature is staged and every activation surface must continue to fail closed.

## Pass 1: exposure and CPU-model consistency

Trace the boot-time host policy, per-guest option, VM-wide atomic freeze,
CPUID, VMX MSRs, instruction interception, reset, and snapshot restore.
Verify every vCPU sees one immutable CPU model.  Test matched enabled and
disabled guests and reject source/destination exposure changes even when no
vCPU entered VMX operation.  Confirm the default remains off.

## Pass 2: instruction and VM-entry semantics

Against the Intel SDM, exercise every supported VMX instruction:

- before VMXON, in VMX root operation, and from L2;
- valid, invalid, misaligned, inaccessible, and aliased operands;
- VMfailInvalid, VMfailValid, instruction-error publication, and exceptions;
- every implemented control, host-state, guest-state, event, PDPTE, linked
  VMCS, and MSR-list VM-entry failure class.

Expected values must come from independent SDM fixtures, not implementation
headers.  Compare Linux KVM selftest behavior and document every intentional
difference.

## Pass 3: real L2 execution and exit ownership

Run a Linux/KVM L1 twice: once with a Linux L2 and once with a disposable
5BSD L2.  Each feature group must execute a distinguishing operation and
correlate its guest result with the bhyve DTrace event or bounded diagnostic
counter for the exact host path.  Require:

- ordinary, synthetic, L1-requested, L0-owned, and failed-entry exits;
- exact VMCS12 exit fields and instruction length;
- external interrupt, NMI, interrupt-window, NMI-window, APIC priority, and
  blocked-delivery ownership;
- preemption timer, TSC offset/scaling, TSC writes, CPU migration, and
  IA32_TSC_AUX residency;
- EPT permission, violation, misconfiguration, A/D, stale-root, INVEPT,
  INVVPID, and concurrent invalidation paths.

If a guest lacks a driver or test facility, record `driver-gap` and add the
guest-side implementation to the roadmap.  Do not weaken the host test or
claim cross-guest coverage.

## Pass 4: lifecycle, concurrency, and failure recovery

Trace every VMCS, EPT root, VPID, pinned mapping, bitmap, MSR workspace,
continuation, and pending event from allocation through rollback and teardown.
Look for stale callbacks, wrong-CPU cleanup, missed invalidation, retry loops
without a changing generation, partial publication, and locks held across
faulting guest-memory access.

Inject failures at every preparation, hardware-entry, reflection, refreeze,
restore, and cleanup boundary.  Prove L1 remains runnable after a rejected
entry or restore.  Repeat create, run, reset, abort, destroy, CPU migration,
checkpoint, and restore concurrently.

For multi-vCPU active restore, fail after an earlier vCPU has staged a host
VPID and after an earlier MSR workspace has begun.  Prove the unpublished VPID
is returned exactly once, no destination owner or registry entry changes, and
a retry into a fresh destination succeeds.  Include allocator exhaustion,
VPID reuse on a different physical CPU, and the VMCS01-without-VPID fallback.

## Pass 5: save-state and portability

Verify the wire format is explicitly versioned, little-endian, bounded, and
free of pointers, descriptors, native padding, CPU-local VMCS state, and
physical resource identities.  Reject truncation, unknown flags, duplicate
owners, incompatible capabilities, changed exposure, and invalid generations
transactionally.  Check repeated active-L2 restore and failed restore without
altering the live source or destination.

Keep portable VM/device state separate from Intel-only CPU state.  Flag any
x86 assumption that escaped the Intel backend or any common VirtIO/migration
structure that depends on host word size, page size, or endianness.

## Pass 6: test integrity and operational behavior

Audit that every `exercised` live-ledger entry names:

1. a scheduled qualification case;
2. the Linux-L2 assertion;
3. the 5BSD-L2 assertion;
4. the exact host-side trace assertion.

Treat a label as routing metadata, not evidence.  Require each Linux-L2,
5BSD-L2, and host label to resolve to a distinct immutable artifact whose
versioned metadata names the feature and role and whose content includes the
actual guest assertion or host trace.  For every normative requirement,
require a distinct typed proof record containing its requirement ID, the
role-appropriate guest-test or host-trace kind, a stable execution label, and
a positive observation count.  Reject a group-level label replicated across
several requirements as insufficient evidence.  Verify the complete content-addressed
bundle is published atomically and reject missing, aliased, role-confused,
mutable, or extra artifacts.

The case must fail when the feature is hidden, declined, handled by a
fallback, or never reaches the expected host path.  Review timeout and
cleanup behavior, resource deltas, DTrace argument stability, rate-limited
diagnostics, and absence of polling where an event or generation boundary is
available.

## Pass 7: second independent kernel implementation review

### Mandatory four-phase restart rule

Every production change in this scope invalidates all four conclusions below,
even when it appears to affect only userspace or tests.  Run and record them
as distinct reviews:

1. a forward kernel ownership walk from allocation and admission through
   hardware execution and publication;
2. a definition-first inventory of every non-standard, private, experimental,
   diagnostic, resource-limit, and save-state value before looking at its
   consumers;
3. a reverse kernel walk beginning at final close, cancellation, reset,
   failed copyout, rollback, restore failure, and VM destruction; and
4. a consumer-first reconstruction of every non-standard value from ioctl,
   libvmmapi, bhyve, checkpoint, probe, sysctl, and test call sites back to its
   single owner.

The two kernel walks and two private-interface walks are independent phases,
not one review described four ways.  A fix found by any phase restarts all
four, and a clean model-only pass cannot substitute for either kernel walk.

After every fix from Passes 1 through 6, discard the earlier kernel-path
conclusions and retrace the production implementation from the outer VMM
entry points.  This is a new review, not verification that the first review's
findings were edited.  In particular:

- follow VMXON ownership, current-VMCS selection, VMCS02 construction,
  hardware entry, VM-exit capture, L1 reflection, refreeze, reset, and
  teardown through every success and failure edge;
- prove interrupts, preemption, GDTR, IDTR, LDTR, debug registers, guest/L1
  MSRs, TSC_AUX, EPT/pmap activity, the current hardware VMCS, and per-CPU
  VPID ownership are restored before their residency boundary ends;
- review lock ordering, generation checks, callback lifetime, guest-memory
  faults, partial publication, rollback failure, and fail-stop behavior from
  the actual Intel adapter rather than only the value-only model;
- compare the nested run loop with the ordinary VMX run loop and explain every
  ordering difference; and
- trace every exit completed by the architecture-neutral emulation layer back
  into the cold L2 image, including RIP, STI/MOVSS blocking, pending debug or
  monitor-trap work, restart, userspace return, and retry semantics; and
- require direct evidence for hardware-adapter boundaries.  A portable helper
  test or a successful kernel compile alone does not prove hardware residency.

Any modification made because of this pass invalidates its clean result.  Run
the pass again from a different entry point and with failure paths considered
before success paths.

This pass is the forward kernel-lifetime traversal: allocation,
initialization, publication, VMXON/entry use, revocation, and destruction.
Capture fresh warnings-as-errors diagnostics.  Repeating the same diff walk
does not constitute the second kernel review required by Pass 9.

## Pass 7A: architecture-record restore staging

Treat the VMX and SVM `STRUCT_VMCX` record as a kernel-private, fixed-order
wire decoder.  Starting at `vm_snapshot_req()`, determine whether every
restore failure can occur before the first architectural write.  Do not infer
that the surrounding userspace checkpoint transaction provides that property:
trace the individual VMCS/VMCB register, descriptor, and software-context
setters as well.

For each record element, classify decoding, range validation, semantic
validation, mutation, publication, and rollback ownership.  A malformed,
truncated, or otherwise rejected record must leave the destination's
architectural state unchanged.  If a hardware setter can fail after decoding,
stage a complete candidate and publish it only after all fallible work has
succeeded, or retain a complete rollback image and prove its exact recovery.
Do not add a public `VM_SNAPSHOT_VALIDATE` kernel operation merely to obtain a
second parser: it is intentionally a userspace codec operation.  The kernel
solution must preserve the existing wire format, keep source-host cache state
out of the portable image, and remain usable by non-Intel backends.

Add independent malformed-at-every-offset, setter-failure, retry, and
unchanged-destination tests.  Until those prove the property, record the
architecture record decoder as a non-atomic legacy boundary and do not claim
failure-atomic restore for VMCS/VMCB state.

## Pass 7B: private restore-contract reverse review

Rebuild the checkpoint contract from consumers: bhyve preflight, VMMDEV
snapshot dispatch, VMX/SVM setter helpers, architecture completion, device
rollback, and the resume gate.  Reconcile it with the definition-first
inventory without reusing Pass 7A's call graph.  Identify every private
promise about buffer consumption, error precedence, retained state, retry,
diagnostic output, and destination stoppage.  Reject any test that proves
only a model registry exchange while omitting the real VMCS/VMCB decoder.
Every new staging mechanism must have one owner, an explicit destruction
path, no native pointers or host cache identity in portable state, and a
bounded negative test for all reserved/unknown inputs.

## Pass 8: non-standard and experimental interface review

Inventory every behavior which is not defined by the Intel VMX architecture,
including bhyve configuration, CPUID exposure policy, loader tunables,
per-guest opt-in, private ioctls, snapshot envelopes, diagnostic counters,
DTrace argument contracts, timeouts, and implementation resource limits.
Classify each item as one of:

1. a private implementation detail with no guest or userspace ABI;
2. a documented bhyve compatibility contract;
3. a versioned private save-state or management ABI; or
4. an experimental guest-visible interface.

For each non-standard item, identify its owner, versioning rule, reserved-bit
policy, default, authorization boundary, compatibility promise, rollback
behavior, and negative test.  Experimental nested VMX and VPID exposure must
remain default-off, separately gated where their qualification differs, and
transactionally rejected when source and destination policy or capability
contracts differ.  Treat host-only exit controls such as bus-lock detection
and instruction timeout as an explicit exposure policy: an L0 exit must remain
safe if the outer VMCS enables it, but it must not be reflected to L1 until
its control, qualification, save-state, and live-test contract is versioned.
Private values must not enter Intel SDM fixtures, and
Linux KVM or QEMU behavior must not be presented as an architectural
requirement.  Unknown versions, flags, operations, and extensions must fail
closed without mutating live state.

Enumerate every compile-time VMCS/EPT/VPID cache bound, maximum record or
mapping count, timeout, retry count, polling cadence, rate limit, tunable,
sysctl, and guest-visible resource ceiling.  Classify each as
standard-derived, citing the exact Intel/PCI section and independent oracle,
or private policy, recording units, owner, default, mutability, authorization,
compatibility promise, rollback, and a direct boundary or negative test.
Linux/KVM and QEMU defaults are explanatory evidence only.

Treat common-to-architecture callbacks and frozen value bridges as private
kernel contracts too.  In particular, prove that generic instruction
emulation cannot advance an L2 `nextrip` without transactionally updating the
portable architecture state, and that an arbitrary userspace register change
cannot be mistaken for a successfully retired instruction.

## Pass 8A: architecture-specific assumption and workaround audit

Independently inventory every `XXX`, empirical observation, undocumented
priority ordering, compatibility workaround, and implementation-defined
hardware assumption in the VMX, SVM, IOMMU, interrupt, and snapshot paths.
Do not dismiss an item because the current host is Intel or because the path
is not reached by nested VMX.  For each item, identify the controlling Intel
SDM, AMD APM, PCI/IOMMU specification, or documented host policy; the exact
architectural scope; the normal and faulted execution path; the failure-safe
behavior; and the test hardware needed to qualify it.

Pay particular attention to NMI blocking around intercepted IRET.  VMX has
an architectural interruptibility-state recovery path when IRET faults; the
SVM implementation currently documents that a stack/NPT fault after it drops
the IRET intercept can permit a pending NMI too early.  Treat that as an
unresolved AMD correctness boundary, not an Intel result and not a reason to
invent an unreviewed emulation.  Require an AMD APM-backed design and an AMD
hardware fault-injection test before changing it.  Until then, preserve the
warning in the implementation, expose no claim of cross-architecture NMI
equivalence, and include it in the release qualification ledger.

The audit must also classify CPU-local cache invalidation, decoded-exit
assumptions, timer frequency defaults, IPI choice, interrupt ordering,
descriptor access, and device-model compatibility exceptions.  Every
unresolved item receives a bounded release gate or is removed; none is hidden
behind a generic "portable" label.  Repeat this audit from consumers to
definitions with a fresh source inventory after each correction.

Run this pass separately from architectural conformance.  A clean Intel-wire
review cannot approve a private ABI, and compatibility with Linux does not by
itself justify a non-standard guest-visible behavior.

## Pass 9: final kernel replay after private-interface review

Pass 8 can change policy and save-state code reached by the Intel execution
path, so repeat the kernel review after it.  This is the reverse lifetime
traversal.  Begin at VM teardown, restore
rollback, VM-exit publication, per-CPU residency release, and policy changes,
then trace backward to VMXON and VM-entry.  Compile the complete VMM module
with warnings as errors; treat signedness, alignment, atomic-object type, and
packed-member diagnostics as possible correctness findings.  Do not conceal a
real mismatch with a cast.  Record separately any compiler limitation caused
by a documented FreeBSD kernel extension.  A production fix invalidates both
Passes 7 and 9.  Produce fresh diagnostics from the post-private final source;
neither source conclusions nor compiler output from Pass 7 may be reused.

## Pass 10: private-interface composition and namespace separation

Compose all non-standard VMX interfaces: loader tunables, per-VM exposure,
CPUID policy, ioctls, snapshot records, migration contracts, counters,
timeouts, DTrace arguments, and resource limits.  Test wrong version, flags,
owner, VM, generation, capability digest, and source/destination policy in
combination.  Prove that private sentinels, exits, and record identifiers
cannot be mistaken for Intel architectural values or enter the SDM oracle.
Every composed contract must resolve to a ledger row and a real negative test
or explicit static review anchor.

## Pass 11: second independent non-standard inventory replay

Discard Pass 8's inventory conclusions and reconstruct the private-interface
set from production declarations and call sites, working from serialization,
ioctl, sysctl, tunable, DTrace, timeout, cache-bound, and experimental feature
uses back to their definitions.  Do not begin with the private ledger.  Diff
the reconstructed set against the ledger and classify every missing, stale,
or multiply-owned contract.  For each versioned record, decode every retained
legacy version and prove that new semantics cannot enter through an old
wrapper, reserved flag, or mismatched nested subrecord.  For every private
limit, exercise minimum, maximum, maximum-plus-one, exhaustion, retry, and
rollback.  This pass must produce its own clean result after Pass 10; edits to
code, tests, or the ledger invalidate both Passes 8 and 11.

## Pass 12: final cross-layer synthesis

Repeat the kernel review one final time around the boundaries changed by the
two non-standard reviews.  Start with a guest-observable operation and trace
simultaneously through the Intel architectural contract, private policy,
portable state, hardware owner, rollback, test oracle, and live evidence.
Then repeat in reverse from teardown or failed restore.  Verify that each
advertised control has complete semantics on hardware exits and L0-emulated
instruction paths, and that withholding an incomplete feature is consistent
across legacy and true VMX MSRs, VMCS validation, checkpoint compatibility,
documentation, and live-test scheduling.  No conclusion or compiler artifact
from Pass 7 or Pass 9 may be reused.  A production change restarts Passes 7
through 14.

## Pass 13: independent kernel transaction replay

Perform a second review of the final kernel source without using the findings,
checklists, or traversal order from Passes 7, 9, or 12.  Start at each
transactional publication point: VMCS ownership, VMCS02 hardware programming,
portable L2 instruction completion, pending-event consumption, VM-exit
reflection, active checkpoint capture, active restore, reset, and teardown.
For every operation, enumerate all mutable inputs, immutable identities,
generation and capability digests, output aliases, and rollback owners.  Then
prove that every validation failure leaves all owners and caller outputs
unchanged.  Pay particular attention to values which are valid independently
but stale in combination, including a current capability object paired with an
older portable image or frozen plan.

Repeat the traversal from the hardware adapter inward and from the portable
state outward.  Compare both results.  A value-only test does not approve a
kernel adapter, and a warning-clean kernel build does not approve a state
transaction.  Any production correction invalidates this pass and requires a
fresh replay after Passes 8, 11, and 14 are also current.

## Pass 14: independent non-standard contract reconciliation

Reconstruct every non-Intel contract from the final kernel and management
source without starting from the private-interface ledger.  Inventory record
magic and versions, legacy decoders, flags, sentinels, tunables, sysctls,
ioctls, counters, DTrace arguments, timeouts, fixed capacities, experimental
feature gates, common-VMM callbacks, and architecture-adapter handoffs.  For
each item, reconcile definition, every producer, every consumer, documentation,
ledger ownership, negative tests, and rollback behavior.

Compose independently valid private records and policies in invalid pairs:
old outer record with new inner record, changed capability digest with an
otherwise valid frozen plan, disabled exposure with retained state, reused
generation with a different owner, and valid records from a different VM or
destination policy.  Unknown or mismatched combinations must fail before any
live-state mutation.  Confirm that private numbers never enter the independent
Intel oracle and that explanatory Linux or QEMU behavior is not promoted to an
architectural rule.  A code, ledger, documentation, or test change invalidates
this pass; rerun Pass 13 afterward so the final kernel and private reviews
describe exactly the same source.

## Pass 15: kernel/private adapter failure-atomicity replay

Review the final kernel a second time specifically where an Intel-defined
operation crosses a bhyve-private adapter: generic event ownership into Intel
priority, common instruction completion into a cold L2 image, portable state
into VMCS02 resources, private handoffs into VMCS12 publication, and VMS2
records into live owners.  Start from the private adapter rather than the VMX
instruction.  For every callback and helper, list the last fallible operation,
the first live mutation, the retry identity, and the rollback or quarantine
owner.  Reject any path that mutates a live owner before a later allocation,
lock acquisition, guest-memory access, hardware operation, result-domain
validation, or handoff publication can fail.

Repeat with failures injected conceptually at every call boundary and in
reverse order.  Prove that retry cannot retire an instruction twice, consume
an event twice, reuse a stale generation, publish the original exit as a
synthetic exit, or pair staged hardware resources with a different portable
image.  Require a kernel-source anchor and a value-level negative test where
hardware injection is not rootlessly available.  A clean Pass 13 does not
satisfy this adapter-specific replay.

## Pass 16: withheld, unsupported, and implementation-defined behavior review

Inventory every standard feature bit, exit, event, state field, and lifecycle
operation which is parsed or modeled but not advertised or fully executed.
For each one, prove one of: complete implementation and live qualification;
consistent withholding at every exposure surface; or an explicit fail-closed
internal guard with no guest-reachable partial semantics.  Review non-standard
fallbacks, fixed limits, default-off policies, manual waits, polling, debug
paths, compatibility decoders, and provisional save-state records for dead
code, accidental activation, stale documentation, and unbounded behavior.

Compare each decision independently with the Intel SDM, the pinned Linux KVM
implementation, and the pinned QEMU management/migration behavior.  Classify
differences as architectural, compatibility, private policy, or unfinished;
never treat Linux or QEMU as the normative source.  Tests must demonstrate
that hidden features are actually rejected and that fallback paths cannot
make a positive qualification pass.  A production correction restarts Passes
7 through 16, including both kernel reviews and both independently rebuilt
non-standard inventories.

## Pass 17: shared-kernel ownership and execution-context review

Review the final kernel again from the machine-independent VMM boundary rather
than from Intel VMX.  Enumerate every caller of each event publisher, snapshot
callback, rendezvous callback, interrupt injection helper, callout, taskqueue,
and architecture operation.  For every call edge, record whether it can run in
thread, spin-lock, interrupt, callout, or teardown context and whether it may
sleep, allocate, fault on guest memory, notify a vCPU, or acquire another
owner.  Reject an architecture-neutral interface whose contract is only safe
because of an undocumented amd64 or Intel caller assumption.

Trace freeze, event-ingress exclusion, immutable capture, userspace
publication, restore planning, all-vCPU publication, abort, and source resume
as one coordinator transaction.  A generation comparison detects overlapping
publishers but is not an ingress lease: prove separately how publishers after
the final comparison are excluded or retained until publication completes.
Internal LAPIC/timer events must not be silently dropped merely because a
checkpoint is active.  Require explicit lock order, bounded/no-wait behavior
where required, teardown wakeup, stale-token rejection, and unchanged state on
every failed transition.  Common state must remain architecture-neutral;
Intel-only state belongs in an explicitly versioned architecture section.

This is a second kernel-code review with a different root and execution-context
model from Passes 7, 9, 12, 13, and 15.  A value-only model or an amd64 module
build does not prove execution-context safety.  Any production correction
restarts this pass and the non-standard compatibility review in Pass 18.

## Pass 18: non-standard dispatch, compatibility, and operator-policy review

Reconstruct every non-standard interface by starting at the code which accepts
or emits it: ioctl dispatch, snapshot record-name tables, legacy decoders,
management manifests, tunables, sysctls, DTrace probes, audit records, rate-
limited diagnostics, backend identities, and experimental feature exposure.
For each accepted value, identify exactly one owner and classification:
historical compatibility ABI, versioned private ABI, operator policy,
implementation detail, or unfinished/unadvertised feature.

Exercise explicit legacy-versus-current selection, unknown names and versions,
truncation, extension bytes, reserved fields, wrong architecture, wrong VM,
wrong destination topology, wrong backend identity, stale generation, disabled
feature, partial restore, and abort-after-publication failure.  Legacy native
records must not silently acquire current semantics, and a current record must
not fall back to a legacy decoder.  Parsed or modeled features which remain
unsupported must be consistently withheld across CPUID/MSRs, PCI features,
ioctls, save-state, documentation, and test scheduling.  Fixed limits,
timeouts, retries, polling, and fallback behavior are private policy and need
units, defaults, authorization, mutation rules, rollback, observability, and
boundary tests.

Compare observable behavior with the pinned Linux and QEMU revisions without
turning either implementation into a normative oracle.  Then replay Pass 17
from teardown toward publication so both reviews describe the identical final
kernel.  Any code, ledger, test, or documentation correction invalidates both
Passes 17 and 18 as well as the earlier phase whose scope it changed.

## Pass 19: final-source kernel teardown and publication review

Discard the Pass 17 trace and review the corrected kernel from two independent
roots: VM/vCPU destruction and asynchronous event publication.  Meet at the
coordinator boundary and prove external pointer stability, admission closure,
waiter and publisher drain, stable all-vCPU lock order, exact-member rollback,
and release after callees consume or zero transaction records.  Audit every
failure between portable capture, architecture staging, hardware ownership,
userspace copyout, abort, and source resume.  Require fresh Werror diagnostics
and focused failure evidence; Pass 17 cannot satisfy this phase.

## Pass 20: final-source private ABI and compatibility review

Discard the Pass 18 inventory and rediscover non-standard behavior from every
decoder, retained checkpoint, installed management consumer, sysctl/tunable,
probe, audit event, diagnostic, backend reconstructor, and experimental gate.
Compose every value with wrong lifecycle owner, generation, architecture,
topology, backend, authorization, namespace, version, and legacy/current
selector.  Prove that kernel-only locks, pointers, credentials, tickets,
cookies, file descriptors, and hardware residency identities cannot be
serialized.  Any finding restarts Passes 19 and 20 and the earlier affected
phase; a clean producer-side inventory is not reusable evidence.

## Pass 21: second final-source kernel implementation review

Discard every earlier kernel trace and review the final source line by line
from the machine-independent VM lifetime boundary.  Begin independently at
VM creation/reset/destruction, vCPU activation/freeze/thaw, interrupt and
exception publication, snapshot copyout/import, module unload, and backend
failure.  For each object, identify its allocation owner, pointer-stability
authority, admission gate, lock order, sleepability, cancellation point,
drain condition, final release, and rollback owner.  Trace both the forward
success path and the reverse destruction path until they meet; do not accept
a generation counter as a substitute for retained ingress exclusion.

Review release-kernel behavior separately from INVARIANTS diagnostics.  A
panic is acceptable only for a proved impossible internal invariant whose
caller has no recovery contract; externally triggerable resource exhaustion,
version skew, malformed state, or backend failure must return a stable error
without partial publication.  Recheck all architecture-neutral code on
amd64, arm64, and riscv assumptions, and isolate Intel-only operations behind
explicit adapters.  Require fresh Werror builds and focused negative tests.
For every finite generation, sequence, ticket, and claim namespace, also prove
that exhaustion cannot prevent release of ownership already acquired; an
exhausted counter may close new admission but must not strand teardown.
This is the second final-source kernel review and cannot reuse Pass 19.

For INIT/SIPI, trace the completion owner past kernel exit construction and
`VM_RUN` copyout.  Copying `VM_EXITCODE_IPI` or the legacy
`VM_EXITCODE_SPINUP_AP` payload to userspace is not proof that userspace
suspended, reset, programmed, or resumed the target.  Reject a target-local
design which makes an AP suspended by INIT responsible for running again in
order to deliver its later SIPI.  Any new kernel-owned startup mode must be an
explicit, immutable per-VM capability with complete reset/register/APIC
semantics; any userspace-owned mode must retain an exact claim until a
versioned, target-specific acknowledgment identifies the completed side
effect.  Mixed L0/L2 destination sets, partial userspace failure, copyout
failure, process death, reset, checkpoint, and destroy must each have one
unambiguous release owner.

Before reading, create a sorted source manifest from both modified tracked
files and untracked production or test files in scope.  Hash every manifest
member before Pass 21 and again after Pass 22.  `git diff --name-only` is not
sufficient because it omits newly created, untracked kernel sources.  Reject
the review evidence if either the manifest membership or any file hash changes;
restart Passes 19 through 22 from the new complete manifest.

## Pass 22: second final-source non-standard and private-policy review

After Pass 21, discard Pass 20's inventory and rediscover every behavior not
defined by the Intel SDM from actual producers and consumers.  Include kernel
coordination tokens, internal exits, checkpoint envelopes, compatibility
decoders, ioctls, sysctls, tunables, resource ceilings, retry or timeout
policy, probes, audit records, diagnostics, management manifests, and
experimental exposure switches.  Classify each as transient implementation
detail, compatibility ABI, versioned private ABI, operator policy, or
unfinished feature; record its owner, units, default, authorization,
versioning, reserved fields, rollback, observability, and direct rejection
test.

Compose valid private values in invalid contexts: wrong VM incarnation,
vCPU, generation, architecture, backend, credential, namespace, version,
outer/inner record pairing, and feature policy.  Prove that transient kernel
pointers, locks, tickets, cookies, credentials, file descriptors, and
hardware-residency identities are neither serialized nor treated as Intel
architectural state.  Linux/KVM and QEMU are behavioral comparisons only;
they cannot define these FreeBSD-private contracts.  Any finding restarts
Passes 19 through 22 and the earlier affected phase.

Treat the modern IPI exit, legacy SPINUP_AP exit, any completion token or
ioctl, and any opt-in kernel-owned startup capability as separate
FreeBSD-private compatibility contracts.  Record exact structure layout,
copyout behavior, source and target identity, token namespace, retry and
duplicate-ack behavior, old-userspace fallback, Capsicum/ioctl authorization,
checkpoint exclusion or encoding, and teardown disposition.  A claim may not
be finished merely because an exit was selected or copied out, and an older
consumer may not accidentally opt into semantics which require an
acknowledgment it cannot send.

## Pass 23: production activation-edge kernel review

Discard the earlier forward traces and start at every place production can
cross from staged state into execution: `vm_run()` restart, machine-dependent
run entry, internal-exit redispatch, vLAPIC INIT/SIPI publication, restore,
reset, and management configuration.  Prove that the complete transaction is
reachable exactly once in the execution context required by its contract.
Record the vCPU state, critical-section state, interrupt state, sleepability,
and every held lock at the call edge.  A callback which requires
`VCPU_FROZEN` must not first be invoked by a machine run callback after common
code has changed the vCPU to `VCPU_RUNNING`.

Trace the successful result back into the common restart loop and prove the
next RIP, startup-wait membership, event ownership, nested context, vLAPIC,
and translation state become visible atomically.  Trace every error to one
stable retry or terminal disposition.  Absence of a production caller is not
a harmless omission: record the path as staged, keep every selector disabled,
and require a direct negative test for the activation boundary.

## Pass 24: definition-first staged and private activation review

Without consulting Pass 23's call graph, inventory every declaration which
could activate or describe the staged path: feature flag, ioctl, sysctl,
tunable, config option, callback table, internal exit, command number, status
enum, checkpoint field, probe, diagnostic, and test-suite selector.  For each
one record whether it is staged, supported, deprecated, or compatibility-only
and identify its single authority for changing that classification.

Prove staged values cannot mutate VM state, advertise guest capability, be
serialized as active state, or be selected by an older userspace consumer.
Unknown and unsupported activation requests must fail before controller,
claim, event, register, LAPIC, translation, or scheduler mutation.  A source
build and a rootless model are staging evidence only.

## Pass 25: reverse activation and teardown kernel review

Begin independently at module unload, VM destruction, controller final close,
claim abort, reset, restore failure, target suspension, and a finalizer panic
boundary.  Walk backward until each path meets its admission and production
dispatch edge.  Prove a pending or in-progress startup transaction has one
release owner and cannot strand a frozen target, startup-wait bit, publisher
lease, nested resource, VMCS selection, EPT/VPID owner, timer, or event.

Review the ordinary L0 run path and nested L2 path separately.  Compare INIT
and SIPI separately: INIT resets nested/LAPIC/translation state while SIPI
preserves those owners and changes only the architectural entry state and
startup wait.  Require fresh warnings-as-errors output after this traversal;
Pass 23 compiler output cannot be reused.

## Pass 26: consumer-first operational and compatibility review

Start from bhyve, libvmmapi, ioctl decoders, checkpoint tools, DTrace scripts,
audit/log consumers, and the qualification orchestrator.  Reconstruct every
activation value and expected result back to its kernel definition.  Prove
the consumer can distinguish unsupported, staged, retryable, committed,
aborted, and compatibility-fallback outcomes without polling or guessing from
an unrelated VM exit.

Compose each valid request with the wrong file description, credential, VM,
vCPU, generation, architecture, backend, checkpoint incarnation, and legacy
consumer.  Verify the independent test oracle uses literal private wire values
and normative Intel values from the pinned SDM fixture rather than production
headers.  Passes 23 through 26 describe one byte-identical manifest; any code,
test, ledger, or documentation correction restarts all four as well as the
earlier affected review.

## Pass 27: independent second kernel-code review

Set aside the Pass 23 and Pass 25 traces and assign no correctness credit for
their conclusions.  Read the byte-identical final kernel source again in a
different order: begin at each callback invocation and error return, expand
outward to its caller, then trace forward through the next ownership transfer.
For multi-callback operations, snapshot the complete callback identity before
the first call and prove a callback cannot redirect a later callback before
corruption is detected.  Recheck failure atomicity at every preflight/commit
boundary, including release kernels without diagnostic assertions.

Repeat the object-lifetime review for claims, wait tickets, controller
credentials, vCPU state, LAPIC state, translation owners, VMCS resources, and
checkpoint transactions.  Review the ordinary L0 and active-L2 paths as
separate implementations.  Require a fresh warnings-as-errors kernel build
and focused regression evidence generated after this pass.  A finding in this
phase restarts Passes 23 through 28.

## Pass 28: independent non-standard-interface lifecycle review

Discard the Pass 24 and Pass 26 inventories.  Rediscover every non-SDM value
from definitions first and then, in a separate traversal, from consumers
first.  Include private kernel callback tables, command numbers, fixed-width
ioctl payloads, compatibility exits, status and errno vocabularies, sysctls,
tunables, probes, diagnostics, checkpoint envelopes, test selectors, and
unfinished activation gates.  For each interface record introduction,
versioning, authorization, namespace, reserved fields, copyin/copyout
failure, retry/duplicate behavior, reset/close/destroy disposition,
observability, compatibility promise, and retirement rule.

Compose valid values with the wrong owner, VM, vCPU, generation, file
description, architecture, backend, checkpoint incarnation, and old consumer.
Verify unsupported or staged interfaces fail before mutation and cannot be
mistaken for an Intel architectural feature.  Confirm test oracles use pinned
normative fixtures or independent private literals, never the implementation
header under test.  Linux and QEMU remain comparison material and do not
define FreeBSD-private policy.  Pass 28 is clean only when its definition-first
and consumer-first inventories reconcile exactly with the non-standard ledger.

## Pass 29: second kernel-primitive lifecycle review

Start below the nested-VMX implementation and inspect every common kernel
primitive that a production activation path would call.  Trace host timers,
callouts, sleep queues, rendezvous locks, translation caches, interrupt state,
and vCPU state transitions across INIT, SIPI, reset, suspend, restore, destroy,
and interrupted operations.  Verify that resetting architectural state also
cancels or invalidates every host-side asynchronous producer of that state.
Do not accept a correct value model as evidence that an existing kernel
primitive has the required concurrency semantics.  Record and fix stale
callbacks, lock-order inversions, non-atomic publication, and post-reset work.

## Pass 30: second private-boundary activation review

Rebuild the inventory of every FreeBSD-private command, callback table,
generation, storage cookie, owner token, feature gate, sysctl, and temporary
policy used by the activation path.  Review definition-to-consumer and
consumer-to-definition independently.  Require one explicit unsupported result
while activation is withheld, named semantic comparisons instead of object
representation, immutable callback identity across compound operations, and a
documented retirement or compatibility plan.  Then trace the boundary into the
common kernel primitives from Pass 29 and prove that no private success result
can precede all fallible preflight work.

## Pass 31: doubled kernel callback-context and irreversible-tail review

Discard the conclusions of Passes 27 and 29 and review the final kernel once
more from every indirect call and irreversible publication.  For each callback
table, validate the complete table before any member is dereferenced, bind its
identity for the whole compound operation, and classify the callback's actual
execution context, sleepability, allocation behavior, lock acquisitions,
failure domain, and ownership transfer.  Trace successful and malformed
providers separately.  A quiescence predicate is not sufficient evidence for
an irreversible finalizer: prove that every operation after event or state
commit is infallible, allocation-free, nonblocking, and cannot initiate a
cross-CPU drain.  Move vmspace, pmap, backend, and other potentially sleeping
destruction into a fallible precommit preparation phase, or keep the production
activation gate closed with an explicit ledger blocker.

Repeat from teardown toward publication and from publication toward teardown.
Require unchanged caller outputs and live owners for every rejected callback
table, negative callback errno, reentry, stale reference, and partial provider
result.  Generate fresh warnings-as-errors and focused negative-test evidence
after this pass; earlier compiler output cannot satisfy it.

## Pass 32: doubled non-standard provider and policy-domain review

Reconstruct every non-SDM provider table and lifecycle policy twice: first from
its definition and owner, then independently from every consumer and error
return.  Include callback completeness, opaque backend objects, derived-cache
retirement, fixed capacities, generation exhaustion, retry classification,
experimental gates, panic boundaries, diagnostics, probes, and checkpoint
exclusion.  Verify each private error distinguishes malformed, stale, busy,
unsupported, and exhausted state without being confused with an Intel VMX
instruction result or guest-visible architectural status.

Compose complete providers with malformed cache state and valid cache state
with incomplete providers.  Exercise every public entry point, not only the
checkpoint/quiesce path, and prove the hot path performs bounded validation
while the full duplicate/ownership scan remains at lifecycle boundaries.
Compare the resulting policy with pinned Linux and QEMU behavior only as an
implementation reference.  Any code, test, ledger, or documentation change
restarts Passes 31 through 34 and the earlier affected phase.

## Pass 33: independent second kernel-code review

Start from a clean finding list and review the compiled kernel paths a second
time without reusing Pass 31's callback inventory.  Traverse each public and
private entry point forward into locks, allocations, hardware mutation,
cross-CPU work, publication, and teardown; then independently traverse every
cleanup and restore path backward to its admitting validator.  Include common
VMM, vLAPIC, VMX, pmap/vmspace, callout, rendezvous, character-device, and
snapshot code reached by nested VMX.  Check positive errno domains, ownership
and generation composition, sleeping and allocation context, lock order,
integer and address overflow, output aliasing, partial rollback, module unload,
and stale work after reset.  Do not treat a model test or a prior private-table
review as proof of the kernel integration.  Record new source anchors and
focused negative evidence, or explicitly record a clean independent pass.

## Pass 34: independent second non-standard-interface review

Discard Pass 32's inventory and reconstruct all behavior not defined by the
Intel SDM: callback tables, owner records, provider identifiers, generations,
resource caps, checkpoint envelopes, errno/status mappings, sysctls, ioctls,
feature gates, probes, diagnostics, and test-only controls.  Begin once from
definitions and once from consumers.  For compound operations, prove callback
identity is captured before the first callback and that rollback uses the same
provider and concrete resource generation; distinguish provider identity from
per-vCPU resource identity.  Verify runtime-only identities never enter the
portable wire format.  Require wrong-provider, stale-generation, malformed,
busy, unsupported, reentrant, and partial-completion tests with unchanged
owners and outputs.  Reconcile both inventories exactly with the private
ledger.  Changes restart Passes 31 through 34.

## Pass 35: post-preparation final kernel-code replay

After any change to a fallible preparation callback or an irreversible
architectural tail, discard the earlier kernel traces and review the exact
final source twice.  The forward traversal starts at event admission and
follows the frozen target, exact claim, provider snapshot, preparation,
architectural apply, publication, wakeup, and teardown.  The reverse traversal
starts at every prepare/apply error, reset, detach, destroy, callback failure,
and retry and proves which state is architectural, derived, reconstructible,
retained, rolled back, or deliberately poisoned.  Include common VMM,
vLAPIC, VMX, EPT/pmap/vmspace, rendezvous, sleepqueue, cdev, and snapshot
paths.  A model result cannot substitute for a warning-clean kernel build or
for the separately recorded installed-kernel gates.

## Pass 36: post-preparation final non-standard contract replay

Reconstruct every behavior in the Pass 35 path that is not defined by the
Intel SDM without consulting the existing private ledger first.  Inventory
provider tables, prepare/apply separation, derived-cache retirement, owner and
generation cookies, errno mapping, feature gates, ioctls, checkpoint records,
debug controls, and withheld activation.  Then reconcile the definition-first
and consumer-first inventories with exactly one private-ledger row each.
Prove with independent negative tests that a private preparation success cannot
weaken an Intel architectural validator, a failed apply cannot hide
architectural mutation, SIPI cannot inherit INIT-only retirement, and no
runtime pointer, callback, lock, or provider identity enters portable state.
Any code, test, ledger, or documentation correction restarts Passes 35 and 36.

## Pass 37: dormant and unsupported kernel-code replay

Review every compiled kernel path that is deliberately unreachable, returns
`ENOTSUP` or `EOPNOTSUPP`, or is guarded by a false readiness predicate as if
it were about to be enabled.  Start once from the disabled public or private
entry point and follow every validator, provider snapshot, fallible
preparation, reversible mutation, irreversible finalizer, wakeup, and cleanup.
Then start from each dormant callback and work backward to prove that no
current caller can reach it and that removing any one gate would still leave a
complete, failure-atomic transaction.  Check stack-owned bindings and
finalizers, callback argument lifetime, provider immutability, positive errno
classification, retry state, derived-cache loss, and cleanup after partial
preparation.  Mechanically verify the call graph and gate rather than relying
on comments.  Unsupported code must be warning-clean and tested; unreachable
does not mean exempt from kernel review.  Treat every negative status returned
by a private mutating callback as a malformed-provider result: prove it cannot
leave a durable owner retryable, cannot repeat a possibly ambiguous callback,
and cannot release an exact claim merely to recover.

## Pass 38: implementation-defined and non-standard behavior replay

Without consulting the private-interface ledger, reconstruct every behavior
in the Pass 37 scope that is not prescribed by the Intel SDM: readiness gates,
private ioctls, provider and storage cookies, callback tables, retry/result
vocabulary, cache-retirement policy, fail-stop choices, debug and tracing
controls, checkpoint envelopes, and operator-visible errors.  Repeat the
inventory from consumers and teardown paths, then reconcile both inventories
with the ledger.  For each behavior, identify its owner, lifetime, concurrency
domain, compatibility promise, architecture scope, portable-state status, and
negative test.  Prove that a private policy cannot relax an architectural
validator, that no runtime pointer or provider identity is serialized, and
that unsupported or withheld behavior is reported consistently without
advertising a guest feature.  Reconcile every private callback's result domain
as well as its signature: zero, positive errno, explicit disposition, unknown
value, and contradictory result pairs must each have one documented owner
transition.  Any finding restarts Passes 35 through 38.

The first Pass 7/8 application retraced VMX-region identity from instruction
decode through VMCS02 programming, active-L2 checkpoint, continuation restore,
and the Intel-only residency adapters.  It found that two private checkpoint
validators had independently treated guest-physical address zero as invalid,
although Intel permits an aligned VMX region there and the instruction model
already did.  The VMCS02 identity predicate is now shared by the portable,
continuation, lifecycle, and Intel resource boundaries; it accepts GPA zero,
rejects the private `UINT64_MAX` sentinel and unaligned values, and is covered
by independent operand and wire-format tests.  The sentinel is separately
classified in the non-standard-interface ledger so it cannot be mistaken for
an Intel architectural restriction.  Because this pass changed production
code, it does not count as the final clean Pass 7/8 cycle.

The second non-privileged Pass 7/8 application began at EPT-exit and failed
late-entry paths rather than instruction decode.  It found five additional
kernel value boundaries which had copied only part of the VMCS02 identity
contract.  EPT-exit planning, hardware-program construction and application,
refreeze, and late-entry recovery now call the same predicate, including its
alignment and private-sentinel rules.  The requirements validator enumerates
all known identity consumers and fails if one stops using the predicate.  It
also freezes and inventories the Intel guest-memory adapter's private
one-page/two-segment resource bound, the 144-field VMCS02 programming bound,
and both versions of the composite checkpoint envelope.  The sanitizer model,
requirements validator, and `vmm.ko` `-Werror` build pass after these changes.
This records a clean source/model cycle only; it does not replace the rebuilt-
kernel Intel hardware, Linux-L1/Linux-L2, 5BSD-L2, checkpoint, concurrency,
fault, and soak evidence required by the termination condition.

The test-quality rotation then reviewed the anti-drift gate itself.  Its
identity-equality inventory incorrectly included the transactional VMCS02
program applier, which carries one immutable identity into `begin()` and the
result but never compares two independently sourced identities.  Requiring a
helper call there would have encouraged a meaningless self-comparison merely
to satisfy a textual oracle.  The inventory now covers only actual identity
comparators; validity remains checked independently in the applier.  The
206-entry requirements validator, 33-entry non-standard-interface inventory,
policy-pair verifier, live-staging verifier, coverage verifier, and evidence
verifier all pass after that correction.

The following independent private-ABI rotation checked the non-standard
interface inventory as test evidence rather than accepting its prose.  It
found six stale negative-test names and semantic labels which resolved to no
ATF case or review-script anchor.  The ledger now names the actual exposure,
canonical-wire, registry-capacity, VPID-residency, VMCS-store, and timeout
tests.  The requirements validator resolves every semicolon-delimited claim
to a real ATF declaration or an explicit script anchor and separately proves
that the kernel-private internal-exit value is consumed by the frozen common
VM_RUN dispatcher.  A future rename or prose-only private contract therefore
fails the same gate as architectural requirement drift.

The next test-quality rotation ran the entire nested model under ASan and
UBSan from an interactive terminal.  All 148 model cases passed, but cleanup
of deliberately sealed read-only evidence could invoke FreeBSD `rm`'s
terminal confirmation and stall an otherwise automated gate.  Every nested
self-test cleanup now restores owner read/write/search permissions before
removing its exact private temporary directory.  This is test-orchestration
correctness only; it is not Intel hardware qualification.

The first Pass 9 compiler replay built the complete amd64 VMM module with
warnings promoted to errors.  It found a negative `hw.vmm.maxcpu` tunable
could wrap through unsigned storage, atomic objects whose signed types did not
match the kernel atomic API, VMX byte buffers declared as plain `char`, and an
AMD CPUID path taking the address of a packed VMCB member.  The tunable is now
validated in signed storage before publication, atomic state uses the API's
unsigned object type on both amd64 and arm64 boundaries, byte buffers use
`uint8_t`, and SVM stages CPUID registers in aligned locals.  The complete
`vmm.ko` build passes with `-Werror`; only Clang's inability to model the
FreeBSD kernel `%b` format extension is suppressed for that completeness
build.  This source/compiler result still requires rebuilt-kernel Intel and
AMD live qualification where hardware is available.

The following Pass 8/10 inventory replay began with concrete production
storage rather than the existing ledger.  It found that the eight-entry
per-vCPU EPT02 root cache and the 512-field-per-image private checkpoint bound
were enforced and negatively tested but were not classified as bhyve resource
policy.  Both limits now have explicit private-interface rows describing
ownership, exhaustion behavior, rollback, serialization, and independent
tests.  The validator pins each production declaration to its ledger row and
keeps the checkpoint test's literal bound independent from the kernel header.
Neither limit may therefore be mistaken for an Intel architectural maximum.
This changed review evidence and requires the final Pass 9 reverse kernel
replay to continue through restore publication, teardown, and VM-entry.

The next Pass 9/10 composition replay followed the VM-level exposure header,
registry record, per-vCPU record, and final registry/workspace swap as one
restore transaction.  It found that a disabled legacy exposure envelope could
carry a syntactically valid non-empty private VMCS registry.  The hidden state
could not become guest-visible because the destination CPU model was already
frozen without VMX, but accepting it violated the cross-record contract and
weakened malformed-checkpoint rejection.  VM-level staging now rejects that
combination before publication.  The model independently checks zero, one,
and maximum registry counts; the requirements validator pins the production
call site; the ASan/UBSan model and complete `vmm.ko` `-Werror` build pass.
Because this changed production restore policy, both kernel passes restart.

The restarted reverse publication review then found a destination-local VPID
ownership hole: final VM-wide restore validation rejected an occupied host
VPID only when the incoming record represented active L2 execution.  An
inactive incoming vCPU could therefore overwrite a destination with an active
owner or a pending pre-allocation invalidation.  Restore now validates every
present destination owner before registry publication, independently of the
incoming active bit.  The model covers empty, pending-flush, and active-owner
destinations; the requirement ledger pins the production helper; the full
`vmm.ko` warning-clean build and the 148-case ASan/UBSan model pass.  This
production correction restarts both kernel passes and the private-boundary
composition pass again.

The next forward kernel/control-policy replay traced an L2 instruction from
EPT/MMIO exit through common emulation, the frozen continuation, VMCS02 thaw,
and event arbitration.  The continuation now commits the decoded instruction
boundary transactionally, but no production owner yet preserves a pending
monitor-trap exit across that L0 completion.  The virtual primary-control MSR
nevertheless inherited hardware support for MTF exiting.  That made an
allowed-one control a guest ABI promise whose emulated-instruction semantics
were incomplete.  Production now withholds primary-control bit 27 until the
generation-bound pending owner, Intel priority arbitration, reset/teardown,
checkpoint reconstruction, and Linux plus 5BSD live proof exist.  The
negative fixture uses the independent SDM bit number, the exposure decision
has its own private-interface row, and the validator binds the mask, ledger,
and test.  Hardware MTF exits forced by architected entry-event behavior
remain classified and safely routable.  This production policy correction
invalidates the current Passes 7 through 10; both kernel traversals and both
private-interface passes must run again on the final source.

The restarted reverse traversal began at active-L2 restore rejection and
followed the canonical capability record and signature through VMCS-registry
replacement, per-vCPU publication, nested RDMSR dispatch, module policy
construction, and the raw-hardware control reader.  There is one guest MSR
adapter, and it reads only the immutable filtered virtual policy; raw host
VMX MSRs are inputs only to policy construction.  Both legacy
IA32_VMX_PROCBASED_CTLS and IA32_VMX_TRUE_PROCBASED_CTLS now have direct
independent bit-27 rejection checks.  Version-2 registry restore compares the
complete canonical capability object as well as its signature, so a snapshot
from the earlier MTF-advertising contract is rejected rather than silently
accepted.  The separate non-standard inventory and composed-boundary replay
found no additional MTF exposure path.  The 210-entry requirements validator,
37-entry private-interface validator, 149-case model, ASan/UBSan model, and
complete amd64 VMM warnings-as-errors build pass on this final source.  MTF
remains a tracked deferred feature, not an advertised partial implementation.

The following forward and reverse kernel reviews revisited the withheld MTF
path without treating withholding as completion.  The forward traversal from
L0 instruction emulation found that retired RIP and STI/MOVSS state had an
exact cold owner, but pending MTF had none.  The portable image now owns MTF by
generation, refuses another retirement until it is consumed, synthesizes only
the Intel exit-reason-37 image, and preserves the owner through the sole
current little-endian portable and continuation records while rejecting every
obsolete development encoding.  Active checkpoint capture and restore bind
the outer flag, embedded flag, and VMCS12 primary-control bit transactionally.

The independent reverse/private-boundary replay then found that ordinary thaw
could pair a pending-MTF portable image with a frozen plan that did not enable
MTF even though checkpoint restore rejected the same mismatch.  Portable
apply now rejects that composition before producing a plan, with unchanged
output on failure.  The private ledger distinguishes canonical MTF state from
decode-only RUN_PENDING and obsolete timer state, and the validator pins the
legacy-wrapper, flag-dependency, generation, alias, and double-consumption
tests.  Pre-entry priority arbitration and exception/debug suppression remain
unfinished, so MTF stays absent from both legacy and true virtual VMX control
MSRs.  The current 211-entry requirement ledger, 39-entry private-interface
ledger, 150-case model, ASan/UBSan model, and full amd64 VMM `-Werror` build
pass.  The
Passes 11 through 14 require a second independently reconstructed private
inventory, a final cross-layer kernel replay, an independent kernel
transaction replay, and a final private-contract reconciliation; no earlier
clean conclusion may satisfy them.

Pass 11's first reverse wire-inventory replay found that upgrading the
embedded continuation while retaining the same outer version would silently
redefine a private envelope.  The sole current active checkpoint therefore
uses outer version 3 with continuation version 2.  Because no version was
released, decode rejects all obsolete outer and continuation versions.  Tests
reject relabeled records after independently recomputing every nested digest.
This private-format fix invalidates Passes 9 through 14 and requires their
replay on the final source.

The first Pass 13 transaction replay began at the cold L2 instruction-
completion publication point.  It found that the portable owner and frozen
plan were identity-checked, but the caller-supplied capability object was not
bound to the portable capability signature before RIP, interruptibility, and
pending-MTF state could be published.  Completion now computes the canonical
capability signature and rejects a stale combination transactionally.  The
independent negative test changes a valid capability field unrelated to guest
runtime validation, requires `ESTALE`, and proves that the portable owner and
caller output remain unchanged.  The subsequent Pass 14 reconstruction found
that the same function rejected a `retired` output alias with the portable
state but not with its capability or frozen-plan inputs, and did not reject the
mutable portable owner itself overlapping either immutable input.  All four
compositions now fail before validation or publication and direct tests prove
each affected owner remains byte-for-byte unchanged.  These production
corrections invalidate Passes 8 through 14 and require the private
reconciliation and both final replays on the resulting source.

The next forward kernel replay traced every currently available bhyve debug
event producer before attempting to connect pending MTF to the hot run loop.
The common interrupt snapshot records a debug vector but not whether #DB came
from a fault-like source, ICEBP, a TSS task switch, or an instruction-complete
trap.  Treating all #DB alike would violate Intel priority, while adding an
unversioned common snapshot field would create a separate migration ABI
change.  A cold value-only planner now requires that classification from its
future adapter, exhaustively covers all 160 combinations of owner, blocking,
INIT/wait-for-SIPI, non-debug high-priority work, and the five closed debug
classes, and publishes only
NONE, DEFER, DISCARD, or REFLECT.  Nested-entry and reinjection ownership defer
before any destructive action; discard is permitted only when INIT is
actually processed in wait-for-SIPI; high-priority events defer; trap-like
#DB remains pending behind MTF.  This ordering was reconstructed independently
from the pinned Linux event path and is now inventoried as a non-standard
adapter contract.

No hot-path adapter was added: the current continuation thaw would otherwise
lose a deferred MTF owner, and bhyve cannot yet supply exact #DB provenance.
Accordingly monitor-trap exiting remains withheld from the virtual capability
MSRs.  Passes 7 through 14 must now replay over the planner, its future owner
transfer boundary, and the unchanged exposure policy; a clean value-model
result must not be reported as live MTF qualification.

The following non-standard value-contract replay searched for one-sided enum
validation rather than following the architectural happy path.  It found that
event kinds/actions, VPID transition direction, and all three exit-provenance
domains accepted negative C enum representations because they checked only
`value > maximum`.  A negative event kind could consequently enter the
external-interrupt/default branch.  Every affected boundary now closes its
zero-based domain with an unsigned comparison before branching, and independent
negative tests prove rejection plus unchanged caller output at the provenance,
policy, context, routing, event, and VPID layers.  The requirement and private
interface ledgers separately record this implementation-language contract.
This production correction restarts both kernel passes and all non-standard
passes on the resulting source.

Rotate the starting pass after each fix, including Passes 7 through 22.  Exit only
when no high or medium
correctness issue remains, every requirement row maps to production code
and an independent test, every live group has Linux-L2 and 5BSD-L2
dispositions, the kernel builds with `-Werror`, and the complete host,
checkpoint, concurrency, fault, and soak gates pass.  Require separately
recorded clean results for every kernel review, both independently rebuilt
non-standard inventories, and their composed-boundary reviews; none may be
inferred from the other passes.  Passes 19 through 22 must all be rerun on the
identical final source after the last correction.

The next Pass 13/14 replay found three private transaction defects before MTF
exposure.  Variable-sized VMS2 restore plans cleared only their fixed header;
teardown now clears the allocator-owned extent.  Generic event snapshots lost
#DB provenance after dropping the event lock; the provenance class now travels
inside the same compare-and-commit value.  Pending-MTF reflection consumed its
owner while only constructing an exit; it is now an immutable peek followed by
a separate generation-checked commit after publication.  These fixes restart
Passes 7 through 14.  MTF remains withheld until the hot adapter consumes this
transaction and real Linux/5BSD L2 tests prove priority and rollback.

The rootless portability replay rejected the first MTF adapter because it
exposed a `_KERNEL`-only generic snapshot type to the value model.  The final
boundary uses an explicit Intel-private, non-serialized value snapshot and a
closed provenance enum.  Passes 10 and 14 must continue to reject dependencies
on installed kernel structure layout or implicit include order.

The following Pass 15 replay found that the cold continuation wrote completed
RIP, interruptibility, and pending MTF into the live portable owner before a
later thaw-resource operation could fail.  Completion is now staged in a
value copy and published only after thaw preparation succeeds.  The Pass 16
unsupported-path inventory then found that a future synthetic MTF reflection
could not reuse the original continuation's REFLECT_L1 identity: the original
EPT or device exit and the post-instruction MTF exit are distinct events.  A
closed private `MTF_REFLECTED` disposition and a generation-bound all-owner
publication transaction now make that distinction explicit.  Unsupported
DEFER and DISCARD retain every owner and MTF remains withheld.  This correction
restarts Passes 7 through 16 on the resulting source.

The first Pass 17 final-source ownership traversal of the architecture-neutral
checkpoint event coordinator found an indeterminate control-flow value in
`vmm_event_coordinator_drain_publishers()`: a successful ingress scan reached
the drain decision without ever initializing `error`.  Teardown could
therefore spuriously fail or complete according to prior stack contents even
though every ingress owner was validated while locked.  Each predicate
iteration now initializes its scan result before acquiring and inspecting the
entry set.  The requirements validator enforces that ordering, and the
non-standard ledger records the result as private lifecycle control flow rather
than a guest or management ABI.  The VMM module rebuilds with `-Werror`.
Because this is production kernel code, the correction invalidates Passes 17
through 22: the independent reverse kernel traversal and both independently
rebuilt private-interface inventories must run again on the corrected source.

The restarted Pass 17 and Pass 18 lifetime traversal then followed pending
monitor-trap state through vCPU construction, ordinary run unwind, reset,
all-vCPU snapshot freeze, destination restore publication, and final teardown.
The value model already had a generation-bound hot owner, but production
`vmx_vcpu` did not have the corresponding runtime owner.  Production now owns
that runtime-only state explicitly, initializes it with each vCPU incarnation,
rejects an occupied or malformed owner at source snapshot and destination
restore publication, and fails stop if teardown would abandon one.  The owner
is absent from the checkpoint wire image and restore staging structures.

The independent Pass 19 and Pass 20 reverse reading confirmed that primary
processor control bit 27 remains removed from both legacy and true virtual
control MSRs and that no management ABI, decoder, DTrace record, sysctl, or
checkpoint field exposes the runtime owner.  It also found that cold-to-hot
MTF transfer cannot be landed separately: the event-priority snapshot is
recomputed after thaw, so a formerly deferred obligation can become reflect or
discard before the first real L2 instruction.  Transfer, priority
re-resolution, exact publication or discard, and successful-entry ownership
therefore remain one withheld transaction.

Pass 21 and Pass 22 repeated both traversals on the resulting final source and
found no additional ownership or private-interface path.  The validator now
tracks 252 requirements and 88 private contracts, the 149-case nested model
passes, and `vmm.ko` builds with kernel `-Werror`.  MTF remains unadvertised and
live Intel qualification remains mandatory before exposure.

The next doubled replay connected the production owner only at proven commit
points: a real resumed VM exit takes it from the cold image; hot-to-cold
refreeze returns it to a strictly newer portable generation; and direct or
synthetic architectural nested-exit publication consumes it only after the
exit is irrevocable.  Comparison with pinned Linux corrected an unsafe review
assumption: `DEFER` means repeat arbitration after the entry/reinjection
blocker clears, not permission to execute another L2 instruction.  The
production bridge therefore continues to reject every non-`NONE` post-thaw
plan until that retry boundary and authoritative INIT-in-wait-for-SIPI
provenance exist.

Pass 21 then found two adapter details missed by the forward walk.  A hardware
MTF exit can carry bit-26 bus-lock metadata in its full exit reason, so the
owner validates the basic reason while the destructive publisher retains the
complete routed hardware image.  A fatal hot VM-entry abort also deliberately
abandons L2 without creating a portable image; after runtime and workspace
retirement, teardown now consumes only the exact identity/generation MTF
owner.  Every other unexplained owner still fails stop.  The production source
validator pins both orderings.  These kernel changes restart Passes 19 through
22 and the two independent non-standard inventories on the new source.

The restarted compiler review also proved that the ordinary `vmm.ko` module
build is not snapshot coverage: its generated `opt_bhyve_snapshot.h` leaves
the snapshot implementation out.  Every final-source kernel pass must build
the module twice with warnings as errors, once with the default options and
once with `MK_BHYVE_SNAPSHOT=yes`, using separate clean object roots.  The
first such enabled build found that the shared amd64 snapshot dispatcher used
the portable snapshot-envelope range helpers without including their public
declaration.  The kernel now includes `vmm_snapshot_envelope.h` under the same
option guard, and the source validator pins that dependency.  Success in only
one configuration is not review evidence and restarts Passes 19 through 22.

Passes 19 through 22 were then replayed from a fresh 361-file scope manifest.
The reverse kernel walk and the independent consumer-led private inventory
reconciled all 88 private contracts without finding another orphan producer,
decoder, compatibility selector, resource ceiling, internal exit, or
observability surface.  The before/after hashes were identical.  Both clean
module configurations, all 252 source requirements, and the 163-case rootless
model gate passed.  This closes the rootless doubled review for the current
source; default-off MTF and nested-VMX live Intel qualification remain open.

The next doubled review traced virtual INIT and SIPI from the LAPIC ICR through
the common rendezvous and startup-mask owners before considering the remaining
MTF discard path.  `startup_cpus` proves only that a vCPU is awaiting a later
SIPI; it does not prove which INIT generation was accepted at the retained L2
instruction boundary, whether nested-entry or reinjection ownership blocked
it, or whether L1 must receive an INIT-signal exit.  The pinned Linux event
path keeps pending APIC INIT as an event owner, retries arbitration while those
blockers exist, and clears pending MTF only when that exact INIT is processed.
The current bhyve path instead resets the target LAPIC and publishes the common
startup mask through a rendezvous without a generation-bound nested-event
receipt.  Inferring discard from the mask would therefore consume the wrong
MTF owner after a later INIT or restore.  No such inference is permitted:
production remains fail-closed, primary control bit 27 remains withheld, and
the next implementation must introduce one architecture-neutral INIT/SIPI
receipt and retry transaction before the Intel adapter can implement DISCARD.

The first bounded foundation for that transaction is now
`vmm_startup_event`: an allocation-free, caller-synchronized value protocol
whose receipt is bound to the exact owner, vCPU, state address, receipt
address, and generation.  INIT replaces older SIPIs; a SIPI arriving after
INIT remains pending with its latest vector; selection always presents INIT
first.  Overflow, stale, copied, cross-owner, overlapping-storage, and corrupt
receipts cannot mutate the state.  This is deliberately common VMM code and
deliberately not an APIC adapter, checkpoint format, management ABI, or guest
feature.  Passes 19 through 22 must therefore review both the helper and every
future caller, and must continue to report production INIT/SIPI, no-entry
retry, and MTF discard as withheld until the rendezvous and Intel paths are
connected and live-qualified.

The value state is now owned by the common per-vCPU event coordinator under
the same stable entry-lock order used by checkpoint ingress.  VM reset
preflights every ingress and startup generation before changing any of them;
checkpoint begin rejects a selected pending startup value while all selected
entry locks are held.  The rejection is intentionally fail-closed until a
portable, versioned startup-event record exists.  A first implementation
allocated the finite transaction owner before this new rejection and thereby
lost an identity on every retry.  The corrected ordering validates caller
credentials and all selected startup states first, then uses a non-sleeping
spin-owned allocator while the entry locks remain held and immediately
publishes the transaction to those entries.

Passes 19 through 22 must recheck this coordinator integration independently.
In particular, prove that the global owner spin lock has no inverse order,
that preflight makes the reset commit loop infallible, that a rejected begin
clears staged membership and caller state pointers, and that no startup value
can enter after ingress closes.  Do not connect the LAPIC publisher merely to
exercise these functions: publication also needs an event-driven vCPU wakeup
and an architecture adapter that commits APPLY-L0, REFLECT-L1, or RETAIN-AND-
RETRY before exact receipt consumption.  Publishing without that consumer
would leave ordinary INIT/SIPI pending indefinitely and make every later
checkpoint fail.  Polling the coordinator, immediately consuming around the
old rendezvous path, or treating `startup_cpus` as provenance is not an
acceptable substitute.

The independent reverse pass found that even generation-bound receipts are
insufficient when `peek` and `consume` are separate coordinator calls.  A
newer publisher can invalidate the receipt after an external LAPIC reset or
nested-exit publication has committed but before consumption.  The former
coordinator wrappers were unused and have been removed.  Any replacement must
claim the selected event under the entry owner, permit later publications to
remain ordered behind that claim, and provide exact finish or abort semantics
around the external side effect.  The source gate rejects reintroduction of an
unlocked coordinator peek/consume pair.

The replacement claim lease now exists in the common value and coordinator
layers.  Review it in both directions: publication while claimed, finish,
abort, reset, checkpoint admission, cancellation, drain, and destruction.
Verify the abort age rules for all four claimed/newer INIT/SIPI combinations,
claim-ID exhaustion, copied storage, and a finish racing cancellation.  This
still does not authorize LAPIC wiring: the publisher must notify the target
vCPU without polling, and the architecture adapter must classify and commit
the claim before finish or abort.

The next Pass 21/22 restart must include the exact Intel startup transaction.
Review the plan-to-claim binding independently from both its producer and its
future LAPIC consumer.  Prove that L0 SIPI application retains the original
vector, that reflected SIPI qualification equals that vector, and that owner,
claim, state storage, claim storage, vCPU, kind, and vector cannot be mixed
across VM incarnations or copied transaction objects.  Treat callback success
as irrevocable and callback failure as retryable only when both transaction
and claim storage remain byte-for-byte unchanged.  Distinguish an ignored
SIPI, whose failed claim-only release can retry, from L0 application, L1 exit
publication, and MTF discard, whose post-effect release failure must poison.
Reentrancy during EXECUTING or RELEASING, false release success, callback
mutation, and copied storage must have direct negative tests.  The adapter
must remain runtime-only and absent from `vmx.c` until target rendezvous,
reflection publication, MTF-owner composition, reset, and live Intel evidence
are one reviewed transaction.

The next mandatory four-phase replay covered the new shared amd64 startup
machine adapter before any Intel or AMD production consumer was permitted.
The forward kernel traversal found that the transaction workspace originally
embedded the executor input at the same address as its opaque argument, which
the executor correctly rejects as an ownership alias.  The adapter now passes
a distinct immutable input candidate.  The same traversal found that a zero
setter result was treated as proof of publication; every successful register
and descriptor write is now read back before the event commit.

The definition-first private-interface inventory classifies the transient
register and descriptor enums and callback table as a private amd64 kernel
contract, not VM_REG numbering, a VMCS/VMCB layout, save state, ioctl, sysctl,
DTrace record, or guest ABI.  It requires caller serialization, disjoint
storage, atomic selector-plus-hidden-descriptor callbacks, exact named event
comparison, and an infallible frozen-target finalizer.  Production consumers
remain absent and the historical userspace INIT/SIPI path is unchanged.

The independent reverse kernel traversal started at rollback and discovered
that restored values were not read back, allowing a backend to silently drop
a rollback write while the transaction reported atomic recovery.  Rollback
now proceeds in strict reverse order, verifies every restored value, and
poisons any failed or silently lost restore.  Walking farther backward found
that a setter which mutated while returning an error could evade the applied
count; the adapter now compares that location with its captured old value,
marks a contract-violating mutation as applied, and rolls it back.

The consumer-first private-interface replay found only the independent ATF
model and module linkage.  It found no decoder, ioctl, management utility,
checkpoint field, compatibility fallback, diagnostic consumer, Intel adapter,
or AMD adapter.  Direct negative tests now cover every INIT setter failure,
both SIPI setter failures, silently lost register and descriptor writes,
mutating setter errors, event-generation races, silently lost rollback, and
external input or callback-table mutation.  Any later Intel/AMD mapping,
LAPIC/run-state finalizer, ownership selector, or live dispatcher is a new
consumer and invalidates all four phases.

The following four-phase replay covers the first FreeBSD-private backend
namespace boundary.  The forward kernel pass followed SIPI through the shared
machine executor and found that it captured and cleared the generic pending
exception, NMI, interrupt, reinjection, and interrupt-shadow image exactly as
INIT did.  The Intel architecture and the pinned Linux delivery path instead
make SIPI a CS:RIP plus run-state transition.  The adapter now performs exact
event capture and compare-clear only for INIT; SIPI never calls either event
callback, and its test proves an unrelated pending NMI image survives.

The definition-first non-standard pass classified the new startup-to-VM_REG
mapping as a private transient FreeBSD kernel adapter.  It is not a guest ABI,
management ABI, checkpoint format, stable KPI, VMCS encoding, or VMCB
encoding.  Every one of its 30 register names and 10 descriptor names uses an
explicit switch, invalid input leaves output unchanged, and neither enum's
numeric order is an authority.  The private ledger also records that mapping
a segment name does not make selector and hidden descriptor-cache publication
atomic, and that the common RIP setter remains unsuitable because it also
updates `nextrip`.

The reverse kernel pass started at the prospective VMX and SVM consumers and
walked back through raw get/set operations.  It confirmed that the mapping
layer performs no mutation, allocation, locking, sleeping, or serialization,
and that it leaves backend side effects and rollback to the reviewed machine
executor.  It also confirmed that SIPI rollback still restores RIP before CS
in reverse apply order, while INIT restores registers then descriptors in
strict reverse order.  No new production consumer was introduced.

The consumer-first non-standard replay found only the independent ATF mapping
test, module linkage, validator, and requirements/private-interface ledgers.
It found no ioctl, sysctl, DTrace record, userspace header, save-state record,
diagnostic fallback, VMX callback, or SVM callback.  The rootless model now
runs 216 cases.  Adding either backend callback table, a selector-plus-cache
segment adapter, a LAPIC/run-state finalizer, or an immutable per-VM startup
selector invalidates all four phases again.

The subsequent kernel build found one additional definition-boundary defect:
the private mapping header included `machine/vmm.h` before the kernel's
fundamental parameter and type definitions.  The userland ATF translation unit
already supplied them and therefore could not reveal the error.  The header is
now self-contained by including `sys/param.h` and `sys/types.h` first.  Both
module configurations must be rebuilt after this correction; this finding is
why the kernel build remains part of the doubled review rather than a
substitute for it.

The next four-phase replay covers the selector-plus-hidden-cache backend
adapter.  The forward kernel pass traces a transient segment through explicit
VM_REG mapping, raw selector capture, hidden-cache capture, selector
publication, hidden-cache publication, verification by the outer machine
transaction, and reverse rollback.  A hidden-cache failure now attempts both
hidden-cache and selector restoration even if one restoration fails, and
reports recovery failure rather than concealing a partially changed segment.
Direct tests cover both a well-behaved failed setter and a setter that mutates
while reporting failure.

The definition-first private-interface pass classifies the raw callback table
and bound context as a private amd64 kernel adapter, not a stable KPI, public
VM_REG contract, VMCS/VMCB layout, ioctl, sysctl, DTrace record, or checkpoint
format.  It rejects incomplete and overlapping bindings, rejects selectors
wider than 16 bits, preserves getter output until success, and copies the raw
callback table at bind time.  It does not claim the two raw writes are
hardware-atomic; their transactional visibility depends on the required
frozen target and outer verified rollback owner.

The reverse kernel pass began at failed restoration and confirmed the outer
machine transaction can read back a remaining selector or hidden-cache
mutation and either restore it or poison the transaction.  It also found that
entry points trusted a previously initialized context and could dereference a
later-corrupted null callback.  Every adapter entry now validates the complete
context and fails closed, with direct corruption tests.  The pass found no
common `vm_set_register` use and therefore no accidental RIP-to-`nextrip`
side effect.

The consumer-first non-standard pass found only the shared adapter test,
module linkage, validator, and ledgers.  It found no VMX binding, SVM binding,
LAPIC reset, translation invalidation, run-state mutation, startup-mode
selection, userspace consumer, or serialized representation.  The rootless
suite now runs 223 cases.  Any raw VMX/SVM callback binding or frozen-target
finalizer is a new consumer and restarts all four review phases.

The next doubled review begins at the vCPU execution lifecycle rather than at
the startup value engine.  The forward kernel pass found that bhyve already
opens, activates, debugger-suspends, and creates one userspace thread for every
configured vCPU before resuming the BSP.  The missing kernel-owned SIPI
contract is therefore not thread creation.  It is an explicit opt-in which
resumes those pre-created AP threads into an architectural wait-for-SIPI gate
owned separately from `debug_cpus` and VM-wide suspend.  Reusing debugger
suspension would let SIPI accidentally override an operator or GDB stop;
creating a thread from the kernel would cross the VM_RUN ownership boundary.

The definition-first non-standard pass must treat this selection and any
future ioctl or capability as a FreeBSD-private management ABI.  Its default
must preserve the current unacknowledged `VM_EXITCODE_IPI` and
`VM_EXITCODE_SPINUP_AP` paths exactly.  Kernel ownership must be selected and
locked while all vCPUs are frozen, derive exactly one BSP from virtual
IA32_APIC_BASE.BSP, initialize every other configured vCPU as waiting, and
prove userspace has entered VM_RUN for all pre-created threads before guest
execution begins.  Partial setup must leave owner, wait state, debug state,
and thread lifecycle unchanged.

The reverse kernel pass must start at reset, restore, destroy, debugger stop,
signal interruption, and a SIPI racing a sleeping AP.  The wait must use an
interlocked generation and targeted wakeup, not a periodic timeout or busy
poll.  Rendezvous and VM suspend must still be serviceable while waiting.
After exact INIT commit an AP publishes wait-for-SIPI; after exact SIPI commit
only that accepted target leaves the wait and is awakened.  A BSP INIT remains
runnable, matching the pinned Linux path.

The consumer-first private-interface pass must reconstruct the mode from
bhyve configuration, libvmmapi, ioctl decoding, checkpoint compatibility,
legacy fallback, diagnostics, and tests.  No such consumer exists yet, so the
kernel finalizer and production dispatch remain withheld.  Adding the mode,
wait primitive, userspace handshake, finalizer, or snapshot field invalidates
all four phases again.

The value-layer correction now makes execution readiness an explicit half of
the immutable selection.  A userspace owner can lock only with the historical
userspace-resume contract, while a kernel owner can lock only with the
prestarted event-wait contract.  This prevents a caller from deriving an
`APPLY_KERNEL_*` action from a mode that never arranged a runnable target
thread.  The new field remains transient and has no production consumer or
serialized form; the four phases must be repeated when either is added.

The next mandatory four-phase replay covers the shared amd64 frozen-target
startup finalizer.  The forward kernel pass traces the irreversible tail only
after all register and descriptor writes have been verified and INIT has
compare-cleared its exact event image.  INIT then resets nested execution
ownership, resets the LAPIC, invalidates guest translations, synchronizes
machine-independent `nextrip` to `0xfff0`, and atomically publishes BSP
runnable or AP wait-for-SIPI.  SIPI performs none of the reset operations,
synchronizes `nextrip` to zero, and atomically leaves wait-for-SIPI while
waking the exact target.  The callbacks are void deliberately: each consumer
must preflight them as allocation-free, nonblocking, target-frozen, and
fail-stop on an impossible backend failure because no recoverable error is
truthful after exact event consumption.

The definition-first private-interface pass classifies the finalizer as a
FreeBSD-private common-amd64 adapter, not a guest ABI, management ioctl,
sysctl, DTrace payload, checkpoint field, stable KPI, VMCS layout, or VMCB
layout.  Its plan retains event-kind and architectural-BSP provenance and
rejects inconsistent reset/wait compositions.  Binding copies both the plan
and complete callback table into storage authenticated by its own address;
the finalizer consumes and clears that storage before the first callback so a
retried exact-claim finish cannot repeat already committed side effects.
Malformed, overlapping, copied, nonempty, or incomplete bindings fail without
changing caller storage.

The reverse kernel pass begins with reset, destroy, a SIPI wake, and a durable
startup claim in `FINISH_PENDING`.  It found that the original draft accepted
an externally mutable plan at commit and could be committed more than once.
The finalizer is now a one-shot bound owner with a copied self-consistent plan.
Callbacks execute from a local copy after the bound object is consumed, so an
enclosing backend mutation cannot rewrite the remaining callback order.  The
generic transaction executor remains intentionally policy-neutral and still
passes its complete SIPI input to capture; rejecting SIPI-to-BSP belongs in
the finalizer plan, where BSP provenance is relevant.  No polling, timeout,
allocation, serialization, host pointer persistence, or fallible return path
was introduced.

The consumer-first private-interface pass found only the module link, direct
ATF model, requirements ledger, private-interface ledger, and validator.  It
found no VMX or SVM raw binding, LAPIC/TLB callback, sleepqueue consumer,
startup-mode selector, ioctl, libvmmapi operation, bhyve option, restore
record, or production dispatch.  The rootless model now runs 229 cases, its
ASan/UBSan replay runs the same 229, and the production `vmm.ko` builds with
warnings as errors.  Adding any production
consumer invalidates all four phases and requires fault injection proving
that preflight makes the post-event callback sequence genuinely infallible.

The four-phase replay for the prestarted-vCPU handshake begins at the generic
VMM boundary.  The forward kernel pass follows the initialized historical
userspace default through explicit kernel configuration, one admission per
canonical configured vCPU, exactly one externally classified BSP, immutable
commit, and precommit cancellation.  It found that the first draft could
report a corrupt aggregate as merely incomplete and could retain caller-owned
array pointers after cancellation.  Commit now distinguishes internal
inconsistency as `EINVAL` from a valid incomplete set as `EAGAIN`, while
cancellation advances the generation and removes every live external-storage
reference.

The definition-first non-standard pass classifies this as a transient private
kernel implementation, not a guest ABI, management ioctl, sysctl, DTrace
record, checkpoint format, sleep primitive, run-state field, debug-suspend
mask, vCPU creation interface, or stable KPI.  The canonical contiguous vCPU
index set is an explicit compatibility constraint matching current bhyve,
not an architectural rule; noncontiguous CPU hotplug requires a new versioned
selection design and restarts the reviews.  The protocol requires an external
owner for serialization and storage lifetime and deliberately makes no claim
that a VM_RUN thread is sleeping or wakeable.

The reverse kernel pass starts at commit, cancel, corrupted canonical
records, copied owners, storage overlap, generation exhaustion, and teardown.
It found that header-only validation could authenticate a handshake while its
per-vCPU records were malformed.  Validation now recomputes every binding,
self-cookie, vCPU identity, entered count, BSP count, array size, and
disjointness in both collecting and kernel-committed states.  The same pass's
fresh module build also found a release-kernel defect in the earlier startup
finalizer: its validity check existed only inside `KASSERT`, so non-INVARIANTS
kernels compiled the check away and left the helper unused.  Commit now
performs an unconditional unlikely validity check and panics before any
irreversible callback on corruption.

The consumer-first non-standard pass finds only the direct ATF model, module
link, ledgers, validator, and model runner.  There is still no ioctl,
libvmmapi operation, bhyve option, VM_RUN admission hook, sleepqueue, reset or
restore record, Intel/AMD dispatcher, or finalizer callback binding.  Adding
any such consumer restarts all four phases.  Current rootless evidence is 235
model cases with matching ASan/UBSan replay, a clean requirements validator,
and a production `vmm.ko` warnings-as-errors link.

The four-phase replay restarted when the handshake became a coordinator
consumer.  The forward kernel pass found three boundaries that the standalone
value model could not prove: the aligned record-array offset could wrap before
`roundup2`, a self-consistent handshake could name storage outside the opaque
coordinator allocation, and startup selection could mutate while a checkpoint
transaction owned the same VM lifetime.  The allocation calculation now
preflights alignment addition, validation requires the exact canonical
in-allocation pointer and a zero unused tail, and every startup mutation is
serialized against the checkpoint transaction owner.

The reverse kernel pass began at VM destruction and found a high-severity
waiter lifetime defect: cancellation woke the new startup wait channel but
the destroy path drained only the pre-existing checkpoint wait channel.  A
startup waiter could therefore retain the coordinator sleep address after its
allocation was erased and freed.  Admission, handshake retirement, record
erasure, and cancellation of both wait generations now form one terminal
operation, and destruction drains both waiter sets.  Generation exhaustion in
either channel closes this same complete lifetime instead of leaving the
other channel apparently live.

The definition-first non-standard replay classifies the combined coordinator
state as private kernel implementation only.  Its canonical contiguous vCPU
array, two generations, owner identifiers, storage cookies, zero tail, error
selection, and persistence across an ordinary VM reset are neither guest nor
management ABI and are never serialized.  The consumer-first replay finds no
ioctl, libvmmapi entry, bhyve option, sysctl, DTrace/audit record, restore
decoder, VM_RUN hook, or Intel/AMD dispatch consumer.  In particular, the
kernel readiness wait now rejects the historical userspace owner instead of
preparing a ticket that could sleep forever.  Adding any withheld consumer
restarts all four phases on a new identical-source manifest.

The doubled review restarted again for monitor-process replacement.  The
forward kernel pass traced `vm_reset()` through the retained kernel VM and the
new bhyve child and found that an immutable kernel owner cannot leave its old
admission set committed: those VM_RUN threads no longer exist.  Ordinary reset
now advances the handshake generation, preserves the locked owner, and, only
for the kernel owner, clears and canonically rebinds every record before
returning to collecting.  Enter, readiness wait, and commit all require that
exact generation, so a delayed operation from the former process returns
`ESTALE` instead of satisfying the replacement generation.

The reverse kernel pass begins at generation exhaustion, checkpoint-owned
reset, a sleeping readiness waiter, and a stale monitor call.  Reset preflights
the handshake before touching per-vCPU event generations, wakes the distinct
startup channel after successful rebinding, and leaves all state unchanged at
exhaustion.  A waiter woken by reset rechecks its supplied generation and
fails stale.  The historical userspace owner remains committed but advances
generation, preserving its established execution model without silently
switching owners.

The definition-first non-standard pass classifies reset generation, record
rebinding, and the status snapshot as transient private kernel values, not a
management ABI, checkpoint field, DTrace record, architectural wait state, or
stable KPI.  The consumer-first pass found that an initial status query could
write over the externally stored canonical records even though it rejected
overlap with the handshake itself.  It now rejects both alias ranges and
copies only pointer-free mode, generation, counts, phase, and zero reserved
fields after full validation.  The future management ioctl must use its own
versioned structure and fd-owned authorization, and the historical VM_RUN
ioctl must not change size; adding those consumers restarts all four phases.

The second forward/reverse kernel traversal of the shared wait channel found
that a zero return from `sleepq_wait_sig()` escaped directly as coordinator
success.  A broadcast therefore could make startup admission or checkpoint
readiness appear complete without re-evaluating either predicate.  An
ordinary wake now reacquires the sleepqueue-chain interlock, validates the
exact generation-bound ticket and cancellation state, and returns `EAGAIN`;
the coordinator then releases the ticket, reacquires its transaction owner,
and recomputes the full predicate.  A spurious unchanged wake follows the
same replay, while `EINTR`/`ERESTART`, cancellation, and corrupt identity stay
distinct.  The definition-first and consumer-first private reviews classify
this as internal condition-wait behavior rather than a timeout, polling rule,
userspace ABI, checkpoint field, or successful-operation guarantee.

The next identical-source four-phase cycle covers the future file-description
startup owner.  The forward kernel pass follows controller allocation, exact
ticket claim, handshake configuration, every VM_RUN admission, readiness,
commit, reset, and inherited monitor replacement.  It found that mutable phase
was reported before ticket authentication and that generation, status, or wait
output could alias and corrupt the external credential.  Exact state, owner,
generation, controller, state-storage, and ticket-storage identity is now
authenticated first, and every coordinator output must be disjoint from the
credential as well as the opaque coordinator allocation.

The reverse kernel pass begins at cdevpriv final close, an active checkpoint,
coordinator cancellation, and concurrent historical VM_RUN.  It found that a
close path cannot return `EBUSY` while its credential storage is about to be
freed, and that a one-shot default lock would reject every legacy vCPU after
the first.  Final close now aborts only an unconfigured claim with no active
checkpoint; otherwise it fail-closes admission, retires handshake and
controller, cancels both wait domains, and locally forgets the ticket while
the exact checkpoint owner performs its normal abort.  Historical default
selection is idempotent only for the exact committed-userspace/revoked-
controller state and remains blocked by an explicit claim.

The definition-first non-standard pass classifies controller identifiers,
generations, pointer cookies, phases, and errno choices as transient private
kernel values.  They are not descriptor numbers, process identities, user
credentials, checkpoint fields, sysctls, probes, or stable KPI.  The
consumer-first pass currently finds only the coordinator and model tests: no
production cdevpriv, ioctl, libvmmapi call, bhyve option, or VM_RUN hook exists.
Adding those consumers restarts all four phases and must introduce new
versioned management and generation-bearing run structures without changing
the historical VM_RUN command.

That consumer restart has begun for the historical default only.  Both the
current amd64 VM_RUN and its FreeBSD 13 compatibility command now lock the
userspace-resume owner after the common dispatcher freezes the exact vCPU and
before guest execution.  The operation is idempotent across concurrent vCPU
threads and reset generations, returns no generation through the old ABI, and
is blocked by a prior explicit controller claim.  Kernel-owned execution is
still unreachable.  The next reverse pass must start from copyout failure,
VM_RUN thread exit, VM_REINIT, checkpoint ownership, final close, and VM free;
the forward pass must preserve old exit and IPI behavior byte-for-byte.

The event-driven AP-wait slice then restarts the cycle.  Its lock-order proof
is `rendezvous_mtx -> vCPU spin owner -> sleepqueue chain`: the waiter tests
the architectural startup bit and enqueues before releasing either predicate
owner, while a future accepted SIPI clears under `rendezvous_mtx` and notifies
through the exact vCPU owner.  The vCPU moves FROZEN to SLEEPING only after it
is queued and returns to FROZEN after every wake.  The sleep is interruptible
and indefinite; no `hz` wake, timeout, or polling is a progress mechanism.
Every ordinary wake replays startup, rendezvous, suspend, reqidle, debugger,
and thread predicates.  Kernel ownership is still unreachable, so installed-
kernel lost-wake and lifecycle evidence remains mandatory before ABI exposure.

The restarted reverse kernel pass found two additional boundary defects.  The
raw sleepqueue call originally passed `PCATCH` as the scheduler priority even
though interruptibility is already encoded by `SLEEPQ_INTERRUPTIBLE`; unlike
`_sleep()`, a direct `sleepq_wait_sig()` call does not strip that flag.  The
wait now passes priority zero.  The same pass moved `retu` initialization to
the common `restart:` boundary so neither a startup-gate error nor a backend
error depends on a callee initializing diagnostic stack state.  Finally, the
consumer-first concurrency replay made kernel-owner commit idempotent only
when the authenticated controller, generation, committed phase, and owner all
match.  A concurrent admitted vCPU can therefore observe the already
committed transaction without weakening stale-generation or wrong-owner
rejection.  These corrections restarted all four phases; the resulting source
passes the 246-case model, address/undefined sanitizers, the `vmm.ko` Werror
build, and the 289-requirement/123-private-interface validators.

The next forward/reverse restart found a readiness-publication race before any
management ABI was added.  If the final admitted thread were an AP, the raw
coordinator could announce complete readiness before that AP's architectural
wait-for-SIPI bit was installed.  `vm_startup_enter()` now acquires
`rendezvous_mtx`, sets the AP bit or clears the BSP bit, retains the mutex
across authenticated coordinator admission, and restores exact prior
membership after a failed call.  A woken committer and every committed VM_RUN
must acquire the same mutex before testing the mask.  The raw coordinator API
remains private; a future cdevpriv consumer must use the VM wrapper and
restarts all four reviews.

The portability replay then rejected the first wrapper revision because the
wait set still lived in `VMM_VM_MD_FIELDS` on amd64.  The set is now common VM
state, is initialized with the common coordinator lifetime, and is cleared
under `rendezvous_mtx` only after a successful common reset.  The amd64 tail
retains only architecture-specific event and device state.  This does not
claim arm64 or riscv execution support: their run-loop bindings remain
withheld, but common code no longer embeds an x86-only field dependency.

The next doubled kernel traversal found that merely taking the rendezvous
owner for the clear was insufficient.  The first revision reset the
coordinator, released its transaction owner, and only then acquired
`rendezvous_mtx`; a replacement monitor could admit a new-generation AP in
that interval and have reset erase its newly published wait-for-SIPI bit.
The common reset wrapper now acquires `rendezvous_mtx` before entering the
coordinator reset and retains it through the successful mask clear, matching
the admission lock order and preserving the old mask on every reset error.
This correction restarts the forward kernel, reverse kernel,
definition-first private, and consumer-first private phases.

The next source slice adds a common VM-lifetime boundary for controller claim,
release, configuration, readiness wait, commit, and authenticated status.
This layer deliberately contains no ioctl structure, controller-ID allocator,
file-description state, or architecture classification.  Raw coordinator
operations remain confined to their value owner and `vmm_vm.c`; AP admission
continues to use the rendezvous-owned wrapper.  A future cdevpriv consumer must
hold the exact embedded ticket under a reviewed operation lease and restarts
all four phases before any userspace exposure.

The reverse consumer pass also found an older checkpoint caller passing
`PCATCH` to the private event-wait layer.  That layer already registers
`SLEEPQ_INTERRUPTIBLE` and calls `sleepq_wait_sig()` directly, so `_sleep()`
flag bits are not valid priorities there.  Snapshot readiness now passes zero,
and both raw wait and drain entry points reject bits outside `PRIMASK` before
taking their sleepqueue locks.  This finding restarts all four phases again.

The next forward/reverse retry review addresses signal interruption between
vCPU admission and handshake commit.  The value layer now reports
`EALREADY` only for the same canonical vCPU record and identical
architecture-derived BSP classification, both while collecting and after
commit.  The coordinator translates that exact retry to success without
broadcasting or advancing the wait generation; changed BSP provenance remains
`EBUSY`.  This is still private and must be exercised by future ioctl signal
tests before exposure.

The attempted file-description integration was withheld because its first
shape still accepted a BSP boolean at an internal caller boundary and used a
panic as close-time recovery.  The safer prerequisite is now explicit: a pure
x86 value function classifies BSP provenance solely from virtual
IA32_APIC_BASE bit 8, with independent set/clear fixtures and failure-atomic
output.  The production machine-dependent adapter now reads that value from
an exclusively frozen target vLAPIC and publishes only a successfully
classified local value; neither ioctl input, vCPU ordinal, nor host CPU
identity selects the BSP.  It remains deliberately unconsumed until the
generation-bearing run ABI can prove the common dispatcher freeze,
file-description credential, and signal-retry contract.
The coordinator close wrapper now avoids a second fallible ticket check after
terminal retirement and directly erases only the credential it authenticated
under the retained transaction owner.  Expected close therefore has no panic
recovery.  Cdevpriv exposure remains withheld until active-operation lifetime,
dup/fork semantics, and checkpoint/reset/destroy races are independently
proved.

A fixed-width 48-byte version-one startup management request is now exposed as
amd64 command 116.  Its closed operations distinguish configure,
interruptible wait-ready, exact-generation commit, and status; reserved and
caller-output fields must be zero.  The exact controller ticket is stored in
cdevpriv, so dup and fork share it and final close releases it after aborting
any exact checkpoint transaction.  The per-file `sx` is never held across the
interruptible wait.  The value encoder supports true in-place ioctl output
while rejecting partial alias and handles OPEN, collecting, and
kernel-committed status separately.  Installed-kernel lifetime and race tests
remain release gates rather than assumed evidence.

The following reverse kernel-lifetime pass started at VM teardown and proved
the generic ownership prerequisite for that future cdevpriv consumer.  Devfs
attaches private state to the open file description, so dup and fork share one
credential and only final file close destroys it.  Forced character-device
destruction drains active device methods, invokes every cdevpriv destructor,
and waits for those destructors before returning; the VMM destruction path
then frees the VM only after `destroy_dev()` completes.  The definition-first
non-standard phase records this as a private lifetime dependency rather than
a userspace contract.  The consumer-first phase still withholds exposure
until live dup, fork, final-close, forced-destroy, active-operation, signal,
checkpoint, and reset races pass, and forbids holding the per-file `sx` across
the interruptible readiness wait.

The next definition-first ABI pass rejected reusing the historical native
pointer and native `size_t` run layout.  A separate 64-byte value is exposed
as amd64 command 117 with fixed-width version, size, flags, vCPU, generation,
user addresses, buffer sizes, and reserved fields.  Its signed 32-bit vCPU is
the first member because the common dispatcher consumes it before acquiring
the exclusive vCPU freeze.  The decoder validates complete ranges against the
caller's ABI address limit, including compat32, and rejects overlapping output
buffers.  The cdevpriv adapter derives BSP provenance from the frozen virtual
LAPIC, admits the exact generation idempotently, and waits event-driven for
manager commit before entering `vm_run()`.  The historical VM_RUN is unchanged.
Installed-kernel malformed-pointer, signal-retry, reset, close, checkpoint,
arbitrary-BSP-ordering, and live Intel qualification remain mandatory.

The first consumer-first replay of that run ABI found two additional boundary
requirements.  The management request exposes its own closed result enums and
now translates internal handshake values explicitly; a 32-bit configured
count above 65,535 is rejected before reaching the coordinator's 16-bit
capacity.  The libvmmapi generation-run wrapper is bound to a `struct vcpu`,
not merely a VM context, so the existing first-field ioctl helper supplies the
authoritative vCPU identifier.  Source builds now resolve the new versioned
VMM headers directly from the source tree.

The doubled review deliberately withholds the attempted bhyve consumer.  A
default-off selector was still semantically incorrect because production
`vlapic.c` continued to exit SIPI to userspace and bhyve still performed the AP
reset/resume sequence.  The versioned management and vCPU-bound run interfaces
remain staged foundations, but no bhyve option may activate them until the
production frozen-target INIT/SIPI application and finalizer are kernel-owned,
portable controller/generation restore state exists, and installed-kernel
lifecycle evidence passes.  The validator now fails if that premature selector
or its adapters reappear.  This finding restarts the forward-kernel,
definition-first-private, reverse-kernel, and consumer-first-private phases.
The same replay found that a direct caller could otherwise activate the staged
management ioctl without bhyve.  `CONFIGURE` therefore fails with
`EOPNOTSUPP` before controller claim or mode mutation while the production
INIT/SIPI finalizer is absent.  The private ABI can compile and receive layout
review, but it cannot change a running VM's startup ownership.

The portability/private replay must also identify the owner of every command
number, not merely hide its macro.  Commands 116 and 117 are reserved by name
in the amd64 `IOCNUM` namespace and only their amd64-gated public macros use
those names.  Independent ABI fixtures continue to assert the literal group,
number, direction, and payload size.  Treat an unexplained numeric ioctl in a
common header, a command macro on an architecture without a dispatcher, or an
x86 live test in a non-x86 test manifest as a new finding and restart all four
phases.
The portability replay also confines commands 116/117 and their live/ABI
tests to amd64, matching the only implemented dispatcher and libvmmapi
wrappers.  Machine-independent coordinator and wire-value tests remain common;
arm64 and riscv gain no placeholder ABI or misleading legacy stub.

The next doubled replay must reject an untyped or late-bound irreversible
startup tail.  Start the forward kernel phase at vLAPIC INIT/SIPI acceptance
and prove that one exact typed finalizer is bound before capture or machine
mutation.  Revalidate its event kind, vector, and architecture-derived BSP
provenance immediately before compare-and-clear; after that commit permit
only infallible operations and consume the binding before the first callback.
Start the reverse phase at reset, destroy, callback corruption, and event
replacement.  Verify complete pre-commit rollback and a poisoned result when
external callback storage, including the finalizer itself, changes.

For every private ioctl, rebuild ownership from both directions.  A wire
number must have one payload-owned definition, an explicit reservation in the
implementing architecture's ioctl namespace, an architecture-matched command
macro and dispatcher, and an independent literal test oracle.  Source-tree
tests must not silently select an older installed machine header.  Any
duplicate literal, unavailable enum dependency, command on an unsupported
architecture, or production-header-derived expected value restarts all four
phases.

For each staged production callback table, perform the four reviews twice:
first over the adapter in isolation and then over the complete kernel path
from producer to final teardown.  Compiled but unreachable code is staged,
not supported.  A fail-closed placeholder is acceptable only when executable
validation proves both its exact error boundary and the absence of every
activation consumer.  Inventory callback identity, opaque context,
generation, storage cookies, private errno behavior, and every assumption not
defined by the Intel SDM or VirtIO specification.

For INIT/SIPI specifically, compare the architectural state writer with every
post-commit cache and scheduler publication.  Prove that SIPI's `vector << 12`
entry point is identical in CS base, architectural RIP composition, backend
next-run state, and the common vCPU next-instruction cache.  A test that checks
only CS/RIP or only the finalizer is insufficient; require a composed nonzero-
vector test and reject inconsistent private plan fields before event clear.

The Pass 29/30 replay must separately inspect established common primitives,
not merely the new staged consumer.  In particular, trace INIT through target
selection, inactive-target prepublication, active-target rendezvous, reset,
and the final wait predicate.  Compare virtual `IA32_APIC_BASE.BSP` behavior
with Intel SDM 11.11.1 and the pinned Linux/KVM INIT state transition: reset
both roles, leave the BSP runnable at the reset vector, and place only APs in
wait-for-SIPI.  Reject vCPU-number role assumptions, AP-only convenience
wrappers, debug-mask reuse, or a release build that can publish wait bits
outside the exact target set.  Repeat the private-boundary pass afterward and
prove that the staged finalizer and historical path express the same rule.
Follow the historical `VM_EXITCODE_IPI` consumer into bhyve as a separate
non-standard owner: AP INIT may remain suspended until SIPI, whereas BSP INIT
must reset and resume without SIPI.  A corrected kernel mask is not evidence
that this userspace compatibility path is correct.  Do not implement that
transition by reusing the legacy `vcpu_reset()` helper: its compatibility CR0
image and fallible multi-ioctl publication are not an atomic INIT transaction.
Treat the old path as an explicit activation blocker until the frozen kernel
machine transaction owns the complete reset and run-state publication.
Finally, execute the source/ledger requirements validator from the rootless
model orchestrator itself.  The value cases and live-ledger selftests are not
substitutes: a missing or broken requirements invocation invalidates the
entire review result even if every compiled model case passes.

When one startup transaction is embedded inside another, review the complete
result tuple as well as the errno.  A nonzero error is retryable only when the
inner operation proves that it is uncommitted, fully rolled back, and not
poisoned.  Treat an incomplete rollback, explicit poison, reserved-field
mutation, non-boolean flag, negative callback error, or contradictory success
shape as a separate fail-stop outcome.  Repeat this check once from the common
kernel primitive outward and once from the Intel-private consumer inward; do
not remove the production `ENOTSUP` gate until installed-kernel INIT/SIPI race,
BSP/AP, rollback, and VPID evidence is complete.

For VM-wide active-L2 restore, perform the doubled kernel/private traversal on
the complete destination ownership graph.  Treat the registry headers and
their separately allocated entries, the per-vCPU binding table, workspace
owners, immutable capability records, mutable plan/rollback arrays, and
generation outputs as distinct live ranges.  Prove all required disjointness
before acquiring the first workspace.  A failed rollback must retain the
generation that still identifies the owner; the kernel must fail-stop rather
than report an atomic restore failure after silently abandoning active scratch.

Repeat the startup scheduler review in both directions.  From the accepted
SIPI, prove that exactly the consumed wait-for-SIPI subset is cleared under
the rendezvous owner and that every accepted target is notified only after
that owner is released.  From the sleeping target, prove the
`rendezvous_mtx -> vCPU owner -> sleepqueue` enqueue interlock prevents a
clear-before-enqueue lost wake.  Then examine a single locked snapshot in
which SIPI clears the wait bit while rendezvous, suspend, reqidle, or debugger
work is already pending.  Lifecycle work must take precedence over runnable
return; no cleared startup bit may bypass a request already observed by that
snapshot.  Keep both races in the installed-kernel qualification ledger even
after the source and Werror gates pass.

For every VM-wide nested restore, repeat the destination review independently
of wire decoding.  Enumerate all runtime-only owners on the destination vCPU,
including startup dispatch, cold continuation, entry runtime, thaw/refreeze,
hot-failure recovery, EPT references and callbacks, hardware VMCS02 state,
resource leases, VPID, MTF, MSR workspace and exit transaction, prepared
plans, hardware-MSR transitions, and TSC_AUX residency.  Prove that the whole
inventory is quiescent before workspace acquisition or registry replacement.
Distinguish malformed owner state from valid but busy state.  Reverse-trace
every cache whose contents depend on guest memory: an idle shadow-translation
cache must be discarded after all destinations validate and before restored
architectural state is published, rather than surviving merely because it has
no active reference.  Then reverse the trace from every failure return and
prove that registry, architectural state, scratch generations, and opaque
resources remain unchanged; explicitly document safe loss of derived runtime
caches after validation.

Repeat that inventory independently on the snapshot source before considering
the encoder.  A stopped vCPU is not necessarily quiescent: startup dispatch,
thaw/refreeze, callbacks, leases, VPID/MTF, exit-MSR work, hardware MSRs, and
TSC_AUX rollback state can remain runtime-only.  Prove the complete source
fence executes before the first ordinary VMCS or nested byte is written, while
still admitting active L2 only in its detached cold-continuation form.  Do not
infer source safety from the destination validator or from encoder success.

Pass 39 must trace the future kernel startup dispatcher at the common vCPU
entry boundary in both event and lifecycle order.  Include an AP already
asleep in wait-for-SIPI with a new INIT pending, an accepted SIPI wake, and a
single snapshot that also observes rendezvous, suspend, reqidle, or debugger
work.  Define a bounded event-driven rule for IDLE, RETAINED, and CONSUMED;
RETAINED must permit L1 to run and remove a live blocker, while CONSUMED must
replay lifecycle and wait predicates before guest entry.  Do not wire the
machine step into `vm_run()` merely because the adapter compiles.

Pass 40 must rebuild the same boundary from every non-standard readiness and
machine-step definition without using Pass 39's caller inventory.  Verify the
complete enum and errno domains, failure-atomic output, frozen-target rule,
architecture support statement, teardown relationship, and absence of a
production caller.  AMD must remain a false-readiness `EOPNOTSUPP` provider;
Intel must map the private durable result exactly but remain false-readiness
and stop at the existing `ENOTSUP` apply gate.  Removing any gate restarts the
doubled kernel and non-standard reviews plus installed race qualification.

Pass 41 must trace the notification window rather than assuming the ordinary
vCPU notifier queues work for every state.  Start at startup publication,
observe that notification is intentionally inert while FROZEN, and follow the
target through RUNNING publication and machine entry.  Require a value-only
token containing every mutable event and claim field.  Capture the notification
generation before dispatch and after dispatch; idle and retained dispatch may
observe no transition, while consumed dispatch must observe exactly the one
claim-release notification it produces.  Reject a missing or extra transition
before arming the entry handoff, then validate the admitted post-dispatch value
only after RUNNING is visible.  A later commit before final validation must
force replay, while a publisher after that interrupt-disabled validation must
observe RUNNING and leave an interrupt pending for immediate guest exit.
Classify wrong owner/vCPU as stale, not retryable drift.

Pass 42 must independently reconstruct the eventual consumer from vCPU-state,
FPU, critical-section, notifier, and teardown paths.  Prove rollback to FROZEN
and host-FPU restoration on every token mismatch and provider error, lifecycle
priority after replay, dispatch-before-wait for a pending INIT, and a bounded
fairness rule for continuous coalesced publications.  The value token and
policy model are not activation evidence: retain the absent `vm_run()` call,
false machine readiness, and Intel `ENOTSUP` apply gate until installed races
cover publication before, during, and after RUNNING transition.

Pass 43 must discard the Pass 41/42 finding list and perform a second review of
the exact final kernel source.  Begin separately at `vm_run()`, every vCPU state
transition, `vcpu_notify_event()`, the startup generation-advancing notifier,
the event-coordinator spin owner, the Intel machine adapter, the AMD
fail-closed adapter, FPU save/restore, rendezvous,
suspend, reqidle, debugger, reset, destroy, and signal interruption.  Traverse
forward to hardware entry and backward from every unwind.  Prove lock ordering,
sleepability, notification delivery, output failure atomicity, positive errno
domains, bounded replay, and exact FROZEN/RUNNING plus host/guest-FPU symmetry.
Do not reuse the token or priority-table review as integration evidence.  A
clean pass must record source anchors and focused negative evidence; otherwise
fix the finding and restart Passes 41 through 44.

The repeated Pass 43 walk found that a handoff captured only after frozen
dispatch could absorb a concurrent publication as its baseline because the
ordinary notifier sends no IPI to a FROZEN target.  The corrected admission
protocol samples before and after dispatch and accounts for only the exact
consumed-claim self-notification.  Focused negative tests cover idle and
retained drift, missing and extra consumed transitions, exhaustion, malformed
results, and failure-atomic output.  This correction remains a dormant value
contract rather than production activation evidence.

Pass 44 must ignore the private ledger initially and independently rediscover
every non-SDM behavior in that same final-source slice from both definitions
and consumers.  Include the three-value dispatch result, retry versus stale
classification, run token, notification generation and entry handoff,
readiness switches, AMD unsupported result, Intel apply gate,
controller/ioctl ownership, diagnostics, DTrace and audit policy,
checkpoint exclusion, architecture scope, and any fixed retry or resource
bound.  For each item record owner, lifetime, concurrency domain, compatibility
promise, portable-state status, and negative test, then reconcile exactly with
the non-standard ledger.  Prove that no private success bypasses common
lifecycle work or Intel validation and that compiled dormant code cannot be
mistaken for supported behavior.

Pass 45 must review the architecture-neutral startup entry runtime model as a
proof obligation, not as production integration.  Enumerate every phase and
transition from frozen host-FPU ownership through critical entry, guest-FPU
restore, RUNNING publication, coordinator and notification checks, refreeze,
guest-FPU save, and critical exit.  Exercise successful entry, retryable drift,
non-retryable positive errors, invalid ordering, malformed flags, output
aliasing, negative errors, matching retry failures, retry-plus-terminal
failures, matching terminal failures, and conflicting terminal failures.
Require order-independent composition: duplicate `EAGAIN` replays, terminal
errors dominate `EAGAIN`, equal terminal errors retain identity, and conflicting
terminal errors fail closed as `EPROTO`.  Verify identical
unwind for replay and return, then mechanically prove that no live `vm_run()`,
VMX, or SVM consumer references the model.

Pass 46 must independently review the deferred activation boundary after Pass
45 without treating compiled value code as approval.  Reconstruct every
non-standard phase, action, errno, readiness flag, Intel apply gate, AMD
unsupported result, runtime-only epoch, token, handoff, diagnostic policy, and
serialization exclusion from definitions and consumers.  Require explicit
approval plus installed before/during/after-RUNNING races before inserting a
consumer into live VMX/SVM entry.  Any future insertion restarts Passes 41
through 46 and must prove exact hardware cleanup, FPU/state symmetry, bounded
event-driven replay, Linux/KVM L1 behavior, Linux/5BSD L2 behavior, checkpoint,
concurrency, signal, reset, close, and soak gates.

Pass 47 must restart the kernel-source review after the final correction,
without reusing Pass 43 findings or its source traversal.  Pin a fresh sorted
manifest and begin from four independent roots: publication, frozen dispatch,
final hardware entry, and unwind/teardown.  Walk each root forward and backward
through vCPU locking, coordinator ownership, notification generations,
pre/post-dispatch admission, RUNNING publication, interrupt disable, FPU state,
reset, suspend, debugger, signal, and destroy paths.  Require exact evidence
that every interval is covered, every error preserves or deliberately consumes
ownership, no sleep occurs under a spin owner, and every replay is event-driven
and bounded by work rather than a fixed polling count.  A finding restarts Pass
47 after the correction.

Pass 48 must perform the matching second non-standard review on the corrected
manifest without reading Pass 44's inventory first.  Rediscover private enums,
errno meanings, generations, tokens, handoffs, readiness and apply gates,
architecture limitations, resource limits, checkpoint exclusions, tracing,
audit, diagnostics, and experimental controls from definitions; independently
rediscover them from consumers; then reconcile both inventories with the
private ledger.  Prove absence from public ABI and portable state where stated,
prove fail-closed behavior on unsupported architectures, and require a focused
negative test for every private success or retry result.  Any mismatch restarts
Passes 47 and 48 and withholds activation.

## Pass 49: every backend hardware-entry boundary

Starting from the machine instructions rather than the common run wrapper,
enumerate every VMX and SVM loop edge that can execute another hardware entry
without first returning from `vmmops_run()`.  For each initial, nested, resume,
and backend-internal re-entry, require the same admitted coordinator token and
notification handoff to remain armed and to be checked inside the existing
interrupt-disabled window.  Treat a one-shot check as a correctness defect:
an INIT or SIPI notification may cause a hardware exit that the backend
handles internally, and it must force return to common frozen dispatch before
another entry.  Prove repeated successful checks do not consume ownership,
and prove retry or terminal drift after any internal exit uses the identical
RUNNING-to-FROZEN, guest-FPU-save, and critical-exit unwind.  Reconcile the
placement with an architecture-neutral NEED_CHECK/CHECKED/IN_GUEST/RETURNABLE
state machine whose exact counters make a second entry without a second check
invalid.  Reject malformed result domains, reserved fields, aliasing, invalid
order, and counter exhaustion without mutation.  Reconcile the
result with Linux/KVM's request checks and QEMU's run-loop boundaries without
copying code.  Keep the live consumer absent until installed Intel timing,
nested L1/L2, checkpoint, signal, reset, concurrency, and soak tests cover
publication before, during, and after a backend-handled exit.

## Pass 50: backend-loop ownership and return publication

Restart from guard-result producers and from common return consumers rather
than trusting Pass 49's phase machine.  Prove that the backend-loop owner
captures a canonical normal, replay, or terminal-error disposition before it
becomes RETURNABLE and that finish publishes that owned snapshot rather than a
separately retained mutable callback result.  Require canonical normal state
through NEED_CHECK, CHECKED, and IN_GUEST; require disjoint non-null output;
and reject malformed embedded state, aliases, invalid phases, counter drift,
and post-check mutation without changing either the loop or caller output.
Repeat the non-standard inventory independently: classify the disposition as
runtime-only private control state, prove it is absent from portable save
state, ABI, DTrace, audit, and live VMX/SVM/common-run consumers, and add a
focused negative test for each rejection.  A correction restarts Passes 47
through 50 on a fresh source manifest.

## Pass 51: action-domain and final-consumer semantics

Restart at every action producer and every branch in the eventual common
consumer.  Treat startup guard admission and backend return as different
private protocols.  Require an explicit checked translation from guard
REPLAY/RETURN_ERROR into backend-loop REPLAY/RETURN_ERROR, and represent an
ordinary unhandled hardware exit only as RETURN_VMEXIT.  Reject reuse of
ENTER_GUEST as a normal return, unknown values, action/errno mismatches, and
reserved bits without mutation.  Verify with focused tests that normal exit
cannot request another hardware entry and that retry and terminal identities
survive input mutation.  Re-run both corrected-source kernel and non-standard
inventories after any correction.

## Pass 52: first exact hardware-entry kernel traversal

Discard the earlier entry-edge inventory.  Begin at every concrete
`vmx_enter_guest()` and `svm_launch()` and walk backward through interrupt
disable, lifecycle checks, guest-event injection, descriptor capture, debug
register transition, TSC_AUX and MSR residency, pmap activation, VMCS
selection, nested cold/hot preparation, and common RUNNING/FPU publication.
Then walk forward through every hardware result, handled exit, re-entry,
synthetic exit, error, and common unwind.  Review ordinary VMX, initial L2,
resumed L2, hot L2, and SVM independently.  Do not accept a shared guard
callback unless each path proves exactly which resources are not yet owned or
which path-specific rollback releases them.

## Pass 53: reverse hardware-unwind kernel traversal

Do not read Pass 52's findings first.  Start independently from every
`enable_intr()`, `enable_gintr()`, descriptor restore, pmap deactivation,
guest-MSR exit, TSC_AUX transition, `VMCLEAR()`, refreeze, hot-residency abort,
`fail_intr`, `out_error`, `save_guest_fpustate()`, and `critical_exit()`.
Reconstruct the preceding entry path and prove that a guard retry or terminal
failure reaches one and only one valid cleanup class.  Look specifically for
CPU migration with a current VMCS02, L2 MSRs or TSC_AUX still resident,
double-refreeze, stale hot continuations, interrupts restored twice, pmap
activation leaks, and backend-handled exits that re-enter without a fresh
check.  Any finding restarts Passes 52 and 53 on corrected sources.

## Pass 54: definition-first private and non-standard replay

Build a new inventory from definitions only: private enums, phases, action and
errno domains, generations, tokens, handoffs, callback tables, provider IDs,
resource bounds, readiness/apply gates, architecture restrictions,
checkpoint exclusions, probes, audit policy, diagnostics, and experimental
controls.  Classify each item as transient common state, Intel runtime state,
AMD runtime state, or portable state.  Verify that no runtime pointer, native
layout, CPU-local ownership, x86 assumption, or undocumented outcome crosses
an ABI or save-state boundary.  Require unsupported paths to fail closed.

## Pass 55: consumer-first private and non-standard replay

Without using Pass 54's list, reconstruct the same contract from every result
consumer, branch, formatter, encoder/decoder, ioctl adapter, machine backend,
readiness gate, and teardown path.  Reconcile both inventories exactly with
the non-standard ledger and require an independent negative test for each
success, retry, terminal, malformed, stale, unsupported, and teardown result.
Compiled-but-unreachable code remains unsupported: mechanically prove the
activation consumer is absent until installed Intel timing, nested L1/L2,
checkpoint, reset, signal, close, concurrency, and soak gates pass.  Any
correction restarts Passes 52 through 55.

## Pass 56: forward composed-entry transaction review

Using the corrected source rather than Pass 52's notes, trace common RUNNING
publication through the failure-atomic guard admission to each ordinary VMX,
nested initial/resumed/hot VMX, and SVM hardware attempt, then back through the
failure-atomic return transaction and common unwind.  Separate pre-entry
lifecycle returns that execute no hardware from handled exits, ordinary VM
exits, post-entry `EAGAIN`, and terminal post-entry errors.  Reject placement
that records IN_GUEST before a fallible preparation step unless that failure
has an explicit transaction cancellation, and require every nested rejection
to select the already-proven residency-specific unwind.

## Pass 57: reverse composed-entry transaction review

Do not use Pass 56's path inventory.  Begin at every RETURN_VMEXIT, REPLAY, and
RETURN_ERROR consumer, every VMX/SVM cleanup label, and every nested refreeze,
abort, and fail-stop edge.  Walk backward to exactly one matching hardware
attempt and IN_GUEST record, then forward through host descriptor/debug/pmap,
MSR, TSC_AUX, VMCS, FPU, interrupt, and critical-section cleanup.  Report any
normalization of an error into a normal VM exit, double return transition,
unguarded handled-exit re-entry, or lifecycle return falsely counted as entry.

## Pass 58: definition-first composed-entry non-standard review

Build a fresh inventory from definitions of the handled flag, positive backend
errno, three-value backend return domain, counter phases, coordinator and
notification error composition, transient owner storage, Intel unwind action,
AMD unsupported path, readiness gate, tracing policy, and save-state/public-ABI
exclusions.  Prove zero, `EAGAIN`, and other positive post-entry results map to
RETURN_VMEXIT, REPLAY, and RETURN_ERROR respectively and that negative or
handled-plus-error shapes fail without mutation.

## Pass 59: consumer-first composed-entry non-standard review

Without reading Pass 58's inventory, reconstruct the contract from every
current test and every proposed common/VMX/SVM/nested consumer, formatter,
checkpoint path, and teardown edge.  Reconcile both inventories with the
non-standard ledger and demand negative evidence for null, alias, negative
errno, handled-plus-error, stale phase, counter drift, unsupported backend,
and post-entry unwind failures.  Keep the live consumer absent until Passes 56
through 59 are clean and installed Intel timing, Linux/KVM L1, Linux/5BSD L2,
checkpoint, reset, signal, concurrency, and soak qualification pass.

## Pass 60: forward stack-owned run transaction

Trace the proposed production owner from common FROZEN state in this exact
order: notification generation before dispatch, frozen machine dispatch,
notification generation after dispatch, handoff admission, post-dispatch
coordinator-token capture, critical entry, guest-FPU restore, RUNNING
publication, and the final interrupt-disabled checks before every hardware
attempt.  Continue across backend-handled exits and common unwind.  Explicitly
prove why a coordinator token captured before a consumed dispatch is invalid:
claim acquisition and release change its generation and active-claim fields.

## Pass 61: reverse stack-owned run transaction

Do not use Pass 60's inventory.  Begin at handoff disarm, token destruction,
common refreeze, host-FPU restoration, every VMX/SVM cleanup label, and every
nested typed unwind action.  Walk backward to the two frozen observations and
forward again through return.  Exercise publication in every interval,
checkpoint cancellation, reset/destroy, signals, handled exits, and backend
errors.  Report retained stack pointers, early disarm, split cleanup, or any
path that does not leave both owners valid until common unwind completes.

## Pass 62: definition-first stack-owner non-standard review

Inventory every field and operation of the proposed coordinator token,
notification handoff, runtime phase, backend loop, run-signature pointer,
errno/result domain, and readiness switch directly from definitions.  They
must be transient private values with named validation: not save state, not a
public KPI or ioctl, not a callback owner, not architecture-specific common
state, and never retained beyond synchronous `vmmops_run()`.  Require
failure-atomic construction, admission, return, disarm, and destruction.

## Pass 63: consumer-first stack-owner non-standard review

Without consulting Pass 62, reconstruct the contract from common `vm_run()`,
ordinary VMX, initial/resumed/hot nested VMX, SVM, trace and diagnostic sites,
checkpoint encoders, reset, and teardown.  Reconcile the two inventories and
the private ledger.  Demand independent negative tests for empty, alias,
reserved, stale owner, same-owner drift, consumed and retained dispatch,
concurrent publication, handled re-entry, positive/negative backend errors,
and nested unwind failure.  Any correction restarts Passes 60 through 63 and
keeps the live run signature unchanged until the corrected cycle is clean.

## Pass 64: forward cross-owner state-product review

Begin with the canonical BOUND owner and derive every reachable tuple of
outer phase, runtime phase/flags, loop phase/counters/disposition, token, and
handoff.  Require each newly reachable tuple to be introduced only by one
named failure-atomic owner operation with independent positive and negative
tests.  Generate the surrounding invalid Cartesian-product pairs and prove
that individually valid embedded owners are rejected when their combination
is unreachable.

## Pass 65: reverse retirement and destruction review

Do not use Pass 64's graph.  Begin with cleared stack storage and reconstruct
the only legal retirement paths through final coordinator/notification
arbitration, exact handoff lifetime, loop completion, refreeze, FPU save, and
critical exit.  Include pre-entry replay/error, ordinary VM exit, handled
re-entry, terminal backend failure, conflicting final errors, cancellation,
reset, destroy, and signal interruption.  Report any early clear, double
finish, retained pointer, or return that lacks one final disposition.

## Pass 66: definition-first outer-owner private review

Inventory the complete outer owner directly from definitions: phase domain,
embedded owners, counters, disposition, armed/reserved fields, output values,
and erasure.  Prohibit public ABI, serialization, architecture residency,
callback ownership, padding-based emptiness, and validation that checks only
the embedded values without their relationship.

## Pass 67: consumer-first outer-owner private review

Without consulting Pass 66, search every production and test consumer for
direct member writes, copied owners, retained addresses, formatting, tracing,
checkpointing, or architecture-specific assumptions.  Reconstruct the state
product from those consumers, compare it with Pass 64, and require the private
ledger and mechanical validator to reject all bypasses.  Any correction
restarts Passes 64 through 67 before live wiring.

## Pass 68: first no-entry kernel return review

Trace every `vmmops_run()` return that can occur without executing VMX or
VMRUN.  Include common lifecycle exits synthesized for suspend, rendezvous,
reqidle, AST, and debugger work; ordinary VMX nested-target selection;
initial, resumed, and hot nested-VMX preparation; and SVM setup.  Require a
typed software-exit transition for a valid synthesized `vm_exit` and a
separate positive-error transition for failed pre-entry preparation.  Neither
may increment the hardware-entry count or reuse the hardware-return label.

## Pass 69: independent reverse no-entry kernel review

Ignore Pass 68 and start at every common `error`, `retu`, and `vmexit`
consumer.  Walk backward through VMX, nested VMX, and SVM to determine whether
hardware was actually attempted and which machine cleanup owns the return.
Then walk forward through common refreeze, FPU restoration, critical exit,
final token arbitration, restart, and userspace return.  Reject an ambiguous
zero-entry hardware exit, an error that bypasses typed nested unwind, or a
synthesized exit that is converted into replay without a later owner change.

## Pass 70: definition-first no-entry private-result review

Inventory the software-exit action, pre-entry-failure operations, entry
counters, positive errno rules, final arbitration, and all reserved fields
directly from definitions.  Classify them as transient machine-independent
kernel policy rather than Intel architecture, public ABI, saved state, or a
claim that a hardware instruction ran.  Require disjoint outputs and
byte-identical failure behavior for null, alias, negative, zero-error failure,
wrong phase, malformed owner, and repeated completion.

## Pass 71: consumer-first no-entry private-result review

Without consulting Pass 70, reconstruct the result domain from common run
dispatch, VMX/SVM lifecycle branches, nested unwind classes, tracing,
statistics, checkpoint, reset, and teardown consumers.  Reconcile it with an
independent test matrix containing software exit before the first entry,
software exit after a handled entry, retryable and terminal pre-entry
failure, ordinary hardware exit, and final owner drift.  Any correction
restarts Passes 68 through 71 and then Passes 64 through 67.

## Pass 72: forward common frozen-admission review

Ignore the backend entry loops.  Start at common `vm_run()` restart with a
FROZEN vCPU and prove the exact kernel-owned admission sequence.  Lifecycle
work for rendezvous, suspend, reqidle, and debugging precedes startup
dispatch.  When none is present, bracket exactly one frozen dispatch with
notification-generation observations, then classify consumed as replay,
IDLE plus wait-for-SIPI as interruptible wait, and RETAINED or nonwaiting
IDLE as entry admission.  RETAINED must run the guest because no independent
wake source is guaranteed to remove its live architectural blocker.  A
pending SIPI must be dispatchable before a waiting AP sleeps.  Capture the coordinator token
after dispatch and construct the stack owner before critical/FPU/RUNNING
side effects.

## Pass 73: reverse common return and wait review

Do not consult Pass 72.  Begin independently at userspace return, restart,
startup-sleep wakeup, and cleared owner storage.  Walk backward through final
owner arbitration, common refreeze and FPU/critical unwind, machine return,
RUNNING publication, post-dispatch token capture, notification admission, and
the frozen dispatcher.  Prove no wait path retains an entry owner, no
consumed dispatch sleeps, no admitted owner reaches userspace uncleared, and
signals, cancellation, reset, checkpoint quiesce, and teardown have exactly
one bounded disposition.

## Pass 74: exact VMX, nested-VMX, and SVM placement review

Trace each actual `vmx_enter_guest()` and `svm_launch()` separately.  Identify
the final guard location before the instruction and the complete
architecture-specific cleanup required before classifying its result.
Ordinary VMX and SVM handled exits must return to recheck.  Nested VMX must
keep the attempt open across report and residency classification, use its
typed unwind before publishing an error, distinguish preparation failure
from an attempted VM-entry failure, and preserve whether a transformed
VMM_INTERNAL exit arose after hardware.  Reject generic shared labels that
obscure these classes or permit an unguarded second attempt.

## Pass 75: consumer-first live private-boundary review

Reconstruct the integration contract without reading Passes 72 through 74.
Inventory every future `vm_eventinfo` member, stack address, machine helper,
result translation, errno, trace, statistic, reset, checkpoint, and teardown
consumer.  Reject retained stack pointers, direct phase writes, transient
state serialization, public ABI, polling, architecture data in common state,
and readiness changes justified only by models.  Require mechanical
source-order checks, focused injected failures, strict kernel builds, and
installed Intel before/during/after-entry race evidence.  Any correction
restarts Passes 72 through 75 and keeps readiness false.

## Pass 76: forward frozen-admission transaction review

Ignore proposed production placement.  Begin at the private admission value
and walk forward through pre-snapshot validation, one dispatch-result and
notification-generation bracket, post-snapshot arbitration, final action,
and handoff publication.  Prove that pre-existing lifecycle work makes the
claimed transaction invalid, lifecycle work arriving during dispatch is
serviced afterward, CONSUMED becomes replay only when lifecycle is quiet,
and WAIT follows only a completed IDLE dispatch.  Prove that RETAINED always
enters so the guest can remove the blocker which retained the claim.  Require an armed
handoff exclusively for ENTER_GUEST and byte-identical output on all failure
paths.

## Pass 77: reverse frozen-admission transaction review

Do not consult Pass 76.  Start independently from each service, replay, wait,
and entry result and derive every allowed pre/post snapshot, dispatch result,
and generation predecessor.  Enumerate the complete Boolean snapshot product
for IDLE, RETAINED, and CONSUMED.  Reject DISPATCH as a final action, wrong
lifecycle precedence, armed non-entry results, empty entry results, drift,
overflow, malformed fields, overlap, and output mutation.

## Pass 78: definition-first admission private-interface review

Inventory the admission structure, action and dispatch domains, handoff,
snapshot, generation arithmetic, errno, reserved fields, and lifetime from
definitions only.  Confirm it is transient machine-independent private
kernel control state: not public ABI, save state, architecture residency,
polling state, callback ownership, or evidence that dispatch or hardware
entry occurred.  Check fixed-width representation and named-field semantic
validation rather than native-layout or padding assumptions.

## Pass 79: consumer-first admission private-interface review

Without consulting Pass 78, search all production and test consumers for
creation, copying, retention, formatting, tracing, serialization, clearing,
or direct member mutation.  Reconstruct the contract from those uses and
prove only ENTER_GUEST may construct the later stack owner.  Require source
checks preventing snapshot/output aliasing, wait-before-dispatch, ignored
lifecycle arrival, and accidental activation.  Any correction restarts
Passes 76 through 79 and then Passes 72 through 75.

## Pass 80: post-correction forward kernel entry review

Discard the earlier action table and begin at common `vm_run()`.  Trace the
FROZEN lifecycle snapshot, exactly one machine dispatch, notification bracket,
post-dispatch arbitration, typed admission-to-owner construction, critical and
FPU transitions, RUNNING publication, every ordinary VMX, nested VMX, and SVM
hardware-entry edge, handled-exit re-entry, and common unwind.  Prove RETAINED
always reaches execution which can clear its blocker, only IDLE may wait, and
each hardware entry consumes a freshly checked stack owner.  Report any
missing lock, wake source, cleanup, or failure-atomic publication.

## Pass 81: post-correction reverse kernel entry review

Do not consult Pass 80.  Start independently at each hardware-entry
instruction and each pre-entry software return.  Walk backward to the one
legal owner tuple and forward through every return and error label.  Look for
retained sleeps, internal re-entry without a new guard check, stale callbacks,
missed wakeups, polling, run-state/FPU imbalance, terminal-error demotion, or
claim loss.  Compare the resulting graph with the common runtime and nested
residency unwind models.

## Pass 82: post-correction definition-first non-standard review

Ignore the private ledger initially.  Inventory every non-SDM action, errno,
generation, callback, token, handoff, stack owner, readiness gate, trace/stat
value, compatibility promise, and deliberately unsupported behavior from its
definition.  Classify its lifetime and architecture scope.  Prove transient
control values do not leak into ABI or save state and that withheld behavior
cannot be activated accidentally.

## Pass 83: post-correction consumer-first non-standard review

Do not consult Pass 82.  Search consumers, tests, validators, formatters,
tracing, statistics, snapshot/restore, reset, teardown, and absent activation
edges.  Reconstruct each private contract and compare it with definitions,
the Intel SDM, pinned Linux behavior, and the private ledger.  Any correction
restarts Passes 80 through 83 and 76 through 79 and requires fresh normal,
sanitizer, strict-kernel, installed-race, checkpoint, fault, and soak gates.

## Pass 84: second machine-entry activation review

Treat the optional private `vmmops_run()` stack-owner parameter as inert until
the complete caller-to-retirement path is ready to activate.  From the
historical `NULL` caller and each proposed non-`NULL` caller, trace every
ordinary VMX, nested VMX, and SVM entry attempt.  Require a checked owner
inside every interrupt-disabled attempt window and before any guest-residency
side effect.  Classify each pre-instruction path as software exit or typed
pre-entry failure.  Do not accept a partial conversion, retained stack
pointer, direct phase mutation, or generic nested cleanup for initial,
resumed, and hot residency.

## Pass 85: reverse machine-entry and cleanup review

Independently begin at each `vmx_enter_guest()` and `svm_launch()` call, every
no-entry return, and every nested cleanup label.  Derive the unique legal
owner phase, entry count, handled/retry disposition, host-residency state,
and FPU/critical/run-state unwind.  Require handled exits to recheck the same
owner before another attempt, zero-entry paths never to become normal VM
exits, and common retirement only after the backend has restored host
residency.  Reject error demotion, missed final checks, and cleanup that can
drop a retained startup claim.

## Pass 86: dormant and non-standard activation-surface review

Inventory private owner plumbing, false readiness gates, model-only backend
paths, errno vocabulary, validators, trace/statistic omissions, and
unsupported behavior twice: definition-first and consumer-first.  Classify
each by lifetime and architecture scope.  Prove no transient field leaks into
public ABI, checkpoint state, a retained callback, or non-amd64 common code;
prove a rootless model cannot enable an Intel capability.

## Pass 87: cross-architecture and reference behavior replay

Review shared owner/admission logic for endian, word-size, alignment,
page-size, interrupt, and sleep assumptions.  Isolate Intel VMX and AMD SVM
details behind explicit machine operations.  Compare observable lifecycle,
entry, reset, suspend, and restore behavior with the cited Intel SDM and the
pinned Linux/KVM and QEMU references; classify differences without copying
reference implementation.  A correction restarts Passes 80 through 87 and
requires fresh independent model, sanitizer, strict-build, checkpoint,
fault, live-Intel, and soak evidence.

## Pass 88: common frozen-observation and dispatch transaction review

Review the live common `vm_run()` startup-dispatch slice independently of the
future stack owner.  Start at the exact FROZEN restart boundary and prove that
the lifecycle predicate and notification epoch are captured as one observation
under the documented lock order before and after exactly one backend dispatch.
Check every lifecycle result (rendezvous, suspend, reqidle, debugger, idle,
retained, consumed, malformed, and error): no pre-existing lifecycle action
may be dispatched past; a consumed request must replay; retained work must
enter rather than sleep; and no observation, admission, or output value can
leak into ABI, save state, a backend callback, or a non-amd64 interface.  Test
alias rejection, output non-mutation on error, epoch drift, and a publication
between the two observations.  This phase does not authorize a non-`NULL`
machine-run owner.

## Pass 89: consumer-first newly-live private-boundary review

Without using Pass 88's inventory, locate every consumer of the common
observation, dispatch result, admission action, notification epoch, and
readiness predicate.  Reconstruct the complete contract from callers,
locking, wait paths, machine backends, teardown, validators, tests, tracing,
and documentation.  Reconcile it with the non-standard-interface ledger and
the pinned Intel SDM, Linux/KVM, and QEMU observable behavior.  Reject a
hidden activation switch, direct field mutation, copied stack owner, polling
fallback, stale callback, or a test that proves only a local value model.  A
correction restarts Passes 88 and 89, then Passes 80 through 87, with fresh
strict-build and rootless model evidence; installed Intel, checkpoint, fault,
and soak evidence remains required before readiness can change.

## Pass 90: compiled-kernel and dormant-path second traversal

Review the exact compiled kernel source a second time, independently of the
value-model and requirement ledgers.  Trace every return from the common run
loop, ordinary VMX entry loop, nested VMX entry loop, and SVM entry loop,
including code currently held dormant by a false readiness predicate.  For
each path, record the vCPU state, interrupt state, FPU ownership, pmap
residency, startup-owner phase, hardware-entry provenance, error domain, and
final caller-visible disposition.  Check that no `__unused` owner argument,
false readiness stub, model-only callback, or diagnostic-only helper can be
silently promoted into live behavior by a local change.  Require the source
validator to reject a non-NULL owner or a live guard consumer until every
entry and unwind edge is converted together.  Reconcile the resulting map
with the Intel SDM's VM-entry/VM-exit model and classify Linux/KVM and QEMU
differences as behavioral references only.

## Pass 91: reverse non-standard contract and containment review

Starting from every private definition, loader/sysctl knob, cdev request,
machine-operation hook, provider callback, test-only symbol, trace point, and
future save-state field, rediscover the non-standard contract without using
Passes 88 through 90.  Prove each item has one owner, an explicit lifetime,
bounded resource behavior, an errno vocabulary, a reserved-field policy, and
an independent negative test.  In particular, prove that transient startup
owners, notification epochs, and backend pointers cannot become an ABI, a
wire record, a checkpoint field, a retained callback, or a non-amd64
dependency.  Reject undocumented activation aliases, polling fallbacks,
hard-coded platform assumptions, copied implementation constants, and tests
whose oracle is the implementation under test.  Any change found here
restarts Passes 88 through 91 and the preceding portability/reference passes;
readiness remains false until fresh strict-build, model, installed Intel,
checkpoint, fault, and soak evidence is collected.

## Pass 92: machine-entry edge matrix review

Build an independently derived edge matrix for the compiled `vm_run()`,
ordinary VMX, nested VMX, and SVM paths.  The rows are every pre-entry return,
each hardware entry instruction, each handled internal exit, each unhandled
exit, and every error/unwind label.  The columns are vCPU state, critical and
interrupt state, guest/host FPU state, pmap residency, VMCS/VMCB residency,
startup-owner phase, owner entry/check counters, and the precise caller
disposition.  Verify the matrix from source rather than model assumptions.
Before a real owner can cross the private run ABI, every row must have one
owner transition and one exact cleanup sequence; ordinary VMX, cold nested
VMX, resumed nested VMX, hot nested VMX, and SVM must not share a generic
cleanup merely because their visible errno matches.  Require the validator to
pin both the currently inert `entry_owner` parameters and the `NULL` call site
until this complete matrix has installed-kernel evidence.

## Pass 93: implementation-defined boundary and observability review

Review every behavior outside the Intel SDM, VirtIO specification, or stable
FreeBSD ABI as an explicitly owned implementation-defined contract.  Include
false readiness predicates, private startup commands, stack-only owners,
notification epochs, private errno mappings, cdev lifetime rules, trace and
counter behavior, diagnostics, model-only paths, and withheld feature gates.
For each, document scope, architecture ownership, lifetime, activation
condition, rollback/teardown behavior, resource bound, and independent test.
Then traverse from observable consumers back to each definition to prove that
neither a sysctl, a build option, a private ioctl, nor a local change to an
`__unused` argument can expose a half-integrated capability.  Compare
observable behavior with Linux/KVM and QEMU only where they provide a useful
compatibility reference; do not treat their private mechanisms as normative.
A finding restarts Passes 90 through 93 and all preceding kernel,
cross-architecture, and test-quality passes.  Readiness remains false until
strict build, independent model, installed Intel, checkpoint, fault, and soak
qualification is fresh.

## Pass 94: restore-residency and derived-cache review

Review every snapshot and restore field by class: architectural guest state,
portable derived state, source-host backend identity, and CPU-local execution
cache.  Begin at both VMX and SVM snapshot routines and trace each field to
the first destination hardware entry.  A historical wire field may remain for
format compatibility, but a failed or truncated restore must not mutate
runtime state and a successful restore must never make a CPU-local cache look
valid merely because CPU numbering, an ASID/VPID generation, or a host mapping
value coincides.  Require explicit invalidation/rebuild at the first real
entry, with no pointer, file descriptor, CPU id, host page size, or
architecture-private cache interpreted as portable state.  Compare the
observable migration contract with QEMU's versioned device state and KVM's
nested-state separation, but use the specification and the local snapshot ABI
as the authority.  Test normal, failed, truncated, same-CPU, cross-CPU, and
repeated restore cases independently; installed Intel and AMD execution remain
separate qualification gates.  A finding restarts Passes 90 through 94.

## Pass 95: historical common-record forward kernel review

Trace `VM_SNAPSHOT_REQ` for the retained `STRUCT_VM` record from the VMMDEV
all-vCPU lock through every byte consumed by `vm_snapshot_vcpus()` and the
startup-cpuset suffix.  Treat this native-order stream as a compatibility
decoder, not as the versioned VMS2 event format.  Prove bounded allocation
precedes the first restore read; each decoded candidate remains associated
with exactly one frozen destination slot; an absent slot cannot receive a
record; and a later truncation, invalid value, allocation failure, or topology
change leaves every generic vCPU field and `startup_cpus` unchanged.  Then
verify the post-validation publication contains only ordinary scalar/structure
copies and stage erasure.  Do not append pending-event state to this historical
stream: full event ownership belongs exclusively to the separately versioned
VMS2 transaction.

## Pass 96: historical common-record reverse and non-standard review

Without using Pass 95's path, begin at each live write to generic vCPU state,
the startup bitmap, stage destruction, and VMMDEV request dispatch.  Rebuild
the ownership and failure contract from all consumers, tests, checkpoint
tools, architecture snapshot callbacks, and compatibility definitions.  Flag
native-layout, pointer, host-time, page-size, CPU, or architecture leakage;
tests that use the decoder's own values as their oracle; undocumented partial
restore behavior; and any use of the all-vCPU ioctl lock as an excuse to skip
the decoder's own no-publication-before-complete-input invariant.  Compare
only observable state compatibility with KVM and QEMU.  A finding restarts
Passes 94 through 96 plus the earlier kernel and non-standard-interface
reviews; final qualification still requires installed Intel, fault, repeated
restore, Linux/5BSD checkpoint, and soak evidence.

## Pass 97: legacy architecture-exception inventory replay

Starting from every `XXX`, empirical capability condition, compatibility
filter, and fail-closed feature withholding in the VMX/SVM run paths, create
an architecture-scoped record before considering its callers.  Distinguish
Intel SDM requirements, AMD APM requirements, observed compatibility behavior,
and deliberate unsupported-feature policy.  For each value or branch, state
why accepting it cannot silently alter guest architectural state, save state,
or a cross-architecture contract; prove its fallback is conservative; and
require a source marker plus an independent negative or live trace test.
Specifically revisit SVM DecodeAssist segment attribution, rejected
`EFER_LMSLE`, the virtual-NMI IRET caveat, and VMX's invalid external-interrupt
information filter.  Current Intel hardware cannot qualify AMD behavior, and
an observed VMware compatibility case is not an Intel-SDM rule.  Any correction
restarts the common/kernel/non-standard review sequence and the Intel/AMD
qualification matrix.

## Pass 98: privileged qualification-runner boundary review

Review the root-only L1/L2 harness as an operational component, not a benign
test script.  Reconstruct the trust chain for its runner, bhyve executable,
images, working directory, manifest, artifacts, hashes, policy snapshot, and
final rename.  The two executed binaries must be executed through canonical
absolute paths whose complete parent chains are root-owned and
non-group/world-writable; the wrapper must use a fixed helper `PATH` and a
private umask before invoking any tool.  Image inputs may remain operator data
but must be immutable for the measured run.  Prove failed and
interrupted runs remove only their unpublished mode-0700 staging directory
without recursively changing artifact file permissions or link targets,
the timeout bounds the external runner, policy and input hashes are checked
before publication, and evidence cannot be reused across run identifiers.
The work directory itself must be root-owned mode 0700.  A root-owned sticky
ancestor such as `/tmp` may be accepted solely for that newly created work
directory, because its sticky ownership rule prevents non-root replacement;
never extend that exception to an executable or final staging directory.
Require a rootless structural guard plus an installed dry-run/failure test;
this harness does not make an unqualified nested feature supported.

## Pass 99: final independent common-kernel traversal

After all prior corrections, discard every earlier ownership graph and begin
at the final common VMM entry points: `vm_run()`, VMMDEV management, snapshot
decode/commit, reset, rendezvous, and destruction.  Follow each state-bearing
object through the architecture-neutral layer into the Intel adapter and back
again, including all no-entry returns, actual hardware entry attempts,
handled-exit re-entry, interrupt/FPU/critical-section transitions, and final
userspace return.  Verify that the common layer names only portable lifecycle
and transaction contracts; VMX- and SVM-specific residency, cache, and
instruction rules must remain behind their respective adapters.  Work from
both success and failure starts, verify every lock/generation boundary, and
require an independently compiled, function-local source map plus model and
negative tests.  A clean earlier VMX-only review is not a substitute for this
common-kernel pass.

## Pass 100: final independent non-standard decoder and policy replay

Without consulting Pass 99's inventory, reconstruct every non-standard
contract from final acceptance points and observable consumers: private
decoders, ioctls, management commands, sysctls, checkpoint compatibility
records, backend readiness gates, architecture filters, DTrace/audit/log
records, resource limits, timeout/cancellation paths, and test fixtures.
For each accepted value, prove reserved-field, version, length, ownership,
generation, authorization, rollback, stable-error, and teardown handling;
then compose it with the common-kernel contract from Pass 99.  Reject a
private compatibility rule that can bypass common lifecycle, portable
save-state, or architecture isolation.  Rebuild this inventory separately
from definitions and from consumers, and require an independent negative test
for malformed, stale, unsupported, exhausted, cancelled, and teardown cases.
Any correction restarts Passes 99 and 100 and the relevant earlier lifecycle,
portability, and live-qualification passes.

## Pass 101: second independent kernel implementation replay

Perform another final source review that does not reuse the Pass 99 traversal.
Start separately at VMX instructions, VMCB/VMCS resource setters, scheduler
and rendezvous callbacks, FPU/critical-section transitions, pmap/EPT/VPID
operations, interrupt and timer delivery, snapshot callbacks, module teardown,
and every error label that returns to common VMM code.  Trace each forward to
publication and backward to allocation.  For every state transition, prove
the lock/CPU context, ownership, generation, rollback, terminal error, and
architecture boundary.  Audit unchanged code and dormant signatures as real
future activation surfaces.  A built module or a model-only passing path is
not proof of this replay.

## Pass 102: implementation-defined and non-standard seam replay

Independently enumerate all behavior outside the Intel SDM and public VMM ABI:
private structures and cookies, readiness flags, error mappings, checkpoint
wrappers, test hooks, policy selectors, topology limits, timeouts/retries,
logging, DTrace/audit, compatibility fallbacks, and host-specific resource
assumptions.  Reconstruct the list both from definitions and from consumers.
For each seam prove validation, authority, owner, lifetime, generation,
architecture applicability, endian/alignment rule, failure atomicity,
observability, and direct success/rejection evidence.  Ensure none makes an
Intel-specific decision in common code or lets a private policy bypass an SDM,
portable snapshot, or common VMM lifecycle invariant.  Any correction
restarts Passes 99 through 102 and all affected earlier passes.

## Pass 103: second reverse kernel-lifetime replay

Perform a second kernel-source review independently of Passes 99 and 101.
Begin at final destruction, reset, module detach, snapshot rollback,
rendezvous cancellation, interrupt/event retirement, and every no-entry
failure label, then trace backward to the allocation or admission that made
the object reachable.  Cover unchanged common VMM code as well as the Intel
VMX and AMD SVM adapters.  For each object or CPU-local resource, prove the
last possible callback, waiter, IPI, host interrupt, pmap/EPT/VPID use, and
machine entry have all retired before memory, a lock, a VMCS/VMCB workspace,
or an owner record is released.  Distinguish a normative SDM/architecture
requirement from a local kernel lifetime rule; the latter must be recorded in
the private-contract ledger.  Do not accept a `KASSERT`, a model-only
success, or a successful normal teardown as proof that a release kernel
handles a late callback or failed rollback.  Require focused negative,
repeated-reset, and destruction-order evidence.  A finding restarts Passes
99 through 103.

## Pass 104: second private-policy and observability replay

Rebuild the non-standard inventory without using Passes 100 or 102.  Start
from diagnostic consumers, DTrace and audit probes, sysctls, loader tunables,
private ioctls, compatibility aliases, timeout and retry constants, test
hooks, checkpoint manifests, host-provider protocols, and unsupported-feature
gates.  Then independently start from each producer and acceptance point.
For every value prove whether it is a private implementation detail, an
operator policy, a versioned bhyve compatibility contract, or an experimental
interface.  Verify architecture applicability, privilege/authority,
range/reserved-field validation, bounded or deliberately ownership-preserving
wait semantics, rate limiting where a guest can trigger it, stable error
mapping, rollback, and teardown.  Ensure tests use independent values rather
than production headers and cannot pass merely because a feature remains
disabled.  No policy or observability seam may become an implicit public
VirtIO, Intel-SDM, or portable-checkpoint ABI.  A finding restarts Passes 99
through 104 and the affected normative, Linux/QEMU, lifecycle, portability,
and test-quality reviews.

The first Pass 45/46 execution split the proposed common entry/unwind proof
into eight exact phases rather than treating critical-section and FPU changes
as one opaque step.  Its independent test-quality replay found missing direct
assertions for corrupted phase flags, nonzero reserved state, result padding,
and attempted reuse after COMPLETE.  Those negative cases now preserve both
the runtime owner and caller output byte-for-byte.  The complete rootless
model passes 287 cases; the requirement and private-interface validators pass
375 and 212 rows respectively; and the full amd64 VMM module builds with
warnings as errors.  Mechanical call-graph checks confirm that common
`vm_run()`, VMX, and SVM still have no consumer.  Therefore this is clean
dormant-model evidence, not installed activation evidence, and Passes 41
through 46 restart if a live consumer is proposed.

The initial Pass 47/48 replay found the post-dispatch-baseline defect described
above.  Its integration-oriented repetition then found that the runtime model
rejected two simultaneous token errors even though one publication normally
invalidates both the coordinator token and notification handoff.  Error
composition is now deterministic and failure-atomic as specified in Pass 45.
Pass 49 then found that a one-shot successful check was still insufficient:
both machine backends can handle an exit and perform another hardware entry
without returning from `vmmops_run()`.  CHECKED state now permits repeated
ownership-neutral validation, and drift after any prior entry requests the
same common unwind and replay.  A separate backend-loop model now makes the
required check, entry, handled exit, and return transitions explicit instead
of relying on call-count convention.  Pass 50 then found that RETURNABLE
depended on an externally retained mutable result.  The loop now owns the
validated disposition, requires canonical normal state before RETURNABLE, and
publishes the snapshot failure-atomically through a disjoint output.  After
correction, Pass 51 separated guard admission from backend return: an ordinary
unhandled exit now produces RETURN_VMEXIT rather than overloading ENTER_GUEST,
and replay/error values cross through an explicit checked translation.  The
fresh source and
consumer inventories found no additional kernel or private-contract mismatch.
The handoff remains absent
from public ABI, save state, probes, audit records, VMX/SVM entry, and common
`vm_run()`; those absences are mechanically checked rather than inferred from
the readiness gates.

Passes 52 and 53 then rebuilt the still-dormant production placement from the
hardware instructions and, independently, from cleanup labels.  They found
that ordinary VMX and SVM can reject before acquiring their per-attempt
descriptor/debug/pmap residency, but nested VMX cannot be represented by one
undifferentiated guard-error edge: cold-unentered, resumed, and hot-resident
attempts have distinct refreeze or abort ownership.  No live callback or run
signature was added.  Passes 54 and 55 classify the proposed guard, loop,
token, and handoff as transient private control state and require the eventual
consumer to select the proven path-specific unwind rather than serialize or
export that state.

For common all-vCPU checkpoint composition, treat the startup-wait cpuset and
pending-event generation as separate owners.  Capture the cpuset under
`rendezvous_mtx`; bind a restore plan to the destination value; and reject
commit if INIT/SIPI changed it before publication.  Frozen vCPUs do not make an
unlocked cpuset read valid and do not reserve management-plane startup state.
Repeat the lock-order review from both `vm_start_cpus()` and restore commit.

For Intel VM-wide restore, distrust dispatcher ordering at the private cookie
boundary.  Re-prove at decode and completion that every present sparse vCPU
has exactly one staged record, no absent vCPU has one, and the staged VM owner,
generic vCPU pointer, and identifier all match the live slot.  Perform this
before derived-cache retirement, workspace acquisition, registry replacement,
or architectural publication.  On the source, validate the nested context
itself—not only adjacent runtime owners—as quiescent or as the exact pending
cold continuation before ordinary VMCS serialization.

### Pass 7C: all-vCPU architecture publication

Starting from `vm_snapshot_vcpu()`, verify that `STRUCT_VMCX` restore is a
single frozen-VM transaction.  Per-vCPU candidate decoding is necessary but
not sufficient: a failure while decoding or committing sparse vCPU *n* must
leave every earlier vCPU and VM-wide nested state unchanged.  Inventory the
private lifetime of every VMCS field rollback image, VMCB shadow, software
context, nested restore stage, and completion callback.  Require bounded
non-sleeping allocation before frozen publication; exact rollback or a
fail-closed boundary for a late hardware setter failure; no pointer, host CPU,
or provider identity in the portable image; and retry after failure.  Cover
each sparse-vCPU index, truncation position, injected VMREAD/VMWRITE/VMCB
setter failure, cross-vCPU isolation, and a repeated same-host restore.  Do
not mistake a successful VM-wide nested completion callback for proof that
ordinary VMCS/VMCB fields were committed atomically.

The implementation uses this completion boundary now: SVM holds each decoded
VMCB/software candidate in a bounded per-VM stage; VMX holds the explicit
VMCS candidate, exact rollback image, and software candidate beside its
nested stage.  VMX first applies all VMCS candidates, then invokes the
rollback-capable nested registry transaction, and publishes software/nested
state only after both succeed.  Re-review that exact ordering after every
change.  It still needs hardware fault injection on Intel and AMD; a model or
warnings-as-errors build cannot demonstrate a failed VMWRITE/VMRUN setter.

In Pass 33, mechanically enumerate every kernel function that performs more
than one indirect callback, including repeated guest-memory reads hidden in a
loop and callbacks retained inside a durable owner.  For a single public
operation, capture the complete provider table before the first callback.  For
a durable owner, copy the provider table into owner storage at construction;
do not retain caller-owned callback storage.  Trace allocation to release,
detach to later release, plan to commit, and side effect to claim completion.
Mutation tests must change the original table from the first callback and
prove that later work uses the admitted provider.

In Pass 34, rebuild that inventory without using Pass 33's list.  Start from
every non-SDM type containing a function pointer, opaque cookie, provider ID,
generation, or host pointer.  Classify whether its identity is per-call,
runtime-durable, cross-domain staged, or portable.  Provider IDs may bind
runtime staged ownership but must not enter portable checkpoint state.  Check
all prerequisite pointers before copying a provider table, preserve typed
positive errno results, and distinguish a provider identity from the concrete
VMCS02, VPID, EPT-root, or generation-bound resource it operates on.

## Pass 105: terminal kernel callback-current-owner review

Trace every nested-VMX and common VMM callback from its kernel entry through
the final callback, wakeup, queue re-arm, or state publication.  Begin at
interrupt, rendezvous, callout, event-ingress, snapshot completion, provider
detach, and vCPU destroy paths rather than from the owner constructor.  For
each retained object, prove that the receiver still owns the exact context,
generation, and provider identity immediately before the operation can touch
machine or staged state.  A global non-NULL test is not an ownership proof;
replacement, invalidation, teardown, and failed restoration must stop the old
path before it touches its retired resource.

Repeat this review independently from owner withdrawal and cleanup labels.
Require a direct model mutation test at every non-standard callback boundary
which can replace or revoke an owner.  Such tests must prove unchanged staged
and architectural state, no stale wakeup or callback, and no portable image
containing the runtime identity.  Any correction restarts Passes 99 through
105 and the affected save-state and startup-owner reviews.

## Pass 106: second restore-resource publication review

Trace each restore-owned resource from allocation or borrowing through failed
decode, frozen destination validation, VMCS candidate application, registry
replacement, software publication, successful transfer, and final teardown.
Cover ordinary VMCS/VMCB images, nested VMCS registries, EPT roots, VPIDs, MSR
workspaces, continuation state, event sessions, and every backend identity.
For a fresh destination allocation, prove that an unpublished stage owns it
until the last fallible VM-wide commit succeeds; a failure must unbind, wipe,
and release it exactly once without changing the destination.  For a
pre-existing destination allocation, prove that reuse is explicit, validated,
bounded, and cannot make rollback retain new generation, active, or callback
state.  Re-run the traversal starting at each cleanup label and at each final
publication assignment.  Record non-SDM ownership rules in the private ledger
and add a direct model or fault-injection test for every transfer boundary.
Any correction restarts Passes 99 through 106 and the affected save-state and
startup-owner reviews.  A terminal synthesis must reconcile this
restore-resource inventory with the callback-owner inventory, independent
common-kernel traversal, and private-policy inventory before it records a
clean cycle; rootless model results remain evidence of the model only, never
live Intel VMX qualification.

## Pass 107: opaque-provider transfer and rollback replay

Independently enumerate every private callback which creates, acquires,
releases, invalidates, destroys, maps, unmaps, allocates, or returns an opaque
runtime object.  Start once at each callback declaration and once at each
failure/rollback label, without borrowing the owner inventory from Pass 105.
For every successful callback, state exactly whether ownership, a reference,
or only a borrowed capability was transferred; then prove that every local
validation rejection, replacement, eviction, abort, reset, detach, and
restore failure returns that transfer exactly once.  A duplicate object
identity is not proof that no transfer occurred: distinguish an invalid
provider response from a retained object and preserve the provider's explicit
ownership contract.  Conversely, never invent a destroy/release operation
where the declared contract supplies only a borrow.  Require callback-recursion
protection, retained-table identity, unchanged caller outputs on failure, and
tests that inject duplicate identities, stale references, callback failures,
and rollback failures.  Record all non-SDM provider semantics in the private
ledger.  Independently enumerate every explicit `ENOTSUP` return in nested
sources: identify the withheld feature, prove that no related capability is
advertised, and record its enabling prerequisite and live test under the
source's private-ledger mapping.  The validator requires source-level
coverage; the review must still resolve the individual returns.  Any correction restarts Passes 99 through 107 and the affected
callback-owner, restore-resource, portability, and live-qualification
reviews; model evidence alone does not establish Intel hardware behavior.

## Pass 108: second common-kernel lifecycle and portability replay

Independently reconstruct the common VMM contract used by nested VMX from
shared primitives outward: vCPU lifetime and rendezvous ownership, frozen and
running publication, guest FPU state, interrupt and event delivery,
guest-memory/DMA mappings, sleep and wake predicates, devfs and cdevpriv
ownership, credentials, prison/VNET policy, module teardown, and snapshot
dispatch.  Then enumerate every AMD64 consumer, including ordinary VMX,
nested VMX, SVM, snapshot, and bhyve-facing adapters, and prove that it
preserves the common contract across success, no-entry return, failure, reset,
destroy, checkpoint, and restore.

Do not assume an Intel host fact is a common guarantee: pointer width,
endianness, page size, CPU residency, interrupt masking, VMCS format, VPID,
and pmap semantics belong behind explicit architecture adapters.  Rebuild the
trace from definitions and consumers rather than from the prior kernel or
provider inventory.  Any correction restarts Passes 99 through 108 and all
affected lifecycle, save-state, portability, and qualification reviews.

## Pass 109: second non-standard operational and decoder replay

Independently inventory all accepted values and operational seams which are
not defined by the Intel SDM or the public VMM ABI: nested exposure policy,
sysctls and ioctls, startup controls, provider records, opaque cookies,
checkpoint envelopes and manifests, compatibility selection, limits,
timeouts, retries, DTrace/audit/MAC hooks, debug/fault injection, withheld
features, and test-only controls.  For each, follow input parsing through
validation, authorization, namespace and generation binding, architecture
scope, persistence, error/rollback, cancellation, and observability.

Require independent positive and rejection or withdrawal evidence for every
private contract.  A compatibility behavior observed in Linux or QEMU may
motivate an interoperability check but cannot define FreeBSD policy or weaken
an SDM requirement.  Build the inventory from consumers and accepted inputs,
not the ledger.  Any correction restarts Passes 99 through 109 and all
affected earlier reviews; model results remain distinct from required Intel
hardware, Linux-L1/L2, and 5BSD-L2 qualification.

## Pass 110: staged common-owner kernel implementation replay

Review the final composed `vm_run()` path and every VMX/SVM run adapter after
the shared startup owner is threaded through the common AMD64 entry boundary.
Trace from a frozen INIT/SIPI admission through token capture, owner
construction, critical section, guest-FPU transition, RUNNING/FROZEN
publication, synchronous backend return, final FPU/critical unwind, owner
retirement, and userspace disposition.  Repeat the trace backwards from every
ordinary VMX entry/re-entry, cold/resumed/hot nested-VMX edge, and SVM VMRUN
edge.  Treat any backend that does not consume the owner as a deliberate
staging condition only if it rejects before machine-state acquisition and the
common path produces one typed no-entry unwind.

Do not infer correctness from the public readiness predicate being false.  In
particular, test that a non-ENTER admission never constructs an owner, that a
backend rejection cannot strand VCPU_RUNNING, host guest-FPU state, or a
critical section, and that replay retries only after retirement.  Compare the
shape with the Intel SDM's entry/exit constraints and Linux/KVM's separation
of common run-loop policy from VMX-specific preparation, without importing
their implementation.  Any correction restarts Passes 99 through 110 and the
affected source, model, save-state, and future installed-kernel qualification
reviews.

## Pass 111: staged common-owner non-standard contract replay

Independently reconstruct the non-SDM contracts introduced or relied upon by
the staged common-owner boundary: event-run token generation, admission
handoff, owner phase/result encoding, the meaning of `EOPNOTSUPP` before
backend conversion, readiness gating, diagnostics, model-only evidence, and
the separation between a transient stack owner and portable snapshot state.
Start at accepted values and consumers rather than the private ledger.  Prove
that no ordinary guest, ioctl, sysctl, snapshot, trace, audit, DTrace, or
cross-architecture consumer can select this staged path while readiness is
false; prove the same restriction remains valid if a backend is built but not
yet converted.

Require direct positive and negative evidence for the common owner lifecycle,
backend rejection before VMX/VMCB state acquisition, stale-token rejection,
and no owner pointer or host-private phase in a portable state record.  Record
every remaining Intel-only live gate separately from rootless model/build
evidence.  Any correction restarts Passes 99 through 111 and all affected
normative, lifecycle, portability, Linux/QEMU-comparison, and test-quality
reviews.

## Pass 112: nested VMCS02 owner-conversion feasibility replay

Before allowing a non-NULL common startup owner into `vmx_run_nested()`, map
the cold initial-entry, resumed cold-entry, and hot re-entry paths separately.
For each path, enumerate the exact point at which VMCS02 becomes current, L2
MSRs and TSC_AUX become resident, an EPT root is active, the descriptor/debug
preparation is live, and the event transaction becomes committed.  Starting
both from the guard candidate and from every `fail_intr`, `refreeze_first`,
hot-freeze, VMfail, synthetic-event, shutdown, and outer-exit label, prove
which typed unwind preserves a frozen portable continuation and which must
detach fail-stop.  A common owner may be checked only after the complete
pre-entry preparation has a tested reverse operation and before the precise
VM-entry instruction; it must never be used to relabel an L2-resident return
as a no-entry software exit.

Compare the resulting observable phases with the Intel SDM distinction among
VMfail, VM-entry failure, and a VM exit, then compare lifecycle shape—not
source text—with Linux KVM's VMCS01/VMCS12/VMCS02 split and QEMU migration
boundaries.  Preserve bhyve's existing userspace exit semantics.  Require an
independent value-model for all source shapes, a source-order check for each
converted path, fault injection at every pre-entry reversal, and later Intel
host/L1/L2 evidence.  Until all three nested paths satisfy that proof, retain
the current `EOPNOTSUPP` boundary and public readiness false.  Any correction
restarts Passes 99 through 112 and all affected lifecycle, checkpoint,
portability, Linux/QEMU-comparison, and live-qualification reviews.

## Pass 113: second kernel execution-path review

Repeat the kernel source review without reusing the prior path inventory.
Begin at every architecture entry instruction and walk outward: `VMRUN`, the
ordinary VMX entry instruction, and each nested VMCS02 entry or re-entry.
For each return site, classify whether it is a lifecycle software exit, a
declined pre-entry guard, an instruction failure, a real guest exit, or a
fatal nested unwind.  Check that interrupt state, pmap/EPT or NPT residency,
debug and descriptor state, guest and host MSR state, FPU state,
critical-section ownership, vCPU state, and startup-owner phase are balanced
on both the forward and reverse paths.

Pay particular attention to assertions inherited from loops that assumed an
entry instruction had run: a typed no-entry return must not trip such an
assertion, but it must not weaken it for a real entry attempt.  Verify that
common code remains architecture-neutral and that Intel-only VMCS02 state does
not leak into portable save state or the SVM path.  Require a focused model
mutation or source-order assertion for each correction.  This is static/model
evidence only and does not replace Intel or AMD hardware qualification.

## Pass 114: second private-interface and non-standard containment review

Independently rediscover all interfaces not defined by the Intel SDM, AMD
manuals, or public VMM ABI that participate in a machine run: startup tokens,
entry owners, readiness gates, `EOPNOTSUPP` staging behavior, checkpoint
envelopes, policy tunables, debug/fault controls, private generation values,
and test-only hooks.  Start from parsers, writers, and consumers rather than
from the ledger.  For every value, identify its owner, lifetime, architecture
scope, persistence rule, error domain, observability, and rejection behavior.

Reject retained stack addresses, host pointers in portable state, accidental
activation through a private knob, raw errno reinterpretation, hidden
cross-architecture assumptions, polling where an event boundary exists, and
tests deriving expected values from implementation headers.  Reconcile the
inventory with the non-standard ledger and require each intentional private
contract to have positive and rejection evidence.  Any correction restarts
Passes 99 through 114 and the affected architecture, save-state, portability,
Linux/QEMU comparison, and live qualification gates.

## Pass 115: nested guard-result and unwind-outcome composition review

For every proposed nested VMCS02 owner guard, follow both results of the
guard before changing code: the selected replay or terminal owner disposition,
and the cold/resumed/hot residency unwind selected after that point.  Prove
that they have compatible terminal meaning.  A guard result becomes
RETURNABLE immediately; it must therefore never cause common retirement to
replay a continuation which the nested unwind had to detach, invalidate, or
turn into a different terminal error.

Inventory initial rollback, cold refreeze, hot freeze, and fatal hot detach
separately.  If all applicable reversals preserve the result, record the
exact guard placement and test it.  Otherwise retain the pre-residency
fail-closed boundary, or introduce one private typed composition transaction
which validates local copies and gives a required terminal unwind error
dominance over replay.  Model a stale-token replay paired with every unwind
class and require later Intel fault and hot-reentry qualification.  Do not
serialize or expose this transient composition in portable state.

## Pass 116: deferred common-owner commit review

Review the common startup-owner state machine for the one operation required
by a future nested VMCS02 conversion: observe a pre-entry guard at the exact
machine boundary, retain its replay/error result while private reverse
cleanup runs, then publish either the preserved result or a terminal unwind
override exactly once.  The common operation must be architecture-neutral,
stack-only, failure-atomic, and must preserve check/entry provenance.  It
must not expose Intel residency, VMCS identity, or a private error enum.

Trace all current consumers of the one-phase guard.  They must retain their
existing behavior unless explicitly converted, including ordinary VMX and
SVM no-entry cleanup.  Reject any design that lets an Intel adapter write a
common owner field directly, repeats the live token/handoff observation after
private cleanup, treats a terminal unwind as replay, or leaves a pending owner
reachable by common retirement.  Add independent transition-model and alias,
invalid-error, repeated-resolution, and final-retirement tests before using
the operation in VMCS02 paths.  Compare lifecycle shape with Linux KVM's
private VMCS02 teardown and QEMU's migration stop/error behavior, while using
the Intel SDM—not either implementation—for VMX instruction semantics.

Until that review and its model prove the complete transaction, retain the
current nested `EOPNOTSUPP` boundary and readiness false.  Any correction
restarts Passes 99 through 116 and all affected portability, lifecycle,
checkpoint, Linux/QEMU-comparison, and Intel qualification reviews.

## Pass 117: deferred-owner kernel state-product replay

Perform a second, source-complete kernel review of the common deferred-owner
primitive without using the Pass 116 finding list.  Start with every write to
`vmm_startup_entry_owner`, its runtime result, and its loop result, then trace
forward to every validator and consumer.  Enumerate BOUND, CRITICAL,
GUEST_FPU, RUNNING, IN_GUEST, RECHECK, DEFERRED, RETURNABLE, REFROZEN,
HOST_FPU, and COMPLETE.  For DEFERRED, prove both permitted products:
unentered RUNNING with a replay/error observation, and re-entry CHECKED with
the same observation.  Prove that every other product, an ENTER result, a
zero or negative result error, reserved bytes, stale loop action, duplicate
resolution, or a pending state at common retirement is rejected without
mutation.

Review every ordinary VMX and SVM consumer to confirm that it still uses the
one-phase operation and cannot accidentally produce DEFERRED.  Review the
future nested adapter boundary to confirm that it must resolve exactly once
before returning to common `vm_run()`, before FPU/critical retirement, and
before any retry decision.  No architecture-specific implementation may
write the deferred result field directly.  Require an exhaustive independent
state-product model which constructs valid and invalid DEFERRED tuples, plus
failure-atomic alias and resolver tests.  This is a common-kernel review; it
does not authorize VMCS02 conversion or replace Intel hardware qualification.

## Pass 118: deferred-owner private-contract and non-standard review

Independently inventory the non-standard contracts introduced by deferral:
the meaning of a temporarily retained guard decision, terminal private-unwind
error dominance, the distinction between a replayable admission and a
detached continuation, the fail-closed nested `EOPNOTSUPP` boundary, and the
rule that this stack-only record is absent from snapshots, public ABIs,
tracing payloads, and cross-architecture state.  Build the inventory from
all writers, callers, tests, and error returns rather than from the private
ledger.

For each contract, document owner, lifetime, architecture scope, allowed
errno domain, cleanup authority, observability, rejection behavior, and
positive plus negative evidence.  Reject use of a private error enum in
common state, conversion of a fatal cleanup into `EAGAIN`, resolution after
the owner has entered retirement, policy activation through a tunable, and
tests that only inspect internal fields without exercising the transition.
Compare lifecycle shape with Linux/KVM and QEMU only as explanatory
references; the Intel SDM and public VMM ABI continue to control semantics.

Until both passes and the subsequent terminal post-entry composition review
are clean, retain the current nested `EOPNOTSUPP` boundary and readiness
false.  Any correction restarts Passes 99 through 118 and all affected
kernel, private-contract, save-state, portability, Linux/QEMU-comparison, and
Intel qualification reviews.

## Pass 119: post-entry deferred-owner kernel transaction review

Review the post-entry deferred-owner primitive independently from the
pre-entry form.  Trace an actual guest entry through an unhandled VM exit,
the private freeze-or-detach operation, the final common loop disposition,
FROZEN publication, and retirement.  The recorded post-entry result must be
derived once from an `IN_GUEST` loop state but that live loop state must remain
unpublished until private cleanup proves a frozen continuation or supplies a
non-retryable terminal error.  A handled exit must retain the ordinary
recheck-before-re-entry path and may not use this terminal defer operation.

Enumerate normal VMEXIT, replay, terminal backend error, successful freeze,
failed freeze, fatal detach, duplicate resolution, invalid EAGAIN override,
and aliasing.  Verify the stored result is a loop result—not a private VMX
result—and that its validation is local rather than an accidental dependency
on a hidden implementation-private helper.  Require model evidence that
exactly one completed loop disposition is published and no owner reaches
FROZEN while still DEFERRED.  This common primitive alone does not authorize
live nested VMX conversion.

## Pass 120: post-entry deferred-owner non-standard containment review

Rebuild the private-contract inventory for post-entry deferral from all
writers and consumers.  Distinguish a successful portable freeze from a
terminal Intel-private detach; only their generic non-retryable outcome may
cross into common state.  Confirm that no deferred record contains VMCS02,
EPT, pmap, MSR, CPU, pointer, provider, or snapshot identity, and that no
public ABI, trace schema, sysctl, or readiness toggle exposes the operation.

Confirm all current VMX/SVM consumers remain one-phase and that nested VMX
remains `EOPNOTSUPP` before any residency until the complete cold, resumed,
and hot source-order conversion and qualification are reviewed.  Any
correction restarts Passes 99 through 120 and all affected lifecycle,
portability, state, Linux/QEMU comparison, and Intel hardware gates.

## Pass 121: deferred-owner live-observation boundary review

Review the vCPU-facing boundary separately from the architecture-neutral
owner state machine.  A deferred pre-entry guard must obtain the coordinator
token and notification generation exactly once at the real vCPU boundary,
then hand both values to the common deferred operation.  Once that operation
returns a retained result, resolution is cleanup-only: it must not recapture
either observation, re-admit entry, or turn a newer notification into a
different historical decision.  Post-entry deferral must likewise derive
only from the actual exit result and must not read the pre-entry handoff.

Trace every vCPU wrapper and every direct common deferred caller.  Reject
duplicate observation wrappers, a vCPU-shaped wrapper which merely suggests
an observation while taking none, direct adapter writes to deferred fields,
or a resolver that consults live vCPU state.  Confirm the existing one-phase
ordinary VMX and SVM wrappers retain their two-observation behavior.  This
phase records the non-standard timing rule; it does not authorize nested
VMCS02 conversion, readiness, snapshot exposure, or a new public ABI.

Any correction restarts Passes 99 through 121 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, and Intel qualification
reviews.

## Pass 122: nested no-entry disposition and unwind review

Independently enumerate every `vmx_run_nested()` path that returns, breaks,
or reports an internal exit without executing `vmx_enter_guest()`.  Separate
the already-safe outer lifecycle stop from cold preparation, resumed thaw,
event planning, VMCS02 launch selection, pmap activation, and hot
continuation cases.  For every later path, identify exactly which private
resources remain owned and the source-ordered inverse operation required
before a common owner could become returnable.

Do not collapse these paths into a generic software exit merely because no
L2 instruction ran.  A no-entry result is owner-safe only after its selected
rollback/refreeze/detach transaction has completed and a generic result has
been composed without private residency.  Verify that the current source
permits owner consumption solely for the initial lifecycle stop and otherwise
returns `EOPNOTSUPP` before guest MSR, VMCS02, EPT, or event ownership.  Add
the exact cold/resumed/hot conversion only as a single source-order change
with independent path models and installed Intel qualification.

Any correction restarts Passes 99 through 122 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 123: selected-unwind action handoff review

Review the nonstandard, Intel-private handoff from `vmx_nested_run_unwind_intel`
to a future deferred startup-owner transaction.  The selected unwind action is
the only pre-cleanup fact a caller may need to compose a generic guard or exit
result with the cleanup result.  It is not a substitute for the unwind result,
and it must not expose VMCS02, EPT, pmap, MSR, CPU, pointer, or snapshot state.

Verify that selection is validated before publication; the optional output is
written exactly once before its corresponding inverse operation; recoverable
actions return the original error only after their inverse succeeds; terminal
actions return a non-replay terminal error; and fail-stop paths never publish a
fictional returnable result.  Existing callers must deliberately pass `NULL`
until the complete cold/resumed/hot owner transaction is installed.  Reject a
caller which re-selects from post-cleanup facts, guesses an action from an
errno, serializes the action, or enables nested readiness from this seam.

Compare only observable lifecycle shape with Linux/KVM and QEMU as explanatory
references.  The Intel SDM and the public VMM ABI control behavior.  Require
the independent selector/outcome models and source-order gate to remain clean;
this phase does not authorize partial VMCS02 owner conversion or live nested
execution.

Any correction restarts Passes 99 through 123 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 124: VMCS02 transaction-boundary completeness review

Trace `vmx_run_nested()` as a transaction graph, not as one apparent
`vmx_enter_guest()` call.  Independently account for: initial cold event
shutdown and synthetic reflection; resumed thaw plus pmap failure/refreeze;
hot stop/freeze; hot synthetic reflection; VMCS02 instruction preparation;
pmap/debug/descriptor residency; an actual guest entry; initial and resumed
hardware rejection; EPT/reflected exits; handled hot re-entry; and unhandled
or reflect-to-L1 freeze.  For each edge, state whether L2 executed, which
private resources can be live, the only permitted inverse action, and whether
a common owner can be deferred, resolved, or must remain rejected.

Require a future conversion to install the pre-entry deferred guard only after
the final machine-local preparation and before the L2 instruction, to resolve
it only after the selected inverse action, and to install post-entry deferral
only after a real entry and before any terminal freeze/detach.  Handled exits
must use a fresh ordinary recheck before re-entry.  No synthetic or rejected
path may be treated as an actual L2 exit merely to reuse post-entry logic.

Validate the graph against the independently maintained edge matrix and value
models.  The matrix is a source-order review aid, not proof of Intel hardware
behavior.  Do not enable readiness until the entire graph is converted in one
change and the Intel qualification gates pass.

Any correction restarts Passes 99 through 124 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 125: second kernel-code and non-standard-boundary review

Perform a second independent traversal of production code—not merely the
ledger—for common startup ownership, event coordination, ordinary VMX, SVM,
nested VMX, and checkpoint boundaries.  Reconstruct contracts from entry
points, types, lock domains, cleanup paths, and error returns before checking
the ledger.  Inventory every non-standard mechanism: retained handoffs,
deferred-owner results, notification observations, selected Intel unwind
actions, Intel-private outcome composition, phase enums, fail-closed
readiness, backend reconstruction records, and test-only models.

For each mechanism prove scope, owner, lifetime, errno domain, mutation and
cleanup authority, serialization status, observability, and architecture
boundary.  It must map to a normative VirtIO, VMM, or Intel-SDM requirement,
or be explicitly contained as private infrastructure with a narrow reason.
Reject an Intel VMX object in common code, private state in snapshots/traces/
sysctls/ioctls, unbounded retry in place of a wakeup, implicit ownership
transfer, cleanup that recaptures live observation, native-layout persistence,
or a test that proves a helper but not call-site ordering.  Linux/KVM and QEMU
may inform observable lifecycle comparison only; do not copy implementation.

## Pass 126: independent evidence and portability review

Review tests and validators independently of production code and ledgers.
Reconstruct expected state transitions from the VMM contract and Intel SDM
concepts, then verify models cover success, rejection, replay, terminal
cleanup, aliasing, double resolution, reset, detach, and checkpoint edges.
A common test must build on every supported architecture; an Intel-private
cross-layer test belongs only in the amd64 VMX suite.  Do not import an
architecture-private implementation into a portable target.

For every non-standard interface require a negative proof that a forbidden
crossing fails: private outcome/action in common persistence, late owner
resolution, terminal detach rewritten as replay, synthetic nested event
treated as real L2 exit, or non-amd64 code importing Intel state.  Check build
guards, object-tree artifact discovery, deterministic timeout ownership, and
that tests do not use production-private constants as their oracle.  Rootless
models prove value and ordering properties only, never installed-kernel VMX,
L1/L2, or live checkpoint behavior.

Any correction restarts Passes 99 through 126 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 127: hardware-attempt versus real-L2-exit classification review

Trace the nested paths that publish an L1-visible internal result without
using the ordinary `vmx_exit_process()` branch.  In particular distinguish an
initial VM-entry rejection after a VMX hardware attempt from an EPT-walk
publication or direct L1 reflection after a captured real L2 exit.  Hardware
attempt is not equivalent to L2 execution; conversely, bypassing generic L0
exit processing does not erase the fact that L2 executed.

For each path, identify the last completed instruction, entry-event ownership,
VMCS02/L2-MSR/TSC_AUX residency, exact private publication or inverse action,
and only then the allowable common-owner settlement domain.  Rejection must
remain pre-entry and use the selected no-entry inverse.  EPT-walk and direct
reflection must use post-entry settlement and prove a portable freeze or a
non-retryable detach before the owner is returnable.  Reject errno-based
classification, treating an L1 internal exit as synthetic merely because it
does not call `vmx_exit_process()`, or giving a failed entry post-entry
semantics.

Compare the classification boundary with the Intel SDM VM-entry-failure versus
VM-exit distinction; Linux/KVM and QEMU may only provide explanatory lifecycle
comparison.  Add an independent source-order edge record and model evidence
for each branch.  This phase does not activate nested readiness.

Any correction restarts Passes 99 through 127 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 128: fail-closed activation and unsupported-surface review

Independently inventory every deliberate non-standard or incomplete execution
surface before proposing an activation change: machine readiness callbacks,
kernel-owned INIT/SIPI dispatch, deferred startup-entry owners, nested VMCS02
entry, active-L2 continuation restore, and architecture-specific feature
exposure.  Trace the real production caller of each gate, its default, the
errno presented to management, and every path that could bypass it.  A build,
a pure value model, or a host capability bit is not qualification to change a
false readiness predicate.

For each gate, state the exact missing proof: common run-owner source-order
conversion, installed-kernel transaction coverage, Intel VM-entry/exit
validation, L1/L2 execution, active checkpoint/restore, or non-x86 adapter
review.  Require a private-ledger record for every intentional
`EOPNOTSUPP`/false-readiness decision and a negative validator that rejects a
partial enablement.  Do not replace a fail-closed gate with polling, a hidden
tunable default, a synthetic successful result, or an Intel-only object in
common code.  Keep VMX and SVM policy independently fail-closed until their
respective hardware and lifecycle evidence exists.

Compare only observable policy shape with Linux/KVM and QEMU; the Intel SDM
continues to control VMX architectural behavior.  This phase records an
activation prerequisite, not an activation.  Rootless tests prove source and
value containment only.

Any correction restarts Passes 99 through 128 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 129: attempted-entry ownership review

Review the common startup-owner model for architectures where an entry
instruction may be attempted but guest execution is not established until the
hardware result is classified.  Distinguish final admission, a pending
hardware attempt, a rejected attempt, and a committed real guest entry.  The
pending state may contain only portable value state; it must not retain a
VMCS/VMCB, pmap, interrupt state, or architecture-specific exit reason.

Require failure-atomic transitions.  A declined admission still follows the
existing deferred pre-entry path.  A successful admission enters
ENTRY_PENDING, a verified guest execution commits exactly one guest entry,
and a verified unentered rejection becomes the ordinary software-return
domain with no fabricated entry count.  Reject duplicate commit/abort,
late abort after commit, malformed checked-loop counts, aliases, and any
attempt to use this state for a normal hardware VM exit.  The architecture
adapter must prove the classification before choosing commit or abort.

Compare the distinction conceptually with Intel VM-entry failure semantics;
do not derive common results from an Intel exit-code encoding.  Linux/KVM and
QEMU may explain lifecycle shape only.  This is a generic prerequisite for
future VMX/SVM conversion and does not change readiness or production
execution.

Any correction restarts Passes 99 through 129 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 130: conclusive no-entry terminal-outcome review

Review the portable ENTRY_PENDING state for the case where an architecture
adapter conclusively proves that a hardware entry did not execute guest
instructions, but also has a terminal adapter error to report.  It must not
commit a fictional entry merely to use the usual post-entry error route, and
it must not treat an uncertain retryable classification as a no-entry result.

Require a separate checked-loop terminal-error transition: it consumes the
pending admission, preserves prior real-entry history, reports only a
positive non-EAGAIN error, and reaches RETURNABLE through the same portable
retirement lifecycle as software rejection.  Reject aliases, zero or EAGAIN
errors, duplicate settlement, and any change after commit.  Test an initial
attempt and a later re-entry attempt so count arithmetic cannot hide behind
the first-entry case.

This is a generic state-model prerequisite, not VMX/SVM execution enablement.
It carries no architecture-private residency, exit encoding, VMCS/VMCB state,
or saved-state format.  A future adapter must complete all private cleanup
before selecting this terminal settlement.

Any correction restarts Passes 99 through 130 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 131: admission-observation authority review

Review every common vCPU owner wrapper that reads mutable coordinator or
notification state.  Identify whether it is an admission operation or a
post-admission cleanup operation.  Admission wrappers may capture the two
live values once and pass immutable values to a common owner; commit, abort,
resolution, freeze, and retirement operations must never recapture them.

Verify that comments, ledgers, validators, and tests name all admission
wrappers, including deferred and attempted-entry forms.  A stale claim that
one wrapper is the sole observer is a correctness defect: it can cause a
future architecture adapter to add an unauthorized second sampling point or
misclassify an existing one.  Preserve the no-private-state and no-readiness
properties of this interface.

Any correction restarts Passes 99 through 131 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 132: classified hardware-attempt settlement review

Review the boundary between an immutable VMX hardware-attempt classification
and the portable `ENTRY_PENDING` owner.  Treat a captured L2 exit, an
initial/resumed failed entry, and an L0-only failure as three distinct facts.
Only a captured L2 exit may commit a common guest entry.  A rejected or failed
entry that completed recoverable private rollback settles as software without
an L2 entry; an L0-only failure or terminal private detach settles as a
positive non-retryable error without an L2 entry.

Model the mapping in Intel-private value code using the existing attempt and
unwind enums, then prove it against the common owner in the amd64 test suite.
Reject a post-entry cleanup action during an attempt settlement, fabricated
failure errno, `EAGAIN` as a conclusive no-entry error, aliases, and malformed
enum values.  Do not put VMX exit encodings, VMCS02 ownership, pointers, or
save-state fields in the common owner.

This is a prerequisite model for one future atomic source-order conversion;
the non-null nested owner path must remain fail-closed until every private
cleanup and publication edge is connected and root-qualified.

Any correction restarts Passes 99 through 132 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 133: private attempted-entry adapter review

Review the private adapter that settles one already-validated Intel
hardware-attempt result into the portable `ENTRY_PENDING` owner.  It is a
mechanical boundary, not a second classifier: it must not inspect VMCS state,
recapture vCPU state, infer an errno, run cleanup, or change readiness.  Its
only authority is to map `COMMIT_ENTRY`, `ABORT_SOFTWARE`, or `ABORT_ERROR` to
the matching common owner operation.

Require `COMMIT_ENTRY` to have no result buffer and use only the commit
operation.  Require both no-entry dispositions to have a caller-owned result
buffer and use their corresponding abort operation.  Reject malformed output
or incompatible argument combinations before mutating the pending owner.
Prove that the adapter leaves a pending owner untouched on every rejected
combination and that it cannot be used from the production nested VMX path
until the complete source-order transaction is converted atomically.

This is a private Intel glue contract with no public ABI, save-state encoding,
or execution enablement.  It must remain independent of common code except
for the explicit portable owner calls.

Any correction restarts Passes 99 through 133 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 134: nonstandard private-storage and alias review

Review every nonstandard kernel helper that combines immutable private input
with caller-owned mutable output or a mutable lifecycle owner.  List every
input/output pair, verify its overlap contract before the first write, and
verify that all validation precedes side effects.  Do not rely on an adjacent
common helper to protect private inputs it cannot see.

For VMX attempted-entry settlement, specifically verify owner/outcome and
outcome/result separation.  An immutable classification must not be
overwritten by a result publication, even through an invalid caller alias.
Test rejected aliases with a pending owner and prove its phase, counters, and
admission state are unchanged.  Check related Intel and SVM private adapters
for the same shape, but do not introduce architecture-specific fields into the
portable owner solely to share a check.

This pass concerns kernel API hygiene and failure atomicity.  It does not
alter any ISA-visible behavior, save-state layout, transport feature, or
readiness gate.

Any correction restarts Passes 99 through 134 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 135: nested private error-domain preservation review

Trace each nested VMX hardware-attempt result from the architectural report,
through its selected inverse, to the eventual caller result.  Keep three
domains distinct: a validated L1 VM-entry rejection, a host-only failure that
proves no L2 instruction executed, and a terminal error from private detach.
Do not use an arbitrary errno merely because the public report encoding has
no host errno field, and do not let a terminal cleanup error masquerade as
the earlier report result.

For every initial, resumed, and hot source-order edge, identify whether the
error is synthesized by a documented host policy or returned by the selected
private inverse.  A future `ENTRY_PENDING` conversion may settle only after
that source is immutable and the inverse is complete.  Add table-driven tests
for each error domain, including precedence when cleanup itself fails.

This is an Intel-private error-meaning audit.  It must not export VMX report
encodings or Intel errno policy to the portable owner, and it cannot enable
the current fail-closed execution path.

Any correction restarts Passes 99 through 135 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 136: kernel payload-provenance review

Perform a second consumer-first traversal of every kernel-only adapter that
accepts a classified nested-attempt plan, including late-entry refreeze,
resume-result construction, private owner settlement, and any future live
VMX call site.  Treat every embedded exit image, rejection record, errno, and
commit flag as an independent capability: an action tag and otherwise
plausible flags are not proof that the payload came from the same hardware
attempt.

Require the plan validator to reject stale non-selected payloads, invalid or
wrong-kind exit records, malformed L1 rejection records, and output aliases
before a downstream adapter observes the value.  An L2-exit plan carries a
normalized non-entry-failure exit and no rejection; an initial rejection
carries a validated L1 rejection and no exit; a resumed failed entry carries
only a normalized entry-failure exit; and an L0-only failure carries neither.
Do not add VMCS fields, host pointers, or native-layout records to make this
check easier.  Verify that a failed validator is side-effect free and cannot
turn an unentered path into a post-entry settlement.

Validate semantic fields, not object representation: compiler padding is not
architectural state, may not be used as a validation discriminator, and must
not become a persistence or ABI dependency.

This is a private kernel value-contract review.  It does not activate nested
execution, change architectural VM-entry semantics, or serialize the plan.

Any correction restarts Passes 99 through 136 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 137: non-standard payload containment replay

Rebuild the private-interface inventory without relying on the action enum or
the requirements ledger.  Starting at each downstream consumer, identify
which fields it reads and prove their producer, normalization rule, lifetime,
alias contract, and persistence exclusion.  In particular, distinguish
architectural L1 rejection data from L0 diagnostic policy and from a captured
L2 exit.  No generic startup owner, snapshot envelope, trace payload, ioctl,
sysctl, or non-amd64 target may learn these Intel-private values.

Require table-driven negative tests which mutate an otherwise valid plan one
field at a time.  The test oracle must derive valid/invalid shape from the
Intel VM-entry/VM-exit distinction and the private plan contract, rather than
from the implementation under test.  Compare only externally observable
lifecycle behavior with Linux/KVM and QEMU; neither implementation defines
the private FreeBSD plan format.

Any correction restarts Passes 99 through 137 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 138: private representation and ABI-boundary review

Independently inspect every nonstandard Intel-private value passed between
adapters.  Separate semantic state from its in-memory representation.  Reject
whole-object comparisons, raw structure persistence, implicit enum width,
padding-dependent validation, host pointers, and compiler-layout assumptions
unless an explicit, versioned wire format defines them.  Field-wise equality
is required for semantic state; byte comparisons remain permissible only for
explicit byte arrays whose format is independently specified.

Repeat the containment replay from each common VMM, snapshot, ioctl, sysctl,
libvmmapi, arm64, and riscv boundary.  Those boundaries may not learn an
Intel-private type solely to make an internal comparison convenient.  Add a
negative regression test or static gate for every representation hazard found.

Any correction restarts Passes 99 through 138 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 139: public common-primitives precondition review

Review every exported common VMM helper as a complete contract rather than
only through its current callers.  In particular, inspect range, overflow,
ordering, endian, and state-validation primitives used by snapshot and
checkpoint code.  A public helper must not return a plausible affirmative or
negative answer for an input outside the domain it claims to model; callers
must not need undocumented validation ordering merely to use it safely.

For the VMS2 envelope range helpers, test NULL, zero-length, top-of-address
space, wrapping, adjacent, nested, and equal ranges in both argument orders.
The public overlap predicate must first reject non-empty non-representable
ranges, while preserving the explicit convention that zero-length ranges do
not overlap.  Confirm that this remains architecture-neutral and that it
does not serialize pointers, host page size, or native layout.

This is a common-kernel contract review.  It must not turn an experimental
snapshot envelope into a production snapshot ABI or broaden any Intel-private
type beyond its adapter boundary.

Any correction restarts Passes 99 through 139 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, and Intel
qualification reviews.

## Pass 140: VMX/SVM common-entry parity review

Review the ordinary VMX and SVM run loops as two consumers of the same
architecture-neutral startup-entry-owner contract.  Enumerate the exact
pre-entry lifecycle exits, the final interrupt-disabled admission point, the
no-entry cleanup, the first successful hardware entry, each backend-handled
exit, and the final unhandled exit.  The two backends may use different
hardware preparation and inverse sequences—VMCS/EPT versus VMCB/NPT/ASID—but
must have the same owner-state meaning at each boundary: a declined admission
does not execute guest instructions, a real entry obtains exactly one
post-entry settlement, and every internal re-entry obtains a new admission.

Do not use the VMX source as an oracle for SVM or vice versa.  Compare each
against the common `RUNNING`, `IN_GUEST`, `RECHECK`, and `RETURNABLE` state
machine, then record any hardware-specific cleanup required before returning
to common code.  In particular, prove that a declined final guard restores
debug-register state, address-space state, interrupt state, and dirty/cache
metadata without fabricating a VM exit; that a backend-handled exit rechecks
before another entry; and that an unhandled exit is settled exactly once.

Keep this review portable: it must not add an AMD-specific field to a common
or Intel-private record, expose a hardware register in an ioctl/snapshot, or
claim nested-SVM support.  Add source-shape and value-model coverage for the
shared contract, leaving installed AMD qualification explicitly pending on
AMD hardware.

Any correction restarts Passes 99 through 140 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, Intel, and
future AMD qualification reviews.

## Pass 141: terminal doubled common-kernel implementation review

Perform a fresh, source-first review of the final common VMM and amd64 run
paths without reusing the Pass 139 or Pass 140 finding lists.  Follow each
public helper through normal, reset, suspend, checkpoint, restore, detach,
and error returns.  Recheck ownership, interrupt state, overflow, byte order,
allocation lifetime, and portable state versus CPU-private residency.  Verify
that VMX and SVM consume common contracts rather than define them.

Use the specification as authority; use Linux/KVM and QEMU only to compare
observable lifecycle behavior.  Require independent negative evidence for
each new common-kernel edge.  This is the terminal second review of final
accepted kernel sources.

Any correction restarts Passes 99 through 141 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, Intel, and
future AMD qualification reviews.

## Pass 142: terminal doubled non-standard/private-contract review

Independently reconstruct every non-standard, experimental, and
implementation-defined contract from its external consumer and accepted
input.  Cover private VMCS02 adapters, checkpoint scratch ownership,
diagnostic records, staged startup controls, unsupported returns, tracing,
and test-lab orchestration.  Confirm the private ledger identifies owner,
lifetime, serialization exclusion, errno domain, rollback rule, and negative
proof for every item.  Private convenience code must not leak amd64 layout or
policy into portable VMM, ioctl, snapshot, tracing, or future architectures.

This pass is independent of Pass 141 and prior inventories.  Record root-only
Intel execution, Linux/KVM L1, 5BSD L2, migration, fault, and soak work as
pending evidence; never substitute the model for those gates.

Any correction restarts Passes 99 through 142 and all affected common-kernel,
private-contract, portability, Linux/QEMU comparison, checkpoint, Intel, and
future AMD qualification reviews.

## Pass 143: checkpoint and guest-memory kernel transaction replay

Perform a second kernel-only review of every nested checkpoint, restore,
guest-memory, VMCS-registry, and frozen-vCPU adapter.  Start from each
mutation of guest memory or registry ownership and trace backwards to its
freeze/admission condition and forwards through every successful and failed
return.  Prove that a decode, capability, allocation, mapping, stale-epoch,
or ownership failure leaves externally visible context, registry, continuation,
and guest bytes unchanged.  A mutation which is necessarily irreversible must
be last, must have no remaining fallible work, and must have a direct negative
test.

Review byte order, explicit wire widths, field-by-field serialization,
overflow, aliasing, page-boundary splitting, guest mapping lifetime, and
release on every error path.  Native structs, host pointers, hardware VMCS
regions, and compiler padding may be used only as private temporary storage;
they must not cross a checkpoint wire, common VMM, ioctl, trace, or future
architecture boundary.  Compare lifecycle behavior with Linux/KVM and QEMU
only after the local Intel SDM and common snapshot contracts have established
the required behavior.

This is a doubled common-kernel transaction review.  It does not claim that a
rootless model proves hardware EPT/NPT dirty-bit collection, live L2 restore,
or migration.  Any correction restarts Passes 99 through 143 and all affected
checkpoint, portability, and Intel/AMD qualification reviews.

## Pass 144: non-standard host-policy and resource-boundary replay

Independently rebuild the inventory of implementation-defined policy from
callers and operators, not from the prior ledger: allocation limits, NOWAIT
behavior, timeout and retry policy, feature exposure, `ENOTSUP` boundaries,
debug/logging knobs, guest-CID and backend identity choices, snapshot
compatibility rejection, and test-lab controls.  For each item identify the
owner, authority, namespace or generation binding, failure errno, rollback,
observability, persistence exclusion or explicit wire encoding, and positive
and negative proof.

Require that host policy cannot silently alter an Intel architectural VMX
result, a VirtIO normative device rule, or a portable VMM contract.  Confirm
that failed allocation and unsupported hardware capability remain fail-closed;
that diagnostic state is rate-bounded and cannot become snapshot input; and
that a test-only switch cannot be mistaken for negotiated guest capability.
Compare observable behavior with Linux/KVM and QEMU only where it is a guest
or migration compatibility question—neither is an authority for FreeBSD's
private policy.

This is a doubled non-standard/private-contract review.  Any correction
restarts Passes 99 through 144 and all affected common-kernel,
private-contract, test-quality, and root-only qualification reviews.

## Pass 145: terminal kernel mutation/rollback replay

Perform a fresh mutation-first review of the final production kernel source.
For every write to live VMM, VMX, SVM, VirtIO, snapshot, interrupt, DMA,
queue, registry, cache, or provider state, identify its admission predicate,
the last fallible operation before it, its rollback or invalidation rule, and
the direct negative proof.  Reconstruct this from assignments, stores, and
destructive helper calls rather than from comments or the prior review list.

Distinguish architectural state from derived, quiescent caches explicitly.
A derived cache may be discarded before publication only when it is proven
rebuildable from restored architectural guest state and no later fallible
operation can leave an externally visible half-published owner.  A hardware
VMCS write must retain an exact rollback image until the registry and all
software owners have committed.  Check partial-loop failures, allocator
failure, callback failure, stale generation, CPU freeze loss, reset, detach,
and restore cancellation.  Do not turn an intentional cache invalidation into
a native-layout snapshot field or use a rootless model as evidence of live
hardware rollback.

Any correction restarts Passes 99 through 145 and all affected checkpoint,
common-kernel, private-contract, portability, Intel, and future AMD review
and qualification passes.

## Pass 146: terminal non-standard semantics and observability replay

Independently review all behavior that is deliberately outside a normative
architecture or VirtIO specification: private snapshot staging, cache
retirement, host resource ceilings, NOWAIT allocation, errno translation,
unsupported-feature returns, debug controls, SDT/DTrace probes, test-lab
timeouts, provider/back-end identity, and root-only qualification controls.
Start at each accepted operator input or emitted trace record and trace to its
kernel consumer, owner, teardown, persistence rule, and negative test.

For every such behavior prove it has a named authority, bounded lifetime,
clear rollback or fail-closed result, and cannot alter guest-visible normative
semantics merely because a host policy changed.  Require tests to distinguish
an implementation-defined rejection from a normative protocol response, and
record whether evidence is model-only, installed-kernel, or root-only live
qualification.  This pass must use a consumer-derived inventory before
reconciling it with the private ledger.

Any correction restarts Passes 99 through 146 and all affected common-kernel,
private-contract, test-quality, observability, and root-only qualification
reviews.

## Pass 147: withheld-feature reachability and error-domain replay

Independently enumerate every explicit unsupported, unavailable, or deferred
outcome in the composed VMM and nested-VMX source.  For each `ENOTSUP`,
`EOPNOTSUPP`, `ENOENT`, policy rejection, capability omission, loader gate,
or diagnostic-only path, identify the exact feature being withheld, its
normative or private-policy authority, every negotiation and execution path
that could otherwise reach it, and the prerequisite before it may be exposed.
A missing capability bit, rejected ioctl, disabled checkpoint envelope, and
runtime fallback are distinct contracts; do not collapse them merely because
they use the same errno.

Start from callers and guest-visible consequences, then reconcile the result
with the requirements and private-interface ledgers.  Prove an unsupported
path cannot leave a partially installed VMCS02, VPID, event claim, timer,
interrupt, checkpoint stage, or CPU-model state.  Retain one positive and one
rejection test for each implementation-defined gate, and distinguish a guest
VMfail or exception from a host-management errno.  Linux and QEMU may show
which path their guests exercise, but cannot turn a withheld FreeBSD feature
into a supported contract.

Any correction restarts Passes 99 through 147 and all affected normative,
kernel-mutation, private-contract, portability, and Intel/AMD qualification
reviews.

## Pass 148: independent test-oracle and activation replay

Review the final model, static validator, and live-qualification layers from
their expected values rather than implementation includes.  Every Intel VMX
result must come from the cited SDM rule or a separately written private
contract; every VirtIO result must come from a pinned specification fixture;
and every Linux or 5BSD activation claim must prove that the guest driver
negotiated and exercised the feature.  A build, source-shape match,
capability read, or guest attach alone is not activation evidence.

For each withheld or experimental feature, prove a test cannot pass because
the path was skipped, a host gate was disabled, a mock accepted an impossible
value, or an implementation header supplied the expectation.  Exercise
malformed, stale-generation, duplicate, rollback, reset, and restore cases
where their contract has them.  Preserve the separation among rootless
models, installed-kernel tests, and live Intel, Linux, 5BSD, checkpoint,
migration, and soak evidence.

Any correction restarts Passes 99 through 148 and the affected source,
requirements, model, and root-only qualification reviews.
