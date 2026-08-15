# VirtIO-vsock correctness review loop

Use this prompt against the complete change range and current worktree.  Do
not treat a successful build, a happy-path VM run, or a previous review as
proof that a path is correct.

## Scope

Review these implementations as separate backends sharing one guest-facing
VirtIO device:

* bhyve `backend=userspace`: `usr.sbin/bhyve/pci_virtio_vsock.c`, its Unix
  control socket, relay sockets, virtqueues, reset, and teardown;
* bhyve `backend=kernel`: the same PCI device's `/dev/vsock` packet bridge;
* the kernel provider: `sys/kern/uipc_vsock_user.c` and the transport/domain
  code it calls in `sys/kern/uipc_vsock.c`;
* all direct harnesses and live tests under `tests/sys/kern/vsock_*`.

Treat the kernel provider as a CID-keyed multiplexer.  Include simultaneous
providers with different feature sets, duplicate-CID attach races, CID reuse,
hash collisions, and independent reset/detach while other providers have
active sockets and queued packets.  Prove that no provider pointer survives
a lock-dropping copy or sleep, and that a wakeup for one CID cannot be lost or
incorrectly satisfy another CID's routing decision.

Review the diff and the surrounding implementation.  Code outside the diff
is in scope when a changed call site depends on its lifetime, locking, error,
or protocol contract.

## Rules for every pass

1. State the invariants before judging the code.  Include ownership, lock
   state, connection state, queue bounds, descriptor ownership, credit
   accounting, record boundaries, and who must wake whom.
2. Trace every return value and errno from its origin through cleanup and
   recovery.  An error that is logged and then leaves a dead queue, lost
   wakeup, leaked fd, consumed descriptor, or permanently failed backend is a
   finding.
3. Construct a concrete schedule or packet sequence that reaches the issue.
   Do not report a hypothetical race without identifying both racing
   operations and the missing serialization.
4. Check the existing tests before calling something uncovered.  A mock test
   only counts when it models the relevant ownership and failure semantics.
5. For each confirmed issue or gap, specify a regression test that fails
   before the fix and passes afterward.  Prefer deterministic fault injection
   over timing sleeps.
6. Re-read the final patch, not the remembered patch.  Check cleanup paths
   introduced by the test scaffolding too.
7. Report findings by severity with file/function, reachability, consequence,
   and evidence.  Separate confirmed defects, coverage gaps, and deliberate
   design tradeoffs.

## Passes in one cycle

Run every pass, even if an earlier pass found issues.

### Pass A: state, ownership, and lifetime

Follow attach, feature negotiation, connect, accept, data transfer,
half-close, disconnect, reset, detach, and initialization failure.  Look for
UAF, double close/free, stale callbacks, fd reuse, abandoned cdevpriv state,
packets surviving reset, and state transitions that cannot recover.

### Pass B: error propagation and recovery

At every allocation, read, write, writev, recvmsg, sendmsg, ioctl, poll,
mevent, virtqueue, and copy boundary, consider:

* `EAGAIN`, `EINTR`, hard error, EOF, zero progress, short I/O, malformed
  framing, allocation failure, and queue full;
* whether input was consumed before failure;
* whether retry preserves byte/record order and descriptor ownership;
* whether `NEEDS_RESET`, poll/kqueue readiness, logging, and DTrace reflect
  the resulting state;
* whether a successful reset demonstrably restores service.

### Pass C: concurrency and reset schedules

Interleave reset/detach with blocked provider read/write, a parked kernel
packet, a partially injected guest record, a pending control connection,
credit wait, TX backlog drain, kqueue detach, and callback dispatch.  Verify
lock order and all wakeups.  Also interleave same-CID attach, different-CID
attach, per-CID feature changes, and last-provider unregister.  Require
deterministic harness schedules for important races.

### Pass D: protocol validation and boundary values

Exercise wrong CIDs, wrong port pairs, reserved CIDs/ports, unknown operation
and type, invalid flags, control packets with payload, mismatched length,
zero-length records, maximum and maximum-plus-one payloads, wraparound credit,
excess descriptors, mixed descriptor directions, duplicate/colliding
requests, and stale packets after reset.  Compare STREAM and SEQPACKET
independently and check modern and legacy PCI transport.

### Pass E: resource exhaustion and longevity

Try connection, control-connection, provider-control, provider-data,
reassembly, TX-backlog, descriptor, and host socket limits.  Repeatedly fail
connections in both directions, then prove immediate recovery.  A soak must
reuse one bhyve process, include errors and abrupt teardown—not just
successful echo—and check fd, RSS, connection, and bounded-queue state after
warmup.  Exercise enough simultaneous provider CIDs to collide in the
provider hash table, and record attach/detach time and provider-count recovery.

### Pass F: observability and authority boundaries

For every fatal error, nonfatal drop, reset, attach/detach, backpressure
episode, and resource-limit rejection, verify an operator can distinguish it
without packet payloads.  Check debug log volume, DTrace probe arguments and
lifetime safety, standard audit claims, Capsicum rights, privilege checks,
MAC hooks, and absence of ambient path/fd authority.

### Pass G: test validity

Deliberately break one load-bearing behavior in each harness category and
confirm the intended test fails.  Look for duplicate registrations, tests
that accept multiple unrelated errnos, mocks that cannot produce partial I/O,
fixed sleeps instead of readiness, leaked background processes, stale files,
and success checks that ignore one endpoint.

### Pass H: second independent production-kernel review

After applying every finding from Passes A through G, discard the earlier
kernel conclusions and retrace the final composed kernel from its production
entry points.  Treat this as the forward lifetime traversal: follow
allocation, initialization, publication, active use, revocation, and
destruction in a different subsystem order from the original reading.  Follow
socket, PCB, mbuf, provider, cdevpriv, credential,
prison/VNET, MAC claim/token, poll/kqueue, taskqueue, callout, and transport
objects through allocation, publication, reference acquisition, lock-drop or
sleep, reset, revocation, detach, and destruction.

Review unchanged surrounding code as well as the diff.  Verify mbuf packet
headers and accounting across fragmented STREAM and SEQPACKET data, callback
generation and provider identity after every sleep, wakeup ownership for each
CID, and rollback after partial attach or feature publication.  Any fix made
because of this pass invalidates its clean result; run it again from a
different kernel boundary and reverse the userspace/kernel backend order.
Capture fresh warnings-as-errors diagnostics; repeating the same diff walk is
not an independent kernel review.

### Pass I: non-standard interfaces and operator policy

Inventory everything outside the AF_VSOCK and VirtIO specifications:
`/dev/vsock` ioctls, deprecated command encodings, bhyve control-socket
messages, provider feature epochs, checkpoint records, sysctl ceilings and
timeouts, DTrace arguments, audit records, MAC ownership rules, debug knobs,
and harness-only protocols.  Classify each as a private implementation
detail, documented compatibility contract, versioned private ABI,
experimental guest interface, or operator policy.

For every item record its owner, versioning and reserved-field rules, default,
authorization boundary, compatibility promise, rollback behavior, and direct
negative test.  Unknown commands, versions, flags, reserved bits, CIDs, and
features must fail closed without changing live provider or socket state.
Linux behavior is an interoperability comparison, not the normative source
for a FreeBSD-private ABI.  Keep compatibility constants separate from the
independent VirtIO oracle, and require source-tree ABI tests so an installed
old header cannot produce a false pass.

Explicitly enumerate every compile-time queue count, maximum connection,
packet, record, object or transfer size, memory cap, timeout, retry count,
polling cadence, rate limit, sysctl, tunable, and guest-driver resource
ceiling.  Each is either standard-derived with an exact section and independent
oracle, or private policy with units, owner, default, mutability,
authorization, compatibility promise, rollback, and a direct boundary or
negative test.  Linux defaults and unexplained literals remain findings.

### Pass J: post-private production-kernel replay

Run a second independent kernel review after Pass I.  This is the reverse
lifetime traversal.  Begin with provider
detach, cdevpriv destruction, blocked-operation wakeups, mbuf release,
interrupt teardown, checkpoint rollback, and concurrent sysctl writes, then
trace ownership backward to attach and publication.  Revisit every path
changed while classifying or testing a private contract.  A correction in
this pass invalidates both Pass H and Pass J.  Generate fresh compiler
diagnostics for the post-private source; do not reuse Pass H evidence.

### Pass K: composed private-boundary review

Combine the private interfaces and exercise wrong-owner, wrong-credential,
wrong-CID, wrong-generation, wrong-backend, version-skew, and standard-versus-
private namespace cases.  Verify that a provider ioctl cannot inherit MAC or
checkpoint authority, that policy values cannot masquerade as VirtIO fields,
and that tracing and audit metadata confer no ownership.  Add every new
contract to the private ledger with a direct negative test before this pass
can be clean.

### Pass L: second independent non-standard inventory replay

Discard the Pass I inventory and rediscover non-standard contracts from their
consumers and decoders.  Begin with ioctl dispatch, compatibility fallbacks,
checkpoint import, sysctl writers, DTrace and audit consumers, MAC decisions,
management tools, and installed documentation, then trace each accepted value
back to its definition and owner.  Do not begin from the private ledger.

Reconcile every discovered version, reserved field, legacy encoding, timeout,
retry, queue or connection ceiling, sentinel, feature epoch, and diagnostic
argument with exactly one ledger row and a real positive and rejection test.
Compose old outer records with new inner records, correct values from the
wrong CID/provider/VM, and valid policy values at the wrong authorization or
generation boundary.  This pass is independent of Pass K: composition tests
known interfaces, while this pass searches for omitted or stale interfaces.
Any code, test, documentation, or ledger correction invalidates Passes H
through L.

### Pass M: final kernel/private transaction synthesis

On the final source, choose each publication transaction—provider attach,
feature update, pending packet or event publication, reset, checkpoint
capture, restore, revocation, and teardown—and trace it simultaneously through
the kernel owner, private contract, normative wire behavior, authorization,
rollback, observability, and test oracle.  Repeat from failure and destruction
backward.  Verify validation failure leaves every live owner and caller output
unchanged and that an accepted private contract cannot weaken a standard
invariant.  Use fresh source and compiler evidence; a production correction
restarts Passes H through M.

### Pass N: kernel/private adapter failure-atomicity replay

At every socket, mbuf, transport, provider, MAC, cdevpriv, poll/kqueue,
checkpoint, and bhyve backend adapter, identify the last fallible operation,
the first retained-owner mutation, rollback ownership, and retry identity.
Inject failure in reverse order, including successful callbacks followed by
caller validation failure.  Prove that a retry sees the same CID, generation,
credits, queue state, wakeup obligation, and caller output, or document an
explicit fail-stop transition.  This is independent of the two lifetime
traversals; a production correction restarts Passes H through N.

### Pass O: withheld, unsupported, and implementation-defined behavior

Inventory every AF_VSOCK or VirtIO-vsock behavior which is parsed, modelled,
restored, or logged but remains unsupported or unadvertised.  Check all socket
types, feature bits, provider versions, legacy paths, checkpoint decoders,
backend choices, sysctls, timeouts, retry/polling rules, resource ceilings,
and debug interfaces.  Require consistent fail-closed behavior and a private
ledger row with a direct negative test for every implementation choice.
Standards are normative; Linux is an interoperability comparison.  Any
production correction restarts Passes H through O.

### Pass P: shared-kernel ownership and wakeup replay

Restart outside the device implementation and review the shared VMM, socket,
PCI, interrupt, sleepqueue, taskqueue, callout, snapshot, and module-lifecycle
code which owns or schedules it.  Trace every all-vCPU or all-queue operation
by exact member identity, including partial acquisition and rollback; never
assume that an iteration cursor still names an earlier acquired member.

For each asynchronous publication boundary, write the predicate/interlock
proof for signal-before-check, signal-between-check-and-enqueue, signal-after-
enqueue, cancellation, generation exhaustion, signal interruption, and
teardown.  Polling, bounded sleeps, and a generation comparison without a
retained ingress lease are findings.  Interrupt-adjacent publishers must not
take a sleepable lock.  A wait credential must bind a non-reused lifecycle
owner, exact state storage, generation, and exact credential storage, and none
of those transient cookies may enter a checkpoint record.  Compare the shape
with native FreeBSD kernel practice and pinned Linux/QEMU behavior, but treat
only the applicable standard as normative.

This is a fresh shared-kernel traversal, not another reading of the device
diff.  Any production correction restarts Passes H through P.

### Pass Q: consumer-led non-standard replay and composition

Discard the earlier private inventory again.  Start from every decoder,
dispatcher, restore selector, management consumer, compatibility fallback,
sysctl handler, DTrace/audit reader, and installed manual.  Work backward to
discover private values and policies which the producer-side inventories may
have missed.  In particular, distinguish transient kernel synchronization
details from versioned private ABI, operator policy, compatibility contract,
and experimental guest-visible behavior.

Then compose each rediscovered private value with the shared-kernel ownership
from Pass P: wrong VM incarnation, copied credential, stale generation,
cancelled owner, teardown in progress, legacy outer/current inner record,
valid value at the wrong authorization boundary, and restore into a changed
backend.  Require an independent rejection test and unchanged live state.
Linux and QEMU can justify architectural expectations, but cannot define a
FreeBSD-private ABI.  Any code, test, ledger, or documentation correction
restarts both Pass P and Pass Q as well as the affected earlier phases.

### Pass R: final-source kernel review from teardown and interrupts

After every correction from Passes P or Q, discard their notes and review the
new source a second time.  Start simultaneously at VM/device destruction and
at interrupt, callout, taskqueue, and backend completion entry points; meet in
the ownership middle.  Prove pointer lifetime before lock acquisition,
admission closure before drain, exact-member rollback, stable multi-owner lock
order, wakeup after owner release, and release of every lock after a callee
zeroes or invalidates caller-visible transaction storage.  Reconstruct every
error edge instead of reusing the earlier forward trace.  Require fresh
compiler diagnostics and focused fault tests.  This phase cannot inherit a
clean result from Pass P.

### Pass S: final-source non-standard boundary review

Rebuild the private-interface inventory again from installed consumers and
retained artifacts after Pass R is clean.  Cover legacy PCI identities,
provider ioctls, record names and versions, manifests, backend reconstruction,
authorization, tunables, sysctls, probes, audit fields, diagnostics, resource
ceilings, polling/retry policy, and experimental feature gates.  Cross each
value with wrong owner, generation, architecture, device, backend, namespace,
authorization, and legacy/current decoder.  Verify that transient pointers,
locks, tickets, cookies, file descriptors, and host object identities never
enter save state.  A finding restarts Pass R and this phase; neither producer-
side Pass O nor consumer-led Pass Q is sufficient evidence.

### Pass T: second final-source kernel implementation review

Discard Pass R and independently review the final kernel line by line from
shared VM, socket, PCI, DMA, interrupt, sleepqueue, taskqueue, callout,
snapshot, and module-lifecycle owners.  Start separately at allocation,
publication, reset, detach, cancellation, and destruction, then make the
forward and reverse ownership traces meet.  For every object and callback,
prove pointer stability before locking, execution-context compatibility,
admission closure before drain, stable multi-owner ordering, exact-member
rollback, wakeup obligations, and release-kernel failure behavior.

Distinguish recoverable external failures from impossible internal
invariants: malformed descriptors, version skew, backend loss, resource
exhaustion, and guest-controlled values must fail without panic or partial
publication.  Recheck common code for amd64 assumptions and require explicit
adapters for architecture-specific behavior.  Generate fresh Werror evidence
and focused fault tests; Pass R cannot satisfy this second final-source kernel
review.

Create the final-source manifest from the union of modified tracked files and
untracked in-scope production/test files, sort it, and hash every member before
Pass T and after Pass U.  A `git diff --name-only` manifest is incomplete for a
large new implementation because Git omits untracked files.  Any membership or
hash change restarts Passes R through U.

### Pass U: second final-source non-standard and private-policy review

After Pass T, discard Pass S and rediscover all behavior outside the VirtIO
and AF_VSOCK specifications from both producers and installed consumers.
Include private ioctls, provider protocols, checkpoint records, compatibility
encodings, backend identities, manifests, sysctls, tunables, limits, timeouts,
retries, polling, probes, audit fields, diagnostics, MAC policy, and
experimental feature gates.  Classify and ledger every value with owner,
units, default, authorization, versioning, reserved fields, rollback,
observability, and independent positive and rejection tests.

Compose valid values with the wrong VM/CID/provider generation, architecture,
device, backend, namespace, credential, decoder version, and outer/inner
record.  Prove that transient pointers, locks, tickets, cookies, credentials,
file descriptors, and host object identities are never serialized or treated
as standard fields.  Linux and QEMU are interoperability comparisons, not
normative sources for FreeBSD-private policy.  Any finding restarts Passes R
through W and the earlier affected phase.

### Pass V: repeated common-kernel primitive lifecycle review

Start below AF_VSOCK, VirtIO, and bhyve at their shared kernel primitives.
Independently trace socket-buffer ownership, sleep and wakeup, taskqueue and
callout drain, cdevpriv lifetime, VMM event publication, DMA, interrupts,
freeze, restore, and module teardown in both directions. Verify execution
context, lock order, admission closure, cancellation, exact rollback, and
release-kernel behavior without relying on the earlier device-centric pass.

### Pass W: repeated non-standard activation-boundary review

Reconstruct private provider protocols, ioctls, checkpoint records, backend
identities, limits, tunables, probes, audit records, compatibility selectors,
and experimental gates from final consumers. Bind owner, generation,
authorization, namespace, architecture, lifetime, and error policy; then
compose each contract with the common primitives reviewed in Pass V. A
private success result must not bypass a common lifetime or activation gate.
Any correction restarts Passes R through W on a new complete source manifest.

### Pass X: terminal production-kernel source review

After Passes R through W are clean, discard their kernel conclusions and make
a fresh, complete pass over the final production kernel.  Start at every
public syscall, socket, ioctl, VMM, device, interrupt, taskqueue, callout, and
snapshot entry point.  Trace each operation forward through publication,
locking, copyin/copyout, guest-memory ownership, admission, wakeup, reset,
detach, error recovery, and destruction; then trace backward from every
release and asynchronous callback.  Include shared code and all architecture
adapters.  Do not let an Intel, amd64, Linux-reference, or bhyve-only
assumption become an undocumented common-kernel contract.

### Pass Y: terminal non-standard and private-contract review

Discard the existing inventory and rediscover every behavior outside the
VirtIO and AF_VSOCK specifications from final consumers, decoders, installed
operator interfaces, diagnostics, and test runners.  Include ioctls, provider
protocols, checkpoint/manifests, backend identity, defaults, limits, timeout
and polling policy, compatibility selectors, DTrace/audit fields, MAC policy,
and experimental switches.  For every contract prove owner, authorization,
namespace, generation, architecture scope, versioning, rollback, observability,
and an independent rejection case.  Compose valid inputs at wrong
owner/credential/VM/device/backend/version/restore boundaries and verify that
private success cannot bypass the standard or common-kernel lifetime rules.

Passes X and Y require a newly generated complete source manifest after Passes
R through W.  Any code, test, documentation, ledger, or manifest change
restarts Passes R through Y and the earlier affected phase; neither terminal
pass may inherit earlier traces, inventories, compiler diagnostics, or test
results.

### Pass Z: independent common-kernel contract replay

After Pass Y, start at final common-kernel consumers rather than vsock or
bhyve code.  Reconstruct ownership, wakeup, execution-context, cancellation,
failure-atomicity, and portability contracts of the VMM, socket, DMA,
interrupt, taskqueue, callout, sleepqueue, credential, prison/VNET, MAC,
snapshot, and module interfaces.  Then prove AF_VSOCK and VirtIO adapters
preserve those contracts without creating an undocumented Intel, pointer,
page-size, process, or bhyve-specific invariant.  Require fresh Werror and
deterministic fault evidence; a correction restarts Passes R through AA.

### Pass AA: independent private decoder and operator-policy replay

After Pass Z, rediscover every non-standard interface from final accepted
inputs: ioctls, provider/backend messages, checkpoint records/manifests,
compatibility selectors, sysctls, tunables, limits, retries, timeouts,
polling, DTrace/audit metadata, MAC policy, and experimental gates.  For every
value prove validation, owner, authorization, namespace, generation,
architecture scope, reserved-field rule, rollback, observability, and direct
positive and rejection evidence.  Compose it against wrong VM/CID/provider,
credential, jail, VNET, backend, architecture, version, and restore state.
Private success must not bypass the common contract from Pass Z or normative
VirtIO/AF_VSOCK requirements.  A correction restarts Passes R through AA.

### Pass AB: second final common-kernel and cross-device lifecycle review

Discard the conclusions of Passes T, V, X, and Z.  Start at the shared
VirtIO PCI/MMIO transport and VMM lifecycle owners, then trace each
implemented device through feature publication, queue enable, notification,
selective reset, full reset, guest suspend, guest resume, checkpoint pause,
snapshot, restore, backend loss, and detach.  Review the final production
kernel and bhyve code line by line where a common callback, queue fence, DMA
lease, interrupt, taskqueue/callout, sleep/wakeup, or snapshot owner crosses
a device boundary.

In particular, prove that a device advertises `VIRTIO_F_SUSPEND` only when
both required lifecycle callbacks are present; that successful suspend
closes admission before backend drain; that failed suspend or resume cannot
reopen a partially usable device; that resume completion runs only after the
common fence opens; and that a checkpoint callback cannot confuse a
guest-suspend owner with an external pause owner.  Reconcile common
architecture-neutral state with each AMD64 adapter without importing VMX,
SVM, pointer-width, host-endian, page-size, host-file-descriptor, or process
lifetime assumptions into portable paths.  Check direct, translated-DMA, and
no-DMA devices separately.

This is an implementation review, not a device capability survey: inspect
the actual callback order, lock context, error result, and rollback state in
every path.  Require an independent model or fault test for every confirmed
shared lifecycle invariant, and fresh Werror diagnostics for the final
source.  Any correction restarts Passes R through AC and the affected
normative/device pass.

### Pass AC: second final non-standard lifecycle and test-orchestration review

Discard the inventories from Passes S, U, W, Y, and AA.  Begin with final
consumers of every implementation-defined VirtIO/bhyve value: device-model
options, backend identity strings, checkpoint manifests, run-lab profiles,
timeouts, retry bounds, work directories, CID allocation, bridge setup,
debug/DTrace/audit controls, and test-only feature toggles.  Trace every
accepted value backward to exactly one definition, owner, authorization and
namespace rule, unit, default, version/reserved-field policy, lifecycle
rollback, and positive plus rejection test.

Classify each value as specification-derived, a documented FreeBSD/bhyve
operator policy, or an intentionally withheld experiment.  A Linux or QEMU
default is comparison evidence only and must not silently become a local
contract.  Compose valid private values at the wrong VM, device, backend,
CID, credential, jail/VNET, generation, architecture, restore version, or
run directory.  Prove that test settings cannot turn an unsupported optional
feature into an advertised one, weaken a queue/interrupt/DMA lifecycle
invariant, or make a failed live qualification appear passed.  Ensure that
root-only qualification requirements are recorded as pending evidence rather
than hidden by a rootless model pass.

Any code, test, documentation, ledger, or policy correction restarts Passes
R through AC.  This pass is independent of Pass AB: AB proves the common
execution contract; AC proves that non-standard control and orchestration
interfaces cannot bypass or misrepresent it.

## Loop and termination

After fixing confirmed issues and adding tests, begin a new cycle with a
different pass order.  On the next cycle, start at the pass following the one
that found the last issue.  Continue until:

* one complete twenty-nine-pass cycle finds no new actionable defect or material
  coverage gap;
* sanitizer-backed direct harnesses and Werror builds pass;
* privileged provider tests pass on the installed kernel;
* modern userspace and kernel live matrices pass; and
* the same-process error-inclusive soak passes for both backends.

Passes H through AC require separately recorded clean results.  None may be
inferred from protocol conformance, a successful module build, or another
pass.

Do not claim absence of long-run bugs.  Record the duration, iterations,
traffic/error mix, diagnostic-kernel options, and final resource deltas so the
strength and limits of the evidence are explicit.
