# bhyve VirtIO 1.4 implementation validation

Status: active validation record
Reference catalog:
`tests/sys/kern/vsock_device_harness/virtio-reference-corpus.tsv`

The catalog, rather than a mutable pathname under `/tmp`, identifies the
normative VirtIO 1.4 CS01 artifact and the pinned explanatory Linux and QEMU
trees by revision, publication date, URL, and SHA-256.  A local reference
cache is useful while reviewing, but it is accepted only when its digest
matches a catalog entry.

The corpus validator has two deliberately separate modes.  Its generic mode
validates a self-contained synthetic or downstream catalog, which is useful
for testing the validator itself.  The canonical validation and release gates
use `--waspnest`; that mode additionally requires the pinned VirtIO 1.4,
Intel SDM Volumes 3 and 4, Linux, and QEMU records with their intended
normative or explanatory classifications.  A review therefore cannot silently
omit one of the required comparison sources.
Machine-readable coverage:
`tests/sys/kern/vsock_device_harness/virtio-1.4-requirements.tsv`

## Review method

The review is repeated with a different emphasis on each pass.  Every finding
must identify the applicable specification text, the observable consequence,
the production change, and a test which fails without the change.

### Pass 1: normative behavior

> Validate the changed bhyve and FreeBSD VirtIO code against the applicable
> VirtIO 1.4 MUST, MUST NOT, and relevant SHOULD statements.  Trace each
> advertised feature from its feature bit through negotiation, configuration,
> normal operation, reset, and error reporting.  Report any behavior which is
> not backed by both an implementation and a focused test.

### Pass 2: lifecycle and ownership

> Validate device reset and individual queue reset as ownership transitions.
> For every asynchronous backend, identify when it stops reading or writing
> guest memory, how completion is fenced by a generation, which mutex protects
> the state, and when the driver may safely observe reset completion.  Consider
> reset overlapping notification, completion, reconfiguration, and another
> full reset.

### Pass 3: register and descriptor boundaries

> Validate register widths, alignment, feature-page selection, invalid queue
> selection, maximum queue sizes, 64-bit address arithmetic, descriptor length
> accumulation, indirect chains, and mappings at the first and last valid
> guest-memory byte.  Check both modern and legacy PCI paths and require
> deterministic state after every rejected operation.

### Pass 4: feature allocation and interoperability

> Compare every common and device feature number with VirtIO 1.4.  Confirm
> that transport filtering does not discard device-specific bits, that
> unsupported common features cannot be negotiated, and that legacy devices
> cannot accidentally negotiate modern-only features.  Check PCI identity,
> capability lengths, feature pages, and Linux and FreeBSD guest expectations.

### Pass 5: sustained state transitions

> Repeat reset, re-enable, notify, and completion transitions for thousands of
> iterations with alternating synchronous and asynchronous backend results.
> Include stale completions, periodic full resets, feature renegotiation, and
> queue address changes.  Require stable memory use, no sanitizer findings,
> and the same final state after every equivalent transition sequence.

### Pass 6: performance and observability

> Identify avoidable work in queue notification, descriptor traversal,
> interrupt generation, reset, and backend drain paths.  Confirm that disabled
> optional features are not claimed.  Confirm that DTrace exposes feature
> negotiation, status changes, queue enable/notify/reset, configuration
> changes, and failure paths without requiring high-volume permanent logs.

### Pass 7: second independent kernel implementation review

> Repeat the kernel review after fixes from the preceding passes.  This pass
> is a forward lifetime traversal: begin at production entry points and follow
> allocation, initialization, publication, use, revocation, and destruction.
> Use a different subsystem order from the first reading.  Reconstruct
> allocation, publication, locking, sleep and lock-drop boundaries, callback
> ownership, rollback, reset, detach, suspend, restore, DMA, interrupt, and
> destruction.  Recheck architecture-independent memory ordering and audit
> partial attach, timeout, unload, and failed restore separately from the
> happy path.  Record fresh compiler diagnostics for the final source.  A
> previous clean kernel pass is not evidence after code changes, and a review
> of the same diff in the same direction does not count as the second pass.

### Pass 8: non-standard interfaces and policy

> Review non-normative behavior in five independent subphases: compatibility
> identities; host/provider ABIs; checkpoint ABIs; experimental guest ABIs;
> and operational policy.  Classify every item as a private detail, documented
> compatibility contract, versioned state ABI, experimental interface, or
> operator policy.  Keep compatibility values separate from the VirtIO oracle,
> require private ABIs to validate versions and reserved fields, keep incomplete
> guest interfaces default-off, and test policy limits, timeouts, tracing, and
> authorization directly.  Linux and QEMU are comparison references in this
> pass, not normative sources.  A fix in any subphase restarts all five.
> The inventory must include every compile-time queue count, maximum object or
> transfer size, memory cap, timeout, retry count, polling cadence, rate limit,
> sysctl, tunable, and guest-driver resource ceiling.  Each value is either
> standard-derived, with an exact normative section and independent oracle, or
> private policy, with owner, units, default, mutability, authorization,
> version/compatibility promise, rollback semantics, and a boundary or negative
> test.  An unexplained literal or a Linux/QEMU default is not a disposition.

### Pass 9: post-private kernel replay

> Repeat the production-kernel review after Pass 8 has classified and tested
> every private boundary.  This pass is a reverse lifetime traversal: start at
> teardown, rollback, wakeup, interrupt
> drain, restore failure, and concurrent policy writes and trace backward to
> allocation and publication.  Recheck every kernel path changed by a private
> ABI or resource-policy fix.  A material correction invalidates the earlier
> kernel review and this replay; both must run again on the final source with
> fresh compiler diagnostics and without reusing conclusions from the other
> traversal.

### Pass 10: private-boundary composition

> Compose the non-standard interfaces rather than validating each alone.
> Exercise wrong owner, credential, CID, device, generation, version, backend
> identity, and standard-versus-private namespace combinations.  Prove that
> compatibility identities, provider protocols, policy tunables, checkpoint
> records, observability contracts, and experimental controls cannot grant
> one another authority or leak constants into the independent VirtIO oracle.
> Record every newly discovered contract in the machine-readable private
> ledger before this pass can finish.

### Pass 11: second independent non-standard inventory

> Discard Pass 8's inventory and reconstruct private contracts from final
> consumers and decoders: ioctl dispatch, restore import, compatibility
> fallback, sysctl writes, tracing/audit readers, MAC hooks, management tools,
> and installed documentation.  Work backward to each definition without
> starting from the ledger.  Reconcile versions, reserved fields, legacy
> encodings, sentinels, timeouts, retry and polling policy, resource ceilings,
> and observability arguments with exactly one owner, ledger row, and direct
> positive and rejection test.  Pass 10 cannot satisfy this pass because it
> composes already-known contracts rather than searching for omissions.

### Pass 12: final kernel/private transaction synthesis

> On the final source, review each publication transaction across all layers:
> normative wire semantics, kernel ownership, private ABI or policy,
> authorization, rollback, observability, and independent tests.  Traverse
> both forward from input to publication and backward from failure or teardown.
> Prove every rejection leaves live state and caller outputs unchanged.  Any
> production correction restarts the two kernel passes and both independent
> non-standard passes with fresh compiler evidence.

### Pass 13: kernel/private adapter failure atomicity

> At every kernel adapter crossing, identify the last fallible operation, the
> first retained-owner mutation, rollback ownership, and retry identity.
> Inject failure before and after callbacks, DMA translation, backend resource
> acquisition, interrupt publication, checkpoint staging, and suspend/resume
> reconstruction.  A promised retry must preserve every live owner and caller
> output byte-for-byte; otherwise the interface must enter an explicit,
> documented fail-stop state.  This pass is independent of the forward and
> reverse lifetime reviews.

### Pass 14: withheld, unsupported, and implementation-defined behavior

> Inventory features which are parsed, modelled, restored, or partially
> implemented but not advertised.  Prove they are withheld at every feature,
> transport, legacy, management, checkpoint, and backend surface and fail
> closed without mutating standard state.  Classify compatibility fallbacks,
> provisional devices, timeouts, retry and polling rules, resource ceilings,
> debug behavior, and old decoders as private contracts with owners and direct
> negative tests.  Compare Linux and QEMU only after the controlling standard
> and do not inherit their defaults implicitly.

### Pass 15: second final-source kernel implementation review

> After Pass 14, discard both earlier kernel traversals and review the final
> composed kernel again.  Begin independently at destruction, module unload,
> interrupts, taskqueues, callouts, deferred DMA callbacks, blocked-operation
> cancellation, reset, suspend, restore publication, and backend loss; trace
> each owner backward to allocation and publication.  Prove pointer stability
> before locking, execution-context compatibility, admission closure before
> drain, stable lock order, exact-member rollback, wakeup obligations, and
> release-kernel behavior for malformed input, exhaustion, and external
> failure.  Generate fresh warnings-as-errors evidence.  This pass cannot
> inherit a clean result from either earlier kernel reading.

### Pass 16: second final-source non-standard and private-policy review

> Discard both earlier private inventories and rediscover non-standard values
> from final consumers and decoders: ioctls, backend protocols, compatibility
> selectors, checkpoint import, manifests, sysctls, tunables, limits,
> timeouts, retry and polling policy, DTrace, audit, MAC policy, diagnostics,
> provisional devices, and withheld features.  Classify every value with one
> owner, units, default, authorization, versioning, reserved-field behavior,
> rollback, observability, and direct positive and rejection evidence.  Then
> compose valid values with the wrong VM, device, queue, generation, backend,
> credential, jail, architecture, transport, and decoder version.  Linux and
> QEMU remain explanatory comparisons rather than authorities for a private
> FreeBSD contract.

### Pass 17: post-fix shared-kernel execution-context review

> After every production correction from Pass 15 or 16, discard the kernel
> trace again and start from machine-independent VM/vCPU lifetime, interrupt
> publication, rendezvous, snapshot, DMA, callout, and teardown entry points.
> Record the execution context and sleepability of every edge into device or
> architecture code.  Prove that pointer stability precedes lock acquisition,
> admission closes before drain, cancellation wakes every waiter, multi-target
> publication is failure-atomic, finite identity exhaustion cannot strand an
> acquired owner, and Intel-only state remains behind an explicit adapter.
> Use fresh compiler diagnostics and focused fault evidence; Pass 15 cannot
> satisfy this post-fix traversal.

### Pass 18: post-fix non-standard consumer and composition review

> Independently rebuild the non-standard inventory by starting at installed
> consumers, retained artifacts, decoders, management policy, diagnostics,
> probes, audit records, sysctls, tunables, and compatibility selectors.  Trace
> every accepted private value back to exactly one producer and owner.  Compose
> it with wrong VM incarnation, vCPU, generation, architecture, transport,
> backend, credential, namespace, version, and legacy/current selector.  Prove
> that transient locks, pointers, credentials, tickets, cookies, file
> descriptors, and hardware-residency identities are never serialized or used
> as standard-derived test oracles.  Any finding restarts Passes 15 through 18
> on the corrected source.

### Pass 19: independent final-source kernel reverse-lifetime review

> Discard the Pass 17 trace and review the unchanged final source from the
> opposite ownership direction.  Start at VM/device destruction, failed
> attach, failed restore, backend disconnect, queue reset, cancelled wait,
> interrupt teardown, and module unload; trace every retained reference back
> to its allocation and admission point.  Independently prove pointer
> stability, execution-context compatibility, stable lock order, notification
> after lock release, exact-member rollback, bounded drain, and release of
> already-acquired ownership after sequence or generation exhaustion.  Cover
> release kernels separately from diagnostic assertions and require fresh
> warnings-as-errors and focused failure evidence.  Pass 17 evidence cannot be
> reused to satisfy this review.

### Pass 20: independent final-source private-boundary rediscovery

> Discard the Pass 18 inventory and rediscover non-standard behavior from
> actual final consumers and retained artifacts.  Include management and
> backend protocols, compatibility decoders, checkpoint envelopes, ioctls,
> sysctls, tunables, resource ceilings, retries, timeouts, polling, DTrace,
> audit, MAC policy, diagnostics, provisional devices, and withheld features.
> Classify every accepted value with exactly one owner, units, default,
> authorization, version, reserved-field rule, rollback, observability, and
> direct rejection evidence.  Compose valid values with the wrong VM/device
> incarnation, queue, generation, architecture, transport, backend,
> credential, jail, namespace, and legacy/current decoder.  Prove transient
> locks, pointers, credentials, tickets, cookies, file descriptors, and
> hardware-residency identities are never serialized or treated as standard
> state.  Linux and QEMU remain comparison sources, not private-contract
> authorities.  Any finding restarts Passes 17 through 20 and the earlier
> affected phase.

### Pass 21: repeated common-kernel primitive lifecycle review

> Start below bhyve and the device models at shared VMM event/freeze state,
> DMA ownership, interrupt and taskqueue publication, sleep/wakeup, callout
> drain, cdevpriv lifetime, architecture runtime tags, snapshot publication,
> reset, detach, and teardown.  Trace allocation through final release with
> fresh execution-context, lock-order, admission, cancellation, rollback,
> wakeup, and release-kernel evidence.  Do not reuse Pass 17 or 19 results.

### Pass 22: repeated private/non-standard activation review

> Rebuild compatibility identities, provider/ioctl ABIs, backend and
> checkpoint envelopes, experimental gates, limits, DTrace, audit, and
> architecture adapters from final consumers and decoders.  Bind every value
> to owner, generation, lifetime, authorization, namespace, architecture,
> rollback, and independent rejection evidence, then compose it with the
> primitives from Pass 21.  A private success may not bypass a common
> lifetime or activation gate.  Any finding restarts Passes 17 through 22 on
> a new complete source manifest.

### Pass 23: doubled callback-context and irreversible-tail review

> Revisit every kernel indirect call from the execution site after the prior
> owner reviews are clean.  Prove the callback table is complete and captured,
> the callback may run in that lock, critical-section, allocation, and sleep
> context, reentry is classified, and callback-side mutation cannot redirect
> rollback or corrupt a durable owner.  Separately trace every operation after
> irreversible publication and require it to be infallible, allocation-free,
> nonblocking, and free of teardown that can enter pmap, vmspace, taskqueue,
> callout, or backend drain paths.

### Pass 24: doubled non-standard provider and policy-domain review

> Discard the preceding private inventory again.  Walk from each provider
> table, experimental gate, compatibility identifier, checkpoint envelope,
> resource limit, and architecture adapter to every consumer.  Distinguish
> invalid caller input, malformed retained state, live ownership, stale
> generations, and provider failure with typed positive errno results.  Prove
> provider tables cannot change during a compound operation, private pointers
> and handles are never serialized, and no private success bypasses a standard
> lifecycle or architecture-neutral save-state rule.

Before Pass 15, create a sorted manifest from all modified tracked files and
all untracked production, header, test, fixture, ledger, script, and manual
files in scope, then hash every member.  Recompute it after Pass 18 and again
after Pass 20.  A
`git diff --name-only` list is insufficient because it omits untracked source.
Any membership or hash change restarts Passes 7 through 24 on the new source.

The first Pass 7/8 application to the final common guest queue closed four
issues: split IN_ORDER lacked batch consumption, packed non-IN_ORDER equated
opaque owner IDs with physical positions, and malformed used data could leave
synchronous callers spinning after the queue had failed.  A second kernel
reading also found that concurrent interrupt rearm could overwrite the
suppression published by the failure path.  The corrected
common path supports both ordered batch formats, allocates independent packed
owner IDs, atomically publishes standard FAILED status once, disables
interrupts, rejects a racing rearm, suppresses notifications after observed
failure, and returns from polling.  The review also removed the obsolete
no-op private feature-policy hook.  Independent wrap, marker, owner-ID,
failure, rearm, and reset models plus PCI, MMIO, and complete `-Werror`
VirtIO module builds pass; rebuilt-guest live batch and malformed-device
qualification remains pending.

## Findings closed during these passes

- The portable-state range guard now treats every non-empty null extent and
  every wrapping address extent as invalid.  This makes alias rejection
  fail closed at the common boundary instead of relying on each device codec
  to duplicate pointer validity checks.  Direct tests cover empty extents,
  adjacent and overlapping ranges, null extents, and `UINTPTR_MAX` wrap.
- Administration-state validation now has a true read-only path through the
  group fabric, queue bank, PCI controller, and transport binding.  It no
  longer validates by publishing the candidate and allocating a second
  restore to compensate.  A valid candidate therefore cannot alter live
  command selection, and corrupt state is rejected before publication.
- Active-L2 nested-VMX restore now rejects plan, rollback, and generation
  storage that aliases either registry header or any separately allocated
  VMCS entry.  The registry owns the bounded storage walk, so checkpoint
  encoding and VM-wide restore apply the same fail-closed rule.  Focused
  atomicity cases preserve both live and replacement VMCS contents, and all
  147 architectural model cases pass with AddressSanitizer and
  UndefinedBehaviorSanitizer after validating all 168 nested requirements.
- Queue-reset backend failure no longer reports a completed reset.  The queue
  remains frozen with `queue_reset == 1`, `DEVICE_NEEDS_RESET` is set, and only
  a full device reset can recover it.
- Synchronous and asynchronous queue-reset completions are generation-fenced.
  A callback which temporarily drops the device mutex cannot alter a queue
  created by an overlapping full reset.
- Full device reset keeps the old nonzero status visible until backend users
  of guest buffers have drained.  Other transport access is frozen during
  that interval, and status becomes zero only when guest memory can be
  reclaimed.
- Virtio block reset now cancels queued operations, waits for active callbacks,
  and prevents stale callbacks from writing status or used-ring entries.
- Virtio block requests are validated before backend submission: read and
  write lengths use 512-byte units and remain within advertised capacity,
  discard ranges remain within capacity, FLUSH uses sector zero with no data,
  and GET_ID writes exactly the standard's 20-byte field.
- A read-only block backend now advertises `VIRTIO_BLK_F_RO`; the backend
  continues to reject writes without modifying storage.
- Legacy and modern configuration-window arithmetic uses checked, half-open
  ranges and handles offsets near `UINT64_MAX`.
- VirtIO 1.4 feature allocation is represented correctly: bits 28 through 40
  are the contiguous common range; bits 41 and 42 retain context-dependent
  device interpretations (with modern bit 41 assigned to `ADMIN_VQ`); and the
  common `SUSPEND` feature is the non-contiguous bit 43.
- The modern bhyve feature mask now treats bit 41 as unsupported
  `ADMIN_VQ`, permits device-specific bit 42 only on explicit device opt-in,
  and no longer describes the legacy-only 24/27 bits as modern features.
- MSI-X queue and configuration interrupts are now suppressed whenever the
  selected vector is `VIRTIO_MSI_NO_VECTOR`, for both modern and transitional
  PCI devices.
- Transitional PCI register writes are width-normalized; nonzero device status
  writes are cumulative; and feature or queue-PFN writes cannot reinterpret a
  live backend after `DRIVER_OK`.
- Invalid transitional MSI-X mappings now read back as
  `VIRTIO_MSI_NO_VECTOR`, matching the modern transport behavior.
- Modern split-ring mappings now include the `used_event` and `avail_event`
  trailers only when `EVENT_IDX` is negotiated, so a valid non-EVENT_IDX ring
  may end at the final mapped guest byte.
- Available-ring parsing now performs an acquire fence after observing
  `avail->idx`, pairing with the driver's descriptor-publication barrier on
  weakly ordered hosts.
- Modern virtio-net device configuration is now read-only as required; only
  the legacy interface retains its bounded writable MAC-address field.
- Configured virtio-net MTU values now use the VirtIO range of 68 through
  65535 rather than Ethernet's smaller minimum payload size.
- Once negotiated, virtio-net MTU is enforced for ordinary ingress and egress
  frames using their actual plain or VLAN Ethernet header length; valid GSO
  records remain eligible for backend segmentation.
- Generic VirtIO DTrace probes now identify the device model, and accepted
  notifications plus feature, status, reset, and configuration transitions
  are visible for both modern and legacy transports where applicable.
- FreeBSD guest VirtIO DTrace probes bracket device reinitialization with the
  requested feature set and final error, and bracket individual queue resets
  with the affected queue index and result.  This makes reset/rebind failures
  observable without changing their timing with diagnostic logging.
- Split-ring `EVENT_IDX` now covers both used-buffer interrupt suppression and
  available-buffer notification suppression.  Virtio-net advertises it
  because both RX and TX close the notification-enable race by rechecking the
  available index before sleeping.  Other device models remain opted out
  until their queue sleep transitions have the same proof and tests.
- Every modern PCI device now offers `VIRTIO_F_NOTIFICATION_DATA`; after
  negotiation the shared doorbell accepts only the required 32-bit form,
  decodes the low-half queue index, and treats the high-half available index
  as advisory.  Legacy devices retain their 16-bit doorbell.
- The FreeBSD split-ring guest now supplies its full available index with
  each queue notification.  Modern PCI and modern MMIO negotiate
  `VIRTIO_F_NOTIFICATION_DATA` and emit the required 32-bit notification;
  legacy PCI remains 16-bit.  The PCI guest rejects misaligned notification
  capabilities, invalid multipliers, arithmetic overflow, and per-queue
  offsets that do not fit the mapped capability before a queue can use them.
- The FreeBSD PCI and MMIO guest transports now implement negotiated
  `VIRTIO_F_RING_RESET`, wait for the transport-specific reset-complete value,
  and verify that the queue is disabled before returning ownership to a child
  driver.  The common filter preserves the feature instead of silently
  discarding it.  MMIO full-device reset now also performs the required status
  read-back synchronization before queue memory can be reclaimed.
- Virtio-rng is the first FreeBSD guest queue-reset consumer.  Random-source
  deregistration waits for in-flight callbacks, a driver mutex serializes the
  final read and drain, attach failure no longer clears another device's
  global provider, and detach falls back to synchronized full-device reset
  when individual reset is unavailable.
- Guest individual queue reset exposes
  `virtio:::queue-reset-begin` and `virtio:::queue-reset-end` probes.  The
  disposable-FreeBSD-guest test repeatedly detaches and reattaches virtio-rng
  under concurrent random reads and requires a successful queue-0 reset probe
  for every detach.
- Virtio-rng now offers `VIRTIO_F_IN_ORDER` on modern PCI.  Its sole queue is
  mutex-serialized and completes each request synchronously in available-ring
  order; the harness verifies multiple FIFO completions.  Linux releases
  before split-ring IN_ORDER support correctly decline the optional feature,
  so the Alpine helper records the negotiated state without requiring it.
  Devices with asynchronous completion remain opted out.
- Virtio-rng no longer completes a request with zero bytes when the host
  entropy source fails.  Every zero-byte or failed host read retains the chain
  and raises `DEVICE_NEEDS_RESET`, because the backend has no readiness event
  that could safely retry it without another guest kick.  Successful host reads
  are capped at 64 KiB, using the entropy device's permitted partial-fill
  behavior to bound mutex hold time and host work per guest request.
- Virtio-console control and additional-port queues remain inactive unless
  `VIRTIO_CONSOLE_F_MULTIPORT` was negotiated; full reset also clears cached
  feature and device-ready state.  A port is announced with `DEVICE_ADD` only
  once per device incarnation; failed delivery remains retryable and a full
  reset starts a new port lifecycle.
- Virtio-console now tracks each device-to-driver port lifecycle event
  independently.  If control receive buffers run out after `DEVICE_ADD`,
  later kicks resume with `PORT_NAME` and any pending host-open event without
  replaying the already published add event.
- Virtio-scsi now completes commands already consumed from the available ring
  with `VIRTIO_SCSI_S_FAILURE` before a full device reset, while selective
  queue reset still discards the old queue incarnation without a stale used
  entry.  Its `max_sectors` hint is derived from the actual 32-bit transfer
  and used-length bound, and reset clears cached negotiated features.  CTL
  completion is translated separately from ioctl completion: CHECK CONDITION
  remains a completed SCSI command with `VIRTIO_SCSI_S_OK`, while aborted,
  frontend-transport, and internal CTL failures receive non-OK VirtIO
  responses.
- Virtio-input configuration queries now start from a zeroed response, so an
  unsupported `select`/`subsel` pair returns a stable zero `size` without
  exposing a previous response or stack bytes beyond a string's declared
  length.  `ABS_INFO` now queries the requested absolute axis directly; the
  prior inverted check prevented valid axis metadata from being returned.
  Full device reset also clears the driver-selected query and cached response,
  as well as any partial event frame.
- Virtio-input now advertises `VIRTIO_F_IN_ORDER`.  Its event and status
  queues are synchronous under the device mutex, and focused multi-request
  tests verify that successful and malformed frames are retired in
  available-ring order.
- Virtio-console now advertises `VIRTIO_F_IN_ORDER` on modern PCI.  Port and
  control queue paths are mutex-serialized and consume available heads FIFO;
  a multi-request test verifies the published used-head order.  Alpine
  exercises the data path and records whether its Linux kernel accepted this
  optional feature; the implementation-level harness proves the device offer
  and ordering contract independently of guest support.
- Full device reset now clears the private negotiated-feature caches in the
  network, vsock, and 9P models.  The network model also restores its
  transport-specific header defaults; selective queue reset deliberately
  preserves the active device negotiation.
- Modern virtio-net receive packets now always use the 12-byte header and set
  `num_buffers` to one when mergeable receive buffers are not negotiated.  The
  two-byte-shorter non-mergeable header is retained only for the legacy
  interface, as required by the legacy exception in section 5.1.9.1.
- Receive offload metadata supplied by a network backend is checked against
  the guest-negotiated checksum and segmentation features before publication.
  Unsupported flags, GSO types, tunnel encodings, and out-of-bounds checksum
  offsets cause the packet to be dropped rather than exposing metadata the
  guest did not agree to consume.
- Virtio-net transmit offload metadata is validated before it reaches a
  backend.  Checksum output must fit in the packet, GSO types require their
  negotiated feature and a nonzero segment size, and the tunnel combinations
  forbidden by VirtIO 1.4 are rejected.  Unknown flag bits remain ignored as
  required.
- Virtio-net backend capabilities are restricted to the offload features the
  interface can carry and are rejected if checksum, segmentation, or ECN
  dependencies are incomplete.  Transmitted GSO records now also require
  `NEEDS_CSUM`, valid checksum bounds, and the negotiated checksum feature
  before any metadata reaches the backend.  Receive-only `DATA_VALID` and a
  nonzero transmit `num_buffers` are rejected without treating unknown flag
  bits as errors.
- Virtio-net now applies only negotiated backend offload features to the
  backend.  Frontend-only and common transport features retain the existing
  headerless tap and slirp path.  If a backend cannot apply the requested
  framing, or reports a different framing after success, receive processing
  and transmit processing remain disabled and the device requests reset.
  Snapshot restore reapplies framing while its existing device locks are held,
  replaces saved derived header state with current verified values, and does
  not reactivate processing after a failure.
- Virtio-block now enforces read-only media before backend submission and
  does not advertise contradictory discard support for a read-only backend.
  Both writes and defensive stale discard requests are rejected without
  modifying storage.  The translating multi-iovec backend now drains a
  partially completed host write before advancing the guest iovec cursor, so
  no unwritten suffix is skipped, and a zero-progress backing-file read fails
  with `IOERR` instead of retrying forever.  Focused fault injection covers
  both cases.  When FLUSH is offered but the driver declines it, a write
  remains outstanding until an implicit backend flush succeeds, providing the
  writethrough stability required by the resulting negotiated mode.  Drivers
  that negotiate FLUSH retain normal writeback behavior and issue explicit
  flush requests.
- FreeBSD guest PCI and MMIO reinitialization now preserves an explicit ceiling
  from the original negotiated feature set.  A child can continue to disable
  and later restore an originally negotiated feature, but cannot introduce a
  new queue or buffer contract.  Reinitialization also fails if the device no
  longer offers every requested feature, because the existing API cannot
  return a reduced set to the child, and all feature, finalization, or queue
  reconstruction failures return the device to reset.
- FreeBSD PCI DEVICE_CFG accesses are bounded by the mapped capability, and
  MMIO device-configuration accesses are bounded by the firmware-provided
  resource.  A missing or truncated configuration region now produces zeroed
  reads, ignored writes, and FAILED status instead of a guest kernel panic or
  out-of-range bus access.  Failures detected before feature finalization
  reject it; failures detected later in child attach suppress DRIVER_OK and
  detach the child.
- Virtio-console now offers emergency write.  A complete `emerg_wr` field
  write is accepted before feature negotiation or queue setup and sends its
  low byte through port zero's existing bounded output path; partial,
  overlapping, and unrelated configuration writes remain rejected.

## Current evidence

- Requirements inventory: 94 entries validated against 401 constants and
  layouts in the independent VirtIO 1.4 oracle.
- AddressSanitizer/UndefinedBehaviorSanitizer device harness: 2,845 checks,
  zero failures.
- ThreadSanitizer device harness: the same 2,845 checks, zero failures and no
  reported data races.
- Native ATF device harness: 246 cases, zero failures or skips.  The recorded
  result is
  `usr_obj_usr_src_amd64.amd64_tests_sys_kern_vsock_device_harness.20260724-114713-822965`.
- Focused production block-backend regression: 4 cases, zero failures.  This
  includes forced 1 KiB host-write fragments across two guest iovecs and an
  empty backing file reached through the translating read path.  The recorded
  result is
  `usr_obj_usr_src_amd64.amd64_tests_sys_kern_vsock_device_harness.20260724-114300-467387`.
- Transport state soak: 4,096 queue reset/re-enable cycles with stale
  completion and full-reset crossings.
- Production bhyve: clean `-Werror` build with DTrace linkage.
- Clang static analysis of `block_if.c` and `pci_virtio_block.c` with the
  core, dead-code, and Unix API checkers: zero findings.
- Virtio block WRITE ZEROES: the focused device tests cover independent wire
  vectors, feature and flag validation, exact and over-limit boundaries,
  capacity, read-only media, reset, and writethrough completion.  A separate
  test runs the production block backend against a real file, crosses the
  `MAXPHYS` boundary, verifies both neighboring regions, and checks read-only,
  bad-descriptor, and arithmetic failures.  Both tests pass under native ATF,
  ASan/UBSan, and TSan.
- Alpine Linux modern and legacy block transports negotiated WRITE ZEROES,
  reported the advertised 16 MiB limit, completed the `BLKZEROOUT` data test,
  preserved the independently calculated whole-disk checksum, and passed the
  matrix reboot/persistence gate.
- Alpine 3.24.1 with Linux 6.18.35-0-virt completed the isolated modern
  virtio-rng data test (657,968 bytes), negotiated
  `VIRTIO_F_NOTIFICATION_DATA` and `VIRTIO_F_RING_RESET`, and correctly
  declined `VIRTIO_F_IN_ORDER`, which that Linux split-ring implementation
  does not support.  The result distinguishes a supported optional device
  offer from a driver-negotiation requirement.
- FreeBSD guest integration: clean `virtio.ko`, `virtio_pci.ko`,
  `virtio_random.ko`, and `virtio_vsock.ko` module builds.
- All eight Linux guest helpers pass syntax checks and their host-side
  self-tests.  Each helper which requires a modern transport feature is
  tested with every required feature removed one at a time.
- Prior live Alpine coverage exercises modern and legacy net, block, SCSI,
  console, RNG, input, vsock userspace backend, vsock kernel backend, device
  reset/rebind, and monitor-mode reboot.  The current modern and legacy net
  and block matrix passed with Linux feature assertions, network traffic,
  WRITE ZEROES, exact checksum, and persistence coverage.

## Linux implementation comparison

The 2026-07-24 review compared bhyve with the corresponding upstream Linux
VirtIO core, modern PCI, split-ring, net, block, SCSI, console, RNG, input,
9P, and vsock sources.  The comparison treats Linux as an interoperability
oracle, not as a replacement for the specification.

- Linux preserves transport feature bits before device-driver negotiation.
  Its split-ring finalizer accepts indirect descriptors, event index,
  in-order operation, and notification data; modern PCI then accepts ring
  reset when the device offers it and the common capability is long enough.
- Linux constructs notification data as the available index in the upper
  half and the queue index in the lower half.  The focused bhyve test now
  follows Linux's feature/status/queue-enable/notify/queue-reset ordering.
- The Linux console, RNG, input, 9P, block, SCSI, net, and vsock queue
  directions and feature tables agree with the device-specific assumptions
  in the harness and Alpine helpers.
- The Linux virtio-net path treats `hdr_len` as a hint unless
  `VIRTIO_NET_F_GUEST_HDRLEN` is negotiated.  bhyve does not advertise that
  feature; its netmap backend independently parses the Ethernet, IP, and
  transport headers rather than relying on the hint.
- Linux's one-segment WRITE ZEROES path emits one contiguous little-endian
  range and derives the queue zeroing limit from
  `max_write_zeroes_sectors`.  That matches bhyve's one-segment, 16 MiB
  contract and the live Linux `BLKZEROOUT` result.

## Optional-feature roadmap

1. Keep block write-zeroes in the regular Alpine acceptance matrix.  The
   implementation advertises one segment, `write_zeroes_may_unmap = 0`, and
   a conservative 16 MiB limit on writable backends.  The device harness
   covers feature gating, read-only media, capacity and flag validation,
   UNMAP permission, cancellation, and flush completion.  The Linux helper
   independently requires negotiated bit 14, checks Linux's queue limit,
   issues `BLKZEROOUT`, verifies every resulting byte, and checks persistence
   after reboot.  The modern and legacy acceptance run passed.
2. Build a black-box PCI/virtqueue conformance runner from the section 7
   conformance clauses.  Run the same command corpus against bhyve and a QEMU
   reference device, while keeping expected constants and layouts sourced
   from the independent VirtIO 1.4 oracle.
3. Add cross-build and emulated-guest jobs for amd64, aarch64, and riscv64.
   Add synthetic byte-swapped register and wire-structure tests now; real
   big-endian interoperability requires a suitable platform and is a
   separate acceptance environment.
4. Implement packed virtqueues as a second queue engine behind shared queue
   operations, not as conditional branches throughout the split-ring code.
   Gate advertisement per device and rerun every descriptor, reset,
   notification, sanitizer, soak, Linux, and FreeBSD guest test in both ring
   layouts.  The staged design and acceptance matrix are recorded in
   `docs/bhyve-virtio-packed-ring-design.md`.
5. Extend `VIRTIO_F_EVENT_IDX` from virtio-net to another device only after
   that device's queue sleep transition has an enable-and-recheck test; add
   notification-rate measurements to the Alpine net run.
6. `VIRTIO_F_NOTIF_CONFIG_DATA` is implemented for modern PCI.  bhyve uses
   the specification-permitted trivial queue-index identifiers, while the
   FreeBSD guest retains the device-provided opaque identifier.  Keep the
   16-bit and 32-bit notification paths independently tested.
7. Extend `VIRTIO_F_IN_ORDER` beyond RNG, input, and console only to devices
   whose every queue has a documented completion-order guarantee and a
   multi-request ordering test.

The remaining exclusions are intentionally coupled to missing prerequisites:

- `VIRTIO_F_ACCESS_PLATFORM` requires an enforceable IOVA-to-GPA translation
  and invalidation model, normally a virtual IOMMU.  Advertising only the bit
  would misrepresent direct guest-physical DMA as protected DMA.
- Administration virtqueues, device groups, and SR-IOV form one owner/member
  project.  It needs PCI VF lifecycle, group membership, command
  authorization, reset, migration, and error handling before any of those
  features can be exposed.
- Device suspend requires a versioned device-state format and a proven
  quiesce boundary for all queues and asynchronous backends.  bhyve process
  snapshot support alone does not satisfy this contract.
- Shared-memory PCI capabilities should be added with their first consumer,
  such as a future virtio-fs or GPU implementation.  An unused region is not
  interoperability progress.
- New device models should be selected by a concrete guest workload.  Each
  one needs its own section 7 inventory, independent wire oracle, Linux
  helper, reset/error tests, and soak coverage rather than inheriting a
  generic “VirtIO compliant” claim.
- OASIS VirtIO 1.4 defines conformance targets and clauses, but the current
  validation record does not identify an external certification program or
  authoritative executable certification suite.  Until one is identified,
  the practical external checks are Linux guest interoperability and a
  differential device command corpus against another mature implementation.

## Remaining acceptance work

The repeated kernel/private review now also covers nested transaction
composition and active-L2 restore publication.  The common x86 startup result
has a closed classifier over errno, committed, rollback-complete, poisoned,
and reserved fields; its direct test enumerates all sixteen boolean shapes and
rejects malformed fields.  Intel INIT/SIPI execution remains behind the
existing `ENOTSUP` gate until installed-kernel BSP/AP, race, rollback, and
VPID qualification is complete.

The save-state replay found that VM-wide VMCS-registry replacement could alias
the per-vCPU rollback binding array or acquired workspace/capability owners.
The restore transaction now validates the complete registry-entry, binding,
owner, capability, scratch, and generation storage graph before acquisition.
An impossible kernel rollback failure is fail-stop, while the userspace model
retains the generation that still identifies an active owner.  The focused
negative model, full 269-case nested suite, 326-entry requirement validator,
163-entry private-interface validator, and fresh `vmm.ko` Werror build pass.
Live active-L2 restore under memory pressure and repeated running-L2 restore
remain installed-kernel gates.

The subsequent common-kernel startup replay found two independent wakeup
defects in the still-gated kernel-owned INIT/SIPI path.  An accepted SIPI
cleared `startup_cpus` without notifying a target blocked in the event-driven
startup sleep, and the wake-side predicate replay returned runnable on a
cleared startup bit before servicing rendezvous, suspend, reqidle, or debugger
work observed in the same locked snapshot.  SIPI now notifies every accepted
target after releasing `rendezvous_mtx`, preserving the waiter lock order, and
the wait loop gives lifecycle predicates precedence over hardware re-entry.
The requirements validator carries explicit source-order anchors for both
races.  A fresh `vmm.ko` Werror build passes; activation remains disabled
until installed-kernel before/during/after-enqueue and simultaneous lifecycle
race tests pass.

The next save-state replay expanded the active-L2 destination fence.  Before
registry replacement, restore now rejects destination startup dispatch,
thaw/refreeze, hot-failure recovery, referenced EPT roots, EPT callbacks,
hardware VMCS02 state, resource leases, VPID/MTF ownership, exit-MSR work,
prepared plans, hardware-MSR transitions, and non-L1 TSC_AUX residency.  A
quiescent L1 VMX architectural context remains replaceable.  After every
destination validates, restore discards even unreferenced nested-EPT cache
roots before publication: their shadow translations were derived from the
pre-restore guest-memory image and cannot survive memory replacement safely.
Structural corruption is propagated separately from ordinary `EBUSY`
ownership so a permanent defect is not mislabeled as retryable.  The complete
fence and cache retirement run before workspace acquisition or registry
publication; installed repeated-restore and nonquiescent-destination cases
remain pending.

The reverse source-side replay found that save used a narrower ad hoc runtime
check than restore.  Snapshot now validates startup dispatch, staged
thaw/refreeze, hot-failure recovery, EPT references and callbacks, the full
inactive VMCS02 adapter and lease owner, VPID/MTF state, exit-MSR work,
hardware-MSR transitions, and both current and rollback TSC_AUX residency
before writing the first ordinary VMCS byte.  Active L2 remains admissible
only as the detached cold continuation with a validated portable image and
owned MSR workspace.  Installed fault injection for each rejected source
owner remains pending.

The private VMCS02 inactive-owner predicate now also has a typed form.
Checkpoint paths return `EBUSY` only for a live transaction, deferred VMCS01
write, or current VMCS02; missing or aliased permanent VMCS storage and stale
inactive identity are structural errors.  Blocker-only callers retain the
boolean wrapper.  The negative model covers each classification.

The doubled common and Intel checkpoint review added four further source-side
requirements.  VMS2 capture now copies the startup-wait cpuset under its
rendezvous owner, and an immutable restore plan reserves both event generation
and the destination startup mask so concurrent INIT/SIPI causes `EAGAIN`
instead of lost state.  Intel restore staging now proves an exact sparse
topology-to-private-cookie mapping before any cache or architectural mutation.
The source fence validates the nested context as quiescent or as the exact
active cold continuation before ordinary VMCS serialization.  These are
foundation corrections only: legacy snapshot ordering is unchanged and VMS2
is not production-selected.  Installed startup/restore races and sparse active
L2 restore remain live qualification gates.

- Kernel-backed vsock restore now replays the restored device feature set
  into the empty, frozen destination provider before THAW.  Focused tests
  prove that feature-replay and thaw failures retain a retryable fence, that
  validation does not mutate the feature state, and that frozen provider
  readiness remains suppressed across the epoch change.  The live split and
  packed checkpoint cases transfer STREAM and SEQPACKET data in both
  directions after restore, so attach-time STREAM defaults cannot satisfy the
  reconstruction gate.  Those cases remain pending because the installed
  kernel must contain the matching frozen-provider ioctl behavior.

- Retain the complete Alpine matrix as an acceptance gate, including modern
  and legacy transports and MSI-X-disabled cases.
- Retain the block topology's `write_zeroes=yes`, exact-checksum, neighboring
  data, and reboot-persistence assertions as regression gates.
- Run the new longer VM-backed reset soak for net, block, SCSI, console, RNG,
  9P, and both vsock backends.  Input remains a separate single-run gate
  because its software provider is intentionally one-shot.
- Retain negotiated net `EVENT_IDX` in both Alpine transports and
  `NOTIFICATION_DATA` on modern PCI; `gnet.py` checks Linux's
  negotiated-feature bitmap and fails if the required bits are absent.
- Boot a FreeBSD guest with the rebuilt VirtIO PCI transport and confirm
  `NotificationData` appears in its negotiated feature line while net and
  block I/O continue across queue activity and reboot.
- In that disposable FreeBSD guest, run
  `ITERATIONS=100 /usr/tests/sys/kern/vsock_e2e/run-freebsd-vtrnd-reset.sh`.
  Only after it observes successful queue-reset probes should the guest
  `RING_RESET` entries be promoted into the machine-readable requirements
  inventory.
- Add per-device enable-and-recheck coverage before advertising `EVENT_IDX`
  beyond virtio-net.
- Continue converting the requirements inventory from common transport and
  reset clauses into per-device normative clauses.
## 2026-08-03 nested-VMX doubled kernel/private phases

The nested-VMX review gate now includes two additional mandatory phases after
the independent kernel and private-boundary replays.  The first audits actual
callback execution context and every irreversible tail; the second rebuilds
the inventory of non-standard provider and policy domains from definitions and
consumers independently.  Changes restart both phases.

The first application found that staged INIT correctly needed to discard
destination-local EPT02 roots, but incorrectly placed vmspace destruction in
an infallible startup finalizer.  The finalizer now only accepts an already
empty cache, and production activation remains disabled until a fallible
precommit retirement step is implemented and qualified.  A separate finding
made EPT-cache callback-table validation uniform across every public hot path,
with negative tests for incomplete providers.  These are nested-VMX lifecycle
and private-policy corrections; they do not advertise a new VirtIO feature or
change the architecture-neutral save-state format.

The consumer-side replay subsequently corrected typed MTF-owner propagation,
VMCS02 lease callback isolation, and hardware-entry callback stability.  The
lease and hardware adapters now capture provider tables before compound work,
use private rollback candidates where ownership is destructively traversed,
and reject negative provider statuses as malformed private behavior.  The
strict kernel-module build and all 269 rootless nested tests pass with 346
requirements and 183 non-standard interfaces validated.  Live Intel VMX
qualification remains a separate required gate.

## 2026-08-04 terminal kernel and private-contract review phases

The review gate now ends with two independently recorded final-source phases.
The kernel phase starts from public syscall, socket, VMM, device, interrupt,
taskqueue, callout, and snapshot entries and performs forward and reverse
lifetime traces through common code and architecture adapters.  The following
private-contract phase rebuilds every non-standard interface from consumers
and installed operator surfaces, including private records, backend identity,
limits, timeouts, compatibility policy, DTrace/audit metadata, and MAC policy.
Both require a fresh complete source manifest; any change restarts the common
primitive and private activation passes as well as the terminal pair.  They
are review obligations, not a claim that the pending privileged and live
qualification has completed.

## 2026-08-04 common-contract and decoder-policy replay phases

The terminal pair is followed by two more independent review phases.  The
first begins at common production-kernel consumers—VMM, socket, DMA,
interrupt, taskqueue, callout, sleepqueue, credentials, prison/VNET, MAC,
snapshot, and module lifetime—and proves that each bhyve or device adapter
preserves those contracts.  It explicitly rejects undocumented Intel,
pointer, native-endian, page-size, process-lifetime, and bhyve-only common
assumptions.

The second begins at accepted private decoder and operator values, including
ioctls, provider and backend protocols, checkpoint envelopes, manifests,
compatibility selectors, limits, timeouts, retries, polling, probes, audit,
and MAC policy.  Each must have a validation boundary, owner, authorization,
namespace, generation, architecture scope, rollback behavior, and independent
positive and rejection evidence.  Either pass restarts the complete final
review sequence; neither asserts that privileged or long-run qualification is
complete.

## 2026-08-04 second common-kernel and non-standard policy replays

Two final review phases now follow the callback-identity traversal.  The first
starts with common kernel primitives—DMA, guest-memory mappings, interrupts,
taskqueues/callouts, sleep/wakeup, credentials, prison/VNET, module lifetime,
and snapshot dispatch—and traces every final VirtIO/VMM consumer through
success, error, reset, suspend, restore, and teardown.  Pointer width,
endianness, page size, Intel behavior, and process lifetime are treated as
architecture or interface facts only where the common ABI states them.

The second reconstructs non-standard behavior from accepted configuration and
operator surfaces: private PCI and ioctl values, providers/backends,
snapshots/manifests, feature gates, limits, retries, observability, MAC
policy, and test controls.  Each contract requires independent acceptance and
rejection or withdrawal evidence and may not weaken a normative VirtIO, PCI,
socket, DMA, or checkpoint invariant.  A correction in either phase restarts
the final common/private sequence.  These source and model obligations do not
replace pending root-only Linux/5BSD, checkpoint, soak, or Intel-hardware
qualification.

## 2026-08-04 complete terminal VirtIO review sequence

The executable VirtIO review gate now requires every terminal phase, Passes
35 through 42, exactly once.  Passes 37 and 38 provide the mutation/rollback
and implementation-defined replay; Passes 39 and 40 independently cover
withheld features and test-oracle activation; and Passes 41 and 42 repeat the
production-kernel and private-contract traversals from fresh entry- and
consumer-derived inventories.  The validator rejects an obsolete completion
rule at Pass 36 or Pass 40, a missing detailed terminal phase, or a duplicate
terminal heading.  These checks enforce the review process itself; they do
not promote rootless evidence into installed-kernel, Linux, 5BSD, checkpoint,
or soak qualification.

## 2026-08-04 non-standard failure-boundary replay

The paired kernel/private review was also applied to the nested-VMX failure
surface.  The review starts from every explicit `ENOTSUP` and `EOPNOTSUPP`
outcome in the production Intel VMX sources (`vmx.c` and `vmx_nested*.c`) and
traces it to the capability, provider, checkpoint, or execution consumer that
makes the feature unavailable.  It distinguishes a guest architectural
outcome from a host-management errno and requires the latter to leave no
partially published VMCS02, EPT/VPID, registry, checkpoint, or callback owner.

The review found a validator omission: its inventory recognised only direct
`return (ENOTSUP)` sites.  Staged rollback paths that assign `ENOTSUP` or
`EOPNOTSUPP` before using shared cleanup are equally implementation-defined
contracts, so the inventory now includes both direct and deferred forms and
requires every contributing source file to appear in the consumer-derived
private ledger.  The widened inventory is clean.  This is rootless
source/ledger evidence only; it does not qualify the withheld Intel execution
paths on installed hardware.

## 2026-08-04 independent VirtIO unsupported-source inventory

The non-standard VirtIO gate previously verified that every listed private
contract named a negative test, but it began from the ledger.  The second
consumer-derived inventory instead starts at final `ENOTSUP` and `EOPNOTSUPP`
sites in the bhyve VirtIO core and device-model sources.  Every such source is
now required to name an exact owner in the private-interface catalog; the
catalog entry in turn requires a direct rejection test.  The newly recorded
sources were the provisional administration capability/group/resource/device
part paths, virtio-fs backend/session/cancellation/reset boundaries, GPU 2D
unsupported command handling, and IOMMU unknown-request handling.

This is intentionally a source-file inventory rather than an assertion that
all unsupported results have identical semantics.  Each row distinguishes an
unadvertised experimental facility, private host backend ABI, standard
optional-command subset, or internal normalization, and records its
no-publication rollback rule.  The rootless requirements and full device
harness passed after the change.  Live Linux/5BSD activation, checkpoint, and
soak qualification remain separate evidence gates.

## 2026-08-04 VMX exit-ownership double review

The second production-kernel review followed raw VMX exits through hardware
provenance, outer-exit dispatch, policy construction, context construction,
and final L0/L1 routing.  The review confirmed that unknown basic reasons,
raw host interrupts/NMIs, and each deliberately unexposed Appendix-C facility
remain L0-owned.  The implementation-defined decision is normalized before a
caller can build routing policy, rather than relying only on the final router.

The review found a coverage gap, not a production defect: the provenance test
sampled INIT and a short consecutive range, while the final-routing test held
the complete independent Appendix-C list.  The provenance fixture now carries
the complete literal list and proves every one sets `l0_must_handle` before
policy/context publication.  Its expected values remain independent from the
production switch.  The focused rootless model test and `git diff --check`
pass.  This is still model evidence; real Intel VMX execution and nested
Linux/5BSD qualification remain required root-only gates.

## 2026-08-04 common snapshot portability replay

The follow-on common-code review traced the envelope and common VM/vCPU state
code used before the Intel adapter.  It has fixed-width little-endian wire
records, validates all reserved bytes and lengths, keeps host pointers only in
the in-memory builder/reader, and rejects overlapping caller storage before
publication.  No x86 register, VMX capability, host page-size, or native
structure image crosses this common boundary.  Architecture-specific state is
therefore still carried in an explicit machine section rather than being
smuggled through common state.

This is a source/model conclusion only.  Cross-endian, non-amd64, and
cross-host restore remain explicit future qualification gates rather than
claims made by this replay.

## 2026-08-04 common snapshot iterator alias correction

The portability replay found one shared-code failure-atomicity defect:
`vmm_snapshot_envelope_next()` rejected a section output that overlapped the
wire buffer, but did not reject one that overlapped its reader object.  Such a
call could overwrite the iterator after it advanced its cursor.  The common
codec now rejects that alias before examining or publishing the next section.
The regression fixture constructs a non-empty envelope, supplies the reader as
the output storage, and proves `EINVAL` leaves the complete reader unchanged.

The reciprocal output path had the same class of defect: `finalize()` checked
its length output against the wire buffer but not its builder object.  It now
rejects that alias before finalization, and the same fixture proves the builder
is unchanged.  Together these checks make iterator and builder publication
fail-atomic even for hostile in-process callers.

The correction is architecture-neutral and applies to every snapshot consumer;
it is covered by the full rootless common-envelope test.  It does not itself
provide cross-host restore evidence.

The expanded alias fixture also exposed a test-only boundary regression: it
had used `sizeof(wire) - 1` to represent a too-small envelope, which stopped
being below the required header size when the fixture buffer grew to exercise
non-empty iteration.  The assertion now uses
`VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE - 1`, the independent wire-format minimum.
The complete rootless envelope suite passes with the corrected boundary.

## 2026-08-04 doubled clean-room kernel and non-standard replays

The terminal review procedure now extends through Passes 43 and 44.  Pass 43
rebuilds production kernel invariants directly from external entries and final
state readers/writers rather than from the requirements ledger or findings of
the preceding reviews.  It covers common VMM and device-model state,
guest-memory/DMA, queues, interrupts, asynchronous work, kernel lifetime,
transport, snapshot, and VM-entry/exit boundaries across success and failure.

Pass 44 separately reconstructs every implementation-defined contract from
operators, production consumers, diagnostics, and unsupported results.  It
requires explicit ownership, validation, authorization, namespace/generation
scope, portable-state treatment, failure atomicity, observability, and
independent positive and rejection evidence.  Both phases restart the final
cycle upon any correction.  They deliberately keep the distinction between
rootless source/model review and pending installed-kernel, Linux, 5BSD,
checkpoint, and soak qualification.

## 2026-08-04 nested startup fail-closed caller-state proof

The staged kernel-owned startup management ABI remains unavailable until the
installed-kernel INIT/SIPI transaction and the complete VMCS02 owner
conversion are qualified.  The negative installed-kernel test now proves more
than its `EOPNOTSUPP` result: rejected configuration leaves the complete
caller request unchanged, and a rejected generation run leaves both the
request and caller-provided `vm_exit` record unchanged.  The static nested
requirements gate requires those assertions, alongside the machine-owned
false readiness gate and VMX's pre-residency startup-owner rejection.  This
keeps the temporary boundary transactional while the missing execution paths
are deliberately withheld.

## 2026-08-04 nested attempted-entry inverse-provenance review

The second Intel-private review examined the handoff between a classified
unentered VMX attempt and the portable pending-entry owner.  It found that the
private outcome model had accepted either recoverable inverse operation for
all unentered failures.  That is not a harmless equivalence: an initial
attempt must roll back the initial private VMCS02 preparation, while a resumed
attempt must refreeze its previously detached continuation.  Both leave L2
unentered, but they have different private residency provenance.

The model now accepts only `ROLLBACK_INITIAL` for initial rejection or L0
failure and only `REFREEZE_UNENTERED` for resumed failed entry or L0 failure.
The two crossed combinations fail before the mutable owner outcome is
published, and the test proves the prior outcome is retained.  The rule is
recorded as a non-standard Intel-private lifecycle contract; it neither
enables the withheld kernel startup path nor changes the portable owner ABI.
The immutable attempt-plan bridge is tested separately with the same crossed
initial/resumed L0-failure pairs, so a later bridge refactor cannot weaken the
classifier-level proof while still appearing to preserve it.  The static
ledger gate and rootless nested model suite pass.  Installed-kernel Intel
execution, including VMCS02 cleanup and real-entry classification, remains a
required later qualification gate.

## 2026-08-04 ordinary VMX attempted-entry accounting review

The independent kernel replay also examined ordinary, non-nested VMX rather
than assuming that its earlier startup-owner conversion was covered by the
nested model.  `VMLAUNCH` and `VMRESUME` can report an instruction failure
without executing a guest instruction.  The old ordinary-loop placement had
already changed the common owner to `IN_GUEST` before that distinction was
known, and its normal post-entry settlement could therefore record a
non-entry as an ordinary guest exit.

The ordinary VMX loop now uses the pending attempted-entry form immediately
before the instruction.  A declined admission reverses local VMX preparation
and resolves the deferred common result.  Only `VMX_GUEST_VMEXIT` commits the
owner as a real entry; an instruction failure aborts the pending owner as a
no-entry software result while retaining the historical `VM_EXITCODE_VMX`
visible to userspace.  The local launch selector is likewise advanced only
after a real VM exit, so a failed initial `VMLAUNCH` remains eligible for a
later `VMLAUNCH` rather than being silently retried as `VMRESUME`.
Post-entry settlement is reached only after a proven guest exit.  This is an
Intel-private execution-status adaptation, not a
VMCS field, saved-state record, or readiness change.  The static requirements
gate checks the complete source order and the portable owner model proves the
pending/commit/abort distinction.  A warning-free kernel build and installed
Intel lifecycle, re-entry, and instruction-failure tests remain required
before this is treated as live-qualified.

## 2026-08-05 nested exposure-policy consumer replay

The consumer-first non-standard pass reviewed the private nested-VMX CPU-model
selection and its checkpoint header independently of instruction and VMCS
logic.  The implementation already constructs capability and exposure values
locally before publication.  The review found that the exposure test checked
rejection errno values but did not prove caller output stability for rejected
configuration and lock transitions.  The model test now uses a sentinel output
for locked-policy changes and malformed state and proves it remains unchanged
on `EBUSY` or `EINVAL`.  This confirms the private host/guest policy cannot
partially alter a future CPUID model after rejecting the request.

This evidence covers only value-layer policy, does not enable default-off
nested exposure, and does not replace installed Intel Linux/KVM L1 with Linux
and FreeBSD L2 qualification.

## 2026-08-04 VirtIO-IOMMU snapshot accounting invariant

The IOMMU snapshot path now validates its locked live bookkeeping before it
uses cached counts as allocation sizes or serialization cursor bounds.  The
check requires endpoint and domain counts to match their present entries,
unique endpoint/domain identifiers, attached endpoints to name a present
domain, detached endpoints to have no stale domain, each domain's endpoint
count to match the attached endpoints, and mappings to occupy exactly the
compact sorted prefix.  Each live mapping must also meet the same static
domain, permission, range, alignment, overflow, and non-overlap constraints
needed for a portable image.  The bounded fault FIFO's cursors must match its
count, and every configured backing table must be present.  A violated
internal invariant returns `EPROTO` before the caller's output buffer is
modified.

This is a fail-closed implementation-defined checkpoint contract; it does not
add a guest-visible VirtIO-IOMMU request rule.  The independent white-box
model test perturbs each cached counter and mapping invariant after a valid
control-plane setup and checks both snapshot-size and snapshot rejection,
including unchanged output.

## 2026-08-05 VirtIO-IOMMU translation and existing-device lifecycle replay

The common IOMMU review traced endpoint registration, attach/detach, map and
whole-range unmap, translation, fault reporting, deferred reset, and portable
restore through their success and error paths.  Authorization is decided while
the state lock is held, while the external GPA mapping callback runs after the
lock is released.  Request-level DMA leases retain the previously authorized
address space until the active set drains; map revocation, detach, reset, and
snapshot/restore therefore return a retryable busy result rather than
invalidating a host pointer held by accepted work.  The event-driven idle
callback is the retry edge.  The review found no additional source-level
correctness defect.

The rootless `virtio_iommu_state_test`, protocol, request, queue, event, and
topology model suites were rebuilt with warning-as-error flags and completed
cleanly.  The independent DMA-boundary and snapshot-portability validators
also passed.  A separate lifecycle replay rebuilt and ran the SCSI (including
event and multiqueue checkpoint ownership), console, 9P, and input model
suites; they completed cleanly with their expected malformed-input diagnostics.
This is model and source evidence only.  Linux and 5BSD live activation,
translated-DMA operation, active-I/O restore, and long fault/reset soak remain
installed-host qualification gates.

## 2026-08-05 virtio-vsock reconstruction boundary replay

The userspace and kernel provider paths were reviewed as separate external
backend contracts.  A checkpoint contains only the stable device identity,
guest CID, negotiated device features, and allocator state; it never treats
file descriptors, host sockets, buffered packets, or provider queues as
portable bytes.  The userspace path consequently rejects active listener or
connection state.  The kernel path stops every readiness source, requires a
successful empty-provider FREEZE response, restores the provider feature epoch
while still fenced, and only then THAWs and reopens callbacks.  Malformed
provider checkpoint replies and thaw failures retain the fence or force reset;
they do not publish a half-resumed backend.

The `vsock_device_test` model suite was rebuilt and run directly, covering
both backend names, suspend/rearm, checkpoint freeze/thaw, malformed provider
replies, retryable thaw failure, identity mismatch, active-resource rejection,
and reset recovery.  It completed cleanly.  This is not live migration
evidence: multi-provider active checkpoint, Linux and 5BSD guest recovery,
CID collision handling during destination reconstruction, and long concurrent
VM soak remain root-only gates.

## 2026-08-05 common interrupt and portable checkpoint replay

The common PCI VirtIO review treated guest-visible interrupt state separately
from host interrupt plumbing.  The snapshot encodes the ISR latch, queue and
configuration vector assignments, transport feature state, and deferred
notification state in fixed-endian fields.  It does not serialize host MSI,
MSI-X, INTx, file-descriptor, or platform callback handles; those remain
destination-local PCI responsibilities.  Restore validates the negotiated
feature and vector topology before publication, while the pause fence keeps
queue and configuration notifications deferred until the backend is ready.
The event-driven resume edge then replays one coalesced configuration update
and every ready queue notification.

The rootless checkpoint compatibility, checkpoint machine, PCI checkpoint,
portable snapshot, RNG-interrupt, and common VirtIO model suites were rebuilt
and run.  They covered incompatible topology rejection, malformed state,
little-endian persistence, deferred-notification replay, MSI/MSI-X/INTx
selection, ISR read serialization, and checkpoint rollback.  They completed
cleanly.  This does not replace installed-host validation of real MSI/MSI-X
delivery, device suspend, active-I/O restore, or cross-host checkpoint
compatibility; those remain explicit qualification gates.

## 2026-08-07 host-IOMMU mapping failure and domain-lifetime replay

The host-IOMMU wrapper was rechecked independently of the VirtIO-IOMMU guest
model.  Its backend contract now requires each successful map or unmap call to
report a positive prefix no larger than the remaining request; zero progress or
an oversized prefix is converted to `EIO`, preventing an infinite cursor loop
or address wrap.  Host-domain identity-map construction now fails closed before
host devices are attached.  Cleanup clears the backend availability state, so a
failed initialization cannot later construct a domain through a cleaned-up
provider.

The per-VM passthrough path now propagates mapping errors, invalidates the VM
domain rather than the host domain, rolls back a failed first assignment, and
destroys the per-assignment domain after the last device detaches.  This avoids
both a device proceeding with a partial DMA view and a later assignment
reusing stale translation state.  Unmap attempts all marked segments before
returning its first error, allowing teardown to remove the domain even after a
backend fault.

`sys/modules/vmm` rebuilt successfully with `-Werror` after this change, and
the complete rootless VirtIO/vsock/nested host-regression gate passed (including
the device harness, snapshot build modes, and 348 ASan/UBSan nested-VMX model
cases).  Hardware IOMMU and passthrough remain an explicit privileged gate:
exercise failed map/unmap injection, first and repeated device assignment,
detach/reassign, IOTLB invalidation, and translated DMA under Linux and 5BSD.

## 2026-08-07 vsock lifecycle follow-up and source build closure

A follow-up review treated the two vsock backends as separate reconstruction
boundaries.  For the kernel-backed form, the exclusive provider is released by
the cdev-private destructor when bhyve closes its provider descriptor; there
is intentionally no independent detach ioctl.  The review traced attach,
feature setup, freeze, thaw, reset, source rearm, snapshot validation, and
initialization-failure cleanup.  It found no additional actionable lifecycle
defect.  In particular, a malformed FREEZE reply is thawed before admission
reopens, while a thaw or feature-epoch failure retains the fence and requires a
retry or reset.

The sanitizer-backed device harness was rerun from the current source tree:
all component checks completed with zero failures, including the vsock
snapshot/failure-injection cases and independent VirtIO requirement,
portability, DMA-boundary, and DTrace validators.  A clean, isolated build of
the source `libvmmapi` followed by the full DTrace-enabled bhyve program also
linked with `-Werror`.  Building bhyve against the installed libvmmapi alone
initially failed because that older library does not export the newly added
memory-management entry points; this was a build-order/environment mismatch,
not a source-level link failure.  Privileged guest, hardware-IOMMU, and
active-backend checkpoint tests remain required before release qualification.

## 2026-08-07 IOMMU errno-contract and architecture-boundary replay

An additional error-path and portability replay found that the internal
`IOMMU_REMOVE_MAPPING()` forwarding wrapper widened the backend's `int` errno
result to `uint64_t` before callers narrowed it again.  It happened to retain
ordinary positive errno values on the current host, but it did not preserve the
declared IOMMU operation contract.  The wrapper now returns `int`, matching the
operation table and both VT-d and AMD-Vi implementations end-to-end.

The VMM module rebuilt with `-Werror` after the correction.  The independent
snapshot-portability, DMA-boundary, requirements, reference-corpus, DTrace,
and private-interface validators all passed.  A source review also confirmed
that the common coordinator and checkpoint APIs contain no VMX/SVM state: the
private startup request ABI and its cdev state are compiled only on amd64, and
non-amd64 calls return `EOPNOTSUPP` rather than implying an incomplete machine
action is portable.  Cross-architecture builds and real translated-DMA runs
remain privileged or hardware-specific qualification gates.

## 2026-08-07 SCSI event-channel conformance replay

The virtio-SCSI control and event paths were reviewed against the 1.4
asynchronous-notification and eventq definitions.  The controlq
`AN_QUERY`/`AN_SUBSCRIBE` fields describe MMC physical-interface notification
classes on a specified LUN.  bhyve's CTL source instead supplies logical-unit
inventory and parameter changes, which are reported through eventq transport
reset and parameter-change records.  It therefore correctly reports an empty
AN subscription set rather than pretending that a CTL LUN add/remove/change is
an MMC notification.  Event delivery remains gated by negotiated HOTPLUG and
CHANGE features; source continuity, overflow, missing-buffer reporting,
multimedia filtering, suspend, and checkpoint fences have independent host
tests.

The review found no new SCSI wire or lifecycle defect.  The focused source
checks and repository-wide whitespace check passed.  Live CTL event injection,
guest discovery, packed rings, and active checkpoint remain root-qualified
matrix gates.

## 2026-08-07 nested restore ownership and publication replay

The active-L2 destination-restore path was reviewed as an ownership
transaction rather than as a wire-format decoder.  Before any destination
resource is acquired, it validates both VMCS registry graphs and rejects every
alias involving the binding table, workspace owners, immutable capability
records, mutable plan/rollback storage, and generation outputs.  It then
acquires all MSR workspaces before replacing the VM-wide registry.  A late
workspace failure rolls earlier acquisitions back in reverse order; an
impossible rollback failure stays fail-stop in the kernel so an active owner
cannot be silently abandoned.  Registry replacement itself swaps only
validated disjoint entry sets, and all subsequent per-vCPU publication steps
are non-fallible transfers from the staging object.

The destination's cached nested EPT translations are intentionally discarded
before publication: after memory restore they describe the old destination
guest-memory image and may not be reused.  That invalidation is retained even
when a later restore check rejects the image, leaving the frozen destination
safe rather than retaining stale translations.  Rootless focused model cases
for atomic restore, active checkpoint envelopes, and nested run residency all
passed, and the nested requirements/private-interface validator reported 433
requirements and 282 private-boundary entries mapped.  Active-L2 snapshot,
rollback-after-real-VMCS-write failure, and multi-vCPU restore remain
Intel-hardware qualification work; the current model evidence is not a claim
of live nested-VMX enablement.

## 2026-08-07 common checkpoint ingress and wait replay

The architecture-neutral checkpoint coordinator was reviewed for event-driven
progress, cancellation, and cross-owner lifetime rules.  Admission closure
takes all ingress locks in a stable order, and publisher exit uses the same
sleepqueue interlock as the waiter predicate and broadcast.  A transition
immediately before, during, or after waiter registration therefore cannot be
lost.  Waits are interruptible and predicate-driven: a wake returns to the
coordinator for a fresh readiness check rather than treating a timeout or a
bare broadcast as success.  The coordinator's durable and native-resource
adapters remain above this portable state machine, so it contains no VMX, SVM,
PCI, host file descriptor, or machine-word snapshot representation.

All rootless ingress, checkpoint-group, and wait-state model cases passed,
covering normal completion, draining abort, validation and alias rejection,
overflow, cancellation, exact ticket storage identity, and post-wake predicate
replay.  Kernel scheduling races, real device callbacks, durable checkpoint
I/O failure, and multi-VM load remain privileged qualification gates.

## 2026-08-07 packed-ring and VirtIO-IOMMU replay

The packed-ring implementation was traced from descriptor availability through
chain acquisition, completion publication, event suppression, queue reset, and
snapshot cursor validation.  It is shared by the bhyve queue path rather than
being only a standalone model.  The production engine limits a single chain
or completion interval to one queue revolution; the independent oracle walks
descriptor positions explicitly, including non-power-of-two queue sizes and
wrap boundaries.  This keeps the implementation's modular arithmetic from
being its own expected-result source.

The VirtIO-IOMMU review then checked topology construction, endpoint binding,
translated-DMA acquisition/release, request retry after a revoking operation,
fault/event delivery, reset, and snapshot validation.  Reset defers until
already accepted endpoint DMA has released, so an active mapping is not
revoked beneath an in-flight request.  The provider is excluded from its own
translated endpoint set and multiple providers fail closed until device-group
partitioning exists.  Full rootless packed-engine/model and VirtIO-IOMMU
protocol, state, request, queue, topology, and PCI suites rebuilt with
`-Werror` and passed.  Hardware IOMMU, real ACCESS_PLATFORM guests, packed
Linux/5BSD guests, and translated-DMA checkpoint remain root-only gates.

## 2026-08-07 nested-entry and live-harness recovery replay

The Intel-only nested VMX execution edge was reread separately from the
portable checkpoint transaction.  `vmx_run_nested()` deliberately refuses to
consume a common startup owner after a path can select VMCS02 or acquire L2
CPU-local state: an error at that point cannot honestly be represented as a
portable no-entry result.  The resulting `EOPNOTSUPP` is a fail-closed
qualification boundary, not an advertised nested-VMX success path.  The
matching entry-validation, hardware-result conversion, exit-provenance,
dynamic-intercept, reflection, and unwind model cases were run from the
freshly built nested-state binary and completed cleanly.  This preserves the
architecture-neutral lifecycle contract while keeping Intel VMCS ownership
behind the VMX adapter.

The real-guest reset-soak replay also checked recovery of asynchronous Linux
device-node publication.  The block verifier obtains the device through the
PCI/virtio relationship, then waits only for the corresponding block-special
node with a finite diagnostic deadline; it does not assume that a successful
sysfs bind has synchronously recreated `/dev/vdX`.  The runner uses
`udevadm settle` when available and a synchronous `mdev -s` scan otherwise.
The 9P/virtio-fs reset cleanup accepts a lazy detach only for the documented
already-invalidated-superblock case and otherwise keeps unmount failures
fatal.  All sixteen guest-helper self-tests and the virtio-lab self-tests
passed locally.  The lab separately exposes a short `soak-smoke` profile and
the longer endurance profile, and its nested profile has an explicit,
exclusive Intel-hardware live gate; neither can be inferred from ordinary
release or model-test evidence.

## 2026-08-07 nested live-runner environment boundary

The hardware qualification wrapper now starts the reviewed external L1 runner
with an empty environment and a small declared contract: the immutable guest
images, reviewed bhyve path, evidence and artifact destinations, VPID policy,
run identifier, timeout, work directory, and a private temporary directory.
This prevents an invoking shell from changing root-runner behavior through
loader, interpreter, build, or helper-selection variables while retaining the
inputs that bind generated artifacts to this exact run.  The private temporary
directory is mode 0700 and stays with the attempt for diagnostics.

The requirements validator checks the clean environment, private temporary
directory, and run-identifier forwarding.  Its negative fixture removes the
`env -i` boundary and is rejected.  The ordinary validator completed with 433
requirements, 282 non-standard interface entries, and 12 hardware live groups
tracked.  The complete requirements self-test remains a rootless pre-flight
command for the next qualification run; it is intentionally distinct from the
hardware L1/L2 evidence gate.

## 2026-08-07 device-parts publication-alias replay

The architecture-neutral device-parts encoder was checked as a transaction,
not merely as a wire formatter.  `virtio_device_part_append()` used to publish
its header before copying the value while accepting an overlapping value
source.  Such a caller could have the source interval overwritten by the
header and receive a syntactically valid but corrupted portable-state record.
The public header-only builder had the corresponding cursor-alias hazard.

Both builders now reject a source or cursor that overlaps the exact destination
interval before modifying either the byte stream or the cursor.  The
independent section-2.14 harness covers value-source and cursor aliases and
checks that rejected calls preserve bytes and cursor.  It completed 214 checks
under AddressSanitizer and UndefinedBehaviorSanitizer, and the production
encoder compiled with `-Wall -Wextra -Werror`.  This is portable-state
correctness work: no host pointer, native structure, page-size, or Intel VMX
assumption is introduced.

## 2026-08-07 administration resource candidate-boundary replay

The transport-neutral administration resource manager was reviewed for the
point at which caller-owned command bytes become owned resource state.  CREATE
and MODIFY first take a private bounded copy, but previously passed the
original caller range to a type-specific validator and later published the
earlier copy.  That split could approve different bytes from those eventually
stored if a caller reused the input range while the operation was in progress.

Both operations now validate the exact private candidate that will be
published.  The callback remains under the manager mutex and retains its
documented no-reentry contract; no caller pointer is retained or serialized.
The review also found that the manager discarded a callback's policy errno and
reported every policy refusal as `EINVAL`.  CREATE and MODIFY now preserve the
callback result, so a type can distinguish malformed data from a temporary
resource refusal such as `EBUSY`; wire-status conversion remains centralized in
the administration command adapter.  The resource adapter now maps retryable
`EAGAIN`/`EBUSY` results to the standard `TRYAGAIN` qualifier instead of
mislabeling them as invalid commands.  The independent resource test verifies
that both CREATE and MODIFY receive a detached candidate rather than their
caller’s storage, that a callback `EBUSY` survives both operations, and that a
wire CREATE reports independently specified busy/try-again values.  The fresh
full resource-manager unit binary and a strict `-Wall -Wextra -Werror` build
passed.  This removes an ownership and error-domain ambiguity from the common
administration layer without changing any advertised feature or introducing
architecture-specific state.

## 2026-08-07 administration capability retry classification

The generic capability manager now classifies callback `EAGAIN` and `EBUSY`
as the standard administration `TRYAGAIN` qualifier.  Before this change,
`DRIVER_CAP_SET` preserved the error status but mislabeled retryable policy
refusals as invalid commands.  The independent wire test verifies the busy
status and qualifier, and confirms that refused values are not published.

## 2026-08-07 AF_VSOCK receive-chain follow-up

The kernel receive path was reread independently from the device-model work.
It builds preallocated mbuf chains by filling each allocated segment directly,
sets only the leading packet header length, and rejects any incomplete
allocation before publication.  Fragmented SEQPACKET payloads are joined with
`m_catpkt()`, preserving the packet-header accounting required by the socket
layer; incomplete records remain owned by the PCB until EOM or teardown.
Credit accounting includes that partial ownership and the EOM path transfers
the complete chain once to the receive socket buffer.

No additional source-level defect was found in this pass.  The existing
fragment-credit, large-record, close-race, and receive harnesses remain the
rootless evidence; installed-kernel memory-pressure and concurrent transport
qualification are still required before promoting the transport.

## 2026-08-07 nested VMX admission follow-up

The Intel nested-run admission boundary was reviewed separately from ordinary
VMX entry.  A common startup owner is consumed only on the pre-resource
software-exit branch.  Once a nested run can acquire guest MSRs, select or
enter VMCS02, activate a composed EPT root, or create an L2 event transaction,
the owner path remains fail-closed with `EOPNOTSUPP`; a partial execution edge
cannot be truthfully reported as a generic no-entry outcome.

The nested requirements validator, including its negative fixtures, completed
with 433 requirement entries, 282 private-interface entries, and 12 separately
tracked hardware-live groups.  Focused model cases for exit routing, nested
run residency selection, VM-entry pipeline handling, and instruction-ownership
transfer also passed.  This is evidence for the staged ownership model only;
it does not claim Intel hardware execution or relax the L1/L2 qualification
gate.
