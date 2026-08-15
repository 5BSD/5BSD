# bhyve VirtIO 1.4 implementation roadmap

This roadmap is ordered by deployment value and dependency, not by device ID.
The conformance source is the OASIS VirtIO 1.4 specification.  Independent
wire constants and requirement-to-test mappings live under
`tests/sys/kern/vsock_device_harness`; production headers are not test oracles.

## Current baseline (provisional)

The modern PCI transport and the existing net, block, console, entropy, SCSI,
input, socket, and 9P devices have implementations and source-level tests for
their currently advertised VirtIO 1.4 requirements.  Modern devices negotiate
64-bit features, validate cumulative status transitions, implement
notification data, and selectively implement queue reset.  Block
write-zeroes, socket STREAM/SEQPACKET feature semantics, and host AF_VSOCK
operation are included.

That is not a release sign-off.  Commits are review checkpoints, and a passing
source harness proves neither Linux interoperability nor long-run lifecycle
correctness.  In particular:

- modern virtio-net queue-pair, RSS, MSI/MSI-X, reset, and checkpoint gates
  have passed the Linux matrix.  They remain in the release and soak profiles
  because a previous EVENT_IDX control-queue defect appeared only in that
  composed live path;
- the virtio-net control callback now only publishes work to the existing TX
  worker.  That worker processes at most one queue-sized control batch before
  giving a ready data queue a turn, preserves Linux's synchronous command
  progress through EVENT_IDX arm-and-recheck continuation, and uses the same
  reset/suspend/checkpoint ownership fence as packet sends.  Lifecycle drains
  have one monotonic deadline and transactional rollback; full reset still
  performs a mandatory drain before guest iovecs can be reclaimed;
- concurrent kernel-backed VSOCK providers, duplicate-CID rejection,
  per-provider reset/feature isolation, and CID-scoped MACF ownership are
  implemented and covered by source, kernel, and two-bhyve live tests;
- sanitizer tests do not replace a reset/rebind/reboot soak.  The network RSS
  path now has a real split-ring-parser-to-production-callback test, but that
  test still cannot reproduce every backend, interrupt, and VMM scheduling
  interaction.

Until those gates pass, the affected rows in the requirements catalog must
name the pending live gate instead of citing a generic matrix as evidence.

Legacy PCI remains a compatibility path.  New devices should be modern-only
unless the specification defines a transitional identity and a concrete user
requirement justifies the additional interface.

## Implementation classification

The tree must distinguish compiled helper code from a guest-visible feature.
The current classification is:

| Scope | Classification | Default/qualification boundary |
| --- | --- | --- |
| Modern PCI split queues and existing devices | production | Release and soak profiles cover Linux and 5BSD where drivers exist |
| Packed virtqueues | production, explicit opt-in | `packed=true`; default advertisement waits for the complete split/packed live matrix |
| Balloon | production, modern-only | Inflate/deflate and portable state are present; statistics, deflate-on-OOM, free-page hinting, free-page reporting, and page poisoning are explicit opt-ins pending live qualification |
| RTC | production, modern-only | Baseline clock is present; alarms remain opt-in pending live qualification |
| GPU 2D | production, modern-only but provisional | PCI device, bounded 2D protocol engine, DMA-backed resources, portable state, exclusive renderer ownership, and an external-fbuf presentation path exist; the release lane verifies guest-written boundary pixels over raw RFB, while successful live Linux/5BSD evidence remains a release gate |
| VirtIO-IOMMU and ACCESS_PLATFORM | production, modern-only but provisional | PCI device, VIOT topology, domains, endpoint attachment, translation, faults, and portable state exist; no non-IOMMU device may advertise ACCESS_PLATFORM unless every one of its DMA paths uses the common mapper |
| Virtio-fs without DAX | production, modern-only but provisional | A modern PCI device composes the authenticated `VFSB` backend, asynchronous request queues, reset cancellation, optional portable backend-state transfer, and DTrace probes; the capability-confined read-only daemon transactionally reconstructs bounded idle or active node and handle state using one current format, while exact Linux queue activation, packed/reset operation, live active-checkpoint qualification, and longer soak remain release gates |
| Administration virtqueues/device parts | foundation only, unadvertised | Queue, group, device-parts, PCI composition, reset, suspend, and portable state are rootlessly covered; production advertisement remains gated on a concrete PF/VF owner/member topology and live Linux command execution |
| Virtio-mem | production, modern-only but provisional | PCI device, bounded PLUG/UNPLUG/STATE protocol, generic device-memory mapping, portable device and payload state, split/packed composition, and Linux qualification cases exist; live gates have not passed and 5BSD has no stock virtio-mem guest driver |
| Virtio-pmem | production, modern-only but provisional | Device 27, shared-memory region zero, split/packed request queues, event-driven durable FLUSH, reset/suspend, portable backend-bound state, Linux release/checkpoint lanes, and reset-soak composition exist; live execution, repeated restore, and correlated DTrace evidence remain gates, while stock 5BSD has no driver |
| Shared-memory regions | production infrastructure with a provisional pmem consumer | The common sealed topology, runtime fencing, portable compatibility contract, and pmem region are implemented; live Linux/checkpoint qualification remains a release gate |
| DAX, SR-IOV device groups, live migration | unadvertised/incomplete | Architecture and qualification work remains |
| Intel nested VMX | experimental, default-off qualification path | Requires both the boot-time `hw.vmm.vmx.nested=1` host gate and per-guest `x86.nested_vmx=true`; VPID/INVVPID additionally requires the loader-only `hw.vmm.vmx.nested_vpid=1` qualification gate and changes the saved capability signature; rootless architectural tests do not qualify release until Linux/KVM L1 with Linux and 5BSD L2 activation, host traces, active-L2 restore, and soak all pass |

“Production, provisional” means the device is registered and selectable, not
that it has completed the release gate.  Documentation and tests must not call
a foundation-only component implemented merely because it is present in the
bhyve build.

The hardware-only nested-VMX matrix is scheduled by the `nested`
`virtio-lab` profile.  It consumes immutable L1/L2 images and a reviewed
root-owned L1 driver, and accepts a pass only when all twelve feature groups have
distinct Linux-L2, 5BSD-L2, and host-trace evidence.  This profile remains
separate from ordinary VirtIO qualification while nested VMX is experimental
and default-off; it becomes a mandatory release constituent before that
exposure policy changes.

## P0: fleet-safe socket devices

1. Concurrent `backend=kernel` providers are indexed by guest CID.
2. Provider queues, negotiated features, reset, close, and backpressure are
   isolated by CID.  Duplicate CID attachment fails with `EADDRINUSE`.
3. Provider DTrace events include the CID and
   `kern.vsock.userspace_providers` exposes the active provider count.
4. Test two simultaneous providers with different negotiated socket types,
   bidirectional routing, reset/detach isolation, duplicate rejection, and CID
   reuse. The kernel ATF gate covers 1,024 simultaneous provider descriptors;
   `run-alpine-multi-vsock.sh` and the release profile provide the passing
   two-bhyve live gate.
5. `virtio-lab` allocates root-owned, per-CID directory leases for real-VM
   launch cases.  Generated CIDs advance as a complete allocation group when
   another lab owns the default range; explicitly requested CIDs are never
   silently remapped.  A root-owned per-run manager lease prevents concurrent
   `--resume` supervisors from racing CID cleanup.  CID leases survive an
   interrupted supervisor until its child is reattached or the host runtime
   directory is cleared, and are released only after the supervised case
   exits.  The kernel remains the
   final duplicate-CID authority for VMs launched outside this orchestration
   layer.
6. Kernel-provider attachment uses an optional-policy-safe MACF interface and
   `FI_VSOCK_PROVIDER` whole-CID claims.  The provider label pins the claim
   identity for the descriptor lifetime, later claims cannot be bypassed, and
   access is rechecked after waits and user copies.  Unit tests cover invalid
   provider scopes, endpoint/provider separation, token delegation, `exec`,
   token close, claim close, and a claim created after attachment.  Live audit
   and DTrace assertions plus reset, close, descriptor-passing, and CID-reuse
   races remain part of the two-bhyve acceptance gate.

VirtIO 1.4 defines no additional socket-device feature beyond STREAM,
SEQPACKET, and NO_IMPLIED_STREAM.  Once those and the common ring/transport
features are covered, further VSOCK work is operational: VNET/jail namespace
policy, migration behavior, per-CID rate limits, and longer concurrent-VM
soaks.

## P1: existing-device performance and lifecycle

1. **Network multiqueue, RSS, and hash reports.**  Implemented with the
   control virtqueue, queue-pair negotiation, receive steering, 20-byte
   HASH_REPORT receive headers, independent HASH_CONFIG handling, and
   per-queue reset.  Host backends retain their 10- or 12-byte base-header
   contract.  Unmodified Linux guests have passed the one-, two-, and
   eight-queue matrix, RSS control negotiation, traffic, reset/rebind, reboot,
   MSI, MSI-X, and live checkpoint/restore gates.  A composed regression sends
   Linux's exact indirect RSS chain through the real split-ring parser and
   production callback, including the EVENT_IDX decision for the following
   command.  These cases remain in the release and soak profiles so later
   common-ring changes cannot silently regress the control path.
2. **Block multiqueue.**  `VIRTIO_BLK_F_MQ`, up to eight independent request
   queues, queue-local quiesce/reset, an independent document oracle, and a
   Linux hardware-queue gate are implemented.  Modern devices also implement
   writable `VIRTIO_BLK_F_CONFIG_WCE`, retain the historical writeback reset
   default, and stabilize guest-selected writethrough writes before completion.
   The existing topology fields are already advertised and covered.
3. **SCSI multiqueue and events.**  Modern devices now expose up to eight
   independently resettable request queues with a bounded device-wide worker
   budget and an exact Linux hardware-queue oracle.  CTL now provides a
   versioned, event-driven, per-open inventory subscription with monotonic
   sequence numbers, bounded queues, an initial RESCAN barrier, and explicit
   loss reporting.  A bhyve instance advertises HOTPLUG and CHANGE only when
   that subscription succeeds; older kernels remain fail-closed.  The event
   queue preserves accepted ordering, reports gaps and saturation with
   EVENTS_MISSED, and maps CTL add, remove, and capacity-change notifications
   to the document-defined wire records.
   The recommended REPORT LUNS well-known logical unit is now accepted through
   CTL's explicit no-LUN command path; exact and malformed address forms have
   independent tests, while live Linux discovery remains a qualification gate.
   A dedicated Linux case creates, resizes, and removes a unique CTL LUN
   without issuing a guest rescan; root-only execution and equivalent 5BSD
   activation remain qualification gates.  Restore intentionally reconstructs
   the destination subscription and forces a rescan rather than serializing
   host descriptors or replaying stale source events.
4. **9P queue reset.**  Implemented with generation-fenced asynchronous
   request draining, preserving the lib9p connection and fid state while the
   old queue relinquishes every guest buffer.
5. **Packed virtqueues.**  The common engine and layout-neutral device
   interface are implemented.  Explicit modern opt-in now covers every
   existing device, indirect descriptors, event suppression, wrap counters,
   ordered asynchronous block/SCSI completion, grouped mergeable-network
   completion, queue reset, and versioned cursor state.  Parsed requests retain
   their total writable capacity, and common single/grouped completion rejects
   a used length beyond that capacity before publishing the used ring.  Default
   advertisement remains disabled until the Linux/5BSD split-versus-packed,
   checkpoint, reset, and interrupt-mode qualification lanes pass.
6. **Notification configuration data.**  Implemented for modern PCI
   independently of 32-bit notification data.  bhyve supplies the
   specification-permitted trivial queue-index identifier, while the FreeBSD
   guest reads, retains, and uses the device-provided value.  Independent
   tests cover both notification widths and the Linux block lane now requires
   negotiated bit 39 during real I/O; rebuilt-5BSD activation remains open.

## P2: isolation and migration foundations

1. **VirtIO IOMMU plus ACCESS_PLATFORM.**  A provisional modern PCI device now
   provides bounded map/unmap/probe processing, event reporting, endpoint and
   domain state, VIOT topology, portable state, and common-core DMA
   translation.  Post-initialization attaches eligible modern VirtIO
   endpoints to the configured domain and only then adds
   `VIRTIO_F_ACCESS_PLATFORM`; the modern handshake rejects `FEATURES_OK`
   unless an attached guest accepts that feature.  Balloon is excluded
   because its Linux PFN-reporting ABI deliberately bypasses the DMA API.
   The IOMMU provider itself is also excluded from translated endpoints, and
   multiple unpartitioned providers are rejected instead of forming circular
   or ambiguous DMA domains; device groups must define partition ownership
   before that restriction can be relaxed.
   Qualification must still prove every descriptor, indirect table, device
   payload, and device-specific DMA path is translated, and must exercise
   permission, partial-map, invalidation, detach, reset, checkpoint, and
   concurrent-device failures.  Advertising ACCESS_PLATFORM before that
   end-to-end gate remains forbidden.
2. **Device suspend.**  The common status state machine, queue-ownership
   fence, notification suppression, deferred configuration notification,
   failure/reset behavior, FreeBSD modern-PCI guest handshake, and checkpoint
   nesting plumbing are implemented.  Virtio-net drains without retaining a
   pthread mutex across vCPU threads; block uses a reference-counted backend
   quiesce owner shared with checkpoint pause; entropy is synchronous under
   the common device mutex.  The current balloon, GPU 2D, IOMMU, memory, and
   null-sound models also perform all queue and backend work synchronously
   under that fence; direct tests pin their no-op private lifecycle contract
   so adding an asynchronous renderer, audio backend, invalidation engine, or
   memory-hotplug worker cannot silently bypass ownership draining.  RTC has
   explicit timer suspension and checkpoint serialization.  Checkpoint pause
   still takes backend
   serialization ownership when guest suspend is already active, and its
   resume path preserves the guest owner.  Vsock now fences the userspace and
   kernel provider event sources, connection relays, listener, and timer for
   both owners and rearms only after the common queue fence opens.  Versioned
   little-endian serialization now covers modern common status/features, PCI
   transport latches, split-queue addresses and indices, device state, and
   restored suspend ownership for net, block, entropy, SCSI, console, input,
   9P, virtio-fs, userspace vsock, and kernel-backed vsock.  The 9P device
   drains accepted lib9p requests through a condition variable while
   preserving its live fid namespace.  Identity-bound virtio-fs instances use
   their authenticated backend QUIESCE/THAW protocol, close admission while
   accepted requests drain, and retain restored opaque state until the guest
   resumes; a checkpoint nested inside guest suspend never thaws the backend.
   Active external sessions
   remain deliberately non-migratable: userspace vsock requires an empty
   connection set and kernel-backed vsock uses a bounded provider FREEZE/THAW
   contract which succeeds only after its CID-scoped connections and queues
   drain.  Failed thaw remains retryable without reopening queue submission.
   Pause failures propagate to the checkpoint coordinator.  Per-device pause
   ownership makes partial walks and resume retries safe; vCPUs are not
   restarted while any backend remains paused.
   AHCI propagates flush failures and rolls back earlier ports.  Snapshot
   memory and state writes handle interruption, short I/O, and zero-progress
   EOF without a polling progress thread.
   A clean snapshot-enabled bhyve build compiles and links, although the option
   remains marked broken by the wider tree.  Live running-device
   checkpoint/restore round trips pass independently for net, RNG, block,
   SCSI, userspace vsock, kernel-backed vsock, console, input, and 9P, plus a
   combined-device VM.  Fault injection still covers pause, flush,
   metadata-finalization, and resume failures in the source harness.  Snapshot
   publication now writes generation-matched memory, kernel/device state, and
   metadata members, fsyncs them, computes canonical SHA-256 digests for all
   three members, and atomically renames a version-3 manifest.  Restore verifies
   those members before any VM or device state is published.  Because the
   format is unreleased, restore accepts only the current manifest and rejects
   earlier manifests and raw three-file layouts.
   The digests are deliberately classified as corruption and mutation
   detection, not authentication: they are unkeyed, and checkpoint files
   remain inside the trusted operator boundary.
   Device validation, device commit, and kernel-record commit now also require
   exact named-record consumption; an appended suffix is never an implicit
   extension mechanism.  The kernel ioctl rejects the userspace-only
   validation opcode before architecture dispatch.  Format evolution must use
   an explicit versioned codec, and both boundaries have independent ATF
   coverage.
   Parser, mutation, replacement, pre-publication failure, and post-rename
   directory-fsync failure cases run in the sanitizer harness.  Live round
   trips and injected device failures remain release gates.  The checkpoint
   profile contains independent cases for net, RNG,
   block, SCSI, userspace vsock, kernel vsock, console, input, 9P, and a
   combined device VM; no new device is considered checkpoint-capable merely
   because common transport state can be encoded.  Cross-release and
   cross-architecture restore remain future format-compatibility gates.
   A runtime-only common restore-incomplete latch also survives generic
   in-memory rollback: if a device cannot compensate an external backend or
   guest-memory side effect, the common layer reasserts `NEEDS_RESET` after
   restoring its status backup and refuses another snapshot operation until a
   successful full reset.  A failed mem or sound recovery reset republishes
   the latch after common reset.  Balloon backing-page transitions, network backend feature
   reconstruction, virtio-mem range reconstruction, and virtio-sound stream
   reconstruction use this fail-closed boundary.
3. **Administration virtqueues and device groups.**  Add these only with a
   concrete owner/member lifecycle such as migration or assigned-device
   management.  Unsupported commands, privilege boundaries, and resource
   limits require tests before advertisement.  An unadvertised foundation now
   implements the self-group LIST_QUERY/LIST_USE wire contract, an
   allocation-free fragmented-chain adapter, and a portable device-parts
   codec with ordering, selector, reserved-field, duplicate, and truncation
   validation.  A separate capability manager implements the capability-list,
   device-get, and driver-set commands with byte-granular Linux-compatible
   payloads and a checksummed transactional portable state record.
   The device-parts composition binds negotiated GET/SET limits to type-zero
   resource objects, keeps one global ID namespace, and serializes limit
   changes against object creation so no successful race can strand an
   out-of-range object.
   A separate group fabric provides independent supported/used command lists,
   member validation, dynamic lifecycle leases, reset, and transactional
   state for each group type.  Snapshot output is staged before publication,
   and restore locks every owner in an internal canonical order before
   validating and atomically publishing the complete group image.  This is
   still transport-neutral and unadvertised.
   A bounded queue bank now composes that fabric with preallocated
   per-queue request and response scratch space.  Distinct administration
   queues may execute concurrently while reset and restore take an exclusive
   lifecycle fence.  Its fixed-width little-endian `AQB1` envelope binds the
   queue count and both scratch capacities to the checksummed group payload;
   truncated, corrupt, differently shaped, or otherwise incompatible images
   are rejected transactionally before live state changes.
   Validation follows a dedicated parse-only path through the group fabric,
   queue bank, PCI controller, and transport binding; it never publishes a
   candidate and therefore needs no fallible compensating restore.
   Reset admission and transient group-lifecycle conflicts return the
   specification-defined `EAGAIN` status with the `TRYAGAIN` qualifier and
   have no command side effects.  Permanent group-selection failures remain
   `EINVAL`; tests verify the status and qualifier independently so a
   retryable qualifier cannot accidentally be paired with a permanent status.
   Command adapters translate host errors at the common wire boundary, and
   the dispatcher rejects private status or qualifier values so neither a
   platform-specific errno allocation nor an adapter bug can extend the
   VirtIO ABI.
   The PCI ring adapter, common-configuration fields, lifecycle fence, queue
   state, and controller-state composition are now implemented and tested,
   but production advertisement remains gated.  Comparison with the pinned
   Linux transport found that Linux initializes the administration queue by
   querying the SR-IOV group.  Attaching the existing self-group controller
   to an ordinary emulated virtio-net device would therefore negotiate the
   feature and then reject Linux's first command.  The next production step
   is a concrete PF/VF owner whose PCI SR-IOV lifecycle, membership, reset,
   and device-parts callbacks are real; a synthetic network-device opt-in is
   explicitly not an acceptable shortcut.
   A transport-neutral SR-IOV lifecycle fence now models capability presence,
   VF Enable, NumVFs, and VF Migration Capable.  Administration commands hold
   a shared lease from group revalidation through completion; PCI lifecycle
   writers take the exclusive side, so membership cannot change underneath a
   command and no polling loop is required.  The fence deliberately does not
   duplicate PCI-owned state in a common snapshot.
   Reset-time assumed-command semantics, LIST_USE command disabling, and
   immediate legal-list enforcement have independent tests.  Group-fabric
   teardown takes exclusive lifecycle ownership through complete command end
   callbacks, so returning from a handler cannot race owner or lock
   destruction.
   VirtIO 1.4 defines device-parts commands only for
   the SR-IOV group, so the handling commands, an actual PF/VF owner-member
   model, and PCI administration-virtqueue composition remain prerequisites
   rather than being simulated through the self group.  The PCI composition
   boundary validates ordinary/admin queue ranges in the wide caller domain
   before narrowing them to the common-configuration fields, including the
   exact 65536-queue namespace limit; no guest-visible field or feature is
   exposed until the owner/member composition exists.
4. **Shared-memory regions.**  The transport foundation now has an
   initialization-only PCI capability builder for the exact 24-byte cap64
   layout.  It validates memory-BAR containment without overflow and reserves
   each 8-bit region ID exactly once.  Legally overlapping aliases must map
   the same bytes and access policy, and an unbound alias cannot shadow a
   later bound alias merely because its region ID sorts first.  The registry
   is destination policy,
   not mutable guest state, so it is reconstructed from device configuration
   and is not serialized in the modern register record.  Virtio-pmem is the
   first production consumer and reconstructs its destination-local file
   mapping from configuration rather than checkpoint bytes.  The rendererless
   GPU deliberately exposes no host-visible region: its GUEST blobs remain
   ordinary guest-memory backing.  Virtio-fs DAX and future consumers still
   require their own mapping lifetime, revocation, backend identity, and
   restore contracts before exposing a region.

SR-IOV is not useful for a purely emulated bhyve device and should remain
unadvertised.  ORDER_PLATFORM is not applicable while device and driver share
the guest CPU memory-ordering model.

Common request ownership is now explicit for both ring layouts.  Every
successful direct or indirect descriptor acquisition returns one outstanding
token and, when ACCESS_PLATFORM is active, holds exactly one DMA-domain lease
until completion, rollback, or reset cancellation.  Because an asynchronous
backend can copy a token, authoritative ownership is held in the queue: split
rings key it by descriptor head and packed rings by head plus wrap.  Completion
and rollback consume that owner once; duplicate backend action sets
NEEDS_RESET without rewinding a packed cursor, publishing a second used entry,
or releasing a lease twice.  Reset owners use a separate discard operation
which releases DMA ownership without making stale guest descriptors visible.
The block cancellation paths use this contract, including stale-generation
and no-callback cancellation cases.  A request records its acquisition layout
so a packed callback remains attributable after reset returns the queue
configuration to split format.  Reset discards reorder-only completions but
preserves live packed owner slots until the late callback retires them.
Balloon checkpoint pause instead completes its retained statistics descriptor
before save, allowing the guest to submit a fresh descriptor after restore.
DMA-domain detachment is rejected while any request lease remains active, so a
late generation-fenced completion cannot call through a detached IOMMU
backend.

DMA which is not naturally enclosed by a descriptor request uses the same
architecture-neutral lease contract.  Initial split/packed ring mapping holds
a lease while it validates and translates all ring structures.  Domain detach
therefore cannot clear a provider callback,
argument, or endpoint while a vCPU is inside one of those paths.  The
sanitizer harness covers duplicate acquisition, idempotent release, detach
rejection, queue-enable bracketing, provider-acquire failure, and aperture
error paths.  Every future shared-memory or device-private DMA consumer must
use this contract and add the corresponding live IOMMU trace evidence.

## P3: modern devices, in implementation order

1. **Traditional memory balloon (device 5).**  The modern inflate/deflate
   baseline, actual/desired page accounting, native-page aggregation,
   deferred-discard cancellation, packed queues, and portable checkpoint
   state are implemented.  The checkpoint record preserves exact guest PFN
   ownership and reapplies complete host-page discards before publishing
   restored accounting; obsolete record versions are rejected.
   The statistics queue is now an explicit `stats_interval=N` opt-in with an
   single bhyve event-loop refresh timer, one retained split/packed
   descriptor, allocation-free parsing, and DTrace/debug observability.  The
   event-loop timer prevents periodic callback threads from accumulating
   behind lifecycle locks.  Checkpoint pause
   completes the retained descriptor before writing versioned state, so
   restore never fabricates queue ownership from a copied token; only the
   current state version is accepted.  Linux split, packed, and
   active-checkpoint cases are scheduled.  Each checkpoint round records the
   current host-consumed statistics count and requires a strictly newer
   sample after restore, so boot-time log output cannot satisfy the
   active-state gate; default advertisement waits for those live gates.
   The 5BSD guest driver now implements the device-driven statistics queue
   without polling: it primes one readable 30-byte buffer containing a stable
   SWAP_IN/MEMFREE/MEMTOT subset, satisfying both the ten-byte entry layout
   and CS01's six-byte buffer-size multiple, refreshes that buffer only after
   the host returns it, and encodes fields in transport byte order.  A separate release case
   requires `StatsVq` negotiation plus host sample and refresh traces; that
   live gate remains pending until a guest image containing the rebuilt
   driver is supplied.
   Deflate-on-OOM, free-page hinting, free-page reporting, and page poisoning are separate
   explicit opt-ins with independent Linux activation cases.  The complete
   16-byte VirtIO 1.4 configuration is exposed; poison_val is writable only
   before DRIVER_OK and is preserved by version 6 checkpoint state. Reporting uses an
   architecture-neutral reverse-RAM contract, validates writable-only report
   chains, leaves queue 3 at size zero unless hinting is enabled,
   discards only aligned guest RAM when poisoning is absent, and serializes no
   transient report ownership.  When poisoning is negotiated, reporting
   acknowledges without discarding so the host does not replace the mandated
   poison pattern.  A fresh lifecycle and portability review traced PFN
   ownership through host-operation failure, reset, selective statistics
   queue reset, guest suspend, checkpoint validation, transactional restore,
   and repeated restore.  No unresolved medium or high implementation defect
   remained; the outstanding balloon work is live activation evidence and
   optional guest-driver functionality listed below.  Free-page hinting uses
   a versioned command-state handshake, ignores stale IDs, stops on host
   memory-boundary failure, and is now scheduled in split and packed Linux
   lanes.
2. **File system (device 26).**  The modern PCI device implements
   non-DAX virtio-fs over the authenticated `VFSB` backend.  The production
   read-only daemon preopens its export and socket, enters capability mode,
   authenticates its peer, bounds nodes, handles, messages, in-flight work,
   pending bytes, and workers.  Its sole version-2 little-endian state format
   represents both idle sessions and a bounded object graph for live nodes
   and handles; obsolete version-1 records are rejected.  Restore preserves exact guest-visible identifiers, reopens every
   relative object beneath the destination export, validates regular-file
   type and size, and publishes both tables only after complete preparation.
   Open handles survive a prior FUSE FORGET without serializing a descriptor.
   Live Linux qualification of active-object checkpoint and repeated restore
   remains a release gate.
   DAX waits for shared-memory-region support.
   The protocol boundary validates the 40-byte base configuration and the
   feature-gated 44-byte notification configuration, UTF-8 tag, both FUSE
   byte orders, replacement INIT, exact bounded framing, high-priority
   request classification, no-reply operations, and backend responses.
   A fixed-width little-endian `VFSB` backend codec now also provides bounded
   version/limit negotiation, correlated lifecycle controls, and reconnect
   incarnations.  Authenticated, nonblocking Unix `SOCK_SEQPACKET` framing
   rejects truncation and descriptor passing.  Fixed-capacity concurrent
   request ownership and the portable freeze-gated `VFS1` state codec are
   independently tested.  The retained queue engine owns fragmented guest
   chains through asynchronous completion and keeps guest reset distinct from
   terminal backend disconnect, so the same authenticated backend can accept
   a fresh FUSE INIT after reset.  Cancellation races and full-reset late
   replies are bounded by an incarnation-fenced FIFO retirement index;
   selective sent-request reset publishes one high-priority CANCEL at a time
   and advances from acknowledgements without polling.  The PCI composition
   connects asynchronous reset completion before advertising ring reset and
   integrates readiness callbacks with bhyve's event loop.  An optional stable
   backend identity enables snapshot callbacks only after the peer explicitly
   negotiates freeze plus state transfer.  Event-driven QUIESCE returns one
   bounded opaque backend-state record, THAW imports it, control request IDs
   are disjoint from FUSE ownership, and a bounded monotonic condition wait
   replaces polling.  Restore checks the exact destination identity and
   negotiated resource contract before publication.  The sandboxed production
   read-only daemon implements the non-transferable contract with
   descriptor-relative socket and export confinement, narrowed Capsicum
   rights, bounded concurrent execution, cancellation rollback, and
   transactional INIT/DESTROY lifetime.  A teardown review found and fixed a
   distinct sent-request ownership gap: connection destruction now uses the
   unconditional terminal disconnect drain instead of the ordinary reset
   operation, which can legitimately return `EBUSY` for a request already
   consumed by the backend.  The drain returns every retained guest chain
   exactly once before its pending table is freed, with sanitizer coverage for
   the sent-request case.  Rootless protocol, lifecycle,
   Werror, and sanitizer gates pass.  Split and packed Linux
   mount/reset/checkpoint lanes plus an eight-queue packed reset soak are
   scheduled; live results for both transferable idle state and rejected
   active state remain release gates, so this registered device is not yet
   release-qualified.
3. **GPU (device 16).**  A provisional modern PCI device now implements a
   bounded 2D command engine, resources/backing, scanout and cursor queues,
   ACCESS_PLATFORM-aware backing reads, reset, packed opt-in, and portable
   state.  The 5BSD guest driver is now an amd64-loadable module and its
   control path is bounded and interrupt-driven: commands begin only after
   DRIVER_OK, stack-backed descriptors are reset and drained on timeout or
   detach, physical scatter/gather segments are counted correctly, fenced
   responses are correlated, and device-provided scanout geometry and
   transfer rectangles are overflow/bounds checked.  The release lab includes
   a packed 5BSD lane that requires the complete six-command framebuffer
   activation sequence; a rebuilt guest image still must supply live evidence.
   Host display integration and live Linux/5BSD tests remain required before
   release.  VIRGL remains unadvertised.  Guest-memory blob resources are
   available only behind the provisional `blob=true` option and remain
   disabled by default.  The device intentionally advertises no host-visible
   shared-memory region: MAP_BLOB is defined for host-only blobs and those
   memory types require a renderer that this 2D device does not provide.  The
   transport-neutral blob foundation now decodes CREATE, SET_SCANOUT_BLOB,
   MAP, and UNMAP, owns
   bounded guest-memory blobs and saves versioned pointer-free blob,
   scanout-layout, and retained-pixel
   state.  Only version 3 is accepted; obsolete version-1 2D and version-2
   inactive-blob records are rejected.  Version 3 is required because Linux's upstream DRM driver
   uses SET_SCANOUT_BLOB for dumb buffers; the command imports the complete
   single-plane backing transactionally and flush refreshes changed rows.
   Linux also creates hardware cursor buffers as guest/shareable blobs, so
   UPDATE_CURSOR imports that fixed 64-by-64 B8G8R8A8 view transactionally.
   The state codec preserves an active blob cursor and rejects incompatible
   simultaneous cursor and scanout interpretations of one resource.
   Host-only/default blobs still require rendering-context semantics
   negotiated by VIRGL and remain rejected.  The feature and shared-memory
   capability remain explicit opt-ins until Linux reset and active-checkpoint
   qualification passes.
4. **Memory (device 24) and PMEM (device 27).**  The provisional memory device
   has VM-map, bounded protocol, portable payload-state, and Linux
   qualification foundations; its remaining live and 5BSD gates are tracked
   below.  PMEM is now a selectable modern-only PCI device.  When feature zero
   is negotiated it publishes its exact exclusively locked regular-file mapping
   through shared-memory region zero and emits the canonical all-zero device
   configuration; drivers that decline the optional feature receive the same
   range through the physical-address configuration fallback.  Its split or
   packed request queue accepts fragmented and zero-length descriptor segments,
   retains only the exact response storage,
   and returns the specification's literal zero or minus one.

   One condition-variable worker owns requests in FIFO order, performs
   `msync(MS_SYNC)` plus `fsync`, retains ledger ownership through used-ring
   publication, and uses bounded monotonic reset, suspend, and checkpoint
   drains.  Snapshot state contains only fixed-width little-endian magic,
   version, exact size, and stable operator identity.  Direct callback tests
   cover every truncation boundary and mismatch; Linux split/packed lanes
   verify exact host bytes after reset and active-I/O checkpoint, and
   automatically reject changed identity or capacity before two independent
   accepted restores of the same checkpoint.  Live execution and
   DTrace-correlated lifecycle flush evidence remain promotion gates.  Stock
   5BSD has no VirtIO PMEM
   driver, so no cross-guest pass is claimed.
5. **Sound (device 25).**  The modern four-queue baseline now provides two
   bounded PCM streams, a deterministic null backend, nonblocking
   readiness-driven OSS playback/capture, split/packed queues, lifecycle and
   release ordering, selective reset, suspend, and portable backend-bound
   state.  A callback-lifetime review fixed partial-init teardown so every
   OSS mevent is synchronously retired before its embedded callback argument,
   audio descriptor, or softc can be destroyed.  Production OSS live
   qualification, underrun/overrun injection, repeated active checkpoint,
   rate conversion, controls, channel maps, and a 5BSD guest driver remain
   open.
6. **Crypto (device 20).**  Implement only algorithms backed by a reviewed
   kernel or userspace crypto provider.  Bound session counts and request
   sizes, zero key material, reject overlapping buffers, and never advertise
   an algorithm whose full error semantics are not implemented.
7. **RTC (device 17).**  The modern request-queue baseline and opt-in alarm
   feature are implemented with one `UTC_MAYBE_SMEARED` clock,
   packed/split request and alarm queues, event-driven deadlines, suspend
   rescheduling, missed-alarm delivery, and portable cross-version `RTC1`
   state.  The Linux checkpoint worker now holds an armed alarm and RTC
   descriptor across both live checkpoint and suspend/restore, and requires
   the restored `AF|IRQF` notification.  The rebuilt-5BSD driver now
   negotiates ALARM, posts a validated interrupt-driven notification buffer,
   serializes absolute-deadline control, and has distinct split/packed live
   gates which must observe a real alarm before disabling it.  Live execution
   of those gates remains required before enabling alarms by default.

RPMB, I2C, SCMI, GPIO, CAN, SPI, and media devices need a real host backend or
passthrough use case before implementation.  Stub devices that merely satisfy
driver probing are out of scope.

## Release-closure inventory

The following is the explicit unfinished release inventory.  An item remains
open until its requirement rows, scheduled Linux and 5BSD activation cases,
host-path evidence, negative tests, lifecycle tests, and documentation are
complete.  A missing stock guest driver is recorded as a guest-driver gap; it
does not turn a host implementation or feature negotiation into cross-guest
qualification.

### Definition-of-done matrix

The following matrix is normative for this project plan.  It is intentionally
redundant with the detailed device notes below: a feature cannot disappear
from the release gate merely because its implementation is discussed in
another section.

| Scope | Required proof before release |
| --- | --- |
| Every supported queue | Split and packed operation; direct and indirect descriptors; event and interrupt suppression; NOTIFICATION_DATA; selective queue reset; wrap boundaries; malformed and looping chains; MSI and MSI-X; save/restore at significant producer, consumer, and wrap states |
| Every advertised multiqueue feature | Linux and 5BSD must negotiate more than one queue and the host trace must show useful notifications and completions on every advertised queue; merely allocating queues is not activation |
| Every advertised device feature | An independent specification fixture, negative and boundary tests, and an unmodified live guest must prove that exact feature bit causes its required behavior; probing the PCI ID is insufficient |
| ACCESS_PLATFORM | Every descriptor table, indirect table, payload, device-private DMA access, reset path, and late completion must use translated DMA; direct-versus-translated differential tests and IOMMU fault evidence are required |
| Shared-memory regions | Device-specific mapping, unmapping, overlap, revocation, backend identity, suspend, reset, and portable-state policy must be complete; a capability plus an anonymous byte array is not a usable feature |
| Checkpoint and migration | Active I/O, failed quiesce rollback, repeated restore, backend identity changes, feature/topology mismatch, truncated/unknown state, and cross-version fixtures must pass without serializing pointers, descriptors, locks, or host-native structures |
| Portable common code | Fixed-width little-endian state, bounded arithmetic, explicit page-size contracts, and architecture-specific CPU state isolation; tests must include synthetic endian, word-size, alignment, and page-size variations |
| Operational behavior | Event-driven progress, bounded resources and waits, rate-limited diagnostics, DTrace evidence for meaningful transitions, deterministic cancellation, and no stale callback after reset, detach, or restore |

For devices whose stock 5BSD driver lacks a feature, the plan must retain a
named guest-driver task and a live activation gate.  A Linux pass may qualify
Linux interoperability, but it cannot be relabeled as cross-guest coverage.

### Common infrastructure

- Qualify every supported device with split and packed queues, including
  indirect chains, event suppression, NOTIFICATION_DATA, selective queue
  reset, wrap boundaries, malformed and looping chains, MSI and MSI-X, and
  checkpoints at significant cursor/wrap states.

  The release profile now includes a dedicated NOTIFICATION_DATA activation
  case which correlates Linux negotiation and I/O with the host's decoded
  queue and nonzero available-index payload.  Cross-device and 5BSD evidence
  remain open.
- Finish the architecture-neutral DMA interface and prove that every
  ACCESS_PLATFORM descriptor, indirect table, payload, and device-specific
  access is translated.
- Complete VirtIO-IOMMU endpoint attach/detach, map/unmap, permissions,
  invalidation, fault reporting, concurrency, and restore qualification.
  PCI topology discovery now treats every VirtIO-IOMMU function as a fabric
  provider even though providers are themselves ineligible for
  `ACCESS_PLATFORM`, rejects ambiguous multiple-provider configurations until
  device-group partitioning exists, and publishes requester IDs and endpoint
  lists only after the complete topology validates.  Failed post-init
  discovery therefore cannot leave a partially constructed DMA binding.
- Finish shared-memory consumers and mapping lifetime, device suspend/resume,
  administration virtqueues and device groups, and restore/migration feature
  compatibility manifests.  Restore now validates an exact, duplicate-free
  device-section topology and, for new snapshots, preflights every VirtIO
  device's transport, queue/MSI-X/configuration shape, shared-memory layout,
  offered contract, negotiated features, and private payload before any
  device publishes restored state.  Fabric validation constructs a temporary
  incoming VirtIO-IOMMU mapping view first, so ACCESS_PLATFORM endpoint ring
  addresses are checked through their saved translations rather than the old
  destination fabric.  A fixed-width little-endian envelope binds those
  requirements to the device payload instead of trusting editable metadata.
  Restore also proves that all named kernel and device records are nonempty
  and form one exact, gap-free, nonoverlapping partition of the complete state
  member before guest RAM is copied.
  Saved guest-memory allocation flags are now validated against the complete
  supported mask and preserved through restore memory setup; previously they
  were parsed and then silently overwritten by destination defaults.
  The common libvmmapi memory constructor now resolves an existing kernel
  memory segment before reserving host address space and checks domain sums,
  the low/high-memory hole, guard regions, guest-physical span, and the
  destination host span before any mapping.  Its pure tests model both native
  and synthetic 32-bit hosts.  A separate architecture-neutral checkpoint
  validator now requires saved NUMA sizes and vCPU membership to form exact
  memory and CPU partitions, without treating destination-local host NUMA
  allocation policy as guest state.  New metadata encodes that complete
  identity canonically with an explicit schema, restores it transactionally
  before guest memory allocation and ACPI affinity publication, and rejects
  absent, partial, noncanonical, unknown-schema, or mismatched tuples.  Live
  multi-domain checkpoint/restore remains the qualification gate.
  Callback-backed shared-memory BAR reads are now width-normalized by the
  transport, matching direct backings and preventing a device callback from
  leaking nonarchitectural high bits through a narrow MMIO access.
  Modern and transitional device-configuration callbacks are normalized at
  the same boundary, so a narrow guest read cannot expose callback bits above
  its PCI access width.
  The embedded compatibility codec also rejects any source whose negotiated
  feature mask is not a subset of its own offered mask.  A destination
  feature superset cannot legitimize a source negotiation that was impossible,
  even when metadata, payload CRC, and the outer manifest were all rewritten
  consistently.
  The sole current checkpoint format also preserves sockets/cores/threads and
  validates their exact vCPU product before affinity maps or VM creation;
  count-only metadata is rejected.  The current format also binds
  the guest memory granule and exact low-memory/high-memory GPA geometry before
  destination allocation; partial tuples, unaligned or overflowing extents,
  and changed destination geometry fail before state publication; an absent
  tuple is invalid.
  New checkpoints now carry a canonical, architecture-tagged CPU contract.
  On amd64 it is obtained from the kernel's actual guest CPUID policy rather
  than host userspace CPUID, canonicalizes execution-state-dependent leaves,
  virtualizes both Intel topology leaves 0x0b and 0x1f from the configured
  guest topology, and binds XSAVE limits, configured x2APIC mode, TSC
  frequency, and the exact
  nested-VMX capability and VMCS-schema signatures when nested VMX is enabled.
  Restore compares the complete contract before vCPU execution.  The current
  policy is deliberately exact-match; named migratable CPU models and
  explicit TSC scaling can relax it later without silently weakening existing
  images.  Live same-host restore and changed-policy rejection remain
  qualification gates.  The current format also
  carry an order-independent whole-machine topology seal over device/BDF
  identity and every immutable VirtIO transport, queue, MSI-X, configuration,
  and shared-memory shape; restore reconstructs and checks both source and
  destination seals before device-state validation.  Live changed-topology
  rejection, no-fail or compensating commit contracts for every external
  backend, and cross-version migration policy remain.
- Exercise portable state fixtures across endian, word-size, page-size, and
  architecture boundaries; common code may not acquire x86-only assumptions.

### Existing devices

- **Network:** Linux and 5BSD packed operation; real work and nonzero host
  notifications/completions on every negotiated queue; RSS and HASH_REPORT
  negative paths; queue-local reset under traffic; repeated active restore;
  concurrent reset/traffic soak; translated-DMA qualification.
- **Block:** the 5BSD driver now negotiates and allocates multiple request
  queues, distributes ordinary I/O across them, preserves ordered-I/O and
  dump semantics across the queue set, and exposes the active count.  The
  scheduled every-queue live proof remains pending.  Packed Linux/5BSD
  operation; discard; write-zeroes boundaries and failures;
  optional secure erase only if its full backend contract is implemented;
  WCE transitions; active restore; backend identity/replacement rejection;
  translated DMA.

  The Linux release lane now performs actual WRITE ZEROES and DISCARD
  requests against separate patterned ranges, validates queue limits and the
  whole-device digest, and verifies persistence after reboot.  Its discard
  zero-readback assertion is deliberately limited to the sparse-file test
  backend, and a dedicated case requires this backend-dependent feature so
  ordinary block cases remain portable.  CONFIG_WCE is transitioned in both directions with sysfs
  readback after every change.  The rootless verifier is green; the updated
  live lane must still run on the installed bhyve before these become release
  results.  A separate read-only lane requires successful reads, rejected
  writes, absence of media-modifying features, and the same result after
  reset.  The scheduled 5BSD common lane now also attaches a uniquely sized
  disposable read-only disk, requires the stock driver to negotiate
  `ReadOnly`, verifies its full host-side digest, rejects a write, and
  re-verifies the digest without relying on disk enumeration order.  It also
  requires the stock driver to negotiate `ConfigWCE`, changes the root device
  through writethrough and writeback with synchronous I/O in each mode,
  restores the original setting, and correlates both configuration writes
  with the host device.  The
  `fivebsd-block-modern-q2` case requires two active queues,
  concurrent CPU-pinned root-disk I/O, and a host notification on each queue;
  it remains a live gate rather than a claimed pass.  Queue-local reset,
  ACCESS_PLATFORM, and repeated active-I/O restore remain open.
- **SCSI:** the 5BSD driver now allocates a CPU- and device-bounded request
  queue set, selects only queues with enough descriptors for the actual
  command, and exposes the active count.  The scheduled CTL-backed
  every-queue data-integrity proof now also requires an observed REPORT LUNS
  command and binds subsequent READ/WRITE(10) traffic to the exact
  dynamically allocated CTL LUN; its live result remains pending.  The host
  now implements asynchronous HOTPLUG/CHANGE delivery with loss-aware
  EVENTS_MISSED and a Linux no-rescan activation case.  Remaining work is
  live malformed-event injection after the 5BSD guest's used-length
  validation and recoverable requeue/reset paths were added;
  packed Linux/5BSD operation; execution of the now-scheduled 5BSD event
  activation lane; concurrent LUN add/remove/change races and saturation;
  live active-command checkpoint qualification; live repeated-subscription
  reconstruction; and translated DMA.  The host-side active-command policy is
  complete: a common admission fence lets consumed commands drain normally
  under one monotonic device-wide deadline, and any later-queue failure rolls
  back every earlier queue acquisition without changing the running source.
  Rootless repeated-restore coverage also proves that destination-local CTL
  sequence state is discarded on every restore and a fresh loss-aware rescan
  boundary is delivered instead of replaying stale LUN events.
- **Console:** the scheduled Linux release case now discovers two named ports
  on one device and performs two independent close/reopen bidirectional
  exchanges on each port, while the
  state codec independently covers every port and rejects a changed secondary
  listener identity atomically.  A per-port `console=true` setting now makes
  the standard `CONSOLE_PORT` lifecycle reachable from production
  configuration (including multiple nominated ports), rather than leaving
  the existing control-message code test-only.  The portable state validator
  rejects disabled-port state and impossible announcement, guest-ready,
  naming, and console-notification relationships before publishing any
  restored port.  Its split and packed checkpoint lanes now
  hold a live host session, require portable checkpoint rejection, prove
  bidirectional traffic on the same connection after rollback, drain it, and
  then save listener-only state.  Live completion remains pending.  Selective
  receive-queue reset now publishes a cleared readiness latch under the
  VirtIO mutex and requests disable of the corresponding host read source
  through the generic port-backend boundary, while leaving every other port
  active.  A callback selected before the asynchronous event update rechecks
  that latch before descriptor or host-byte access; a later guest kick
  explicitly rearms the replacement queue.  Receive and transmit callbacks
  selected for a closed connection are also fenced by the immutable mevent
  descriptor, preventing a stale callback from operating on a newer session
  stored in the same port object.
  The rebuilt-5BSD split lane activates one named port, while its packed
  common-lifecycle lane activates two independently named ports and performs
  a complete host-to-guest and guest-to-host exchange on each exact devfs
  alias. This makes both packed operation and multiport support depend on real
  data rather than attachment alone; live promotion still requires the
  rebuilt guest run.
  The rebuilt guest now rejects short and oversized control completions and
  converts event-buffer requeue failure into a stopped-device state rather
  than an assertion.  Remaining work is live malformed-control injection,
  simultaneous host/guest close qualification, live blocked-I/O
  reset qualification, packed 5BSD activation, and a production reconnect
  policy beyond the now-tested sequential reconnect behavior.
- **9P:** the export root now carries sticky `O_RESOLVE_BENEATH` semantics,
  so all relative lib9p lookups inherit a kernel-enforced subtree boundary;
  a negative test proves an intermediate symlink cannot escape while an
  ordinary in-export lookup still succeeds.  The backend also rejects
  separators, empty names, and dot elements in create/link/rename/unlink
  components, and FIFO creation, Unix-socket binding, legacy truncation, and
  symlink metadata lookup are now descriptor-relative instead of depending
  on bhyve's process working directory.  The rebuilt-FreeBSD guest transport
  now finalizes features and waits for `DRIVER_OK` before publication, claims
  mount tags atomically, records exact used lengths, validates response
  framing, encodes every scalar explicitly little-endian, and resets/drains
  an incomplete descriptor before returning caller-owned buffers.  Distinct
  split and packed live lanes mount a private export twice and prove
  bidirectional visibility; execution with the rebuilt guest remains pending.
  Remaining work is live
  intermediate-symlink qualification, authentication-policy review, active
  fid portability (currently rejected), reset during
  live requests, and fid/reconnect soak.
- **Input:** split and packed Linux checkpoint lanes now stage a key-down
  event without `SYN_REPORT`, save that incomplete frame, append the tail only
  after online checkpoint or restore, and require the same guest verifier PID
  to observe the exact frame and return LED status.  Live execution remains
  pending.  Event-queue and full-device reset now synchronously drain
  already-readable evdev input under the device mutex, closing the
  fast-reenable window in which pre-reset input could otherwise reach a new
  queue incarnation; a focused test performs that exact ordering.  Host
  `SYN_DROPPED` is now a first-class loss boundary: already staged and
  subsequent stale events are discarded through `SYN_REPORT`, while the
  minimal loss-marker frame is delivered so the guest queries current state.
  The sole accepted snapshot version 2 preserves and validates an in-progress
  resynchronization; obsolete version 1 images are rejected.  VirtIO 1.4 defines
  this capability table as driver-selected query data and defines no
  input-specific feature or command for replacing it dynamically.  The evdev
  pass-through backend is identity-bound and its advertised capabilities are
  fixed for the device lifetime; a synthetic configuration-change
  notification without a normative backend transition is deliberately not a
  release gate.  Remaining work is live reset during injection and
  cross-guest packed activation; oversized frames and descriptor shortage
  already have explicit whole-frame drop tests.
  The split release topology covers the single-device baseline and the packed
  topology creates two distinct uinput providers and modern PCI functions and
  runs the complete guest event/host status exchange independently on each;
  live execution remains pending.
- **RNG:** packed Linux/5BSD activation and reset/rebind and source-failure
  soak.  Its private configuration size is zero and checkpointing delegates
  only to the common queue codec, so entropy bytes and host-source state are
  never serialized or replayed.  The scheduled Linux checkpoint case keeps
  one raw `/dev/hwrng` reader alive and requires the same PID and a durable
  progress counter to advance across online checkpoint and restore.  Startup
  and request reads retry signal interruption; EOF, transient source failure,
  and unexpected source loss fail closed with `DEVICE_NEEDS_RESET` and never
  publish fabricated or stale entropy.  The rebuilt-FreeBSD driver also
  propagates initial and replacement request-publication failures instead of
  asserting: initial failure unwinds attach, while a later failure disables
  the source and lets detach reset and drain the DMA buffer.  Live fault
  injection must still prove those guest paths.  Device-supplied completion
  lengths are now also checked against the exact posted DMA capacity before
  copying, rather than only against the random subsystem caller's requested
  size.
- **5BSD balloon guest:** synchronous inflate and deflate completion is now
  bounded and detach-cancelable.  Queue publication and wrong-cookie failures
  are propagated instead of asserted, and ambiguous ownership forces a full
  reset before any page is returned to the VM.  Rebuilt-guest fault injection
  must still prove a withheld completion cannot hang detach and that reset
  releases all host tracking before page reuse.
- **Vsock:** scheduled split and packed cases now cover both userspace and
  kernel backends, hold a live connection, require checkpoint rejection,
  prove post-rollback traffic on that same connection, drain it, and then
  perform the portable idle-backend restore.  Live reruns remain pending.
  The socket core now applies its global connection ceiling to inbound,
  outbound, and two-PCB loopback creation and adds a tunable per-remote-CID
  ceiling (`kern.vsock.max_connections_per_cid`, default 1024, zero for
  unlimited).  CONNECTING sockets consume the budget and teardown immediately
  reclaims it, preventing one guest from exhausting the fleet-wide table.
  Remaining work is active connection migration/reconstruction if a portable
  protocol is later defined, multiple-provider checkpoint, jail/VNET policy,
  per-CID byte/queue accounting beyond the connection ceiling, longer
  concurrent-VM soak, and packed cross-guest activation.

### New and provisional devices

- **Balloon:** live qualification of statistics, deflate-on-OOM, free-page
  hinting, reporting, and page poisoning; pressure/OOM
  recovery, invalid/duplicate PFNs, active restore, and Linux/5BSD activation.
  Duplicate inflate and deflate PFNs are now explicitly idempotent in the
  host-page tracker and cannot replay a native discard/undiscard side effect;
  the production callback has direct negative coverage for a mixed duplicate,
  out-of-range, and valid PFN request, including exact accepted/rejected
  accounting and host-side effect counts.  Malformed PFNs are a device-model
  negative test rather than a stock-driver activation requirement.  Free-page
  hint command association is also enforced per chain: page-only Linux
  buffers may inherit the active round, but writable ranges combined with a
  stale command are ignored and have a direct no-discard regression.
  The rebuilt 5BSD driver now negotiates DEFLATE_ON_OOM and registers a
  detach-safe `vm_lowmem` handler.  That callback only coalesces
  `VM_LOW_PAGES`; the worker returns at most one bounded request and waits one
  low-memory interval before target-driven reinflation.  Its dedicated live
  lane uses the kernel's supported low-memory test event and requires both
  guest page-count movement and a successful host deflate trace.
  The release matrix now keeps free-page discard and poison preservation in
  separate Linux cases.  A reporting-only case requires the host discard
  trace, while a reporting-plus-poison case requires the preservation trace;
  enabling PAGE_POISON can no longer satisfy both activation claims by
  bypassing the discard branch.
  The 5BSD statistics queue and its independent live activation lane are now
  implemented.  The rebuilt driver also accepts PAGE_POISON when offered,
  publishes a zero poison value before DRIVER_OK, and zeroes every
  successfully deflated page before returning it to the VM allocator.  Its
  dedicated live lane combines low-memory deflation with negotiated-feature,
  page-count, saturating poisoned-page-counter, and host configuration-trace
  evidence.  Remaining 5BSD optional-feature work is free-page hinting and
  reporting, sustained real-pressure behavior, and active restore.
  PAGE_POISON is implemented as an explicit opt-in with the complete 16-byte
  configuration layout.  The guest may select `poison_val` only before
  DRIVER_OK, reset clears it, versioned state preserves it, and free-page
  reports are acknowledged without host discard while poisoning is active so
  the device cannot destroy the guest's mandated poison contents.
- **GPU 2D:** resource/backing/scanout/EDID/cursor/rectangle coverage,
  malformed commands, saturation, reset, active restore, Linux and
  rebuilt-image 5BSD live evidence, and ACCESS_PLATFORM.  Production display
  integration is implemented and the release lane now verifies two
  guest-written scanline-boundary pixels through the raw RFB consumer; that
  live lane still has to pass before promotion.
  The 5BSD driver/module and its split/packed activation lane now exist; that
  lane deliberately remains pending until it runs inside the updated guest.
- **Input:** the host device already has split/packed Linux qualification,
  reset recovery, active-frame checkpoint coverage, multiple providers, and
  bounded soak coverage.  A rebuilt-5BSD evdev frontend and independent
  split/packed lanes now add real device-to-guest key/relative/absolute data
  and guest-to-device LED status for two independently named devices.  Live
  promotion requires an updated guest image; selective queue reset with
  blocked clients and active-event checkpoint remain open cross-guest gates.
  The input configuration structure is a driver-selected capability-query
  window and the VirtIO 1.4 input chapter defines no dynamic replacement
  command or input-specific configuration-change notification, so that
  previously listed item is not an implementable protocol feature.
- **Virtio-fs:** complete live Linux split/packed queue activation, reset,
  reconnect, saturation, active checkpoint, repeated restore, and soak
  qualification, and add a 5BSD driver when cross-guest qualification is
  required.  The capability-confined read-only daemon retains its versioned
  current idle record and transactionally transfers active relative node and handle
  identities without serializing descriptors; the provisional modern PCI
  composition, asynchronous
  cancellation/reset, authenticated backend transport, explicit optional
  freeze/state-transfer protocol, and portable device-side state already
  exist.  DAX remains blocked on shared memory.
- **Virtio-mem:** Linux plug/unplug under busy and partial conditions,
  alignment/capacity and changed-destination checks, active restore, packed
  queues, and a 5BSD driver with activation proof.  A device-specific DTrace
  probe now records the exact request type, address, block count, and
  response or host-side failure for every structurally valid request, so live
  activation and soak can distinguish actual plug/unplug/state work from
  driver attachment or queue notification alone.
- **Virtio-RTC:** alarm activation, forward/backward time changes, missed alarm
  prevention, suspend/resume, repeated restore, and Linux/5BSD activation.
  A rebuilt-5BSD read-only system-clock driver and distinct split/packed live
  lanes now issue and host-correlate configuration, clock-capability, clock
  read, alarm control, and alarm notification requests.  The guest sanitizes
  device-retained alarm state before publishing its first notification
  buffer, validates every notification, reads the associated clock outside
  interrupt context, and exposes bounded alarm controls and counters.  Live
  promotion still requires a rebuilt guest image to pass both lanes.
- **Virtio-sound:** production audio-backend qualification,
  playback/capture lifecycle,
  format/rate/channel negotiation, underrun/overrun, active PCM checkpoint
  policy, Linux activation, packed queues, and a 5BSD driver.
  Backend selection is explicit as `backend=null` or host-dependent
  `backend=oss`; unknown names are rejected.  The OSS backend has a distinct
  identity, uses nonblocking PCM operations driven by kqueue readiness instead
  of waiting in the vCPU notification path,
  bound queued guest-buffer ownership, drain all stream I/O before RELEASE
  completion, and define versioned reconstruction/checkpoint policy.
  The shared OSS boundary now supports nonblocking open, partial
  playback/capture progress, explicit `EAGAIN`, kqueue registration rights,
  and zero-progress rejection while retaining the existing blocking HDA
  contract.  A transport-independent asynchronous PCM owner now bounds one
  copied or privately staged request per stream, carries partial descriptor
  progress without replay, preserves ownership across `EAGAIN`, serializes
  readiness against cancellation, fences stale generations, and refuses
  teardown while a completion is owed.  Rootless tests cover playback-copy
  ownership, capture atomicity, partial progress, backend contract violations,
  generation races, concurrent progress/cancel, fragmented direct-to-owner
  copies, and backend-free prepare/completion adapters; they run in both ATF
  and the sanitizer-backed VM-free release gate.  The adapters derive the
  normative PCM success/error records independently and separate guest-chain
  validation from host I/O.  The PCI data queues now install host-issued
  generation claims atomically with one retained `vi_req` per stream, copy
  playback out of guest memory before backend ownership, stage capture
  privately, preserve the DMA lease through partial progress, and publish only
  through the original queue generation.  RELEASE cancels and publishes the
  retained request before backend teardown; selective and full reset discard
  it without touching an invalid queue incarnation; suspend and checkpoint
  fail closed until the owner is quiescent.  Rootless composition tests force
  `EAGAIN` to prove these paths rather than relying on the immediately
  completing null backend.  This remains a production-backend boundary:
  Completion remains owned through the entire completion callback, so pause,
  reset, destroy, and replacement submission cannot observe a falsely idle
  stream while the callback still holds retained queue or guest-memory state.
  The portable PCI state carries an explicit backend-kind and endpoint
  envelope; restore rejects an unknown backend or different destination
  playback/capture path before reconstruction.  OSS open is nonblocking and
  the retained owner is driven by mevent/kqueue read/write readiness, with
  readiness disabled across selective and full reset.  Rootless tests cover
  partial progress, retryable and terminal errors, capture privacy, reset, and
  backend/endpoint mismatch.  Terminal completion and stale readiness disable
  the source under the same device mutex that protects retained ownership,
  preventing an old callback from disabling a replacement job after it has
  been enabled.  OSS remains provisional until backend
  reconnect, underrun/overrun policy, and live Linux playback, capture, reset,
  and checkpoint gates pass on representative host audio devices.

After completing those devices, the next conditional additions are
virtio-crypto when a reviewed acceleration requirement exists, virtio-video
for a concrete media workload, and virtio-SCMI when ARM platform management is
in scope.  Device count is not a goal: low-value or obsolete interfaces remain
out of scope without a real backend and qualification workload.

### Conditional-device decision record

These entries are deliberately not probe-only device stubs.  A new device
enters implementation only when it has a production backend, a concrete
workload, and an unmodified guest that can exercise its distinguishing paths.
This avoids advertising a nominal VirtIO surface that has no meaningful error,
lifecycle, or migration contract.

| Device | Current decision | Required production boundary | Qualification that unblocks implementation |
| --- | --- | --- | --- |
| Virtio-crypto | Deferred | A reviewed host cryptographic provider with explicit key ownership, cancellation, queue bounds, side-channel policy, and checkpoint behavior | A concrete acceleration or isolation workload; Linux live algorithm/session tests; failure, reset, concurrency, and provider-loss tests; a 5BSD activation plan where its guest support exists |
| Virtio-video | Deferred | A maintained codec/backend API with bounded frame ownership, format negotiation, cancellation, and a defined active-stream checkpoint policy | A concrete encode/decode workload; Linux live streaming and malformed-buffer coverage; host backend fault and saturation tests; a 5BSD driver plan if cross-guest qualification is required |
| Virtio-SCMI | Deferred until a non-x86 platform target exists | Architecture-neutral SCMI transport plus an ARM platform-management backend; no Intel-only stand-in | ARM bhyve platform support, a real clock/reset/power-domain model, Linux and 5BSD guest activation on that platform, and save/restore tests for every exposed protocol |

The present Intel host remains the live nested-VMX qualification machine, but
common VirtIO, DMA, interrupt, lifecycle, and save-state code must not encode
Intel assumptions.  SCMI and other platform-management work is therefore
gated by a real ARM target rather than simulated success on unrelated
hardware.

### Administration owner topology gate

The common PCI administration controller can now register a dynamic SR-IOV
group backed by the PF/VF lifecycle fence.  Group and command registration is
permanently sealed before a PCI binding publishes queue state, and the first
standalone command execution seals it as a fail-safe.  The sealed fast path is
atomic and does not serialize commands on independent administration queues.
Retained initialization owner pointers cannot add commands after sealing.

No production device advertises `VIRTIO_F_ADMIN_VQ`.  The pinned Linux PCI
transport creates and enables the administration queue, then immediately
queries the SR-IOV group.  An ordinary virtio-net owner exposing only the
type-zero self group would therefore negotiate successfully and fail its first
real command.  Production exposure remains gated on a real SR-IOV-capable PF
device model whose capability writes, VF Enable, NumVFs, VF identity,
reset/FLR, suspend, restore, and member command callbacks are wired to this
controller.  Linux PF/VF discovery and successful command execution are
mandatory before that group type is exposed.

## Required gate for every feature or device

1. A requirement table names each mandatory and advertised optional clause.
2. Wire-layout tests use constants and byte vectors transcribed independently
   from the specification.
3. Positive, malformed-descriptor, range/overflow, feature-dependency,
   backpressure, reset, detach, and allocation-failure paths are covered.
4. Queue tests include indirect descriptors, EVENT_IDX or packed-ring event
   suppression as applicable, interrupt fallback, and selective reset.
5. The device builds with `-Werror`; sanitizer-backed source harnesses pass.
6. An unmodified Linux guest and, where a driver exists, an unmodified FreeBSD
   guest pass isolated and combined-device matrices.
7. Advertising or reading a feature bit is not activation evidence.  For each
   advertised feature, the stock guest driver must negotiate it and exercise
   its distinct data or control path.  The guest records driver-visible state
   (for example active queue pairs, hardware queues, packed-ring negotiation,
   or translated DMA), while a host trace records the corresponding queue,
   control command, reset, or mapping operation.  Multiqueue therefore
   requires real traffic with multiple active Linux queues and, where the
   stock driver supports it, multiple active FreeBSD queues; a configured
   `queues=` value alone does not pass the gate.  The release matrix includes
   separate 5BSD split and packed two-queue cases; each pins concurrent
   traffic to both vCPUs and requires host notifications on both TX queues.
   The machine-readable `virtio-feature-activation.tsv` ledger records Linux
   and 5BSD independently.  `pending` and `driver-gap` are not coverage, and
   an `exercised` claim is rejected unless it names both guest and host-path
   evidence.  If the stock 5BSD driver does not expose an otherwise
   high-value feature, that is a guest-driver roadmap item rather than
   permission to call the bhyve feature fully qualified.  Block and SCSI
   multiqueue are examples: Linux activation alone is useful evidence, but
   the cross-guest release gate also requires 5BSD drivers to allocate
   multiple request queues, report the active count, drive every queue, and
   correlate those requests with bhyve queue traces.
   Every exercised claim must also be scheduled by the qualification
   profile.  A standalone helper or a manually recorded pass is retained as
   development evidence but does not close the release gate.  The scheduled
   case must fail if the guest declines the feature, falls back to the
   single-queue or split-ring path, leaves any required queue idle, or
   produces no matching host trace event.
8. A reset/rebind/reboot soak checks bounded fd, memory, thread, and connection
   growth.  Concurrent-device tests prove one device's failure does not reset
   another.
9. Manual pages, configuration schema, DTrace metadata, rate-limited logs, and
   audit behavior are updated before the feature is advertised.
10. After all ordinary conformance, lifecycle, portability, reference, and
    test-quality findings are fixed, repeat the kernel review from the real
    production entry points.  This is the forward lifetime traversal: re-trace
    allocation and publication ownership,
    lock and sleep context, interrupt/callout/taskqueue teardown, reset and
    detach races, restore rollback, DMA lifetime, integer arithmetic, and
    hot-path bounds.  Generate fresh warnings-as-errors diagnostics.  A pre-fix
    kernel pass is not reusable evidence, and repeating the same diff walk is
    not an independent second review.
11. Run a separate non-standard-interface phase.  Inventory every bhyve-only
    PCI identity, compatibility quirk, provider ioctl, checkpoint record,
    policy tunable, experimental feature, and private backend protocol.
    Classify each as a private detail, compatibility contract, versioned ABI,
    or experimental opt-in; keep its constants out of normative fixtures;
    document its stability and default; and require positive, rejection,
    version-skew, and fallback tests.  Linux and QEMU are behavioral
    comparisons in this phase, not normative authorities.
    Include every compile-time queue count, maximum object/transfer/mapping
    size, memory cap, timeout, retry count, polling cadence, rate limit, sysctl,
    tunable, and guest-driver resource ceiling.  Classify it as
    standard-derived with an exact section and independent oracle, or private
    policy with units, owner, default, mutability, authorization,
    compatibility promise, rollback, and a direct boundary or negative test.
12. Run a second, independent kernel review after the non-standard inventory.
    Start at teardown, failed restore, reset, interrupt drain, DMA revocation,
    and backend disconnect, then trace each object backward to allocation and
    publication.  Re-read the final source and generate fresh compiler
    diagnostics; findings or evidence from item 10 do not satisfy this phase.
    Any production-code correction restarts items 10 through 13.
13. Compose the non-standard boundaries after both kernel traversals.  Cross
    private PCI identities, provider ioctls, authorization, tunables, backend
    identities, checkpoint versions, resource ceilings, and experimental
    feature gates.  Require wrong-owner, wrong-generation, wrong-device,
    version-skew, disabled-feature, and rollback tests, and verify that no
    private constant is used as the oracle for a normative VirtIO or Intel
    requirement.
14. Repeat the non-standard inventory independently from its consumers and
    decoders rather than its definitions.  Start at restore dispatch,
    management tools, manuals, DTrace and audit consumers, MAC hooks, guest
    feature selection, and compatibility fallbacks, then trace accepted
    values back to their producer.  Reconcile every discovered contract with
    exactly one private-ledger row and direct positive and rejection tests.
    This replay is separate from boundary composition; any finding restarts
    both kernel traversals and both private reviews.
15. Replay kernel/private adapter failure atomicity independently of object
    lifetime.  At each callback, DMA, interrupt, backend, checkpoint,
    suspend, and architecture-adapter boundary identify the last fallible
    operation, first retained-owner mutation, rollback owner, and exact retry
    identity.  Reverse-inject every failure and require unchanged owners and
    caller outputs where retry is promised.
16. Inventory withheld, unsupported, and implementation-defined behavior.
    Prove partially implemented features remain consistently unadvertised
    across modern, legacy, management, checkpoint, and backend surfaces;
    classify fallbacks, waits, polling, retries, debug paths, and resource
    ceilings as explicit private contracts.  Any production correction
    restarts both kernel traversals and all private phases.
17. Repeat the kernel review from shared VMM and device-core entry points.
    Build a caller/context table for interrupt, callout, taskqueue, worker,
    ioctl, reset, suspend, restore, and teardown paths.  Prove every common
    callback's sleep/allocation/locking contract on all supported host
    architectures.  For checkpointing, distinguish a generation comparison
    from an ingress lease and prove that events arriving after capture are
    excluded or retained through atomic publication without dropping internal
    timer or interrupt work.
18. Repeat the non-standard review from dispatch and compatibility consumers.
    Audit record-name selection, old decoders, manifests, backend identities,
    tunables, sysctls, probes, audit records, diagnostics, and unfinished
    features.  Require explicit legacy/current selection and rejection of
    unknown, cross-architecture, wrong-owner, stale-generation, wrong-backend,
    and disabled-feature combinations.  Replay item 17 after any finding so
    the final shared-kernel and private-policy conclusions cover identical
    source.
19. Run an independent final-source kernel teardown/publication pass.  Record
    a sorted, hashed scope manifest which includes untracked production and
    test files, then start at final close, detach, failed restore, interrupt
    publication, worker cancellation, DMA revocation, and capacity exhaustion.
    Trace backward to allocation and admission.  This pass may not reuse the
    ownership graph, findings, or compiler output from items 10, 12, or 17.
20. Rebuild the final-source private ABI and policy inventory independently.
    Start from installed consumers, retained checkpoint artifacts, ioctls,
    sysctls, tunables, logs, probes, audit records, compatibility decoders,
    backend protocols, and disabled-feature errors.  For each accepted value,
    prove version, owner, generation, architecture, backend, authorization,
    namespace, rollback, and stable errno behavior.  A requirement-derived
    constant and a private policy value must never share an oracle.
21. Repeat item 19 from a different root order on the byte-identical scope.
    Begin with capacity and arithmetic boundaries, then asynchronous producer
    entry, rollback, and teardown.  Generate fresh warnings-as-errors output
    and focused fault evidence.  Kernel build evidence must include separate
    clean-object `vmm.ko` builds with the default options and with
    `MK_BHYVE_SNAPSHOT=yes`; the default generated option header does not
    compile snapshot-only ownership and restore paths.  A source or test
    change, including a review-harness correction, invalidates both
    final-source kernel passes.
22. Repeat item 20 from decoders and negative consumers on that same byte-
    identical scope.  Verify unknown versions, reserved fields, stale and
    cross-owner identities, wrong architecture/backend, disabled features,
    fallback selection, and observability stability.  Compare the two private
    inventories and require exact reconciliation before either is clean.
    Any finding in items 19 through 22 restarts all four phases.

The event-ingress review additionally requires a checked caller/context
inventory.  It must cover publication, consumption, reset, restore, abort, and
teardown—not only the externally visible injection helpers—and it must keep
each production adapter marked pending until the common ingress lease spans
capture through durable publication.  Credentials bind to the exact state,
owner incarnation, generation, and credential storage; pointer-derived
lifetime guards are transient and must never enter save state.  Deferred work
is limited to explicitly idempotent event classes and must be merged while the
same non-sleeping ingress lock remains held, with wakeups after unlock.

The common grouped checkpoint transaction closes every selected vCPU ingress
under one caller-owned, stable lock order and reopens the complete set only
after all members quiesce or the operation aborts.  It is an allocation-free
value protocol: it does not serialize state, interpret architecture events, or
wait.  The production adapter must supply an event-driven wait channel and a
durable-publication boundary; polling the group-ready predicate is not an
acceptable substitute.  Exact transaction, entry-array, lease, and ingress
storage bindings make copied, moved, overlapping, duplicate, stale, and
cross-state credentials fail without changing any owner.

## Post-fix kernel and non-standard review phases

These are independently terminating phases of every rotating review cycle,
not informal checks folded into another pass.

Two additional final-source phases are mandatory after the ordinary forward
and reverse reviews.  They are roadmap phases 23 and 24 and correspond to
nested-VMX review Passes 29 and 30, respectively:

23. **Second common-kernel primitive lifecycle review.**  Start below bhyve
    and each device model at the kernel primitives they consume: VMM event
    publication, vCPU freeze/wakeup, LAPIC timers, VMX/SVM runtime ownership,
    DMA pinning, interrupt delivery, cdevpriv lifetime, sleep queues, and
    snapshot publication.  Traverse allocation, publication, rollback,
    reset, detach, restore, and destruction independently of the device-side
    review.  Recheck lock order and execution context at every callback.  A
    passing device model or value test is not evidence that the underlying
    primitive is safe in its production context.
24. **Second private/non-standard activation-boundary review.**  Reconstruct
    every bhyve-private or provisional contract from its consumers and
    decoders: ioctl and provider ABIs, legacy PCI identities, backend and
    checkpoint envelopes, feature-policy switches, architecture adapters,
    DTrace/audit records, and withheld activation gates.  Bind each value to
    an owner, generation, lifetime, architecture, authorization domain, and
    failure policy.  Verify that a private success result cannot bypass the
    common primitives reviewed in phase 23 and that no experimental feature
    is advertised merely because its value model compiles.
25. **Doubled kernel callback-context and irreversible-tail review.**  Discard
    the earlier kernel conclusions and begin at every indirect callback and
    irreversible publication.  Validate complete callback tables before any
    member is used; record thread, lock, interrupt, allocation, sleep, and
    cross-CPU-drain behavior; and prove every post-commit callback is truly
    infallible and nonblocking.  Move vmspace, pmap, backend, and other
    potentially sleeping destruction into fallible precommit preparation, or
    retain an explicit production activation gate.
26. **Doubled private-provider and policy-domain review.**  Rebuild every
    non-standard provider, opaque owner, fixed limit, retry/error vocabulary,
    generation, diagnostic, and unfinished gate once from definitions and
    once from consumers.  Compose valid state with incomplete providers and
    valid providers with malformed state at every public entry point.  Keep
    bounded constant-time checks on hot paths and full ownership/duplicate
    scans at lifecycle boundaries.  These correspond to nested-VMX review
    Passes 31 and 32; any correction restarts both phases.
27. **Post-preparation final kernel-code replay.**  After a fallible
    preparation or irreversible-tail change, perform two new traversals of
    the exact final kernel source: event admission forward through prepare,
    apply, publication, wakeup, and teardown; then every error and teardown
    backward to its admitting validator.  Classify each mutation as
    architectural, derived and reconstructible, rollback-owned, retained, or
    fail-stop.  This corresponds to nested-VMX review Pass 35.
28. **Post-preparation final non-standard contract replay.**  Independently
    rediscover prepare/apply callbacks, cache-retirement policy, owner and
    generation values, private errno mappings, activation gates, ioctls, and
    checkpoint envelopes from definitions and consumers.  Reconcile them
    with the private ledger only after discovery and prove private policy
    cannot weaken Intel or VirtIO validation.  This corresponds to
    nested-VMX review Pass 36.
29. **Dormant and unsupported kernel-code replay.**  Review every compiled
    path behind `ENOTSUP`, `EOPNOTSUPP`, or a false readiness gate twice: once
    from admission through cleanup and once from each dormant callback back to
    its gate.  Prove the gate mechanically, but otherwise hold the code to the
    same provider-lifetime, rollback, finalizer, errno, build, and test
    requirements as reachable kernel code.  Negative private callback results
    must fail-stop their mutating durable owner rather than silently remaining
    retryable.  This corresponds to nested-VMX review Pass 37.
30. **Implementation-defined and non-standard behavior replay.**  Rebuild all
    private policy in the dormant scope from definitions and independently
    from consumers: command namespaces, readiness predicates, cookies,
    provider identities, retry states, derived-cache policy, fail-stop rules,
    diagnostics, and checkpoint envelopes.  Reconcile the two inventories
    with the private ledger only after discovery, enumerate every callback
    result domain and contradictory pair, and prove none weakens the normative
    architecture or leaks into portable state.  This corresponds to
    nested-VMX review Pass 38.
31. **Kernel vCPU-entry integration review.**  Trace one future kernel-owned
    INIT/SIPI from common publication through lifecycle arbitration, an AP
    already asleep in wait-for-SIPI, machine dispatch, exact event commit,
    scheduler publication, and guest re-entry.  Prove that pending INIT can be
    serviced without a SIPI wake, while rendezvous, suspend, reqidle, and
    debugger work already observed at the boundary cannot be bypassed.  Define
    a bounded, non-polling disposition for IDLE, RETAINED, and CONSUMED before
    adding any `vm_run()` call or changing machine readiness.
32. **Reverse non-standard entry-boundary review.**  Start independently from
    every machine readiness and startup-step operation, rebuild its consumer,
    enum/error domain, output publication, architecture support claim, and
    teardown owner.  Require disabled architectures to fail closed without
    output mutation and require the Intel adapter to preserve the private
    durable dispatch result exactly.  Compiled adapters with no `vm_run()`
    caller remain staged, unsupported code and both readiness providers stay
    false until installed lifecycle/race qualification completes.
33. **Frozen-to-running notification-window review.**  Trace publication from
    the coordinator commit through both the generation-advancing startup
    notifier and `vcpu_notify_event()` and prove the event
    cannot be lost while the target changes from FROZEN to RUNNING.  Sample the
    notification generation before and after frozen dispatch: idle and retained
    dispatch require equality, while consumed dispatch requires exactly its one
    claim-release notification.  Admit the post-dispatch value into a
    pointer-free handoff, publish RUNNING, and validate afterward; missing or
    extra transitions and changes before validation force replay, while changes
    after the final interrupt-disabled validation must observe RUNNING and
    interrupt the target.  Distinguish stale owner identity from retryable
    mutable drift.
34. **Entry-transition unwind and fairness review.**  Before consuming the
    token in `vm_run()`, prove exact FPU restore/save symmetry and vCPU-state
    rollback on token drift or error, lifecycle precedence after every replay,
    dispatch-before-wait for an already-sleeping AP, and bounded host fairness
    under continuous coalesced INIT/SIPI publication.  Repeat from notifier,
    machine-entry, teardown, and signal-interruption consumers.  Keep the run
    call and readiness switches disabled until this review and live races pass.
35. **Second final-source kernel integration review.**  Discard phases 33 and
    34's finding inventory and independently traverse the exact final kernel
    from `vm_run()`, vCPU state and FPU transitions, notifier, coordinator,
    machine adapters, rendezvous, reset, destroy, and interrupted entry.  Walk
    both admission-to-hardware and every unwind-to-admission direction.  Prove
    lock order, execution context, bounded event-driven replay, notification
    timing, positive errno handling, failure-atomic outputs, and exact state
    and FPU symmetry.  A value-model result is not integration evidence.
36. **Second final-source non-standard behavior review.**  Without consulting
    the private ledger first, inventory the same slice from definitions and
    independently from consumers.  Classify dispatch results, run tokens, the
    startup-notification generation and runtime entry handoff, readiness and
    unsupported gates, retry/stale policy, private ioctls and
    owners, diagnostics, probes, audit records, architecture scope, fixed
    limits, and checkpoint exclusions.  Bind each to an owner, lifetime,
    concurrency domain, compatibility promise, portable-state status, and
    negative test, then reconcile both inventories exactly with the ledger.
    Any finding restarts phases 33 through 36 before activation.
37. **Architecture-neutral entry-unwind model review.**  Prove the exact
    critical-section, FPU, FROZEN/RUNNING, token-check, refreeze, and return
    sequence in a rootless value model.  Cover success, replay, positive
    failure, malformed state, aliases, invalid ordering, duplicate retry
    observations, retry-plus-terminal errors, matching terminal errors, and
    conflicting terminal errors with deterministic fail-closed composition.
    Mechanically reject any live `vm_run()`, VMX, or SVM
    consumer while installed timing qualification is absent.  This corresponds
    to nested-VMX review Pass 45.
38. **Deferred activation and private-policy review.**  Rebuild the complete
    private entry contract from definitions and consumers, including every
    phase, action, errno, gate, epoch, token, handoff, diagnostic, audit/trace
    policy, and serialization exclusion.  A future live consumer requires
    explicit approval and restarts phases 33 through 38 with installed Intel,
    Linux/KVM L1, Linux/5BSD L2, checkpoint, concurrency, signal, reset, close,
    and soak evidence.  This corresponds to nested-VMX review Pass 46.
39. **Post-correction kernel replay.**  After the last production correction,
    pin a new source manifest and repeat the kernel review without importing
    phase 35's findings.  Start independently from publication, frozen
    dispatch, hardware entry, and unwind/teardown; traverse each direction
    through locking, coordinator ownership, notification admission, vCPU/FPU
    state, reset, suspend, debugger, signals, and destroy.  Verify interval
    coverage, exact ownership consumption, execution context, and event-driven
    replay.  A new correction restarts this phase.
40. **Post-correction non-standard replay.**  On the same final manifest,
    rediscover private behavior separately from definitions and consumers
    before consulting phase 36's inventory.  Reconcile enums, errno domains,
    epochs, tokens, handoffs, readiness/apply gates, architecture limits,
    resource bounds, checkpoint exclusions, diagnostics, tracing, audit, and
    experimental controls with the private ledger and focused negative tests.
    Any mismatch restarts phases 39 and 40 and keeps activation disabled.
41. **Every-hardware-entry guard review.**  Trace every loop in each machine
    backend that can execute VM entry more than once before returning from
    `vmmops_run()`.  Keep the common coordinator token and notification
    handoff armed across the complete synchronous run call and require both to
    be checked inside the interrupt-disabled window before every initial or
    repeated hardware entry.  A backend-handled exit must not bypass common
    INIT/SIPI dispatch by re-entering after its notification.  Prove repeated
    successful checks are ownership-neutral and that retry or terminal drift
    after any internal exit follows the same refreeze, FPU-save, and critical
    unwind.  Model NEED_CHECK, CHECKED, IN_GUEST, RETURNABLE, and COMPLETE as
    explicit architecture-neutral phases with exact check/entry counts so a
    missing recheck is an invalid transition rather than a review convention.
    Keep live consumers absent until Intel and AMD loop placement and
    before/during/after-internal-exit races are installed-qualified.
42. **Backend-loop ownership and return review.**  Restart from every guard
    result producer and every common return consumer.  Require the transient
    backend loop to snapshot its canonical normal, replay, or terminal-error
    disposition before becoming RETURNABLE, to retain the canonical normal
    value in every earlier phase, and to publish only its owned value through
    a disjoint output when completing.  Reject null or overlapping output,
    malformed embedded disposition, invalid phase, and later mutation of the
    guard-result input without changing either owner or output.  Rebuild the
    private-interface inventory independently and confirm that this loop is
    runtime-only, untraced, unaudited, unserialized, and absent from live VMX,
    SVM, and common `vm_run()` until installed loop-edge qualification passes.
43. **Backend-loop semantic-domain review.**  Re-read every action at its
    producer and final consumer.  Keep guard admission (`ENTER_GUEST`, replay,
    error) distinct from backend return (`RETURN_VMEXIT`, replay, error), and
    require an explicit checked translation between those private domains.
    Prove that an unhandled hardware exit can never be interpreted as another
    entry request, that each action has one exact errno domain, and that
    malformed or cross-domain values are rejected failure-atomically.  Repeat
    the corrected-source kernel and non-standard inventories after any change.
44. **First exact machine-entry kernel review.**  Start at each actual
    `vmx_enter_guest()` and `svm_launch()` instruction and walk backward to the
    common `vm_run()` state publication, then forward through every return and
    retry edge.  Treat ordinary VMX, initial nested VMX, resumed nested VMX,
    hot nested re-entry, and SVM as separate paths.  Record the exact point at
    which interrupts are disabled, host descriptors and debug state are
    borrowed, guest MSRs and TSC_AUX are resident, the pmap is active, and a
    VMCS02 or hot continuation becomes owned.  A startup guard may be inserted
    only where failure has a proven path-specific unwind back to common
    FROZEN/host-FPU state; a generic error callback is not evidence of that
    unwind.
45. **Second exact machine-entry kernel review.**  Ignore phase 44's path list
    and rebuild the graph from every `enable_intr()`, `enable_gintr()`,
    `VMCLEAR()`, pmap deactivation, MSR exit, descriptor restore, refreeze,
    hot-residency abort, `fail_intr`, and `out_error` edge.  Walk each cleanup
    backward to the hardware-entry instruction and forward to common
    `save_guest_fpustate()` and `critical_exit()`.  Prove that every
    pre-entry rejection and post-exit replay has exactly one cleanup class,
    does not double-release nested ownership, never migrates with CPU-local
    state resident, and cannot re-enter without another successful check.
46. **Definition-first non-standard entry review.**  Rediscover every private
    phase, action, errno, generation, token, handoff, callback, provider ID,
    readiness gate, architecture limitation, diagnostic, and serialization
    exclusion used by the proposed entry integration directly from
    definitions.  Classify each value as transient common state, Intel-only
    runtime state, AMD-only runtime state, or portable state.  Reject any
    implicit public ABI, native-pointer persistence, x86 assumption in common
    state, undocumented positive result, or private value reused across two
    semantic domains.
47. **Consumer-first non-standard entry review.**  Without consulting phase
    46's inventory, start from every branch that will consume guard and loop
    results, every trace or diagnostic formatter, each checkpoint encoder and
    decoder, and each unsupported-architecture/readiness gate.  Reconstruct
    the private contract, reconcile it exactly with the definition-first
    inventory and non-standard ledger, and require focused negative evidence
    for every success, retry, terminal, malformed, stale, unsupported, and
    teardown outcome.  Any correction restarts phases 44 through 47 before a
    live consumer may be added.
48. **Forward composed-adapter kernel review.**  Rebuild the corrected
    pre-entry and post-return transactions from common RUNNING publication to
    every real VMX/VMRUN instruction and back.  Distinguish lifecycle returns
    that never attempted entry from handled exits, normal exits, retryable
    post-entry failures, and terminal post-entry failures.  Require the guard
    record to bracket exactly one hardware attempt and require each nested
    error to pass through its typed residency unwind before common cleanup.
49. **Reverse composed-adapter kernel review.**  Ignore phase 48 and start at
    every common replay/error/VM-exit consumer and every architecture cleanup
    label.  Walk backward to prove it has exactly one matching IN_GUEST record
    and forward to prove RETURN_VMEXIT, REPLAY, and RETURN_ERROR retain their
    identities without double cleanup or an unguarded re-entry.
50. **Definition-first composed-adapter private review.**  Re-inventory the
    corrected handled flag, positive backend errno, return-action translation,
    loop counters, transient runtime owner, path-specific Intel unwind, AMD
    unsupported behavior, and all serialization/ABI exclusions directly from
    definitions.  Treat a boolean-only post-entry result as incomplete.
51. **Consumer-first composed-adapter private review.**  Without consulting
    phase 50, derive the contract from future common, VMX, nested-VMX, SVM,
    trace, diagnostic, checkpoint, and teardown consumers.  Reconcile it with
    the private ledger and focused negative tests.  Any correction restarts
    phases 48 through 51 and keeps all live consumers absent.
52. **Forward stack-owner kernel review.**  Starting with a target frozen in
    common `vm_run()`, prove this exact order: sample the startup notification
    generation, perform the frozen machine dispatch, sample the generation
    again and admit the handoff, then capture the coordinator run token from
    the post-dispatch state.  Only after both value owners exist may common
    code enter its critical section, restore guest FPU state, and publish
    RUNNING.  Continue through every interrupt-disabled VMX and SVM check,
    every handled-exit recheck, and the single common refreeze/FPU unwind.
    Reject a pre-dispatch coordinator-token baseline: consuming a claim
    legitimately changes the very fields that token protects.
53. **Reverse stack-owner kernel review.**  Reconstruct the same ordering
    independently from handoff disarm, coordinator-token release, common
    FROZEN publication, host-FPU restoration, each backend cleanup label, and
    every nested typed unwind action.  Prove no path disarms either owner
    after the first hardware attempt, returns with a stack pointer retained by
    a backend, or lets an error bypass the one common unwind.  Check reset,
    destroy, checkpoint cancellation, signal interruption, and an event
    published in every gap between the ordered captures.
54. **Definition-first stack-owner non-standard review.**  Inventory the
    proposed stack-owned token, handoff, runtime, loop, backend pointer,
    positive errno, readiness gate, and lifetime flags directly from their
    definitions.  Classify all of them as transient private control state;
    prohibit serialization, copying into a VM/vCPU durable record, retention
    after `vmmops_run()`, public ABI exposure, architecture-specific members,
    and callback-table ownership.  Require named-field validation and
    failure-atomic construction/destruction.
55. **Consumer-first stack-owner non-standard review.**  Without consulting
    phase 54, rebuild the contract from common `vm_run()`, ordinary VMX, every
    nested VMX entry/residency class, SVM, tracing, diagnostics, checkpoint,
    reset, and teardown.  Reconcile both inventories with independent tests
    for empty, stale, aliased, malformed, consumed, retained, concurrent
    publication, handled-exit, backend-error, and unwind-error cases.  Any
    finding restarts phases 52 through 55 before changing the run signature.
56. **Forward cross-owner transition review.**  Starting from the only
    admitted BOUND tuple, enumerate every operation that may jointly advance
    the runtime and backend-loop owners.  Add a distinct outer phase only in
    the same change as the operation that produces it, its exact member-state
    relation, failure-atomic local-copy transition, and negative tests for
    every other Cartesian-product pairing.  Separately valid member values
    are not evidence that their combination is reachable.
57. **Reverse cross-owner retirement review.**  Start at zeroized stack
    retirement and walk backward through final owner arbitration, handoff
    validation/disarm, loop completion, common critical/FPU unwind, every
    backend return class, and every pre-entry rejection.  Prove exactly one
    terminal disposition, no premature token destruction, and no phase that
    can be forged by direct member mutation.
58. **Definition-first outer-owner non-standard review.**  Inventory the
    outer phase, embedded phases and counters, armed/reserved fields, errno
    composition, output ownership, and destruction semantics without reading
    consumers.  Reject padding comparisons, native pointers, public ABI,
    save-state use, architecture residency, or a validator that merely checks
    each embedded value independently.
59. **Consumer-first outer-owner non-standard review.**  Without consulting
    phase 58, reconstruct the reachable product state from tests and every
    proposed common, VMX, SVM, nested, trace, checkpoint, reset, and teardown
    consumer.  Mechanically reject direct field transitions outside the owner
    module.  Any mismatch restarts phases 56 through 59 and keeps production
    wiring absent.
60. **First kernel no-entry return review.**  Trace every ordinary VMX,
    nested-VMX, and SVM return that can occur before VMX/VMRUN.  Distinguish a
    valid software-synthesized lifecycle exit from selection or preparation
    failure and from a hardware exit.  Require separate owner operations,
    zero hardware-entry increment, positive errno validation, path-specific
    nested unwind, and the normal common FPU/critical cleanup.
61. **Independent reverse kernel no-entry review.**  Start at common
    userspace-return, restart, error, and diagnostic consumers and walk
    backward to determine which returns executed hardware.  Reconstruct all
    lifecycle, ordinary VMX, initial/resumed/hot nested VMX, and SVM paths
    without using phase 60.  Reject ambiguous zero-entry hardware provenance
    and any pre-entry failure that skips its machine cleanup owner.
62. **Definition-first no-entry non-standard review.**  Inventory the private
    software-exit action, pre-entry-failure operations, counters, errno
    domains, output ownership, final arbitration, and exclusions.  They are
    transient machine-independent kernel policy, not Intel architecture,
    public ABI, save state, or proof that VMX/VMRUN executed.
63. **Consumer-first no-entry non-standard review.**  Rebuild the same result
    domain from common, machine, nested, trace, statistic, checkpoint, reset,
    and teardown consumers.  Require independent positive and negative tests
    for software exits before and after handled entries, retryable and
    terminal preparation failures, ordinary hardware exits, and final owner
    drift.  Any correction restarts phases 60 through 63 and then 56 through
    59.
64. **Forward common frozen-admission review.**  Start at the `restart` label
    with a FROZEN vCPU and reconstruct the kernel-owned order without using
    the machine-entry graph: service rendezvous, suspend, reqidle, and debug
    before machine dispatch; bracket exactly one frozen startup dispatch with
    the notification generation; and only then decide replay, wait-for-SIPI,
    or admission.  A waiting AP must dispatch a pending SIPI before sleeping,
    while dispatching before a pending lifecycle request is equally invalid.
    Capture the coordinator token only after an admitted idle or retained
    dispatch and construct the stack owner before `critical_enter()`.
65. **Reverse common return-and-wait review.**  Begin at userspace return,
    kernel restart, interruptible startup sleep, and zeroized owner storage.
    Walk backward through final token/handoff arbitration, critical/FPU
    unwind, backend return, RUNNING publication, token capture, frozen
    dispatch, and lifecycle selection.  Prove consumed dispatch replays
    without sleeping, retained dispatch may run to remove a blocker, an idle
    waiting AP sleeps without owning a run transaction, and every admitted
    owner is retired exactly once.
66. **Per-machine exact guard-placement review.**  For ordinary VMX, initial,
    resumed, and hot nested VMX, and SVM, identify the last logical check
    before each actual VMX/VMRUN attempt and the first point after complete
    host-residency restoration where its return can be classified.  Ordinary
    handled exits recheck; nested exits retain an open attempt until typed
    unwind determines handled, software-transformed, retryable, terminal, or
    userspace-return disposition.  Every error before the instruction uses
    fail-before-entry; every lifecycle exit uses software-exit; no cleanup
    label may both retire machine residency and bypass the owner.
67. **Live-boundary non-standard contract review.**  Independently rebuild
    the proposed `vm_eventinfo`, stack-pointer, result, errno, trace,
    statistic, checkpoint, reset, and teardown contract from consumers.
    Prohibit backend retention of the stack owner, direct member writes,
    serialized transient state, polling, public ABI exposure, or enabling a
    readiness provider based only on rootless evidence.  Require the common
    and machine source-order map, focused failure injection, strict builds,
    and installed before/during/after-entry race qualification before the
    production-consumer prohibition can be removed.
68. **Forward frozen-admission transaction review.**  Starting only from the
    private value definitions, trace validation of the pre-dispatch snapshot,
    one notification-bracketed dispatch result, the independent
    post-dispatch snapshot, final action selection, and optional armed
    handoff.  Prove pre-existing lifecycle work rejects a transaction that
    claims dispatch occurred, lifecycle work arriving during dispatch wins
    afterward, CONSUMED replays only when lifecycle is quiet, WAIT is
    reachable only after IDLE had an opportunity to consume SIPI, and
    RETAINED always enters so the guest can remove its live blocker.
    Require local-copy publication and an empty handoff for every non-entry
    result.
69. **Reverse frozen-admission transaction review.**  Do not use phase 68.
    Begin at each final action and reconstruct the only legal predecessor
    tuple of pre/post snapshots, dispatch result, and notification
    generations.  Include rendezvous, suspend, reqidle, debug, consumed
    replay, idle wait, retained entry, and idle entry.  Reject
    DISPATCH as a final result, an armed handoff on a non-entry action, a
    missing handoff on entry, generation drift, wrap, overlap, malformed
    reserved fields, or output mutation on failure.
70. **Definition-first admission non-standard review.**  Inventory the
    admission value, action domain, notification handoff, snapshot booleans,
    generation arithmetic, errno policy, and storage lifetime directly from
    headers and implementation.  Classify the entire transaction as private,
    transient, machine-independent kernel control state—not ABI, save state,
    architecture residency, a polling result, or proof that machine dispatch
    ran.  Require named-field validation and architecture-neutral fixed-width
    storage.
71. **Consumer-first admission non-standard review.**  Without consulting
    phase 70, search tests and every future common, machine, trace, statistic,
    checkpoint, reset, and teardown consumer.  Reconstruct who may create,
    copy, retain, format, serialize, or clear the value.  Mechanically require
    that only ENTER_GUEST crosses into stack-owner construction, that no
    output pointer aliases either snapshot, and that no consumer treats
    lifecycle-arrival-during-dispatch as malformed or sleeps before pending
    SIPI dispatch.  Any correction restarts phases 68 through 71 and then 64
    through 67.
72. **Post-correction forward kernel entry review.**  Restart at common
    `vm_run()` and trace the exact FROZEN dispatcher, wait decision, typed
    admission-to-owner crossing, critical/FPU/RUNNING transitions, ordinary
    VMX entry, nested VMX entry, SVM entry, handled-exit re-entry, and common
    unwind.  Prove RETAINED has a runnable path that can remove its blocker,
    IDLE wait is interruptible and generation-bound, and no backend entry can
    bypass the armed guards.  Keep production wiring and readiness disabled
    until every edge has a tested owner and unwind.
73. **Post-correction reverse kernel entry review.**  Do not use phase 72.
    Start at every VMX, nested VMX, and SVM hardware-entry instruction and
    every no-entry return.  Walk backward to the unique admitted owner and
    forward through all cleanup labels.  Reject retained sleeps, unguarded
    internal re-entry, unmatched FPU/run-state publication, stale callbacks,
    missed wakeups, polling, and any terminal path that destroys a live claim.
74. **Post-correction definition-first non-standard review.**  Reinventory
    every private action, errno, generation, callback, token, handoff, stack
    owner, readiness bit, trace point, and withheld behavior without using
    phases 70 or 71.  Classify storage lifetime and compatibility domain;
    prove transient values are absent from ABI and save state, and record
    every behavior not specified by Intel or VirtIO in the private ledger.
75. **Post-correction consumer-first non-standard review.**  Ignore phase 74
    and reconstruct the same contracts from all consumers, formatters,
    validators, tests, trace/statistic paths, restore/reset code, and absent
    activation edges.  Compare the inferred contract with the definitions and
    the Intel SDM/Linux model.  Any mismatch restarts phases 72 through 75,
    then 68 through 71, and requires fresh normal, sanitizer, strict-kernel,
    installed-race, checkpoint, fault, and soak evidence as applicable.
76. **Second machine-entry activation review.**  Treat the optional
    stack-owner argument on the private amd64 machine-run operation as an
    inactive compatibility seam until all callers, entry attempts, and exits
    have been reviewed again.  Starting from the `NULL` historical caller and
    each future non-`NULL` caller, prove that the owner is stack-bounded and
    inspected immediately before every VMX/VMRUN attempt while interrupts are
    disabled.  Distinguish ordinary VMX and SVM loop exits from nested
    initial, resumed, and hot paths; each no-entry path must publish
    software-exit or pre-entry-failure provenance before reaching its existing
    path-specific cleanup.  Reject partial activation, a guard after a
    guest-residency side effect, direct owner-field writes, or generic nested
    cleanup.
77. **Reverse machine-entry activation review.**  Start at every ordinary
    `vmx_enter_guest()`, nested `vmx_enter_guest()`, and `svm_launch()` call,
    then independently start at every pre-instruction return and nested
    cleanup label.  For each, derive the sole legal owner phase, guard result,
    hardware-entry count, host-residency state, FPU/run-state state, and
    final-refreeze path.  Require handled exits to recheck without
    reconstructing ownership; require a no-entry result to retain zero
    hardware-entry count; and require common retirement only after host
    residency, guest FPU, and critical state have all been unwound.
78. **Dormant and non-standard activation-surface review.**  Inventory the
    private run-owner argument, readiness predicates, false-return stubs,
    experimental error vocabulary, source validators, trace/statistic
    absences, and unsupported guest-visible features from definitions first
    and consumers second.  Classify each as architecture-neutral common
    state, amd64-private plumbing, Intel-specific behavior, AMD model-only
    behavior, or explicitly unsupported.  No item may enter save state,
    ioctl ABI, a public header contract, or a non-amd64 implementation merely
    because the private model compiles.
79. **Cross-architecture and reference comparison replay.**  Recheck the
    final common interfaces without using amd64 assumptions: pointer size,
    endian order, alignment, page size, interrupt model, sleep primitive, and
    availability of VMX/SVM must not be embedded in the common owner or
    admission values.  Compare observable entry, reset, suspend, and restore
    behavior with the cited Intel SDM on this host and with pinned Linux/KVM
    and QEMU behavior where those references define an observable contract.
    Record intentional differences rather than importing GPL implementation
    detail.  Any production correction restarts phases 72 through 79 and the
    corresponding test, checkpoint, fault, and soak evidence.
80. **Common frozen-observation and dispatch transaction review.**  Review the
    now-live common `vm_run()` startup-dispatch slice separately from the
    dormant stack owner.  Prove that the lifecycle predicate and notification
    epoch are captured together under the documented lock order on both sides
    of exactly one frozen backend dispatch.  No pre-existing lifecycle work
    may be dispatched past; consumed requests replay; retained work enters;
    and only an idle AP may sleep.  Cover alias rejection, output stability,
    epoch drift, and publication between the two observations.  This is not
    permission to pass a non-`NULL` owner to a machine backend.
81. **Consumer-first newly-live private-boundary review.**  Independently
    derive the contract from all consumers of the observation, dispatch
    result, admission action, notification epoch, and readiness predicate.
    Check wait paths, machine backends, teardown, validators, tracing,
    documentation, and tests against the non-standard ledger and the pinned
    Intel SDM, Linux/KVM, and QEMU behavior.  Reject hidden activation,
    direct field mutation, retained stack pointers, polling fallbacks, stale
    callbacks, and value-only tests.  Any correction restarts phases 80 and
    81, then phases 72 through 79 and their rootless and installed gates.
82. **Compiled-kernel and dormant-path second traversal.**  Independently
    trace the actual common, ordinary VMX, nested VMX, and SVM entry/return
    paths, including code currently suppressed by false readiness.  For every
    outcome record vCPU state, interrupt/FPU/pmap residency, stack-owner
    phase, hardware-entry provenance, errno domain, and caller disposition.
    A source gate must reject a non-`NULL` owner or live guard consumer until
    all machine-entry and unwind paths convert atomically.  Compare only
    observable behavior with Intel SDM, Linux/KVM, and QEMU references; do
    not import their implementation.
83. **Reverse non-standard contract and containment review.**  Starting from
    private definitions, knobs, cdev operations, machine hooks, provider
    callbacks, test-only symbols, trace points, and possible save-state
    fields, rebuild each contract without relying on phases 80 through 82.
    Require one owner, explicit lifetime, bounded resources, errno and
    reserved-field rules, and independent negative evidence.  Prove
    transient owners, notification epochs, and backend pointers cannot leak
    into ABI, wire state, checkpoint records, retained callbacks, or
    non-amd64 common code.  Reject undocumented activation aliases, polling,
    hard-coded platform assumptions, and implementation-derived oracles.
    Any correction restarts phases 80 through 83 and their rootless and
    installed qualification gates.
84. **Machine-entry edge matrix review.**  Independently construct a source
    matrix for every pre-entry return, hardware entry, handled internal exit,
    unhandled exit, and unwind label in `vm_run()`, ordinary VMX, nested VMX,
    and SVM.  Each row records vCPU, critical/interrupt/FPU, pmap, VMCS/VMCB,
    stack-owner, entry/check-count, and caller-disposition state.  No real
    owner may cross the run ABI until every row has exactly one phase
    transition and the path-specific cleanup is installed-kernel qualified.
    The source validator must keep both inert machine arguments and the
    `NULL` call site pinned until then.
85. **Implementation-defined boundary and observability review.**  Inventory
    every non-SDM/non-VirtIO/non-stable-ABI behavior: readiness gates, private
    commands, transient owners, notification epochs, errno mappings, cdev
    lifetime, trace/counter output, diagnostics, model-only paths, and
    withheld features.  For each define architecture scope, owner, lifetime,
    activation condition, rollback, teardown, bound, and independent test;
    then reconstruct it from consumers to definitions.  No sysctl, build
    option, private ioctl, or formerly `__unused` argument may expose a
    half-integrated capability.  A correction restarts the kernel,
    cross-architecture, reference, and test-quality review loop.
86. **Restore-residency and derived-cache review.**  Classify every snapshot
    field as architectural, portable-derived, source-backend identity, or
    CPU-local execution cache.  Preserve historical format fields only when
    needed for compatibility; never treat host CPU identity, translation-cache
    generation, host mapping, pointer, descriptor, page size, or architecture
    cache as destination-portable state.  Failed or truncated restore must not
    mutate runtime state.  Successful restore must force a destination rebuild
    before the next real entry even when host identifiers happen to coincide.
    Recheck VMX, SVM, and each VirtIO backend with normal, failed, same-host,
    cross-host, and repeated-restore tests.  QEMU and KVM state formats are
    behavioral comparisons only; this portable state contract is authoritative.
87. **Kernel architecture-record staging review.**  Independently trace each
    `STRUCT_VMCX` restore from VMMDEV dispatch through VMX VMCS and SVM VMCB
    setters.  The userspace checkpoint transaction does not itself make these
    setters failure-atomic.  Decode and validate a complete architecture
    candidate before its first mutation, then publish it only after all
    fallible work succeeds.  An opaque VMX VMCS must use an explicit field
    candidate plus an exact pre-write rollback image; an SVM VMCB may use a
    preallocated memory shadow.  Preserve the established wire layout and the userspace-only
    `VM_SNAPSHOT_VALIDATE` boundary; do not invent a public kernel validation
    operation.  Test truncation at every field, semantic rejection,
    injected-setter failure, unchanged destination, retry, same-host, and
    cross-host restore for both VMX and SVM.
88. **Reverse private restore-contract review.**  Starting from bhyve
    preflight, VMMDEV dispatch, architecture setters and completion, rollback,
    and resume, reconstruct the private restore contract independently of
    phase 87.  Inventory buffer-consumption, error precedence, retry,
    destination-stoppage, diagnostics, and retained-owner rules.  Model-only
    registry publication is not evidence for a real VMCS/VMCB decoder.  Every
    staging owner must be bounded, pointer-free in portable state, destroyed
    on all exits, and covered by a reserved/unknown/truncated negative test.
89. **All-vCPU architecture publication review.**  Treat a `STRUCT_VMCX`
    restore as one frozen-VM transaction, not a loop of independently safe
    vCPU restores.  Retain one bounded candidate and rollback image per
    destination vCPU, complete every decode and semantic check before the
    first VMCS/VMCB publication, then commit all vCPUs and the VM-wide nested
    stage together.  If a late commit fails, restore every previously
    published vCPU from its exact rollback image or fail closed.  Keep this
    coordinator private, non-sleeping while frozen, pointer-free on the wire,
    and independent of userspace `VM_SNAPSHOT_VALIDATE`.  Test every
    truncation position, a failure on each sparse-vCPU index, retry after
    failure, VMCS/VMCB setter injection, and no-mutation of every peer.
    The current implementation stages VMX VMCS/software and SVM
    VMCB/software candidates per frozen vCPU and publishes them at VM-wide
    completion only after all topology checks.  VMX applies each candidate
    before the existing nested-registry transaction and reinstalls every
    exact rollback image if a later VMCS or nested transaction fails.  This
    source-level transaction is not a substitute for the required Intel and
    AMD injected-setter, sparse-vCPU, and repeated live-restore evidence.
90. **Architecture-specific assumption and workaround review.**  Starting
    from all `XXX`, empirical comments, compatibility exceptions, and
    implementation-defined hardware behavior in VMX, SVM, IOMMU, interrupt,
    timer, and checkpoint paths, build a separate requirement-to-code-to-test
    ledger.  The current Intel host does not qualify AMD behavior.  In
    particular, SVM's intercepted-IRET virtual-NMI bookkeeping documents a
    stack/NPT-fault window after the intercept is removed; VMX has a distinct
    SDM-defined interruptibility-state recovery path.  Do not equate the two
    or install a speculative AMD fix.  Require an AMD APM-backed design,
    fault injection, and AMD hardware evidence before claiming equivalent
    NMI semantics.  For each remaining assumption, record architecture
    scope, normative source or explicit policy owner, normal and failure
    behavior, resource bound, save-state impact, and negative/live
    qualification.  Repeat from consumers to definitions after every change.
91. **Current common-record restore review.**  Independently trace the sole
    VMS2 `STRUCT_VM` decoder from VMMDEV's all-vCPU frozen lock through every
    common and architecture-specific vCPU field.  Allocate its bounded private
    wire image, decoded stage, and restore plan before publication; validate
    the complete topology and event ownership before the first write; then
    publish only through the no-fail all-vCPU commit and erase each private
    allocation on every exit.  A late truncation, unknown critical record,
    invalid field, topology change, or occupied event destination must leave
    all peer vCPUs and `startup_cpus` unchanged.  The deleted native-order
    stream is neither selected nor accepted as a fallback.
92. **Reverse current-record and non-standard review.**  Starting at each
    generic live write, startup-bitmap write, stage free, dispatcher edge, and
    compatibility consumer, reconstruct the contract without using phase 91.
    Reject native-layout expansion, pointers, host-time/CPU/page-size leakage,
    partial publication, implementation-derived test oracles, and an
    undocumented reliance on the ioctl's all-vCPU lock.  Compare only
    observable compatibility with KVM/QEMU.  A correction restarts phases 86
    through 92 and requires fresh strict-build, model, installed Intel, fault,
    repeated-restore, Linux/5BSD checkpoint, and soak evidence.
93. **Legacy architecture-exception inventory replay.**  Independently
    inventory every `XXX`, empirical capability condition, compatibility
    filter, and fail-closed feature withholding in VMX/SVM execution.  Record
    whether Intel SDM, AMD APM, an observed compatibility case, or deliberate
    unsupported policy owns it; prove its fallback is conservative and cannot
    leak into portable state.  This currently includes SVM DecodeAssist
    segment attribution, `EFER_LMSLE` withholding, the virtual-NMI IRET caveat,
    and VMX's invalid external-interrupt-information filter.  The Intel host
    does not qualify AMD paths, and a VMware observation is not an Intel-SDM
    requirement.  Every item needs a source marker and independent
    negative/live trace evidence before release.
94. **Privileged nested-qualification runner review.**  Treat the root-only
    L1/L2 orchestrator as part of the release boundary.  Its executed L1
    runner and bhyve binary must be executed through canonical absolute paths
    with root-owned non-group/world-writable parent chains; the wrapper must
    fix its helper `PATH` and private umask before any privileged helper runs.
    Images are operator inputs but their identities and hashes must remain
    stable through the run.  The final work directory must be root-owned mode
    0700; a root-owned sticky ancestor is acceptable only to contain that
    newly created directory, never an executable.  Review
    timeout, signal cleanup, staging-directory scope, immutable evidence,
    run-id binding, policy/input hash checks, and atomic publication.  Add a
    rootless structural guard and retain an installed dry-run/failure test.
    Passing this harness is evidence collection, never automatic feature
    enablement.

Phases 23 through 94 use the same byte-identical sorted source manifest, including
untracked production and test files.  They require fresh build and focused
fault evidence and cannot reuse conclusions from earlier kernel/private
passes.  A production correction discovered by any phase restarts the
affected doubled pair and the final phase 35 through 94 sequence.

The first phases 35/36 replay found that the ordinary vCPU notifier is
intentionally inert while a vCPU is FROZEN.  Startup publication and exact
claim release now advance a separate per-vCPU epoch under the run-state spin
owner before wakeup or IPI delivery.  Its zero, increment, exhaustion, stale,
malformed, and failure-atomic transitions have an independent rootless value
model.  A repeated source walk then found that sampling only after dispatch
could absorb a publication made while the target remained FROZEN.  Entry
admission therefore samples both before and after dispatch, accepts no change
for idle or retained dispatch, and accepts exactly one self-notification for a
consumed claim; every missing or extra transition returns `EAGAIN` before the
handoff is armed.  This epoch and its entry handoff are runtime-only private state: they
are not serialized, exported, audited, or traced while activation is
withheld.  VMX and SVM already provide the later half of the interlock by
disabling interrupts before their final lifecycle checks; the common
`vm_run()` consumer and final backend check remain deliberately absent until
the FPU/state unwind, bounded replay, and installed before/during/after-entry
races qualify the complete path.

The independent phases 37/38 replay then reconstructed the common entry
sequence from `vm_run()`'s critical-section, FPU, and vCPU-state operations
without inserting a live consumer.  The resulting value model represents
critical entry, guest-FPU restore, RUNNING publication, the final coordinator
and notification checks, refreeze, guest-FPU save, and critical exit as eight
separate phases.  Replayable drift and terminal positive errors use the same
unwind; malformed state, reserved fields, negative errors, aliases,
and out-of-order calls fail without modifying the owner or result.  The
second test-quality walk found that result padding and corrupted runtime flags
were not asserted directly; those cases are now explicit.  A mechanical gate
still rejects any reference to this runtime model from common `vm_run()`, VMX,
or SVM.  The repeated-entry extension keeps the guard valid in CHECKED state
so VMX and SVM can revalidate it before every backend-internal hardware entry;
the explicit backend-loop model rejects entry without that fresh check, and a
new publication after an earlier entry forces common replay.  The loop also
owns its validated return disposition, so mutation of a prior guard-result
object cannot redirect common replay or error handling; earlier phases reject
an injected non-normal disposition and finish publishes only to disjoint
storage.  Guard admission and backend return use separate action enums, so
an ordinary VM exit is `RETURN_VMEXIT`, never the guard's `ENTER_GUEST`.  The
strict VMM build and the 287-case rootless model pass with 375 architectural
requirement rows and 212 private-contract rows.  This closes
the dormant model review only; activation still requires explicit approval
and installed before/during/after-RUNNING race evidence.

For Intel nested startup specifically, an allocated VPID02 or deferred VPID02
invalidation is now an explicit activation blocker: INIT may not discard the
nested architectural context until a separately reviewed, consumed,
infallible destination-local VPID release finalizer exists.  VMCS01 lazy VPID
retirement is not that ownership release.

The post-fix kernel phase starts with kernel/user ABI entry points and follows
objects all the way through VMM, VirtIO transport, VSOCK, DMA, interrupt, and
snapshot implementations.  It includes writable sysctls and tunables because
operator policy can race the same counters and ownership state as packet or
vCPU paths.  The first 2026-08-01 pass found exactly such a VSOCK connection
limit race: an unlocked concurrent limit reduction could occur between a
comparison and unsigned subtraction.  Limit and related buffer-policy writes
are now serialized with the VSOCK mutex, while socket creation uses an atomic
coherent policy snapshot.  Kernel `-Werror` and focused connection-cap tests
cover the fix; the installed-kernel stress case remains part of the root live
gate.

The non-standard phase currently includes, at minimum, the legacy bhyve input
and VSOCK PCI identities, `/dev/vsock` provider ABI, bhyve checkpoint and
manifest formats, device-backend identity envelopes, nested-VMX exposure and
VPID policy, and provisional device/backend options.  Modern VirtIO wire IDs
and fields remain sourced only from the independent VirtIO fixture; bhyve
compatibility values have a separate oracle.  Experimental interfaces remain
default-off or unadvertised until their live qualification gates pass.

After the non-standard phase, run a second post-private kernel replay as a
reverse lifetime traversal from teardown and rollback toward attach and
publication.  Then compose the
private interfaces across boundaries: PCI compatibility identity, provider
ABI, authorization, policy, backend identity, checkpoint state, and
experimental feature controls must reject wrong-owner, wrong-generation,
wrong-device, and version-skew combinations without leaking private values
into the independent VirtIO oracle.  Produce fresh compiler diagnostics for
this final source; the first pass's diagnostics and conclusions cannot be
reused.  Any production fix restarts both kernel passes and the non-standard
inventory.  Finally replay the private inventory from consumers and decoders;
the definition-first inventory and composed-boundary result cannot be reused
as that independent evidence.

The first nested-VMX replay under these phases found that VM-wide restore
validated destination-local host VPID ownership only for an active incoming
L2 record.  Final publication now rejects an active owner or pending
invalidation for every incoming vCPU, including inactive records.  Independent
model cases cover empty, pending-flush, and active-owner destinations.  Since
this changes production restore composition, both kernel phases and the
private-boundary phase restart from this source.

The restarted reverse kernel phase also found a non-x86 SCMI polling defect:
sub-two-millisecond positive timeouts performed no probe and a matching reply
on the final probe was misreported as timed out.  The arm64 consumer now uses
a warning-clean, architecture-independent bounded-poll policy helper, and
focused tests cover timeout rounding and final-probe completion.  Its fixed
two-millisecond non-sleeping cadence is private scheduling policy entry 50,
not a VirtIO architectural constant.  This fix again restarts the second
kernel and composed-private-boundary phases.

That same destructor-first replay then found callback drain alone was not a
DMA fence: SCMI P2A buffers could be freed while their descriptors remained
device-owned.  The private transport boundary now closes enqueue admission,
resets and drains all queues, and only then allows the consumer pool to be
freed; restart reinitializes the stopped device.  Callback and initial-buffer
publication failures use the same rollback.  The arm64 objects build with
warnings as errors and the private-interface validator pins the teardown
ordering.  Both kernel passes remain restarted after this production fix.

Continuing the reverse traversal found that failed SCMI enqueues leaked their
unconsumed private PDU, `/dev/vsock` feature updates did not close read/write
admission while draining copies, and direct provider reads did not observe the
checkpoint fence.  It also found the same missing-final-probe pattern in PCI
and MMIO queue-reset and suspend polling.  Those ownership and deadline edges
are corrected and classified as private policies 51 through 53.  Focused
rootless tests, the 223-entry requirements gate, the 53-entry private ledger,
and amd64/arm64 warnings-as-errors object builds pass.  Because these are
production fixes, neither kernel traversal nor private composition is yet
allowed to terminate cleanly.

The continued reverse traversal corrected renewed request deadlines in the
GPU, balloon, RTC, and block guest drivers and an invalid one-wakeup 9P
response predicate.  The machine-checked private ledger now contains 76
entries, including the remaining guest resource ceilings, ownership waits,
socket callouts, boot tunables, runtime policy, and read-only observability
surfaces discovered by the macro/sysctl inventory.  Full device reset and
console module unload deliberately retain unbounded predicate waits because
the current APIs cannot return failure without releasing live DMA or callback
ownership.  Both require explicit fallible revocation contracts before a
bounded deadline would be safe.  These production corrections restart both
kernel traversals and private-boundary composition again.

The fresh final-source compiler replay found one additional configuration
edge: guest-vsock TX-drop metadata existed only in SDT probe arguments, so a
kernel built without `KDTRACE_HOOKS` diagnosed the decoded header as unused.
Both trace and non-trace configurations now compile cleanly without changing
the packet path.  The complete VirtIO module tree, full nested-enabled
`vmm.ko`, focused vsock harness, aggregate rootless device matrix, private
ledger, and nested requirement validators pass on this source.  Root-only
installed-kernel, Linux/5BSD, checkpoint, fault, and soak cases remain
qualification gates rather than inferred passes.

The final review structure is enforced by the requirement validators rather
than existing only as prose.  VirtIO validation requires the independent
forward kernel, non-standard inventory, reverse kernel, and composed-private
passes plus their restart rule.  Nested-VMX validation requires the analogous
four phases.  A pinned Linux KVM/QEMU comparison of the composed nested
checkpoint boundary records one intentional difference: WASPNest currently
publishes only its explicitly reconstructed cold active-L2 continuation and
rejects unsupported run-pending forms, while KVM exposes a broader versioned
nested-state ABI.  Expanding that boundary requires a new requirements entry,
portable representation, destination reconstruction, and live L1/L2 tests;
it cannot be enabled as an undocumented compatibility shortcut.

## Common kernel vCPU state review subphase

Before publishing the versioned replacement for the historical `STRUCT_VM`
record, freeze or generation-snapshot pending exception, NMI, external
interrupt, restart cursor, and architecture collateral as one event-owner
transaction.  Encode common and architecture-specific state in separate VMS2
sections, copy restore bytes into immutable kernel-owned staging, validate all
destination vCPUs before publishing any.  Because none of these private
formats has shipped,
the replacement is the sole accepted encoding: do not append to the old
stream and do not retain a fallback decoder.

Both kernel reviews must exercise asynchronous event arrival at the freeze
boundary.  The non-standard phase separately verifies named-record selection,
unknown critical sections, duplicate and reordered keys, exact-current reader
admission, source-paired private-enum validation, and immutable staging.
Any event-fence, codec, or selection change restarts both kernel traversals and
the private-interface composition pass.

The shared-kernel subphase also owns the wait protocol.  A checkpoint waiter
must prepare a generation ticket before evaluating grouped readiness and then
sleep through a FreeBSD-native predicate/enqueue interlock; publishers advance
that generation and broadcast under the same interlock.  Fixed sleeps,
timeouts used as progress engines, and compare-then-sleep loops are not
accepted.  Cancellation wakes all waiters and a cancellation-bound lifecycle
drain waits without polling until the final registered waiter has returned;
VM teardown must retain the enclosing operation and VM lifetime through that
drain.  Transient owner
and storage cookies are kernel implementation details and must never appear in
VMS2 or another private ABI.

This subphase has already found one surrounding production defect:
`vcpu_set_state_all()` reused the failed iteration's vCPU pointer while
rolling back earlier members.  Rollback now resolves every recorded CPU ID to
its exact vCPU.  Installed-kernel partial-transition fault injection remains
the qualifying test; a successful module build is not substituted for it.

The architecture-neutral coordinator is now attached to every VMM VM
incarnation on amd64, arm64, and riscv, and the amd64 exit-information,
exception, single-vCPU restore, NMI, and ExtINT publishers enter it.  It owns
globally non-reused VM and checkpoint transaction identities, retains a
private strictly ordered vCPU membership list until finish or abort completes,
and unlocks by that retained list even though the value protocol consumes and
zeroes the caller checkpoint.  Its idempotent publisher operation decides
admission versus deferral under one per-vCPU spin lock, avoiding a reopen race
between separate enter and defer calls.  Cancellation closes both forms of
admission and wakes waiters.  The enclosing VM lifetime prevents new API entry
and drains admitted publishers and waiters before destruction.

The amd64 adapter now exposes a versioned, writable, descriptor-owned private
checkpoint session.  It allocates bounded membership storage with `M_NOWAIT`,
uses the coordinator's event-driven ready wait, retains ingress exclusion from
before the first bhyve capture through member and directory `fsync()` plus the
atomic manifest rename, and commits or aborts by an exact nonreused session
identity.  Final descriptor close aborts any retained session before VM
destruction.  Deferred NMI and ExtINT work is merged under the normal pending
event owner and notifies after unlock, including close cleanup where another
controller might already have restarted execution.  The management path does
not resume devices or vCPUs while session ownership is unresolved.

This is production plumbing, not complete VMS2 or migration qualification.
Frozen-vCPU consumer exclusion still depends on the bhyve pause owner, VMS2
record selection remains withheld, and stop-and-copy delivery of events which
arrive after the encoded cut needs a separate live migration-boundary proof.
Those gates must not be inferred from successful session or manifest tests.

Two more independently terminating review phases, Passes 21 and 22, now
follow the existing shared-kernel and private-interface phases.  Pass 21
re-reads the identical final kernel from teardown, interrupt publication, and
allocation-capacity roots with fresh compiler and fault evidence.  Pass 22
rebuilds the non-standard inventory from retained artifacts and installed
consumers, composing every private value with owner, generation, architecture,
backend, authorization, namespace, decoder selection, KPI exposure, and
management errno policy.  A finding in either restarts both; earlier clean
notes cannot be reused, and neither pass may be declared clean while the other
is still reviewing a different source revision.

The identical-source proof uses a sorted manifest containing both modified
tracked files and untracked production/test files in scope.  A diff-only file
list is explicitly rejected because it omits newly created kernel sources.
Manifest membership and per-file hashes are compared before and after the two
passes; any difference restarts Passes 19 through 22.

The doubled kernel review also treats virtual INIT/SIPI delivery as shared VMM
event infrastructure, not an Intel-only shortcut.  The existing
`startup_cpus` mask is a wait-for-SIPI state owner and cannot be reused as proof
that a particular INIT was accepted at a nested instruction boundary.  Add a
generation-bound, architecture-neutral INIT/SIPI event receipt which composes
with nested-entry and reinjection ownership before LAPIC reset or startup-mask
publication.  Intel nested VMX may consume a pending MTF on INIT only through
that receipt.  The value protocol, exact claim, durable target-local resolver,
and pre-reset/pre-destroy architecture cleanup hook now exist.  The resolver
is bound to its exact callback table and vCPU context, is never serialized,
and retains blocked work without polling or releasing its claim.  Runtime
dispatch and mixed L0/L2 completion are still withheld: the production path
must preserve both the current `VM_EXITCODE_IPI` userspace contract and the
legacy `VM_EXITCODE_SPINUP_AP` behavior rather than replacing either with an
Intel-private action.  Until that composition and its live Intel tests pass,
monitor-trap exiting remains unadvertised.

The latest doubled replay extends that boundary through bhyve monitor-process
replacement.  A retained kernel VM cannot keep the old process's prestarted
thread admissions committed after `VM_REINIT`; reset now advances an exact
generation, preserves the immutable owner, and recollects all kernel-owner
threads from canonical storage.  A pointer-free private status value exposes
collecting progress without exposing record pointers.  The consumer-first
private pass found and fixed output aliasing with the live record array.  The
reverse kernel pass then found that a zero return from the shared sleepqueue
wait was incorrectly treated as completed readiness.  Every ordinary or
spurious wake now revalidates the generation ticket and forces the enclosing
startup or checkpoint predicate to replay.  Neither private value is the
future management ABI; its fd ownership, versioned structure, reserved fields,
authorization, and generation-bearing VM_RUN operation remain a separate
four-phase review gate.

For this boundary the four final-source phases are mandatory and distinct:

1. Follow allocation, publication, claim, frozen derivation, side effect,
   release, retry, reset, and destruction forward through kernel ownership.
2. Independently start at final free, coordinator drain, reset rollback, and
   cancellation, and reconstruct every lifetime in reverse.
3. Inventory every FreeBSD-private value and policy, including userspace exit
   compatibility, callback identity, errno, limits, sysctls, serialization
   exclusions, and architecture/backend ownership.
4. Rebuild that inventory from consumers and decoders, then test composition
   across wrong owner, wrong generation, wrong vCPU, copied storage, version
   skew, and mixed L0/L2 destinations.

All four phases must inspect the identical source manifest.  A correction in
any phase invalidates the other three conclusions and restarts the cycle.

The startup-management phase applies the same doubled review before exposing
any ABI.  Its forward kernel traversal follows a file-description-owned claim
through configure, per-vCPU entry, predicate wait, commit, reset, monitor
replacement, and execution.  Its independent reverse traversal begins at
final cdevpriv close, cancellation, checkpoint abort, reset rollback, waiter
drain, and VM free.  Both must prove disjoint output storage, exact generation
and owner identity, idempotent concurrent legacy entry, and a close path that
cannot strand credentials by returning a retryable error from a destructor.

Two non-standard phases then rebuild the inventory.  The definition-first
phase records every private controller identifier, generation, pointer cookie,
phase, errno, bound, and serialization exclusion.  The consumer-first phase
starts from every ioctl, libvmmapi call, bhyve option, VM_RUN variant,
checkpoint decoder, sysctl, audit event, and probe, then traces back to the
private definition.  No historical ioctl may change size or meaning; kernel
startup requires separately versioned management and generation-bearing run
requests.  A finding or new consumer restarts all four phases on one source
manifest.

The first production consumer is deliberately compatibility-only: current
amd64 VM_RUN and VM_RUN_13 select the historical userspace-resume owner before
their first guest entry.  This changes no ioctl number, size, output, IPI
handling, or libvmmapi contract and is idempotent for concurrent vCPU threads
and replacement monitor generations.  It also closes the race in which an
explicit kernel controller could otherwise be claimed after guest execution
had already started.  Kernel-owned startup remains unreachable until the new
management/run ABI and event-driven AP lifecycle complete their own four-pass
review and live qualification.

The prestarted AP execution primitive is now event driven in the amd64 run
loop but remains unreachable from userspace.  It reuses the common
`VCPU_SLEEPING` lifecycle, interlocks the startup predicate with enqueue using
`rendezvous_mtx`, the exact vCPU spin owner, and the sleepqueue chain, and uses
an interruptible indefinite sleep.  Rendezvous, VM suspend, reqidle, debugger,
signals, reset, and destroy therefore retain their existing wake paths; there
is no periodic polling.  An accepted SIPI producer and its Intel/AMD frozen-
target finalizer still must be bound and live-qualified before a management
selector is exposed.

The doubled kernel/non-standard replay subsequently corrected the direct
sleepqueue priority contract, made the run-loop disposition locally defined
before every startup/backend error, and made generation-exact kernel startup
commit safe for concurrent admitted vCPU threads.  These are private kernel
contracts, not new guest features or userspace ABI.  Any cdevpriv, ioctl,
libvmmapi, or bhyve-option consumer still restarts the forward, reverse,
definition-first, and consumer-first phases before exposure.

Prestarted AP admission now publishes its wait-for-SIPI predicate before the
same admission can make the handshake ready.  The VM wrapper holds the
rendezvous owner across the coordinator transaction and performs exact
failure rollback, closing the last-AP/commit race without adding ABI or an
architecture-specific rule to the coordinator.

The startup wait set itself has moved from amd64-private VM fields into common
VM lifecycle state.  Common create/reset owns initialization under the
rendezvous lock.  Non-x86 run-loop consumers remain deliberately withheld
until their architecture-specific startup semantics and live tests exist.

The second kernel pass then closed a reset/admission race in that common
ownership.  Reset now holds `rendezvous_mtx` while advancing the coordinator
generation and clearing the wait set, using the same outer-to-inner lock order
as AP admission.  A replacement monitor can no longer publish a new AP wait
bit between those operations and have it erased.  Failed reset preserves the
old mask.  This private correction adds no ioctl or guest-visible feature and
restarts all four kernel/non-standard review phases.

A narrow common VM boundary now wraps controller claim, release,
configuration, readiness, commit, and status.  It intentionally adds no
userspace ABI and makes no non-x86 execution claim.  Raw coordinator calls are
confined below this boundary; the eventual device-file implementation must
embed the exact credential in cdevpriv storage, lease it without holding an
`sx` across waits, and repeat all four reviews before exposure.

The reverse private-consumer pass found that checkpoint readiness still
forwarded `PCATCH` to a direct sleepqueue API.  Interruptibility is already a
property of the registered sleepqueue entry; snapshot readiness now passes an
ordinary priority, and the shared private wait layer rejects all `_sleep()`
flag bits before direct wait or drain calls.  Signal and generation replay
semantics are unchanged.

Generation-bearing admission now has exact retry semantics for the future run
ABI.  An interrupted vCPU may repeat the same generation and
architecture-derived BSP classification before or after peer commit without
changing counters or waking waiters again.  Any changed classification remains
an error; no user-supplied BSP decision is accepted.

The first cdevpriv integration draft was intentionally withheld: it accepted
an internal BSP boolean and proposed panic-based close rollback.  BSP
classification is now a separate tested architectural value derived only from
virtual IA32_APIC_BASE[8].  A machine-dependent adapter supplies that value
only from an exclusively frozen target vLAPIC, without an ioctl field, vCPU-0
convention, or host-CPU inference.  The adapter is now consumed only by the
private generation-bearing run path after dispatcher freeze and credential
authentication.  Controller close/revocation now erases its already-authenticated
credential without a second stale-generation check or panic-based expected
recovery.  The private management and run ioctls are build-staged, but no
bhyve selector consumes them until the production frozen-target INIT/SIPI
finalizer and installed-kernel lifetime matrix are complete.

The definition-first management slice now includes a fixed-width, versioned,
size-checked private request value for configure, readiness wait, commit, and
status.  It has independent literal layout tests, strict reserved/output-field
validation, operation-specific generation rules, coherent status encoding,
and exact in-place output semantics.  Its assigned private command and
userspace value have compat32 and cdevpriv adapters; installed-kernel dup/fork,
signal, reset, close, checkpoint, and destroy races remain release gates.

The doubled kernel review now pins the generic lifetime underneath the future
controller credential.  Cdevpriv belongs to an open file description, making
dup and fork share one identity and final close the single destruction point.
Forced device destruction drains active methods and all cdevpriv destructors
before returning, and the VMM path invokes it before freeing the VM or event
coordinator.  This is tracked as a private dependency, not a public ABI
promise.  The eventual dispatcher must not retain its per-file `sx` across an
interruptible readiness wait and still requires installed-kernel dup/fork,
close, forced-destroy, active-operation, signal, checkpoint, and reset races.

The run-ABI definition pass also avoids extending the historical `VM_RUN`
native-pointer layout.  A separate fixed 64-byte private request carries a
version, size, signed fixed-width vCPU identifier, exact startup generation,
64-bit output addresses, explicit output sizes, and reserved space.  Its value
tests independently cover 32-bit and 64-bit address limits, overflow,
adjacency, overlap, unknown fields, and exact buffer sizes.  Its assigned
private command is bound to a `struct vcpu` by libvmmapi and authenticates the
file-description controller through cdevpriv.  Bhyve activation remains
withheld until architecture-owned BSP classification is connected to the
production INIT/SIPI finalizer and live signal/reset/close tests pass.

The consumer-first private replay found that withholding only the bhyve option
was insufficient: a direct command-116 caller could otherwise select kernel
ownership while production SIPI still exits to userspace.  The kernel now
returns `EOPNOTSUPP` from `CONFIGURE` before controller claim or mode mutation.
The validator independently requires both this kernel gate and the absence of
all bhyve and non-x86 activation adapters.  Removing the gate restarts the
forward-kernel, definition-first-private, reverse-kernel, and consumer-first
private phases on the completed production finalizer.

The portability replay also found that the assigned private startup commands
and their x86-only live tests were visible from common build surfaces even
though only amd64 supplies the dispatcher and libvmmapi operations.  It then
found that their numbers were unexplained literals rather than reservations in
the owning machine ioctl namespace.  AMD64 now reserves the command names and
wire numbers; the command macros, kernel entry points, and machine-specific
ATF targets are gated on amd64.  Independent ABI tests continue to assert the
literal wire values.  The value protocol and coordinator model remain common
so a future architecture can reuse the mechanism, but arm64 and riscv acquire
no stub command, implied startup policy, or false compatibility promise.
Adding another architecture requires an explicit owner, lifecycle design, and
live qualification and restarts all four review phases.

The doubled kernel gate additionally requires an exact typed INIT/SIPI
finalizer to be bound before capture or any reversible target mutation.  Its
plan is revalidated immediately before the exact pending-event commit and is
consumed before the irreversible callbacks.  Corruption of input, callbacks,
or finalizer storage is a poisoned transaction, never a stale retry reported
as successful rollback.  Production vLAPIC and Intel/AMD callback adapters
remain a release blocker; until they exist, the private kernel-startup
management command fails closed before claiming ownership.

Private, architecture-specific control surfaces receive two reviews beyond
the ordinary kernel lifetime passes: a definition-first inventory and a
consumer/decoder-first reconstruction.  Ioctl numbers have one payload-owned
definition, an explicit architecture namespace reservation, matching
dispatcher and wrapper scope, and literal independent ABI tests.  This rule
also applies to future save-state, IOMMU, nested-virtualization, DTrace, audit,
and migration extensions; no x86-only interface may imply support on a future
non-x86 host.

Staged production adapters receive both kernel traversals and both
non-standard-interface inventories twice: first in isolation, then across the
complete producer-to-teardown path.  Reachability, callback/context identity,
generation, storage cookies, errno semantics, and all behavior outside the
normative specifications must be explicit.  Compiled but unreachable code is
not supported; validators must pin both its fail-closed boundary and the
absence of an activation consumer.

The repeated composition phase must inspect nested transactions rather than
assuming a nonzero inner errno proves rollback.  The shared x86 startup result
is classified as committed, safely rolled back, poisoned, or invalid from its
complete fixed-width tuple.  Intel production execution remains fail closed
until its adapter can return only the proven rollback-safe class and fail-stop
the latter two classes with installed-kernel evidence.

For VM-wide active-L2 restore, the same phase treats both VMCS registry
headers and separately allocated entries, the binding array, workspace
owners, capability records, mutable scratch, and generation outputs as one
ownership graph.  All required disjointness is established before acquiring
the first workspace.  Rollback may not clear a generation when release failed;
the kernel fails stop rather than publishing a false atomic-failure result.

## Doubled kernel and implementation-defined review gates

Every implementation phase, including work that remains deliberately
experimental or unreachable, must end with two additional independent source
reviews before it can advance the roadmap.

1. **Mutation-first kernel replay.**  Start from every live-state write—not
   from a feature checklist—and trace its admission, last fallible operation,
   rollback or cache-retirement rule, reset/detach/restore behavior, and
   independent negative test.  Cover VMM, VMX, SVM, VirtIO transport, queues,
   DMA/IOMMU, interrupts, provider state, and snapshot staging.  Require
   portable wire state to remain distinct from host pointers, compiler
   layout, hardware resources, and derived caches.  This review is repeated
   after each correction with a fresh traversal.

2. **Consumer-first non-standard replay.**  Independently inventory every
   behavior not determined by the VirtIO specification, the Intel/AMD
   architecture manuals, or a public ABI: private ioctls, compatibility
   records, backend choices, limits, allocation policy, timeout/retry rules,
   diagnostics, DTrace/audit/MAC hooks, test controls, unsupported returns,
   and checkpoint compatibility policy.  For each, document authority,
   validation, owner/generation binding, errno, rollback, observability,
   persistence exclusion or explicit encoding, and direct positive and
   negative evidence.  Host policy must not change a negotiated VirtIO rule or
   an architectural VMX/SVM result.

The two replays are separate from the normative conformance, lifecycle,
portability, Linux/QEMU comparison, and test-quality passes.  They apply to
legacy compatibility paths as well as new code: a fixed historical wire
format is not permission to bypass current event ownership or failure-atomic
publication.  A fix restarts both replays and every affected device,
save-state, nested-virtualization, Linux/5BSD activation, checkpoint, and
soak gate.  Rootless source and model evidence remains distinct from the
installed-kernel and live-hardware evidence recorded by the qualification
matrix.

After those two replays, run two short independent closure phases before
declaring a scoped cycle clean:

3. **Withheld-feature/error-domain replay.** Start at every omitted feature,
   explicit unsupported return, capability omission, host gate, and
   implementation-defined errno. Identify the authority, guest-visible
   consequence, state-cleanup rule, persistence treatment, and prerequisite
   for activation. A guest protocol response, management errno, and test-lab
   cancellation are separate contracts even if they share an errno value.

4. **Independent activation-oracle replay.** Re-derive expectations from a
   pinned specification fixture or separately documented private contract,
   never from the bhyve headers being tested. A live feature claim requires
   proof that the Linux or 5BSD driver negotiated and exercised that feature
   on every relevant queue. Model, installed-kernel, and live/soak evidence
   remain separate evidence classes.

5. **Second production-kernel replay.** Independently start at common kernel
   and device-model entries—guest-memory/DMA, interrupts, taskqueues,
   sleep/wakeup, credentials and VNET/prison policy, module lifetime,
   snapshot dispatch, PCI transport, and queue callbacks—and trace the final
   production call graph through success, error, reset, suspend/resume,
   detach, checkpoint, restore, and teardown. For every live-state mutation,
   record its serialization owner, last fallible point, rollback or cache
   retirement, portability boundary, and independent negative test. This is a
   second review, not a re-use of the mutation-first inventory.

6. **Second implementation-defined contract replay.** Independently rebuild
   every behavior not set by VirtIO, an architecture manual, or public ABI
   from accepted operator values, diagnostics/audit/DTrace output, and
   explicit unsupported results. This includes backends/providers, manifests,
   limits, allocation/retry/timeout policy, feature withholding, test-lab
   controls, identity allocation, MAC policy, and architecture gates. Each
   needs authority, validation and authorization boundary, owner/generation,
   version/reserved-field policy, fail-closed or rollback rule, observability,
   portable persistence treatment, and direct positive/rejection evidence. It
   may not change negotiated device semantics, a guest architectural result,
   a common lifecycle invariant, or the evidence classification.

Definition-first and consumer-first review must also reconcile architectural
state with derived execution caches.  For x86 SIPI, a nonzero-vector composed
test must prove the same `vector << 12` entry point reaches CS state and the
common next-run cache; checking either layer alone is not conformance evidence.
