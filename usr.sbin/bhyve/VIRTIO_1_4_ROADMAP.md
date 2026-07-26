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

- modern virtio-net with two queue pairs has not passed its Linux boot gate;
  review found that its control queue did not re-enable driver notifications
  after the first synchronous command when `VIRTIO_F_EVENT_IDX` was
  negotiated.  The repair has a composed Linux-shaped regression, but still
  needs the live two-queue rerun;
- the virtio-net control callback preserves Linux's synchronous command
  progress and EVENT_IDX re-arm semantics, but a guest that continuously
  refills the control queue from another vCPU can keep that callback running.
  A real fairness bound needs an asynchronous control worker or equivalent
  continuation; an arbitrary callback limit would strand descriptors after
  notification suppression and is not an acceptable substitute;
- concurrent kernel-backed VSOCK providers, duplicate-CID rejection,
  per-provider reset/feature isolation, and CID-scoped MACF ownership are
  implemented and covered by source and kernel tests.  They have not yet
  passed the two-bhyve live gate on a kernel built from the current source;
- sanitizer tests do not replace a reset/rebind/reboot soak.  The network RSS
  path now has a real split-ring-parser-to-production-callback test, but that
  test still cannot reproduce every backend, interrupt, and VMM scheduling
  interaction.

Until those gates pass, the affected rows in the requirements catalog must
name the pending live gate instead of citing a generic matrix as evidence.

Legacy PCI remains a compatibility path.  New devices should be modern-only
unless the specification defines a transitional identity and a concrete user
requirement justifies the additional interface.

## P0: fleet-safe socket devices

1. Concurrent `backend=kernel` providers are indexed by guest CID.
2. Provider queues, negotiated features, reset, close, and backpressure are
   isolated by CID.  Duplicate CID attachment fails with `EADDRINUSE`.
3. Provider DTrace events include the CID and
   `kern.vsock.userspace_providers` exposes the active provider count.
4. Test two simultaneous providers with different negotiated socket types,
   bidirectional routing, reset/detach isolation, duplicate rejection, and CID
   reuse. The kernel ATF gate covers 1,024 simultaneous provider descriptors;
   `run-alpine-multi-vsock.sh` is the two-bhyve live gate and remains required
   before this item is accepted.
5. Add a management-layer CID allocator/lease file for launch tooling.  The
   kernel remains the final duplicate-CID authority.
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
   contract.  This work remains provisional until an unmodified Linux guest
   boots with `queues=2`, completes RSS control negotiation, passes traffic,
   reset/rebind, and reboot.  A composed regression now sends Linux's exact
   indirect RSS chain through the real split-ring parser and production
   callback, including the EVENT_IDX decision for the following command.
2. **Block multiqueue.**  `VIRTIO_BLK_F_MQ`, up to eight independent request
   queues, queue-local quiesce/reset, an independent document oracle, and a
   Linux hardware-queue gate are implemented.  Modern devices also implement
   writable `VIRTIO_BLK_F_CONFIG_WCE`, retain the historical writeback reset
   default, and stabilize guest-selected writethrough writes before completion.
   The existing topology fields are already advertised and covered.
3. **SCSI multiqueue and events.**  Modern devices now expose up to eight
   independently resettable request queues with a bounded device-wide worker
   budget and an exact Linux hardware-queue oracle.  HOTPLUG and CHANGE remain
   deliberately unadvertised: correct delivery first requires a loss-aware
   asynchronous CTL subscription for ordered LUN add, remove, and parameter
   changes.  Snapshot polling is not an acceptable substitute because it can
   silently collapse transitions and cannot implement EVENTS_MISSED reliably.
   The recommended REPORT LUNS well-known logical unit is also not implemented;
   the current parser rejects that address before CTL submission, and the
   requirements catalog records this separately from mandatory SCSI command
   handling.
4. **9P queue reset.**  Implemented with generation-fenced asynchronous
   request draining, preserving the lib9p connection and fid state while the
   old queue relinquishes every guest buffer.
5. **Packed virtqueues.**  Implement the common packed-ring engine once and
   enable it per device only after split-ring differential tests, wrap-counter
   tests, indirect descriptors, event suppression, reset, and Linux/FreeBSD
   interoperability pass.
6. **Notification configuration data.**  Implement only after a measured
   notification-path benefit; notification data already removes the important
   queue-index readback.

## P2: isolation and migration foundations

1. **VirtIO IOMMU plus ACCESS_PLATFORM.**  Build an enforceable DMA address
   space in bhyve, implement map/unmap/probe and fault reporting, associate
   endpoints with domains, then permit other devices to negotiate
   `VIRTIO_F_ACCESS_PLATFORM`.  Advertising the bit before all DMA paths use
   the translation is forbidden.
2. **Device suspend.**  The common status state machine, queue-ownership
   fence, notification suppression, deferred configuration notification,
   failure/reset behavior, FreeBSD modern-PCI guest handshake, and checkpoint
   nesting plumbing are implemented.  Virtio-net drains without retaining a
   pthread mutex across vCPU threads; block uses a reference-counted backend
   quiesce owner shared with checkpoint pause; entropy is synchronous under
   the common device mutex.  Checkpoint pause still takes backend
   serialization ownership when guest suspend is already active, and its
   resume path preserves the guest owner.  Vsock now fences the userspace and
   kernel provider event sources, connection relays, listener, and timer for
   both owners and rearms only after the common queue fence opens.  Versioned
   serialization now covers modern common status/features, PCI transport
   latches, split-queue addresses and indices, device state, and restored
   suspend ownership for net, block, entropy, and an idle userspace vsock
   device.  Active userspace vsock sessions return `EBUSY`; kernel-backed
   vsock returns `EOPNOTSUPP` because the provider ABI does not expose its
   connection/socket-buffer state.  Pause failures propagate to the checkpoint
   coordinator.  Per-device pause ownership makes partial walks and resume
   retries safe; vCPUs are not restarted while any backend remains paused.
   AHCI propagates flush failures and rolls back earlier ports.  Snapshot
   memory and state writes handle interruption, short I/O, and zero-progress
   EOF without a polling progress thread.
   A clean snapshot-enabled bhyve build compiles and links, although the option
   remains marked broken by the wider tree.  The next gate is live
   running-device and guest-suspended checkpoint/restore round trips, including
   injected pause, flush, metadata-finalization, and resume failures.  Snapshot
   publication now writes generation-matched memory, kernel/device state, and
   metadata members, fsyncs them, and atomically renames a manifest.  Legacy
   three-file snapshots remain readable.  Parser, replacement, pre-publication
   failure, and post-rename directory-fsync failure cases run in the sanitizer
   harness.  Live round trips and injected device failures remain release
   gates.  Then opt in SCSI, console, input, and 9P only
   after each backend proves in-flight ownership and restart.
3. **Administration virtqueues and device groups.**  Add these only with a
   concrete owner/member lifecycle such as migration or assigned-device
   management.  Unsupported commands, privilege boundaries, and resource
   limits require tests before advertisement.
4. **Shared-memory regions.**  Add the common PCI capability with the first
   consumer (normally virtio-fs DAX or GPU host-visible blobs), including
   overflow-safe BAR placement, revocation, and snapshot semantics.

SR-IOV is not useful for a purely emulated bhyve device and should remain
unadvertised.  ORDER_PLATFORM is not applicable while device and driver share
the guest CPU memory-ordering model.

## P3: modern devices, in implementation order

1. **Traditional memory balloon (device 5).**  Start with inflate/deflate and
   actual/desired page accounting, then statistics, free-page reporting,
   poison, and OOM deflation as independently negotiated features.  FreeBSD
   and Linux already have mature guest drivers, making this the lowest-risk
   new device and a useful overcommit primitive.
2. **File system (device 26).**  Implement non-DAX virtio-fs with a
   sandboxed `virtiofsd`-style backend first.  Add request-queue isolation,
   explicit cache policy, inode/fd limits, and disconnect recovery.  DAX waits
   for shared-memory-region support.
3. **GPU (device 16).**  Implement the 2D command set and scanout/cursor path
   before VIRGL or blob resources.  Reuse bhyve framebuffer output without
   exposing host graphics APIs to unvalidated guest command streams.
4. **Memory (device 24) and PMEM (device 27).**  Memory-device plug/unplug
   needs VM map and migration integration.  PMEM requires a backend with a
   real persistence boundary and explicit flush/error semantics.
5. **Sound (device 25).**  Begin with PCM playback/capture and a bounded host
   audio backend; add controls and channel maps after stream lifecycle,
   underrun, reset, and rate-conversion tests.
6. **Crypto (device 20).**  Implement only algorithms backed by a reviewed
   kernel or userspace crypto provider.  Bound session counts and request
   sizes, zero key material, reject overlapping buffers, and never advertise
   an algorithm whose full error semantics are not implemented.
7. **RTC (device 44).**  A small modern-only device with alarm and clock
   policy tied to bhyve's existing time model.

RPMB, I2C, SCMI, GPIO, CAN, SPI, and media devices need a real host backend or
passthrough use case before implementation.  Stub devices that merely satisfy
driver probing are out of scope.

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
7. A reset/rebind/reboot soak checks bounded fd, memory, thread, and connection
   growth.  Concurrent-device tests prove one device's failure does not reset
   another.
8. Manual pages, configuration schema, DTrace metadata, rate-limited logs, and
   audit behavior are updated before the feature is advertised.
