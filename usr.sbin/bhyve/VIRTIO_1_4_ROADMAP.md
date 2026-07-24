# bhyve VirtIO 1.4 implementation roadmap

This roadmap is ordered by deployment value and dependency, not by device ID.
The conformance source is the OASIS VirtIO 1.4 specification.  Independent
wire constants and requirement-to-test mappings live under
`tests/sys/kern/vsock_device_harness`; production headers are not test oracles.

## Current baseline

The modern PCI transport and the existing net, block, console, entropy, SCSI,
input, socket, and 9P devices cover their currently advertised VirtIO 1.4
requirements.  Modern devices negotiate 64-bit features, validate cumulative
status transitions, implement notification data, and selectively implement
queue reset.  Block write-zeroes, socket STREAM/SEQPACKET feature semantics,
and host AF_VSOCK operation are included.

Legacy PCI remains a compatibility path.  New devices should be modern-only
unless the specification defines a transitional identity and a concrete user
requirement justifies the additional interface.

## P0: fleet-safe socket devices

1. Allow concurrent `backend=kernel` providers, indexed by guest CID.
2. Keep provider queues, negotiated features, reset, close, and backpressure
   isolated by CID.  Duplicate CID attachment must fail with `EADDRINUSE`.
3. Include the CID in every provider DTrace event and expose the active
   provider count through `kern.vsock.userspace_providers`.
4. Test two simultaneous providers with different negotiated socket types,
   bidirectional routing, reset/detach isolation, duplicate rejection, and CID
   reuse. The kernel ATF gate covers 1,024 simultaneous provider descriptors;
   `run-alpine-multi-vsock.sh` is the two-bhyve live gate.
5. Add a management-layer CID allocator/lease file for launch tooling.  The
   kernel remains the final duplicate-CID authority.

VirtIO 1.4 defines no additional socket-device feature beyond STREAM,
SEQPACKET, and NO_IMPLIED_STREAM.  Once those and the common ring/transport
features are covered, further VSOCK work is operational: VNET/jail namespace
policy, migration behavior, per-CID rate limits, and longer concurrent-VM
soaks.

## P1: existing-device performance and lifecycle

1. **Network multiqueue and RSS.**  Add the control virtqueue, queue-pair
   negotiation, receive steering, hash reporting, and per-queue reset.  This is
   the largest immediate throughput improvement for multi-vCPU guests.
2. **Block multiqueue.**  Add `VIRTIO_BLK_F_MQ`, independent request queues,
   queue-local quiesce/reset, topology fields, and write-cache configuration.
3. **SCSI multiqueue and events.**  Scale request queues with vCPUs and cover
   hotplug/change events without disturbing unrelated queues.
4. **9P queue reset.**  Refactor lib9p request ownership so a selected queue can
   cancel and drain its own requests without destroying session or fid state.
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
2. **Device suspend.**  Define frozen queue, backend, configuration, and
   in-flight request ownership first.  Integrate it with bhyve snapshot and
   restore; reject the feature until round-trip migration tests pass.
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
