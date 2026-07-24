# bhyve VirtIO 1.4 implementation validation

Status: active validation record
Specification source: `/tmp/virtio-v1.4.html`
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

## Findings closed during these passes

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
   Real big-endian interoperability requires a suitable platform and is a
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
6. Consider `VIRTIO_F_NOTIF_CONFIG_DATA` only if a device needs opaque
   per-queue identifiers; queue indices remain sufficient today.
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
