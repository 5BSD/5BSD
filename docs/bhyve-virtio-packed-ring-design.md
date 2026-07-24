# bhyve VirtIO packed-ring implementation plan

Status: design and prerequisite inventory; no feature advertisement

Normative source: VirtIO 1.4 sections 2.8, 4.1.4.3, 4.1.4.4, 4.1.5.1.3,
and 6.

## Safety rule

`VIRTIO_F_RING_PACKED` must not be added to any device capability mask until
the packed engine, PCI queue mapping, reset, notification suppression, and
at least one Linux interoperability test all pass.  A driver is entitled to
use the packed layout immediately after negotiating the bit; advertising an
incomplete implementation is therefore not a compatible staging mechanism.

## Current split-ring dependencies

Device models use a small shared surface:

- `vq_ring_ready()` and `vq_has_descs()` for readiness and availability;
- `vq_getchain()` and `vq_retchains()` for descriptor ownership;
- `vq_relchain_prepare()`, `vq_relchain_publish()`, and `vq_relchain()` for
  completion;
- `vq_endchains()` for interrupt suppression and delivery;
- `vq_kick_enable()` and `vq_kick_disable()` for driver notification
  suppression.

The surface is suitable for a second engine, but its implementation and
`struct vqueue_info` are currently split-specific.  In particular, the
inline availability and kick helpers dereference `vring_avail` and
`vring_used`, and the common completion path publishes a split used index.
Modern PCI currently maps three independently supplied split-ring regions.

## Required queue state

Packed queues need state separate from the split indices:

- driver and device descriptor offsets in the range `[0, queue_size)`;
- driver and device wrap counters, initialized to one;
- mapped packed descriptor array;
- mapped driver-event and device-event suppression structures;
- a completion token that identifies the first descriptor offset, descriptor
  count, wrap generation, and buffer ID from the last descriptor, rather than
  treating a split-ring head index as sufficient;
- an in-flight ownership record for asynchronous completions and queue reset.

The public request token must remain opaque to device models.  Reusing only
the existing 16-bit `vi_req.idx` is unsafe after the same packed descriptor
offset wraps while an earlier asynchronous request is still outstanding.

## Implementation phases

### Phase 1: layout-neutral API

Introduce an explicit queue layout selected only after successful feature
negotiation.  Keep the split engine behavior unchanged.  Move direct
split-ring accesses behind layout operations for:

- readiness and availability;
- descriptor acquisition and rollback;
- prepared and published completion;
- interrupt decision;
- kick suppression;
- queue mapping, unmapping, and reset.

Every existing native, sanitizer, soak, Alpine, and FreeBSD guest test must
remain green before adding packed code.  No feature bit changes in this
phase.

### Phase 2: packed descriptor engine

Implement direct chains first:

- AVAILABLE/USED bit and wrap-counter interpretation;
- NEXT and WRITE handling;
- checked guest-address mapping;
- descriptor-count and aggregate-byte bounds;
- device-readable descriptors preceding device-writable descriptors;
- release publication of used length, id, and flags.

Malformed chains set `DEVICE_NEEDS_RESET` and stop later queue processing,
matching the existing split-ring failure policy.

Then add indirect descriptors.  Packed indirect tables contain sequential
`pvirtq_desc` entries, not split-ring descriptors.  WRITE is the only valid
table-entry flag; the other flag bits and table-entry buffer IDs are reserved
and ignored.  The main descriptor's WRITE bit is also reserved when INDIRECT
is set.  Tables must be feature-gated, bounded, non-nested, and fully mapped
before device access.

### Phase 3: notifications

Implement packed driver-event and device-event structures:

- ENABLE, DISABLE, and DESC modes;
- off_wrap encoding and wrap-aware event arithmetic;
- the required publication and observation barriers;
- notification-data handling without assuming split available indices;
- MSI-X no-vector suppression and queue-reset exclusion.

Tests must cover threshold crossing on both sides of the ring wrap, no-event
and every-event modes, a notification arriving during enable-and-recheck,
and malicious event offsets.

### Phase 4: lifecycle

Full and per-queue reset must:

1. freeze new descriptor acquisition;
2. change the queue generation;
3. cancel or drain every backend user of guest memory;
4. suppress stale completions;
5. clear offsets, wraps, mappings, suppression state, and pending kicks;
6. publish queue-reset completion only after the old generation is quiescent.

Run the existing 4,096-cycle reset soak in both layouts, including
asynchronous completion, full-reset crossings, remapping, and feature
renegotiation.

### Phase 5: opt-in and interoperability

Start with one simple synchronous device, preferably virtio-rng.  Its packed
feature is opt-in while all other devices remain split-only.  Required gates:

- independent VirtIO 1.4 byte-vector and wrap tests;
- ASan/UBSan and TSan;
- native ATF;
- Linux modern-PCI negotiation and bulk I/O;
- device reset/rebind and individual queue reset;
- MSI-X and MSI/INTx paths;
- a sustained run that crosses the wrap boundary many times.

Only then enable a device with asynchronous completions, followed by network
and block after their reset and notification tests pass in both layouts.

## Non-goals

- Packed rings do not imply `VIRTIO_F_IN_ORDER`; advertise it separately
  only where the device completion order is guaranteed.
- Packed rings do not provide DMA isolation and do not justify
  `VIRTIO_F_ACCESS_PLATFORM`.
- Administration virtqueues are a separate facility and cannot reuse an
  incomplete packed implementation as their lifecycle model.
- Legacy PCI remains split-only.  Packed queues require `VIRTIO_F_VERSION_1`
  and are exposed only by the modern transport.

## Acceptance matrix

For each opted-in device, run:

| Axis | Required values |
|---|---|
| Ring | split, packed |
| Interrupt | MSI-X, MSI/INTx |
| Descriptor form | direct, indirect where supported |
| Notification | default, event suppression, notification data |
| Lifecycle | boot, rebind, queue reset, full reset, reboot |
| Guest | Linux; FreeBSD after guest packed support is available |
| Runtime checks | native ATF, ASan/UBSan, TSan, reset soak |

Split-ring results are the regression baseline.  A packed result does not
compensate for a split regression.
