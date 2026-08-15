# bhyve VirtIO-IOMMU and ACCESS_PLATFORM design

Status: translation state, feature-gated configuration, request protocol,
queue boundaries, fault events, portable state, modern PCI composition,
requester routing, and ACPI VIOT publication are implemented.  The device is
opt-in as `virtio-iommu`; live Linux and 5BSD qualification remains required.

The normative reference is VirtIO 1.4 Committee Specification 01 section
5.13. Linux is used to identify exercised driver behavior and QEMU only as a
device-model and migration comparison. No reference implementation code is
copied.

## Architecture boundary

`virtio_dma.h` defines only the direction of a DMA operation from the device's
point of view. It deliberately has no PCI, x86, `vmctx`, ring, or native
snapshot dependency.

`virtio_iommu_state.c` owns endpoint registration, domain attachment, IOVA
mappings, permissions, invalidation, and translation. It is a bounded,
mutex-protected model:

- endpoint, domain, and mapping storage have explicit configured limits;
- mappings use inclusive IOVA ends as defined by section 5.13;
- the least significant page-size-mask bit defines alignment;
- overlapping MAP operations are rejected atomically;
- UNMAP removes only complete mappings and never partially mutates on error;
- detach and final-domain destruction remove access to all domain mappings;
- translation authorization is linearized under the state lock, then the
  external GPA mapper runs without that lock; a concurrent UNMAP prevents
  later translations but does not invalidate guest RAM already pinned for an
  active device request;
- an optional platform validator rejects physical ranges that are not valid
  RAM or intentionally allowed MMIO before a mapping is published;
- faults enter a bounded oldest-first queue with explicit loss accounting,
  and short guest event buffers do not consume a pending fault;
- the optional fault callback runs after unlocking to avoid callback lock
  inversion;
- the checksummed `VIMS` record transactionally restores endpoints, domains,
  mappings, ordered faults, configuration identity, and generation;
- no host pointer, mutex, native structure, file descriptor, host page size,
  or Intel-specific state is part of the wire state.

The common VirtIO queue engine routes descriptors, indirect tables, and ring
mappings through `vi_map_dma()`. Payload and indirect-table mappings are
request-scoped. Enabled queue rings are longer-lived, so a revocable domain
also publishes a monotonic translation generation. The split and packed ring
paths compare that generation before every public ring operation and remap all
three ring areas as one bounded transaction after a change. Pointers are
committed only when one generation spans all mappings; revocation or
continuous mutation fails closed with `NEEDS_RESET`. Every installed domain
must provide a generation callback (a static domain may return zero). Devices
without an ACCESS_PLATFORM domain retain the zero-overhead cached direct-DMA
path.

Device-private guest-memory accesses must use the same operation. Before
ACCESS_PLATFORM can be offered, the PCI composition must install an
endpoint-specific mapper backed by this state and an audit must prove that no
device bypasses it.

The common engine has a per-device DMA-domain binding.  Binding is allowed
only before a modern device starts initialization, advertises
`VIRTIO_F_ACCESS_PLATFORM` only after the endpoint mapper is installed, rejects
live rebinding, and leaves interrupt and RAM-discard operations on the original
platform interface.

The PCI post-initialization phase now enumerates the complete topology before
guest execution, rejects multiple IOMMUs, registers every modern VirtIO
requester, binds its common DMA boundary, and only then offers
`VIRTIO_F_ACCESS_PLATFORM`.  Legacy and non-VirtIO PCI functions are not
claimed.  This ordering is independent of command-line PCI slot order.

`virtio_iommu_viot.c` builds the architecture-neutral payload for ACPI VIOT
revision 1.  It publishes a separate PCI-range node for each explicitly
protected requester rather than claiming unrelated PCI functions, and rejects
duplicate endpoints and the IOMMU's own requester ID.  Firmware publication
appends this payload to a revision-zero ACPI table header, as required for the
first VIOT table format revision, after final PCI requester IDs are known.

The PCI device is modern-only, uses device ID 23, has request and event
virtqueues, gates MAP/UNMAP and PROBE requests on negotiated features, and
wraps the transactional `VIMS` codec in bhyve's versioned snapshot stream.
IOMMU request, fault, translation, configuration, and topology DTrace probes
provide observability without enabling hot-path logging.

## Remaining enablement gates

1. Run the Linux `iommu-modern` and `iommu-packed-modern` cases.  They verify
   PCI identity, `virtio_iommu` binding, packed negotiation, IOMMU-group
   membership, and `VIRTIO_F_ACCESS_PLATFORM` on every configured endpoint;
   the ordinary device tests then prove network and block traffic through
   translated DMA.
2. Run `checkpoint-iommu-modern` and
   `checkpoint-iommu-packed-modern`.  Generic phased PCI restore now restores
   the IOMMU fabric before endpoint queues regardless of PCI slot order.
   Restored queues explicitly discard destination-local generation-cache state
   and revalidate against the restored fabric before first use.
3. Add a live fault-injection case and a supported non-Linux guest once that
   guest has a VirtIO-IOMMU driver.  The present 5BSD image does not provide
   one, so it must not be counted as IOMMU qualification.
4. Repeat the complete endpoint DMA audit whenever a new VirtIO PCI device is
   registered.

The current Intel host is the first live qualification target. The translation
model and state format remain architecture-neutral so arm64 or another bhyve
host can supply its own GPA mapper and interrupt plumbing.
