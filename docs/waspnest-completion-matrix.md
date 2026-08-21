# WASPNest completion matrix

Date: 2026-08-20

This file is the entry point for deciding whether the VirtIO, device,
save/restore, and nested-virtualization work is complete.  Narrative review
documents are historical evidence and must not be used as the source of
current row counts or activation status.

## Authoritative inputs

| Scope | Authoritative ledger |
| --- | --- |
| VirtIO normative and project requirements | `tests/sys/kern/vsock_device_harness/virtio-1.4-requirements.tsv` |
| Linux and 5BSD feature activation | `tests/sys/kern/vsock_device_harness/virtio-feature-activation.tsv` |
| VirtIO implementation-defined interfaces | `tests/sys/kern/vsock_device_harness/virtio-nonstandard-interfaces.tsv` |
| Non-VirtIO device live and save/restore coverage | `tests/waspnest/waspnest-nonvirtio-coverage.tsv` |
| Intel nested-VMX requirements | `tests/sys/vmm/vmx-nested-requirements.tsv` |
| Intel nested-VMX live qualification | `tests/sys/vmm/vmx-nested-live-qualification.tsv` |
| Default-off nested policy qualification | `tests/sys/vmm/vmx-nested-default-policy-live-qualification.tsv` |
| Nested implementation-defined interfaces | `tests/sys/vmm/vmx-nested-nonstandard-interfaces.tsv` |
| Common/Intel/AMD startup-entry edges | `tests/sys/vmm/vmx-startup-entry-edge-matrix.tsv` |

Every activation row must reference an existing requirement row.  Requirement
and feature identifiers must be unique.  The existing validators enforce
those relationships; prose summaries may describe them but may not override
them.

## Current ledger snapshot

These counts are a dated diagnostic snapshot, not an independently maintained
source of truth.

### VirtIO

| Item | Count |
| --- | ---: |
| Requirement rows | 241 |
| `implemented-tested` | 238 |
| `not-applicable` and unadvertised | 2 |
| `unsupported-optional` and unadvertised | 1 |
| Live activation rows | 130 |
| Linux `exercised` | 33 |
| Linux `pending` | 79 |
| Linux `driver-gap` | 5 |
| Linux `not-applicable` | 13 |
| 5BSD `exercised` | 8 |
| 5BSD `pending` | 81 |
| 5BSD `driver-gap` | 38 |
| 5BSD `not-applicable` | 3 |
| Exercised by both Linux and 5BSD | 6 |
| Implementation-defined interface rows | 113 |

The three non-implemented requirement dispositions are explicit and
fail-closed: platform ordering and SR-IOV are not applicable to the emulated
topology, while block secure erase is unsupported because the backend cannot
promise secure-erasure semantics.  None is advertised.

The 2026-08-13 revision reflects this cycle's guest-side additions: five new
5BSD VirtIO guest drivers (virtio-sound, virtio-fs, virtio-mem, virtio-pmem,
virtio-IOMMU, all build- and model-verified) plus block/SCSI multiqueue and
net/transport packed guest work moved thirteen rows from 5BSD `driver-gap`
to 5BSD `pending` with scheduled live cases.  `pending` here is
still-live-only: none of this is `exercised`, because none has passed a live
Intel-host guest run.  Rows whose only remaining 5BSD scenario is a save-state
or packed-lane case with no scheduled 5BSD live lane (for example
`SOUND-SAVE-STATE`, `PMEM-PACKED`) correctly remain `driver-gap`.

#### Guest capability boundary: virtio-mem and virtio-IOMMU

Two of the new 5BSD guest drivers are **protocol-complete but capability-bounded
by the FreeBSD/5BSD kernel**, and must not be counted as guest end-user
features:

- **virtio-mem (guest):** negotiates, plugs/unplugs, and accounts, but does
  **not** online plugged pages into the page allocator — there is no runtime
  `vm_phys_add_seg`/`vm_page_array` growth path.  Defaults to protocol-only
  (`hw.virtio_mem.allow_plug=0`).
- **virtio-IOMMU (guest):** models domains/endpoints/mappings and fault
  reporting, but does **not** drive `busdma(9)` translation for other devices —
  that needs an ACPI VIOT parser plus a `busdma_iommu` back end that do not yet
  exist in-tree.  Disabled by default (`hw.virtio_iommu.enable=0`); the driver
  declines the device unless opted in.

Their value on 5BSD is protocol compliance, host-model validation, and a marked
future seam — not memory hotplug or DMA isolation.  The **useful production
deliverable is the bhyve host-side model** for each: the host presents a
functional virtio-mem device and a functional virtio-IOMMU (with a generated
ACPI VIOT binding) to guests whose OS can consume them, e.g. Linux.  Both host
models are build- and model-verified in this tree; neither is live-qualified.

### Non-VirtIO bhyve devices

| Item | Count |
| --- | ---: |
| Inventory rows | 13 |
| Linux live `exercised` | 0 |
| Linux live `pending` | 12 |
| Linux live `environment-dependent` | 1 |
| 5BSD live `exercised` | 0 |
| 5BSD live `pending` | 11 |
| 5BSD live `driver-gap` | 1 |
| 5BSD live `environment-dependent` | 1 |
| Save/restore `pending` | 13 |

Hostbridge enumeration and LPC serial output from the existing guest boots
remain `pending`: reachability is not distinguishing activation evidence.
AHCI-assisted Alpine ISO boot likewise does not activate the disk, queue,
error, reset, and active-I/O restore contract.  Host model tests exist for AHCI, NVMe, e82545,
HDA, xHCI/USB mouse, framebuffer ownership, UART, TPM CRB, pvpanic, and
qemu-fwcfg, but model evidence is not live guest or active save/restore
evidence.  Passthrough remains environment-dependent for live activation; its
checkpoint cases now require deterministic rejection unless a portable
device-state contract is introduced.
Virtio-sound delivers a supported 5BSD pcm(4) data path.  The in-tree
virtio-fs, virtio-mem, virtio-pmem, and virtio-IOMMU frontends remain explicit
prototypes: they compile, but do not yet provide the required 5BSD filesystem,
memory-onlining, NVDIMM, or downstream busdma integration for live
qualification.

### Intel nested VMX

| Item | Count |
| --- | ---: |
| Requirement rows | 437 |
| `foundation-tested-experimental` | 408 |
| `experimental-pending-live` | 29 |
| `pending` implementation rows | 0 |
| Live qualification groups | 12 |
| Linux-L2 groups passed | 0 |
| 5BSD-L2 groups passed | 0 |
| Default-off VPID qualification groups pending | 1 |
| Implementation-defined interface rows | 282 |
| Startup-entry edge rows | 23 |

The four former `pending` requirements — `NVMX-EVENT-048`, `NVMX-EVENT-050`,
`NVMX-EVENT-058`, and `NVMX-EVENT-102`, covering the kernel-owned INIT/SIPI
completion and event-driven wait-for-SIPI transaction — are now implemented
and model-tested and were re-filed this cycle from `pending` to
`experimental-pending-live` (raising that class from 25 to 29).  The Intel
adapter binds the frozen INIT/SIPI machine transaction; the AMD adapter
remains fail-closed by design; the scope is Intel-only.  This is
implementation-plus-model evidence only: live L1/L2 Intel qualification is
still required.  Nested VMX must remain unexposed until those rows and the
twelve live Intel qualification groups complete.

## Completion states

Every required row must end in exactly one of these states:

1. implemented, advertised where applicable, independently tested, and live
   qualified on every guest/platform claimed by the release;
2. intentionally unsupported or not applicable, with the feature not
   advertised and a negative test enforcing that boundary; or
3. an explicit guest/platform exclusion recorded as release scope, never as a
   silent skip.

`implemented-tested` is rootless implementation evidence.  It does not mean a
live activation row is complete.  Likewise, enumeration or feature-bit
negotiation is not activation evidence unless the guest drives the feature's
distinguishing behavior and the host trace proves that path ran.

## Ordered completion work

1. Reconcile all narrative status documents with these ledgers and remove or
   date-label stale totals.
2. Close common VirtIO infrastructure and its activation rows: packed queues,
   translated DMA/VirtIO-IOMMU, shared-memory regions, device suspend,
   administration virtqueues/device groups, and compatibility manifests.
3. Close existing-device activation and lifecycle rows for net, block, SCSI,
   console, 9P, input, RNG, and vsock.
4. Complete the production contracts and guest scope for balloon, GPU,
   virtio-fs, virtio-mem, PMEM, RTC, and sound.
5. Close all active-I/O, backend-reconstruction, repeated-restore,
   cross-version, combined-device, dirty-log, and migration rows.
6. The kernel-owned INIT/SIPI transaction is now implemented and model-tested
   (rows `experimental-pending-live`); finish the nested-entry ownership
   review, then run the Intel Linux/KVM-L1 and Linux/5BSD-L2 live qualification
   before enabling nested VMX.
7. Repeat the normative, failure-path, concurrency, portability,
   Linux/QEMU-comparison, test-falsification, and maintainability reviews for
   each completed scope.
8. Run the complete world/kernel/package, sanitizer, live guest, checkpoint,
   migration, fault, concurrency, and bounded-soak release gates.
9. Close every non-VirtIO inventory row with named Alpine and 5BSD live cases
   where drivers exist, plus active save/restore or an explicit, tested
   rejection.  A VirtIO-only qualification run cannot satisfy this gate.

## Release gate

The project is complete only when the validators pass and every required live
row is exercised or explicitly excluded by release scope.  There must be no
failed, blocked, silently skipped, `pending`, `experimental-pending-live`, or
unclassified required row, and nested VMX may be exposed only after its
production readiness gates no longer fail closed.
