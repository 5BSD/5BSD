# bhyve: Virtio 1.4, VM State, and Nested Virtualization Architecture

Status: design proposal
Target: FreeBSD/5BSD `bhyve` and `vmm`
Primary architecture: amd64, with interfaces that do not prevent later arm64 work

Current nested-virtualization implementation target: Intel VMX on the
available Intel qualification host.  Shared lifecycle, validation,
guest-memory, interrupt, DMA, and save-state interfaces must remain
vendor-neutral.  AMD SVM is a later hardware-qualified backend; Intel-only
VMCS fields and instructions must not leak into the portable state ABI.

The active-L2 restore transaction treats a software VMCS registry as an
owning aggregate rather than only its fixed header.  Destination-local MSR
plan, rollback, and generation storage must be disjoint from every registry
entry allocation on both sides of the publication exchange.  One bounded
registry-owned overlap predicate is shared by portable checkpoint encoding
and restore validation, and malformed registry bookkeeping fails closed
before any workspace is acquired.

## Purpose

This document describes a clean architecture for three related projects:

1. Bring bhyve's implemented Virtio devices into conformance with Virtio 1.4
   and add the features that matter most to real guests.
2. Turn the existing experimental checkpoint code into a versioned save,
   restore, and eventually live-migration framework;
3. Add nested virtualization without putting VMX or SVM policy into
   userspace.

The projects should be implemented in that order. Virtio needs an explicit
quiesce and state contract before its devices can be saved reliably. Nested
virtualization needs its own versioned state before an L1 VM running an L2 can
be saved or migrated.

The design uses Linux, QEMU, and KVM as behavioral references, not as code to
copy mechanically. The FreeBSD locking, VM object, pmap, device-model, and
kernel/user ABI boundaries are different.

## Scope and effort

These are engineering estimates, not elapsed Codex compute time. They assume
one experienced kernel/virtualization engineer directing Codex, prompt access
to Intel and AMD test hosts, Linux and FreeBSD guests, automated crash
recovery, and continuous review. Codex can substantially reduce time spent
writing repetitive code and tests; it does not remove the time needed to
interpret architecture manuals, diagnose hardware-only failures, review
security boundaries, or run long stress matrices.

| Deliverable | Estimated work | Likely calendar time with one primary engineer and Codex |
|---|---:|---:|
| Virtio 1.4 audit and conformance for devices already in bhyve, including lifecycle, queue reset, negative tests, and modern/legacy parity | 12–20 engineer-weeks | 3–5 months |
| Packed rings, net/block multiqueue, and the high-value optional features in this document | 12–20 additional engineer-weeks | 3–5 additional months |
| New balloon and non-DAX virtio-fs device models | 12–24 additional engineer-weeks | 3–6 additional months |
| Robust same-host checkpoint/restore with a versioned format and converted core devices | 20–32 engineer-weeks | 5–8 months |
| Cross-release compatibility, dirty logging, and production pre-copy migration | 20–36 additional engineer-weeks | 5–9 additional months |
| Correct, hardened nested virtualization for one CPU vendor | 40–70 engineer-weeks | 10–18 months |
| A second CPU vendor after the common ABI and tests exist | 25–45 additional engineer-weeks | 6–12 additional months |

The ranges include design, implementation, tests, documentation, review, and
fault-injection work. They do not include every Virtio 1.4 device, post-copy
migration, DAX migration, Hyper-V compatibility, or every optional VMX/SVM
capability. Adding people helps most with independent device conversions and
test infrastructure; it helps less with the serial core of the state ABI and
nested-exit design.

## Current tree baseline

### Virtio

bhyve currently implements these Virtio PCI devices:

| Device | Implementation |
|---|---|
| Network | `usr.sbin/bhyve/pci_virtio_net.c` |
| Block | `usr.sbin/bhyve/pci_virtio_block.c` |
| SCSI | `usr.sbin/bhyve/pci_virtio_scsi.c` |
| Console | `usr.sbin/bhyve/pci_virtio_console.c` |
| Entropy | `usr.sbin/bhyve/pci_virtio_rnd.c` |
| 9P transport | `usr.sbin/bhyve/pci_virtio_9p.c` |
| Input | `usr.sbin/bhyve/pci_virtio_input.c` |
| Vsock | `usr.sbin/bhyve/pci_virtio_vsock.c` |
| Balloon | `usr.sbin/bhyve/pci_virtio_balloon.c` |
| GPU 2D | `usr.sbin/bhyve/pci_virtio_gpu.c` |
| Filesystem | `usr.sbin/bhyve/pci_virtio_fs.c` |
| IOMMU | `usr.sbin/bhyve/pci_virtio_iommu.c` |
| Memory | `usr.sbin/bhyve/pci_virtio_mem.c` |
| RTC | `usr.sbin/bhyve/pci_virtio_rtc.c` |
| Sound | `usr.sbin/bhyve/pci_virtio_snd.c` |

The common split-ring implementation is in `usr.sbin/bhyve/virtio.c` and
`virtio.h`. Modern PCI transport support is in
`usr.sbin/bhyve/virtio_pci_modern.c`.

The modern transport exposes `VIRTIO_F_VERSION_1` and allows device models to
opt into `INDIRECT_DESC`, `EVENT_IDX`, `NOTIFICATION_DATA`, and `RING_RESET`.
Queue reset has a common generation-fenced lifecycle and device-specific
quiesce callbacks for every existing bhyve Virtio model.  The split-ring core
implements both EVENT_IDX directions, including the arm-and-recheck race
closure exercised by Linux control queues.  A provisional VirtIO-IOMMU,
VIOT topology, per-request DMA lease, and common ACCESS_PLATFORM mapper now
exist, but endpoint devices remain gated on end-to-end live translation
qualification.  The modern PCI transport has a tested shared-memory
capability builder and immutable restore topology.  The optional VirtIO-GPU
blob aperture is its first production consumer: sparse BAR accesses are
resolved through a bounded handler, hold the common device-private DMA lease,
and reject an unbound alias without hiding another valid capability for the
same BAR bytes.  Transport-neutral administration, resource, device-parts,
group, and SR-IOV lifecycle foundations exist but are intentionally
unadvertised until a real PCI owner/member model and administration
virtqueues consume them.  A common packed-ring engine is implemented behind
explicit modern-device opt-in, including indirect descriptors, event
suppression, ordered asynchronous completion, queue reset, and versioned
cursor/wrap state.  It remains disabled by default until the full Linux and
5BSD live qualification matrix passes.

Device feature depth is uneven. For example:

- virtio-net has a control virtqueue, one through eight RX/TX pairs,
  multiqueue, RSS, hash reporting, MTU enforcement, and backend-qualified
  checksum/segmentation offloads;
- virtio-blk has flush, topology, indirect descriptors, one through eight
  request queues, write-cache configuration, optional discard, and bounded
  single-segment write-zeroes;
- virtio-scsi has a working command path but advertises few optional features;
- console, RNG, 9P, input, and vsock have modern transport coverage, the
  common reset lifecycle, and fixed-width versioned save/restore contracts.
  Live checkpoint cases remain mandatory because source serializers cannot
  prove external-backend reconstruction or event-source rearming.

### Save and restore

There is already a checkpoint implementation:

- `usr.sbin/bhyve/snapshot.c` and `snapshot.h`;
- `sys/amd64/vmm/vmm_snapshot.c`;
- snapshot hooks in `lib/libvmmapi`;
- kernel snapshot hooks in VMX, SVM, LAPIC, IOAPIC, PIC, PIT, HPET, PM timer,
  and RTC code;
- device callbacks in PCI emulation and a subset of device models.

It is disabled by default with `MK_BHYVE_SNAPSHOT=no`. Its manual page
explicitly says that the format is unstable. The current format consists of a
memory file, a `.kern` file, and JSON metadata containing offsets into raw
serialized data.

The current checkpoint publication manifest is version 3.  It identifies the
source architecture and a machine ABI before naming the atomically published
data, kernel, and metadata members.  The current machine ABI is
`bhyve-virtio-v3`.  The ABI changed when the AMD kernel snapshot gained a
versioned VM header and nested SVM state.  Restore accepts the current
manifest and machine ABI by default.  An explicit
`checkpoint.restore_abi_v2` destination setting also admits the v0.1.0
`bhyve-virtio-v2` machine ABI through its legacy record decoders; that path
has v0.1.0 hello/topology wire fixtures and a full rootless v1 session model
which checks both opt-in rejection and successful commit.  The
`tests/sys/kern/vsock_device_harness/cross_release/run-v010-interop.sh`
gate also compiles the actual v0.1.0 source state machine from its release
tag and verifies both pre-quiesce rejection without opt-in and a complete
socketpair handoff with opt-in to the current destination.
It still needs a release-produced VM checkpoint fixture and live-VM
qualification.  Unknown manifest
versions, unknown architectures, and architecture/machine mismatches are
rejected.  This is an initial
compatibility gate, not
the final migration header described below.  The metadata device-section list
and kernel-state section lists are also now treated as exact compatibility
manifests: restore rejects empty or duplicate names and any missing, changed,
or extra source/destination section before publishing that class of state.
Device ordering may differ because fabric restore phases deliberately reorder
publication.

Versioned basic metadata also records the exact guest-visible NUMA identity:
each memory-domain size and each vCPU-to-domain assignment.  Its canonical
fixed-width text codec is independent of host byte order and word size.
Restore validates the complete tuple transactionally before guest memory is
allocated or ACPI affinity is published.  Destination host domain-set policy
remains a local allocation choice and is not serialized as guest identity.
The complete NUMA tuple is mandatory; absent, partial, or unknown-version
metadata fails closed.  Live multi-domain checkpoint/restore remains a release
gate.

New checkpoints also record a canonical, architecture-tagged CPU contract.
On amd64, bhyve asks the kernel for the CPUID values its guest emulation
actually exposes instead of executing host CPUID in userspace.  The
introspection form removes mutable OSXSAVE and x2APIC execution state,
canonicalizes the current-size XSAVE field, and derives both Intel topology
leaves 0x0b and 0x1f from the configured guest topology.  Separate fixed records bind the
maximum XCR0/XSAVE policy, configured x2APIC mode, guest-visible TSC
frequency, and, when nested VMX is enabled, exact virtual-VMX capability and
portable VMCS-schema signatures.  When nested SVM is enabled, the contract
also records that policy, the nested snapshot schema version, and whether the
host can restore virtual-NMI state.  Restore compares the complete mandatory
contract after platform policy is configured and before any vCPU runs;
absent, malformed, or partially encoded contracts fail closed.  The initial policy is
an intentionally conservative exact match.  Future named CPU models or TSC
scaling must introduce an explicit compatibility policy instead of
reinterpreting these records.

The kernel checkpoint session fixes the set of vCPUs while holding the VM's
vCPU topology lock.  Creating a previously absent vCPU during that session
returns `EBUSY`, including from another VM descriptor.  Once the session
aborts or commits, vCPU creation can proceed.  This keeps the source CPU
set identical through memory, event, and architecture-state capture.

The remaining architectural limitations are:

- the top-level format is still explicitly experimental, although new VirtIO
  records have per-device magic/version fields and fixed-width little-endian
  encoding;
- older non-VirtIO records remain closely coupled to C structure layout;
- the initial machine ABI is a single exact-match identifier rather than a
  user-selectable, versioned machine type;
- the compatibility manifest now includes exact guest-memory granule,
  low/high GPA geometry, an exact architecture-tagged CPU baseline, and a
  canonical whole-machine topology seal.  Per-section feature requirements
  and backend reconstruction remain explicit device contracts rather than
  being collapsed into that immutable topology seal;
- no dirty-memory API for incremental checkpoints;
- no stream abstraction for migration;
- backend identity validation is device-specific and still needs fault and
  cross-version fixtures for every backend.

The existing implementation is valuable scaffolding, but should not become
the permanent external format.

### Nested virtualization

The design began from a tree with no nested-virtualization implementation.
The current Intel branch now contains an experimental, default-off nested-VMX
path: a software VMCS12 registry, VMX instruction emulation and architectural
failure publication, VMCS01/VMCS12-to-VMCS02 composition, nested EPT and VPID
ownership, exit reflection, interrupt/timer/TSC composition, versioned nested
state, and active-L2 freeze/rebuild/thaw transactions.  Exposure requires both
the boot-time `hw.vmm.vmx.nested=1` policy and explicit per-guest
`x86.nested_vmx=true`.

VPID/INVVPID is additionally isolated behind the boot-time
`hw.vmm.vmx.nested_vpid=1` qualification tunable.  It remains off by default
even when nested VMX is enabled.  The virtual policy requires host VPID and
INVVPID single-context support, then exposes all four architectural INVVPID
types because each is conservatively implemented by invalidating the one
destination-local effective VPID02 context.  This mirrors the Linux/KVM
architecture without copying its implementation: virtual capabilities describe
the model, while host capabilities need only support the primitive actually
executed.  Saved capability signatures bind the setting, so a destination
which omits the qualification tunable rejects VPID-bearing nested state.

That code is not release-qualified merely because its rootless architectural
models and kernel build pass.  The remaining Intel gates are real VMX
execution with Linux/KVM as L1, both Linux and rebuilt-5BSD L2 guests,
instruction and VM-entry failure comparison against the pinned Intel SDM,
interrupt/APIC/timer/EPT/VPID/invalidation and exit-reflection evidence,
active-L2 save/restore, repeated create/destroy, concurrency, fault, and soak
runs.  The `nested` virtio-lab profile records those as distinct evidence
groups and refuses to infer a pass from a generic boot.

AMD SVM now has a private VMCB02 and NPT02 run path, a frozen L2 exit
handoff, VMCB12 exit reflection, and a versioned active-L2 checkpoint format.
Exposure requires the boot-time `hw.vmm.svm.nested=1` policy and the per-guest
`x86.nested_svm=true` setting.  Each vCPU's exposure policy freezes on its
first run and at the architecture checkpoint boundary.  It remains default-off pending hardware
qualification of L0-only exits,
virtual interrupts, NPT12 translation, and active-L2 restore.  VMCB02
composition rejects any L0 control intercept without a known L2 exit handler
before L2 can run.  The ordinary AMD guest CPU model hides
SVM in CPUID and intercepts EFER reads to hide the host-required SVME bit;
attempts to enable guest SVME fail closed.
SVM checkpoint restore validates required VMCB intercepts and destination-owned
NPT and bitmap roots before publication, then discards source ASID and VMCB
cache state.  Nested restore rebuilds a destination-local VMCB02 and NPT02;
its active-L2 round trip still requires live qualification.

### Remaining live qualification gates

Run these only with a matching installed kernel, `vmm` module, bhyve binary,
and test programs.  A rootless model pass or a module link does not replace a
guest run.  Keep the nested SVM and kernel startup opt-ins off for ordinary
guests until the corresponding hardware evidence passes.

| Area | Required live evidence |
| --- | --- |
| AMD nested SVM | On AMD hardware with DecodeAssists, run installed `run-svm-nested-atf.sh` with `POLICY_ONLY=1` on a default-off policy boot and with `hw.vmm.svm.nested=1` before loading `vmm` on the enabled boot.  Retain its Kyua database and host hashes.  It runs `vmm_run_live_test` cases for L2 I/O, L0/L1 exit ownership, NPT12 faults and device access, IRQ/NMI delivery, CR8, MSRs, virtual GIF, and active-L2 checkpoint.  Its `svm_l2_npt12_readonly_alias` case proves L2 can read and execute an L0 read-only boot-ROM alias while a write permitted by L1 fails as an L0 paging error without changing ROM bytes.  It then unmaps that L0 page and remaps another object at the same GPA; L2 must execute the replacement bytes instead of a stale NPT02 alias.  On the enabled boot, run `run-svm-nested-live.sh` with a reviewed Linux/KVM L1 driver and pinned Linux and 5BSD L2 images.  Its `svm-nested-live-qualification.tsv` ledger requires 12 feature groups and 36 run-bound guest or host artifacts; missing or malformed evidence cannot publish a result.  Keep the sealed result, host hashes, guest logs, and ATF database together. |
| Intel nested VMX | Run `tests/sys/vmm/run-vmx-nested-live.sh` with a reviewed `NESTED_L1_RUNNER`, pinned L1 and both L2 images, and a private `WORKDIR`.  Retain its complete evidence directory, including VM entry failures, EPT/VPID invalidation, interrupts, active-L2 restore, and soak results. |
| Versioned checkpoint | Restore a checkpoint produced by the pinned v0.1.0 release binary into a fresh destination with `checkpoint.restore_abi_v2` enabled; verify the default rejection without opt-in.  Run `tests/sys/kern/vsock_device_harness/cross_release/run-v010-interop.sh` first for the rootless release-source session gate, then capture an actual release-produced VM fixture and verify guest state after resume. |
| Active 9P | Under the destination's configured export policy, checkpoint and restore open regular files and directory reads while guest requests are in flight.  Exercise changed inode, changed export, stale fid, partial reply, failed restore, and a successful continuation without duplicate or lost responses. |
| Active vsock | With `checkpoint.migrate_active_vsock=true` and the same `migration_endpoint_id` on both userspace backends, migrate STREAM and SEQPACKET connections with buffered data in both directions, EOF/half-close, timer expiry, queue reset, pre-commit rollback, and release cutover.  Verify one runnable VM and one endpoint owner at every failure boundary.  The operator-supplied migration stream carries live endpoint data and must be secured by the operator.  A failed handoff after one-shot descriptor transfer leaves the source usable but those connections cannot be exported again.  Active kernel-provider handoff remains unsupported. |
| TPM | Use the separate storage, key, guest traffic, and fault-injection procedure in `docs/bhyve-tpm-checkpoint.md` for both disk checkpoint and live migration. |

These gates are pending on this host: the current user cannot load the module
and `/dev/vmm` is absent.  Building packages does not authorize installing an
upgrade or rebooting to run them.

## Design principles

1. **Separate architecture from compatibility.** Internal structures may
   evolve; externally saved state and guest-visible behavior must be
   versioned.
2. **Separate Virtio core, transport, ring, device, and backend.** A device
   must not know PCI BAR layout, and a ring engine must not know block or
   network semantics.
3. **Save semantic state, not process state.** Never serialize pointers,
   mutexes, condition variables, host file descriptor numbers, or raw C
   structs as an external ABI.
4. **The kernel owns nested hardware virtualization.** Userspace selects a
   policy and saves/restores an opaque, versioned state object. It must not
   synthesize VMCS02/VMCB02 on every exit.
5. **Every asynchronous component has a quiesce contract.** Reset,
   checkpoint, device removal, and process exit must share the same lifecycle
   rules.
6. **Features require tests before advertisement.** A feature bit is not
   enabled merely because Linux negotiates it.
7. **Fail closed on compatibility.** Restore must reject an incompatible CPU,
   machine type, device topology, backend, or required state section before
   running a vCPU.

---

# Part I: Virtio 1.4

## Which devices are used most

There is no universal public deployment telemetry, so this is an engineering
priority based on common server, cloud, appliance, and development workloads.
Desktop-oriented deployments change the relative importance of GPU and input.

### Priority 0: required for a credible server VM

1. **virtio-net** — primary high-performance network device.
2. **virtio-blk and virtio-scsi** — primary storage paths. They overlap, but
   both are widely used: blk for simple disks and SCSI for multiple LUNs,
   hotplug, and SCSI semantics.
3. **virtio-console** — boot, emergency access, agents, and named guest/host
   channels.
4. **virtio-rng** — early-boot entropy and unattended provisioning.

For this tree, **virtio-vsock also belongs in Priority 0** because it is the
control plane for the automated guest tests and is useful for host/guest
agents without configuring guest networking.

### Priority 1: common operational features

5. **virtio-balloon** — a bounded traditional balloon, statistics queue, and
   free-page reporting model are implemented; Linux/5BSD pressure and live
   checkpoint qualification remain.
6. **virtio-fs** — a modern PCI model and authenticated, reconnectable backend
   protocol are implemented without DAX. Existing Virtio 9P remains for
   compatibility. Production daemon, namespace, live restore, and soak gates
   remain; DAX waits for a shared-memory consumer contract.

### Priority 2: workload dependent

7. **virtio-gpu** — a bounded provisional 2D resource/scanout model exists;
   production display integration and live Linux/5BSD qualification remain.
8. **virtio-input** — keyboard, pointer, tablet, and automated input.
9. **virtio-iommu** — the provisional PCI model, topology, translation,
   invalidation, fault, and state foundations exist. It remains a release
   gate because every endpoint DMA path must be proven translated before
   `VIRTIO_F_ACCESS_PLATFORM` is advertised.

### Lower initial priority

Sound and memory now have bounded provisional devices, and RTC has a baseline
clock/alarm device, because identified test consumers exist. Crypto, pmem,
CAN, GPIO, I2C, SCMI, RPMB, SPI, media, and Bluetooth remain consumer-driven.
Implementing every device in the specification is not necessary to claim
conformance for the devices bhyve actually exposes.

## Which features matter most

### Common transport and ring features

| Priority | Feature | Reason |
|---|---|---|
| P0 | `VIRTIO_F_VERSION_1` | Mandatory foundation for modern devices |
| P0 | `VIRTIO_F_INDIRECT_DESC` | Reduces descriptor pressure for block, SCSI, and network I/O |
| Done | Complete `VIRTIO_F_EVENT_IDX` | Both interrupt and available-buffer notification suppression are implemented and tested |
| Done | `VIRTIO_F_RING_RESET` | Lets Linux recover or reconfigure one queue without resetting the entire device |
| P0 | Correct `DEVICE_NEEDS_RESET` behavior | Required fault containment for malformed rings and backend failure |
| P1 | `VIRTIO_F_RING_PACKED` | Better cache behavior and lower ring overhead at high I/O rates |
| Done | `VIRTIO_F_NOTIFICATION_DATA` | Modern queue notifications carry and validate queue notification data |
| P1 | `VIRTIO_F_IN_ORDER` | Useful when a backend can guarantee ordered completion |
| P2 | `VIRTIO_F_ACCESS_PLATFORM` | Needed with a virtual IOMMU; must not be advertised before DMA translation exists |
| P3 | Admin virtqueue/device-resource features | Valuable for advanced management and scalable devices, but not before core queue lifecycle is complete |

`RING_RESET` should precede packed rings. It forces the design to define queue
ownership, cancellation, and in-flight completion correctly, which is also
needed for snapshots.

### virtio-net

Implement in this order:

1. control virtqueue and RX-mode/MAC commands;
2. multiple queue pairs (`VIRTIO_NET_F_MQ`);
3. MTU and status/config-generation correctness;
4. checksum and host/guest TSO where supported by the selected backend;
5. mergeable RX buffers;
6. RSS and hash reporting;
7. guest-offload control and rate limiting.

The backend interface in `net_backends.c` should report capabilities rather
than letting the device model assume that netmap, tap, and slirp have identical
offload behavior.

### virtio-blk

Implement in this order:

1. retain the passing Linux-guest bounded write-zeroes persistence matrix;
2. multiqueue;
3. write-cache configuration;
4. capacity-change notification;
5. secure erase only when the backend can provide the promised semantics.

Flush completion must mean that the selected backend has honored the requested
durability boundary. A file, zvol, raw disk, and network block backend may have
different guarantees.

### virtio-scsi

Priorities are multiqueue, hotplug/change events, correct task-management
responses, bidirectional requests when supported, and complete residual/sense
reporting. Protection information should wait for CTL and backend end-to-end
support.

### console, RNG, vsock, input, 9P, balloon, and fs

- console: multiple named ports, emergency write, queue reset, and
  reconnectable backends;
- RNG: request cancellation and deterministic quiesce;
- vsock: STREAM and SEQPACKET lifecycle, credit correctness, queue reset,
  native-provider state policy, and connection limits;
- input: config selection, event/status queue reset, and host-device
  disconnect behavior;
- 9P: keep compatibility and harden reset/quiesce; do not grow it into a
  replacement for virtio-fs;
- balloon: stats, free-page reporting, poison, and well-defined interaction
  with saved memory;
- virtio-fs: start without DAX. DAX complicates dirty tracking, revocation,
  and migration and should be a later feature.

## Retained production-qualification backlog

Passing the model harness does not remove any item in this section.  A feature
is production-qualified only when its advertised path has independent
normative tests, negative and lifecycle tests, and a real guest-driver
activation result.  Linux and 5BSD results are recorded separately; discovery
or feature negotiation alone is not activation evidence.

### Common infrastructure

- Qualify split and packed rings on every supported device with indirect
  descriptors, event suppression, notification data, selective queue reset,
  wrap boundaries, malformed and looping chains, MSI/MSI-X, interrupt
  suppression, and checkpoint at significant cursor states.
- Route every DMA operation through the architecture-neutral mapper.  An
  endpoint may advertise `VIRTIO_F_ACCESS_PLATFORM` only after request,
  configuration, event, and indirect-table traffic have all been observed
  through translated mappings.
- Complete VirtIO-IOMMU endpoint attach/detach, permissions, map/unmap,
  invalidation, bounded fault reporting, active-DMA concurrency, and
  checkpoint/restore.
- Retain shared-memory regions, device suspend/resume, administration
  virtqueues, device groups, and feature-compatibility manifests as common
  infrastructure.  Do not replace them with device-local save-state
  exceptions.
- Keep portable state independent of host endianness, pointer width, page
  size, native structure padding, file descriptors, and x86-only interrupt or
  DMA representations.

### Existing devices

- Network: activate every configured queue in Linux and 5BSD; qualify RSS and
  hash-report failures, active queue-local reset, repeated active-I/O restore,
  translated DMA, and concurrent traffic/reset soak.
- Block: activate multiqueue in both guests; qualify discard, write-zeroes
  boundaries, WCE transitions, backend identity/replacement, active restore,
  packed rings, and translated DMA.  Secure erase remains off until a backend
  can guarantee secure-erasure semantics.
- SCSI: activate multiqueue in both guests; add ordered HOTPLUG/CHANGE events
  and loss-aware `EVENTS_MISSED` only with a trustworthy CTL inventory source;
  qualify LUN races, active-command checkpoint, backend identity, packed
  rings, and translated DMA.
- Console: qualify multiple active ports, guest/host close races, blocked I/O
  queue reset, backend reconnect, packed rings, and active-port restore.
- 9P: version 6 records rebind quiescent active fids by root-relative path,
  numeric credentials, open mode, and device/inode/type identity. An explicit
  matching share ID permits mount-path and device-number rebinding. Open
  directories carry an ordered prefix hash and either a 9P2000.L entry index
  or classic Tread packed-stat byte position; restore reconstructs and verifies
  both. Version 2 empty-fid records and later qualified formats remain readable.
  Qualify active-request drain, reset during requests, reconnect, path
  confinement, packed rings, long fid soak, and cross-host credential mapping.
- Input: qualify active event restore, configuration-change delivery,
  saturation/drop policy, reset during injection, multiple devices, and
  packed rings.
- RNG: qualify source failure, reset/rebind soak, packed Linux/5BSD operation,
  and a restore policy which never replays entropy bytes.
- Vsock: qualify active userspace and kernel backend reconstruction, multiple
  providers, CID collision/destination validation, namespace/VNET policy,
  per-CID limits, connection migration policy, packed rings, and concurrent-VM
  soak.

### New and provisional devices

- Balloon: qualify statistics, free-page reporting, poisoning,
  pressure/OOM recovery, invalid/duplicate PFNs, packed rings, and active
  restore in real Linux and 5BSD drivers.
- GPU 2D: add a production presentation backend and qualify resource/backing,
  scanout, EDID, cursor, rectangles, saturation, reset, active restore, packed
  rings, and translated DMA.
- Virtio-fs without DAX: finish the sandboxed backend service, FUSE validation,
  credentials and namespace confinement, cancellation, reconnect, object
  lifetime, active restore, and Linux live operation.  DAX waits for qualified
  shared-memory regions; 5BSD requires a real guest driver.
- Virtio-mem: qualify Linux plug/unplug, busy and partial requests, alignment,
  changed destination capacity, active restore, and packed rings.  A 5BSD
  claim requires a guest driver which actually changes memory ownership.
- Virtio-RTC: qualify alarms across forward/backward clock steps, suspend,
  missed-alarm prevention, repeated restore, Linux activation, and a future
  5BSD driver.
- Virtio-sound: introduce a bounded asynchronous production audio backend
  before adding playback/capture ownership, underrun/overrun, and active-PCM
  policy beyond the current null backend.  Qualify Linux packed operation; a
  5BSD claim requires a real driver.

Virtio-crypto is conditional on a concrete acceleration or isolation
workload.  Virtio-video requires a production media backend, and Virtio-SCMI
belongs to an ARM/platform-management milestone.  These devices start with a
normative ledger and backend contract; placeholder PCI functions are not a
completion metric.

## Clean Virtio architecture

The target structure is:

```text
device model (net, blk, scsi, vsock, ...)
        |
        v
virtio device core: status, features, config generation, lifecycle
        |
        +----------------------+
        |                      |
split-ring engine       packed-ring engine
        |                      |
        +----------+-----------+
                   |
             transport ops
                   |
          PCI modern / PCI legacy
                   |
            PCI interrupt layer

device model <----> typed backend contract (net, block, fs, ...)
```

### Common device lifecycle

Replace implicit flags with a documented state machine:

```text
RESET
  -> ACKNOWLEDGED
  -> DRIVER
  -> FEATURES_OK
  -> DRIVER_OK
  -> QUIESCING
  -> DRIVER_OK or RESET

Any running state -> NEEDS_RESET on an unrecoverable device/ring error.
Each queue: DISABLED -> ENABLED -> QUIESCING -> DISABLED/BROKEN.
```

Rules:

- a queue kick is ignored until the device is `DRIVER_OK` and that queue is
  enabled;
- reset and quiesce prevent new backend submissions before waiting for
  existing requests;
- every backend request has a cancellation or drain rule;
- a queue generation number invalidates callbacks from an earlier reset;
- config-generation changes and config interrupts are centralized;
- a device cannot advertise a feature without a validation and apply hook;
- restore recreates transport/ring state before device-specific workers run.

### Interfaces

Evolve `struct virtio_consts` into three explicit operation sets:

```c
struct virtio_device_ops {
        uint64_t (*get_features)(void *);
        int      (*validate_features)(void *, uint64_t);
        int      (*set_features)(void *, uint64_t);
        void     (*queue_kick)(void *, uint16_t);
        int      (*quiesce)(void *, enum virtio_quiesce_reason);
        int      (*resume)(void *);
        void     (*reset)(void *);
        const struct bhyve_state_desc *state;
};

struct virtio_transport_ops {
        int  (*queue_enable)(struct virtio_queue *);
        void (*queue_disable)(struct virtio_queue *);
        void (*queue_interrupt)(struct virtio_queue *);
        void (*config_interrupt)(struct virtio_device *);
        const struct bhyve_state_desc *state;
};

struct virtio_ring_ops {
        int  (*pop)(struct virtio_queue *, struct virtio_chain *);
        int  (*push)(struct virtio_queue *, struct virtio_chain *, uint32_t);
        bool (*should_interrupt)(struct virtio_queue *);
        int  (*validate)(struct virtio_queue *);
        const struct bhyve_state_desc *state;
};
```

Names are illustrative. The important boundary is that device code consumes a
validated `virtio_chain`; it must not walk raw guest descriptors itself.

### File-level changes

| Area | Proposed change |
|---|---|
| `usr.sbin/bhyve/virtio.h` | Define device, queue, ring, transport, quiesce, and state interfaces |
| `usr.sbin/bhyve/virtio.c` | Retain device lifecycle and feature negotiation; remove split-ring-specific walking |
| new `virtio_ring_split.c` | Move current split-ring parsing, validation, event-index, and completion |
| new `virtio_ring_packed.c` | Add packed-ring implementation after split-ring conformance |
| `usr.sbin/bhyve/virtio_pci_modern.c` | Modern PCI register/capability transport; queue reset is complete, notification data remains |
| new `virtio_state.c` | Common Virtio core, transport, and ring state descriptors |
| `pci_virtio_*.c` | Adopt validated chains, common lifecycle, typed backend quiesce, and device state descriptors |
| `iov.c` | Keep generic iovec helpers; reject overflow, loops, and direction errors before device dispatch |
| `pci_emul.c` | Integrate device quiesce/state registration without Virtio-specific knowledge |

Do not create separate copies of device logic for legacy and modern PCI.
Legacy should be a transport shim over the same core and split-ring engine.

## Conformance method

Create a machine-readable requirements inventory from the Virtio 1.4
conformance clauses. Each applicable `MUST`, `MUST NOT`, and relevant `SHOULD`
maps to:

- implementation location;
- positive test;
- negative or malformed-input test;
- Linux/QEMU interoperability case;
- unsupported/not-applicable justification.

Tests should have four layers:

1. **Ring unit tests:** wraparound, event suppression, indirect descriptors,
   packed descriptors, malformed loops, overflow, and queue reset.
2. **Device-model tests:** real bhyve source with mocked guest memory and
   backend fault injection.
3. **Kernel/guest interoperability:** current Linux drivers, FreeBSD drivers,
   modern/legacy, MSI-X/MSI/INTx where applicable.
4. **Differential tests:** feed equivalent valid and invalid transactions to
   bhyve and QEMU and compare externally visible behavior where the
   specification permits a single result.

Run generated boundary-case sequences through the descriptor parser and
configuration-register state machine. Those are the highest-value
guest-controlled interfaces.

## Virtio implementation phases

1. **Done:** freeze a requirements matrix for the devices currently exposed.
2. **Done:** route layout-neutral device requests through the common split
   and packed queue interface.
3. **Done:** implement the queue/device lifecycle and `RING_RESET`.
4. Complete Priority 0 device features and conformance.
5. **Done for existing devices:** add versioned Virtio state and
   modern-transport restore; cross-release migration remains a later gate.
6. **Implemented, live qualification pending:** add packed rings and
   notification data.
7. **Traditional balloon implemented, live qualification pending:** add
   balloon, then virtio-fs without DAX.
8. **Foundation implemented, exposure pending:** VirtIO-IOMMU,
   ACCESS_PLATFORM, shared-memory capabilities, administration commands,
   resources, device parts, groups, and SR-IOV lifecycle.  Keep all of these
   unadvertised until a production consumer and its live negative,
   checkpoint, and cross-guest qualification gates exist.

---

# Part II: Versioned VM Save, Restore, and Migration

## Goal

One state framework should support:

- stop-and-copy checkpoint to a file;
- restore on the same machine;
- restore after a compatible kernel/userland update;
- streaming state to another bhyve process;
- iterative pre-copy migration;
- eventually, post-copy or storage migration if there is a demonstrated need.

Do not create separate file formats for checkpoint and migration.

## State framework architecture

```text
                 bhyvectl / management service
                            |
                     checkpoint request
                            |
                    bhyve state coordinator
                  /           |             \
             vCPU/kernel   device registry   memory stream
                state       and backends     + dirty bitmap
                  \           |             /
                   versioned state stream
                  file, pipe, or network fd
```

### State coordinator

Replace the global callback scan in `snapshot.c` with a registry. Every state
owner registers:

- stable section name;
- instance identifier;
- current and minimum loadable version;
- required/optional flags;
- dependencies;
- `prepare`, `quiesce`, `save`, `load`, `resume`, and `abort` operations.

The coordinator topologically orders sections. For example:

- PCI bus state loads before PCI function state;
- Virtio transport loads before Virtio core/rings;
- Virtio core loads before device-specific state;
- backend recipes validate before device workers resume;
- nested vCPU state loads after ordinary architectural registers but before
  the vCPU can run.

### External state format

Use a canonical little-endian binary stream with bounded, checksummed
sections. JSON/UCL may be emitted by an inspection tool, but should not be the
authoritative format.

Top-level header:

- magic and format major/minor;
- architecture;
- machine-type identifier and version;
- VM UUID;
- source ABI/build information for diagnostics, not equality checks;
- guest physical page size and memory-map digest;
- CPU model/baseline identifier;
- device-topology digest;
- stream features;
- header checksum.

Each section:

- stable UTF-8 name or numeric registered ID;
- device instance ID;
- schema version and minimum reader version;
- required/optional flags;
- payload length with a configured maximum;
- checksum;
- dependency list or ordering class.

Memory is a sequence of address/length chunks with flags for zero, raw,
compressed, or referenced storage. The format must work without seeking so it
can be sent over a socket.

Unknown optional sections are skipped. Unknown required sections, unsupported
versions, duplicate required sections, overlapping memory chunks, integer
overflow, and excessive sizes are rejected before vCPU execution.

### Machine types

Introduce an explicit machine type for the sole current development ABI, for
example:

```text
bhyve-x86_64-v2
```

A machine type freezes:

- chipset and firmware-visible layout;
- PCI slot/function topology rules;
- default Virtio transport and feature set;
- interrupt-controller behavior;
- CPUID/MSR baseline;
- timer semantics;
- state-schema compatibility defaults.

After the first release, a later bhyve release can add a new machine type
without silently changing the virtual hardware of an old saved VM.  Before
that release there is no reason to retain the superseded development type.

### CPU compatibility

Do not save "host CPU" as an opaque promise. Define named CPU baselines and
record:

- exposed CPUID leaves;
- guest-writable architectural MSRs;
- XSAVE layout;
- TSC frequency/scaling requirements;
- required VMX/SVM host capabilities;
- microarchitecture-sensitive mitigations that affect guest ABI.

Restore validates that the destination can provide the same virtual CPU
contract. For same-host checkpoints, a host-passthrough mode may be allowed
but must be marked non-migratable.

## Quiesce protocol

Use a transaction:

1. **Prepare:** validate all devices/backends and allocate save buffers while
   the VM still runs.
2. **Block new work:** close device submission gates and bump queue/backend
   generations.
3. **Stop vCPUs:** rendezvous every active vCPU at a kernel-confirmed boundary.
4. **Quiesce:** drain or cancel asynchronous device and backend requests.
5. **Capture:** save kernel, device, backend recipe, and memory state.
6. **Commit:** fsync as requested, write final manifest/checksum, and atomically
   publish the checkpoint.
7. **Resume or terminate:** reopen submission gates, or destroy only after a
   successful committed checkpoint.

On any error before commit, call `abort` in reverse order and resume the exact
pre-checkpoint VM. The present `vm_checkpoint()` flow should be changed so
that partially created files are never mistaken for a valid checkpoint.

Lock order and callbacks must guarantee:

- no vCPU can enqueue new device work after step 3;
- no backend callback can mutate saved state after its quiesce completes;
- no pause callback waits while holding a lock required by a worker being
  drained;
- reset and checkpoint use the same device lifecycle primitives.

## What state to save

### Kernel/vCPU

Save architectural guest state and semantic virtual-controller state:

- general, control, debug, segment, descriptor-table, and FPU/XSAVE state;
- pending exceptions, interrupts, NMI, interrupt shadow, and event injection;
- LAPIC, IOAPIC, PIC, PIT, HPET, PM timer, RTC;
- TSC offset/scaling and guest-visible time epoch;
- VM memory map and protection state;
- nested VMX/SVM state when enabled.

Do not expose raw host VMCS, VMCB, pmap, callout, or kernel pointer layout as
the file ABI. The kernel should translate between its internal representation
and versioned state records.

### PCI and Virtio

Save in layers:

1. PCI configuration, BARs, MSI, and MSI-X table/PBA state;
2. Virtio PCI transport registers and config generation;
3. Virtio core status and negotiated features;
4. ring type and queue configuration/index/wrap/event state;
5. device-specific guest-visible state;
6. backend reopen recipe and semantic state.

QEMU documents the same core/transport/device split for Virtio migration. It
is the right boundary for bhyve as well.

### Backends

Host file descriptors are not state. Save recipes and validate them:

- block: stable object identity, size/generation, read-only mode, cache mode,
  and durability boundary;
- tap/netmap: interface identity and required capabilities; in-flight packets
  may be drained or dropped according to a documented policy;
- slirp: either serialize its full network stack or mark the backend
  non-migratable;
- console: endpoint recipe and guest-visible buffered data;
- RNG: no entropy-pool contents; save only device/ring state after requests
  drain;
- 9P/virtio-fs: export identity and security policy; reopen path handles under
  the destination's policy;
- vsock: the userspace backend has a bounded active-connection state codec,
  capture, one-shot descriptor handoff to a standby relay owner, and
  destination reconstruction after the device restore.  It is explicitly
  enabled with `checkpoint.migrate_active_vsock=true` on both VMs and requires
  matching `migration_endpoint_id` values.  The relay starts only after
  RELEASE; any pre-commit failure cancels the standby owner before source
  rollback.  The setting remains off by default pending live qualification.
  One-shot transfer prevents exporting the same connection again after a
  failed handoff.  The kernel provider still freezes only with empty queues
  and no active AF_VSOCK connections; active kernel-provider handoff remains
  unsupported.
  For the empty kernel backend, freeze the destination provider, replay the
  restored device-feature epoch while it remains fenced, and thaw only after
  that replay succeeds.  A feature or thaw failure retains the fence for a
  safe retry; restoring bhyve's feature field without reconstructing the
  provider is not sufficient.

### Storage consistency

Saving VM RAM does not make the backing disk consistent by itself. Support
three explicit modes:

1. **External stable storage:** flush and record backend identity.
2. **Coordinated ZFS snapshot:** quiesce virtual disks, create ZFS
   snapshots/clones, and record immutable dataset GUIDs.
3. **Application-consistent:** notify a guest agent to freeze filesystems or
   applications before the VM transaction.

Never imply application consistency from a crash-consistent memory checkpoint.

## Dirty memory and live migration

Add a generation-based dirty logging API to `vmm` and `libvmmapi`:

```text
VM_DIRTY_ENABLE(range, generation)
VM_DIRTY_READ(generation, bitmap)
VM_DIRTY_CLEAR(generation, bitmap)
VM_DIRTY_DISABLE(generation)
```

The actual ioctl names can differ. Required properties:

- page-granular bitmap;
- no lost write between reading and clearing a generation;
- range validation and bounded allocation;
- interaction defined for wired memory and MMIO;
- EPT and NPT implementations with the same userspace contract;
- counters for dirty rate and pages copied.

Pre-copy:

1. enable dirty logging;
2. send all memory while vCPUs run;
3. repeatedly send pages dirtied in the previous generation;
4. stop vCPUs when dirty rate or iteration limits reach policy;
5. quiesce devices and send final dirty pages plus machine state;
6. validate and atomically activate the destination;
7. destroy the source only after destination acknowledgement.

Post-copy should not be part of the initial design. It introduces remote page
faults and a failure mode where neither endpoint has a complete VM.

## File-level state changes

| Area | Proposed change |
|---|---|
| new `usr.sbin/bhyve/state.[ch]` | Registry, schemas, section stream, transaction coordinator |
| `usr.sbin/bhyve/snapshot.c` | Become a compatibility frontend and checkpoint command implementation over `state.[ch]` |
| new `usr.sbin/bhyve/migration.[ch]` | Pre-copy protocol and transport, after file restore is stable |
| `usr.sbin/bhyve/pci_emul.[ch]` | Register PCI bus/function state owners and dependency order |
| `usr.sbin/bhyve/virtio*.c` | Register separate core/transport/ring state sections |
| `usr.sbin/bhyve/*backend*` | Add capability, quiesce, reopen, and migratability methods |
| `lib/libvmmapi` | Versioned VM/vCPU state and dirty-log APIs |
| `sys/amd64/include/vmm_dev.h` | Stable ioctl envelopes with size/version fields |
| `sys/amd64/vmm/vmm_snapshot.c` | Translate internal state to versioned semantic records |
| EPT/NPT and VM memory code | Dirty logging and generation handling |
| `bhyvectl` or a management daemon | Inspect, validate, checkpoint, restore, and migration status |

Once the new framework covers the supported matrix, remove the
`BHYVE_SNAPSHOT` compile-time condition and make checkpoint support a normal
runtime capability.

## Save/restore acceptance tests

- save at every boot phase: firmware, kernel boot, idle, and heavy I/O;
- modern and legacy Virtio;
- MSI-X, MSI, and INTx;
- queue reset concurrent with checkpoint request;
- block writes and flushes across repeated restore cycles;
- network traffic with loss accounting;
- timers, wall clock, monotonic clock, and TSC behavior;
- SMP with vCPU hot/idle states;
- malformed, truncated, duplicated, reordered, and oversized state sections;
- reject every superseded development state version.  Until the first
  published checkpoint ABI, restore accepts only the exact current schema;
- backend identity mismatch and changed disk size;
- forced allocation, write, fsync, and destination-acknowledgement failures;
- 100+ repeated checkpoint/restore cycles under INVARIANTS and sanitizers.

---

# Part III: Nested Virtualization

## Boundary between bhyve and vmm

Nested virtualization belongs primarily in the kernel:

- VMX/SVM instruction semantics;
- VMCS12/VMCB12 validation;
- construction of hardware VMCS02/VMCB02;
- combined EPT/NPT translation;
- L2 exit routing;
- interrupt/event injection;
- nested TLB invalidation;
- nested state serialization.

bhyve userspace owns:

- `nested=off|on` configuration;
- virtual CPU model selection;
- policy limits;
- diagnostics and statistics;
- save/restore orchestration;
- tests that launch L1 and L2.

The default remains `nested=off` until the implementation is hardened.

## Common kernel architecture

Add a small vendor-independent nested layer for lifecycle and ABI, not for
pretending that VMX and SVM are the same:

```text
vmm core
  |
  +-- nested capability/policy
  +-- nested state get/set
  +-- common L1 memory access helpers
  +-- nested statistics and tracing
  |
  +-- Intel nested_vmx: VMCS12 -> VMCS02
  |
  `-- AMD nested_svm: VMCB12 -> VMCB02
```

Suggested common files:

- `sys/amd64/vmm/vmm_nested.c`;
- `sys/amd64/vmm/vmm_nested.h`;
- versioned state definitions in an amd64 machine header;
- API wrappers in `lib/libvmmapi`.

Extend `struct vmm_ops` with operations such as:

- query nested capabilities;
- enable/disable nested mode before first vCPU run;
- get/set nested vCPU state;
- invalidate nested translations;
- report whether L2 is active.

Do not add one generic structure containing a union of every VMCS and VMCB
field to ordinary vmm state. Keep vendor-defined state opaque above the
versioned ABI envelope.

## Intel VMX design

Add `sys/amd64/vmm/intel/nested_vmx.c` and `.h`.

Per vCPU maintain:

- VMXON state and guest physical address;
- current VMCS12 pointer;
- canonical software VMCS12;
- launch state;
- VM-instruction error;
- nested MSR capability values;
- L1 host state and L2 guest state;
- pending L2 events;
- EPT12/VPID state;
- derived VMCS02 cache and generation.

### VMCS12 and VMCS02

VMCS12 is the architectural VMCS visible to L1. It must have a stable software
layout independent of the host CPU's physical VMCS layout.

VMCS02 is the real hardware VMCS used by L0 to run L2. It is derived from:

```text
L0 safety/mandatory controls
        +
L1-requested controls allowed by virtual VMX capability MSRs
        +
L2 guest state from VMCS12
```

L1 must never be able to clear an L0-required intercept, select host physical
addresses, access L0 MSR/I/O bitmaps, or escape L0's EPT.

Implement VMX instructions in the kernel:

- VMXON/VMXOFF;
- VMPTRLD/VMPTRST/VMCLEAR;
- VMREAD/VMWRITE;
- VMLAUNCH/VMRESUME;
- INVEPT/INVVPID;
- capability and fixed-bit MSRs.

Each instruction must implement privilege checks, VMfailValid/VMfailInvalid,
RFLAGS results, error numbers, alignment, physical-address width, and revision
ID checks.

Shadow VMCS is an optimization after the software VMCS12 path is correct.

The software guest page walker now translates cold L2 addresses through
EPT12, including nonidentity mappings.  A denied walk replaces the pending
L0 emulation continuation with an EPT exit to L1.  When EPT12 resolves a
data access to an L1 device address, the EPT handoff retains cold L2 state
and invokes the ordinary instruction emulator with the translated address.
No-fault inspection probes EPT permissions without writing EPT accessed or
dirty bits.

## AMD SVM design

The AMD implementation is split across `svm.c` and the
`sys/amd64/vmm/amd/nested_svm_*.c` helpers.  The helpers cover VMCB admission,
composition and writeback, L1 memory access, intercept policy, and NPT12
translation.

The current `nested_svm_policy.c` supplies a bounded, copied VMCB12 view and
VMRUN admission checks for guest physical ranges, intercepts, ASID, paging
state, CR3 and debug-register reserved bits, EFER MBZ bits, event type,
reserved event-injection bits, and supported exception
vectors.  The SVM exit loop stages VMRUN, VMLOAD, and VMSAVE
until the vCPU is frozen; `nested_svm_memory.c` then accesses the L1 guest
physical VMCB page.  `nested_svm_aux.c` transfers only the VMLOAD/VMSAVE
fields.  The frozen handoff fetches the intercepted instruction and applies
its effective address size to AX/EAX/RAX, including the 67h override.  A
valid VMRUN now stages a private VMCB02 and selects it, its NPT02 pmap, and a
separate ASID for the next CPU-bound entry.  L2 exits reach a frozen handoff:
NPT12 denials and L1-requested intercepts can be written back to VMCB12,
while an NPT02 miss can populate a 4 KiB alias and retry L2.  Known L0-owned
L2 exits are handled or reported without reflecting them to L1; an unhandled
L0-only exit fails closed.  Live AMD qualification remains pending.
`VM_CAP_NESTED_SVM` is opt-in, requires the boot-time
`hw.vmm.svm.nested=1` host policy, and requires host DecodeAssists for L2 CR8
instruction emulation.  The root-gated
VMRUN, intercept reflection, virtual-GIF, and active-L2 checkpoint tests
still need execution on a host running the new module.  CPUID gates
the SVM bit and feature leaf on that capability, and bounds an exposed
guest's MAXPHYADDR to 47 bits to match the private NPT02 root.  VMCB, NPT12,
and VM_HSAVE_PA address checks use the same bound.  VMCB12 admission and L1
bitmap lookup ignore bits 11:0 of IOPM/MSRPM base fields, as AMD hardware
does; checkpoint writeback retains L1's original field values.
Unlike Intel's VM-wide nested-VMX CPU-model switch, the SVM capability is a
per-vCPU virtual MSR and CPUID state.  `bhyve` applies `x86.nested_svm=true`
to each vCPU it creates, including later APs.  The per-vCPU capability and
saved exposure bit preserve that model on restore; mixed exposure through a
different VMM client is an explicit per-vCPU configuration, not a VM-wide
promise.
The NPT12 walker now resolves 4 KiB, 2 MiB, and 1 GiB leaves, accumulates
permissions, and prepares accessed/dirty updates.  A frozen adapter commits
those updates with compare-and-swap and can install a 4 KiB alias in an
L0-owned NPT02 pmap.  VMRUN prepares that root; L2 NPF dispatch now walks
NPT12, reflects L1 denials, and maps successful translations.  With NPT12
disabled it maps L2 physical addresses directly to L1 physical addresses.
If L1 changes an NPT12 entry during all bounded A/D commit retries, L2
refaults on its next entry rather than poisoning the vCPU.
An NPT02 alias allocation failure returns ENOMEM after replaying any
interrupted event, so the caller can retry the still-active L2 later.
The current root covers the lower LA48
half-space.  The four-level walker rejects L2 physical addresses at or above
48 bits and checks every source entry during its A/D commit.  It derives the
L1-visible NPF error code from an NPT12 denial, including present and
reserved-bit status, and gives reserved huge-page bits precedence over a
simultaneous permission denial.  The backend
must discard cached NPT02 aliases when L1 requests a TLB flush through
VMCB12 TLB_CONTROL or changes the nested ASID.  L1 is responsible for
requesting that flush after changes to its NPT translations, as specified by
the AMD64 Architecture Programmer's Manual, volume 2, section 15.16.1.
An L1 bitmap reader and exit policy now determine whether an I/O, MSR, or
other intercepted L2 exit was requested by L1 rather than forced by L0;
the frozen L2 exit path consults it before reflecting to L1.  A VMCB02 composition helper
copies L2 state while replacing L1 hardware pointers and ASID with L0-owned
values, preserving L0 safety intercepts and taking the VMLOAD auxiliary fields
from L1's live VMCB01.  It excludes L0's temporary VINTR and IRET intercepts
from L2 while retaining those requested by L1.  It clears pause-filter fields
because the nested CPUID
profile does not advertise that facility.  L1 and L2 now have separate ASID
and pmap-generation bookkeeping.  The staged VMCB02 keeps ASID zero until a
CPU-bound L2 entry path allocates its real ASID.  The CPU-bound run loop now
selects that ASID and VMCB02 when L2 is active.  A frozen writeback helper now copies
the VMRUN/#VMEXIT state and exit fields from VMCB02 to L1's VMCB12 while
preserving the VMLOAD/VMSAVE fields and guest-supplied control pointers.  It
keeps LBR state in VMCB12 only when L1 enabled LBR virtualization.  The
helper is invoked for L1-owned L2 exits.  L0's L1-only single-step intercepts
for PUSHF, POPF, and traced exceptions are omitted from VMCB02.  It retains
L0's machine-check and breakpoint exception controls, while L1's own
intercepts remain active.  Rare L0-only instruction exits without an L2
handler fail closed.
When L1 clears `V_INTR_MASKING`, L0 traps L2 CR8 reads and writes while
running VMCB02 with physical interrupt masking enabled.  Reads use L1's
virtual APIC TPR; writes update both that TPR and L2's `V_TPR`.  L1-requested
CR8 intercepts still take precedence and reflect to VMCB12.
The live AMD suite includes a 32-bit alternate-encoding CR8 check for both
TPR copies; it still requires the matching kernel on AMD hardware.
L0-only CPUID now uses L2's CR4 for the OSXSAVE bit.  Ordinary nonstring
L2 port I/O that L1 did not intercept now reaches the existing port handler
or userspace device model with L2 register and segment access, after
validating the I/O size and nRIP.  Unintercepted L2 HLT and PAUSE follow
the ordinary L0 halt and pause paths and leave L2 ready to resume at nRIP.
Unintercepted string I/O reaches the ordinary L0 string exit path with or
without NPT12.  Userland string emulation calls `VM_GLA2GPA` and
`vm_copy_setup`; the backend translates L2 page-table and data addresses
through NPT12 before any guest-memory access.  An NPT12 denial reflects an
NPF to L1 and stops the current string operation.  The ordinary AMD checkpoint
field walker still reads VMCB01 explicitly, so active L2 state remains in
its separate portable record.
INVD and WBINVD advance L2's RIP after a checked nRIP.  SVM,
MONITOR, MWAIT, SKINIT, ICEBP, and VMMCALL instructions that L1 did not
intercept follow the ordinary L0 #UD policy in L2.  The L2
CPUID path hides SVM and its feature leaf even when L1 has nested SVM enabled,
because this backend does not support a further nested level.  When L1 does
not intercept L2 CPUID, it also hides L0's hypervisor and paravirtual-clock
leaves; those clock MSRs are not an L2 interface.
Physical host interrupt and NMI exits resume L2 directly, even if L1 requested
the corresponding intercept; they are not written into L1's VMCB12.
Physical SMI, INIT, and FERR freeze exits remain L0-owned generic SVM exits.
An actual VMRUN rejection of the composed VMCB02 is an L0 failure and poisons
the nested run owner; L1-visible invalid-VMCB exits are produced from VMCB12
validation before L2 entry.  The VMCB02 failure is never reflected to L1.
AMD kernel-owned INIT/SIPI remains disabled by default.  Setting the read-only
module-load tunable `hw.vmm.svm.kernel_startup_experimental=1` before loading
`vmm` admits it for root hardware qualification; the default zero value and
every value other than one reject it.  The live startup cases must pass with a
matching running kernel before the default can be changed.
VMCB02 retains L1's virtual interrupt request fields, so L1 can request an
L2 interrupt.  At an L2 entry boundary, a pending L0 virtual IRQ or NMI
requested by L1's intercepts produces a frozen synthetic nested exit.  The
event stays pending for L1 after the exit; NMI priority, pending event
injection, L1's interrupt masking choice of L1 or L2 IF, and the L0 interrupt
mask capability gate this path.  L1-requested exits can occur during L2's
interrupt shadow.  When L1 leaves IRQ intercept clear, L0 can inject a pending
virtual IRQ into L2.  For blocked IRQ delivery it borrows V_IRQ and the VINTR
intercept for one hardware entry, then restores L1's virtual interrupt state
before checkpoint or exit reflection.  L2.IF blocking with L1 interrupt
masking disabled cannot use the hardware VINTR window because VMCB02 must use
L0's masking mode; delivery resumes at another L0 exit.  On hosts with the
AMD virtual NMI feature, L0 injects pending NMIs into L2 directly when L1
does not intercept them.  VMCB02 tracks NMI blocking through IRET.  A bounded
per-vCPU table preserves blocking for each L2 VMCB GPA across nested exits and
version 2 snapshots; when all slots are occupied, a new NMI stays pending.
L1 event-injected NMIs reserve a slot before entry so their blocking state
survives an L2 exit and checkpoint.  While an NMI is blocked, an L1 interrupt
intercept can still run when interrupts are enabled.
Version 1 snapshots remain restorable.  Hosts without virtual NMI support
defer direct NMI delivery until L1 resumes.
The L1 SVM feature profile does not advertise virtual NMI controls, and
VMCB12 admission rejects them instead of silently ignoring L1's request.
Queued L0 exceptions and software interrupts inject into active VMCB02 after
the guest-entry guard.  They take precedence over pending asynchronous L1
exits, and their queue entry is consumed only for an actual L2 entry.
The live AMD suite checks delivery of an L1 V_IRQ, an L0 APIC IRQ, an
L1 event-injected NMI, and two successive L0 NMIs to an L2 real-mode handler.
It also checks an active-L2 checkpoint while an NMI is blocked.  These cases
are pending execution on the matching kernel.
When L0 exception tracing catches an L2 fault that L1 did not intercept, the
frozen exit path reinjects the fault into VMCB02, preserving its error code
and updating CR2 for a page fault.  An L0 breakpoint intercept reports the
same breakpoint exit ABI from L2, including its instruction length, even when
L1 also intercepts #BP.  Changes
to L0 breakpoint, HLT, and PAUSE exit capabilities update an active VMCB02
without removing L1's intercepts.  L0 exception tracing remains scoped to
L1; L2's own #DB and other trap-class exceptions follow L1's intercepts.
L1 CLGI and STGI update a software GIF.  When GIF is clear, L0 keeps
guest-directed interrupts and NMIs pending while still delivering exceptions;
an L2 exit clears L1's GIF as the hardware #VMEXIT contract requires.  The
GIF state is part of the AMD checkpoint record.  L1 INVLPGA conservatively
refreshes L1 and L2 hardware ASIDs.
Before an L0-owned exit resumes L2, the frozen handoff carries a valid
EXITINTINFO into EVENTINJ and clears the consumed exit field.  It rejects a
conflicting or malformed event, and leaves reflected exits' event information
for L1.
L0-only reads of EFER, PAT, FS/GS base, TSC, and the VMLOAD auxiliary MSRs
now read the live saved VMCB02 state and advance L2 using checked nRIP.  TSC
uses the composed VMCB02 offset; EFER masks the hardware-required SVME bit to
match L2 CPUID.  L2 writes to STAR, LSTAR, CSTAR, SFMASK, FS/GS base,
SYSENTER, PAT, and EFER now update the live VMCB02 image after checked nRIP.
L2 reads of SFMASK and SYSENTER_CS expose only their low 32 bits, including
when L1's initial VMCB image had upper bits set.
When L1 disables NPT12, PAT remains shared with L1: composition takes it
from VMCB01, L2 PAT writes update VMCB01, and VMCB12 G_PAT is preserved on
exit and checkpoint.  With NPT12 enabled, VMCB12 G_PAT is the L2 value.
EFER writes validate long-mode transitions and advertised feature bits while
retaining the physical SVME bit that VMRUN needs.  Noncanonical FS/GS base,
LSTAR, and CSTAR values, invalid PAT, and invalid EFER writes inject #GP into
L2 without advancing RIP, or synthesize a #GP exit to L1 when L1 intercepts
that exception.  L0-generated #UD follows the same L1 intercept rule.  An L2
TSC write adjusts the shared L1 clock offset
after subtracting L1's VMCB12 offset; the existing clock checkpoint record
carries that change.
Checkpoint copies the live VMLOAD fields, PAT, and EFER into the
portable L2 record.  L0 handles the ordinary AMD shared MTRR and zero-valued
status MSRs for L2 when L1 leaves them unintercepted.  APIC_BASE reads and
writes use the shared L1 virtual LAPIC state and its existing write policy;
an unknown MSR injects #GP into L2.  Interrupted event delivery is replayed
before any L0-owned instruction exit is emulated.  L2 device MMIO and string
port I/O use the ordinary L0 emulators.  With NPT12, the software guest page
walk and final data address translate through L1's nested tables; a translated
emulated-device address skips RAM alias creation and reaches instruction
emulation.  Assigned PCI passthrough BARs have no NPT02 alias and are not
supported for L2 access; that case fails closed.
An NPT12 denial during a software page walk synthesizes an L1 NPF exit;
no-fault inspection leaves guest state unchanged.  The userspace string-I/O
path commits each completed element's index and count, then recognizes an L1
transition before changing registers for the faulting element.  Other
L0-only instruction exits without an emulation path fail closed.  Software
NPT12 translation chooses the requested read, write, or execute access before
walking L1's tables.  With read-only guest page tables disabled, guest
page-table walks use a user data-write NPT access even when software only
reads the PTE, and reflect those access bits to L1.
The frozen exit dispatcher forwards nested string
I/O, breakpoint, and SVM exits to the ordinary guest-exit handlers.  Broad
guest qualification still requires the matching kernel on AMD hardware.

The virtual SVM MSR state keeps the L0-required physical `EFER.SVME` separate
from the bit visible to L1.  It also bounds `VM_HSAVE_PA` and models the
`VM_CR` LOCK/SVMDIS interaction.  The current VM_CR model rejects writes to
the other control bits.  AMD
checkpoints now prefix each vCPU's established architecture record with a
versioned nested state record.  A paused L2 record contains a copied VMCB12
with current L2 guest state and virtual MSRs; restore stages a fresh NPT02
root and VMCB02 with destination hardware pointers before VM-wide commit.
Older ordinary AMD images remain readable.  This checkpoint path still needs
live active-L2 save and restore qualification.  Active-L2 records require
the virtual GIF to be clear, matching VMRUN entry.  VMCB12 admission checks
the guest PAT when NPT12 is enabled.  VMCB12 admission and the ordinary AMD
snapshot validator share checks for CR0 cache mode and long-mode PAE and
protected-mode requirements.  AMD VMRUN permits CR0.PG=1 with CR0.PE=0 outside long mode
and does not compare EFER.LMA with EFER.LME and CR0.PG; both validators
preserve those SVM-specific states.  When nested SVM is exposed, restore also
limits VMCB01 CR3 to the same 47-bit guest physical range advertised by CPUID.

Per vCPU maintain:

- virtual `EFER.SVME` and `MSR_VM_CR` policy;
- L1 VMCB guest physical address;
- validated software VMCB12 snapshot;
- derived VMCB02;
- virtual hsave area;
- nested intercepts, event injection, and exit state;
- nested NPT root and ASID generations;
- virtual SVM capability leaf.

Implement:

- VMRUN;
- VMLOAD/VMSAVE;
- STGI/CLGI;
- INVLPGA;
- VMMCALL routing;
- VMCB validation and clean-bit semantics;
- nested exit reflection to VMCB12.

The hardware VMCB02 must always retain L0-required intercepts and L0's NPT
root. L1-provided IOPM/MSRPM addresses are guest physical addresses and must
be read through safe L1 memory helpers, bounded, validated, and cached with an
invalidation generation.

## Nested memory translation

With L1 nested paging enabled:

```text
L2 virtual address
  -- L2 guest page tables --> L2 guest physical address
  -- L1 EPT12/NPT12 -------> L1 guest physical address
  -- L0 EPT01/NPT01 -------> host physical address
```

Hardware needs an efficient combined EPT02/NPT02 view. The implementation
must:

- build combined mappings lazily;
- record enough reverse mapping to invalidate them when L1 changes or
  invalidates EPT12/NPT12;
- honor permissions and memory types from both levels;
- distinguish an L2 fault that L1 should receive from an L0 fault that L0
  handles;
- compose accessed/dirty behavior correctly;
- invalidate on INVEPT, INVVPID, INVLPGA, CR3/ASID changes, memory-slot
  changes, and L1 page-table writes;
- bound shadow-page memory and reclaim it safely.

Do not overload the current ordinary EPT/NPT code with nested conditionals in
every path. Add a translation context interface used by EPT and NPT, with a
separate combined-map implementation.

## Exit routing

Every L2 exit goes through one decision point:

```text
exit generated while running L2
        |
        +-- required for L0 safety/host service --> handle in L0
        |
        +-- requested by L1 intercepts ---------> synthesize nested exit to L1
        |
        `-- neither ----------------------------> handle and resume L2
```

Exit qualification, instruction length, fault address, interruption
information, pending debug state, and error codes must be translated exactly.
This is especially important for exceptions that L0 handles while L1 asked to
intercept them.

## Interrupts and time

First implementation:

- disable nested posted interrupts/APICv/AVIC optimizations;
- use the existing virtual LAPIC and explicit exit/injection paths;
- model L1 interrupt-window and NMI-window requests;
- compose TSC offsets:

```text
L2 visible TSC = host TSC + L0->L1 offset + L1->L2 offset
```

- validate TSC scaling and deadline-timer behavior;
- preserve pending events across L2 exit and L1 re-entry.

Add APICv/AVIC and posted-interrupt optimizations only after interrupt
correctness tests pass without them.

## Nested CPUID and MSR policy

Expose VMX/SVM only when nested mode is enabled and the complete advertised
subset is implemented.

Use named nested CPU profiles rather than raw host passthrough. A profile
defines:

- VMX/SVM capability MSRs or CPUID leaf;
- EPT/NPT capabilities;
- VPID/ASID behavior;
- unrestricted guest support;
- virtual interrupt features;
- maximum physical/virtual address widths;
- features safe for save/restore and migration.

Mask capabilities that cannot be maintained on all hosts in a migration pool.
An L1 must see stable capability values for its lifetime.

## Nested save/restore

Nested support is not complete until the state framework can save an L1 while
L2 is active.

Save:

- VMXON/SVME state;
- VMCS12/VMCB12 architectural contents;
- current control-block pointer and launch state;
- pending nested events and exits;
- virtual capability profile;
- nested TSC state;
- nested translation generation and architecturally visible invalidation
  state.

Do not save VMCS02/VMCB02 or combined EPT02/NPT02 as authoritative state.
They are host-derived caches and must be rebuilt on restore.

The initial implementation was permitted to reject active-L2 checkpoint while
ordinary nested execution was stabilized.  The current implementation no
longer relies on that staging exception: it freezes an active L2 into portable
architectural state, rebuilds destination-local VMCS02/EPT02/VPID resources,
publishes the VM-wide replacement transactionally, and thaws execution only
after commit.  Rootless model and build evidence cover that transaction, while
live save/restore with Linux/KVM as L1 remains a mandatory Intel qualification
gate.

## Security requirements

Treat L1 as hostile:

- copy VMCS12/VMCB12 and bitmaps through checked guest-memory helpers;
- revalidate after every L1-visible modification or generation change;
- never trust an L1 physical address as a host address;
- cap shadow page tables, cached control blocks, ASIDs/VPIDs, and pending
  events;
- prevent stale combined mappings after memory-slot removal;
- fuzz every VMX/SVM instruction state transition and invalid control field;
- use INVARIANTS assertions for internal impossibilities, but return
  architectural failures for guest-triggerable errors;
- add SDT probes and rate-limited diagnostics without logging guest secrets.

## File-level nested changes

| Area | Proposed change |
|---|---|
| `sys/amd64/vmm/vmm_nested.[ch]` | Common capability, lifecycle, memory helpers, state envelope, tracing |
| `sys/amd64/vmm/intel/nested_vmx.[ch]` | VMCS12, VMCS02 construction, VMX instruction emulation, exit routing |
| `sys/amd64/vmm/amd/nested_svm.[ch]` | VMCB12, VMCB02 construction, SVM instructions, exit routing |
| `sys/amd64/vmm/intel/ept.c` | Combined EPT context and invalidation hooks |
| `sys/amd64/vmm/amd/npt.c` | Combined NPT context and invalidation hooks |
| `sys/amd64/vmm/vmm.c` | Nested capability lifecycle and common statistics |
| `sys/amd64/include/vmm.h` | Internal `vmm_ops` extensions |
| `sys/amd64/include/vmm_dev.h` | Versioned nested capability/state ioctls |
| `lib/libvmmapi` | Nested query/enable/state wrappers |
| `usr.sbin/bhyve/amd64` | CPU profile/configuration and diagnostics, not VMCS/VMCB execution |
| state framework | Required nested state section and compatibility checks |

## Nested implementation phases

For each vendor, do not start with "boot Linux L2" as the only test. Build the
architectural instruction and state tests first.

1. Nested capability disabled by default; CPUID/MSR profile tests.
2. VMXON/VMXOFF or EFER/VM_CR and instruction-result tests.
3. Software VMCS12/VMCB12 validation.
4. Uniprocessor L2 with paging disabled or simple paging.
5. Combined EPT/NPT and invalidation.
6. Exceptions, interrupts, NMI, timers, and TSC.
7. SMP L2 and L1 scheduling stress.
8. Linux KVM L1 running `kvm-unit-tests` and Linux L2.
9. FreeBSD/bhyve L1 running a FreeBSD or Linux L2.
10. Nested state save/restore.
11. Optimizations: shadow VMCS, APICv/AVIC, large combined pages.
12. Second CPU vendor.

Use KVM unit tests and Linux KVM as references, plus direct architectural tests
for invalid VMCS/VMCB states. Windows Hyper-V is a later compatibility target,
not the initial definition of correctness.

---

# Cross-project sequence

## Recommended work order

### Milestone 1: Virtio foundation

- requirements matrix;
- split-ring refactor;
- queue lifecycle and reset;
- modern/legacy transport parity;
- Priority 0 conformance.

### Milestone 2: state framework

- versioned stream and machine type;
- transaction coordinator;
- kernel semantic state ABI;
- PCI and legacy Virtio conversion;
- malformed-state tests.

### Milestone 3: modern Virtio state

- modern PCI transport serialization;
- split-ring state;
- net, blk, SCSI, console, RNG, input, 9P, and vsock quiesce/state;
- repeated checkpoint/restore tests.

### Milestone 4: performance and operations

- packed rings (implemented for explicit opt-in; live qualification pending);
- net/block multiqueue (implemented and live-tested);
- dirty logging;
- pre-copy migration;
- balloon and virtio-fs.

### Milestone 5: one-vendor nested virtualization

- choose Intel or AMD based on the supported hardware fleet;
- complete the unoptimized correctness path;
- add active-L2 save/restore only after ordinary nested execution is stable.

## Definition of done

No project is done based only on a successful Linux boot.

Virtio is done when every advertised feature has mapped conformance clauses,
negative tests, reset tests, and modern/legacy interoperability results.

Save/restore is done when a committed format version survives repeated
restore, detects incompatible or corrupt input before vCPU execution, and has
a documented compatibility policy.

Nested virtualization is done when invalid L1 inputs cannot panic or escape
L0, architectural instruction tests pass, Linux KVM and bhyve work as L1, SMP
L2 stress is stable, and nested state can be saved or is explicitly rejected
before checkpoint commit.

The doubled kernel and non-standard review adds an explicit final-entry gate
to that definition.  Startup publications and claim releases advance a
per-vCPU notification epoch before wakeup/IPI delivery, and a pointer-free
runtime handoff detects changes between frozen dispatch and the final
interrupt-disabled machine-entry check.  Admission captures the epoch before
and after dispatch: idle or retained dispatch permits no change, while consumed
dispatch permits exactly the claim-release notification it generates.  A
missing or extra transition returns `EAGAIN` without arming the handoff, closing
the otherwise silent FROZEN dispatch-to-capture window.  The epoch is neither
portable state nor public ABI.  Its value transitions are rootless-tested, but
the production run-loop and VMX/SVM consumers remain withheld until exact
FPU/state unwind, bounded event-driven replay, and installed Intel timing races
pass.

The coordinator token and notification handoff are independent observations of
the same publication, so both may legitimately report `EAGAIN`.  The common
runtime model composes those results without check-order dependence: one or two
`EAGAIN` results request replay, a terminal error dominates `EAGAIN`, matching
terminal errors retain their identity, and conflicting terminal errors become
`EPROTO`.  Every non-entry result still follows the identical RUNNING-to-FROZEN
and guest-FPU-to-host-FPU unwind before it is returned or replayed.

The final entry guard is not one-shot.  A machine backend can handle a guest
exit and execute another hardware entry before `vmmops_run()` returns.  The
same coordinator token and notification handoff therefore remain armed for
the complete synchronous run interval and are rechecked inside the backend's
interrupt-disabled window before every hardware entry.  Repeated successful
checks leave the runtime in CHECKED state.  Drift after any backend-internal
exit forces the same common refreeze and FPU unwind before INIT/SIPI dispatch;
otherwise an interrupt raised for a newly published startup event could be
observed as an ordinary handled exit and followed by an incorrect re-entry.
An independent backend-loop value machine enforces this mechanically:
NEED_CHECK can become CHECKED only through a canonical guard result, CHECKED
can enter hardware once, an internally handled exit returns to NEED_CHECK,
and replay, terminal drift, or an unhandled exit becomes RETURNABLE.  Exact
check and entry counts reject a missing recheck, malformed ordering, or
counter exhaustion without changing the owner.

RETURNABLE also owns its return identity.  The loop snapshots a validated
replay or terminal error when the guard rejects entry and retains a canonical
normal disposition for an unhandled hardware exit.  NEED_CHECK, CHECKED, and
IN_GUEST cannot carry a non-normal disposition.  Completion validates the
owned value and publishes it only to a disjoint non-null output, so mutation
of an earlier guard-result object cannot redirect common replay or error
handling.  This remains transient private control state and is neither
serialized nor exposed as a machine or guest ABI.

Guard admission and backend return deliberately use different action domains.
`ENTER_GUEST` is only a successful guard decision.  An ordinary unhandled
hardware exit is `RETURN_VMEXIT`; retry and positive terminal errors are
translated into the corresponding backend-loop actions.  This prevents a
future common consumer from treating a normal VM exit as permission for
another hardware entry.

### Nested-VMX ownership review record

The value-only VM-exit planners reject result storage overlapping their input
descriptors, host state, L2 runtime state, or frozen VMCS12 state.  The
hardware exit-capture transaction likewise keeps its callback descriptor
immutable and publishes only a completely captured, width-checked result.
Focused negative tests verify byte-for-byte preservation.  These model and
compile gates do not replace the pending root-only Intel VMX, Linux/KVM L1,
Linux/5BSD L2, active-L2 checkpoint, concurrency, and soak qualification.
The same ownership rule applies to VM-exit MSR loading: the immutable list and
base state, rollback workspace, processor/software results, outcome, and
failed-entry index use checked, pairwise-disjoint extents before any callback
or mutation is allowed.
When nested VMX is enabled, the L1 CPUID MAXPHYADDR now matches the 47-bit
EPT02 vmspace bound already enforced by the virtual VMX capability model.
Production Intel environment capture, final programming, portable rebind, and
VMCS02 resource acquisition apply the same rule before touching VMCS01 or a
destination-local lease.  This adapter coverage currently has a clean kernel
`-Werror` build; it remains explicitly pending live Intel execution tests.
The second ownership pass extended that invariant across execution-control
composition, EPT fault/reflection planning, EPT walks with accessed/dirty
updates, PDPTE validation, VMCS02 programming callbacks, staged thaw, portable
freeze, hardware entry, late-entry resolution, and cross-domain refreeze.
Every side-effecting callback now follows complete range validation, including
pairwise checks among mutable state machines and their rollback/result
publications.

VM-entry validation and frozen entry-MSR capture now reject output storage that
overlaps the capability policy, VMCS12 input wrapper, any pointed architectural
state, or the memory/policy callback descriptors.  Entry arrays, counts, and
results must also be pairwise disjoint and have representable extents before a
guest-memory read.  Frozen-context APIs apply the same rule to IDs, handoff
requests, resolutions, and results before consuming a handoff or changing the
running nested phase.  The model exercises representative aliases and verifies
that the entire retryable owner remains byte-for-byte unchanged.
The same audit was applied to pure architectural planners: invalidation and
VPID translation, exit provenance/routing, run-loop residency selection,
portable L2 capture/apply, and L1 restoration all reject typed output aliases.
This is intentionally a common ABI rule rather than a collection of
device-specific exceptions, which also keeps these value-only paths portable
to future non-x86 hosts.

### Incremental checkpoint dirty-log prerequisite

Pre-copy migration requires a guest-RAM dirty-log contract that is distinct
from CPU state-cache "dirty" bits and guest page-table accessed/dirty
emulation.  The contract belongs in the common VMM memory/memseg layer, with a
generic `vmmops` operation and a versioned libvmmapi/ioctl representation;
VMX/EPT and SVM/NPT implement it below that boundary.  It must describe a
range in guest physical address space, a fixed bitmap granularity, a
generation, and whether retrieval is observing or atomically clearing the
generation.  It may not expose EPT entries, NPT entries, host virtual
addresses, native word width, or host page-size assumptions.

The first implementation must be stop-and-copy safe before it is used for
pre-copy: validate mapped ranges and bitmap capacity without mutation; reject
overflow, holes, aliasing output, unsupported memory backends, and an active
checkpoint conflict; freeze or otherwise establish the documented collection
boundary; then return a canonical little-endian bitmap and generation.  Clear
on successful collection only, never on a failed copyout.  Reset, memseg
unmap, snapshot abort, restore, destroy, and backend detach must invalidate
old generations.  A destination restore must not inherit source dirty bits.

Required independent tests include every bit boundary, unaligned range,
overlapping and disjoint mappings, repeated observe/clear, clear-after-copyout
failure, reset/unmap/destroy races, generation overflow, cross-endian fixture
decoding, VMX/SVM parity, and an active-I/O stop-and-copy checkpoint.  Linux
and 5BSD guest tests can validate migration behavior, but dirty-log ABI tests
must not derive expected bitmap layout from the implementation.  Incremental
or live migration remains unavailable until these common, backend, and live
qualification gates pass.

The first committed foundation is intentionally smaller than a tracking ABI:
`vmm_dirty_log_range_validate()` and its byte-bitmap helpers define only the
portable logical range, canonical low-GPA/low-bit ordering, and non-wrapping
generation arithmetic.  `vmm_dirty_log_map_validate()` and
`vmm_dirty_log_map_covers()` add the next value-only seam: a caller that has
already frozen the VMM map can represent its relevant mappings as an ordered,
pointer-free list bounded by the common `VM_MAX_MEMMAPS` capacity.  The helper
distinguishes a map hole (`EFAULT`) from a
valid mapping that cannot be collected (`EOPNOTSUPP`), such as MMIO.  It does
not inspect `vm_mem_map`, retain the list, decide when a VM is frozen, enable
tracking, or expose an ioctl.  Segment identities, objects, permissions, host
addresses, host page size, EPT, and NPT remain below this seam.

The next layer must bind this validated frozen-map value to an
architecture-neutral backend operation and a generation-invalidation owner
before VMX/EPT or SVM/NPT-specific collection can be added.

That owner is now a value-only `vmm_dirty_log_owner` transaction.  Enabling
it validates a caller-owned frozen map and retains only the requested logical
range, a caller-owned non-reused map generation, and dirty generation one.
`begin` revalidates the current frozen map and returns an immutable ticket for
either observation or clear-after-publication.  At most one ticket may be
live.  A clear ticket advances the dirty generation only after the caller has
published its canonical bitmap and the future architecture backend has
atomically cleared that exact generation; abort retains the generation.  Map
change, reset, snapshot abort, restore, destroy, and backend detach use the
same invalidation operation, which revokes every outstanding ticket.  The
owner stores no pointers, EPT/NPT state, host page size, backend callback, or
user ABI data.  Generation exhaustion fails closed and permanently disables
the owner rather than reusing a ticket identity.

This is still not an exposed dirty-log API or a backend implementation.  The
common `vm_mem` layer now supplies a nonwrapping map generation and a
lock-stable, by-value snapshot of the logical map.  The snapshot carries only
GPA range and collectability, rejects aliases to the live `vm_mem` object, and
fails closed if its generation is exhausted.  It owns the private transaction
owner: map, reset, and destroy paths revoke outstanding tickets; owner
operations require exclusive `mem_segs_lock`, while a snapshot remains a
shared-lock inspection operation.  A collection lifecycle additionally freezes
vCPUs before it retains a generation.  Kernel snapshot dispatch now validates
its selector before changing transaction state, then revokes a ticket before a
real save or restore callback; the map lock is released before arbitrary
architecture/device callbacks.  The common collector is now deliberately
limited to an all-or-nothing *observation* pass: it accepts a ticket plus
architecture-neutral dirty-leaf values, builds into a caller-supplied staging
bitmap, and copies to the result only after every leaf validates and the
complete scan succeeds.  It has no pmap, VMX, SVM, clear, ioctl, or
publication-policy dependency.  A backend clear remains a separate future
transaction, because it may proceed only after the completed bitmap is durably
published and must have matched EPT and NPT semantics.  No dirty-log ioctl,
pre-copy advertisement, or migration claim is enabled by this foundation.

### Hardware nested-page dirty-bit seam

The amd64 pmap layer now exposes only an internal, by-value
`pmap_guest_query_dirty()` helper for a *single nested-page-table leaf*.  It
accepts EPT or NPT pmaps using hardware accessed/dirty support, returns the
actual 4 KiB, 2 MiB, or 1 GiB leaf containing the requested GPA, and can clear
that leaf only after the caller has frozen the relevant vCPUs.  A successful
clear invalidates the nested translation context before returning.  EPT with
software-emulated A/D is rejected: there its writable bit is a permission
mechanism, not evidence that the guest wrote the page.

This is intentionally below the common dirty-log contract.  A future
collector must expand a dirty superpage into canonical logical 4 KiB bitmap
units.  `vmm_dirty_log_bitmap_mark_range()` now provides that expansion as a
pure value operation: it validates both ranges before changing a bit, clips a
hardware leaf to the tracked range, and preserves the low-GPA/low-bit bitmap
ordering without consulting host page size or native bitmap words.  A future
collector must bind that operation to a `vmm_dirty_log_owner` ticket and provide
equivalent VMX/EPT and SVM/NPT behavior.  The helper exposes neither hardware
entries nor host pages, and it creates no ioctl, snapshot field, migration
feature, or claim that pre-copy is available.  Root-only qualification still
must exercise clean/dirty/clear/rewrite behavior for 4 KiB, 2 MiB, and 1 GiB
leaves, verify rejection under emulated A/D, and prove that clearing while
vCPUs are frozen does not lose writes across the nested-context invalidation.

The common owner now has a read-only `ticket_check` boundary.  A backend must
check that ticket while the common map and vCPU-freeze boundary are still
held, immediately before observing or clearing hardware A/D bits.  A stale
ticket has no side effects and means reset, map change, snapshot cancellation,
or another collection revoked the attempt.  This keeps map/collection
generations in common code while EPT and NPT retain their different
page-table mechanics.  Malformed arguments remain `EINVAL`; only a valid
ticket revoked by lifecycle change is `ESTALE`.  It remains a private kernel
seam, reached through the lock-asserting `vm_mem` wrapper rather than by
inspecting `vm_mem` storage, and is not an ioctl or migration capability.

## References

- [OASIS Virtio 1.4 Committee Specification 01](https://docs.oasis-open.org/virtio/virtio/v1.4/cs01/virtio-v1.4-cs01.pdf)
- [QEMU migration framework](https://qemu.readthedocs.io/en/master/devel/migration/main.html)
- [QEMU Virtio device migration](https://qemu.readthedocs.io/en/master/devel/migration/virtio.html)
- [Linux KVM nested VMX documentation](https://www.kernel.org/doc/html/latest/virt/kvm/x86/nested-vmx.html)
- [Linux KVM API, including nested state](https://www.kernel.org/doc/html/latest/virt/kvm/api.html)
- [Intel 64 and IA-32 system programming manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [AMD64 Architecture Programmer's Manual, Volume 2](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2)
