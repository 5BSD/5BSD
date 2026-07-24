# bhyve: Virtio 1.4, VM State, and Nested Virtualization Architecture

Status: design proposal
Target: FreeBSD/5BSD `bhyve` and `vmm`
Primary architecture: amd64, with interfaces that do not prevent later arm64 work

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

The common split-ring implementation is in `usr.sbin/bhyve/virtio.c` and
`virtio.h`. Modern PCI transport support is in
`usr.sbin/bhyve/virtio_pci_modern.c`.

The modern transport exposes `VIRTIO_F_VERSION_1` and allows device models to
opt into `INDIRECT_DESC` and `RING_RESET`.  Queue reset now has a common
generation-fenced lifecycle and device-specific quiesce callbacks for every
existing bhyve Virtio model.  `EVENT_IDX` interrupt suppression exists in the
split-ring core, but the available-buffer notification-suppression half is not
complete, so no production device advertises it.  The transport does not yet
provide a packed-ring engine, notification data, an IOMMU/access-platform
path, or admin virtqueues.

Device feature depth is uneven. For example:

- virtio-net has a single RX/TX pair, no control virtqueue, and no Virtio
  multiqueue or RSS;
- virtio-blk has flush, topology, indirect descriptors, optional discard, and
  bounded single-segment write-zeroes, but not multiqueue;
- virtio-scsi has a working command path but advertises few optional features;
- console, RNG, 9P, input, and vsock have modern transport coverage and the
  common reset lifecycle; they still need a versioned save/restore state
  contract.

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

The main architectural limitations are:

- no stable top-level or per-device version contract;
- serialization is closely coupled to C structure layout;
- no machine type or CPU compatibility contract;
- modern Virtio explicitly returns `EOPNOTSUPP` from
  `vi_pci_snapshot()`;
- only a subset of devices has pause, resume, and snapshot callbacks;
- no dirty-memory API for incremental checkpoints;
- no stream abstraction for migration;
- limited validation of restore input and backend identity.

The existing implementation is valuable scaffolding, but should not become
the permanent external format.

### Nested virtualization

Nested virtualization is not implemented:

- `sys/amd64/vmm/x86.c` hides AMD SVM from guest CPUID;
- `usr.sbin/bhyve/amd64/xmsr.c` reports SVM disabled through `MSR_VM_CR`;
- Intel VMX instructions exit as `VM_EXITCODE_VMINSN`, but there is no VMCS12
  model or L2 execution;
- SVM has the hardware intercept definitions needed to recognize `VMRUN` and
  related instructions, but no VMCB12/VMCB02 implementation.

The existing EPT and NPT code refers to "nested page faults" in the ordinary
hardware sense: translating a guest physical address through L0's second-level
page tables. That is not support for an L1 hypervisor running an L2.

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

5. **virtio-balloon** — memory reclamation and guest memory statistics.
   FreeBSD has a guest driver, but bhyve needs a host device model.
6. **virtio-fs** — modern host/guest filesystem sharing. Existing Virtio 9P
   should remain for compatibility, but new production shared-filesystem work
   should target virtio-fs.

### Priority 2: workload dependent

7. **virtio-gpu** — important for desktop and graphical appliance guests.
8. **virtio-input** — keyboard, pointer, tablet, and automated input.
9. **virtio-iommu** — important for protected DMA, nested use cases, and a
   principled implementation of `VIRTIO_F_ACCESS_PLATFORM`, but not required
   for the first server conformance milestone.

### Lower initial priority

Crypto, sound, memory/pmem, CAN, GPIO, I2C, SCMI, RPMB, SPI, media, and
Bluetooth should be driven by an identified consumer. Implementing every
device in the specification is not necessary to claim conformance for the
devices bhyve actually exposes.

## Which features matter most

### Common transport and ring features

| Priority | Feature | Reason |
|---|---|---|
| P0 | `VIRTIO_F_VERSION_1` | Mandatory foundation for modern devices |
| P0 | `VIRTIO_F_INDIRECT_DESC` | Reduces descriptor pressure for block, SCSI, and network I/O |
| P0 | Complete `VIRTIO_F_EVENT_IDX` | Reduces interrupt and notification overhead; advertise only after both directions are implemented |
| Done | `VIRTIO_F_RING_RESET` | Lets Linux recover or reconfigure one queue without resetting the entire device |
| P0 | Correct `DEVICE_NEEDS_RESET` behavior | Required fault containment for malformed rings and backend failure |
| P1 | `VIRTIO_F_RING_PACKED` | Better cache behavior and lower ring overhead at high I/O rates |
| P1 | `VIRTIO_F_NOTIFICATION_DATA` | More efficient and precise queue notification |
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
2. Refactor split rings behind `virtio_ring_ops` without behavior changes.
3. **Done:** implement the queue/device lifecycle and `RING_RESET`.
4. Complete Priority 0 device features and conformance.
5. Add versioned Virtio state and modern-transport restore.
6. Add packed rings and notification data.
7. Add balloon, then virtio-fs without DAX.
8. Consider virtio-iommu and admin virtqueues when a consumer requires them.

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

Introduce explicit versioned machine types, for example:

```text
bhyve-x86_64-v1
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

New bhyve releases can default to a new machine type without silently changing
the virtual hardware of an old saved VM.

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
- vsock: active host connections and Unix/native provider FDs cannot be
  reconstructed transparently. Initially require no active connections or
  explicitly reset them and expose the disconnect to the guest on restore.

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
- restore across one supported old-to-new state-version transition;
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

## AMD SVM design

Add `sys/amd64/vmm/amd/nested_svm.c` and `.h`.

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

Initially it is acceptable to mark active-L2 checkpoint unsupported while
ordinary nested execution is stabilized. The state format and kernel API
should still be designed from the beginning so active-L2 support can be added
without another incompatible ABI.

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

- packed rings;
- net/block multiqueue;
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

## References

- [OASIS Virtio 1.4 Committee Specification 01](https://docs.oasis-open.org/virtio/virtio/v1.4/cs01/virtio-v1.4-cs01.html)
- [QEMU migration framework](https://qemu.readthedocs.io/en/master/devel/migration/main.html)
- [QEMU Virtio device migration](https://qemu.readthedocs.io/en/master/devel/migration/virtio.html)
- [Linux KVM nested VMX documentation](https://www.kernel.org/doc/html/latest/virt/kvm/x86/nested-vmx.html)
- [Linux KVM API, including nested state](https://www.kernel.org/doc/html/latest/virt/kvm/api.html)
- [Intel 64 and IA-32 system programming manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [AMD64 Architecture Programmer's Manual, Volume 2](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2)
