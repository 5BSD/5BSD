# WASPNest remaining work: VirtIO, state transfer, and Intel nested VMX

Date: 2026-08-12 (revised 2026-08-13)

The 2026-08-13 revision reconciles this handoff with the current ledgers after
a cycle of implementation-plus-model work.  Items completed this cycle are
collected in section 1A and re-filed in place throughout as
implemented-plus-model-tested with the live-qualification residual still open.
Nothing here is live-qualified: every completion below is rootless/model/build
evidence only, and live Intel-host (and rebuilt-5BSD) qualification is still
pending for all of it.  `pending` is not `exercised`;
`experimental-pending-live` is not live-qualified.

This is the concise implementation and qualification handoff for the current
WASPNest tree.  It answers three different questions separately:

1. what production code is still missing;
2. what code exists but is still provisional or unadvertised; and
3. what is implemented in rootless models but still lacks privileged Linux,
   rebuilt-5BSD, checkpoint, migration, or Intel-hardware evidence.

Those classes must not be collapsed into “pending tests.”  A source model, a
feature bit, a scheduled lab case, and a passing live workload are different
forms of evidence.

## 1. Sources of truth

The machine-readable ledgers override prose and old review counts:

| Scope | Authoritative file |
| --- | --- |
| VirtIO requirements | `tests/sys/kern/vsock_device_harness/virtio-1.4-requirements.tsv` |
| Linux and 5BSD activation | `tests/sys/kern/vsock_device_harness/virtio-feature-activation.tsv` |
| VirtIO implementation-defined interfaces | `tests/sys/kern/vsock_device_harness/virtio-nonstandard-interfaces.tsv` |
| Intel nested-VMX requirements | `tests/sys/vmm/vmx-nested-requirements.tsv` |
| Intel live qualification groups | `tests/sys/vmm/vmx-nested-live-qualification.tsv` |
| Default-off nested policy | `tests/sys/vmm/vmx-nested-default-policy-live-qualification.tsv` |
| Nested implementation-defined interfaces | `tests/sys/vmm/vmx-nested-nonstandard-interfaces.tsv` |
| Common/Intel/AMD startup edges | `tests/sys/vmm/vmx-startup-entry-edge-matrix.tsv` |
| Lab profiles and cases | `tests/sys/kern/vsock_e2e/virtio-lab.yaml` |
| Pinned reference catalog | `tests/sys/kern/vsock_device_harness/virtio-reference-corpus.tsv` |

Useful explanatory documents are:

- `usr.sbin/bhyve/VIRTIO_1_4_ROADMAP.md`;
- `docs/waspnest-completion-matrix.md`;
- `docs/waspnest-feature-completion-backlog.md`;
- `docs/waspnest-qualification-handoff.md`;
- `docs/waspnest-review-status.md` (a chronological review journal, not a
  current status ledger);
- `docs/bhyve-virtio-state-nested-architecture.md`;
- the device design documents under `docs/bhyve-virtio-*-design.md`; and
- `docs/vmm-bhyve-bugs.md`, whose findings must be revalidated against the
  current source before being closed or promoted.

### Current ledger snapshot

The current tree contains:

- 240 VirtIO requirement rows: 237 `implemented-tested`, two explicit
  `not-applicable`, and one explicit `unsupported-optional`;
- 130 activation rows;
- Linux activation: 33 `exercised`, 79 `pending`, five `driver-gap`, and 13
  `not-applicable`;
- 5BSD activation: eight `exercised`, 86 `pending`, 33 `driver-gap`, and three
  `not-applicable` (this cycle moved thirteen 5BSD rows from `driver-gap` to
  `pending` behind new guest drivers and packed/multiqueue guest work; none
  became `exercised`);
- 437 nested-VMX requirement rows: 408
  `foundation-tested-experimental` and 29 `experimental-pending-live` (the four
  former `pending` INIT/SIPI implementation rows are now implemented and
  model-tested and were re-filed to `experimental-pending-live`; there are no
  remaining `pending` nested implementation rows); and
- 12 nested live-qualification groups, none presently carrying accepted
  Linux-L2 or 5BSD-L2 evidence.

Therefore the project is not feature complete and is not release qualified.
The 237 VirtIO rows prove broad host-model coverage; they do not erase the 130
guest-activation rows.

## 1A. Completed this cycle (implemented + model-tested; live-qualification pending)

The items below moved out of the "missing/needs-code" framing into
implementation-plus-model completion.  Every one of them is rootless, model,
and build evidence only.  None is live-qualified; each keeps its live-only
residual, and the corresponding ledger rows are `pending`,
`experimental-pending-live`, or an unchanged host row — never `exercised`.

- **Phase A snapshot data-loss fixes (§7.3):** guest FPU/XSAVE snapshot record;
  `pe_snapshot` for NVMe, HDA, and PCI-UART; xHCI pause/resume quiesce; PIT
  `now_bt` reanchor, IOAPIC `id`, and LAPIC `svr_last`; and IA32_XSS plus
  IA32_SPEC_CTRL resolved fail-closed.  All model-tested; whole-VM checkpoint
  of a VM using those devices no longer silently drops the state.
- **Five new 5BSD VirtIO guest drivers:** virtio-sound; virtio-fs
  (FUSE-over-virtio bridging fusefs); virtio-mem (protocol-only — no runtime
  onlining, a documented FreeBSD VM boundary); virtio-pmem; and virtio-IOMMU
  (protocol-only — no busdma translation, because there is no MI IOMMU hook).
  Built and adversarially reviewed, now in the 5BSD -Werror module gate.
  Twelve activation rows moved 5BSD `driver-gap` to `pending` with scheduled
  live cases; the virtio-fs 5BSD live case is deferred pending a
  `virtiofsd`-equivalent backend.  These remain live-only.
- **Packed/multiqueue guest activation:** block and SCSI multiqueue plus
  net and transport packed activation on the guest side; the packed-ring guest
  engine was independently re-reviewed clean.  The `*-PACKED` and
  `*-MULTIQUEUE` 5BSD rows stay `pending` until a rebuilt guest passes.
- **Nested-VMX INIT/SIPI machine transaction (§8.1):** `NVMX-EVENT-048`,
  `NVMX-EVENT-050`, `NVMX-EVENT-058`, and `NVMX-EVENT-102` are implemented and
  model-tested and moved `pending` to `experimental-pending-live`.  The Intel
  adapter binds the frozen transaction; the AMD adapter is fail-closed by
  design; scope is Intel-only; live L1/L2 qualification is still required.
- **Live migration control plane and cutover (§7.4):** a real management
  control plane plus the stop-and-copy cutover now exist — multi-frame
  chunking, a snapshot-reuse `dev_state` bridge, a `bhyve -R` destination
  listener, and highmem coverage — loopback- and model-proven.  The one-copy
  invariant holds.  Live two-host operation still needs listener
  authentication, per-device compatibility identity, and kernel dirty-log
  confirmation.  See `docs/bhyve-migration-design.md`.
- **Balloon FREE_PAGE_HINT (guest side):** implemented (PAGE_REPORTING kept
  fail-closed at the FreeBSD VM boundary).  It is INERT end-to-end until the
  host bumps the free-page-hint command-id during operation; the host now does
  so both at snapshot-restore and in the migration pre-copy free-page-hint
  round (with the retain-until-finish invariant described in
  `docs/bhyve-migration-design.md` §5.1).  Both host consumers are loopback/
  model-proven only, so its ledger row stays `pending` with no scheduled 5BSD
  lane, not `exercised`.
- **New host devices:** pvpanic (LPC 0x505 / ACPI `QEMU0001`; a Linux guest
  binds, no FreeBSD guest driver yet) and pvclock (KVM-compatible host clock,
  opt-in via `hw.vmm.pvclock.enabled`, default off).  See
  `docs/bhyve-pvclock-design.md`.
- **`docs/vmm-bhyve-bugs.md`:** 16 findings fixed plus the two
  XSS/SPEC_CTRL findings resolved this cycle; those are already
  dated-annotated in that file and are only cross-referenced here.

Administration virtqueues, SR-IOV, and device groups remain **excluded** from
release scope (§4.6); that is unchanged.

## 1B. 2026-08-13 whole-tree adversarial review loop

Separate from the implementation work in §1A, a multi-round rotated-lens
adversarial review loop (the eight lenses of §9) was run this session over
**all** virtualization code: the bhyve device models, the VMM kernel (base
Intel VMX, AMD SVM, emulated io-devices, instruction emulation), Intel nested
VMX, snapshot/checkpoint, and the code added this cycle (the migration control
plane and pvclock).  That pass fixed **52** additional
correctness/concurrency/portability/divergence bugs beyond the §1A work and the
2026-08-12 `docs/vmm-bhyve-bugs.md` fix wave.  The loop ran two full cycles of
rotated-lens rounds over the 7-area fan-out and converged when both remaining
live veins were swept to exhaustion: the guest-driver attach-unwind
DMA-after-free class (every driver individually cleared; last instance
virtio_scsi) and the lib9p unchecked-syscall / stale-`error` class (every
`fs_*` mutation handler audited; only fs_setattr and fs_remove ever affected).

Many of these land in subsystems already tracked in `docs/vmm-bhyve-bugs.md`
(for example gdb bounds hardening, a vlapic x2apic path, AHCI, e1000, and HDA),
and a dated cross-reference note was added there **without** altering any
historical finding text.  As with everything in this handoff, the loop's fixes
are rootless/model/build evidence only — none is live-qualified; live
checkpoint, migration, and Intel-host nested qualification remain pending.

## 2. Reference corpus and use rules

The pinned corpus currently names these immutable inputs:

| Reference | Role | Revision/identity | Required areas |
| --- | --- | --- | --- |
| OASIS VirtIO 1.4 CS01 | normative | Committee Specification 01, 2026-04-08, SHA-256 `497b7b989b5161444e87866c264a46be90911b8f4738eadf4dd4f52eb37c8727` | Common transport/rings, PCI, every implemented device chapter |
| Intel SDM Volume 3 | normative for nested VMX | revision 092, SHA-256 `5b77208f34f7220b489db1642a681153e19dea5251a32973c01cb9e760bd0cce` | VMX operation, entry checks, exits, EPT, VPID, APIC, timers |
| Intel SDM Volume 4 | normative for capability MSRs | revision 092, SHA-256 `31d5a364c155a9a8855feb46eb8c3fa8777d768bf04272c0f90757c9e3a644d4` | IA32_VMX_* capability MSRs |
| Linux | explanatory guest/KVM reference | commit `1590cf0329716306e948a8fc29f1d3ee87d3989f` | `drivers/virtio`, device drivers, `drivers/vhost`, `net/vmw_vsock`, `arch/x86/kvm/vmx`, KVM UAPI |
| QEMU | explanatory device/migration reference | commit `300438ffbb8d9430cac2fcc15cba6f482b2c0587` | `hw/virtio`, individual device models, VMState, migration |

The exact URLs and applicable paths are in the reference TSV.  VirtIO and the
Intel SDM control conformance.  Linux shows what real guest and L1 drivers
exercise.  QEMU is a behavioral/device-state comparison.  GPL code must not
be copied or mechanically translated.

`docs/waspnest-reference-corpus-status.md` records one unresolved provenance
problem: the cached Linux archive did not match the catalog digest, and the
exploratory cache was not a sealed qualification bundle.  Before privileged
qualification, correct the catalog or obtain the exact catalogued bytes, put
exactly one artifact per row in a mode-0700 directory, and pass:

```sh
sh tests/sys/kern/vsock_device_harness/validate-virtio-reference-corpus.sh \
  tests/sys/kern/vsock_device_harness/virtio-reference-corpus.tsv \
  --waspnest /path/to/sealed-reference-bundle
```

## 3. Completion semantics

A requirement is complete only when it is in one of these states:

1. implemented, independently tested, truthfully advertised, and live
   qualified on every guest/platform claimed by the release;
2. intentionally unsupported/not applicable, not advertised, and protected
   by a negative test; or
3. explicitly excluded from the release's guest/platform scope.

The following are not sufficient evidence by themselves:

- compilation or registration of a PCI device;
- successful PCI probing;
- feature-bit negotiation without the distinguishing operation;
- multiple queues allocated without useful traffic on each queue;
- a test derived from the production header it is supposed to verify;
- a model-only checkpoint round trip;
- a scheduled but unexecuted `virtio-lab` case; or
- a Linux pass used to claim 5BSD support, or the reverse.

## 4. Common VirtIO infrastructure remaining work

### 4.1 Packed virtqueues

The common split/packed engine is implemented in `usr.sbin/bhyve/virtio.c`,
`usr.sbin/bhyve/virtio.h`, and `usr.sbin/bhyve/virtio_pci_modern.c`; the 5BSD
guest implementation is in `sys/dev/virtio/virtqueue.c` and the modern PCI
transport.  Independent model tests are in
`virtio_packed_model_test.c`, `virtio_packed_engine_test.c`, and the common
VirtIO tests.

Remaining work:

- complete live packed activation for every advertised device, not merely the
  common engine;
- prove direct and indirect chains, wrap transitions, event suppression,
  notification data, in-order behavior where advertised, MSI and MSI-X,
  selective queue reset, malformed/looping chains, and used-length bounds;
- checkpoint at significant producer, consumer, wrap, event, and retained
  asynchronous-completion states;
- run split-versus-packed differential workloads; and
- finish rebuilt-5BSD packed activation for net, block, SCSI, console, RNG,
  input, 9P, balloon, GPU, RTC, and vsock.

Linux has exercised packed operation for several existing devices; the exact
remaining per-device statuses and case names are rows `*-PACKED` in the
activation ledger.  This cycle added the guest-side block and SCSI multiqueue
and net/transport packed activation, and the packed-ring guest engine was
independently re-reviewed clean; the corresponding 5BSD `*-PACKED` and
`*-MULTIQUEUE` rows are still `pending` (implemented, not yet live-exercised).
Packed advertisement should remain explicit opt-in until those rows close.

### 4.2 Notification and queue lifecycle features

`NOTIFICATION_DATA` and notification configuration data have Linux evidence
but still require rebuilt-5BSD evidence.  `RING_RESET`, PCI reset,
reconfiguration, per-device reset, `EVENT_IDX`, indirect descriptors, and
`IN_ORDER` remain activation gates even though the model paths exist.

For every queue, test reset while:

- a chain is being parsed;
- an asynchronous backend owns guest buffers;
- a completion is ready but unpublished;
- interrupts are suppressed;
- the queue is at a packed wrap boundary; and
- suspend/checkpoint also owns the device.

No completion from an old generation may access guest memory or disable a
new callback source.

### 4.3 Architecture-neutral DMA and VirtIO-IOMMU

Production files are `virtio_dma_domain.*`, `pci_virtio_iommu.*`, and the
`virtio_iommu_*` protocol, queue, event, topology, VIOT, and state files.
The host model covers domains, endpoint attachment, map/unmap, permissions,
faults, VIOT, and portable state.  Live ACCESS_PLATFORM qualification is
still pending.  A 5BSD virtio-IOMMU guest driver was added this cycle
(`sys/dev/virtio/iommu/virtio_iommu.c`, build- and model-verified) but is
protocol-only: it parses config and publishes queues, while ATTACH/MAP
translation still needs a downstream endpoint fabric and there is no MI busdma
IOMMU hook, so translated-DMA rows stay 5BSD `driver-gap` (see §6.8).

Remaining work:

- prove every descriptor table, indirect table, payload, device-private DMA
  path, asynchronous completion, reset, and restore uses the mapper;
- test attach/detach, final IOVA page, partial mappings, overlap, arithmetic
  overflow, permissions, invalidation, fault queue saturation, and active-DMA
  revocation;
- run direct-versus-translated differential tests;
- exercise all protected endpoint types together, including packed queues;
- prove destination reconstruction and rejection of changed topology/domain
  identity; and
- make any future non-x86 IOMMU backend implement the same platform ops rather
  than exposing amd64 pmap details in common code.

Do not advertise ACCESS_PLATFORM on an endpoint until every DMA path for that
endpoint has passed.  Balloon's PFN reporting is a special guest ABI and must
remain explicitly excluded from ordinary DMA translation.

### 4.4 Shared-memory regions

The common PCI capability/topology exists, with virtio-pmem as the current
provisional consumer.  Remaining work is live Linux split/packed mapping,
marker I/O, request-queue FLUSH, reset, suspend, checkpoint, backend identity,
capacity mismatch, repeated restore, and DTrace-correlated completion.

Virtio-fs DAX remains out of scope until a coherent shared-memory mapping,
invalidation, destination reconstruction, and guest-driver contract exists.
GPU blob resources are not evidence for this contract unless they actually
use a host-visible shared-memory region.

### 4.5 Device suspend and resume

The common status/fence model exists and the 5BSD transport has guest-side
work.  Pinned upstream Linux does not negotiate the VirtIO 1.4 Device Suspend
feature.  Remaining work is therefore both implementation/guest policy and
live qualification:

- lock the per-VM/device contract before DRIVER_OK;
- prove event-driven drain with no manual polling;
- inject delayed completion, NEEDS_RESET, failed resume, reset, detach, and
  checkpoint nesting;
- test PCI and a suitable modern-MMIO platform;
- prove all asynchronous backends close admission and drain ownership; and
- either maintain a Linux guest implementation, qualify rebuilt 5BSD, or
  state a narrower release scope.

### 4.6 Administration virtqueues and device groups

**Release scope: EXCLUDED (decision 2026-08-12).**  Administration
virtqueues, SR-IOV / device groups, and device-parts are intentionally NOT in
this release's scope.  The `virtio_admin*` queue, capability, group, resource,
device-parts, SR-IOV, and PCI models remain in-tree as rootless-tested
foundations, but no production device advertises `VIRTIO_F_ADMIN_VQ`, none is
wired to a real PF/VF topology, and none will be for this release.  This is an
explicit exclusion, not implicitly-partial work: `VIRTIO_F_ADMIN_VQ` stays
unadvertised and fail-closed, and SR-IOV is already dispositioned
`not-applicable` to the emulated topology in the completion matrix.  Whole-VM
live migration does NOT depend on this — device-parts migration is only for
migrating SR-IOV VFs, which this release does not offer.

If a future release adds SR-IOV/VF passthrough, the work below applies; until
then it is deliberately unbuilt.

The queue, capability, group, resource, device-parts, SR-IOV, and PCI models
exist in `virtio_admin*` and have rootless tests.  They are foundations only:
no production device advertises `VIRTIO_F_ADMIN_VQ`, no `pci_virtio_*.c`
registers a device-parts handler for real operation, and there is no real PF/VF
owner/member topology.

To finish (only if the exclusion above is reversed):

- choose a concrete PF/VF-capable device model and immutable group topology;
- wire VF Enable/NumVFs, identity, FLR/reset, suspend, state, and member
  command ownership;
- connect device-parts state to the same portable migration transaction;
- implement cancellation, queue saturation, invalid group/member/resource
  handling, and source rollback;
- run Linux administration-queue discovery and successful real commands; and
- keep all features unadvertised until those operations pass.

SR-IOV is not completed by a type-zero self group.

### 4.7 Portability and non-x86 readiness

Common VirtIO, DMA, interrupt, lifecycle, and state code must use fixed-width
little-endian records and explicit platform operations.  Remaining gates:

- synthetic opposite-endian and unaligned fixtures;
- 32/64-bit word-size and multiple page-size fixtures;
- no native pointer, fd, lock, pthread object, `size_t`, `long`, or raw host
  structure in state;
- architecture-specific CPU state outside portable device records; and
- build/model validation on arm64 and riscv, with real hardware/guest
  qualification when those platforms become release targets.

Intel nested VMX must stay under `sys/amd64/vmm/intel`; it must not change AMD
SVM or non-x86 behavior unless a common startup/lifecycle API is explicitly
selected.

## 5. Existing VirtIO devices

The exact normative section and requirement IDs for each line are in the
VirtIO requirement ledger.  Linux driver and QEMU comparison paths are listed
in the reference-corpus TSV.

### 5.1 Network

Production: `pci_virtio_net.c`, common VirtIO transport, net backends, and
5BSD `sys/dev/virtio/network/if_vtnet.c`.

Implemented foundations include multiqueue, control queue, RSS, hash report,
packed queues, queue-local reset, suspend, and portable state.  Remaining:

- rebuilt-5BSD packed, RSS, and hash-report activation;
- useful traffic and completions on every advertised queue pair;
- negative RSS key/table/hash-type and malformed indirect control commands;
- reset one queue while traffic continues on others;
- active-traffic repeated checkpoint/restore in split and packed modes;
- translated DMA qualification; and
- long concurrent traffic/reset/backend-loss soak.

### 5.2 Block

Production: `pci_virtio_block.c`, `block_if.*`, and 5BSD
`sys/dev/virtio/block/virtio_blk.c`.

Implemented foundations include multiqueue, CONFIG_WCE, discard,
write-zeroes, readonly, packed queues, reset, suspend, backend identity, and
portable state.  Remaining:

- rebuilt-5BSD multiqueue and packed activation;
- 5BSD write-zeroes/discard/readonly/WCE transitions;
- active-I/O repeated restore and backend replacement/identity rejection;
- translated DMA and reset during retained backend work; and
- filesystem/backend-specific discard qualification.

Secure erase is intentionally unsupported and unadvertised because the
backend cannot promise secure-erasure semantics.  It is complete only as an
explicit negative policy, not as a supported feature.

### 5.3 SCSI

Production: `pci_virtio_scsi.c`, CTL event interfaces under `sys/cam/ctl`, and
5BSD `sys/dev/virtio/scsi`.

Implemented foundations include multiqueue, event subscription, HOTPLUG,
CHANGE, EVENTS_MISSED, REPORT LUNS, packed queues, reset, suspend, CTL-bound
state, and portable queue/device state.  Remaining:

- rebuilt-5BSD packed and real multiqueue activation;
- live add/resize/remove without guest rescan, saturation/loss, and ordering;
- LUN add/remove/change races with active commands;
- active-command checkpoint policy and repeated restore;
- CTL identity/reconstruction and changed-destination rejection; and
- translated DMA qualification.

### 5.4 Console

Production: `pci_virtio_console.c`, console backends, and 5BSD
`sys/dev/virtio/console`.

Remaining:

- live two-port discovery, nomination, independent data, close, and reconnect;
- simultaneous host/guest close and blocked reader/writer reset races;
- emergency-write policy or explicit unadvertised status;
- active-port checkpoint policy and backend reconstruction;
- split/packed Linux and rebuilt-5BSD state tests; and
- deterministic reconnect semantics beyond sequential reconnect.

### 5.5 9P

Production: `pci_virtio_9p.c`, `contrib/lib9p`, `sys/fs/p9fs`, and the 5BSD
virtio-9P transport.

Remaining:

- rebuilt-5BSD split and packed mount/data qualification;
- reset during active requests and long fid/reconnect soak;
- live authentication/credential and intermediate-symlink isolation review;
- portable active-fid semantics, or retain and test the current explicit
  active-session checkpoint rejection;
- backend/export identity mismatch and repeated restore; and
- translated DMA qualification.

### 5.6 Input

Production: `pci_virtio_input.c` and 5BSD `sys/dev/virtio/input`.

Remaining:

- live rebuilt-5BSD split/packed bidirectional event/LED operation;
- multiple devices with distinct identities;
- reset during injection and blocked-client queue reset;
- active partial-frame checkpoint in both ring formats; and
- saturation, SYN_DROPPED, and stale-source qualification in a real guest.

VirtIO input has no normative dynamic capability-replacement command; do not
invent a configuration-change feature merely to satisfy an old checklist.

### 5.7 RNG

Production: `pci_virtio_rnd.c` and 5BSD `sys/dev/virtio/random`.

Remaining:

- rebuilt-5BSD packed activation;
- reset/rebind and source EOF/failure soak;
- checkpoint with a live reader and post-restore progress; and
- prove that no entropy bytes or host entropy-source state are serialized or
  replayed.

### 5.8 Vsock

Production: `pci_virtio_vsock.c`, userspace and kernel provider backends,
`sys/kern/uipc_vsock*`, `sys/dev/virtio/vsock`, MACF hooks, and 5BSD guest
driver.

STREAM, SEQPACKET, both host backends, multiple kernel providers, CID
isolation, packed Linux paths, and portable idle-backend state have broad
coverage.  Remaining:

- rebuilt-5BSD packed activation;
- multi-provider active checkpoint and destination CID collision handling;
- define active-connection migration/reconstruction, or continue to reject it
  explicitly and prove source rollback;
- jail/VNET namespace policy and delegated CID ownership;
- per-CID byte/queue limits beyond the connection ceiling;
- provider loss, reset, and descriptor-passing races; and
- long concurrent multi-VM soak for both backends.

## 6. New and provisional VirtIO devices

### 6.1 Balloon

Production files: `pci_virtio_balloon.c`, `virtio_balloon_host.*`, and 5BSD
`sys/dev/virtio/balloon`.

Baseline inflate/deflate is live-exercised.  Remaining optional-feature work:

- statistics queue;
- deflate-on-OOM under sustained pressure;
- free-page hinting and reporting;
- page poison interaction and preservation;
- invalid/duplicate PFNs, OOM recovery, detach-cancel, and withheld completion;
- packed activation; and
- active checkpoint/repeated restore on Linux and rebuilt 5BSD.

Each optional bit needs distinct host evidence; poison preservation cannot be
used to pass the reporting/discard path.

### 6.2 GPU 2D

Production files: `pci_virtio_gpu.c` and `virtio_gpu_2d_*`; 5BSD driver under
`sys/dev/virtio/gpu`.

The bounded 2D model, resources, blob state, EDID construction, display/RFB
path, cursor, DMA leases, and portable state exist.  Remaining:

- real Linux and rebuilt-5BSD create/back/scanout/transfer/flush operation;
- host presentation proof, resource/backing/cursor/rectangle boundaries, and
  malformed/fenced response tests;
- queue saturation and reset while presentation is active;
- split/packed active checkpoint and deterministic framebuffer readback;
- blob-resource restore and backend/scanout identity rejection; and
- ACCESS_PLATFORM permission/direction tests.

### 6.3 Virtio-fs without DAX

Production files: `pci_virtio_fs.c`, `virtio_fs_*`, and the authenticated
backend daemon/client protocol.  A 5BSD guest driver
(`sys/dev/virtio/fs/virtio_fs.c`) that bridges FUSE-over-virtio into fusefs was
added this cycle (build- and model-verified); the 5BSD implementation plan is
in `docs/waspnest-virtio-fs-5bsd-driver-plan.md`.  Unlike the other four new
drivers, the virtio-fs 5BSD **live** case is deferred because it needs a
`virtiofsd`-equivalent backend, so the FS 5BSD activation rows remain
`driver-gap`/`not-applicable` in the ledger rather than moving to `pending`.

Remaining:

- live Linux split/packed queue activation at q1/q2/q8;
- FUSE INIT and ordinary traffic on every request queue;
- credentials, namespace/path isolation, malformed FUSE requests, saturation,
  cancellation, reset, backend death, and reconnect;
- active and idle checkpoint policies, backend state transfer, repeated
  restore, and changed-export rejection;
- long node/handle/fid soak; and
- implement/qualify a 5BSD driver or explicitly declare Linux-only scope.

DAX remains blocked by the shared-memory/coherency work.

### 6.4 Virtio-mem

Production: `pci_virtio_mem.c` and `virtio_mem_host.*`.  A 5BSD guest driver
(`sys/dev/virtio/mem/virtio_mem.c`) was added this cycle, build- and
model-verified and in the -Werror module gate; it issues the PLUG protocol
toward `requested_size`.  Runtime memory onlining is intentionally out of
scope, a documented FreeBSD VM boundary (protocol-only).  The
`fivebsd-mem-modern` rows are now 5BSD `pending`, not `driver-gap`, and remain
live-only.

Remaining:

- live Linux PLUG, UNPLUG, UNPLUG_ALL, and STATE operations;
- rebuilt-5BSD `fivebsd-mem-modern` activation (host request-queue
  enable/notify correlation);
- busy/partial memory, alignment, capacity, invalid ranges, and concurrent
  memory workload;
- packed queues; and
- active-page checkpoint, repeated restore, and destination geometry/capacity
  rejection.

### 6.5 Virtio-pmem

Production: `pci_virtio_pmem.c`, `virtio_pmem_host.*`, queue, worker, and
asynchronous lifecycle modules.  A 5BSD guest driver
(`sys/dev/virtio/pmem/virtio_pmem.c`) was added this cycle, build- and
model-verified and in the -Werror module gate; it maps the advertised
shared-memory region as an nvdimm SPA.  The `fivebsd-pmem-modern` row is now
5BSD `pending`, not `driver-gap`; deterministic marker+flush byte correlation
stays live-only.

Remaining:

- live Linux shared-memory region mapping and deterministic marker I/O;
- rebuilt-5BSD `fivebsd-pmem-modern` activation (host request-queue enable
  correlation);
- split/packed FLUSH, reset, suspend, callback generation, and failure paths;
- active-I/O checkpoint, same-PID progress, backend identity/capacity
  rejection, and independent repeated restores; and
- DTrace-correlated submit/completion.

### 6.6 Virtio-RTC

Production: `pci_virtio_rtc.c`, `virtio_rtc_host.*`, alarm module, and 5BSD
`sys/dev/virtio/rtc`.

Remaining:

- live Linux and rebuilt-5BSD split/packed clock operation;
- alarms, forward/backward time steps, missed-alarm prevention, disable races,
  and timer-source failure;
- suspend/resume with an armed alarm; and
- repeated restore with exact notification and destination clock policy.

### 6.7 Virtio-sound

Production: `pci_virtio_snd.c`, `virtio_snd_*`, common `audio.*`, null and OSS
backend paths.  A 5BSD guest driver (`sys/dev/virtio/sound/virtio_snd.c`) was
added this cycle, build- and model-verified and in the -Werror module gate; the
`fivebsd-sound-modern` lane drives probe/attach, control-queue negotiation, and
a bounded PCM playback with host queue-enable/notify correlation and fails
closed otherwise.  Its rows are now 5BSD `pending`, not `driver-gap`, and
remain live-only.

Remaining:

- live Linux control, playback, and capture on representative OSS devices;
- rebuilt-5BSD `fivebsd-sound-modern`/`fivebsd-sound-packed` activation;
- format/rate/channel negotiation, underrun/overrun, partial nonblocking I/O,
  provider loss, reset, and callback-generation races;
- split/packed active PCM checkpoint, reconstruction, endpoint mismatch, and
  repeated restore; and
- long playback/capture soak.

The null backend proves protocol mechanics, not production audio behavior.

### 6.8 VirtIO-IOMMU as a device

In addition to the common DMA work in section 4.3, the device needs live
config, VIOT, request, event, queue publication, packed, translation-state,
and checkpoint cases.  A 5BSD guest driver
(`sys/dev/virtio/iommu/virtio_iommu.c`) was added this cycle, build- and
model-verified and in the -Werror module gate; it parses config and publishes
its request/event queues, so `IOMMU-CONFIG` and `IOMMU-QUEUE-PUBLICATION` are
now 5BSD `pending` rather than `driver-gap`.  ATTACH/MAP translation is
protocol-only for now — it needs a downstream endpoint fabric and no MI busdma
IOMMU hook exists, a documented boundary — so the translation/save-state rows
correctly remain 5BSD `driver-gap`.  The Linux rows remain `pending`.

### 6.9 Administration, crypto, video, and SCMI

Administration/device-parts is an unadvertised foundation as described above.
Virtio-crypto and virtio-video remain deferred until a real backend and
workload exist.  The in-tree 5BSD VirtIO-SCMI guest work is not a reason to
invent an x86 device; production SCMI requires an ARM platform-management
backend and ARM bhyve qualification.

## 7. Portable save/restore and migration

### 7.1 Implemented foundations

The tree has substantial state infrastructure:

- fixed-width checkpoint manifest and compatibility envelopes in
  `checkpoint_manifest.*`, `snapshot.*`, and the portable snapshot helpers;
- device pause/resume/validate/snapshot callbacks;
- backend identity and topology records for many VirtIO devices;
- descriptor-owned kernel event-fence/session APIs;
- destination restore staging and failure fencing;
- dirty tracking in `migration_dirty.*`;
- CPU/device pre-copy generation composition in `migration_precopy.*`; and
- extensive codec, truncation, alias, version, rollback, and repeated-restore
  model tests.

These foundations are not a complete migration product.

### 7.2 VirtIO device state still requiring live closure

The activation ledger has explicit save-state rows for net, block, RNG,
console, SCSI, input, vsock, 9P, IOMMU, sound, memory, GPU, PMEM, balloon, RTC,
and combined-device cases.  Close each with:

- active distinguishing work during checkpoint;
- bounded quiesce and failure rollback that leaves the source usable;
- no stale completion or callback after restore;
- backend identity/reconstruction and changed-destination rejection;
- split and packed records;
- two independent restores of one sealed checkpoint;
- truncated, unknown-version, feature, queue-geometry, topology, and capacity
  mutation; and
- combined-device restore with translated DMA where applicable.

Where active external state is intentionally nonportable (for example a live
9P fid, console socket, or vsock connection), the release contract may reject
checkpoint.  That rejection must happen before destructive mutation and the
source must resume correctly.  It must not be mislabeled active migration.

### 7.3 Whole-machine snapshot gaps outside VirtIO

The VirtIO ledgers do not prove a general bhyve checkpoint.  The Phase A
data-loss gaps identified by earlier source inspection were **closed this
cycle** (implemented + model-tested; live checkpoint qualification of a
source-matched install is still pending):

- `pci_nvme.c`, `pci_hda.c`, and `pci_uart.c` now register `pe_snapshot`
  callbacks, so a VM using those PCI devices can be checkpointed;
- xHCI now has a pause/resume quiesce fence for in-flight USB work;
- guest `vcpu->guestfpu` XSAVE/FPU/SSE/AVX state now has a snapshot record;
- IA32_XSS/supervisor XSAVE state and IA32_SPEC_CTRL policy are resolved
  fail-closed;
- the IOAPIC snapshot now captures its guest-writable `id`;
- the LAPIC `svr_last` shadow is now handled on restore; and
- PIT `now_bt` is now reanchored on the destination.

These were high priority because a checkpoint that succeeds while silently
losing CPU vector state is worse than a fail-closed unsupported device; that
silent-loss class is now addressed in the model.

Remaining live-only residual: qualify these records against a real
checkpoint/restore on a source-matched installation, and continue the
`pe_pause`, `pe_resume`, `pe_snapshot`, `pe_snapshot_validate`, and
`pe_migration_flags` inventory for any other non-VirtIO PCI device before it is
declared checkpoint-eligible.

### 7.4 Live migration: control plane and cutover exist (loopback-proven)

This is no longer "not wired end to end."  Beyond the
`migration_precopy_enable()`, `collect()`, and `disable()` pre-copy
foundations, a real management **control plane** and the stop-and-copy
**cutover** now exist and are loopback- and model-proven (see
`docs/bhyve-migration-design.md`):

- a versioned session protocol
  (HELLO/CAPS/TOPOLOGY/MEM_GEN/DEV_STATE/FINAL/COMMIT/RELEASE) drives source
  pre-copy, destination staging, final stop-and-copy, and commit;
- multi-frame chunking carries memory generations and device state;
- a snapshot-reuse `dev_state` bridge reuses the checkpoint device-serialization
  path for the DEV_STATE phase;
- a `bhyve -R` destination listener stages and resumes the incoming machine;
- highmem and the MMIO hole are covered; and
- the one-copy invariant holds: the source becomes defunct only after RELEASE
  and the destination resumes only after RELEASE, so the guest is never live in
  two places.

Remaining live-only residual (two-host, not "missing code"):

1. listener authentication on the destination `-R` endpoint;
2. per-device compatibility-identity checks across the two hosts;
3. kernel dirty-log confirmation under a real two-host run;
4. cross-version compatibility fixtures and downgrade/rejection policy; and
5. expand `pe_migration_flags` to each additional device only when its
   external-state contract is real.

QEMU's VMState and migration code is the device-side behavioral comparison;
KVM's versioned state APIs are a CPU-state comparison.  Neither defines
bhyve's wire protocol.

### 7.5 Architecture portability

Device state can be portable across host architectures; CPU state generally
cannot be assumed portable.  The manifest must explicitly describe source
architecture, CPU model/capabilities, page size, interrupt controller, and
architecture-specific record versions.  Cross-ISA restore should fail before
publication unless a reviewed conversion exists.

## 8. Intel nested VMX

Nested VMX is experimental, Intel-only, default-off, and additionally
per-guest opt-in.  It must not affect AMD SVM or arm64/riscv except through
reviewed architecture-neutral lifecycle APIs.

### 8.1 The four INIT/SIPI rows: implemented and model-tested this cycle

These four rows were implementation blockers; they are now implemented and
model-tested and were re-filed from `pending` to `experimental-pending-live`.
The Intel adapter binds the frozen INIT/SIPI machine transaction; the AMD
adapter is fail-closed by design; scope is Intel-only.  This is
implementation-plus-model evidence only — installed-kernel and live L1/L2
Intel qualification (BSP-targeted and mixed-target) is still required, and the
descriptions below now record what was built rather than what is missing:

#### NVMX-EVENT-048: acknowledged L0 startup completion ownership

The historical userspace IPI/SPINUP_AP exit is unacknowledged.  Selecting or
copying out the exit cannot be treated as completion of an INIT/SIPI claim.
Either preserve that ABI only for the default userspace owner and implement a
separate immutable kernel owner, or add a versioned target-specific
acknowledgment protocol with duplicate, partial-failure, process-death,
copyout-failure, reset, checkpoint, and teardown semantics.

#### NVMX-EVENT-050: complete kernel-owned INIT/SIPI transaction

Implement one frozen-target, rollback-capable machine transaction.  INIT must
derive CPUID signature, CR0, and BSP role once; reset the SDM-defined register
and segment state; clear pending exception/interrupt/NMI/reinjection and nested
ownership; reset LAPIC and translation state; keep the BSP runnable at its
reset path; and put APs in wait-for-SIPI without resetting architecturally
unchanged x87/vector/MSR/time state.  SIPI is accepted only in wait-for-SIPI
and changes exactly the startup CS:RIP state before waking the target.

Intel and AMD adapters must either commit every side effect or roll back every
mutation.  The common API cannot expose a half-reset vCPU.

#### NVMX-EVENT-058: event-driven wait-for-SIPI lifecycle

Separate wait-for-SIPI from debugger suspension and VM-wide suspension.  Lock
the owner while vCPUs are frozen, derive one BSP from virtual
IA32_APIC_BASE.BSP, precreate/enter every configured vCPU for kernel mode, and
sleep APs on generation-bound interruptible events.  Rendezvous, reset,
destroy, and signals must not lose wakeups.  Default userspace VM_EXITCODE_IPI
and SPINUP_AP behavior must remain unchanged.

#### NVMX-EVENT-102: BSP INIT restart semantics

The historical userspace path suspends every INIT destination, including the
BSP.  Do not reuse the cold `vcpu_reset` helper: it is not the SDM INIT
transaction and is not atomic.  Kernel ownership must restart the BSP at the
reset vector while APs wait for SIPI, with BSP-targeted and mixed-target live
tests.

### 8.2 Next implementation tranche

The immediate production tranche should be:

1. add a pure startup delivery decision to `vmm_startup_mode.*`;
2. add one coordinator operation that selects userspace versus kernel owner
   and publishes a whole target set atomically under the coordinator
   transaction lock;
3. add VM wrappers which validate targets and notify only after successful
   kernel publication;
4. route LAPIC INIT/SIPI through that operation while preserving the existing
   userspace exit byte-for-byte;
5. fail closed on routing errors rather than falling back and duplicating an
   event;
6. add owner-selection, alias, invalid-kind, empty-mask, cancellation,
   checkpoint-active, reset, and output-immutability tests; and
7. then implement the complete frozen machine-state transaction and
   wait-for-SIPI scheduler contract described above.

The routing tranche alone does not complete NVMX-EVENT-050; it only closes the
atomic ownership/publication boundary needed by the full machine transaction.

Relevant common files:

- `sys/dev/vmm/vmm_startup_mode.*`;
- `sys/dev/vmm/vmm_event_coordinator.*`;
- `sys/dev/vmm/vmm_vm.*`;
- `sys/dev/vmm/vmm_startup_event.*` and controller/handshake modules; and
- `sys/amd64/vmm/io/vlapic.c`.

Relevant Intel files are `sys/amd64/vmm/intel/vmx.c` and the
`vmx_nested_*` modules.  Keep Intel VMCS02, EPT, VPID, MSR, and hardware-entry
details out of common VMM files.

### 8.3 Live-pending requirements

With the four INIT/SIPI rows now re-filed to `experimental-pending-live`, the
nested ledger holds 29 `experimental-pending-live` rows in total.  Besides the
four INIT/SIPI rows (§8.1), the following 25 still require privileged
evidence:

- EPT/EPT02: `NVMX-EPT-008`, `NVMX-EPT-013`;
- runtime ownership and CPU-local refresh: `NVMX-RUNTIME-036`,
  `NVMX-RUNTIME-043`, `NVMX-RUNTIME-066`, `NVMX-RUNTIME-067`,
  `NVMX-RUNTIME-068`;
- exposure policy: `NVMX-EXPOSE-001`;
- event/MTF/debug/coordinator publication: `NVMX-EVENT-006`,
  `NVMX-EVENT-008`, `NVMX-EVENT-016`, `NVMX-EVENT-017`,
  `NVMX-EVENT-018`, `NVMX-EVENT-019`, `NVMX-EVENT-022`,
  `NVMX-EVENT-024`, `NVMX-EVENT-026`, `NVMX-EVENT-027`,
  `NVMX-EVENT-028`, `NVMX-EVENT-029`, `NVMX-EVENT-032`;
- destruction/owner integrity: `NVMX-STATE-038`, `NVMX-STATE-039`;
- checkpoint publication: `NVMX-STATE-040`, `NVMX-STATE-043`.

The full text, code mapping, and model tests are in the nested requirements
TSV.  Do not replace those texts with this summary.

### 8.4 Twelve live qualification groups

`run-vmx-nested-live.sh` and the live ledger require distinct Linux-L2,
5BSD-L2, and host evidence for:

1. exposure policy;
2. VMX instructions;
3. VM-entry validation;
4. exit reflection;
5. EPT/INVEPT;
6. VPID/INVVPID;
7. interrupt/APIC behavior;
8. timer/TSC behavior;
9. startup-owner lifecycle;
10. active checkpoint;
11. concurrency/soak; and
12. checkpoint publication.

Required inputs are a reviewed root-owned L1 runner, a Linux/KVM L1 image, a
Linux L2 image, and a 5BSD L2 image.  Evidence must cover all requirement IDs
assigned to each group, not merely show that an L2 booted.

### 8.5 Nested save/restore work

The tree has versioned VMXON/current-VMCS/VMCS12 registry, VMCS02 planning,
portable cold L2 state, EPT/VPID reconstruction, continuation, and active-L2
checkpoint models.  Remaining proof and possible implementation include:

- active L2 freeze/restore while real hardware is executing;
- destination capability-signature rejection;
- CPU migration between frozen preparation and final pinned entry;
- VM-entry rejection and L0 failure at every preparation/finisher boundary;
- interrupt/APIC/timer/EPT/VPID state across restore;
- repeated restore of one sealed checkpoint;
- restore while an L0 continuation or pending event exists; and
- no serialization of a hardware VMCS or host pointer.

Current userspace rejects combining kernel-owned startup with restore because
the restore hold and all-vCPU startup commit can deadlock.  Do not remove that
check until startup admission and restore-release fences are explicitly
composed.

### 8.6 Nested capability audit

Before exposure, regenerate a requirement-to-capability table from the Intel
SDM and prove every advertised allowed-one bit has validation, VMCS02
composition, execution, exit handling, reset, and save/restore.  Recheck the
independent findings concerning five-level EPT representation and
save-preemption-timer writeback against current production call paths.  If a
path is not complete, mask the capability rather than relying on a model
helper.

## 9. Review loop required for every tranche

Run these lenses independently and rotate their order:

1. **Normative conformance:** requirement-to-code-to-independent-test map,
   feature dependencies, reserved fields, byte order, and truthful exposure.
2. **Lifecycle/concurrency:** allocation to destruction, lock order, memory
   ordering, reset, suspend, checkpoint, cancellation, wakeups, rollback, and
   stale callbacks.
3. **Portability/state:** native-layout leakage, pointer/fd persistence,
   endian/word/page size, overflow, architecture isolation, and destination
   compatibility.
4. **Linux/QEMU comparison:** negotiation, descriptor use, error behavior,
   reset, and migration differences, classified as intentional or defective.
5. **Test falsification:** shared constants, mocks that remove the target
   behavior, weak assertions, nondeterministic sleeps, environment leakage,
   and tests which pass without activating the feature.
6. **Maintainability/operations:** duplicate mechanisms, device-specific
   workarounds that belong in common code, dead code, hardcoded limits,
   polling, unbounded resources, logging/rate limits, DTrace, and hot-path
   cost.
7. **Release-kernel review:** no required side effect inside `assert`,
   `KASSERT`, or INVARIANTS-only code; run `-DNDEBUG` userspace and
   non-INVARIANTS kernel reasoning/build gates.
8. **Negative/fault review:** every validation and backend operation fails at
   the first, middle, and final mutation boundary without partial publication.

After fixes, rerun the focused suite, then the complete rootless suite, then
the live profile.  Continue until a fresh synthesized pass finds no new high
or medium issue.  A clean review does not waive unrun live evidence.

## 10. Ordered execution plan

### Phase A: close correctness and snapshot data-loss gaps

**Status: implemented + model-tested this cycle (live checkpoint/nested
qualification still pending); see §1A, §7.3, and §8.1.**

1. Complete the nested INIT/SIPI ownership and frozen machine transaction.
   (Done in model; rows now `experimental-pending-live`.)
2. Add guest XSAVE/FPU state to the architecture-specific snapshot contract.
   (Done.)
3. Implement NVMe snapshot support; then HDA and PCI UART, and xHCI quiesce.
   (Done.)
4. Resolve PIT uptime reanchoring, IOAPIC ID, LAPIC shadow, IA32_XSS, and
   IA32_SPEC_CTRL decisions.  (Done; XSS/SPEC_CTRL fail-closed.)
5. Revalidate all open high/major findings in `docs/vmm-bhyve-bugs.md`.
   (Done: 16 fixed plus the two XSS/SPEC_CTRL findings resolved.)

### Phase B: close common VirtIO activation

1. Packed queues and transport lifecycle across every existing device.
2. ACCESS_PLATFORM/VirtIO-IOMMU with all endpoint types.
3. Shared-memory/PMEM.
4. Device suspend with a supported guest policy.
5. Administration/device groups only after choosing a real PF/VF owner.

### Phase C: close existing devices

Order by operational value and dependency: net, block, SCSI, console, RNG,
vsock, 9P, and input.  Close Linux, rebuilt-5BSD, reset, checkpoint,
translated-DMA, combined, and soak rows for each before promotion.

### Phase D: close provisional devices

Balloon optional features, GPU 2D, virtio-fs, virtio-mem, PMEM, RTC, sound,
then VirtIO-IOMMU as a fully qualified device.  For each missing 5BSD driver,
choose implementation or an explicit Linux-only release scope.

### Phase E: complete migration

**Status: control plane and cutover implemented this cycle, loopback-proven
(§7.4, `docs/bhyve-migration-design.md`); live two-host qualification still
pending.**  The session protocol, multi-frame chunking, snapshot-reuse
`dev_state` bridge, `bhyve -R` listener, and highmem coverage exist.  Remaining:
listener authentication, per-device compatibility identity, kernel dirty-log
confirmation under a real two-host run, cross-version/downgrade fixtures, and
expanding eligible devices only with real external-state contracts, then run
cross-version, failure, reconnect, and repeated migration tests.

### Phase F: qualify Intel nested VMX

Keep it default-off.  Complete all four pending rows, pass rootless model and
module builds, then run Linux/KVM L1 with Linux and 5BSD L2 through all twelve
live groups, active-L2 checkpoint, CPU migration, fault injection, and soak.
Only then reconsider exposure defaults.

### Phase G: release qualification

Build and install a source-matched world, kernel, modules, tests, and packages.
Reboot into that kernel.  Run the sealed-corpus, host regression, release,
checkpoint, bounded soak, audio, migration, and nested profiles.  Preserve
manifests, hashes, DTrace/audit artifacts, guest evidence, and failure logs.

## 11. Test entry points

Rootless/model gates:

```sh
RESULT_FILE=/tmp/waspnest-device-harness.result \
  sh tests/sys/kern/vsock_device_harness/run.sh

RESULT_FILE=/tmp/waspnest-nested-model.result \
  VMX_NESTED_BUILD_JOBS=2 sh tests/sys/vmm/run-vmx-nested-model.sh

RESULT_FILE=/tmp/waspnest-snapshot-model.result \
  sh tests/sys/kern/vsock_device_harness/run-snapshot-model.sh

/usr/libexec/flua tests/sys/kern/vsock_e2e/virtio-lab.lua \
  run --profile vmfree --jobs 1 --workdir /tmp/waspnest-vmfree
```

Privileged orchestration is documented in
`docs/waspnest-qualification-handoff.md`.  The complete profile is
`full-qualification`, which composes release, checkpoint, soak, nested,
audio, and checkpoint-audio.  It additionally needs a real migration profile
once the control plane in section 7.4 exists.

Use `plan` first and require every expected `COVERED` marker.  A terminal
result file and final summary are authoritative; `RUNNING`, a guest boot, or
feature negotiation alone is not a pass.

## 12. Definition of done

The work is complete only when all of the following are true:

- no required VirtIO activation row remains `pending` or `driver-gap` unless
  that guest/platform is explicitly excluded from release scope;
- no nested requirement remains `pending` or `experimental-pending-live`;
- all twelve nested live groups have accepted Linux-L2, 5BSD-L2, and host
  evidence;
- every advertised feature has an independent oracle and distinguishing live
  operation;
- every supported device has reset, suspend where advertised, checkpoint,
  backend reconstruction, repeated restore, fault, and soak evidence;
- every supported whole-VM device and CPU state class is either serialized
  correctly or causes a pre-mutation fail-closed rejection;
- pre-copy and final migration are reachable through a reviewed management
  transaction and have passed failure/cutover tests;
- no unresolved high or medium correctness finding remains;
- world, kernel, modules, tests, bhyve with and without snapshot support, and
  packages build cleanly with the required warning modes;
- rootless sanitizer/model gates pass;
- Linux, rebuilt-5BSD, checkpoint, migration, audio, bounded-soak, and Intel
  hardware gates pass from one source-matched installation; and
- a final rotated review finds no new actionable issue.

Until then, describe the tree as a broad experimental/provisional VirtIO 1.4,
portable-state, and nested-VMX implementation—not as feature complete.
