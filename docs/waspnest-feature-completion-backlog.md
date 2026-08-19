# WASPNest feature-completion backlog

Date: 2026-08-11 (revised 2026-08-13)

This backlog is the implementation gate preceding privileged qualification.
It is derived from the current requirement and activation ledgers, then
checked against the executable production fences.  A named live test is not
used to hide a missing feature, guest driver, or runtime transaction.

The authoritative ledger inventory and completion rules are in
`docs/waspnest-completion-matrix.md`.  Counts in dated review records are
historical snapshots and do not override that matrix or its source TSV files.

## Current classification

| Class | Current evidence | Meaning |
| --- | --- | --- |
| Host model implemented | 237 of 240 VirtIO requirement entries marked `implemented-tested` | Rootless wire, lifecycle, and negative tests exist; this is not live qualification. |
| Intentionally unadvertised | block secure erase; platform ordering and SR-IOV are not applicable to this emulated topology | Keep unadvertised unless an explicit, reviewable backend/platform contract is added. |
| Live-only evidence pending | 130 activation rows classify Linux and 5BSD independently as `exercised`, `pending`, `driver-gap`, or `not-applicable` | No host code work is inferred solely from this status. |
| Guest-driver/platform gap | rows marked `driver-gap` or `not-applicable` for a guest family | Requires a driver, a supported guest interface, or an explicit release-scope exclusion. |
| Ready for privileged qualification | Intel nested VMX runtime ownership bridge; the kernel-owned INIT/SIPI machine transaction (`NVMX-EVENT-048/050/058/102`); five new 5BSD VirtIO guest drivers (sound, fs, mem, pmem, IOMMU); block/SCSI multiqueue and net/transport packed guest work | Implemented and model-tested this cycle; the four nested rows moved to `experimental-pending-live` and the driver rows to 5BSD `pending`.  Exposure and any live claim remain blocked until privileged Intel and rebuilt-5BSD qualification passes; none of this is `exercised`. |

The table is intentionally conservative.  A rootless host model may move a
feature into the first class but cannot erase guest-driver or hardware work.

## Blocking implementation work

### 1. Intel nested VMX production runtime transaction

The implementation portion of this item is complete and ready for privileged
qualification.  The former model-only adapter is linked into `vmm.ko` and
called by the three initial/resumed/hot admission paths.  The implementation
stage predicate and Intel machine-readiness gate are true; the host tunable is
still default-off and each guest must explicitly request the immutable VM-wide
nested-VMX CPU model.

- `vmx_startup_kernel_actions_ready()` in `sys/amd64/vmm/intel/vmx.c` returns
  `true` after the all-path owner conversion.
- `vmx_run_nested()` uses a source-ordered owner transaction: a declined
  admission performs the selected initial rollback, resumed refreeze, or hot
  freeze before it resolves the captured common result; hardware attempts are
  settled only after their Intel-private finisher classifies them.
- `VMX_NESTED_STAGE_ENTRY_TRANSACTION` is present in
  `NVMX_IMPLEMENTED_STAGES` and is required by the exposure predicate.
- `vmx_nested_owner_outcome.c` is linked into `vmm.ko`; the rootless module
  runner verifies that its production symbols are present.

Release qualification still requires privileged live validation of the
source-ordered
runtime transaction that couples each
pre-entry and post-entry outcome with its matching private inverse:

1. initial-entry rollback;
2. resumed-entry refreeze;
3. hot-exit freeze;
4. fatal detach;
5. no-entry software exit; and
6. common startup-owner settlement only after residency is safe.

It must preserve the current fail-closed behavior for every unclassified
edge.  Do not enable the stage bit, VMX exposure, or management startup
actions until the runtime bridge, its failure inverses, and model coverage are
complete.

#### Required runtime edge map

The Intel-private model in `vmx_nested_owner_outcome.c` is a specification for
the common-owner boundary, not permission to change the production stage bit.
The production bridge must cover the following paths in `vmx_run_nested()`.
The *private completion* column must happen before the associated common-owner
call; an error in either operation is terminal and must not be converted into
a retry or a synthetic VM exit.

| Run-path result | Private completion before owner settlement | Common owner operation | Required result |
| --- | --- | --- | --- |
| Early suspend/rendezvous/idle/yield/debug, before L2 resources | none | `software_exit` | typed no-entry return |
| Guard declines before an initial VMCS02 instruction | initial rollback | `resolve_deferred` | preserve deferred result |
| Guard declines before a resumed VMCS02 instruction | unentered refreeze | `resolve_deferred` | preserve deferred result |
| Initial hardware entry returns an L2 VM exit | establish entered state | `commit_attempt` | owner is committed |
| Initial VM-entry rejection | rollback completed by initial finish | `abort_attempt` | software no-entry result |
| Initial L0/hardware failure | matching rollback or fatal detach | `abort_attempt_error` | original terminal error |
| Resumed hardware entry returns an L2 VM exit | establish resumed hot state | `commit_attempt` | owner is committed |
| Resumed VM-entry failure | unentered refreeze completed by resumed finish | `abort_attempt` | software no-entry result |
| Locally handled L0 exit followed by another L2 attempt | retain hot residency | `guard_after(... handled ...)` | recheck before every re-entry |
| EPT walk, direct reflection, or unhandled L0 exit | publish or freeze the L1-visible result | `guard_after_defer`, then deferred resolution | no result escapes while VMCS02/L2 state is retained |

#### Failure-classification constraints

The bridge must not use `abort_attempt()` as a generic error cleanup.  That
operation asserts a conclusively *unentered* attempt.  The current source has
enough information to distinguish the following additional cases:

| Failure point | Owner state that is safe to publish | Required treatment |
| --- | --- | --- |
| Entry-event, VMCS02, MSR, or EPT preparation fails before the owner has been admitted | running/recheck | finish the Intel-private inverse, then use a terminal no-entry result |
| Guard itself declines after private preparation | deferred pre-entry | finish the selected rollback/refreeze/freeze, then resolve the captured deferred result |
| Initial/resumed finisher reports VMfail after its documented rollback/refreeze completion | entry pending | settle the classified attempt: rejection is software; an L0 failure is terminal |
| VMX instruction returned, but report capture/classification fails before an authoritative entered/unentered result | entry pending, after the selected private unwind has made the CPU-local state safe | settle a terminal `abort_attempt_error()`; do not convert this to a replay or an invented VM exit |
| A committed L2 exit encounters a later routing/publication failure | in guest | complete the route-specific freeze/detach, defer the post-entry owner result, then publish the terminal error |
| A hot continuation is stopped before the next hardware re-entry | recheck | freeze/publish first, then complete a typed no-entry exit; do not consume a previous L2 entry twice |

This distinction is particularly important for a VMfail-valid report: Intel
defines it as a failed VMX instruction, while a failure to *obtain* a valid
report after the instruction has returned is an implementation integrity
failure.  The latter may be reported only as a terminal common-owner error
after the selected private unwind has made CPU-local state safe; it may never
be normalized into replay or a synthetic VM exit.

The private unwind action is initialized to an explicit fail-stop sentinel
before any validation or inverse operation.  Both common-owner bridges reject
that sentinel.  Thus an unexpected failure that occurs before an inverse has
established safe CPU-local residency cannot be composed from an indeterminate
action and published as a guest-visible replay or exit.

This table is intentionally architecture-specific.  The generic
startup-owner API stays in `sys/dev/vmm`; the VMCS02, L2-MSR, EPT, TSC_AUX, and
Intel instruction-state sequencing stays in `sys/amd64/vmm/intel`.

#### Required admission placement

The common admission observation is not interchangeable with a generic
``before entering the guest`` check.  `vmx_run_nested()` owns three distinct
private preparation states, and the common owner must be sampled at the
following points:

| Attempt class | Required placement | Declined-attempt inverse |
| --- | --- | --- |
| Initial L2 entry | After VMCS02/MSR preparation has made the initial rollback available, but before pmap activation, debug-register entry, or `vmx_enter_guest()` | abort the entry-event transaction, then initial hardware rollback |
| Resumed cold continuation | After the resumed VMCS02/MSR preparation has made an unentered refreeze available, but before pmap activation, debug-register entry, or `vmx_enter_guest()` | abort the entry-event transaction, then unentered refreeze |
| Re-entry of a hot L0 continuation | Before hot-resume preparation consumes the freezable `L0_EXIT` continuation | hot-exit freeze and continuation publication |

The event-plan shutdown and synthetic-reflection branches occur before those
admission points.  They are typed no-entry software exits and must settle the
owner with `software_exit`; they must never manufacture an attempted L2
entry.  Conversely, the common `commit_attempt` follows only an authoritative
hardware VM-exit classification and its matching Intel-private completion.
This placement rule prevents both an unavailable rollback and an accidental
second live observation during cleanup.

### 2. Guest-driver completion decisions

The feature baseline needs an explicit decision for every driver gap.  A
driver source file is not, by itself, proof that it negotiated the feature
with this device model; conversely, a pending live-activation row is not
evidence that the driver is absent.

| Guest-side class | Current source inventory | Completion condition |
| --- | --- | --- |
| Shared FreeBSD transport | `virtqueue.c`, modern PCI, and MMIO transport implement split/packed selection and suspend negotiation | Prove negotiated packed/suspend behavior in a real guest for each advertised device; retain a per-device fallback when the driver does not accept the feature. |
| Existing FreeBSD device driver | net, block, SCSI, console, RNG, input, 9P, balloon, GPU, RTC, and vsock have in-tree drivers | Exercise the relevant advertised feature in a real FreeBSD guest.  This includes multiqueue, control/event queues, optional queues, reset/rebind, suspend, and restore where the device claims support. |
| New 5BSD driver this cycle (model-verified, live-pending) | virtio-sound, virtio-mem, virtio-pmem, and virtio-IOMMU now have in-tree 5BSD guest drivers (build- and model-verified, in the -Werror module gate) | Their config/operation activation rows moved from 5BSD `driver-gap` to `pending` with scheduled `fivebsd-*` live cases.  virtio-mem exposes protocol only (no runtime onlining) and virtio-IOMMU protocol only (no busdma translation), both documented FreeBSD/MI boundaries.  Cannot be claimed cross-guest complete until a live Intel-host pass. |
| No stock FreeBSD driver | virtio-fs (5BSD live case deferred pending virtiofsd; the host-side FUSE-over-virtio bridge exists) | Implement a supported driver, provide an equivalent supported guest interface, or explicitly declare a Linux-only release scope.  Cannot be claimed cross-guest complete meanwhile. |

- **Existing-driver activation work:** packed-ring activation, device suspend,
  console lifecycle, RTC/alarm, input, 9P, GPU, balloon optional queues,
  block/SCSI multiqueue and events still require independent 5BSD live
  evidence against the host implementation.  They are activation and
  conformance work, not a claim that the base driver is missing.
- **Feature-level 5BSD gaps recorded by the activation ledger:**
  ACCESS_PLATFORM/IOMMU operation; balloon free-page hint/reporting; console
  emergency-write; virtio-fs config, queue, packed, and
  suspend paths; GPU 2D, EDID, blob, shared-memory, and DMA-permission paths;
  virtio-mem and virtio-pmem; 9P selective queue reset; sound queues, PCM,
  save-state, and packed paths; and the common shared-memory-region contract.
  Some of these sit beneath an existing base driver and others require a new
  driver.  In both cases they remain implementation work, rather than tests
  that may be waived because a different device attached successfully.
- **New 5BSD guest drivers this cycle (model-verified, live-pending):**
  virtio-sound, virtio-mem (protocol-only; no onlining), virtio-pmem, and
  virtio-IOMMU (protocol-only; no busdma translation) now have in-tree 5BSD
  drivers built under the -Werror module gate.  Their config/operation rows
  are 5BSD `pending`, not `exercised`; a live Intel-host pass is still
  required before any cross-guest claim.
- **No stock 5BSD driver:** virtio-fs.  The host FUSE-over-virtio bridge
  exists but the 5BSD live case is deferred until a `virtiofsd`-equivalent
  backend is available; either finish a supported guest driver and backend or
  declare the feature Linux-only before release.  It may not be reported as
  cross-guest complete.
- **Linux core limitation:** upstream Linux does not negotiate VirtIO 1.4
  Device Suspend.  This requires a maintained guest-side implementation for
  a Linux claim or a 5BSD-only device-suspend release contract.

### 3. Host optional-feature decisions

The following remain intentionally bounded until a production contract is
selected and implemented:

- block secure erase (requires a backend guarantee; currently unadvertised);
- physical SR-IOV/device groups (requires real PF/VF topology and host
  resource ownership);
- DAX for virtio-fs (requires completed shared-memory and coherency contract);
- full production display/audio backend policies for GPU and sound.

These should be marked intentionally unsupported for the baseline unless a
concrete product requirement promotes them to implementation work.  A helper
or model alone is insufficient.

## Feature-completion rule

Before privileged testing begins, every row in this document and in the
activation ledger must be classified as one of:

1. implemented and ready for live qualification;
2. intentionally unsupported and not advertised; or
3. guest/platform gap with the release scope explicitly excluding that guest
   or platform.

No row may remain implicitly partial.  After that classification, live tests
are evidence of the completed implementation rather than a discovery process
for missing architecture.
