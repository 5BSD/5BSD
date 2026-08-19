# WASPNest test-readiness plan

The authoritative current inventory and completion-state definitions are in
`docs/waspnest-completion-matrix.md`.  This document describes execution order;
it must not duplicate or override the TSV-ledger status.

Date: 2026-08-09

This is the execution plan between implementation work and privileged
qualification.  It does not promote a feature merely because it builds or
because a host-model test passes.  The source of truth for individual feature
status remains `virtio-feature-activation.tsv`; the VirtIO requirement ledger
and VMX requirement ledger provide the requirement-to-code-to-test mapping.

## Status vocabulary

- **model-verified**: independent rootless test and relevant source validator
  pass.  This does not imply guest-driver or hardware activation.
- **live-qualified**: the documented Linux and, where a driver exists, 5BSD
  guest activation test passes on the production device model.
- **release-qualified**: live-qualified plus checkpoint/reset/fault and soak
  gates appropriate to the feature have passed.
- **driver gap**: the guest family has no suitable driver.  The feature must
  not be described as qualified for that guest.

## Phase 1 — inventory and truthfulness

1. Run the independent VirtIO and nested requirement validators.
2. Run the feature activation and nonstandard-interface validators.
3. Confirm every advertised optional feature has a ledger entry and every
   unimplemented or unqualified feature is withheld from promotion claims.
4. Confirm requirements, guest activation, and live evidence are separate
   columns: a model test cannot accidentally become a guest result.

**Exit condition:** all validators pass and every active device/feature has a
defined status plus a named next live case or an explicit driver gap.

## Phase 2 — rootless correctness and portability

1. Run the complete device harness with AddressSanitizer and
   UndefinedBehaviorSanitizer.
2. Run the snapshot model, snapshot portability validator, and runner
   self-test.
3. Run the complete nested-VMX model with both sanitizers and its requirements
   validator.
4. Build bhyve and the production VMM module with warnings as errors.

**Exit condition:** no sanitizer finding; fixed-width portable snapshots,
backend identities, endian handling, truncation handling, and feature
compatibility checks pass independently of implementation headers.

## Phase 3 — test-lab operational readiness

1. Run `virtio-lab-selftest.sh`.
2. Validate `plan` output for `qualification`, `soak-smoke`, and
   `full-qualification` using inert absolute input paths.
3. Confirm cancellation/resume tests authenticate manager identity before
   signaling and preserve per-case teardown logs.
4. Use `soak-smoke` as the bounded preflight.  Reserve `soak` for endurance
   evidence; do not use a timeout or Ctrl-C result as a device conclusion.

**Exit condition:** a failed case has a per-case log, cleanup result, stable
classification, and a reproducible rerun command; a plan-only invocation
mutates no host networking or VM state.

## Phase 4 — device and save-state contracts

For every device, classify checkpoint state as one of:

1. portable and self-contained;
2. portable with an identical/reconstructible external backend identity;
3. accepted only after active external work drains; or
4. explicitly rejected while active (for example, active 9P fids or a live
   console host socket).

The qualification matrix must exercise each advertised state with split and
packed rings where supported, selective reset, suspend/resume, malformed
request containment, and a second restore of the same image.  Feature rows
that name multiqueue, RSS, queue reset, write-zeroes, IOMMU, or device events
require real guest observation on every active queue—not merely negotiation.

**Exit condition:** each contract maps to an independent model test and a
named live case; external backend mismatch is rejected before publication.

## Phase 5 — privileged campaign, in order

1. `host-regression` and host tools.
2. Linux modern/legacy activation matrix, including packed and multiqueue.
3. Rebuilt 5BSD activation matrix for every device with a supported guest
   driver; retain driver gaps where no driver exists.
4. Reset, reboot, checkpoint, and compatibility-mutation profiles.
5. Direct-versus-translated DMA/IOMMU and shared-memory device gates.
6. Bounded `soak-smoke`, then endurance `soak` after smoke is clean.
7. Intel-only nested VMX: authenticated Linux/KVM L1, Linux and 5BSD L2,
   VMX failure paths, EPT/VPID, APIC/timers, exit reflection, active-L2
   checkpoint, and repeated create/destroy tests.

The root-owned entry point is
`tests/sys/kern/vsock_e2e/run-waspnest-qualification.sh`.  Exact input
requirements and recovery procedures are in
`docs/waspnest-qualification-handoff.md`.

### Safe preflight commands

These do not create a VM, TAP, bridge, or snapshot artifact:

```sh
sh /usr/src/tests/sys/kern/vsock_device_harness/validate-virtio-requirements.sh
sh /usr/src/tests/sys/kern/vsock_device_harness/validate-virtio-snapshot-portability.sh
sh /usr/src/tests/sys/vmm/validate-vmx-nested-requirements.sh
sh /usr/src/tests/sys/kern/vsock_e2e/virtio-lab-selftest.sh
```

Use `PLAN_ONLY=yes` with `run-waspnest-qualification.sh` to inspect the
selected root campaign before it is authorized.  The reference-corpus
validator takes the pinned artifact directory; the requirements validator
takes its optional *ledger* path and otherwise uses the source-tree default.
Keeping those two interfaces distinct prevents a corpus path from being
misinterpreted as an empty requirements catalog.

## Release rule

The milestone is not release-qualified until every applicable ledger row is
live-qualified, all expected driver gaps remain explicit, all model gates are
green, and the final full qualification plus endurance gates complete without
unexplained timeout, cancellation, or cleanup failure.
