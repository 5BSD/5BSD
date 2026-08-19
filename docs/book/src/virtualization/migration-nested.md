# Live Migration and Nested VMX

WASPNest builds two capabilities stock bhyve lacks: a live-migration
session protocol and Intel nested VMX. Both follow the same discipline —
implement, model-test rootlessly, and keep the feature unexposed until
live qualification passes.

## Live migration: migration_session

The design is `docs/bhyve-migration-design.md`; the implementation is
`usr.sbin/bhyve/migration_session.c` and `.h`, with pre-copy dirty-page
support in `migration_precopy.c` and `migration_dirty.c`.

The wire protocol (`MIG1`, version 1) uses fixed-width little-endian
frames — a 24-byte header with type, sequence, length, and payload CRC-32 —
and proceeds through explicit phases:

```text
HANDSHAKE  HELLO -> CAPS_ACCEPT / CAPS_REJECT
VALIDATE   TOPOLOGY -> TOPO_ACCEPT / TOPO_REJECT   (fail-closed, pre-quiesce)
PRECOPY    MEM_GEN -> MEM_ACK, iterated dirty rounds
STOPCOPY   final MEM_GEN, DEV_STATE, FINAL
COMMIT     destination publishes state (does not run yet)
RELEASE    source becomes defunct; destination resumes
```

Large payloads are chunked (16 MiB maximum per frame, strictly contiguous
offsets validated before any copy; device-state blobs bounded at 512 MiB).
Device eligibility is contract-based: each device declares migration flags
(state codec, compat, DMA tracking, quiesce behavior) mirrored between the
PCI layer and the session. Convergence is bounded by `max_rounds` and a
`converge_pages` ceiling with optional abort-if-unconverged. A
virtio-balloon free-page-hint round can shrink the initial memory pass,
with a retain-until-finish invariant on the guest's STOP descriptor.

Operationally, both ends are handed an already-connected stream socket:

```sh
# Destination: start bhyve listening for inbound migration on fd 5
bhyve -R 5 ... vmname          # config key: migrate.receive_fd

# Source: issue the per-VM IPC command over bhyve's control socket
migrate fd=<fd> [max_rounds=n] [converge_pages=n]
```

The source command is a bhyve IPC command (see `bhyve(8)`), not a
`bhyvectl` subcommand; a supervisor establishes the connection and passes
the descriptor. `-R` is mutually exclusive with snapshot restore (`-r`).
The transport is an injectable vtable, so the whole session runs under test
over a socketpair: `tests/sys/kern/vsock_device_harness/migration_session_test.c`
holds 27 ATF cases covering codec round-trips, downgrade and CRC rejection,
loopback migration, rollback on destination commit failure, mid-copy
cancellation, and chunk-reassembly faults.

The session rides on the versioned checkpoint/state model
(`usr.sbin/bhyve/checkpoint_*.c`, `snapshot.c`) described in
`docs/bhyve-virtio-state-nested-architecture.md`: named, versioned,
checksummed state sections with dependencies, explicit machine-type ABIs,
and named CPU baselines instead of host-passthrough guesswork.

Status: the control plane, both state machines, `-R` listener, and device
bridge are implemented and loopback/model-proven; live two-host migration
is not yet qualified. Known residuals: no authentication on the `-R`
listener, kernel dirty-log confirmation and cross-version fixtures
pending (`compat_crc32` is now computed — fixed in-flight, uncommitted
as of 2026-08-19).

## Nested VMX

Nested VMX (running a hypervisor inside a guest) is implemented for Intel
only. The kernel owns all VMX semantics — VMCS12 validation, VMCS02
construction, combined EPT, exit reflection, event injection, and nested
state serialization — while bhyve owns only policy and orchestration.

`sys/amd64/vmm/intel/vmx_nested_instruction_handoff.c` implements a strict
IDLE→PENDING→HANDLING→RESOLVED transaction for guest-executed VMX
instructions (VMXON, VMXOFF, VMCLEAR, VMPTRLD, VMPTRST, VMREAD, VMWRITE,
INVEPT, INVVPID, VMLAUNCH, VMRESUME), executed against a frozen vCPU with
generation-checked handoff IDs so stale or concurrent handling fails with
distinct errnos rather than corrupting state. The kernel-owned INIT/SIPI
startup transaction lives in the companion
`vmx_nested_startup_transaction.c`/`vmx_nested_startup_dispatch.c` owner.
Active-L2 checkpoints freeze L2 into portable architectural state and
rebuild VMCS02/EPT02 caches on the destination — derived hardware state is
never serialized.

Exposure is triple-gated and default-off:

```sh
# Boot-time host tunables (CTLFLAG_RDTUN, both default 0)
hw.vmm.vmx.nested=1          # permit explicitly configured guests
hw.vmm.vmx.nested_vpid=1     # separately expose nested VPID/INVVPID
```

plus the per-VM capability `nested_vmx` (`VM_CAP_NESTED_VMX`), which each
guest must request before VMX CPUID bits and MSRs appear. On AMD the
capability is simply absent: `svm_getcap` returns `EINVAL` and the CPUID
VMX bit is cleared — fail-closed by design.

Testing is ledger-driven under `tests/sys/vmm/`:
`vmx_nested_state_test.c` (166 rootless model cases — test counts in
this section reflect the working tree as of 2026-08-19 and float with
pending commits),
`vmm_snapshot_session_live_test.c` (root-required live snapshot-session
cases), dirty-log and startup-edge suites, and the TSV ledgers
`vmx-nested-requirements.tsv` (437 requirement rows citing Intel SDM
sections), `vmx-nested-live-qualification.tsv` (12 live qualification
groups), and `vmx-nested-default-policy-live-qualification.tsv`.

Status: all 437 nested requirements are implemented at
`foundation-tested-experimental` or `experimental-pending-live` — none is
live-qualified. All 12 live qualification groups (Linux and 5BSD L2) are
pending, and nested VMX remains unexposed by default until they pass.
