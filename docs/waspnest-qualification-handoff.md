# WASPNest qualification handoff

Current requirement totals, activation dispositions, and release-completion
rules are maintained in `docs/waspnest-completion-matrix.md`.  Counts in dated
qualification records below describe those particular runs and are not the
current source of truth.

The completed rootless review, known boundaries, and next implementation
order are recorded in `docs/waspnest-review-status.md`.

## Destination startup-fence qualification

The restore path now holds every newly created vCPU before it can enter guest
execution and releases it only after restore commit and device resume.  Run
the checkpoint profile after installing the rebuilt bhyve and kernel; it
exercises successful restore.  Then repeat one checkpoint case with an
intentionally incompatible destination topology or feature configuration and
verify that bhyve exits without guest-console output from the destination.
The rootless structural gate already verifies the source ordering; this live
step confirms it against real vCPU scheduling.

## Build-mode prerequisite

Checkpoint qualification requires a snapshot-enabled bhyve build.  Use the
same source, world, kernel, module, and package configuration that will be
tested.  A focused source-tree build must compile the matching `libvmmapi`
first and must use a fresh object root:

```sh
snapshot_objdir=$(mktemp -d /tmp/bhyve-snapshot-qualification.XXXXXX)
env MAKEOBJDIRPREFIX="$snapshot_objdir" MK_BHYVE_SNAPSHOT=yes \
    make -C /usr/src/lib/libvmmapi
env MAKEOBJDIRPREFIX="$snapshot_objdir" MK_BHYVE_SNAPSHOT=yes \
    make -C /usr/src/usr.sbin/bhyve
```

The bhyve Makefile records `MK_BHYVE_SNAPSHOT` in the object directory and
rebuilds its mode-sensitive objects whenever that value changes.  A bare
`make` may therefore switch an existing bhyve object directory safely; the
rootless build-mode validator exercises `no -> yes -> no` in one private
object tree.  A fresh object root remains the clearest qualification setup,
and the normal world/package build keeps the matching source, library, and
kernel configuration coherent.

The reusable qualification entry point is:

```sh
/usr/src/tests/sys/kern/vsock_e2e/run-waspnest-qualification.sh
```

It runs the host regression gate before the Linux, 5BSD, checkpoint, and soak
profiles.  `virtio-lab` owns host preparation, isolated case directories,
parallel resource allocation, cleanup, resumability, and the final summary.
Before any VM starts, qualification also compiles all 15 in-tree 5BSD VirtIO
guest modules with `-Werror`; this is a source/driver build gate and does not
replace the rebuilt-image activation cases.
The VM-free and nested profiles now also compile the production `vmm.ko` in
an isolated object tree before the hardware case.  This prevents model tests
from masking a compiler or linker regression in the module that will execute
on the Intel host; it does not replace live L1/L2 evidence.
The host gate also builds and runs the Intel nested-VMX architectural
save-state tests.  These value-only tests validate the experimental state ABI;
they do not claim that accelerated L2 execution has passed live qualification.

For a standalone rootless sanitizer/model run whose standard output may be
collected asynchronously, use the device harness's optional completion
record.  It atomically changes from `RUNNING device harness` to
`PASS device harness all tests passed` only after every compiler and sanitizer
lane reaches the terminal marker:

```sh
RESULT_FILE=/tmp/waspnest-device-harness.result \
    sh /usr/src/tests/sys/kern/vsock_device_harness/run.sh \
    > /tmp/waspnest-device-harness.log 2>&1
```

`RUNNING` is deliberately not success evidence.  An early nonzero exit
atomically replaces it with `FAIL device harness exit=N`; the log remains the
diagnostic source.  This distinguishes a still-running worker from an
interrupted one and avoids treating a stale passing marker from a preceding
run as a new result.

SIGHUP, SIGINT, and SIGTERM are also terminal non-success paths: the harness
publishes the corresponding conventional shell status (129, 130, or 143)
once its current child has returned.  Supervisors that need immediate process
tree termination must signal the whole worker process group; the completion
record is the authoritative post-cleanup result, not a cancellation-acknowledge
protocol.

The rootless nested-VMX model runner has the same optional completion
contract.  Its nonterminal record includes the worker PID, private build
directory, and current bounded phase; its terminal PASS is published before
the human-readable stdout PASS marker:

```sh
RESULT_FILE=/tmp/waspnest-nested-model.result \
    VMX_NESTED_BUILD_JOBS=2 \
    sh /usr/src/tests/sys/vmm/run-vmx-nested-model.sh \
    > /tmp/waspnest-nested-model.log 2>&1
```

`RUNNING nested-vmx` is progress information, never proof of a completed
model run.  A nonzero exit replaces it with `FAIL nested-vmx`; a successful
model run replaces it atomically with `PASS nested-vmx` only after all model,
validator, evidence, staging, policy, and coverage lanes complete.  This is
rootless source/model evidence and does not replace the privileged Intel L1/L2
qualification described below.

The smaller snapshot-model runner also accepts `RESULT_FILE`.  It publishes
`RUNNING virtio-snapshot-model` atomically before it validates its source tree
or options, replaces that record with an explicit `FAIL ... exit=N` for every
early exit or signal, and writes its terminal `PASS` before printing the
human-readable result.  This makes the checkpoint codec and manifest model
safe to supervise from the same detached test-lab plumbing without treating a
missing or stale record as success:

```sh
RESULT_FILE=/tmp/waspnest-snapshot-model.result \
    sh /usr/src/tests/sys/kern/vsock_device_harness/run-snapshot-model.sh \
    > /tmp/waspnest-snapshot-model.log 2>&1
```

As with the other rootless records, this is source/model evidence only; it
does not authorize a running-device checkpoint or restore claim.

The same rootless gates are now first-class, resumable VirtIO-lab cases rather
than a collection of manual commands.  This is the source/model preflight; it
does not require an ISO, a bridge, `/dev/vmm`, or root.  It includes separate
ordinary and ASan/UBSan nested-model cases, each built in a private object
tree, so a resume can retain ordinary evidence while rerunning an
instrumented-toolchain failure:

```sh
/usr/libexec/flua /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile vmfree --jobs 1 --workdir /tmp/waspnest-vmfree
```

`vmfree-nested-vmx-model` deliberately remains distinct from
`nested-vmx-live`.  The latter is the root-owned Intel L1/L2 qualification
gate and is the only lab case allowed to satisfy live nested-VMX coverage.

The current rootless Intel gate validates the nested-requirement and private-
interface ledger counts reported by its matching validators, runs the selected
model/ABI cases, and builds the production `vmm.ko` with the complete
nested-VMX object set.  Hardware evidence uses the version-3 transaction
format: each Linux-L2, 5BSD-L2, and host artifact must name every requirement
ID assigned to its feature group exactly once and bind each ID to a typed,
role-appropriate proof with a stable execution label and positive observation
count.  The cross-ledger coverage
gate also requires every `experimental-pending-live` requirement to appear in
exactly one hardware feature group.  Feature and artifact counts are derived
from the validated live ledger rather than duplicated constants.

At present, a kernel-owned startup-entry owner paired with an L2 VMX attempt
is an expected fail-closed result, not a live-qualification failure:
`vmx_run_nested()` returns `EOPNOTSUPP` before VMCS02, EPT, guest-MSR, or L2
event ownership becomes active, and the common caller retires the owner as a
pre-entry failure.  The root-only live runner must record that boundary as an
expected negative test.  It must not treat it as evidence that L2 startup
under the kernel-owned protocol works, nor enable that management path.  The
future promotion test has to show one composed runtime transaction across
every VMCS02 entry, exit, unwind, refreeze, and common-owner outcome before
this expectation may be removed.

## Current rootless evidence (2026-08-09)

The current source revision completed both bounded, rootless gates with their
durable result records:

- `run-vmx-nested-model.sh`: `PASS nested-vmx cases=349`, including the
  requirement, evidence, staging, policy-pair, and live-coverage validator
  self-tests, plus an isolated `vmm.ko` build.  The separate lab sanitizer
  lane also completed `PASS nested-vmx cases=349 sanitizers=address,undefined`;
  it rebuilds the model and its matching `libvmmapi` privately rather than
  reusing the ordinary-model objects.
- `vsock_device_harness/run.sh`: `PASS device harness all tests passed` under
  AddressSanitizer and UndefinedBehaviorSanitizer.
- `validate-virtio-requirements.sh`: 238 VirtIO requirements and 693
  independently defined oracle values validated, including packed/split
  ordering, lifecycle, common-DMA, pause-unwind, and no-manual-wait checks.
- The `vmfree` manifest contains 8 cases, and the final combined run completed
  `passed=8`, `failed=0`, `blocked=0`.  Together these cases exercise the 5BSD
  guest-module build, production VMM module build, ordinary and sanitized
  nested models, normative/reference/private-interface ledgers, sanitizer
  device harness, RX harness, and host helper self-tests.

These records establish source, model, and sanitizer evidence only.  They do
not authorize nested-VMX exposure, kernel-owned startup selection, live
migration support, or a claim of Linux/5BSD guest activation.  The installed,
root-owned Intel qualification remains the promotion gate below.

`run-vmx-nested-model.sh` builds `libvmmapi` in the same private object tree
as its model binaries.  It also compiles the root-only snapshot-session and
startup-staging liveness tests in both ordinary and sanitizer runs.  Those
tests are not executed by the rootless gate: compilation proves that the
public ABI and its source-matched library link together, while installed
kernel runs remain mandatory evidence for descriptor ownership and
fail-closed behavior.

The hardware nested-VMX wrapper runs those two liveness suites as mandatory
host preflights before it starts the external L1 runner.  By default it uses
the source-built executables under
`/usr/obj/usr/src/amd64.amd64/tests/sys/vmm/`, falling back to their installed
counterparts under `/usr/tests/sys/vmm/`.  `NESTED_SNAPSHOT_SESSION_TEST` and
`NESTED_STARTUP_STAGING_TEST` may select reviewed replacement executables.
Both are root-owned, protected-path inputs and are included in the before/after
input hash manifest.  `NESTED_SNAPSHOT_SESSION_TIMEOUT` bounds each ATF case
and defaults to 120 seconds; it is separate from the four-hour L1 timeout.

On the current development host, run:

```sh
su root -c 'env \
    ISO=/home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    FIVEBSD_IMAGE=/home/koryheard/vm/bsd-guest.img \
    PROFILE=full-qualification UPLINK=re0 JOBS=3 \
    SOUND_PLAY=/dev/dsp SOUND_RECORD=/dev/dsp \
    NESTED_L1_RUNNER=/path/to/reviewed-l1-runner \
    NESTED_L1_IMAGE=/path/to/linux-kvm-l1.raw \
    NESTED_LINUX_L2_IMAGE=/path/to/linux-l2.raw \
    NESTED_FIVEBSD_L2_IMAGE=/path/to/fivebsd-l2.raw \
    WORKDIR=/tmp/virtio-qualification-current \
    /usr/src/tests/sys/kern/vsock_e2e/run-waspnest-qualification.sh'
```

The wrapper forwards the four required L1/L2 `NESTED_*` paths, the optional
reviewed VMM-preflight executable paths, both nested timeout controls, and
both `SOUND_*` endpoints through `virtio-lab`'s allowlisted `--set` interface
for the applicable profiles; ambient variables alone are intentionally not
inherited by case workers.  `full-qualification` is the complete Intel-host gate: portable
release, checkpoint, bounded soak, nested VMX, and representative split/packed
OSS sound and sound-checkpoint coverage in one manifest-derived transaction.
Its coverage preflight must print `COVERED nested-vmx-live-gate`; that marker
is internal and cannot be satisfied with `--set`.

The current tree also tightens the kernel snapshot ioctl boundary and exact
record consumption.  Install a source-matched world, kernel, modules, and
packages before qualification; a standalone snapshot-enabled bhyve build
against older installed `machine/vmm*.h` headers is intentionally not a valid
integration result.  The host regression includes
`vmm_snapshot_op_test:kernel_snapshot_operation_boundary` and
`checkpoint_topology_test:exact_record_consumption` before any VM case.

If the run is interrupted, use the identical command with `RESUME=yes`.  A
resume reuses passed cases and reruns failed or incomplete cases:

```sh
su root -c 'env \
    ISO=/home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    FIVEBSD_IMAGE=/home/koryheard/vm/bsd-guest.img \
    PROFILE=full-qualification UPLINK=re0 JOBS=3 RESUME=yes \
    SOUND_PLAY=/dev/dsp SOUND_RECORD=/dev/dsp \
    NESTED_L1_RUNNER=/path/to/reviewed-l1-runner \
    NESTED_L1_IMAGE=/path/to/linux-kvm-l1.raw \
    NESTED_LINUX_L2_IMAGE=/path/to/linux-l2.raw \
    NESTED_FIVEBSD_L2_IMAGE=/path/to/fivebsd-l2.raw \
    WORKDIR=/tmp/virtio-qualification-current \
    /usr/src/tests/sys/kern/vsock_e2e/run-waspnest-qualification.sh'
```

The concise result is in
`/tmp/virtio-qualification-current/summary`.  Per-case output is under
`logs/`, retained failure state is under `cases/`, and the immutable manifest
path and resume-compatible configuration are recorded in `manifest.path` and
`run.config`.

The nested live result seals `inputs.sha256` with hashes of the reviewed L1
runner, all three guest images, bhyve, both root-only VMM preflight
executables, the live requirements ledger, and each validator used to accept
the evidence.  The privileged wrapper is anchored to `/usr/src/tests/sys/vmm`;
it deliberately ignores `SRCTOP` so a caller cannot select a different ledger
or validator at the root execution boundary.
Before invoking that wrapper from a development source tree, install the
matching test package or ensure its four control-plane files (the live ledger
and the three validators) are root-owned and not writable by group or other.
The wrapper rejects a loose caller-owned control plane rather than executing
it with root authority.  The normal installed `/usr/tests/sys/vmm` layout is
accepted as the packaged fallback when the matching source corpus is absent.

The qualification manifest includes explicit modern virtio-rng,
virtio-balloon, and virtio-rtc split and packed cases plus packed
checkpoint/restore cases.  Balloon targets of 1 MiB and 64 MiB exercise the
bounded control surface.  RTC cases verify an unmodified Linux driver,
UTC-like clock reads, opt-in alarm delivery over both ring layouts,
reset/rebind, combined-device operation, and restore with an armed alarm.
Packed mode and RTC alarms are qualification opt-ins and are not advertised
by default.

The current manifest also contains separate Linux balloon gates for
`deflate_on_oom=true`, `free_page_reporting=true`, and `page_poison=true`.
The first must observe the independently defined feature bit while
`MUST_TELL_HOST` remains active.  Reporting must submit a writable queue
request; without poisoning it must reach the host discard path, while the
combined poison lane must instead produce host evidence that backing was
preserved.  The poison lane also validates the complete 16-byte device
configuration.  Feature negotiation alone does not pass any case.  All
options remain off by default, and the standard qualification command above
automatically includes these gates after the matching world/packages are
installed and the host is rebooted.

The Linux block verifier now issues both `BLKZEROOUT` and `BLKDISCARD` against
distinct nonzero patterned ranges.  It checks the Linux queue limits, the
whole-device digest, the affected ranges, and reboot persistence.  Zero
readback after discard is explicitly a qualification property of the lab's
sparse-file backend, not a general promise added to the VirtIO DISCARD
contract.  The verifier also exercises every CONFIG_WCE transition
writeback -> writethrough -> writeback -> writethrough and reads `cache_type`
after each change.  CONFIG_WCE remains in `block-modern-q1`; backend-dependent
DISCARD has its own `block-discard-modern` case so ordinary block coverage
does not fail on filesystems without deallocation support.  The next
privileged release run is the live result gate.

`notification-data-modern` is the common 32-bit doorbell activation gate.
The Linux block driver must negotiate feature bit 38 and complete I/O, while
the host trace must show the queue selector and a nonzero available index
decoded from the same four-byte notification.  Merely finding the negotiated
feature bit does not pass this case.  The same lane now requires bit 39 and
therefore activates notification configuration data through real block I/O.
bhyve intentionally returns the queue index as its permitted trivial
notification identifier; the rebuilt FreeBSD guest must retain and use the
device-provided field rather than assuming that policy.

The release manifest also has a dedicated `block-readonly-modern` case.  It
attaches the disposable backing file with `ro=true`, requires the Linux guest
to negotiate RO without DISCARD or WRITE_ZEROES, proves reads work, proves a
write is rejected, resets the device, and repeats the same checks.

For a focused pre-release check before the complete qualification profile,
run these three root-only lanes after installing the matching
world/packages and rebooting:

```sh
env ISO=/home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    DEVICES=block TRANSPORTS=modern BLOCK_QUEUES=1 \
    BLOCK_DISCARD=yes WORKDIR=/tmp/virtio-block-discard \
    sh /usr/src/tests/sys/kern/vsock_e2e/run-alpine-auto.sh

env ISO=/home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    DEVICES=block TRANSPORTS=modern BLOCK_QUEUES=1 \
    BLOCK_READONLY=yes RESET_TEST=yes \
    WORKDIR=/tmp/virtio-block-readonly \
    sh /usr/src/tests/sys/kern/vsock_e2e/run-alpine-auto.sh

env ISO=/home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    DEVICES=block TRANSPORTS=modern BLOCK_QUEUES=1 \
    VIRTIO_DEBUG=2 VERIFY_NOTIFICATION_DATA=yes \
    WORKDIR=/tmp/virtio-notification-data \
    sh /usr/src/tests/sys/kern/vsock_e2e/run-alpine-auto.sh
```

The current CPU-specific qualification target is Intel.  Device, transport,
DMA, interrupt, and save-state records remain architecture-neutral; nested VMX
work and hardware evidence are explicitly Intel-specific.

The portable snapshot envelope is deliberately not a cross-ISA CPU-migration
claim.  It carries common VM and device records in fixed-width little-endian
form, while each architecture owns validation and restoration of its processor
state.  A snapshot may therefore be restored only onto a destination with a
compatible architecture-specific CPU-state adapter and compatible advertised
features.  Future arm64 and riscv support must add their own CPU-state sections
and installed-build/live qualification before cross-architecture portability is
claimed.

Do not treat `make -C sys/modules/vmm TARGET=arm64` or an object-directory
name containing `arm64` as cross-architecture evidence: the module Makefile
selects the host amd64 VMM source set.  For each supported non-x86 target,
use that target's complete kernel build configuration and retain the compiler
commands showing its architecture include tree and source list.  The minimum
gate is a warnings-as-errors kernel build that includes `sys/dev/vmm/vmm_vm.c`
and the common event-coordinator sources; an architecture with a VMM backend
must additionally boot a disposable guest, create/reset/destroy a VM, and
exercise checkpoint rejection or its architecture-native CPU-state adapter.
This avoids misrepresenting a host-only module link as portable VMM proof.

The latest complete rootless release gate completed successfully on
2026-07-27 with every VirtIO sanitizer/model/helper check and all 59
then-current nested-VMX architectural cases passing.  A subsequent focused
gate passed all 63 current nested cases, built `vmm.ko` with `-Werror`, and
validated the 78-entry nested requirement-to-code-to-test ledger against the
immutable Intel SDM revision 092 and pinned Linux 7.2-rc4 corpus IDs.

The focused nested suite includes a
generation- and epoch-bound, value-only VMCS02 runtime plan and retryable
commit boundary.  The planner verifies the current VMCS, derives the EPT
capability tag and virtual preemption-timer rate, composes TSC and VPID
runtime state, captures conditional DEBUGCTL/DR7/PAT/EFER inheritance, and
cannot publish an architecturally rejected VM entry.  A complementary
transactional VM-exit planner now preserves or saves L2 state according to
the VM-exit controls, consumes entry injection, updates virtual IA-32e mode,
and derives the effective L1 host runtime state.  A separate resource-binding
stage accepts only generation-matched L0 host state and reconstructed
host-owned EPT, bitmap, APIC, and MSR-list resources; VMCS12 guest physical
addresses cannot enter its hardware plan.  The VM-entry and VM-exit MSR-list
paths now snapshot and validate complete little-endian record sets before
mutation.  VM-exit MSR stores commit in Intel-defined order and preserve
earlier stores when a later entry requests abort indicator 1, avoiding an
unsafe rollback over concurrent L1 memory updates.  Each record header is
revalidated immediately before its value write so a concurrent index change
cannot be paired with a stale effective-L2 value.  VM-exit host MSR loads roll
back partial per-vCPU L1 updates, distinguish L0 rollback failures, and
classify Intel VMX-abort indicator 4.  The
virtual VMCS-region and portable state layers accept only indicators 1
through 6 and reject abort state that claims active L2 execution.  The
per-vCPU runtime owner now fences reset, restore, entry, exit, internal
handoffs, and destruction with distinct generations and epochs.  Its frozen
internal-exit boundary rejects stale or mismatched transactions before
runtime callbacks.  The instruction path now uses fault-injecting
guest-memory helpers only after `vmx_run()` has returned, tracks the VMREAD
destination GPR, and commits CPU and nested-machine results through a
retryable context boundary.  A bounded, hashed per-VM registry keeps active
implementation-defined VMCS data out of raceable guest memory and enforces
one owning vCPU.  The per-vCPU EPT02 cache now has generation-checked
resolution, transactional L2-lifetime binding, and a frozen runtime adapter
for atomic EPT12 walks and successful population.  Production VM entry binds
the reconstructed EPT02 root through the VMCS02 resource owner and activates
that root only for the CPU-pinned L2 run interval.  Resolved EPT12 faults have an independent
value-only reflection builder, a copy-staged VMCS12 exit-information commit,
and a generation-checked context commit.  VMCS02 preserves the original
VMCS12 guest state and exit policy separately from effective L2 state, and a
composite planner prepares both the reflected exit information and the
conditional L2/L1 processor-state transition from frozen value snapshots.
The context accepts the transition only after the Intel production transaction
has saved L2 state, copy-staged and committed VMCS12, restored L1 runtime
state, and completed the ordered VM-exit MSR transaction.
The generation/epoch-owned fault handoff now includes the complete value-only
VMCS02 exit snapshot, ensuring the future frozen adapter cannot accidentally
pair a resolved EPT12 walk with stale exit metadata or reread another
hardware VMCS after `vmx_run()`.  The production VMX critical-section capture
and frozen commit adapter are connected through `vmx_run_nested()` and
`vmx_handle_internal_exit()`.  The bounded VMCS registry now
has canonical GPA-sorted, capability/schema-bound checkpoint state and a
transactional restore that reconstructs every entry as inactive and unowned;
runtime owner identities and implementation-defined region bytes are not
serialized.  A frozen generation-bound VMCS02 resource plan is now converted
into a deterministic, strictly encoding-ordered, value-only Intel VMCS
programming image.  It contains only L0-owned resource addresses, rejects
inconsistent or unrepresented optional state, and leaves its output unchanged
on failure.  A fault-injectable subordinate apply boundary now requires a
private unpublished VMCS02, publishes only after every write succeeds, and
rolls back every write or commit failure.  The actual Intel VMCS allocation,
selection, write, entry, and exit-capture adapter is connected and each vCPU
owns a separate VMCS02.  Nested VMX remains default-off behind the loader-only
`hw.vmm.vmx.nested` policy and the explicit VM-wide `VM_CAP_NESTED_VMX`
setting; the production path is therefore available only to deliberate live
qualification and is not advertised by default.  The
complete rootless regression output is under
`/tmp/waspnest-host-regression-nested-runtime`.

MBEC remains fail-closed and is removed from the production virtual
capability contract because EPT bit 10 collides with the current amd64 pmap
managed metadata bit.  The independent model retains MBEC validation and
walker tests for a future non-aliasing pmap representation.
At that historical checkpoint the nested implementation remained deliberately
unexposed.  The current tree now has the separately gated experimental
qualification path documented below, but rootless regression still proves
only the surrounding architecture and build, not L2 execution.  The Intel
L1/L2 instruction, exit-reflection, EPT/VPID, interrupt/timer, checkpoint,
and repeated-lifecycle cases remain mandatory before release qualification.

The latest complete rootless gate after the EPT-exit handoff changes is
retained at `/tmp/waspnest-host-regression-ept-exit`.  It passed the complete
VirtIO oracle/model/sanitizer/helper suite plus all 63 nested cases and all 78
ledger entries.

The latest complete rootless gate is
`/tmp/waspnest-host-regression-vmcs02-intel`.  It passed the complete
VirtIO oracle/model/sanitizer/helper suite plus all 66 nested cases and all 81
ledger entries.

The subsequent focused VMCS02 resource-ownership gate passes all 68 nested
cases and all 83 ledger entries and builds `vmm.ko` with `-Werror`.  It adds
transactional per-vCPU MSR-bitmap materialization and generation-bound
APIC/posted-interrupt mapping leases, but does not yet enable nested VMX or
claim live L2 execution.

The follow-up frozen-entry gate passes 69 nested cases and 84 ledger entries.
It eliminates the VMCS12 entry-MSR validate/reread window, adds aliasing and
address-negative resource tests, and still leaves CPUID VMX and capability
MSR exposure closed.

The frozen snapshot is now consumed by
`vmx_nested_vmcs02_prepare_frozen()` itself, so the production planner has no
second MSR-list read.  It rejects stale host capability/policy inputs before
guest-memory access and retains the prior MSR values needed to unwind a later
failed hardware entry.  The focused 69-case gate and `vmm.ko` `-Werror`
build remain green after this integration.

The corresponding complete VM-free gate is retained at
`/tmp/waspnest-host-regression-vmcs02-resources`; it passed the independent
VirtIO oracle/model/sanitizer/helper suite plus all 69 nested cases and all 84
ledger entries.

A newer complete rootless gate is retained at
`/tmp/waspnest-host-regression-frozen-entry-rootless`.  It passed the full
VirtIO oracle/model/sanitizer/helper suite, all 69 nested cases, and all 84
ledger entries after frozen preparation and Intel resource mapping were
integrated.  Privileged kernel/MAC tests were deliberately deferred; use the
root-only wrapper for those rather than interpreting direct unprivileged ATF
permission failures as regressions.

After that gate, the Intel-only resource adapter was completed and
`vmm.ko` was rebuilt with `-Werror`.  It now pins APIC and posted-interrupt
guest pages, consumes a VMCS01-owned MSR-area snapshot captured in a short
non-sleeping critical section, materializes a merged host MSR bitmap using
per-vCPU scratch, resolves EPT02 outside the critical section, and tears the
generation-bound resources down after VMCS01 is restored.  This is
build-verified plumbing,
not a claim of live nested execution; `vmx_run()` exposure remains closed
until the frozen entry/exit commit path is complete.

The subsequent entry-runtime slice adds a non-serialized per-vCPU publication
state machine for the Intel hardware boundary.  It holds generation and count
metadata only, requires resource/VMCS02/MSR/entry ordering, retains resources
until the nested-exit value transaction commits, and provides retryable
reverse cleanup after a raw hardware-entry failure.  An incomplete entry-MSR
rollback leaves the runtime quarantined and requires a frozen reset.  Kernel
snapshot and teardown now fail closed unless this transient owner is idle.
This does not yet make nested VMX live-test eligible: the bhyve virtual-MSR
backend and the actual VM-entry/VM-exit adapter still need production wiring.

The following frozen-VMCS12 slice captures every value consumed by an entry
attempt under one registry ownership boundary and derives the entry-validation
view from that immutable capture.  It also adds the previously omitted Intel
TSC-multiplier VMCS encoding and gates it on the virtual TSC-scaling control.
The capture now freezes the exact virtual capability policy and signature as
well, because the successful instruction handoff is consumed before VMCS02
preparation.  A conservative production policy builder merges execution
intercepts while treating L1 entry/exit transition controls as software
emulation, so VMCS02 retains L0's hardware transition contract.
Before any derived entry image is published, snapshot validation recomputes
the capability signature and cross-checks its VMCS GPA, launch epoch, SMM
state, executive-VMCS state, host IA-32e mode, and TSC-scaling semantics.
Corrupt or internally inconsistent snapshots fail transactionally.

The common entry/exit MSR-list validators also enforce Intel/Linux-observed
mandatory exclusions for microcode, SMM-monitor, SMBASE, FS/GS load, and the
x2APIC MSR page.  x2APIC is intentionally stricter than Linux for now:
Linux's acceptance depends on an APIC-mode input that the frozen bhyve
boundary does not yet carry.  This must remain fail-closed until that input is
part of the reproducible transaction.
The value-only virtual-MSR adapter now directs VMCS-managed MSRs into the
unpublished VMCS02 image and software-managed syscall/KGSBASE/TSC_AUX values
into an L2-owned bank.  It distinguishes legal FS/GS exit stores from
forbidden FS/GS loads and uses the same callbacks for rollback.  The entry
runtime order is resources, prospective MSR application, final VMCS02
programming, and hardware entry; VMCS01 is restored before rollback after a
raw hardware-entry failure.
The latest rootless focused inventory is 143 nested cases and 168
independently mapped ledger entries; `vmm.ko` builds with `-Werror`.  The
runtime-only, generation-fenced MSR workspace is backed by two disjoint
externally owned arrays.  It derives its 512-to-4096-entry capacity from the
immutable virtual IA32_VMX_MISC policy and rejects undersized, overlapping,
stale-policy, and active-unbind cases.  The per-vCPU owner allocates its
single backing slab lazily at the frozen entry handoff outside VMX critical
sections, refuses snapshots while it is active, and validates/unbinds/frees
it during teardown.  The production run loop now selects L1, initial L2,
resumed L2, or an internal frozen handoff explicitly; it connects VMCS02
programming, composed-EPT residency, hardware-result classification, exit
reflection, cold refreeze, and active-L2 restore without serializing
destination-local resources.  This remains rootless architectural evidence,
not live nested-execution qualification: five ledger rows and all ten live
feature groups still require Intel hardware evidence.
The same Intel Volume 3C/Volume 4 review corrected VM-entry WRMSR semantics:
IA32_EFER.LMA changes are ignored and the prior bit is preserved, and
IA32_SYSENTER_CS bits 63:32 are accepted but ignored.
The corresponding complete rootless gate passed under
`/tmp/waspnest-host-regression-msr-workspace-final`.

## Intel nested-VMX live gate (default-off qualification)

Nested VMX now has two independent opt-in gates:

```
hw.vmm.vmx.nested=1
x86.nested_vmx=true
```

The first is a boot-time host qualification tunable and must be set before
`vmm` is loaded.  The second is a per-guest bhyve setting implemented as an
immutable VM-wide CPU-model choice.  The complete implementation predicate
must also succeed.  Unless all
three conditions hold, guest CPUID VMX, virtual VMX capability MSRs, VMX
instructions, and active nested checkpoint restore remain unavailable.
Canonical inactive nested state remains restorable.

After installing the matching world and kernel, prepare a dedicated
qualification boot (not a general workstation default) with:

```sh
sysrc -f /boot/loader.conf hw.vmm.vmx.nested=1
```

Reboot before loading `vmm`, then verify:

```sh
sysctl -n hw.vmm.vmx.nested
```

The live harness must run two otherwise-identical L1 guests.  The control
guest omits `-o x86.nested_vmx=true` and must observe no CPUID VMX bit, no
readable VMX capability MSRs, and `#UD` for VMX instructions.  The
qualification guest includes that option and must observe one identical VMX
CPU model on every vCPU before KVM is loaded.  This negative control is
mandatory evidence that the host tunable alone does not expose VMX.

Do not enable these gates merely to run a partial test.  The live Intel gate
must include:

- a Linux L1 that runs the pinned KVM nested-VMX selftests and a Linux L2;
- a Linux L1 with a disposable 5BSD L2;
- every VMX instruction both outside and inside VMX operation;
- entry failures, reflected ordinary exits, EPT violation and
  misconfiguration, INVEPT/INVVPID, interrupt/NMI/window and timer cases;
- active-L2 checkpoint/restore and destination-capability rejection;
- multi-vCPU active restore with a failure after an earlier vCPU staged its
  MSR workspace and destination-local VPID, proving both are rolled back;
- host-VPID exhaustion and allocator reuse on another physical CPU, proving
  the failed restore publishes no owner and the first successful entry
  invalidates the reused context;
- repeated restoration of one sealed checkpoint into fresh destinations;
- inactive-L1 checkpoint rejection when the source and destination
  `x86.nested_vmx` CPU-model settings differ, in both directions;
- repeated L1/L2 create, reset, abort, destroy, and restore soak;
- explicit proof that a failed entry or restore leaves L1 runnable.

The tests must prove real accelerated L2 execution and host-path activity;
CPUID visibility, KVM module attachment, or an L2 boot log alone is not enough.
The mandatory live feature groups and their separate Linux-L2 and
5BSD-L2 dispositions are tracked in
`tests/sys/vmm/vmx-nested-live-qualification.tsv`; the normal nested ledger
validator rejects missing groups, nonexistent requirement references, and
any exercised claim without structured guest and host evidence.

The live gate is a first-class `virtio-lab` profile rather than a manual
collection of commands.  It deliberately requires a reviewed, root-owned L1
driver and immutable Linux/KVM L1, Linux L2, and 5BSD L2 images:

```
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile nested --jobs 1 \
    --workdir /tmp/waspnest-nested-vmx \
    --set NESTED_L1_RUNNER=/path/to/reviewed-l1-runner \
    --set NESTED_L1_IMAGE=/path/to/linux-kvm-l1.raw \
    --set NESTED_LINUX_L2_IMAGE=/path/to/linux-l2.raw \
    --set NESTED_FIVEBSD_L2_IMAGE=/path/to/fivebsd-l2.raw'
```

The host wrapper rejects non-amd64 hosts, a VMX backend which did not
initialize, a disabled `hw.vmm.vmx.nested` boot gate, an unloaded VMM,
non-regular images, and an L1
driver that is not root-owned or is writable by group/other.  The driver
writes one assertion for every live-ledger row.  Linux-L2, 5BSD-L2, and
correlated host evidence are all mandatory.  Evidence is staged and
published only after its schema, identifiers, cardinality, and complete
feature-group set validate.  SHA-256 values for the driver and all three
images are captured before execution and checked again afterward, so a driver
that mutates a qualification input cannot publish a pass.  The profile runs
the complete architectural host regression first and gates the hardware case
on that result.

`NESTED_LIVE_TIMEOUT` bounds the external L1 runner in seconds and defaults
to 14400 (four hours).  `NESTED_SNAPSHOT_SESSION_TIMEOUT` independently bounds
each mandatory root-only snapshot-session and startup-staging preflight case,
defaulting to 120 seconds.  A failed, timed-out, or interrupted attempt removes
only its unpublished `vmx-nested-live-result.new` tree; an already published
result is never removed or overwritten.  FreeBSD `timeout` supervises the
runner's descendants as well, so a failed qualification does not leave nested
guests running behind a stale staging directory.

The higher-level `virtio-lab` nested cases retain a four-hour case envelope
but default the forwarded `NESTED_LIVE_TIMEOUT` to 13800 seconds.  The reserved
ten minutes cover the two host VMM preflights, artifact validation/sealing, and
cleanup; an operator may set a smaller positive timeout, but the outer case
deadline remains the final bound.

VPID qualification is intentionally two transactions because its loader-only
policy cannot change in a running kernel.  The command above is the positive
`nested` profile and requires `hw.vmm.vmx.nested_vpid=1`.  On a second boot
with `hw.vmm.vmx.nested=1` and `hw.vmm.vmx.nested_vpid=0`, use the same
immutable inputs with `--profile nested-default` and a new work directory.
That profile selects the one-group default-policy ledger and records the
observed VMX initialization, both policy values, kernel ABI, a hash of
`kern.version`, and the loaded `vmm.ko` size and image hash in an immutable
`host-policy.tsv`; it rejects a policy or build change during execution.  Both result
directories are required for promotion.  Verify them together rather than
comparing logs manually:

```sh
/usr/tests/sys/vmm/validate-vmx-nested-policy-pair.sh \
    /tmp/waspnest-nested-vmx/vmx-nested-live-result \
    /tmp/waspnest-nested-default/vmx-nested-live-result
```

The pair verifier revalidates every artifact against its mode-specific ledger,
recomputes a canonical artifact hash manifest, requires sealed owner-only
files and directories, requires distinct run identifiers, and rejects changed
L1/L2/bhyve inputs or a different kernel or `vmm.ko` build between boots.

For the VM-free standards gate to authenticate the local source corpus as
well as its committed metadata, set `VIRTIO_REFERENCE_ARTIFACT_DIR` to a
directory containing exactly the five pinned VirtIO, Intel SDM, Linux, and
QEMU artifacts.  Missing, duplicate, or additional files fail qualification.

Until every case passes, the expected default result remains “nested VMX
unavailable,” and the current rootless architectural suite remains the
authoritative non-live evidence.

VPID and INVVPID remain a separate experimental feature, not part of the
current EPT/INVEPT completion claim.  A strict per-vCPU destination-local
VPID02 owner, frozen-instruction deferred invalidation, allocator-reuse flush,
and final pinned-CPU consumption are now connected.  The owner and its pending
flush are runtime reconstruction state and are never serialized; active-L2
restore allocates the fresh owner into an unpublished VM-wide stage, transfers
it only at final commit, and forces invalidation before entry.  The
virtual capability policy still withholds VPID/INVVPID pending real
CPU-migration, reset, restore, reuse, and every-type execution evidence.  The
live ledger requires both a negative unavailable test now and full
Linux-L2/5BSD-L2 activation evidence before those capabilities can be
advertised.

Current pre-live evidence after connecting the disabled VMCS02 loop is:

- 147/147 value-only nested-VMX architectural cases;
- 168/168 independently mapped nested requirements;
- a clean `vmm.ko` `-Werror` build;
- exhaustive run-unwind state classification and successful-return residency
  assertions.

The latest restore and cold-thaw review closed two additional integration
boundaries.  A VMXON or active-L2 checkpoint can no longer bypass the same
implementation-stage gate that keeps guest CPUID VMX, virtual VMX MSRs, and
VMX instructions hidden; only canonical inactive nested state is accepted
while exposure is disabled.  In addition, a missing, stale, or mismatched
composed-EPT binding discovered after cold thaw is exactly refrozen and its
original host error is returned.  It is not converted into an internal
continuation retry that could repeat forever without an ownership or
generation change.  Focused rootless cases cover the exposure gate and the
run-unwind model, but the destination restore and concurrent EPT invalidation
paths remain part of the live Intel gate above.

The rootless result alone does not authorize enabling CPUID VMX for production
guests.  Ordinary and failed-entry
VM-exit MSR-list processing is now connected to the disabled production
loop, including ordered partial stores, retry-persistent host-load images,
and abort-indicator publication.  The ordered host-state transaction now
loads and validates 32-bit PAE L1 PDPTEs after exit stores and before exit
MSR loads, retains their value-only image across publication retries, and
publishes abort indicator 2 for both ordinary exits and failed entries.  The
L1 restore commit also synchronizes the VMM core next-run cache and Intel
interruptibility last-RIP cache without redispatching the write through a
detached L2 owner.  Paused nested execution now restores the per-CPU host
IA32_TSC_AUX value before interrupts are enabled while retaining L1 and L2
values in their architectural software banks.  The connected VMCS02 loop
also restores complete L0 GDTR, IDTR, and LDTR state immediately after the
hardware attempt and before calling any C result classifier.  Intercepted L2
IA32_PAT writes are synchronized to the live VMCS02 field before their
software value is published, so a resume cannot silently reload stale PAT
state.  Intercepted L2 IA32_TSC writes recompose the active VMCS02 clock
from the updated L1 offset plus VMCS12's L2 scaling and offset, reload the
nested preemption timer from its unchanged L1 virtual deadline, and defer
the matching VMCS01 update until that VMCS is current.  The
Linux-L1/L2 live matrix above has not run.

The latest virtual-control audit also withholds pause-loop exiting even when
the physical CPU supports it.  VMCS02 has only one PLE gap/window pair, so
two independent L0 and L1 policies cannot generally be represented without
losing an owner's exit or rejecting an otherwise valid L1 configuration;
the pinned Linux nested policy makes the same conservative choice.  CR0 and
CR4 guest-host masks now compose as a union while the L1 architectural read
shadow wins on overlap and the effective guest register retains L0's forced
hardware bits.  These changes are covered by the 141-case architectural
suite and the 165-entry requirements ledger, and the resulting Intel module
completed a clean warnings-as-errors build.  They do not change the live
qualification requirement or authorize exposing VMX to a guest.

The same review cycle tightened two non-hardware boundaries.  VMCS02 now
rejects any L0-owned hardware MSR area whose complete 16-byte record range
would wrap the address space, without changing the prior hardware plan.
Portable nested-state decoding also rejects an output view placed inside
its immutable wire buffer, preventing the returned borrowed field pointers
from referring to bytes overwritten by the view itself.  Both cases have
focused transactional regressions in the rootless architectural suite.

For the live Intel run, capture the dedicated nested lifecycle probes in a
separate terminal:

```sh
dtrace -n 'vmm:vmx:nested:entry { printf("vcpu=%d vmcs=%#x epoch=%d launch=%d", arg1, arg2, arg3, arg4); } vmm:vmx:nested:vmexit { printf("vcpu=%d vmcs=%#x epoch=%d reason=%#x", arg1, arg2, arg3, arg4); } vmm:vmx:nested:failure { printf("vcpu=%d error=%d runtime=%d continuation=%d", arg1, arg2, arg3, arg4); } vmm:vmx:nested:withheld { printf("vcpu=%d error=%d runtime=%d continuation=%d", arg1, arg2, arg3, arg4); } vmm:vmx:nested:restore { printf("error=%d active=%d valid=%d registry=%d", arg1, arg2, arg3, arg4); }'
```

The first probe argument is the private VM pointer; the formatted fields
begin at `arg1`.  Correlate a failure by vCPU and the preceding entry/exit
identity rather than by a hardware VMCS pointer.  A `withheld` observation
means the deliberate, fail-closed owner-admission fence returned
`EOPNOTSUPP` before VMCS02 or guest-MSR ownership changed; it is neither a
VM-entry failure nor a nested unwind failure.

The exit-list model now records an additional ordering requirement for live
qualification.  L1 memory containing an exit store or load list is sampled
after L2 exits, not cached at VM entry.  Effective L2 values are captured
before sleepable guest-memory access; store entries then commit sequentially,
and the load list is sampled only after all stores complete so overlapping
areas observe the committed values.  A generation-bound phase machine
prevents retries from repeating irreversible stores and distinguishes
virtual abort indicators 1 and 4 from an L0 rollback failure.  The
value-only L1 host-load planners and Intel restore transactions include
software-owned MSRs atomically.  The production coordinator is connected,
but this remains rootless model and build evidence until nested exposure is
separately authorized and live-tested.

When installed from pkgbase, the same wrapper is available at:

```sh
/usr/tests/sys/kern/vsock_e2e/run-waspnest-qualification.sh
```

## Virtio-mem live activation gate

The modern memory-device implementation has rootless protocol, composition,
malformed-chain, reset, portable-state, and sanitizer coverage.  It is not
qualified merely because Linux binds `virtio_mem` or reads its configuration.
The release cases require the stock Linux driver to negotiate every offered
common feature, issue successful PLUG requests, online memory blocks from the
device GPA range, run an anonymous-memory checksum workload, survive
reset/rebind, and repeat that evidence after checkpoint restore.  Split and
packed queues are separate cases and the host log must contain the successful
PLUG operation.

After installing a world containing the new bhyve and libvmmapi plus a kernel
containing the generic device-memory slots, run:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile release --jobs 1 \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --workdir /tmp/virtio-mem-release'
```

For the focused checkpoint cases:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile checkpoint --jobs 1 \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --workdir /tmp/virtio-mem-checkpoint'
```

The `checkpoint` profile is a 44-case Linux matrix, not the earlier
four-case bring-up subset.  It separately schedules split and packed device
lanes, active-state rollback checks, IOMMU endpoint coverage, both vsock
providers, and a combined-device restore.  Use `plan --profile checkpoint`
to inspect the exact manifest-derived list before a root run; `run` records
per-case results and supports `--resume` without rerunning passed cases.

The stock 5BSD guest tree currently has no virtio-mem driver.  PCI discovery
therefore cannot satisfy the activation gate.  This remains a named driver
and live-test gap; the lab must not report 5BSD virtio-mem coverage until a
stock guest driver negotiates the device, plugs and unplugs blocks, and
survives reset and restore.

## Virtio-sound live activation gate

The deterministic null backend still exercises the unmodified Linux
`virtio_snd` and ALSA stack: the guest must discover the modern device,
negotiate the selected ring features, configure S16_LE 48 kHz stereo
playback and capture, transfer exactly 192000 bytes in each direction, and
verify that capture returns exactly that many zero bytes.  Debug-level-two
host logs must independently prove nonzero TX and RX queue/backend byte
counts.  Run split and packed cases separately:

```sh
su root -c 'env \
    ISO=/home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    TOPOLOGIES=sound TRANSPORTS=modern SOUND_PACKED=no \
    VM_FREE_GATES=no WORKDIR=/tmp/virtio-sound-split \
    sh /usr/src/tests/sys/kern/vsock_e2e/run-alpine-matrix.sh'
su root -c 'env \
    ISO=/home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    TOPOLOGIES=sound TRANSPORTS=modern SOUND_PACKED=yes \
    VM_FREE_GATES=no WORKDIR=/tmp/virtio-sound-packed \
    sh /usr/src/tests/sys/kern/vsock_e2e/run-alpine-matrix.sh'
```

The stock 5BSD tree has no virtio-sound guest driver, so discovery alone
cannot qualify this device.  That remains a named driver and live-activation
gap.  The production OSS backend has a separate hardware-dependent gate so
the portable null-backend release suite does not claim host-audio coverage:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile audio-qualification --jobs 1 \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --set SOUND_PLAY=/dev/dsp --set SOUND_RECORD=/dev/dsp \
    --workdir /tmp/virtio-audio'
```

This runs split and packed queues against unmodified Linux ALSA, then repeats
both formats with active playback and capture across in-process checkpoint
and relaunched restore.  Each normal path must transfer exactly 192000 bytes
in each direction; each checkpoint path must prove that host completion
counters advance before and after restore.  Real OSS capture may contain
arbitrary samples, so the all-zero assertion belongs only to the null
backend.  Portable qualification retains deterministic null endpoints and
does not claim host-audio coverage.

## Feature-activation release audit

Every advertised optional feature has an independent Linux and 5BSD
disposition in `virtio-feature-activation.tsv`.  Normal VM-free validation
checks the ledger's consistency without pretending unfinished live work has
passed.  The stricter release audits are:

```sh
VIRTIO_ACTIVATION_GATE=linux \
    sh /usr/src/tests/sys/kern/vsock_device_harness/validate-virtio-requirements.sh
VIRTIO_ACTIVATION_GATE=both \
    sh /usr/src/tests/sys/kern/vsock_device_harness/validate-virtio-requirements.sh
```

The `both` gate intentionally fails for `pending` and `driver-gap` entries.
A feature is exercised only when the stock guest negotiates it, drives its
distinguishing operation, records the guest-visible result, and a host trace
shows the corresponding queue, command, mapping, reset, or state transition.
Block and SCSI multiqueue currently pass this standard on Linux.  The in-tree
5BSD block driver now negotiates MQ and allocates multiple request queues, but
its scheduled `fivebsd-block-modern-q2` live activation case has not yet run
on an installed kernel built from this tree.  SCSI still allocates one request
queue.  Neither feature may be marked exercised on 5BSD until its guest
driver, concurrent I/O, and per-queue host-correlation gate all pass.

After installing a rebuilt 5BSD guest image, run the focused block gate:

```sh
su root -c 'env \
    IMAGE=/home/koryheard/vm/bsd-guest.img \
    TRANSPORTS=modern FIVEBSD_BLOCK_QUEUES=2 VIRTIO_DEBUG=2 \
    BULK_MB=1 VM_FREE_GATES=no \
    WORKDIR=/tmp/fivebsd-block-mq \
    sh /usr/src/tests/sys/kern/vsock_e2e/run-5bsd-auto.sh'
```

The result is valid only if the guest reports two active `vtblk` queues,
the concurrent root-disk workload succeeds, and the retained bhyve trace
contains a notification for both request queues.

The corresponding SCSI gate uses an isolated CTL ramdisk and verifies the
bytes read back from each queue's nonoverlapping range:

```sh
su root -c 'env \
    IMAGE=/home/koryheard/vm/bsd-guest.img \
    TRANSPORTS=modern FIVEBSD_SCSI_QUEUES=2 VIRTIO_DEBUG=2 \
    BULK_MB=1 VM_FREE_GATES=no \
    WORKDIR=/tmp/fivebsd-scsi-mq \
    sh /usr/src/tests/sys/kern/vsock_e2e/run-5bsd-auto.sh'
```

The runner creates and removes the CTL LUN, requires
`dev.vtscsi.0.num_queues=2`, compares randomized source and readback data, and
requires notifications on request queues 2 and 3.  A retained VM deliberately
retains its CTL LUN too; it must be cleaned up with the VM rather than removed
under an active backend.

An `exercised` entry is not complete until its live proof is scheduled in the
qualification profile.  The ledger's `linux_case` and `fivebsd_case` fields
must resolve to exact `virtio-lab.yaml` case IDs; comma-separated lists are
required when a claim spans devices.  The case must name the guest assertion and host
correlation it relies on, and must fail closed if the feature is declined or
the distinct path is not reached.  Each `artifact:assertion` reference also
resolves to an explicit `VIRTIO_ACTIVATION_ASSERTION: assertion` source marker;
a plausible filename and prose label alone are not evidence.
A case must not pass merely because a fallback path handles the workload.
Multiqueue cases therefore verify
the actual active queue count, issue concurrent distinguishing I/O, and
require nonzero host notifications and completions on every active queue in
both Linux and 5BSD.  Ad-hoc commands and driver attachment are useful
diagnostics, but are not release evidence.

## Current common queue and DMA gate

The 2026-07-28 rootless gate completed after the packed-reset, DMA-owner, and
SCSI lifecycle review:

- the requirements validator accepted 151 entries and 625 independent oracle
  definitions;
- the full device harness passed, including 1,189,896 independent packed-ring
  model checks;
- packed requests retain their acquisition layout and queue-owned completion
  token across reset, so a late callback cannot consume a new split-ring
  incarnation;
- restore refuses ownership left by either ring layout, transactionally
  replaces an empty packed completion cache when queue sizes differ, restores
  the original cache after a later device-section failure, and permits a
  repeated restore;
- legacy QueuePFN replacement refuses to discard a generation-fenced split or
  packed owner;
- ACCESS_PLATFORM request leases prevent domain detachment until the final
  completion releases its callback dependency; and
- retained balloon statistics are completed while the queue is valid during
  pause, while an unreconstructible live retained token is rejected by the
  portable snapshot codec; and
- selective SCSI queue reset and successful CTL task-management operations use
  monotonic bounded drains.  A timeout retains all old request ownership,
  leaves request queues parked, reports the operation as failed, and requires
  a full device reset rather than allowing stale completion into replacement
  guest memory; the checkpoint path applies one monotonic deadline to the
  complete multiqueue drain rather than multiplying it by the queue count; and
- the exact VBSD kernel build passes with the production EPT02-root backend
  and the typed architecture-neutral internal-exit DTrace probe linked into
  `vmm.ko`; and
- block checkpoint drain admits only completion-time stability flushes after
  the backend is paused, rejects new data work, and rolls back after one
  monotonic 30-second device-wide drain deadline; read-only FLUSH is a
  successful no-op, and the new BLK1 version-2 record uses fixed-width field-wise little-endian
  configuration state rather than a native packed structure.  Obsolete
  version-1 development records are rejected.

These are VM-free proofs.  They do not replace the root-only split/packed
Linux and 5BSD activation, IOMMU translation, active-I/O checkpoint, repeated
restore, and soak cases in the qualification profiles.

## 2026-07-28 restore-epoch follow-up

The current rootless ledger contains 168 requirements and 638 independent
oracle definitions.  Modern and legacy common queues, the VirtIO-IOMMU DMA
domain, and 9P asynchronous request state now treat completion/translation
generations as destination-local epochs.  Restore consumes old wire fields
where compatibility requires them, but never republishes a source runtime
token; repeated restores advance monotonically and overflow fails before
mutation.  Administration-owner reset now drains active callbacks with a
condition variable and rejects arrivals during the drain with TRYAGAIN.

The corresponding fresh ASan/UBSan harness passes completely.  A source-paired
`libvmmapi` plus `bhyve` build also passes with the normal FreeBSD `-Werror`
flags.  A component build against the currently installed headers is not a
valid gate for this tree: those headers predate the new device-memory and
nested-VMX APIs.  Install world and kernel from one build before interpreting
any live failure as an implementation regression.

After installing a world built from this exact tree, the focused privileged
confirmation is:

```sh
su root -c 'sh /usr/tests/sys/kern/run_vsock_tests.sh \
    /tmp/vsock-root-results.txt'
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile checkpoint --jobs 2 \
    --prepare-host --bridge bridge0 --uplink re0 \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --fivebsd-image /home/koryheard/vm/bsd-guest.img \
    --workdir /tmp/virtio-epoch-checkpoint'
```

The release matrix and soak profile remain required afterward.  In
particular, the live evidence must show queue reset plus repeated restore for
split and packed devices, 9P reset/rebind with an empty reconstructible
session, both vsock backends, and translated ACCESS_PLATFORM traffic.  The
9P active-fid case is expected to fail checkpoint with `EBUSY` until a
portable fid/backend reconstruction protocol exists; it must not be recorded
as active-session migration coverage.

The unadvertised administration group foundation also has a rootless
concurrency gate for all-or-nothing multi-owner restore.  Live SR-IOV
administration qualification is still blocked on concrete PF/VF composition;
no release result may infer that coverage merely from the passing codec and
lifecycle tests.

The soak profile now has two prerequisite gates and five independently
scheduled VM soak lanes (seven manifest cases total).  Run it with enough jobs
to avoid serializing unrelated VMs:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile soak --jobs 5 \
    --prepare-host --bridge bridge0 --uplink re0 \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --workdir /tmp/virtio-soak-current'
```

Besides the two 100-iteration vsock backend lanes and the original
100-iteration split-ring core-device reset lane, this runs two bounded
20-iteration packed-ring lanes.  One repeatedly resets input, GPU, memory, and
sound while reusing a persistent uinput provider; the other resets an IOMMU
and packed net/RNG/block endpoints in dependency order and revalidates
translated I/O every five resets.  A failure in either added lane is real
qualification evidence and must not be converted to a skip merely because the
device is provisional.

The vsock lanes run one full conformance pass before and after their hot loops;
each loop iteration is the four-direction concurrent STREAM/SEQPACKET churn
matrix, not a second copy of every full-matrix case.  This keeps the longevity
gate inside one bhyve process while retaining full protocol/error coverage at
both endpoints.  A normal cancellation is intentional only when issued through
the root-owned lab controller, for example:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    cancel --workdir /tmp/virtio-soak-current'
```

The controller records cancellation as status 143 after the case wrapper has
given the runner its bounded cleanup opportunity.  A shell interrupt alone is
not qualification evidence and must not be classified as a product failure.

For a bounded operational screen before spending hours on the endurance lane,
use the separate `soak-smoke` profile.  It is seven manifest cases: the same
two prerequisite gates plus both vsock backends and the core, optional, and
IOMMU reset fabrics.  Each lane performs three iterations and validates data
after every rebind.  It is a useful pre-commit or post-upgrade gate, but is
not a substitute for the 100-iteration soak evidence:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile soak-smoke --jobs 3 \
    --prepare-host --bridge bridge0 --uplink re0 \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --workdir /tmp/virtio-soak-smoke-current'
```

## Historical PIT checkpoint retry confirmation

The fixed historical VATPIT record carries output-latch bytes but not the
cursor that says those bytes are still pending.  A checkpoint made with that
cursor active is therefore intentionally rejected with `EBUSY`; it is not
valid to restore it as an idle latch.  The root-only checkpoint regression
must force a count latch, confirm the first save fails without publishing an
image, consume the one or two pending guest port reads, retry successfully,
and verify normal PIT output after restore.  This protects the historical
wire ABI without inventing an incompatible record extension.  That live test
is pending; do not treat ordinary idle-PIT checkpoint coverage as proof of
this retry path.

The per-vCPU historical VLAPIC records are now decoded and validated as a
complete set before any destination LAPIC is published.  The privileged
multi-vCPU negative case must corrupt only a later VLAPIC record and prove
that every earlier vCPU retains its pre-restore APIC page and timer state.
This confirms the all-vCPU publication boundary rather than merely the
single-record semantic validators.

## Nested-VMX root-only continuation after the 2026-07-28 review

The source tree now passes the complete 143-case rootless nested architectural
suite both normally and under ASan/UBSan, its 166-entry requirements ledger,
ordinary and snapshot-enabled `vmm.ko` builds, and the source-paired
`libvmmapi`/`bhyve` build.  The latest fixes bind VM-entry
zero-instruction-length policy into the final event plan and make active-L2
restore validate every destination vCPU while provisioning fresh
destination-local MSR scratch before shared publication.

Do not treat those rootless results as live nested qualification.  On the
Intel test host, install world and kernel from this exact source revision,
reboot, keep `hw.vmm.vmx.nested` default-off for ordinary release testing, and
use the dedicated nested qualification profile to opt in explicitly.  The
required live evidence remains:

- Linux/KVM L1 with both Linux and 5BSD L2 guests;
- Intel-defined VMX instruction and VM-entry failure behavior;
- interrupt/APIC, timer, EPT/VPID, invalidation, and exit reflection under
  actual L2 execution;
- checkpoint and restore while L2 is running;
- repeated nested create/destroy, concurrency, fault, and soak runs; and
- a final Intel SDM and pinned Linux KVM comparison after those traces exist.

Any failure in this matrix keeps guest VMX exposure experimental.  VPID and
INVVPID remain deliberately unadvertised until the destination-local owner and
deferred-flush implementation pass the live invalidation matrix, including
reuse and migration across physical CPUs.

## VirtIO compatibility-envelope live confirmation

The rootless suite proves the byte format and rejection predicates.  After
installing a world built from this exact tree, add live checkpoint cases that:

- restore an unchanged modern split and packed VM successfully;
- reject a changed transport, queue count/size, MSI-X shape, shared-memory
  layout, and destination missing a source feature before any device restore
  callback runs;
- reject an envelope whose negotiated mask contains a bit absent from its own
  source offered mask, even after recomputing its payload CRC, matching
  metadata, member SHA-256, and outer manifest;
- accept a destination with a strict feature superset;
- reject metadata edited independently of the embedded payload envelope; and
- reject a one-byte device-payload mutation through the embedded CRC-32
  before any device restore callback runs; and
- reject independent one-byte mutations of each version-3 guest-RAM,
  kernel/device-state, and JSON-metadata member through the outer SHA-256
  manifest before VM state publication;
- reject a missing, duplicated, extra, zero-length, overlapping, gapped,
  overflowing, or trailing-unreferenced kernel/device record and prove guest
  RAM has not been copied into the destination;
- reject malformed, truncated, reordered, identity-mismatched, or
  digest-corrupt generic device-memory extensions before ordinary guest RAM
  is copied;
- reject retained version-1 and version-2 architecture manifests before any
  state publication; and
- reject a retained historical checkpoint without the current compatibility
  metadata rather than exercising a legacy per-device path.

These cases should use disposable guests and verify the failed destination
process exits without starting vCPUs.  They do not establish global
transactionality for corrupt later payloads; that requires the planned
validate/commit conversion of every snapshot section.

That VirtIO device-payload conversion is now implemented in the source tree.
The privileged confirmation must therefore strengthen the last assertion:
mutate a late normal-phase device record and an ACCESS_PLATFORM endpoint ring
address, recompute the enclosing integrity fields, and verify that neither
the earlier IOMMU fabric nor any earlier normal device was published.  Repeat
with split and packed rings.  The translated case must retain a valid incoming
IOMMU mapping for the control run, then remove only the mapping covering one
saved ring for the negative run.  Validation must reject the negative image
before vCPU start and must not emit a live IOMMU fault event while inspecting
the temporary mapping view.

## 2026-07-29 next privileged qualification

The rootless handoff now also includes an explicit null sound-backend identity
and a corrected maximum-block virtio-mem bitmap calculation.  Rebuild and
install world and kernel from the same source tree before running these gates;
an older installed bhyve cannot exercise either contract.

Run the release and checkpoint profiles first.  They now cover
`SOUND_BACKEND=null`, multiple virtio-mem region/request geometries, split and
packed RTC, memory, GPU, and sound, and the non-default GPU monitor identity.
The GPU blob cases require DTrace and must report both
`host_gpu_blob_commands create=yes set_scanout=yes` and the active checkpoint
framebuffer-marker progress messages; negotiation alone is not sufficient:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile release --jobs 3 \
    --prepare-host --bridge bridge0 --uplink re0 \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --fivebsd-image /home/koryheard/vm/bsd-guest.img \
    --workdir /tmp/virtio-release-20260729'

su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile checkpoint --jobs 2 \
    --prepare-host --bridge bridge0 --uplink re0 \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --fivebsd-image /home/koryheard/vm/bsd-guest.img \
    --workdir /tmp/virtio-checkpoint-20260729'
```

Then run the bounded soak profile already documented above.  Treat unsupported
guest drivers as unresolved ledger entries, not as passing cross-guest
coverage.  In particular, stock 5BSD currently has no virtio-mem, RTC, sound,
GPU, or virtio-fs guest driver.

The release profile's `fivebsd-modern-common-lifecycle` case also performs the
explicit VirtIO device-suspend gate.  It must report guest suspend/resume plus
post-resume data checks for RNG, block, vsock, console, and balloon, together
with matching host lifecycle completions.  This requires the rebuilt 5BSD
transport from this tree; an older guest which does not negotiate
`VIRTIO_F_SUSPEND` is a failed qualification rather than a skip.

The normal live Device Suspend path can be rerun in isolation with:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile release --jobs 1 \
    --case fivebsd-modern-common-lifecycle \
    --fivebsd-image /home/koryheard/vm/bsd-guest.img \
    --workdir /tmp/virtio-suspend-rollback'
```

That case does not yet inject transport failure and therefore cannot close
requirement `GUEST-SUSPEND-ROLLBACK`.  Before promotion, add a dedicated live
negative lane which can deterministically hold completion across the one-second
guest deadline, return `NEEDS_RESET`, and fail the function-child resume.  For
each injection it must prove that a running device is reopened, a suspend which
completed exactly at the deadline is resumed through the VirtIO 1.4 status
handshake, and a failed, reset-required, indeterminate, or failed-rollback
device leaves the function child fenced.  Record both the guest status samples
and host lifecycle transitions.  Run the same assertions through modern PCI
and, when a platform with the modern VirtIO MMIO transport is available, MMIO.
Do not treat the normal lifecycle case or a transport-only mock as satisfying
this negative gate.

Nested VMX remains a separate, explicit Intel qualification.  Its 143
rootless architectural tests and kernel-module build are green, but
`hw.vmm.vmx.nested` must stay default-off until the dedicated Linux/KVM L1
matrix records Linux and 5BSD L2 execution, VM-entry failures, event and
EPT/VPID behavior, active-L2 checkpoint, and soak results in
`tests/sys/vmm/vmx-nested-live-qualification.tsv`.

## 2026-07-30 VirtIO-SCSI event qualification

The CTL kernel ABI and bhyve event consumer must come from the same source
tree.  After installing kernel, world, and tests and rebooting, first run the
subscription ABI test:

```sh
su root -c 'kyua test -k /usr/tests/Kyuafile \
    sys/cam/ctl/lun_event_test'
```

Then run the dedicated live case through the release profile, or directly:

```sh
su root -c 'env \
    ISO=/home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    DEVICES=scsi TRANSPORTS=modern SCSI_QUEUES=2 SCSI_EVENTS=yes \
    VM_FREE_GATES=no WORKDIR=/tmp/bhyve-scsi-events \
    sh /usr/src/tests/sys/kern/vsock_e2e/run-alpine-auto.sh'
```

Success must include `PASS scsi-event-add`, `PASS scsi-event-change`, and
`PASS scsi-event-remove`, with `hotplug=yes change=yes`.  The runner issues no
guest scan command: Linux must discover all three transitions from the
VirtIO-SCSI event queue.  Confirm the bhyve log has no invalid CTL record,
event-queue overflow, or `DEVICE_NEEDS_RESET`.  A follow-up 5BSD case must
repeat the same transition sequence with the rebuilt `vtscsi` driver before
cross-guest event support is considered qualified.

## RTC and packed-device live evidence

Alarm-enabled RTC checkpoint cases add roughly twice
`RTC_CHECKPOINT_ALARM_SECONDS` (20 seconds by default) because each case proves
one live checkpoint and one suspend/restore alarm.  Do not shorten this below
five seconds: the alarm must still be pending when checkpoint begins.  A pass
must contain all three lines for each round:

```
PASS active-checkpoint-start device=rtc alarm=pending
PASS active-checkpoint-progress device=rtc alarm=delivered
PASS active-checkpoint-stop device=rtc
```

Every single-device packed lane also requires a matching host
`virtio:::chain` record with `packed=1`; feature negotiation printed by the
guest is not sufficient.  GPU blob lanes additionally require successful host
command records for resource-create-blob and set-scanout-blob.

After installing the matching snapshot-enabled kernel/world/bhyve, the
smallest repeatable live gate for the latest checkpoint changes is:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile checkpoint --jobs 1 \
    --case checkpoint-balloon-modern \
    --case checkpoint-balloon-packed-modern \
    --case checkpoint-rtc-alarm-modern \
    --case checkpoint-rtc-alarm-packed-modern \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --workdir /tmp/virtio-checkpoint-active-state'
```

These four selected cases cover split and packed balloon statistics plus
split and packed pending RTC alarms.  `--case` may be repeated; selection
preserves manifest order and is recorded in the resume configuration.  It is
a focused diagnostic gate, not a substitute for full-profile coverage.
Do not remove `BALLOON_STATS_INTERVAL=1`, `RTC_ALARM=yes`, or the packed
host-ring evidence settings.  Promotion requires both split and packed
results; rootless tests deliberately leave their activation-ledger rows
pending.

## VirtIO-memory active-page checkpoint gate

After installing a matching kernel, world, tests, and bhyve, run the two
dedicated memory lanes:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile checkpoint --jobs 1 \
    --case checkpoint-mem-modern \
    --case checkpoint-mem-packed-modern \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --workdir /tmp/virtio-checkpoint-mem-active'
```

Each lane must report `active-checkpoint-start device=mem pinned_pages=8`,
then progress after both the live checkpoint and the suspend/restore round,
and finally stop cleanly.  The worker fails if Linux cannot identify eight
application pages inside the configured VirtIO-memory physical range, if any
PFN or marker changes, or if the requested and plugged sizes cease to match.
The packed lane must also retain the independent host packed-ring trace
evidence.

## VirtIO-sound active-PCM checkpoint gate

The sound checkpoint proof now requires host-side PCM completions after each
checkpoint boundary.  A surviving `aplay` PID alone is not a pass.  After
installing the matching bhyve and tests, run:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile checkpoint --jobs 1 \
    --case checkpoint-sound-modern \
    --case checkpoint-sound-packed-modern \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --workdir /tmp/virtio-checkpoint-sound-active'
```

Both lanes must emit `PASS active-checkpoint-progress device=sound` after the
online checkpoint and again after suspend/restore.  The completion count must
increase, the original guest playback and feeder processes must remain
observable, and the ordinary exact-byte playback/capture check must still
pass.  The packed lane additionally requires host ring-layout evidence.  This
qualifies the deterministic null backend.  The production nonblocking OSS
backend has separate split and packed live activation in the `audio` profile;
provider-loss, underrun/overrun, and OSS active-checkpoint fault qualification
remain explicit follow-on gates.

## VirtIO-balloon free-page-hint activation gate

After installing a matching bhyve and test suite, run the split Linux lane and
the packed combined-feature lane:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile release --jobs 1 \
    --case balloon-free-page-hint-modern \
    --case balloon-optional-packed-modern \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --workdir /tmp/virtio-balloon-free-page-hint'
```

Both cases must negotiate feature bit 3, expose a non-STOP request or the
completed DONE state in the 16-byte device configuration, and show host
evidence that queue 3 processed either an active page hint or the terminal
STOP command.  The packed case must additionally retain the common host
packed-ring evidence.  A feature bit alone is not sufficient.  Stock 5BSD
does not implement free-page hinting; its activation-ledger entry remains a
driver gap rather than an unexplained skip.

## 5BSD balloon low-memory deflation gate

The matching rebuilt 5BSD kernel now negotiates DEFLATE_ON_OOM and handles
FreeBSD's event-driven `vm_lowmem` notification outside the callback context.
After installing that kernel, bhyve, and the tests, run:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile release --jobs 1 \
    --case fivebsd-balloon-deflate-on-oom \
    --fivebsd-image /home/koryheard/vm/bsd-guest.img \
    --workdir /tmp/virtio-fivebsd-balloon-lowmem'
```

The case must observe `DeflateOnOOM` in the negotiated guest features, inflate
to the configured target, invoke the kernel's `debug.vm_lowmem=2` test event,
observe `dev.vtballoon.0.current` fall, and then observe it return to
`desired`.  The host log must independently show a nonempty, fully accepted
deflate request.  This is a controlled low-memory event gate; sustained
allocation-pressure and OOM-killer soak remains a separate disposable-guest
qualification.

## 2026-07-31 current promotion run

On this Intel development host, `--profile intel-qualification` is the
definition-of-done profile.  It composes portable release, checkpoint, and
soak coverage with the nested-VMX hardware profile; `host-regression` remains
a single prerequisite rather than running once per constituent profile.

The current rootless baseline is clean: the complete device harness passes
under ASan/UBSan with 659 checks and zero failures; the VirtIO ledger contains
238 independently mapped requirements and 693 independent oracle definitions;
the activation ledger tracks 129 live claims; the production bhyve rebuild
completes cleanly; and the Intel nested model passes 349 cases.  These counts
describe the source tree; they do not replace a newly installed root run.

After building and installing matching kernel, world, packages, and tests and
rebooting, use the single qualification wrapper at the top of this document.
It runs the host regression before the Linux, rebuilt-5BSD, checkpoint, and
bounded soak profiles and preserves resumable per-case results.  In
particular, do not replace the full wrapper with only the focused commands in
the intervening historical sections.

The activation ledger deliberately remains unresolved for features which
have only model coverage.  Promotion requires the release output to close the
scheduled Linux and 5BSD rows with real queue traffic and host-side path
evidence.  A missing guest driver remains `driver-gap`; it must not be
converted into an exercised result or a silent skip.

The release and checkpoint manifests now treat virtio-fs as a required member
of both the reset-device and checkpoint-device domains.  A run from an older
installed test package may still print those coverage contracts as complete
without requiring `fs`; verify that the plan contains `fs-packed-modern-q8`,
`checkpoint-fs-idle-modern`, and `checkpoint-fs-idle-packed-modern` before
accepting its coverage summary.

Nested VMX remains default-off for ordinary guests, but the Intel promotion
wrapper now schedules its `nested` case through `intel-qualification`.  A
valid result is one fresh 36-artifact transaction covering Linux L2, 5BSD L2,
and host traces for all twelve groups.  Rootless model success does not authorize
enabling nested VMX for ordinary guests.

The latest CPU-model review additionally fixed an LA57-host/LA48-guest
capability mismatch.  The installed kernel used for the nested profile must
include the shared leaf-7 CPUID policy and nested CR4 fixed-bit shaping from
this source tree.  In the negative exposure control, record CPUID leaf 7 ECX,
`IA32_VMX_CR4_FIXED1`, and attempted LA57 VM-entry behavior together: when
CPUID omits LA57, fixed bit 12 must be clear and an L1 VMCS requesting
`CR4.LA57` must fail VM-entry validation.  This check is required even on a
host whose physical CPUID advertises LA57.

## Whole-machine topology-seal live gate

New checkpoints include a versioned machine-topology seal.  After installing
the matching snapshot-enabled bhyve, first rerun the ordinary checkpoint
profile unchanged.  Then preserve one disposable checkpoint and attempt
restore with one change at a time: move a VirtIO function to a different BDF,
change its configured queue count, change its MSI-X table shape through the
corresponding supported launch option, and change an enabled shared-memory
region's size.  Every changed launch must fail during preflight with
`Checkpoint machine topology is incompatible`, before backend reconstruction
or guest execution.  The original launch configuration must still restore and
pass its post-restore data check.  Historical fixtures without either
`machine_topology_version` or `machine_topology_digest` remain compatibility
fixtures; a fixture containing only one field, an unknown version, uppercase
digest text, or a digest inconsistent with its device envelopes must fail
closed.

## External-backend restore-preflight race gate

The 2026-07-31 lifecycle review made vsock and virtio-fs validation
side-effect-free when the public preflight API is called independently, while
preserving the normal production order of device pause, whole-machine
preflight, and restore commit.  After installing matching world and kernel,
run the existing split and packed checkpoint cases first:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile checkpoint --jobs 2 \
    --case checkpoint-vsock-userspace \
    --case checkpoint-vsock-userspace-packed \
    --case checkpoint-vsock-kernel \
    --case checkpoint-vsock-kernel-packed \
    --case checkpoint-fs-idle-modern \
    --case checkpoint-fs-idle-packed-modern \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --workdir /tmp/virtio-external-preflight'
```

Retain disposable images from those controls and add one mutation at a time.
For kernel vsock, make the provider acquire a connection or pending queue item
after successful independent preflight but before commit.  Commit must reject
the image, thaw the provider, and leave the source usable; validation itself
must emit no FREEZE or THAW.  Repeat with a provider identity/CID mismatch
present before preflight.

For virtio-fs, change one authenticated backend contract field before
preflight, then in a separate run change the incarnation or negotiated limit
after preflight but before commit.  The first image must fail without a
QUIESCE frame.  The second must be caught by the pause/commit recheck and must
not publish FUSE, queue, or opaque backend state.  A control run must prove the
same state-transfer-capable daemon completes split and packed idle restore.
Finally repeat each accepted restore twice to prove that destination-local
epochs and backend ownership are reconstructed rather than imported.

- `checkpoint-gpu-modern` must report both `PASS active-checkpoint-progress
  device=gpu` and a post-restore `PASS gpu-rfb` whose last pixel is
  `759abfe4`.  This is the restored checkpoint marker, not the initial display
  smoke-test marker.

## Restore compatibility mutation gate

The rootless contract now covers specification-derived feature, queue,
shared-memory, translated-DMA, and backend-identity rejection.  Privileged
qualification still needs real destination launches that change exactly one
contract field.  Preserve the original checkpoint, attempt each incompatible
restore, require bhyve to exit before guest execution, and then restore the
unmodified configuration successfully:

1. Change modern net, block, and SCSI queue count independently.
2. Remove packed-ring or ACCESS_PLATFORM support from a source that negotiated
   it; for ACCESS_PLATFORM retain the IOMMU device but detach the endpoint in a
   separate case.
3. Change a GPU shared-memory aperture and an administration-device shared
   memory region without changing the BDF.
4. Change block image/checkpoint identity, tap identity, 9P export root,
   console endpoint, input path, virtio-fs backend identity, sound backend,
   and userspace/kernel-vsock provider identity one at a time.
5. Corrupt a later device payload in a combined VM and prove an earlier device
   retained its destination state, demonstrating that payload validation
   precedes every commit.

Every rejected attempt must contain the device name and incompatibility class
in its diagnostic log, leave no restored VM process or backend ownership, and
must not emit backend FREEZE/QUIESCE traffic during validation.  The following
successful control restore must repeat the device workload so a rejection
cannot be mistaken for a harmless early exit.

The net queue-geometry and negotiated-PACKED mutations are now automated by
`checkpoint-net-modern` and `checkpoint-net-packed-modern`.  Their success
markers are respectively:

```text
PASS incompatible checkpoint restore rejected contract=net-queue-geometry
PASS incompatible checkpoint restore rejected contract=net-ring-feature-set
```

Both cases still perform the ordinary restored network workload afterward.
The block/SCSI queue mutations, ACCESS_PLATFORM endpoint mutation,
shared-memory changes, backend identities, and combined-payload corruption
remain privileged completion items from the list above.

## VirtIO PMEM split, packed, reset, and checkpoint gate

After installing the matching snapshot-enabled bhyve, run the dedicated Linux
PMEM lanes.  They use an unmodified Alpine `virtio_pmem`/libnvdimm driver and
disposable per-case backing files:

```sh
su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile release --jobs 1 \
    --case pmem-modern --case pmem-packed-modern \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --workdir /tmp/virtio-pmem-release'

su root -c '/usr/libexec/flua \
    /usr/src/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile checkpoint --jobs 1 \
    --case checkpoint-pmem-modern \
    --case checkpoint-pmem-packed-modern \
    --iso /home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
    --workdir /tmp/virtio-pmem-checkpoint'
```

Each release case must report a PMEM marker whose guest digest equals the
fixed-offset host backing digest before and after reset/rebind.  Each
checkpoint case additionally keeps one guest PMEM write/fsync/read process
alive, requires its durable counter to advance after online checkpoint and
again after restore, and then writes a new independently verified marker.
Packed cases must show an enabled packed `vtpmem` request queue.

Both checkpoint cases automatically attempt restore with a changed
`PMEM_IDENTITY` and then a backing enlarged by one page.  Both attempts must
fail before guest execution and before importing queue state; the harness
restores the original identity and exact byte size before the accepted
restore, same-PID workload check, and host backing comparison.  It then stops
that destination and restores the same checkpoint a second time, repeating
the workload and persistence proof.  Correlate `virtio:::pmem-flush`
lifecycle-submit/completion events during this run; that trace is the remaining
manual promotion gate.  Stock 5BSD has no VirtIO PMEM guest driver, so no 5BSD
pass is claimed.

## Historical kernel-device checkpoint qualification

The fixed historical VMM records for VM events, PIT, PIC, RTC, HPET, I/O APIC,
PM timer, and local APIC now use staged restore transactions.  Their rootless
validators prove wire-field ordering, ownership boundaries, and malformed
record rejection, but cannot establish host-callout or interrupt timing.

Before promoting checkpoint/restore, add this explicit installed-kernel lane
to the matching snapshot-enabled bhyve run:

- establish pending PIC/I/O-APIC/APIC work and an armed PIT, RTC, HPET, and
  LAPIC timer, then checkpoint before the selected delivery or expiry;
- restore into a fresh destination and prove exactly one intended interrupt or
  timer event is delivered, with no source-relative deadline replay;
- verify the PM timer advances from the saved guest-visible counter rather
  than from source-host uptime;
- reject truncated and semantically inconsistent records, including an APIC
  ISR-stack mismatch and an APIC-page/LVT-shadow mismatch, while the stopped
  destination retains its pre-restore state; and
- repeat accepted restore into a second fresh destination.  Preserve console,
  bhyve log, and interrupt trace artifacts for each attempt.

This lane is architecture-neutral at the VMM/device boundary.  Its Intel
nested-VMX extension must additionally checkpoint an L1 while an L2 has a
pending interrupt or timer and must run only after the ordinary device-state
lane passes.

## Intel nested VPID/INVVPID qualification

The positive VPID live group now has a separate default-off host policy.  For
the disposable Intel qualification boot, install the matching kernel/world
and set both loader tunables before rebooting:

```sh
sysrc -f /boot/loader.conf hw.vmm.vmx.nested=1
sysrc -f /boot/loader.conf hw.vmm.vmx.nested_vpid=1
```

After reboot, verify both values are exactly one.  The nested live wrapper now
refuses to run otherwise:

```sh
sysctl -n hw.vmm.vmx.initialized hw.vmm.vmx.nested hw.vmm.vmx.nested_vpid
```

All three values must be `1`.  Absence of either nested-policy sysctl means
the matching kernel has not yet been installed and booted; do not substitute
an `hw.model` string or another vendor-name heuristic for the initialized VMX
backend state.

Run the `nested` or `full-qualification` profile with the reviewed Linux/KVM
L1 runner and both L2 images described above.  The VPID group must prove all
four guest INVVPID types, allocator reuse, CPU migration, isolation from
unrelated host tags, reset, active-L2 checkpoint/restore, staged-allocation
exhaustion, and abort cleanup.  A separate boot without
`hw.vmm.vmx.nested_vpid` must prove that IA32_VMX_PROCBASED_CTLS2 withholds
VPID and INVVPID raises #UD.  Do not promote the feature or enable the tunable
on ordinary hosts until both evidence sets pass.

## Rebuilt FreeBSD guest IN_ORDER qualification

The common guest kernel now supports the optional split and packed IN_ORDER
batch-completion forms.  After installing a world/kernel containing this
tree, run the existing `fivebsd-packed-core` lane and the per-device split and
packed 5BSD cases.  Evidence must show that the guest accepted both
`VIRTIO_F_RING_PACKED` and `VIRTIO_F_IN_ORDER`, completed real data in both
formats, crossed the packed wrap boundary under repeated traffic, and still
completed traffic after selective queue reset.  A guest which declines
IN_ORDER is interoperable but does not qualify this implementation path.

The live device model normally completes one buffer at a time, so successful
negotiation alone does not exercise the optional batched record.  Promotion
also requires a controlled test device or fault mode which emits one valid
multi-buffer batch followed by unreachable-marker and excessive-length
records.  The valid batch must return every cookie in order with the recorded
writable lengths; each malformed record must publish `FAILED`, stop further
notifications without a kernel panic or unbounded poll, and recover only
after the documented reset/reinitialization path.  Preserve console and
kernel status logs as the evidence for that negative lane.

## Dirty-log collector prerequisite (not a migration interface)

The common VMM source now has a private staged observation primitive and an
amd64-private guest-pmap leaf query.  Neither is a public dirty-log interface,
and no current qualification profile may claim pre-copy migration from their
presence.  Before such an interface is proposed, add and run a dedicated
privileged lane that proves the same operation for both EPT and NPT:

- clean, write, observe, publish, clear, rewrite, and re-observe for 4 KiB,
  2 MiB, and 1 GiB leaves;
- rejection under emulated A/D operation without a changed output bitmap;
- frozen-vCPU plus map/reset/destroy races, including a stale ticket with no
  backend query or clear;
- an injected scan/clear/publication failure which preserves either the prior
  published bitmap or the still-dirty backend state; and
- active-I/O checkpoint and repeated restore with Linux and rebuilt 5BSD
  guests, where the destination compatibility decision occurs before any
  guest execution.

Capture the logical low-GPA/low-bit bitmap independently in the test harness;
do not compute expected values from VMM headers.  The initial live lane must
remain Intel-host scoped, because it uses EPT/NPT hardware A/D behavior, while
the common bitmap, map-generation, and ticket contracts remain portable and
must keep passing their normal and UBSan model gates on every supported build
architecture.

## Rootless checkpoint and nested preflight replay

Before scheduling a privileged checkpoint, migration, or nested-VMX run, the
following checks are safe to run from the source tree and do not create a VM,
bridge, TAP, or checkpoint artifact:

```sh
sh /usr/src/tests/sys/kern/vsock_device_harness/run-snapshot-model.sh
sh /usr/src/tests/sys/kern/vsock_device_harness/validate-virtio-snapshot-portability.sh
sh /usr/src/tests/sys/kern/vsock_device_harness/validate-virtio-snapshot-portability-selftest.sh
sh /usr/src/tests/sys/vmm/validate-vmx-nested-requirements.sh
sh /usr/src/tests/sys/vmm/vmx-nested-policy-pair-selftest.sh
```

For a dry nested qualification plan, provide only the immutable L1/L2 input
names; the files need not be opened in `PLAN_ONLY` mode:

```sh
env PLAN_ONLY=yes PROFILE=nested JOBS=1 \
  NESTED_L1_RUNNER=/absolute/path/to/l1-runner \
  NESTED_L1_IMAGE=/absolute/path/to/l1.img \
  NESTED_LINUX_L2_IMAGE=/absolute/path/to/linux-l2.img \
  NESTED_FIVEBSD_L2_IMAGE=/absolute/path/to/freebsd-l2.img \
  sh /usr/src/tests/sys/kern/vsock_e2e/run-waspnest-qualification.sh
```

This prints the selected `virtio-lab` invocation.  It is deliberately not a
hardware result: the live nested lane remains fail-closed until its complete
VMCS02 ownership transaction is implemented and then run on an Intel host
with the authenticated L1/L2 corpus.
