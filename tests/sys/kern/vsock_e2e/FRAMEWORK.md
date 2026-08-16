# bhyve VirtIO test framework

This directory is the real-VM half of a layered VirtIO acceptance suite.  A
change is not accepted merely because a guest enumerates a PCI function: each
device must prove its untrusted descriptor handling without a VM, its isolated
guest data path, its compatibility transport, and its behavior beside every
other covered device.

## Orchestrated runs

`virtio-lab` is the preferred front end once more than one focused case is
needed.  It reads `virtio-lab.yaml`, validates that the selected profile covers
its declared public option domains, assigns every VM a distinct CID, port
range, console port, and work directory, and schedules only cases whose
declared host resources do not conflict.  Every run writes a concise
`events.tsv`, one log and atomic status file per case, and a final summary.
The existing shell runners remain the case executors and therefore retain
their focused diagnostics and cleanup behavior.

Exercise the complete VM-free layer with two scheduler slots:

```sh
/usr/tests/sys/kern/vsock_e2e/virtio-lab run \
    --profile vmfree --jobs 2 --workdir /tmp/virtio-vmfree-1
```

Plan a release without root or booting a VM:

```sh
/usr/tests/sys/kern/vsock_e2e/virtio-lab plan --profile release
```

For a repeatable focused diagnosis, add one or more case identifiers from the
plan:

```
/usr/tests/sys/kern/vsock_e2e/virtio-lab plan --profile checkpoint \
    --case checkpoint-balloon-modern \
    --case checkpoint-rtc-alarm-modern
```

`--case` preserves manifest order, rejects identifiers outside the selected
profile, and becomes part of the run's resume identity.  A filtered plan or
run intentionally does not claim that the profile coverage contract passed;
`coverage --case` is rejected.  Release and qualification promotion still
require the unfiltered profile.

Run up to three independent cases concurrently:

```sh
su root -c '/usr/tests/sys/kern/vsock_e2e/virtio-lab run \
    --profile release --jobs 3 --prepare-host \
    --bridge bridge0 --uplink re0 --iso /path/to/alpine-virt.iso \
    --workdir /tmp/virtio-release-1'
```

The `release` profile first runs the exclusive `host-regression` gate.  It
executes the requirements ledger, host-helper controls, and the canonical
VirtIO/vsock/AF_VSOCK ATF runner.  No VM worker is launched unless that gate
passes.  A second exclusive VM-free gate compiles the complete in-tree 5BSD
VirtIO guest stack with `-Werror` (core and PCI transports plus net, block,
SCSI, balloon, RNG, console, GPU, input, 9P, RTC, and vsock modules).  This
proves that the drivers used by the 5BSD activation matrix build from the same
source revision; successful compilation does not replace live feature
activation in the disposable guest image.  The `vmfree` and `nested` profiles
also compile the production `vmm.ko` in an isolated object tree.  That closes
the build/link boundary for the Intel nested implementation, but cannot
replace the L1/L2 hardware evidence produced by `nested-vmx-live`.  The
individual `vmfree` cases remain available for focused development and the
`smoke` profile, without duplicating them in a release
run.  A gate failure records every unstarted case as `BLOCKED`; `--resume`
reruns the failed gate and starts VM work only after it succeeds.
The gate includes the AF_VSOCK isolation tests, so `/dev/mac_capability` must
be accessible.  Stop `oracled` (and any other process holding an isolation
claim on that device) before starting a release run; host preflight reports
this condition before creating any VM.

Parallel runs require a shared bridge prepared once by the orchestrator before
workers launch.  The uplink is always explicit; the lab does not silently
modify the interface carrying the default route.  `run --prepare-host` performs
the idempotent preparation shown above.  The same lifecycle is also available
separately for preparing a host once and executing several profiles:

```sh
su root -c '/usr/tests/sys/kern/vsock_e2e/virtio-lab host-prepare \
    --bridge bridge0 --uplink re0'
/usr/tests/sys/kern/vsock_e2e/virtio-lab host-status --bridge bridge0
```

`host-prepare` is idempotent and records exactly whether it created the bridge
and added the uplink in a root-owned state file under `/var/run/virtio-lab`.
Workers create and remove their own tap interfaces but leave the shared bridge
alone.  After all runs have stopped, remove only resources owned by the lab:

```sh
su root -c '/usr/tests/sys/kern/vsock_e2e/virtio-lab host-cleanup \
    --bridge bridge0'
```

Cleanup refuses unmanaged bridges and bridges which still contain a VM tap.
Cases using CTL, uinput, checkpoint publication, or the kernel-vsock provider
declare resource locks in the manifest.  `status --workdir ...` reports
progress without streaming guest consoles.  Stop active case children with
`cancel --workdir ...`; cancellation is recorded as status 143 after the
runner has received a termination signal and performed its cleanup.  If the
front end is interrupted but its supervised cases remain alive, use the same
manifest and settings with `run --resume --workdir ...`.  Resume reuses only
successful cases and rejects a changed manifest, profile, ISO, or override
set.  The `checkpoint` and `soak` profiles separate expensive lifecycle and
longevity gates from the ordinary smoke profile.

Nested VMX has a separate `nested` profile because it is Intel-only,
experimental, and default-off.  This profile first runs the same architectural
host-regression gate, then executes one exclusive hardware case through the
strict L1-driver evidence contract:

```sh
su root -c '/usr/tests/sys/kern/vsock_e2e/virtio-lab run \
    --profile nested --jobs 1 \
    --workdir /tmp/waspnest-nested-vmx \
    --set NESTED_L1_RUNNER=/path/to/reviewed-l1-runner \
    --set NESTED_L1_IMAGE=/path/to/linux-kvm-l1.raw \
    --set NESTED_LINUX_L2_IMAGE=/path/to/linux-l2.raw \
    --set NESTED_FIVEBSD_L2_IMAGE=/path/to/fivebsd-l2.raw'
```

The runner must be root-owned and not writable by group or other.  It boots
the pinned Linux/KVM L1 with `x86.nested_vmx=true`, runs both L2 operating
systems, and writes the four-column evidence transaction named by
`NESTED_EVIDENCE_FILE`.  Every evidence token must resolve below
`NESTED_LIVE_ARTIFACT_DIR` to a distinct, nonempty, owner-only artifact.  Its
version-3 header names the matching feature and role, records `result=PASS`,
copies the wrapper-generated `NESTED_LIVE_RUN_ID`, records strict UTC start and
finish bounds, and includes exactly one `assertion` record for every normative
requirement ID assigned to that feature group plus one corresponding `proof`
record.  Each proof names that requirement, a guest-test or host-trace type
appropriate to the artifact role, a stable test/trace label, and a positive
observation count.  Missing, duplicate, zero-count, unknown, cross-role, or
cross-group proof IDs fail closed.  The host wrapper derives the required feature and artifact
counts from the validated live ledger (currently twelve groups and 36 artifacts),
separate Linux-L2, 5BSD-L2, and host assertions, unchanged SHA-256 values for
the runner, all images, and bhyve, plus stable hashes while the evidence
bundle is validated and atomically published.  The profile is orchestration, not
evidence by itself; it remains outside `qualification` until the live ledger
is complete and nested VMX is ready to leave its default-off policy.  On the
Intel development target, `intel-qualification` deliberately composes that
hardware profile with portable qualification while leaving the portable
profile usable on future non-Intel hosts.

The VPID/INVVPID feature group additionally requires the test host to have
booted with `hw.vmm.vmx.nested_vpid=1` as well as
`hw.vmm.vmx.nested=1`.  A second boot with the VPID tunable off must run the
`nested-default` profile in a distinct work directory and prove that VPID and
INVVPID are absent while untagged L2 execution remains functional.  The
wrapper binds each transaction to its observed boot policy, kernel-version
hash, and loaded `vmm.ko` image hash in
`host-policy.tsv`; one transaction cannot satisfy the other policy.  The
installed `validate-vmx-nested-policy-pair.sh` tool revalidates both sealed
transactions and requires identical qualification inputs and exact kernel and
VMM module build identity.  The
positive VPID group must cover
all four virtual INVVPID types, tag reuse, CPU migration, reset, active-L2
restore, allocation exhaustion, and transactional restore abort before the
default policy can be reconsidered.

`full-qualification` is the single-machine release gate for this Intel host.
It composes portable `qualification`, nested-VMX hardware qualification, the
representative split/packed OSS sound cases, and the 46-case non-VirtIO
Alpine/5BSD live and checkpoint matrix.  Run it through the wrapper so host
preparation, device backends, nested inputs, cleanup, resumability, and the
result ledger are one transaction:

```sh
su root -c 'env \
    PROFILE=full-qualification JOBS=3 \
    ISO=/path/to/alpine-virt.iso \
    FIVEBSD_IMAGE=/path/to/disposable-freebsd.raw \
    UPLINK=re0 SOUND_PLAY=/dev/dsp SOUND_RECORD=/dev/dsp \
    NONVIRTIO_TPM_PATH=/path/to/swtpm.sock \
    NONVIRTIO_PASSTHRU=ppt0 \
    NONVIRTIO_PASSTHRU_LINUX_ASSERT=/root/test-selected-ppt-device \
    NONVIRTIO_PASSTHRU_FIVEBSD_ASSERT=/root/test-selected-ppt-device \
    NESTED_L1_RUNNER=/path/to/reviewed-l1-runner \
    NESTED_L1_IMAGE=/path/to/linux-kvm-l1.raw \
    NESTED_LINUX_L2_IMAGE=/path/to/linux-l2.raw \
    NESTED_FIVEBSD_L2_IMAGE=/path/to/fivebsd-l2.raw \
    WORKDIR=/tmp/waspnest-full-qualification \
    sh /usr/tests/sys/kern/vsock_e2e/run-waspnest-qualification.sh'
```

Set `RESUME=yes` with the identical inputs to reuse only successful cases.
The profile currently resolves to 200 de-duplicated cases.  Portable hosts can
continue to use `qualification`; machines without suitable OSS endpoints can
use `intel-qualification` and keep audio as an explicit external gate.

Before a privileged run, `PLAN_ONLY=yes` validates the selected profile and
prints the exact `virtio-lab` argument vector without creating a bridge,
changing host networking, or starting a VM.  It is particularly useful for
the nested-only profiles, whose L1/L2 inputs are independent of the ordinary
Alpine and disposable-5BSD images:

```sh
env PLAN_ONLY=yes PROFILE=nested JOBS=1 \
    NESTED_L1_RUNNER=/path/to/reviewed-l1-runner \
    NESTED_L1_IMAGE=/path/to/linux-kvm-l1.raw \
    NESTED_LINUX_L2_IMAGE=/path/to/linux-l2.raw \
    NESTED_FIVEBSD_L2_IMAGE=/path/to/fivebsd-l2.raw \
    sh /usr/tests/sys/kern/vsock_e2e/run-waspnest-qualification.sh
```

The emitted nested plan must contain no `--prepare-host`, `--uplink`, `--iso`,
or `--fivebsd-image` argument.  A release-family plan intentionally rejects
missing Alpine, 5BSD-image, and uplink inputs.

The YAML `coverage` section is the release contract for behavior-affecting
VirtIO test options.  A release plan fails when any declared value lacks a
case.  The `coverage` verb therefore prints a `SCOPE` line before its stable
`COVERED` records: those records prove the selected manifest has the declared
option combinations, not that any guest case has run or passed.  Runtime
evidence belongs exclusively to a completed `run` summary and its per-case
terminal records.  `allowed_overrides` is the deliberate command-line environment API, so
a misspelled or undeclared `--set` is rejected.  Infrastructure paths,
diagnostic verbosity, allocation values, data-set sizes, and soak thresholds
are not treated as pairwise feature dimensions.  The standards requirements
ledger is a separate VM-free case, which prevents an advertised or mandatory
VirtIO requirement from silently lacking implementation and positive-test
evidence.  The adjacent `virtio-feature-activation.tsv` ledger separately
records whether Linux and 5BSD actually negotiate and drive each optional
mechanism.  An `exercised` entry requires a guest-visible assertion, real
data/control traffic, and host-side evidence from the distinct implementation
path.  `pending` and `driver-gap` are explicit non-coverage states; they cannot
be summarized as a pass merely because another guest exercised the feature.
Each exercised guest status also names its exact scheduled `virtio-lab.yaml`
case.  The VM-free validator rejects missing and unknown case IDs; a
cross-device claim lists every applicable case instead of using one device as
proof for the others.

Every Alpine run also inventories every attached VirtIO PCI function through
the guest's 64-bit negotiated `features` bitmap.  It requires VERSION_1 on
modern functions, forbids it on legacy functions, and requires RING_PACKED to
match the per-device opt-in exactly.  The 5BSD runner performs the equivalent
audit through each `vtpci` parent's `host_features` and
`negotiated_features` sysctls and applies the packed expectation to every
supported child.  These inventories make negotiation an explicit artifact;
the device-specific helpers still have to drive the corresponding data or
control path before a feature can be promoted to `exercised`.

Coverage values are scalar unless a contract explicitly sets `tokens: true`.
Tokenized contracts split an environment value on ASCII whitespace and are
used for domains such as a combined `DEVICES` topology.  This lets one VM
prove that every named endpoint was present while the live verifier still
requires independent translated-DMA activity for each enumerated endpoint;
it does not turn one endpoint's activity into evidence for another.
Each `artifact:assertion` evidence reference must also resolve to an explicit
`VIRTIO_ACTIVATION_ASSERTION: assertion` marker in that artifact.  Fabricated
labels and real files with nonexistent markers fail validation.
Together these checks cover declared supported behavior; they do
not claim that unsupported VirtIO features or every host backend combination
has become supported.

The allocator reserves a 1,024-port lane per selected case.  The two-VM
provider case uses two 512-separated sub-lanes, which exceed the test suite's
247-port span while keeping every generated port below 65536 even at the
32-job scheduler limit.  CIDs and console TCP ports are also unique per case.
Direct shell-runner invocations independently reject offsets that would place
the highest test port outside the 16-bit port space.

## Required gates

Run the gates in this order.  Early failures are cheaper and more specific.

1. **Device and transport harnesses (VM-free).** Run
   `../vsock_device_harness/run.sh` and `../vsock_rx_harness/run.sh`.  These
   tests include the real bhyve device sources, guest `uipc_vsock.c` RX state
   machine, and guest `virtio_vsock.c` transport.  They exercise malformed
   descriptors, invalid queue directions, short buffers, queue ownership and
   exhaustion, reset/failure cleanup, interrupt suppression, feature
   negotiation, credit handling (including atomic-record partial-credit
   stalls), lifecycle wakeups, and boundary sizes under
   ASan and UBSan.  The guest transport test uses a pthread-backed kernel
   sleep shim to race a TX-ring-blocked sender against detach and enforce the
   one-second wakeup contract.  It also schedules RX delivery across detach's
   queue drain and makes TX interrupt dequeue hold the transport mutex while
   detach waits.  The guest socket-domain test verifies that send-side shutdown
   and asynchronous errors are checked under their owning locks before any
   user data is consumed.
2. **Host helper controls (VM-free).** Run `host-tools-selftest.sh` with
   `TOOLS` set to the Makefile's `.OBJDIR`.  It validates stream and SEQPACKET
   relays, an intentionally fragmented SCM_RIGHTS control reply, a 1 MiB
   stream, a single 200 KiB record, and the serial-console payload chunking
   used to provision guests.  It also validates rejected input-provider paths,
   commands, and status events without opening `/dev/uinput`.
3. **Guest verifier self-tests.** Each guest helper must have a
   `--self-test` mode for parsing and negative cases that do not require its
   device.  `run-alpine-auto.sh` executes it after a checksum-verified upload.
4. **Isolated real-VM test.** `DEVICES=<name>` must attach only that device.
   The verifier must uniquely match the expected PCI function, prove it is
   bound to the intended upstream driver, and exercise actual data in every
   supported direction.  Each vsock preflight also verifies guest-initiated
   reserved-CID behavior: CID 0 must time out and CID 2 on an unused host port
   must be reset.  Its full data matrix requires remote SEQPACKET graceful
   close in both directions, with the payload and EOF observed by each peer.
   It also SIGKILLs an established host connector, requires guest EOF/reset,
   and proves a fresh connection immediately afterward.
5. **Transport compatibility.** `modern` explicitly opts in to the modern
   transport.  `legacy` deliberately omits the transport option, which tests
   existing bhyve command lines rather than a synthetic explicit-legacy path.
   A historical interface without an upstream guest driver is preserved and
   covered by VM-free compatibility tests, but is not represented as a passing
   real-VM data path.  The matrix must report that scope explicitly.
6. **Combined regression test.** Attach all covered devices and rerun every
   verifier.  This detects shared VirtIO, PCI layout, interrupt, and lifecycle
   regressions.

The full Alpine acceptance command is below.  By default it executes gates 1
and 2 once before starting the topology/transport VM matrix:

```sh
ISO=/path/to/alpine-virt.iso ./run-alpine-matrix.sh
```

The declarative release lab runs the complete sanitizer/device harness and
the installed ATF suites once as its exclusive host gate, then starts the VM
matrix.  It also runs `run-5bsd-auto.sh` against a caller-supplied 5BSD raw
   base image.  A private sparse copy is booted once with modern PCI transport and
once with the default legacy command-line behavior, and validates root
virtio-blk I/O, vsock and RNG attachment, plus the full bidirectional vsock
matrix.  A separate scheduled lane requires packed block, RNG, and vsock
queues and correlates each guest workload with host queue evidence:

```sh
/usr/libexec/flua ./virtio-lab.lua run --profile release --jobs 3 \
    --iso /path/to/alpine-virt.iso \
    --fivebsd-image /path/to/5bsd-base.raw \
    --prepare-host --bridge bridge0 --uplink re0 \
    --workdir /tmp/virtio-release
```

The base image is never attached writable.  The runner serializes access,
refuses a base already attached to bhyve, creates a sparse copy for each
transport, forces a UFS check on the copy, and requests a clean shutdown.

`vsock-kernel` is a focused matrix topology that selects bhyve's
`backend=kernel` provider and host `AF_VSOCK` helpers.  It is intentionally
separate from `vsock-userspace`, which remains the compatibility test for the
default userspace socket backend.  The kernel topology forces driver reset and
monitor-mode reboot so provider reset, detach, and re-attach are exercised as
well as the data path.

`run-alpine-multi-vsock.sh` is the multi-provider fleet gate.  It runs two
kernel-backed guests with distinct CIDs and port ranges and synchronizes them
before the initial VSOCK data matrix, immediately before reset/rebind, and
after post-reset verification.  The first barrier guarantees both providers
are attached before transport traffic begins.  Requiring both guests at the
later barriers proves simultaneous provider usability through reset instead
of only proving that two bhyve processes existed at the same time.
The checkpoint profile also runs this executor with reset disabled and
checkpoint enabled.  Pre- and post-checkpoint barriers keep both distinct CID
providers attached while each VM proves active-connection rejection and
rollback, then completes an idle portable save and destination restore.

The default topology order also includes the modern-only `fs` backend between
9P and input.  Net, both vsock backends, RNG, block, SCSI, console, and 9P run
both `modern` and `legacy`; virtio-fs and input's real-VM data paths run only
with their modern interfaces
because VirtIO 1.4 assigns no transitional PCI identity to the input device,
and defines virtio-fs as a modern device.
Every topology retains and verifies the network interface used to provision
the guest.  SCSI uses a uniquely sized, fully backed CTL ramdisk which is
removed on exit.  The legacy combined run contains net, vsock, RNG, block,
SCSI, console, and 9P and omits modern-only devices.  A development run can
narrow either axis, for example:

```sh
ISO=/path/to/alpine-virt.iso \
TRANSPORTS=modern TOPOLOGIES='rng combined' ./run-alpine-matrix.sh
```

The focused shared-interrupt lifecycle gate is:

```sh
ISO=/path/to/alpine-virt.iso ./run-alpine-no-msix.sh
```

It runs the legacy net/vsock/RNG/block combination with bhyve `-W`, resets and
rebinds every attached VirtIO PCI function, rechecks data paths, reboots under
monitor mode with established STREAM and SEQPACKET connections, requires both
old endpoints to disconnect within 30 seconds, and verifies fresh vsock paths
and the same block prefix after the new guest boot.

`VSOCK_SOAK_ITERATIONS=N` converts either focused vsock topology into a
same-process longevity gate.  It first runs the full conformance matrix, then
runs `N` hot iterations containing concurrent STREAM and SEQPACKET traffic in
both directions; each worker proves connection, tagged data integrity,
orderly close, and endpoint reuse.  It performs full conformance again after
the hot loop and checks bhyve descriptor/RSS growth after every iteration.
The kernel backend additionally requires `kern.vsock.cur_connections` to
return to its post-warmup baseline.  This is the acceptance gate for slow
descriptor, connection, and heap leaks; it complements rather than replaces
the sanitizer and deterministic race harnesses.

`VIRTIO_RESET_SOAK_ITERATIONS=N` repeatedly unbinds and rebinds every selected
VirtIO PCI function, reruns the real network and selected device data checks,
and bounds bhyve descriptor and RSS growth after every cycle.  Block and SCSI
checks verify the original data after each reset; console, 9P, RNG, and vsock
perform fresh transfers.  Input is included through the long-lived
`uinput-inject` provider: each rebind starts a fresh guest event exchange and
requires a new host-observed LED response.  This avoids treating a stale event
node or a one-shot provider result as reset evidence.  For example:

```sh
ISO=/path/to/alpine-virt.iso VM_FREE_GATES=no \
TOPOLOGIES='net vsock-userspace vsock-kernel rng block scsi console 9p' \
TRANSPORTS=modern \
VIRTIO_RESET_SOAK_ITERATIONS=100 ./run-alpine-matrix.sh
```

`virtio-lab.lua --profile soak-smoke` is the bounded operational screen.  It
runs three hot iterations for each userspace and kernel vsock backend, and
three reset/rebind cycles for the core, optional-device, and IOMMU fabrics.
Unlike a reduced one-off command, it uses the same host-regression gate,
resource serialization, CID allocation, independent coverage contracts, and
post-rebind data checks as the full soak profile.  It verifies functionality
after every reset.  Use it for a practical pre-commit or post-upgrade gate;
the `soak` profile retains the 100-cycle endurance evidence and must not be
replaced by the bounded screen in a release report.

```sh
su root -c '/usr/libexec/flua \
    /usr/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile soak-smoke --jobs 3 \
    --iso /path/to/alpine-virt.iso --workdir /tmp/virtio-soak-smoke'
```

`VM_FREE_GATES=no` skips the first two gates for a repeated VM-only debugging
run; it is not an acceptance result by itself.  Gate 1 requires the bhyve
source tree named by `SRCTOP` (default `/usr/src`).  The VM runners and host
controls otherwise work from either a source/object build or an installed test
package, using helper binaries installed beside the scripts when no Makefile is
present.

The `checkpoint` profile is the checkpoint qualification matrix, not the
historical four-device smoke test.  It has modern split- and packed-ring cases
for net, RNG, balloon, RTC, block, SCSI, userspace and kernel vsock, console,
input, 9P, virtio-fs, GPU, virtio-mem, pmem, sound, and translated-DMA/IOMMU
compositions where the device contract supports them.  The cases select the
appropriate device-specific policy: for example, active 9P and active console
checkpoints are expected to reject and roll back intact, while the virtio-fs
lane exercises its explicitly reconstructible backend session.

The manifest's `checkpoint-devices` contract makes that intended matrix
machine-checkable.  A manifest entry is still only a qualification obligation:
it must not be reported as live checkpoint evidence until the root-only case
has passed using a source-matched snapshot-enabled kernel, bhyvectl, bhyve,
and backend.  In particular, a feature negotiation or an idle boot does not
substitute for a post-restore data-path assertion.

## FreeBSD guest queue-reset acceptance

The Alpine matrix validates bhyve as the VirtIO device.  The complementary
FreeBSD guest transport test must run inside a disposable bhyve VM using a
modern virtio-rng device:

```sh
ITERATIONS=100 /usr/tests/sys/kern/vsock_e2e/run-freebsd-vtrnd-reset.sh
```

The test requires `kern.vm_guest=bhyve`, an attached `vtrnd` below
`virtio_pci`, and the `virtio:::queue-reset-end` DTrace probe.  It keeps
random reads active while repeatedly detaching and reattaching the entropy
driver, verifies random-source registration at each transition, and requires
at least one successful queue-0 reset probe for every detach with no reset
errors.  This distinguishes negotiated individual queue reset from the safe
full-device-reset fallback.  Increase `ITERATIONS` for a teardown soak.

## Adding a device

A new device is complete only when all of the following are present:

- a device-harness target that includes the real backend and validates
  descriptor counts, directions, lengths, addresses, queue exhaustion, reset,
  and host-I/O errors;
- a guest verifier with `--self-test`, unique PCI/driver binding checks, exact
  data assertions, awkward boundary sizes, repetitions, and useful failures;
- a `DEVICES` selector and isolated topology in the Alpine runners;
- modern opt-in and option-omitted default-legacy launches where both have an
  upstream guest driver, plus VM-free preservation tests for historical
  interfaces that cannot be exercised by that guest;
- automatic log capture for the provider, bhyve, helper, and guest console;
- inclusion in the combined topology and in the installed `vsock-tests`
  package.

Provider-backed devices such as input also need a disposable software provider
that reports its created path programmatically, has a readiness handshake, and
proves the reverse/status path before it exits.  Tests must not depend on a
physical device number or stale `/dev` node.

## Failure contract

The runners stop at the first failed prerequisite or bidirectional smoke test.
They report command status and byte counts, retain per-case host logs, and tail
the bhyve and guest-console logs.  A matrix of identical unexplained `FAIL`
lines is a harness bug: do not add retries that hide it.  Retries are permitted
only for an explicitly transient protocol result, such as the vsock control
path's `ECONNREFUSED` while a newly announced guest listener becomes visible.

Root-run work directories must be real, root-owned, mode-0700 directories
before logs, FIFOs, sockets, or device paths are created in them.  The runner
refuses an existing permissive directory instead of changing a system path's
mode on the caller's behalf.
Guest helper uploads are chunked for the serial console and verified by both
checksum and size before execution.
Provisioning bounds DHCP retries, selects the repository branch encoded by the
booted ISO instead of `latest-stable`, and prints the exact Alpine and Python
versions into the retained console log.
