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
passes.  The individual `vmfree` cases remain available for focused
development and the `smoke` profile, without duplicating them in a release
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

The YAML `coverage` section is the release contract for behavior-affecting
VirtIO test options.  A release plan fails when any declared value lacks a
case.  `allowed_overrides` is the deliberate command-line environment API, so
a misspelled or undeclared `--set` is rejected.  Infrastructure paths,
diagnostic verbosity, allocation values, data-set sizes, and soak thresholds
are not treated as pairwise feature dimensions.  The standards requirements
ledger is a separate VM-free case, which prevents an advertised or mandatory
VirtIO requirement from silently lacking implementation and positive-test
evidence.  Together these checks cover declared supported behavior; they do
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
once with the default legacy command-line behavior, and validates vsock and
RNG attachment plus the full bidirectional vsock matrix:

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

The default topology order is
`net vsock-userspace vsock-kernel rng block scsi console 9p input combined`.
Net, both vsock backends, RNG, block, SCSI, console, and 9P run both `modern`
and `legacy`; input's real-VM data path runs only with its modern interface
because VirtIO 1.4 assigns no transitional PCI identity to the input device,
and upstream Alpine has no driver for bhyve's historical hybrid interface.
Every topology retains and verifies the network interface used to provision
the guest.  SCSI uses a uniquely sized, fully backed CTL ramdisk which is
removed on exit.  The legacy combined run contains net, vsock, RNG, block,
SCSI, console, and 9P and reports the input omission.  A development run can
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
same-process longevity gate.  After the initial full matrix, it repeats that
matrix `N` times and checks bhyve descriptor/RSS growth after every iteration.
The kernel backend additionally requires `kern.vsock.cur_connections` to
return to its post-warmup baseline.  This is the acceptance gate for slow
descriptor, connection, and heap leaks; it complements rather than replaces
the sanitizer and deterministic race harnesses.

`VIRTIO_RESET_SOAK_ITERATIONS=N` repeatedly unbinds and rebinds every selected
VirtIO PCI function, reruns the real network and selected device data checks,
and bounds bhyve descriptor and RSS growth after every cycle.  Block and SCSI
checks verify the original data after each reset; console, 9P, RNG, and vsock
perform fresh transfers.  The one-shot input provider is excluded from this
gate.  For example:

```sh
ISO=/path/to/alpine-virt.iso VM_FREE_GATES=no \
TOPOLOGIES='net vsock-userspace vsock-kernel rng block scsi console 9p' \
TRANSPORTS=modern \
VIRTIO_RESET_SOAK_ITERATIONS=100 ./run-alpine-matrix.sh
```

`VM_FREE_GATES=no` skips the first two gates for a repeated VM-only debugging
run; it is not an acceptance result by itself.  Gate 1 requires the bhyve
source tree named by `SRCTOP` (default `/usr/src`).  The VM runners and host
controls otherwise work from either a source/object build or an installed test
package, using helper binaries installed beside the scripts when no Makefile is
present.

The `checkpoint` profile currently covers modern net, RNG, block, and idle
userspace-vsock devices.  Those are the devices with complete bhyve
pause/snapshot/resume callbacks.  SCSI, console, 9P, and input remain ordinary
boot/reset data-path coverage and must not be reported as checkpoint-tested
until their device-specific external and in-flight state can be quiesced,
serialized, and restored.  The manifest's `checkpoint-devices` contract makes
this boundary machine-checkable.

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
