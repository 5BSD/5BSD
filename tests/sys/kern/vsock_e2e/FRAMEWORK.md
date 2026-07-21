# bhyve VirtIO test framework

This directory is the real-VM half of a layered VirtIO acceptance suite.  A
change is not accepted merely because a guest enumerates a PCI function: each
device must prove its untrusted descriptor handling without a VM, its isolated
guest data path, its compatibility transport, and its behavior beside every
other covered device.

## Required gates

Run the gates in this order.  Early failures are cheaper and more specific.

1. **Device and transport harnesses (VM-free).** Run
   `../vsock_device_harness/run.sh` and `../vsock_rx_harness/run.sh`.  These
   tests include the real bhyve device sources, guest `uipc_vsock.c` RX state
   machine, and guest `virtio_vsock.c` transport.  They exercise malformed
   descriptors, invalid queue directions, short buffers, queue ownership and
   exhaustion, reset/failure cleanup, interrupt suppression, feature
   negotiation, credit handling, lifecycle wakeups, and boundary sizes under
   ASan and UBSan.
2. **Host helper controls (VM-free).** Run `host-tools-selftest.sh` with
   `TOOLS` set to the Makefile's `.OBJDIR`.  It validates stream and SEQPACKET
   relays, an intentionally fragmented SCM_RIGHTS control reply, a 1 MiB
   stream, a single 200 KiB record, and the serial-console payload chunking
   used to provision guests.  It also attacks input-provider path, command,
   and status-event parsing without opening `/dev/uinput`.
3. **Guest verifier self-tests.** Each guest helper must have a
   `--self-test` mode for parsing and negative cases that do not require its
   device.  `run-alpine-auto.sh` executes it after a checksum-verified upload.
4. **Isolated real-VM test.** `DEVICES=<name>` must attach only that device.
   The verifier must uniquely match the expected PCI function, prove it is
   bound to the intended upstream driver, and exercise actual data in every
   supported direction.
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

The default topology order is `vsock rng block input combined`.  Vsock, RNG,
and block run both `modern` and `legacy`; input's real-VM data path runs only
with its modern interface because upstream Alpine has no driver for bhyve's
historical hybrid interface.  The legacy combined run contains vsock, RNG,
and block and reports that input omission.  A development run can narrow
either axis, for example:

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

`VM_FREE_GATES=no` skips the first two gates for a repeated VM-only debugging
run; it is not an acceptance result by itself.  Gate 1 requires the bhyve
source tree named by `SRCTOP` (default `/usr/src`).  The VM runners and host
controls otherwise work from either a source/object build or an installed test
package, using helper binaries installed beside the scripts when no Makefile is
present.

## Adding a device

A new device is complete only when all of the following are present:

- a device-harness target that includes the real backend and attacks descriptor
  counts, directions, lengths, addresses, queue exhaustion, reset, and host-I/O
  errors;
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
