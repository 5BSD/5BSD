# Alpine Linux modern Virtio smoke test

The harness uses Alpine's unmodified upstream `virtio_vsock` guest driver.
The modern run verifies PCI device `1af4:1053`; the legacy control run verifies
`1af4:1013`.  The data matrix then tests STREAM and SEQPACKET in both
directions, including a 200 KiB record and bulk transfer.  Each live vsock
preflight also connects from the guest to reserved CID 0 and to an unused port
on host CID 2, requiring ETIMEDOUT and ECONNRESET respectively.  The full data
matrix explicitly half-closes remote SEQPACKET connections in each direction
and requires the payload and EOF to reach both endpoints.  It also SIGKILLs an
echo-proven host connector, requires the guest to observe EOF or reset, and
then verifies an immediate fresh connection.

Every VM also verifies its provisioning interface is uniquely backed by
Alpine's upstream `virtio_net` driver.  Modern runs require PCI device
`1af4:1041`; legacy runs require `1af4:1000` while deliberately omitting the
transport option.  DHCP package installation and a three-packet gateway ping
prove the transmit, receive, and interrupt paths rather than enumeration
alone.  `DEVICES=net` provides a focused topology for this check.

The automated runner also loads Alpine's upstream `virtio_input` driver and
connects bhyve to a disposable composite host `uinput` device.  Using its
specification-mandated modern transport, it checks the PCI capability layout,
injects exact keyboard, relative-pointer, and absolute-axis events, and
requires the guest to return a Caps Lock LED event through the status queue.
This covers host uinput -> bhyve -> virtio event queue -> Linux evdev and the
reverse guest evdev -> virtio status queue -> host uinput path without physical
input hardware.

`DEVICES=scsi` creates a uniquely sized, fully backed disposable CTL ramdisk
and attaches it through bhyve's virtio-scsi controller.  Supplying CTL's
`capacity` option is essential because its default zero-capacity ramdisk is a
fake target that discards writes.  The guest verifier requires the
upstream `virtio_scsi` driver and PCI device `1af4:1048` for modern or
`1af4:1004` for option-omitted legacy, finds only the LUN with that exact
capacity, and verifies a deterministic write/read checksum.  Modern runs
default to `SCSI_QUEUES=2`; the verifier counts the Linux hardware queues
under `/sys/class/block/*/mq` and requires the exact configured count.
Set `SCSI_QUEUES=1..8` to select another count.  The runner supplies at least
that many vCPUs so Linux does not legitimately reduce the hardware-queue
count, then pins concurrent writers to distinct guest CPUs and writes
disjoint ranges before checking the whole payload.  Legacy runs retain one
request queue.  The runner removes only the CTL LUN it created, including on
test failure.

`DEVICES=console` attaches a named virtio-console port backed by a host UNIX
stream socket.  The guest verifier requires PCI device `1af4:1043` for modern
or `1af4:1003` for option-omitted legacy, confirms the upstream
`virtio_console` binding and named port, and exchanges distinct payloads in
both directions with the host.

`DEVICES=9p` exports a disposable host directory under a unique mount tag.
The guest verifier requires the upstream `9pnet_virtio` driver and PCI device
`1af4:1049` for modern or `1af4:1009` for option-omitted legacy.  It mounts the
share with 9P2000.L and verifies distinct host-to-guest and guest-to-host file
payloads.  Modern runs require `VIRTIO_F_RING_RESET`; reset/rebind verifies
full-device recovery and remounting.  Linux's 9P driver does not currently
issue selective queue reset, so the sanitizer-backed source harness separately
proves that an in-flight selective reset drains old guest buffers without
discarding the lib9p connection or fid namespace.

The fully automated path needs only an Alpine `virt` ISO and a bhyve binary.
The runner prefers the matching object-tree binary, using `SRCTOP` and
`OBJROOT`, then falls back to `bhyve` in `PATH`.  It similarly discovers the
usual `uefi-firmware` and `edk2-bhyve` firmware locations.  It boots and
provisions a disposable RAM-only guest, then runs
the requested transport tests.  Use the matrix runner below for the complete
modern and applicable legacy coverage:

```sh
cd /path/to/vsock_e2e
su root -c 'ISO=/path/to/alpine-virt.iso ./run-alpine-auto.sh'
```

The standard assigns virtio-input no transitional PCI identity.  bhyve retains
its older hybrid interface for compatibility, but Alpine's upstream driver
cannot bind it, so this rig exercises input with `transport=modern`.  A direct
legacy Alpine run must omit `input` from `DEVICES`; the matrix does this
automatically and reports the omission.  The runner creates and
removes its own tap interface, chooses an unused TCP console port, and confines
VM destruction to its unique per-run names.  Logs are retained
under `/tmp/bhyve-vsock-alpine` by default.

Set `DEVICES=net`, `DEVICES=vsock`, `DEVICES=rng`, `DEVICES=input`,
`DEVICES=scsi`, `DEVICES=console`, or `DEVICES=9p` to run a device in isolation;
`DEVICES=block` uses a disposable sparse image and verifies a deterministic
write/read checksum.  A provisioning virtio-net interface remains present in
every topology and is always verified.  The default,
`DEVICES='vsock rng input'`, attaches those three devices beside the network
interface and runs every suite to detect cross-device regressions.

## No-MSI-X interrupt and lifecycle regression

`run-alpine-no-msix.sh` packages the focused regression that previously
required separate launch and console scripts.  It uses the common automated
runner and console framing, adds bhyve `-W`, and defaults to Alpine's legacy
virtio-net, vsock, block, and RNG drivers.  The test requires at most one
allocated interrupt vector per device, then exercises real traffic, driver
unbind/rebind resets, a monitor-mode guest reboot, and post-reboot block-data
persistence.  Before reboot it establishes live STREAM and SEQPACKET echo
connections; both old endpoints must disconnect within 30 seconds, and fresh
connections must pass after the guest returns:

```sh
su root -c 'ISO=/path/to/alpine-virt.iso ./run-alpine-no-msix.sh'
```

There are no machine-specific paths in the wrapper.  Override `BHYVE`, `UEFI`,
`SRCTOP`, `OBJROOT`, `WORKDIR`, `BRIDGE`, or `UPLINK` when automatic discovery
does not match the host.  `BLOCK_TEST_MB` and `BLOCK_IMAGE_MB` control the
written prefix and disposable image size.  `RESET_TEST=no` or `REBOOT_TEST=no`
can narrow a debugging run without changing the acceptance defaults.

Modern block runs default to `BLOCK_QUEUES=2`.  The verifier requires
`VIRTIO_BLK_F_MQ`, counts the Linux hardware queues under
`/sys/class/block/*/mq`, and exercises reset/rebind plus persistence with the
multiqueue device.  Set `BLOCK_QUEUES=1..8` to select another advertised queue
count; the runner supplies at least that many vCPUs so Linux does not
legitimately reduce its hardware-queue count.  Legacy runs deliberately retain
one queue.  The modern gate also requires `VIRTIO_BLK_F_CONFIG_WCE`, verifies
that reset retains the historical writeback default, toggles Linux's virtio-blk
`cache_type` attribute through both modes, and leaves the persistence workload
in writethrough mode.

Modern network runs default to `NET_QUEUES=2`.  The verifier requires
`VIRTIO_NET_F_CTRL_VQ`, `VIRTIO_NET_F_MQ`, and `VIRTIO_NET_F_RSS`, checks the
exact Linux RX and TX queue counts under `/sys/class/net/eth0/queues`, and
repeats those checks after driver unbind/rebind and monitor-mode reboot when
lifecycle testing is enabled.  Linux selects RSS mode with its standard
128-entry indirection table and 40-byte Toeplitz key during device setup.
The verifier also uses `ethtool` to replace the live indirection table and
read back the resulting Toeplitz configuration, exercising the RSS control
command rather than checking only its negotiated feature bit.
Set `NET_QUEUES=1..8` to select another advertised queue-pair count.  The
runner supplies at least that many vCPUs so Linux can activate every pair.
Legacy runs deliberately retain one pair.

For acceptance testing, use `run-alpine-matrix.sh`.  It first runs the
sanitizer-backed real-source device harnesses and VM-free host pipeline
controls.  It then runs net, vsock, RNG, block, SCSI, console, 9P, and input
alone, followed by all devices together, for every selected transport.  This
distinguishes device regressions from cross-device interactions:

```sh
ISO=/path/to/alpine-virt.iso ./run-alpine-matrix.sh
```

The matrix names the two host implementations `vsock-userspace` and
`vsock-kernel`.  The userspace topology selects bhyve's default
`backend=userspace` protocol engine and its Unix control/data socket protocol.
The kernel topology selects `backend=kernel` and uses ordinary host
`AF_VSOCK` sockets through `/dev/vsock`.  Both topologies run for modern and
legacy transport and execute the same bidirectional STREAM/SEQPACKET,
large-record, graceful-close, abrupt-close, reset, and monitor-mode reboot
checks. Kernel-backed VMs with distinct guest CIDs may run concurrently;
duplicate CIDs fail deterministically with `EADDRINUSE`. To repeat either
gate:

```sh
TOPOLOGIES=vsock-userspace ISO=/path/to/alpine-virt.iso ./run-alpine-matrix.sh
TOPOLOGIES=vsock-kernel ISO=/path/to/alpine-virt.iso ./run-alpine-matrix.sh
```

The fleet gate runs two complete kernel-backed guests concurrently. It gives
each guest a disjoint AF_VSOCK port range and exercises reset/rebind in both
VMs while the other provider remains active:

```sh
ISO=/path/to/alpine-virt.iso ./run-alpine-multi-vsock.sh
```

`CID1`, `CID2`, `PORT_OFFSET1`, `PORT_OFFSET2`, `CONSOLE_PORT1`, and
`CONSOLE_PORT2` can be overridden. The two port offsets must differ by at
least 300 so parallel and lifecycle endpoints cannot overlap.

Set `VM_FREE_GATES=no` only when repeating VM boots after those exact source
and helper binaries have already passed in the same worktree.

For a long-lived backend gate, set `VSOCK_SOAK_ITERATIONS` on either focused
topology.  Each iteration reuses the same bhyve process and reruns the complete
bidirectional Linux matrix, including repeated refused connections for both
socket types and directions, STREAM and SEQPACKET graceful close, abrupt
endpoint death, large records, bulk data, eight simultaneous distinct
connections for each socket type and direction, and an immediate success
probe after each error phase.  The parallel cases require every client,
listener, and uniquely tagged echo to complete; they exercise connection-table,
virtqueue, provider-queue, credit-wakeup, and teardown contention rather than
merely increasing a byte counter.  Every tenth iteration (configurable with
`VSOCK_SOAK_RESET_EVERY`, or disabled with zero) also unbinds and rebinds the
guest vsock PCI function and reruns the error-and-data smoke gate.  The runner
requires the host kernel connection gauge to return to its post-warmup baseline
for `backend=kernel`, requires the `vtvsock` kernel malloc allocation count and
bytes to return to baseline, and rejects any new kernel RX drops.  Both
backends fail if bhyve's descriptor count or resident memory grows beyond the
configured allowances:

```sh
TOPOLOGIES=vsock-userspace TRANSPORTS=modern \
VSOCK_SOAK_ITERATIONS=100 ISO=/path/to/alpine-virt.iso \
    ./run-alpine-matrix.sh

TOPOLOGIES=vsock-kernel TRANSPORTS=modern \
VSOCK_SOAK_ITERATIONS=100 ISO=/path/to/alpine-virt.iso \
    ./run-alpine-matrix.sh
```

The default allowances are zero additional bhyve descriptors and 16 MiB of
resident memory after the first complete matrix has warmed the process.  The
final summary records elapsed time, descriptor and RSS baselines/deltas/peaks,
kernel-connection state, kernel allocations, and RX drops.
Override `VSOCK_SOAK_MAX_FD_GROWTH` or `VSOCK_SOAK_MAX_RSS_KB` only when the
reason is understood and recorded.  A zero iteration count, the default,
keeps the normal acceptance matrix bounded.
`VSOCK_DEBUG=2` enables per-packet vsock metadata when diagnosing a failure;
generic `VIRTIO_DEBUG` remains off by default so a soak run does not generate
unbounded queue-notification logs.

See `FRAMEWORK.md` for the VM-free gates, failure-reporting contract, and the
required checklist when another VirtIO device is added.

For manual debugging, start with either an installed **raw** Alpine disk or an
Alpine `virt` ISO.  From the host:

```sh
cd /path/to/vsock_e2e
make
IMAGE=/path/to/alpine.raw TRANSPORT=modern ./run-alpine-bhyve.sh
# Or the RAM-only serial-console rig already used for vsock testing:
ISO=/path/to/alpine-virt.iso \
CONSOLE=tcp=127.0.0.1:4322 \
TRANSPORT=modern ./run-alpine-bhyve.sh
```

In another terminal, prepare the guest and install the test helper:

```sh
export ALPINE_HOST=192.0.2.10
scp alpine-guest-setup.sh gvsock.py root@$ALPINE_HOST:/tmp/
ssh root@$ALPINE_HOST sh /tmp/alpine-guest-setup.sh
```

Run the host/guest matrix:

```sh
DIR=$HOME/vm/vsock-sockdir-alpine \
TRANSPORT=modern \
GUEST_CID=4 \
ACMD="sh $PWD/acmd-ssh.sh" \
GPY=/tmp/gvsock.py \
./run-linux.sh
```

Repeat with `TRANSPORT=legacy` in both commands to prove the unchanged legacy
path.  Omitting `transport` from the bhyve device option is equivalent to the
legacy run; `run-alpine-bhyve.sh` always spells it out so the selected test is
unambiguous.
