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

The automated runner also loads Alpine's upstream `virtio_input` driver and
connects bhyve to a disposable composite host `uinput` device.  Using its
specification-mandated modern transport, it checks the PCI capability layout,
injects exact keyboard, relative-pointer, and absolute-axis events, and
requires the guest to return a Caps Lock LED event through the status queue.
This covers host uinput -> bhyve -> virtio event queue -> Linux evdev and the
reverse guest evdev -> virtio status queue -> host uinput path without physical
input hardware.

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

Set `DEVICES=vsock`, `DEVICES=rng`, or `DEVICES=input` to run a device in
isolation; `DEVICES=block` uses a disposable sparse image and verifies a
deterministic write/read checksum.  The default,
`DEVICES='vsock rng input'`, attaches those three devices and runs every suite
to detect cross-device regressions.

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

For acceptance testing, use `run-alpine-matrix.sh`.  It first runs the
sanitizer-backed real-source device harnesses and VM-free host pipeline
controls.  It then runs vsock, RNG, block, and input alone, followed by all devices
together, for every selected transport.  This distinguishes device regressions
from cross-device interactions:

```sh
ISO=/path/to/alpine-virt.iso ./run-alpine-matrix.sh
```

Set `VM_FREE_GATES=no` only when repeating VM boots after those exact source
and helper binaries have already passed in the same worktree.

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
ACMD="sh $PWD/acmd-ssh.sh" \
GPY=/tmp/gvsock.py \
./run-linux.sh
```

Repeat with `TRANSPORT=legacy` in both commands to prove the unchanged legacy
path.  Omitting `transport` from the bhyve device option is equivalent to the
legacy run; `run-alpine-bhyve.sh` always spells it out so the selected test is
unambiguous.
