# Alpine Linux modern Virtio smoke test

The harness uses Alpine's unmodified upstream `virtio_vsock` guest driver.
The modern run verifies PCI device `1af4:1053`; the legacy control run verifies
`1af4:1013`.  The data matrix then tests STREAM and SEQPACKET in both
directions, including a 200 KiB record and bulk transfer.

The automated runner also loads Alpine's upstream `virtio_input` driver and
connects bhyve to a disposable composite host `uinput` device.  Using its
specification-mandated modern transport, it checks the PCI capability layout,
injects exact keyboard, relative-pointer, and absolute-axis events, and
requires the guest to return a Caps Lock LED event through the status queue.
This covers host uinput -> bhyve -> virtio event queue -> Linux evdev and the
reverse guest evdev -> virtio status queue -> host uinput path without physical
input hardware.

The fully automated path needs only an Alpine `virt` ISO and the object-tree
bhyve binary. It boots and provisions a disposable RAM-only guest, then runs
the requested transport tests.  Use the matrix runner below for the complete
modern and applicable legacy coverage:

```sh
cd /usr/src/tests/sys/kern/vsock_e2e
su root -c 'ISO=/home/me/alpine-virt.iso ./run-alpine-auto.sh'
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
isolation.  The default, `DEVICES='vsock rng input'`, attaches all three
devices and runs every suite to detect cross-device regressions.

For acceptance testing, use `run-alpine-matrix.sh`.  It first runs the
sanitizer-backed real-source device harnesses and VM-free host pipeline
controls.  It then runs vsock, RNG, and input alone, followed by all devices
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
cd /usr/src/tests/sys/kern/vsock_e2e
make
IMAGE=$HOME/vm/alpine.raw TRANSPORT=modern ./run-alpine-bhyve.sh
# Or the RAM-only serial-console rig already used for vsock testing:
ISO=$HOME/vm/alpine-virt-3.24.1-x86_64.iso \
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
