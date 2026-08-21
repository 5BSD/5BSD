# Alpine Linux modern Virtio smoke test

The sound-device launch contract is explicit.  `SOUND_BACKEND` defaults to
the deterministic `null` backend.  Host-audio runs may select `oss`;
`SOUND_PLAY` and `SOUND_RECORD` then select nonblocking OSS endpoints and
default to `/dev/dsp`.  `virtio-lab --profile audio` runs split and packed
Linux activation against those real endpoints and serializes the cases with
the `audio` resource.  Every backend must return the exact requested capture
length; only the deterministic null backend is required to return zero-filled
capture.  The portable release matrix continues to use `null` because it must
run on hosts without audio hardware.  Resume metadata includes the backend
and endpoint identities, and restore rejects different audio side effects.

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
The `input-modern` release case sets `INPUT_DEVICES=2`: it creates two
different uinput providers and two modern PCI functions, resolves each guest
event node by its unique name, and performs the complete event and LED-status
exchange independently.  The runner rejects any accidental provider-path
alias before boot.  Other cases default to one device; `INPUT_DEVICES=1|2`
is an explicit lab override.

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

`DEVICES=fs` starts the capability-confined in-tree `virtiofsd`, attaches the
modern-only PCI device `1af4:105a`, and mounts a disposable export read-only
with Linux's upstream `virtiofs` driver.  The live check reads a host seed,
reads a symbolic link without following it during backend lookup, rejects a
guest write, and verifies the mount flags.  `FS_QUEUES=1..64` selects request
queues; the release profile exercises 1, 2, and 8.  `FS_PACKED=yes` adds a
packed-ring reset/rebind/remount case.  `FS_IDENTITY` opts into the daemon's
bounded state-transfer contract.  It preserves only an idle initialized FUSE
session and fails quiesce while any non-root node or open handle remains.
Split and packed checkpoint-policy cases keep an actual guest file descriptor
open, require fail-closed checkpoint rejection, and prove that the same daemon
and mount remain usable after rollback.  Identity-bound checkpoint cases then
unmount, checkpoint/restore the empty session, and remount the export.  The
optional-device reset
soak includes eight packed request queues, repeats rebind/remount validation,
and bounds both bhyve and virtiofsd descriptor and resident-memory growth.

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

`DEVICES=gpu` exercises the modern virtio-gpu 2D scanout with Linux's upstream
DRM driver.  `GPU_WIDTH` and `GPU_HEIGHT` select the monitor dimensions and
`GPU_BLOB=yes` opts into provisional guest-memory RESOURCE_BLOB and
BLOB_ALIGNMENT support.  It does not advertise a host-visible shared-memory
region: the 2D-only device accepts Linux's GUEST/SHAREABLE dumb buffers, while
MAP_BLOB and host-only blob memory types require renderer support and remain
unavailable.  The blob case requires Linux to negotiate both features and then
performs the same boundary framebuffer writes and readback, so feature
advertisement without a working guest resource does not pass.  The default is
`GPU_BLOB=no`, and that lane rejects accidental blob advertisement.
`GPU_WIDTH` and `GPU_HEIGHT` default to 1024 by 768.  The verifier requires the
exact connected mode and
checks that the EDID detailed timing reports those same dimensions.  It then
resolves the framebuffer owned by that exact VirtIO function, validates its
32-bit geometry and stride, and writes and reads deterministic pixels in the
first and last scanout rows.  This forces the stock DRM/fbdev path to create
backing, select the scanout, transfer pixels, and flush damage rather than
passing on enumeration alone.  The release matrix additionally boots
packed-ring 1920 by 1080 devices both with ordinary 2D resources and with the
blob contract, while the optional-device soak retains blobs across repeated
packed queue resets.  The checkpoint matrix saves and restores both the
non-default monitor identity and an active blob scanout.  A restore into a
device configured with different dimensions is rejected rather than silently
changing the guest-visible monitor.

The production presentation path is opt-in with `display=true`.  A VNC
consumer is configured separately as
`fbuf,source=external,vga=off,w=$GPU_WIDTH,h=$GPU_HEIGHT`; it owns no renderer
and therefore cannot overwrite the Virtio GPU producer.  The host-side
qualification copies scanout pixels and the 64 by 64 alpha cursor atomically,
checks hotspot clipping at display edges, and verifies that a second producer
is rejected.  The `gpu-display-modern` lane additionally connects a minimal
RFB 3.8 client to the Unix socket, requests raw pixels, and requires fixed
guest-written markers at the first pixel of both the first and last scanline.
That assertion spans guest fbdev damage, VirtIO transfer and flush, the bhyve
display adapter, external framebuffer ownership, scanout stride, byte order,
and final VNC presentation.  The ordinary Linux matrix remains headless so its framebuffer
assertions continue to prove guest resource/transfer/flush behavior without
depending on VNC timing.

`VIRTIO_IOMMU=yes` adds the modern VirtIO-IOMMU function and requires every
eligible endpoint selected by `DEVICES` to negotiate `ACCESS_PLATFORM`, appear
in an IOMMU group, and complete its ordinary workload through translated DMA.
The `iommu-combined-packed-modern` release case puts net, vsock, RNG, RTC,
block, SCSI, console, 9P, input, GPU blob, memory, and sound behind one packed
IOMMU fabric, exercises every device, and then selectively resets the
functions.  This complements the smaller split and packed net/block cases:
the combined case is the release gate for device-private DMA paths that a
descriptor-only test would miss.  The checkpoint profile repeats this topology
with active net, RNG, block, SCSI, input, and sound work, checkpoints it,
restores it, and reruns every device lifecycle smoke against the restored
translated mappings.  Balloon is intentionally absent because its
PFN-reporting ABI is not a guest DMA transaction.

`DEVICES=balloon` requires Linux to reach the exact configured target and
checks the guest-maintained `actual` value without assuming that its update is
synchronous with every completed PFN batch.  Release cases cover 1 MiB and
64 MiB targets, split and packed rings, `BALLOON_STATS_INTERVAL=0|1`,
`BALLOON_DEFLATE_ON_OOM=no|yes`, and
`BALLOON_FREE_PAGE_REPORTING=no|yes`, and
`BALLOON_PAGE_POISON=no|yes`.  The page-poison lane also verifies the
16-byte VirtIO 1.4 configuration layout.  When reporting and poisoning are
combined, the host must acknowledge reports without discarding their backing,
which preserves the negotiated poison pattern.  These are public
`virtio-lab --set` options, so adding another advertised balloon feature
requires a release coverage contract rather than an untracked one-off
environment setting.

`DEVICES=rtc` verifies the clock class exported by Linux's upstream driver and
has independent split/packed alarm cases.  `RTC_ALARM=no|yes` is likewise a
governed lab option: enabled cases program and observe the alarm queue, reset
the function, and prove alarm operation again rather than checking only the
negotiated bit.

`DEVICES=mem` requires Linux to plug and online the requested memory, validates
the complete device configuration, and touches an anonymous-memory workload.
The release profile covers split and packed rings, a 128 MiB full-capacity
region, a 256 MiB half-capacity region, and a 256 MiB full-capacity request.
`MEM_REGION_MB` and `MEM_REQUESTED_MB` are public governed options; their
geometry must remain compatible with both the device block size and Linux
memory block size.

`DEVICES=pmem` attaches the modern-only VirtIO PMEM device at PCI identity
`1af4:105b`.  The runner loads Linux's unmodified `libnvdimm`, `nd_pmem`, and
`virtio_pmem` modules, requires exactly one device bound to `virtio_pmem`, and
resolves exactly one descendant `/dev/pmem*` block device.  The guest verifier
independently checks required feature bit zero, the modern ring features, and
the requested split or packed format.  It writes a deterministic 4096-byte
marker at offset 2 MiB with `O_SYNC`, issues `fsync`, reads the marker back,
and reports its digest.  The host then reads that exact range from the sparse
backing file and requires the same digest, so enumeration or a guest-page-cache
hit cannot satisfy the test.

`PMEM_IMAGE_MB` selects the disposable backing capacity and must be at least
4 MiB.  `PMEM_IDENTITY` is the stable external-backend identity recorded in
portable checkpoint state; restore requires both it and the capacity to match.
`PMEM_PACKED=yes` selects the packed ring and is valid only with the modern
transport.  The release profile has dedicated split and packed cases, reset
and rebind rerun the complete persistence proof, and the checkpoint profile
has split and packed restore cases that write a new generation marker after
restore.  During both the online checkpoint and the suspend/restore phase,
the same guest PID continuously writes, fsyncs, and reads a second PMEM marker;
its durable counter must advance after each boundary.  Stock 5BSD currently
has no VirtIO PMEM guest driver, so that live
activation remains an explicit driver gap rather than a skipped success.

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
`VIRTIO_NET_F_CTRL_VQ`, `VIRTIO_NET_F_MQ`,
`VIRTIO_NET_F_HASH_REPORT`, and `VIRTIO_NET_F_RSS`, checks the exact Linux RX
and TX queue counts under `/sys/class/net/eth0/queues`, and repeats those
checks after driver unbind/rebind and monitor-mode reboot when lifecycle
testing is enabled.  Linux selects RSS mode with its standard 128-entry
indirection table and 40-byte Toeplitz key during device setup and consumes
the 20-byte receive header used for hash reports.
The verifier also uses `ethtool` to replace the live indirection table and
read back the resulting Toeplitz configuration, exercising the RSS control
command rather than checking only its negotiated feature bit.
Set `NET_QUEUES=1..8` to select another advertised queue-pair count.  The
runner supplies at least that many vCPUs so Linux can activate every pair.
Legacy runs deliberately retain one pair.

Set `CHECKPOINT_TEST=yes` to add two live checkpoint gates for the selected
transport.  The runner first creates a checkpoint while the guest continues
running and verifies that the guest and network remain usable.  Every
checkpoint case keeps one guest UDP workload alive across the boundary.  RNG,
block, and SCSI cases additionally keep the same guest process continuously
reading the selected raw VirtIO device; a durable progress counter must
advance after both the online checkpoint and the later restore.  The storage
workloads are read-only so this proof does not change the independent
persistence digest.  The runner then
replaces that checkpoint with `bhyvectl --suspend`, verifies the generation
manifest and all three referenced members, restores the VM with the same
device configuration, and confirms guest-RAM state plus networking survived.
The exact same workload PID and its progress counter must survive that
restore.  Entropy bytes are deliberately never serialized or compared:
virtio-rng saves common queue state only, and the restored workload must
obtain fresh bytes from the host source.  Devices with external sessions must
either prove an explicit reconstruction contract or reject an active
checkpoint while leaving the source VM usable; common queue serialization
alone is not acceptance evidence.  `BHYVECTL` may name an object-tree binary
when the installed utility does not yet match the object-tree bhyve.
The input checkpoint cases use a stricter staged-frame proof.  The host
injects `KEY_A` down without `SYN_REPORT`, waits until bhyve records that
partial frame, checkpoints it, and injects the remaining events only after
the online checkpoint or restored VM is running.  The same guest verifier PID
must receive the exact completed frame and return its LED status.  Both split
and packed input queues have dedicated scheduled cases.
The vsock checkpoint cases likewise test the non-portable active-connection
policy for both userspace and kernel backends, with split and packed queues.
They hold a live echo connection, require checkpoint admission to fail, prove
the same connection still carries data after rollback, drain it, and then run
the normal portable idle-backend checkpoint and restore.
The console checkpoint cases apply the same rule to host port sessions.  A
live split or packed console connection must reject portable checkpoint,
continue bidirectional traffic after rollback, and close cleanly before the
listener-only state is saved and restored.
The 9P checkpoint case sets `CHECKPOINT_ACTIVE_9P_REJECT=yes`: it first keeps
the export mounted with live fids, requires checkpoint admission to fail, and
then proves that the same source mount still reads and writes.  Only after
that rollback proof does it unmount and run the portable idle-session
checkpoint/restore path.
`checkpoint-fs-active-modern` and
`checkpoint-fs-active-packed-modern` supply a stable backend identity, keep
the Linux mount and an actual guest file descriptor active, complete both a
live checkpoint and a suspend/restore, and require reads through that same
descriptor and the restored mount to succeed.  Each active lane then restores
the same immutable image again and repeats those descriptor and mount checks.
The split and packed lanes
therefore qualify active node and handle reconstruction rather than an idle
substitute.  `checkpoint-fs-idle-modern` and
`checkpoint-fs-idle-packed-modern` remain separate compact-state compatibility
lanes which unmount to trigger `FUSE_DESTROY` before checkpoint.
This exercises bhyve checkpoint pause while the guest devices are running.
Both the host kernel and bhyve/bhyvectl must be built with
snapshot support (the amd64 default); the runner checks both sides before
booting the guest.  The `VBSD` kernel configuration also enables
`BHYVE_SNAPSHOT` explicitly.
The separate nested case in which a guest has already set the VirtIO
`DEVICE_SUSPEND` status bit is covered by the device state-machine harness;
stock Alpine/Linux does not currently expose a userspace control that can
reliably hold that state while an external checkpoint is requested.  A live
FreeBSD guest-driver gate is still required before release.

The focused modern two-queue release gate is:

```sh
env ISO=/path/to/alpine-virt.iso DEVICES=net TRANSPORTS=modern \
    NET_QUEUES=2 CHECKPOINT_TEST=yes VM_FREE_GATES=no \
    WORKDIR=/tmp/bhyve-net-checkpoint ./run-alpine-auto.sh
```

The modern console release case sets `CONSOLE_MULTIPORT=yes`.  It configures
two independently named host sockets on one VirtIO-console device, requires
Linux to discover both port names, and performs a separate bidirectional token
exchange through each port.  This is the activation proof for additional-port
queues; discovering a single port is not treated as MULTIPORT coverage.

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
each guest a disjoint AF_VSOCK port range and uses three two-guest barriers:
before the initial VSOCK data matrix, immediately before reset/rebind, and
after post-reset verification.  A guest cannot leave any barrier until both
providers have reached that stage.  The first barrier guarantees that both
providers are attached before either data matrix begins; the later barriers
prove that each remains usable while the other is active across reset/rebind,
rather than merely overlapping the two bhyve process lifetimes:

```sh
ISO=/path/to/alpine-virt.iso ./run-alpine-multi-vsock.sh
```

`CID1`, `CID2`, `PORT_OFFSET1`, `PORT_OFFSET2`, `CONSOLE_PORT1`, and
`CONSOLE_PORT2` can be overridden. The two port offsets must differ by at
least 300 so parallel and lifecycle endpoints cannot overlap.

Set `VM_FREE_GATES=no` only when repeating VM boots after those exact source
and helper binaries have already passed in the same worktree.

For a long-lived backend gate, set `VSOCK_SOAK_ITERATIONS` on either focused
topology.  The runner first performs the complete bidirectional Linux matrix,
including refusal recovery, graceful and abrupt close, large records, and bulk
data.  It then reuses the same bhyve process for a hot matrix on each
iteration: concurrent, uniquely tagged STREAM and SEQPACKET echo/close
lifecycles in both directions.  The parallel cases require every client,
listener, and tagged echo to complete; they exercise connection-table,
virtqueue, provider-queue, credit-wakeup, and teardown contention rather than
merely increasing a byte counter.  The runner performs the complete matrix
again after the hot loop.  Every tenth iteration (configurable with
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

For routine qualification, `virtio-lab.lua --profile soak-smoke` runs the
same structured hot-churn and reset code paths with three iterations per
lane, verifies the functional data paths after every rebind, and includes the
host-regression gate.  It is deliberately separate from the 100-iteration
`soak` profile: report it as a bounded screen, not as endurance evidence.

```sh
su root -c '/usr/libexec/flua \
    /usr/tests/sys/kern/vsock_e2e/virtio-lab.lua \
    run --profile soak-smoke --jobs 3 \
    --iso /path/to/alpine-virt.iso --workdir /tmp/virtio-soak-smoke'
```
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

## Non-VirtIO qualification

`run-alpine-auto.sh` also accepts one reviewed `NONVIRTIO_DEVICE` value.  The
lab's `nonvirtio-alpine-*-live` cases verify the exact PCI/ACPI identity and a
distinguishing guest operation.  The matching `*-checkpoint` cases keep that
operation active through a nonterminal checkpoint and suspend/restore.  TPM
CRB and passthrough deliberately assert a rollback-safe rejection because
those models do not implement portable snapshot state.

Use the declarative entry point rather than constructing cases by hand:

```sh
PROFILE=nonvirtio PLAN_ONLY=yes UPLINK=igb0 \
    ISO=/path/to/alpine-virt.iso FIVEBSD_IMAGE=/path/to/5bsd.raw \
    NONVIRTIO_TPM_PATH=/path/to/swtpm.sock \
    NONVIRTIO_PASSTHRU=ppt0 \
    NONVIRTIO_PASSTHRU_LINUX_ASSERT='/root/test-selected-ppt-device' \
    NONVIRTIO_PASSTHRU_FIVEBSD_ASSERT='/root/test-selected-ppt-device' \
    ./run-waspnest-qualification.sh
```

Framebuffer cases write fixed pixels through the PCI framebuffer BAR and
verify the result with an independent RFB client.  UART cases use a separate
COM2 or PCI-UART backend log, so control-console traffic cannot satisfy them.
