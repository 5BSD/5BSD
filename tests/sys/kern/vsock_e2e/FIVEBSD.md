# 5BSD modern VirtIO validation

`run-5bsd-auto.sh` boots the existing 5BSD raw image twice.  The modern run
opts the root virtio-blk device, vsock, and RNG into the non-transitional PCI
transport.  The legacy run omits the `transport` option entirely, proving that
existing bhyve command lines retain their old PCI identities and behavior.

Run it as root from the source tree:

```sh
cd /path/to/vsock_e2e
env IMAGE=/path/to/guest-base.img \
    WORKDIR=/tmp/bhyve-vsock-5bsd \
    TRANSPORTS="modern legacy" \
    BULK_MB=256 \
    sh ./run-5bsd-auto.sh
```

The image must provide a root serial-console login and `/root/vsock-pipe`,
`/root/vsock-conntest`, and `/root/vsock-recrx`.  The runner verifies the
expected block, vsock, and RNG PCI IDs, driver attachment, root-disk I/O, RNG
reads, and the configured guest CID before starting the complete bidirectional
vsock matrix.
For each transport it creates a sparse private copy, repairs that copy with a
forced UFS check, and requests a clean guest shutdown.  The base image is never
attached writable.  The runner refuses to start if another bhyve process is
using the base, since a concurrently changing source cannot be copied safely.

Set `TRANSPORTS=modern` for a shorter development pass or reduce `BULK_MB` for
a smoke test.  Logs are retained below `WORKDIR`; unique VM names and socket
directories are used for each run.

Set `FIVEBSD_BLOCK_PACKED=yes`, `FIVEBSD_RNG_PACKED=yes`, or
`FIVEBSD_VSOCK_PACKED=yes` to require the corresponding device to negotiate a
packed queue.  These options automatically enable transport debug evidence;
the run fails unless the guest operation reaches an enabled packed queue and
the host observes a notification.  The release profile schedules all three
together as `fivebsd-packed-core`.

Set `FIVEBSD_NOTIFICATION_DATA=yes` to require the guest-visible transport
sysctl to report both `NotificationData` and `NotifConfigData`, followed by
an actual 32-bit modern PCI doorbell carrying both the selected block queue
and a nonzero available index during root-disk I/O.  This proves negotiation
of bits 38 and 39 independently of the host trace.

Set `FIVEBSD_BLOCK_DISCARD=yes` to attach a separate disposable 64 MiB
virtio-blk disk and exercise FreeBSD `BIO_DELETE` through the stock `trim`
utility.  The test writes a patterned target range with independent guard
sectors, verifies the pre-trim bytes, trims only that range, requires sparse
file zero readback, rechecks both guards, and correlates the operation with a
host VirtIO block request of type 11.  The root disk is never trimmed.

Set `FIVEBSD_BLOCK_WRITE_ZEROES=yes` to use the same disposable disk but
explicitly select `dev.vtblk.N.write_zeroes_delete=1` before issuing `trim`.
The driver must negotiate `WriteZeros`, accept the per-device policy change,
write the target range as zeroes without the WRITE_ZEROES `UNMAP` flag, retain
both guard sectors, restore the default DISCARD policy, and produce a host
VirtIO block request of type 13.  It is intentionally separate from the
DISCARD lane: `BIO_DELETE` remains DISCARD by default for compatibility.

Set `FIVEBSD_BLOCK_READONLY=yes` to attach a separate patterned 8 MiB
read-only disk.  The stock driver must negotiate `ReadOnly`, read the exact
host-side digest, reject a write, and preserve the digest after that rejected
operation.  The guest locates this disk by its unique media size rather than
assuming an enumeration unit, so it can run in the same release case as the
discard disk.

Set `FIVEBSD_BLOCK_WCE=yes` to require `ConfigWCE` on the root block device
and transition the stock driver's `writecache_mode` through writethrough and
writeback while completing synchronous filesystem writes in both modes.  The
original mode is restored even if the guest command is interrupted, and the
host log must show both configuration writes.

Set `FIVEBSD_RNG_RESET_ITERATIONS=N` to copy the installed queue-reset helper
into the disposable guest and detach/reattach its entropy device `N` times
while a concurrent random reader runs.  The helper requires paired successful
`virtio:::queue-reset-begin` and `queue-reset-end` probes for queue zero on one
device object.  The release suite combines ten iterations with the
notification-data check in `fivebsd-modern-common-lifecycle`; longer reset
soaks remain available explicitly.

Set `FIVEBSD_CONSOLE_TEST=yes` to attach named modern virtio-console ports and
require a bidirectional token exchange between each host Unix socket and its
exact `/dev/vtcon/<name>` guest alias. `FIVEBSD_CONSOLE_PORTS` accepts one or
two; the two-port lane proves independent control-plane discovery and data
queues rather than accepting a single working port as multiport evidence.
Add `FIVEBSD_CONSOLE_PACKED=yes` to require those same data paths to use
enabled packed queues. The release suite uses one split port and two packed
ports so both the baseline and multiport boundaries are activated without an
extra guest boot.

Set `FIVEBSD_INPUT_TEST=yes` to attach a named modern virtio-input device,
load the rebuilt-FreeBSD `virtio_input` driver, and verify an exact key,
relative-axis, absolute-axis, and synchronization-event sequence through
evdev. The guest then writes an LED status event back to the host provider,
so both virtqueues are exercised. Set `FIVEBSD_INPUT_PACKED=yes` to require
`RingPacked` negotiation and independent packed-layout evidence for both the
event and status queues. Set `FIVEBSD_INPUT_DEVICES=2` to attach independent
host providers and prove that both named guest instances receive their own
event stream and return status independently. The release lanes cover one
split-ring device and two independent packed-ring devices, so both the
single-device baseline and device multiplicity are explicit. These lanes require a rebuilt guest
containing the driver; the runner installs only its static verifier into the
disposable per-attempt image and never modifies the base image.

Set `FIVEBSD_RTC_TEST=yes` to attach an alarm-capable modern virtio-RTC and
load the rebuilt-FreeBSD `virtio_rtc` driver.  The runner requires real
configuration, capability, clock-read, alarm-set, alarm-disable, and alarm
notification operations.  It arms an absolute deadline through
`dev.vtrtc.0.alarm_time_ns`, waits for the validated
`dev.vtrtc.0.alarm_count` to advance, requires the driver's asynchronous
post-notification clock read to reach the deadline, and correlates both
request and alarm queues with the host trace.  Add
`FIVEBSD_RTC_PACKED=yes` to require
`RingPacked` and packed layout evidence for both queues.  The two release
lanes remain pending until run with a rebuilt guest containing the module.

Set `FIVEBSD_NINEP_TEST=yes` to attach a private host export to a modern
VirtIO-9P device, load the rebuilt-FreeBSD `p9fs` and `virtio_p9fs` modules,
and prove guest-to-host and host-to-guest file visibility across separate
mount lifetimes. The export and guest disk are per-attempt copies; the base
image is never modified. Add `FIVEBSD_NINEP_PACKED=yes` to require
`RingPacked` in the guest and correlated packed request-queue enable and
notification evidence in bhyve. The release profile schedules distinct
`fivebsd-ninep-modern` and `fivebsd-ninep-packed` cases. They remain pending
until run with a rebuilt guest containing both modules.

The declarative release suite includes this runner as the serialized
`fivebsd-virtio` case.  Supply its raw base image separately from the Alpine
ISO:

```sh
/usr/libexec/flua ./virtio-lab.lua run --profile release \
    --iso /path/to/alpine-virt.iso \
    --fivebsd-image /path/to/guest-base.img \
    --workdir /tmp/virtio-release
```

`VM_FREE_GATES=no` is set by the lab because its exclusive host gate has
already built and validated the helper programs.
