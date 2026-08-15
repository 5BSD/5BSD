# bhyve VirtIO RTC design

The `virtio-rtc` PCI device implements the baseline request queue from
VirtIO 1.4 section 5.23.  It is modern-only and exposes one dense clock
identifier, clock 0.  No device configuration region is defined.

## Clock contract

Clock 0 is backed by host `CLOCK_REALTIME` and returns an unsigned
little-endian nanosecond count from the Unix epoch.  Its type is
`VIRTIO_RTC_CLOCK_UTC_MAYBE_SMEARED`: host time policy can either step at a
leap second or discipline the clock with a smear, so promising unsmeared UTC
would be stronger than the host interface can guarantee.

The clock set and baseline capability responses are immutable across reset.
Alarm support is opt-in with `alarm=true`; without it there is no alarm
virtqueue and alarm requests return the feature-specific `ENODEV` status.
With it, the device advertises `VIRTIO_RTC_F_ALARM`, reports
`ALARM_CAP` for clock zero, implements all three alarm control messages, and
publishes exact 16-byte notifications on alarmq.  Cross-timestamp capability
is reported clear and `READ_CROSS` is unsupported.

## Validation and ordering

The bounded request engine is separate from PCI and queue handling.  It
validates request and response sizes, common and message-specific reserved
fields, dense clock identifiers, standardized counter identifiers, and the
status precedence required by section 5.23.6.2.  Extra request and response
capacity is ignored.

The PCI queue path requires at least one device-readable and one
device-writable descriptor, preserves descriptor direction ordering, and
completes requests synchronously in availability order.  Malformed descriptor
topology sets `DEVICE_NEEDS_RESET`.

## Lifecycle and migration

The device uses the common reset, queue-reset, suspend, packed/split queue,
interrupt, and checkpoint machinery.  Alarm expiration is scheduled with a
bounded host timer for the exact next deadline; a distant deadline is
re-evaluated only when that bounded timer fires, rather than by a periodic
polling loop.  Suspend and checkpoint pause disable the event and resume
recomputes it from the authoritative destination clock.

The sole accepted device-specific `RTC1` version 2 record embeds a checksummed
fixed-width little-endian `ALA1` alarm record.  Restore rejects obsolete
version 1 records.  A sampled wall-clock value, timer
handle, host pointer, file descriptor, or CPU counter is never serialized;
after restore, the destination host clock is authoritative and an alarm that
elapsed during migration becomes pending.

This state contract is architecture-neutral.  The current live qualification
host is Intel amd64, but no RTC device state depends on VMX, TSC layout,
native word size, or host byte order.  Future counter cross-timestamp support
must be introduced through an architecture operation and separately
versioned capability contract.

## Tests and observability

Independent protocol tests use document-transcribed sizes and byte vectors.
They cover valid discovery/capability/read requests, mixed-error status
precedence, unimplemented private counter identifiers, malformed reserved
fields, short buffers, host-clock errors, and API misuse.  A separate device
test includes the production PCI source and covers default and alarm-enabled
advertisement, packed opt-in, descriptor rejection, exact request and alarm
queue bytes, undersized notification buffers, immediate and stepped
expiration, reset, repeated restore, obsolete-version rejection, and snapshot
truncation/corruption.  DTrace records message type, input/output sizes, bytes
written, and status.

The root qualification manifest contains Linux split, packed, reset,
checkpoint, combined-device, and reset-soak lanes.  Current Linux deliberately
exports a clock that may step or smear leap seconds through its PTP class
rather than its RTC class.  The live test therefore requires exactly one
related RTC or PTP class clock and reads that actual clock; it does not weaken
the device declaration merely to obtain an `/sys/class/rtc` node.  The opt-in
`RTC_ALARM=yes` lane additionally requires an RTC-class node, programs
`wakealarm`, polls `/dev/rtcN`, and checks `AF|IRQF`, proving that Linux
consumed an alarmq notification.

The tree now also contains a rebuilt-5BSD read-only system-clock and alarm
driver.  It negotiates `VIRTIO_RTC_F_ALARM` when offered, validates the
matching `ALARM_CAP`, keeps one exact notification buffer posted on alarmq,
and exposes `dev.vtrtc.N.alarm_time_ns` plus the monotonic notification count
`dev.vtrtc.N.alarm_count`.  Each validated notification schedules a bounded
taskqueue clock read, as recommended by section 5.23.6.6.3.1, and publishes
the result through `dev.vtrtc.N.alarm_observed_time_ns`; the interrupt handler
never sleeps.  Writing an absolute UTC nanosecond deadline arms the alarm and
writing zero disables it.  Requests are serialized, completion
lengths and every reserved byte are checked, malformed notification data
permanently fails the instance, and all stack-backed request descriptors are
drained before an error can return.

Separate split and packed 5BSD live lanes require PCI discovery, driver
registration, host-correlated configuration/capability/read/alarm traffic, a
real increment of the guest notification count, a post-notification clock
sample at or beyond the deadline, negotiated-feature evidence, and matching
request and alarm ring-layout evidence.  Those lanes remain
pending until run with an image containing the new module; a mock guest does
not substitute for that qualification.
