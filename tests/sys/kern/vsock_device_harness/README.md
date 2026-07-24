# bhyve VirtIO device-level harnesses

Standalone unit harnesses for the bhyve virtio-vsock, virtio-input,
virtio-rng, virtio-console, virtio-9p, virtio-block, virtio-net, and
virtio-scsi backends, the shared split-ring parser, and the generic modern
VirtIO PCI transport.

It `#include`s the real device `.c` and mocks the virtio RX ring (to capture the
packets the device injects back toward the guest) and the host-socket syscalls
(via `ld --wrap`), so the op state machine can be driven with crafted guest
headers with no VM, no virtio bus, and no real sockets.

## Build & run

    ./run.sh

Requires a C compiler.  The device and modern-transport harnesses run under
AddressSanitizer and UndefinedBehaviorSanitizer for standalone iteration.
Set `SANITIZERS=thread` to run the identical test set under ThreadSanitizer;
the validation record in `docs/bhyve-virtio-1.4-validation-review.md` records
both modes.

These harnesses are also wired into ATF/kyua (see this directory's Makefile,
which supplies the mock-header shadowing and `--wrap` linker flags the stock
`ATF_TESTS_C` build does not), so the same cases run as part of the kernel test
suite.  The standalone script also exercises transport policy, PCI identity
and capability layout, 64-bit feature negotiation, separately addressed
virtqueues, notification and ISR behavior, and the PCI configuration access
window, including the modern network, SCSI, console, and 9P device identities.
The entropy interrupt test combines the real virtio-rng callback with
the real legacy BAR notification and shared split-ring completion path; only
guest memory and the PCI/VMM boundary are mocked.

The VirtIO 1.4 requirements ledger is
`virtio-1.4-requirements.tsv`.  `validate-virtio-requirements.sh` rejects
advertised features without an implementation and positive test.  The current
1.4 milestone implements `VIRTIO_F_RING_RESET` for the bhyve net, block,
console, entropy, SCSI, input, and vsock devices.  The 9P device does not
advertise this optional feature because lib9p does not expose queue-local
request cancellation; reconnecting the whole device would incorrectly discard
session and fid state.  Every modern device also implements
`VIRTIO_F_NOTIFICATION_DATA`; the FreeBSD PCI and MMIO
guest transports send the full available index in the 32-bit notification.
It does not claim packed rings, notification configuration data, an IOMMU
platform, administration queues, or suspend.  FreeBSD virtio-rng is the first
guest consumer of individual queue reset.  Its VM acceptance test is
`../vsock_e2e/run-freebsd-vtrnd-reset.sh`.

Protocol expectations in the harness come from `virtio_1_4_spec.h` and
`virtio_1_4_wire.h`, which are literal transcriptions of the cited document
tables and layouts and may not include or derive from production VirtIO
headers.  Device tests include the real implementation before remapping its
protocol names to this independent oracle; structured request tests assemble
raw bytes using document offsets.  Values such as mock guest addresses,
payload patterns, fault-injection errors, counters, and implementation state
are test inputs rather than protocol expectations.  The explicit transitional
virtio-input PCI ID is a separately documented bhyve compatibility extension
recorded in `bhyve_virtio_compat.h`: VirtIO 1.4 assigns input no transitional
ID, so it is not presented as a standard conformance value.

## Coverage

Coverage includes malformed direct and indirect descriptors; EVENT_IDX;
in-place iovec splitting (including packed virtio-scsi request/data
descriptors without losing the response tail);
virtio-console feature and configuration bounds, fragmented control messages,
invalid port IDs and queue directions, idempotent `DEVICE_ADD` lifecycle,
multi-descriptor data transfer, and host-side backpressure without data loss;
virtio-9p configuration bounds, request/response descriptor directions,
lib9p request rejection, synchronous flush completion, and stale completion
after reset;
virtio-block descriptor ordering, header/status placement, opcode-specific
layouts, offset overflow, discard flags and feature negotiation, and immediate
backend queue errors;
virtio-net RX/TX descriptor directions and bounds, undersized receive buffers,
merged-buffer accounting beyond 32 bits, zero TX used lengths, and
configuration-write bounds;
virtio-scsi request/control descriptor validation, response isolation,
accurate failure used lengths, invalid task-management functions,
bidirectional feature enforcement, bounded configuration hints, full-reset
completion versus selective-reset discard, and oversized payload rejection;
virtio-input configuration bounds, fresh zeroed query responses, absolute-axis
metadata, reset-state clearing, event/status queue directions, and whole-frame
delivery or drop;
virtio-rng short and invalid host reads, retained failed chains with reset
signaling, and bounded partial fills;
virtio-rng queue
notification through MSI/INTx delivery with MSI-X disabled; and vsock state,
credit, record-boundary, shutdown, timeout, resource-limit, and invalid-packet
cases.  SEQPACKET credit coverage includes an atomic record larger than current
credit: it remains queued, sends only one CREDIT_REQUEST across repeated
callbacks and RX-notification redispatch, keeps a reaper timestamp through a
liveness probe and credit update, and clears it after delivery.  Connection
setup coverage also rejects nonzero initial `fwd_cnt` values before opening a
host relay socket.  A discarded type-mismatched data packet is also credited
back at the reporting threshold so the sender cannot remain blocked on bytes
bhyve no longer holds.  Pending-control-reply coverage fills the bounded ring,
verifies overflow accounting without false credit advancement, drains the
retained FIFO, and confirms that the dropped credit update is retried.
Fault injection also forces SEQPACKET reassembly growth to fail and verifies
RST/connection cleanup without leaking either device-global byte budget.
Queue-reset coverage includes synchronous completion, asynchronous drain,
failure and stale-completion generations, frozen configuration and
notifications, reconfiguration with new queue addresses, per-device queue
isolation, backend quiescing, a full-device reset crossing an unlocked backend
reset callback, and reset-safe preservation or rejection of staged data.  The
transport state soak performs 4,096 mixed synchronous and asynchronous queue
reset/re-enable cycles, including stale completions and periodic full-device
resets.
See `../vsock_e2e/FRAMEWORK.md` for the complete
acceptance layers and the checklist for adding another device.
