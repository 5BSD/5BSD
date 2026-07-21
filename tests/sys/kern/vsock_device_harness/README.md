# bhyve VirtIO device-level harnesses

Standalone unit harnesses for the bhyve virtio-vsock, virtio-input,
virtio-rng, virtio-console, virtio-9p, and virtio-block backends, the shared
split-ring parser, and the generic modern VirtIO PCI transport.

It `#include`s the real device `.c` and mocks the virtio RX ring (to capture the
packets the device injects back toward the guest) and the host-socket syscalls
(via `ld --wrap`), so the op state machine can be driven with crafted guest
headers with no VM, no virtio bus, and no real sockets.

## Build & run

    ./run.sh

Requires a C compiler.  The device and modern-transport harnesses run under
AddressSanitizer and UndefinedBehaviorSanitizer for standalone iteration.

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

## Coverage

Coverage includes malformed direct and indirect descriptors; EVENT_IDX;
in-place iovec splitting (including packed virtio-scsi request/data
descriptors without losing the response tail);
virtio-console feature and configuration bounds, fragmented control messages,
invalid port IDs and queue directions, multi-descriptor data transfer, and
host-side backpressure without data loss;
virtio-9p configuration bounds, request/response descriptor directions,
lib9p request rejection, synchronous flush completion, and stale completion
after reset;
virtio-block descriptor ordering, header/status placement, opcode-specific
layouts, offset overflow, discard flags and feature negotiation, and immediate
backend queue errors;
virtio-input configuration bounds, event/status queue directions and frame
delivery; virtio-rng short, invalid and failed host reads; virtio-rng queue
notification through MSI/INTx delivery with MSI-X disabled; and vsock state,
credit, record-boundary, shutdown, timeout, resource-limit, and hostile-packet
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
See `../vsock_e2e/FRAMEWORK.md` for the complete
acceptance layers and the checklist for adding another device.
