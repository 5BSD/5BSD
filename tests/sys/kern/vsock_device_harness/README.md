# bhyve VirtIO device-level harnesses

Standalone unit harnesses for the bhyve virtio-vsock, virtio-input, and
virtio-rng backends, the shared split-ring parser, and the generic modern
VirtIO PCI transport.

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
window.  The entropy interrupt test combines the real virtio-rng callback with
the real legacy BAR notification and shared split-ring completion path; only
guest memory and the PCI/VMM boundary are mocked.

## Coverage

Coverage includes malformed direct and indirect descriptors; EVENT_IDX;
virtio-input configuration bounds, event/status queue directions and frame
delivery; virtio-rng short, invalid and failed host reads; virtio-rng queue
notification through MSI/INTx delivery with MSI-X disabled; and vsock state,
credit, record-boundary, shutdown, timeout, resource-limit, and hostile-packet
cases.  See `../vsock_e2e/FRAMEWORK.md` for the complete acceptance layers and
the checklist for adding another device.
