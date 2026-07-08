# vsock device-level TX harness

Standalone unit harness for the bhyve virtio-vsock host device's untrusted-guest
TX ingress state machine (`vtvsock_process_tx_pkt` in
`usr.sbin/bhyve/pci_virtio_vsock.c`).

It `#include`s the real device `.c` and mocks the virtio RX ring (to capture the
packets the device injects back toward the guest) and the host-socket syscalls
(via `ld --wrap`), so the op state machine can be driven with crafted guest
headers with no VM, no virtio bus, and no real sockets.

## Build & run

    ./run.sh

Requires a C compiler; runs under AddressSanitizer for standalone iteration.

This harness is also wired into ATF/kyua as `vsock_device_test` (see the
dedicated build rules for it in `../Makefile`, which supply the mock-header
shadowing and `--wrap` linker flags the stock `ATF_TESTS_C` build does not), so
the same cases run as part of the kernel test suite.

## Coverage

Spoofed src_cid drop, unknown-type RST, unknown-connection RST, RST-for-RST
avoidance, OP_REQUEST connect relay (listener present/absent), OP_RW forwarding
+ credit accounting, malicious `fwd_cnt > tx_cnt` teardown, the dropped
CREDIT_UPDATE `last_fwd_cnt` regression, and bidirectional SHUTDOWN teardown.
