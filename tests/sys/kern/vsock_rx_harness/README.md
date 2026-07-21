# vsock guest unit harness

Mirror of `vsock_device_harness/` but for the GUEST side.  It builds two ATF
programs from the real kernel sources: `sys/kern/uipc_vsock.c` for the socket
domain/RX state machine, and `sys/dev/virtio/vsock/virtio_vsock.c` for the
guest VirtIO transport.  Small userspace shims model socket buffers, devices,
scatter/gather lists, and descriptor-owning virtqueues.

This covers the guest RX / credit / feature / reset logic that the
loopback-only ATF suite (`vsock_test`) and the AF_UNIX-limited e2e suite
structurally cannot reach (a crafted/malicious peer can only be injected
here).  The transport binary directly covers CID config sanitization,
descriptor-aware TX readiness, reclaim-and-retry, bounded control queuing,
FIFO interrupt draining, transport-reset wakeup/recycling, and the
attach-completed/detach lifecycle.

## Correctness

The socket-buffer layer in `kmock.h` does REAL byte accounting (sbappend
adds to sb_cc, sbspace = hiwat - cc) so credit tests are meaningful.  The
harness is negative-control verified: breaking the DUT's spoof guard makes
`rx_peer_fwd_cnt_spoof_rst` fail, and a wrong expected credit fails
`credit_arithmetic_and_clamp` -- i.e. the tests detect broken code, they
don't pass blindly.

## Run

    sh run.sh        # builds under ASan/UBSan with a tiny atf-c.h shim
    make             # builds the packaged ATF test

## Files

- `kmock.h`         kernel-environment shim (types, sockbuf behavior, stubs)
- `transport_kmock.h` descriptor-owning virtqueue and VirtIO bus model
- `glue.c`          non-inline mock definitions (mbuf helpers, globals)
- `vsock_rx_test.c` the tests + capturing transport + sonewconn
- `virtio_vsock_transport_test.c` direct guest VirtIO transport tests
- `sys/`,`net/`,`kern/`,`machine/`,`dev/` shadow headers for DUT includes

## Scope / TODO

Covered: reserved-CID sanitization, feature-negotiation gating (both
directions), credit arithmetic incl. wrap, peer_fwd_cnt spoof -> RST,
flow-control-violation ECONNRESET, CID_LOCAL wire isolation, SEQPACKET
fragment-limit RST, deferred-teardown timeout, and transport reset with CID
re-registration.  It also covers the global inbound connection cap, the
non-blocking TX-ready gate before uio consumption, and guest SEQPACKET
`MSG_EOR` transport marking.  The direct transport binary additionally checks
descriptor ownership, bounded FIFO overflow, interrupt and reset wakeup
channels, and attach/detach reclamation.  `msleep` is still a non-blocking stub
and `wakeup` is instrumented rather than scheduled, so genuinely blocking
credit/ring stalls stay in the e2e suite.
