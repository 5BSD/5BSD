# vsock guest RX unit harness

Mirror of `vsock_device_harness/` but for the GUEST side: it compiles the
kernel source `sys/kern/uipc_vsock.c` as a userspace program (via the
`kmock.h` kernel-environment shim + empty `sys/`,`net/`,`kern/` shadow
headers) and drives the real socket domain + `vsock_rx_packet` RX state
machine with a mock `vtvsock_transport` that captures emitted wire packets.

This covers the guest RX / credit / feature / reset logic that the
loopback-only ATF suite (`vsock_test`) and the AF_UNIX-limited e2e suite
structurally cannot reach (a crafted/malicious peer can only be injected
here).

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
- `glue.c`          non-inline mock definitions (mbuf helpers, globals)
- `vsock_rx_test.c` the tests + capturing transport + sonewconn
- `sys/`,`net/`,`kern/`  empty shadow headers (satisfy the DUT's #includes)

## Scope / TODO

Covered: reserved-CID sanitization, feature-negotiation gating (both
directions), credit arithmetic incl. wrap, peer_fwd_cnt spoof -> RST,
flow-control-violation ECONNRESET, CID_LOCAL wire isolation, SEQPACKET
fragment-limit RST, deferred-teardown timeout, and transport reset with CID
re-registration.  It also covers the global inbound connection cap, the
non-blocking TX-ready gate before uio consumption, and guest SEQPACKET
`MSG_EOR` transport marking.  `msleep`/`wakeup` are stubs (return
EWOULDBLOCK), so blocking-sender credit-stall tests stay in the e2e suite.
