# vsock deep-review findings (2026-07-09)

Three parallel reviews (device edge cases, guest-kernel correctness, test
coverage) over the AF_VSOCK stack. Each finding below was verified against
the source. Severity: HANG/LOSS/CRASH > throughput/spec > cosmetic.

STATUS: D1, D2, D3 FIXED (commit be4d3921bc7, device harness 86 checks).
G1, G4, G5 FIXED (commit 65e6d29b5a8, guest kernel). The guest unit harness
now covers both `uipc_vsock.c` and `virtio_vsock.c`. Remaining: G3 (minor lock
race), device nits, and genuinely concurrent lifecycle coverage.

## Confirmed real bugs

### D1 REACHABILITY (measured 2026-07-09, live guest)
Our 5BSD guest CANNOT trigger D1: `vsock_sosend` (uipc_vsock.c:2166) rejects
any SEQPACKET record > peer `buf_alloc` (256KB) with EMSGSIZE *before* sending
(confirmed: a 1 MiB guest→host record returns -1/EMSGSIZE instantly, no hang).
D1's deadlock is reachable ONLY by a sender that fragments a large record and
streams fragments against credit without the up-front whole-record check --
i.e. a potential LINUX-interop case, unknown until §4 runs. The D1 fix is
correct-and-defensive regardless (the device must credit incrementally), and
is validated by the unit harness (seqpacket_large_record_credits_incrementally,
which drives the device reassembly as a fragmenting sender would). END-TO-END
proof of D1 requires a Linux guest (GAP 3), not our own.

### D1 — SEQPACKET record >256KB deadlocks (HANG, main data path)
`usr.sbin/bhyve/pci_virtio_vsock.c` `vtvsock_seqpkt_rx`. Host buffers guest
seqpacket fragments into `rx_reasm` but only advances `fwd_cnt` at EOM
(lines 1187/1203). A conformant guest bounds in-flight bytes to the host's
advertised `buf_alloc` (256KB), so a record larger than 256KB exhausts the
guest send window mid-record and blocks forever waiting for credit the host
won't grant until EOM. Reaper never touches it (ESTABLISHED, stall_time==0).
Fix: credit fragments as they're accepted into `rx_reasm` (Linux receiver
semantics); the 4MB `VTVSOCK_MAX_PEER_BUF_ALLOC` reasm cap already bounds it.
NOTE: `fwd_cnt` is also advanced at tx_buf drain (line 1068, shared with
STREAM) — the fix must not double-count for SEQPACKET.

### G1 — Non-blocking send with full TX ring silently loses data (LOSS)
`sys/kern/uipc_vsock.c` `vtvsock_tx_space` + `sys/dev/virtio/vsock/virtio_vsock.c`
`vtvsock_virtio_send`. `vtvsock_tx_space` (remote branch) returns only
`vtvsock_credit_available()` — it ignores TX virtqueue occupancy. On a NBIO
send with credit available but the ring full, `vsock_sosend` consumes the uio
via `m_uiotombuf`, `vtvsock_virtio_send` gets EWOULDBLOCK from the ring, rolls
back credit and frees the mbuf — but `dofilewrite` sees uio progress and
reports those (freed) bytes as written. Same class as the pr_sosend bug we
fixed, different dimension. Fix: make the NBIO capacity gate also reflect TX
ring free space so it returns EWOULDBLOCK before consuming the uio.

### D3 — FIONREAD ioctl lacks CAP_IOCTL (throughput regression under Capsicum)
`pci_virtio_vsock.c` line 2410 `ioctl(conn->fd, FIONREAD, &avail)`. The conn
fd rights (lines 1417, 2753) omit CAP_IOCTL, so under a real Capsicum sandbox
the ioctl returns ENOTCAPABLE, `avail` stays 0, and every STREAM host->guest
read caps at 4KB/dispatch. Invisible: tests build -DWITHOUT_CAPSICUM. Fix: add
CAP_IOCTL + cap_ioctls_limit(FIONREAD) to both conn-fd rights sites.

### D2 — Reaper misreads 0-length SEQPACKET record as EOF (spurious teardown)
`pci_virtio_vsock.c` `vtvsock_reap_stale` ~line 1810. Dead-peer probe uses
bare `recv()==0`, which for SEQPACKET is returned both for EOF and for a
legit 0-length record. The data path uses recvmsg+MSG_EOR to disambiguate;
the reaper reintroduced the confusion. Narrow (needs 0-len record during a
>=5s credit stall) but a real regression of a distinction the code otherwise
defends. Fix: mirror the data path (recvmsg, treat 0+!MSG_EOR as EOF).

## Lower-severity (real, minor)

- **G4** `uipc_vsock.c:2559` — peer_fwd_cnt stored non-monotonically; a peer
  that rewinds fwd_cnt inflates `used` and stalls the sender. Clamp with MAX.
- **G5** `virtio_vsock.c:806` — TX-ring-full sleeper (`&sc->sc_txvq`) not woken
  by `vsock_transport_reset_locked` (live migration); bounded by 1s poll.
- **G3** `uipc_vsock.c:2139` — so_error/sb_state read-cleared without SOCK_LOCK
  in vsock_sosend; a racing async-reset store can be lost.
- **Device nits**: OP_REQUEST doesn't validate peer_fwd_cnt vs tx_cnt (self-
  inflicted starve); type-mismatched OP_RW skips the credit update; seqpacket
  "record > current credit" defer doesn't set stall_time.

## Verified SOUND (checked, no action)
Credit arithmetic wrap-correctness, tx_buf/rx_reasm overflow guards + global
budgets, conn_close fd double-close ordering, mevent-vs-vCPU re-lookup UAF
guards, malformed-TX validation, detach-vs-delivery UAF guards, lock ordering
(vtvsock_mtx -> SOCK_*BUF_LOCK), reserved-CID handling, feature-negotiation
gating, connect() failure SS_ISCONNECTING clearing.

## Coverage gaps (biggest lever first)

**Structural gap (closed):** the packaged guest harness includes the real
`uipc_vsock.c` and `virtio_vsock.c` in separate ATF binaries.  Crafted peer
packets cover the RX state machine; a descriptor-owning virtqueue model covers
TX readiness, reclaim/retry, bounded FIFO drain, reset recycling/wakeup, and
attach/detach.  The remaining limitation is simultaneous scheduling: its
userspace mutex and sleep model is deterministic, so interrupt-vs-detach and a
genuinely blocked sender still require lifecycle/e2e tests.

**Completed action:** build a guest-side unit harness mirroring
`vsock_device_harness/` — `#include` `uipc_vsock.c` with a mock
`vtvsock_transport` (capturing emitted packets) + mock sockbuf primitives.
That one harness automates: established-conn ECONNRESET (flow-control
violation), guest-side peer_fwd_cnt spoof RST, connection-cap RST + slot
reclaim, feature-negotiation permutations, CID_LOCAL wire isolation,
SEQPACKET frag-limit RST, deferred-teardown callout, TRANSPORT_RESET, and
guest->host MSG_EOR wire emission.

**Device harness additions:** connection cap (257 REQUESTs), the whole
control-socket path (VSOCK_CTL_CONNECT limits/idle-timeout/errnos/unknown-cmd),
the 4 remaining malformed-TX drops, reaper timeouts (advance the clock).

**ATF additions:** SEQPACKET exact-MAX boundary (succeeds) vs +1 (EMSGSIZE),
SEQPACKET SHUT_RDWR, SEQPACKET peer-close EOF+SIGPIPE, connect_timeout ERANGE.

## Testplan §6 status
Automated: rows 1-4, 7, 8, 11 (partial), 15. Partial: 5, 6, 10, 14.
Aspirational (no automation): row 9 (>=256 conns/cap), row 12 (guest reboot),
row 13 (bhyve-detach blocked-sender wakeup), row 16 (CID_LOCAL wire isolation).
