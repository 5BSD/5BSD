# vsock deep-review findings (2026-07-09)

> **2026-07-25 correction:** The D1 conclusion below was superseded after a
> document-first comparison with VirtIO 1.4 and Linux.  A SEQPACKET sender
> must keep a record within the receive window.  Linux caps the record against
> `min(peer_buf_alloc, local buf_alloc)` and advances `fwd_cnt` only when
> queued receive data is consumed.  Crediting fragments merely copied into
> bhyve's reassembly buffer falsely advertised capacity still occupied by that
> record and could reset a valid following record under host backpressure.
> The userspace backend now bounds reassembly to its advertised 256 KiB
> `buf_alloc`, returns credit only after complete host-socket delivery, and has
> deterministic inline, deferred, and over-window regressions.  The historical
> D1 text is retained below to document why the earlier reasoning was rejected.

Three parallel reviews (device edge cases, guest-kernel correctness, test
coverage) over the AF_VSOCK stack. Each finding below was verified against
the source. Severity: HANG/LOSS/CRASH > throughput/spec > cosmetic.

STATUS: D1, D2, D3 FIXED (commit be4d3921bc7, device harness 86 checks).
G1, G3, G4, G5 FIXED (G1/G4/G5 in commit 65e6d29b5a8). The guest unit harness
now covers both `uipc_vsock.c` and `virtio_vsock.c`, including a concurrent
TX-ring-blocked send/detach wakeup and deterministic RX/TX interrupt-versus-
detach schedules.  The functional matrix is complete; remaining Tier-3 items
require broad resource-exhaustion or allocation fault injection.

## Confirmed real bugs

### G6 — SEQPACKET queue pressure could disconnect a healthy socket (fixed)

Both kernel remote transports fragment a record into 64 KiB wire packets.
`sys/kern/uipc_vsock_user.c:vsock_user_send_seqpacket()` and
`sys/dev/virtio/vsock/virtio_vsock.c:vtvsock_virtio_send_seqpacket()` now
allocate every fragment before taking transport credit, reserve complete
record capacity under `vtvsock_mtx`, and publish all fragments in FIFO order
or none.  Blocking sends wait on the existing event-driven capacity channel;
nonblocking queue pressure returns `EWOULDBLOCK` with unchanged connection,
credit, and queue state.  This mirrors Linux's intermediate
`send_pkt_queue` admission shape while retaining bounded FreeBSD queues.

Deterministic provider and virtqueue tests cover multi-fragment success,
one-slot-short pressure, descriptor pressure, allocation failure at each
fragment, credit rollback, and later successful retry.  No test accepts a
prefix of a SEQPACKET record as success.

### D1 REACHABILITY (measured 2026-07-09, live guest)
Our 5BSD guest CANNOT trigger D1: `vsock_sosend` (uipc_vsock.c:2166) rejects
any SEQPACKET record > peer `buf_alloc` (256KB) with EMSGSIZE *before* sending
(confirmed: a 1 MiB guest→host record returns -1/EMSGSIZE instantly, no hang).
D1's hypothesized sender is non-conforming: Linux rejects a record larger than
the applicable receive window before fragmenting it.  Incremental credit for
reassembly was therefore not a defensive extension and has been removed; see
the correction above.

### D1 — SEQPACKET record >256KB deadlocks (HANG, main data path)
`usr.sbin/bhyve/pci_virtio_vsock.c` `vtvsock_seqpkt_rx`. Host buffers guest
seqpacket fragments into `rx_reasm` but only advances `fwd_cnt` at EOM
(lines 1187/1203). A conformant guest bounds in-flight bytes to the host's
advertised `buf_alloc` (256KB), so a record larger than 256KB exhausts the
guest send window mid-record and blocks forever waiting for credit the host
won't grant until EOM. Reaper never touches it (ESTABLISHED, stall_time==0).
The rejected historical fix was to credit fragments as they entered
`rx_reasm`.  The corrected implementation instead rejects a record above
`buf_alloc` and returns credit at complete inline or deferred delivery.

### G1 — Non-blocking send with full TX ring silently lost data (fixed)
`sys/kern/uipc_vsock.c` `vtvsock_tx_space` + `sys/dev/virtio/vsock/virtio_vsock.c`
`vtvsock_virtio_tx_ready()` now requires an empty software holding queue and
enough free direct descriptors for a maximum packet.  `vsock_sosend()` checks
that predicate before consuming a nonblocking caller's uio.  Threshold,
full-ring, capacity-disappears-after-check, reclaim/retry, and detach wakeup
cases have direct pthread-backed transport and socket-layer tests.

### D3 — FIONREAD ioctl lacked CAP_IOCTL (fixed)
`pci_virtio_vsock.c` line 2410 `ioctl(conn->fd, FIONREAD, &avail)`. The conn
fd rights now include `CAP_IOCTL`, and both guest-originated and
control-originated relay descriptors are restricted with
`caph_ioctls_limit()` to exactly `FIONREAD`.  The host contract test checks
both rights sites and both calls to the common limiter.

### D2 — Reaper misreads 0-length SEQPACKET record as EOF (fixed)
`pci_virtio_vsock.c` `vtvsock_reap_stale` ~line 1810. Dead-peer probe uses
bare `recv()==0`, which for SEQPACKET is returned both for EOF and for a
legit 0-length record. The data path uses recvmsg+MSG_EOR to disambiguate;
the reaper reintroduced the confusion. Narrow (needs 0-len record during a
>=5s credit stall) but a real regression of a distinction the code otherwise
defends. The reaper now mirrors the data path with `recvmsg()` and treats
zero plus `MSG_EOR` as an empty record, not EOF.

## Lower-severity (real, minor)

- **G4 (fixed)** Peer `fwd_cnt` is advanced only by wrap-aware monotonic
  comparison and is rejected if it moves beyond locally transmitted bytes.
- **G5 (fixed)** TX-ring-full sleepers use an explicit wakeup channel.
  Queue completion, reset, and detach wake it; there is no periodic one-second
  retry loop.
- **G3 (fixed)** `uipc_vsock.c:2139` — `vsock_sosend` now reads
  `SBS_CANTSENDMORE` under the send-buffer lock and consumes `so_error` under
  `SOCK_LOCK`, serializing the read-and-clear with asynchronous reset writers.
- **Mismatched data handling (fixed again)**: a wrong-type OP_RW now resets
  the connection.  Crediting and silently discarding it hid guaranteed-
  delivery loss and differed from Linux's connected-socket type check.
- **Initial request credit (fixed)**: a new flow has sent no bytes, so bhyve
  rejects an OP_REQUEST with nonzero `fwd_cnt` before opening its host relay
  socket; accepting it could make unsigned credit accounting self-starve.
- **SEQPACKET partial-credit stall (fixed)**: an atomic record larger than
  current credit now sends one CREDIT_REQUEST, timestamps the disabled read
  event for the reaper, preserves it across RX-ring redispatch, suppresses
  duplicate requests, and clears the timestamp only after actual record
  progress.

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
attach/detach, including undersized RX/TX ring rejection and nonblocking-
allocation cleanup/credit rollback.  A pthread-backed sleep model now blocks
a real send thread on
the full-ring channel while another thread detaches the device, covering the
G5 wakeup and stale-softc guard.  Additional gates pause RX after it dequeues
and drops the mutex, allowing detach to drain before RX resumes, and pause TX
dequeue under the mutex while detach waits.  They verify private-buffer
ownership, serialized queue access, and late-interrupt guards under ASan/UBSan.
The pthread harness also passes ThreadSanitizer.  Actual kernel interrupt-
thread scheduling remains a live-stress concern, but the critical source-level
lock-drop and lock-held interleavings are deterministic.

**Completed action:** build a guest-side unit harness mirroring
`vsock_device_harness/` — `#include` `uipc_vsock.c` with a mock
`vtvsock_transport` (capturing emitted packets) + mock sockbuf primitives.
That one harness automates: established-conn ECONNRESET (flow-control
violation), guest-side peer_fwd_cnt spoof RST, connection-cap RST + slot
reclaim, feature-negotiation permutations, CID_LOCAL wire isolation,
SEQPACKET frag-limit RST, deferred-teardown callout, TRANSPORT_RESET, and
guest->host MSG_EOR wire emission.

**Device harness additions:** connection cap (257 REQUESTs), bounded pending-
reply overflow/FIFO/credit retry, SEQPACKET reallocation-failure cleanup, the
whole control-socket path (VSOCK_CTL_CONNECT limits/idle-timeout/errnos/
unknown-cmd),
the 4 remaining malformed-TX drops, reaper timeouts (advance the clock).

**ATF additions:** SEQPACKET exact-MAX boundary (succeeds) vs +1 (EMSGSIZE),
SEQPACKET SHUT_RDWR, SEQPACKET peer-close EOF+SIGPIPE, connect_timeout ERANGE.

## Testplan §6 status
Automated: rows 1-16.  Row 5 treats the local receive limit and the remote
peer-advertised `buf_alloc` as the meaningful MAX/MAX+1 boundaries; VirtIO
defines flow-control windows, not a universal SEQPACKET record maximum.  The
direct guest transport verifies exact-window fragmentation and atomic
window+1 `EMSGSIZE`, the bhyve harness covers its matching receive behavior,
and Alpine carries a 200 KiB record whole in both directions.  Row 10 includes
live Alpine remote SEQPACKET graceful close
in both directions, with payload and EOF observed at each endpoint.  Row 11
combines the existing guest-client kill with a live Alpine host-connector kill,
guest EOF/reset, and immediate reconnect.  Row 13 is automated in the direct
guest transport harness with a pthread-blocked sender and a one-second wakeup
deadline.  Row 14 includes live Alpine guest connects: CID 0 yields ETIMEDOUT
and CID 2 on an unused host port yields ECONNRESET.

## 2026-07 restore and multi-provider review

- **virtio-blk destination identity (fixed):** restore now rejects an image
  whose capacity, topology, queue/range limits, or 20-byte device identifier
  differs from the destination backing store.  Only the negotiated
  `CONFIG_WCE` writeback byte is migratable.  The negative test also checks the
  implementation's terminating identifier byte so an unterminated snapshot
  string cannot escape validation.
- **virtio-net destination identity (fixed):** restore now rejects changes to
  destination queue/RSS limits, MTU/link properties, and modern read-only MAC
  identity.  Legacy guest-writable MAC bytes remain migratable.
- **AF_VSOCK current-CID synchronization (fixed):** bind now validates and
  remaps `CID_ANY` in the same `vtvsock_mtx` transaction as endpoint
  reservation.  Socket and `/dev/vsock` `GET_LOCAL_CID`, plus the guest-CID
  sysctl, take the same lock.  Concurrent provider attach/detach can no longer
  produce a stale or torn local CID.
- **Validation:** the independent VirtIO requirement validator passes; every
  ASan/UBSan device harness suite passes; the direct AF_VSOCK/virtio-vsock
  harness passes 335 + 1,347 checks under both the normal sanitizers and
  ThreadSanitizer; `vsock.ko`, `virtio_vsock.ko`, and bhyve (including its USDT
  provider object) compile and link with `-Werror`.
- **Checkpoint coordinator failure atomicity (fixed):** checkpoint setup no
  longer resumes devices or vCPUs when the matching pause phase never began.
  The PCI layer records pause ownership per device, so cleanup after a partial
  device walk resumes only devices whose pause callback succeeded.  It rejects
  a device exposing only one half of the pause/resume contract, retains
  ownership when resume fails so a retry is possible, and attempts every
  device resume while returning the first error.  Guest vCPUs remain stopped
  if any backend cannot resume, rather than running against partially paused
  emulation.  Metadata allocation, open, finalization, `fclose()`, and data-fd
  `close()` failures now return an error, and descriptor zero is no longer
  leaked by cleanup.  Memory progress is driven by completed I/O rather than
  a polling thread that raced on stack state; interrupted and short writes are
  retried, while zero-progress reads or writes fail instead of looping
  forever.  AHCI now propagates backing-store flush failures and rolls back
  ports paused earlier in the same device callback; the block harness verifies
  that a failed flush releases its quiesce owner.  The focused state-machine
  harness covers absent and mismatched callbacks, duplicate calls, failed
  pause, failed resume, and successful retry.  Live failure injection and
  running/guest-suspended checkpoint round trips remain required.
- **Checkpoint publication atomicity (fixed):** new checkpoints use three
  generation-qualified members and a small canonical manifest.  Every member
  and its directory entry is fsynced before an atomic manifest rename; the
  previous generation is removed only after the replacement manifest is
  durable.  Restore accepts legacy raw/`.kern`/`.meta` sets, rejects malformed,
  cross-generation, and path-escaping manifests, and bounds all restored file
  and metadata ranges.  The sanitizer harness proves that an unpublished
  replacement cannot displace the old generation, and distinguishes failure
  before rename from directory-fsync failure after a visible rename so cleanup
  cannot delete files referenced by the canonical manifest.  A stable sibling
  advisory lock spans manifest resolution/member opens and
  publication/old-generation cleanup, preventing a concurrent restore from
  losing the generation it selected.
