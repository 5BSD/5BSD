# vsock — comprehensive test plan for what remains

Companion to `vsock_bhyve_testplan.md` (the §6 host↔guest matrix) and
`REVIEW.md` (the deep-review findings). This document is the forward-looking
plan: what is covered today, the biggest gaps ranked by risk, the concrete
test cases to close them, and a phased roadmap.

## Progress log

**2026-07-21:** closed GAP 3 with Alpine 3.24.1 using its unmodified upstream
Linux VirtIO drivers.  The packaged matrix passed isolated and combined
modern/legacy vsock, RNG, and block coverage plus modern input.  The focused
legacy no-MSI-X gate also passed driver reset/rebind, monitor-mode reboot, and
post-reboot data-path/persistence checks.  Direct `virtio_vsock.c` coverage is
now packaged with the guest harness: 14 ATF cases / 760 assertions exercise
descriptor-aware readiness, reclaim/retry, bounded FIFO control queuing,
interrupt drain/wakeup, the SEQPACKET peer-window boundary, event reset,
undersized-ring and allocation-failure cleanup, attach-completed/detach, and a
real pthread sender blocked on the full-ring sleep channel while detach wakes
it within one second.  Deterministic RX/TX handler schedules now overlap detach
both outside and inside the transport mutex.
The socket-domain half now has 13 ATF cases / 89 assertions, including locked
send-side terminal-state checks that close G3; together the guest harness has
27 cases / 849 assertions.
The focused no-MSI-X run now also passes monitor-mode reboot with established
STREAM and SEQPACKET endpoints: each is echo-proven before reboot, both old
endpoints disconnect within 30 seconds, and fresh connections pass afterward.
Every live vsock preflight now also asserts guest-initiated reserved-CID
behavior: CID 0 times out with ETIMEDOUT, while CID 2 on an unused host port
is rejected with ECONNRESET.
The modern and legacy Alpine matrices also pass explicit remote SEQPACKET
graceful-close probes in both directions: each receiver observes the payload
followed by EOF, and each initiating endpoint observes the peer's final EOF.
Abrupt peer death is now covered in both directions as well: the original
guest-client SIGKILL makes the host observe teardown, while the Alpine matrix
SIGKILLs an echo-proven host connector and requires guest EOF/reset plus an
immediate fresh connection.
Row 5 now uses the boundary VirtIO actually defines: `buf_alloc`, the peer's
advertised credit window, rather than a universal SEQPACKET maximum.  The
direct guest transport accepts an exact-window record across two wire packets
and rejects window+1 atomically without closing; the bhyve harness covers the
matching receive-window and current-credit behavior.  Live Alpine retains a
200 KiB whole-record test in both directions as an interoperability check.

**2026-07-09 (this session):** closed GAP 1, GAP 2, GAP 4, GAP 5. The only
remaining gap is GAP 3 (Linux interop), which needs the Linux VM.
- GAP 4 + GAP 2: device harness 86 → 111 checks (conn cap, reaper timers,
  oversized-paylen, ctl idle-reap + referenced-protection, ctl accept cap,
  ctl CONNECT→OP_REQUEST handshake, unknown-cmd, socketpair-fail ENOMEM).
- GAP 5: ATF +4 (seqpacket exact-max boundary, SHUT_RDWR, peer-close
  EOF/EPIPE, connect ERANGE) — all pass in-guest.
- GAP 1: **guest RX unit harness BUILT** (tests/sys/kern/vsock_rx_harness).
  Compiles the kernel uipc_vsock.c in userspace via kmock.h; drives the real
  vsock_rx_packet state machine. 13 tests / 89 checks, negative-control
  verified. Covers reserved-CID sanitization, feature-negotiation gating,
  credit arithmetic incl. wrap, peer_fwd_cnt spoof → RST, flow-control
  violation → ECONNRESET, CID_LOCAL isolation, SEQPACKET fragment-limit RST,
  deferred teardown, transport reset/CID re-registration, connection-cap slot
  reclaim, the G1 TX-ready gate, and guest `MSG_EOR` emission. The harness is
  packaged as an ATF test and runs in the Alpine matrix's VM-free gate.

## Where coverage stands today (baseline)

| Artifact | Scope | Status |
|---|---|---|
| `vsock_test.c` (ATF) | socket ops + **loopback** transport | 152/153 pass (1 platform skip) |
| `vsock_wire_test.c` (ATF) | struct/ABI wire layout | complete for static layout |
| `vsock_device_harness/` | bhyve host device TX/RX ingress | 222 vsock checks plus transport/device suites |
| `vsock_rx_harness/` | guest domain + direct VirtIO transport | 27 tests / 849 checks |
| `vsock_e2e/` (live guest) | upstream Linux driver interop | modern/legacy matrix passed; root-only |

**Remaining structural limitation:** both guest source files now have direct
userspace coverage and the live Alpine matrix exercises the complete stack.
The pthread-backed transport model forces send-vs-detach plus RX/TX handler-
versus-detach interleavings through the real handler code.  It does not emulate
the kernel interrupt-thread runtime itself; scheduler stress remains live-only,
but the critical queue-ownership branches are directly scheduled in the
harness.

---

## GAP 1 — guest RX state machine coverage (CLOSED)

**Original gap:** every wire event the guest handles —
OP_REQUEST/RESPONSE/RST/SHUTDOWN/RW/CREDIT_UPDATE/CREDIT_REQUEST — plus
peer-credit ingest, the `peer_fwd_cnt` spoof check, the cumulative-overflow
ECONNRESET, SEQPACKET wire reassembly + frag-limit, the deferred-teardown
callout, `vsock_transport_reset_locked`, and reserved-CID sanitization. On the
transport: feature negotiation, virtqueue enqueue/reclaim, the credit-stall and
ring-full sleep loops, detach-vs-inflight races, and the new G1 `tx_ready` gate.

**Why it matters:** this is where 3 of this session's confirmed bugs lived
(the VNET panic, the pr_sosend data loss, G1). A regression here is silent
data loss or a hang, and nothing in CI would catch it.

**Implemented:** a harness at
`tests/sys/kern/vsock_rx_harness/` mirroring `vsock_device_harness/`:
`#include "uipc_vsock.c"` with a mock `vtvsock_transport` that **captures
emitted packets**, plus mock sockbuf primitives. Then drive `vsock_rx_packet`
directly with crafted headers.

Concrete cases (each is one ATF check-group):
1. **flow-control-violation ECONNRESET** — inject OP_RW pushing `rx_bytes`
   past `buf_alloc`; assert RST emitted + `so_error == ECONNRESET` (the ONLY
   established-conn ECONNRESET path; loopback can't reach it).
2. **guest-side peer_fwd_cnt spoof** — CREDIT_UPDATE with `fwd_cnt > tx_cnt`;
   assert teardown + RST. (Mirror of the host-side `peer_fwd_cnt_overflow_rst`.)
3. **G4 monotonic clamp** — CREDIT_UPDATE that rewinds `fwd_cnt`; assert the
   send window does NOT shrink (regression for the clamp we just added).
4. **connection cap** — drive OP_REQUESTs past `vtvsock_max_conn`; assert the
   overflow REQUEST gets RST and that closing one frees a slot.
5. **feature-negotiation permutations** — register the transport with each
   mask (stream-only / seqpacket-only+NO_IMPLIED_STREAM); assert
   `socket(SEQPACKET)` → EPROTONOSUPPORT on a stream-only device and
   `socket(STREAM)` → EPROTONOSUPPORT on a seqpacket-only one.
6. **CID_LOCAL wire isolation** — bind CID_LOCAL, connect to a remote CID →
   EADDRNOTAVAIL; inject an inbound REQUEST targeting a CID_LOCAL listener →
   not matched (RST). (§5.10.6.4.1; testplan row 16.)
7. **SEQPACKET frag-limit RST** — inject > `seqpacket_frag_max` non-EOM
   fragments (or > `buf_alloc`); assert RST + `rx_drops` increment.
8. **deferred-teardown callout** — OP_SHUTDOWN(RCV|SEND) with buffered rx
   data, never drained; advance the callout; assert RST + `soisdisconnected`.
9. **TRANSPORT_RESET** — deliver the reset with live connections; assert all
   → CLOSED/ECONNRESET and the transport is re-registered with the new CID.
10. **guest→host MSG_EOR emission** — assert the emitted OP_RW carries
    SEQ_EOR iff the sender passed MSG_EOR (the M_PROTO1 path; Linux conformance).
11. **G1 tx_ready** — mock the ring full with credit available; assert a
    non-blocking send returns EWOULDBLOCK *before* consuming the uio (regression
    for the silent-loss fix).

**Result:** 11 Tier-1/2 behaviors moved from live-e2e-only coverage into CI.

### GAP 1 scoping (dependency analysis, done 2026-07-09)

Unlike the device harness (which #includes *userspace* bhyve code with a
narrow syscall surface), `uipc_vsock.c` is *kernel* code deeply entangled
with the socket subsystem. A userspace `#include` harness must provide a
functional-enough shim for:

- **socket/sockbuf** — ~16 fields touched (`so_rcv/so_snd/so_state/so_error/
  so_pcb/so_type/so_options/so_qlimit/so_vnet`, `sb_hiwat/sb_lowat/sb_state/
  sb_timeo`, `sol_sbrcv_hiwat`). The sockbuf accounting must ACTUALLY WORK
  (`sbappendstream/record`, `sbspace`, `sb_hiwat`) — credit tests are
  meaningless otherwise, and a subtly-wrong mock yields false-confidence
  passes (worse than no test).
- **socket ops** — `sonewconn` (×12, must return a working child with a
  pcb), `soreserve`, `soisconnected`, `socantrcvmore/sendmore`,
  `soisdisconnected`, `so_setsockopt`.
- **sync** — `mtx_*` (×19; pthread mutex or no-op), `msleep`/`wakeup` (×6/×31;
  need real condvar semantics for the credit-stall tests), `callout_*` (×19;
  a manual-fire timer for the deferred-teardown test).
- **mbuf** — `m_get`, `m_freem` (×20), `m_uiotombuf`, `m_length`, `M_EOR`/
  `M_PROTO1`.
- **infra** — `malloc`/`free` (M_ tags), `counter_u64_*` (×17), `SYSCTL_*`
  (×19, stub), `SDT_PROBE*` (×24, stub via the harness pattern), `CURVNET_*`/
  VNET (×4, stub).

The load-bearing 20% is the **sockbuf + msleep/wakeup + sonewconn** shim; the
rest stubs cleanly. Budget the session around getting sockbuf accounting and
the credit-stall wakeup semantics provably correct (e.g. cross-check against
the live e2e credit behavior) before writing the 11 test cases.

Alternative if the userspace shim proves too costly: a small in-guest **test
kernel module** that calls the static-exposed entry points, or a crafted-peer
injector — but note the e2e path canNOT reach the malicious-peer cases
(spoofed fwd_cnt, flow-control-violation RST): the host side is AF_UNIX and
bhyve only emits well-formed wire frames, so those RST/teardown paths are
reachable ONLY by a unit harness or a raw-wire injector.

**Automated result (2026-07-21):** every Alpine vsock preflight asserts that a
guest connect to reserved CID 0 times out with ETIMEDOUT and that CID 2 with
no listener returns ECONNRESET.  The CID-0 result matches Linux's treatment of
an unreachable CID; the CID-2 result proves bhyve returned RST for the unused
host port.

---

## GAP 2 — bhyve control-socket path (CLOSED)

**Original gap:** `pci_vtvsock_ctl_conn_cb`/`ctl_accept`. e2e covered only the
happy host→guest path + one refused case. Untested was the `VTVSOCK_MAX_CTL_CONNS`
(16) cap, the 30 s idle-timeout reap of a ctl conn that never sent CONNECT, the
CONNECTING-reap `-ETIMEDOUT` reply, the `-ENOMEM` paths, unknown-`cmd`, and
SCM_RIGHTS fd correctness under the cap.

**Why it matters:** remotely reachable control surface; a bug leaks fds or
wedges the device.

**The fix — extend `vsock_device_harness/`** (it already mocks socketpair /
sendmsg / recvmsg):
1. Feed 17 ctl connections; assert the 17th is dropped.
2. Feed a CONNECT the guest never RESPONSEs; advance the reaper clock; assert
   `-ETIMEDOUT` reply.
3. Idle ctl conn (connect, never send CONNECT); advance clock 30 s; assert reap.
4. Unknown `cmd`; assert clean rejection, no fd leak.
5. socketpair/fcntl/alloc failure → assert `-ENOMEM` reply (fault injection).

**Effort:** ~half session. **Payoff:** hardens the privileged host surface.

---

## GAP 3 — Linux guest interop (§4) (CLOSED)

Validated with Alpine 3.24.1's upstream drivers in both modern and legacy
transport modes.  The matrix covers bidirectional stream/SEQPACKET traffic,
credit churn and bulk checksums, isolated devices, and combined-device runs.

**Four specific risks this settled** (from the conformance review):
- The `NO_IMPLIED_STREAM` feature bit (bit 2) — ratified in virtio 1.4 but
  historically contested; confirm a real Linux kernel negotiates it correctly.
- Legacy config-space endianness assumption (fine on x86, unverified elsewhere).
- SEQPACKET (incl. the D1 large-record and EOR fixes) against Linux's own code.
- Legacy virtio-PCI binding: confirm the guest kernel has
  `CONFIG_VIRTIO_PCI_LEGACY` (mainstream x86 yes; stripped cloud kernels no).

**Validation executed from testplan §4:**
1. Host prereq: `pkg install edk2-bhyve` (UEFI firmware).
2. Boot an Alpine/Debian cloud image with a serial console (§4.1–4.3).
3. `modprobe vsock vmw_vsock_virtio_transport`; confirm attach + `/dev/vsock`.
4. Run §6 rows 1–6 with Linux as guest, both directions, S and SP:
   `socat - VSOCK-CONNECT:2:<port>` / `socat VSOCK-LISTEN:<port> -` and the
   python `AF_VSOCK` snippets. Compare byte-exact (sha256) for bulk.
5. Capture `BHYVE_VTVSOCK_DEBUG=1` during rows 3/4/9 to watch credit under load.

**Result:** independent Linux confirmation of the wire protocol, feature
negotiation, and legacy/modern driver binding.

---

## GAP 4 — device harness caps, malformed input, reaper timers (CLOSED)

Cheap additions to the existing `vsock_device_harness/`:
1. **Connection cap** — drive 257 OP_REQUESTs (`VTVSOCK_MAX_CONNS` = 256);
   assert the 257th RSTs and closing one frees a slot. (§6 row 9, host half.)
2. **Malformed TX drops** — 4 remaining cases (chain > `VTVSOCK_MAX_IOV`, null
   iov base, `paylen > VTVSOCK_MAX_PKT`, non-zero paylen on a control op);
   assert silent drop, no conn side-effects. (Only 1 of 5 is currently tested.)
3. **Reaper timers** — manipulate `created`/`close_time`/`stall_time` and invoke
   the reaper: CLOSING ≥ 8 s force-RST, CONNECTING ≥ 30 s `-ETIMEDOUT`, idle
   ctl-conn 30 s. (The D2 stall-probe path also wants a direct test.)
4. **Config-parse edges** — missing cid/path, `cid < 3`, `cid >= 0xffffffff`,
   non-directory path; and assert `cid == 0xfffffffe` is accepted (intended).

**Effort:** ~half session. **Payoff:** the DoS backstops (row 9) become tested.

---

## GAP 5 — ATF loopback SEQPACKET edges and teardown holes (CLOSED)

Small, high-value additions to `vsock_test.c` (loopback, already in CI):
1. **SEQPACKET exact-MAX boundary** — send exactly `sb_hiwat` bytes (must
   succeed, full recv) and that + 1 (must EMSGSIZE, conn survives). Only the
   far-over case (8K into 4K) is tested; the off-by-one edge is not.
2. **SEQPACKET SHUT_RDWR** — the teardown matrix has this hole (stream is
   covered, seqpacket is not).
3. **SEQPACKET peer-close → EOF + SIGPIPE** — stream has `peer_close_sigpipe`
   / `close_eof_and_epipe`; seqpacket has no equivalent.
4. **connect_timeout ERANGE** — set `tv_usec = 2000000`; assert ERANGE
   (`vsock_ctloutput` malformed-timeval path).
5. **SIOCOUTQ non-zero** — needs the RX harness (loopback runs no credit
   accounting); belongs in GAP 1.

**Effort:** ~2 hours. **Payoff:** closes the cheapest correctness holes.

---

## §6 matrix: automated vs still-aspirational

| Row | Scenario | Status |
|---|---|---|
| 1–4 | echo, bulk, credit churn | ✅ e2e + ATF |
| 5 | seqpacket 0/1 and local/peer-window boundaries | ✅ ATF + both direct harnesses + 200 KiB e2e both directions |
| 6 | MSG_EOR/partial records | ✅ device + guest RX harnesses + e2e |
| 7, 8 | dead host/guest port | ✅ e2e |
| 9 | ≥256 concurrent, excess refused, slots freed | ✅ host and guest harnesses |
| 10 | graceful close both directions | ✅ stream + remote SEQPACKET, both directions |
| 11 | abrupt peer kill | ✅ e2e, both directions + recovery |
| 12 | guest reboot with conns open | ✅ e2e, stream + seqpacket old-endpoint teardown and fresh reconnect |
| 13 | detach with blocked sender (≤1s wakeup) | ✅ direct transport harness, pthread-blocked full-ring sender |
| 14 | reserved-CID connects | ✅ guest-initiated e2e + bind-side harness |
| 15 | port 0 / auto-bind | ✅ ATF |
| 16 | CID_LOCAL isolation | ✅ guest RX harness |

---

## Completed roadmap

**Phase A — the guest RX harness (GAP 1).** Completed.  One unprivileged,
CI-able harness closes 11 behaviors including 3 that regression-guard the G1,
G4, and VNET/reset fixes.

**Phase B — Linux interop (GAP 3).** Completed with the Alpine matrix.

**Phase C — harness fill-in (GAP 2 + GAP 4).** Completed in the device harness.

**Phase D — ATF edges (GAP 5).** Completed.

**Remaining targeted work:** none in the §6 functional matrix.  VirtIO defines
credit windows rather than a universal SEQPACKET record maximum, so row 5 is
closed at the local receive limit and the remote peer-advertised `buf_alloc`
boundary.  Interrupt-vs-detach scheduling remains a kernel-runtime stress item
rather than an uncovered source interleaving.

**Lowest-priority (Tier 3, documented in REVIEW.md, likely leave alone):**
auto-bind port exhaustion, EMFILE/fd exhaustion, and the broad bhyve host-side
allocation-failure matrix.  Guest holding-queue overflow, bhyve pending-reply
overflow, undersized-ring attach, and representative guest attach/send
allocation failures are now covered by their direct transport/device
harnesses; the remaining cases need process-wide fault injection and are hard
to hit in practice.
