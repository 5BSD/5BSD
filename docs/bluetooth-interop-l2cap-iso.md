# L2CAP, EATT and isochronous channels: 5BSD against BlueZ, Zephyr and NimBLE

A second external-reference sweep, narrower and deeper than
`bluetooth-interop-comparison.md`. That document swept ATT, SMP, GAP and mesh
and found fourteen divergences; it explicitly left two areas alone, noting that
"LE ISO is not comparable" and that the ISO data header "was out of scope here
and deserves its own audit". A conformance audit subsequently put L2CAP at 23%
covered. This is the audit those two notes asked for.

Nothing in the code was changed while this was written; it is reconnaissance.

## Scope

Target is **Bluetooth 5.2 plus Connection Subrating**. Nothing is reported as a
gap because it is a 5.4 or 6.x feature this stack deliberately omits. Five
areas: enhanced credit-based flow control, EATT, L2CAP signalling and the LE
fixed channels, isochronous channels (CIS/CIG and BIS/BIG), and controller
buffer accounting.

## Reference implementations obtained

| Stack | Source | Snapshot commit | Role |
| --- | --- | --- | --- |
| BlueZ 5.87 | `git.kernel.org/pub/scm/bluetooth/bluez.git` | `92305dc06ab8a6d89af2dae1d725cc4d51462ad1` | the dominant Linux peer |
| Zephyr | `github.com/zephyrproject-rtos/zephyr` | `2665fcca3cced3aefb7202d6289991d8cc1dfcac` | PTS-qualified; the only reference with a full host-side EATT and ISO implementation |
| Apache NimBLE | `github.com/apache/mynewt-nimble` | `1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845` | a third independent reading; host **and** controller, which matters for ISO |

Adjudicating text: `/usr/src/bluetooth-specs/Core_Specification_6_3.txt`. Vol 3
Part A is L2CAP, Vol 3 Part G §5.3-§5.4 is EATT, Vol 4 Part E §7.8.97-§7.8.110
is the isochronous HCI, Vol 4 Part E §4 is HCI flow control.

**A reference limitation, stated up front.** BlueZ's L2CAP, its ECRED (enhanced
credit) state machine, its ISO socket and its HCI credit scheduler all live in
the **Linux kernel**, not in the bluez repository. `net/bluetooth/l2cap_core.c`,
`iso.c` and `hci_core.c` are not in the cloned tree and were verified absent.
For those three subsystems the bluez tree offers only decoders
(`monitor/l2cap.c`, `monitor/packet.c`), a PTS driver
(`tools/l2cap-tester.c`) and the `bthost` peer emulator (`tools/bthost.c`).
**No BlueZ behavioural citation is made for L2CAP signalling, ECFC credit
handling, or HCI buffer accounting.** Those areas are adjudicated from Zephyr,
NimBLE, `bthost` and the spec. Where BlueZ *is* cited — EATT bearer policy, BAP
QoS, retransmission defaults — it is from userspace code that is present.

## Classification key

Same as the previous document, with one addition.

- **OURS-WRONG** — the spec, or the unanimous practice of the references,
  contradicts us.
- **OURS-RIGHT-OTHERS-DIFFER** — we match the spec and at least one reference
  does not. Recorded so nobody "fixes" us towards the reference.
- **ECOSYSTEM-SPLIT** — the references disagree and the spec does not settle it.
- **AGREE** — checked, no divergence.
- **KERNEL-SIDE** — the behaviour is `sys/netgraph/bluetooth/`, not `blued`.
  This matters more here than in the previous sweep: **the overwhelming
  majority of the L2CAP findings below are kernel findings.** `blued` is a
  socket client; it never sees an L2CAP signalling PDU.

---

## Ranked findings

Ranked by interoperability impact against a real peer.

| # | Area | Finding | Class | Impact |
| --- | --- | --- | --- | --- |
| 1 | Fixed channels | ATT/SMP receive path hard-capped at 23 octets; the transmit path has the exemption, receive never got it | OURS-WRONG, KERNEL-SIDE | LE Secure Connections pairing cannot complete; every ATT PDU above 23 octets is dropped after a successful MTU exchange |
| 2 | EATT / ECFC | outgoing enhanced credit-based `connect()` can never complete — no `IDTYPE_ECBFC` case in the socket layer | OURS-WRONG (gap), KERNEL-SIDE | 5BSD can never open an EATT bearer as central; the entire `att_open_eatt()` path is dead |
| 3 | Buffers | ISO socket takes the controller's ISO packet count with no clamp or default; zero means the transmit loop never runs | OURS-WRONG, KERNEL-SIDE | all ISO transmit is silently mute — `send()` succeeds, nothing goes out |
| 4 | Buffers | LE Read Buffer Size v1 is never issued anywhere; `blued` issues v2 unconditionally and ungated | OURS-WRONG | on an LE-only or pre-5.2 controller, no LE data can be sent at all |
| 5 | Signalling | incoming Command Reject reason is passed through as the L2CA result; reason 0x0000 collides with success | OURS-WRONG, KERNEL-SIDE | a peer rejecting our request drives `soisconnected()` on a channel L2CAP has just freed |
| 6 | ECFC | credits are returned only when a whole SDU completes, never mid-SDU | OURS-WRONG, KERNEL-SIDE | credit deadlock against a peer using a small MPS; unique to us among all available references |
| 7 | ISO | a CIS request that times out leaves a permanent ghost stream; every later request on that handle is auto-rejected | OURS-WRONG | one slow accept and that CIS is dead for the life of the adapter |
| 8 | ECFC | any per-CID failure refuses the whole group; no partial success | OURS-WRONG, KERNEL-SIDE | a peer asking for five EATT bearers gets zero instead of the three we could host |
| 9 | EATT | `att_bearer::stale` is never cleared when a bearer slot is reused | OURS-WRONG | a recycled slot silently discards genuine responses, then fails the bearer |
| 10 | Buffers | SCO credits are debited but Synchronous Flow Control is never enabled, so they are never returned | OURS-WRONG, KERNEL-SIDE | SCO transmit stalls permanently after the pool drains (pre-existing FreeBSD defect) |
| 11 | EATT | indication confirmations are accepted from any bearer | OURS-WRONG | two unconfirmed indications outstanding on the fixed bearer; §3.3.2 violation |
| 12 | Signalling | connection-parameter supervision-timeout multiplier is 8 where the algebra gives 4 | OURS-WRONG, KERNEL-SIDE (false comment) | previously reported as #11 in the earlier sweep; still present |
| 13 | ECFC | reconfigure response 0x1A is parsed and then dropped; no upcall, no socket message | OURS-WRONG (gap), KERNEL-SIDE | reconfigure always reports success; the socket's MTU goes stale |
| 14 | EATT | no retry and no collision mitigation: one refusal permanently abandons EATT | OURS-WRONG (robustness) | a transient `0x0004` costs EATT for the life of the connection |
| 15 | EATT | a reconfigure never re-derives the per-bearer ATT_MTU | OURS-WRONG (gap) | a peer that grows its MTU mid-connection is size-checked against a stale value |
| 16 | ISO | `LE Set CIG Parameters` RTN is bounded at 0x1E, a bound that belongs to a different command | OURS-WRONG (false comment) | rejects host values the spec permits; see the determination below |
| 17 | EATT | blocking `recv()` on the event-loop thread, with a 30 s socket timeout | OURS-WRONG | one stale kevent on a reused fd stalls the whole daemon for 30 s |
| 18 | Signalling | Connection Parameter Update Request transmit arm is a `TBD` stub | OURS-WRONG (gap), KERNEL-SIDE | previously reported as #6; the substantive blocker, re-confirmed |
| 19 | Buffers | LE Read Buffer Size v2 completion notifies only the ACL hook, never the ISO hook | OURS-WRONG (latent), KERNEL-SIDE | makes finding 3 routine rather than exotic |
| 20 | EATT | EATT is attempted exactly once, at setup, with a hard-coded count of two | OURS-WRONG (gap) | no late open after deferred pairing, no top-up when the peer grants fewer |
| 21 | ISO | no client-visible event when a CIS or BIG goes away | OURS-WRONG (gap) | a client holding an ISO fd is never told the stream died |
| 22 | Signalling | identifier 0x00 accepted on receive and echoed in responses | OURS-WRONG, KERNEL-SIDE | PTS-visible conformance only |
| 23 | Buffers | zero-buffer fallback keys on the packet count but never on the packet length | OURS-WRONG (edge), KERNEL-SIDE | LE pool debited while fragmenting to the BR/EDR size |
| 24 | ECFC | one Source CID per connection request, so N bearers is N sequential transactions | OURS-WRONG (gap), KERNEL-SIDE | five times the signalling; widest possible collision window |
| 25 | EATT | notifications and indications never use an EATT bearer | OURS-WRONG (minor) | the server-to-client half of EATT multiplexing is unused |
| 26 | EATT | the client never writes the peer's Client Supported Features characteristic | OURS-WRONG (gap) | peer servers never learn we support EATT, Robust Caching or Multiple Notifications |
| 27 | Buffers | no controller-to-host flow control anywhere in the stack | ECOSYSTEM-SPLIT | spec-legal opt-out; Zephyr defaults it on for host-only builds |
| 28 | Buffers | ISO socket credit window is per-unit, not per-stream | ECOSYSTEM-SPLIT | head-of-line blocking across concurrent CISes |
| 29 | ECFC | no SPSM range validation; RFU values above 0x00FF accepted | OURS-WRONG (gap, minor), KERNEL-SIDE | low; but the header comment beside it would misdirect the fix |

---

## 1. Where the code actually is

Before anything else, because it changes who owns every finding above.

**All of L2CAP is kernel.** Signalling receive and dispatch, the ECFC state
machine, credit accounting, K-frame reassembly, the fixed-channel data path:
`sys/netgraph/bluetooth/l2cap/ng_l2cap_{evnt,ulpi,cmds,misc,llpi}.c` and
`sys/netgraph/bluetooth/socket/ng_btsocket_l2cap.c`. `blued` and `libble` are
socket clients — they `bind()` and `connect()` to CIDs 0x0004 and 0x0006, set
`SO_L2CAP_ECBFC` and `SO_L2CAP_IMTU`, and read and write records. They emit no
L2CAP signalling at all.

**All controller buffer accounting is kernel**, in
`sys/netgraph/bluetooth/hci/`. The netgraph HCI node does not issue the buffer
commands itself; it *snoops* the Command Complete events for them as they pass
up from the driver, and sets `unit->buffer.{acl,sco,le,iso}_*` from what it
sees. The actual issuers are `libexec/rc/rc.d/bluetooth` (BR/EDR Read Buffer
Size) and `blued` (LE Read Buffer Size v2). That indirect coupling is itself
finding 19 and part of finding 4.

**ISO is split.** Parameter validation, the HCI command encoders, the CIG/BIG
lifecycle and event handling are `blued` (`iso.c`, `ctl_iso.c`, `hci_misc.c`).
The ISO data path is kernel (`sys/netgraph/bluetooth/socket/ng_btsocket_iso.c`)
and is handed to the client as a file descriptor — `ISO_ST_HANDED_OFF`. So the
control plane is ours to get wrong, and the data plane is the kernel's.

**EATT sits on top of the kernel ECFC transport**, which is why finding 2 —
a kernel bug — is what makes the daemon's whole central-role EATT path
unreachable, and why several daemon-side EATT findings below are today only
reachable through the peripheral accept path.

---

## 2. Enhanced credit-based flow control

The kernel genuinely implements ECFC. Codes 0x17/0x18 are parsed and generated
(`ng_l2cap_evnt.c:1330-1440`, `:1600-1730`), 0x19/0x1A reconfigure exists
(`ng_l2cap_ulpi.c:548-660`), K-frame credit accounting exists
(`ng_l2cap_ulpi.c:1427-1600`), and the acceptor side aggregates a multi-CID
group correctly (`ng_l2cap_ulpi.c:342-435`). The PDU layouts were compared
field by field against Zephyr, NimBLE and the `bthost` emulator and are
byte-identical.

This is worth saying plainly because the previous sweep's conclusion — that our
ECFC support was thin — understates it. The protocol machinery is there. What
is broken is the socket-layer join, the credit *timing*, and the partial-success
case.

### F2.1 — Outbound ECFC `connect()` can never complete [OURS-WRONG, KERNEL-SIDE, CRITICAL]

`ng_btsocket_l2cap_process_l2ca_con_req_rsp()`
(`sys/netgraph/bluetooth/socket/ng_btsocket_l2cap.c:489-542`) dispatches on
`pcb->idtype` and has exactly three arms: `IDTYPE_ATT`/`IDTYPE_SMP` at `:490`,
`IDTYPE_LE` at `:506`, and everything else. `IDTYPE_ECBFC` — value 4,
`include/ng_l2cap.h:446` — is set by `SO_L2CAP_ECBFC` (`:2548-2561`) and
preserved by `connect()` (`:2376-2381`), and it lands in the `else`:

```c
	} else {
		/*
		 * Channel is now open, so update local channel ID and
		 * start configuration process. ...
		 */
		pcb->cid = op->lcid;
		pcb->encryption = op->encryption;
		error = ng_btsocket_l2cap_send_l2ca_cfg_req(pcb);
		...
		pcb->state = NG_BTSOCKET_L2CAP_CONFIGURING;
```

Credit-based channels have **no configuration phase** — that is the point of
the mode. The `L2CA_ConfigReq` that gets sent cannot even be resolved:
`ng_l2cap_l2ca_cfg_req()` (`ng_l2cap_ulpi.c:823`) looks the channel up as
`IDTYPE_BREDR`, and `ng_l2cap_chan_by_scid()` (`ng_l2cap_misc.c:427-435`) skips
ECFC-on-LE channels for that idtype, so it returns `ENOENT`. The pcb sits in
`NG_BTSOCKET_L2CAP_CONFIGURING` until the socket timeout fires.
`soisconnected()` is never called.

The comparison is stark: the `IDTYPE_LE` arm immediately above it does exactly
the right thing — takes `op->imtu`/`op->omtu` from L2CAP, goes straight to
`OPEN`, calls `soisconnected()`. ECFC needs the same three lines and does not
have them.

The **acceptor** path is fine.
`ng_btsocket_l2cap_process_l2ca_con_ind()` takes the L2CAP-supplied idtype
(`:717-718`), the negotiated MTUs (`:738-741`), and puts LE channels straight
into `OPEN` (`:777-786`). So an inbound EATT bearer from a BlueZ or Zephyr
central works. Outbound does not.

Separately, ECFC is unreachable in both directions on BR/EDR: `:2366-2403`
overwrites `pcb->idtype` and `:775-793` never opens a non-LE accepted socket.
Table 4.2 (spec line 52098) permits 0x17 on CID 0x0001 as well as 0x0005.

**Consequence:** `att_open_eatt()` (`att.c:1878-1926`) → `ble_ecbfc_connect()`
(`hci_conn.c:1185-1290`) is our only outbound EATT path and our production path
in the central role. It cannot succeed against any real peer.

### F2.2 — Credits are returned only on SDU completion [OURS-WRONG, KERNEL-SIDE]

`ng_l2cap_ulpi.c` replenishes credits at the label `le_coc_sdu_complete:`
(`:1574` onward). Both of the "more K-frames expected" paths return without
granting anything — `:1545` in the first-frame arm and `:1571` in the
continuation arm:

```c
			/* More K-frames expected */
			return (0);
	...
			if (ch->rx_sdu_got < ch->rx_sdu_len)
				return (0); /* more to come */
```

§10.2 (spec lines 58131-58136) says a peer "may return credits for an L2CAP
channel at any time". It does not permit withholding them until an SDU
completes. Every available reference grants earlier:

- Zephyr grants, on the *first* K-frame, credits sized for the whole remaining
  SDU — `DIV_ROUND_UP(remaining, mps)` (`host/l2cap.c:2799-2810`) — and tops up
  mid-SDU (`:2657-2671`).
- NimBLE grants one credit per K-frame consumed, mid-SDU included
  (`ble_l2cap_coc.c:302-308`).
- `bthost` grants one per K-frame (`tools/bthost.c:3159-3182`).

**Deadlock condition:** `ceil(sdu_len / peer_mps) > credits_granted`. We grant
65 initial credits (`ng_l2cap_var.h:244-246`). At the minimum legal MPS of 64,
any SDU above 65 × 64 = 4160 octets deadlocks permanently — we wait for the
rest of the SDU, the peer waits for credits. Not reachable for EATT itself,
where the ATT_MTU ceiling keeps SDUs small, but reachable for any other
credit-based profile channel and for any peer that negotiates a small MPS.

### F2.3 — Credits decoupled from socket buffer space, and a false comment [OURS-WRONG, KERNEL-SIDE]

Credits are replenished at reassembly time, in L2CAP, with no reference to
`sbspace()`. The SDU is then dropped at `ng_btsocket_l2cap.c:1674` if the
socket receive queue is full, under this comment:

```c
			/*
			 * This is really bad. Receive queue on socket does
			 * not have enough space for the packet. We do not
			 * have any other choice but drop the packet. L2CAP
			 * does not provide any flow control.
			 */
```

"L2CAP does not provide any flow control" is true of Basic mode and false of
§10.2, which is the mode the channel is in. The credit scheme exists precisely
so that this drop never has to happen. Zephyr grants from
`bt_l2cap_chan_recv_complete()` (`host/l2cap.c:2580`) and NimBLE from
`ble_l2cap_coc_recv_ready()` (`ble_l2cap_coc.c:649`) — both application-driven,
both making credits a proxy for real buffer space. Ours is a lossless channel
that silently loses data.

### F2.4 — No partial success, and the comment that justifies it is wrong [OURS-WRONG, KERNEL-SIDE]

`ng_l2cap_evnt.c:1382-1443` refuses the entire group if any single CID cannot be
served, and `ng_l2cap_ulpi.c:388-400` does the same on the response side. The
justification at `ng_l2cap_evnt.c:1385-1389` states:

> §4.25: if the device cannot create ALL requested channels, it must refuse ALL
> of them.

The specification says the opposite. Table 4.17 (spec lines 53245-53257) has
three result codes whose own wording is "**Some** connections refused" — 0x0004,
0x0009, 0x000A — and §4.26 (spec lines 53276-53281) is explicit about the
per-CID encoding:

> "The order of the Destination CIDs shall correspond to the order of the Source
> IDs in the corresponding L2CAP_CREDIT_BASED_CONNECTION_REQ packet. If a
> Destination CID is non-zero, the channel was established. If a Destination CID
> is 0x0000, the channel was not established."

Zephyr (`host/l2cap.c:1681-1705`) and NimBLE (`ble_l2cap_sig.c:1006-1046`) both
fill `dcid[i] = 0` per refused CID and answer 0x0004. A BlueZ central asking for
five EATT bearers against us gets zero rather than the three we could host —
and since finding F2.1 means we cannot initiate, the inbound direction is the
only EATT we have.

### F2.5 — Reconfigure response is a black hole [OURS-WRONG (gap), KERNEL-SIDE]

Code 0x1A is parsed (`ng_l2cap_evnt.c:1955-2033`) and then nothing happens:
there is no L2CA upcall and no corresponding socket-layer message case
(`ng_btsocket_l2cap.c:1862-1900`). `ble_ecbfc_reconfig()` therefore always
reports success, and `pcb->imtu` goes stale, so post-reconfigure SDUs are
dropped by the size check at `ng_btsocket_l2cap.c:1659`. This is the transport
half of EATT finding F3.6 below.

### F2.6 — One Source CID per request [OURS-WRONG (gap), KERNEL-SIDE]

`ng_l2cap_ulpi.c:151-165` hard-codes `scids[1]` and `ncids = 1`, and the
response handler rejects `ncids != 1` (`ng_l2cap_evnt.c:1640`). §4.25 exists to
let one transaction create up to five channels; we use five transactions. Both
BlueZ (`gatt-client.c:2362`, with `BT_DEFER_SETUP` batching) and Zephyr
(`host/att.c:3766`) batch, specifically to keep the §5.4 collision window
narrow. Ours is the widest possible.

### F2.7 — `SO_L2CAP_IMTU` is ignored on credit-based channels [KERNEL-SIDE]

`ng_l2cap_ulpi.c:154-157` and `ng_l2cap_evnt.c:874-878` hard-code
`imtu = NG_L2CAP_LE_COC_LOCAL_MTU` (512), `mps = 247`, `credits = 65`
(`ng_l2cap_var.h:244-246`). `ble_ecbfc_connect()`'s `SO_L2CAP_IMTU` setsockopt
(`hci_conn.c:1243-1246`) has no wire effect. The daemon cannot choose its own
bearer MTU.

### F2.8 — SPSM range not validated, and a third false comment [OURS-WRONG (gap, minor), KERNEL-SIDE]

`ng_l2cap_evnt.c:1320` accepts any SPSM, including the RFU range above 0x00FF.
The comment at `include/ng_l2cap.h:111`, sitting beside `NG_L2CAP_PSM_EATT`,
describes the ranges as "0x0001-0x007F fixed, 0x0080-0x00FF reserved,
0x0100-0xFFFF dynamic". Table 4.15 (spec lines 52995-53007) says
0x0080-0x00FF is **dynamic** and everything above 0x00FF is **RFU** — the
comment has the two halves backwards. Low impact on its own; recorded because
it would send whoever fixes the validation in the wrong direction.

### Checked and clean

Recorded so this ground is not re-ploughed. All PDU layouts byte-identical to
all three references. CID list length 2-10 octets and even, at most 5. MTU ≥ 64
and MPS in 64-65533 both enforced. Initial credits of zero rejected (NimBLE does
not reject them). LE-U SCID ceiling 0x007F and the LE CID allocator. Codes
0x17-0x1A routed on both 0x0001 and 0x0005 per Table 4.2. The §4.26 duplicate
Destination CID rule — both channels made unusable. **All three §3.4.3 mandatory
disconnects** (SDU length above MTU, K-frame above MPS, payload sum above SDU
length); we check the over-run on the *first* frame too, which is stricter than
both `bthost` and NimBLE. Zero-credit indications ignored. Credit count above
65535 produces a real Disconnection Request. A K-frame arriving at zero credits
disconnects (NimBLE does not). The reconfigure DCID direction — the sender's own
CIDs — correct on both send and receive. MTU-no-reduce and
MPS-no-reduce-when-more-than-one-channel both enforced. RTX timers armed for
0x17 and 0x19. `rx_sdu` and `tx_sdu_pending` freed on teardown.

---

## 3. EATT

### F3.1 — Nothing works as initiator

See F2.1. `att_open_eatt()` cannot succeed. Everything else in this section is
therefore, today, reachable only through the peripheral accept path
(`blued_eatt_listen()`/`blued_eatt_accept()`,
`blued_peripheral.c:1658-1795`) — but every one of them becomes live the moment
F2.1 is fixed, which is why they are reported rather than deferred.

### F3.2 — `att_bearer::stale` survives slot reuse [OURS-WRONG]

`struct att_bearer::stale` (`att.h:150-153`) counts responses to abandoned
transactions that must be discarded (`att_bearer_stale_mark()` /
`att_bearer_stale_consume()`, `att.c:509-556`). But
`att_eatt_remove_bearer()` (`att.c:2050-2078`) clears only three fields on the
vacated tail slot:

```c
	ac->eatt[ac->eatt_count].fd = -1;
	ac->eatt[ac->eatt_count].active = false;
	ac->eatt[ac->eatt_count].pending = 0;
```

and `att_eatt_add_bearer()` (`att.c:1991-1998`) writes only `fd`, `active`,
`pending` and `mtu` — never `stale`. `att_close_eatt()` (`att.c:2080-2097`) is
the same. A bearer that had a caller-timeout abandonment (`stale > 0`) and was
then removed leaves a phantom count in the slot; the **next** bearer into that
slot inherits it and `att_request()` silently discards the first N genuine
responses on the new bearer (`att.c:889-898`), burning `max_skip` and finally
failing the bearer with `EBADMSG`. The trigger is ordinary: op timeout, bearer
churn, EATT re-open.

This is the second defect this stack has had in EATT bearer release. The
pattern is the same both times — a per-bearer field that the add and remove
paths do not agree on.

### F3.3 — Indication confirmations accepted from any bearer [OURS-WRONG]

Indication state is per *connection*: `ind_pending`, `ind_handle`,
`ind_deadline` (`att.h:273-289`). Indications go out on the fixed bearer, but
`ATT_OP_HANDLE_CFM` is accepted from any bearer —
`att_server_dispatch.c:2497-2520` never compares `bearer_fd` against the bearer
the indication left on, and `blued_event.c:1918-1935` documents this as
intended.

Vol 3 Part F §3.3.2 (spec lines 69702-69704) scopes indication flow control to
"the same ATT bearer", and §3.3.3 (line 69751) forbids splitting a transaction
across bearers. A peer can confirm on an EATT bearer an indication we sent on
CID 0x0004, clearing `ind_pending` early and letting us emit a second
indication while the first is still unconfirmed.

### F3.4 — No retry, no collision mitigation [OURS-WRONG (robustness)]

`att_open_eatt()` (`att.c:1904-1909`) logs and returns 0 on a refusal. A single
`0x0004 Some connections refused – insufficient resources` — the *expected*
outcome of a simultaneous-open collision, and the case §5.4 exists to describe —
permanently abandons EATT for the life of the connection.

Zephyr implements §5.4 verbatim (`host/att.c:3605-3679`): the 100 ms peripheral
floor, the `2 × (connPeripheralLatency + 1) × connInterval` alternative, and a
retry of just the missing channels. BlueZ re-drives on the next
`gatt_client_ready`. We are not *violating* the §5.4 "shall" — it binds a
retrying peripheral, and we never retry — but we also never recover.

Related: we do not drop an inbound bearer while our own request is outstanding,
so a peer that also initiates gets both directions accepted, where BlueZ
suppresses one.

### F3.5 — One-shot at setup, hard-coded count of two [OURS-WRONG (gap)]

EATT is attempted exactly once, in the central connection-setup thread, for a
hard-coded 2 bearers (`blued_central.c:781`). `ATT_MAX_EATT_BEARERS` is 5
(`att.h:113`), matching §4.25's ceiling, but the request count is not
configurable — `config.c:503` exposes only a boolean. If encryption completes
later (peer-initiated pairing, deferred bonding), nothing re-attempts; the
encryption-change handler only ever tears down (`blued_event.c:1353-1395`). And
when the peer grants fewer bearers than requested, we never top up.

Counts across the ecosystem: BlueZ default 1 (EATT off unless configured),
NimBLE exactly 1, Zephyr `CONFIG_BT_EATT_MAX` default 3 with range 1-16. The
count itself is **ECOSYSTEM-SPLIT** — the spec constrains only the per-request
maximum of five. The gap is the absence of configurability and top-up.

### F3.6 — Reconfigure never re-derives the per-bearer MTU [OURS-WRONG (gap)]

Vol 3 Part G §5.3.1 (spec lines 74807-74811) binds the ATT_MTU to the values
from the connection request and response "or the latest
L2CAP_CREDIT_BASED_RECONFIGURE_REQ packets". The kernel implements 0x19/0x1A
and `ble_ecbfc_reconfig()` exists (`hci_util.h:644`), but nothing re-reads
`SO_L2CAP_IMTU`/`SO_L2CAP_OMTU` into `ac->eatt[i].mtu` afterwards. Zephyr does
(`host/att.c:3448-3455`). Compounded by F2.5, where the kernel does not
surface the reconfigure response at all.

This is the second defect this stack has had in per-bearer MTU.

### F3.7 — Blocking `recv()` on the event-loop thread [OURS-WRONG]

`att_eatt_add_bearer()` sets `SO_RCVTIMEO` to 30 s on every bearer
(`att.c:1985-1989`). The peripheral read path runs on the kqueue thread and
calls `att_recv_record()` with no `MSG_DONTWAIT` (`blued_event.c:1905-1913`),
as does the central path (`blued_central.c:2322` → `att_recv_bearer()`,
`att.c:1799-1823`). A readable event that turns out to carry no record blocks
the entire daemon for 30 seconds.

The concrete way to produce one is fd reuse: `att_eatt_remove_bearer()` and
`att_close_eatt()` close bearer fds from a GATT worker while an event for the
old fd is already in the current `kevent()` batch, and `blued_eatt_accept()` can
hand the same fd number to a new bearer under the same `conn` udata
(`blued_peripheral.c:1734-1786`, `conn.c:472-484`). The demux does look the fd
up in the bearer array first (`blued_event.c:1884-1892`), which closes the
wrong-connection case but not the same-fd-new-bearer case.

### F3.8 — Notifications and indications never use an EATT bearer [OURS-WRONG, minor]

`att_server_notify.c` always sends on `ac->fd`. BlueZ prefers an EATT channel
for notifications (`src/shared/att.c:1288`). The server-to-client half of the
multiplexing benefit is simply unused.

### F3.9 — The client never advertises its own features [OURS-WRONG (gap)]

We *serve* the Client Supported Features (0x2B29) and Server Supported Features
(0x2B3A) characteristics correctly — the SSF byte 0x01 and the CSF bit
assignments in `blued_peripheral.c:1415-1440` check out against spec lines
75222 and 75076. But nothing in `blued_central.c` or `gatt.c` ever **writes**
the peer's CSF, so a peer server never learns we support Enhanced ATT bearers,
Robust Caching or Multiple Handle Value Notifications. BlueZ writes it
(`src/device.c:6326-6331`). Not required to *establish* EATT on LE — §6.2.1
(spec line 74896) explicitly disclaims the check — but it suppresses
multi-notifications from conformant peers.

### F3.10 — Cleanup nits [OURS-WRONG, minor]

(a) `att_bearers_lock()` is a raw CAS spin (`att.c:81-101`) held across
`close(2)` of up to five sockets in `att_close_eatt()` (`att.c:2080-2097`).
(b) `blued_conn_destroy()` (`conn.c:308-330`) tears the bearer array down inline
rather than via `att_close_eatt()`, and without the bearer lock — safe today
only because it runs at the last unref. (c) `blued_eatt_accept()` takes
`att_sec_lock` for the add but not for the remove rollback
(`blued_peripheral.c:1770-1786`). (d) `att_eatt_accept()` (`att.c:2010-2040`)
attaches a bearer **without** registering it with the kqueue, so a bearer
attached through it would never be read; it appears unused but is exported
(`att.h:423`). (e) `att_select_bearer_for_pdu()` reports `EPIPE` whenever
`ac->failed`, even when live EATT bearers exist and are merely busy
(`att.c:155-158`), turning a retryable `EBUSY` into a dead connection.

**No double-close was found.** Every `att_eatt_add_bearer()` failure path leaves
fd ownership with the caller as documented (`att.c:1950-1956`), both callers
close exactly once (`att.c:1911-1917`, `blued_peripheral.c:1773-1779`), and the
`IPC_L2CAP_EATT_OPEN` rollback (`ctl.c:5999-6012`) unregisters `[0, i)` and then
closes — correct.

### Where we are ahead

Recorded so nobody "aligns" us with a reference and regresses us.

- **Per-bearer ATT_MTU = `min(imtu, omtu)`** (`att.c:1975`) is exactly what
  §5.3.1 says (spec lines 74807-74811). Zephyr agrees
  (`bt_att_mtu()`, `host/att.c:140`). **BlueZ uses `omtu` alone** and would
  over-size its receive buffer when `imtu < omtu`. **OURS-RIGHT-OTHERS-DIFFER.**
- **The 64-octet floor is enforced** (`att.c:1971`); BlueZ only enforces 23.
- **Exchange MTU is excluded on EATT in both directions** (`att.c:714-716`,
  `att_server_dispatch.c:2407-2412`) and we answer `Request Not Supported`.
  NimBLE (`ble_eatt.c:271-285`) and Zephyr **disconnect the channel** instead.
  The spec (Vol 3 Part G §4.2, lines 73160-73164) mandates the exclusion but
  not the reaction; answering an error is the interoperable choice.
  **ECOSYSTEM-SPLIT, ours preferable.**
- **Bearer-scoped failure.** `att_bearer_fail()` (`att.c:641-660`) kills one
  bearer, not the link, and `att_request_expired()` (`att.c:620-635`)
  distinguishes the 30 s protocol ceiling from a caller-supplied op timeout.
  That is §3.3.3 and §4.14 implemented properly.
- **Write-Command bearer pinning** (`att.c:172-272`) is a real ordering property
  none of the three references has.
- **Encryption preconditions enforced in three independent places**, including
  the kernel (`ng_l2cap_evnt.c:1330-1338`) — the strongest of the four stacks,
  and the comment claiming it (`blued_event.c:1354-1356`) is one of the few in
  this area that checks out.

---

## 4. L2CAP signalling and the fixed channels

### F4.1 — Inbound ATT and SMP PDUs are dropped above 23 octets [OURS-WRONG, KERNEL-SIDE, CRITICAL]

The highest-impact finding in this document, and it is four lines apart from its
own fix.

On connect confirmation for an ATT or SMP channel the socket layer overwrites
the MTUs with the LE minimum (`ng_btsocket_l2cap.c:491-496`):

```c
		if((pcb->idtype == NG_L2CAP_L2CA_IDTYPE_ATT)||
		   (pcb->idtype == NG_L2CAP_L2CA_IDTYPE_SMP)){
			pcb->encryption = op->encryption;
			pcb->cid = op->lcid;
			/* LE fixed channels use 23-byte default MTU */
			pcb->imtu = pcb->omtu = NG_L2CAP_MTU_LE_MINIMUM;
```

The accept path does the same (`:734-737`). `SO_L2CAP_IMTU` can only be set
while the pcb is `CLOSED` (`:2589-2596`), so a value set before `connect()` is
clobbered here and cannot be restored; `blued` does not set it on the fixed
sockets anyway. The receive path then hard-drops anything larger (`:1657-1670`):

```c
		/* Check packet size against socket's incoming MTU */
		if (hdr->length > pcb->imtu) {
			... goto drop;
```

reached for ATT and SMP because the guard at `:1628-1631` explicitly includes
both idtypes.

And the **transmit** path already has the exemption, with a comment that states
the correct reason (`:2853-2862`):

```c
	/*
	 * Check packet size against outgoing MTU.  Skip for LE fixed
	 * channels (ATT/SMP) — the upper protocol manages its own MTU
	 * via ATT Exchange MTU and may negotiate larger than the
	 * initial 23-byte default.
	 */
	if (pcb->idtype != NG_L2CAP_L2CA_IDTYPE_ATT &&
	    pcb->idtype != NG_L2CAP_L2CA_IDTYPE_SMP &&
	    m->m_pkthdr.len > pcb->omtu) {
```

The symmetric exemption was never added on receive. This is the
false-justification pattern in its purest form: the comment is *right* — 23 is
an initial default, the upper layer owns the real MTU — and the fix it justifies
was applied to one direction only.

Consequences:

- Every inbound ATT PDU above 23 octets is discarded after a successful
  Exchange MTU, and `blued` negotiates up to 517 (`att.c:1017`). Long reads,
  long notifications and `ATT_READ_BY_GROUP_TYPE_RSP` from a real peer vanish.
  The upper layer sees a transaction timeout, not an error.
- SMP is worse. Vol 3 Part H Table 3.2 (spec lines 77963-77970) sets the SMP
  channel MTU to **65** when LE Secure Connections is supported, and
  `SMP_PAIRING_PUBLIC_KEY` is 65 octets — `blued` sizes its buffer accordingly
  (`smp.c:931`, `uint8_t pdu[65]`). At `imtu == 23` the peer's public key is
  dropped by the kernel and **LE Secure Connections pairing cannot complete over
  a real radio.**

Neither Zephyr nor NimBLE imposes an L2CAP-level receive cap on the ATT/SMP
fixed channels.

This will not show up in unit or virtual-HCI tests that inject at the ATT or SMP
layer, because those bypass `ng_btsocket_l2cap.c` entirely. The signature on a
real controller is `"L2CAP data packet too big ... imtu=23"` in the L2CAP debug
log.

### F4.2 — Incoming Command Reject reason is laundered into a result [OURS-WRONG, KERNEL-SIDE]

The reason code from an inbound `L2CAP_COMMAND_REJECT_RSP` is passed straight
through into the L2CA *result* field, which is a different code space. Reason
0x0000, "Command not understood" (Table 4.3, spec line 52169), is numerically
`NG_L2CAP_SUCCESS`. A peer that rejects our connection request with the most
common reason code drives `soisconnected()` on a channel L2CAP has just freed.

### F4.3 — Supervision-timeout multiplier is twice the legal bound [OURS-WRONG, KERNEL-SIDE, false comment]

Already reported as #11 in the previous sweep and still present; re-confirmed
here with the arithmetic spelled out, because the comment does its own algebra
and gets it wrong (`ng_l2cap_evnt.c:719-733`):

```c
	 * Units: timeout in 10ms, interval in 1.25ms.
	 * Convert: timeout*10ms > (1+latency) * interval*1.25ms * 2
	 *       => timeout*8 > (1+latency) * interval_max
```

`timeout × 10 > (1 + latency) × interval × 2.5` divides to
`timeout × 4 > (1 + latency) × interval`, not `× 8`. The constant in the code
matches the comment's wrong conclusion (`:734`), so we ACCEPT parameter sets
with a supervision timeout half the required length, tell the peer 0x0000
Accepted, and the subsequent HCI LE Connection Update fails. The peer sees an
acceptance and no update. Zephyr uses the factor 4.

Spec: Vol 6 Part B (line 140255) and its HCI restatement in Vol 4 Part E (line
112864). Under Connection Subrating the Vol 6 form additionally multiplies by
`connSubrateFactor`, which is 1 unless subrating is in use.

### F4.4 — Connection Parameter Update Request cannot be sent [OURS-WRONG (gap), KERNEL-SIDE]

`ng_l2cap_cmds.c:617-621` is still
`case NG_L2CAP_CMD_PARAM_UPDATE_REQUEST: /* TBD -- for now, clean up the unsent
command */`. Reported as #6 in the previous sweep; re-confirmed unchanged. A
5BSD peripheral has no L2CAP fallback when the central's controller lacks the
connection-parameter-request feature.

### F4.5 — Identifier 0x00 accepted and echoed [OURS-WRONG, KERNEL-SIDE, low]

Spec line 52125: "Signaling identifier 0x00 is an invalid identifier and shall
never be used in any command." We do not reject it on receive and we echo it in
the response. Zephyr checks on both channels. PTS-visible only; a real peer will
not send it.

### F4.6 — Command Reject in reply to identified responses [ECOSYSTEM-SPLIT, low]

We reject BR/EDR `CONNECTION_RSP`/`CONFIG_RSP` arriving unexpectedly, and BR
response codes arriving on LE. Spec line 52140 says reject packets "**should
not** be sent in response to an identified response packet" — a SHOULD. Zephyr
agrees with us; NimBLE no-ops them. No action needed.

### Checked and clean

The per-channel command sets match Table 4.2 (spec lines 52078-52102)
cell-for-cell in both dispatchers (`ng_l2cap_evnt.c:466-471`, `:521-533`) —
better than NimBLE. Unknown codes produce reason 0x0000 on both channels
(`:497-506`, `:648-661`). Malformed fixed-length commands also produce 0x0000
(`ng_l2cap_validate_fixed_cmd_len`, `:182-202`), matching the
"not correctly formed" list at line 52011; neither Zephyr nor NimBLE rejects
here, they silently drop — **OURS-RIGHT-OTHERS-DIFFER**. The oversized-C-frame
reject uses the first *request's* identifier and silently discards
response-only frames (spec lines 52143-52148) — **neither oracle implements
this**. The Invalid-CID reason-data ordering is correct at all four call sites
including the null-CID substitution, and the long comment claiming it
(`ng_l2cap_cmds.h:74-82`) checks out against spec lines 52184-52190. Identifier
allocation correctly skips 0 on wrap. The one-command-per-LE-C-frame rule is
enforced. Truncated or malformed B-frames on ATT/SMP are discarded without
tearing down the link, which is what line 51866 requires. Codes 0x14-0x1A are
all dispatched on both signalling channels. RTX 60 s and ERTX 300 s are the
maxima of the legal ranges (spec lines 54751-54810), so spec-legal, though a
dead peer costs a full minute. ACL-U MTUsig pinned at the 48-octet Table 4.1
floor, which Zephyr also does.

Five more suspect comments in this area were opened and found **correct**: the
Extended Features bit-7-not-bit-3 comment (`ng_l2cap_evnt.c:2959-2965`), the
MTUsig-48 justification (`:229-234`), the Table 4.2 and one-command-per-LE-frame
comments (`:466-471`, `:521-533`), the Connection Parameter Update direction
gate (`:681-691`), and the non-obvious claim that `CREDIT_RECONFIG_REQ` must
stay PENDING with an RTX timer (`ng_l2cap_cmds.c:524-537`).

---

## 5. Isochronous channels

The previous sweep declined this area on the grounds that "our ISO is
control-plane only and hands the data socket to the client". That is still true
of the data path, but the control plane is large, wire-visible and worth
auditing — it issues fourteen HCI commands and consumes six LE meta events.

**And the headline is that the control plane is good.** Parameter validation in
`hci_misc.c` is field-by-field against §7.8.97, §7.8.103 and §7.8.106 and is
**more thorough than any of the three references**. Zephyr validates a subset
in the host and the rest in its own controller; NimBLE has no CIG support at all
in the host (only BIG), and validates LE Create BIG in the controller; BlueZ
validates almost nothing, passing QoS through to the kernel. Everything below
should be read against that baseline.

### The retransmission-number bound — SETTLED

This was recorded as an open question: our code accepts RTN up to 0x1E for
`LE Set CIG Parameters`, and the comment justifying it
(`ctl_iso.c:105-121`) says the bound "could NOT be settled from in-tree
sources", that "no in-tree spec table covers it", and keeps 0x1E as "the
tightest bound we can defend without the spec text".

**It is settled, three ways, and the answer is that 0x1E is wrong.**

*The spec text is in tree.* `Core_Specification_6_3.txt` has the §7.8.97 command
parameter tables. `RTN_C_To_P[i]` and `RTN_P_To_C[i]` (lines 121221-121232) read:

> | Value | Parameter Description |
> | --- | --- |
> | `0xXX` | Number of times every CIS Data PDU should be retransmitted from the Central to the Peripheral |

There is no `0x00 to 0xNN` row and no "All other values / Reserved for future
use" row. Every other bounded parameter in the *same command* has one — CIG_ID
`0x00 to 0xEF` + RFU, SDU_Interval `0x0000FF to 0x0FFFFF` + RFU, Worst_Case_SCA
`0x00 to 0x07` + RFU, Packing, Framing, Max_Transport_Latency
`0x0005 to 0x0FA0` + RFU, CIS_Count `0x00 to 0x1F` + RFU (line 121174), CIS_ID,
Max_SDU `0x0000 to 0x0FFF`. `0xXX` is this specification's notation for a field
with no reserved values. **CIG RTN is a full octet, 0x00 to 0xFF.**

The descriptive text agrees that it is advisory, not an encoding:

> "this parameter is a recommendation to the Controller which the Controller may
> ignore."

*0x1E belongs to a different command.* §7.8.103 `LE Create BIG`, RTN
(lines 122174-122178):

> | Value | Parameter Description |
> | --- | --- |
> | `0x00 to 0x1E` | The number of times that every BIS Data PDU should be retransmitted. |
> | All other values | Reserved for future use |

*The references draw exactly this distinction.* Zephyr has two separately named
macros (`include/zephyr/bluetooth/iso.h:135-142`):

```c
/** Maximum connected ISO retransmission value (255) */
#define BT_ISO_CONNECTED_RTN_MAX    0xFF
/** Maximum broadcast ISO retransmission value (30) */
#define BT_ISO_BROADCAST_RTN_MAX    0x1E
```

and applies the check **only when the channel is broadcast**
(`subsys/bluetooth/host/iso.c:1055-1059`); the unicast/CIG path
(`:1736`, `:1741`, `valid_cig_param()` at `:2061`) performs no RTN range check
at all. NimBLE's only RTN bound is `IN_RANGE(cmd->rtn, 0x00, 0x1e)` in
`nimble/controller/src/ble_ll_iso_big.c:1281` — the LE Create BIG handler.
BlueZ applies no RTN bound anywhere and uses small unicast defaults
(`src/shared/bap.c:384,391` rtn = 2; `:1041-1042` defaults an unset rtn to
0x05).

**Determination.** `LE Set CIG Parameters` RTN is 0x00-0xFF.
`LE Create BIG` RTN is 0x00-0x1E. We apply the BIG bound to the CIG command in
two places — `ctl_iso.c:122-126` and `hci_misc.c:828-836` — and reject legal
host values 0x1F-0xFF.

**Class: OURS-WRONG (validation too strict), with a false comment.** The
practical impact is low: RTN is advisory, and real LE Audio configurations use
values in the range 2-13. But the comment is wrong on a checkable fact — the
spec table it says does not exist is in the tree it is describing — and its
"tightest bound we can defend" reasoning produced a bound with no basis. This is
the seventh comment in this stack found to contradict its own cited source, and
it is the one the brief flagged: an isochronous parameter bound justified by
pointing at an unrelated command. Note that a *previous* version of this comment
justified 0x1E by naming LE Create BIG directly; that was caught and the
justification was replaced, but the value was kept. The value was the defect.

### F5.1 — A timed-out CIS request leaves a permanent ghost [OURS-WRONG]

The peripheral CIS path leaks, and the leak is self-perpetuating.

`iso_on_cis_request()` (`iso.c:1101-1148`) allocates a stream in
`ISO_ST_REQUESTED` and notifies the client. Vol 4 Part E §7.7.65.26 (spec lines
107805-107812) is explicit about what happens if the client does not answer:

> "When the Host receives this event it shall respond with either an
> HCI_LE_Accept_CIS_Request command or an HCI_LE_Reject_CIS_Request command
> before the timer Connection_Accept_Timeout expires. If it does not, the
> Controller shall reject the request and generate an HCI_LE_CIS_Established
> event with the status Connection Accept Timeout Exceeded (0x10)."

That event arrives. `iso_on_cis_established()` (`iso.c:1018-1035`) checks
`s->state != ISO_ST_CREATING` — and `ISO_ST_REQUESTED` is not `ISO_ST_CREATING`,
because only `blued_iso_cis_accept()` (`iso.c:570`) makes that transition — so
it logs `"CIS Established 0x%04x in state %d ignored"`, drops its reference and
returns **without unlinking**. The stream stays in the registry in
`ISO_ST_REQUESTED` forever.

The next CIS Request from the central for that same CIS connection handle then
hits the duplicate guard at the top of `iso_on_cis_request()`
(`iso.c:1108-1113`) and is **auto-rejected**. Permanently.

Nothing else cleans it up. `blued_iso_client_gone()` (`iso.c:89-104`) only
clears `requesting_client_fd`, which is `-1` for a peripheral-side stream
anyway. `blued_iso_sweep_adapter()` runs only on adapter power-down. And nothing
in the tree writes `Write_Connection_Accept_Timeout`, so the controller default
of about 5 seconds applies — meaning any client slower than five seconds to
accept, or that crashes between the request event and the accept, poisons that
CIS for the life of the adapter.

Zephyr handles this by keying the pending CIS on the `bt_conn` and releasing it
on any `LE_CIS_Established` regardless of status.

### F5.2 — No client-visible teardown event [OURS-WRONG (gap)]

`iso_on_cis_disconnected()` (`iso.c:1280-1303`), `iso_on_big_sync_lost()`
(`:1306-1321`) and `iso_on_big_terminated()` (`:1324-1341`) all unlink the
stream and log. None of them notifies the client. `ctl.h:70-78` declares
`blued_ctl_iso_cis_request()`, `blued_ctl_iso_established()` and
`blued_ctl_iso_failed()` — and no loss or disconnect counterpart exists at all.
A client holding an ISO data-path fd learns the stream is gone only from the
socket.

### F5.3 — A teardown comment describes code that is not there [false comment]

`blued_iso_cis_teardown()` (`iso.c:855-870`):

```c
	/*
	 * Reverse of setup: remove data paths, disconnect the CIS, then unlink
	 * so the peer's later Disconnection Complete finds nothing (no double
	 * free, no spurious ISO_LOST).
	 */
	iso_remove_paths(s);
	if (hci_disconnect(adp->hci_fd, cis_handle, reason) != 0) {
	...
	s->state = ISO_ST_TEARDOWN;
	iso_unref(s);
```

There is no unlink. The stream stays in the registry, and
`iso_on_cis_disconnected()` does find it and does log `"CIS lost"`. The comment
also names an `ISO_LOST` event that does not exist anywhere in the tree —
which is finding F5.2 seen from the other side. Functionally the actual
behaviour is defensible (unlinking in the disconnect handler is arguably
cleaner), but the stated invariant is not implemented, and a reader relying on
it would conclude the disconnect path cannot see the stream.

### F5.4 — CIG reconfiguration is refused [OURS-DIFFER (gap), low]

`blued_iso_cig_create()` (`iso.c:379-380`) returns `-1` if
`iso_cig_refs(adp, cig_id) != 0` — i.e. if the CIG already exists. §7.8.97
(spec lines 120946-120952) explicitly supports modifying an existing CIG while
it is in the configurable state:

> "If the CIG_ID does not exist, then the Controller shall first create a new
> CIG. Once the CIG is created (whether through this command or previously), the
> Controller shall modify or add CIS configurations in the CIG that is
> identified by the CIG_ID"

Zephyr exposes this as `bt_iso_cig_reconfigure()`
(`host/iso.c:2330`, `valid_cig_param()` with an existing `cig`). This is a local
API limitation rather than a wire defect: a client can remove and re-create.

### F5.5 — Local ceilings below the spec maxima [gap, low]

Three, all defensive and all documented, but each rejects a spec-legal
configuration:

- `ISO_MAX_BIS` is 8 (`iso.h:48`) against a spec maximum of 0x1F. We cannot
  synchronise to, or broadcast, a BIG with more than 8 BISes — a real limit for
  a large Auracast source.
- `blued_iso_cig_create()` caps at 16 CISes (`iso.c:369-375`) and the control
  plane at 8 (`ctl_iso.c:216-221`), against a spec maximum of 0x1F.
  `hci_le_set_cig_params()` itself handles the full 31.
- The three limits do not agree with each other, which is worth tidying whether
  or not the ceilings move.

### F5.6 — Both CIS data-path directions are set up unconditionally [AGREE, documented]

`iso_setup_paths()` (`iso.c:246-259`) sets up Input and Output on every CIS and
counts successes. For a unidirectional CIS the controller answers Command
Disallowed on the unused direction — §7.8.109's error table (spec line 122970):

> "Connection_Handle identifies a unidirectional CIS and Data_Path_Direction is
> the direction where BN is set to 0. → Command Disallowed (0x0C)"

The comment at `hci_misc.c:1843-1851` states exactly this and treats it as
expected. That is honest and correct. The cost is that we cannot distinguish the
expected rejection from a real failure, because we do not track per-CIS
directionality (`max_sdu_c`/`max_sdu_p` are stored, `iso.h:113`, but not
consulted here). Zephyr sets up only the directions its QoS declares. Not a
conformance defect; recorded as the reason `up <= 0` is the only failure signal.

### Checked and clean

`LE Set CIG Parameters` (`hci_misc.c:800-838`): CIG_ID ≤ 0xEF, SDU intervals in
0x0000FF-0x0FFFFF, SCA ≤ 0x07, Packing ≤ 1, Framing ≤ 2, latencies in
0x0005-0x0FA0, CIS_Count ≤ 31, and per-record CIS_ID ≤ 0xEF, Max_SDU ≤ 0x0FFF
both directions, PHY a non-zero mask within bits 0-2 both directions — every one
matches the §7.8.97 tables exactly. The comment noting that §7.8.97 takes a PHY
*bitfield* where the `_test` variant takes a single PHY is correct.

`LE Create BIG` (`hci_misc.c:1256-1266`): handles ≤ 0xEF, Num_BIS 0x01-0x1F,
SDU_Interval, Max_SDU 0x0001-0x0FFF (note the minimum of **one**, which the spec
specifies and which the CIG command does not), latency, PHY mask, Packing,
Framing, Encryption ≤ 1, and the Broadcast_Code rule — non-NULL when encrypted,
all-zero when not (`hci_broadcast_code_zero()`, `:1235-1242`). All correct
against §7.8.103.

`LE BIG Create Sync` (`hci_misc.c:1450-1467`) validates MSE ≤ 0x1F,
BIG_Sync_Timeout 0x000A-0x4000, Num_BIS 0x01-0x1F, and enforces that the BIS
index list is **strictly ascending** with no duplicates. That last check is not
gratuitous strictness — §7.8.106 (spec lines 122627-122629) says:

> "The list of BIS_Numbers shall be in ascending order and shall not contain any
> duplicates."

Neither Zephyr nor NimBLE enforces the ordering on the host side.
**OURS-RIGHT-OTHERS-DIFFER.**

`LE Setup ISO Data Path` (`hci_misc.c:1570-1579`): connection handle ≤ 0x0EFF,
direction ≤ 0x01, Data_Path_ID ≠ 0xFF (the RFU value), Controller_Delay ≤
0x3D0900 (the 4-second ceiling), Codec_Configuration_Length within the
one-octet HCI parameter budget, and the §7.8.109 rule that a non-zero
Codec_Configuration_Length with the transparent coding format (0x03) is Invalid
HCI Command Parameters. That last one is a genuinely obscure check and it is
right.

Feature gating: `LE_FEAT_CIS_CENTRAL` (bit 28), `LE_FEAT_CIS_PERIPH` (29),
`LE_FEAT_ISO_BROADCASTER` (30) and `LE_FEAT_ISO_SYNC_RECEIVER` (31) in
`hci_util.h:253-256` match Vol 6 Part B, and `ctl_iso.c:214,269,326,345` gates
the CIG, CIS, BIG-create and BIG-sync verbs on the right bits.

Teardown ordering: `blued_iso_cig_remove()` (`iso.c:499-547`) refuses unless
every CIS in the CIG is still in `ISO_ST_CIG_CONFIGURED`, which is the host-side
enforcement of §7.8.100's Command Disallowed; and it correctly refuses to touch
an inbound peripheral CIS carrying the same peer-assigned CIG_ID, which is a
separate namespace. On a failed CIS establishment
(`iso.c:1041-1055`) the CIG is removed only when its last reference goes.
`iso_on_big_established()` (`iso.c:1150-1257`) is careful about every failure
arm, including the case where the terminate itself fails, and the reasoning
about not leaving a "ghost" that blocks re-creating the BIG handle is sound.
Error codes: 0x13 for teardown, 0x0D for rejection, and 0x44 "Operation
Cancelled by Host" for the cancelled-BIG case are all valid choices.

### Not comparable

The ISO **data** path — PSN, SDU length, packet boundary flags, timestamps — is
`sys/netgraph/bluetooth/socket/ng_btsocket_iso.c` and is handed to the client as
a descriptor. Its buffer accounting is finding 3 below; its header packing was
not audited here and remains the open item the previous sweep named.

---

## 6. Flow control and buffer accounting

All kernel except where noted.

### F6.1 — ISO transmit is silently mute when the ISO pool is unknown [OURS-WRONG, KERNEL-SIDE]

`ng_btsocket_iso.c:1184-1190` sets the route's packet size with a clamp and a
default, and then takes the packet *count* with neither:

```c
		if (ep->pkt_size <= sizeof(ng_hci_iso_data_load_hdr_t))
			rt->pkt_size = NG_BTSOCKET_ISO_DEFAULT_PKT_SIZE;
		else if (ep->pkt_size > NG_BTSOCKET_ISO_MAX_PKT_SIZE)
			rt->pkt_size = NG_BTSOCKET_ISO_MAX_PKT_SIZE;
		else
			rt->pkt_size = ep->pkt_size;
		rt->num_pkts = ep->num_pkts;
```

The transmit loop is gated on it (`:2212`):

```c
	while (pcb->rt->pending < pcb->rt->num_pkts &&
	       sbavail(&pcb->so->so_snd) > 0) {
```

If `num_pkts` is zero the loop body never executes. Writes accumulate in
`so_snd`, `send()` returns success, and nothing is ever transmitted. There is no
error and no log line. The asymmetry with the line above it — where the author
did think about a zero value — is what makes this look like an oversight rather
than a decision.

### F6.2 — LE Read Buffer Size v1 is never issued [OURS-WRONG]

This one is userland plus `rc`. `blued.c:2734-2747` issues **LE Read Buffer Size
v2 unconditionally**, with no Supported Commands bit test and no v1 fallback,
via `hci_misc.c:672-714`. Nothing anywhere in the tree issues v1 (0x2002) except
interactive `hccontrol`.

Vol 4 Part E §4.1.1 (spec lines 86581-86582) is a "shall":

> "on initialization, a Host that supports LE shall issue the
> HCI_LE_Read_Buffer_Size command"

On a pre-5.2 controller v2 fails and LE silently falls back to the BR/EDR pool
that `libexec/rc/rc.d/bluetooth:148` established — which happens to work. On an
**LE-only** controller there is no BR/EDR pool, and §4.1.1 (spec lines
86590-86592) says so explicitly:

> "A Controller that does not support BR/EDR shall not return zero for the total
> number of HCI ACL packets used to transmit ACL data for an LE transport."

so the fallback is not available and **no LE data can be sent at all**. Zephyr
gates on the Supported Commands bit and falls back to v1.

### F6.3 — The v2 completion never reaches the ISO hook [OURS-WRONG (latent), KERNEL-SIDE]

`ng_hci_cmds.c:1021-1054` handles the v2 Command Complete, sets the LE pool if
non-zero and the ISO pool if non-zero — and then notifies only the `acl` hook.
The ISO socket layer learns its window solely from `NODE_INIT`
(`ng_hci_main.c:383`). It works today only because `blued.c:2777-2786` happens
to call `hci_node_init()` last. Any reordering, and any re-read (which the
not-ready guard at `:1026-1028` silently discards anyway), leaves the ISO
window at zero — which is finding F6.1.

### F6.4 — SCO credits are debited and never returned [OURS-WRONG, KERNEL-SIDE]

`ng_hci_evnt.c:392-403` debits SCO credits, but Synchronous Flow Control
defaults to **disabled** (§7.3.37, spec lines 96027-96029), and while it is
disabled "No HCI_Number_Of_Completed_Packets events shall be sent from the
Controller for synchronous Connection_Handles". Nothing in the tree issues
`Write_Synchronous_Flow_Control_Enable` (0x0C2F). SCO transmit stalls
permanently once `sco_pkts` packets are outstanding. This is a pre-existing
FreeBSD defect rather than something this project introduced, but it is real and
it affects HFP/HSP.

### F6.5 — Zero-buffer fallback keys on count but not length [OURS-WRONG (edge), KERNEL-SIDE]

`ng_hci_cmds.c:1032-1045` and `:1069-1077` treat a zero *count* as "no dedicated
LE buffer". §7.8.2 (spec lines 111919-111921) gives a second, independent
trigger:

> "If the Controller returns a length value of zero for ACL data packets, the
> Host shall use the HCI_Read_Buffer_Size command"

A controller returning a zero length with a non-zero count leaves `le_size == 0`
and `le_pkts != 0`, so L2CAP fragments to the BR/EDR size while the HCI node
debits the LE pool.

Related, `ng_hci_cmds.c:1063-1067` attributes the count-keyed rule to §7.8.2.
§7.8.2's own rule is the length-keyed one; the count rule is §4.1.1 and §7.4.5.
The behaviour is defensible, the citation is wrong, and the missing trigger sits
right next to it — the same pattern again.

### F6.6 — A load-bearing call documented as diagnostic [OURS-WRONG (architecture)]

`blued.c:2735-2737` describes the v2 buffer read as being "for diagnostics" and
only logs the values it gets back. It is in fact the sole path by which
`unit->buffer.iso_*` is ever populated, because the kernel sets those counters
by snooping the Command Complete this call generates. Deleting what the comment
describes as a diagnostic would disable all ISO transmit.

### F6.7 — No controller-to-host flow control [ECOSYSTEM-SPLIT]

`Set_Controller_To_Host_Flow_Control` (0x0C31), `Host_Buffer_Size` (0x0C33) and
`Host_Number_Of_Completed_Packets` (0x0C35) are dead "no post processing" cases
(`ng_hci_cmds.c:651-653`, `:672`, one marked `XXX Not supported this time`) with
no issuer anywhere. §4.2 makes this opt-in, so it is spec-legal. Zephyr enables
it by default for host-only builds; NimBLE implements it but leaves it off. On a
lossy or slow transport its absence shows up as dropped inbound data.

### F6.8 — ISO credit window is per-unit, not per-stream [ECOSYSTEM-SPLIT]

`rt->pending` / `rt->num_pkts` (`ng_btsocket_iso.c:2212`) are per HCI unit, so
one ISO socket can drain the whole ISO window and head-of-line block every other
stream — defeating the HCI node's own least-outstanding fairness. Spec-legal.
Zephyr is better here (per-connection ISO semaphores); NimBLE is worse.

### F6.9 — L2CAP over-commits the unit pool [OURS-WRONG (design), KERNEL-SIDE, low]

`ng_l2cap_llpi.c:1009-1014` grants each connection the entire unit-wide packet
pool. The over-commitment is resolved by dropping at `ng_hci_main.c:915-928`
rather than by back-pressure. Related: the `KASSERT(frag_size > 0)` at
`ng_l2cap_llpi.c:680-683` is reachable in exactly the F6.2 LE-only
configuration, so an INVARIANTS kernel panics where the production kernel takes
the graceful `EIO` path below it.

### Where we are ahead

- **Number Of Completed Packets handling is stricter than every reference.**
  `ng_hci_evnt.c:2701-2779` clamps an over-large count to what was actually
  outstanding (`:2738-2748`). Zephyr drops the surplus
  (`host/hci_core.c:740-745`); NimBLE **resets the host**
  (`ble_hs_hci_evt.c:312`). **OURS-RIGHT-OTHERS-DIFFER.**
- **Credit reclamation on disconnect and reset is correct in all four pools**
  (`ng_hci_misc.c:352-380` implementing §4.3, `ng_hci_cmds.c:729-741`,
  `ng_btsocket_iso.c:624-629`, `:2605-2611`). **NimBLE leaks here** —
  `ble_hs_conn_free()` never returns `bhc_outstanding_pkts`.
  **OURS-RIGHT-OTHERS-DIFFER.**
- **The HCI node cannot overrun the controller.** Debits equal packets actually
  forwarded, bounded by the free count (`ng_hci_evnt.c:374-436`, `:442-544`),
  satisfying the §4.1.1 prohibition at spec lines 86653-86654. The buffer
  accessor macros (`ng_hci_var.h:90-191`) saturate at 0 and clamp to the pool
  total, so a free counter can never be inflated past what the controller
  advertised — and the LE and ISO counts are correctly 8-bit, matching the
  one-octet spec fields.

---

## 7. What the pattern says, again

The previous document ended on the observation that justifications are where the
defects are, and counted six comments citing sources that contradict them. This
sweep found **eight more**, and the rule held every time.

1. `ng_l2cap_evnt.c:1385-1389` — "§4.25: if the device cannot create ALL
   requested channels, it must refuse ALL of them." The spec says the opposite,
   in a table whose own wording is "Some connections refused". → F2.4
2. `ng_btsocket_l2cap.c:1674-1680` — "L2CAP does not provide any flow control."
   True of Basic mode, false of the §10.2 mode the channel is in. → F2.3
3. `include/ng_l2cap.h:111` — the PSM range comment has the dynamic and reserved
   ranges backwards relative to Table 4.15. → F2.8
4. `ng_btsocket_l2cap.c:2853-2862` — correct rationale, applied to one direction
   only. The most expensive item in this document. → F4.1
5. `ng_l2cap_evnt.c:719-733` — arithmetic that disproves its own constant.
   Already known; still there. → F4.3
6. `ctl_iso.c:105-121` — "the exact upper bound could NOT be settled from
   in-tree sources" and "no in-tree spec table covers it", about a table that is
   in the tree. → the RTN determination
7. `iso.c:855-859` — describes an unlink the function does not perform and names
   an event that does not exist. → F5.3
8. `att.c:473-484` — describes a "least-loaded selector" the code does not
   implement (`att.c:127-129` is a binary busy flag) and attributes a load-count
   model to Vol 3 Part G §5.3, which says nothing of the kind.

Plus four more EATT comments with wrong section numbers rather than wrong
claims: `blued_central.c:764-765` cites a **nonexistent** "Vol 3 Part G §2.4.1";
`att.c:107-111` and `att.c:1946-1952` attribute the Exchange-MTU restriction to
Vol 3 Part F §3.4.2 / §5.3.1 when it is Vol 3 Part **G** §4.2;
`blued_peripheral.c:1651-1653` says "Part F §5.3.2" for a Part G section. The
behaviour in all four cases is right. They are noted because the next reader who
goes looking for the rule in Part F will not find it and may conclude there is
no rule.

Against that, **twelve** suspect comments were opened and found **correct**, and
several were non-obvious: the Invalid-CID reason-data ordering, the Extended
Features bit-7 distinction, the `CREDIT_RECONFIG_REQ` must-stay-PENDING claim,
the credit-CID-is-the-peer's-SCID claim, the "MPS may exceed MTU" note, the
Table 4.2 routing claims, the unidirectional-CIS data-path note, and the
EATT-cannot-survive-an-unencrypted-ACL claim. The rule is not "comments are
wrong"; it is "a comment is written at the moment someone decides not to do the
obvious thing, which is the moment they are most likely to be wrong". Opening
the source is cheap and it worked eight times here.

**A second pattern, specific to this sweep: the join between layers is where
the bugs are.** F4.1 is a rule applied to transmit and not receive. F2.1 is a
protocol layer that works and a socket layer that has no case for it. F6.3 is a
value the kernel learns only by snooping a command it does not send. F6.1 is a
clamp applied to one field of a pair. F5.1 is an event handler whose state
machine does not admit a state the event can legitimately arrive in. None of
these is a misreading of the specification — every one is two correct pieces of
code that do not meet.

**And the ecosystem note from last time is reinforced.** BlueZ was *unusable* as
a reference for three of the five areas here, because the code is in the Linux
kernel and not in the repository. Anyone repeating this exercise should clone
the kernel tree as well. Zephyr carried most of the adjudication load and was
right every time we differed from it except on the EATT MTU derivation and the
Exchange-MTU reaction; NimBLE's controller was the decisive third voice on the
retransmission-number question, which BlueZ alone could never have settled
because BlueZ does not bound RTN at all.

---

## 8. Files

Created by this sweep:

- `docs/bluetooth-interop-l2cap-iso.md` — this document.
- `tests/usr.sbin/bluetooth/blued/spec_extref_iso_cig_rtn.h` — the CIG and BIG
  retransmission bounds with both §7.8.97 RTN tables quoted verbatim and the
  §7.8.103 table beside them, Zephyr's two macros as the external corroboration,
  plus the full §7.8.97 / §7.8.103 / §7.8.106 / §7.8.109 parameter ranges so a
  validator can be checked field by field against something other than itself.
  Also pins the §7.8.106 ascending-BIS-index "shall" and the §7.7.65.26
  Connection_Accept_Timeout rule behind F5.1.
- `tests/usr.sbin/bluetooth/blued/spec_extref_l2cap_ecfc.h` — §3.4.2, §3.4.3,
  §4.25, §4.26, §4.27 and §10.2 quoted verbatim: the three mandatory
  reassembly disconnects, Table 4.17 transcribed in full with each result code
  annotated "All" or "Some", the zero-Destination-CID rule that settles partial
  success, the MTU/MPS/credit ranges, the reconfigure no-reduce rules, and the
  credit-return timing of all three available references with the deadlock
  condition written as a macro.
- `tests/usr.sbin/bluetooth/blued/spec_extref_l2cap_eatt.h` — Vol 3 Part G
  §4.2, §5.3.1, §5.3.2, §5.4 and §6.2.1 and Vol 3 Part F §3.2.8, §3.3.2 and
  §3.3.3 quoted verbatim, with the correct part and section numbers stated up
  front because four in-tree comments get them wrong. Includes the §5.4 backoff
  as a computable macro and the SMP channel MTUs from Tables 3.1 and 3.2.
- `tests/usr.sbin/bluetooth/blued/spec_extref_l2cap_signalling.h` — Tables 4.1,
  4.3 and 4.4, the per-channel command rules, the identifier rules, the RTX and
  ERTX ranges, the ATT and SMP fixed-channel sizes, and the supervision-timeout
  constraint with the multiplier of **4** written as a macro so F4.3 has an
  oracle that is not our own arithmetic.
- `tests/usr.sbin/bluetooth/blued/spec_extref_iso_buffers.h` — Vol 4 Part E
  §4.1, §4.1.1, §4.3, §7.3.37, §7.4.5, §7.7.19 and §7.8.2 quoted verbatim,
  including both independent zero-buffer fallback triggers, the one-octet packet
  count fields, and the LE-only-controller rule that makes F6.2 critical rather
  than cosmetic.

All five compile standalone and follow the existing headers' conventions: every
value traceable to a named external source, nothing derived by running our own
code, and every reference-implementation claim attributed to a file and line in
a named snapshot. Where a reference could not be consulted — BlueZ's L2CAP, ISO
and HCI flow control, all of which live in the Linux kernel — the headers say so
rather than guessing.

As with the four headers from the previous sweep, these are inert until
something includes them; wiring them up requires a change to the tests Makefile,
which was out of scope for this pass.

## 9. Suggested order of work

Not a plan, just the order the evidence supports.

1. **F4.1** (ATT/SMP receive MTU) — the fix is a two-condition guard copied from
   the transmit path twelve hundred lines below. It unbreaks LE Secure
   Connections pairing and every ATT PDU above 23 octets. Nothing else in this
   document is close in ratio of impact to effort.
2. **F6.1 and F6.3** (ISO buffer window) — one missing clamp and one missing
   hook notification. Without them no ISO data leaves the machine, so every
   other ISO finding is untestable.
3. **F2.1** (ECFC socket connect) — three lines modelled on the `IDTYPE_LE` arm
   directly above. It is the gate on the entire central-role EATT feature, and
   on findings F3.2 through F3.10 becoming reachable.
4. **F6.2** (LE Read Buffer Size v1 fallback) — a Supported Commands check and a
   fallback call. Turns "works on my dongle" into "works on an LE-only dongle".
5. **F5.1** (CIS request ghost) — accept `ISO_ST_REQUESTED` in
   `iso_on_cis_established()` and unlink on a non-zero status. A few lines, and
   it removes a permanent poisoning of a CIS handle.
6. **F2.4 and F2.2** (partial success, mid-SDU credits) — larger, and both need
   care, but they are the two places where a conformant peer can be deadlocked
   or refused by us alone among the four stacks.
7. **F3.2 and F3.3** (bearer `stale` reuse, cross-bearer confirmations) — small,
   and both are silent-corruption classes rather than failure classes, which
   makes them expensive to find later.
8. **The RTN bound** — a one-character change in two files, plus deleting a
   comment that is now known to be false. Lowest impact on this list, but it
   closes the open question and the header gives it an oracle.
