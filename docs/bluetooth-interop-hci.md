# HCI command and event handling: 5BSD against BlueZ, Zephyr and NimBLE

An external-reference sweep of the layer where blued talks to the controller.
It follows the method of `bluetooth-interop-comparison.md` — establish what
each implementation does with file and line citations, then determine from the
specification which is right — and applies it to the HCI command/event seam
rather than to ATT, SMP and mesh.

The motivation is that errors here do not fail uniformly. They surface as a
daemon that works with one controller and not another, because the divergence
only shows up on adapters that lack an optional command, report a reserved
value, or take an unexpected branch. Findings are ranked accordingly: a defect
that only appears on controllers lacking an optional feature outranks an
encoding nit that no shipping controller will ever see.

Nothing in this document was changed in the code when it was written; it is
reconnaissance.

## Reference implementations obtained

| Stack | Source | Snapshot commit | Role |
| --- | --- | --- | --- |
| BlueZ 5.87 | `git.kernel.org/pub/scm/bluetooth/bluez.git` | `92305dc06ab8a6d89af2dae1d725cc4d51462ad1` | host-only over the kernel, the same shape as us |
| Zephyr | `github.com/zephyrproject-rtos/zephyr` | `2665fcca3cced3aefb7202d6289991d8cc1dfcac` | host **and** controller; shows both sides of each command |
| Apache NimBLE | `github.com/apache/mynewt-nimble` | `1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845` | host **and** controller; a third independent reading |

Adjudicating text: `/usr/src/bluetooth-specs/Core_Specification_6_3.txt`,
principally Vol 4 Part E (HCI), with Vol 6 Part B (Link Layer) and Vol 1 Part F
(error codes) where the HCI text defers to them.

Target is **Bluetooth 5.2 plus Connection Subrating**. Commands and events
introduced after that are out of scope and are only mentioned where a
5.2-vintage validator rejects a newer value it should have ignored.

Because BlueZ's LE event mask, advertising-report parsing and flow control all
live in the Linux kernel rather than in the BlueZ tree, BlueZ contributes less
to this comparison than it did to the ATT/SMP one. Zephyr and NimBLE, which
ship a controller alongside the host, carry most of the adjudicating weight.

## Classification key

Same as `bluetooth-interop-comparison.md`:

- **OURS-WRONG** — the spec, or the unanimous practice of the references,
  contradicts us.
- **OURS-RIGHT-OTHERS-DIFFER** — we match the spec and at least one reference
  does not. Recorded so nobody "fixes" us towards the reference.
- **ECOSYSTEM-SPLIT** — the references disagree and the spec does not settle it.
  Needs a product decision, not a patch.
- **AGREE** — checked, no divergence. Recorded so the ground is not re-ploughed.
- **KERNEL-SIDE** — the behaviour is `sys/netgraph/bluetooth`'s, not blued's.

---

## Ranked findings

| # | Area | Finding | Class | Impact |
| --- | --- | --- | --- | --- |
| 1 | Feature negotiation | LE event mask never sets bit 5, so the controller rejects the peer's Connection Parameters Request on air with 0x1A | OURS-WRONG | every central-initiated parameter update fails; explains the peripheral dead end from the other side |
| 2 | Feature negotiation | blued never reads Supported Commands or Local Version; every optional command is blind-fired and every failure collapses to `EIO` | OURS-WRONG (gap) | startup and feature aborts on any controller missing an optional command |
| 3 | Event decoding | one reserved value in one report discards the entire multi-report advertising event | OURS-WRONG | intermittent, controller-dependent loss of mesh beacons and scan results |
| 4 | Event decoding | `hci_parse_ext_adv_report` reports "unparseable" for purely semantic values, and callers then abandon the rest of the batch | OURS-WRONG | silent scan-result loss against 5.4+ controllers |
| 5 | Event decoding | Connectionless IQ Report rejects the spec-defined Receiver Test handle 0x0FFF | OURS-WRONG (wrong range) | all direction-finding IQ reports discarded during receiver test |
| 6 | Feature negotiation | LE CIS Established mask bit gated on a central-only feature bit | OURS-WRONG | a peripheral-only ISO controller accepts a CIS and never learns it was established |
| 7 | Feature negotiation | LE Request Peer SCA Complete never unmasked although the command is issued | OURS-WRONG | `hci_le_request_peer_sca()` can never complete |
| 8 | Feature negotiation | Directed Advertising Report and Channel Selection Algorithm never unmasked | OURS-WRONG | directed advertisements from a bonded peer are invisible |
| 9 | Event decoding | reserved bits and values reject whole Path Loss / TX Power / Periodic Advertising Report events | OURS-WRONG | breaks against controllers that populate a future field |
| 10 | Return parsing | 81 of 100 command wrappers read `rp.status` without checking `r.rlen`; libbluetooth pre-zeroes, so a truncated Command Complete reads as **success** | OURS-WRONG (robustness) | fail-open on malformed replies; no conformant controller triggers it |
| 11 | Timeouts | 104 of 107 commands use a 5-second timeout against a 10-second ecosystem norm | OURS-DIFFER | marginal; two commands at 1 second are the tight ones |
| 12 | Event decoding | legacy-PDU PHY tuple enforced host-side, and enforced fatally | OURS-RIGHT-OTHERS-DIFFER | strictest position in the ecosystem; costs a batch on a firmware quirk |

Findings 1, 2, 6, 7 and 8 are all the same structural problem seen from
different angles — capability and event enablement are decided from LE
**feature** bits alone — and are treated together in section 3.

---

## 1. The reply-length sweep: complete for its stated scope

The brief asked whether the "reading fields from a reply shorter than expected"
sweep (the H-H3 findings) was actually finished. It was mechanically
re-derived rather than assumed.

Every function in `hci_adv.c`, `hci_conn.c`, `hci_scan.c`, `hci_privacy.c`,
`hci_misc.c` and `hci_util.c` that sets `r.rparam` and calls `bt_devreq` was
enumerated, and each was classified by whether it checks `r.rlen` after the
call and whether it reads any return-parameter field beyond `status`.

**100 command wrappers. 19 check `r.rlen`. Every one of the 19 is a function
that reads a field beyond `status`, and there are no others.** The set of
functions that read a multi-field return parameter without a length check is
empty:

| | reads only `status` | reads fields beyond `status` |
| --- | --- | --- |
| checks `r.rlen` | 4 | **15** |
| no check | 77 | **0** |

So the sweep is **complete for the defect it was scoped to**: no function
reads a return-parameter field off the end of a short reply. That includes the
awkward ones — `hci_le_read_iso_link_quality`, `hci_le_read_antenna_info`,
`hci_le_read_buffer_size_v2`, `hci_le_read_iso_tx_sync`,
`hci_le_read_resolving_list_size`, `hci_get_bdaddr` — all of which check.

### F1.1 — The residual 77 fail *open*, not closed [OURS-WRONG, LOW]

The 77 status-only wrappers are not equivalent to the 19. `bt_devreq()` was
changed to pre-zero the caller's buffer (`lib/libbluetooth/hci.c`, the H-H3
comment block), and to reduce `r->rlen` to the number of octets actually
copied:

```c
	if (r->rparam != NULL && r->rlen > 0)
		memset(r->rparam, 0, r->rlen);
	...
		if ((ssize_t)r->rlen > n)
			r->rlen = n;
		if (r->rlen > 0)
			memcpy(r->rparam, cc + 1, r->rlen);
```

That fixed the uninitialised-stack problem, and it is the right fix. But it
converts the failure mode rather than removing it: a Command Complete carrying
**zero** return-parameter octets now leaves `rp.status == 0x00`, and a wrapper
that checks only `rp.status != 0` reports **success** for a command the
controller never acknowledged. `hci_le_set_event_mask()`
(`hci_misc.c:560-590`) is representative — it returns 0, and `blued.c:2686`
proceeds as though the mask were programmed.

This is a fail-open robustness gap, not an interop defect: Vol 4 Part E
requires a Status octet in the Command Complete for every one of these
commands, so a conformant controller never produces the input. It is ranked
low for that reason. It is worth recording because the *shape* of the H-H3 fix
makes the missing check invisible — the code reads as though a zeroed reply
were safe, and for these 77 wrappers it is not.

The two wrappers using `r.event = NG_HCI_EVENT_COMMAND_STATUS`
(`hci_disconnect`, `hci_le_ext_create_connection`) are not affected: `bt_devreq`
copies from the Command Status event structure, whose first octet is the real
status.

---

## 2. Command parameter encoding

Encoding was spot-checked rather than swept exhaustively; the two
highest-risk commands — the ones whose parameter length is driven by a PHY
bitmask, where a wrong length produces Invalid HCI Command Parameters on some
controllers and silent misparsing on others — were checked in full, and both
are correct.

### F2.1 — LE Extended Create Connection: PHY block count correct [AGREE]

`hci_conn.c:1039-1055` counts set bits in `Initiating_PHYs` and requires the
caller's buffer to match exactly:

```c
	phy_count = ((phys & HCI_LE_PHY_1M) != 0) +
	    ((phys & HCI_LE_PHY_2M) != 0) +
	    ((phys & HCI_LE_PHY_CODED) != 0);
	expected_phy_len = phy_count * sizeof(ng_hci_le_ext_create_conn_phy_t);
```

with `clen = sizeof(*cp) + phy_len`. It also rejects a 2M-only initiation
(`(phys & (HCI_LE_PHY_1M | HCI_LE_PHY_CODED)) == 0`), which is correct: there
is no 2M primary advertising channel to initiate on.

The `C3-L` comment at `hci_conn.c:1046-1051` claiming `Peer_Address_Type`
accepts 0x00-0x03 was checked against Vol 4 Part E §7.8.66 and is accurate —
one of the few comments in this stack that survives verification unchanged.

### F2.2 — LE Set Extended Scan Parameters: block order and count correct [AGREE]

`scan_params_fill_ext()` (`hci_scan.c`) emits `Own_Address_Type`,
`Scanning_Filter_Policy`, `Scanning_PHYs`, then one `{type, interval, window}`
block per set PHY bit **in ascending bit order** (1M then Coded), and returns
the length it actually wrote, which becomes `r.clen`. That matches the §7.8.64
field table. The 2M bit is excluded from `HCI_SCAN_PHYS_MASK`, correctly —
there is no 2M primary advertising channel to scan.

### F2.3 — LE feature bit numbering is correct [AGREE]

All 21 `LE_FEAT_*` definitions in `hci_util.h:237-260` were checked against the
Vol 6 Part B §4.6 feature list. Every one is right, including the three that
are easy to get wrong because they are non-contiguous: `LE_FEAT_CODED_PHY`
(bit 11, not 9 or 10 — those are the Stable Modulation Index bits),
`LE_FEAT_PAST_SENDER`/`RECIPIENT` (24/25, correctly kept distinct, with a
comment that is accurate), and `LE_FEAT_CONN_SUBRATING` (37).

### F2.4 — LE event mask bit numbering is correct [AGREE]

All 34 in-scope `LE_EVTMASK_*` definitions were checked against the Vol 4 Part
E §7.8.1 bit table (spec text lines 111788-111860). Every assigned bit is
correct, including the ones defined out of numeric order in the header
(`PER_ADV_SYNC_XFER` = 23, `PATH_LOSS_THRESH` = 31, `SUBRATE_CHANGE` = 34).

**The bit numbering is right. What is done with it is not** — see section 3.

Pinned in `tests/usr.sbin/bluetooth/blued/spec_extref_hci_le_event_mask.h`.

---

## 3. Feature and capability negotiation

This is where the interesting failures are, and they share one root: **blued
decides everything from the LE feature bitmask, which is the wrong instrument
for most of these questions.**

### F3.1 — LE event mask bit 5 is never set, so the controller must reject the peer's parameter request on air [OURS-WRONG, HIGH]

`hci_le_default_event_mask()` (`hci_misc.c:593-660`) builds the LE event mask.
Bit 5, `HCI_LE_Remote_Connection_Parameter_Request`, is never set — there is no
`LE_EVTMASK_REMOTE_CONN_PARAM_REQ` constant in `hci_util.h` at all. blued also
never decodes subevent 0x06, and never issues
`LE_Remote_Connection_Parameter_Request_Reply` or its negative form.

This is not merely "we do not get told". Vol 6 Part B §5.1.7.2 (spec text lines
143896-143901):

> "If the request is being indicated to the Host and the event to the Host is
> masked, then the Link Layer shall issue an LL_REJECT_EXT_IND PDU with the
> ErrorCode set to Unsupported Remote Feature (0x1A). The initiating device may
> retry in case this is a temporary situation. If the request is not being
> indicated to the Host, then the event mask shall be ignored."

The preceding paragraph (spec text lines 143885-143890) establishes when the
Link Layer *must* consult the host: it may proceed autonomously only if the
request is anchor-point-only, or if the requested values fall within a range
the Host has already provided. blued provides no such range. So on any
parameter request that actually changes an interval, latency or timeout, our
controller is obliged to ask us, finds the event masked, and rejects the peer's
procedure with **Unsupported Remote Feature**.

From the peer's side that is indistinguishable from "this device does not
implement the Connection Parameters Request procedure", and peers cache that
conclusion.

**And the code says the opposite.** `blued.c:2766-2773`:

```c
	/*
	 * Log LL-level connection parameter request support.
	 * If supported, the controller handles parameter negotiation
	 * at the Link Layer, making our l2cap_conn_param_update_req
	 * stub acceptable.
	 */
	if (adp->le_features & LE_FEAT_CONN_PARAM_REQ)
		LOG_HCI(1, "%s: LL Connection Parameter Request supported",
		    adp->name);
```

The controller handles it at the Link Layer *only* in the two narrow cases
§5.1.7.2 enumerates. The comment generalises those cases into a blanket
guarantee, and that guarantee is what justifies the stub. This is a seventh
instance of the pattern the brief warned about: an in-tree comment citing a
mechanism that the cited mechanism does not actually provide, sitting on top of
a real defect.

The kernel is not the obstacle. `sys/netgraph/bluetooth/include/ng_hci.h`
already has all three pieces: `NG_HCI_LEEVMSK_REM_CONN_PARAM_REQ` (`:308`),
`NG_HCI_OCF_LE_REMOTE_CONN_PARAM_REQ_REPLY` (`:2214`),
`NG_HCI_OCF_LE_REMOTE_CONN_PARAM_REQ_NEG_REPLY` (`:2230`) and
`NG_HCI_LEEV_REMOTE_CONN_PARAM_REQUEST` (`:3651`). Only blued is missing.

**References.** Zephyr sets the bit, gated on the feature — and, critically,
implements the other half:

- `zephyr/subsys/bluetooth/host/hci_core.c:3765-3766` sets the mask bit
- `:3075` registers the event handler (`le_conn_param_req`)
- `:2105` sends the Reply, `:2082` the Negative Reply

NimBLE sets it for every controller reporting HCI 4.1 or later,
`nimble/host/src/ble_hs_startup.c:220-225`.

BlueZ's LE event mask is set by the Linux kernel, not by the BlueZ tree.

This finding is the controller-side counterpart of finding 6 in
`bluetooth-interop-comparison.md` ("peripheral connection-parameter update is a
dead end"). That entry described our inability to *initiate*; this one explains
why we also cannot *respond*. They are one defect with two symptoms, and the
`0x1A` that the earlier HCI/GAP notes recorded as an unexplained status is
emitted by our own controller under this rule.

### F3.2 — No capability query at all [OURS-WRONG (gap), HIGH]

blued never issues `HCI_Read_Local_Supported_Commands` (Vol 4 Part E §7.4.2)
or `HCI_Read_Local_Version_Information` (§7.4.1). Neither string appears
anywhere under `usr.sbin/bluetooth/blued/`; the only consumer in the tree is
`hccontrol/info.c`.

All three references query a capability axis before issuing an optional
command. They disagree about *which* axis — that part is an ECOSYSTEM-SPLIT —
but not about whether to ask:

- **Zephyr**: reads the Supported Commands bitmap into
  `bt_dev.supported_commands` (`hci_core.c:3609-3615`, installed at `:3696`),
  then gates each optional command on a bit test — `:344`, `:2254` (octet 10
  bit 5), `:620` (27/7), `:3905` (41/5), `:5291` (27/3).
- **NimBLE**: reads Local Version Information first in startup
  (`ble_hs_startup.c:53`, called at `:411`; exposed by `ble_hs_hci.c:648`) and
  gates on the HCI version (`ble_hs_startup.c:206`, `:354`, `:424`).
- **BlueZ**: reads the same bitmap (`tools/btinfo.c:140`,
  `tools/hciconfig.c:1099`, `tools/hci-tester.c:278`); per-command gating for
  the managed adapter is in the Linux kernel.

Because blued asks nothing, it must interpret failures after the fact — and it
does not do that either. Across `hci_adv.c`, `hci_conn.c`, `hci_scan.c`,
`hci_privacy.c` and `hci_misc.c` there are 101 `rp.status != 0` tests, and
**exactly one** distinguishes a status code: `hci_le_set_privacy_mode()`
(`hci_privacy.c:300-309`) maps 0x01 to `EOPNOTSUPP` so callers can skip the
command. Every other site collapses every controller status — Unknown HCI
Command, Memory Capacity Exceeded, Command Disallowed, Unsupported Feature —
to `EIO`.

Vol 1 Part F §2.1 makes 0x01 the specified way a controller says an optional
command is absent:

> "The opcode given might not correspond to any of the opcodes specified in
> this document, or any vendor-specific opcodes, **or the command may have not
> been implemented**."

Treating that as `EIO` is refusing the spec's own capability signal. This is
the mechanism behind the startup abort on a controller with a small resolving
list that prompted this review, and it is the general form of that bug rather
than a one-off.

The status dispositions, and the reference gating strategies, are pinned in
`tests/usr.sbin/bluetooth/blued/spec_extref_hci_status_codes.h`.

### F3.3 — Feature-gating the event mask can only lose events [OURS-WRONG, structural]

`hci_le_default_event_mask()` gates most bits on LE feature bits. Vol 4 Part E
§7.8.1 (spec text lines 111772-111775) says this is unnecessary:

> "The Controller shall ignore those bits which are reserved for future use or
> represent events which it does not support. If the Host sets any of these
> bits to 1, the Controller shall act as if they were set to 0."

Setting a bit for an unsupported event is therefore free and cannot fail the
command. Gating has no upside and one downside: **a gate keyed on the wrong
feature silently loses the event**, and the loss is invisible because
`LE_Set_Event_Mask` still returns success. Every gate is a liability with no
compensating benefit. Three of them are currently wrong:

**F3.3a — LE CIS Established gated on a central-only feature [OURS-WRONG, MEDIUM]**

`hci_misc.c:618-621`:

```c
	if ((features & LE_FEAT_CIS_CENTRAL) != 0)
		mask |= LE_EVTMASK_CIS_ESTABLISHED;
	if ((features & LE_FEAT_CIS_PERIPH) != 0)
		mask |= LE_EVTMASK_CIS_REQUEST;
```

Vol 4 Part E §7.7.65.25 (spec text lines 107560-107564):

> "This event indicates that a CIS has been established, was considered lost
> before being established, or—on the Central—was rejected by the Peripheral.
> **It is generated by the Controller in the Central and Peripheral.**"

On a peripheral-only ISO controller (bit 29 set, bit 28 clear) blued unmasks
CIS Request, calls `hci_le_accept_cis_request()` (`hci_misc.c:1149`), and then
never receives the establishment event, because it masked it. The ISO stream
comes up on the air and the daemon never learns.

**F3.3b — LE Request Peer SCA Complete never unmasked [OURS-WRONG, MEDIUM]**

`hci_le_request_peer_sca()` exists (`hci_misc.c:1670`) and is issued, but bit
30 is not defined in `hci_util.h` and never set. Vol 6 Part D §6.26 (spec text
lines ~169833) shows the flow: Command Status, then
`LE Request Peer SCA Complete`. With bit 30 masked the command reports success
and the result never arrives — the function cannot complete by construction.

**F3.3c — Directed Advertising Report and Channel Selection Algorithm never unmasked [OURS-WRONG, MEDIUM]**

Bit 10 (`HCI_LE_Directed_Advertising_Report`) has no constant and is never set.
Bit 19 (`HCI_LE_Channel_Selection_Algorithm`) is defined as
`LE_EVTMASK_CHAN_SEL_ALGO` (`hci_util.h:277`) but never added to the mask —
dead. NimBLE sets both unconditionally for any controller at 4.2 and 5.0
respectively (`ble_hs_startup.c:227-235`, `:237-251`).

Bit 10 is the one that matters. A bonded peripheral reconnecting with directed
advertising to our RPA produces a Directed Advertising Report and nothing else
when the controller cannot resolve the target address; masked, the reconnection
attempt is invisible to us.

---

## 4. Event and LE meta-event decoding

The layouts are right; the dispositions are wrong. Field offsets, sizes and
byte order in `blued_le_meta.h` were checked against the §7.7.65 field tables
and against the `__packed` structures in `ng_hci.h:3739-3956` — CIS Established
(28 octets), Create BIG Complete (18-octet header), BIG Sync Established (14),
PAST Received (19), Periodic Advertising Sync Established (15) — and all match
with no padding risk. Truncated-event handling is solid at every entry point
(`blued_event.c:612-616` checks `n == buf[2] + 3`; `blued_le_meta.h:200-214`;
`hci_scan.c:1492-1494`; `hci_misc.c:172-174`), equivalent to Zephyr's
`buf->len < handler->min_len` (`hci_core.c:237-259`) and BlueZ's fixed-versus-
minimum size check (`monitor/packet.c:13698-13710`).

What diverges is what happens when a value is unrecognised.

### F4.1 — One reserved value in one report discards the whole event [OURS-WRONG, HIGH]

`blued_mesh_adv_event_valid()` (`blued_event.c:26-68`) validates *every* report
in a multi-report advertising event and returns `false` for the whole event if
any one fails. `blued_event.c:657-661` then drops the event entirely:

```c
		if (!blued_mesh_adv_event_valid(buf, (size_t)n, subevent))
			return;
		blued_mesh_demux_adv_event(buf, subevent);
```

The function's own comment states the intent:

```c
 * Validate an entire multi-report advertising event before exposing any AD
 * field to the Mesh broker.  HCI permits several reports in one event; a
 * malformed later report must not cause an earlier prefix to be forwarded.
```

That is a coherent fail-closed argument, and it is honestly stated — unlike the
comments in section 3, this one does not misrepresent its source. But it
answers the wrong question. The choice is not "forward a prefix or not"; each
report's length is fully determined by its own `Data_Length` at a fixed offset,
so a bad report is always *skippable*. The real choice is between skipping one
report and discarding valid ones, and no reference discards valid ones:

- **NimBLE** advances past the offending report and continues the loop
  (`nimble/host/src/ble_hs_hci_evt.c:667-693`:
  `report = &report->data[report->data_len]; continue;`).
- **Zephyr** stops at the bad report but keeps everything already delivered
  (`subsys/bluetooth/host/scan.c:1753-1763`, `:881-884`), and performs no value
  validation at all — `create_ext_adv_info` (`scan.c:826-843`) copies raw.
- **BlueZ** labels reserved PHY, SID and RSSI values `"Reserved"` and continues
  (`monitor/packet.c:12605-12657`).

Nothing in §7.7.65.2 or §7.7.65.13 authorises discarding an event because one
report carries a reserved value. The consequence is intermittent and
controller-dependent — it appears only on adapters that coalesce reports, and
only in busy radio environments, which is precisely the profile of a bug that
"works on my adapter".

### F4.2 — Semantic rejects propagate into batch aborts [OURS-WRONG, HIGH]

`hci_parse_ext_adv_report()` (`hci_scan.c:1047-1068`) returns 0 — its
"unparseable" signal — for reserved `event_type` bits, data status `0b11`,
reserved address type, reserved PHY or SID, out-of-range RSSI, and a legacy
PHY-tuple mismatch. Callers treat 0 as fatal to the batch: `hci_scan.c:1646`
breaks the loop, `blued_event.c:46-49` abandons the event.

The parser itself is well built and deserves credit: it correctly admits
`Primary_PHY` 0x04 (LE Coded S=2), address type 0xFF (anonymous), SID 0xFF and
`Direct_Address_Type` 0xFE. The problem is only that a value it does not admit
becomes indistinguishable from a framing error, when the report's length is
known and it could simply be skipped.

The worked example of why RFU rejection is dangerous is in this same field
table: `Primary_PHY` 0x04 is **already defined** in Core 6.3 under Advertising
Coding Selection. A validator written against 5.2 that rejects it drops reports
from any shipping 5.4+ controller using LE Coded S=2.

Layout, ranges and the reference batch policies are pinned in
`tests/usr.sbin/bluetooth/blued/spec_extref_hci_ext_adv_report.h`.

### F4.3 — Connectionless IQ Report rejects the Receiver Test handle [OURS-WRONG (wrong range), MEDIUM]

`blued_le_meta.h:298`:

```c
		if (blued_le_meta_le16(p) > 0x0eff || ...)
			return (-1);
```

Vol 4 Part E §7.7.65.21 (spec text lines 106983-106988):

```
Sync_Handle:                    Size: 2 octets (12 bits meaningful)
 0xXXXX   Sync_Handle identifying the periodic advertising train.
          Range: 0x0000 to 0x0EFF
 0x0FFF   Receiver Test
```

0x0FFF is neither a handle nor reserved — it is the value the controller uses
for IQ reports generated during `HCI_LE_Receiver_Test`. The `-1` return reaches
`blued_event.c:1238-1240`, which logs "malformed LE meta subevent" and drops
the event, so every IQ report from a direction-finding receiver test is
discarded. This is the third instance of the exact pattern the brief flagged:
a field validated against the wrong range, causing whole events to be thrown
away.

Neither Zephyr (`hci_core.c:3148-3153`, minimum length only) nor NimBLE
performs any handle-range validation on IQ reports.

Note the near miss next door: the *channel index* bounds are correct, and
correctly different between the two IQ reports — 0x27 for connectionless
(`blued_le_meta.h:299`, test-mode channels 0x25-0x27 permitted) and 0x24 for
connection (`:329`). That distinction is right and was verified against
§7.7.65.21 and §7.7.65.22.

### F4.4 — Reserved bits reject whole Power Control events [OURS-WRONG, LOW-MEDIUM]

- `blued_le_meta.h:414-417` rejects the TX Power Reporting event when any
  reserved bit of `TX_Power_Level_Flag` is set. §7.7.65.33 (spec text lines
  108515-108519) defines bits 0 and 1 and marks "All other bits: Reserved for
  future use" — RFU bits must be ignored.
- `blued_le_meta.h:392-394` rejects the Path Loss Threshold event for
  `Zone_Entered > 0x02`. §7.7.65.32 (spec text lines 108389-108395) marks those
  RFU, and the Description (line 108359) says `Zone_Entered` "shall be
  **ignored**" when `Current_Path_Loss` is 0xFF — the mandated verb is ignore,
  not reject.

The Zone_Entered case carries its own proof: the handler at
`blued_event.c:1014-1017` already prints `"reserved"` for zone > 2. That branch
is unreachable, because the decoder rejected the event first. Dead code that
implements the correct behaviour, behind a check that prevents it from running,
is about as clear a signal as this kind of review produces.

- `blued_le_meta.h:260-264` rejects Periodic Advertising Report `Data_Status`
  0xFF, which §7.7.65.15 (spec text line 106642) defines as "Failed to receive
  an AUX_SYNC_SUBEVENT_IND PDU". That value is 5.4 PAwR and outside our target,
  but the reject is unconditional, so we break against a newer controller
  rather than ignoring a value we do not need.

Pinned in `tests/usr.sbin/bluetooth/blued/spec_extref_hci_le_meta_ranges.h`.

### F4.5 — Host-side enforcement of the legacy PHY tuple [OURS-RIGHT-OTHERS-DIFFER]

`hci_scan.c:1060-1063` drops a report whose `event_type` marks a legacy PDU
unless `Primary_PHY == 0x01 && Secondary_PHY == 0x00`. §7.7.65.13 (spec text
line 106119) does state that requirement — but as an obligation on the
*Controller*. Neither Zephyr (`scan.c:910-917`) nor NimBLE
(`ble_hs_hci_evt.c:671-678`) checks it.

We are within our rights. Recorded so nobody removes the check as a "bug": it
is the strictest position in the ecosystem, and its cost is only that a
firmware quirk here currently costs the whole batch — which F4.2 fixes anyway.

### F4.6 — `num_reports` bounds disagree between two paths [OURS-WRONG, COSMETIC]

`blued_event.c:35-40` caps extended reports at 10 and legacy at 25, both
spec-exact (§7.7.65.13 spec text line 106221 gives `0x01 to 0x0A`; §7.7.65.2
line 105134 gives `0x01 to 0x19`). But `hci_scan.c:1632-1636` applies no cap on
the extended path, while its legacy paths (`:828`, `:1543`) cap at 25. Harmless
— both loops are length-bounded — but the two paths disagree about the same
event. NimBLE caps both at 0x19 (`hci_common.h:2364`), over-permissive for
extended; Zephyr caps neither (`scan.c:847`, `:1729`).

### F4.7 — Classic events are the kernel's [KERNEL-SIDE]

blued decodes only Disconnection Complete (`blued_event.c:1254`), Encryption
Change v1/v2 (`:1263`), Encryption Key Refresh (`:1378`) and Authenticated
Payload Timeout Expired (`:1401`), all exact-length-checked. The Encryption
Change v1/v2 parse (`blued_encryption_event.h:54-73`) matches §7.7.8 including
the v2 field order.

Number Of Completed Packets, Hardware Error and Data Buffer Overflow are not
decoded in userspace at all; netgraph handles them
(`sys/netgraph/bluetooth/hci/ng_hci_evnt.c:333`, `:325`, `:341`). Command
Complete and Command Status are matched by `bt_devreq()`. blued's one inline
Command Status decode (`hci_misc.c:187-205`, fast-failing LE Start Encryption)
correctly gates on `evt->length == sizeof(ng_hci_command_status_ep)`.

---

## 5. Error and status handling, timeouts

### F5.1 — Status collapse

Covered as F3.2: 101 status tests, one of which distinguishes a code. The
disposition table — which codes mean "degrade", "retry", "expected race" and
"fatal", each with the spec text that justifies the assignment — is pinned in
`spec_extref_hci_status_codes.h` rather than restated here.

The distinction most worth acting on is 0x11 versus 0x12. Both currently become
`EIO`, but Vol 1 Part F §2.17 and §2.18 point in opposite directions: 0x11
(Unsupported Feature or Parameter Value) indicts the *controller* and should
degrade, while 0x12 (Invalid HCI Command Parameters) indicts the *host* and is
the status a mis-encoded variable-length command produces. Collapsing them
means an encoding bug in this stack is indistinguishable from a controller
limitation — which is exactly the diagnostic that section 2 needed and could
not get.

### F5.2 — Command Status versus Command Complete [AGREE, with one note]

Every wrapper that sets `r.event = NG_HCI_EVENT_COMMAND_STATUS` was checked
against the spec's "Event(s) generated" statement for that command:
`hci_disconnect` (§7.1.6), `hci_le_ext_create_connection` (§7.8.66),
`hci_le_create_cis`, `hci_le_create_big`, `hci_le_big_create_sync`,
`hci_le_request_peer_sca`, `hci_le_read_remote_tx_power_level`,
`hci_le_set_phy`, `hci_le_connection_update`, `hci_le_subrate_request`. All
correct.

Worth recording is `bt_devreq()`'s behaviour when a controller returns the
*other* completion event, because the two directions fail differently
(`lib/libbluetooth/hci.c`):

- Expecting Command Complete, receiving Command Status with a **nonzero**
  status: returns `EIO` promptly. Good.
- Expecting Command Complete, receiving Command Status with status **0x00**:
  the event is ignored and the loop continues until the deadline, then returns
  `ETIMEDOUT`. A controller that answers a Command Complete command with a
  successful Command Status therefore costs the full timeout and reports a
  timeout rather than a protocol error.

That is a latent robustness issue in libbluetooth rather than an observed
interop failure, and it is out of scope to change here.

### F5.3 — Command timeouts are half the ecosystem norm [OURS-DIFFER, LOW]

Of 107 `hci_devreq_logged()` call sites: 104 use 5 seconds, two use 1 second
(`hci_util.c:269` Read BD_ADDR, `hci_util.c:445` Disconnect), one uses 2.

Zephyr uses 10 seconds for every command
(`subsys/bluetooth/host/hci_core.c:114`, `HCI_CMD_TIMEOUT K_SECONDS(10)`,
applied at `:561` and `:576`).

5 seconds is defensible for commands answered from controller state. The two
1-second sites are the tight ones, and `bt_devreq` computes its deadline in
whole seconds (`t_end = time(NULL) + to`), so a 1-second timeout is really
"somewhere between 0 and 1 second" depending on where the call lands within the
current second. Neither command is slow in practice, so this is ranked low —
but 1 second buys nothing over 5.

---

## 6. Flow control

### F6.1 — Command credits are the kernel's, and it does account for them [KERNEL-SIDE, AGREE]

blued has no notion of `Num_HCI_Command_Packets`; `bt_devreq()` issues one
command and blocks for its completion. The accounting is in netgraph:
`ng_hci_cmds.c:203` and `:322` update the unit's command buffer from the
`num_cmd_pkts` field of each Command Complete and Command Status
(`NG_HCI_BUFF_CMD_SET`), and `ng_hci_send_command()` (`:113`) consumes a credit
via `NG_HCI_BUFF_CMD_GET` (`:123`) before transmitting, re-running the queue at
`:299`, `:369` and `:473`.

blued's per-fd mutex (`hci_util.c:72`) serialises command/response pairs per
adapter, so the synchronous model does not itself overrun a controller. Two
adapters are independent units with independent credit pools, so cross-fd
concurrency is fine.

### F6.2 — ACL and ISO buffer accounting [KERNEL-SIDE]

`hci_le_read_buffer_size_v2()` (`hci_misc.c:672`) reads the sizes and checks
its reply length correctly, but blued only logs them; outstanding-packet
accounting and Number Of Completed Packets are handled in
`ng_hci_evnt.c:333`. Not examined further here — it is kernel territory and
outside the brief's userspace focus.

---

## 7. Comments that contradict their cited source

The brief warned that six comments in this stack cite a source that
contradicts them, and that each marked a real defect. Five more were found.
All spec references below were read, not assumed.

| Location | Claim | What the cited section says |
| --- | --- | --- |
| `blued.c:2766-2771` | "If supported, the controller handles parameter negotiation at the Link Layer, making our `l2cap_conn_param_update_req` stub acceptable." | Vol 6 Part B §5.1.7.2 (spec text 143885-143901): the Link Layer proceeds without the Host only for anchor-point-only requests or values inside a Host-provided range. Otherwise it must ask; masked, it rejects with 0x1A. **Marks F3.1.** |
| `blued_le_meta.h:255-259` | "Tx_Power spans the full int8 -127..+126 dBm range with 0x7F = not available (§7.7.65.15); only -128 is reserved. The +20 dBm cap applies to RSSI alone." | §7.7.65.15 (spec text 106591-106594): `TX_Power ... Range: -127 to +20 ... 0x7F` — identical to RSSI. Also contradicts `ng_hci.h:3758`, the header this file claims to cross-check against. |
| `hci_scan.c:1043-1046` | same TX_Power claim, citing §7.7.65.13 | §7.7.65.13 (spec text 106236-106240): `TX_Power[i] ... Range: -127 to +20 ... 0x7F`. |
| `blued_le_meta.h:409-413` | "§7.7.65.33 places no constraint on Delta for any Reason" | §7.7.65.33 (spec text 108487): "When this event is generated with Reason set to 0x02, Delta shall be set to zero. Delta shall be ignored if the TX_Power_Level parameter is set to 0x7E." |
| `blued_event.c:241-242` | "0x22 (Periodic Advertising Report v2)" | Spec text 108590: 0x22 is BIGInfo Advertising Report. Periodic Advertising Report v2 is 0x25 (line 106579). |
| `blued_le_meta.h:115` | `data_status /* 0=complete,1=more,2=truncated */` | §7.7.65.15 (spec text 106642) also defines 0xFF. The omission is what produces the F4.4 reject. |

The three TX_Power comments are *over-permissive* in effect — they widen an
accept, so they cost nothing at runtime. They are listed because they are the
same wrong-range reasoning that, applied to RSSI and to handles, produced F4.1
and F4.3. The reasoning is the defect; where it currently lands is luck.

---

## What was and was not covered

Covered exhaustively: the reply-length sweep (all 100 command wrappers,
mechanically enumerated); LE event mask and LE feature bit numbering (all 34
and all 21 definitions); LE meta subevent layouts and field ranges; classic
event decoding; command-credit accounting.

Covered by spot check: command parameter encoding. The two highest-risk
commands — the PHY-bitmask-driven variable-length ones — were checked in full
and are correct, as were the LE Set Event Mask byte order and the resolving
list and privacy commands. The ISO command family (`LE Set CIG Parameters` and
its `_test` variant, `LE Create BIG`, `LE Setup ISO Data Path`) was **not**
swept field by field; those are the largest remaining unexamined encoders, and
ISO is where a hand-built layout is most likely to be wrong because it is
least exercised.

Not covered: BR/EDR command encoding (blued is LE-only in practice), and the
kernel's ACL buffer accounting beyond confirming where it lives.

## Reference headers added

Under `tests/usr.sbin/bluetooth/blued/`, following the existing
`spec_extref_*.h` conventions — every value traceable to a named external
source, nothing derived from our own code, each compiles standalone:

| File | Pins |
| --- | --- |
| `spec_extref_hci_le_event_mask.h` | the §7.8.1 bit table (0-38), the specified default, the "controller shall ignore unsupported bits" rule, the 0x1A consequence of masking bit 5, and each reference's gating strategy |
| `spec_extref_hci_status_codes.h` | Vol 1 Part F Table 1.1, and the degrade/retry/expected-race/fatal disposition for each code that matters, with the spec text justifying each assignment |
| `spec_extref_hci_ext_adv_report.h` | the §7.7.65.13 per-report layout and value tables, and the batch policy each reference uses when one report is unusable |
| `spec_extref_hci_le_meta_ranges.h` | the LE meta fields whose tables carry a special value outside the ordinary range, or an explicit RFU row |
