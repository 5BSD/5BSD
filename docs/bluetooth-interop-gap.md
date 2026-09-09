# GAP interoperability: 5BSD against BlueZ, Zephyr and NimBLE

A focused external-reference sweep of the 5BSD Bluetooth stack's Generic
Access Profile layer: advertising, scanning, connection establishment, privacy
and addressing, and advertising-data encoding.

This document follows the conventions of `bluetooth-interop-comparison.md` and
is a companion to it. That sweep covered the wire representation, ATT errors,
pairing, the state machine and mesh; it touched GAP only where GAP intruded on
those areas, and two of its findings (its #9 and #11) were GAP findings noted in
passing. A conformance audit subsequently put GAP at 3.4% covered — 11 of 324
applicable requirements, the thinnest layer in the stack — which is why it was
swept properly here.

GAP is also the layer with the shortest path from a defect to a user-visible
failure. It decides whether a phone can find us, whether it can connect, and
whether it can still connect an hour later after the addresses have rotated.
Nothing below is subtle in its consequences even where it is subtle in its
cause.

Nothing in this document was changed in the code when it was written; it is
reconnaissance. No file under `usr.sbin/bluetooth/` or `lib/` was modified.

## Reference implementations obtained

| Stack | Source | Snapshot commit | Role |
| --- | --- | --- | --- |
| BlueZ 5.87 | `git.kernel.org/pub/scm/bluetooth/bluez.git` | `92305dc06ab8a6d89af2dae1d725cc4d51462ad1` | the dominant Linux peer |
| Zephyr | `github.com/zephyrproject-rtos/zephyr` | `2665fcca3cced3aefb7202d6289991d8cc1dfcac` | PTS-qualified; where it differs from BlueZ it usually tracks the qualification tests |
| Apache NimBLE | `github.com/apache/mynewt-nimble` | `1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845` | a third independent reading of the same specifications |

A standing caveat for this area specifically: **BlueZ is the weakest of the
three references for GAP.** BlueZ's advertising, scanning and connection
policy live in the Linux kernel's `net/bluetooth`, not in the userspace
repository, so `src/adapter.c` and `src/advertising.c` show only the D-Bus
surface and a thin parameter-validation layer. Where a comparison below says
"BlueZ delegates to the kernel", that is a real gap in the evidence, not a
finding about BlueZ. Zephyr and NimBLE carry the whole host in-tree and are the
load-bearing references here.

Adjudicating text: `/usr/src/bluetooth-specs/Core_Specification_6_3.txt` (Vol 3
Part C is GAP, Vol 6 Part B has the link-layer advertising, scanning and privacy
rules, Vol 4 Part E has the HCI commands) and the Core Specification Supplement
v15 for advertising data. Line numbers below are lines in those text files.

## Scope

The target is Bluetooth 5.2 plus Connection Subrating. Features from 5.4 or 6.x
that this stack deliberately does not implement — PAwR, Encrypted Advertising
Data, Advertising Coding Selection, Channel Sounding — are out of scope and are
not reported as gaps. Where a 6.3 spec paragraph has drifted from what 5.2 said,
the 5.2 reading governs and the drift is noted.

## Classification key

- **OURS-WRONG** — the spec, or the unanimous practice of the references,
  contradicts us.
- **OURS-RIGHT-OTHERS-DIFFER** — we match the spec and at least one reference
  does not. Recorded so nobody "fixes" us towards the reference.
- **ECOSYSTEM-SPLIT** — the references disagree and the spec does not settle
  it. Needs a product decision, not a patch.
- **AGREE** — checked, no divergence. Recorded so the ground is not re-ploughed.

---

## Ranked findings

Ranked by impact against a real peer — an Android or iOS phone, or a Linux
host — ahead of theoretical conformance. The area prefix is G (general/policy),
A (advertising), S (scanning), C (connection), P (privacy), D (advertising
data).

| # | Area | Finding | Class | Impact |
| --- | --- | --- | --- | --- |
| 1 | G1 | the first successful pairing makes the device permanently unpairable | OURS-WRONG | violates a GAP `shall`; no new phone can ever connect again |
| 2 | C1 | LE event mask omits bit 5, so every peer parameter request is link-layer rejected | OURS-WRONG | phones get `LL_REJECT_EXT_IND` 0x1A; stuck or dropped links |
| 3 | C2 | as Central we force 7.5–15 ms with peripheral latency 4, immediately | OURS-WRONG | phones disconnect with 0x3B Unacceptable Connection Parameters |
| 4 | S1 | extended advertising reports are recognised as fragmented and then discarded | OURS-WRONG | BT5 peers appear as a bare MAC address with no name or UUIDs |
| 5 | C3 | `ng_l2cap` supervision-timeout check is 2x too lax; the comment's own algebra disproves it | OURS-WRONG | we answer "accepted" to an illegal request the controller then rejects |
| 6 | D1 | a long local name silently deletes the Service UUID list from the advertisement | OURS-WRONG | UUID-filtered scans on Android and iOS never see us |
| 7 | A1 | Mesh Proxy connectable advertising is rejected by our own validator and can never start | OURS-WRONG | mesh-over-GATT from a phone is entirely non-functional |
| 8 | A2 | the extended-to-legacy advertising fallback violates the command-mixing rule and `err(1)`s | OURS-WRONG | peripheral unreachable, or the daemon exits, on a BT5 controller |
| 9 | C4 | a kernel LE connect timeout frees the connection without `LE Create Connection Cancel` | OURS-WRONG | one failed connect wedges the adapter until reset |
| 10 | P1 | one rejected resolving-list entry stops every later peer from being programmed | OURS-WRONG | bonded peers silently lose reconnection, in bond-table order |
| 11 | C5 | Peripheral Preferred Connection Parameters (0x2A04) is neither published nor read | OURS-WRONG | no negotiation surface in either role |
| 12 | S2 | a scan response is consumed as a fragment tail of an outstanding advertising chain | OURS-WRONG | loses exactly the name that lives only in the scan response |
| 13 | C6 | the advertising filter policy is computed once at boot and never revisited | OURS-WRONG | unpaired peers stay connectable; new peers stay locked out |
| 14 | S3 | the Flags AD type is never parsed, so no discoverability filtering exists | OURS-WRONG | discovery lists fill with undiscoverable beacons; no limited discovery |
| 15 | D2 | 128-bit service UUIDs are never advertised, and the 16-bit list is hardcoded but marked complete | OURS-WRONG | custom-service filtering cannot find us; the complete marker lies |
| 16 | A3 | directed advertising is unusable on the extended path | OURS-WRONG | the fast HID reconnect path fails on every BT5 controller |
| 17 | P2 | one RPA is generated once and applied to every adapter | OURS-WRONG | separate adapters become linkable to one another |
| 18 | D3 | `BR/EDR Not Supported` is set unconditionally although CTKD is implemented | OURS-WRONG | peers classify a dual-mode device as LE-only; our own CTKD is unreachable |
| 19 | C7 | peripheral parameter update checks only local features and has no L2CAP fallback | OURS-WRONG | fails with 0x1A against a central lacking LL CPR, with no recovery |
| 20 | S4 | scan defaults (100 ms / 50 ms) match no GAP-recommended configuration | OURS-WRONG (a `should`) | measurably worse discovery of a backgrounded phone |
| 21 | S5 | the LE Coded PHY is scanned with the LE 1M parameters | OURS-WRONG | long-range peripherals are discovered erratically |
| 22 | A4 | advertising uses one flat interval, 100 ms, with min equal to max | OURS-WRONG (a `should`) | roughly doubles worst-case discovery latency |
| 23 | D4 | the scan response advertises a Complete name longer than GATT 0x2A00 serves | OURS-WRONG | the device visibly renames itself after connecting |
| 24 | A5 | no client notification for `LE Advertising Set Terminated` | OURS-WRONG | a client that sets a duration cannot learn the set stopped |
| 25 | S6 | truncated and incomplete reports are surfaced with no status | OURS-WRONG | cannot distinguish a silent beacon from a lost advertisement |
| 26 | S7 | the result array bounds the scan loop, starving scan-response name merging | OURS-WRONG | in a crowded room, a truncated list of unnamed devices |
| 27 | C8 | `LE Extended Create Connection` exists but has no callers | OURS-WRONG (gap) | cannot connect to an extended-only or Coded-PHY advertiser |
| 28 | S8 | RSSI 0x7F "not available" is treated as +127 dBm by the RSSI filter | OURS-WRONG | proximity gating admits exactly the devices it cannot measure |
| 29 | A6 | `connectable && scannable` with extended PDUs is not rejected, though the comment cites the rule | OURS-WRONG | opaque `IPC_ERR_IO` instead of a diagnosable error |
| 30 | D5 | name shortening truncates on a byte boundary and can split a UTF-8 character | ECOSYSTEM-SPLIT | non-ASCII names render with a replacement glyph |
| 31 | P3 | bonded peers with no IRK are excluded from the resolving list | ECOSYSTEM-SPLIT | inconsistent local-address policy across peers |
| 32 | C9 | Connection Subrating: the host-support bit is advertised, nothing implements it | OURS-WRONG (gap) | subrate changes are silently dropped; cached interval goes stale |

Six spec-citing comments were checked and found to contradict their own source
or their own code. Consistent with the pattern recorded in the previous sweep,
**three of the six mark live defects** (C3, A1, A6) and three are citation
errors over correct code (A7, S9, S10). They are listed in section 6.

---

## 1. Advertising

### G1 — The first successful pairing makes the device permanently unpairable [OURS-WRONG, HIGHEST]

This is the highest-impact finding in the sweep and it is one line.

`blued.c:4755`:

```c
uint8_t filt = (nbonded > 0) ? 0x02 : 0x00;
```

`nbonded` is the number of bonds with an LTK, counted by
`load_filter_accept_list()` (`blued.c:2218-2261`). `filt` becomes the
`Advertising_Filter_Policy` passed to `hci_le_set_ext_adv_params_phy()` at
`blued.c:4783-4786` and to `hci_le_set_advertising_params()` at
`blued.c:4837-4839`. Policy 0x02 is "process connection requests only from
devices in the Filter Accept List".

At the same time the advertising data is built by `ble_build_adv_data()`
(`blued.c:4685`), whose Flags octet is fixed at `hci_adv.c:310-312`:

```c
/* Default: LE General Discoverable + BR/EDR Not Supported. */
return (ble_build_adv_data_flags(buf, buflen,
    AD_FLAG_GENERAL_DISC | AD_FLAG_BREDR_NOT_SUPP, name, uuids, nuuids));
```

So from the moment there is one bond, we advertise **LE General Discoverable
Mode** while refusing connections from everything except the accept list.

Vol 3 Part C Section 9.2.4.2, text lines 65067-65071, verbatim:

> While a device is in general discoverable mode the Host configures the
> Controller as follows:
>
> - The Host **shall** set the advertising filter policy for all advertising
>   sets that share the same Identity Address or the same IRK to 'process scan
>   and connection requests from all devices'.

The identical `shall` appears for Limited Discoverable Mode at text line 65012.
This is not a recommendation and it has no exception for bonded devices; it is
the rule that makes "discoverable" mean something. The two modes where a filter
policy is at the Host's discretion are Non-Discoverable (text line 64957) and
Non-Connectable (text line 65358), and in both the spec says *should*, not
*shall*, and lists both policies as acceptable.

All three references default to no filter and require an explicit opt-in:

- Zephyr, `subsys/bluetooth/host/adv.c:814-827` — `get_filter_policy()` returns
  `BT_LE_ADV_FP_NO_FILTER` unless the application passes
  `BT_LE_ADV_OPT_FILTER_CONN` or `BT_LE_ADV_OPT_FILTER_SCAN_REQ`
  (`include/zephyr/bluetooth/bluetooth.h:703-706`), and returns no-filter
  unconditionally when `CONFIG_BT_FILTER_ACCEPT_LIST` is off.
- NimBLE, `nimble/host/src/ble_gap.c:2699` — `cmd.filter_policy =
  adv_params->filter_policy`, an application field that defaults to zero.
- BlueZ userspace has no advertising filter policy at all; the Linux kernel
  advertises with policy 0x00 and exposes accept-list filtering only through
  explicit mgmt operations.

**Consequence.** A device that has been paired once advertises itself to every
phone in range as generally discoverable, and then silently drops their
connection requests in the controller. The phone shows the device in its
scan list, the user taps it, and it times out. There is no error anywhere —
the connection request never reaches the host. The device is, from the user's
point of view, permanently broken for new pairings after the first one.

Compounding it, `nbonded` is read once during startup and never recomputed
(finding C6), so the policy is also wrong in the other direction after an
unpair, and the accept list cannot be edited at runtime *because* the policy is
0x02 (finding C6 again — the accept-list commands are Command Disallowed while
a policy that uses the list is active).

This finding also corrects a partial reading. At the HCI level the code's own
comment (`blued.c:4742-4753`) is accurate: it correctly explains that policy
0x01 filters scan requests only and would not enforce a bonded-only policy, and
it correctly names 0x02. Judged against Vol 4 Part E Section 7.8.5 alone,
nothing is wrong. The defect is only visible one layer up, in Vol 3 Part C — a
good illustration of why an HCI-level review is not a GAP review.

### A1 — Mesh Proxy connectable advertising is rejected by our own validator [OURS-WRONG, HIGH]

`hci_adv.c:1278-1280`:

```c
/* max_events 0: air until explicitly stopped (Section 7.2.2.2.2). */
return (hci_le_set_ext_adv_enable_burst(hci_fd,
    MESH_PROXY_ADV_HANDLE, 0x00));
```

`hci_adv.c:880-890`:

```c
hci_le_set_ext_adv_enable_burst(int hci_fd, uint8_t handle, uint8_t max_events)
{
	...
	if (!hci_adv_handle_valid(handle) || max_events == 0) {
		errno = EINVAL;
		return (-1);
	}
```

The call site's comment says `max_events` 0 means "air until explicitly
stopped". The callee's comment (`hci_adv.c:878`) says "max_events must be
non-zero". They cannot both be right, and the spec settles it in the call
site's favour: Vol 4 Part E Section 7.8.56, `Max_Extended_Advertising_Events[i]`
parameter table, text lines 117048-117049, gives 0x00 as **"No maximum number
of advertising events"**. Zero is the correct and only value for indefinite
advertising, and our own generic `hci_le_set_ext_adv_enable()` (`hci_adv.c:832`)
uses it.

So `hci_mesh_proxy_adv_start()` always returns -1 without ever reaching the
air. The caller is `ctl.c:1915`. Every test stubs the function out
(`tests/usr.sbin/bluetooth/blued/test_common.h:302`, `ctl_test.c:325`,
`mesh_broker_loop_test.c:166`), which is why no test catches it.

References: NimBLE passes `max_events` through with no non-zero requirement
(`ble_gap.c:3456-3555`); Zephyr writes `param ? param->num_events : 0`
(`adv.c:330-363`).

**Consequence.** A phone running nRF Mesh, or any GATT Proxy client, can never
discover or connect to this node's Mesh Proxy Service. Mesh provisioning and
control over GATT from a phone is entirely non-functional.

### A2 — The extended-to-legacy advertising fallback is a spec violation and a fatal exit [OURS-WRONG, HIGH]

`blued.c:4735` issues an extended command unconditionally, with no
`LE_FEAT_EXT_ADVERTISING` check:

```c
hci_le_clear_adv_sets(aa->hci_fd);
```

`blued.c:4783-4849` then attempts the full extended chain and, on any failure,
falls through to legacy commands with fatal error handling:

```c
} else {
	LOG_HOGP(1, "ext adv not supported, using legacy");
	if (hci_le_set_advertising_params(aa->hci_fd,
	    adv_imin, adv_imax, 0x00, own_addr_type, filt) < 0)
		err(1, "set advertising parameters");
```

Vol 4 Part E Section 3.1.1, text lines 86407-86410, verbatim:

> If, since the last power-on or reset, the Host has ever issued a legacy
> advertising command and then issues an extended advertising command, or has
> ever issued an extended advertising command and then issues a legacy
> advertising command, the Controller shall return the error code Command
> Disallowed (0x0C).

and text line 86412:

> A Host should not issue legacy commands to a Controller that supports the LE
> Feature (Extended Advertising).

Because line 4735 has already issued an extended command on every adapter, on a
BT-5.x controller the legacy branch is *guaranteed* to return 0x0C, and `err(1)`
terminates blued. The trigger is realistic: the persisted `adv_props` restored
at `blued.c:4764-4776` is an arbitrary 16-bit value from the persist file, and a
restored non-scannable type makes `hci_le_set_ext_scan_response_data()` fail,
which takes the fallback.

The structural point is that the choice of command family must be made **once**,
from the LE feature bits, before the first advertising command of any kind. All
three references do exactly that: BlueZ's kernel picks once from the feature
bits, Zephyr selects from `BT_DEV_FEAT_EXT_ADV`, NimBLE compiles one family in
via `MYNEWT_VAL(BLE_EXT_ADV)`. None of them falls back mid-sequence. Note that
`hci_adv_configure()` (`hci_adv.c:660`), `hci_le_mesh_scan_set()`
(`hci_scan.c:517`) and `ctl_adv_program()` (`ctl.c:2418`) all gate correctly —
it is only this startup path that does not.

### A3 — Directed advertising is unusable on the extended path [OURS-WRONG, MEDIUM-HIGH]

Two independent failures, either sufficient.

First, duration. `hci_adv.c:832-856` — the only enable the primary set uses —
hardcodes `cp[3..4] = 0` (duration) and `cp[5] = 0` (max events).
`adv_kind_to_ext_props()` (`hci_adv.c:628-636`) can produce `0x001D`, high duty
cycle connectable directed, reachable from the operator verb
`IPC_ADV_SET_PARAMS` (`ctl.c:5271` accepts `payload[5] <= 4`, which includes
`HCI_ADV_CONN_DIR_HIGH`), and `ctl.c:5334-5338` re-enables with duration 0.

Section 7.8.56, text line 116933, verbatim:

> If the advertising is high duty cycle connectable directed advertising, then
> Duration[i] shall be less than or equal to 1.28 seconds and shall not be
> equal to 0.

Second, advertising data. Table 7.3 (text lines 116219-116222) marks both
directed rows — low and high duty cycle — as advertising data **"Not allowed"**,
and Section 7.8.53's error table (text line 116330) returns Invalid HCI Command
Parameters when the event type does not support advertising data and the set
already contains data. blued always programs advertising data into set 0 at
startup (`blued.c:4791`), so switching set 0 to any directed kind fails outright
regardless of duration.

Both references enforce both rules host-side. Zephyr forces the timeout itself
(`adv.c:1267-1273`, `start_param.timeout = BT_GAP_ADV_HIGH_DUTY_CYCLE_MAX_TIMEOUT`
= 128) and rejects high-duty directed combined with `BT_LE_ADV_OPT_EXT_ADV`
(`adv.c:388-394`). NimBLE rejects `duration == 0 || duration > 128` for
high-duty directed (`ble_gap.c:3484-3489`) and rejects legacy advertising data
on a directed set (`ble_gap.c:3615-3653`). BlueZ has no directed advertising API.

**Consequence.** Directed advertising is the standard fast-reconnect path for a
HID peripheral against Android and iOS. On this stack it silently fails with
`IPC_ERR_IO` on every BT5 controller.

### A4 — One flat advertising interval, min equal to max [OURS-WRONG (a `should`), MEDIUM]

`blued_internal.h:184` defines `ADV_INTERVAL_100MS 0x00A0` and it is used as
*both* min and max at `blued.c:3038`, `:3177`, `:4267-4268`, `:4764-4765` and
`:4811-4812`, and likewise for the mesh bearer (`hci_adv.c:1147`) and the proxy
(`hci_adv.c:1267-1268`).

Two separate `should`s are missed. Section 7.8.5, text lines 112144-112146
(identical wording for extended at text lines 116250-116252):

> The Advertising_Interval_Min and Advertising_Interval_Max should not be the
> same value to enable the Controller to determine the best advertising
> interval given other activities.

and Vol 3 Part C Appendix A, text lines 68267-68271: `TGAP(adv_fast_interval1)`
is **30 ms to 60 ms** for Undirected Connectable Mode and for General or Limited
Discoverable Mode sending connectable undirected advertising events, which is
exactly what we do; text lines 65861-65872 make it a `should` for a Peripheral
entering those modes.

NimBLE ships the GAP values verbatim as a range —
`BLE_GAP_ADV_FAST_INTERVAL1_MIN/MAX = 48/96` (30/60 ms) for connectable modes,
`FAST_INTERVAL2 = 160/240` (100/150 ms) for non-connectable
(`ble_gap.h:73-82`, applied in `ble_gap_adv_dflt_itvls()`,
`ble_gap.c:2632-2658`). BlueZ passes a caller-supplied range and lets the kernel
default (`advertising.c:1100-1104`). Zephyr's `BT_LE_ADV_CONN_FAST_1` macros
carry a range.

We advertise at 100 ms flat where GAP recommends 30-60 ms, and by pinning min to
max we deny the controller any room to de-conflict advertising against an active
scan or connection.

The values are pinned in `spec_extref_gap_timers.h`.

### A5 — No client notification for `LE Advertising Set Terminated` [OURS-WRONG, MEDIUM]

`blued_event.c:958-975` decodes subevent 0x12 and calls
`blued_ctl_adv_set_terminated()` (`ctl.c:2360-2375`), which only sets
`ctl_adv_sets[i].enabled = false`. No IPC event is emitted, and libble has no
advertising-complete callback.

Section 7.8.56 (text lines 117092-117102) makes this event the only signal for
duration expiry, `Max_Extended_Advertising_Events` exhaustion, and
connection-caused termination. NimBLE surfaces it as `BLE_GAP_EVENT_ADV_COMPLETE`
with `.reason`, `.instance`, `.conn_handle`, `.num_ext_adv_events`
(`ble_gap.c:1613-1630`). Zephyr surfaces `adv->cb->sent` with
`num_completed_ext_adv_evts` and `adv->cb->connected` (`adv.c:2228-2337`).

A libble client that sets a duration or an event count therefore has no way to
learn that the set stopped, and reports "enabled" state it never learns has
changed.

### A6 — Half of the extended-PDU prohibition is implemented, and the comment quotes the half that is missing [OURS-WRONG, MEDIUM]

`hci_adv.c:452-463`:

```c
/*
 * Finding H-M4: Core Spec Vol 4 Part E §7.8.53 forbids the high-duty-
 * cycle directed bit (bit 3) with extended-PDU advertising (the "use
 * legacy PDUs" bit 4 clear).  ...
 */
if ((event_props & BLUED_HCI_EXT_ADV_PROP_HIGH_DUTY_DIRECTED) &&
    !(event_props & BLUED_HCI_EXT_ADV_PROP_LEGACY)) {
	errno = EINVAL;
	return (-1);
}
```

The sentence being cited, text lines 116228-116231, contains *two*
prohibitions:

> If extended advertising PDU types are being used (bit 4 = 0), then the
> advertisement shall not be both connectable and scannable (bits 0 and 1 must
> not both be set to 1) and high duty cycle directed connectable advertising
> (<= 3.75 ms advertising interval) shall not be used (bit 3 = 0).

Only the second is implemented. The first is the one with no legacy analogue —
`ADV_IND` is exactly connectable-and-scannable — so it is the one that code
written against the legacy model carries forward by accident. And it is
reachable: `ctl.c:5464-5467` passes `ipc_get_le16(payload + 8)` straight into
`hci_le_set_ext_adv_params_phy()` with no validation of the properties word at
all, and `lib/libble/ble.c:3621-3641` validates only min and max. Properties
`0x0003` reaches the controller.

NimBLE rejects it host-side in `ble_gap_ext_adv_params_validate()`
(`ble_gap.c:3319-3362`) *and* enforces the full Table 7.3 whitelist for legacy
properties (`ble_gap.c:3170-3185`). Zephyr does not check host-side either, only
documenting the rule in `bluetooth.h:714-721` — so *whether* to check is partly
an ecosystem split. What is not a split is citing the sentence and implementing
half of it.

Wire harm is nil (the controller rejects), but the operator gets an opaque
`IPC_ERR_IO` instead of a diagnosable `IPC_ERR_INVAL`. Table 7.3 and both
prohibitions are pinned in `spec_extref_gap_adv_props.h`.

### A7 — Two more advertising-parameter laxities, and one comment citing a number the spec does not contain [OURS-WRONG, LOW]

Three smaller items, grouped:

**Legacy PDUs with a Coded primary PHY are not rejected.** `hci_adv.c:442-450`
accepts `primary_phy` in {0x01, 0x03} independently of the LEGACY properties
bit; `hci_adv_configure()` (`hci_adv.c:692-700`) does the same; `ctl.c:5270`
accepts `payload[8]` in {1,3} with any kind, all of which map to legacy
properties. Text lines 116277-116280: "If legacy advertising PDUs are being
used, the Primary_Advertising_PHY shall indicate the LE 1M PHY." NimBLE forces
1M for legacy (`ble_gap.c:3208-3214`); Zephyr pins it likewise.

**Legacy-properties sets are not held to the 31-octet single-write rule.**
`hci_le_set_ext_adv_data()` (`hci_adv.c:782-826`) accepts up to 1650 octets and
fragments regardless of the set's properties, and blued's primary set 0 is
always legacy-properties (`0x0013`). Text lines 116659-116661: "The advertising
set uses legacy advertising PDUs that support advertising data and either
Operation is not 0x03 or Advertising_Data_Length exceeds 31 octets." ->
Invalid HCI Command Parameters. Reachable via `IPC_ADV_SET_HANDLE_DATA`
(`ctl.c:5486-5501`, length up to 255). Zephyr clamps to 31 for non-extended sets
(`adv.c:552-556`); NimBLE rejects it (`ble_gap.c:3615-3653`). Both are stricter
than us.

**A comment citing a limit that does not exist.** `hci_adv.c:726-734`:

```
 * The Core Spec (Vol 4 Part E §7.8.54) allows up to 254 bytes for
 * non-connectable, non-scannable extended advertising PDUs.  We use
 * the conservative limit of 251 (NG_HCI_LE_EXT_ADV_DATA_MAX) for
 * all advertising types for simplicity, ...
```

Section 7.8.54's `Advertising_Data_Length` table, text lines 116713-116714, says
"0 to 251". 251 is the *spec maximum* per HCI fragment, not a conservative host
choice, and 254 appears nowhere in the section. The code is right; only the
rationale is wrong — and a rationale that describes the legal maximum as
conservative invites a future "relaxation" to an illegal value.

Also low: `lib/libble/ble.h:223-224` types `interval_min`/`interval_max` as
`uint16_t` in `ble_adv_params_t`, so the operator API tops out at 0xFFFF (40.96 s)
against the extended field's 0xFFFFFF (Section 7.8.53, text lines 116394-116398).
The daemon-side `struct hci_adv_config` is correctly `uint32_t`
(`blued.h:78-79`), and the per-set `ble_adv_set_params()` is correct too.

### A8 — Advertising is restarted after a connection ends, which is right, and better than two of the three references [OURS-RIGHT-OTHERS-DIFFER]

Recorded because this was one of the questions the sweep was asked, and because
the answer is the good one.

`blued_peripheral.c:28-91`, `blued_periph_readvertise_one()`, is called from the
disconnect path (`blued_event.c:2569`, in the peripheral-role arm), from the
setup-thread failure pipe (`blued_event.c:1671-1676`, `:1734-1737`), and —
notably — immediately after accepting a peripheral ATT connection
(`blued_peripheral.c:317-319`, "A connectable advertising set is disabled when
it creates a link"), so a second central can still connect. Failures retry on a
one-second kqueue timer up to `BLUED_READVERTISE_MAX_RETRIES`. The legacy arm
first calls `blued_adv_legacy_reclaim()` (`blued.c:3034-3097`) to take the
single legacy advertising resource back from a mesh burst, restoring our own
parameters and payload before enabling. `blued_event.c:970-972` clears
`adp->adv_enabled` on Advertising Set Terminated for handle 0, so the host's
view stays honest.

The peripheral is reachable again after a disconnect. Against the references:

- **Zephyr** has removed the persist mechanism entirely in this snapshot — no
  `BT_ADV_PERSIST`, no `BT_LE_ADV_OPT_ONE_TIME`, no `bt_le_adv_resume()`. The
  legacy advertiser object is *destroyed* on connection
  (`hci_core.c:1610-1618`, `bt_le_adv_delete_legacy()`). The application must
  re-arm from its `disconnected` callback.
- **NimBLE** calls `ble_gap_slave_reset_state(instance)` on connection
  (`ble_gap.c:2113-2120`) and touches no advertising state on disconnect
  (`ble_gap.c:1244-1293`). `ble_gap.h:1428-1438` warns that restarting from
  inside the host task is unreliable.
- **BlueZ** userspace does nothing either; the Linux kernel's
  `hci_enable_advertising_sync()` does the re-enable.

So blued matches the BlueZ-plus-kernel *system* behaviour, which is what a phone
expects from a Linux-class host, and is more robust than either embedded stack.
Do not "fix" this towards Zephyr or NimBLE.

**One caveat, and it is ours alone (LOW).**
`blued_periph_readvertise_one()` re-enables **only handle 0x00**
(`blued_peripheral.c:41`). Client-created connectable sets (`ctl.c:5449+`) are
terminated by the controller on connection, marked `enabled = false`
(`ctl.c:2371-2374`), and never re-enabled — and per A5 the client is never told.
Requiring the client to re-arm matches Zephyr and NimBLE; being unable to
*learn* that it must is the divergence. The Coded-PHY set 1 created at
`blued.c:4808-4826` is non-connectable, so it is unaffected.

---

## 2. Scanning

### S1 — Extended advertising reports are recognised as fragmented and then discarded [OURS-WRONG, HIGH]

The previous sweep listed this as its finding #9, "extended advertising reports
are never reassembled". It is still true, and the code has since changed in a
way that makes it *harder* to notice rather than fixing it.

`hci_scan.c:1119-1163`:

```c
unsigned status = (event_type >> 5) & 0x03u;
...
if (status == 0x01u && addr_type != 0xFF) {
	ext_frag_mark(addr_type, p + 3, sid);            /* fragment: NOT parsed */
} else if (status == 0x02u && addr_type != 0xFF) {
	(void)ext_frag_take(addr_type, p + 3, sid);      /* truncated: NOT parsed */
} else if (status == 0x00u &&
    (addr_type == 0xFF || !ext_frag_take(addr_type, p + 3, sid))) {
	hci_parse_ad_fields(p + EXT_ADV_REPORT_HDR_LEN, data_len, sr);
}
```

The tracking table, `hci_scan.c:959-965`, holds `{used, at, addr[6], sid}` and
**no data buffer and no length**. `hci_parse_ext_adv_report()` returns
`EXT_ADV_REPORT_HDR_LEN + data_len` and retains no bytes. There is no
accumulation buffer anywhere in the tree.

So the code now correctly *identifies* fragmentation — which is why it no longer
mis-parses a fragment's tail as a fresh AD structure, the bug the tracking table
was added to fix — and then, instead of joining the fragments, throws them all
away. Net behaviour for a fragmented advertisement: the first fragment produces
a result row with `has_name = false`, `mfr_id = 0xFFFF`, `num_svc_uuids = 0`;
the terminal report is dedup-merged into the same row and contributes nothing.
The device appears as a MAC address and an RSSI.

Section 7.7.65.13, text lines 106057-106063, verbatim:

> The Controller may split the data from a single advertisement or scan response
> (whether one PDU or several) into several reports. If so, each report except
> the last shall have an Event_Type with a data status field of "incomplete,
> more data to come", while the last shall have the value "complete"; the
> Address_Type, Address, Advertising_SID, Primary_PHY, and Secondary_PHY fields
> shall be the same in all the reports.

And the arithmetic that makes this unavoidable rather than exotic — Vol 6 Part B
Section 4.4.3.5, text lines 138919-138922:

> the Controller must be able to store and report to the Host at least 251
> octets of data from a single advertisement or scan response (irrespective of
> the number of PDUs used to transmit the data) if the Controller supports LE
> extended advertising and 31 octets otherwise.

The per-report `Data_Length` maximum is 229 (text lines 106292-106294). 251 is
greater than 229, so an advertisement at the controller's *guaranteed minimum
capacity* cannot fit in one report. A host without reassembly has a hard ceiling
of 229 observable octets against a 1650-octet maximum it may itself transmit.

- **Zephyr** accumulates. `subsys/bluetooth/host/scan.c:70` declares
  `ext_scan_buf`; `:127-144` has `init_reassembling_advertiser()` /
  `reset_reassembling_advertiser()`, keyed on (address, SID); `:990-1000`
  appends each fragment and delivers the joined buffer, with a reassembly
  timeout (`:96-108`) and an explicit overflow path (`:968-972`).
- **NimBLE** does not reassemble in the host, but delivers **every fragment's
  data** to the application along with `desc.data_status`
  (`ble_hs_hci_evt.c:678-708`), so the application can. `desc.data` and
  `desc.length_data` are always populated.
- **BlueZ** delegates reassembly to the Linux kernel's
  `hci_le_ext_adv_report_evt()`; userspace only ever sees joined EIR.

Ours is the only one of the four that neither joins the data nor hands it up.

**Consequence.** Every extended advertiser whose data the controller splits is
discovered as an anonymous MAC with no name, no service UUIDs and no
manufacturer data. Our own `ble_scan_result_match()` name and UUID filters
(`hci_scan.c:544-571`) then reject those devices outright.

The Data Status contract and the 251-versus-229 arithmetic are pinned in
`spec_extref_gap_ext_adv_report.h`.

### S2 — A scan response is consumed as the tail of an outstanding advertising chain [OURS-WRONG, HIGH]

`ext_frag_take()` (`hci_scan.c:998-1009`) matches on (address type, address,
SID) only. It does not consider Event_Type bit 3, the scan-response bit.

Section 7.7.65.13, text lines 106065-106067, verbatim:

> When a scan response is received, bits 0 to 2 and 4 of the event type shall
> indicate the properties of the original advertising event and the
> Advertising_SID field should be set to the value in the original scannable
> advertisement.

A scan response therefore carries the *same* SID as the advertisement it
answers, so a complete `SCAN_RSP` report arriving while an advertising chain is
outstanding matches the mark, is treated as a continuation tail, and is never
AD-parsed. And Vol 6 Part B Section 4.4.3.5, text lines 138937-138939, requires
the two streams to be kept apart anyway:

> Advertising data reports and scan data reports shall be processed separately
> when determining duplicate advertising reports; i.e., an advertising data
> report shall not be treated as a duplicate of a scan response report or vice
> versa.

Zephyr's key has the same shape (`scan.c:919-921`) and shares the conflation —
but Zephyr *concatenates* rather than discards, so the scan-response bytes still
reach the application. NimBLE never conflates, having no host-side chain state.

Listed separately from S1 because it bites even when the advertisement itself is
short, as long as any preceding fragment mark is live — and the name living only
in the scan response is the overwhelmingly common iOS and Android peripheral
layout.

### S3 — The Flags AD type is never parsed, so no discoverability filtering exists [OURS-WRONG, MEDIUM]

`AD_TYPE_FLAGS` is defined at `hci_scan.c:40` and never referenced anywhere in
the file. `hci_parse_ad_fields()` (`hci_scan.c:219-272`) handles only 0x08/0x09
(name), 0xFF (first two octets), and 0x02/0x03 (16-bit UUIDs). `struct
ble_scan_result` (`hci_util.h:42-52`) has no flags field; `ble_scan_params_t`
(`ble.h:259-268`) has no `limited` knob; `struct ctl_scan_params`
(`ctl_internal.h:87`) has none either.

Vol 3 Part C Section 9.2.6.2 — the general discovery procedure this code claims
to implement — text lines 65252-65256, verbatim:

> The Host shall check for the Flags AD type in the advertising data. If the
> Flags AD type (see Section 1.3 of [4]) is present and either the LE General
> Discoverable Mode flag is set to one or the LE Limited Discoverable Mode flag
> is set to one then the Host shall consider the device as a discovered device,
> otherwise the advertising data shall be ignored.

and Section 9.2.5.2 for limited discovery, text lines 65159-65162, the same
shape with only the Limited flag.

- **BlueZ** implements the general-discovery rule and has it **on by default**:
  `src/adapter.c:7429-7434`, `device_is_discoverable()`, `discoverable = eir->flags
  & (EIR_LIM_DISC | EIR_GEN_DISC)`, with `btd_opts.filter_discoverable = true`
  at `src/main.c:1408`, relaxed only when a client installs an explicit filter.
- **NimBLE** implements the limited-discovery rule exactly, in
  `ble_gap_rx_adv_report_sanity_check()` (`ble_gap.c:1566-1576`), applied to both
  legacy (`:1590`) and extended (`:1605`) reports.
- **Zephyr** does not filter in the host; it hands every report up
  (`scan.c:700-704`), pushing the rule to the application. So *where* the check
  lives is an ecosystem split — but no reference silently reports
  non-discoverable devices as a completed GAP discovery, and both stacks that
  expose a limited-discovery API implement the flag check.

**Consequence.** Two concrete symptoms. Our discovery list fills with iBeacons,
Eddystone tags, trackers and every AirPods-class device advertising
non-connectable and non-discoverable — which, with the 64-slot result array of
S7, crowds out the devices a user is looking for. And there is no way for an
application to run the limited-discovery procedure, so the "user just pressed
the pairing button" flow that phone accessories rely on cannot be expressed.

### S4 — Scan defaults match no GAP-recommended configuration [OURS-WRONG (a `should`), MEDIUM]

`hci_scan.c:310-319`:

```c
p->active = 1;			/* active scan */
p->interval = 160;		/* 100 ms / 0.625 */
p->window = 80;			/* 50 ms / 0.625 */
```

100 ms interval with a 50 ms window, a 50% duty cycle. This is the default for
every scan path: `hci_le_scan()` (`:579-587`), `hci_le_ext_scan()`
(`:1271-1280`), `ctl_scan_result()` (`ctl_conn.c:78`), `do_scan()`
(`blued.c:2450`) and the mesh bearer (`hci_scan.c:526`).

Vol 3 Part C Section 9.3.11.2, text lines 65839-65841:

> A Central starting a user-initiated GAP connection establishment procedure
> should use the recommended scan interval TGAP(scan_fast_interval) and scan
> window TGAP(scan_fast_window) for TGAP(scan_fast_period) when scanning on the
> LE 1M PHY

The values, from Appendix A: `TGAP(scan_fast_interval)` = **30 ms to 60 ms**
(text lines 68374-68376), `TGAP(scan_fast_window)` = **30 ms** (text lines
68382-68384), `TGAP(scan_slow_interval1)` = 1.28 s with an 11.25 ms window (text
lines 68399-68419), `TGAP(lim_disc_scan_int)` = 11.25 ms (text lines
68355-68357). 100 ms is above the fast range and far below the slow ones;
50 ms matches no recommended window.

NimBLE ships the GAP values (`ble_gap.h:85,97`,
`BLE_GAP_SCAN_FAST_INTERVAL_MIN` = 30 ms, `BLE_GAP_SCAN_FAST_WINDOW` = 30 ms —
100% duty — applied in `ble_gap_disc_fill_dflts()`, `ble_gap.c:5059-5077`, with
`BLE_GAP_LIM_DISC_SCAN_INT/WINDOW` = 11.25 ms for limited discovery). Zephyr
ships them too (`include/zephyr/bluetooth/gap.h:44-48`), with
`BT_LE_SCAN_ACTIVE` = 60/30 and `BT_LE_SCAN_ACTIVE_CONTINUOUS` = 30/30 carrying
a `BUILD_ASSERT` that documents the continuous case. BlueZ leaves it to the
kernel.

Related and worse: `ctl_conn.c:71-76` caps any scan at 5 seconds, while
`TGAP(gen_disc_scan_min)` is 10.24 s (text lines 68334-68336). We can never
satisfy the GAP general-discovery minimum scan time.

All the TGAP values are pinned in `spec_extref_gap_timers.h`.

### S5 — The LE Coded PHY is scanned with the LE 1M parameters [OURS-WRONG, MEDIUM]

`hci_scan.c:1186-1208` writes the same `p->interval` and `p->window` into both
the 1M and the Coded entries of the extended scan parameter array. `struct
hci_scan_params` (`hci_util.h:66-72`) has no Coded variants, and
`ctl_conn.c:126-128` sets `sphys = 0x05` when the controller supports Coded, so
both PHYs get 100 ms / 50 ms.

Vol 3 Part C, text lines 65841-65843: "...and should use scan interval
TGAP(scan_fast_interval_coded) and scan window TGAP(scan_fast_window_coded)...".
Those are 90-180 ms and 90 ms (text lines 68366-68380) — three times the 1M
values, because Coded-PHY packets are two to eight times longer on air.

Zephyr models the distinction explicitly (`scan.c:259-268`,
`scan_param->interval_coded ? scan_param->interval_coded : scan_param->interval`).
NimBLE takes separate `uncoded_params` and `coded_params` structs
(`ble_gap.c:5099-5145`).

A 50 ms window on Coded S=8 is under one long-range advertising PDU duration in
the worst case, so long-range peripherals are discovered erratically despite our
having correctly asked to scan on the Coded PHY.

### S6 — Truncated and incomplete reports are surfaced with no status [OURS-WRONG, MEDIUM]

`hci_parse_ext_adv_report()` returns a non-zero consumed length for data status
0b00, 0b01 and 0b10 alike, so `hci_le_ext_scan_ex()` (`hci_scan.c:1621-1660`)
stores all three as results. For 0b01 and 0b10 the stored record has
`has_name = false`, `mfr_id = 0xFFFF`, `num_svc_uuids = 0`
(`hci_scan.c:1095-1099`). `struct ble_scan_result` carries no data-status field,
nor does the IPC scan-result event (`ctl.c:2997-3028`), nor `ble_scan_result_t`
(`ble.h:57-64`).

To the sweep's precise question — no, a partial buffer is never surfaced as if
complete. No bytes are accumulated, so there is nothing partial to leak. The
defect is the opposite: the truncation is invisible.

Section 7.7.65.13, text lines 106069-106071, verbatim:

> An Event_Type with a data status field of "incomplete, data truncated" shall
> indicate that the Controller attempted to receive an AUX_CHAIN_IND PDU but was
> not successful or received it but was unable to store the data.

Zephyr suppresses: on truncated it logs "Discarding incomplete advertisement",
resets the reassembly state and does not notify the application
(`scan.c:941-952`). NimBLE reports with status: `desc.data_status =
BLE_GAP_EXT_ADV_DATA_STATUS_TRUNCATED` and delivers
(`ble_hs_hci_evt.c:683-690`). Those are the two defensible designs. Ours is the
third: report *without* status, which is the one behaviour neither reference
chose. An application cannot distinguish a beacon that genuinely carries no
name from a device whose data the controller could not store, so retry logic and
the Section 9.2.7 Name Discovery fallback (text lines 65290-65302) can never be
triggered correctly.

### S7 — The result array bounds the scan loop, starving scan-response name merging [OURS-WRONG, MEDIUM]

Both receive loops are bounded by `count < maxresults` in the `while` condition,
not merely in an inner loop: `hci_scan.c:753` and `hci_scan.c:1474`.
`maxresults` is `BLE_MAX_SCAN_RESULTS` = 64 (`hci_util.h:54`) at every call site.

Two consequences. With `filter_dup == 0` (the operator's `no_dedup` flag,
`ctl_conn.c:85`) no deduplication runs at all (`hci_scan.c:886`, `:1594`,
`:1651`), so 64 slots fill within a few advertising intervals and a "no-dedup"
scan is effectively 64 sightings of three devices. With deduplication on, once
64 distinct addresses have been seen the loop exits — so scan responses that
would have merged names into earlier entries are never received.
`scan_result_merge()` (`hci_scan.c:279-303`) is the only place a name from a
scan response reaches a result row.

The spec requires the scan response to arrive as a *separate* report (Vol 6
Part B, text lines 138937-138939, quoted under S2), which is exactly the report
our loop may already have stopped listening for.

Neither Zephyr nor NimBLE bounds a scan by a result count; both are
callback-driven with unbounded duration. BlueZ accumulates into an unbounded
`adapter->discovery_found` list.

In any environment with more than 64 advertisers in the window — an office, a
train, a ward — discovery returns a truncated list of *unnamed* devices, because
the advertisement of device 64 arrives before the scan response of device 1.

### S8 — RSSI 0x7F "not available" is treated as +127 dBm by the RSSI filter [OURS-WRONG, LOW-MEDIUM]

The extended path validates 0x7F as a legal sentinel (`hci_scan.c:1054`) and
then stores it verbatim (`:1087`). The legacy paths do no RSSI validation at all
(`:876`, `:1583`). The sentinel then flows into the operator filter,
`hci_scan.c:551`:

```c
if (f->has_rssi && sr->rssi < f->rssi_min)
	return (false);
```

`127 < rssi_min` is false for every legal threshold, so a report with **no RSSI
available always passes an RSSI filter**, is displayed as `RSSI: 127`
(`blued.c:2474`) and is cached as the device's RSSI in libble
(`ble.c:766-768`, returned by `ble_get_rssi()`).

Section 7.7.65.13, text lines 106259-106264 (and 105191-105196 for legacy):
"0xXX Range: -127 to +20 Units: dBm / 0x7F RSSI is not available".

Zephyr (`scan.c:838`) and NimBLE (`ble_hs_hci_evt.c:697`) also pass 0x7F
through, so the pass-through itself is an ecosystem split and not a defect.
Neither then *uses* the value as a signal-strength comparand inside the host.
That part is ours alone: a proximity-gated pairing UI admits every device whose
RSSI the controller could not measure, and ranks them as the closest.

Note also `blued_event.c:60-61`, the mesh validator, *does* range-check RSSI.
The scan path does not.

### S9 — Extended scan parameters are clamped to the legacy maximum, and the comment attributes the legacy bound to the extended command [OURS-WRONG, LOW]

`hci_scan.c:305-307` defines `HCI_SCAN_ITVL_MAX 0x4000` citing Section 7.8.10,
and `scan_params_valid()` applies it to the extended paths too
(`hci_le_set_ext_scan_params()` at `:1225`, `hci_le_ext_scan_ex()` at `:1307`).

The two commands have different bounds. Legacy, Section 7.8.10, text lines
112639-112653: range 0x0004 to 0x4000. Extended, Section 7.8.64, text lines
117878-117890: "Range: 0x0004 to 0xFFFF / Time = N x 0.625 ms / Time Range:
2.5 ms to 40.959375 s".

The comment in `hci_util.h:57-64` compounds it by citing "§7.8.64 LE Set
Extended Scan Parameters" alongside the 0x0004-0x4000 range — attributing the
legacy bound to the extended command by name. Impact today is low (all the TGAP
slow values are below 0x4000), but a duty-cycled background scanner using the
upper extended range is refused by our own validator rather than by the
controller.

### S10 — Two more scanning items, one of them a comment that contradicts the spec it cites [OURS-WRONG, LOW]

**A comment that overstates the TX_Power range, and validation written to match
the comment.** `hci_scan.c:1041-1047`:

```
 * ... TX_Power spans the full -127..+126 dBm
 * range with 0x7F = not available (§7.7.65.13); only RSSI is capped
 * at +20 dBm.
```

Section 7.7.65.13's `TX_Power[i]` table, text lines 106251-106257: "0xXX Range:
-127 to +20 Units: dBm / 0x7F Tx Power information not available". TX_Power is
capped at +20 dBm *identically* to RSSI. The comment's claim that only RSSI is
capped is false, and the validator that follows it (`:1053`, `tx_power < -127`)
is exactly as permissive as the false comment describes, admitting 0x15 through
0x7E. Latent rather than live, because the value is discarded (see S11).

**Extended `Num_Reports` is unbounded in the scan path.** `hci_scan.c:1613-1617`
reads `num_reports = p[0]` with no check, while the legacy branch immediately
above (`:1536`) correctly bounds to 25 and `blued_event.c:37-40` correctly bounds
the extended case to 10. Section 7.7.65.13, text lines 106215-106219: "0x01 to
0x0A ... All other values Reserved for future use". Memory safety is preserved
because `hci_parse_ext_adv_report()` returns 0 once the remaining length is
short, which breaks the loop. NimBLE rejects the whole event with
`BLE_HS_EBADDATA` (`ble_hs_hci_evt.c:620-623`).

### S11 — TX power, PHYs, Advertising SID and periodic interval are parsed and thrown away [OURS-WRONG, LOW-MEDIUM]

`hci_parse_ext_adv_report()` reads every one of these and stores none: TX power
at `hci_scan.c:1030` reaches only a log line at `:1090`; primary PHY, secondary
PHY and SID are commented at `:1086` and dropped; the periodic advertising
interval is read at `:1032` and dropped. `struct ble_scan_result`
(`hci_util.h:42-52`) has fields only for address, address type, RSSI, name,
manufacturer ID and 16-bit UUIDs. Even `name_complete` — which is tracked
internally and correctly honoured by `hci_parse_ad_fields()` (`:231-254`) and
`scan_result_merge()` (`:282-287`) — is dropped at the IPC boundary
(`ctl.c:3025-3027`).

Zephyr populates all of it in `create_ext_adv_info()` (`scan.c:826-843`); NimBLE
in `ble_hs_hci_evt.c:694-706`.

Two concrete gaps follow. `ble_periodic_sync(..., uint8_t sid, ...)`
(`ble.h:855`) requires a SID that an application has no way to learn from a
scan, so periodic advertising sync is unreachable through our own API. And TX
power is the only way to convert RSSI into a path-loss estimate, so proximity
logic against phone beacons is impossible. Dropping `name_complete` additionally
means a Shortened Local Name is presented to the application as if it were the
full name, and the Section 9.2.7 Name Discovery fallback can never be triggered.

### S12 — The fragment table is a global reachable from a validator [OURS-WRONG, LOW]

`ext_frag_tbl` (`hci_scan.c:960-965`) is file-scope, documented at `:957` as
safe because it "Runs on the single scan-parsing thread", and cleared once per
extended scan (`:1468`). But `hci_parse_ext_adv_report()` has a second caller:
`blued_event.c:46`, inside `blued_mesh_adv_event_valid()`, a function whose
stated purpose is pure validation. Every mesh advertising report validated that
way silently calls `ext_frag_mark()` or `ext_frag_take()` on the shared table.

Both callers run on the main event-loop thread — the GAP scan is synchronous
(`ctl_conn.c:29-31`) — so there is no data race today. The problem is that a
validate-only pass mutates discovery state, and the eight-slot table's
`free_i = 0` eviction (`:988-989`) means a busy mesh network can evict a live
scan fragment mark. Neither reference exposes reassembly state as a global
reachable from a validator.

---

## 3. Connection establishment

### C1 — The LE event mask omits bit 5, so every peer parameter request is link-layer rejected [OURS-WRONG, HIGH]

`hci_misc.c:592-616`, `hci_le_default_event_mask()`, applied at
`blued.c:2686`, builds its mask from `LE_EVTMASK_CONN_COMPLETE`,
`ADV_REPORT`, `CONN_UPDATE`, `READ_REMOTE_FEAT`, `LTK_REQUEST`,
`DATA_LENGTH_CHANGE`, `ENH_CONN_COMPLETE`, `PHY_UPDATE_COMPL` and
`SCAN_TIMEOUT`, plus feature-gated additions. `hci_util.h:262-288` defines bits
0, 1, 2, 3, 4, 6, 9, 11 and upward — **bit 5 has no definition at all** and is
never set.

Bit 5 is `HCI_LE_Remote_Connection_Parameter_Request` (Section 7.8.1 mask table,
text line 111793). The kernel already has a handler for the event —
`sys/netgraph/bluetooth/hci/ng_hci_evnt.c:1091-1146`,
`NG_HCI_LEEV_REMOTE_CONN_PARAM_REQUEST`, logged as "auto-accepted" — and
`ng_hci.h:308` defines `NG_HCI_LEEVMSK_REM_CONN_PARAM_REQ 0x20`. Nothing sets
it, so that handler is unreachable dead code.

Vol 6 Part B Section 5.1.7.2, text lines 143897-143901, verbatim:

> If the request is being indicated to the Host and the event to the Host is
> masked, then the Link Layer shall issue an LL_REJECT_EXT_IND PDU with the
> ErrorCode set to Unsupported Remote Feature (0x1A).

and text lines 143883-143889, which explains when the indication happens at all:

> if the values selected by the Link Layer are, respectively, within the range
> of the connInterval, the value of connPeripheralLatency and the value of
> connSupervisionTimeout provided by the local Host, then the Link Layer may
> choose to not indicate this request to its Host... Otherwise, if the event to
> the Host is not masked, then the Link Layer shall first indicate this request
> to its Host.

Zephyr masks bit 5 whenever the feature is present
(`hci_core.c:3765-3766`) and handles it with policy —
`bt_conn_le_param_req()` then either `le_conn_param_req_reply()` or
`le_conn_param_neg_reply(BT_HCI_ERR_INVALID_LL_PARAM)`
(`hci_core.c:2108-2135`). NimBLE handles the event too. BlueZ's handling is
kernel-side, in `net/bluetooth/hci_event.c`.

**Consequence.** When we are Central and a phone peripheral asks for its
preferred parameters via `LL_CONNECTION_PARAM_REQ` — which it will, because the
parameters we gave the controller are the ones in C2 — the controller must
indicate to the host, finds the event masked, and sends `LL_REJECT_EXT_IND` with
Unsupported Remote Feature. The peripheral concludes the central does not
support the procedure, and either stays on bad parameters or gives up. This is
the single highest-impact connection finding against a phone.

### C2 — As Central we force 7.5-15 ms with peripheral latency 4, immediately [OURS-WRONG, HIGH]

`blued_central.c:508-522`:

```c
if (conn->has_req_conn_params)
	hci_le_connection_update(dev->hci_fd, dev->con_handle,
	    conn->req_itvl_min, conn->req_itvl_max,
	    conn->req_latency, conn->req_timeout);
else
	hci_le_connection_update(dev->hci_fd, dev->con_handle,
	    6, 12, 4, 500);
```

Interval 7.5-15 ms, **peripheral latency 4**, supervision timeout 5 s — issued
on every central link *before* MTU exchange, pairing and GATT discovery.

Vol 3 Part C Section 9.3.12.2, text lines 65915-65919, verbatim:

> The connection interval should be set to TGAP(initial_conn_interval) when
> establishing a connection on the LE 1M PHY ... and connPeripheralLatency
> should be set to zero. These parameters should be used until the Central has
> no further pending actions to perform...

`TGAP(initial_conn_interval)` is **30 ms to 50 ms** (text lines 68331-68333).
And text lines 65904-65905:

> If the requested or updated connection parameters are unacceptable to the
> Central or Peripheral then it may disconnect the connection with the error
> code 0x3B (Unacceptable Connection Parameters).

NimBLE's defaults are the GAP values verbatim
(`ble_gap.c:106-115`, `BLE_GAP_INITIAL_CONN_ITVL_MIN/MAX`,
`BLE_GAP_INITIAL_CONN_LATENCY`). Zephyr uses `BT_LE_CONN_PARAM_DEFAULT`
(24-40 in 1.25 ms units, latency 0). BlueZ takes the peripheral's own preferred
parameters (see C5).

**Consequence.** As Central we send `LL_CONNECTION_UPDATE_IND`, which a
peripheral cannot negotiate — it accepts or disconnects with 0x3B. Apple
peripherals reject sub-15 ms intervals. Latency 4 during pairing and discovery
also stretches every SMP and ATT round trip by up to five connection events.
This is the most frequent source of "connects, then drops" against a phone
acting as peripheral.

### C3 — The kernel supervision-timeout check is 2x too lax, and the comment's own algebra disproves it [OURS-WRONG, HIGH]

The previous sweep listed this as its finding #11. It is unfixed.

`sys/netgraph/bluetooth/l2cap/ng_l2cap_evnt.c:719-733`:

```c
/*
 * Spec constraint (Vol 6 Part B §2.4.2.16):
 *   connSupervisionTimeout > (1 + connPeripheralLatency) *
 *                            connIntervalMax * 2
 * Units: timeout in 10ms, interval in 1.25ms.
 * Convert: timeout*10ms > (1+latency) * interval*1.25ms * 2
 *       => timeout*8 > (1+latency) * interval_max
 */
if (interval_min < 6 || ... ||
    (uint32_t)timeout * 8 <= (uint32_t)(1 + latency) * interval_max)
	result = NG_L2CAP_UPDATE_PARAM_REJECT;
```

Work the stated conversion through. `timeout * 10 > (1 + latency) *
interval_max * 1.25 * 2` is `timeout * 10 > (1 + latency) * interval_max * 2.5`,
which is `timeout * 4 > (1 + latency) * interval_max`. The comment's own
premises yield 4, and it writes 8; the code implements the 8. The check
therefore accepts supervision timeouts up to exactly twice shorter than legal.

Our own user space gets it right, in two places. `hci_conn.c:134-144`:

```c
/*
 * Timeout(10ms) * 10 > Interval_Max(1.25ms) * (1+Lat) * 2
 * i.e. Timeout * 4 > Interval_Max * (1 + Latency)
 */
if ((uint32_t)timeout * 4 <= (uint32_t)interval_max * (1 + (uint32_t)latency))
```

and `lib/libble/ble.c:2170-2172`, also 4.

Vol 4 Part E Section 7.8.12, text lines 112862-112865, verbatim:

> The Supervision_Timeout parameter defines the link supervision timeout for the
> connection. The Supervision_Timeout in milliseconds shall be larger than
> (1 + Max_Latency) x Connection_Interval_Max x 2, where Connection_Interval_Max
> is given in milliseconds.

Zephyr uses `(param->timeout * 4U) <= ((1U + param->latency) *
param->interval_max)` (`hci_core.c:2058-2061`) and build-asserts the same
relation on its preferred connection parameters (`gatt.c:117-119`). BlueZ
derives `max_latency = (timeout * 4 / max_interval) - 1`
(`profiles/gap/gas.c:189`). NimBLE does not check the relation host-side at all
(`ble_gap.c:5475-5479` checks only ranges) — so *whether* to check is a split,
but every implementation that checks uses 4.

**Consequence.** We answer `L2CAP_CONNECTION_PARAMETER_UPDATE_RSP` result 0x0000
(accepted) to an illegal request from a phone peripheral, then hand it to
`ng_l2cap_lp_con_update()` and thence to HCI Connection Update, which the
controller rejects with Invalid HCI Command Parameters. The peripheral believes
the update was accepted, never receives an LL update, and its own state machine
stalls — and the spec explicitly says the peripheral gets no indication when the
central's controller rejects (text lines 52913-52915).

This is the clearest case in the sweep of the standing pattern: the comment
cites a correct source, derives a correct intermediate step, and then writes a
number that contradicts its own derivation. The number is the bug.

### C4 — A kernel LE connect timeout frees the connection without cancelling it [OURS-WRONG, HIGH]

`sys/netgraph/bluetooth/hci/ng_hci_ulpi.c:1821-1836`:

```c
case NG_HCI_CON_W4_CONN_COMPLETE:
	ng_hci_lp_con_cfm(con, 0xee);
	break;
...
ng_hci_free_con(con);
```

No `HCI_LE_Create_Connection_Cancel` is emitted. The timeout is
`bluetooth_hci_connect_timeout()` = 60 s
(`sys/netgraph/bluetooth/common/ng_bluetooth.c:53`). The "only one pending
create" guard lives purely in host state (`ng_hci_ulpi.c:713-728`) and is
discarded along with the descriptor — while the controller is still initiating.

Section 7.8.13 (text line 113065) is the only way to stop an outstanding
initiator; Section 7.8.12 has no timeout parameter.

Zephyr uses `CONFIG_BT_CREATE_CONN_TIMEOUT`, default 3 s
(`subsys/bluetooth/host/Kconfig:787-790`), then `bt_le_create_conn_cancel()`
(`conn.c:4076`, `:1960`, `:2331`). NimBLE's `ble_gap_master_timer()` calls
`ble_gap_conn_cancel_tx()` (`ble_gap.c:2225`, `:2243`).

**Consequence.** One failed connect leaves the controller initiating forever.
The next `LE Create Connection` passes the now-cleared host guard and the
controller answers Command Disallowed, so blued can no longer connect to
anything on that adapter until reset. Note that blued *has*
`hci_le_create_connection_cancel()` (`hci_conn.c:590-626`) and calls it on
power-off, RPA rotation and shutdown (`blued.c:2124`, `:3466`, `:5018`,
`:5550`) — just never on a plain connect timeout.

### C5 — Peripheral Preferred Connection Parameters (0x2A04) is neither published nor read [OURS-WRONG, MEDIUM]

An exhaustive grep over `usr.sbin/bluetooth`, `lib/libble` and
`sys/netgraph/bluetooth` for `0x2A04`, `PPCP` and `PREF_CONN` returns nothing.
Our GAP service (`blued_peripheral.c:1356-1404`) publishes only Device Name
(0x2A00), Appearance (0x2A01) and Central Address Resolution (0x2AA6); our
central discovery reads only the Device Name (`blued_central.c:1739-1741`).

Vol 3 Part C Section 12.3, text lines 67537-67539 and 67550-67553:

> The Peripheral Preferred Connection Parameters characteristic value shall be 8
> octets in length. A device shall have only one instance of the Peripheral
> Preferred Connection Parameters characteristic.
>
> Each field shall have the same meaning and requirements as the field of the
> LL_CONNECTION_PARAM_REQ PDU ... or shall contain the value 0xFFFF which
> indicates that no specific value is requested.

and Section 9.3.12.2, text lines 65911-65926:

> The Central should either read the Peripheral Preferred Connection Parameters
> characteristic (see Section 12.3) or retrieve the parameters from advertising
> data... After the Central has no further pending actions to perform and the
> Peripheral has not initiated any other actions within TGAP(conn_pause_central),
> then the Central should invoke the Connection Parameter Update procedure ...
> and change the connection interval to that specified in the Peripheral
> Preferred Connection Parameters characteristic.

All three references have it. NimBLE exposes it under configuration
(`nimble/host/services/gap/src/ble_svc_gap.c:188-193`, `:224-227`, four
`htole16` fields in the Table 12.6 layout). Zephyr exposes it under
`CONFIG_BT_GAP_PERIPHERAL_PREF_PARAMS` with build-asserts on the ranges and on
the timeout relation (`subsys/bluetooth/host/gatt.c:106-119`). BlueZ **reads and
honours it as central** — `profiles/gap/gas.c:140-197` requires length 8, maps
0xFFFF to 30 ms / 50 ms defaults, validates ranges, and feeds the result through
`btd_device_set_conn_param()` to `MGMT_OP_LOAD_CONN_PARAM`
(`src/adapter.c:4678-4721`).

**Consequence.** Two-sided. As Peripheral we give a phone Central nothing to
work with, so it keeps its own defaults and our only recourse is the fragile
update path of C7. As Central we ignore the peripheral's stated preference and
impose C2's 7.5 ms with latency 4 — precisely the case Section 9.3.12.2 exists
to prevent.

### C6 — The advertising filter policy is computed once at boot and never revisited [OURS-WRONG, MEDIUM]

The other half of G1. The policy is derived exactly once, at `blued.c:4755`,
from a bond count taken at init, stored into `adv_config->filter_policy`
(`blued.c:4869`), and never recomputed on pair or unpair. Meanwhile the accept
list *is* mutated at runtime while advertising is live:

- unpair: `ctl.c:4431-4438`,
  `hci_le_remove_device_from_filter_accept_list(...)` with the return value
  discarded;
- operator verb: `ctl.c:4670-4724`, `ctl_security_acceptlist_result()`,
  ADD / REMOVE / CLEAR, with no advertising or scanning stop.

Section 7.8.16, text lines 113215-113220 (the identical text appears for
Section 7.8.15 at text line 113171 and for Section 7.8.17):

> This command shall not be used when:
>
> - any advertising filter policy uses the Filter Accept List and advertising is
>   enabled,
> - the scanning filter policy uses the Filter Accept List and scanning is
>   enabled, or
> - the initiator filter policy uses the Filter Accept List and an
>   HCI_LE_Create_Connection or HCI_LE_Extended_Create_Connection command is
>   pending.

**Consequence, and it is a security consequence.** With bonds present at boot
the policy is 0x02, so every runtime accept-list edit returns Command
Disallowed. **Unpairing therefore does not remove the peer from the
controller's accept list** — the unpaired device can still connect. Conversely,
once the last bond is removed the policy stays 0x02 over a stale list, so the
device silently becomes unpairable. And a boot with zero bonds pins policy 0x00
forever, so the bonded-only restriction never takes effect after the first
pairing at all.

The four different quiescing condition sets — for `LE Set Random Address`, the
accept-list commands, the resolving-list commands, and `LE Set Address
Resolution Enable` — are subtly different from one another and are pinned side
by side in `spec_extref_gap_privacy.h`, because reusing one quiesce for another
is the mistake this family of findings keeps producing.

### C7 — Peripheral parameter update checks only local features and has no L2CAP fallback [OURS-WRONG, MEDIUM]

The previous sweep called this "a dead end" (its finding #6). That verdict is
too flat: the HCI path *does* work when the local feature bit is set. What is
wrong is narrower and still serious.

`hci_conn.c:189-297`:

```c
bool
l2cap_conn_param_use_hci_update(uint64_t local_features)
{
	return ((local_features & LE_FEAT_CONN_PARAM_REQ) != 0);
}
...
if (!l2cap_conn_param_use_hci_update(local_features)) {
	LOG_HCI(1, "conn param update: LL Connection Parameters "
	    "Request unsupported (LE feature bit 1 clear); L2CAP "
	    "signaling fallback (Vol 3 Part A 4.20) not available "
	    "from user space -- declining");
	close(hci_fd); errno = ENOTSUP; return (-1);
}
```

Three defects:

**Only local features are consulted.** Section 7.8.18's error table, text lines
113398-113400: "The Controller is the Peripheral and the local Controller
supports the Connection Parameters Request procedure but the peer Controller
does not" -> Unsupported Remote Feature (0x1A). blued receives LE Read Remote
Features Complete but only logs it (`blued_event.c:790-799`) — peer features are
never stored, so this case is undetectable and unrecoverable.

**The L2CAP fallback genuinely does not exist.** Confirmed by exhaustive grep of
`sys/netgraph/bluetooth`: `NG_L2CAP_CMD_PARAM_UPDATE_REQUEST` (0x12) appears
only as an inbound case (`ng_l2cap_evnt.c:602`, `:158`), a timeout case
(`ng_l2cap_cmds.c:823`) and a header define. There is no builder and no L2CA or
socket API to transmit one. The comment at `hci_conn.c:204-208` is accurate.

**The 5-second delay is absent.** The request is fired inside peripheral
connection setup (`blued_peripheral.c:1294-1303`), at time zero. Vol 3 Part C
Section 9.3.12.2, text lines 65933-65935: "The Peripheral should not perform a
Connection Parameter Update procedure within TGAP(conn_pause_peripheral) after
establishing a connection." `TGAP(conn_pause_peripheral)` is 5 s (text lines
68323-68325).

Zephyr checks **both** sides and falls back — `conn.c:2188-2210`:

```c
if ((BT_FEAT_LE_CONN_PARAM_REQ_PROC(bt_dev.le.features) &&
     BT_FEAT_LE_CONN_PARAM_REQ_PROC(conn->le.features) && ...) ||
     (conn->role == BT_HCI_ROLE_CENTRAL)) { ... bt_conn_le_conn_update ... }
return bt_l2cap_update_conn_param(conn, param);
```

and enforces the delay via `CONFIG_BT_CONN_PARAM_UPDATE_TIMEOUT`, default
5000 ms, whose help text cites this exact spec clause
(`subsys/bluetooth/host/Kconfig:791-806`). NimBLE implements the L2CAP sender
(`ble_l2cap_sig.c:568-610`).

Against any central lacking LL Connection Parameters Request — older Android,
many embedded and dongle centrals — our peripheral's request fails with 0x1A and
there is no recovery path.

### C8 — `LE Extended Create Connection` exists but has no callers [OURS-WRONG (gap), LOW-MEDIUM]

Connection initiation is entirely kernel-side via the L2CAP socket path,
`sys/netgraph/bluetooth/hci/ng_hci_ulpi.c:762-793`, which builds a legacy
`LE_CREATE_CONNECTION` with fixed parameters from
`sys/netgraph/bluetooth/include/ng_hci.h:2099-2106`: scan 60 ms / 30 ms,
interval 30-50 ms, latency 0, timeout 2 s, CE lengths 0. Those values are
GAP-conformant — `TGAP(initial_conn_interval)` and `TGAP(scan_fast_*)` — and are
then immediately overwritten by C2.

`hci_le_ext_create_connection()` exists and is well-formed
(`hci_conn.c:1025-1088`, declared at `hci_util.h:547`) but has no callers
anywhere in the tree. So: no 2M or Coded initiating PHYs, no per-PHY scan
windows, and the initiator filter policy is permanently 0x00, which makes
accept-list-based auto-connect impossible even though the accept list is
populated.

Section 7.8.12, text lines 112829-112832: "The Initiator_Filter_Policy is used
to determine whether the Filter Accept List is used. If the Filter Accept List
is used, then the device to connect to is the first one that sends an
advertising packet..." — the auto connection establishment procedure of Vol 3
Part C Section 9.3.5.

Zephyr picks extended versus legacy at runtime (`hci_core.c:1012-1020`) and
drives per-PHY parameters and `BT_HCI_LE_CREATE_CONN_FP_FILTER` for
auto-connect (`hci_core.c:833-903`). NimBLE mirrors that
(`ble_gap.c:5489-5600`, `BLE_HCI_CONN_FILT_USE_WL` when `peer_addr == NULL`).

We cannot connect to a peer that advertises only with extended PDUs or on the
Coded PHY — a growing class of BT5 peripherals — and there is no
background auto-connect for bonded devices.

### C9 — Two smaller connection items [OURS-WRONG, LOW]

**Peer-proposed parameters are auto-accepted with no policy — and the code is
unreachable.** `sys/netgraph/bluetooth/hci/ng_hci_evnt.c:1091-1146` echoes the
peer's interval, latency and timeout straight back in an
`LE_REMOTE_CONN_PARAM_REQ_REPLY` with no validation, logging "auto-accepted".
Because of C1 this never runs; if bit 5 is ever set, it becomes an
accept-anything path and a peer could pin us to a 4 s interval with latency 499.
Zephyr routes the same event through `bt_conn_le_param_req()`,
`bt_le_conn_params_valid()` and an application callback, and negative-replies
with `BT_HCI_ERR_INVALID_LL_PARAM` (`hci_core.c:2108-2135`,
`conn.c:2128-2172`). Fix C1 and this becomes live; they should be fixed
together.

**Daemon-side CONNECT validation is materially weaker than the library's.**
`ctl_conn.c:232-243` checks `interval_min < 0x0006`, `interval_max > 0x0c80`,
`interval_min > interval_max` and `timeout < 0x000a`. Missing: `interval_min >
0x0C80`, `interval_max < 0x0006`, `latency > 0x01F3`, `timeout > 0x0C80`, and
the timeout relation. `lib/libble/ble.c:2162-2172` checks all of them. A
non-libble IPC client therefore gets bad parameters stored into `conn->req_*`
(`ctl_conn.c:269-275`); the connection proceeds while
`hci_le_connection_update()` silently rejects them, so the operator sees a
successful CONNECT with parameters that were never applied and no error.

**The operator parameter-update verb is refused on central links.**
`ctl_conn.c:500-513` gates on `l2cap_conn_param_use_hci_update(le_features)`
without regard to role. Section 7.8.18, text lines 113356-113357: "This command
is used to change the ACL connection parameters. This command may be issued on
both the Central and Peripheral", and the only feature-conditioned failures in
its error table are both prefixed "The Controller is the Peripheral". This also
contradicts our own code: `blued_central.c:517` calls
`hci_le_connection_update()` with no such gate, so the daemon's automatic update
works on a controller where the operator's explicit `CONNPARAMS` verb is
refused — with `IPC_ERR_INVAL`, which is a lie about what went wrong.

### C10 — Connection Subrating: the host-support bit is advertised, nothing implements it [OURS-WRONG (gap), LOW]

In scope because the sweep's target is 5.2 plus Connection Subrating.

`hci_le_set_default_subrate()` and `hci_le_subrate_request()` are implemented
with correct validation (`hci_conn.c:638-732`, helper at `:64-79`, matching the
Section 7.8.124 conditions at text line 124518) but have **no callers**: no ctl
verb, no libble API, and `config.h:152` / `config.c:130`, `:547` mark
`subrate_factor` "reserved, unused".

Meanwhile `blued.c:2726-2730` *does* set LE host-feature bit 38, Connection
Subrating Host Support, whenever the controller advertises the feature, and
`hci_misc.c:643-645` unmasks the Subrate Change subevent 0x23 — yet
`blued_event.c` has no case for subevent 0x23 (only 0x01, 0x02, 0x03, 0x04,
0x05, 0x0A, 0x0C, 0x0D and 0x12). So we tell peers we support subrating,
unmask the event, and then drop it: `conn->conn_interval` goes stale after any
subrate change.

All three references implement it: Zephyr (`conn.c:3323-3358`,
`bt_conn_le_subrate_request`), NimBLE (`ble_gap.c:1984-1996` for the change
event, `:5405` for set-default-subrate), BlueZ (`src/adapter.c:210-216`,
`struct conn_subrate`, `get_conn_subrate()`).

Advertising host support for a feature that is not implemented is worse than not
advertising it; at minimum bit 38 and the event unmask should not be set until
there is a consumer.

---

## 4. Privacy and addressing

This area was swept most carefully, because address-type confusion has already
produced two confirmed defects in this stack. The headline is better than
expected.

**The address-type handling in the connection path is correct, and the
resolvable-private-address cryptography is correct.** Both were checked against
the spec text field by field rather than against our own oracles.

`smp_generate_rpa()` (`smp_keys.c:1095-1150`) places the hash at `rpa[0..2]` and
prand at `rpa[3..5]`, which is exactly Vol 6 Part B Section 1.3.2.2, text lines
131830-131838: "randomAddress = prand || hash. The least significant octet of
hash becomes the least significant octet of randomAddress and the most
significant octet of prand becomes the most significant octet of
randomAddress." The 22-bit random-part constraint ("at least one bit ... shall
be 0", "at least one bit ... shall be 1", text lines 131810-131811) is enforced
with a bounded retry, and a failure of the `ah` primitive returns an error
rather than emitting a predictable all-zero address. `smp_rpa_matches()`
(`smp_keys.c:1040-1078`) extracts the same fields in the same orientation, uses
`timingsafe_bcmp`, and refuses to resolve against an all-zero IRK.

`blued_conn_note_enhanced()` (`conn.c:180-235`) handles the four-value
`Peer_Address_Type` correctly with `(peer_type & 0x01)`, which is the right test
for all of 0x00/0x01/0x02/0x03 — 0x02 is a public identity and 0x03 a random
static identity, both "corresponds to a resolved RPA" (text lines 105153-105159).
`hci_scan.c:854-856` and `:1083-1084` fold the same four values the same way.
The subtle case is handled too: under `Own_Address_Type` 0x03 a zero `Local_RPA`
does *not* identify the fallback address, and the code says so and declines to
infer (`conn.c:216`, `:230`). The RPA timeout default of 900 s
(`config.h:29`) matches `TGAP(private_addr_int)` (text line 68360).

The four address-type enumerations that make this area treacherous, and the
value sets that distinguish them, are pinned in `spec_extref_gap_privacy.h`.

### P1 — One rejected resolving-list entry stops every later peer from being programmed [OURS-WRONG, MEDIUM-HIGH]

`load_resolving_list()` (`blued.c:1316-1520`) walks the bond database and, on
*any* per-entry failure, `break`s out of the loop:

```c
if (hci_le_add_dev_resolving_list(dev->hci_fd, at,
    b->addr, b->irk, local_irk) != 0) {
	LOG_HCI(1, "resolving-list add failed after %d "
	    "entry(ies); remaining peers use host-based "
	    "resolution", loaded);
	break;
}
```

The same `break` follows a `LE Set Privacy Mode` failure and a shadow-full
condition, and `blued_privacy_program()` (`blued.c:1596-1700`) repeats the
pattern. The long comment at `blued.c:1407-1419` justifies it as "stops further
adds and keeps what is already programmed, exactly as the list-full arm above
does".

That justification conflates two different failures. For **Memory Capacity
Exceeded** — the list is full — stopping is right, and the loop already has a
separate, correct arm for it (`loaded >= rl_cap`). For a **per-entry rejection**
it is wrong: the next peer is unrelated and might program fine.

And per-entry rejections are not hypothetical. Section 7.8.38's error table,
text line 115152, verbatim:

> RC: Peer_Identity_Address_Type is 0x01 and Peer_Identity_Address is a
> non-static address. -> Invalid HCI Command Parameters (0x12)

`hci_le_add_dev_resolving_list()` (`hci_privacy.c:95-135`) validates
`addr_type <= 0x01` but never checks that a random identity address is a
*static* random address, i.e. that its two most significant bits are both 1.
A bond whose stored identity is an on-air RPA — which happens when pairing
completed without identity distribution — is rejected with 0x12, and takes every
subsequent bond down with it.

Zephyr programs each key independently: `bt_id_add()`
(`subsys/bluetooth/host/id.c:1030-1160`) is called once per key, and a failure
of `hci_id_add()` logs "Failed to add IRK to controller" and falls through to
the shared `done:` label rather than abandoning the remaining keys. Its
list-full arm is also structurally different and worth noting
(`id.c:1101-1118`): on overflow Zephyr **clears the entire controller list** and
switches wholly to host-side resolution, rather than leaving a partially loaded
list with resolution enabled.

**Consequence.** A silent, order-dependent failure: bonded peers past the first
bad entry can no longer be resolved, so they cannot be recognised on reconnect.
Combined with G1 — advertising filter policy 0x02 with those peers still in the
accept list — a bonded peer whose IRK never reached the resolving list cannot
reconnect at all, because its RPA never resolves to an accept-list identity and
the controller drops its connection request. The comments say the fallback is
"host-based resolution", and host-based resolution does exist for bond lookup
(`smp_find_bond()`, `smp_keys.c:1001-1029`, resolves RPAs against stored IRKs) —
but it cannot help when the controller filters the connection request before the
host sees anything.

### P2 — One RPA is generated once and applied to every adapter [OURS-WRONG, MEDIUM]

`blued_event.c:2152-2196`, the rotation timer handler, generates a single
address and then hands the same one to every adapter:

```c
if (smp_generate_rpa(blued_local_irk, rpa) != 0) { ... }
LIST_FOREACH(ra, &blued_g.adapters, entries) {
	...
	if (blued_adapter_rotate_rpa(ra, rpa) == 0) {
```

Two adapters therefore advertise, scan and initiate from the *same* resolvable
private address at the same time. An observer that sees both adapters sees one
address and links them; the whole point of the address being per-device is
defeated for a multi-adapter host.

Zephyr generates per-identity addresses — `bt_id_set_private_addr(id)` and
`bt_id_set_adv_private_addr(adv)` (`subsys/bluetooth/host/id.c`), keyed on the
identity or the advertising set, never one address broadcast across them.

Impact is bounded by how rare multi-adapter hosts are, which is why it is ranked
at 17 rather than higher. It is a privacy defect rather than an interop one.

The surrounding machinery is otherwise careful and should be recorded as such:
`blued_adapter_rotate_rpa()` (`blued.c:2061-2141`) correctly disables legacy
advertising, quiesces the always-on mesh scanner and cancels a pending
create-connection before issuing `LE Set Random Address`, because Section 7.8.4
(text lines 112088-112090) makes the command Command Disallowed while any of
those is active. It restores exactly what it suspended. That is finding H-H6 in
the code's own numbering and it is correctly done.

### P3 — Bonded peers with no IRK are excluded from the resolving list [ECOSYSTEM-SPLIT, LOW]

`load_resolving_list()` skips any bond without an IRK (`blued.c:1396`,
`if (!b->has_irk) continue;`). Zephyr adds every bonded key, whatever its IRK
value (`id.c:1122`, `hci_id_add(keys->id, &keys->addr, keys->irk.val)`).

The spec explicitly contemplates zero-IRK entries. Vol 3 Part C Section 10.7,
text lines 67050-67052, verbatim:

> A device identity consists of the peer's Identity Address and a local and
> peer's IRK pair. The local or peer's IRK shall be an all-zero key if not
> applicable for the particular device identity.

and text lines 67059-67061, which is the only case where they are barred:

> If the Host requires network privacy mode, then it shall only populate
> entries in the Controller's resolving list that have non-zero IRKs and shall
> not instruct the Controller to use device privacy mode.

Our default is `privacy_mode = 1`, device privacy (`config.c:129`), so we do not
require network privacy mode and the bar does not apply. Zero-IRK entries would
be legal.

The behavioural difference is small but real. Under `Own_Address_Type` 0x03,
a peer with a resolving-list entry gets a local RPA generated by the controller
from that entry's local IRK; a peer without one gets the fallback address from
`LE Set Random Address`. Both are resolvable private addresses, so no identity
leaks either way — but *which* address a given peer sees now depends on whether
that peer once distributed an IRK, which is an inconsistency with no stated
rationale. Classified as a split rather than a defect because the spec permits
both and BlueZ's behaviour is kernel-side and unreadable here.

Worth noting alongside it, because it is the same paragraph and it is a `shall`:
under 0x02 the fallback for an unmatched peer is the **public identity
address** (Section 7.8.53, text lines 116449-116452), so 0x02 fails open on
privacy where 0x03 fails closed. This stack correctly uses 0x03 everywhere
(`blued.c:1724`, `:2697`, `:3071`, `:3178`, `:3813`), which is the right choice
and should not be changed.

### P4 — Verified correct, recorded so it is not re-ploughed

- **The resolving list is edited with address resolution disabled.**
  `load_resolving_list()` calls `hci_le_set_addr_resolution_enable(fd, 0)` before
  clearing and reprogramming (`blued.c:1367-1376`), which satisfies Section
  7.8.38's condition ("This command shall not be used when address resolution is
  enabled in the Controller and: ...", text lines 115128-115136) directly rather
  than by quiescing.
- **The runtime resolving-list mutation path quiesces advertising and the mesh
  scanner.** `blued_reslist_quiesce_begin()` / `_end()` (`blued.c:2271-2315`)
  disable the primary set, every enabled extended set, and the always-on mesh
  scan, and restore exactly what was suspended. That is finding H-H7 and it is
  correctly done. Note the residual gap: neither it nor the rotation path
  accounts for a *pending create-connection*, which Section 7.8.44 (text lines
  115540-115545) lists unconditionally. In practice the GAP discovery scan is
  synchronous on the event-loop thread (`ctl_conn.c:29-31`) so it cannot overlap,
  but the initiating case is not structurally excluded.
- **The Filter Accept List is populated with identity addresses, not observed
  RPAs.** `load_filter_accept_list()` (`blued.c:2218-2261`) uses `b->addr` from
  the bond record. This is required by Vol 3 Part C Section 10.7, text lines
  67053-67056: "When address resolution is enabled in the Controller, all
  references to peer devices that are included in the resolving list from Host to
  the Controller shall be done using the peer's device Identity Address."
  Populating it with a scanned RPA would go stale on every rotation; we do not.
- **Enhanced Connection Complete is decoded and used for the SMP address
  binding.** `blued_event.c:701-747` and `conn.c:180-235`. This is the machinery
  that fixed the previous sweep's finding #2, and it holds up on re-reading.
- **`LE Read Resolving List Size` failure is non-fatal.**
  `hci_le_read_resolving_list_size()` (`hci_privacy.c:225-255`) returns success
  with a size of 0 on any failure or short reply, and the caller falls back to
  the shadow cap. Section 7.8.41 gives no guarantee the command is supported, and
  treating an unknown size as fatal previously bricked the daemon at startup.
- **`LE Set Privacy Mode` is treated as optional.** It is a Bluetooth 5.0 command
  (Section 7.8.77) and a 4.2 controller answers Unknown HCI Command (0x01);
  `hci_le_set_privacy_mode()` maps exactly that status to `EOPNOTSUPP`
  (`hci_privacy.c:290-296`) and callers skip it, while any other failure rolls
  the just-added resolving-list entry back out so the shadow and the controller
  cannot diverge. Correct on both counts, and stricter than Zephyr, which logs
  and continues (`id.c:1143-1147`).

---

## 5. Advertising data

### D1 — A long local name silently deletes the Service UUID list [OURS-WRONG, HIGH]

`ble_build_adv_data_flags()` (`hci_adv.c:316-402`) writes Flags, then the Local
Name, then the 16-bit UUID list — and sizes the name against *all* remaining
buffer:

```c
namelen = fulllen;
if ((size_t)(p - buf) + 2 + namelen > buflen) {
	if ((size_t)(p - buf) + 2 >= buflen) namelen = 0;
	else namelen = buflen - (p - buf) - 2;
}
...
size_t avail = buflen - (size_t)(p - buf);
if (avail >= 2 + 2 * (size_t)nuuids) { fit = nuuids; list_type = COMPLETE; }
else if (avail >= 4) { fit = (avail - 2) / 2; list_type = INCOMPLETE; }
else { fit = 0; ... }              /* no UUID AD emitted at all */
```

Work the live case. Both callers (`blued.c:3267`, `blued.c:4685`) pass
`buflen = 31` and two UUIDs. Flags takes 3 octets; the name takes 2 + N; so
`avail = 26 - N`:

- N up to 20: complete list, both UUIDs.
- N of 21 or 22: only the first UUID, marked incomplete.
- **N of 23 or more: no Service UUID AD structure at all, silently.**

And N can reach 26: `blued_set_device_name()` (`blued.c:3330`) accepts up to
`BLUED_GAP_NAME_MAXLEN` = 26 (`blued_internal.h:149`), and `config.c:492-495`
accepts up to 63 bytes with no length check at all. A perfectly legal operator
name kills service-UUID advertising.

All three references give the UUID lists priority and shrink or refuse the name:

- **BlueZ**, `src/shared/ad.c:709-721`, `bt_ad_generate()` serialises
  `service_uuids`, `solicit`, `manuf`, `service_data` and then the name **last**;
  `serialize_name()` (`ad.c:647-664`) is the only field that shortens, and
  `name_length()` (`ad.c:482-493`) pre-clamps so the total always fits.
- **Zephyr**, `subsys/bluetooth/host/adv.c:481-518`: any element that does not
  fit is a hard `-EINVAL`, "Too big advertising data", *except*
  `BT_DATA_NAME_COMPLETE`, which is demoted to `BT_DATA_NAME_SHORTENED`.
- **NimBLE**, `nimble/host/src/ble_hs_adv.c:261-323`: UUID16, UUID32 and UUID128
  are encoded before the name, and any overflow returns `BLE_HS_EMSGSIZE`
  (`ble_hs_adv.c:53`) — never a silent drop.

CSS v15, Part A Section 1.1: "An omitted Service or Service Class UUID data type
shall be interpreted as an empty incomplete-list." Core Vol 3 Part C, text line
65003, lists the Service or Service Class UUIDs AD type among those a
discoverable device *should* include "to enable a faster connectivity
experience".

**Consequence.** An Android app using `ScanFilter.setServiceUuid()` or an iOS
app using `scanForPeripherals(withServices:)` cannot see the device at all once
the name reaches 23 bytes. BlueZ's `bluetoothd` will not populate `UUIDs` on the
D-Bus device object before connecting. The failure is silent and depends on the
length of a name the operator chose.

### D2 — The advertised UUID list is hardcoded to two entries and marked complete, and 128-bit UUIDs are never advertised [OURS-WRONG, HIGH]

`blued.c:3259` and `blued.c:4668-4669` hardcode
`uuids[] = { UUID_DIS_SERVICE, UUID_CUSTOM_SERVICE }`. But
`peripheral_build_gattdb()` also registers config-driven services —
`blued_peripheral.c:1482` (`attdb_add_service(db, svc->uuid16)`) and `:1484`
(`attdb_add_service128(db, svc->uuid128)`) — none of which reach the advertising
data. `hci_adv.c:373` nonetheless stamps `AD_TYPE_UUID16_COMPLETE`.

There is also **no 128-bit list on the live path at all**: `adv_builder.c:80-95`
has `adv_ad_add_uuid128()` but it is never called (see D6), and
`ble_build_adv_data_flags()` has no 128-bit parameter.

CSS v15 Part A Section 1.1: "One Service or Service Class UUID data type
indicates that the Service or Service Class UUID list is incomplete and the
other indicates the Service or Service Class UUID list is complete", and "If a
device has no Service or Service Class UUIDs of a certain size ... the
corresponding field ... shall be marked as complete with no Service or Service
Class UUIDs."

BlueZ's `serialize_service_uuids()` (`ad.c:579-586`) emits the complete type for
whatever the client actually registered, grouped by size; the set is
client-declared, never hardcoded.

**Consequence.** A phone filtering on a custom 128-bit service UUID can never
discover the device, and a scanner that trusts the complete marker concludes we
do not host the config-declared services and does not connect.

### D3 — `BR/EDR Not Supported` is set unconditionally although CTKD is implemented [OURS-WRONG, MEDIUM]

`blued.c:3135-3136` and `hci_adv.c:310-312` both set the bit unconditionally.
The bit *values* are right (`hci_util.h:215-217` = 0x01/0x02/0x04) and bits 0
and 1 are structurally mutually exclusive because the code uses a ternary. The
problem is the condition.

Core Vol 3 Part C, text lines 65053-65056, gates it: "**For an LE-only
implementation** with all the following flags set as described: a. The 'BR/EDR
Not Supported' flag set to one. b. The 'Simultaneous LE and BR/EDR to Same
Device Capable (Controller)' flag set to zero." CSS v15 Part A Section 1.3 binds
bit 2 to a controller fact: "BR/EDR Not Supported. Bit 37 of LMP Feature Mask
Definitions (Page 0)."

blued never reads LMP page 0 — the only feature read is
`hci_le_read_local_features()` (`hci_misc.c:521-551`), which reads LE features
only. And blued explicitly implements Cross-Transport Key Derivation
(`smp_keys.c:1156`, LE LTK to BR/EDR link key, and `:1227` for the reverse),
i.e. it is built for dual-mode operation while telling every scanner the
controller has no BR/EDR.

NimBLE leaves the Flags value entirely to the application
(`ble_hs_adv.c:243-259`) and never fabricates bit 2.

On a dual-mode controller an Android or BlueZ peer that reads bit 2 will not
attempt BR/EDR transport or CTKD with us, and BlueZ classifies the device as
LE-only in its cache — making blued's own CTKD code unreachable from the peer
side.

### D4 — The scan response advertises a Complete name longer than GATT 0x2A00 serves [OURS-WRONG, MEDIUM]

Two identical copies of the scan-response builder, `blued.c:3271-3279` and
`blued.c:4700-4718`:

```c
name_truncated = (namelen > 29);
if (namelen > 29) namelen = 29;
scan_rsp[scan_rsp_len++] = (uint8_t)(1 + namelen);
/* CSS Part A §1.2: use Shortened if truncated */
scan_rsp[scan_rsp_len++] = name_truncated ? 0x08 : 0x09;
```

But the GATT Device Name characteristic is built with
`char namebuf[BLUED_GAP_NAME_MAXLEN]` = 26 and `if (nl > sizeof(namebuf)) nl =
sizeof(namebuf);` (`blued_peripheral.c:1368-1381`). Since `config.c:492-495`
allows 63 bytes, a 28-byte configured name is advertised as a **Complete** Local
Name of 28 bytes while a GATT read of 0x2A00 returns 26.

CSS v15 Part A Section 1.2: "The Local Name data type shall be the same as, or a
shortened version of, the local name assigned to the device. The Local Name data
type value indicates if the name is complete or shortened. If the name is
shortened, the complete name can be read ... by reading the device name
characteristic after the connection has been established using GATT."

BlueZ caches the AD name and then re-reads 0x2A00, so the device visibly renames
itself in the UI after connecting. Worse, this inverts the spec's contract:
reading 0x2A00 gives a *shorter* name than the advertisement claimed was
complete.

### D5 — Name shortening truncates on a byte boundary and can split a UTF-8 character [ECOSYSTEM-SPLIT, MEDIUM]

`hci_adv.c:340` computes `namelen = buflen - (p - buf) - 2` and `hci_adv.c:359`
`memcpy`s that many bytes; `blued.c:4712` clamps to 29 and `blued.c:4716`
`memcpy`s. No UTF-8 boundary walk-back anywhere.

The references behave identically: BlueZ `ad.c:655-663` computes
`len = ad->max_len - (iov->iov_len + 2)` and does a raw push (it validates UTF-8
on *input*, `ad.c:281`, but not on truncation); Zephyr `adv.c:495-512` does a raw
`memcpy` of `shortened_len`.

CSS v15 Part A Section 1.2 types both name AD types as `utf8s` and says "A
shortened name shall only contain contiguous characters from the beginning of
the full name." A half-encoded code point is not a character, so all four
implementations are technically non-conformant.

Classified as a split because the references share the behaviour, so it is not a
differentiator against a BlueZ or Zephyr peer. It is still a real user-visible
defect against a phone — any accented Latin, CJK or emoji character crossing the
cut point advertises an invalid UTF-8 sequence, which Android's scanner and iOS
render as a replacement glyph or drop — and it is a cheap fix: walk back while
`(b & 0xC0) == 0x80`.

### D6 — `adv_builder.c` is entirely dead code, and with it six AD types [OURS-WRONG (unwired), MEDIUM]

Tree-wide there is not a single call site:

```
$ grep -rn "adv_ad_add\|adv_ad_init\|adv_ad_append" /usr/src --include=*.c --include=*.h \
    | grep -v "/blued/adv_builder"
(no output)
```

`ctl.c:41` includes `adv_builder.h` and uses no symbol from it. The file is
compiled in via `Makefile:9`. What follows from that:

- `adv_ad_add_tx_power()` (`adv_builder.c:111-117`) is unreachable, so blued
  **never emits a TX Power Level (0x0A) AD**. Note `hci_adv.c:523` already logs
  `rp.selected_tx_power` from LE Set Extended Advertising Parameters and throws
  it away. NimBLE plumbs it: `ble_hs_adv.c:330-331` calls
  `ble_hs_hci_util_read_adv_tx_pwr()` when the application passes
  `BLE_HS_ADV_TX_PWR_LVL_AUTO`.
- `adv_ad_add_appearance()` (`adv_builder.c:119-126`) is unreachable, so **no
  Appearance (0x19) AD is ever emitted**.
- `adv_ad_add_service_data16()` (`adv_builder.c:148-166`) is unreachable, so **no
  Service Data of any size (0x16/0x20/0x21) is ever emitted** — nor parsed.
- **Peripheral Connection Interval Range (0x12) does not exist anywhere in the
  tree** — no encoder, no decoder, no constant. NimBLE has both
  (`ble_hs_adv.c:346-355` encode, `:659-663` decode with a strict length check).
- **32-bit UUID lists (0x04/0x05) have no constant, no encoder, no decoder.**
  NimBLE `ble_hs_adv.c:277-291`; BlueZ `ad.c:583`, `eir.c:265-266`.

Core Vol 3 Part C, text lines 65001-65004, lists what a discoverable device
*should* include: "TX Power Level AD type ... Local Name AD type ... Service or
Service Class UUIDs AD type ... Peripheral Connection Interval Range AD type".
We emit one of the four.

**Consequence.** Proximity features that compute path loss from
`Tx Power Level - RSSI` get nothing; a phone shows the generic Bluetooth icon
instead of an Appearance-derived one; a Central picks arbitrary connection
intervals because we express no preference — which is C5 and C2 arriving from a
second direction; and beacon-style Service Data consumers see nothing.

### D7 — Our AD parser understands five of the AD types the references decode [OURS-WRONG, MEDIUM]

`hci_scan.c:219-272` (`hci_parse_ad_fields`) handles exactly 0x08 and 0x09
(name), 0xFF (first two octets only, `:255-257`), and 0x02 and 0x03 (16-bit
UUIDs, `:258-266`). Everything else falls through the chain and is discarded.
In particular Flags (0x01) is never parsed — which is finding S3 — and 128-bit
UUIDs are unparseable, because `struct ble_scan_result` carries only
`uint16_t svc_uuids[8]`.

BlueZ `src/eir.c:260-347` decodes 0x02-0x07, 0x01, 0x08/0x09/0x30, 0x0A, 0x0D,
0x19, 0x0E, 0x0F, 0x10, 0x16/0x20/0x21 and 0xFF. NimBLE `ble_hs_adv.c:639-663`
and following decodes the same span including 0x12.

Beyond S3's consequence, this means blued cannot discover or filter on the
128-bit service UUIDs that virtually all non-SIG BLE products advertise.

### D8 — Two smaller advertising-data items [OURS-WRONG, LOW]

**An all-zero Flags octet can be emitted.** `adv_builder.c:55-60`
unconditionally appends a one-octet value. CSS v15 Part A Section 1.3: "The
Flags data type shall be included when any of the Flag bits are non-zero and the
advertising packet is connectable, otherwise the Flags data type may be omitted.
**All all-zero octets after the last non-zero octet shall be omitted from the
value transmitted.**" NimBLE encodes exactly this rule and documents it:
`ble_hs_adv.c:248-251`, "Note: The CSS prohibits advertising a flags value of 0",
with `if (adv_fields->flags != 0)`. The same hazard exists on the live path via
`ble_build_adv_data_flags()` (`hci_adv.c:326-328`), which writes the Flags
structure with no zero check; the only in-tree caller passes non-zero, so it is
latent.

**Operator-supplied advertising data is accepted unvalidated.**
`ctl.c:5375-5396` checks only `len <= 31` and the framing, then hands the buffer
to `ctl_adv_program()` and thence to `hci_le_set_advertising_data()`. There is
no AD well-formedness walk — a client can submit a structure whose length octet
runs past the payload, a zero length octet mid-buffer, or duplicate Flags — and
nothing stops a client putting a Flags structure into the **scan response**,
where CSS v15 Table 1.1 marks Flags as "X: Reserved for future use". Core Vol 3
Part C, text lines 67345-67347: "Each AD structure shall have a Length field of
one octet, which contains the Length value and **shall not be zero**." A
malformed payload produces an on-air buffer that a phone's scanner abandons at
the bad structure, dropping every AD structure after it — including the name.
Secondarily, the 31-octet cap is applied even when the adapter is running
extended advertising, where `ctl_adv_program()` (`ctl.c:2424-2430`) would
program up to `ADV_EXT_BUDGET` = 251; operator-supplied extended data is capped
at legacy size for no stated reason.

**An empty configured name produces a zero-data Complete Local Name.**
`config.c:492-495` accepts an empty `peripheral_name` with no non-empty check
(the check at `blued.c:3330` guards only the runtime SET_NAME verb), and
`blued.c:3276-3279` and `:4713-4718` then emit `[0x01][0x09]`. The AD path is
inconsistent with this — `hci_adv.c:356` skips the name entirely when
`namelen == 0`. BlueZ deliberately avoids it: `src/advertising.c:666-672`, with
the comment "adding a empty name as AD data as it just take space that could be
[used]", sets `client->name = NULL` when the name is empty.

### D9 — Verified correct, recorded so it is not re-ploughed

- **The AD length octet covers the type octet.** `adv_builder.c:47`
  (`b->data[b->len++] = (uint8_t)(vlen + 1)`), `hci_adv.c:357`, `:392`,
  `blued.c:4713`. Matches Core Vol 3 Part C text lines 67345-67348 and all three
  references.
- **The parser rejects a length octet that runs past the buffer.**
  `hci_scan.c:200-205`: `if (len < 2) return NULL; if (adlen == 0 || adlen > len
  - 1) return NULL;` — no underflow, correct upper bound. This is the classic AD
  parser bug and it is not present.
- **The parser terminates on a zero length octet**, per text line 67346 "shall
  not be zero" and the non-significant-part rule at `:67349-67350`.
- **Report-level length bounds are right** in all three paths:
  `hci_scan.c:867` (legacy, 31), `:1057` (extended, 229), `:1069` (remaining
  buffer against the header plus data length).
- **No silent mid-structure truncation on the build side.** `hci_adv.c:336-361`
  cuts the name to a whole value; `:370-398` cuts the UUID list on whole
  two-octet boundaries and re-marks it incomplete. The emitted buffer is always a
  valid AD sequence. (What it may omit is D1's problem, not this one.)
- **Flags is present in the advertisement and absent from the scan response.**
  Every scan-response builder emits only the name. Satisfies CSS v15 Table 1.1.
- **Little-endian encoding.** `ble_util.h:17-21` `put_le16` is LSB-first and is
  used at `adv_builder.c:74`, `:124`, `:142`, `:162`, and open-coded correctly at
  `hci_adv.c:396-397`.
- **Manufacturer Specific Data and Service Data minimum lengths.**
  `adv_builder.c:128-146` always writes the two-octet company ID and `:148-166`
  the two-octet service UUID, and the bounds use subtraction rather than
  addition so there is no `size_t` overflow.
- **The builder fails closed.** `adv_builder.c:38-46`: value length above 254 is
  `EINVAL`, exceeding the budget is `ENOSPC`, and `cap` is clamped to
  `ADV_EXT_BUDGET` at `:26`. It never truncates.
- **Name-merge precedence on scan-response merge.** `hci_scan.c:231-234` prefers
  a Complete Local Name over a stored Shortened one, which is the right reading
  of CSS v15 Part A Section 1.2.
- **Appearance is consistent, if empty.** The 0x19 AD is never emitted and the
  0x2A01 characteristic is `{0x00, 0x00}` = Unknown
  (`blued_peripheral.c:1355`, `:1383-1385`), two octets, readable without
  authentication. The absence of a meaningful Appearance is D6's problem; the
  two surfaces do not contradict each other.

---

## 6. Spec-citing comments that contradict their source

The previous sweep recorded that six comments citing a specification had been
found to contradict what the code did, and that in every case the comment marked
a real defect. That check was repeated here across `hci_adv.c`, `hci_scan.c`,
`hci_conn.c`, `ctl_conn.c`, `adv_builder.c` and the L2CAP signalling path.

Six more were found. **Three mark live defects; three are citation errors over
correct code.** The pattern holds, but it is not absolute — which is itself
worth recording, because it means each one has to be checked rather than
assumed.

| Where | The comment says | The source says | Verdict |
| --- | --- | --- | --- |
| `ng_l2cap_evnt.c:719-733` | derives `timeout*8` from premises | its own premises give `timeout*4` | **live defect (C3)** |
| `hci_adv.c:1278` | "max_events 0: air until explicitly stopped" | the callee it calls rejects 0 | **live defect (A1)** |
| `hci_adv.c:452-457` | quotes §7.8.53's extended-PDU prohibition | the sentence has two clauses; one is unimplemented | **live defect (A6)** |
| `hci_scan.c:1041-1047` | "TX_Power spans the full -127..+126 dBm range ... only RSSI is capped at +20" | §7.7.65.13 caps TX_Power at +20 too | latent; the validator matches the wrong comment (S10) |
| `hci_adv.c:726-734` | "§7.8.54 allows up to 254 bytes ... we use the conservative limit of 251" | §7.8.54's maximum *is* 251 | doc only; code correct (A7) |
| `hci_scan.c:49-61` | cites "Vol 3 Part C Section 12.4" for scanner own-address selection | §12.4 is the Central Address Resolution characteristic; the rule is §10.7 | doc only; code correct |
| `hci_util.h:57-64` | cites §7.8.64 alongside the range 0x0004-0x4000 | §7.8.64's range is 0x0004-0xFFFF | live but low (S9) |
| `hci_conn.c:38` | cites "§7.8.50" for PHY bit assignments | §7.8.50 is "[This section is no longer used]" | doc only; constants correct |

Four smaller CSS citation errors in `adv_builder.c` and its header were also
found — §1.1 cited for the length-octet rule and for UUID endianness (both live
in Core Vol 3 Part C §11 and Vol 1 Part E §2.9 respectively), and Core Vol 3
Part C §11 cited for the Flags bit values (which are CSS §1.3). In each case the
claim is correct and only the pointer is wrong. Two citations in the same file
(§1.11 for Service Data, §1.4 for Manufacturer Specific Data) are correct.

Also worth recording as *not* a defect, because it looks like one:
`hci_adv.c:87-98` argues that the Bluetooth 4.0 "0x00A0 floor for
non-connectable or scannable undirected advertising" is gone. **That conclusion
is right for our 5.2 target** — Section 7.8.5's interval tables (text lines
112200-112217) carry only the 0x0020-0x4000 range, and the residual modern text
is a soft `should` at Vol 3 Part C text lines 65888-65892. Zephyr *still*
enforces the old floor, gated on HCI version below 5.0 (`adv.c:421-432`), so a
future reviewer comparing against Zephyr will find a difference and be tempted
to "fix" it. Do not. The comment's historical characterisation is slightly off —
in 4.0 through 4.2 it was a normative HCI `shall`, not "a GAP guideline" — but
the conclusion and the code are correct.

---

## 7. Reference headers created

Four headers were added under `tests/usr.sbin/bluetooth/blued/`, following the
existing `spec_extref_*.h` conventions: hand-written, every value traceable to a
named external source with a spec text line number, nothing derived by running
5BSD code, each compiling standalone.

| Header | Pins |
| --- | --- |
| `spec_extref_gap_timers.h` | the complete GAP TGAP table (Vol 3 Part C Appendix A), with the Requirement/Recommendation column preserved as a suffix on each macro — the table is almost entirely `Recommended`, and `TGAP(lim_adv_timeout)` is the one `Required value` |
| `spec_extref_gap_privacy.h` | the four one-octet "address type" enumerations and their differing value sets, the RPA format and its field orientation, privacy modes and their defaults, the RPA timeout ranges, and the four distinct command-disallowed condition sets for `LE Set Random Address`, the accept-list commands, the resolving-list commands and `LE Set Address Resolution Enable` |
| `spec_extref_gap_adv_props.h` | Table 7.3's five legal legacy property values with their advertising-data column, both halves of the extended-PDU prohibition, the interval and channel-map ranges, the advertising-data length and fragmentation-operation values, the enable-command duration and max-events semantics, and the legacy/extended command-mixing rule |
| `spec_extref_gap_ext_adv_report.h` | the Event_Type bit assignments and Data Status values, the reassembly contract and the fields that must be invariant across a chain, Table 7.1's legacy event types, every field range and sentinel (RSSI, TX power, periodic interval, data length, num reports), the duplicate-filtering rules, and the 251-versus-229 arithmetic that makes fragmentation unavoidable |

The privacy header is the one to read first if only one is read. The four
address-type enumerations it pins are the direct cause of the two defects this
stack has already had in that area, and the sense of the values 0x02 and 0x03
inverts between the command form and the event form.
