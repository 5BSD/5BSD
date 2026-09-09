# HID over GATT and GATT client procedures: 5BSD against BlueZ, Zephyr and NimBLE

A second external-reference sweep, narrowed to the stack's flagship use case:
a Bluetooth LE keyboard that types into the system. The first sweep
(`docs/bluetooth-interop-comparison.md`) covered ATT, SMP, HCI/GAP and mesh
and found fourteen divergences. It did not touch HOGP, because the HID Over
GATT Profile and HID Service specifications were not in tree. They are now,
and the conformance-coverage generator scores this area at 0% covered.

Nothing in the code was changed while this was written; it is reconnaissance.
Constraint of this pass: no file under `usr.sbin/bluetooth/` or `lib/` was
touched, and no existing test file or test Makefile was modified.

## Reference implementations obtained

| Stack | Snapshot commit | Role in this comparison |
| --- | --- | --- |
| BlueZ 5.87 | `92305dc06ab8a6d89af2dae1d725cc4d51462ad1` | the only true peer: `profiles/input/hog.c` + `hog-lib.c` is also a HID **host** over GATT |
| Zephyr | `2665fcca3cced3aefb7202d6289991d8cc1dfcac` | GATT **client** procedures only; ships no HID service at all (see below) |
| Apache NimBLE | `1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845` | GATT **client** procedures only; ships no HID service at all |

### What the role difference rules out

The brief anticipated that Zephyr and NimBLE would be HID *devices* and that
device-side comparisons would not apply. The reality in these two snapshots is
stronger than that, and it removes a comparison axis entirely:

- **Zephyr ships no HID-over-GATT service.**
  `subsys/bluetooth/services/` contains `bas/ ias/ nus/ ots/ ans.c cts.c dis.c
  ets.c gap_svc.c hrs.c tps.c` and no `hids.c`. `BT_UUID_HIDS_VAL 0x1812` is
  defined at `include/zephyr/bluetooth/uuid.h:410` and referenced by nothing.
  The whole HOGP characteristic UUID set is likewise declared
  (`uuid.h:954,963,1297,1441,1450,1657,1666,1675,1684,1693`) and instantiated
  nowhere. The widely-cited `bt_hids` library is an nRF Connect SDK component,
  not Zephyr proper, and this snapshot has no `samples/` directory. What Zephyr
  does have is the **BR/EDR** HID Device profile over L2CAP/HIDP
  (`subsys/bluetooth/host/classic/hid_device.c`), a different transport.
- **NimBLE ships no HID service either.** `nimble/host/services/` is
  `ans bas bleuart dis gap gatt ias ipss lls tps`. A tree-wide grep for
  `0x1812`, `0x2a4b`, `0x2a4d` returns zero hits; NimBLE does not even define
  the UUIDs. Applications are expected to hand-build a `ble_gatt_svc_def`.

Consequences for this document, stated once rather than repeated per finding:

- **Sections 1-4 (HID service handling, boot vs report, report handling,
  suspend/control point) are a two-way comparison: 5BSD against BlueZ.**
  Zephyr and NimBLE are marked NOT-COMPARABLE throughout.
- The load-bearing question "what security permission does a real HID device
  put on its Report characteristic" **cannot be answered from any of the three
  snapshots.** Neither Zephyr nor NimBLE has an attribute table to inspect, and
  BlueZ is a host. Only the specifications adjudicate section 6.
- **Section 5 (GATT client procedures) is a genuine four-way comparison**, and
  it is where Zephyr and NimBLE carry their weight.

## Adjudicating text and a version warning

- `/usr/src/bluetooth-specs/HOGP_v1.1.txt` — title page line 5 "Version: v1.1",
  line 6 "Version Date: 2025-08-05".
- `/usr/src/bluetooth-specs/HIDS_v1.1.txt` — line 26, "v1.1 ... 2026-04-21".
- `/usr/src/bluetooth-specs/HOGP_v1.2.txt` — for reference; §7 Security becomes
  §8 and the "excluded" cell notation changes from `X` to `E`. No normative
  text used here differs between the two.
- `/usr/src/bluetooth-specs/Core_Specification_6_3.txt` for GATT.

**HOGP 1.1.1 does not exist.** The SIG adopted 1.0, 1.1 and 1.2. Six comment
and header sites in tree cite "1.1.1"; the section numbers they use match
v1.1, so the intent is clear and the fix is cosmetic. They are listed in §7.

**A sharper version hazard.** The in-tree HOGP v1.1 is a heavy restructure. It
has **no connection-establishment section and no link-loss section**; §5 and §6
are HID ISO. Any in-tree citation of the shape "HOGP §3.1 / §3.3.3 / §5.x" is
citing **HOGP 1.0**, not this document. `blued_central.c` contains four such
citations (`:1502`, `:1636`, `:1124`, `:2027`); see F4.4.

**A third: the GATT Specification Supplement in tree (2026-02-05) contains no
HID definitions at all** — `grep -ci '\bHID\b'` yields one hit, a lighting
enumeration at line 7029. §1 line 604 excludes anything "defined in Bluetooth
service specifications". All seven HID characteristic and descriptor
definitions are owned by HIDS v1.1. Any GSS citation for them is invalid.

## Classification key

Same as the first sweep, with one addition:

- **OURS-WRONG** — the spec, or the unanimous practice of the references,
  contradicts us.
- **OURS-RIGHT-OTHERS-DIFFER** — we match the spec and at least one reference
  does not. Recorded so nobody "fixes" us towards the reference.
- **ECOSYSTEM-SPLIT** — the references disagree and the spec does not settle it.
- **AGREE** — checked, no divergence.
- **NOT-COMPARABLE** — the reference implements the opposite role, or does not
  implement the area at all.

---

## Ranked findings

Ranked by whether a real keyboard or mouse works reliably, not by conformance
tidiness.

| # | Area | Finding | Class | Impact |
| --- | --- | --- | --- | --- |
| H1 | Multi-instance | report maps from multiple HID Services are concatenated into one vhid and reports share one flat table | OURS-WRONG | composite keyboard+mouse devices deliver the wrong report to the wrong collection |
| H2 | Robust caching | the Service Changed CCCD is never written | OURS-WRONG | a bonded device that changes its database is never able to tell us; stale handles until the hash happens to be re-read |
| H3 | Security | bonding is reactive — we only pair after an ATT error, never proactively | OURS-WRONG | HID traffic before the first error is unencrypted; a device that does not gate its characteristics is read in the clear |
| H4 | Boot protocol | Boot Protocol Mode is written to the first HID Service only | OURS-WRONG | a dual-instance boot device leaves the second service in Report mode and half the device is dead |
| H5 | Boot protocol | we write Report Protocol Mode, then Boot Protocol Mode, on the same connection | OURS-WRONG | acts as Report Host and Boot Host concurrently, which the profile forbids in both directions |
| H6 | Report handling | a Report characteristic whose Report Reference read fails is silently retained with the prohibited Report Type 0x00 | OURS-WRONG | keyboard enumerates and then delivers nothing, with no error |
| H7 | Discovery | External Report Reference (0x2907) is discovered and then ignored | OURS-WRONG (gap) | any device that reports through an external service characteristic loses those reports entirely |
| H8 | Discovery | included-service (relationship) discovery is never performed; `gatt_discover_includes()` has no caller | OURS-WRONG (gap) | mandatory for a Report Host; the Battery-Level-as-report path cannot work |
| H9 | Boot protocol | a boot device exposing both keyboard and mouse registers only the keyboard | OURS-WRONG | the mouse half of a boot combo device is silently dropped |
| H10 | Report handling | Feature reports are classified, stored, and unreachable — `hogp_find_feature_handle()` is dead code | OURS-WRONG (gap) | no Get_Report/Set_Report(Feature) path at all |
| H11 | Robust caching | we never write Client Supported Features (0x2B29) | OURS-WRONG | we cache handles across connections without opting into the mechanism that protects the cache; our own 0x12 handler is unreachable |
| H12 | Suspend | Suspend (0x00) is never written; only Exit Suspend | OURS-WRONG (gap) | a device told "exit suspend" stays fully powered across a host sleep |
| H13 | Robust caching | Database Out Of Sync (0x12) is handled on exactly one code path | OURS-WRONG | every other request that can receive it treats it as a fatal discovery failure |
| H14 | Reconnection | reconnect is a backoff-timer connect, not continuous scanning | OURS-DIFFER | the 5-second advertising burst that carries the first keystroke can land in a backoff gap |
| H15 | Boot protocol | Boot Keyboard Output Report (0x2A32) is never discovered | OURS-WRONG (gap) | no LEDs in boot mode |
| H16 | Discovery | discovery arrays fill silently: 16 reports, 64 characteristics, 128 descriptors, 4 cached report maps | OURS-WRONG | a large composite device is truncated with no diagnostic |
| H17 | Report handling | Output reports always use Write Without Response, ignoring characteristic properties | OURS-DIFFER | drops LED writes on a device that offers only Write |
| H18 | HID Information | the Flags octet is read and discarded; RemoteWake and NormallyConnectable are never stored | OURS-WRONG (gap) | the two flags the profile says "shall be used" for suspend and resume policy |
| H19 | Discovery | Battery Level is read once and never subscribed | OURS-DIFFER | battery display goes stale; matches BlueZ, which is also broken here |
| H20 | Robust caching | Database Hash is read *after* first discovery on a fresh bond, not before | OURS-DIFFER | a race window in which a stale hash is persisted against a database we did not fully see |

Comparisons that came out clean are recorded in §8 so the ground is not
re-ploughed.

---

## 1. HID Service discovery and characteristic handling

### H1 — Multiple HID Service instances are merged into one HID device [OURS-WRONG, HIGH]

`hogp_discover()` (`blued_central.c:1783-1830`) iterates every primary service
with UUID 0x1812 and calls `hogp_process_service()` for each. That much is
right. What happens inside is not.

**The report maps are concatenated.** `blued_central.c:945-957`:

```c
} else {
        /* Concatenate report maps from multiple services */
        uint8_t *p = realloc(dev->report_map,
            dev->report_map_len + total);
        ...
        memcpy(p + dev->report_map_len, rmbuf, total);
```

**The reports share one flat table** with no instance index at all
(`hogp_report.h:15-20`):

```c
struct hogp_report {
        uint16_t        value_handle;
        uint16_t        cccd_handle;
        uint8_t         report_id;
        uint8_t         report_type;
};
```

and lookup is first-match on `(report_type, report_id)`
(`hogp_report.c:14-19`):

```c
if (reports[i].report_type == report_type &&
    reports[i].report_id == report_id)
        return (reports[i].value_handle);
```

**Why this is not merely untidy.** HIDS v1.1 §2.5.3.2 (text line 844) scopes
report-ID uniqueness to a *service*:

> "Report ID shall be nonzero in a Report Reference characteristic descriptor
> where there is more than one instance of the Report characteristic for any
> given Report Type."

Device-wide uniqueness across instances is required by HOGP §3.1.6 (line 693)
**only** for devices supporting the HID ISO feature:

> "When a HID Device supporting the HID ISO feature has more than one instance
> of the HID Service [3], all Report IDs shall be unique within each Report
> Type within the HID Device."

So a conformant non-ISO composite device — the ordinary keyboard-plus-mouse
dongle — may legally use report ID 1 for the keyboard in instance A and report
ID 1 for the mouse in instance B. And this topology is not exotic; HOGP §2.5
line 603 sanctions it explicitly:

> "Multiple service instances of the HID Service may be supported to allow
> implementers to define composite HID Devices whose combined functions require
> more than 512 octets of data to describe."

With the concatenated map, the kernel HID parser sees two top-level collections
both declaring report ID 1 with different layouts. Inbound, the notification
path (`hogp_deliver_notification`, `blued_central.c:2163-2197`) matches on the
*value handle*, so it prepends the right ID but the parser then decodes it
against whichever collection it bound first. Outbound is worse:
`hogp_handle_vhid_output()` (`:2094-2110`) and `hogp_find_feature_handle()`
resolve by report ID alone and take the first hit — the LED write for the
keyboard can be delivered to the mouse's Output Report characteristic.

**BlueZ does not do this.** It instantiates one `struct bt_hog` and one uhid
device per HID service instance, so report IDs are namespaced per instance.
`hog-lib.c:1565-1582` (cached-database path):

```c
if (!hog->attr) { hog->attr = attr; return; }      /* first instance = self */
instance = hog_new(hog->uhid_fd, hog->name, ..., attr);
hog->instances = g_slist_append(hog->instances, bt_hog_ref(instance));
```

and `hog-lib.c:1723-1749` for the live-discovery path. `hog->uhid_fd` is `-1`
for the top-level device (`hog.c:81`), so `hog_new` opens a fresh `/dev/uhid`
per instance (`hog-lib.c:1531-1532`, `src/shared/uhid.c:189-207`). Each
instance carries its own `hog->reports` list.

Zephyr and NimBLE: NOT-COMPARABLE, no HID implementation.

**Related, and already half-known.** `blued_central.c:1826-1828` records only
the *first* HID service in `dev->hid_disc`:

```c
/* Use the first HID service as the primary instance. */
if (svcs[s].start_handle == svcs[0].start_handle ||
    dev->hid_disc.service.start_handle == 0)
        dev->hid_disc = disc;
```

Every consumer of `hid_disc` — the boot-protocol path, the handle-cache save —
therefore sees instance 0 only. That is the mechanism behind H4 and H9.

The bond cache compounds it: `smp.h:231-232` and `blued_internal.h:207-208`
cap `report_map_handles[]` at **four** instances, and `HOGP_MAX_REPORTS` at
sixteen reports across *all* instances (`hogp_report.h:22`). Both overflow
silently.

### H7 — External Report Reference (0x2907) is discovered and then ignored [OURS-WRONG (gap), HIGH]

A tree-wide grep for `0x2907`, `EXTERNAL_REPORT` or `External Report` across
`usr.sbin/bluetooth/` and `lib/libble/` returns **nothing**. The descriptor is
discovered — `hogp_discover()` runs `gatt_discover_descriptors()` over the
range after each characteristic value handle (`blued_central.c:1806-1824`),
which includes the Report Map's descriptors — and then
`hogp_process_service()` inspects the descriptor array only for
`GATT_UUID_REPORT_REFERENCE` and `GATT_UUID_CCCD`
(`blued_central.c:993-1010`).

HOGP §4.6.1.1 line 1036 is a `shall`:

> "The Report Host shall discover all External Report Reference characteristic
> descriptors for each Report Map characteristic."

and §4.7 lines 1103-1105:

> "The Report Host shall read all characteristic descriptors of the Report Map
> characteristic to allow the Report Host to map information within the Report
> Map characteristic to external service characteristics used to transfer data
> described by the information between the Report Host and HID Device."

The binding rule, §4.8.1 lines 1136-1145, makes this a data-path requirement
rather than a bookkeeping one: for each (Report ID, Report Type) pair in the
Report Map there is **either** a HID Service Report characteristic **or** an
external service characteristic named by an External Report Reference. If the
device chose the second form, we never subscribe to that characteristic and
those reports never arrive. Table 4.1 line 815 makes "Non-HID Service
characteristic defined within Report Map" **M** for a Report Host.

**BlueZ implements this**, and its implementation is worth reading before
copying. `hog-lib.c:643-676`: on reading a 0x2907 whose value is 0x2A4D, it
launches a whole-database `discover_char(0x0001, 0xffff, Report UUID)` and
folds the foreign Report characteristics into this HoG's report list. But
`discover_external` (`hog-lib.c:495-508`) builds a UUID filter and then does
not pass it (`gatt_discover_desc(attrib, start, end, NULL, ...)` at `:247`),
so *every* descriptor in the Report Map's range is read and any 3-byte result
is interpreted as an External Report Reference. Implement the feature; do not
implement that bug.

### H8 — Relationship discovery is never performed [OURS-WRONG (gap), HIGH]

`gatt_discover_includes()` exists at `gatt.c:610` and has **zero callers** in
production code. `hogp_discover()` finds the Battery Service by scanning the
primary-service list (`blued_central.c:1775-1781`) and never looks at
`«Include»` definitions.

HOGP §4.5.3 lines 1004-1005:

> "The Report Host shall perform relationship discovery to find included
> services to discover all Battery Services with characteristics described
> within a HID Service Report Map characteristic value."

and Table 4.2 line 850 lists "Find included Services" as **X** for the Boot
Host and **M** for the Report Host — a mandatory GATT sub-procedure we do not
issue. §4.6.3.1 lines 1085-1087 then requires discovering the Report Reference
descriptors of those Battery Level characteristics, which is the mechanism by
which a battery level becomes a HID report.

This is the same defect as H7 seen from the service end: HOGP §3.1.1 lines
654-656 requires the device to `«Include»` any non-HID service whose
characteristic is described in the Report Map, and we do not read includes.

### H16 — Discovery arrays fill silently [OURS-WRONG, MEDIUM]

Four independent silent truncations, none of which produces a diagnostic:

- `HOGP_MAX_REPORTS` is 16 (`hogp_report.h:22`) and
  `hogp_process_service()` simply `break`s when the table is full
  (`blued_central.c:976-978`).
- `GATT_MAX_CHARS` is 64 (`gatt.h:17`); `gatt_discover_characteristics()`
  terminates its outer loop on `count < maxchars` (`gatt.c:738`) and returns
  success.
- `GATT_MAX_DESCS` is 128 (`gatt.h:18`); `hogp_discover()` passes the
  *remaining* space per characteristic (`blued_central.c:1818`), so once full
  every later characteristic gets `maxdescs == 0`, `gatt_discover_descriptors`
  returns 0 descriptors and 0 status, and those characteristics lose their
  CCCD and Report Reference.
- `report_map_handles[4]` (`smp.h:231`) caps the bond cache at four HID
  service instances.

A truncated characteristic list on a composite device means missing reports;
a truncated descriptor list means an input report with no CCCD, which H6 then
turns into silence. Note the contrast with the Report Map read, which *does*
warn on truncation (`blued_central.c:930-933`) — the diagnostic discipline
exists in this file, it just is not applied here.

### H18 — The HID Information Flags octet is read and thrown away [OURS-WRONG (gap), MEDIUM]

`blued_central.c:1026-1041` reads all four octets and stores only `bcdHID`:

```c
if (ret == 0 && len >= 4) {
        dev->hid_bcdHID = (uint16_t)info[0] |
            ((uint16_t)info[1] << 8);
        LOG_HOGP(1, "HID Information: bcdHID=%04x "
                    "country=%d flags=%02x", ...);
}
```

`bCountryCode` and `Flags` reach a log line and nothing else. HOGP §4.10 lines
1165-1174 states two `shall`s about those flag bits:

> "When a system enters a low-power Suspend Mode, the RemoteWake flag shall be
> used to determine whether the Report Host includes the HID Device in the set
> of devices that can wake it up."

> "When a Report Host is exiting a low power Suspend Mode, the
> NormallyConnectable flag shall be used to determine whether the Report Host
> can connect to the HID Device before any user interaction occurs on the HID
> device."

Bit assignments are HIDS Table 2.16 lines 1100-1121: bit 0 RemoteWake, bit 1
NormallyConnectable, **bit 2 SCI Supported and bit 3 SCI Low Power mode
supported are new in HIDS v1.1** (bits 2-7 were RFU in 1.0). Pinned in
`spec_extref_hogp_characteristics.h`.

BlueZ stores all three fields (`hog-lib.c:1091-1130`) and passes bcdHID and
bCountryCode into `UHID_CREATE2`; it acts on flag bit 0x04 (SCI) but, like us,
does not act on RemoteWake or NormallyConnectable.

---

## 2. Boot protocol versus report protocol

The profile's model, which our code does not implement, is that **Boot Host and
Report Host are two mutually exclusive roles chosen by the implementation**,
not two modes selected per device. HOGP §2.1 line 493: "This profile defines
three roles: HID Device, Boot Host, and Report Host." §2.3 lines 575 and 577:

> "A Boot Host shall not concurrently be a Report Host."
> "A Report Host shall not concurrently be a Boot Host."

Our code decides at runtime, per device, by whether a Report Map turned up.

### H5 — We write Report mode and then Boot mode on the same connection [OURS-WRONG, HIGH]

The order of operations in a boot-only device's setup is:

1. `hogp_process_service()` writes **Report Protocol Mode (0x01)** to every
   Protocol Mode characteristic in the service (`blued_central.c:1061-1071`).
2. Back in `hogp_discover()`, `dev->report_map == NULL`, so
   `hogp_setup_boot_protocol()` runs (`blued_central.c:1636-1642`).
3. That calls `hogp_enter_boot_protocol()`, which writes **Boot Protocol Mode
   (0x00)** (`hogp_boot.c:35-42`).

The device sees `0x01` then `0x00` on the same connection, from what it must
regard as one host. Beyond the role violation, step 1 is pure cost: HIDS
§2.4.1.1 line 672 says

> "The Protocol Mode characteristic value shall be reset to the default value
> following connection establishment."

and Table 2.2 line 665 gives that default as `0x01 Report Protocol Mode`. The
value is already 0x01. HOGP §4.11 line 1189 is explicit that we owe nothing
here:

> "There are no requirements on a Report Host to use the Protocol Mode
> characteristic."

**BlueZ is a Report-Host-only implementation and gets this right by
construction.** Its PICS (`doc/qualification/hogp-pics.rst:29-31`) leaves the
Boot Host row `TSPC_HOGP_1_3` unselected; no boot characteristic UUID appears
anywhere in the tree. It *reads* Protocol Mode and writes only in the one
direction that can be needed (`hog-lib.c:1221-1229`):

```c
if (value == HOG_PROTO_MODE_BOOT) {
        uint8_t nval = HOG_PROTO_MODE_REPORT;
        gatt_write_cmd(hog->attrib, hog->proto_mode_handle, &nval,
                                        sizeof(nval), NULL, NULL);
} else if (value == HOG_PROTO_MODE_REPORT)
        DBG("HoG is operating in Report Protocol Mode");
```

Note this is BlueZ recovering from a device that a *different* host left in
boot mode — exactly the mess our unconditional 0x01 write is aimed at, but
conditioned on a read.

Zephyr/NimBLE: NOT-COMPARABLE.

Note for whoever fixes this: the read-first optimisation BlueZ uses has **no
spec basis** either. HOGP §4.11 line 1187 says the Boot Host "shall write ...
following connection establishment", unconditionally. Reading first is a
defensible extra; it is not a substitute for the write.

### H4 — Boot Protocol Mode reaches only the first HID Service [OURS-WRONG, HIGH]

`hogp_boot.c:20-43` loops correctly over the characteristic array it is given,
and carries a comment claiming multi-instance coverage:

```c
	/*
	 * A-F6: a composite (dual-HID) device exposes one Protocol Mode
	 * characteristic per HID Service (HOGP v1.1 §4.11).  Write Boot mode to
	 * EVERY Protocol Mode characteristic, not just the first, or the second
	 * HID Service stays in Report mode.
	 */
	for (i = 0; i < nchars; i++) {
		if (chars[i].uuid16 != UUID_PROTOCOL_MODE)
			continue;
```

The comment is true about the requirement and false about the effect, because
of what the caller passes (`blued_central.c:1660-1661`):

```c
	ret = hogp_enter_boot_protocol(&dev->att, dev->hid_disc.chars,
	    dev->hid_disc.nchars);
```

`dev->hid_disc` is the **primary instance only** (`blued_central.c:1826-1828`,
quoted in H1). A second HID Service's Protocol Mode characteristic is not in
that array, so it is never written, and per HIDS Table 2.2 line 662 —

> "A HID Service shall only enter Boot Protocol Mode after this value has been
> written."

— that service stays in Report Protocol Mode and produces nothing on its Boot
Keyboard/Mouse Input Report characteristics.

HOGP §4.11 lines 1187-1188 requires the write "for each HID Service on the
GATT Server". The loop in `hogp_boot.c` is also defending against a case the
spec forbids: HIDS §2.4 line 642 says "Only a single instance of this
characteristic shall exist as part of the HID Service", so there is never more
than one Protocol Mode per service. The multiplicity that matters is across
*services*, which is exactly the axis the call site collapses.

This is the sixth instance of the "comment cites a source that contradicts it"
pattern; the comment is not wrong about the spec, it is wrong that the code
satisfies it.

### H9 — A boot combo device loses its mouse [OURS-WRONG, MEDIUM]

`hogp_setup_boot_protocol()` picks exactly one map and one report
(`blued_central.c:1587-1602`):

```c
	for (i = 0; i < dev->hid_disc.nchars; i++) {
		if (dev->hid_disc.chars[i].uuid16 == UUID_BOOT_KB_INPUT_REPORT) {
			map = boot_kb_report_map;
			...
			break;
		}
		if (dev->hid_disc.chars[i].uuid16 == UUID_BOOT_MOUSE_INPUT_REPORT &&
		    map == NULL) {
			map = boot_mouse_report_map;
			...
			/* Keep scanning in case a keyboard is also present */
		}
	}
```

Keyboard wins, mouse is discarded, one report is registered. HOGP §4.12 line
1196 and §4.14 line 1211 are two independent `shall`s:

> "If the Boot Host supports the Boot Keyboard Input Report characteristic,
> then it shall enable notifications of the Boot Keyboard Input Report
> characteristic using the Client Characteristic Configuration descriptor."

> "If the Boot Host supports the Boot Mouse Input Report characteristic, then
> it shall enable notifications of the Boot Mouse Input Report characteristic
> using the Client Characteristic Configuration descriptor."

Nothing makes them alternatives. HOGP Table 4.1 condition C.3 (line 822) —
"If one of these features is supported, both features shall be supported" —
points the other way.

The two canonical descriptors themselves are correct: both match
`bt_hid_spec_boot_keyboard_descriptor[]` in the existing
`spec_hogp_report_map_oracles.h`, which is HID 1.11 Appendix B.1.

### H15 — Boot Keyboard Output Report (0x2A32) is never discovered [OURS-WRONG (gap), MEDIUM]

`hogp_boot.h` defines `UUID_BOOT_KB_INPUT_REPORT` (0x2A22) and
`UUID_BOOT_MOUSE_INPUT_REPORT` (0x2A33) and no output-report UUID; 0x2A32
appears nowhere in the tree. The synthesised boot keyboard descriptor
(`blued_central.c:1529-1538`) *does* declare the five LED output bits, so the
kernel will emit `UHID` output reports that
`hogp_handle_vhid_output()` then fails to route — there is no report with
`report_type == HID_REPORT_TYPE_OUTPUT` in boot mode, so every LED write hits
the drop path at `blued_central.c:2113`.

HIDS Table 2.1 makes Boot Keyboard Input and Boot Keyboard Output both
condition C.2, "Mandatory for HID Devices operating as keyboards, else
excluded" — a boot keyboard has both, and a Boot Host that ignores one has no
Caps Lock. §2.8.1 lines 1002-1004 gives the write procedure as GATT Write
Characteristic Value **or** Write Without Response.

BlueZ: NOT-COMPARABLE, it implements no boot protocol at all.

---

## 3. Report handling

### H6 — A failed Report Reference read leaves a prohibited Report Type in place [OURS-WRONG, HIGH]

`hogp_process_service()` initialises each report to zero and overwrites only on
a successful two-octet read (`blued_central.c:980-1002`):

```c
		rpt->report_id = 0;
		rpt->report_type = 0;
		...
			if (disc->descs[j].uuid16 ==
			    GATT_UUID_REPORT_REFERENCE) {
				uint8_t ref[2];
				ret = att_read(&dev->att, dh, ref,
				    sizeof(ref), &len);
				if (ret == 0 && len >= 2) {
					rpt->report_id = ref[0];
					rpt->report_type = ref[1];
				}
			}
```

The `ret` is discarded. Three things follow.

First, **0x00 is not a spare value.** HIDS Table 2.7 line 831 reads
`0x00: Prohibited.` — the field layout is pinned in
`spec_extref_hogp_characteristics.h`. Core's disposal rule for prohibited
values differs from the RFU rule, and neither is "store it and carry on".

Second, the report is kept in the table with a type that matches no branch.
`hogp_subscribe()` only subscribes `HID_REPORT_TYPE_INPUT`
(`blued_central.c:1993-1994`), so no notification is enabled; and — the part
that makes this silent — the guard at `blued_central.c:2013-2017` only fires
if at least one input report was *found*:

```c
	if (any_input && !any_success) {
		warnx("all CCCD writes failed, no notifications will arrive");
		return (-1);
	}
	return (0);
```

If **every** Report Reference read failed, `any_input` is 0, `hogp_subscribe()`
returns success, and setup completes. A vhid device is created from a valid
Report Map, the user sees a keyboard appear, and no key ever arrives.

Third, the most likely cause of that failure is the one HOGP §7 line 2073
guarantees will happen:

> "HID Service characteristics shall require an encrypted link for reading,
> writing, and notification."

The descriptor read runs before any pairing (see H3). The Report Map read is
error-checked and would normally trip the auth-retry path first
(`blued_central.c:899-904`) — but only because it happens to be read first. A
device that permits reading the Report Map unencrypted while gating the
descriptors lands squarely in this hole.

**BlueZ has the same shape and one crucial difference.**
`report_reference_cb` (`hog-lib.c:443-458`) logs and `goto remove`s on a bad
read, leaving `id = 0, type = 0`, and does not block uhid creation either. But
BlueZ enables notifications from *inside* that callback, so a report whose
descriptor read failed is unreachable in exactly the same way. Classification
is OURS-WRONG rather than ECOSYSTEM-SPLIT because the spec settles it: HIDS
line 847, "HID Devices shall have a Report Reference characteristic descriptor
in each Report characteristic definition for Report Protocol Mode", and Table
2.4 makes Notify **M** for an Input Report. A host that cannot classify a
Report characteristic has lost the device, and should say so.

### H10 — Feature reports are unreachable, and three comments describe a command that does not exist [OURS-WRONG (gap), MEDIUM]

`hogp_find_feature_handle()` (`blued_central.c:2150-2159`) is defined,
exported in `blued.h:645`, and **called from nowhere**. The comments around it
describe a control path that has never existed:

- `blued_central.c:2116`: "Used by ctl.c for HOGP_READ/HOGP_WRITE commands."
- `ctl.c:614`: "HOGP_READ, HOGP_WRITE). These commands block the main event
  loop"
- `ctl.c:658`: "Rate-limit blocking ATT commands (DISCOVER, READ, WRITE,
  HOGP_READ, HOGP_WRITE)."

A grep for `HOGP_READ` or `HOGP_WRITE` across `usr.sbin/bluetooth/` and
`lib/libble/` finds only those three comments. There is no such IPC opcode.
Feature reports are therefore discovered, classified, stored in
`dev->reports[]`, and can be neither read nor written.

The relevant spec text, should this be implemented, is HIDS §2.5.1 lines
786-791 and Table 2.4 line 713: Feature Report is Read **M**, Write **M**, and
**Write Without Response `E` — excluded, not permitted**. The obvious
implementation, reusing `att_write_cmd()` as the Output path does, would be
non-conformant. Pinned as `bt_extref_hid_char_props[]`.

BlueZ routes Feature reports through `UHID_GET_REPORT` / `UHID_SET_REPORT`
(`hog-lib.c:897-900`, `:984-986`), always as a Write Request escalating to
Prepare/Execute Write over the MTU — conformant.

### H17 — Output reports ignore characteristic properties [OURS-DIFFER, MEDIUM]

`hogp_handle_vhid_output()` always uses Write Without Response
(`blued_central.c:2098-2104`), justified by:

```c
		/*
		 * HOGP v1.0 Section 3.3.3: Output Reports use Write
		 * Without Response (ATT Write Command, opcode 0x52).
		 */
```

Two problems with that citation. It names HOGP **1.0**, whose section numbering
does not survive into the in-tree v1.1 (see the version warning above). And it
overstates: the in-tree text gives Write Without Response as one of two
procedures, chosen by which USB HID operation is being emulated. HIDS §2.5.1
lines 781-784:

> "The GATT Write Characteristic Value sub-procedure is used to write to a
> Report characteristic containing Output Report data. This procedure maps to a
> Set_Report (Output) request in USB HID [2]. The GATT Write Without Response
> sub-procedure is also used to write to a Report characteristic containing
> Output Report data, and this procedure maps to Data Output in USB HID [2]."

Both are mandatory *properties* for an Output Report (Table 2.4 line 711), so
in practice an unconditional Write Command works against a conformant device.
It is classified OURS-DIFFER rather than OURS-WRONG for that reason. The
`gatt_char.properties` field is already captured at `gatt.c:776` and unused.

BlueZ picks by property on the `UHID_OUTPUT` path (`hog-lib.c:768-775`) —
Write Request preferred, Write Command as fallback, silently dropped if
neither — and always uses Write Request on the `UHID_SET_REPORT` path
(`:897-900`). Its exported `bt_hog_send_report()` (`:1923-1955`) has a real
bug worth not copying: `if` / `if` rather than `if` / `else if`, so a
characteristic advertising both properties gets the report **sent twice**.

### Report ID framing — AGREE

Inbound, `hogp_deliver_notification()` prepends the report ID only when it is
non-zero (`blued_central.c:2176-2190`). Outbound,
`hogp_handle_vhid_output()` strips a leading ID byte if any report in the
device has a non-zero ID (`:2059-2081`). This matches HOGP §4.8.1 lines
1147-1153, which describes prepend-on-receive and strip-on-send.

One caveat, and it is a consequence of H1 rather than a separate defect: the
"does this device use report IDs" test is global over the merged table, so a
device whose first HID Service is numbered and whose second is not will have
the second's reports mis-framed. BlueZ sidesteps this by asking the kernel —
`set_numbered()` reads `UHID_START.dev_flags` (`hog-lib.c:790-821`) — which is
per-uhid-device and therefore per-instance.

Also worth recording: §4.8.1 is titled "Translation layer" and opens with a
Note (line 1118) scoping it to implementations that "utilize a translation
layer located between the GATT layer on the Report Host and the USB HID class
driver". That is exactly what vhid is, so the section applies to us.

---

## 4. Suspend, control point, and connection management

### H12 — Suspend is never written [OURS-WRONG (gap), MEDIUM]

`att_write_cmd(&dev->att, dev->hid_ctrl_handle, &exit_suspend, 1)` at
`blued_central.c:709-713` is the only HID Control Point write in the tree. A
grep for `SUSPEND` across `blued/` finds no counterpart writing `0x00`, and no
hook into any system power-management path.

The write procedure is right — HIDS §2.11.1 lines 1150-1151 mandates Write
Without Response, and `att_write_cmd()` is that. The value is right: Table 2.17
line 1161 gives 0x01 = Exit Suspend. But the pairing is one-sided.

HOGP §4.6.1.3 lines 1049-1051 makes discovering the characteristic conditional
on the host supporting Suspend mode, and Table 4.1 condition C.1 (line 820)
reads "Mandatory if the Host supports Suspend Mode, otherwise optional". By
discovering it and writing Exit Suspend we assert support; by never writing
Suspend we do not deliver it. A device that is told to exit suspend and never
told to enter it holds its radio and scan rates at active levels across every
host sleep.

Note also, from the spec extraction: **HIDS v1.1 adds values 0x02-0x05** to
this characteristic (Enable SCI Default / Fast / Low Power / Full Range), so
the RFU range is now 0x06-0xFF rather than 0x02-0xFF. Pinned in
`spec_extref_hogp_characteristics.h`.

**BlueZ has the plumbing and it is dead.** `hog.c:114-138` wires
`suspend_callback`/`resume_callback` to
`bt_hog_set_control_point(dev->hog, suspend)`, and `hog-lib.c:1907-1921`
writes `suspend ? 0x00 : 0x01` by Write Command. But the only `suspend_init`
compiled in is the stub `profiles/input/suspend-none.c:19-24`
(`Makefile.plugins:69`), which stores neither callback. So BlueZ writes neither
value in any shipped build — its PICS rows `TSPC_HOGP_11_13/14/15/16` are
correspondingly unselected. It also would not propagate to `hog->instances`,
so a multi-instance device would get Suspend on the first service only.

Classification stays OURS-WRONG: BlueZ agreeing with us by accident is not
evidence, and HIDS §2.11 lines 1145-1147 says the behaviour "shall be the same
regardless of which instance of the HID Service is associated with the HID
Control Point", so our single last-wins `hid_ctrl_handle` is fine.

### H14 — Reconnection is a backoff timer, not a scan [OURS-DIFFER, MEDIUM]

`blued_conn_setup_central_impl()` reconnects by opening an ATT socket
(`att_open`/`att_open_fd`, `blued_central.c:417-427`), i.e. a connection
attempt. Failure schedules a retry with exponential backoff
(`blued_central.c:40-66`, cap at `blued_reconnect_max_delay`,
`blued.c:3705-3706`).

HOGP has **no connection-establishment or link-loss section at all**; the
entire model is Appendix A, Table A.1 (text lines 2145-2172), transcribed into
`spec_extref_hogp_host_rules.h`. Both rows have the same shape: **the device
advertises, the host scans.** With `NormallyConnectable` FALSE — labelled
"Most common configuration" — the device does "high duty-cycle advertising for
5 s" when it has data and turns its radio off when idle, and the host does
"low duty-cycle scanning".

The keystroke that wakes a sleeping keyboard is the one that starts that
5-second burst. A host in a backoff gap misses it, and the user presses a key,
sees nothing, and presses again. A connection attempt with an indefinite
controller-side scan window is behaviourally equivalent to continuous scanning;
a *cancelled and retried* one is not.

Classified OURS-DIFFER rather than OURS-WRONG because Appendix A uses no
conformance verbs at all — no `shall`, no `should` — which is a real
qualification weakness in the document rather than in our reading of it.

**BlueZ delegates this to the kernel.** `hog.c:224` sets
`.auto_connect = true`, which reaches
`adapter_auto_connect_add()` (`src/adapter.c:5842-5879`) and issues
`MGMT_OP_ADD_DEVICE` with `cp.action = 0x02` — accept-list background scanning
that persists rather than backing off. Its backoff (`src/device.c:4024-4046`,
1/2/4 s) applies to *authentication* failures only, not link loss. Note also
`device.c:2291-2292`: BlueZ declines to add a device with a private address to
the accept list at all.

Zephyr/NimBLE: NOT-COMPARABLE, no HOGP connection policy.

### Who re-establishes — AGREE, and worth writing down

HOGP §3.1.7 line 696 settles it: a device with `NormallyConnectable` TRUE "is
connections-initiated by the bonded Report Host" and "shall be in the GAP
Undirected Connectable Mode whenever it is not connected to any HID Host". The
device never initiates; it advertises so that the host, which is the GAP
Central by §2.4 line 586, can. Our host-initiated reconnect is the right shape.
H14 is about *when* we listen, not about who connects.

### Service Changed on a live connection — partial

`hogp_process_pdu()` handles a Service Changed indication by confirming it and
invalidating the persistent cache (`blued_central.c:2240-2288`). Two things it
does not do: it does not re-run discovery on the connection that is still up,
so the live session keeps using handles it has just declared invalid until the
next reconnect; and — H2 — nothing ever subscribed, so the indication cannot
arrive in the first place.

Core Vol 3 Part G §2.5.2 lines 72132-72137 requires more than cache
invalidation:

> "The client, upon receiving an ATT_HANDLE_VALUE_IND PDU containing the range
> of affected Attribute Handles, shall consider the attribute cache invalid
> over the affected Attribute Handle range. Any outstanding request transaction
> shall be considered invalid if the Attribute Handle is contained within the
> affected Attribute Handle range. The client must perform service discovery
> before the client uses any service that has an attribute within the affected
> Attribute Handle range."

The identification is right, though, and better than the obvious alternative:
`gatt_indication_is_service_changed()` matches on the value handle recorded at
discovery rather than on a 4-octet length, so an unrelated 4-byte indication
cannot thrash the cache.

---

## 5. GATT client procedures

This is the four-way comparison.

### H2 — The Service Changed CCCD is never written [OURS-WRONG, HIGH]

`hogp_discover()` finds the Service Changed characteristic and records its
value handle (`blued_central.c:1719-1734`). `hogp_subscribe()`
(`blued_central.c:1986-2019`) iterates `dev->reports[]` and writes CCCDs for
input reports only. `dev->svc_changed_handle` appears at exactly five sites
(`blued_central.c:1287,1690,1727,1731,2263` and `blued_internal.h:219`) and at
none of them is a CCCD located or written.

We are a **bonded caching client**: `hogp_cache_save()` persists the HID
service range, the report table and the handles into the bond record
(`blued_central.c:1179-1235`), and `hogp_cache_restore()` reuses them across
connections. Core Vol 3 Part G §7.1 lines 74975-74979:

> "This Characteristic Value shall be configured to be indicated using the
> Client Characteristic Configuration descriptor by a client. Indications
> caused by changes to the Service Changed Characteristic Value shall be
> considered lost if the client has erroneously not enabled indications in the
> Client Characteristic Configuration descriptor."

and line 75025:

> "The client shall support Characteristic Value Indication of the Service
> Changed characteristic."

§2.5.2 lines 72092-72095 explains what we forfeit: for a bonded client "the
attribute cache is valid across connections", and a server that changes its
database while we are away "shall send an indication when the client
reconnects". We have arranged never to receive it. The Database Hash check on
reconnect (H20) is the only remaining safety net, and it is conditional on
`bond->has_db_hash`.

HOGP itself layers a second requirement on top, §4.17 line 1243: the Boot Host
and Report Host "shall share bonding information and information regarding
«Service changed» indications".

**BlueZ registers it.** `register_service_changed()`
(`src/shared/gatt-client.c:1852-1879`) is called from `init_complete:2084`,
finds 0x2A05 in the database and `register_notify()`s it, deferring
`notify_client_ready` until the CCCD write completes
(`service_changed_register_cb:1830-1850`). Zephyr and NimBLE both do **not**
(see below) — but they are libraries whose applications own the decision,
whereas we are the application.

### H11 — Client Supported Features (0x2B29) is never written [OURS-WRONG, HIGH]

Every occurrence of `0x2B29` in the tree is in `att_server_dispatch.c`
(`:46,70,75,1034,1039,1302,1352,1735,1836,1865`) — the **server** side. The
client never writes it.

Core Vol 3 Part G §7.2 Table 7.6 line 75075 defines bit 0 octet 0 as Robust
Caching, and §2.5.2.1 line 72351 makes the whole 0x12 mechanism conditional on
it:

> "If a client that has indicated support for robust caching (by setting the
> Robust Caching bit in the Client Supported Features characteristic) is
> change-unaware then the server shall send an ATT_ERROR_RSP PDU with the Error
> Code parameter set to Database Out Of Sync (0x12) ..."

So a conformant server will **never** send us 0x12, and our handling of it
(`blued_central.c:626-637`) is unreachable against conformant peers. It is not
"safe by omission": the same clause is what makes the server withhold
notifications from a change-unaware client (lines 72371-72372), and by not
opting in we also give up the server-side guarantee that a stale cache is
caught. We cache handles across connections on the strength of a hash we
sometimes read.

The same gap makes one other piece of code unreachable:
`hogp_process_pdu()` parses `ATT_OP_MULTIPLE_HANDLE_VALUE_NTF`
(`blued_central.c:2220-2240`), but bit 2 of octet 0 is the Multiple Handle
Value Notifications bit and we never set it either, so a conformant server may
not send that PDU.

If this is implemented, note the two traps the spec extraction surfaced. Core
line 75100: "A client shall not clear any bits it has set. The server shall
respond to any such request with the Error Code parameter set to Value Not
Allowed (0x13)." And lines 75093-75094: for a bonded client the value is
persistent across connections. A host that rewrites CSF from a zeroed struct
on every reconnect gets 0x13.

**BlueZ writes it unconditionally** when the characteristic is present
(`gatt-client.c:2029-2065`), setting Robust Caching at `:2045` and Multiple
Notifications at `:2063`, seeded from `src/device.c:6395-6399`.
**Zephyr does not** — its CSF handling is server-side only.
**NimBLE names the bit and never sets it**:
`BLE_SVC_GATT_CLI_SUP_FEAT_ROBUST_CATCHING_BIT` (note the typo) at
`services/gatt/src/ble_svc_gatt.c:35` is referenced nowhere;
`ble_svc_gatt_init()` sets only the EATT and multi-notification bits
(`:191,:195`).

### H13 — Database Out Of Sync is handled on one path only [OURS-WRONG, MEDIUM]

`ATT_ERR_DATABASE_OUT_OF_SYNC` (`att.h:89`) is tested at exactly one place,
`blued_central.c:626`, and it wraps only the return of `hogp_discover_cached()`:

```c
	/* Handle Database Out Of Sync -- full rediscovery */
	if (ret == ATT_ERR_DATABASE_OUT_OF_SYNC) {
```

Every other request that can receive 0x12 does not recognise it: the Report
Map read (`:899`), the Report Reference descriptor reads (`:996`), the HID
Information read (`:1030`), the CCCD writes in `hogp_subscribe()` (`:2003`),
the output-report writes, and — notably — the `hogp_discover()` call on the
auth-retry path at `:654`, which is reached *after* the 0x12 branch has already
run and cannot re-enter it.

Core §2.5.2.1 lines 72375-72378:

> "If a client receives an ATT_ERROR_RSP PDU with the Error Code parameter set
> to Database Out Of Sync (0x12), it shall consider its attribute cache invalid
> and shall not make use of the cached information until it has performed
> service discovery or obtained the changed database definitions using an
> out-of-band mechanism."

Lines 72356-72360 make it clear this can arrive on essentially any request; the
only exemptions are a Read By Type for «Include» or «Characteristic», and a
Read By Type over the full 0x0001-0xFFFF range.

Today this is latent, because H11 means we never receive 0x12 at all. Fixing
H11 without fixing H13 would turn a dormant gap into a live failure: a
mid-discovery 0x12 currently propagates as an opaque non-zero status and takes
the `warnx("HOGP discovery failed: %d", ret)` path at `:657`, which drops the
connection instead of rediscovering.

**BlueZ has the most developed handling of the four**, and it lives in the ATT
layer rather than the profile. `src/shared/att.c:819-839` **parks** the failing
operation on `chan->pending_db_sync` rather than failing it, cancels its
timeout, and calls `db_sync_callback`. `gatt_client_db_sync_cb`
(`gatt-client.c:2445-2489`) re-reads the Database Hash and `db_hash_check_cb`
(`:2358-2443`) adjudicates: hash unchanged → `bt_att_resend` the parked
request; hash changed → cancel and rediscover 0x0001-0xFFFF; a Service Changed
already in flight → decide by handle range. Two limits worth knowing:
`pending_retry_att_id` is a scalar, so a second concurrent 0x12 overwrites the
first; and HoG's own GAttrib requests can be silently `bt_att_cancel`led by
this adjudicator with no path back into `hog-lib` to notice.

**Zephyr passes 0x12 straight through.** `att_error_rsp()`
(`subsys/bluetooth/host/att.c:2621-2667`) has no 0x12 case; the only error it
acts on is a security error under `CONFIG_BT_ATT_RETRY_ON_SEC_ERR`
(`:2649-2661`). Robust caching is implemented server-side only — the sole
mention of `BT_UUID_GATT_DB_HASH` in the host directory is the local attribute
table at `gatt.c:1117`.

**NimBLE does not define the error code.** `include/host/ble_att.h` runs
`:111 BLE_ATT_ERR_INSUFFICIENT_RES 0x11` straight to
`:114 BLE_ATT_ERR_VALUE_NOT_ALLOWED 0x13`. No Database Hash characteristic
exists in either direction; `services/gatt/src/ble_svc_gatt.c:54-79` exposes
Service Changed, Server Supported Features and Client Supported Features and
nothing else.

So the ecosystem position is: BlueZ implements robust caching properly, Zephyr
implements the server half, NimBLE implements neither, and **we implement the
server half plus a client stub that cannot fire.** Our server side
(`att_server_dispatch.c:1352,1865`) is the strongest of the three non-BlueZ
stacks.

### H20 — On a fresh bond the Database Hash is read after discovery [OURS-DIFFER, LOW]

`blued_central.c:580-622` reads the hash *before* discovery only when
`bond->has_db_hash` or `bond->has_handle_cache` is already set. On a first
connection neither is, so the hash is read afterwards
(`blued_central.c:661-678`) and persisted alongside the handle cache.

If the database changes between the discovery and that read, we persist a hash
that matches a database we never fully enumerated, and the next reconnect takes
the cache-valid path against stale handles. The window is small and requires a
device that reconfigures mid-connection.

Core does not state a "read the hash first" `shall` for this case — the read is
what makes a *change-unaware* client change-aware (line 72168), and a
non-bonded client's initial state is change-aware (line 72162). Hence
OURS-DIFFER. BlueZ reads the hash at three points, including before primary
discovery (`gatt-client.c:2146`, `:1632`) and again after a successful
discovery (`discovery_op_complete:440-442`), which closes this window.

### Database Hash read procedure — OURS-RIGHT-OTHERS-DIFFER (against Zephyr and NimBLE)

`gatt_read_database_hash()` (`gatt.c:175-214`) uses
`att_read_by_type(ac, 0x0001, 0xFFFF, GATT_UUID_DATABASE_HASH, ...)`. That is
exactly what Core §7.3 lines 75143-75145 demands:

> "In order to read the value of this characteristic the client shall always
> use the GATT Read Using Characteristic UUID sub-procedure. The Starting
> Handle should be set to 0x0001 and the Ending Handle should be set to
> 0xFFFF."

And it is not merely stylistic: lines 72358-72360 exempt precisely
`ATT_READ_BY_TYPE_REQ` over 0x0001-0xFFFF from the 0x12 error, so a client that
reads the hash by handle, or over a narrowed range, deadlocks — it cannot
become change-aware because it cannot read the hash. We match BlueZ
(`gatt-client.c:1511-1537`). Zephyr and NimBLE have no client-side hash read at
all, so nothing to get right.

The response validation is strict and correct: `len != 19`, `entry_len != 18`,
zero handle all rejected (`gatt.c:196-206`).

Per the brief, the wire byte order is out of scope; it is already a run-time
option (`gatt.c:53-112`, `config.h:158-159`) with its own oracle in
`spec_extref_db_hash.h`.

### Read Long — OURS-RIGHT-OTHERS-DIFFER

The Report Map read loop (`blued_central.c:918-933`) is **bounded**:

```c
	while (len == (size_t)(bearer_mtu - 1) &&
	    total < rmbuf_sz) {
```

with `rmbuf_sz = 4096`, and it warns on truncation. Both other client stacks
have an unbounded continuation loop on the same `len < MTU-1` rule — Zephyr
`gatt.c:4848-4857` (`offset` is `uint16_t`, no cap) and NimBLE
`ble_gattc.c:3283-3292` — so a device that always returns exactly MTU-1 octets
drives the loop until the offset wraps. NimBLE even has the guard available and
applies it only on the read-multiple-variable path (`ble_gattc.c:3379-3381`).
The Report Map read is the canonical long read on a HID device, so this is the
exact case those two stacks leave open.

BlueZ is bounded by `UHID_DATA_MAX` at the consumer end but its blob loop has a
worse property: `attrib/gatt.c:758-761` **downgrades any error in the blob
chain to success**, handing whatever was accumulated to uhid:

```c
	if (status != 0 || rlen == 1) {
		status = 0;            /* error downgraded to success */
		goto done;
	}
```

We do not do that; a failed blob breaks the loop and the accumulated length is
used, but the truncation is reported (`blued_central.c:930-933`).

One improvement available for free: HIDS §2.6.1 line 862 caps the Report Map at
**512 octets**. Our 4096 is safe but eight times larger than any conformant
value, and a 512-octet cap would turn a hostile long read into an immediate,
attributable rejection. Pinned as `BT_EXTREF_REPORT_MAP_MAX_OCTETS`.

The bearer-relative MTU test at `blued_central.c:917` — re-reading
`att_last_bearer_mtu()` each iteration because a blob may be routed onto an
EATT bearer with an independently negotiated MTU — is correct and is something
none of the three references needs to do, because none of them mixes bearers
mid-procedure this way. The comment there is accurate.

### Read Multiple — AGREE (unused, correctly)

`att_read_multiple()` and `att_read_multiple_variable()` exist
(`att.c:1318`, `:1371`) and are not used in the HOGP path. Neither is BlueZ's
`bt_gatt_client_read_multiple()`, whose only callers are `unit/test-gatt.c` and
`tools/btgatt-client.c`. Zephyr and NimBLE implement both variants and expose
them to applications. Nothing in HOGP or HIDS names either procedure. No
divergence.

For the record, since it bears on H11: NimBLE fails the whole procedure on a
truncated Length-Value tuple (`ble_gattc.c:3402-3410`), Zephyr silently clamps
it (`gatt.c:4993-4996`), and BlueZ clamps too (`gatt-client.c:2889-2905`) — an
ECOSYSTEM-SPLIT in an area we do not exercise.

### Service and characteristic discovery — AGREE

`gatt_discover_primary_services_range()` (`gatt.c:223`) uses Read By Group
Type, `gatt_discover_characteristics()` (`gatt.c:721`) uses Read By Type on
0x2803, `gatt_discover_descriptors()` (`gatt.c:830`) uses Find Information —
the same three procedures Zephyr (`gatt.c:4711-4738`) and NimBLE
(`ble_gattc.c:1466,1907,2693`) use, and what HOGP §4.6.1 lines 1026-1031
requires.

Response validation is stronger than the references': `entry_len` restricted to
7/9/21 with a modulus check, handle-range and monotonicity checks, and
`value_handle <= decl_handle` rejected (`gatt.c:767-781`). The 32-bit UUID
branch collapsing to 16-bit where possible (`gatt.c:783-799`) is a nicety none
of the three implements.

One divergence not worth a finding number: for a 128-bit **included** service
UUID, both Zephyr (`gatt.c:4228-4268`) and NimBLE do the spec-mandated
follow-up Read Request on the included service's start handle. We have
`gatt_discover_includes()` but never call it (H8), so the question is moot
until H8 is fixed — at which point that follow-up read must be implemented too.

### Notification and indication handling — AGREE, with one note

`hogp_process_pdu()` (`blued_central.c:2199-2292`) distinguishes
`ATT_OP_HANDLE_NOTIFY`, `ATT_OP_MULTIPLE_HANDLE_VALUE_NTF` and
`ATT_OP_HANDLE_IND`, and confirms indications via
`att_confirm_bearer(&dev->att, fd)` at `:2249` — **before** the Service Changed
processing that follows it. That ordering is better than either embedded stack:
Zephyr calls the application callback first and allocates the confirmation
afterwards (`att.c:2784` then `:2786`), and will silently skip the confirmation
entirely if allocation fails (`:2787-2790`), stalling the peer's ATT
transaction. NimBLE pre-allocates the confirmation before dispatch
(`ble_att_svr.c:2824-2827`) but still transmits after (`:2844` then `:2850`).

Length validation on the multi-notification path is correct
(`blued_central.c:2226-2233`): both the 4-octet tuple header and the declared
value length are bounds-checked against the remaining PDU.

Note only: HID reports are delivered to vhid from the notification path only
(`hogp_deliver_notification`), never from the indication path. That is right —
HIDS Table 2.4 makes Notify mandatory and gives no Indicate property for a
Report characteristic — but it is worth stating, because the indication branch
does call `blued_ctl_notify_value()` on any handle, so an indication on a
report handle reaches control clients and not the HID device.

---

## 6. Security expectations

### H3 — Bonding is reactive, not proactive [OURS-WRONG, HIGH]

The setup sequence in `blued_conn_setup_central_impl()` is: connect, exchange
MTU, **encrypt only if a bond already exists** (`blued_central.c:547-570`),
then discover. Pairing happens only after discovery has already failed with an
authentication error (`blued_central.c:639-655`):

```c
		if (ret == ATT_ERR_INSUFF_AUTHEN ||
		    ret == ATT_ERR_INSUFF_ENCRYPTION ||
		    ret == ATT_ERR_INSUFF_ENC_KEY_SIZE) {
			LOG_HOGP(1, "device requires pairing");
			if (blued_central_start_pairing(dev, conn) < 0) {
```

HOGP §7 line 2083 is an unconditional host obligation:

> "The HID Host, which must be a Central as per Section 2.4, shall perform the
> Bonding procedure with the HID Device, as defined in [2] Volume 3, Part C,
> Section 9.4.4."

There is no "if the device asks" and no error-driven trigger. The companion
device-side clause, line 2073 — "HID Service characteristics shall require an
encrypted link for reading, writing, and notification" — means a *conformant*
device forces our hand, which is why this works in practice. Against a
non-conformant device that leaves its characteristics open, we read the Report
Map, the Report Reference descriptors and the HID Information, and enable
notifications, **all in the clear**, and never pair at all, because no error
ever arrives. A keyboard whose keystrokes are readable by any passive listener
is the exact failure mode HOGP §7 exists to prevent.

There is a second-order effect on H6: because pairing is error-driven, the
descriptor reads that H6 fails to error-check are precisely the reads most
likely to hit an authentication error.

**BlueZ gates at accept time and refuses otherwise** (`profiles/input/hog.c:181-192`):

```c
	/* HOGP 1.0 Section 6.1 requires bonding */
	if (!device_is_bonded(device, btd_device_get_bdaddr_type(device))) {
		struct bt_gatt_client *client;
		if (!auto_sec)
			return -ECONNREFUSED;
		client = btd_device_get_gatt_client(device);
		if (!bt_gatt_client_set_security(client, BT_ATT_SECURITY_MEDIUM))
			return -ECONNREFUSED;
	}
```

An unbonded HID device is either refused outright (`LEAutoSecurity=false` in
`input.conf`) or has its ATT link elevated to BT_SECURITY_MEDIUM — LE Security
Mode 1 Level 2 — **before** `bt_hog_attach()` runs a single GATT operation.
Note BlueZ's own comment cites "HOGP 1.0 Section 6.1"; in the in-tree v1.1 this
is §7, and in v1.2 it is §8.

Zephyr and NimBLE: NOT-COMPARABLE for the profile requirement. Two datapoints
from them are still useful, though:

- NimBLE refuses to *deliver* notification and indication payloads to the
  application when `MYNEWT_VAL(BLE_SM_LVL) >= 2` and the link is unencrypted
  (`ble_att_svr.c:2680-2687` and `:2834-2839`); an indication is still
  confirmed but its data is dropped. That is a transport-level version of the
  guarantee HOGP §7 wants and we do not have.
- Zephyr's only automatic security action is `att_change_security()` under
  `CONFIG_BT_ATT_RETRY_ON_SEC_ERR` (`att.c:2649-2661`) — reactive, like us.

### What security *level* the profile requires — nothing, and that is the finding

**HOGP v1.1 and v1.2 name no LE Security Mode or Level anywhere.** No "Mode 1
Level 2/3/4", no MITM requirement, no key-size floor. The only mode/level
sentence is §7 lines 2078-2080, telling the *device* to make the Device
Information, Scan Parameters and Battery Service characteristics match the HID
Service — with no absolute value given.

HIDS is weaker still: every characteristic's Security Permissions cell in
Table 2.1 reads **None**, with the note at lines 574-576 that this "does not
impose any requirements" and that profiles may impose more. Every declaration
table reads "Read Only, No Authentication, No Authorization".

So the requirement resolves to exactly two things: **bond** (HOGP line 2083)
and **encrypt** (line 2073, as a device obligation, plus line 2086 "should
encrypt the link as early as possible after reconnection"). Any test asserting
a specific level has no normative basis. This is worth pinning precisely
because it is the kind of thing that gets "fixed" towards BlueZ's MEDIUM by
someone assuming the profile said so — it does not; MEDIUM is BlueZ's own
policy choice.

### The key-refresh prohibition — unchecked, and easy to violate

HOGP §7 line 2088:

> "The HID Host shall only initiate an encryption key refresh on receipt of a
> Peripheral Security Request, as defined in [2] Volume 3, Part H, Section
> 2.4.6, from the HID Device."

This is a host-side `shall not` in disguise. It was not audited in this pass —
it lives in the SMP and connection-management code rather than the HOGP path —
and it should be, because a stack that proactively re-keys on a timer or on
reconnect violates it silently. Recorded as an open question, not a finding.

### On-error recovery — the applicable text is in Core, not HOGP

HOGP says nothing about what to do on Insufficient Authentication or
Insufficient Encryption. Core Vol 3 Part C §10.3.2 does, and the verb
asymmetry matters: on 0x05 the encryption procedure **should** be started
(lines 66832-66840); on 0x0F it **shall** be (lines 66841-66852). Our single
combined branch (`blued_central.c:639-655`) treats 0x05, 0x0F and 0x0C
identically and goes straight to pairing rather than trying encryption with an
existing LTK first. There is also the MITM trap at lines 66826-66831 — a device
relying on error codes "shall not request pairing with MITM protection in
response to receiving an Insufficient Authentication error code while the link
is unencrypted". Both are ATT/SMP-layer concerns rather than HOGP ones and
overlap finding F3.2 from the first sweep; flagged here for continuity rather
than re-adjudicated.

---

## 7. Citation rot found while checking justifications

Per the standing instruction to treat comments as suspect, every spec citation
in the HOGP path was checked. Nine are wrong, and two of them marked real
defects (H4, H10).

| Site | Citation | Status |
| --- | --- | --- |
| `hogp_report.h:10` | "HOGP 1.1.1 §4.6 Report Reference descriptor Report Type values" | version does not exist; the values are HIDS §2.5.3.2 Table 2.7, not HOGP |
| `hogp_boot.h:15` | "HID Service 1.1 §2.4.1.1, Table 2.2" | **correct** |
| `hogp_boot.c:15-19` | "HOGP 1.1 §4.11 requires a Boot Host to write Boot Protocol Mode to every HID Service" | **correct as to the requirement**; the code does not satisfy it (H4) |
| `hogp_boot.c:29-34` | "A-F6: ... Write Boot mode to EVERY Protocol Mode characteristic" | true of the loop, false of the caller (H4); also defends against a multiplicity HIDS §2.4 line 642 forbids |
| `blued_central.c:1022` | "mandatory per HOGP 3.2" | §3.2 in the in-tree v1.1 is Battery Service; HID Information discovery is §4.6.1.4 |
| `blued_central.c:1055` | "(HOGP v1.1 §4.11)" for writing **Report** mode | §4.11 line 1189 says the opposite: no requirement on a Report Host |
| `blued_central.c:1124` | "Per HOGP v1.0 Section 2: the HID Host shall discover the Battery Service" | 1.0 numbering; in v1.1 it is §4.5.3, and it is the *included-service* form that is mandatory (H8) |
| `blued_central.c:1502`, `:1636-1638` | "HOGP v1.0 Section 3.1 requires the HID Host to support Boot Protocol" | 1.0 numbering, and materially wrong: Boot and Report Host are exclusive roles (§2.3), not a fallback |
| `blued_central.c:2027-2029` | "HOGP v1.0 Section 3.3.3: Output Reports use Write Without Response" | 1.0 numbering; overstates HIDS §2.5.1 lines 781-784, which gives two procedures (H17) |
| `blued_central.c:2116`, `ctl.c:614`, `ctl.c:658` | "HOGP_READ / HOGP_WRITE commands" | no such IPC command exists (H10) |

The existing test header `spec_hogp_oracles.h:5` and
`spec_hogp_report_map_oracles.h:13` also cite "HOGP 1.1.1 §4.6". The values in
both are right; only the attribution is wrong, and the correct source is HIDS
v1.1 §2.5.3.2 Table 2.7 (text lines 827-838). Those files were not modified —
the brief excludes existing test files — but the corrected attribution is
carried in the new `spec_extref_hogp_characteristics.h`.

---

## 8. Checked and clean

Recorded so the ground is not re-ploughed.

- **All fifteen UUID constants** in `blued_internal.h:153-168`, `att.h:121-122`
  and `hogp_boot.h:11-13` were re-derived from the Assigned Numbers tables
  independently of the code and match: 0x1812, 0x180A, 0x180F, 0x2A19, 0x2A22,
  0x2A32, 0x2A33, 0x2A4A, 0x2A4B, 0x2A4C, 0x2A4D, 0x2A4E, 0x2A50, 0x2902,
  0x2907, 0x2908, 0x2B2A. Pinned in `spec_extref_hogp_characteristics.h`.
- **Report Reference field order** — Report ID first, Report Type second
  (`blued_central.c:998-999`) — matches HIDS Table 2.6/2.7 and BlueZ
  `hog-lib.c:457-458`.
- **Report Type enumeration** 1/2/3 matches HIDS Table 2.7.
- **Protocol Mode write procedure** is Write Without Response
  (`att_write_cmd`), per HIDS §2.4.1 lines 652-654. Same as BlueZ.
- **HID Control Point write procedure** is Write Without Response, per HIDS
  §2.11.1 lines 1150-1151. Same as BlueZ.
- **Only one Report Map is read per HID Service** — the `break` at
  `blued_central.c:965` — per HIDS §2.6 line 856.
- **Report Map buffer** is 4096, over-provisioned against the 512-octet cap;
  truncation is warned rather than silent.
- **Input reports only are subscribed** (`blued_central.c:1993-1994`), per
  HOGP §4.8 lines 1111-1113.
- **Boot input reports are not subscribed in report mode**, so notifications on
  them cannot reach vhid — satisfying HOGP §4.12 line 1199 and §4.14 line 1214,
  the two "the Report Host shall ignore" rules. BlueZ satisfies these
  vacuously, having no boot support at all.
- **Exchange MTU precedes service discovery** (`blued_central.c:460-534`), per
  HOGP §4.4.3.1 lines 992-993.
- **PnP ID is read on connection establishment** (`hogp_read_dis_pnpid`,
  `blued_central.c:1084`) and cached in the bond, per HOGP §4.16 lines
  1224-1225.
- **Service Changed is identified by value handle**, not by indication length
  (`gatt_indication_is_service_changed`), per Core §7.1.
- **Database Hash read procedure and response validation** — see §5.
- **Indication confirmation is sent before further processing** — see §5.
- **Multi-notification bounds checking** — see §5.

### H19 — Battery Level is read once, never subscribed [OURS-DIFFER, LOW]

`hogp_read_battery()` (`blued_central.c:1127-1152`) performs a single read.
HOGP §4.15 lines 1217-1221 permits either a read or a notification
subscription and asks hosts to "minimize the frequency of reads", so a one-shot
read is conformant but the value is stale for the life of the connection.

BlueZ is worse here and it is worth recording so the reference is not copied:
`profiles/battery/bas.c` subscribes properly (`:212-221`) but its
`notification_cb` and `read_value_cb` are `DBG()`-only (`:180-189`) — the value
reaches nothing. And `hog_attach_bas` (`hog-lib.c:1713-1721`) is only reachable
on the live-discovery path, so the cached-database reconnect path creates no
`bt_bas` at all.

---

## 9. Files added by this pass

- `docs/bluetooth-interop-hogp.md` — this document.
- `tests/usr.sbin/bluetooth/blued/spec_extref_hogp_characteristics.h` — the
  HID characteristic and descriptor inventory: all fifteen UUIDs transcribed
  row-by-row from Assigned Numbers, the Protocol Mode and HID Control Point
  value enumerations (including the four values **new in HIDS v1.1**), the
  Report Reference and External Report Reference field layouts, the HID
  Information layout with all four flag bits, the 512-octet Report Map cap, the
  per-Report-Type property matrix from HIDS Tables 2.4/2.11/2.13 with the
  `M`/`O`/`E` distinction preserved, and the CCCD existence rules.
- `tests/usr.sbin/bluetooth/blued/spec_extref_hogp_host_rules.h` — forty-four
  normative HID-Host rules as `(role, requirement level, section, line,
  verbatim text)` tuples, plus Appendix A Table A.1 transcribed as the
  reconnection-behaviour oracle. The role dimension is the point: it is what
  makes "we wrote Report mode and then Boot mode" mechanically detectable.

Both compile standalone under `-std=c99 -Wall -Wextra -Werror`, include no
blued header, and contain no value derived from running our code. Like the four
headers added by the first sweep, they will be inert until something includes
them; wiring them up needs a change to the tests Makefile, which was out of
scope for this pass.

No file under `usr.sbin/bluetooth/` or `lib/` was modified, and no existing
test file or test Makefile was touched.

## 10. Suggested order of work

Not a plan, just the order the evidence supports:

1. **H3** (proactive bonding) — small, and it is the difference between an
   encrypted keyboard and a plaintext one against a permissive device. It also
   removes the most likely trigger for H6.
2. **H6** (failed Report Reference) — a few lines: propagate the error, reject
   Report Type 0x00 and 0x04-0xFF, and fail setup rather than presenting a mute
   keyboard.
3. **H2** (Service Changed CCCD) — one CCCD write; we already have the handle.
4. **H4 + H5 + H9** (boot protocol) — these are one change, not three. Decide
   the role once, per device or by configuration, act on it consistently, and
   pass the full per-service characteristic set to `hogp_enter_boot_protocol()`.
5. **H1** (multi-instance) — the largest, and the one that needs a design
   decision: one vhid per HID Service instance, as BlueZ does, versus a service
   index threaded through `struct hogp_report` and the bond cache. The former
   matches the ecosystem and the report-ID scoping rules; the latter is less
   disruptive to the bond record format.
6. **H11 then H13** in that order and only in that order — writing the CSF bit
   without the 0x12 recovery converts a dormant gap into a live one.
7. **H7 + H8** (External Report Reference and included services) — one feature
   in two halves; neither is useful without the other.
8. **H16** (silent truncation) — cheap, and it is what would have made H1's
   failure modes visible during bring-up.
