# Bluetooth Specification References

Local copies pulled from official Bluetooth SIG sources for the Bluetooth roadmap.

## Downloaded files

- `Core_Specification_6_3.pdf`
  - Official source: `https://files.bluetooth.com/download/core_v6-3/`
  - Spec page: https://www.bluetooth.com/specifications/specs/core-specification-6-3/
  - Use: controller/host architecture, LE procedures, GAP/ATT/SMP baseline.

- `GATT_Specification_Supplement.pdf`
  - Official source: `https://btprodspecificationrefs.blob.core.windows.net/gatt-specification-supplement/GATT_Specification_Supplement.pdf`
  - Spec page: https://www.bluetooth.com/specifications/gss/
  - Use: GATT characteristics, descriptors, and service data model.

- `A2DP_v1-3-2.pdf`
  - Official source: `https://www.bluetooth.org/docman/handlers/downloaddoc.ashx?doc_id=457083`
  - Spec page: https://www.bluetooth.com/specifications/specs/advanced-audio-distribution-profile-1-3-2/
  - Use: classic Bluetooth audio sink/source transport.

- `AVDTP_v1-3.pdf`
  - Official source: `https://www.bluetooth.org/DocMan/handlers/DownloadDoc.ashx?doc_id=260860`
  - Spec page: https://www.bluetooth.com/specifications/specs/a-v-distribution-transport-protocol-1-3/
  - Use: classic A/V stream negotiation and transport.

- `AVRCP_v1-6-3.pdf`
  - Official source: `https://files.bluetooth.com/download/avrcp_v1-6-3/`
  - Spec page: https://www.bluetooth.com/specifications/specs/a-v-remote-control-profile1-6-3/
  - Use: classic media remote control.

- `CAP_v1-0-1.pdf`
  - Official source: `https://files.bluetooth.com/download/cap_v1-0-1/`
  - Spec page: https://www.bluetooth.com/specifications/specs/common-audio-profile-1-0-1/
  - Use: LE Audio control plane for unicast and broadcast audio.

## Notable online references

- Assigned Numbers: https://www.bluetooth.com/specifications/assigned-numbers/
- Bluetooth specifications index: https://www.bluetooth.com/specifications/specs/

## Why these were chosen

- `Core Specification` and `GATT Specification Supplement` are the minimum set for general-purpose BLE apps and modern BLE peripherals.
- `A2DP`, `AVDTP`, and `AVRCP` cover the classic audio path.
- `CAP` is the current LE Audio control profile that matters for modern headset and broadcast audio work.

## Current target

Three use cases are being tracked for the FreeBSD Bluetooth roadmap:

- `Beats headphones on FreeBSD`
  - Primary need: classic Bluetooth audio.
  - Required specs: `A2DP`, `AVDTP`, `AVRCP`.
  - If headset microphone or call audio matters: add `HFP` and/or `HSP`.
  - Current blocker in-tree: no A2DP profile implementation, no SBC/AAC codec, no audio sink plumbing to `snd(4)`. A2DP streams over L2CAP (ACL/bulk USB), not SCO.
  - Secondary blocker for HFP/HSP voice calls: SCO uses isochronous USB transfers which `ng_ubt` does not handle reliably.

- `iPhone BLE app talking to FreeBSD`
  - Primary need: BLE peripheral behavior.
  - Required specs: `Core Specification`, `GATT Specification Supplement`, `ATT`, `SMP`, advertising, bonding, privacy, notifications, reconnect behavior.
  - FreeBSD should present a GATT server and stable bond/reconnect behavior for the iPhone app.

- `BLE keyboards and mice on FreeBSD (HOGP)`
  - Primary need: BLE HID input devices.
  - Required specs: `Core Specification` (ATT, GATT, SMP volumes), `HOGP v1.0` (HID over GATT Profile), `HIDS v1.0` (HID Service), `DIS v1.1` (Device Information Service).
  - Spec pages:
    - https://www.bluetooth.com/specifications/specs/hid-over-gatt-profile-1-0/
    - https://www.bluetooth.com/specifications/specs/hid-service-1-0/
  - HID is self-describing via Report Descriptors — once HOGP transport works, all BLE HID devices (keyboards, mice, gamepads) work without per-device drivers.
  - FreeBSD already has a transport-agnostic `hidbus(4)` framework; HOGP needs a new transport backend implementing the `hid_if` KOBJ interface.
  - Shares the ATT/GATT/SMP dependency with the iPhone use case — building HOGP first gives the BLE stack for free.
  - Current blocker in-tree: no ATT, GATT, or SMP implementation exists. L2CAP routes ATT/SMP CIDs to sockets but nothing parses the protocols.

## Roadmap implication

- All three targets share the HCI and L2CAP layers already in-tree.
- Classic headphone support uses SSP (Secure Simple Pairing) for authentication; BLE targets use SMP (Security Manager Protocol). Bond/key storage can be unified but the pairing protocols are distinct.
- They diverge after pairing:
  - Audio work follows the classic profile stack (A2DP over L2CAP, not SCO).
  - iPhone app support follows the BLE/GATT peripheral stack.
  - HOGP follows the BLE/GATT client stack (same ATT/GATT/SMP as iPhone, different role).
- **Recommended build order:** HOGP first (builds ATT/GATT/SMP as a side effect, quickest user-visible result), then iPhone BLE peripheral, then classic audio.
- LE Audio is a later phase, not the first dependency for the three targets above.
