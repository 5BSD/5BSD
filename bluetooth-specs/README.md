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

---

## Use case 1: BLE keyboards and mice (HOGP) — IMPLEMENTED

Status: feature-complete, not yet validated on hardware.

### What was built

Kernel:
- `ng_hci`: LE buffer management (LE_Read_Buffer_Size), Enhanced Connection
  Complete (0x0a), LTK Request forwarding, latency field type fix (u8→u16),
  LE-aware buffer accounting in num_compl_pkts and send_data_packets.
- `vhid.ko`: virtual HID transport module. Exposes /dev/vhid control device
  and /dev/vhidN instances. Implements hid_if KOBJ interface so hidbus
  attaches hkbd/hms/hmt automatically. Race-safe write/attach lifecycle.
  Free-slot reuse on create/destroy.

Userspace (`usr.sbin/bluetooth/btled`):
- ATT protocol client — all PDU types per Core Spec Vol 3 Part F.
- GATT discovery — services, characteristics, descriptors. Handles 16-bit
  and 128-bit UUIDs. Underflow-safe on malformed responses.
- SMP pairing — LE Legacy (Just Works + Passkey Entry) and LE Secure
  Connections (Just Works + Passkey Entry + Numeric Comparison).
  Crypto: c1, s1, AES-CMAC, f4, f5, f6, g2 per spec. ECDH P-256 via OpenSSL.
- HOGP profile — HID Service discovery, Report Map reading (with Read Blob
  for long descriptors), Report Reference classification, Protocol Mode
  setting, CCCD notification subscription, report ID prepending.
- BLE scanning (`btled -s`) via HCI raw socket.
- Bonded reconnect with RPA/IRK address resolution (ah function).
- Auto-reconnect (`-r`) with pre-allocated Capsicum-safe socket pool.
- Multi-device via fork-per-device (up to 16 simultaneous).
- Capsicum sandbox — minimal fd rights, atexit cleanup, signal handling.
- HCI utilities — adapter address, connection handle lookup with retry,
  Encryption Change event wait (replaces usleep hacks).

### Spec compliance

Reviewed against Core Spec v6.3 with PDF cross-references:
- HCI: LE_Read_Buffer_Size, LE Connection Complete, LE Enhanced Connection
  Complete, LE_Start_Encryption — all PASS.
- ATT: all opcodes, PDU formats, error codes, MTU negotiation — all PASS.
- SMP: c1, s1, f4, f5, f6, g2, pairing flow, method selection table,
  IO capabilities, public key byte order, DHKey check — all PASS.
- GATT: UUIDs, response layouts, termination, guards — all PASS.
- HOGP: service/char UUIDs, Report Reference, Protocol Mode — all PASS.

### How to test

Prerequisites:
- FreeBSD with these changes built (kernel + world, or just the modules + btled)
- USB Bluetooth 4.0+ dongle or built-in BT (Intel AX201 in BOSGAME works)
- A BLE HID device (keyboard, mouse, gamepad) in pairing mode

Step 1 — Load modules:
```
kldload ng_ubt        # USB Bluetooth transport
kldload iwmbtfw       # Intel firmware (if Intel adapter)
kldload vhid          # Virtual HID transport
```

Step 2 — Verify adapter:
```
hccontrol -n ubt0hci read_bd_addr
```
If this fails, the adapter is not recognized. Check `dmesg | grep ubt`.

Step 3 — Scan for BLE devices:
```
btled -d -s
```
Should list nearby BLE devices with address, type, RSSI, and name.
If this fails, the HCI raw socket or LE scanning path is broken.

Step 4 — Connect to a device:
```
mkdir -p /var/db/btled
btled -d aa:bb:cc:dd:ee:ff random
```
Replace with the address from the scan. Use `random` for most modern devices.
Debug output shows each phase: ATT connect, MTU exchange, bond check,
GATT discovery, vhid setup, CCCD subscription, Capsicum entry, event loop.

Step 5 — Verify HID attachment:
```
dmesg | grep -i hid    # should show hidbus/hkbd/hms on vhid0
```

Step 6 — Test input:
Type on the BLE keyboard or move the BLE mouse. Input should appear normally.

Step 7 — Test reconnect:
```
btled -dr aa:bb:cc:dd:ee:ff random
```
Turn the device off and on. btled should detect disconnect, wait 3s,
reconnect using a pool socket, and resume without re-pairing.

Step 8 — Multiple devices:
```
btled -dr aa:bb:cc:dd:ee:ff random 11:22:33:44:55:66 public
```
Each device gets its own forked process and vhid instance.

### What will probably fail first

1. `btled -s` — if the HCI raw socket bind or LE scan commands don't work,
   nothing else will. This is the first thing to debug.
2. ATT connect — if L2CAP LE CID 0x0004 connection fails, the kernel
   LE path has a problem. Check `dmesg` for ng_hci/ng_l2cap errors.
3. SMP pairing — if the device rejects pairing, check which method it
   wants (debug output shows the negotiation). Some devices may need
   features we haven't implemented (e.g., OOB pairing).
4. GATT discovery — if the device requires encryption before exposing
   services, the SMP→retry flow should handle it. If not, check whether
   the ATT error code is 0x05 or 0x0F.

---

## Use case 2: iPhone BLE app talking to FreeBSD — NOT STARTED

Status: no code exists. Requires a separate daemon.

### What needs to be built

- ATT server — host an attribute database, handle incoming read/write/notify
- GATT server — register services and characteristics, manage CCCDs
- BLE advertising — send connectable undirected advertisements via HCI
  LE_Set_Advertising_Parameters + LE_Set_Advertising_Data + LE_Set_Advertise_Enable
- SMP responder role — respond to pairing requests (currently only initiator)
- Custom service/characteristic registration API

### What can be reused from use case 1

- SMP crypto (c1, s1, f4, f5, f6 — same functions, different flow direction)
- HCI utilities (adapter address, connection handle)
- Bond storage and RPA resolution
- Capsicum sandbox patterns

### Rough size estimate

~3000-4000 lines for a new daemon (`btle_peripheral` or similar).

---

## Use case 3: Beats headphones on FreeBSD — NOT STARTED

Status: no code exists. Completely separate protocol stack from BLE.

### What needs to be built

- SDP service discovery — query remote device for audio profile support
- AVDTP stream negotiation — codec capabilities exchange, stream configuration
- A2DP sink profile — receive audio stream, decode, play
- SBC codec (mandatory for A2DP) — decode SBC frames to PCM
- AAC codec (for Beats) — decode AAC frames to PCM
- Audio plumbing — pipe decoded PCM to snd(4) via /dev/dsp or virtual OSS device
- AVRCP media control — play/pause/skip/volume
- HFP/HSP (optional) — voice calls, requires SCO/isochronous USB

### What can be reused from use case 1

- Almost nothing. Classic Bluetooth uses BR/EDR (not BLE), SSP (not SMP),
  SDP (not GATT), L2CAP PSMs (not fixed CIDs). The only shared code is
  the HCI raw socket and the bond storage format.

### Current blockers

- No A2DP, AVDTP, or SBC implementation exists anywhere in FreeBSD.
- SCO/isochronous USB transfers in ng_ubt are unreliable (blocks HFP/HSP).
- SBC is ~2000 lines of signal processing. AAC requires a library (libfdk-aac or similar).

### Rough size estimate

~8000-12000 lines across multiple daemons/libraries. Significantly larger than use case 1.

---

## Use case 4: LE Audio (future) — NOT STARTED

- LC3 codec, ISO channels, BAP/CAP profiles
- Modern headphone support (AirPods Pro, etc.)
- Depends on isochronous USB transport in ng_ubt being fixed
- Not a dependency for use cases 1-3

---

## Roadmap

1. **BLE HID (HOGP)** — implemented, needs hardware validation
2. **iPhone BLE peripheral** — next after BLE HID is validated. Shares SMP/crypto.
3. **Classic audio (A2DP)** — independent of BLE work. Largest effort.
4. **LE Audio** — future, after isochronous USB is fixed.
