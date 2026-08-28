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

Status: feature-complete and spec-reviewed, not yet validated on hardware.

### What was built

Kernel:
- `ng_hci`: LE buffer management (LE_Read_Buffer_Size with shared/dedicated
  semantics), Enhanced Connection Complete (0x0a), LTK Request forwarding,
  latency field type fix (u8->u16), LE-aware buffer accounting in
  num_compl_pkts and send_data_packets, LE buffer reset on HCI_Reset,
  underflow guard on LE_USE, null-check on Encryption Change propagation.
- `ng_l2cap`: LE fixed channel support — CID 0x0004 (ATT) and 0x0006 (SMP)
  bypass L2CAP signaling, skip CONFIG state, demux by (CID, con_handle).
- `vhid.ko`: virtual HID transport module. Exposes /dev/vhid control device
  and /dev/vhidN instances. Implements hid_if KOBJ interface so hidbus
  attaches hkbd/hms/hmt automatically. sc_mtx for global instance array,
  per-instance mtx for lifecycle, make_dev_s for proper error paths,
  race-safe uiomove without mutex held. Free-slot reuse on create/destroy.

Userspace (`usr.sbin/bluetooth/btled`):
- ATT protocol client — all PDU types per Core Spec Vol 3 Part F.
  30-second transaction timeout. fd cleanup on malloc failure.
- GATT discovery — services, characteristics, descriptors. Handles 16-bit
  and 128-bit UUIDs. Defensive break on unrecognized entry lengths.
- SMP pairing — LE Legacy (Just Works + Passkey Entry) and LE Secure
  Connections (Just Works + Passkey Entry + Numeric Comparison).
  Crypto: c1, s1, AES-CMAC, f4, f5, f6, g2 per spec. ECDH P-256 via
  OpenSSL with return value checking. Bond dedup on re-pair.
- HOGP profile — HID Service discovery, Report Map reading (with Read Blob
  for long descriptors), Report Reference classification, Protocol Mode
  setting via Write Without Response, CCCD notification subscription via
  Write Request, report ID prepending for multi-report devices.
- BLE scanning (`btled -s`) via HCI raw socket.
- Bonded reconnect with RPA/IRK address resolution (ah function).
- Auto-reconnect (`-r`) with pre-allocated Capsicum-safe socket pool.
  vhid device preserved across reconnect cycles.
- Multi-device via fork-per-device (up to 16 simultaneous).
- Capsicum sandbox — minimal fd rights per descriptor, atexit cleanup,
  signal handling.
- HCI utilities — adapter address, connection handle lookup with retry,
  Encryption Change event wait.

### Spec compliance

Reviewed against Core Spec v6.3 with PDF cross-references (2026-06-15).
127 checks across 18 source files: 117 PASS, 10 FAIL.  All 10 failures
fixed in commit following this review.

- HCI (Vol 4 Part E): 18/18 PASS. LE_Read_Buffer_Size, LE Connection
  Complete, LE Enhanced Connection Complete, LE_Start_Encryption,
  Encryption Change — structs, field offsets, byte order, command/status
  flow all verified.
- L2CAP (Vol 3 Part A): 18/18 PASS. Fixed CIDs 0x0004/0x0005/0x0006,
  no signaling for fixed channels, direct-to-OPEN state.
- Advertising (Vol 3 Part C): 4/4 PASS. AD structure format, Flags,
  Local Name types, UUID16 list.
- ATT (Vol 3 Part F): 34/38 PASS, 4 fixed. Fixes: Read By Type and
  Read By Group Type value truncation to min(ATT_MTU-N, 253/251),
  128-bit Bluetooth Base UUID matching for both request types.
- SMP (Vol 3 Part H): 27/31 PASS, 4 fixed. Fixes: RPA ah() prand
  byte placement, SC crypto functions LE/BE byte order (f4/f5/f6/g2
  now internally convert LE wire values to BE for AES-CMAC), responder
  key distribution masked to initiator constraints, SC Passkey Entry
  responder path added (20-round confirm/nonce exchange).
- GATT (Vol 3 Part G): 26/28 PASS, 1 fixed, 1 deferred. Fix: CCCD
  reset to 0x0000 on new non-bonded connection. Deferred: CCCD
  persistence for bonded devices (needs bond DB schema extension).
- HOGP: HID Service 0x1812, Report Map 0x2A4B, Report 0x2A4D, Protocol
  Mode 0x2A4E, Report Reference 0x2908 [id,type], CCCD 0x2902 — all PASS.

Not yet reviewed (specs not available):
- HOGP v1.0 — HID over GATT Profile client-mode compliance
- HIDS v1.0 — HID Service attribute layout
- DIS v1.1 — Device Information Service characteristics

### How to test

Prerequisites:
- 5BSD with these changes built (kernel + world, or just the modules + btled)
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
   services, the SMP->retry flow should handle it. If not, check whether
   the ATT error code is 0x05 or 0x0F.

---

## Use case 2: BLE peripheral mode (iPhone app) — IMPLEMENTED

Status: feature-complete, not yet validated on hardware. Shares btled
with use case 1 via the `-p` flag — not a separate daemon.

### What was built

Kernel:
- `ng_l2cap`: Auto-creation of ATT/SMP fixed channels on incoming LE
  connections (ng_l2cap_llpi.c). Fix connection response for ATT/SMP
  CIDs in ng_l2cap_ulpi.c.
- `ng_btsocket_l2cap`: LE fixed-channel bind/listen/accept. CID-based
  socket binding (CID 0x0004 for ATT, 0x0006 for SMP), listen on
  CID-bound sockets (PSM=0 allowed when CID is set), CID-based listening
  socket lookup, accepted sockets go directly to OPEN (skip L2CAP CONFIG).

Userspace (`usr.sbin/bluetooth/btled`):
- ATT server (`att_server.c/h`) — attribute database with sequential handle
  assignment, builder helpers (attdb_add_service, attdb_add_characteristic,
  attdb_add_cccd), request dispatcher handling MTU exchange, Find Information,
  Read By Group Type, Read By Type, Read, Read Blob, Write Request, Write
  Command. Error Response and Handle Value Notification senders.
- SMP responder (`smp.c`) — smp_respond() entry point receives Pairing
  Request, sends Pairing Response, dispatches to legacy or SC path.
  Legacy responder: reversed confirm/random exchange, STK derivation,
  LTK Request reply (not LE_Start_Encryption), key distribution (responder
  sends first). SC responder (Just Works / Numeric Comparison): receive
  initiator PK first, compute Cb = f4(PKbx, PKax, Nb, 0), nonce exchange,
  DHKey check (receive Ea, send Eb), LTK Request reply with SC-derived LTK.
- HCI advertising (`hci_util.c`) — LE_Set_Advertising_Parameters,
  LE_Set_Advertising_Data, LE_Set_Advertise_Enable via bt_devreq().
  LE_Long_Term_Key_Request_Reply and Negative Reply for responder-side
  encryption. AD data builder (Flags + Local Name + 16-bit UUID list).
- Peripheral main flow (`btled.c`) — `-p` flag, peripheral_run(): builds
  GATT database (GAP Service with Device Name + Appearance, GATT Service,
  Device Information Service with Manufacturer/Model/Firmware Rev, custom
  service 0xFFE0 with read/write/notify characteristic + CCCD), advertises
  as "5BSD-btled", binds+listens on ATT CID 4, accepts connections, serves
  ATT requests via poll loop, re-enables advertising on disconnect.

### GATT database hosted

| Service | UUID | Characteristics |
|---------|------|----------------|
| GAP (required) | 0x1800 | Device Name (0x2A00), Appearance (0x2A01) |
| GATT (required) | 0x1801 | (empty) |
| Device Information | 0x180A | Manufacturer (0x2A29), Model (0x2A24), Firmware Rev (0x2A26) |
| Custom | 0xFFE0 | Custom char (0xFFE1) — read/write/notify + CCCD |

### How to test

Step 1 — Load modules:
```
kldload ng_ubt
kldload iwmbtfw       # if Intel adapter
```

Step 2 — Start peripheral:
```
mkdir -p /var/db/btled
btled -p -d -a ubt0
```
Debug output shows: advertising parameters set, advertising enabled,
waiting for connections.

Step 3 — Connect from iPhone:
Open nRF Connect (or similar BLE scanner app). "5BSD-btled" should appear.
Tap Connect.

Step 4 — Discover services:
nRF Connect auto-discovers services. Should show GAP (0x1800), GATT
(0x1801), DIS (0x180A), and custom (0xFFE0).

Step 5 — Read characteristics:
Read Device Name -> "5BSD-btled". Read Manufacturer -> "FreeBSD".

Step 6 — Write + notify:
Write a value to custom characteristic (0xFFE1). Enable notifications
via CCCD. Verify round-trip works.

Step 7 — Pairing:
Trigger pairing from iOS Settings or nRF Connect. Just Works or Numeric
Comparison should complete. Bond stored in /var/db/btled/bonds.

Step 8 — Reconnect:
Disconnect and reconnect. Encryption should be restored via LTK without
re-pairing.

### What will probably fail first

1. Advertising — if HCI advertising commands fail, the adapter may not
   support LE peripheral role. Check `hccontrol le_read_supported_states`.
2. Accept — if no connection arrives after advertising, the kernel L2CAP
   listen/accept path for LE fixed channels may have issues. Check
   `dmesg` for ng_l2cap errors.
3. ATT discovery — if the iPhone connects but can't discover services,
   the ATT server dispatch may have a PDU format error. Debug output
   shows each request/response.
4. SMP — if pairing fails, check whether the iPhone wants a method we
   don't support (e.g., OOB). The responder supports Just Works, Numeric
   Comparison, and Legacy Passkey Entry.

---

## Use case 3: Beats headphones on FreeBSD — NOT STARTED

Status: no code exists. Classic Bluetooth (BR/EDR) audio is an entirely
separate protocol stack from BLE. Shares only the HCI layer and L2CAP
transport with the BLE work.

### Architecture

A new daemon (`bt_audio` or similar in `usr.sbin/bluetooth/`) handling
the classic audio profile stack over L2CAP PSM-based connections:

```
bt_audio
  |-- sdp.c      SDP client (query remote for A2DP/AVRCP support)
  |-- avdtp.c    AVDTP signaling + media transport (Core Spec dependent)
  |-- a2dp.c     A2DP sink: codec negotiation, stream management
  |-- sbc.c      SBC decoder (mandatory for A2DP compliance)
  |-- avrcp.c    AVRCP controller: play/pause/skip/volume
  |-- audio.c    PCM output to snd(4) via /dev/dsp or virtual_oss
```

### What needs to be built

- **SDP client** — query remote device for A2DP Source (UUID 0x110A) and
  AVRCP Target (UUID 0x110C) records. L2CAP PSM 0x0001. The `sdpd` daemon
  exists in-tree but is server-side; need a client library. ~300 LOC.
- **AVDTP** (Vol 3 dependent on AVDTP v1.3 spec) — signaling channel on
  L2CAP PSM 0x0019: Discover, Get Capabilities, Set Configuration, Open,
  Start, Suspend, Close, Abort. Media transport channel for streaming.
  ~1500-2000 LOC.
- **A2DP sink** — codec capability exchange (SBC mandatory, AAC optional),
  stream state machine, RTP header parsing, frame reassembly. ~800 LOC.
- **SBC decoder** — mandatory codec. Subbands analysis, bit allocation,
  synthesis filter bank. Pure signal processing, no external deps.
  ~1500-2000 LOC. Alternatively, import libsbc (~same size but tested).
- **AAC decoder** — optional but needed for Beats (they prefer AAC).
  Requires libfdk-aac or similar. Port dependency, not in base.
- **AVRCP** — media control on L2CAP PSM 0x0017 (AVCTP). Passthrough
  commands for play/pause/skip, register notification for track change
  and playback status. ~600-800 LOC.
- **Audio output** — pipe decoded PCM to snd(4). Either direct /dev/dsp
  writes or virtual_oss for mixing. ~200 LOC.

### Current blockers

- No AVDTP or A2DP implementation exists anywhere in FreeBSD.
- No SBC codec in base. Must be written or imported.
- SCO/eSCO over USB isochronous transfers in ng_ubt are unreliable.
  Blocks HFP/HSP voice calls but does NOT block A2DP music playback
  (A2DP uses ACL/L2CAP, not SCO).
- SSP (Secure Simple Pairing) for BR/EDR may need kernel-side work in
  ng_hci if the existing `hcsecd` flow doesn't handle modern devices.

### What can be reused from BLE work

- HCI raw socket patterns from hci_util.c
- Bond file format (different keys — link keys vs LTK — but same storage)
- Capsicum sandbox patterns
- Nothing else. BR/EDR uses SDP (not GATT), L2CAP PSMs (not fixed CIDs),
  SSP (not SMP), and streaming codecs (not HID descriptors).

### Rough size estimate

~5000-7000 LOC for the daemon without AAC. SBC alone is ~1500-2000.
With AAC (external lib), add port integration but not much new code.

---

## Use case 4: LE Audio — NOT STARTED (future)

Status: blocked on kernel infrastructure. LE Audio (LC3 codec, ISO
channels, BAP/CAP/VCP profiles) requires isochronous data paths that
do not exist in the FreeBSD Bluetooth stack.

### What would be needed

- **Kernel**: HCI ISO data path (new packet type 0x05), isochronous
  USB transfers in ng_ubt, Connected Isochronous Streams (CIS) and
  Broadcast Isochronous Streams (BIS) in ng_hci, ISO L2CAP channels.
- **Userspace**: LC3 codec (open-source liblc3 exists), BAP (Basic Audio
  Profile) for unicast/broadcast stream setup, VCP (Volume Control
  Profile), CAP (Common Audio Profile) for coordination.
- This is the path to modern headphone support (AirPods Pro, Galaxy Buds,
  etc.) but the kernel work is substantial.

### Not a dependency for use cases 1-3.

---

## 5BSD integration

The Bluetooth daemons should leverage 5BSD-specific kernel features
beyond stock FreeBSD Capsicum:

**capprotect shields:**
Apply CP_SF_PTRACE | CP_SF_SIGNAL | CP_SF_VISIBLE | CP_SF_KTRACE to
btled after sandbox entry. A BLE daemon handling encryption keys and
pairing secrets should be invisible to ps(1), immune to ptrace(2) and
kill(2) from unprivileged processes, and hidden from ktrace(1). This
prevents a compromised user process from attaching to the daemon to
extract LTKs or IRKs from memory.

**Coalition for multi-device:**
btled's fork-per-device model creates up to 16 child processes. Enlist
all children in a coalition so the parent can revoke everything by
closing one fd. On supervisor crash, the coalition's leader-death trigger
tears down all device connections cleanly instead of leaving orphaned
processes holding HCI sockets.

**cap_cloexec_limit / cap_clofork_limit:**
Apply cap_cloexec_limit to HCI raw sockets and bond file descriptors
after setup. If btled ever exec'd a helper (e.g., a passkey prompt UI),
these fds would not leak. cap_clofork_limit on the SMP socket prevents
forked children from inheriting a parent's active pairing session.

**authorityd/serviced integration:**
btled can be managed as a serviced bundle — authorityd provides supervised
restart, capability-mediated HCI device access via MAC_CAPABILITY claims, and
automatic cleanup on crash. The bond database fd can be a MAC_CAPABILITY-claimed
vnode so access is revocable.

These are hardening steps to apply after hardware validation, not
blockers for initial functionality.

---

## Future: Bluetooth service architecture (btd)

The end-state is a Bluetooth service daemon (`btd`) that owns the radio
and hands out capability-mediated handles to client applications.  This
replaces the current btled model (one monolithic daemon per device) with
a multi-client service integrated with serviced and authorityd.

### Design principles

1. **One daemon owns the radio.**  `btd` is the only process that talks
   to the HCI adapter.  Clients never touch the raw HCI socket.
2. **Opaque handles via cap_xfer.**  When a client wants to talk to a
   BLE device, `btd` establishes the connection, pairs if needed, and
   hands the client an opaque fd (the L2CAP ATT socket) via cap_xfer
   over a Unix socket.  The client can then read/write GATT directly
   without going through btd for data-plane operations.
3. **Alternatively: message-based proxy.**  For tighter control, btd
   keeps the ATT socket and performs GATT operations on the client's
   behalf.  Client sends `{read, handle=0x0003}` over Unix socket,
   btd reads the characteristic and returns the value.  This allows
   btd to enforce per-client access control on characteristics.
4. **Both models can coexist.**  Handle pass for trusted clients (e.g.,
   a HOGP driver running in its own sandbox), message proxy for
   untrusted apps.

### Architecture

```
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │ App: HID │  │ App: HR  │  │ App: IoT │   client processes
  │  (HOGP)  │  │ monitor  │  │  lights  │   (sandboxed)
  └────┬─────┘  └────┬─────┘  └────┬─────┘
       │cap_xfer     │msg         │msg
       │(ATT fd)     │proxy       │proxy
       v             v            v
  ┌──────────────────────────────────────┐
  │              btd                     │   bluetooth service
  │                                      │   (serviced bundle)
  │  scan/connect/pair/bond management   │
  │  GATT cache, service discovery       │
  │  SMP key storage, IRK resolution     │
  │  HCI command serialization           │
  │                                      │
  │  ┌─────────┐  ┌──────┐  ┌────────┐  │
  │  │ att.c   │  │smp.c │  │gatt.c  │  │   existing code
  │  │ (client │  │      │  │        │  │   (already written)
  │  │ +server)│  │      │  │        │  │
  │  └─────────┘  └──────┘  └────────┘  │
  └──────────────────┬───────────────────┘
                     │ raw HCI socket
                     │ (MAC_CAPABILITY claimed via authorityd)
                     v
  ┌──────────────────────────────────────┐
  │           kernel (ng_hci +           │   netgraph stack
  │           ng_l2cap + ng_btsocket)    │   (already working)
  └──────────────────┬───────────────────┘
                     │ USB
                     v
  ┌──────────────────────────────────────┐
  │         BLE radio (ng_ubt)           │   hardware
  └──────────────────────────────────────┘
```

### Client API (Unix socket protocol)

Clients connect to `/var/run/btd.sock`.  Protocol is length-prefixed
binary messages (not JSON — this is a system service, not a web API).

```
Commands from client → btd:
  SCAN_START          — start LE scanning, results streamed back
  SCAN_STOP           — stop scanning
  CONNECT {addr, type} — connect to device, pair if needed
  DISCONNECT {conn_id} — disconnect
  GATT_DISCOVER {conn_id} — discover services/chars/descs
  GATT_READ {conn_id, handle}
  GATT_WRITE {conn_id, handle, data}
  GATT_SUBSCRIBE {conn_id, handle} — enable notifications
  GATT_UNSUBSCRIBE {conn_id, handle}
  PASS_HANDLE {conn_id} — request raw ATT fd via cap_xfer

Events from btd → client:
  SCAN_RESULT {addr, type, rssi, name, ad_data}
  CONNECTED {conn_id, addr}
  DISCONNECTED {conn_id, reason}
  NOTIFICATION {conn_id, handle, data}
  PASSKEY_REQUEST {conn_id, display_value}
  PASSKEY_CONFIRM {conn_id, value}
  HANDLE_PASSED {conn_id, fd} — fd arrives via SCM_RIGHTS
```

### Handle passing via cap_xfer

For the HOGP use case, btd would:
1. Connect to the keyboard, pair, encrypt
2. Discover HID Service, subscribe to reports
3. cap_xfer the ATT socket fd to the HOGP client process
4. The HOGP client (a stripped-down btled) receives notifications
   directly without btd in the data path
5. btd retains the SMP state and bond database
6. On disconnect, btd gets notified (it monitors a dup'd fd or
   the client sends DISCONNECT)

The transferred fd has cap_rights limited to CAP_RECV + CAP_EVENT —
the client can only receive ATT notifications, not send arbitrary
ATT commands.  For read/write access, btd grants additional rights
or acts as proxy.

### cap_clofork_limit / cap_cloexec_limit usage

```
btd sets on each client's transferred fd:
  cap_clofork_limit(client_att_fd)   — fd dies if client forks
  cap_cloexec_limit(client_att_fd)   — fd dies if client exec's

btd sets on its own sensitive fds:
  cap_clofork_limit(hci_fd)          — HCI socket doesn't leak to children
  cap_clofork_limit(bond_fd)         — bond database doesn't leak
  cap_cloexec_limit(hci_fd)          — HCI socket doesn't leak to exec'd helpers
```

This ensures a compromised client can't pass the Bluetooth connection
to another process via fork/exec.

### capprotect integration

```
btd after initialization:
  cap_protect(CP_SF_PTRACE | CP_SF_SIGNAL | CP_SF_VISIBLE | CP_SF_KTRACE)
```

btd holds all LTKs, IRKs, and the HCI raw socket.  capprotect makes it
invisible to ps(1), immune to ptrace(2) and kill(2) from unprivileged
processes, and hidden from ktrace(1).

### serviced bundle

```yaml
# /usr/local/etc/serviced/bundles/btd.bundle
name: btd
binary: /usr/sbin/btd
claims:
  - type: device
    path: /dev/ubt0
    rights: [read, write, ioctl]
  - type: vnode
    path: /var/db/btd/bonds
    rights: [read, write, create]
  - type: socket
    path: /var/run/btd.sock
    rights: [listen, accept]
restart: always
shields: [ptrace, signal, visible, ktrace]
coalition: btd-workers
```

authorityd grants btd access to `/dev/ubt0` via a MAC_CAPABILITY claim.  If btd
crashes, serviced restarts it.  The coalition tears down any worker
children.  The bond database fd is a MAC_CAPABILITY-claimed vnode — access
is revocable if btd is compromised.

### Inspiration: Darwin/macOS Bluetooth architecture

macOS uses: App → CoreBluetooth.framework → XPC → bluetoothd → HCI.
5BSD equivalent: App → libble.so → Unix socket → btd → HCI.

Key mapping:

  macOS bluetoothd          →  btd (serviced bundle)
  CoreBluetooth.framework   →  libble.so
  XPC connection            →  serviced name lookup + Unix socket
  CBCentralManager          →  ble_central_t handle from libble
  CBPeripheralManager       →  ble_peripheral_t handle from libble
  IOBluetoothHostController →  ng_hci + ng_l2cap (kernel, working)
  IOHIDSystem               →  vhid + hidbus (kernel, working)
  Code-signing entitlements  →  capability-mediated fd rights

Critical difference: macOS checks caller identity ("are you signed
with com.apple.bluetooth.central?").  5BSD checks the handle itself
("this fd has CAP_RECV only").  A leaked fd can't do more than its
rights allow, regardless of who holds it.  This is architecturally
stronger — security is in the capability, not the identity.

### libble.so public API (planned)

```c
/* Connect to btd service */
ble_ctx_t    *ble_open(const char *service_name);
void          ble_close(ble_ctx_t *ctx);

/* Central (client) role */
int           ble_scan_start(ble_ctx_t *ctx, ble_scan_cb cb, void *arg);
int           ble_scan_stop(ble_ctx_t *ctx);
ble_conn_t   *ble_connect(ble_ctx_t *ctx, const ble_addr_t *addr);
void          ble_disconnect(ble_conn_t *conn);

/* GATT operations */
int           ble_discover_services(ble_conn_t *conn, ble_service_t *out, int max);
int           ble_read(ble_conn_t *conn, uint16_t handle, void *buf, size_t *len);
int           ble_write(ble_conn_t *conn, uint16_t handle, const void *buf, size_t len);
int           ble_subscribe(ble_conn_t *conn, uint16_t handle, ble_notify_cb cb, void *arg);

/* Peripheral (server) role */
ble_db_t     *ble_db_create(void);
int           ble_db_add_service(ble_db_t *db, uint16_t uuid);
int           ble_db_add_characteristic(ble_db_t *db, uint16_t uuid, uint8_t props, ...);
int           ble_advertise(ble_ctx_t *ctx, ble_db_t *db, const char *name);

/* Raw handle pass (advanced, requires cap_xfer) */
int           ble_get_att_fd(ble_conn_t *conn);
```

Under the hood, every call serializes a message to btd over the Unix
socket.  ble_open() finds btd by serviced name (e.g., "com.5bsd.bluetooth"),
not a hardcoded socket path.  ble_get_att_fd() receives a cap_xfer'd fd
with rights limited to the requested operations.

### btctl command-line tool (planned)

Exposes btd functionality from the shell, built on libble:

  btctl scan                         — list nearby BLE devices
  btctl connect aa:bb:cc:dd:ee:ff    — connect and pair
  btctl gatt-read <handle>           — read a characteristic
  btctl gatt-write <handle> <hex>    — write a characteristic
  btctl subscribe <handle>           — stream notifications to stdout
  btctl advertise --name "My Device" — start peripheral mode
  btctl bonds                        — list bonded devices
  btctl forget aa:bb:cc:dd:ee:ff     — remove a bond

### btled becomes a btd client

After btd exists, btled shrinks to a thin HOGP profile handler:

  ctx = ble_open("com.5bsd.bluetooth");
  conn = ble_connect(ctx, &kbd_addr);
  fd = ble_get_att_fd(conn);    /* cap_xfer'd, low-latency path */
  /* receive ATT notifications directly, inject into vhid */

btd handles scanning, connection, pairing, bond management.
btled only handles HID-specific logic (Report Map parsing, report
ID prepending, vhid interaction).

### Dependencies on serviced

This architecture requires serviced to support:

1. **Service name registration** — btd registers as "com.5bsd.bluetooth",
   clients look it up by name to get the Unix socket path.
2. **MAC_CAPABILITY claims for devices** — btd claims /dev/ubt0 via authorityd.
   If the adapter is unplugged/replugged, authorityd re-grants access.
3. **Supervised restart** — if btd crashes, serviced restarts it.
   Clients detect disconnection (Unix socket EOF) and reconnect.
4. **Coalition support** — btd's worker processes (if any) are in a
   coalition.  Leader death tears down all workers.
5. **cap_xfer over the service socket** — serviced's socket must support
   SCM_RIGHTS for fd passing between btd and clients.

Until serviced supports these features, btled remains the standalone
tool for BLE.  The kernel stack and protocol code are ready — the
blocker is the service framework, not the Bluetooth implementation.

### Migration path

Phase 1 (current): btled works standalone.  Validate on hardware.
Phase 2: Verify serviced supports name lookup, MAC_CAPABILITY, cap_xfer.
Phase 3: Extract libble.so from btled's att/gatt/smp/hci code.
Phase 4: Build btd as a serviced bundle using libble.
Phase 5: Build btctl on libble.
Phase 6: Rewrite btled as a thin btd client.
Phase 7: Third-party apps use libble for any BLE use case.

The kernel netgraph stack and vhid driver are unchanged throughout —
they are already the correct architecture.  The work is entirely in
userspace service design.

---

## Roadmap

1. **BLE HID (HOGP)** — implemented, spec-reviewed (64 bugs fixed across
   8 review rounds), logging and DTrace probes added. Needs hardware
   validation.
2. **BLE peripheral mode** — implemented and spec-reviewed. Kernel LE
   listen/accept, ATT server, SMP responder, HCI advertising.
3. **Hardware validation** — test with real BLE keyboards/mice on
   USB Bluetooth dongles. Verify pairing, reconnect, multi-device.
4. **5BSD hardening** — capprotect shields, cap_clofork_limit,
   cap_cloexec_limit on btled. Low effort, high security value.
5. **libble extraction** — factor att.c/gatt.c/smp.c/hci_util.c out of
   btled into a shared library. Prerequisite for btd.
6. **btd service daemon** — Bluetooth service with Unix socket API,
   cap_xfer handle passing, serviced bundle, coalition management.
   See architecture section above.
7. **Classic audio (A2DP)** — independent of BLE work. New daemon using
   libble for HCI, ~5000-7000 LOC. Blocked on SBC codec.
8. **LE Audio** — future. Requires kernel isochronous data path.
5. **LE Audio** — future. Blocked on kernel isochronous data path.
