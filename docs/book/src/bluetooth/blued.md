# blued

`blued(8)` (source
`/usr/src/usr.sbin/bluetooth/blued/`) is 5BSD's general-purpose Bluetooth Low
Energy host daemon. It implements the BLE protocol stack in userland on top
of netgraph L2CAP sockets: ATT, GATT, SMP (Legacy and Secure Connections
pairing), EATT over enhanced credit-based flow control, privacy (RPA
generation and resolving list), extended and periodic advertising, ISO
streams (CIG/BIG), and the HID over GATT Profile.

## Roles

- **Central (default):** connects to BLE HID devices via HOGP and injects
  reports through the vhid virtual HID transport, so the kernel's native
  drivers (`hkbd(4)`, `hms(4)`, `hmt(4)`) attach as if to local hardware.
  General GATT client operations (discover, read, write, subscribe) are
  available for any peripheral.
- **Peripheral (`-p`):** advertises and serves a GATT database. Services can
  be authored statically in the config file or at runtime over the control
  API (`add-service` / `add-char` / `gatt-begin` / `gatt-commit`), and
  runtime-added services persist across restart.
- **Observer (`-s`):** scanning/monitor mode.

Multiple adapters are supported (`adapters = ["auto"]` discovers all `ubt*`
devices); multiple simultaneous device connections are supported.

## Client API surface

Three layers, all in-tree:

1. A control protocol on `/var/run/blued.sock`.
2. `libble(3)` (`/usr/src/lib/libble/`), the C client library — about 160
   entry points covering scanning, connections, bonding, GATT client and
   server authoring, advertising sets, ISO, PAST, and security events.
3. `bluedctl(8)`, the operator CLI (one-shot and interactive modes).

The `bluedctl` verb set indicates the breadth of the operator surface:
`scan`, `connect`, `pair`, `bonds`, `discover`, `read`/`write`,
`subscribe`, GATT authoring with transactions, `accept-list`, `passkey` /
`confirm` (pairing agents), `eatt-open`, `ecbfc-connect`, `iso-cig` /
`iso-big` and teardown verbs, `adv-set-*` (extended advertising),
`per-adv-*` and `per-sync-*` (periodic advertising and sync),
`past-*` (periodic advertising sync transfer), `path-loss`, `connparams`,
profile shortcuts (`battery`, `devinfo`, `heart-rate`, `thermometer`,
`time`, `find`, `keyboard`), `bond-export`, and `monitor`.

## Configuration

`/etc/bluetooth/blued.conf` is UCL; the annotated sample is
`usr.sbin/bluetooth/blued/blued.conf.sample`. Real excerpt:

```ucl
security {
    io_capability = "keyboard_display";
    bondable = true;
    sc = "on";              # off | on | only
    # key_dist = "enc,id,link";
    # min_pairing_security = "auth";   # none | enc | auth | sc
    # min_key_size = 16;
}

features {
    eatt = true;
    privacy = true;
    reconnect = true;
    reconnect_max_delay = 60;
    # rpa_timeout = 900;
    # privacy_mode = "device";  # or "network"
}
```

Other sections: `general` (loglevel, bond database path, BTSnoop
`logfile` for Wireshark, advertised `peripheral_name`), `adapters`,
per-device override blocks, and `service` blocks declaring custom GATT
services with per-characteristic properties and permissions. SIGHUP applies
every setting the man page marks reloadable. Enable at boot with
`blued_enable="YES"` (`/usr/src/libexec/rc/rc.d/blued`).

Persistence lives under `/var/db/blued/`: bonds (LTK/IRK/CSRK), CCCD state,
runtime GATT services, resolving-list IRKs, and HOGP report-map material.

## Test parity effort

The stack carries a BlueZ-scale conformance suite:
`/usr/src/tests/usr.sbin/bluetooth/blued/` holds roughly 150 ATF test
programs (about 2,600 non-mesh cases) plus fuzzers, coverage tooling, and
oracle generators that derive expected HCI encodings from the Core
Specification and Assigned Numbers texts (`generate_core63_oracles.awk`).
Key techniques:

- **Virtual HCI controller.** `vhcitool(8)` creates `/dev/vhciN` endpoints
  of the `ng_hci_virt(4)` netgraph node, driven by the same
  specification-oracle HCI emulator the unit tests use
  (`tests/.../hci_emulator.c`). Because `ng_hci_virt` presents the identical
  upstream contract as `ng_ubt(4)`, the whole stack attaches to a virtual
  controller exactly as to real hardware — full-stack CI with zero hardware.
- **SEQPACKET transports.** On air, ATT rides L2CAP `SOCK_SEQPACKET`
  sockets; unit tests substitute `AF_UNIX SOCK_SEQPACKET` pairs to exercise
  the same message-boundary semantics without a controller.
- **`bt_devreq()` interposition.** HCI command encoders are tested through
  the real `libbluetooth` request path by interposing `bt_devreq` at link
  time (`hci_devreq_mock_test.c`), covering the post-I/O arms a plain
  socketpair cannot reach.

**Status.** The full ATF suite is green except hardware-only `hci_hw` cases
(need a real controller) and one pre-existing `att_server_edge` case. The
completeness review (`docs/bluetooth-bugs.md`, findings 126–143) closed the
operator-surface gaps it found — filter-accept-list verbs, GATT
descriptor/include authoring, extended/periodic-advertising persistence,
runtime IRK persistence — but flagged that host-feature bits and a
controller-wide default-PHY policy still have no operator control
(finding 143, P3). The daemon has not shipped in a release; internal IPC and
persistence formats are explicitly not yet stable interfaces.
