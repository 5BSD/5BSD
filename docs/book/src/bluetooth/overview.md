# Bluetooth

5BSD's Bluetooth Low Energy and Bluetooth Mesh stack is two cooperating
userland daemons over the kernel's netgraph Bluetooth layer:

- **blued** (`blued(8)`, `/usr/src/usr.sbin/bluetooth/blued/`) — the host
  daemon: HCI adapter management, ATT/GATT/SMP, central and peripheral
  roles, ISO streams, advertising and scanning. CLI: `bluedctl(8)`.
- **meshd** (`meshd(8)`, `/usr/src/usr.sbin/bluetooth/meshd/`) — the
  Bluetooth Mesh node daemon: mesh security material, network/transport/
  access layers, foundation and application models. CLI: `meshctl(8)`.

Both have rc.d scripts (`blued_enable="YES"`, `meshd_enable="YES"`). Three
in-tree libraries back them: `libble(3)` (the client library for blued's
control protocol), `libblemesh(3)` (the mesh
protocol engine, built from `lib/libmesh/`), and the traditional
`libbluetooth(3)` for adapter I/O. The kernel side is netgraph (`ng_hci`,
`ng_l2cap`, `ng_ubt`) plus `ng_hci_virt(4)`, a virtual controller used with
`vhcitool(8)` for hardware-free testing.

**One radio owner.** blued is the only process that opens HCI sockets and
programs the controller. meshd never touches HCI: its radio bearer is a
privileged client of blued's control socket (`/var/run/blued.sock`), using
mesh-bearer commands to move mesh advertising PDUs. If blued is absent, the
mesh node keeps running and reconnects the bearer with backoff.

## blued

blued implements the BLE stack in userland on netgraph L2CAP sockets: ATT,
GATT, SMP (Legacy and Secure Connections), EATT, privacy (RPA generation
and resolving list), extended and periodic advertising, ISO streams
(CIG/BIG), and HID over GATT. Three roles:

- **Central (default):** connects to BLE HID devices via HOGP and injects
  reports through the vhid virtual HID transport, so the kernel's native
  drivers (`hkbd(4)`, `hms(4)`, `hmt(4)`) attach as if to local hardware;
  general GATT client operations work against any peripheral.
- **Peripheral (`-p`):** advertises and serves a GATT database, authored
  statically in the config file or at runtime over the control API, with
  runtime-added services persisting across restart.
- **Observer (`-s`):** scanning/monitor mode.

Multiple adapters and multiple simultaneous connections are supported.
Clients reach the daemon through the control socket, `libble(3)`, or
`bluedctl(8)`, whose verb set spans scanning, connect/pair/bonds, GATT
client and authoring transactions, accept lists, pairing agents, EATT, ISO
setup and teardown, extended/periodic advertising and sync transfer (PAST),
path loss, connection parameters, profile shortcuts (battery, devinfo,
heart-rate, keyboard, and others), bond export, and event monitoring.

Configuration is UCL in `/etc/bluetooth/blued.conf` (annotated sample
in-tree): `security` (IO capability, bondable, SC mode, key distribution),
`features` (EATT, privacy, reconnect policy), `general` (logging, BTSnoop
capture, bond database path), per-adapter and per-device blocks, and
declarative GATT `service` blocks. SIGHUP applies every reloadable setting.
Persistence lives under `/var/db/blued/`: bonds (LTK/IRK/CSRK), CCCD state,
runtime GATT services, resolving-list IRKs, and HOGP report maps.

## BLE mesh

libblemesh implements the Mesh Protocol 1.1 stack: mesh crypto, secure
network and private beacons, IV Index update and Key Refresh, replay
protection, segmentation/reassembly, heartbeats; provisioning in both
directions (device, provisioner, and Remote Provisioning); the Relay, GATT
Proxy, Friend, Low Power Node, and Directed Forwarding roles; Configuration
Server and Client (including the 1.1 private-beacon/SAR/Large Composition
Data additions) and Health foundation models; and application models from
Generic OnOff through Sensor, Time/Scene, Scheduler, and Lighting with the
LC controller.

meshd is the node built on it: it holds the node's security material
(NetKey, AppKey, IV Index, sequence, RPL), registers the foundation and
Generic models, and persists all state (keys, sequence high-water, Key
Refresh phase, bindings, subscriptions, roster) across restarts.
Configuration is plain `key value` lines in `/etc/bluetooth/meshd.conf`; a
node configured with a `netkey` comes up already provisioned, without one
it comes up unprovisioned.

Operators drive it with `meshctl(8)` over a credential-checked control
socket: provisioning over both bearers (PB-ADV and PB-GATT) with scan
control, and a full **Config Client** — `meshctl cfg` sub-verbs cover
composition data, AppKey/NetKey management, model binding, subscriptions,
publication, relay/beacon/proxy/friend/TTL state, heartbeat, SAR, private
beacons and proxy, Large Composition Data, and node reset:

```sh
meshctl cfg comp-get 0x0002
meshctl cfg appkey-add 0x0002
meshctl cfg model-bind 0x0002 0 0x1000
```

## Conformance and honest status

The stack tracks the Core Specification 6.3 and Mesh Protocol/Model 1.1
texts, and the project treats spec conformance and product completeness as
distinct claims: a library feature counts as delivered only once an
operator surface — `meshctl`/`bluedctl` verbs, rc.d scripts, configuration
— exposes it.

Testing needs no hardware: extensive ATF suites, fuzzers, and oracle
generators that derive expected HCI encodings from the specification texts
exercise the stack against the virtual HCI controller. `ng_hci_virt(4)`
presents the identical kernel contract as `ng_ubt(4)`, so the whole stack
attaches to a spec-oracle emulator exactly as to real hardware.

**Known limits:**

- **No mesh DFU / firmware OTA.** There is no BLOB Transfer or Device
  Firmware Update model in libblemesh or meshd; mesh nodes cannot be
  firmware-updated over mesh.
- **Friendship limits.** Friend/LPN delivery is unsegmented-only and uses
  the managed-flooding credential rather than the strict friendship
  credential.
- **Multi-hop.** Directed Forwarding, Remote Provisioning, and friendship
  are exercised two-node against the virtual controller; genuine 3+-hop
  operation across separate daemons needs a live multi-node radio setup.
- Neither daemon has shipped in a release; internal IPC and persistence
  formats are not yet stable interfaces.
