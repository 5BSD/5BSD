# BLE Mesh

5BSD's Bluetooth Mesh support is split between a protocol library,
**libblemesh**, and the mesh node daemon, **meshd** (`meshd(8)`).
The daemon never opens an HCI socket: its radio
bearer is a privileged client of blued, which owns the radio (see the
[stack overview](overview.md)).

## libblemesh

`libblemesh(3)` builds from `/usr/src/lib/libmesh/` and implements the Mesh
Protocol 1.1 stack as a library:

- **Security and network:** mesh crypto (`mesh_crypto.c`), secure network
  and private beacons, IV Index update, Key Refresh, Replay Protection List,
  network/relay layers, subnet bridging via the manager.
- **Transport and access:** segmentation/reassembly, access-layer dispatch,
  heartbeat publication/subscription.
- **Provisioning:** device-side provisioning (`mesh_provision.c`), a
  provisioner role (`mesh_provisioner.c`), and Remote Provisioning
  (`mesh_remote_prov.c`).
- **Roles:** Relay, GATT Proxy (`mesh_proxy.c`), Friend (`mesh_friend.c`),
  Low Power Node (`mesh_lpn.c`), Directed Forwarding (`mesh_df.c`).
- **Foundation models:** Configuration Server and **Config Client**
  (`mesh_cfg_model.c`, plus the 1.1 additions in `mesh_cfg_v11.c`:
  private beacons, SAR, on-demand private proxy, Large Composition Data),
  Health (`mesh_health_model.c`).
- **Application models:** Generic OnOff/Level and relatives
  (`mesh_generic.c`), Sensor, Time and Scene, Scheduler, Lighting including
  Lightness/CTL/HSL/xyL and the LC controller (`mesh_lighting.c`,
  `mesh_lighting_lc.c`).
- **Manager and simulation:** `mesh_manager.c` (roster, DevKey transaction
  engine, Config Client orchestration) and `mesh_sim.c`, a network engine
  the daemon drives as a single-node network; it also powers the multi-node
  ATF simulations. USDT probes are defined in `mesh_provider.d`.

## meshd

`meshd(8)` is a Bluetooth Mesh node. It holds the node's security material
(NetKey, AppKey, IV Index, sequence number, RPL), registers the Generic
OnOff/Level application models and the Configuration and Health foundation
models, and processes access-layer messages through libblemesh's `mesh_sim`
pipeline. Feature roles wired to the live bearer: Relay, GATT Proxy
(`meshd_proxy_gatt.c`), Friend, Low Power Node, Directed Forwarding, and
Remote Provisioning.

Configuration is `/etc/bluetooth/meshd.conf`, plain `key value` lines:

```
device_uuid    00112233445566778899aabbccddeeff
netkey         7dd7364cd842ad18c17c2b820c84c3d6
netkey_index   0
unicast_addr   0x0001
default_ttl    7
relay          1
proxy          0
friend         0
low_power      0
# blued_socket /var/run/blued.sock   # blued mesh-bearer socket
```

A node with a `netkey` comes up already provisioned (static test networks);
omit it to come up unprovisioned. State persists via `meshd_persist.c`
(keys, SEQ high-water, IV Index and phase, netkeys with Key Refresh state,
appkeys, bindings/subscriptions/publication, RPL, roster). Enable at boot
with `meshd_enable="YES"` (`/usr/src/libexec/rc/rc.d/meshd`).

## Provisioning and management

The daemon serves a line-oriented control protocol on `/var/run/meshd.sock`
(mode 0600, peer credentials checked); `meshctl(8)` is the operator CLI.
Provisioning supports both bearers: PB-ADV (`provision`) and PB-GATT
(`provision-gatt`, via `meshd_pbgatt.c`), plus scan control
(`provision-scan on|off|list`) and `provision-status`.

**Config Client status: exposed and persisted.** `meshd_cfgclient.c` drives
a provisioned node's Configuration Server under its DevKey, bridging the
libblemesh Config Client PDU builders and the manager's transaction engine
onto the live bearer. `meshctl cfg` sub-verbs cover composition data,
AppKey/NetKey management, model binding, subscriptions, publication, relay/
beacon/proxy/friend/TTL/network-transmit state, node identity, heartbeat,
SAR transmitter/receiver, private beacons and private proxy, Large
Composition Data, and `node-reset`:

```sh
meshctl cfg comp-get 0x0002
meshctl cfg appkey-add 0x0002
meshctl cfg model-bind 0x0002 0 0x1000
meshctl cfg sar-tx-get 0x0002
```

An earlier product-completeness review (`docs/bluetooth-bugs.md`) found the
opposite state — a Config Client and manager that existed only in the
library — and that gap class was closed in the committed fix waves, along
with `meshctl` itself and the rc.d scripts.

## Status — honest gap list

Documented in-tree; nothing below is speculative:

- **No mesh DFU / firmware OTA.** There is no BLOB Transfer or Device
  Firmware Update model in libblemesh or the daemon; mesh nodes cannot be
  firmware-updated over mesh.
- **Friendship limits.** Friend/LPN roles are implemented and tested
  two-node, but delivery is unsegmented-only and uses the managed-flooding
  credential, not the strict friendship (k2) credential; a true
  over-the-radio multi-daemon run is still outstanding.
- **Multi-hop validation.** Directed Forwarding and Remote Provisioning are
  wired to the live bearer with two-node tests; genuine 3+-hop operation
  across separate daemons and a real downstream device needs a live
  multi-node radio setup.
- **Test scale vs field exposure.** ~650 mesh library cases and ~130 meshd
  cases pass in ATF, largely against the simulated network engine and
  virtual controller; the stack has not shipped in a release, and internal
  IPC/persistence formats are not yet stable interfaces.
