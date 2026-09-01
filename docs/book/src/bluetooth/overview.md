# Bluetooth Stack Overview

5BSD's Bluetooth Low Energy and Bluetooth Mesh stack consists
of two cooperating userland daemons built on three in-tree libraries, running
over the kernel's netgraph Bluetooth layer:

- **blued** — the host daemon: HCI adapter management, ATT/GATT/SMP,
  central and peripheral roles, ISO streams, advertising and scanning.
  Source: `/usr/src/usr.sbin/bluetooth/blued/`.
- **meshd** — the Bluetooth Mesh node daemon: mesh security material,
  network/transport/access layers, foundation and application models.
  Source: `/usr/src/usr.sbin/bluetooth/meshd/`.

The daemons install as `blued(8)` and `meshd(8)`, with CLIs `bluedctl(8)`
and `meshctl(8)`, and rc.d scripts `blued` and `meshd`.

## Architecture: two daemons, one radio owner

blued owns the radio. It is the only process that opens HCI sockets and
programs the controller. meshd never touches HCI directly; its radio
bearer is a privileged client of blued's control socket, using the
mesh-bearer API (`MESH_ADV_ENABLE` / `MESH_ADV_SEND` commands) to transmit
and receive mesh advertising bearer PDUs. From `meshd.c`:

```
The radio bearer is a privileged client of blued ... The daemon never
opens an HCI socket itself; blued owns the radio.
```

If blued is absent, the mesh node keeps running and reconnects the bearer
with backoff; originations resume when the bearer returns. The bearer socket
defaults to `/var/run/blued.sock` (`blued_socket` key in `meshd.conf`).

## Libraries

- `lib/libble` (`libble(3)`) — the client library for blued's control
  protocol; backs `bluedctl` and third-party clients (about 160 entry points
  in `ble.h`).
- `lib/libmesh`, installed as **libblemesh** (`libblemesh(3)`) — the mesh
  protocol engine: crypto, network/transport/access layers, provisioning,
  Config Client/Server, models. meshd is built on it.
- `lib/libbluetooth` — the traditional FreeBSD HCI utility library
  (`bt_devreq()` and friends), used for adapter I/O.

The kernel side is netgraph (`ng_hci`, `ng_l2cap`, `ng_ubt`), plus
`ng_hci_virt(4)` (`sys/netgraph/bluetooth/drivers/vhci/ng_hci_virt.c`), a
virtual controller used with `vhcitool(8)` for hardware-free testing.

## Naming history

The stack began as `blued`, a BLE HID (HOGP) daemon, and grew into a
general-purpose BLE 5.2 stack; the mesh daemon `meshd` followed. Development
history is in-tree (author Kory Heard), e.g.:

```
git log --oneline -- usr.sbin/bluetooth lib/libmesh lib/libble
99960e2fa6b blued: comprehensive BLE 5.2 stack with libble, bluedctl, and full test suite
b80171b10f8 bluetooth: expand LE, ISO, Mesh support and conformance tests
f7e320bcbbf bluetooth: implement mesh Friend and Low Power Node roles
d5d7e848c2a bluetooth: fix correctness regressions and bugs from the audit follow-up
```

The two-daemon split and radio-ownership contract are stable.

## Spec conformance vs product completeness

The project treats these as distinct claims. `docs/bluetooth-bugs.md`
records a sustained correctness and completeness review of the whole stack
against the Core Specification 6.3 and Mesh Protocol/Model 1.1 texts:
125 correctness findings plus 18 product-completeness findings (143 total),
all fixed and committed (`351aca0`, `90e475b`, `f7e320b`).

The completeness round's central theme is worth quoting for evaluators:

> libmesh and libble implement substantially more than the daemons/CLIs
> expose.

That class of gap — Remote Provisioning, Directed Forwarding, the
Private/SAR/LCD Config Client subset, LPN role, extended/periodic
advertising reachable in the libraries but not from any operator surface —
was closed in the committed waves; each daemon chapter lists what is now
exposed.

**Status — known remaining limits** (documented in-tree, not marketing
elisions):

- Mesh friendship delivers unsegmented messages only and uses the
  managed-flooding credential rather than the strict friendship credential;
  validation across three or more real hops with separate daemons needs a
  live multi-node radio setup.
- There is no mesh device-firmware-update (DFU/BLOB transfer) support in
  libblemesh or meshd.
- Hardware-only test cases (`hci_hw`) require a real controller; one
  pre-existing `att_server_edge` test case fails.

See the daemon chapters: [blued](blued.md) and
[BLE Mesh](mesh.md).
