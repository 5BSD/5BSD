# system.Bluetooth (BSDBluetooth)

## What it brokers

BSDBluetooth is the Bluetooth Low Energy host daemon and the single owner of
every radio on the system. It implements ATT, GATT, SMP, EATT, privacy,
extended and periodic advertising, ISO streams and HID over GATT in
userland over the kernel's netgraph Bluetooth layer, and it exposes that
stack to other programs both through a Unix-domain control socket and
through the plane name `system.Bluetooth`. 5BSD has it because FreeBSD's
userland Bluetooth story stopped at BR/EDR; the BLE host, the Mesh stack
built beside it and the hardware-free virtual controller are new. The
program is `BSDBluetooth`; the unit, socket, configuration and state paths
keep the daemon's earlier `blued` name by design.

Two things, through one protocol. First, the radio: scanning, connecting,
pairing and bonding, GATT client and server operations (with atomic
begin/commit authoring), advertising sets, periodic advertising and PAST,
ISO CIG/BIG streams, L2CAP credit-based and ECBFC channels, and EATT.
Second, descriptors: a client may acquire an L2CAP CoC, an ISO stream or a
notify/write pipe as a file descriptor passed over the socket
(`IPC_FEATURE_FDPASS`), limited to `CAP_SEND`, `CAP_RECV` and `CAP_EVENT`.

Three roles. Central (default): connect to HOGP devices and inject their
reports through vhid(4), the virtual HID transport, so hkbd(4), hms(4) and
hmt(4) attach as to local hardware; general GATT client work runs against
any peripheral. Peripheral (`-p`): advertise and serve a GATT database
authored in `blued.conf` or at runtime, runtime additions persisting across
restarts. Observer (`-s`): scan. Multiple adapters and connections are
supported. meshd(8), the Mesh Protocol 1.1 node built on libblemesh(3),
never touches HCI: its bearer is a uid 0 client of the control socket using
the `MESH` domain, reconnecting with backoff if BSDBluetooth is absent.

On the plane, a client calls `ble_open_plane()`: it opens `system.Bluetooth`
with its kernel-stamped identity, sends `BLUED_PLANE_OP_ATTACH`, and is
handed one end of a socketpair speaking the same framed protocol. Such a
client is known by its bundle: the GATT services it registers are recorded
in an ownership file (`gattown`) beside the persisted GATT artifact, it may
edit its own bundle's services without the uid 0 tier and nothing else, and
BSDBluetooth reconciles those records against the delivered `/Capabilities`
directories on the `BLUED_RECLAIM_INTERVAL` timer, removing a bundle's
services once it has been gone for two passes. A socket-path client carries
no identity and is never reclaimed. See
[Containers and Storage](../plane/containers-and-storage.md).
BSDBluetooth is itself a consumer of two other providers. At startup under
switchboard it calls `service_ensure_extension(3)` for `vhid` (see
[system.SystemExtension](extension.md)) and obtains `/dev/vhid` and each
`/dev/vhidN` with `service_open_isolated(3)`; nothing about devices is
declared in its manifest. Both are soft: if a provider is down at startup
it logs a warning and acquires the node lazily when the first HID device
needs it.

## Unit

Source: `usr.sbin/bluetooth/BSDBluetooth/capbundle/Bundle.ucl` and
`blued.ucl` (installed as `Unit.ucl`).

| Field | Value |
|---|---|
| Wire name | `system.Bluetooth` (plane attach protocol `BLUED_PLANE_VERSION` 1) |
| Bundle | `/Capabilities/System/Bluetooth.cap` (bundle_id `org.5bsd.Blued`; label `org.5bsd.Blued/blued`) |
| Unit | `Units/blued.unit` |
| Program | `Units/blued.unit/bin/BSDBluetooth`; `/usr/sbin/blued` is a symlink to it |
| Config | `Units/blued.unit/Config/blued.conf` (installed from `blued.conf.sample`) |
| Activation | `ipc = ["system.Bluetooth"]` (on demand; not started at boot) |
| User | `capability` (manifest default) |
| Launch mode | born in capability mode (`ambient` absent); the program also calls cap_enter(2) itself for the standalone path |
| Declared gates | none |
| Delivered directories | `/Capabilities/System`, `/Capabilities/Apps`, `/Capabilities/Run/live`; persistent state through the `storage:state` descriptor |
| Control | `system` |
| Restart | `on-failure`, `stop_timeout = 10`, `max_failures = 10` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Environment | `BLUED_RECLAIM_INTERVAL` (10 to 86400 s, default 300) |
| Package | `bluetooth` (depends on libservice and switchboard) |

Outside the plane the same program runs from `libexec/rc/rc.d/blued`
(`blued_enable="YES"`) reading `/etc/blued.conf`, storing bonds in
`/var/db/blued/bonds` and opening `/dev/vhid` directly.

## Wire operations

The protocol is not a flat op list. `lib/libble/ipc_proto.h` (private,
explicitly unstable) defines length-prefixed binary framing: an 8-byte
header, payloads up to `IPC_MAX_PAYLOAD` (4096), `IPC_PROTO_VERSION` 6.
The first frame must be `IPC_T_HELLO` with the version and a feature
bitmask; a mismatch gets `IPC_T_ERROR` and no session. `IPC_T_OP_REQ`
frames are answered by `IPC_T_OP_REPLY` with the same request id, plus
unsolicited `IPC_T_OP_EVENT` frames when `IPC_FEATURE_EVENTS` was
negotiated. Each op is a domain plus an opcode; controller-scoped ops carry
the adapter index in the flags word.

| Domain | Covers | Privilege |
|---|---|---|
| `IPC_OP_DOMAIN_CTL` (1) | adapters, status, loglevel, power, capabilities, GATT authoring transactions | loglevel needs the uid 0 tier |
| `IPC_OP_DOMAIN_GAP` (2) | scan, connect, disconnect, connection parameters, PHY, data length, accept and resolving lists, name, discoverability | any client |
| `IPC_OP_DOMAIN_GATT` (3) | discover, read, write, subscribe, notify, indicate, service and characteristic authoring, authorize and read-request replies | plane client: own bundle's services only |
| `IPC_OP_DOMAIN_SECURITY` (4) | pair, passkey and numeric-comparison replies, agent registration, OOB, security policy, bond export/import, rekey, unbond | agent registration needs the uid 0 tier |
| `IPC_OP_DOMAIN_ADV` (5) | advertising sets: create, params, data, enable, remove; legacy advertise and scan response | any client |
| `IPC_OP_DOMAIN_PERIODIC` (6) | periodic advertising, sync create/terminate, advertiser list, PAST | any client |
| `IPC_OP_DOMAIN_L2CAP` (7) | ECBFC session open, reconfigure, fd acquisition, close | `IPC_FEATURE_FDPASS` for descriptors |
| `IPC_OP_DOMAIN_ISO` (8) | CIG/CIS/BIG create, accept, reject, teardown, stream fd acquisition | `IPC_FEATURE_FDPASS` |
| `IPC_OP_DOMAIN_MESH` (9) | bearer subscribe/unsubscribe, advertising send | `IPC_FEATURE_MESH` and uid 0 (`IPC_ERR_PERM` otherwise) |

Structured errors are `IPC_ERR_NONE`, `_GENERIC`, `_UNKNOWN_CMD`,
`_INVAL`, `_NOT_FOUND`, `_NOT_CONN`, `_BUSY`, `_PERM`, `_TOOBIG`, `_NOMEM`
and `_PROTO`. The plane handshake, `lib/libble/blued_plane.h`, is a
single 16-byte `struct blued_plane_msg { magic 'BLUE', version, opcode,
status }` with one op, `BLUED_PLANE_OP_ATTACH`; the reply carries status 0
and the socket end.

## Client library

Header `<ble.h>`, link `-lble` (libble(3), `SHLIB_MAJOR` 1). The header
declares about 210 functions, grouped here by prefix; six worked examples
live in `/usr/share/examples/libble/`.

| Group | Representative functions |
|---|---|
| Session | `ble_open`, `ble_open_fd`, `ble_open_plane`, `ble_handshake`, `ble_close`, `ble_fd`, `ble_process`, `ble_errno`, `ble_strerror` |
| GAP | `ble_scan`, `ble_scan_filtered`, `ble_connect`, `ble_disconnect`, `ble_connections`, `ble_conn_params_update`, `ble_set_phy`, `ble_acceptlist_*`, `ble_resolv_*`, `ble_set_privacy` |
| GATT client | `ble_discover`, `ble_read`, `ble_write`, `ble_write_cmd`, `ble_subscribe`, `ble_unsubscribe`, `ble_get_mtu`, `ble_acquire_notify`, `ble_acquire_write` |
| GATT server | `ble_add_service`, `ble_add_characteristic`, `ble_add_descriptor`, `ble_add_include`, `ble_remove_service`, `ble_set_value`, `ble_notify`, `ble_indicate`, `ble_gatt_begin`, `ble_gatt_commit`, `ble_gatt_rollback`, `ble_on_read_request`, `ble_on_write` |
| Security | `ble_pair`, `ble_unbond`, `ble_rekey`, `ble_register_agent`, `ble_passkey_reply`, `ble_numcmp_reply`, `ble_oob_*`, `ble_set_io_capability`, `ble_set_sc_mode`, `ble_bond_export`, `ble_bond_import` |
| Advertising | `ble_advertise`, `ble_set_adv_data`, `ble_adv_set_create`, `ble_adv_set_params`, `ble_adv_set_data`, `ble_adv_set_enable`, `ble_periodic_adv_*`, `ble_periodic_sync_*`, `ble_past_*` |
| ISO and L2CAP | `ble_iso_cig_create`, `ble_iso_cis_create`, `ble_iso_big_create`, `ble_iso_acquire`, `ble_iso_send`, `ble_iso_recv`, `ble_ecbfc_session_open`, `ble_ecbfc_session_fd`, `ble_eatt_open` |
| Helpers | `ble_read_battery`, `ble_addr_parse`, `ble_addr_str` |

```c
#include <stdio.h>
#include <ble.h>

static void
found(const ble_scan_result_t *r, void *arg)
{
	char buf[18];

	(void)arg;
	printf("%s %d dBm %s\n", ble_addr_str(&r->addr, buf), r->rssi,
	    r->name);
}

int
main(void)
{
	ble_ctx_t *ctx = ble_open(NULL);

	if (ctx == NULL)
		return (1);
	if (ble_scan(ctx, found, NULL) == -1) {
		fprintf(stderr, "scan: %s\n", ble_strerror(ctx));
		ble_close(ctx);
		return (1);
	}
	while (ble_process(ctx) == 0)
		;
	ble_close(ctx);
	return (0);
}
```

A plane unit replaces `ble_open(NULL)` with `ble_open_plane()`. The mesh
engine is separate: libblemesh(3), `-lblemesh`, headers `mesh_*.h`, pure
and I/O-free, with an example in `/usr/share/examples/libblemesh/`.

## Command-line tool

bluedctl(8) drives the control socket (`-s` selects another path, `-j`
emits JSON, `-i` is interactive). Its 83 verbs span connections (`scan`,
`list`, `status`, `adapters`, `connect`, `disconnect`), pairing (`pair`,
`bonds`, `unbond`, `rekey`, `passkey`, `confirm`), GATT (`discover`,
`read`, `write`, `subscribe`, `add-service`, `add-char`, `gatt-begin`,
`gatt-commit`), HID (`keyboard`, `hogp-read`), L2CAP and ISO
(`ecbfc-connect`, `eatt-open`, `iso-cig`, `iso-cis`, `iso-big`),
advertising (`advertise`, `adv-set-*`, `per-adv-*`, `past-*`), profile
shortcuts (`battery`, `heart-rate`, `find`) and `monitor`.

```
# bluedctl scan
aa:bb:cc:dd:ee:01 rssi=-61 name=Keyboard K380
# bluedctl connect aa:bb:cc:dd:ee:01 random
```

Exit codes: 0 success, 1 daemon error, 2 bad arguments, 3 device not found
or not connected, 4 permission denied (privileged peer required), 5 busy or
rate limited, 6 timeout. meshctl(8) does the same for meshd over
`/var/run/meshd.sock` (provisioning over PB-ADV, PB-GATT, remote and
certificate-based; `cfg` Config Client verbs such as `cfg comp-get` and
`cfg model-bind`; `friend`, `low-power`, `key-refresh`). vhcitool(8)
creates `/dev/vhciN` virtual controllers on ng_hci_virt(4) driven by the
in-process spec-oracle emulator (`-n count`, `-l` pairwise air, `-L` also
wire ng_l2cap, `-W` raw only), so `BSDBluetooth -a vhci0` runs the whole
stack with no hardware.

## Policy

| Point | Where | Rule |
|---|---|---|
| Control-socket privilege | `ctl_client_privileged()` in `ctl.c` | peer uid 0 (or a plane client holding ADMIN on the name) may register a pairing agent, subscribe the mesh bearer, receive passed descriptors and change loglevel; everyone else gets `IPC_ERR_PERM` |
| Plane identity | `blued_plane.h`, libcapreclaim | GATT services are attributed to the attaching unit's bundle; a bundle edits only its own |
| Pairing policy | `blued.conf` `security { io_capability, bondable, sc }`, `features { eatt, privacy, reconnect, ... }`, `-P profile`, `-H order` | SMP legacy vs Secure Connections (`sc = "only"` rejects legacy), IO capability, bondability, `compatibility_profile` (`default`, `spec`, `bluez`) and DB-hash byte order to match real peers |
| Device access | [system.Filesystem](filesystem.md) policy `bsdfilesystem.ucl`: `{ label = "org.5bsd.Blued/blued"; path = "/dev/vhid"; prefix = true; rights = ["read", "write", "ioctl"]; }` | the vhid control node and every `/dev/vhidN` are delivered to this label only; HCI is reached over `AF_BLUETOOTH` sockets, which need no network capability |
| Module | [system.SystemExtension](extension.md) allow-list | `vhid` is on the built-in list |
| meshd control | `meshd.c` getpeereid check | root or the daemon's own euid |

The uid-gated control socket is transitional: the inventory records it as
"not yet held-capability based". The plane attach path already carries an
unforgeable identity, and the privileged tier is meant to follow held
capabilities rather than uid 0 (see
[The Authority Model](../capability/authority-model.md)).

## Tests

`tests/usr.sbin/bluetooth/BSDBluetooth/` (package `bluetooth-tests`,
installed under `/usr/tests/usr.sbin/bluetooth/BSDBluetooth`) holds 163 ATF
C programs plus shell cases, an in-process HCI emulator
(`hci_emulator.[ch]`), an independent ATT/SMP peer (`btpeer`), 23
libFuzzer harnesses under `fuzz/` (ATT, SMP, L2CAP, HCI events, HOGP report
maps, advertising parsers, IPC, config and eight mesh layers), and
`coverage.sh`, gated at 95.0% line and 79.8% branch coverage with
per-component floors in `coverage-baseline.txt`. `bundle_test.sh` verifies
the installed bundle; `check_dead_exports.sh` fails on unused exports;
`spec_case_manifest_audit.sh` keeps the spec-derived oracles honest.
Hardware cases skip without a controller; everything else runs against the
emulator or ng_hci_virt(4).

```
# kyua test -k /usr/tests/usr.sbin/bluetooth/BSDBluetooth/Kyuafile
```

## Status and gaps

Shipped in the tree, never released: BSDBluetooth.8 and the inventory both
say the IPC and persistence formats are unstable. Conformance numbers come
from `docs/bluetooth-conformance.md` (assessment dated 2026-09-08,
reproducible with `spec_conf_generate.sh`) and carry caveats: the stack
targets Bluetooth 5.2 plus Connection Subrating, measured against the Core
6.3 text; of 2013 applicable normative sentences, 834 (41.4%) have
section-level coverage by an externally oracled test; 54.8% of the 2255
catalogued requirements are UNKNOWN rather than passed or failed; Mesh
Protocol and Model 1.1.1 coverage is 6.0% and the HOGP 1.1 text 0.0%. Five
interop sweeps against BlueZ, Zephyr and NimBLE recorded about 180 findings
(GAP 44, HCI 20, HOGP 32, L2CAP/ISO 46, Mesh 42); later commits fixed many,
but the residual count is unverified. Known limits: no mesh DFU or firmware
OTA; friendship is unsegmented-only on the managed-flooding credential;
multi-hop features are tested two-node only; ISO sockets and the new L2CAP
socket options are undocumented in `ng_btsocket(4)` and `ng_l2cap(4)`;
vhid(4) has no man page; the control-socket privilege tier is uid based;
meshd is an rc.d daemon, not a capability bundle.
