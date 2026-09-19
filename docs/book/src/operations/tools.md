# Tool Reference

Operator CLIs shipped in the 5BSD base system, at a glance. Each tool's man
page is the reference; this page only says what each one is for.

## The capability plane

**capsulectl** drives system lifecycle — reboot, halt, single-user,
reroot, status — by resolving `system.lifecycle` over the ambient discovery
plane; `switchboard` relays the operation to
[Capsule (PID 1)](../system/capsule.md). No socket, no options — the
caller's authority comes from the capability plane, not from reaching a
control endpoint. The classic `reboot(8)`/`halt(8)` signal path remains
fully supported beside it.

**switchboardctl** controls `switchboard(8)`: status and listings, bundle install
and verification, reload, enable/disable, per-service start, stop, and
restart, and `graph`, the anointment reach graph drawn from the registry on
disk (`--lint` reports unreachable endpoints and dead declarations). There is
no separate low-level capability administration tool:
`/dev/mac_capability` is held exclusively by `capsule`, and capability
administration goes through `capsulectl` and `switchboardctl`.

**anoint** runs one command holding one additional anointment, after the
caller re-enters its password: the capability plane's replacement for `sudo`
and `doas`. It never changes uid; `su` remains for work that needs uid 0.
Whether a principal may elevate to a name is decided by
`/Capabilities/Config/principal-policy.ucl`. See
[IPC Anointments](../security/ipc-anointments.md#anoint-elevation-in-place-of-sudo-and-doas).

**tzfsctl** is a demonstration/health tool for the `BSDFilesystem(8)` storage
broker — ping the broker, request and release claims — not a way to hold
storage open.

Small per-service CLIs round out the plane — `notifyctl`, `logctl`,
`tracectl`, `networkcmpctl` — each speaking to its own provider through a
separately authorized, label-scoped session.

Reference: `capsulectl(8)`, `switchboardctl(8)`, `anoint(1)`, `tzfsctl(8)`,
`notifyctl(8)`.

## Security frameworks

**mac_abac_ctl** manages the `mac_abac(4)` policy: enforcement mode, rules
and atomically swappable rule sets, labels, and a kernel dry-run decision
test. **oeslogger** streams OpenEndpointSecurity NOTIFY events as
newline-delimited JSON (`oeslogger exec open | jq .`); AUTH (blocking)
events are not exposed.

Reference: `mac_abac_ctl(8)`, `mac_abacd(8)`, `oeslogger(8)`.

## Bluetooth

The Bluetooth stack ships the daemons `BSDBluetooth`/`meshd` with the operator
CLIs `bluedctl` (scanning, connections, pairing, GATT client and authoring,
profile shortcuts, monitoring) and `meshctl` (provisioning, key management,
a full Config Client, Directed Forwarding, Remote Provisioning). See the
[Bluetooth](../bluetooth/overview.md) chapter.

## Virtualization

`BSDVM` is a transitional alias for `bhyve(8)`, with a matching man-page
link; the hypervisor will eventually be named BSDVM with bhyve as the
compatibility alias. `bhyvectl` drives running VMs — creation and teardown,
statistics, capabilities, and (with snapshot support) checkpoint and
suspend. See [BSDVM](../virtualization/overview.md).

## Observability

`hwtlm` (hardware telemetry), `bsdinstruments` (DTrace profiling
templates), and `bsdtrace` (Intel PT execution tracing) are covered in
[ObservableBSD](../observability/observablebsd.md); each has its own man
page.
