# Tool Reference

Operator CLIs shipped in the 5BSD base system, at a glance. Each tool's man
page is the reference; this page only says what each one is for.

## The capability plane

**authorityctl** drives system lifecycle — reboot, halt, single-user,
reroot, status — by resolving `system.lifecycle` over the ambient discovery
plane; `serviced` relays the operation to
[Capsule (PID 1)](../system/capsule.md). No socket, no options — the
caller's authority comes from the capability plane, not from reaching a
control endpoint. The classic `reboot(8)`/`halt(8)` signal path remains
fully supported beside it.

**servicectl** controls `serviced(8)`: status and listings, bundle install
and verification, reload, enable/disable, and per-service start, stop, and
restart. There is no separate low-level capability administration tool:
`/dev/mac_capability` is held exclusively by `authorityd`, and capability
administration goes through `authorityctl` and `servicectl`.

**tzfsctl** is a demonstration/health tool for the `tzfsd(8)` storage
broker — ping the broker, request and release claims — not a way to hold
storage open.

Small per-service CLIs round out the plane — `notifyctl`, `logctl`,
`tracectl`, `networkcmpctl` — each speaking to its own provider through a
separately authorized, label-scoped session.

Reference: `authorityctl(8)`, `servicectl(8)`, `tzfsctl(8)`,
`notifyctl(8)`.

## Security frameworks

**mac_abac_ctl** manages the `mac_abac(4)` policy: enforcement mode, rules
and atomically swappable rule sets, labels, and a kernel dry-run decision
test. **oeslogger** streams OpenEndpointSecurity NOTIFY events as
newline-delimited JSON (`oeslogger exec open | jq .`); AUTH (blocking)
events are not exposed.

Reference: `mac_abac_ctl(8)`, `mac_abacd(8)`, `oeslogger(8)`.

## Bluetooth

The Bluetooth stack ships the daemons `blued`/`meshd` with the operator
CLIs `bluedctl` (scanning, connections, pairing, GATT client and authoring,
profile shortcuts, monitoring) and `meshctl` (provisioning, key management,
a full Config Client, Directed Forwarding, Remote Provisioning). See the
[Bluetooth](../bluetooth/overview.md) chapter.

## Virtualization

`waspnest` is a transitional alias for `bhyve(8)`, with a matching man-page
link; the hypervisor will eventually be named waspnest with bhyve as the
compatibility alias. `bhyvectl` drives running VMs — creation and teardown,
statistics, capabilities, and (with snapshot support) checkpoint and
suspend. See [WASPNest](../virtualization/overview.md).

## Observability

`hwtlm` (hardware telemetry), `bsdinstruments` (DTrace profiling
templates), and `bsdtrace` (Intel PT execution tracing) are covered in
[ObservableBSD](../observability/observablebsd.md); each has its own man
page.
