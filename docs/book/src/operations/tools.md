# Tool Reference

Every operator command 5BSD adds to the base system, in one table per area:
what it is for, where its manual page is, which pkgbase package installs it,
and one example. The manual page is the reference; this chapter only tells
you which tool to reach for. Two conventions run through the plane tools.
None of them opens a socket or a device to reach its daemon: each resolves a
name over the ambient lookup channel the caller's session holds, so the
caller's authority is its session and its anointments, not its uid (see
[The Authority Model](../capability/authority-model.md)). And each speaks to
one provider through a separately authorised, label-scoped session, which
is why a tool that "hangs" is almost always a lookup that is not being
answered ([Troubleshooting](troubleshooting.md)).

## The plane

| Tool | Purpose | Man page | Package | Example |
|---|---|---|---|---|
| `capsulectl` | Lifecycle requests to Capsule (PID 1) over `system.lifecycle`: reboot, halt, poweroff, powercycle, single, reroot, rescan (re-read ttys(5)), catatonia, status, reload. Sits beside reboot(8) and shutdown(8), which keep their signal path. | capsulectl(8) | `capsulectl` | `capsulectl reboot` |
| `switchboardctl` | Control switchboard(8): status, services, bundles, reload, start/stop/restart a unit by label, enable/disable a bundle, install and verify `.cap` bundles, deps of a program, and `graph` (the anointment reach graph, `--lint` for unreachable endpoints). | switchboardctl(8) | `switchboardctl` | `switchboardctl graph --lint` |
| `anoint` | Run one command holding one additional anointment after re-entering your password; the replacement for sudo and doas. Never changes uid. `-n` sends an empty password instead of prompting (scripts only). | anoint(1) | `runtime` | `anoint system.trace.client dtrace -l` |
| `reclaimstat` | Per-provider view of the container-model reconcile: which bundles each provider holds resources for and the result of its last pass; `-a` lists orphans still in the grace window. Reads `/var/run/reclaim/<provider>`. | reclaimstat(8) | `runtime` | `reclaimstat -a` |
| `sysextctl` | Client of `system.SystemExtension`: list permitted modules, status of one, ensure one is loaded, reload the allow-list. No unload. | sysextctl(8) | `sysextctl` | `sysextctl load if_wg` |
| `tzfsctl` | Health and demonstration client of `system.Filesystem`: ping the broker, request a claim (`-l` lifetime, `-r` rights, `-m` mount), release it. Not a way to hold storage open. | tzfsctl(8) | `runtime` | `tzfsctl ping` |

## Per-provider clients

| Tool | Purpose | Man page | Package | Example |
|---|---|---|---|---|
| `logctl` | `system.Log`: `configtest [file]`, `emit subsystem category severity message`, `flush`, `stats`, `show [minimum-severity]`. | logctl(8) | `bsdlog` | `logctl show warn` |
| `notifyctl` | `system.Notify`: `publish topic [payload]`, `state-get`, `state-set`, `timer`, `watch topic [timeout-ms]`, `stats`, `configtest`; `-s` selects the system tier. | notifyctl(8) | `bsdnotify` | `notifyctl watch app.Example/ready 5000` |
| `networkcmpctl` | `system.Network`: `config`, `info`, `listen`, `connect addr port`, `udp addr port`, `resolve host [service]`. Exercises the brokered socket and resolver path from a session. | networkcmpctl(8) | `bsdnetwork` | `networkcmpctl resolve example.org https` |
| `sysctlcmpctl` | `system.Sysctl`: `get`, `set`, `fmt`, `descr`, `list [start-name]` through the broker rather than sysctl(3). | sysctlcmpctl(8) | `runtime` | `sysctlcmpctl get kern.ostype` |
| `tracectl` | Validate a BSDTrace allow-list with the daemon's parser: `configtest [file]` (default `/etc/bsdtrace.allow`, which the daemon does not read; pass the bundle's `Config/bsdtrace.allow`). | tracectl(8) | `bsdtrace-provider` | `tracectl configtest /Capabilities/System/Trace.cap/Units/bsdtrace.unit/Config/bsdtrace.allow` |
| `BSDPowerctl` | `system.Power`: `states` lists supported sleep states, `suspend state` enters one. | BSDPowerctl(8) | `runtime` | `BSDPowerctl states` |
| `BSDTimectl` | `system.Time`: `get`, `set epoch[.nsec]`, `adjust [-]sec[.usec]`. | BSDTimectl(8) | `runtime` | `BSDTimectl adjust 0.250000` |

## Security frameworks

| Tool | Purpose | Man page | Package | Example |
|---|---|---|---|---|
| `mac_abac_ctl` | Manage mac_abac(4): `mode disabled|permissive|enforcing`, `default allow|deny`, `status`, `stats`, `limits`, and `rule add|remove|clear|list|load|append|validate` with atomically swapped rule sets (`-s set`). | mac_abac_ctl(8) | `mac-abac` | `mac_abac_ctl rule validate /etc/mac_abac.conf` |
| `oeslogger` | Stream OpenEndpointSecurity NOTIFY events as newline-delimited JSON; `-l` lists event types, `-o file` writes to a file, `-m path` mutes a path prefix, `-d` scopes to the logger's descendants, `-n` disables the default noise mutes, `-p` pretty-prints. AUTH (blocking) events are not exposed. | oeslogger(8) | `oes` | `oeslogger exec open \| jq .` |

## Observability

| Tool | Purpose | Man page | Package | Example |
|---|---|---|---|---|
| `bsdinstruments` | DTrace profile catalogue: `list`, `watch profile`, `generate profile`, `probes`; output text, json, otel or collapsed. | bsdinstruments(8) | `bsdinstruments` | `bsdinstruments watch tcplife --duration 10` |
| `hwtlm` | Hardware telemetry (RAPL power, temperatures, frequencies, C-states, thermal zones): `list`, `watch`, `exec -- command`. | hwtlm(8) | `hwtlm` | `hwtlm exec -- make buildworld` |
| `bsdtrace` | Intel Processor Trace: `list`, `exec -- command`, `trace pid`, `decode file.pt` with `-f text|json|profile|tree|collapsed`. amd64, Intel, root to capture. | bsdtrace(8) | `bsdtrace` | `bsdtrace decode -f collapsed run.pt` |

The 87 scripts in `/usr/share/dtrace` and the `oes` examples in
`/usr/share/examples/oes/dtrace` are tools too; see
[Observability](observability.md).

## Bluetooth

| Tool | Purpose | Man page | Package | Example |
|---|---|---|---|---|
| `bluedctl` | Client of BSDBluetooth(8) over `blued.sock`: `scan`, `list`, `status`, `adapters`, `connect`, `disconnect`, `pair`, `bonds`, `unbond`, `rekey`, `services`, GATT authoring, `monitor`, `keyboard`; `-i` interactive, `-j` JSON. | bluedctl(8) | `bluetooth` | `bluedctl scan` |
| `meshctl` | Client of meshd(8): `status`, `models`, `create-network`, `list-nodes`, `provision-scan`, `provision-oob`, `provision-cert`, the Config Client and Directed Forwarding commands. | meshctl(8) | `bluetooth` | `meshctl provision-scan on` |
| `vhcitool` | Create virtual Bluetooth controllers (`/dev/vhciN` on ng_hci_virt(4)) driven by the test suite's HCI emulator; `-n count`, `-l` links them pairwise into a shared simulated air, `-W` exposes raw devices without wiring netgraph nodes. | vhcitool(8) | `bluetooth` | `kldload ng_hci_virt; vhcitool &` |

See [system.Bluetooth](../providers/bluetooth.md).

## Virtualisation

| Tool | Purpose | Man page | Package | Example |
|---|---|---|---|---|
| `virtiofsd` | Host-side virtio-fs server for bhyve(8): exports one directory over a SEQPACKET socket, enters capability mode with rights-limited descriptors. `-r export -s socket`, plus limits. | virtiofsd(8) | `bhyve` | `virtiofsd -r /srv/share -s /var/run/vfs.sock` |
| `mount_virtiofs` | Guest-side mount of a virtio-fs tag exported by the hypervisor (FUSE over VirtIO). | mount_virtiofs(8) | `runtime` | `mount_virtiofs share /mnt/share` |

bhyve(8) and bhyvectl(8) keep their names and their upstream pages; the
`system.VM` broker (BSDVM) has no separate CLI. See
[Virtual Machines](../compat/virtual-machines.md).

## Names that look alike

| Name | Is | Is not |
|---|---|---|
| `bsdtrace` (package `bsdtrace`) | The Intel Processor Trace tool, bsdtrace(8) | The DTrace broker |
| BSDTrace (package `bsdtrace-provider`) | The `system.Trace` daemon, BSDTrace(8), with tracectl(8) and the Trace bundle | A tool you run by hand |
| bhyve(8) | The hypervisor, unchanged in name | BSDVM |
| BSDVM | The `system.VM` broker daemon behind bhyve for capability clients | A hypervisor binary |
| BSDBluetooth(8) | The Bluetooth host daemon program | The name of its runtime paths, which keep `blued` (`blued.unit`, `blued.sock`, `/var/db/blued`) and the rc variable `blued_enable` |
| `capsulectl reload` | Transactionally rescan bundles and apply additions, changes and removals, requested through Capsule's lifecycle capability | `switchboardctl reload`, which asks switchboard directly |

## What is not here

There is no low-level capability administration tool: `/dev/mac_capability`
is held by capsule and administered through `capsulectl` and
`switchboardctl`. Daemons (`capsule`, `switchboard`, the BSD* providers,
`mac_abacd`, `blued`, `meshd`) have their own man pages and are covered by
their chapters, not by this table. And the FreeBSD tools these sit beside
(`service`, `reboot`, `sysctl`, `dtrace`, `praudit`, `pkg`, `bectl`) are
unchanged and documented upstream.
