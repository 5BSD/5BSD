# Tool Reference

Operator CLIs shipped in the 5BSD base system. Synopses below are taken
from each tool's `usage()` output in `/usr/src`.

## authorityctl — system lifecycle control

Source: `usr.sbin/authorityctl`. Resolves `system.lifecycle` over the
ambient discovery plane; `serviced` relays the operation to
[Capsule (PID 1)](../system/capsule.md). No socket, no options — the
caller's authority comes from the capability plane, not from reaching a
control endpoint.

```
usage: authorityctl reboot|halt|poweroff|powercycle|single|reroot|rescan|
                    catatonia|status|reload
```

`status` prints the authority's state summary; `reload` re-reads
configuration and prints the change summary; the remaining verbs drive
system lifecycle transitions. The classic `reboot(8)`/`halt(8)` signal path
remains fully supported beside it.

## servicectl — control serviced(8)

Source: `usr.sbin/servicectl`.

```
usage: servicectl command [args]

commands:
  status              show serviced status and service list
  services            list loaded services
  reload              reload service bundles
  start <label>       start a loaded service
  stop <label>        stop a running service
  restart <label>     stop then start a service
  enable <bundle-id>  clear a bundle's operator-disabled state
  disable <bundle-id> keep a bundle installed but unregistered
  install <path.cap>  install a .cap bundle to /Capabilities/
  verify <path.cap> [...] validate bundles and dependencies
  deps <program>      suggest component manifest dependencies
  bundles             list all registered bundles
```

There is no separate low-level capability administration tool:
`/dev/mac_capability` is held exclusively by authorityd, and capability
administration goes through `authorityctl` and `servicectl`.

## tzfsctl — TrustedZFS broker CLI

Source: `usr.sbin/tzfsctl`. A demonstration/health tool for `tzfsd(8)`,
not a way to hold storage open.

```
tzfsctl ping
tzfsctl request [-l persistent|cache|boot|lease] [-r rights] [-m] name
tzfsctl release name
```

`request` prints the granted dataset and lifetime; `-m` additionally
mounts and reports the dirfd. Rights names: `props_read, props_write,
snapshot, snap_destroy, clone_src, create, destroy, mount`, plus
`all`/`*`; the default is `mount,props_read`.

## bluedctl and meshctl — Bluetooth stack

The Bluetooth stack ships as the daemons `blued`/`meshd` with the operator
CLIs `bluedctl` and `meshctl` (`usr.sbin/bluetooth/`). Both take
`-s socket` (default `/var/run/blued.sock` for bluedctl) and `-i` for
interactive mode; `bluedctl -j` selects JSON output.

Common `bluedctl` operations: `scan`; `connect <addr> [public|random]`
(async — watch `monitor`); `pair <addr>`; `discover <addr>` (GATT
services); atomic GATT updates via `gatt-begin`/`gatt-commit`/
`gatt-rollback`; `serve <handle> <hex>` to back a characteristic live;
`keyboard <addr>` for end-to-end keyboard pairing; profile shortcuts
`battery`, `devinfo`, `heart-rate`, `thermometer`, `time`, `find <addr>`.

Notable `meshctl` verbs: `status`; `create-network` (mint NetKey/AppKey/IV,
this node as Provisioner); `provision <uuid-hex32> [elements]`;
`key-refresh begin|advance|finish|...`; `friend`/`low-power`; and
namespaced families `cfg` (Config Client), `df` (Directed Forwarding),
`remote-prov`.

## waspnest / bhyve and bhyvectl — WASPNest hypervisor

`waspnest` is a transitional symlink to `bhyve` in `/usr/sbin`, with a
matching man-page link; the hypervisor will eventually be named waspnest
with bhyve as the compatibility alias. Usage self-describes under
whichever name it is invoked. Key flags: `-s slot,driver,configinfo` (PCI
devices), `-l` (LPC), `-k config_file` / `-o var=value` (config), `-G
port` (gdb stub), `-r file` (restore from checkpoint), `-R`
(migrate-receive; mutually exclusive with `-r`).

`bhyvectl` uses long options only: `--vm=<vmname>` plus operations
including `--create`, `--destroy`, `--run`, `--get-stats`,
`--set-mem=<MB>`, `--get-cpu-topology`, `--getcap`/`--setcap`,
`--force-reset`, `--force-poweroff`, and (with snapshot support)
`--checkpoint=<file>` and `--suspend=<file>`.

## mac_abac_ctl — ABAC policy control

Source: `usr.sbin/mac_abac_ctl`. Commands: `mode
[disabled|permissive|enforcing]`, `default [allow|deny]`, `status`,
`stats`, `limits`; `rule add|remove|load|append|list|clear|validate`;
`label get|set|setatomic|refresh|remove`; and a `set` family for
policy-set management — `enable`, `disable`, `swap <A> <B>` (atomic swap
for hot-reloading policies), `move`, `clear`, `list`.

## oeslogger — OpenEndpointSecurity event logger

Source: `usr.sbin/oeslogger` (sources in `share/examples/oes`). Streams
OES NOTIFY events as NDJSON.

```
usage: oeslogger [-dnp] [-m path] [-o file] [event_type ...]
  -d       Observe this process and descendants only
  -n       Disable automatic self and /dev/ noise mutes
  -m path  Mute a path prefix (may be repeated)
  -o file  Write JSON output to file (default: stdout)
  -p       Pretty-print JSON output
  -l       List available event names
```

With no event names it subscribes to all NOTIFY events; e.g.
`oeslogger exec open | jq .`. AUTH (blocking) events are not exposed.

## Observability: hwtlm, bsdinstruments, bsdtrace

`hwtlm` (`usr.sbin/hwtlm`) — hardware telemetry with OpenTelemetry output:
`list`, `watch [--interval s] [--duration s]`, `exec -- command` (energy
and thermal impact of a command); `--format text|json|otel`.

`bsdinstruments` (`cddl/usr.sbin/bsdinstruments`) — DTrace profiling
templates with OpenTelemetry output: `list [--json]`, `watch [profile |
-f script.d]`, `generate` (render to D source), `probes [--provider name]
[--regex re]`. Profiles load from `/usr/share/bsdinstruments/profiles`,
then `/usr/local/share/...`, then `~/.bsdinstruments/profiles` (user
wins).

`bsdtrace` (`usr.sbin/bsdtrace`) — hardware-assisted execution tracing
with Intel PT: `list`, `exec -- cmd`, `trace pid`, `decode file.pt`;
output formats `-f text|json|profile|tree|collapsed`; requires root and
`kldload hwt && kldload pt`. See
[ObservableBSD](../observability/observablebsd.md).

## Component control utilities

Small per-component CLIs, each speaking to its serviced component:
`notifyctl` (`configtest`, `publish`, `state-get`, `state-set`,
`timer`, `watch`, `stats`), `logctl` (`configtest`, `emit subsystem
category severity message`, `flush`, `stats`, `show [minimum-severity]`;
severities `trace..fatal`), `tracectl` (`configtest [file]`), and
`networkcmpctl` (`config`, `info`, `resolve host [service]`).

`notifyctl` talks to the shared BSDNotify router through a separately
authorized session; the service is system-wide, but topic visibility and
publish/state/timer authority are default-deny and bound to the caller's
serviced label. See [BSDNotify](../system/bsdnotify.md).
