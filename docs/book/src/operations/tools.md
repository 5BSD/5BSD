# Tool Reference

Operator CLIs shipped in the 5BSD base system. Synopses below are taken
from each tool's `usage()` output in `/usr/src`.

## authorityctl — control authorityd(8)

Source: `usr.sbin/authorityctl`. One connection, one command, over the
authorityd control socket (`-s socket` overrides the path).

```
usage: authorityctl [-s socket] command
       authorityctl status
       authorityctl reload
       authorityctl shutdown
```

`status` prints running state, uptime, and a summary block; `reload`
re-reads configuration and prints the change summary; `shutdown`
initiates daemon shutdown. `EPERM` maps to exit code `EX_NOPERM`.

## servicectl — control serviced(8)

Source: `usr.sbin/servicectl`.

```
usage: servicectl [-s socket] command [args]

commands:
  status              show serviced status and service list
  services            list loaded services
  reload              reload service bundles
  stop <label>        stop a running service
  install <path.cap>  install a .cap bundle to /Capabilities/
  verify <path.cap> [...] validate bundles and dependencies
  deps <program>      suggest component manifest dependencies
  bundles             list all registered bundles
```

There is no separate low-level capability administration tool:
`/dev/mac_capability` is held exclusively by authorityd, and capability
administration goes through `authorityctl` and `servicectl`.

## tzfsctl — TrustedZFS broker CLI

Source: `usr.sbin/tzfsctl`. A demonstration/health tool for
`tzfsd(8)`, not a way to hold storage open.

```
tzfsctl list-flavors
tzfsctl ping
tzfsctl request [-f flavor] [-l persistent|ephemeral] [-r rights] [-m] name
tzfsctl release name
```

`request` prints `granted <dataset> (flavor=..., ephemeral|persistent)`;
`-m` additionally mounts and reports the dirfd. Rights names:
`props_read, props_write, snapshot, snap_destroy, clone_src, create,
destroy, mount`, plus `all`/`*`; the default is `mount,props_read`.

## bluedctl and meshctl — Bluetooth (Skyblue stack)

**Status:** the stack's target names are `skyblued`/`skybluemeshd` with
a `skyblue` CLI; the shipping binaries today are `blued`/`meshd` with
`bluedctl` and `meshctl` (`usr.sbin/bluetooth/`). No `skyblue` binary
or symlink exists yet.

```
usage: bluedctl [-ij] [-s socket] command [args ...]
       bluedctl [-j] [-s socket] monitor
       bluedctl [-s socket] keyboard <addr>
       bluedctl -i [-s socket]
       bluedctl help [command]
```

`-i` interactive mode, `-j` JSON output; default socket
`/var/run/blued.sock`. Common operations: `scan`; `connect <addr>
[public|random]` (async — watch `monitor`); `pair <addr>`;
`discover <addr>` (GATT services); atomic GATT updates via
`gatt-begin`/`gatt-commit`/`gatt-rollback`; `serve <handle> <hex>` to
back a characteristic live; `keyboard <addr>` for end-to-end keyboard
pairing; profile shortcuts `battery`, `devinfo`, `heart-rate`,
`thermometer`, `time`, `find <addr>`.

```
usage: meshctl [-s socket] command [args ...]
       meshctl [-s socket] -i
       meshctl help
```

meshctl controls `meshd(8)` (Bluetooth Mesh). Notable verbs: `status`;
`create-network` (mint NetKey/AppKey/IV, this node as Provisioner);
`provision <uuid-hex32> [elements]`; `key-refresh
begin|advance|finish|...`; `friend`/`low-power [on|off|status]`; and
namespaced families `cfg <sub-verb> <dst> ...` (Config Client), `df`
(Directed Forwarding), `remote-prov`. Arguments are validated by the
daemon.

## waspnest / bhyve and bhyvectl — WASPNest hypervisor

`waspnest` is a transitional symlink to `bhyve` in `/usr/sbin`
(`usr.sbin/bhyve/Makefile`), with a matching man-page link; the
hypervisor will eventually be named waspnest with bhyve as the
compatibility alias. Usage self-describes under whichever name it is
invoked:

```
Usage: waspnest [-aCDeHhPSuWwxY]
       [-c [[cpus=]numcpus][,sockets=n][,cores=n][,threads=n]]
       [-G port] [-k config_file] [-l lpc] [-m mem] [-o var=value]
       [-p vcpu:hostcpu] [-r file] [-s pci] [-U uuid] vmname
```

Key flags: `-s slot,driver,configinfo` (PCI devices), `-l` (LPC),
`-k config_file` / `-o var=value` (config), `-G port` (gdb stub),
`-r file` (restore from checkpoint), `-R` (migrate-receive; mutually
exclusive with `-r`).

`bhyvectl` uses long options only: `--vm=<vmname>` plus operations
including `--create`, `--destroy`, `--run`, `--get-stats`,
`--get-memmap`, `--get-memseg`, `--set-mem=<MB>`, `--get-cpu-topology`,
`--get-active-cpus`, `--getcap`/`--setcap=0|1 --capname=<name>`,
`--force-reset`, `--force-poweroff`, and (with snapshot support)
`--checkpoint=<file>` and `--suspend=<file>`. Architecture-specific
register/VMCS dump options are appended per platform.

## mac_abac_ctl — ABAC policy control

Source: `usr.sbin/mac_abac_ctl`.

```
usage: mac_abac_ctl <command> [arguments]
```

Commands: `mode [disabled|permissive|enforcing]`, `default
[allow|deny]`, `status`, `stats`, `limits`; `rule
add|remove|load|append|list|clear|validate`; `label
get|set|setatomic|refresh|remove`; and a `set` family for policy-set
management — `enable`, `disable`, `swap <A> <B>` (atomic swap for
hot-reloading policies), `move <from> <to>`, `clear <N>`, `list`.

## oeslogger — OpenEndpointSecurity event logger

Source: `usr.sbin/oeslogger` (sources in `share/examples/oes`).
Streams OES NOTIFY events as NDJSON.

```
usage: oeslogger [-dnp] [-m path] [-o file] [event_type ...]
  -d       Observe this process and descendants only
  -m path  Add a primary-path prefix mute (repeatable)
  -n       Clear normal self and /dev/ noise mutes
  -o file  Write JSON output to file (default: stdout)
  -p       Pretty-print JSON output
  -l       List available event names
```

With no event names it subscribes to all NOTIFY events; e.g.
`oeslogger exec open | jq .`. AUTH (blocking) events are not exposed. Each
NDJSON record includes message and sequence IDs, monotonic and wall-clock
times, AUTH-derived results, process/thread/path metadata, and event-specific
objects.

## Observability: hwtlm, bsdinstruments, bsdtrace

`hwtlm` (`usr.sbin/hwtlm`) — hardware telemetry with OpenTelemetry
output. Subcommands: `list [--format text|json] [--per-core]`;
`watch [--interval s] [--duration s] [--per-core] [--format
text|json|otel] [--endpoint url]`; `exec [--format text|json]
[--per-core] -- command [args]` (energy/thermal impact of a command).

`bsdinstruments` (`cddl/usr.sbin/bsdinstruments`) — DTrace profiling
templates with OpenTelemetry output. Subcommands: `list [--json]`,
`watch [profile | -f script.d]`, `generate [profile | -f script.d]`
(render to D source), `probes [--provider name] [--regex re]`.
Profiles load from `/usr/share/bsdinstruments/profiles`, then
`/usr/local/share/...`, then `~/.bsdinstruments/profiles` (user wins).

`bsdtrace` (`usr.sbin/bsdtrace`) — hardware-assisted execution tracing
with Intel PT. Commands: `list` (HWT/backend status), `exec [opts] --
cmd`, `trace [opts] pid`, `decode [opts] .pt`. Output formats `-f
text|json|profile|tree|collapsed`; requires root and
`kldload hwt && kldload pt`.

## Component control utilities

Small per-component CLIs, each speaking to its serviced component:
`notifyctl` (`configtest`, `publish`, `state-get`, `state-set`,
`watch`, `stats`), `logctl` (`configtest`, `emit subsystem category
severity message`, `flush`, `stats`, `show [minimum-severity]`;
severities `trace..fatal`), `tracectl` (`configtest [file]`),
`networkcmpctl` (`config`, `info`, `resolve host [service]`), and
`filesystemcmpctl` (`config`, `info`, `stat namespace path`;
namespaces `scratch`, `persistent`, `bundle`).

`notifyctl` talks to the shared BSDNotify router through a separately
authorized session; the service is system-wide, but topic visibility and
publish/state/timer authority are default-deny and bound to the caller's
serviced label. See [BSDNotify](../system/bsdnotify.md).
