# Observability

Observability on 5BSD is DTrace with three additions: far more of the system
is instrumented (about 65 new kernel SDT providers and 64 userland USDT
providers, including every plane component), a suite of tools collects and
exports what the probes say (bsdinstruments, hwtlm, bsdtrace and the shared
libotelexport), and a broker decides who may trace so that opening
`/dev/dtrace` as root is no longer the only way in (BSDTrace, the
`system.Trace` provider). Beside it, not inside it, sit the unified log
(BSDLog and logctl) and the BSM audit trail. This chapter is the operator's
view: what to run, on what, and what to expect. Writing a provider or a
tracing client is in [Logging, Audit and Trace](../plane/logging-audit-trace.md)
and [system.Trace](../providers/trace.md); dtrace(1) and the D language are
FreeBSD Handbook material.

## The probes

Kernel providers are defined with `SDT_PROVIDER_DEFINE` and appear in
`dtrace -l -P <provider>`. The 5BSD families, grouped by what they watch:

| Family | Providers | What fires |
|---|---|---|
| Capability plane | `mac_capability` (connect, send, call, dispatch, reply, forward, revoke, fd-install, fd-receive, fd-mint, rights-change, queue-pressure and more), `mac_capability_channel`, `_coalition`, `_isolation`, `_system`, `_capprotect`, `_node`, `_mount`, `_acct`, `_nonce` | Every decision the kernel half of the plane makes |
| Sandboxing | `capsicum`, `envfd`, `procctl`, `fd`, `shmfd`, `pipe`, `eventfd`, `timerfd` | Capability-mode denials, rights changes, descriptor lifecycle |
| Credentials and privilege | `cred`, `priv`, `jail`, `jaildesc`, `imgact`, `ptrace`, `ktrace`, `kld`, `kenv` | Credential changes, privilege checks, exec, module load |
| Security policies | `oes`, `abac`, `mac`, `mac_framework`, `auditpipe` | OES events and verdicts, ABAC rule matches, MAC framework entry points |
| Storage | `trustedzfs`, `vfs`, `mount`, `geom`, `fusefs`, `ext2fs` | Capability handles over ZFS, mounts, filesystem operations |
| IPC and I/O | `aio`, `mqueue`, `squeue`, `unpcb`, `socket`, `kqueue`, `sysvmsg`, `sysvsem`, `sysvshm`, `pts`, `tty` | Queue engines, sockets, terminals |
| Virtualisation | `vmm`, `virtio`, `virtqueue`, `vtblk`, `vsock`, `xbb` | Hypervisor, VirtIO device models, AF_VSOCK |
| Linux | `linuxulator`, `linuxkpi_fw`, `linuxkpi_sdio`, `linuxkpi_fullmac` | Emulation and LinuxKPI drivers |
| Bluetooth | `bluetooth` | Netgraph HCI and L2CAP |

Userland USDT providers ship as `<name>_provider.d` next to the program and
register when it runs: `capsule` (57 probes: claims, minting, shield,
converge, world-stop), `switchboard` (72: lifecycle, naming, anoint and
mint, on-demand, endpoints, quiesce, registry), `service_ambient` and
`channel` in libservice and libchannel, one per BSD* daemon (`bsdlog`,
`bsdtrace`, `bsdauth`, `bsdfilesystem` and so on) and per client library
(`logcmp`, `tracecmp`, `networkcmp`, `notify`), `casper` plus the eight
`cap_*` services, nineteen `pam_*` modules, and `login`, `su`, `cron`,
`inetd`, `syslogd`, `devd`, `jail`, `blued`, `meshd`. List them with
`dtrace -l -P 'switchboard*'` while switchboard runs. The argument
conventions are documented in the headers of the scripts under
`/usr/share/dtrace`; there is no separate provider reference yet.

## The script catalogue

`share/dtrace/Makefile` installs 87 ready-to-run scripts into
`/usr/share/dtrace`. Each starts with `#!/usr/sbin/dtrace -s` (or `-Zs` when
it references providers that may be absent) and a header describing its
probes, so they run directly or with `dtrace -s`:

```sh
dtrace -s /usr/share/dtrace/capwatch
/usr/share/dtrace/mac_capability-summary
```

By purpose:

| Group | Scripts |
|---|---|
| Security watchers | `authwatch`, `privesc`, `capwatch`, `jailwatch`, `tamperwatch`, `rootkit-kld`, `surveil`, `evattr`, `wxwatch`, `inject`, `proctree`, `ipcwatch`, `fdpass`, `netwatch`, `storwatch`, `container-escape`, `persistence`, `fileless-exec`, `cred-theft`, `mac-decisions`, `denials`, `secreport`, `execwatch`, `capflow`, `casper-mediation`, `pam-stack`, `sessions`, `daemon-exec` |
| Plane: kernel | `mac_capability-audit`, `-calls`, `-delegation`, `-denials`, `-errors`, `-fds`, `-holders`, `-messages`, `-nonces`, `-services`, `-shield`, `-summary`, `-who`; `capsicum-changes`, `-denials`, `-xfer`; `envfd-events`; `procdesc-lifecycle`; `trustedzfs-handles`, `-denials` |
| Plane: capsule | `capsule-bootstrap`, `-claims`, `-control`, `-errors`, `-ipc`, `-latency`, `-lifecycle`, `-minting` |
| Plane: switchboard | `switchboard-anoint`, `-capabilities`, `-connections`, `-exec-latency`, `-ipc`, `-latency`, `-lifecycle`, `-naming`, `-resources`, `-shutdown`, `-timeouts` |
| Subsystem flows | `aio-flow`, `squeue-flow`, `-summary`, `-stall`, `mqueue-flow`, `zfs-admin`, `vmm-passthru`, `rctl-limits`, `vsock-connections`, `-overview`, `-perf`, `-provider`, `-security`, `blued-att`, `-connections`, `-overview`, `-pairing`, `-scan`, `rpi-wifi` |
| Upstream network and disk | `tcpconn`, `tcpdebug`, `tcpstate`, `tcptrack`, `udptrack`, `siftr`, `disklatency`, `disklatencycmd`, `hotopen`, `blocking`, `nfsattrstats`, `nfsclienttime` |

`tests/sys/kern/dtrace_catalog_test.sh` is the regression check for the
security group: as root it compiles fourteen of these scripts (`authwatch`,
`capwatch`, `casper-mediation`, `container-escape`, `daemon-exec`, `denials`,
`fileless-exec`, `pam-stack`, `privesc`, `secreport`, `sessions`,
`vmm-passthru`, `mac_capability-delegation`, `mac_capability-messages`)
with `dtrace -Z -e -s` against the providers loaded on the machine, skipping a
script whose kernel providers are absent. Run it with `kyua test
sys/kern/dtrace_catalog_test` from `/usr/tests`, and run it after any change
to a provider's probe signature.

Ten more example scripts for the `oes` provider are in
`/usr/share/examples/oes/dtrace`.

## bsdinstruments

bsdinstruments(8) is a profile runner over libdtrace: 240 `.d` profiles
with `@bsdinstruments-*` markers and `${param}` substitution, installed in
`/usr/share/bsdinstruments/profiles` (then `/usr/local/share/bsdinstruments/profiles`,
then `~/.bsdinstruments/profiles`, later directories overriding earlier
ones). The verbs are `list`, `watch`, `generate` and `probes`:

```sh
bsdinstruments list                       # every profile (--json for machines)
bsdinstruments watch tcplife              # run a profile and stream events
bsdinstruments watch mac-capability-errors --duration 30 --format json
bsdinstruments watch -f my.d --with-ustack
bsdinstruments generate func-trace --param func=vn_open   # print the D, do not run
bsdinstruments probes --provider mac_capability
```

`watch` and `generate` share the targeting options `--pid`, `--execname`,
`--uid`, `--gid`, `--jail`, `--where <predicate>`, `--duration`,
`--with-stack` and `--with-ustack`; `watch` adds `--format
text|json|otel|collapsed`, `--endpoint <url>`, `--bufsize` and
`--switchrate`. The catalogue by family: `tcp` (20), `sched` (18), `proc`
(11), `mac` (11), `oes` (7), then `vm`, `io`, `zfs`, `syscall`, `socket`,
`malloc`, `file`, `capsicum`, `jail`, `casper`, `audit`, `bhyve`, VFS
operations, and USDT profiles for `python`, `node` and `postgresql`. The
profiles are compile-checked by `bsdinstruments_test`. There is no
`bsdinstruments run`; the verb is `watch`.

## hwtlm

hwtlm(8) reads hardware telemetry: RAPL package power through cpuctl(4)
(Intel only), per-core temperature from coretemp(4), frequencies, C-state
residency, acpi(4) thermal zones, and GPU state where a driver exposes it.
Sensors it cannot read are reported absent, so it runs on AMD and arm64 with
fewer columns.

```sh
hwtlm list --format json            # what this machine can report
hwtlm watch --interval 1 --duration 60 --per-core
hwtlm watch --format otel --endpoint http://collector:4318
hwtlm exec -- make -j8 buildworld   # energy and thermal cost of one command
```

## bsdtrace

bsdtrace(8) is the Intel Processor Trace tool. It captures control flow
through hwt(4) and the pt(4) backend and decodes offline with libipt,
libelf and libdwarf. Capture needs root, an Intel CPU, a kernel with
`HWT_HOOKS` (GENERIC has it) and both modules loaded; decoding needs no
privilege and no matching machine, because the `.meta` file written beside
the `.pt` records the capture environment and address ranges.

```sh
kldload pt                                # hwt is preloaded; pt is not
bsdtrace list                             # framework and backend status
bsdtrace exec -o ls.pt -- ls -l /tmp      # trace a command
bsdtrace trace -d 5 -o srv.pt 1234        # attach to a pid for 5 s
bsdtrace decode -f collapsed ls.pt        # text | json | profile | tree | collapsed
```

The output formats are `text`, `json`, `profile`, `tree` and `collapsed`
(the flame-graph input); there is no `folded`. Capture options include
`-r` for IP-range filters (with a `stop:` prefix for TraceStop), `-T` for
thread selection, `-C`/`-M`/`-Y` for timing packets, `-W` for PTWRITE
markers and `-K` to include kernel-mode execution. The tool builds only on
amd64 with `MK_PMC` (it needs libipt) and ships as the `bsdtrace` package,
which is unrelated to the `bsdtrace-provider` package that carries the
BSDTrace daemon.

## Export: libotelexport and OTLP

bsdinstruments and hwtlm share `libotelexport(3)`, which renders a stream of
events or snapshots as text, JSONL, collapsed stacks, or OTLP/HTTP JSON (logs
and metrics, gzip-compressed) and accounts for dropped records. The OTLP
exporter is configured by the standard environment:

| Variable | Use |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector base URL (`--endpoint` overrides) |
| `OTEL_EXPORTER_OTLP_HEADERS` | Extra request headers |
| `OTEL_EXPORTER_OTLP_COMPRESSION` | `gzip` or none |
| `OTEL_EXPORTER_OTLP_TIMEOUT` | Request timeout |
| `OTEL_SERVICE_NAME` | `service.name` resource attribute |
| `OTEL_RESOURCE_ATTRIBUTES` | Additional resource attributes |

The C entry points are `oe_text_new()`, `oe_jsonl_new()`,
`oe_collapsed_new()`, `oe_otlp_new()`, `oe_env_load()` and
`oe_report_drops()` in `<otelexport.h>`. Log records from BSDLog are not
exported over OTLP; only DTrace and telemetry data are.

## BSDTrace: tracing without root

`/dev/dtrace` is opened by exactly one program on a running plane: BSDTrace,
the `system.Trace` provider, which is born in capability mode with `/dev`
delivered as a directory descriptor and opens the device with `openat(2)`.
A client asks switchboard for `system.Trace`; the name is gated on the
`system.trace.client` anointment, which the shipped principal policy grants
to administrators and which an operator can hold without being one. A
session that holds neither gets `ENOENT`, the same answer as an unknown name.
The daemon then checks the client's switchboard label against
`Config/bsdtrace.allow` in its own bundle
(`/Capabilities/System/Trace.cap/Units/bsdtrace.unit/Config/bsdtrace.allow`):
one label per line, no wildcards, default deny, the file owned by the
daemon's user and not group or world writable, under 64 KiB. An allowed
client receives one DTrace consumer descriptor limited to the ioctls
libdtrace needs, transferable once, close-on-fork and close-on-exec; each
client is served by its own worker (256 at most), idle sessions close after
30 seconds, and every grant and rejection is audited and fires the
`bsdtrace` USDT provider.

To let the label `app.Monitor` trace:

```sh
printf 'app.Monitor\n' >> /Capabilities/System/Trace.cap/Units/bsdtrace.unit/Config/bsdtrace.allow
tracectl configtest /Capabilities/System/Trace.cap/Units/bsdtrace.unit/Config/bsdtrace.allow
switchboardctl restart system.Trace/bsdtrace
```

(Unit labels are `<bundle_id>/<unit>`; `switchboardctl services` lists them.)

`tracectl configtest` uses the daemon's parser and rejects wildcard,
duplicate, malformed and oversized entries; with no argument it reads
`/etc/bsdtrace.allow`, which the daemon does not consult. On the client
side, `tracecmp_dtrace_open()` in libtracecmp(3) wraps the new
`dtrace_fdopen(3)` so that unmodified libdtrace code runs on the delegated
descriptor; the recipe is in [system.Trace](../providers/trace.md).

The honest limit: the policy is who, not what. An allowed label has the full
introspection power DTrace has, because an ioctl allow-list cannot constrain
D programs, probes, actions or targets. BSDTrace narrows who may obtain a
consumer and how, and removes the need for root; it does not make DTrace
safe to hand to an untrusted principal.

## Unified logging: BSDLog and logctl

Capability-mode units cannot reach syslogd's socket, so their diagnostics go
to `system.Log` through `logcmp_log(3)`, a capability-mode-safe syslog(3)
replacement that falls back to syslog when the Log provider is unreachable.
BSDLog stores records with OpenTelemetry severities, a subsystem and
category, privacy classes and per-label query scoping, and exposes its own
`bsdlog` provider (record-write and drop, storage rotate and corruption,
query-complete, retention-prune) beside liblogcmp's `logcmp` provider.
logctl(8) is the operator's client:

```sh
logctl stats                     # accepted, rejected, ring-loss, filtered, retained
logctl show warn                 # retained records at warn and above, scoped to your identity
logctl emit myapp startup info "hello"
logctl flush
logctl configtest                # validate the Log bundle's Config/bsdlog.conf
```

Severities are `trace`, `debug`, `info`, `warn`, `error` and `fatal`.
`logctl show` returns records belonging to the caller's switchboard
identity, so an administrator sees the system's records and a user sees
their own agents'. The retention, rate-budget and ring-size policy lives in
the Log bundle's configuration and is validated by `configtest`; the design
is in [system.Log](../providers/log.md). Before the Log provider is up (the
first seconds of boot) a unit's stdout and stderr land in
`/var/log/capability.log`, which switchboard opens for it before the
sandbox closes; that file is where a launch failure explains itself.

Audit is separate: BSM records from every gate daemon commit through
`system.Audit` to auditd's trail (on by default), and `praudit` reads them
as on FreeBSD. See [system.Audit](../providers/audit.md).

## Running the observability suites

| Suite | Where | Needs |
|---|---|---|
| `dtrace_catalog_test` | `/usr/tests/sys/kern` | root, kernel providers loaded |
| `squeue_dtrace_test` | `/usr/tests/sys/kern` | root; proves the `squeue` provider fires |
| `bsdinstruments_test`, `hwtlm_test`, `bsdtrace_test`, `otelexport_test` | `/usr/tests/usr.sbin/*`, `/usr/tests/lib/libotelexport` | unprivileged for the compile checks; capture cases need Intel PT and root |
| BSDTrace `policy_test`, `session_test`, `bundle_test` | `/usr/tests/usr.sbin/BSDTrace` | in-session for the parser; a plane-off VM for the session tests |

The tiers and the plane-off image are explained in
[Testing](../develop/testing.md).

## Status

Everything in this chapter is shipped. Gaps: no per-provider reference for
the kernel and USDT probe arguments beyond the script headers; no
per-profile reference for the 240 bsdinstruments profiles; OTLP export of
log records is deferred; BSDTrace policy is coarse by design; and bsdtrace
capture is Intel-only, with AMD and arm64 unsupported by design of the tool,
not by omission.
