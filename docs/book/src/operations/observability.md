# Observability

Observability on 5BSD is DTrace with three additions: far more of the system
is instrumented (63 new kernel SDT providers and 64 userland USDT
providers, including every plane component), a suite of tools collects and
exports what the probes say (bsdinstruments, hwstat, bsdtrace and the shared
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
| IPC and I/O | `aio`, `mqueue`, `unpcb`, `socket`, `kqueue`, `sysvmsg`, `sysvsem`, `sysvshm`, `pts`, `tty` | Queue engines, sockets, terminals |
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

`share/dtrace/Makefile` installs 95 ready-to-run scripts into
`/usr/share/dtrace` (83 added by 5BSD and the 12 upstream ones in the last
row below). Each starts with `#!/usr/sbin/dtrace -s` (or `-Zs` when
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
| Subsystem flows | `aio-flow`, `mqueue-flow`, `zfs-admin`, `vmm-passthru`, `rctl-limits`, `vsock-connections`, `-overview`, `-perf`, `-provider`, `-security`, `blued-att`, `-connections`, `-overview`, `-pairing`, `-scan`, `rpi-wifi` |
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

bsdinstruments(8) is a profile runner over libdtrace: 243 `.d` profiles
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
profiles are compile-checked by `bsdinstruments_test` with `dtrace -Z`,
because a USDT provider exists only while its daemon runs; since `-Z`
also accepts probes nothing defines, the test separately checks that
`capability-services.d` names no probe retired with BSDAuth and session
minting. There is no `bsdinstruments run`; the verb is `watch`.

The `loader-libraries`, `loader-summary`, and `script-exec` profiles support
cache selection and interpreter workloads. Loader events require an isolated
VM build with `RTLD_CACHE_PROFILE=yes`; ordinary builds emit none. Capture
startup/dependency and dlopen/fdlopen activity without setting process tracing
flags, which would prevent capability authority acquisition. These events are
untrusted diagnostics and contain no service descriptors or argument strings.
The script profile observes exec paths and outcomes, including shebang launches;
it cannot identify every sourced script or interpreter input. See
`tools/test/elfcache/README.md` for capture, ranking, and observer limitations.

## hwstat

hwstat(8) is a native C base-system tool. It reads Intel RAPL or AMD Zen
package energy through cpuctl(4), CPU temperatures from coretemp(4) or
amdtemp(4), logical-CPU frequencies, C-state usage, acpi(4) thermal zones,
and GPU state where a driver exposes it. `--per-core` reports each logical
CPU separately; frequency is the driver's instantaneous reading, not an
interval average. C-state percentages currently describe accumulated idle-state
entry counts from `dev.cpu.N.cx_usage`, not interval time residency.
AMD package temperatures can be shared by logical CPUs. C1/C2/C3 are ACPI
idle states; watch labels their columns `entry%` to distinguish them from
interval `BUSY%`. `list` reports wake latencies and the configured deepest
allowed idle state.

`list` also reports the boot clock, exported cpufreq table bounds, and AMD
CPPC capability/request values. A one-entry frequency table is not a complete
hardware clock range, and CPPC values are abstract performance units, not
MHz. The new read-only `dev.hwpstate_amd.N.caps_*` sysctls expose highest,
nominal, efficient, and lowest performance capabilities. The tool never
changes these policies. Intel HWP offers analogous read-only highest,
guaranteed, efficient, and lowest performance fields; these are HWP units,
not MHz, and dynamic values are refreshed. Intel EPP uses 0-100 percent;
AMD EPP uses 0-255 units. Supported Intel CPUs also report CPUID leaf 16H
base, maximum, and bus specification clocks in MHz. These are informational,
not measured or guaranteed sustained clocks. Pi firmware ARM/core/SDRAM minimum and maximum
clock limits are reported in Hz. They describe firmware configuration,
not immutable product ratings.

The interfaces follow the [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
(HWP capabilities and thermal status), AMD's published CPPC/energy register
interfaces, and Raspberry Pi's [mailbox interface](https://github.com/raspberrypi/firmware/wiki/Mailbox-property-interface)
and [throttle status documentation](https://www.raspberrypi.com/documentation/computers/os.html#get_throttled).
Intel and Pi paths are compile-tested here; hardware readings still need
validation on those platforms.
Named AMD sensors (including available CCD readings) and ACPI zones appear
in the `temperatures` JSON array and in text and OTLP watch output.

The amd64 and i386 GENERIC kernels include cpuctl, coretemp, amdsmn, and
amdtemp. Older/custom kernels can load these through sysextctl; the shipped
SystemExtension policy permits them. Intel and AMD temperature drivers
probe for matching hardware. The Pi 3/4 Broadcom driver path is included in
arm64 GENERIC and exposes shared SoC temperature and CPU frequency through
the existing hwstat sysctl reader. This is source-level integration, not a
hardware validation result or a claim of Pi 5 support. hwstat now also reads
Pi firmware clocks and current/historical throttle flags through a new
read-only `hw.cpufreq.throttled` sysctl. It does not clear sticky flags.
Pi voltage and energy collection remain unavailable. Pi does not use x86
MSRs or these x86 temperature drivers.

Energy requires read access to `/dev/cpuctl0` (normally root), and covers the
package containing CPU 0, including concurrent workloads. AMD family 17h,
19h, and 1ah package counters are probed; unsupported domains are omitted.
Intel-only TDP is not reported for AMD. Sensors it cannot read remain absent.
No energy readings are inferred from temperature or frequency.

Interval CPU utilization comes from `kern.cp_times`, including per-CPU user,
nice, system, interrupt, and idle percentages in JSON. These are scheduler
accounting, not hardware residency counters. Intel coretemp exposes current
thermal status separately from its historical throttle log.

AMD APU metrics versions 2.1 and 2.2 add component temperatures, activity,
power, and clock readings where populated by firmware. The driver exports
binary data through `sys.device.drmnN.gpu_metrics`; the LinuxKPI correction
requires rebuilding the DRM module against the updated headers. Rebuilding
only the kernel is insufficient. Truncated tables from an older module are
reported as `invalid_length`, never decoded as readings. JSON `metrics`
entries carry a source and unit-bearing name; `metric_sources` reports AMD
collector availability. Physical-core firmware slots do not identify logical
CPUs. Socket power overlaps RAPL package power; do not sum them. Firmware
averages use their own windows. The ASIC-dependent throttle bitmap remains
raw. Unknown table versions and sentinel values are not guessed.

Apple's [powermetrics documentation](https://images.apple.com/media/us/osx/2013/docs/OSX_Power_Efficiency_Technology_Overview.pdf)
is a useful comparison for power diagnostics: it combines CPU usage,
wakeups, package idle states, and execution frequency. hwstat uses native
5BSD sysctl and cpuctl interfaces; it does not provide Darwin's task/QoS
attribution or claim its instantaneous frequency readings are execution
frequency averages.

```sh
hwstat list --format json            # what this machine can report
hwstat watch --interval 1 --duration 60 --per-core
hwstat watch --format otel --endpoint http://collector:4318
hwstat exec -- make -j8 buildworld   # energy and thermal cost of one command
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

bsdinstruments and hwstat share `libotelexport(3)`, which renders a stream of
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
`system.trace.client` software attribute. A client without the required
attribute receives a discovery denial; UNIX root or wheel membership does
not supply it. After admission, the provider accepts its administrative
endpoint right or checks the client's software label against
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

(Unit labels are `<bundle_id>/<unit>`; `switchboardctl services` lists them,
with each unit's coalition id and responsible parent; `switchboardctl tree`
draws the chains, and `ps -o pid,coal,rcoal,rpid,comm` or `procstat
coalition` walks any process back to the unit, session, or system that
caused it.)

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
| `bsdinstruments_test`, `hwstat_test`, `bsdtrace_test`, `otelexport_test` | `/usr/tests/usr.sbin/*`, `/usr/tests/lib/libotelexport` | unprivileged for the compile checks; capture cases need Intel PT and root |
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
