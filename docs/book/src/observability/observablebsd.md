# ObservableBSD

Observability on 5BSD is one story told at three depths: what the system can
*emit* (OpenTelemetry metrics and traces from the ObservableBSD tool suite),
what it can *instrument* (a broadened DTrace and a kernel hardware-tracing
framework), and who is *allowed to look* (`traced`, the capability broker
that replaces DTrace's root requirement). This chapter covers all three.

The ObservableBSD suite itself is four components: a DTrace profiler with an
Apple-Instruments-style profile catalog (`bsdinstruments`), a hardware
telemetry collector (`hwtlm`), a hardware execution tracer (`bsdtrace`), and
a shared OpenTelemetry export library (`libotelexport`). The suite is
written in C and ships in the base system. All components are
pkgbase-tagged so they install and upgrade as ordinary `5BSD-*` packages.

## libotelexport

`lib/libotelexport` is an internal static library shared by `bsdinstruments`
and `hwtlm`. An exporter consumes probe events and aggregation snapshots
from a tool's run loop and ships them to stdout (text, JSONL, or folded
stacks for flame graphs) or to an OTLP/HTTP+JSON collector. The OTLP path
includes an asynchronous sender with batching, gzip compression, retry with
backoff and `Retry-After` handling, a minimal HTTP/1.1 client (http and
https, IPv6 literals, timeouts), JSON escaping that keeps arbitrary probe
bytes valid, and `OTEL_*` environment variable support. The public interface
is `lib/libotelexport/otelexport.h`.

## bsdinstruments

`cddl/usr.sbin/bsdinstruments` is a `MK_DTRACE`-gated DTrace profiler that
renders a catalog of bundled `.d` templates covering syscalls, the
scheduler, TCP/UDP/IP, VFS/VM, locks, USDT-instrumented applications, and
5BSD-specific providers (capability runtime, authority, casper, audit,
bhyve). Profiles install to `/usr/share/bsdinstruments/profiles`. The tool
runs a profile through libdtrace and streams results as text, JSONL, folded
stacks, or OTLP via libotelexport, decoding the full set of DTrace
aggregations and symbolizing stack keys the way `dtrace(1)` does.

```sh
bsdinstruments list
bsdinstruments run tcplife
```

## hwtlm

`usr.sbin/hwtlm` collects CPU power (Intel RAPL via `cpuctl(4)` MSRs),
per-core temperatures and frequencies, C-state residency, ACPI thermal
zones, and GPU state, emitted as text, JSONL, or OTLP/HTTP metrics through
libotelexport. Subcommands are `list`, `watch`, and `exec`; `exec` resamples
RAPL across the run so 32-bit energy-counter wraps do not lose data on long
commands. RAPL is compiled only on x86 behind a stub; the sysctl-based
sensors are architecture-independent, so the tool degrades cleanly on arm64
and riscv. See `hwtlm(8)`.

```sh
hwtlm watch
hwtlm exec -- make -j8 buildworld
```

## bsdtrace

`usr.sbin/bsdtrace` is built on amd64 only (it links the `MK_PMC`-gated
libipt) and captures control flow with Intel Processor Trace through the
`hwt(4)` framework. It therefore **requires Intel silicon** — Intel PT is an
Intel-only CPU feature and bsdtrace does not work on AMD processors, even on
amd64. Captured traces are decoded with libipt into symbolized calls,
returns, jumps, and syscalls, with per-function profiles, call trees, and
folded/speedscope stacks. Subcommands are `exec`, `trace`, `list`, and
`decode`. Traces are saved as a `.pt` buffer plus a JSONL `.meta` sidecar
recording the capture machine's CPU identity, TSC/CTC ratio, nominal
frequency, and address-filter setup, so offline and cross-machine decode
feeds libipt the values it needs for timing. See `bsdtrace(8)`.

```sh
bsdtrace exec -- ls -l /tmp
bsdtrace decode -f folded trace.pt
```

## DTrace and hardware tracing

The tools above stand on instrumentation the fork itself broadened.

**USDT coverage.** Security-relevant base userland carries USDT providers:
`lib/libcasper` and every Casper service expose `casper`/`cap_*` providers
around request handling, and `login(1)`, `su(1)`, `cron(8)`, `inetd(8)`,
`jail(8)`, and `syslogd(8)` expose providers for authentication, dispatch,
service activation, jail lifecycle, and log-path events. Kernel SDT probes
cover the VM subsystem, and the `bsdinstruments` catalog matches the
providers the system ships.

**USDT builds.** The build stages the target-ABI `cddl/lib/drti` before the
parallel prebuild-library pass in `Makefile.inc1`, so a clean cross build
never links USDT provider objects against the host `drti.o`;
`cddl/lib/libdtrace` is a prebuild library with explicit dependencies, and
USDT registration works for objects loaded via `fdlopen(3)`.

**hwt(4) and Intel PT.** The 5BSD kernel carries the HWT hardware-trace
framework, enabled via `HWT_HOOKS` in `GENERIC`. The framework is
machine-independent (`sys/dev/hwt/`) with per-architecture backends: Intel
Processor Trace on amd64 (`sys/amd64/pt/`) and ARM SPE on arm64
(`sys/arm64/spe/`). The PT backend provides TSC timing packets, PTWRITE
markers, overflow records, TraceStop filters, and MMAP records for JIT
decode, over a physically contiguous ToPA table. The record ABI couples the
pieces: `hwt.ko` and `pt.ko` must be rebuilt together with a matching
`bsdtrace`.

**VirtIO providers.** The WASPNest virtio device models carry `vsock` and
`virtio` USDT providers.

## traced: brokered tracing

DTrace on stock FreeBSD is an all-or-nothing privilege: opening a consumer
on `/dev/dtrace` requires root, and once you have it, you have kernel-wide
introspection. `traced(8)` replaces that uid gate with a capability gate. It
publishes `system.Trace` as a socket-free service provider (see
[serviced](../system/serviced.md)) and is the only program that opens
`/dev/dtrace`; an *authorized* client receives a raw DTrace consumer
descriptor without ever holding root or opening the device itself.

What the client gets, and on what terms:

- **Authorization by label.** Policy is a default-deny allow-list of session
  labels in `/etc/traced.allow`, derived from the caller's unforgeable
  channel label — never uid, PID, or path (see the
  [authority model](../security/authority-model.md)). Holders of
  `SERVICE_RIGHTS_ADMIN` bypass the list. The privileged `/dev/dtrace` open
  happens only for a session that has already passed policy, so live kernel
  consumers never outnumber authorized sessions.
- **An attenuated descriptor.** Before delivery the consumer is narrowed
  with `cap_ioctls_limit(2)` to the fixed set of 15 ioctls `libdtrace`
  issues; anything else fails `ENOTCAPABLE`. Unmodified `libdtrace` works
  unchanged, but the descriptor is a DTrace consumer and nothing more
  general.
- **A safe worker.** Each client is served by a dedicated `pdfork(2)`ed
  worker that drops to `NOPRIVS` and enters capability mode immediately
  after the open, and holds a parent-liveness back-channel so a crashed or
  disconnected client cannot leave an orphaned privileged consumer enabled
  in the kernel.

Clients link `libtracecmp(3)` (`tracecmp_open`/`tracecmp_consumer_fd`) and
feed the descriptor straight to libdtrace; nothing about tracing appears in
their manifests.

**Known limitation: policy is coarse.** A label on the allow-list receives a
full raw consumer — the complete kernel-introspection surface DTrace
exposes. There is no per-provider, per-probe, or per-action attenuation;
`traced` reduces *who* can trace and *how the consumer is obtained*, not
*how much* an authorized tracer can see — finer-grained policy would need
kernel support, since a userland broker cannot police enables it has
already delegated.

## Packaging

Each tool ships in its own pkgbase package with `dbg` and `man`
subpackages: `packages/hwtlm` unconditionally, `packages/bsdinstruments`
under `MK_DTRACE`, and `bsdtrace` (amd64-only) with metadata in
`release/packages/ucl/bsdtrace-all.ucl`.

Structured logging is a separate service, LogCmp, which shares the
OpenTelemetry orientation; DTrace remains the dynamic-instrumentation layer
both build on.
