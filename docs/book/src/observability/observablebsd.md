# ObservableBSD

ObservableBSD is 5BSD's observability tool suite: a DTrace profiler with an
Apple-Instruments-style profile catalog (`bsdinstruments`), a hardware
telemetry collector (`hwtlm`), a hardware execution tracer (`bsdtrace`), and
a shared OpenTelemetry export library (`libotelexport`). The suite began as
a Swift project (github.com/5BSD/ObservableBSD) and has been ported to C and
folded into the base system, because the Swift toolchain is not available on
ARM 5BSD. All components are pkgbase-tagged so they install and upgrade as
ordinary `5BSD-*` packages.

## libotelexport

`lib/libotelexport` is an internal static library shared by `bsdinstruments`
and `hwtlm`. An exporter consumes probe events and aggregation snapshots
from a tool's run loop and ships them to stdout (text, JSONL, or
folded/collapsed stacks for flame graphs) or to an OTLP/HTTP+JSON collector.
The OTLP path includes an asynchronous pthread sender, count- and time-based
batching, gzip compression via zlib, retry with backoff and `Retry-After`
handling, a minimal HTTP/1.1 client (http and https via OpenSSL, IPv6
literals, timeouts), RFC 8259 JSON escaping that keeps arbitrary probe bytes
valid JSON, and `OTEL_*` environment variable support. The public interface
is `lib/libotelexport/otelexport.h`; ATF-C unit tests live in
`lib/libotelexport/tests`.

## bsdinstruments

`cddl/usr.sbin/bsdinstruments` is a `MK_DTRACE`-gated DTrace profiler that
renders a catalog of 236 bundled `.d` templates covering syscalls, the
scheduler, TCP/UDP/IP, VFS/VM, locks, USDT-instrumented applications, and
5BSD-specific providers (capability runtime, authority, casper, audit, bhyve).
Profiles install to `/usr/share/bsdinstruments/profiles`. The tool applies
CLI filter/parameter/stack/duration flags, runs the profile through
libdtrace, and streams results as text, JSONL, folded stacks, or OTLP via
libotelexport. Its typed aggregation walk decodes
count/sum/min/max/avg/stddev and the quantize/lquantize/llquantize
histograms with correct inclusive bucket bounds, and symbolizes stack and
sym aggregation keys the way `dtrace(1)` does.

```sh
# Catalog and run a bundled profile
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
# Watch live sensors; measure energy over a command
hwtlm watch
hwtlm exec -- make -j8 buildworld
```

## bsdtrace

`usr.sbin/bsdtrace` is an amd64 tool (gated on `MK_PMC`) that captures
control flow with Intel Processor Trace through the `hwt(4)` framework and
so **requires Intel silicon** — Intel PT is an Intel-only CPU feature and
bsdtrace does not work on AMD processors (the `hwt(4)` framework itself is
machine-independent, with an ARM SPE backend on arm64). Captured traces
are decoded with libipt into symbolized calls, returns, jumps, and syscalls,
with per-function profiles, call trees, folded/speedscope stacks, and a
callers view. Subcommands are `exec`, `trace`, `list`, and `decode`. Traces
are saved as a `.pt` buffer plus a JSONL `.meta` sidecar recording the
capture machine's CPU identity, CPUID 0x15 TSC/CTC ratio, nominal frequency,
and address-filter setup, so offline and cross-machine decode feeds libipt
the values it needs for MTC timing. See `bsdtrace(8)` and the review history
in `usr.sbin/bsdtrace/REVIEW-FINDINGS.md`.

```sh
# Trace a command and decode the saved buffer offline
bsdtrace exec -- ls -l /tmp
bsdtrace decode -f folded trace.pt
```

The kernel side of Intel PT support (hwt/pt fixes, PTWRITE, overflow
records, ToPA allocation correctness) is already committed in `sys/`; see
the [DTrace and hardware tracing](dtrace.md) chapter.

## Packaging

Each tool is tagged into its own pkgbase package with `dbg` and `man`
subpackages:

- `packages/bsdinstruments/Makefile` and `packages/hwtlm/Makefile` define
  the package sets (both `PKG_SETS=optional`).
- Package metadata lives in `release/packages/ucl/bsdinstruments-all.ucl`,
  `hwtlm-all.ucl`, and `bsdtrace-all.ucl`.
- Commit `bb9f5be0208` wired `bsdinstruments` (under `MK_DTRACE`) and
  `hwtlm` into `packages/Makefile` so release builds ship them.

## Relationship to LogCmp

ObservableBSD covers metrics and tracing. Structured logging is a separate
effort, LogCmp (`docs/logcmp-unified-logging-design.md`), which shares the
OpenTelemetry orientation (normalized severity, typed attributes, batching)
but is its own service; DTrace remains the dynamic-instrumentation layer
both build on.

## Status

- libotelexport, bsdinstruments, hwtlm, and bsdtrace are committed to base
  with manual pages and ATF tests (commits `7458f62f86b`, `0a9042f5362`,
  `9000f7c975d`, `116fc7669d0`).
- The suite has passed a multi-round adversarial correctness review; the
  history is in `usr.sbin/bsdtrace/REVIEW-FINDINGS.md`.
- One known open kernel item: an overflow-record race in the PT backend's
  NMI-context enqueue path awaits verification on additional PT hardware.
- End-to-end DTrace validation inside a 5BSD guest VM is still an open
  work item.
