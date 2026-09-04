# ObservableBSD

Observability on 5BSD is one story told at three depths: what the system can
*emit* (OpenTelemetry metrics and traces from the ObservableBSD tool suite),
what it can *instrument* (a broadened DTrace and a kernel hardware-tracing
framework), and who is *allowed to look* (`traced`, the capability broker
that replaces DTrace's root requirement). This chapter covers all three.

## The tool suite

The suite is written in C, ships in the base system as ordinary `5BSD-*`
packages, and shares one OpenTelemetry export library (`libotelexport`) that
can stream results as text, JSONL, folded stacks for flame graphs, or
OTLP/HTTP to a collector.

**bsdinstruments** is a DTrace profiler with an Apple-Instruments-style
catalog of bundled profiles — syscalls, scheduler, networking, VFS/VM,
locks, and the 5BSD-specific providers (capability runtime, authority,
casper, audit, bhyve). It runs a profile through libdtrace and streams the
decoded results in any of the output formats above.

```sh
bsdinstruments list
bsdinstruments run tcplife
```

**hwtlm** collects hardware telemetry — CPU power, per-core temperatures and
frequencies, C-state residency, thermal zones, GPU state — and can bracket a
single command to report its energy and thermal cost. The power counters are
x86-specific; the sensor paths are architecture-independent, so the tool
degrades cleanly elsewhere.

```sh
hwtlm watch
hwtlm exec -- make -j8 buildworld
```

**bsdtrace** captures control flow with Intel Processor Trace through the
kernel's HWT hardware-trace framework and decodes it into symbolized calls,
per-function profiles, call trees, and folded stacks. Intel PT is an
Intel-only CPU feature, so bsdtrace requires Intel silicon; saved traces
carry the capture machine's timing metadata so they decode correctly
offline and cross-machine.

```sh
bsdtrace exec -- ls -l /tmp
bsdtrace decode -f folded trace.pt
```

Reference: `bsdinstruments(8)`, `hwtlm(8)`, `bsdtrace(8)`.

## DTrace and hardware tracing

The tools stand on instrumentation 5BSD itself broadened. Security-relevant
base userland carries USDT providers — Casper and its services, the login
and service-dispatch programs, jail and syslog paths — and the
`bsdinstruments` catalog matches the providers the system ships. The kernel
carries the machine-independent HWT hardware-trace framework with
per-architecture backends (Intel PT on amd64, ARM SPE on arm64) feeding
`bsdtrace`, and the WASPNest virtio device models expose their own USDT
providers.

## traced: brokered tracing

DTrace is traditionally an all-or-nothing privilege: opening a consumer on
`/dev/dtrace` requires root, and once you have it, you have kernel-wide
introspection. `traced` replaces that uid gate with a capability gate. It
publishes `system.Trace` as a socket-free provider (see
[serviced](../system/serviced.md)) and is the only program that opens
`/dev/dtrace`; an authorized client receives a rights-limited DTrace
consumer descriptor without ever holding root or opening the device itself.

Authorization is a default-deny allow-list keyed on the caller's unforgeable
channel label — never uid, PID, or path (see the
[authority model](../security/authority-model.md)). The delivered descriptor
is narrowed to exactly the operations `libdtrace` needs, so unmodified
DTrace tooling works unchanged but the descriptor is a DTrace consumer and
nothing more general; each client is served by its own sandboxed worker, so
a crashed or disconnected client cannot leave an orphaned privileged
consumer enabled in the kernel.

The honest limitation: policy is coarse. An allow-listed label receives the
full kernel-introspection power DTrace has — `traced` narrows *who* can
trace and *how the consumer is obtained*, not *how much* an authorized
tracer can see.

Reference: `traced(8)`, `libtracecmp(3)`.

Structured logging is a separate service, LogCmp, which shares the
OpenTelemetry orientation; DTrace remains the dynamic-instrumentation layer
both build on.
