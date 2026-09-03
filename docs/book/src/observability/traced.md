# traced: the DTrace capability broker

DTrace on stock FreeBSD is an all-or-nothing privilege: to open a consumer on
`/dev/dtrace` you are root (or hold the equivalent `dtrace_*` privileges), and
once you are, you have kernel-wide introspection. That is exactly the shape of
authority the capability plane exists to dissolve. `traced(8)` is 5BSD's answer:
a socket-free service provider that publishes `system.Trace` and hands an
*authorized* client a raw DTrace consumer descriptor — attenuated to precisely
the ioctls `libdtrace` needs — without that client ever holding root or opening
the device itself.

`traced` is the DTrace-facing sibling of the tooling described in
[DTrace and Hardware Tracing](./dtrace.md): that chapter covers what the fork
instruments and how USDT/hwt were hardened; this one covers who is allowed to
*consume* it and how the privilege is brokered.

| Component | Location |
|-----------|----------|
| Provider, policy, and worker | `usr.sbin/traced/` |
| Client library `libtracecmp(3)` | `lib/libtracecmp/` |
| Policy file | `/etc/traced.allow` |
| Service bundle | `usr.sbin/traced/capbundle/` |
| Tests | `usr.sbin/traced/tests/`, `lib/libtracecmp/tests/` |

## Why a broker, and not a privilege

The consumer descriptor `libdtrace` drives is powerful and generic: with it a
program can enable any provider, read any principal buffer, and walk kernel
state. There is no way to hand out "a little DTrace." The classic answer is to
gate the whole thing behind uid 0, which forces every tracer — a profiler, a
one-off `dtrace` invocation, a monitoring agent — to run as root.

`traced` replaces the uid gate with a capability gate. It is the only program
that opens `/dev/dtrace`; it derives authority from the caller's **unforgeable
channel label** (never uid, PID, or path — see the
[authority model](../security/authority-model.md)); and it returns the consumer
descriptor already narrowed by `cap_ioctls_limit(2)` to the fixed set of ioctls
`libdtrace` issues. A client that receives the descriptor can run DTrace and
nothing else with it — it cannot re-widen the descriptor, reopen the device, or
reach any other part of the kernel surface.

## The service model

`traced` follows the standard socket-free provider pattern (see
[serviced](../system/serviced.md) and
[Writing a Service Provider](../development/writing-components.md)): it publishes
`system.Trace` in `activation.ipc`, stays stopped until the first lookup, and on
each connection `pdfork(2)`s a dedicated worker for that one client. The worker
authenticates the caller by channel label, and only then does the privileged
side open a consumer.

That last point is a deliberate change from the naïve design. `traced` does
**not** hold a pool of open consumers, and it does **not** open a consumer at
accept time. The privileged `/dev/dtrace` open happens **only for a session that
has already passed policy** — an unauthorized or misbehaving client never causes
a privileged consumer to exist. This keeps the count of live kernel consumers
equal to the count of authorized, live tracing sessions, and no more.

### Per-worker liveness and privilege drop

Two properties make the per-client worker safe to run against a raw consumer:

- **Parent-liveness back-channel.** Each worker holds a descriptor back to the
  parent whose only job is to signal liveness. If the parent (or the client
  session it represents) goes away, the worker observes EOF on that channel and
  shuts the consumer down gracefully. A crashed or disconnected client therefore
  cannot leave an orphaned privileged consumer enabled in the kernel.
- **Privileges dropped after the open.** The privileged open is the worker's
  last act as a privileged process. Having obtained the consumer descriptor, the
  worker drops to `NOPRIVS` and enters capability mode (`cap_enter(2)`), so the
  process that actually talks to the client for the rest of the session holds no
  ambient authority — only the attenuated descriptor it is about to deliver.

The descriptor is delivered with the transfer discipline described in
[Capability Transfer](../security/capability-transfer.md): the client receives
the consumer once, and the ioctl allow-list travels with it.

### The ioctl allow-list

`libdtrace` drives a consumer through a small, fixed vocabulary of ioctls —
program compilation, enabling, buffer snapshot, aggregation snapshot, status,
option get/set, and teardown among them. `traced` enumerates exactly those
**15** ioctls and applies them with `cap_ioctls_limit(2)` before delivery. Any
other ioctl on the descriptor fails with `ENOTCAPABLE`. The allow-list is the
functional contract: it is wide enough that an unmodified `libdtrace` works
unchanged, and narrow enough that the descriptor is a DTrace consumer and
nothing more general.

## Policy: default-deny label allow-list

Authorization is a default-deny allow-list of session labels kept in
`/etc/traced.allow`. A label that appears in the file may open a tracing
session; every other label is refused before any consumer is opened. Holders of
`SERVICE_RIGHTS_ADMIN` bypass the list (the administrative override used by the
operator plane). Policy is loaded and validated **before** the provider enters
capability mode, in the same fail-closed style as the other providers'
config loaders: a malformed or unsafe policy file keeps the previous decision
set rather than failing open.

## Client surface

Consumers link `libtracecmp(3)` and reach the broker lazily on first use — a
unit declares nothing about tracing in its manifest, exactly as with the other
capability services:

```c
tracecmp_open(&t);              /* connect to system.Trace, receive consumer */
tracecmp_consumer_fd(t);        /* the attenuated /dev/dtrace descriptor */
tracecmp_close(t);              /* EOF the worker; consumer torn down */
```

The returned descriptor is fed straight to `libdtrace`; from the client's point
of view it is an ordinary DTrace consumer that happens to have arrived over a
capability channel instead of an `open("/dev/dtrace")`.

## Known limitation: policy is coarse

The honest gap — the kind this book flags rather than papers over — is that
`traced`'s policy granularity stops at the session label. A label is either on
the allow-list or it is not, and a label that is on it receives a **full raw
consumer**: the complete kernel-introspection surface DTrace exposes, every
provider and every action. There is no per-provider, per-probe, or per-action
attenuation. The `cap_ioctls_limit` allow-list constrains the *shape* of the
descriptor (it is a DTrace consumer, not a general device handle) but not the
*reach* of tracing once you legitimately hold one.

Finer-grained policy — restricting an allowed label to particular providers
(say, USDT only, no `fbt`), particular probe scopes, or particular
destructive actions — is future work. It almost certainly belongs partly in the
kernel (the consumer descriptor would have to carry the constraint) rather than
purely in `traced`, since a userland broker cannot police enables it has already
delegated. Until that lands, `traced` should be read as reducing *who* can trace
and *how they obtain the consumer*, not *how much* an authorized tracer can see.
