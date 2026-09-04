# The Hybrid Model: BSD plus a Capability SDK

5BSD is a hybrid, and the word means something concrete for a developer. You
get a whole, ordinary BSD system — `sh`, `cc`, ZFS, jails, `rc(8)`, ports and
packages, the Linux ABI, every man page you already know. Nothing forces a
program into the capability plane. A daemon written the classic way — bind a
socket, drop privileges, log to syslog, start from `rc.d` — runs on 5BSD
exactly as it does on FreeBSD.

Beside that familiar system runs a second one: the **capability plane**, where
authority is a held, unforgeable descriptor rather than a uid or a path (see
[The Authority Model](../security/authority-model.md)). You opt a service into
it not by rewriting it against a strange new OS, but by using an **SDK** —
`libservice` and `libcapbundle` — to do two small things:

1. Make the program a **capability provider**: expose a named service over a
   `libservice` channel instead of a raw socket.
2. Ship it as a **capability bundle**: a `.cap` directory whose manifest says
   how to launch the program — nothing more.

Do that and the program is reachable *by name*, launched on demand, sandboxed
in capability mode, and served to each client in its own isolated worker — and
you wrote something that still looks and feels like a normal BSD daemon. This
is the hybrid: **the BSD you know, plus an SDK that lets you write
capabilities.** Adoption is per-service and reversible; the machine keeps
working at every step (see the "hybrid by design" principle in
[Architecture](../architecture.md)).

This chapter builds one capability end to end — an `Echo` service — to show the
whole shape in one place. For the exhaustive provider mechanics see
[Writing a Service Provider](writing-components.md); for the full manifest
grammar see [Capability bundle manifests](../system/manifests.md).

## The two ways to write a service

| | The BSD way (still supported) | The 5BSD capability way |
|---|---|---|
| Reached by | a socket path / port | a **name** (`org.example.Echo`) |
| Started by | `rc.d`, always running | `serviced`, launched on first lookup |
| Client identity | `getpeereid(3)`, uid | the unforgeable **channel label** |
| Sandbox | opt-in (`cap_enter`, jails) | capability mode by construction |
| Isolation | you fork/thread it | one `pdfork` worker per client, for free |
| Replaceable | rebuild clients | swap the binary; the name is the contract |

You choose per service. A program can even start life as an `rc.d` daemon and
become a capability later without its consumers noticing, because they resolve
a name, not a binary.

## 1. The wire protocol

A capability is a typed request/reply protocol over a channel. Define it once
in a shared header; both the provider and its client library include it.

```c
/* echo_proto.h — the Echo capability's wire contract. */
#ifndef ECHO_PROTO_H
#define ECHO_PROTO_H
#include <stdint.h>

#define ECHO_SERVICE_NAME  "org.example.Echo"   /* reverse-DNS: out-of-tree */
#define ECHO_MAX           240

struct echo_request  { uint32_t length; uint8_t data[ECHO_MAX]; };
struct echo_reply    { int32_t status; uint32_t length; uint8_t data[ECHO_MAX]; };
#endif
```

The `system.` prefix is reserved for base-system capabilities; third-party
services use a reverse-DNS name so they never collide with the base set.

## 2. The provider (server side)

A provider's `main()` is a short, fixed `libservice` sequence — create the
provider, harden it, publish the name, enter capability mode, and signal ready.
It reads like the top of any daemon:

```c
#include <err.h>
#include <libservice.h>
#include "echo_proto.h"

struct service_provider *provider;
struct service_listener *listener;

if (service_provider_create(&provider) == -1 ||
    service_provider_authorize_capabilities(provider) == -1 ||
    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
        SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
    service_provider_expose(provider, ECHO_SERVICE_NAME, &listener) == -1 ||
    service_provider_enter_capability_mode(provider) == -1 ||
    service_provider_ready(provider) == -1)
        err(1, "echo: bootstrap");
```

Note what is *not* here: no `open("/dev/mac_capability")`, no socket, no
`getpeereid`. `serviced` launched this program with an unforgeable channel;
`service_provider_expose()` publishes the name on it. After
`enter_capability_mode()` the process can open no new global resources — it is
sandboxed by construction.

Each accepted client is served in its own `pdfork(2)` worker, so one client can
never see or stall another. The accept loop and the per-client handler:

```c
struct service_identity id = { .size = sizeof(id) };
int fd, pd;

while (service_listener_accept(listener, &id, &fd) != -1) {
        if (pdfork(&pd, PD_CLOEXEC | PD_DAEMON) == 0) {
                /* per-client worker: serves this one caller, then exits */
                serve_client(fd, id.client_label);
                _exit(0);
        }
        close(pd);
        close(fd);
}
```

(The in-tree providers add a barrier handshake so worker-setup failures
propagate, and `service_worker_protect()` + `cap_enter()` inside the worker;
`usr.sbin/auditbrokerd/auditcmp.c` is the smallest complete reference.)

The worker answers requests. `id.client_label` is the caller's **unforgeable
identity** — the kernel stamped it; the client cannot forge it — so a provider
scopes per-caller state by the label, never by a uid or a wire field:

```c
static void
echo_handle(struct channel_message *m)
{
        const struct echo_request *rq;
        struct echo_reply rp;

        memset(&rp, 0, sizeof(rp));
        if (channel_message_fd_count(m) != 0 ||          /* fail closed */
            channel_message_length(m) != sizeof(*rq)) {
                rp.status = EINVAL;
        } else {
                rq = channel_message_data(m);
                rp.status = (rq->length <= ECHO_MAX) ? 0 : EMSGSIZE;
                if (rp.status == 0) {
                        rp.length = rq->length;
                        memcpy(rp.data, rq->data, rq->length);
                }
        }
        channel_send_reply(m, &(struct channel_outgoing){
            .size = sizeof(struct channel_outgoing),
            .data = &rp, .length = sizeof(rp) });
}
```

If `Echo` needed anything from the rest of the system — a file, mutable
storage, a jail, a vsock endpoint — it would acquire it here, at runtime, *by
name*, each grant scoped to its channel label: `service_open_isolated(3)`,
`service_storage_open(3)`, `service_enter_namespace(3)`,
`service_vsock_listen(3)`. It never declares those in its manifest and is never
handed them at launch.

## 3. The bundle

Ship the program as a `.cap` directory. The manifest describes **only how to
launch it** — there is no `capabilities {}` block, because authority is
acquired at runtime, not granted by the manifest.

```text
Echo.cap/
├── Bundle.ucl
└── Units/
    └── echo.unit/
        ├── Unit.ucl
        └── bin/echo        # the provider binary from §2
```

`Bundle.ucl` — identity and the exact unit inventory:

```ucl
schema = "org.5bsd.capability-bundle";
schema_version = 1;

bundle_id = "org.example.echo";
version   = "1.0.0";
sequence  = 1;
publisher = "org.example";
units     = ["echo"];
```

`Units/echo.unit/Unit.ucl` — how to run it, and the name it publishes:

```ucl
user  = "capability";
group = "capability";

activation {
    ipc = ["org.example.Echo"];   # launch on first lookup of this name
}

restart = "on-failure";
limits { nofile = 64; nproc = 8; }
```

`activation { ipc = [...] }` is the whole integration: it reserves the name and
tells `serviced` to launch this unit the first time a client looks it up. (Use
`boot = true` instead, or as well, to start it during boot.) Install the bundle
under `/Capabilities` (site bundles) or `/Capabilities/System` (base bundles);
`serviced` verifies the tree is root-owned and closed-schema, then manages it.

## 4. The consumer (client side)

A client reaches the capability by name and makes typed calls. It does not know
or care which binary answers.

```c
#include <err.h>
#include <libservice.h>
#include "echo_proto.h"

struct service_session *s;
struct echo_request rq = { .length = 5 };
struct echo_reply rp;
int fd;

memcpy(rq.data, "hello", 5);
if (service_open(ECHO_SERVICE_NAME, &fd) == -1)      /* resolves the name */
        err(1, "open %s", ECHO_SERVICE_NAME);
if (service_session_create(fd, &s) == -1)
        err(1, "session");

struct service_message  out = { .size = sizeof(out), .data = &rq,
                                .length = sizeof(rq) };
struct service_reply    in  = { .size = sizeof(in),  .data = &rp,
                                .capacity = sizeof(rp) };
if (service_session_call(s, &out, &in, NULL) == -1)
        err(1, "call");
/* rp.status == 0, rp.data == "hello" */
```

`service_open()` triggers `serviced` to launch `Echo` if it is not already
running (the `ipc` activation), hands back a channel scoped to *this* client's
label, and the call round-trips to the per-client worker. For capabilities with
a richer surface you would wrap this in a small client library of typed calls
(`echo_say(...)`), exactly as the base system ships `libservice`,
`libcryptocmp`, `liblogcmp`, and the rest.

## What the SDK gave you

For roughly the code above — a fixed bootstrap, a request handler, and a
ten-line manifest — `Echo` gained properties a hand-rolled daemon has to build
and get right by hand:

- **Reach by name.** Consumers resolve `org.example.Echo`; you can replace the
  binary without touching them. The name is the contract.
- **Launched on demand,** supervised, restarted on failure, by `serviced`.
- **A capability-mode sandbox** entered before the first request.
- **Per-client isolation** — one `pdfork` worker per caller.
- **Unforgeable client identity** — `id.client_label`, kernel-stamped, the
  basis for any per-caller scoping.
- **Runtime, label-scoped authority** — files, storage, jails, and sockets
  acquired by name when needed, never pre-granted.

And you gave up nothing on the BSD side: the same host still runs stock daemons,
ports, and Linux binaries next to it. That coexistence — a familiar BSD system
you can extend, one capability at a time, with an SDK — is what "hybrid" means
in 5BSD.

## Where to go next

- The full provider mechanics, raw kernel services, the ISOLATION service, and
  process hardening: [Writing a Service Provider](writing-components.md).
- The complete bundle/unit grammar, activation sources (timers, calendars,
  socket, path, queue), and process policy: [Capability bundle
  manifests](../system/manifests.md) and [Capability
  Bundles](../security/capability-bundles.md).
- Why authority is a held descriptor, and how login sessions get one:
  [The Authority Model](../security/authority-model.md).
