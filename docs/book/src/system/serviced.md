# serviced

`serviced(8)` is 5BSD's service manager. It is started by `oracled(8)` (PID 1)
as a single `pdfork(2)` child, inherits a `mac_capability` channel for
requesting activation tokens, channels, coalitions, and pre-exec kernel-module
prerequisites from the oracle, and owns the service world: native capability
services, the transitional `/etc/rc` boot, oneshots, and on-demand
(socket-activated) services. Sources: `usr.sbin/serviced/`,
`usr.sbin/servicectl/`, `lib/libservice/`; design:
`docs/service-architecture-plan.md`, status: `docs/service-daemon.md`.

## Architecture

serviced generalizes its registry and dependency graph over heterogeneous
unit kinds (`SVC_KIND_NATIVE`, `SVC_KIND_RC`, `SVC_KIND_ONESHOT`, plus
scaffolded `TARGET` and `TIMER` kinds). At startup it:

1. Inherits the oracle channel fd (`ORACLED_CHANNEL_FD`) and delegated
   service-instance fds; registers the channel for EOF detection so oracle
   death is observed.
2. Applies an inherited capprotect shield (ambient signals including
   `SIGKILL`/`SIGCONT`, ptrace, ktrace, core dumps are denied; oracled keeps
   stop authority through the procdesc from `pdfork(2)`).
3. Runs `/etc/rc autoboot` as a oneshot and waits for it, however long it
   takes (transitional rc world — see the rc integration chapter).
4. Scans capability bundles from `/Capabilities/System` and `/Capabilities`,
   topologically sorts services (Kahn's algorithm; duplicate labels,
   duplicate `provides` names, unknown providers, and dependency cycles are
   fatal), and launches each via `pdfork(2)`.
5. Binds the control socket `/var/run/serviced.sock` (only after rc has
   remounted `/` read-write) and sends `ORACLE_OP_READY` to PID 1 —
   the boot-convergence signal.

## Service definitions

Native services ship as verified `.cap` bundles whose manifest is a UCL
object (format: `serviced(5)`, and [Service Manifests](manifests.md)). The
manifest declares the program, credentials, `provides` names, required
`components` (`filesystem`, `network`), delegated `capabilities` (paths,
files, network, jails, vsock, services, system gates), `restart` policy,
`stop_timeout`, `max_failures`, `kmod_requires`, and an optional execution
jail:

```ucl
schema = "org.5bsd.serviced.service"
schema_version = "1.0.0"
bundle_id = "org.example.exampled"
program = "exampled"
provides = "org.example.exampled"
components = [ "network" ]
restart = "on-failure"
stop_timeout = 10
```

There are no `requires`/`on_demand` manifest keys: global dependencies are
acquired dynamically through the typed libraries, and all public named
services are launched on first connection. (The `*.plist` files in the source
tree root are clang static-analyzer output, not service definitions.)

## Lifecycle

Each service is launched with `pdfork(2)`; serviced watches the process
descriptor via `EVFILT_PROCDESC` for `NOTE_EXEC`, `NOTE_CAPMODE`, and
`NOTE_EXIT`, and enlists the service in a coalition (component workers are
enlisted before the leader is released). States:

```text
STOPPED → STARTING (pdfork, awaiting NOTE_CAPMODE)
        → RUNNING  (capability-mode entry independently confirmed
                    with pdincapmode(2))
        → STOPPING (SIGTERM via pdkill(2); SIGKILL after stop_timeout,
                    default 5 s)
```

Restart policies are `never`, `always`, and `on-failure`, with linear backoff
for rapid deaths (2 s × restart count, capped at 30 s; counter resets after
60 s of uptime) and a circuit breaker: after `max_failures` consecutive rapid
failures (default 10) the service is disabled until a manifest reload. At
launch serviced mints capability tokens over the oracle channel; unclaimed
resources are auto-claimed dynamically with reference counts and released
when the service exits. During daemon shutdown, services stop in reverse
dependency order. Every lifecycle event emits a DTrace probe through the
`serviced` provider (`svc__start`, `svc__exit`, readiness, naming, fd-reserve
and fd-pressure events).

serviced also operates the naming registry: providers expose reverse-domain
names, no name becomes connectable before the provider's complete check-in
plus verified capability-mode entry, and named services launch on first
client connection.

## Administration

```sh
servicectl status              # daemon status
servicectl services            # per-service state
servicectl stop <label>        # stop a service
servicectl reload              # re-scan bundles (also: SIGHUP via oracled)
servicectl install <path.cap>  # install a bundle
servicectl verify <path.cap>   # verify bundle signatures/structure
servicectl bundles             # registered bundles
```

Commands travel over `/var/run/serviced.sock`. Descriptor hygiene is
explicit: serviced raises `RLIMIT_NOFILE` to `kern.maxfilesperproc`, keeps an
eight-descriptor confined reserve, and fails launches or brokered connections
with `EMFILE`/`ENFILE` before partially allocating headroom.

## libservice client API

Managed programs use `lib/libservice` (`libservice(3)`) rather than raw
protocol. A provider's startup sequence makes each privilege transition
explicit:

```c
service_provider_create(&prov);
service_provider_authorize_capabilities(prov); /* activate minted tokens */
service_provider_protect(prov, flags);         /* capprotect shield */
service_provider_expose(prov, "org.example.exampled", &lsn);
service_provider_enter_capability_mode(prov);  /* cap_enter */
service_provider_ready(prov);                  /* readiness check-in */
```

Consumers use `service_acquire()` / `service_capability_open()` to reach
named services, and `service_local_component_open()` for the process-local
filesystem/network components serviced injects before exec. Channel waiting
is kqueue-based (`channel_wait()`); capability channels are kqueue-only and
report `POLLNVAL` to `poll(2)`.

**Status.** A known open issue in libservice's `service_dispatch` loop:
after the kqueue-only conversion, a thread blocked in `channel_wait()` is not
promptly woken by a cross-thread `service_client_close`, and an earlier
busy-poll behavior in the dispatch path is still being worked
(`docs/service-daemon.md` §3a). Targets and timers (cron replacement) and
user-scoped units are designed but not yet functional (roadmap phases 3–5).

## Capability components

The capability component framework (`docs/capability-components-roadmap.md`)
distinguishes three mechanisms, and each typed client library commits to
exactly one:

1. A **local component** replaces ambient authority removed from a supervised
   process — currently `filesystem` and `network`. serviced constructs a
   private session with the provider *before* exec, enlists the provider
   worker in the consumer's coalition, and injects a confined channel as the
   `FILESYSTEMCMP` or `NETWORKCMP` bootstrap entry (a descriptor number, not
   a name). Local components are not globally discoverable, and the injected
   channels are non-transferable and locked against fork/exec propagation.
2. A **global service** provides functionality under reverse-domain names
   declared in `provides`; the provider claims each name with
   `service_provider_expose()` and is launched on first connection.
3. A **capability** is kernel authority delegated directly as a descriptor or
   activation token — neither a component nor a named service.

Providers are ordinary verified `.cap` bundles launched and supervised by
serviced like any other native service (oracled stays in the loop only for
tokens, coalitions, and kernel-module prerequisites). The base providers,
all under `usr.sbin/`, run as the pkgbase `capability` user:

| Provider | Bundle / names | Role | ctl tool |
|---|---|---|---|
| `localfilesystem` | `org.5bsd.FileSystemCmp` | scratch, persistent, and read-only-bundle namespaces with durable object/byte quotas | `filesystemcmpctl` |
| `localnetwork` | `org.5bsd.NetworkCmp` | kernel TCP/UDP through a provider-owned socket table; per-session Casper DNS | `networkcmpctl` |
| `logd` | `org.5bsd.LogCmp` / `org.5bsd.log` | structured persistent logging with identity-scoped retained queries | `logctl` |
| `bsdnotify` | `org.5bsd.NotifyCmp` / `org.5bsd.notify` | global event service; default-deny publish/subscribe until an identity ACL is granted | `notifyctl` |
| `localcrypto` | `org.5bsd.CryptoCmp` | local authority-replacement provider for `DTYPE_CRYPTO` | — |

Each ctl tool is a strict `configtest` validator plus a bounded diagnostic
client for its service; `tracectl` plays the same role for the tracing
service (`org.5bsd.trace`, provider `traced`), validating the
`/etc/traced.allow` label policy. The two local-component executables carry
the mandatory `cmp` suffix on their bundle identity; global providers keep
daemon names.

Manifest linkage is deliberately minimal. A consumer declares only
`components = ["filesystem", "network"]`; there is no provider selection,
versioning, sharing, or options field — provider policy (quotas, network
policy) is provider-owned, not manifest-injected, so a manifest cannot widen
its own authority. A provider declares `provides` and may route each name to
a different listener; serviced's registry reserves the complete `provides`
set before the process exists and rejects READY until every name is claimed.

Worked example — a supervised service that keeps state but has no ambient
filesystem access:

```ucl
# /Capabilities/org.example.cached.cap manifest
program = "cached"
provides = "org.example.cached"
components = [ "filesystem" ]
```

At launch, serviced asks `localfilesystem` (starting it on demand) for a new
session bound to `org.example.cached`'s identity, enlists that provider
worker in the consumer's coalition, and injects the session channel before
exec. The program opens it with
`service_local_component_open(ctx, interface, version, &fd)` and uses
`libfilesystemcmp` path contexts rooted at its delegated namespace — `..`
clamps at the root, quotas are durable, and `filesystemcmp_sync()` is the
explicit stable-storage boundary. An operator inspects the injected session
with `filesystemcmpctl`. Registration, routing, component construction,
policy denials, and teardown all emit DTrace probes and BSM audit records.
