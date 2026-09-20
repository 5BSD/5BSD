# Capability bundle manifests

`switchboard` loads applications from self-contained `.cap` directories. The
format has two levels: one bundle manifest owns identity and the unit
inventory; each unit has a smaller process manifest.

## Directory contract

```text
Mail.cap/
├── Bundle.ucl
├── Shared/                      bundle-wide Config/ Resources/ Libraries/
└── Units/
    ├── smtpd.unit/
    │   ├── Unit.ucl
    │   ├── bin/smtpd            default executable: bin/<unit-name>
    │   └── Config/
    └── indexer.unit/
        ├── Unit.ucl
        └── bin/indexer
```

At the bundle root only `Bundle.ucl`, `Shared`, and `Units` are accepted;
every name in `Bundle.ucl`'s `units` array must have exactly one
`Units/<name>.unit` directory. Configuration and static resources belong
inside the `.cap` tree, not in `/etc`; at launch `switchboard` sets
`CAPABILITY_UNIT_DIR` to the selected unit directory (a location, not new
authority). Mutable data is storage, obtained from
[`BSDFilesystem`](../storage/trustedzfs.md) at runtime, never written into the installed
bundle.

## Example

`Bundle.ucl` — identity, version ordering, unit inventory:

```ucl
schema = "org.5bsd.capability-bundle";
schema_version = 1;

bundle_id = "org.example.mail";
version = "2.4.1";       # display metadata
sequence = 17;           # monotonic update order
publisher = "org.example";
units = ["smtpd", "indexer"];
```

`Units/smtpd.unit/Unit.ucl` — how to run the program:

```ucl
arguments = ["--foreground"];
user = "capability";
group = "capability";

activation {
    boot = true;
    ipc = ["org.example.mail.smtp"];   # launch on first lookup
}
anointments = ["system.notify.system"];   # what this unit holds

restart = "on-failure";
stop_timeout = 10;
watchdog { interval = 30; }   # liveness deadline (opt-in; omit to disable)
limits { memory = "512M"; nproc = 64; nofile = 1024; }
umask = "0077";
band  = "standard";      # background | standard | interactive
```

## No capabilities block

A unit declares **no** capabilities — there is no `capabilities {}` block, and
eager grant syntax (a top-level `provides`, `requires`, `descriptors {}`, …) is
rejected. The one `requires` that exists sits inside an `activation.ipc`
entry and names anointments a caller must hold, not resources the unit gets
(see [IPC Anointments](../security/ipc-anointments.md)).
The manifest says only how to launch the program; the program acquires
whatever it needs at runtime, by name, every grant scoped to its own
unforgeable channel label: files and devices, mutable storage (`BSDFilesystem`),
jails (`BSDNamespace`), kernel modules (`BSDExtension`), and vsock endpoints (`BSDVM`),
each through its `service_*(3)` call in `libservice(3)`. Brokered outbound
networking is its own chapter: [BSDNetwork](BSDNetwork.md).

## Activation and process policy

Activation is always explicit and at least one mode is required. Demand
sources inside `activation` (details in `switchboard(5)`):

- `boot = true` — start during convergence.
- `ipc = ["name", { name = "…"; requires = ["…"]; }, …]` — reserve
  reverse-domain endpoints; launch on first lookup. A bare name is an open
  endpoint; an object with `requires` is gated on the named anointments.
- `socket` — socket activation.
- `timer { interval = N; }` — every `N` monotonic seconds.
- `schedule = "…"` — wall-clock calendar (five-field cron string or
  `hourly`/`daily`/…); `persistent = true` adds anacron-style catch-up. The
  plane's cron replacement; mutually exclusive with `timer`.
- `path { path = "/abs"; }`, `queue_directory = "/abs"`, `on_mount = true`.

`limits`, `umask`, and `band` are policy applied in the child after
`pdfork(2)` and before `exec`, so they bind the image from its first
instruction: `limits` become `setrlimit(2)` ceilings (`core` defaults to 0),
`umask` defaults to `0077`, and `band` maps to scheduling priority. The MAC
integrity shield (`protect`) separately covers no-new-privileges, W^X, and
ptrace/signal isolation.

## Liveness watchdog

`watchdog { interval = N; }` (seconds, 1…86400) opts a unit into a liveness
deadline. Once switchboard promotes the unit to running — sandbox entry for a
sealed unit, `service_ready(3)` for an ambient one — the program must call
`service_heartbeat(3)` at least every `N` seconds. Each heartbeat resets the
timer; a missed interval means the program has wedged, so switchboard kills it
and its `restart` policy relaunches it exactly as after a crash. The clock
starts at "running", not at the first heartbeat, so a program that hangs during
its own start-up is caught too.

This is the plane's analogue of systemd's `WatchdogSec=` / `sd_notify`: the
deadline is enforced by switchboard, but the program is responsible for pinging
from its own thread of control. Beat from the loop that does the real work — a
background thread that keeps ticking while a request handler is stuck defeats
the purpose. It applies to any unit, `SYSTEM` or `USER`, so end-user
applications get the same supervision as base services. It is off unless
declared; a stray heartbeat from a unit with no watchdog is accepted and
ignored. The mechanism touches no coalition or jail machinery — it is a plain
control-channel ping and a `kqueue` timer.

## Anointments

A top-level `anointments = ["…"]` lists the names this unit holds when it
looks endpoints up; absent means none, and a unit holding nothing still
reaches every open endpoint. `*` is never valid here. The whole mechanism,
the naming rules, and how a login session gets its set are in
[IPC Anointments](../security/ipc-anointments.md).

## Validation and limits

Unknown keys, duplicate keys, UCL directives, symlinked manifests, and
oversized manifests fail closed, and bundle counts and sizes are bounded
(the ceilings are in `switchboard(5)`). Base bundles install in
`/Capabilities/System`, site bundles in `/Capabilities`; every loaded object
must be root-owned and not group/other-writable, and symlinks and special
files are rejected. `switchboardctl verify` and `switchboard` share the same strict
parser, so validation and runtime loading cannot diverge.

Reference: `switchboard(5)`.
