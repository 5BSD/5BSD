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
holds = ["system.notify.system"];   # anointments this unit carries

control = "system";      # who may manage it: core | system | user
visible = "system";      # who may see/reach it: system | user
restart = "on-failure";
stop_timeout = 10;
watchdog { interval = 30; }   # liveness deadline (opt-in; omit to disable)
limits { memory = "512M"; nproc = 64; nofile = 1024; }
umask = "0077";
level = "standard";      # service level: background | standard | interactive
```

## The three-axis policy model

A unit's place in the plane is fixed by three independent policy axes, each a
single manifest key. They answer three different questions and never collapse
into one another — "who may manage a service" is deliberately decoupled from
"who may see it," and both from "what scheduling weight it runs at."

| Axis | Key | Question | Values |
|------|-----|----------|--------|
| Control | `control` | Who may start/stop/reload it? | `core`, `system`, `user` |
| Visibility | `visible` | Who may look it up / reach it? | `system`, `user` |
| Service level | `level` | What scheduling weight does it run at? | `background`, `standard`, `interactive` |

### Control — the management class

`control` decides who may act on the unit's lifecycle, and it is enforced
before any privilege check:

- **`core`** — the trusted computing base. No principal manages a `core`
  unit at runtime, `root` included. `switchboardctl stop` on a `core` unit
  fails with `EPERM` *before* authority is even consulted, so there is no
  privilege to escalate into. This is the plane's analogue of macOS SIP:
  authority over the TCB is removed from the system, not merely gated.
- **`system`** — base services an *operator* manages. Managing one takes
  operator authority (the `admin_rights` grant in principal policy), which
  `root` does not carry by default; a bare `uid 0` login cannot touch them.
- **`user`** — services a user added and owns (see per-user agents below).
  The owning uid manages its own; an operator may also manage them.

`control` defaults to `system` when the key is absent. There is no "root is
magic" path anywhere — `uid 0` is just another principal, and authority comes
from the held capability, never the uid.

### Visibility — reach

`visible` decides who may resolve and connect to the unit's endpoints, a
separate question from who may manage it. `system` endpoints live in the
system domain; `user` endpoints are reachable from a user session. Per-endpoint
`requires` anointments gate individual endpoints on top of this (a `system`
service can still expose one endpoint that any holder of the right anointment
may reach). Manage and see never bleed together: a unit can be operator-managed
(`control = "system"`) yet user-visible, or user-owned yet invisible to the
system domain.

### Service level

`level` sets scheduling weight. `background` and `standard` are free to any
unit. `interactive` is a *privilege*, not a free-for-all: it is a real
scheduling boost, so a non-system unit that asks for it is clamped back to
`standard` at load. Only a unit the plane trusts (a `system`/`core` unit) keeps
the interactive boost. Declaring the level you want costs nothing; being granted
the elevated one is gated.

## No resource grants in the manifest

A unit declares **no** resource capabilities — eager grant syntax (a top-level
`provides`, `requires`, `descriptors {}`, `kmod_requires`, …) is rejected. The
one `requires` that exists sits inside an `activation.ipc` entry and names
anointments a caller must hold, not resources the unit gets (see
[IPC Anointments](../security/ipc-anointments.md)). The manifest says only
how to launch the program; the program acquires whatever it needs at runtime,
by name, every grant scoped to its own unforgeable channel label: files and
devices, mutable storage (`BSDFilesystem`), jails (`BSDNamespace`), kernel
modules (`BSDExtension`), and vsock endpoints (`BSDVM`), each through its
`service_*(3)` call in `libservice(3)`. Brokered outbound networking is its own
chapter: [BSDNetwork](BSDNetwork.md).

### The one exception: system gates

A small `capabilities {}` object does survive, and it declares authority of a
different kind: not a resource the unit is handed, but the `mac_capability`
**system gates** a born-in-capability-mode broker holds so it can perform a
privileged kernel operation on its clients' behalf. Only the base brokers use
it — `BSDTime` (`settime`), `BSDSysctl` (`sysctl` plus an `isolate` list),
`BSDExtension` (`kldload`, `kldunload`) and `BSDNamespace` (`jail`); an
application never needs it.

```ucl
capabilities {
    system  = ["sysctl"];                       # gate names, distinct
    isolate = ["kern.maxfiles", "kern.maxproc"];  # sysctl only: OIDs it alone writes
}
```

- `system` — an array of distinct gate names from the fixed set `kldload`,
  `kldunload`, `reboot`, `swapon`, `swapoff`, `sysctl`, `kenv`, `kenv_read`,
  `acct`, `audit`, `settime`, `jail` (the same names `capsule.conf(5)` accepts
  in `claims.system`). At launch `switchboard` has `capsule` mint one
  system-gate token carrying exactly these gates and delivers it as a
  bootstrap capability; the program authorizes it with
  `service_provider_authorize_capabilities(3)` and performs the operation
  *through* the gate (`service_system_settime(3)`, `service_system_sysctl(3)`,
  `service_system_kldload(3)`, `service_system_jail_set(3)`, …). The raw system
  call stays refused in capability mode, so the sandbox is never loosened. The
  declaration is the grant: the manifest is opened with `O_VERIFY`, so under
  `mac_veriexec` a unit's gate set is exactly what its verified bundle says.
- `isolate` — at most 64 sysctl OID names (each shorter than 128 bytes), legal
  only alongside the `sysctl` gate. `switchboard` resolves them with
  `sysctlnametomib(3)` and has the token minted in its *scoped* form: the unit
  becomes the sole writer of exactly those OIDs outside `capsule`, and any other
  process's direct `sysctl(3)` write to them is denied by the kernel
  (`docs/capability-sysctl-isolation.md`). A bare `sysctl` gate with no
  `isolate` list, or `sysctl` mixed with another gate, is refused at launch.

The block is stripped from any bundle loaded from a per-user agent directory,
and a unit that declares it receives one extra bootstrap token descriptor.
Everything else about a broker's manifest is ordinary: `BSDTime` is
`control = "core"`, runs as the unprivileged `capability` user, and is born in
capability mode — the token, not the uid, is its authority.

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

`limits`, `umask`, and `level` are policy applied in the child after
`pdfork(2)` and before `exec`, so they bind the image from its first
instruction: `limits` become `setrlimit(2)` ceilings (`core` defaults to 0),
`umask` defaults to `0077`, and `level` maps to scheduling priority (subject to
the interactive-boost gate above). The MAC integrity shield (`protect`)
separately covers no-new-privileges, W^X, and ptrace/signal isolation.

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

A top-level `holds = ["…"]` lists the anointments this unit carries when it
looks endpoints up; absent means none, and a unit holding nothing still
reaches every open endpoint. `*` is never valid here. The whole mechanism,
the naming rules, and how a login session gets its set are in
[IPC Anointments](../security/ipc-anointments.md).

## Per-user agents

A user can run their own long-lived agents without operator help. Each user has
an agent root at `/Capabilities/Users/<uid>/Agents`, created on demand: the
first time that user opens their control channel, `switchboard` scans the
directory and loads any `.cap` bundles it finds there. Trust for these bundles
is rooted in the **owning uid**, not `root` — the tree must be owned by that
uid and not group/other-writable.

Whatever a per-user bundle declares, `switchboard` confines it: `control` is
forced to `user` and `visible` to `user`, the unit is barred from minting
authority or resolving users, and it carries no system domain reach. A per-user
agent therefore manages and sees only within its owner's world; it cannot become
a system service by asking to be one. The interactive boost is likewise unheld,
so a user agent that declares `level = "interactive"` runs at `standard`.

## Private helper units

A bundle may carry units that exist only for the bundle itself. A unit whose
activation is `helper = true` (XPC-style) is launched only when a sibling unit
in the same bundle calls `service_helper_open(3)` for it; it declares no other
activation source. switchboard reaches it through a synthetic bundle-local name
(`helper.<bundle-id>.<unit>`) that global lookup rejects, so the helper is
invisible outside its own `.cap` — nothing in the wider plane can resolve,
connect to, or launch it. The reserved `helper.` endpoint prefix is refused
anywhere else in a manifest, so one bundle cannot name or impersonate another's
private helper. This lets a bundle factor an indexer or converter out of its
public face without exposing a new endpoint to the whole plane.

## Validation and limits

Unknown keys, duplicate keys, UCL directives, symlinked manifests, and
oversized manifests fail closed, and bundle counts and sizes are bounded
(the ceilings are in `switchboard(5)`). Base bundles install in
`/Capabilities/System`, site bundles in `/Capabilities`; every loaded object
must be root-owned and not group/other-writable, and symlinks and special
files are rejected. `switchboardctl verify` and `switchboard` share the same strict
parser, so validation and runtime loading cannot diverge.

Reference: `switchboard(5)`.
