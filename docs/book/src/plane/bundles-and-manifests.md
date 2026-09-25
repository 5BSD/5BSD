# Bundles and Manifests

A capability bundle is a `.cap` directory: one `Bundle.ucl` that names the
bundle and lists its units, and one `Unit.ucl` per unit that says how to run
a program. It is 5BSD's install, configuration and execution boundary, the
thing a package installs and [switchboard](switchboard.md) loads. 5BSD has it
because rc.d scripts describe how to start a program with ambient authority,
and the plane needs a description that carries no authority at all: a
manifest says which program, as whom, when, and under what ceilings, and the
program acquires everything else at runtime by name.

The parser is `lib/libcapbundle` (libcapbundle(3)), shared verbatim by
switchboard and `switchboardctl verify`, so what verifies is what loads.

## Layout

```text
/Capabilities/System/Log.cap/
├── Bundle.ucl
├── Shared/                    optional, bundle-wide content
└── Units/
    └── bsdlog.unit/
        ├── Unit.ucl
        ├── bin/BSDLog         the program (default name: the unit name)
        ├── Config/bsdlog.conf delivered as CAPABILITY_CONFIG_FD at launch
        └── lib/               optional private libraries, appended to
                               LD_LIBRARY_PATH_FDS
```

`capbundle_open()` accepts only `Bundle.ucl`, `Units` and `Shared` at the
root and refuses anything else. Every name in `units` must have exactly one
`Units/<name>.unit` directory; an undeclared unit directory is not loaded. The
program is one filename below `bin/`, never a path. Mutable state never
lives in the bundle: a unit gets storage from
[BSDFilesystem](../providers/filesystem.md) and a per-launch scratch
directory under `/Capabilities/Run`.

Base bundles install under `/Capabilities/System`, applications under
`/Capabilities/Apps`, and a user's own agents under
`/Capabilities/Users/<uid>/Agents`. A unit's runtime identity is
`<bundle_id>/<unit>` (`system.Log/bsdlog`), independent of any name it
publishes.

## Verification

Loading is fail-closed at three layers. The UCL parser runs with implicit
arrays, macros, includes and file variables disabled and duplicate keys as
errors, and every manifest is opened with `O_VERIFY`, so under mac_veriexec
an unfingerprinted file cannot even be read. `validate_unit_schema()` in
`libcapbundle_parse.c` rejects any key outside the closed set below, any
value of the wrong type, and any value outside its range, with a diagnostic
naming the key. `capbundle_verify()` in `libcapbundle_verify.c` then walks
the tree with `fts(3)`:

| Check | Limit |
|---|---|
| manifest file size | 1 MiB (`CAPBUNDLE_MAX_UCL_SIZE`) |
| tree entries | 4096 |
| one file | 512 MiB |
| whole tree | 2 GiB |
| object types | directories and regular files only; a symlink or special file rejects the bundle |
| program | exists, regular, `S_IXUSR` |
| activation | at least one trigger |
| names | no duplicate `activation.ipc` name within the bundle; per-unit socket names unique |

switchboard adds ownership: the roots and everything under them must be
root-owned (or owned by the agent's uid under `Users/<uid>/Agents`) and not
group or other writable. There is no compatibility path for older formats;
`descriptors {}`, `kmod_requires`, top-level `provides` and the pre-rename
policy keys are rejected, never translated.

## Bundle.ucl

| Key | Type | Required | Constraint |
|---|---|---|---|
| `schema` | string | yes | exactly `org.5bsd.capability-bundle` |
| `schema_version` | int | yes | exactly 1 |
| `bundle_id` | string | yes | reverse-domain name, `[A-Za-z0-9._-]` with at least one dot, under 128 bytes |
| `version` | string | yes | display only, under 32 bytes |
| `sequence` | int | yes | positive; the registry keeps the highest sequence per `bundle_id` |
| `units` | array | yes | 1 to 32 unit names, each 1 to 63 bytes of `[a-z0-9-]`, unique |
| `author`, `publisher` | string | no | display only, under 128 bytes |
| `groups` | array | no | at most 4 group-container names (`[A-Za-z0-9._-]`, 1 to 63 bytes); each unit may then claim `Data/Shared/<group>` through `service_storage_open_group(3)` |

## Unit.ucl key reference

The closed top-level key set, in the order `validate_unit_schema()` lists it.
Absent keys take the default shown; `capbundle_parse_unit_ucl()` fills the
`struct svc_manifest` in `lib/libcapbundle/switchboard_manifest.h`.

| Key | Type | Default | Constraint | Controls |
|---|---|---|---|---|
| `program` | string | unit name | one filename, no `/`, no control characters | `bin/<program>` is opened `O_EXEC|O_VERIFY` and `fexecve`d |
| `activation` | object | required | see below | when the unit runs and which names it reserves |
| `restart` | string | `never` | `never`, `always`, `on-failure` | relaunch after exit |
| `control` | string | `system` | `core`, `system`, `user` | who may stop, start, unload or disable it; `core` refuses everyone |
| `capabilities` | object | none | see below | system gates a broker holds |
| `user` | string | `capability` | non-empty, under 64 bytes | credentials after `setuid` |
| `group` | string | `capability` | non-empty, under 64 bytes | `setgid` and supplementary groups |
| `stop_timeout` | int | 5 | 1 to 300 seconds | SIGTERM to SIGKILL grace |
| `max_failures` | int | 10 | 1 to 100 | circuit breaker threshold |
| `arguments` | array | none | at most 32 strings, each under 256 bytes; never shell-split | `argv[1..]` |
| `environment` | object | none | at most 32 `NAME = "value"` pairs, each under 1024 bytes; names `[A-Za-z0-9_]` not starting with a digit; `CAPSULE_*`, `SWITCHBOARD_*`, `SERVICE_BOOTSTRAP_FD`, `CAPABILITY_UNIT_DIR`, `NETWORKCMP`, `CRYPTOCMP`, `LOGCMP`, `TRACECMP`, `NOTIFY` rejected | child environment; may override `PATH`, `USER`, `HOME` |
| `protect` | array | none | flag names, no duplicates or overlaps: `ptrace`, `signal`, `visible`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace`, `noprivs`, `nofork`, `noipc`, `nofdrecv`, `noexec`, `nosock`, aliases `protect`, `restrict`, `all` | capprotect shield applied by switchboard on the process descriptor right after `pdfork(2)` |
| `limits` | object | inherit | keys `memory`, `cpu`, `nproc`, `nofile`, `stack`, `fsize`, `core`; integers or byte strings with `K`/`M`/`G`/`T` | `setrlimit(2)` before exec; `core` is 0 even when the object is absent |
| `umask` | octal string or int | `0077` | 0000 to 0777 | file-creation mask |
| `level` | string | `standard` | `background`, `standard`, `interactive` | `nice` +10, 0, or -5; `interactive` is honoured only for a `/Capabilities/System` bundle and clamped otherwise |
| `ambient` | bool | false | honoured only for system bundles | skip `cap_enter(2)`; readiness is `SVC_OP_READY` |
| `mint_authority` | bool | false | honoured only for system bundles | the one unit allowed to mint session lookup channels (BSDAuth) |
| `watchdog` | object | none | `{ interval = N }`, 1 to 86400 seconds | liveness deadline; a missed `service_heartbeat(3)` kills the unit |
| `visible` | string or array | none (system only) | entries `user` or `system` | whether USER-domain sessions may resolve the unit's names |
| `domain` | string | by bundle class | `system` or `user` | which names the unit's own lookups may resolve; system bundles default to `system`, applications to `user` |
| `directories` | array | none | at most 8 absolute paths without `/../`, each under `PATH_MAX` | opened read-only pre-capmode and delivered as `CAPABILITY_DIR_FDS` |
| `holds` | string or array | none | at most 32 unique reverse-domain names; `*` refused | anointments the unit presents at lookup |

### activation

The object is required and its keys are closed. At least one of `boot`,
`ipc`, `timer`, `schedule`, `path`, `socket`, `queue_directory`, `on_mount`
or `helper` must be present; publishing a name does not imply boot.

| Key | Type | Constraint | Effect |
|---|---|---|---|
| `boot` | bool | | launch during startup |
| `ipc` | string or array | 1 to 8 entries; each a bare name or `{ name; requires }`; names reverse-domain, unique, under 64 bytes, not `*`, not prefixed `helper.`; `requires` a string or array of at most 8 unique anointment names | reserve names in the registry; a lookup launches the unit; `requires` gates that endpoint |
| `timer` | object | `{ interval = N }`, 1 to 31622400 monotonic seconds | relaunch every N seconds while stopped; exclusive with `schedule` |
| `schedule` | string | five-field cron (`min hour mday month wday`, numbers or `*`) or `hourly`, `daily`, `midnight`, `weekly`, `monthly`, `yearly`, `annually` | wall-clock activation, all fields must match |
| `persistent` | bool | requires `schedule` | one catch-up run at startup for a match missed while down |
| `path` | object | `{ path = "/abs" }` | activate on `NOTE_WRITE`, `DELETE`, `RENAME`, `EXTEND`, `ATTRIB`; a hint only |
| `socket` | object or array | 1 to 4 objects of `{ name; listen; backlog }`; `listen` is `tcp:ADDR:PORT`, `tcp6:`, `udp:`, `udp6:` (ADDR `*` or empty for any, port 1 to 65535) or `unix:/abs/path`; `backlog` 1 to 1024, default 128 | switchboard binds and holds the listener; the first connection launches the unit; delivered by `name` through `service_activation_socket(3)` |
| `queue_directory` | string | absolute path | relaunch after each exit while the directory has entries |
| `on_mount` | bool | | relaunch on any mount |
| `helper` | bool | no `ipc` allowed | private helper reachable only by a sibling through `service_helper_open(3)` under the synthetic name `helper.<bundle_id>.<unit>` |

### capabilities

The only authority a manifest declares, and only a born-in-capmode broker
needs it. `system` is an array of distinct names from `lib/libcapbundle/gates.h`:
`kldload`, `kldunload`, `reboot`, `swapon`, `swapoff`, `sysctl`, `kenv`,
`kenv_read`, `acct`, `audit`, `settime`, `jail`. At launch switchboard has
Capsule mint one token carrying exactly these gates and delivers it as a
bootstrap capability of type `system`; the program authorizes it with
`service_provider_authorize_capabilities(3)` and performs the operation
through the matching `service_system_*()` call while the raw syscall stays
refused in capability mode. `isolate` is at most 64 sysctl OID names, each
under 128 bytes, legal only alongside the `sysctl` gate; the token is minted
scoped to those OIDs so the unit is their sole writer. The whole object is
stripped from a bundle loaded from a per-user agent root. How the gates work
in the kernel is in [System Gates](../capability/system-gates.md).

## Three policy axes

`control`, `visible` and `domain` answer three different questions and never
collapse into one another. `control` is who may manage the unit
(`core` refuses everyone including root; `system` needs the `admin_rights`
grant from principal policy; `user` is the owning uid or an operator).
`visible` is who may reach the unit's names (absent means SYSTEM sessions
only). `domain` is what the unit itself may reach. A per-user agent is forced
to `control = user`, `domain = user`, no `visible = user`, no `ambient`, no
`mint_authority`, no `capabilities`, whatever it declares
(`usr.sbin/switchboard/startup.c`). Per-endpoint `requires` and the unit's
`holds` layer anointments on top; see
[Anointments and Principal Policy](anointments.md) and
[The Management Model](management-model.md).

## A minimal provider: BSDLog

`usr.sbin/BSDLog/capbundle/Bundle.ucl`, installed as
`/Capabilities/System/Log.cap/Bundle.ucl`:

```ucl
schema = "org.5bsd.capability-bundle";
schema_version = 1;
bundle_id = "system.Log";          # the runtime identity prefix
version = "1.0.0";                 # display only
sequence = 1;                      # bumped on every shipped change
author = "5BSD";
publisher = "org.5bsd.base";
units = ["bsdlog"];                # exactly Units/bsdlog.unit exists
```

`usr.sbin/BSDLog/capbundle/bsdlog.ucl`, installed as
`Units/bsdlog.unit/Unit.ucl` beside `bin/BSDLog` and `Config/bsdlog.conf`:

```ucl
activation { boot = true; ipc = ["system.Log"]; }
                                   # starts at boot AND on the first lookup
control = "core";                  # nobody stops the logger at runtime
protect = ["ptrace", "signal", "wait", "sigkill", "sigcont", "sched",
    "core", "ktrace"];             # shield applied before the image runs
program = "BSDLog";                # bin/BSDLog, not bin/bsdlog
visible = ["user"];                # a login session may reach system.Log
directories = ["/Capabilities/System", "/Capabilities/Apps",
    "/Capabilities/Run/live"];     # delivered as dirfds for the reconcile
restart = "on-failure";
user = "capability";               # the default, stated for clarity
limits { nofile = 2048; nproc = 72; core = 0; }
                                   # 1 main + 1 storage + 64 shards, headroom
umask = "0077";
```

Nothing here grants storage, sockets or files. BSDLog opens
`system.Filesystem` at runtime for its segment store, reads its config
through the delivered `CAPABILITY_CONFIG_FD`, and reads the install roots
through `CAPABILITY_DIR_FDS` because a born-in-capmode process cannot open
`/Capabilities/System` by path. `visible = ["user"]` is the whole reason a
shell can `logctl` without an anointment.

## A gate-holding daemon: BSDTime

`usr.sbin/BSDTime/capbundle/BSDTime.ucl`, installed as
`/Capabilities/System/Time.cap/Units/bsdtime.unit/Unit.ucl`:

```ucl
activation { boot = true; ipc = ["system.Time"]; }
control = "core";
protect = ["ptrace", "signal", "wait", "sigkill", "sigcont", "sched",
    "core", "ktrace"];
program = "BSDTime";
restart = "on-failure";
user = "capability";               # unprivileged; the token is the authority

capabilities { system = ["settime"]; }
                                   # one SYS_GATE_SETTIME token at fd 6

limits { nofile = 256; nproc = 64; core = 0; }
umask = "0077";
```

`clock_settime(2)` and `adjtime(2)` are refused in capability mode. BSDTime
receives the `settime` token as its one launch-time bootstrap capability,
authorizes it, and steps or slews the clock through
`service_system_settime(3)` and `service_system_adjtime(3)`; the kernel does
the operation in kernel context after verifying the held claim. Writes are
bounded by its per-label policy in `Config/time.conf`, default deny. Compare
the two manifests: the only difference in kind is the `capabilities` block,
and it is the declaration, not the uid, that makes BSDTime able to set the
clock.

## Status and limits

The format is shipped and pinned by `lib/libcapbundle/tests` (activation,
anoint, policy, management and format tests). Two things a reader will look
for and not find: there is no dependency key of any kind (ordering is by
demand, not declaration), and the "local descriptors" `switchboardctl verify`
prints in its effective view are launch-time deliveries (config, directories,
sockets, a gate token), not grants, since a manifest makes none.
`activation.timer` is monotonic only; wall-clock work belongs in `schedule`.
The `Resources` unit subdirectory named in switchboard(5) is accepted by the
tree walk but nothing delivers it as a descriptor; use `Config` for files the
program must read after `cap_enter(2)`.

Reference: switchboard(5), libcapbundle(3), `lib/libcapbundle/libcapbundle_parse.c`.
