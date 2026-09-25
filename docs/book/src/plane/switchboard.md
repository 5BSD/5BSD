# Switchboard

switchboard(8) is 5BSD's service manager, `/usr/libexec/switchboard`. It is
the one child [Capsule](capsule.md) starts, and it does two jobs its name
describes: it is a launcher that turns `.cap` bundles into supervised,
born-in-capability-mode processes, and it is a switchboard that resolves
reverse-domain names to live channels, launching a provider on demand when
nothing is listening. 5BSD has it because rc(8) cannot express either job:
rc starts programs with ambient authority and no notion of a name.

switchboard holds no capabilities of its own beyond what Capsule delegates to
it for launching. It never proxies service traffic. It has no dependency
graph: a unit that needs another service asks for it by name at runtime and
fails soft if it is absent.

## Startup

switchboard inherits four descriptors from Capsule (`CAPSULE_CHANNEL_FD`, fd 3,
the channel back to PID 1; fds 4 and 5, delegated channel and coalition
service instances; fd 6, a capprotect instance it must keep open or lose its
shield). It then, in order: raises `RLIMIT_NOFILE` to `kern.maxfilesperproc`
and reserves eight descriptors for control traffic; registers the Capsule
channel for EOF; self-serves `system.switchboard` and `system.lifecycle` in
its registry; applies its shield (`ptrace`, `signal`, `wait`, `sigkill`,
`sigcont`, `sched`, `core`, `ktrace`); scans the bundle roots; launches; and
only after `/etc/rc` has completed sends `CAPSULE_OP_READY`. The log, in
order, on a healthy boot:

```text
switchboard[42]: inherited service fds: channel=3 channel_svc=4 coalition_svc=5 capprotect=6
switchboard[42]: bundle_registry: loaded 'system.Log' (1 services)
switchboard[42]: bundle_registry: 17 bundles loaded
switchboard[42]: capprotect shield active
switchboard[42]: switchboard started, 17 bundles registered
switchboard[42]: startup: loaded system.Log/bsdlog restart=on-failure
switchboard[42]: startup: system.Log/bsdlog provides: system.Log
switchboard[42]: startup: 23 services loaded
switchboard[42]: startup: launched 11 native services
switchboard[42]: startup: system ambient lookup channel on fd 9
switchboard[42]: startup: ambient lookup channel handed to capsule for logins
switchboard[42]: startup: running /etc/rc
switchboard[42]: startup: /etc/rc completed
switchboard[42]: rc adoption: adopted rc.d service 'cron' as a supervised unit
switchboard[42]: startup: launched 12 services
switchboard[42]: startup: complete in 4180 ms
```

`startup: launched N native services` appears before `running /etc/rc`
because the native boot units are launched first and reach readiness while rc
runs (`usr.sbin/switchboard/startup.c`). Born-in-capmode units take their
resources from delivered descriptors, never from rc, so nothing waits on it.
If Capsule's channel goes EOF at any point, switchboard logs `Capsule exited,
stopping all services`, audits it, and stops everything.

## The bundle registry

The registry (`bundle_registry.c`) scans three kinds of root:

| Root | Trust | Loaded when |
|---|---|---|
| `/Capabilities/System` | root-owned, system bundles | boot and every rescan |
| `/Capabilities/Apps` | root-owned, application bundles | boot and every rescan |
| `/Capabilities/Users/<uid>/Agents` | owned by `<uid>`, not group/other writable | first time that user opens a control channel |

Only directories ending in `.cap` are considered. Each bundle's `Bundle.ucl`
carries a `bundle_id` and a `sequence`; when two installed bundles share an
identity, the registry keeps exactly the highest sequence
(`bundle_selection.c`), refuses a duplicate sequence, and refuses a user
bundle that shadows a system identity. A bundle listed in
`/Capabilities/Config/switchboard/disabled` is installed but not registered.
Every declared `activation.ipc` name is reserved in the naming registry at
load time, before any provider runs, so a lookup has a stable activation
target while the process is absent.

The registry watches its roots one level deep with vnode events and rescans
after `SWITCHBOARD_REGISTRY_WATCH_SETTLE` seconds of quiet (default 2), so a
package install or removal loads or unloads units without a reload. A bundle
caught half-extracted is quarantined if it is new, or keeps its previous
registration if it was already loaded, and the rescan is retried up to eight
settled times. An edit below `Units/` is not noticed; use `switchboardctl
reload`. A system root that vanishes at runtime keeps the previous registry
rather than unloading every system unit.

## Unit lifecycle

Every unit is one `svc_runtime` with a state, a process descriptor and a
manifest (`switchboard.h`):

```text
STOPPED -> STARTING -> RUNNING -> STOPPING -> STOPPED
                 \-> DONE   (oneshot: /etc/rc, rc adoption probes)
```

`STARTING` begins at `pdfork(2)`. A native unit becomes `RUNNING` only when
the kernel reports `NOTE_CAPMODE` on the descriptor and `pdincapmode(2)`
confirms it, so readiness is independently observed, not self-reported. An
`ambient = true` unit (the few brokers that need the global namespace)
becomes `RUNNING` on its `SVC_OP_READY` instead. A provider must also have
checked in one listener per declared name (`SVC_OP_NAME_CLAIM`) before its
`READY` is accepted.

Supervision parameters come from the manifest
(`usr.sbin/switchboard/supervisor.c`):

| Parameter | Values | Behaviour |
|---|---|---|
| `restart` | `never`, `always`, `on-failure` (default `never`) | `on-failure` restarts on non-zero exit or signal death |
| rapid death | ran less than `RESTART_MIN_UPTIME_SEC` (5 s) | delayed restart of `restart_count * 2` s, capped at 30 s |
| stable run | ran at least `RESTART_RESET_SEC` (60 s) | counter reset to 1 on the next failure |
| `max_failures` | 1 to 100, default 10 | on reaching it: `service X: failed N times, disabling`; unit stays `STOPPED` until a reload or `switchboardctl start` |
| `stop_timeout` | 1 to 300 s, default 5 | SIGTERM via `pdkill(2)`, then SIGKILL when the timer fires |
| `watchdog.interval` | 1 to 86400 s, off by default | see below |

A provider that requests idle shutdown with `service_idle_shutdown(3)` is
stopped gracefully when its idle timer fires, logged as `stopped for idle;
reservations kept for on-demand relaunch`, and started again by the next
lookup. A unit stopped by the operator is not restarted.

## The launch path

Launching is `svc_exec_native()` in `usr.sbin/switchboard/execute.c`. In the
parent, switchboard asks Capsule for a coalition and a channel pair, mints a
capprotect instance for the child, mints the one launch-time token a manifest
may declare (the system-gate token, see
[Bundles and Manifests](bundles-and-manifests.md#capabilities)), creates the
sealed bootstrap envfd, and `pdfork(2)`s. Immediately after the fork, while
the descriptor is still transferable, it applies the manifest's `protect`
flags to the child through the capprotect instance
(`mac_cap_protect(capprotect_fd, pd_fd, flags)`); a unit that asked to be
contained and cannot be is not run at all. It then enlists the child in its
coalition and confines the process descriptor to `CAP_EVENT`, `CAP_PDGETPID`
and `CAP_PDKILL`.

The child runs `child_exec()`. Each step exists to close a window, and they
happen in this order:

| Step | What | Why |
|---|---|---|
| 1 | stdin from `/dev/null`; stdout and stderr to `/var/log/capability.log` | a capmode daemon cannot reach syslogd and boots before BSDLog; its `LOG_PERROR` output must land somewhere durable |
| 2 | dup descriptors into fixed slots: channel fd 3, capprotect fd 4, bootstrap fd 5, tokens from fd 6; `closefrom(2)` above them | the sealed bootstrap table at `SERVICE_BOOTSTRAP_FD` (5) is the unit's whole authority inventory |
| 3 | build the environment: manifest `environment`, `PATH`, `SERVICE_BOOTSTRAP_FD=5`, `CAPABILITY_UNIT_DIR=<...>/Units/<u>.unit` | a location, never authority; reserved names in the manifest are rejected at parse |
| 4 | open `/lib`, `/usr/lib` and, if present, `<unit>/lib` as directory descriptors; `LD_LIBRARY_PATH_FDS=a:b[:c]` | rtld resolves `NEEDED` libraries and later `dlopen(3)` by `openat(2)` from these, never by path |
| 5 | open `<unit>/Config` as `CAPABILITY_CONFIG_FD`; open each manifest `directories[]` entry as `CAPABILITY_DIR_FDS=path=fd:...` | `service_config_open(3)` and `service_resource_dir(3)` consume these after `cap_enter(2)`; a missing directory is skipped |
| 6 | `open(program, O_EXEC | O_VERIFY)` while still root | the bundle tree has no permission bits after verification; under mac_veriexec an unfingerprinted image fails here with `EAUTH` |
| 7 | `chdir` into the unit's run container `/Capabilities/Run/<label>` (0700, chowned to the unit) | relative paths resolve inside the unit's writable scratch, not the root |
| 8 | `setrlimit(2)` for every `limits{}` field (`core` is 0 even when omitted), `setpriority(2)` from `level`, `umask(2)` (default 0077) | applied while still privileged so ceilings bind the image from its first instruction |
| 9 | `setgroups`, `setgid`, `setuid` to the manifest `user`/`group` (default `capability`) | failure is fatal: running as root when the manifest asked otherwise is an escalation |
| 10 | reset all signal dispositions and the mask | a clean image |
| 11 | `cap_enter(2)`, then `fexecve(2)` of the descriptor from step 6 | the kernel allows a capmode exec of a dynamic binary only when `PT_INTERP` names the brand's own rtld (`kern.elf64.capmode_interp`); the daemon has no un-sandboxed instant |

An `ambient = true` unit skips step 11's `cap_enter` and `execve`s by path
instead. Because the kernel execs the program itself, the process carries the
program's own name in `ps(1)` and `top(1)`, not rtld's. Debug output from a
unit that dies before it can log lands in `/var/log/capability.log`
(`ident[pid]: message`).

## The lookup channel and name resolution

Each unit's fd 3 is its channel to switchboard, and every request that
crosses it is stamped by the kernel with the sender's label. Over that
channel a provider claims, activates and withdraws names, and a consumer looks
names up. A lookup that resolves yields a fresh direct channel between the two
parties; switchboard pushes one end to the provider as `SVC_OP_NEW_CLIENT`
(carrying the requester's label and the exact name addressed) and returns the
other end to the requester. From then on switchboard is out of the path. A
provider may reserve up to eight names; all map to one runtime with
independent listeners, and a lookup for any of them activates that runtime.

Domain scope is applied before anything else: a unit's own lookups run in the
domain its manifest or bundle class gives it (`domain`), and a name is
resolvable from a USER-domain channel only if its provider lists `visible =
["user"]`. Anointments are checked next: an endpoint with `requires` resolves
only for a requester whose `holds` cover it. A refusal for either reason is
`ENOENT`, indistinguishable from an unregistered name, and each anointment
refusal is audited (`AUE_SWITCHBOARD_ANOINT`). The full mechanism is in
[Discovery and the Lookup Channel](discovery-and-lookup.md).

## On-demand activation

A lookup for a reserved name with no published listener launches the bundle
(`on_demand.c`). Concurrent lookups for any name of the same runtime coalesce
onto one launch; each waiter still gets its own channel. switchboard sends
`SVC_OP_ACTIVATE_NAME` only for names that were requested, the provider
answers `SVC_OP_NAME_RESULT`, and success releases only that name's queued
sessions. A provider that dies before publishing fails its waiters
immediately; one that never publishes fails them with `ETIMEDOUT` after
`ON_DEMAND_TIMEOUT_SEC` (10 s). At most 64 lookups may be pending at once. A
lookup whose requester exits is discarded, and a restarted requester cannot
consume a predecessor's reply.

The other activation sources (`timer`, `schedule`, `path`, `socket`,
`queue_directory`, `on_mount`, `helper`) create demand the same way; they are
listed with their manifest syntax in
[Bundles and Manifests](bundles-and-manifests.md#activation). A socket
listener is bound and held by switchboard, so it survives the unit's
restarts with its backlog intact.

## Watchdog heartbeats

A unit with `watchdog { interval = N; }` must call `service_heartbeat(3)` at
least every N seconds once it is `RUNNING`. switchboard arms a kqueue timer at
the `RUNNING` transition (not at the first heartbeat, so a start-up hang is
caught), re-arms it on each `SVC_OP_HEARTBEAT`, and on expiry logs `service X:
watchdog expired (no heartbeat within Ns), killing wedged provider`,
terminates the unit's coalition, and `pdkill`s it with SIGKILL. The ordinary
death path then applies the restart policy, so `never` stays down. Beat from
the thread that does the work; a heartbeat from a helper thread defeats the
point. A heartbeat from a unit with no watchdog is accepted and ignored.

## rc adoption

switchboard runs `/etc/rc autoboot` once as a oneshot unit on the console and
does not gate the plane on it. After rc completes it reads
`/Capabilities/Config/switchboard/rc_adopt.conf`, one rc.d service name per
line, `#` comments allowed (`rc_adopt.c`). The shipped file names `cron`. Each
listed service becomes a `SVC_KIND_RC` unit with `control = system` and
`restart = on-failure`: switchboard first runs `service <name> onestatus` to
adopt an instance `/etc/rc` already started, runs `onestart` only if it is
absent, and stops it with `onestop` (an rc daemon detaches, so signalling the
start wrapper would stop nothing). A name that has no script under
`/etc/rc.d` is logged and skipped; an absent or empty list adopts nothing.
There is no hardcoded fallback: the file is the whole policy, and under
mac_veriexec it is integrity-protected.

Every other rc.d service keeps running under `/etc/rc` exactly as the FreeBSD
Handbook describes; see [rc and service(8)](../compat/rc-and-service.md) for
what `service(8)` and `switchboardctl` each cover.

## switchboardctl

switchboardctl(8) talks to switchboard over `system.switchboard`. Read-only
verbs work from any session that can resolve the name; mutating verbs need the
`system.switchboard.admin` anointment on the session, not root. Managing a
given unit is then decided by its `control` class: a `core` unit refuses
everyone before authority is even checked.

| Verb | Effect |
|---|---|
| `status`, `services` | daemon summary and one line per unit |
| `start`, `stop`, `restart <label>` | drive the unit; `start` also resets its backoff |
| `reload` | transactional rescan; a cycle or malformed set leaves the running registry untouched |
| `enable`, `disable <bundle>` | edit the persistent disable list and reload |
| `install <path>.cap` | verify and copy into `/Capabilities/System` (root) |
| `verify <path>.cap ...` | the same strict parser switchboard uses, no side effects |
| `bundles` | list installed bundles |
| `graph [--text|--dot|--json] [--lint]` | draw the anointment reach graph from disk |

`status` prints what `sctl_cmd_status()` in `sctl.c` formats:

```text
# switchboardctl status
switchboard: running
services: 23 loaded (19 running, 2 stopped, 0 starting, 0 stopping, 2 done)
fd-budget: soft=229672 hard=229672 reserve=8 denied=0 control-shed=0

  system.Log/bsdlog    running  pid 611 restart=on-failure mgmt=core by=system conns=14
  system.Time/bsdtime  running  pid 618 restart=on-failure mgmt=core by=system
  system.Notify/notifyd stopped          restart=on-failure mgmt=system by=system
  cron                 running  pid 702 restart=on-failure mgmt=system by=system
  etc-rc               done             restart=never mgmt=system by=system
```

`restarts=N` appears once a unit has been restarted; `by=` is `system` for
boot launches, `operator` after `switchboardctl start`, `activation` for a
demand source, or the requesting unit's label for an on-demand launch. The
`/etc/rc` oneshot is the unit `etc-rc`; an adopted rc.d service is labelled by
its rc.d name. Stopping a core unit:

```text
# switchboardctl stop system.Log/bsdlog
switchboardctl: stop: Operation not permitted
```

`graph --lint` reports an endpoint requiring an anointment nobody declares
and a declared anointment no endpoint requires, exiting 2 when it found
either:

```text
# switchboardctl graph --lint
system.Notify/notifyd -> system.Log [open]
session.admin -> system.Notify.System [via system.notify.system]
session.default -> system.Log [open]
warning: unreachable: org.example.mail.admin requires "org.example.mail.operator", which no unit or principal declares
summary: 3 units, 2 sessions, 5 endpoints (2 gated), 9 edges, 1 warnings
```

## Observability

The `switchboard` USDT provider covers lifecycle, naming, on-demand,
anointment, control and fd-budget events; switchboard(8) lists every probe,
and `/usr/share/dtrace/switchboard-*` ship ready scripts (`switchboard-
lifecycle`, `switchboard-naming`, `switchboard-anoint`). Audit records are
emitted for start, control commands, exec phases and anointment refusals.

## Status and limits

switchboard is shipped and tested (`usr.sbin/switchboard/tests`: activation,
calendar, anoint, bundle registry, domain, fd budget, management enforcement,
rc adoption and ingest, registry watch, sctl gate, plus VM integration). The
gaps to know about: `/Capabilities/Run` is a tmpfs, so run containers do not
survive reboot by design; only `cron` is adopted from rc.d by default, and
per-service migration of the rest of `/etc/rc` remains; switchboard(8) still
describes a Kahn dependency sort and "reverse dependency order", which is
vestigial since manifests carry no dependency key and startup launches every
boot unit in one tier; and a microsecond-simultaneous burst of eight or more
first lookups from ambient clients can degrade to the shared channel (fail
soft, no hang), documented in
`docs/capability-ambient-lookup-per-process.md`.

Reference: switchboard(8), switchboard(5), switchboardctl(8), libservice(3).
