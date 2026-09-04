# Capsule (PID 1)

5BSD replaces `init(8)` with **Capsule** as PID 1. The same binary serves two
roles: as `authorityd(8)` it is the capability broker — it owns
`mac_capability`, mints capability tokens, and supervises `serviced(8)` — and
when it finds itself running as PID 1 it switches to a dedicated init
personality, **Capsule**, installed as `/sbin/capsule` (a second copy on the
root filesystem, since `/usr` may not be mounted when the kernel starts init).
The shipped `init_path` selects it with executable fallbacks:

```sh
# /boot/loader.conf.d/capsule.conf
init_path="/sbin/capsule:/sbin/init:/sbin/init.bak:/rescue/init"
```

Two install-time requirements, both satisfied by a default install: the
`mac_capability` module stack must be preloaded (it ships in the `bootloader`
package's `loader.conf` defaults — without the device, boot falls through to
the classic `/sbin/init` and no plane comes up), and a **ZFS root pool is the
supported plane configuration** — on a UFS-only root,
[`tzfsd`](../storage/trustedzfs.md) and the components that depend on managed
storage stay stopped and the plane runs degraded.

## Spine and service manager

Capsule deliberately splits the roles launchd combines into one process:

| Role | Process | Control tool | Owns |
| --- | --- | --- | --- |
| Spine (PID 1) | `capsule` / `authorityd` | `authorityctl(8)` | System lifecycle (reboot, halt, single-user, reroot), capability authority, global reaping, recovery console, serviced supervision |
| Service manager | [`serviced`](serviced.md) | `servicectl(8)` | Per-service lifecycle, demand activation, `/etc/rc` |

Authority that must survive the service manager's death stays in the spine:
reboot does not depend on `serviced` being alive, because shutdown tears
`serviced` down. `serviced` runs as a `pdfork(2)` child supervised through its
process descriptor. Kernel-module loading is not a PID 1 operation — it is
brokered by `sysextd` (`system.SystemExtension`), reached at runtime with
`service_ensure_extension(3)`; neither reboot nor module loading has a
standalone daemon.

## Boot: converge or recover

The init personality is a port of `init(8)`'s state machine with one added
state:

```text
single-user → runcom → establish_authority → read_ttys → multi_user
                          │
                          ├─ start capability engine (mac_capability,
                          │  control socket, pdfork serviced)
                          ├─ wait for serviced convergence (serviced runs
                          │  /etc/rc, services boot demand, then reports ready)
                          └─ on failure: recovery single-user shell
```

PID 1 does not run `/etc/rc` itself and does not start getty/login until
`serviced` signals convergence. There is deliberately no clock deadline —
`/etc/rc` has no knowable duration (fsck, entropy waits) — recovery triggers
only when `serviced` *permanently* fails (its restart circuit breaker trips).

Capsule keeps the classic init(8) compatibility invariants: never daemonize, never
exit (every exit path becomes a logged emergency and a deliberate reboot or
recovery), reap all orphans continuously, preserve `/etc/ttys` getty
management. Shutdown mirrors boot: revoke ttys → `/etc/rc.shutdown` (with
`serviced` still available) → drain and stop `serviced` via its procdesc →
global `SIGTERM`/`SIGKILL` sweep → `/etc/rc.final` → `reboot(2)`.

## Control ABI and the signal shield

The classic init is administered by unauthenticated signals to PID 1. Capsule
replaces that with typed, root-authorized operations on the authenticated
control socket `/var/run/authorityd.sock` — shutdown, reboot, halt, poweroff,
power-cycle, single-user, reroot, ttys rescan, and catatonia, plus an
unprivileged status query. `reboot(8)`, `halt(8)`, and `shutdown(8)` speak
this ABI first and fall back to the traditional signal path when the socket is
absent (classic-init systems and the pre-engine early-boot window). Lifecycle
opcodes are rejected when `getpid() != 1`, so an ordinary `authorityd` daemon
cannot reboot the machine.

```sh
authorityctl status      # daemon status, active claims, serviced state (any user)
authorityctl reload      # reload config, SIGHUP serviced (root)
```

Once the control socket is up, Capsule raises its capability integrity shield
(`CP_SF_SIGNAL`, plus `SIGKILL`/`SIGCONT` protection) over itself and
`serviced`, making ambient PID-based signalling of PID 1 unreachable.
Kernel-internal signals (`SIGCHLD` reaping, procdesc signalling of `serviced`)
keep working under the full shield. `init N` (SysV telinit) is a signal path
and is deliberately not converted — it silently no-ops; use
`shutdown(8)`/`reboot(8)`/`halt(8)`. Emergency paths when the event loop is
wedged: `reboot -q` (direct `reboot(2)`), ddb's `reboot`, or a
platform/BMC/hypervisor watchdog.

## Coexistence with rc

5BSD does not replace the rc.d world in a flag day; a mixed system is a
designed, stable operating mode. `serviced` runs `/bin/sh /etc/rc autoboot`
once, init-style, as a oneshot on `/dev/console` — so rcorder metadata,
`rc.conf` layering, `service(8)`, and every enabled rc.d script behave exactly
as they always have — then scans `/Capabilities` bundles, services queued
demand, and reports convergence to PID 1. A non-zero `/etc/rc` exit is logged
but does not block convergence (matching classic rc). What moved out of rc:
`authorityd` itself (it *is* PID 1 — there is no `rc.d/authorityd` script),
reboot and module-load orchestration (above), native capability services
(launched from `.cap` bundles), and lifecycle signalling of PID 1.

Every long-running service has exactly one owner — an rc.d script or a
serviced bundle, never both — and migrates by keeping its public IPC name
stable, proving readiness and shutdown under the new owner, then flipping
ownership. An rc.d script for a capability-shielded daemon becomes an adapter
that calls the daemon's authenticated control tool instead of `kill`, because
the shield denies the generic `kill -TERM`/`kill -0` defaults.

Operators keep their tools: `sysrc`, `service <name> start|stop|status`, and
rc.conf layering work unchanged for rc-owned services; use `servicectl` for
the managed world and `authorityctl status` for the spine. Rollback is a
loader setting: `init_path="/sbin/init"` boots entirely on the classic init and rc.

Timer, path, socket, calendar, queue-directory, and mount demand sources
are provided; user-domain schedules are not. Per-script rc graph ingestion
and dependency targets are deliberately absent.
