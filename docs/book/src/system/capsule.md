# Capsule (PID 1)

5BSD replaces `init(8)` with **Capsule** as PID 1. The `capsule(8)` binary owns
`mac_capability`, mints capability tokens, and supervises `switchboard(8)`. When
it finds itself running as PID 1, it also activates its init personality. A
second copy is installed as `/sbin/capsule`, since `/usr` may not be mounted
when the kernel starts init.
The 5BSD platform loader defaults select it with executable fallbacks:

```sh
# /boot/defaults/loader.conf
init_path="/sbin/capsule:/sbin/init:/sbin/init.bak:/rescue/init"
```

The capsule package repeats the declaration in
`/boot/loader.conf.d/capsule.conf` so a Capsule upgrade remains safe when
the installed bootloader defaults are older than the package.

Two install-time requirements, both satisfied by a default install: the
`mac_capability` module stack must be preloaded (it ships in the `bootloader`
package's `loader.conf` defaults — without the device, boot falls through to
the classic `/sbin/init` and no plane comes up), and an **OpenZFS root pool is
the required system filesystem for a fully functional installation**. On a
pool-less live system, [`tzfsd`](../storage/trustedzfs.md) serves only isolated
paths; storage-dependent services must use an explicitly granted ephemeral
runtime directory or report their persistent features unavailable.

## Spine and service manager

Capsule deliberately splits the roles launchd combines into one process:

| Role | Process | Control tool | Owns |
| --- | --- | --- | --- |
| Spine (PID 1) | `capsule` | `capsulectl(8)` | System lifecycle (reboot, halt, single-user, reroot), capability authority, global reaping, recovery console, switchboard supervision |
| Service manager | [`switchboard`](switchboard.md) | `switchboardctl(8)` | Per-service lifecycle, demand activation, `/etc/rc` |

Lifecycle authority that must survive the service manager's death stays in the spine:
reboot does not depend on `switchboard` being alive, because shutdown tears
`switchboard` down. `switchboard` runs as a `pdfork(2)` child supervised through its
process descriptor. Kernel-module loading is not a PID 1 operation — it is
brokered by `sysextd` (`system.SystemExtension`), reached at runtime by name;
neither reboot nor module loading has a standalone daemon.

## Boot: converge or recover

The init personality is a port of `init(8)`'s state machine with one added
state:

```text
single-user → runcom → establish_capsule → read_ttys → multi_user
                          │
                          ├─ start capability engine (mac_capability,
                          │  control socket, pdfork switchboard)
                          ├─ wait for switchboard convergence (switchboard runs
                          │  /etc/rc, services boot demand, then reports ready)
                          └─ on failure: recovery single-user shell
```

PID 1 does not run `/etc/rc` itself and does not start getty/login until
`switchboard` signals convergence. There is deliberately no clock deadline —
`/etc/rc` has no knowable duration (fsck, entropy waits) — recovery triggers
only when `switchboard` *permanently* fails (its restart circuit breaker trips).

Capsule keeps the classic init(8) compatibility invariants: never daemonize, never
exit (every exit path becomes a logged emergency and a deliberate reboot or
recovery), reap all orphans continuously, preserve `/etc/ttys` getty
management. Shutdown mirrors boot: revoke ttys → `/etc/rc.shutdown` (with
`switchboard` still available) → drain and stop `switchboard` via its procdesc →
global `SIGTERM`/`SIGKILL` sweep → `/etc/rc.final` → `reboot(2)`.

## Control ABI and the signal shield

The classic init is administered by unauthenticated signals to PID 1. Capsule
replaces that with typed, root-authorized operations on the authenticated
control socket `/var/run/capsule.sock` — shutdown, reboot, halt, poweroff,
power-cycle, single-user, reroot, ttys rescan, and catatonia, plus an
unprivileged status query. `reboot(8)`, `halt(8)`, and `shutdown(8)` speak
this ABI first and fall back to the traditional signal path when the socket is
absent (classic-init systems and the pre-engine early-boot window). Lifecycle
opcodes are rejected when `getpid() != 1`, so an ordinary `capsule` daemon
cannot reboot the machine. `capsulectl(8)` is the operator tool for the
spine — status is unprivileged, everything else is root.

Once the control socket is up, Capsule raises its capability integrity shield
(`CP_SF_SIGNAL`, plus `SIGKILL`/`SIGCONT` protection) over itself and
`switchboard`, making ambient PID-based signalling of PID 1 unreachable.
Kernel-internal signals (`SIGCHLD` reaping, procdesc signalling of `switchboard`)
keep working under the full shield. `init N` (SysV telinit) is a signal path
and is deliberately not converted — it silently no-ops; use
`shutdown(8)`/`reboot(8)`/`halt(8)`. Direct `reboot -q`, ddb, and hardware
watchdogs remain as last-resort emergency paths.

## Coexistence with rc

5BSD does not replace the rc.d world in a flag day; a mixed system is a
designed, stable operating mode. `switchboard` runs `/bin/sh /etc/rc autoboot`
once, init-style, as a oneshot on `/dev/console` — so rcorder metadata,
`rc.conf` layering, `service(8)`, and every enabled rc.d script behave exactly
as they always have — then scans `/Capabilities` bundles, services queued
demand, and reports convergence to PID 1. A non-zero `/etc/rc` exit is logged
but does not block convergence (matching classic rc). What moved out of rc:
`capsule` itself (it *is* PID 1 — there is no `rc.d/capsule` script),
reboot and module-load orchestration (above), native capability services
(launched from `.cap` bundles), and lifecycle signalling of PID 1.

Every long-running service has exactly one owner — an rc.d script or a
switchboard bundle, never both — and migrates by keeping its public IPC name
stable, proving readiness and shutdown under the new owner, then flipping
ownership. An rc.d script for a capability-shielded daemon becomes an adapter
that calls the daemon's authenticated control tool instead of `kill`, because
the shield denies the generic `kill -TERM`/`kill -0` defaults.

Operators keep their tools: `sysrc`, `service <name> start|stop|status`, and
rc.conf layering work unchanged for rc-owned services; use `switchboardctl` for
the managed world and `capsulectl status` for the spine. Rollback is a
loader setting: `init_path="/sbin/init"` boots entirely on the classic init and rc.

Demand activation covers timers, calendars, sockets, paths, and mounts;
user-domain schedules are not provided, and per-script rc graph ingestion
and dependency targets are deliberately absent.

Reference: `capsule(8)`, `capsulectl(8)`.
