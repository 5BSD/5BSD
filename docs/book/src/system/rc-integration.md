# rc Integration

5BSD does not replace the rc.d world in a flag day. The Authority/serviced stack
runs the stock rc boot on every boot and migrates services out of it one at a
time; a mixed system is a designed, stable operating mode. References:
`docs/rc-integration-handbook.md` (the full rc handbook),
`docs/freebsd-init-behavior-audit.md` (the init(8) behavior contract),
`docs/service-architecture-plan.md` §14 (the demand-driven transition plan).

## Boot ordering

Under stock FreeBSD, `init(8)` runs `/etc/rc`. Under 5BSD, PID 1
(capsule) does not run rc at all — serviced owns rc startup:

```text
kernel → capsule (PID 1)
  ├─ single-user if requested; console recovery always available
  ├─ establish_authority: mac_capability, control socket,
  │  pdfork serviced
  └─ wait for convergence (no clock deadline)
        │
        ▼
serviced
  1. run /bin/sh /etc/rc autoboot as a oneshot, on /dev/console,
     and block until it exits (the full stock rc graph: rcorder,
     two-pass discovery, firstboot, jail keywords — unchanged)
  2. scan /Capabilities bundles and service demand already queued by boot or
     IPC activation
  3. bind control sockets (now that rc remounted / read-write)
  4. send AUTHORITY_OP_READY to PID 1
        │
        ▼
capsule: read /etc/ttys → getty/login (multi-user)
```

Two properties matter to operators. First, rc semantics are preserved exactly:
`/etc/rc` is executed once, init-style (`sh /etc/rc autoboot`), so rcorder
metadata, `rc.conf` layering, `service(8)`, and every enabled rc.d script
behave as on stock FreeBSD. Second, the **converge step** is the boot-health
gate: gettys do not start until serviced reports convergence. A non-zero
`/etc/rc` exit is logged but does not block convergence (matching stock rc,
which normally exits zero even when individual scripts fail); only serviced
*permanently* failing — its restart circuit breaker tripping — sends PID 1 to
a recovery single-user shell instead of a dead multi-user. There is no
timeout: a legitimately slow fsck or entropy wait is never cut short.

Shutdown is the mirror image: PID 1 revokes ttys, runs `/etc/rc.shutdown`
while serviced is still available (so rc.d `faststop` methods that need the
managed world still work), then drains and stops serviced via its process
descriptor, performs the global `SIGTERM`/`SIGKILL` sweep, runs
`/etc/rc.final`, and calls `reboot(2)`.

## What moved out of rc

- **authorityd itself.** rc no longer starts authorityd; it *is* PID 1 (there is no
  `rc.d/authorityd` script — a duplicate daemon instance at boot would conflict
  with the spine).
- **Reboot and module-load orchestration.** Reboot is a PID 1 control-ABI
  operation; kernel-module loading is brokered by `sysextd`
  (`system.SystemExtension`), which a unit reaches at runtime with
  `service_ensure_extension(3)` rather than through any manifest field. No
  standalone daemons exist for either.
- **Native capability services** are launched by serviced from `.cap`
  bundles, not by rc.d scripts.
- **Lifecycle signalling of PID 1.** `reboot(8)`, `halt(8)`, and
  `shutdown(8)` use the authenticated authorityd control socket, with a signal
  fallback for stock-init systems.

Everything else — filesystem mounts, network configuration, syslogd, and all
enabled legacy daemons — still boots through the stock rc graph.

## Migrating a service (single-owner rule)

Every long-running service has exactly one owner: an rc.d script or a
serviced bundle, never both. Migration keeps the public IPC name stable so
clients continue to discover the same service, and follows a
one-service transaction: inventory the script's ordering, preparation,
credentials, readiness, and shutdown behavior; author the `.cap` bundle and
capability contract; prove one-instance boot, real readiness, `service(8)`
operations, single-stop shutdown, and recovery to the still-active owner if
publication fails; only then flip ownership.
An rc.d script for a control-socket daemon becomes an adapter rather than a
signal sender:

```sh
stop_cmd="exampled_stop"
exampled_stop()
{
        /usr/sbin/examplectl shutdown || return 1
}
```

This is required for capability-shielded daemons: `service(8)` dispatches
operations to the script, and the generic `kill -TERM` / `kill -0` defaults
are denied by the shield, so stop/status/reload must go through the daemon's
authenticated control path (see `docs/rc-integration-handbook.md` §10–11 for
the full pattern, including fail-closed stop).

## Operator guidance

- `sysrc`, `service <name> start|stop|status`, and rc.conf layering work
  unchanged for rc-owned services. Use `servicectl services` for the managed
  world and `authorityctl status` for the spine and claims.
- `init 0/1/6` (SysV telinit) is unsupported under Capsule; use
  `shutdown(8)`, `reboot(8)`, `halt(8)`.
- Rollback: stock `/sbin/init` stays installed and selectable. The shipped
  `init_path` (`/boot/loader.conf.d/capsule.conf`) falls back through
  `/sbin/init:/sbin/init.bak:/rescue/init`; from the loader prompt, set
  `init_path="/sbin/init"` to boot entirely on stock init and rc.
- Boot diagnostics: serviced logs with `LOG_CONS` before syslogd is up, and
  boot-path lifecycle events emit DTrace probes via the `serviced` and
  `authorityd` providers; early failures land on the console and in the
  converge-or-recover shell.

**Status.** Today serviced runs the monolithic `/etc/rc` ("Model A"). Native
services migrate by acquiring a demand trigger and becoming the sole owner of
their public interface. Per-script rc graph ingestion, dependency targets, and
ordering metadata are not part of the pre-v1 design; see
`docs/service-architecture-plan.md` §14.
