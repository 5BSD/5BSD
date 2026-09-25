# rc and service(8)

rc(8) still boots 5BSD. `/etc/rc`, `/etc/rc.d`, rc.conf(5), rcorder(8) and service(8) are the FreeBSD ones, and every rc.d daemon that is enabled in `/etc/rc.conf` starts exactly as it would on FreeBSD. What changed is who runs `/etc/rc`: not init(8), but switchboard, the service manager that PID 1 (capsule) spawns. switchboard launches its own capability units first, runs `/etc/rc` beside them, and adopts a short, curated list of rc.d services into its own supervision. This chapter explains that arrangement, what `service foo start` does on 5BSD, and the seams where the two worlds meet.

## Who runs /etc/rc

capsule(8) is PID 1 and pdforks exactly one child, `/usr/libexec/switchboard`. switchboard's startup (`usr.sbin/switchboard/startup.c`) proceeds in this order:

1. Scan the bundle registry under `/Capabilities/System`, `/Capabilities/Apps` and the per-user agent roots.
2. Mint the SYSTEM ambient lookup channel and install it in its own environment as `SERVICE_LOOKUP_FD`, and hand a duplicate to capsule so getty sessions can carry it (see [Sessions](sessions.md)).
3. Launch every native boot unit. These are born in capability mode and take what they need from descriptors switchboard delivers and from the pool the loader imported; none of them depends on `/etc/rc`.
4. Run `/etc/rc` as a one-shot unit labelled `etc-rc`, exactly as init did: `execve("/bin/sh", {"sh", "/etc/rc", "autoboot"})` with stdio on `/dev/console` so rc's progress is visible.
5. Block until `/etc/rc` exits, but keep dispatching events while waiting, so an rc.d script that performs a service lookup or triggers an on-demand launch does not deadlock against the manager that is waiting for rc.
6. Register the adopted rc.d units and probe or start them.
7. Send `READY` to capsule over the per-instance channel. Boot has converged. Individual unit failures do not block convergence; only a switchboard that never reaches this point triggers PID 1 recovery.

Native units therefore come up in parallel with rc rather than after it, and the born-sandboxed services are typically ready before rc has finished mounting. `/etc/rc` normally exits 0 even when individual scripts fail; a non-zero exit means rc itself is broken and is logged, not fatal. `/etc/rc.shutdown` and the rest of the shutdown sequence remain rc's.

The whole rc world inherits one thing from switchboard that it did not have on FreeBSD: the SYSTEM ambient lookup channel, named by `SERVICE_LOOKUP_FD` in rc's environment and spared from the child's `closefrom(2)`. Every rc.d daemon started by `/etc/rc` therefore holds a descriptor through which it can resolve system-domain service names. That is what makes `switchboardctl`, `logctl` and the other client tools work from an rc-started sshd session; it is also why cron(8) and atrun(8) were patched to close it before running a user's job. [Sessions](sessions.md) covers the hygiene rules.

## rc adoption

Some rc.d daemons should be supervised by switchboard rather than fire-and-forget by `/etc/rc`. The set is policy, not code: `/Capabilities/Config/switchboard/rc_adopt.conf` lists one rc.d service name per line (`#` comments, blank lines ignored). The shipped file adopts one service:

```
# switchboard rc.d adoption list
cron
```

An absent or empty file adopts nothing and logs a NOTICE; there is no hardcoded fallback. Under mac_veriexec the `/Capabilities` tree is integrity-protected, so the list is tamper-evident. Add `sshd` or `ntpd` on a line of their own to widen adoption; remove a line to stop supervising a service.

The mechanism lives in `usr.sbin/switchboard/rc_adopt.c` and `rc_ingest.c`. `rc_ingest` is a pure parser of an rc.d script's rcorder(8) header: it reads the leading comment block for `PROVIDE`, `REQUIRE`, `BEFORE` and `KEYWORD`, stops at the first non-comment line as rcorder does, and rejects a script with no `PROVIDE` or with `KEYWORD: nostart`. `rc_adopt_select` walks the allow-list, checks that each named script exists under `/etc/rc.d` as an executable regular file that parses as an orderable service, and builds a unit for it:

| Unit field | Value for an adopted rc.d service |
|---|---|
| kind | `SVC_KIND_RC` (unconfined; via service(8)) |
| label | the rc.d service name, e.g. `cron` |
| control | `system` (root-manageable, not core) |
| restart | `on-failure` |
| initial state | `stopped`, launched by the boot loop |

Launching an RC unit means running service(8), never exec'ing the daemon directly. The first command is `service cron onestatus`: on an upgraded image or one where the administrator left `cron_enable="YES"` in rc.conf, `/etc/rc` has already started cron, and a zero exit adopts that instance as-is (`rc unit cron: adopted existing instance` in the log) so nothing is started twice. A non-zero probe is followed by `service cron onestart`. The `one` prefix is deliberate: `faststart` honours the rcvar and would refuse a service that rc.conf disables, whereas switchboard must be able to start it regardless. Stopping runs `service cron onestop`, which reads the daemon's pidfile and signals the real process.

The pidfile detail is the honest limit of adoption. An rc.d daemon daemonizes and reparents to init, so the process descriptor switchboard holds refers to the short-lived `onestart` wrapper, not to the daemon. Once the wrapper exits 0 the unit is `running` and switchboard has no further view of the daemon: `restart=on-failure` applies to a failed `onestart`, not to a cron that later dies. Native units are supervised through their process descriptor and channel; RC units are judged by their command's exit. That is why the adoption list is short and why the real migration path is to rewrite the daemon as a bundle (see [Migrating an rc Daemon](../develop/migrating-an-rc-daemon.md)).

## What `service foo start` does

`usr.sbin/service` is unchanged from FreeBSD. `service foo start` finds `/etc/rc.d/foo` (or a script under `local_startup`), gives it the rc.subr environment and dispatches `start`. For a service that is not on the adoption list this is the whole story, and rc.conf's `foo_enable` decides whether `start` does anything.

For an adopted service the script still works, and it is still the only correct way to signal the daemon, but switchboard's record is not updated by it. `service cron stop` stops cron and leaves switchboard believing the unit is `running`; `service cron start` afterwards starts it and switchboard is none the wiser. Use switchboardctl(8) for adopted units so the manager's state and the process agree:

```
$ anoint system.switchboard.admin switchboardctl restart cron
```

`switchboardctl start`, `stop` and `restart` require the `system.switchboard.admin` anointment on the caller's session, not root (see [Anointments and Principal Policy](../plane/anointments.md)); the shipped default policy gives wheel every anointment, so a wheel session runs the command without `anoint`.

## How an rc unit appears in switchboardctl

`switchboardctl status` prints daemon totals, the fd budget, and one line per loaded unit in the form `label state [pid N] restart=... mgmt=... [restarts=N] [by=...] [conns=N]`. An adopted rc unit looks like this among the native ones:

```
$ switchboardctl status
switchboard: running
...
  system.Log           running  pid 611 restart=always mgmt=core conns=4
  system.Network       running  pid 618 restart=always mgmt=system
  cron                 running  restart=on-failure mgmt=system
```

There is no `pid` on the cron line even though cron is running: the pid switchboard prints is that of the process it holds a descriptor for, and the `onestart` wrapper has exited. A unit that has stopped through `onestop` shows `stopped`. `switchboardctl services` prints the same list.

## rc.d scripts added and changed

Three scripts are new in `libexec/rc/rc.d`; all default to off and all carry `KEYWORD: nojail shutdown`.

| Script | rcvar | REQUIRE | Runs | Notes |
|---|---|---|---|---|
| `mac_abacd` | `mac_abacd_enable` | `FILESYSTEMS`, before `DAEMON` | `/usr/sbin/mac_abacd -c /etc/mac_abac.conf -p /var/run/mac_abacd.pid` | refuses to start if the policy file is unreadable or the `mac_abac` module is absent; ships in the `mac-abac` package |
| `blued` | `blued_enable` | `DAEMON bluetooth` | `/usr/sbin/blued` (the BSDBluetooth(8) program) | creates `/var/db/blued` mode 0700, loads `ng_ubt` and `ng_btsocket`, refuses to start with no `ubt` adapter |
| `meshd` | `meshd_enable` | `DAEMON blued` | `/usr/sbin/meshd` | Bluetooth Mesh node daemon; state in `/var/db/meshd.state` and `/var/db/meshd.mgr` |

Four existing scripts changed. `linux` loads only `linux64` and tolerates the missing `kern.elf32.fallback_brand` (there is no 32-bit ELF). `routing` silences the `File exists` error the kernel now produces for loopback routes it has already added. `zfs` only writes `/etc/zfs/exports` when `/etc/zfs` is writable, which matters on read-only install media. `motd` and `os-release` carry the 5BSD name (see [The BSD Side](bsd-side.md)). The `rc.d/Makefile` groups `mac_abacd` into the `mac-abac` package and `blued` and `meshd` into `bluetooth`, so a system without those packages has no dangling scripts.

Two things were removed from rc rather than added. The old daemon starts for the retired PID 1 helpers are gone, and the `rc` package's post-install script deletes a stale `rc.d/oracled` left by an earlier image. `auditd_enable="YES"` is the rc.conf default so system.Audit can commit.

## Shutdown and reboot

reboot(8), halt(8) and shutdown(8) no longer signal init. In normal mode they exec `/usr/sbin/capsulectl` with the matching verb (`reboot`, `halt`, `poweroff`, `single`, and `catatonia` for shutdown's freeze), which asks capsule for a service-ordered shutdown: units are quiesced, `/etc/rc.shutdown` runs, and PID 1 performs the final sweep. If the plane is unavailable or refuses the request they fall back to the process-termination sequence used in fast mode and `reboot(2)`. reboot(8) documents the delegation; `sbin/reboot/tests/reboot_test.c` covers the verb mapping and fallback.

## The /Capabilities/Run tmpfs

`/Capabilities/Run` is where switchboard publishes the running-bundle markers under `live/` that the providers' reconcile loops read (see [Containers and Storage](../plane/containers-and-storage.md)). It is a tmpfs, mounted from `/etc/fstab` by rc's filesystem scripts:

```
tmpfs /Capabilities/Run tmpfs rw,mode=0700 0 0
```

bsdinstall writes that line on every installed system and the release tooling writes it for install media. The directory itself exists in the root mtree with mode 0700 so the mount point is always there. This is the transitional arrangement's known wart: the mount is performed by rc while switchboard is already launching native units, so the ordering between the tmpfs mount and the first marker publication is rc's, not switchboard's. `SWITCHBOARD_RUN_DIR` overrides the path so a test fixture never touches the host's markers.

## Coexistence rules

The rc integration handbook (`docs/rc-integration-handbook.md`, section 23) sets the rule that makes the mixed system stable: every long-running daemon has exactly one owner, rc or switchboard, and no heuristic on process names or pidfiles substitutes for that record. The adoption list is that record for rc.d services. A daemon migrated to a bundle keeps its rc.d script as an adapter that preserves the `PROVIDE`, `REQUIRE` and `BEFORE` metadata and delegates start, stop and status to switchboardctl, so downstream rc.d scripts keep their ordering. `rcorder` establishes invocation order, not readiness; an adapter that returns immediately can let a dependent script run before the managed daemon is usable, so an adapter must wait for the unit's readiness where a downstream script needs a live provider.

## Status

switchboard runs `/etc/rc` concurrently with native units and adopts `cron`; both are VM-validated. `usr.sbin/switchboard/tests/rc_adopt_test.c` and `rc_ingest_test.c` cover the allow-list parsing, unit construction and the `onestatus`, `onestart` and `onestop` argv layouts. The full rc-unit migration, where each remaining rc.d service becomes a supervised unit and `/etc/rc` shrinks to setup, is planned and not done; until then `/etc/rc` starts every service the adoption list does not name, exactly as FreeBSD does.
