# Capsule, PID 1

Capsule is 5BSD's PID 1. It is the `capsule(8)` binary installed as
`/sbin/capsule`, running its init personality: a port of `init(8)`'s state
machine with one extra state that brings up the capability plane. 5BSD has it
because the plane needs a root of authority that exists before any service
does. Capsule claims the `mac_capability` control device and the configured
system gates exclusively, shields itself with capprotect, and starts exactly
one child, [switchboard](switchboard.md), which runs everything else.

Capsule deliberately does less than launchd. It does not read manifests, does
not launch services, and does not run `/etc/rc`. It is the spine: lifecycle
authority (reboot, halt, single-user, reroot), capability minting for
switchboard, orphan reaping, and `/etc/ttys` getty management.

## The boot spine

The loader picks PID 1 from `init_path`. The capsule package installs
`/boot/loader.conf.d/capsule-loader.conf`:

```sh
init_path="/sbin/capsule:/sbin/init:/sbin/init.bak:/rescue/init"
```

The stock `/sbin/init` stays installed as the executable fallback and as the
recovery init. Setting `init_path="/sbin/init"` at the loader prompt boots the
classic init and rc with no plane at all.

There is a second, softer escape hatch. The loader tunable `capability_plane`
is read by Capsule through `kenv(2)` before any plane state is built
(`usr.sbin/capsule/capsule.c`, `capsule_plane.h`). If it is `NO`, `off`
(either case-insensitive) or the exact digit `0`, Capsule logs
`capability_plane=NO: handing PID 1 to /sbin/init (plane-free boot)` and
`execv`s `/sbin/init`, forwarding `-s` when the kernel asked for single user.
The kernel, GENERIC's compiled-in mac_capability framework and every preloaded
module still load; only the plane supervisor stays down. This is how the
`/dev/mac_capability` device tests run: they need to open the control device
without a live switchboard owning it. If the exec fails, Capsule falls through
and boots the plane, so PID 1 is never left dead.

```sh
# at the loader prompt, one boot only
set capability_plane="NO"
boot
```

## Two halves, two tools

| Role | Process | Tool | Owns |
|---|---|---|---|
| Spine | `capsule` (PID 1) | capsulectl(8) | reboot, halt, poweroff, powercycle, single-user, reroot, ttys rescan, catatonia; capability minting; reaping; getty sessions; switchboard supervision |
| Service manager | `/usr/libexec/switchboard` | switchboardctl(8) | bundle registry, unit lifecycle, activation, name resolution, `/etc/rc` |

Lifecycle authority sits below the service manager on purpose: shutdown tears
switchboard down, so switchboard cannot be the thing that owns shutdown. When
switchboard dies, the spine survives and restarts it; when Capsule dies, the
kernel panics as it would for any PID 1 exit, which is why every exit path in
`capsule.c` is a logged emergency followed by a deliberate reboot or recovery.

## Boot: converge or recover

The init state machine keeps the stock names. `single_user` and `runcom` are
unchanged in shape, but `runcom` no longer runs `/etc/rc`; it hands straight
to the added state:

```text
single_user -> runcom -> establish_capsule -> read_ttys -> multi_user
                              |
                              +- capsule_engine_start():
                              |    load /etc/capsule.conf
                              |    verify PID 1 is the real-init reaper
                              |    mac_capability_setup(): claim the device,
                              |      network claims, system gates, shield
                              |    bootstrap_start(): pdfork(2) switchboard
                              +- capsule_await_convergence():
                              |    wait for CAPSULE_OP_READY on the channel
                              +- failure: single_user (recovery shell)
```

switchboard runs `/etc/rc` as a oneshot and launches native boot units in
parallel with it, then sends `CAPSULE_OP_READY` over its per-instance channel
(`usr.sbin/switchboard/switchboard.c`). Only then does Capsule read
`/etc/ttys` and start gettys. There is no clock on this wait: `/etc/rc` has no
knowable duration, and init historically waited forever. Recovery is
triggered only when switchboard permanently fails before convergence, meaning
its restart circuit breaker trips (below). A wedged-but-alive switchboard
hangs boot exactly as a wedged `/etc/rc` hung init before.

Two compatibility invariants carry over from init: PID 1 is already the
real-init reaper (Capsule verifies `PROC_REAP_STATUS` rather than acquiring
it), and `init_exec` is ignored because it is the hook that led the kernel to
this program in the first place. SysV runlevels (`init 0`, `init 6`) are not
accepted; the stock `/sbin/init` remains for that.

Shutdown mirrors boot: revoke ttys, run `/etc/rc.shutdown` while switchboard is
still available (its rc adapters may need it), stop the capability world
through switchboard's process descriptor with a `WORLD_WATCH` (30 s) deadline
and a SIGKILL escalation, global SIGTERM and SIGKILL sweep, `/etc/rc.final`,
`reboot(2)`.

## What Capsule holds

Capsule reads `/etc/capsule.conf` (UCL, optional, defaults compiled in; syntax
errors are fatal). The keys that matter to PID 1:

| Key | Meaning | Default |
|---|---|---|
| `service_manager` | first child | `/usr/libexec/switchboard` |
| `integrity { ptrace, signal, sigkill, sigcont, visible, wait, sched, core, ktrace }` | capprotect flags on Capsule | ptrace, signal, sigkill, sigcont, wait, sched, ktrace on; visible, core off |
| `claims.network[] { port, protocol, direction, domain, address }` | exclusive endpoint claims (at most 32) | empty |
| `claims.system[]` | system gates Capsule claims: `kldload`, `kldunload`, `reboot`, `swapon`, `swapoff`, `sysctl`, `kenv`, `kenv_read`, `acct`, `audit`, `settime`, `jail` (`lib/libcapbundle/gates.h`) | empty |
| `pidfile`, `control_socket`, `control_socket_mode` | daemon-personality only | see capsule.conf(5) |

`signal`, `sigkill` and `sigcont` cannot be turned off. `/dev/mac_capability`
is always claimed; it is the only path Capsule claims, because file access is
brokered at runtime by [BSDFilesystem](../providers/filesystem.md), not
pre-claimed. Claims listed in the file are policy claims: immortal, surviving
switchboard restarts. Anything switchboard asks Capsule to mint that is not
pre-declared becomes a dynamic, reference-counted claim, released from the
kernel when its count reaches zero and swept entirely when switchboard exits.

The system gates are the interesting half. Once Capsule claims a gate, the
gated operation is denied to every process, root included, unless the process
presents a token Capsule minted. Capsule mints those tokens only over its
channel to switchboard, and switchboard delivers them only to a unit whose
verified manifest declares them (see
[Bundles and Manifests](bundles-and-manifests.md#capabilities) and
[System Gates](../capability/system-gates.md)). PID 1 loads no kernel code:
`kldload` is brokered by [BSDExtension](../providers/extension.md), which holds
that gate.

## The control ABI

Classic init is administered by unauthenticated signals to PID 1. Capsule
retires that ABI. The design record is
`docs/capsule-control-abi-design.md`; the shipped shape is a held capability,
not a socket. The opcodes are the ones in `lib/libcapsulert/capsule_ctl.h`:

| capsulectl verb | Opcode | Effect |
|---|---|---|
| `reboot` | `CTL_OP_REBOOT` | reboot(2) `RB_AUTOBOOT` after the full death path |
| `halt` | `CTL_OP_HALT` | `RB_HALT` |
| `poweroff` | `CTL_OP_POWEROFF` | `RB_HALT|RB_POWEROFF` |
| `powercycle` | `CTL_OP_POWERCYCLE` | `RB_POWERCYCLE` |
| `single` | `CTL_OP_SINGLE` | shutdown to single-user |
| `reroot` | `CTL_OP_REROOT` | `RB_REROOT` |
| `rescan` | `CTL_OP_RESCAN` | reread `/etc/ttys` (was SIGHUP) |
| `catatonia` | `CTL_OP_CATATONIA` | stop new logins (was SIGTSTP) |
| `status` | `CTL_OP_STATUS` | spine reachability and unit count |
| `reload` | `CTL_OP_RELOAD` | reload claims from `/etc/capsule.conf` |

The path a request takes (`usr.sbin/capsulectl/capsulectl.c`,
`usr.sbin/switchboard/sctl.c`, `usr.sbin/capsule/capsule_proto.c`):

```text
capsulectl reboot
  -> service_open("system.lifecycle")          ambient lookup channel
  -> switchboard: sctl_rights_is_admin()?      EPERM if not
  -> capsule_lifecycle(channel, CTL_OP_REBOOT) CAPSULE_OP_LIFECYCLE on the
                                               per-instance Capsule channel
  -> capsule_lifecycle_apply(): requested_transition = death
  -> multi_user() kqueue loop returns; death -> death_single -> reboot(2)
```

`system.lifecycle` is a name switchboard self-serves in its registry. A
session can resolve it only if it holds the `system.switchboard.admin`
anointment (or every anointment, as a shipped-default wheel session does); any
other session, and every unit, gets `ENOENT`. There is no `getpeereid`, no
`euid == 0` check and no path. `status` and `reload` are answered by
switchboard from what it already tracks:

```text
# capsulectl status
Capsule: reachable (spine, PID 1)
control plane: capability (system.lifecycle)
services loaded: 23
```

`reboot(8)`, `halt(8)` and `shutdown(8)` call `/usr/sbin/capsulectl` first
(`sbin/reboot/reboot.c`, `reboot_request()`) so an ordinary reboot gets the
service-ordered shutdown. If capsulectl is unavailable or refuses, they fall
back to the stock SIGTERM/SIGKILL sweep and `reboot(2)`; `reboot -q` skips
straight to the kernel escape. The fast paths (`fasthalt`, `-o`) use
`capsulectl catatonia` and `capsulectl single` with signal fallbacks.

The separate daemon personality (`/usr/sbin/capsule` not running as PID 1)
still opens the root-only control socket named in `capsule.conf`
(`usr.sbin/capsule/main.c`, `control.c`), which is what the test harness
drives. PID 1 never opens it: `capsule_engine_start()` does not call
`ctl_setup()`.

## Signals Capsule ignores

The default integrity flags, `CP_SF_SIGKILL` and `CP_SF_SIGCONT` among them,
go on at engine start. Once the mac_capability device is up, and before
`/etc/rc` runs, Capsule adds `CP_SF_SIGNAL` over itself
(`capsule_assert_signal_shield()`, `apply_signal_shield()` in
`usr.sbin/capsule/mac_capability_claims.c`), and asserts it again after
convergence. A userland
`kill(1, SIG*)` from any foreign nonce is denied by the kernel. Because the MAC
signal shield cannot bind root the same way, the legacy transition signals
(`SIGHUP`, `SIGINT`, `SIGTERM`, `SIGTSTP`, `SIGUSR1`, `SIGUSR2`, `SIGWINCH`)
are also caught by a handler that records a boottrace entry and changes no
state (`transition_handler()`). Both doors are closed. Root keeps only the
`reboot(2)` authority the kernel already grants it.

Kernel-internal signalling is unaffected: `SIGCHLD` reaping, `SIGALRM`
shutdown timeouts, and `pdkill(2)` through the switchboard process descriptor
all keep working under the full shield. `init N` (telinit) is a signal path
and silently no-ops under Capsule.

`SIGABRT`, `SIGSEGV` and the other disaster signals reboot deliberately
rather than exiting, because a PID 1 exit panics the kernel.

## What happens when switchboard exits

switchboard is started with `pdfork(2)`; the descriptor is limited to
supervision rights and confined against transfer and inheritance, so holding
it is the only explicit signal authority over switchboard. Its exit is the
single source of truth for lifecycle (`usr.sbin/capsule/bootstrap.c`,
`bootstrap_teardown_and_restart()`):

| Condition | Action |
|---|---|
| switchboard ran at least 5 s (`BOOTSTRAP_MIN_UPTIME`) | crash counter reset, immediate restart |
| died within 5 s | delay `1 << (count - 1)` s, capped at 30 s (`BOOTSTRAP_MAX_DELAY`) |
| 10 consecutive fast failures (`BOOTSTRAP_MAX_FAILURES`) | circuit breaker trips; `bootstrap: switchboard failed 10 times, giving up` |
| Capsule is shutting down | no restart |

Every dynamic claim is swept from the kernel when switchboard exits; policy
claims survive. Because each unit's coalition descriptor is held by the
switchboard instance that launched it, those descriptors close as switchboard
dies and the units are terminated with it. The replacement switchboard rescans
the registry and relaunches boot units, and every provider begins with all of
its names unclaimed. Existing login sessions keep running; their lookups fail
soft until the replacement is up. The channel Capsule hands to each new getty
is a dup switchboard sends to PID 1 during its startup
(`capsule_set_ambient_lookup()`), pinned at `SERVICE_LOOKUP_FIXED_FD` (fd 3)
across the getty fork so login inherits it, and a replacement switchboard
sends a fresh one (see
[Discovery and the Lookup Channel](discovery-and-lookup.md)).

If the breaker trips before convergence, `establish_capsule()` logs
`switchboard did not converge; entering recovery` and drops to the
single-user shell. After convergence it leaves the system in multi-user with
rc-started services running and the plane down; `Capsule engine started;
switchboard pid N` in the log marks each successful start.

## Coexistence with rc

A mixed system is a designed operating mode, not a transition failure.
switchboard owns `/etc/rc` (it runs `/bin/sh /etc/rc autoboot` once, on the
console) and launches native boot units before and concurrently with it; a
non-zero rc exit is logged but does not block convergence. Everything the
FreeBSD Handbook says about rc.conf layering, rcorder and service(8) still
holds for rc-owned daemons. What moved out of rc: Capsule itself (there is no
`rc.d/capsule`), lifecycle signalling of PID 1, module loading, and every
native capability service. The details, including the curated adoption list,
are in [Switchboard](switchboard.md#rc-adoption) and
[rc and service(8)](../compat/rc-and-service.md).

## Observability

Capsule carries a `capsule` USDT provider with lifecycle, claim, mint, IPC and
bootstrap probes; capsule(8) lists them. `dtrace -n 'capsule*:::bootstrap-*'`
shows switchboard starts, exits and scheduled restarts. Boot progress is also
written through `BOOTTRACE`, so `boottrace(8)` output shows `awaiting
switchboard convergence` and `switchboard converged`.

## Status and limits

The lifecycle, minting, shield and plane-free paths are shipped and covered by
`usr.sbin/capsule/tests` (boot, bootstrap, init, lifecycle, plane and request
validation tests, plus VM boot runners). Two things to know before relying on
it. First, Capsule does not pet a hardware watchdog: a wedged-but-alive PID 1
is covered only by `reboot -q`, ddb and platform watchdogs, a deliberate
decision recorded in the design document. Second, capsule.conf(5) and
capsule(8) still document the control socket and its `CTL_OP_SHUTDOWN`,
`CTL_OP_STATUS` and `CTL_OP_RELOAD` opcodes as if they applied to PID 1; they
apply to the daemon personality only, and the reboot man page text that says
capsulectl "sits beside" the stock tools predates `reboot(8)`'s delegation.
Follow the code paths named above.

Reference: capsule(8), capsule.conf(5), capsulectl(8),
`docs/capsule-control-abi-design.md`.
