# Authority Init

5BSD replaces `init(8)` with **Authority** as PID 1. The same binary serves two
roles: as `authorityd(8)` it is the capability broker — the authority that owns
`mac_capability`, mints capability tokens, and supervises `serviced(8)` — and
when it finds itself running as PID 1 it switches to a dedicated init
personality (`usr.sbin/authorityd/authority_init.c`). The daemon path (daemonize,
pidfile, exit-on-error) never runs at PID 1:

```c
/* usr.sbin/authorityd/authorityd.c */
if (getpid() == 1)
        authority_init_main(argc, argv);
```

## Architecture: spine and service manager

Authority deliberately splits the roles launchd combines into one process:

| Role | Process | Control tool | Owns |
| --- | --- | --- | --- |
| Spine (PID 1) | `authority-init` / `authorityd` | `authorityctl(8)` | System lifecycle (reboot, halt, single-user, reroot, rescan, catatonia), capability authority, global reaping, recovery console, serviced supervision |
| Service manager | `serviced` | `servicectl(8)` | Per-service lifecycle, demand activation, trigger ownership, `/etc/rc` |

Authority that must survive the service manager's death stays in the spine:
reboot does not depend on `serviced` being alive, because during shutdown
`serviced` is itself torn down. `serviced` runs as a `pdfork(2)` child of the
spine and is supervised through its process descriptor; if authorityd dies, the
kernel closes that descriptor and the exact serviced instance terminates with
it. Reboot authority lives in PID 1 and module loading is an authorityd
channel operation (`AUTHORITY_OP_ENSURE_KMOD`); neither has a standalone
daemon.

## PID-1 boot path

`/sbin/authority-init` is a second installed copy of the authorityd binary kept on
the root filesystem, because `/usr` may be a separate, unmounted filesystem
when the kernel starts init (see `usr.sbin/authorityd/Makefile`). The shipped
loader configuration selects it with executable fallbacks:

```sh
# /boot/loader.conf.d/authority-init.conf
init_path="/sbin/authority-init:/sbin/init:/sbin/init.bak:/rescue/init"
```

The init personality is a port of `init(8)`'s state machine (behavior
contract: `docs/freebsd-init-behavior-audit.md`) with one added state,
`establish_authority`:

```text
single-user → runcom → establish_authority → read_ttys → multi_user
                          │
                          ├─ start capability engine (mac_capability,
                          │  control socket, pdfork serviced)
                          ├─ wait for serviced convergence (serviced runs
                          │  /etc/rc, services bounded boot demand, then sends
                          │  AUTHORITY_OP_READY on its authenticated channel)
                          └─ on failure: recovery single-user shell
```

This is the **converge-or-recover gate**: PID 1 does not run `/etc/rc` itself
and does not proceed to getty/login until serviced signals convergence.
There is deliberately no clock deadline — `/etc/rc` has no knowable duration
(fsck, key generation, entropy waits) — recovery triggers only when serviced
*permanently* fails (its restart circuit breaker trips). The full boot flow
authority-init → serviced → rc → native services → converge → login is validated
in a VM. Intentional divergences from stock init are logged at runtime:
`init_exec` is ignored (it is the hook that reached this program), and
`COMPAT_SYSV_INIT` runlevels are not accepted — stock `/sbin/init` remains
installed for that.

PID 1 compatibility invariants (from `docs/authority-init-todo.md`): never
daemonize, never exit — every stock-init exit path becomes a logged emergency
followed by deliberate reboot or recovery; verify (not acquire) real-init
reaper status; continuously reap all children and adopted orphans; preserve
`/etc/ttys` getty management with init's crash-throttling constants; shutdown
order is revoke ttys → `/etc/rc.shutdown` (serviced still available) →
drain/stop serviced via its procdesc → global `SIGTERM`/`SIGKILL` sweep →
`/etc/rc.final` → `reboot(2)`.

## Control ABI

Stock init is administered by unauthenticated, untyped signals to PID 1.
Authority replaces that with typed operations on the authenticated control
socket `/var/run/authorityd.sock` (design: `docs/authority-control-abi-design.md`,
opcodes in `lib/libauthorityrt/authorityd_ctl.h`):

```text
CTL_OP_SHUTDOWN    1   graceful authorityd shutdown        (root)
CTL_OP_STATUS      2   status, claims, integrity flags  (any user)
CTL_OP_RELOAD      3   reload config, SIGHUP serviced   (root)
CTL_OP_REBOOT      4   reboot(2) RB_AUTOBOOT            (root)
CTL_OP_HALT        5   RB_HALT                          (root)
CTL_OP_POWEROFF    6   RB_HALT|RB_POWEROFF              (root)
CTL_OP_POWERCYCLE 10   RB_POWERCYCLE                    (root)
CTL_OP_SINGLE     11   shutdown to single-user          (root)
CTL_OP_REROOT     12   RB_REROOT                        (root)
CTL_OP_RESCAN     13   reread /etc/ttys  (was SIGHUP)   (root)
CTL_OP_CATATONIA  14   stop new logins   (was SIGTSTP)  (root)
```

`reboot(8)`, `halt(8)`, and `shutdown(8)` were converted to speak this ABI
first, falling back to the traditional signal ABI when the socket is absent
(stock-init systems and Authority's own pre-engine early-boot window). See
`sbin/reboot/reboot.c`. The lifecycle opcodes are rejected when
`getpid() != 1`: an ordinary authorityd daemon cannot reboot the machine.
Authorization is root via `getpeereid(3)`. Operator usage:

```sh
authorityctl status      # daemon status, active claims, serviced state (any user)
authorityctl reload      # reload authorityd.conf claims, SIGHUP serviced (root)
authorityctl shutdown    # graceful authorityd shutdown (root)
```

## Signal shield

Authority's capability integrity shield (`CP_SF_SIGNAL`, plus `SIGKILL` and
`SIGCONT` protection) denies ambient PID-based signalling of protected
processes — and PID 1 is the most protection-worthy process on the system.
When Authority is PID 1, the `CP_SF_SIGNAL` shield is *deferred* until the
control socket is up and the converted tools have an authenticated lifecycle
path; it is then raised, making the signal ABI unreachable
(`usr.sbin/authorityd/mac_capability_claims.c`). Signal handlers remain
installed only to cover the pre-engine early-boot window.

Kernel-internal signals are unaffected: `SIGCHLD` reaping, shutdown timers,
and authorityd's `pdkill(2)` authority over serviced (procdesc signalling
bypasses `p_cansignal`) keep working under the full shield. `serviced` is
shielded the same way; authorityd retains explicit stop authority through the
process descriptor from `pdfork(2)`.

Emergency paths when the event loop is wedged: `reboot -q` calls `reboot(2)`
directly and touches neither socket nor init; ddb's `reboot` on the console;
and a platform/BMC/hypervisor watchdog. PID 1 deliberately does not pet a
software `watchdog(4)`.

**Status.** `init N` (SysV telinit) is unsupported under Authority PID 1: that
compatibility path signals PID 1 and is deliberately not converted, so it
silently no-ops under the shield — use `reboot(8)`/`shutdown(8)`/`halt(8)`.
`docs/service-architecture-plan.md` is the authoritative pre-v1 service-manager
roadmap. It deliberately rejects dependency targets and per-script rc graph
ingestion; timers and path events are future demand sources. The boot,
shutdown, and control-ABI paths described above are implemented and
VM-validated.
