# FreeBSD `init(8)` Source-Complete Behavior Audit

## Purpose and scope

This document records the complete externally meaningful behavior of the
`init(8)` implementation in this source tree as reviewed on 2026-07-19.  It is
the compatibility baseline for making Authority PID 1.  It describes what the
code does, including obscure recovery and failure paths; it does not assume
that every historical behavior must be copied unchanged.

The primary sources are:

- `sbin/init/init.c`, `init.8`, `Makefile`, `NOTES`, and `pathnames.h`;
- `sys/kern/init_main.c`, `kern_exit.c`, `kern_sig.c`, and `kern_procctl.c`;
- `libexec/rc/rc` and `libexec/rc/rc.shutdown`;
- `sbin/reboot/reboot.c` and `sbin/shutdown/shutdown.c`;
- `lib/libc/gen/ttys.c` and the `ttys(5)` interface.

“Source-complete” means every function, state, signal, boot option, loader
variable, child-management path, and kernel PID-1 special case in those
sources is represented below.  Kernel boot, rc, and shutdown contain other
subsystems of their own; those are referenced where they form an init
contract rather than duplicated line by line.

## 1. The kernel creates a special process, not merely PID number 1

The kernel creates the first user process during boot and assigns it PID 1.
Before the first user instruction executes, the kernel:

- marks the process as a system process resident in memory;
- makes it the real, permanent process-tree reaper;
- installs root credentials and the kernel's initial MAC credentials;
- searches `kern.init_path` for an executable init program; and
- supplies `-s` when the kernel boot flags contain `RB_SINGLE`.

The default executable search path is:

```text
/sbin/init:/sbin/oinit:/sbin/init.bak:/rescue/init
```

These properties have consequences for a replacement:

- PID 1 already owns real-init reaper status.  `PROC_REAP_ACQUIRE` is neither
  necessary nor valid; the process should query and verify that status.
- PID 1 cannot release its reaper role.
- children and qualifying orphaned descendants are ultimately reparented to
  a process reaper, with real init as the final reaper.
- the kernel prevents PID 1 from selecting `SA_NOCLDWAIT`.
- broad process-group signal operations exclude PID 1 and system processes;
  an explicit signal addressed to PID 1 remains a distinct operation.
- if PID 1 exits outside the kernel's deliberate reboot path, the kernel
  panics with the equivalent of “Going nowhere without my init!”.

Authority must treat remaining alive as a safety property.  A normal daemon's
“log and exit” error path is not acceptable in PID-1 mode.

## 2. Build-time personalities and installed recovery copy

The init build supports these compile-time features:

- `DEBUGSHELL`: allow an operator to type an alternate single-user shell;
- `SECURE`: authenticate root before an insecure-console single-user shell;
- `LOGIN_CAP`: apply login-class resource policy to children; and
- `COMPAT_SYSV_INIT`: let a non-PID-1 invocation translate runlevel-like
  arguments into signals sent to PID 1.

The build links init with `libutil` and `libcrypt`.  Installation preserves a
backup init image as `init.bak`.  The kernel's default search path makes that
backup, and then the rescue init, operational rollback mechanisms rather than
mere packaging artifacts.

An Authority rollout must preserve an independently bootable binary in
`kern.init_path`; replacing every candidate with the same implementation
would defeat the fallback design.

## 3. Program entry and one-shot compatibility invocation

`main()` first requires real UID 0.  With
`COMPAT_SYSV_INIT`, invocation while not PID 1 is a command client rather than
a second init.  The exact mappings are `0` to `SIGUSR2` (halt and power off),
`1` to `SIGTERM` (single-user), `6` to `SIGINT` (reboot), `c` to `SIGTSTP`
(catatonia), `q` to `SIGHUP` (rescan ttys), and `r` to `SIGEMT` (reroot).
It sends the signal and exits without checking `kill(2)`'s result.  An invalid
runlevel is rejected; invocation with no runlevel reports “already running.”

When it is PID 1, init:

1. saves its executable name for the reroot trampoline;
2. opens syslog as `init`, with console fallback and the authentication
   facility;
3. calls `setsid(2)`, accepting the already-session-leader case;
4. establishes the system login name as `root`;
5. parses `-d`, `-s`, `-f`, and `-r`;
6. installs fatal and transition signal handling;
7. closes descriptors 0, 1, and 2; and
8. processes loader-provided initialization overrides.

The boot options mean:

- `-d`: mount devfs during early initialization;
- `-s`: begin in single-user mode;
- `-f`: fast boot, suppressing the normal autoboot argument to rc; and
- `-r`: enter the second half of a root-filesystem reroot.

Terminal input/output stop signals are ignored.  Init blocks essentially all
signals except those used by its transition machinery, then waits with masks
chosen by each state.

## 4. Loader environment hooks and their exact order

Init recognizes these kernel environment variables:

| Variable | Behavior |
| --- | --- |
| `init_exec` | Replace init immediately with the named program. |
| `init_script` | Run a script before ordinary initialization; failure selects single-user mode. |
| `init_chroot` | Change root and current directory before continuing. |
| `init_shell` | Select the shell used for `init_exec`, `init_script`, startup/shutdown scripts, and single-user recovery.  The current `rc.final` path execs its file directly and does not consult this value. |
| `init_rc` | Select an alternate startup script in place of `/etc/rc`. |
| `init_path` | Select the post-reroot executable search path. |

The order is security- and deployment-relevant.  `init_exec` and
`init_script` are considered before `init_chroot`, and all three precede
init's devfs detection and mount.  Therefore an Authority entered through
`init_exec` cannot depend on stock init having prepared `/dev`; it must do so
itself or be statically able to continue to recovery.

After these hooks, init detects whether `/dev` needs devfs and mounts it when
requested or necessary.  Except during reroot phase two, it force-unmounts a
leftover `/dev/reroot` from a failed or previous reroot attempt.  The devfs
`nmount(2)` result is not checked; the later console and child paths must cope
with an unusable `/dev`.  A failed `init_chroot` operation is likewise logged
as a warning and boot continues.

## 5. Logging, diagnostics, and the console fallback

The diagnostic functions have intentionally different severity:

- warnings log and continue;
- emergencies log at emergency severity and continue along the caller's
  recovery path;
- stalls log, then sleep for 30 seconds to prevent a tight failure loop.

Fatal handlers cover `SIGABRT`, `SIGFPE`, `SIGILL`, `SIGSEGV`, `SIGBUS`,
`SIGSYS`, `SIGXCPU`, and `SIGXFSZ`.  The handler logs the disaster, sleeps for
30 seconds, and terminates with the signal number.  For PID 1 that termination
is intentionally catastrophic and must not be copied blindly by Authority; a
replacement needs a minimal, async-safe recovery/reboot policy.

Opening the console revokes prior users of the console device, opens it
read/write and initially nonblocking, clears nonblocking mode, and makes it
the controlling terminal.  If that fails, init uses `/dev/null` for input and
tries `/var/log/init.log` (mode 0644) for output.  If the log cannot be opened,
output also goes to `/dev/null`.

Thus neither syslog nor a working console is assumed.  Authority needs the same
early-boot independence and must avoid making `/var` a prerequisite for
survival.

## 6. The state-machine model

Init is an explicit, non-returning state machine.  A state function performs
work and returns the next state function; `transition()` invokes states
forever.  Initial state is runcom, single-user, or reroot phase two according
to boot arguments.

The states are:

```text
single_user      interactive recovery or final reboot syscall
runcom           run the startup script
read_ttys        build the session configuration
multi_user       maintain sessions and reap children
clean_ttys       reconcile a changed /etc/ttys
catatonia        stop creating replacement login sessions
death            orderly shutdown script stage
death_single     terminate remaining processes
reroot           shutdown and construct the reroot trampoline
reroot_phase_two ask the kernel to switch roots and exec the new init
```

The requested next state is stored independently of the currently executing
state.  Long-running waits inspect it, so a transition request can interrupt
a script, shell, or multi-user wait without relying on normal function return
timing.  Before dispatch begins, `current_state` is initialized to
`death_single`; a sufficiently early shutdown signal therefore selects the
minimal process-termination path rather than assuming startup completed.

## 7. Startup script execution

`runcom` selects `/etc/rc` unless `init_rc` overrides it.  On an ordinary
autoboot it passes the argument `autoboot`; fast boot omits that argument.

The common script runner:

- forks a child;
- gives the child the console;
- ignores `SIGHUP` and `SIGTSTP` in the child;
- restores an executable signal mask;
- applies the `daemon` login class when login capabilities are built in;
- attempts to execute an executable script directly first; and
- falls back to the configured shell, using shell verification under the
  secure build.

The parent waits while also reaping unrelated children through the normal
child collector.  Fork failure, wait failure, signal termination, or nonzero
exit selects single-user recovery.  A stopped script is continued.  A
shutdown request received during the script redirects the state machine to
shutdown rather than completing boot.

There is a special reboot interaction: if a script was killed by `SIGTERM`
and init was put into catatonia as part of a direct reboot operation, init
waits indefinitely while the rebooting process completes the kernel reboot.

Successful startup rereads `/etc/ttys`, clears autoboot mode, and enters
multi-user operation.

## 8. Single-user and recovery behavior

Single-user mode is both a boot choice and the universal recovery target.
Init forks a shell attached to the console and waits for it while continuing
to reap unrelated children.

With the secure build, an insecure console plus a protected root account
causes a root-password challenge before a shell is exposed.  With
`DEBUGSHELL`, the operator may choose another shell path.  Init sets `HOME`
from the root account when possible, changes to that directory or `/`, clears
the child's blocked-signal state, and executes the shell with a login-style
`argv[0]`; `/bin/sh` is the final fallback.

If the shell stops, init sends `SIGCONT`.  An outstanding state transition
wins over the shell's result.  Abnormal shell termination starts recovery
again; a shell killed with `SIGKILL` causes a 30-second stall before init
terminates catastrophically.  Normal shell exit requests a fast boot and
runs the startup script.

When a reboot-family request has already set the reboot flag, entry to
single-user mode does not start a shell.  It emits boot tracing, calls
`sync(2)`, runs `/etc/rc.final`, and invokes `reboot(2)` with the selected
halt, poweroff, power-cycle, reroot, or reboot flags.  Returning from the
syscall is treated as an emergency.

## 9. `/etc/ttys` parsing and session representation

Init reads entries enabled by `TTY_ON` that have a name and getty command.
Each becomes an in-memory session containing:

- the tty name and `/dev/<name>` path;
- parsed getty and optional window-system argument vectors;
- terminal type and configured environment;
- process ID and start time;
- crash-throttle counters; and
- presence, shutdown, if-exists, and if-console flags.

The command parser splits on whitespace and supports single-quoted groups.
It is not a shell parser: it does not provide general shell expansion or a
complete escaping language.  Init appends the tty name as the final getty
argument.

A PID-indexed session database maps getty children back to configuration.
Failure to create this database stalls and retries instead of abandoning PID
1 operation.

`TTY_IFEXISTS` and `TTY_IFCONSOLE` entries are conditional.  Init probes the
named device nonblocking; a missing path suppresses the session.  The ttys
interface also permits non-device names, and the manual explicitly supports
using entries to supervise arbitrary daemon commands.  Authority must either
retain this compatibility or clearly migrate every such deployment.

## 10. Starting windows and gettys

For an entry with a window command, each getty launch double-forks a window
process so PID 1 adopts it, waits for the intermediate child, and then delays
three seconds before starting the getty.

The getty child:

- restores its signal mask;
- applies the `default` login class;
- executes with an otherwise empty environment containing only `TERM` when a
  terminal type is configured; and
- executes the configured command with the prepared arguments.

A getty that exits less than five seconds after launch is considered rapidly
failing.  After more than three such starts, init sleeps for 30 seconds before
trying again.  Stable runs reset the effective crash sequence.

The constants in this implementation are therefore part of observable
behavior: five-second spacing, three tolerated rapid failures, a 30-second
backoff, and a three-second window/getty delay.

## 11. Multi-user child supervision and reaping

On entry to multi-user mode, init raises securelevel from zero to one, starts
each configured session not already running, emits its one-time run trace,
and blocks waiting for children or transition signals.

Every collected child is reaped.  A child not found in the session database
is intentionally just an unrelated child from init's perspective.  For a
known session, init removes the PID mapping and then either:

- frees a session marked for shutdown or whose conditional tty vanished; or
- restarts its getty, subject to throttling.

Fork failure while starting a getty requests a tty-configuration cleanup and
retry.  This same collection path is used while init waits for boot,
shutdown, final, and recovery children, which prevents zombies during
otherwise synchronous operations.

## 12. Live `/etc/ttys` reconciliation

`SIGHUP` requests `clean_ttys` from the normal session-management states.
The reconciliation algorithm marks old sessions absent, rereads the file,
and compares each entry:

- unchanged sessions remain running;
- disabled or invalid entries are marked for shutdown and sent `SIGHUP`;
- changed getty, window, or type causes the current child to receive
  `SIGHUP` and reset crash throttling before restart;
- new entries are allocated and started; and
- entries absent from the new file are marked for shutdown and sent
  `SIGHUP`.

Children are not synchronously killed and replaced in the parser.  Their
normal exit and collection completes the transition safely.

One implementation quirk must be treated explicitly: reconciliation does not
recompute `TTY_IFEXISTS` or `TTY_IFCONSOLE` flags for an already existing
session.  Changing only those flags may therefore require a full init/session
restart to take effect.  Authority should test compatible behavior or document
that it intentionally fixes this limitation.

## 13. Catatonia

`SIGTSTP` requests catatonia from boot/session states.  Catatonia marks every
session as shutting down, which prevents exited login sessions from being
restarted, and then continues reaping in the multi-user loop.  It does not by
itself stop all services or reboot the machine.

This is both an administrative “stop spawning logins” operation and a
coordination primitive used by low-level reboot paths.  Authority needs an
explicit equivalent even if it moves from signals to a control protocol.

## 14. Signal-to-transition protocol

The traditional PID-1 control ABI is:

| Signal | Requested operation |
| --- | --- |
| `SIGHUP` | Reread and reconcile `/etc/ttys`. |
| `SIGTSTP` | Enter catatonia; stop replacing sessions. |
| `SIGTERM` | Orderly shutdown to single-user mode. |
| `SIGINT` | Orderly shutdown, then reboot. |
| `SIGUSR1` | Orderly shutdown, then halt. |
| `SIGUSR2` | Orderly shutdown, then power off. |
| `SIGWINCH` | Orderly shutdown, then power-cycle. |
| `SIGEMT` | Begin root-filesystem reroot. |

Some requests are meaningful only from particular states; reboot-family and
reroot requests establish global next-state intent.  Repeated or conflicting
requests are resolved by the current handler and state rather than queued as
independent transactions.

`shutdown(8)`, `reboot(8)`, and `halt(8)` depend on this ABI.  A mandatory
Authority signal shield blocks it unless the tools and rc integration use an
authorized Authority control endpoint.  The desired end state is a capability
control protocol with explicit authority, but compatibility must not be
removed until every base-system caller has migrated or a narrowly defined
bridge remains.

Init also emits boot/shutdown trace events for lifecycle transitions.  An
Authority replacement should preserve equivalent observability even if it uses
a different tracing provider.

## 15. Orderly shutdown

The `death` state first blocks system suspend through
`kern.suspend_blocked`, records the prior value, revokes login terminals, and
runs `/etc/rc.shutdown`.  It restores the suspend setting afterward even if
the script fails.  Script failure is logged but cannot cancel system
shutdown.

The shutdown script receives:

- `reboot` for reboot-family shutdown; or
- `single` for shutdown into single-user mode.

Missing `/etc/rc.shutdown` is allowed.  The timeout defaults to 120 seconds
and may be replaced by `kern.init_shutdown_timeout` when that value is at
least two seconds.  Init waits while reaping other children.  On timeout it
sends `SIGTERM` to the waited-for child and advances shutdown; a stopped
script receives `SIGCONT`.  Signal termination and nonzero status are logged.

The stock `/etc/rc.shutdown` loads the rc framework and configuration,
orders scripts carrying the `shutdown` keyword in reverse dependency order,
and invokes `faststop`, with jail filtering.  Its own `rcshutdown_timeout`
watchdog is distinct from init's outer script deadline.

For Authority, the managed capability world must become an explicit stage
inside this bounded sequence: inhibit new work, ask `serviced` to quiesce,
use the retained procdesc authority if it misses its deadline, then continue
with the Unix/rc world.

## 16. Revoking sessions and terminating the remaining Unix world

Before shutdown scripts, `revoke_ttys()` marks sessions as shutting down,
sends their children `SIGHUP`, and revokes the associated devices.

After the script stage, `death_single` performs two global rounds:

1. broadcast `SIGTERM`, reap for up to ten seconds;
2. broadcast `SIGKILL`, reap for up to ten seconds.

The kernel excludes PID 1 and protected system processes from these broad
broadcasts.  If no targets or no children remain, init advances immediately.
If processes survive both rounds, init logs the condition and still enters
single-user/final-reboot handling rather than waiting forever.

An Authority implementation must distinguish its procdesc-controlled managed
tree from this final global sweep.  The procdesc path supplies race-free,
delegated authority for `serviced`; the global PID-1 cleanup remains necessary
for unrelated Unix processes and adopted orphans.

## 17. Final script and kernel reboot

Immediately before the reboot syscall, init synchronizes filesystems and
runs `/etc/rc.final` if it exists and is executable.  The final child receives
the console and a normal `SIGCHLD` disposition.  Init waits and reaps, but
does not impose a timeout and does not make reboot contingent on the exit
status.

The absence of a timeout is an important existing behavior and a potential
reliability defect.  Authority must make an explicit compatibility decision:
preserve it, add a documented deadline, or offer a compatibility mode.  It
must not acquire an accidental infinite wait merely because the behavior was
not noticed.

After final handling, `reboot(2)` transfers control to the kernel's shutdown
path.  Userland does not itself flush every device or power off hardware.

## 18. Root-filesystem reroot

Reroot is a two-exec operation designed to survive replacement of the root
filesystem:

1. revoke sessions and run the shutdown script;
2. send `SIGKILL` to the remaining user process population;
3. read the currently running init executable into memory;
4. mount a temporary filesystem at `/dev/reroot`;
5. recreate the executable as `/dev/reroot/init`; and
6. execute that copy with `-r`.

The phase-two process calls `reboot(RB_REROOT)` to ask the kernel to switch
roots.  It then obtains `init_path` from the kernel environment or
`kern.init_path`, searches the new root, and executes the first viable init.
Failure returns to single-user recovery.  Ordinary startup removes stale
reroot mount state.

Authority cannot claim init compatibility without either implementing this
trampoline safely or deliberately retaining stock init for reroot requests.

## 19. Resource classes and child execution context

With login capabilities enabled, init applies login-class settings with
environment, priority, resource-limit, login-class, and CPU-mask controls:

- startup and shutdown script children use class `daemon`;
- getty and window children use class `default`.

Child paths also deliberately restore signal masks and dispositions before
exec.  A replacement must audit both inherited descriptors and inherited
process state.  Authority's monotonic descriptor policy should close or limit
authority before exec, while login-class compatibility preserves traditional
resource policy.  These mechanisms solve different problems and both matter.

## 20. What init deliberately does not do

Init does not implement individual daemon dependency policy.  `/etc/rc`,
`rcorder`, rc.d scripts, and service-specific control methods do that.  Init
does not decide that `service authorityd stop` means `SIGTERM`; the Authority rc.d
script can and should translate it into an authenticated control operation.

Init also does not use procdescs for ordinary session children, distribute
capability tokens, activate program capabilities, or understand Authority's
managed service graph.  Those are additions to the model, not compatibility
behaviors to infer from init.

`_PATH_SESSIONLOGGER` is defined by init's path header but is not invoked by
the reviewed implementation.  It is not a current runtime obligation.

## 21. Complete function-to-responsibility inventory

This inventory guards against omissions during future source changes.

| Source unit | Responsibility captured above |
| --- | --- |
| `main`, `handle`, `delset` | PID-1 entry, options, signal masks and handlers |
| `stall`, `warning`, `emergency`, `disaster` | diagnostics and fatal behavior |
| `getsecuritylevel`, `setsecuritylevel` | multi-user securelevel transition |
| `transition` | non-returning state dispatcher |
| `open_console`, `get_shell`, `write_stderr` | console and recovery I/O |
| `read_file`, `create_file`, `mount_tmpfs` | reroot executable trampoline |
| `reroot`, `reroot_phase_two`, `replace_init` | two-phase reroot and exec search |
| `single_user` | authentication, recovery shell, final reboot path |
| `runcom`, `run_script`, `execute_script` | startup/shutdown script execution |
| session database functions | PID-to-session ownership and lifecycle |
| `construct_argv`, `new_session`, `setupargv`, `free_session` | ttys parsing and storage |
| `read_ttys`, `clean_ttys` | initial and live ttys configuration |
| `start_window_system`, `start_getty` | child launch and throttling |
| `session_has_no_tty`, `collect_child` | conditional sessions and reaping |
| `get_current_state`, `boottrace_transition` | state introspection and tracing |
| `transition_handler`, `alrm_handler` | lifecycle signal and timeout requests |
| `multi_user`, `catatonia` | steady state and spawn inhibition |
| `death`, `death_single`, `revoke_ttys` | orderly and forced shutdown stages |
| `runshutdown`, `strk` | bounded rc shutdown and simple command parsing |
| `setprocresources` | login-class child policy |
| `runfinal` | unbounded final script before reboot |

## 22. Source/manual discrepancies that require a decision

The reviewed implementation and its manual are not perfectly aligned.  A
replacement must choose tested semantics rather than copying prose blindly:

- the System V compatibility table in `init.8` displays several operations as
  runlevel `0`, while `main()` accepts `0` only as poweroff (`SIGUSR2`); halt
  and power-cycle remain signal operations but have no separate accepted
  command-line runlevel in the implementation;
- `SIGEMT`/runlevel `r` is implemented for reroot, but the short synopsis and
  compatibility table do not list it;
- the manual says a deleted or commented `/etc/ttys` line is left alone, while
  `clean_ttys()` marks the session for shutdown and sends its child `SIGHUP`;
- the manual says `init_shell` is used for `rc.final`, while `runfinal()`
  requires an executable file and invokes it directly; and
- the manual describes PID-1 death as automatic reboot, while the immediate
  kernel behavior is a panic; whether that panic subsequently reboots depends
  on kernel panic policy.

These are documentation defects or historical seams, not additional Authority
requirements.  Each should receive a regression test and an explicit
compatibility choice before migration.

## 23. Legacy failure seams Authority must not inherit accidentally

Stock init favors continued operation in many failures, but it is not a
memory-safe transaction engine with recovery on every allocation or syscall
failure.  Observable examples in this version include:

- failure to save `argv[0]` for reroot calls `err(3)` and exits PID 1;
- some session allocations and string duplications are assumed to succeed,
  while an `asprintf(3)` failure calls `err(3)`;
- failure to open the in-memory session database enters single-user mode, but
  individual database insert/delete errors only log;
- devfs mount failure is ignored;
- fatal synchronous signals deliberately end PID 1 after a 30-second delay;
- the shutdown timeout sends `SIGTERM` to the PID returned by the most recent
  `waitpid(-1, ...)`, which need not be the shutdown-script PID if the alarm
  races with collection of another child;
- `rc.final` can wait forever; and
- after both global signal rounds, init proceeds even if processes remain.

Compatibility does not require reproducing these defects.  Authority should
define safer behavior while preserving the operator-visible transition:
early failures reach recovery, shutdown remains bounded, and PID 1 never
returns or exits unintentionally.  Fault-injection tests must cover allocation,
fork, exec, wait, console, mount, sysctl, capability-device, and control-loop
failures.

## 24. Authority compatibility decisions and required work

The detailed work list lives in `docs/authority-init-todo.md`.  This audit makes
the following architectural decisions clear:

1. Keep the PID-1 survival, global-reaper, recovery-console, and final reboot
   mechanisms inside Authority, independent of `serviced`.
2. Keep `serviced` as the manager of the capability service world.  Authority
   retains a close-on-exec, non-transferable procdesc authority to terminate
   it, and treats channel loss as a lifecycle event.
3. Treat Authority's PID-1 conversion and daemon migration as independent.  Until
   each daemon is explicitly migrated, Authority runs the complete required rc
   sequence and rc remains that daemon's sole owner.  Mixed rc/`serviced`
   operation is a supported production state, not a brief best-effort bridge.
4. Move daemons one at a time using an authoritative ownership registry,
   retained rc ordering and one-shot preparation, readiness handshakes,
   delegated `service(8)` adapters, shutdown tests, and per-service rollback.
   Never permit rc and `serviced` to launch the same daemon.
5. Continue accepting `service authorityd stop`, but implement it through the
   rc.d script and Authority's control socket rather than ambient signals.
6. Preserve traditional PID-1 signal compatibility only as a migration
   bridge.  Signal shielding and an unmodified signal-only administration
   toolset are mutually incompatible.
7. Enter initially through `init_rc` for boot-flow testing, then through
   `init_exec` only after Authority owns all early `/dev`, console, recovery, and
   fatal-path requirements.  Direct `kern.init_path` replacement is the last
   deployment step.
8. Treat `/etc/ttys`, reroot, login classes, tracing, fallback init images,
   and loader overrides as explicit compatibility items.  None may disappear
   silently.
9. Test every state and failure edge in a VM before making Authority the first
   candidate in `kern.init_path`.

## 25. Transitional rc design checked against stock init

The transitional plan was checked against `init.c`, `/etc/rc`,
`rc.subr`, and `/etc/rc.shutdown`.  That comparison establishes these exact
boundaries:

- stock init launches and waits for one `/etc/rc` child.  It does not parse
  rc.d metadata, invoke each daemon script itself, or become the lifecycle
  owner of daemons started by rc;
- `/etc/rc` calculates the base graph, runs through the early/late divider,
  discovers local scripts after mounts become available, recalculates the
  graph, and skips entries already run;
- rc sources each executable script in a subshell.  Disabled-service policy
  remains inside `run_rc_command`, not `rcorder`;
- autoboot uses `faststart` and deliberately bypasses ordinary “already
  running” checks, so duplicate prevention for migrated services must come
  from authoritative ownership rather than pidfile probing;
- `run_rc_scripts()` does not fail fast or aggregate individual script errors,
  and stock `/etc/rc` ends with `exit 0`.  Authority therefore needs explicit
  required-target validation; merely checking the rc child's exit status does
  not prove that all required services started;
- rc configuration may be reloaded during boot on `SIGALRM`, and the local
  script set may not exist during the first pass.  A one-time static inventory
  cannot be the enforcement mechanism;
- `/etc/rc.shutdown` selects scripts carrying the `shutdown` keyword, reverses
  their rcorder result, invokes `faststop`, ignores individual return values,
  and exits zero unless the script itself is interrupted or killed; and
- `/etc/rc` requests a firstboot reboot with `kill -INT 1`, which mandatory
  Authority signal shielding would reject unless this call is migrated to the
  authorized lifecycle protocol.

Consequently the safe mixed-world design uses rc as the common scheduler.
`serviced` is available but does not independently autostart transitional
units.  A migrated rc.d adapter requests start/readiness or stop at the same
graph position as the old daemon operation.  During shutdown Authority freezes
new work, keeps `serviced` alive while reverse rc order is executed, drains
anything left afterward, terminates `serviced` through its procdesc, and only
then performs PID 1's global Unix-process sweep.  Stopping all managed units
before rc.shutdown would be incorrect because a legacy shutdown action may
still depend on one of them.

## 26. Audit maintenance rule

Any change to the reviewed init, kernel PID-1 code, reboot/shutdown utilities,
or rc entry points must update this audit or state why observable behavior is
unchanged.  Every retained behavior should map to an Authority test; every
intentional incompatibility should have a migration note and rollback path.
