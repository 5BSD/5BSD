# Authority as PID 1: Implementation TODO

Companion compatibility baseline:
`docs/freebsd-init-behavior-audit.md`.  That audit is authoritative for what
the init implementation in this tree currently does; this document tracks
what Authority must retain, replace deliberately, test, and document.

## Objective

Make Authority capable of replacing `init(8)` as PID 1 without losing FreeBSD's
boot compatibility, console recovery, process reaping, login-session
management, orderly shutdown, or reboot semantics.

This is not complete when Authority can merely start `serviced`. It is complete
when Authority remains a safe system spine through partial boot, configuration
failure, service-manager failure, shutdown failure, and recovery.

## Non-negotiable invariants

- PID 1 must never call `daemon(3)`, fork itself into the background, or exit.
- An unrecoverable PID 1 error must enter console recovery or deliberately
  reboot; it must not fall through to `exit(3)`.
- PID 1 must continuously reap every child and adopted orphan.
- The system must retain a recovery console when Authority configuration,
  capability setup, rc startup, or `serviced` startup fails.
- Normal reboot, halt, poweroff, power-cycle, single-user, and reroot requests
  must remain available.
- Shutdown must stop the managed capability world before terminating the
  remaining Unix world.
- Capability protection must not silently break the system administration
  interface used by `shutdown(8)`, `reboot(8)`, `halt(8)`, and rc.
- Forced termination authority must be explicit. Do not restore broad ambient
  signal access merely for compatibility.
- The live system must always have a tested fallback init in `kern.init_path`.

## Existing behavior to preserve

The current `init(8)` implementation provides the following state machine:

```text
single-user
    ↓
run /etc/rc
    ↓
read /etc/ttys
    ↓
multi-user
    ├── SIGHUP  → reread ttys
    ├── SIGTSTP → stop creating login sessions
    ├── SIGTERM → shutdown to single-user
    └── reboot request → orderly shutdown and reboot
```

It also:

- runs `/etc/rc` and enters single-user mode when startup fails;
- provides a secure single-user shell on the console;
- starts and restarts gettys from `/etc/ttys` with crash throttling;
- raises the kernel securelevel when entering multi-user mode;
- runs `/etc/rc.shutdown` with a configurable timeout;
- sends `SIGTERM`, then `SIGKILL`, to remaining user processes;
- runs `/etc/rc.final` after user processes have terminated;
- syncs and calls `reboot(2)` for reboot, halt, and power operations;
- supports root-filesystem rerooting;
- remains useful before syslog, `/var`, `/usr`, or all device files exist.

Relevant source:

- `sbin/init/init.c`
- `sbin/init/init.8`
- `sys/kern/init_main.c`
- `sys/kern/kern_exit.c`
- `libexec/rc/rc`
- `libexec/rc/rc.shutdown`

## Current Authority gaps

- [ ] Authority daemonizes unless foreground mode is requested.
- [ ] Normal Authority shutdown ends in `exit(0)`, which would panic the kernel
      when Authority is PID 1.
- [ ] Authority calls `PROC_REAP_ACQUIRE`; real init is already the permanent
      reaper, so that operation returns `EBUSY`.
- [ ] Authority requires a pidfile under `/var/run`, even though `/var` may not be
      mounted during early boot.
- [ ] Authority assumes syslog is available.
- [ ] Authority requires `/dev/mac_capability` before it has performed early
      devfs and module bootstrap.
- [ ] The Authority binary and its shared-library dependencies may reside under
      `/usr`, which may be a separate unmounted filesystem.
- [ ] Authority has no single-user or emergency-console state.
- [ ] Authority does not run `/etc/rc`, `/etc/rc.shutdown`, or `/etc/rc.final`.
- [ ] Authority does not manage `/etc/ttys`, getty, or console login sessions.
- [ ] Authority handles only a subset of the traditional PID 1 signal protocol,
      and its `SIGINT`/`SIGTERM` meanings differ from `init(8)`.
- [ ] Mandatory capability signal shielding blocks the signals currently sent
      to PID 1 by `shutdown(8)`, `reboot(8)`, and `halt(8)`.
- [ ] Authority's subtree cleanup is not yet a complete global-system shutdown.
- [ ] Child notification currently installs `SIGCHLD` as ignored before using
      kqueue; PID 1 needs deliberate, continuously verified orphan reaping.
- [ ] Several Authority fatal-error paths call `exit(3)` directly.
- [ ] Authority does not support `-s`, `-f`, and `-r` with init-compatible boot
      meanings.

## Target architecture

```text
Authority PID 1
├── early boot and recovery core
├── global child reaper
├── lifecycle/control state machine
├── capability authority
├── rc compatibility runner
│   └── transitional rc-managed Unix services
├── console/session manager
└── procdesc supervisor
    └── serviced
        └── migrated capability services
```

The PID 1 portion must remain small and independent of `serviced`. Ordinary
service policy can live in `serviced`, but reboot, recovery, global reaping,
and the emergency console must continue working when `serviced` is absent or
crash-looping.

During migration, Authority has two simultaneous responsibilities: it is the
system lifecycle authority, and it is the compatibility host for the existing
rc-managed Unix world.  That second responsibility remains until every rc.d
daemon has either moved to `serviced`, been classified as a boot-time one-shot,
or been deliberately retained as a compatibility service.

## Phase 0: Define the compatibility contract

- [ ] Assign every item in the companion audit to one of: preserve exactly,
      replace with a documented Authority mechanism, or intentionally remove
      with a migration path.
- [ ] Maintain a requirement-to-test matrix keyed to the audit's numbered
      sections.
- [ ] Document the exact Authority PID 1 state machine.
- [ ] Define named states at minimum:
  - `EARLY_BOOT`
  - `FILESYSTEM_BOOTSTRAP`
  - `ESTABLISH_AUTHORITY`
  - `MULTI_USER`
  - `QUIESCE`
  - `RC_SHUTDOWN`
  - `DRAIN_MANAGED`
  - `STOP_SERVICED`
  - `KILL_REMAINDER`
  - `RC_FINAL`
  - `SINGLE_USER`
  - `RECOVERY`
  - `REROOT`
- [ ] Define which transitions are legal from each state.
- [ ] Define behavior for repeated or conflicting lifecycle requests.
- [ ] Define the disposition of compile-time init personalities:
      `SECURE`, `DEBUGSHELL`, `LOGIN_CAP`, and `COMPAT_SYSV_INIT`.
- [ ] Resolve every source/manual discrepancy listed in section 22 of the
      companion audit with an explicit behavior, regression test, and manual
      update.
- [ ] Define timeout ownership at each layer:
  - PID 1 owns the whole-system deadline.
  - Authority owns the `serviced` deadline.
  - `serviced` owns managed-service deadlines.
- [ ] Decide which traditional init signals remain temporarily compatible and
      which commands move immediately to the Authority control protocol.
- [ ] Define stable control operations for:
  - status;
  - reload;
  - enter single-user;
  - inhibit new login sessions;
  - reboot;
  - halt;
  - poweroff;
  - power-cycle;
  - reroot;
  - graceful system shutdown.

### Exit gate

- [ ] The state/transition document has been reviewed before PID 1 code is
      added.
- [ ] Every path currently represented by an init signal has an explicit
      Authority transition.

## Phase 1: Test alternative boot orchestration under stock init

Use the existing `init_rc` loader variable to test an Authority-aware startup
script while stock `init(8)` remains PID 1.

- [ ] Create an experimental Authority rc entry point separate from `/etc/rc`.
- [ ] Preserve a path that runs the stock rc sequence.
- [ ] Ensure the rc script does not recursively start a second Authority.
- [ ] Split trusted early boot from capability-world service startup.
- [ ] Identify the minimum rc providers required before Authority can establish
      capability authority:
  - mounted root and required local filesystems;
  - devfs;
  - required kernel modules, unless built in;
  - configuration storage;
  - console access.
- [ ] Ensure no untrusted or capability-managed daemon starts before Authority
      has claimed the resources it must protect.
- [ ] Test `init_rc` rollback from the loader prompt.

### Exit gate

- [ ] Normal boot succeeds with stock init and the experimental rc path.
- [ ] Startup failure reliably returns to stock init's single-user shell.
- [ ] Stock `/etc/rc` remains selectable without reinstalling the system.

## Phase 2: Introduce an Authority PID 1 personality

Add a distinct initialization path selected by `getpid() == 1`. Do not overload
ordinary daemon mode with scattered PID checks.

- [ ] Add an explicit `od.pid1_mode` state flag.
- [ ] Split daemon-mode and PID-1-mode startup functions.
- [ ] In PID 1 mode:
  - [ ] force foreground operation;
  - [ ] never call `daemon(3)`;
  - [ ] do not require a pidfile;
  - [ ] avoid `/var` as an early dependency;
  - [ ] establish console logging before syslog;
  - [ ] use syslog only after it becomes available;
  - [ ] accept init-compatible boot arguments;
  - [ ] query boot flags when entered through `init_exec` without arguments.
- [ ] Replace PID 1 `exit`, `err`, and fatal event-loop paths with transitions
      to `RECOVERY` or a deliberate reboot path.
- [ ] Audit every `_exit`, `exit`, `err`, and `errx` reachable in PID 1 mode.
- [ ] Replace stock init's fatal-signal sleep-and-exit behavior with a minimal,
      async-safe recovery or deliberate reboot path that cannot return from
      PID 1.
- [ ] Reset inherited signal dispositions and masks explicitly.
- [ ] Ignore terminal job-control signals where required for PID 1.
- [ ] Call `setsid(2)` and establish the root login identity where appropriate.
- [ ] Preserve useful lifecycle tracing for boot, multi-user entry, shutdown,
      and reboot even if Authority does not use stock `BOOTTRACE` macros.

### Suggested source structure

- [ ] Add a PID 1 module, for example `capsule.c` and `capsule.h`.
- [ ] Keep early console and recovery code independent of UCL and service
      manifests.
- [ ] Make the ordinary Authority authority engine callable from the PID 1 state
      machine rather than making the state machine exit into the daemon.

### Exit gate

- [ ] A test harness can execute the PID 1 personality in a jail, VM, or
      controlled fake-init environment without daemonizing.
- [ ] Injected initialization failures reach recovery code instead of exit.

## Phase 3: Correct real-init process semantics

- [ ] Change process-policy setup for PID 1:
  - [ ] do not call `PROC_REAP_ACQUIRE`;
  - [ ] query `PROC_REAP_STATUS`;
  - [ ] require `REAPER_STATUS_OWNED`;
  - [ ] require `REAPER_STATUS_REALINIT`.
- [ ] Preserve OOM and tracing protection where meaningful for `P_SYSTEM`.
- [ ] Install `SIGCHLD` handling suitable for PID 1.
- [ ] On every child notification, call `waitpid(-1, ...)` until no reapable
      children remain.
- [ ] Correctly distinguish:
  - direct children;
  - procdesc-supervised children;
  - adopted orphans;
  - login-session children;
  - shutdown-script children.
- [ ] Ensure no pidfile or remembered PID is the sole lifecycle identity for a
      supervised critical child.
- [ ] Add reaping metrics and diagnostics without assuming syslog exists.

### Exit gate

- [ ] Fork/orphan storms leave no zombies.
- [ ] `serviced` procdesc exit handling and global orphan reaping do not race.
- [ ] PID 1 remains responsive while reaping large child batches.

## Phase 4: Establish a viable early-boot binary

- [ ] Install the PID 1-capable Authority binary on the root filesystem, normally
      under `/sbin`.
- [ ] Audit all shared-library dependencies for availability before `/usr` is
      mounted.
- [ ] Prefer a minimal static or root-filesystem-complete dependency set.
- [ ] Ensure configuration required before filesystem bootstrap is also on the
      root filesystem.
- [ ] Open `/dev/console` with a fallback to `/dev/null` and an early log file.
- [ ] Mount devfs when the kernel/root layout requires it.
- [ ] Assume that `init_exec` may enter Authority before stock init has detected
      or mounted devfs; test that exact ordering.
- [ ] Decide whether the MAC capability framework is built into the kernel.
- [ ] Prefer building PID 1's required capability policies into the kernel to
      remove the early KLD loading cycle.
- [ ] If modules remain supported, implement a trusted early module-loading
      phase before capability setup.
- [ ] Verify MAC initialization gives PID 1 a valid initial nonce and that exec
      into Authority rotates or establishes the intended program identity.
- [ ] Verify the complete early path works after `init_chroot`, and decide
      whether Authority preserves `init_script`, `init_shell`, and `init_rc`
      loader-environment compatibility.

### Exit gate

- [ ] Authority reaches recovery mode with `/usr` and `/var` unavailable.
- [ ] Authority reaches recovery mode when `/dev/mac_capability` is unavailable.
- [ ] The console provides actionable diagnostics in both cases.

## Phase 5: Implement startup and rc compatibility

- [ ] Add a child runner for `/etc/rc` with:
  - console stdin/stdout/stderr;
  - controlled signal mask and dispositions;
  - boot-compatible environment;
  - exact exit-status handling;
  - stopped-child recovery;
  - timeout or operator interruption policy.
- [ ] Preserve direct execution of executable scripts and configured-shell
      fallback, or document and test a deliberate replacement.
- [ ] Apply the `daemon` login class resource, environment, priority, CPU-mask,
      and limit policy to rc children when login capabilities are enabled.
- [ ] Continue global child reaping while synchronously waiting for rc scripts.
- [ ] Enter single-user/recovery mode when the top-level `/etc/rc` process
      fails, is signaled, or exits nonzero.
- [ ] Do not mistake an individual rc.d command failure for a top-level rc
      failure: stock `run_rc_scripts()` continues after script errors and
      stock `/etc/rc` normally exits zero.  Add explicit post-rc validation for
      Authority's required multi-user target.
- [ ] Support autoboot and fastboot semantics.
- [ ] Prevent `/etc/rc` from starting an ordinary daemon instance of Authority
      when Authority is already PID 1.
- [ ] Initially let rc start every enabled legacy service.  Suppress an rc
      daemon launch only after that specific service has an approved,
      rollback-tested `serviced` replacement (plus the special case that rc
      must not launch a second Authority when Authority is PID 1).
- [ ] Define the boundary between the Unix compatibility world and the Authority
      capability world.
- [ ] Ensure resource claims occur after required mounts exist but before
      protected services begin.

### Exit gate

- [ ] Existing rc.d boot succeeds without duplicate Authority instances.
- [ ] A failed top-level `/etc/rc` enters recovery, and failure of a required
      migrated unit is detected by explicit readiness/target validation.
- [ ] Capability-managed services never start before authority setup.

## Phase 6: Operate the transitional rc-managed Unix world

Authority must continue running the complete required rc sequence on every boot
while services are migrated incrementally.  Replacing PID 1 and replacing all
rc-managed daemons are separate projects; the former must not require the
latter to happen atomically.

### Inventory and ownership

- [ ] Build a machine-readable inventory of every rc.d entry selected on the
      target system, including base, ports, and site-local scripts.
- [ ] Classify each entry as:
  - early boot or filesystem preparation;
  - one-shot configuration;
  - long-running legacy daemon;
  - delegated adapter for a `serviced` unit;
  - shutdown-only action; or
  - intentionally disabled.
- [ ] Record `PROVIDE`, `REQUIRE`, `BEFORE`, and `KEYWORD` metadata, enable
      variables, pidfiles, control sockets, user/jail context, and shutdown
      behavior.
- [ ] Give every long-running service exactly one active owner:
      `RC_LEGACY`, `SERVICED`, or `DISABLED`.
- [ ] Make the ownership registry authoritative and inspectable at runtime;
      do not infer ownership from a process name or pidfile.
- [ ] Refuse boot or enter recovery when the same service is configured for
      both legacy rc startup and `serviced` startup.

### Compatibility boot

- [ ] Have Authority execute `/etc/rc` exactly once, with init-compatible
      `autoboot`/fastboot arguments.  Authority must not reimplement the loop over
      rc.d files or independently run a second copy of the graph.
- [ ] Initially let that stock `/etc/rc` graph start all currently enabled
      legacy services, apart from the script that would start a duplicate
      Authority PID 1.
- [ ] Preserve rc's two-pass discovery: base scripts run through the
      early/late divider before mounted local-startup directories are added
      and the graph is recalculated.
- [ ] Preserve diskless initialization, firstboot sentinels, jail filters,
      `nostart`/`firstboot` keywords, configuration reload on `SIGALRM`, and
      the optional `run_rc_scripts_final` hook.
- [ ] Start the `serviced` control plane before the first migrated adapter can
      run, but in transitional mode do not let `serviced` autostart migrated
      units outside rc order.  Each adapter requests its unit at the exact
      rcorder position formerly occupied by the daemon launch.
- [ ] Start only explicitly migrated units through `serviced`; absence from
      the migration registry means rc retains ownership.
- [ ] Make ownership checks authoritative even during autoboot `faststart`,
      because stock rc deliberately skips ordinary already-running checks in
      that mode.
- [ ] Preserve rc ordering milestones even when a daemon implementation moves
      to `serviced`.  `rcorder` metadata expresses ordering, not service
      readiness, so add an explicit readiness handshake where downstream rc
      scripts require a live migrated provider.
- [ ] Account for stock rc's non-fail-fast behavior.  A migrated adapter records
      failure with Authority; dependent migrated adapters refuse to start without
      their provider; and Authority validates the required multi-user target when
      `/etc/rc` returns.  Define how legacy dependents are prevented from
      consuming a failed migrated provider.
- [ ] Split rc scripts that combine one-shot host preparation with daemon
      launch.  Keep the preparation action in the correct rc phase and move
      only the long-running process when necessary.
- [ ] Keep `service <name> start|stop|restart|reload|status` working throughout
      migration.  A migrated service's rc.d script becomes an adapter to the
      authorized Authority/`serviced` control path rather than signaling a pidfile.
- [ ] Ensure adapter operations are idempotent so rc shutdown and Authority's
      managed-world shutdown cannot double-stop or restart a service.
- [ ] Preserve jail and `KEYWORD` filtering in both worlds.
- [ ] Replace `/etc/rc`'s firstboot `kill -INT 1` reboot request, and inventory
      equivalent requests in rc.d scripts, with the authorized Authority
      lifecycle operation before mandatory signal shielding is enabled.

### Capability and descriptor boundary

- [ ] Declare resource ownership before either launcher runs a daemon.
- [ ] Do not exclusively claim a path, socket, device, jail, or network
      resource for a migrated service while its legacy rc instance remains
      active.
- [ ] For each migration, define the exact capability tokens, procdescs, and
      transferred descriptors the new program receives before launch.
- [ ] Keep token activation in the executed program, never in Authority or
      `serviced` on the program's behalf.
- [ ] Apply close-on-exec and monotonic descriptor-rights reduction before
      invoking legacy rc children as well as capability-managed children.
- [ ] Treat a legacy daemon outside the capability world as an explicit,
      temporary security exception with an owner and removal milestone.

### One-service migration transaction

For every daemon, perform the following as one reviewed change:

1. inventory its rc ordering, preparation, configuration, credentials,
   resources, readiness condition, control operations, and shutdown behavior;
2. add its `serviced` definition and capability/descriptor contract;
3. convert its rc.d script into a compatibility adapter while retaining its
   ordering metadata and any required one-shot preparation;
4. prove that boot starts exactly one instance and waits for real readiness;
5. prove that manual `service` operations reach the managed instance;
6. prove that reboot and single-user transitions stop it exactly once;
7. test rollback to `RC_LEGACY` without changing PID 1; and
8. only then change its ownership record to `SERVICED` by default.

### Shutdown during migration

- [ ] Enter global quiesce first: reject new starts and new external work, but
      keep both legacy and migrated dependencies alive for ordered teardown.
- [ ] Keep `serviced` operational while `/etc/rc.shutdown` walks the unified
      rcorder graph in reverse.  Migrated adapters issue authorized stop
      requests at their graph positions; legacy scripts stop their own daemons.
- [ ] Do not stop the entire managed world before `/etc/rc.shutdown`; doing so
      can invert a cross-world dependency needed by a legacy shutdown action.
- [ ] Ensure migrated adapters implement `faststop`, because that is the
      operation used by stock `/etc/rc.shutdown`.
- [ ] After rc.shutdown returns or times out, ask `serviced` to drain any
      managed units not selected by the `shutdown` keyword or left behind by
      adapter failure.
- [ ] Then terminate `serviced`, escalating through Authority's exact retained
      procdesc if its deadline expires, and prove the managed world is gone
      before the global Unix signal sweep.
- [ ] Preserve the final global `SIGTERM`/`SIGKILL` sweep for unmanaged,
      orphaned, or incorrectly classified Unix processes.
- [ ] Report ownership mismatches, duplicate instances, and processes that
      survive their owner's shutdown stage.

### Exit gate

- [ ] An unmodified legacy service set boots and shuts down under Authority PID 1.
- [ ] A mixed system with rc-owned and `serviced`-owned daemons boots with one
      instance of every service and correct cross-world readiness ordering.
- [ ] Mixed ownership shuts down in reverse dependency order while the
      `serviced` control plane remains available to every migrated adapter.
- [ ] Each service can roll back independently from `SERVICED` to `RC_LEGACY`.
- [ ] `service(8)` remains a valid operator interface for both ownership modes.
- [ ] The transition phase can remain in production safely for an extended
      period; completing every daemon migration is not required to deploy
      Authority PID 1.

## Phase 7: Implement console recovery and single-user mode

- [ ] Open and revoke the system console safely.
- [ ] Fall back to `/dev/null` input and an early local log when the console is
      unavailable; do not require `/var/log` to exist.
- [ ] Support secure/insecure console policy from `/etc/ttys`.
- [ ] Authenticate the root password when required.
- [ ] Launch a single-user shell with a valid controlling terminal, session,
      login identity, `HOME`, and signal mask.
- [ ] Restart an abnormally terminated recovery shell rather than exiting.
- [ ] Continue reaping unrelated and adopted children while waiting for the
      recovery shell, and continue a stopped shell safely.
- [ ] Treat normal shell exit as a request to retry multi-user startup.
- [ ] Provide recovery commands for:
  - retry capability initialization;
  - retry rc startup;
  - inspect Authority state;
  - disable optional policy temporarily;
  - reboot or halt safely;
  - select the fallback init for the next boot.
- [ ] Ensure recovery does not depend on `serviced` or the Authority control
      socket.

### Exit gate

- [ ] Boot with malformed Authority configuration reaches a usable console.
- [ ] Boot with missing capability modules reaches a usable console.
- [ ] Exiting the shell can retry boot without rebooting.

## Phase 8: Preserve tty and login-session behavior

Choose one initial implementation:

- [ ] Port the `/etc/ttys` session manager into Authority's PID 1 personality; or
- [ ] launch a dedicated tty/session manager under a procdesc while retaining
      a PID-1-owned emergency console.

Required behavior:

- [ ] Parse enabled `/etc/ttys` entries.
- [ ] Match or deliberately replace init's simple quoted-command parser; do
      not accidentally treat getty/window fields as unrestricted shell text.
- [ ] Start getty and optional window commands with correct sessions and
      controlling terminals.
- [ ] Preserve the optional window command's adoption and startup ordering.
- [ ] Restart getty after logout.
- [ ] Throttle rapidly exiting gettys.
- [ ] Specify and test the compatibility constants: five-second rapid-exit
      window, three tolerated failures, 30-second backoff, and three-second
      window/getty spacing.
- [ ] Support `onifexists` and `onifconsole` behavior.
- [ ] Reread `/etc/ttys` and reconcile additions, changes, and removals.
- [ ] Revoke tty access during shutdown.
- [ ] Stop creating sessions during catatonia/quiesce.
- [ ] Apply login-class resource policy.
- [ ] Inventory `/etc/ttys` entries used to supervise arbitrary non-tty
      daemons and either support them or provide a migration to `serviced`.
- [ ] Preserve a console path even if the delegated tty manager fails.

### Exit gate

- [ ] Console and configured serial gettys survive repeated login/logout.
- [ ] Broken getty configuration cannot crash or starve PID 1.
- [ ] Tty configuration reload is race-free.

## Phase 9: Replace or preserve the PID 1 administration ABI

Traditional tools currently signal PID 1:

| Signal | Traditional action |
| --- | --- |
| `SIGHUP` | reread `/etc/ttys` |
| `SIGTERM` | enter single-user mode |
| `SIGTSTP` | stop creating logins |
| `SIGINT` | reboot |
| `SIGUSR1` | halt |
| `SIGUSR2` | poweroff |
| `SIGWINCH` | power-cycle |
| `SIGEMT` | reroot |

- [ ] Decide on a transition period for this signal ABI.
- [ ] Extend the Authority control protocol with equivalent lifecycle operations.
- [ ] Update `shutdown(8)`, `reboot(8)`, and `halt(8)` to prefer the Authority
      control protocol when Authority is PID 1.
- [ ] Provide a compatibility utility for System V-style init commands.
- [ ] Authenticate control peers using kernel credentials or explicit
      capabilities.
- [ ] Do not authenticate based only on executable pathname.
- [ ] Decide how emergency reboot works when the control event loop is wedged.
- [ ] Ensure mandatory `CP_SF_SIGNAL`, `CP_SF_SIGKILL`, and `CP_SF_SIGCONT`
      protection does not remove every system recovery mechanism.
- [ ] Document which operations remain root-wide and which require a narrower
      capability.

### Exit gate

- [ ] Normal and forced shutdown tools work with Authority's signal shield active.
- [ ] Unauthorized foreign processes cannot trigger lifecycle transitions.
- [ ] A wedged control client cannot wedge PID 1.

## Phase 10: Implement whole-system shutdown

Add explicit ordered shutdown states rather than extending the daemon's current
single shutdown callback.

- [ ] Reject new starts, restarts, reloads, and capability grants after
      quiesce begins while still allowing the authorized status and stop
      operations required by rc.shutdown adapters.
- [ ] Stop creating login sessions.
- [ ] Revoke active tty sessions.
- [ ] Freeze new work in both service worlds without prematurely terminating
      dependencies needed during shutdown.
- [ ] Run `/etc/rc.shutdown` with `single` or `reboot` while `serviced` remains
      available to migrated rc adapters.
- [ ] Enforce `kern.init_shutdown_timeout` or an explicitly compatible policy.
- [ ] Block system suspend during shutdown.
- [ ] After rc shutdown, request a graceful drain and exit from `serviced`.
- [ ] Escalate against the exact `serviced` procdesc on timeout.
- [ ] Wait for the managed capability world to be gone.
- [ ] Send `SIGTERM` to remaining user processes.
- [ ] Reap until the grace deadline.
- [ ] Send `SIGKILL` to remaining killable user processes.
- [ ] Continue reaping until no children remain or the hard deadline expires.
- [ ] Run `/etc/rc.final` after user processes are gone.
- [ ] Decide explicitly whether `/etc/rc.final` retains stock init's unbounded
      wait or receives a documented Authority deadline; test a hung final script.
- [ ] Ignore `rc.final` exit status for reboot compatibility unless a new,
      documented policy says otherwise.
- [ ] Sync filesystems.
- [ ] Call `reboot(2)` with the correct flags for:
  - reboot;
  - halt;
  - poweroff;
  - power-cycle;
  - reroot.
- [ ] If returning to single-user mode, enter the recovery state instead of
      exiting.
- [ ] Preserve diagnostics for unkillable processes.

### Exit gate

- [ ] Reboot, halt, poweroff, power-cycle, and single-user transitions all work.
- [ ] Shutdown order proves managed services exit before Authority releases their
      capability authority.
- [ ] Cross-world dependencies remain available until their reverse-ordered
      rc.shutdown position.
- [ ] A hung rc.shutdown script is terminated at its deadline.
- [ ] An uninterruptible process produces diagnostics without causing PID 1 to
      exit.

## Phase 11: Implement reroot

- [ ] Revoke tty sessions and stop service activity.
- [ ] Run the shutdown path required before reroot.
- [ ] Terminate remaining user processes.
- [ ] Copy or provide a runnable PID 1 binary outside the old root.
- [ ] Invoke `reboot(RB_REROOT)`.
- [ ] Search the new root's configured init path.
- [ ] Exec the selected PID 1 binary.
- [ ] Fall back to recovery if any reroot phase fails.
- [ ] Preserve capability-policy correctness across the exec and new root.

### Exit gate

- [ ] Successful reroot reaches multi-user operation on the new root.
- [ ] Every injected reroot failure reaches recovery on a usable root.

## Phase 12: Boot selection and rollback

The tree provides three useful mechanisms:

- `init_rc`: stock init remains PID 1 but runs an alternate startup script.
- `init_exec`: stock init immediately execs another binary as PID 1.
- `init_path`: the kernel searches a colon-separated list of PID 1 binaries.

- [ ] Use `init_rc` for the first integration stage.
- [ ] Use `init_exec=/sbin/capsule` only after recovery and shutdown work.
- [ ] Test direct kernel launch with an ordered fallback path such as:

  ```text
  /sbin/capsule:/sbin/init:/sbin/init.bak:/rescue/init
  ```

- [ ] Preserve loader-console instructions for selecting stock init.
- [ ] Preserve `/sbin/init.bak` and `/rescue/init` recovery paths.
- [ ] Preserve the install-time backup behavior and verify that fallback
      entries are independently runnable rather than aliases of Authority.
- [ ] Remember that fallback only helps if Authority cannot be exec'd. Once Authority
      starts successfully, a later PID 1 exit panics rather than trying the next
      path.
- [ ] Do not make Authority the first default `init_path` entry until all VM boot
      gates pass.

## Phase 13: Test matrix

Run destructive PID 1 testing only in bhyve or another disposable VM with
snapshots and console access.

### Boot modes

- [ ] Normal autoboot.
- [ ] Single-user boot (`-s`).
- [ ] Fastboot/retry from single-user.
- [ ] Separate `/usr` and `/var` filesystems.
- [ ] Read-only root during early boot.
- [ ] Missing console device.
- [ ] Serial console.
- [ ] Missing and malformed Authority configuration.
- [ ] Missing capability device or policy.
- [ ] Failure before and after devfs is mounted.
- [ ] Entry through each supported loader hook: `init_script`, `init_chroot`,
      `init_exec`, `init_rc`, `init_shell`, and `init_path`.
- [ ] `/etc/rc` nonzero exit and signal termination.
- [ ] Individual rc.d failure while `/etc/rc` still exits zero.
- [ ] Required migrated-unit failure with migrated and legacy dependents.
- [ ] Early/late two-pass discovery with local startup on a later mount.
- [ ] Firstboot reboot request with Authority signal shielding active.
- [ ] Executable rc script and configured-shell fallback paths.

### Process semantics

- [ ] Direct child exit.
- [ ] Double-forked orphan adoption.
- [ ] Large orphan and zombie storms.
- [ ] Procdesc child exit concurrent with `SIGCHLD`.
- [ ] `serviced` immediate crash loop.
- [ ] `serviced` channel loss.
- [ ] Tty child exit storms.
- [ ] PID 1 memory pressure and OOM conditions.
- [ ] Verify kernel real-init reaper flags and rejection of reaper release.
- [ ] Verify `SA_NOCLDWAIT` cannot silently disable PID-1 child collection.

### Administration

- [ ] Status and reload.
- [ ] Enter single-user mode.
- [ ] Inhibit and resume login creation.
- [ ] Reboot.
- [ ] Halt.
- [ ] Poweroff.
- [ ] Power-cycle.
- [ ] Reroot.
- [ ] Unauthorized lifecycle requests.
- [ ] Control-socket client stalls and malformed messages.

### Shutdown failures

- [ ] Managed service ignores `SIGTERM`.
- [ ] `serviced` ignores graceful shutdown.
- [ ] `rc.shutdown` hangs.
- [ ] A migrated `faststop` adapter fails while stock rc.shutdown still exits
      zero; post-rc managed drain must find and stop the unit.
- [ ] Cross-world reverse ordering in both directions: a legacy shutdown action
      depends on a migrated provider, and a migrated shutdown action depends
      on a legacy provider.
- [ ] `rc.final` hangs under the selected compatibility/deadline policy.
- [ ] Remaining Unix process ignores `SIGTERM`.
- [ ] Process stuck in uninterruptible kernel sleep.
- [ ] Filesystem sync or reboot syscall failure.
- [ ] Repeated shutdown requests during every shutdown state.

### Recovery

- [ ] Recovery shell authentication on secure and insecure consoles.
- [ ] Recovery shell abnormal termination.
- [ ] Retry boot after repairing configuration.
- [ ] Select stock init on next boot.
- [ ] Recovery without syslog, `/usr`, `/var`, or `serviced`.

## Phase 14: Documentation and operator tooling

- [ ] Add an Authority PID 1 mode section to `authorityd(8)`.
- [ ] Document loader variables and rollback procedures.
- [ ] Document the lifecycle control protocol.
- [ ] Update `shutdown(8)`, `reboot(8)`, and `halt(8)` manuals if their
      transport changes.
- [ ] Document early-console diagnostics.
- [ ] Document the distinction between normal Authority daemon mode and PID 1
      mode.
- [ ] Add a boot troubleshooting decision tree.
- [ ] Add a release checklist that prevents installation without a fallback
      init.
- [ ] Keep `docs/freebsd-init-behavior-audit.md` synchronized with changes to
      init, kernel PID-1 behavior, rc entry points, and administration tools.
- [ ] Document every intentional divergence from stock init with its operator
      impact, migration procedure, test, and rollback path.

## Initial implementation order

Do these first:

1. Define the PID 1 state machine and control ABI.
2. Test an Authority-aware `init_rc` under stock init.
3. Add PID 1 mode without making it the boot default.
4. Replace all PID 1 exit paths with recovery transitions.
5. Implement real-init reaping and console recovery.
6. Add rc startup/shutdown compatibility.
7. Inventory the complete rc graph and establish single-owner records before
   migrating any daemon.
8. Prove an entirely rc-owned system and then a mixed rc/`serviced` system.
9. Add full reboot and single-user transitions across both service worlds.
10. Add tty compatibility or a supervised tty manager.
11. Update administrative tools for the protected PID 1 control path.
12. Test through `init_exec` in a disposable VM.
13. Test direct `init_path` launch with fallback entries.
14. Only then consider making Authority the default init.

## Definition of done

Authority may replace init only when all of the following are true:

- [ ] It boots from the kernel as PID 1 without daemonizing.
- [ ] It never exits outside an active kernel reboot.
- [ ] It provides a usable recovery console after every tested early failure.
- [ ] It continuously reaps all children and adopted orphans.
- [ ] It starts the compatibility Unix world and capability world in the
      intended order.
- [ ] It can run indefinitely with a mixed population of rc-owned and
      `serviced`-owned daemons, with exactly one owner and one instance of
      every service.
- [ ] Each daemon migration preserves rc ordering, readiness, `service(8)`
      operations, shutdown, and independent rollback.
- [ ] It keeps recovery and whole-system lifecycle independent of `serviced`.
- [ ] It preserves getty/login behavior or provides an intentional replacement.
- [ ] It performs orderly reboot, halt, poweroff, power-cycle, single-user, and
      reroot transitions.
- [ ] Capability protection remains active without breaking authorized system
      administration.
- [ ] All destructive VM tests pass repeatedly.
- [ ] Stock init remains selectable from the loader and present on disk.
