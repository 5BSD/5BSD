# Integrating Daemons with FreeBSD rc

## A practical handbook for boot, shutdown, service control, and capability-aware daemons

FreeBSD's rc system is small enough to read and powerful enough to run an entire operating system. It is also easy to misunderstand. The command `service example stop` looks like a process-management operation, but `service(8)` does not decide how the process stops. It finds an rc.d script, gives that script a controlled environment, and asks the script to execute its `stop` method. The script may use `SIGTERM`, a control socket, a process descriptor, a hypervisor API, or anything else its author defines.

That distinction is the foundation of this handbook:

> rc expresses system policy and dispatches lifecycle operations. Your daemon and its rc.d script define the actual lifecycle protocol.

This book explains the stock FreeBSD mechanisms and then applies them to capability-oriented services such as Authorityd. It is written for developers integrating base-system daemons, although most of it also applies to ports installed under `/usr/local/etc/rc.d`.

## 1. The cast of characters

Several components cooperate. Treating them as one program causes confusion.

### `init(8)`

The traditional PID 1 starts `/etc/rc` during multi-user boot. It is the top-level origin of the normal boot sequence, but it does not individually understand every daemon.

### `/etc/rc`

This is the boot conductor. It loads rc support code and configuration, asks `rcorder(8)` for an ordered set of scripts, and runs those scripts with the `start` operation.

### `/etc/rc.shutdown`

This is the shutdown conductor. It selects scripts carrying the `shutdown` keyword, reverses the dependency order, and invokes them with `faststop`.

### `rcorder(8)`

`rcorder` reads metadata comments such as `PROVIDE`, `REQUIRE`, `BEFORE`, and `KEYWORD`. It computes an order. It does not start processes, poll sockets, or determine whether a dependency is healthy.

### `/etc/rc.subr`

This shell library implements the standard rc.d vocabulary. Its central function is `run_rc_command`. It loads configuration, discovers a process when necessary, dispatches custom methods, and supplies default implementations for operations such as `start`, `stop`, and `status`.

### An rc.d script

An rc.d script is the adapter between the generic rc vocabulary and one particular service. It declares ordering metadata, names configuration variables, and either accepts or replaces `rc.subr`'s default lifecycle behavior.

Base-system scripts live in `/etc/rc.d` at runtime and under `libexec/rc/rc.d` in this source tree. Port and site-local scripts normally live in `/usr/local/etc/rc.d`.

### `service(8)`

`service` is a convenient front end. For a command such as:

```sh
service authorityd stop
```

it locates the `authorityd` rc.d script, constructs a boot-like restricted environment, and invokes the script with `stop`. It does not inherently send a signal.

### `sysrc(8)`

`sysrc` reads and modifies rc configuration safely. Prefer it to appending shell fragments manually:

```sh
sysrc authorityd_enable=YES
sysrc authorityd_flags="-d"
```

## 2. The whole lifecycle at a glance

The normal path is:

```text
boot
  init
    /etc/rc
      rcorder metadata
        rc.d script start
          run_rc_command start
            custom start_cmd OR default daemon command

manual administration
  service <name> <operation>
    rc.d script <operation>
      run_rc_command <operation>
        custom <operation>_cmd OR default implementation

shutdown
  /etc/rc.shutdown
    reverse rcorder for scripts marked shutdown
      rc.d script faststop
        custom stop_cmd OR default SIGTERM stop
```

The important branch is “custom method or default implementation.” Most daemon integrations can remain simple because the defaults are sensible. Security-sensitive or unusual daemons should replace the operations whose default semantics are wrong.

## 3. Anatomy of a minimal rc.d script

A conventional script looks like this:

```sh
#!/bin/sh
#

# PROVIDE: exampled
# REQUIRE: FILESYSTEMS syslogd
# BEFORE:  SERVERS
# KEYWORD: shutdown

. /etc/rc.subr

name="exampled"
desc="Example daemon"
rcvar="exampled_enable"
command="/usr/sbin/exampled"
pidfile="/var/run/exampled.pid"

load_rc_config "$name"

: ${exampled_enable:="NO"}
: ${exampled_flags:=""}

run_rc_command "$1"
```

Each section has a distinct purpose.

### Interpreter and metadata

The script uses the base-system `/bin/sh`. Metadata comments must appear in the form understood by `rcorder`.

### Loading `rc.subr`

The line:

```sh
. /etc/rc.subr
```

imports the framework. Do this before calling framework functions.

### Service identity

`name` is the rc identity, not merely a display label. It drives variable lookup. If `name=exampled`, the framework looks for variables such as:

- `exampled_enable`
- `exampled_flags`
- `exampled_program`
- `exampled_user`
- `exampled_chdir`
- `exampled_env`

`rcvar` names the enable variable. Usually it is `${name}_enable`.

### Executable and process identity

`command` is the executable used by the default start implementation and process checks. `pidfile` tells the framework where to find the daemon PID. A correct pidfile is much safer than broad process-name matching.

### Loading configuration

`load_rc_config "$name"` loads defaults and administrator overrides, including per-service files under `rc.conf.d`.

The `: ${variable:="default"}` statements establish script defaults only when the administrator did not supply a value.

### Dispatch

`run_rc_command "$1"` hands the requested operation to `rc.subr`.

## 4. Ordering is a graph, not a list

The metadata header defines nodes and edges in the boot graph.

### `PROVIDE`

```sh
# PROVIDE: exampled
```

This declares one or more names provided by the script. Other scripts refer to these names, not necessarily the filename.

### `REQUIRE`

```sh
# REQUIRE: FILESYSTEMS syslogd
```

The script must be ordered after the providers named here.

`REQUIRE` means ordering, not runtime health. If `syslogd` was invoked but failed immediately, the graph is still satisfied. A daemon that requires a usable socket or device must check that condition itself, normally in `start_precmd` or during its own initialization.

### `BEFORE`

```sh
# BEFORE: SERVERS
```

This asks that the script run before scripts requiring or providing the named point. Use it sparingly. `REQUIRE` usually expresses the relationship more directly.

### `KEYWORD`

Common keywords include:

- `shutdown`: include the script in ordered shutdown.
- `nojail`: do not run it inside a jail.
- `nojailvnet`: skip it in jails without VNET.
- `firstboot`: select first-boot behavior.
- `nostart`: exclude it from ordinary automatic startup.

For long-running daemons, `shutdown` is usually correct. Without it, the daemon is not part of the orderly rc shutdown pass.

### Inspecting the actual order

Useful commands include:

```sh
service -r
rcorder /etc/rc.d/* /usr/local/etc/rc.d/*
```

Do not infer order from filenames. Metadata controls it.

## 5. Configuration and override rules

The normal configuration layers include:

1. `/etc/defaults/rc.conf`
2. vendor defaults
3. `/etc/rc.conf`
4. `/etc/rc.conf.local`
5. matching files or directories under `rc.conf.d`

Administrators should change local policy rather than editing installed rc.d scripts.

### Standard per-service variables

For `name=exampled`, useful framework variables include:

```sh
exampled_enable="YES"
exampled_flags="-v"
exampled_program="/opt/example/exampled"
exampled_user="example"
exampled_group="example"
exampled_chdir="/var/db/example"
exampled_env="KEY=value"
exampled_env_file="/etc/exampled.env"
exampled_nice="5"
exampled_cpuset="0-3"
exampled_fib="1"
exampled_umask="027"
exampled_oomprotect="YES"
```

Not every daemon should expose every knob. Publish only combinations the daemon can support safely.

### `flags` versus `command_args`

`<name>_flags` is administrator-controlled. `command_args` is script-controlled. A common design is:

```sh
command_args="-p ${pidfile}"
: ${exampled_flags:=""}
```

Avoid constructing shell commands from unvalidated configuration. rc.d is shell; quoting mistakes become correctness and security bugs.

### Enable checks

Normal `start` honors `<name>_enable`. For manual recovery or testing:

```sh
service exampled onestart
```

The `one` prefix temporarily treats the enable variable as true. It does not permanently modify `rc.conf`.

## 6. How `run_rc_command` chooses behavior

For an operation named `stop`, `run_rc_command` looks for `stop_cmd`. For `status`, it looks for `status_cmd`. This pattern applies to every supported command.

Conceptually:

```text
requested operation
  normalize fast/force/one/quiet prefix
  load operation hooks
  if <operation>_cmd exists:
      run the custom method
  else:
      run rc.subr's default implementation
```

The major hooks are:

- `<operation>_setup`
- `<operation>_precmd`
- `<operation>_cmd`
- `<operation>_postcmd`

Use the smallest hook that expresses the requirement.

### `start_precmd`

Use this for preparation or validation before the default start:

```sh
start_precmd="exampled_precmd"

exampled_precmd()
{
    install -d -o example -g example -m 0750 /var/run/exampled
    test -r /etc/exampled.conf || err 1 "missing configuration"
}
```

Returning nonzero prevents startup unless force semantics explicitly override the failure.

### `start_cmd`

Use a custom start only when the default command construction cannot represent the required protocol. Once you replace `start_cmd`, you own process launch correctness.

### `stop_cmd`

Use a custom stop when lifecycle authority is not ordinary PID signaling:

```sh
stop_cmd="exampled_stop"

exampled_stop()
{
    /usr/sbin/examplectl shutdown
}
```

This is the mechanism Authorityd uses. The existence of `stop_cmd` prevents the generic stop branch from issuing `kill -TERM`.

### `status_cmd`

Use a custom status when a pidfile or process listing is not the right health or authority check:

```sh
status_cmd="exampled_status"

exampled_status()
{
    /usr/sbin/examplectl status
}
```

This is especially important when visibility or signal-zero checks are intentionally denied.

### `reload_cmd` and `extra_commands`

Reload is not automatically exposed merely because `reload_cmd` exists. Advertise it:

```sh
extra_commands="reload"
reload_cmd="exampled_reload"

exampled_reload()
{
    /usr/sbin/examplectl reload
}
```

Without a custom method, generic reload sends `SIGHUP` and does not wait for exit.

You may add service-specific commands:

```sh
extra_commands="reload validate rotate"
validate_cmd="exampled_validate"
rotate_cmd="exampled_rotate"
```

They then become available through `service exampled validate` and `service exampled rotate`.

## 7. The default operations, precisely

Defaults are useful only when you know their contracts.

### Start

The default start path:

1. Checks whether the service is enabled, unless an applicable prefix changes that.
2. Checks whether it appears to be running.
3. Runs setup and pre-start hooks.
4. Applies configured environment, identity, limits, jail, FIB, cpuset, nice, and directory settings.
5. Executes `command` with flags and arguments.
6. Runs the post-start hook.

The framework does not automatically prove application readiness. A successful fork or exec is not the same as a listening control socket.

### Stop

Without `stop_cmd`, the default stop path finds the PID, sends `${sig_stop:-TERM}`, waits for it to disappear, and runs the post-stop hook.

This is why people reasonably say “service stop sends SIGTERM.” It is true for the default method, but it is not a property of `service(8)` itself.

### Reload

Without `reload_cmd`, generic reload sends `${sig_reload:-HUP}`. The command must be listed in `extra_commands`.

### Status

Generic status reports whether the configured process check found a process. That is a liveness observation, not necessarily a health check.

### Restart

Restart runs stop and then start. Custom stop behavior is preserved because restart recursively dispatches the stop operation.

Be careful with failure cases. The stock restart implementation attempts its
start subcommand after its stop subcommand rather than treating both as one
transaction. Its final result is driven by the subsequent start path. Design
start so it refuses to create a second instance, and consider a custom
`restart_cmd` when start must never be attempted after an unsuccessful stop.

### Poll

Poll waits for the discovered PIDs to exit. It does not request shutdown.

## 8. Prefixes: `fast`, `force`, `one`, and `quiet`

Operations may be prefixed.

### `fast`

`faststart` skips the ordinary already-running check. `faststop` is used by system shutdown. A custom `stop_cmd` is still selected.

Do not read `faststop` as “send a stronger signal.” It means framework checks are reduced for the shutdown path.

### `force`

`forcestart` treats the service as enabled and relaxes some framework failure handling. It does not magically bypass kernel permissions or replace a custom method with generic signaling.

A fail-closed custom stop remains a custom stop under `forcestop`.

### `one`

`onestart` and `onestop` temporarily satisfy the enable condition. They are useful for disabled services during development and recovery.

### `quiet`

The quiet prefix suppresses selected diagnostics. It does not change lifecycle authority.

## 9. Process identity, pidfiles, and readiness

An rc integration is only as reliable as the daemon contract beneath it.

### Pidfiles

A daemon should create its pidfile only after it has secured single-instance ownership and should remove it during orderly exit. Creation should be race-safe. The file should contain the correct long-lived process PID, not a transient pre-daemonization child.

Pidfiles have limitations:

- PIDs can be reused.
- A stale file can outlive its process.
- A protected process may reject signal-zero probing.
- A pidfile says nothing about application readiness.

`check_pidfile` mitigates some reuse risk by comparing process identity, but a control protocol or process descriptor can provide stronger identity.

### Foreground versus daemonizing mode

The cleanest service architecture often keeps the daemon in the foreground and lets a real supervisor own it. Traditional rc does not itself remain as that supervisor, so many daemons still daemonize and use pidfiles.

Whichever model you choose, document it and ensure `command_args` selects the correct mode. Double-daemonization is a common cause of incorrect PIDs and unreliable shutdown.

### Readiness

Choose an explicit readiness contract:

- control socket exists and answers a status request;
- readiness pipe closes or receives a byte;
- daemon parent waits until initialization succeeds;
- protocol-specific health query succeeds.

Avoid using a fixed sleep as proof of readiness.

### Exit status

Custom methods should return meaningful status:

- `0`: requested state or operation confirmed;
- `1`: ordinary failure or wrong state;
- another documented nonzero value: a distinguishable condition, such as “pidfile exists but control plane is unreachable.”

Do not erase failures with `|| true` unless the operation is genuinely best-effort.

## 10. Control sockets as lifecycle authority

Signals are convenient but coarse. A control socket supports explicit operations and structured replies:

```text
administrator
  service exampled stop
    exampled_stop
      examplectl shutdown
        authenticated control socket
          daemon shutdown state machine
```

Advantages include:

- The daemon can authenticate peer credentials.
- Shutdown, reload, status, and diagnostics are distinct operations.
- The daemon can reject malformed requests.
- A reply can distinguish “accepted” from “completed.”
- The protocol can initiate ordered teardown of child processes and resources.
- Ambient PID signal authority can be denied.

### Accepted is not completed

If `examplectl shutdown` only reports that shutdown began, the rc method should wait for a completion condition. Authorityd waits for its pidfile to disappear. A stronger design could wait on a process descriptor or an explicit control reply.

### Fail closed

For a protected daemon, do not silently fall back from an authenticated control path to ambient `kill(2)`. That fallback changes the security model exactly when the control plane is unhealthy.

A fail-closed stop should:

1. Report that the control path is unavailable.
2. Leave live-state evidence such as the pidfile intact.
3. Return failure.
4. Reserve forced termination for an explicit authority such as a process descriptor holder.

### Root is not executable identity

A root-only Unix-domain socket authorizes eligible root clients. It does not prove that the caller executable is `/usr/sbin/service` or `/usr/sbin/examplectl`.

Trying to authorize based on a process pathname is usually the wrong model. If authority must be narrower than root, use an unforgeable descriptor, token, or dedicated credential boundary.

## 11. Authorityd as a worked example

Authorityd deliberately rejects foreign-nonce ambient PID signals. Its rc integration therefore replaces every standard operation that would otherwise depend on a signal.

The essential declarations are:

```sh
pidfile="/var/run/authorityd.pid"
extra_commands="reload"

stop_cmd="${name}_stop"
status_cmd="${name}_status"
reload_cmd="${name}_reload"
```

### Stop

```sh
authorityd_stop()
{
    local _i

    if [ ! -S /var/run/authorityd.sock ]; then
        echo "${name}: control socket unavailable; refusing ambient signal fallback." >&2
        return 1
    fi

    /usr/sbin/authorityctl shutdown || return 1

    _i=0
    while [ -f "${pidfile}" ] && [ $_i -lt 100 ]; do
        _i=$((_i + 1))
        sleep 0.1
    done

    [ ! -f "${pidfile}" ] || return 1
}
```

The resulting authority flow is:

```text
service authorityd stop
  /etc/rc.d/authorityd stop
    custom authorityd_stop
      authorityctl shutdown
        root-only control socket
          Authorityd stops serviced
            serviced cleans up managed children
          Authorityd exits and removes pidfile
```

No signal from `service(8)` needs to pass Authorityd's capability shield.

### Reload

```sh
authorityd_reload()
{
    /usr/sbin/authorityctl reload
}
```

The `extra_commands="reload"` declaration is necessary. Otherwise `run_rc_command` does not include reload in the accepted vocabulary.

### Status

Authorityd cannot use `kill -0` as an ambient liveness probe because signal zero goes through signal authorization. Status therefore queries the control socket. If a pidfile remains but the socket is absent, the script reports uncertainty rather than declaring the pidfile stale and deleting it.

### What remains impossible without a supervisor

If Authorityd's control loop is permanently wedged, rc cannot force-kill it while all foreign PID signals are denied. This is not an rc defect; it is the chosen authority boundary.

The capability-correct emergency authority would be a process descriptor held by init or another supervisor. Until such a holder exists, normal `service authorityd stop` works, while forced termination of a nonresponsive Authorityd does not.

## 12. Shutdown ordering and whole-world teardown

Shutdown is dependency order in reverse. If service A requires B during startup, A should normally stop before B.

For a hierarchy such as:

```text
Authorityd
  serviced
    managed services
      resources
```

the clean teardown order is bottom-up from the managed world's perspective:

1. Stop accepting new work.
2. Tell managed services to drain.
3. Terminate services that exceed their deadlines.
4. Release coalitions, channels, and delegated capabilities.
5. Exit serviced.
6. Exit Authorityd.

The rc.d script should request the top-level lifecycle operation, not independently signal every descendant. Descendant knowledge belongs to Authorityd and serviced.

### Timeouts

Put timeouts at protocol boundaries and state what happens on expiration. Do not create several unrelated timeout loops that race each other.

A useful hierarchy is:

- rc waits for Authorityd's overall shutdown deadline;
- Authorityd controls serviced's deadline;
- serviced controls individual service deadlines.

Each layer should log which child or phase prevented completion.

## 13. Dependencies versus active supervision

rc ordering answers:

> In what order should lifecycle operations be attempted?

It does not answer:

> Who restarts this process after a crash?

> Who owns an exact process identity?

> Who force-terminates a wedged process?

> Who receives child exit notifications continuously?

Those are supervision questions. A daemon may implement supervision internally, as Authorityd does for serviced, or a future init system may own process descriptors. Avoid pretending that a pidfile plus `REQUIRE` creates a supervisor.

## 14. Service jails and framework execution context

This tree's `rc.subr` supports service-jail settings through `<name>_svcj` and related variables. The framework can create a jail, start the service inside it, and remove the jail during stop.

This changes where custom methods execute. Review the `rc.subr` service-jail dispatch before assuming a control socket or path is visible from the host or jail.

Use `KEYWORD: nojail` when the daemon fundamentally cannot run in a jail. For example, a hardware broker may require global device or network-stack authority that a jail should never receive.

Capability confinement and jails solve different problems:

- a jail provides a namespace and privilege boundary;
- Capsicum restricts available operations to descriptors;
- MAC capability policies mediate relationships and resource authority;
- rc defines lifecycle ordering and administrative dispatch.

They should compose rather than impersonate one another.

## 15. Security design rules for rc integration

### Keep authority explicit

Ask what allows each operation:

| Operation | Weak authority | Stronger authority |
| --- | --- | --- |
| Stop by PID | UID plus signal permission | authenticated control operation or procdesc |
| Status | process-name scan | control health request |
| Reload | ambient SIGHUP | authenticated reload request |
| Child termination | remembered PID | procdesc or confined coalition |
| Resource access | pathname and UID | delegated capability descriptor |

### Do not widen policy for framework convenience

If generic rc stop conflicts with the daemon's security model, replace `stop_cmd`. Do not weaken the daemon merely so the default SIGTERM path keeps working.

### Avoid executable-path authentication

“Allow signals only from `service(8)`” is not a stable kernel authority model. `service` is a dispatcher that exits after invoking the script. The actual operation may be performed by `authorityctl`, shell code, or another helper.

Authenticate credentials or require possession of an unforgeable capability.

### Protect inherited descriptors

An rc script can control the initial environment, but the daemon must govern descriptor inheritance itself. Sensitive descriptors should receive appropriate Capsicum rights plus close-on-exec, close-on-fork, and transfer restrictions before untrusted children are created.

### Treat shell as privileged code

Rc scripts usually run as root. Quote expansions, validate configuration values, use absolute paths, set restrictive file modes, and avoid evaluating administrator data as shell code.

## 16. Testing an rc integration

High-quality testing has several layers.

### Syntax tests

```sh
sh -n libexec/rc/rc.d/exampled
```

This catches parsing errors, not behavioral errors.

### Metadata and ordering tests

Stage the script with its expected peers and run `rcorder`. Assert important relative ordering rather than copying the entire system order into a brittle golden file.

### Dispatch tests

Test that custom methods are selected. A mock control client can record calls such as:

```text
shutdown
reload
status
```

Verify that stop and reload do not invoke a mock `kill` command.

### Daemon integration tests

Launch a test-local daemon with private pidfile and socket paths. Exercise:

- start succeeds;
- duplicate start fails safely;
- status succeeds only when the control plane answers;
- reload reaches the daemon;
- stop waits for complete exit;
- pidfile and socket cleanup occur;
- malformed control replies fail closed;
- shutdown timeout preserves diagnostic state.

### Security tests

For a protected daemon, test both sides of the boundary:

- foreign ambient signals are denied;
- the control socket still authorizes graceful shutdown;
- disabling mandatory shields in configuration is rejected or ignored;
- an explicitly authorized procdesc path still works, if one exists;
- ordinary unshielded UNIX semantics remain unchanged.

### Shutdown-tree tests

Start child services and force failures at each layer. After top-level shutdown, assert that no Authorityd, serviced, managed-service, socket, pidfile, or coalition artifact remains.

### Run through Kyua

ATF test programs should normally run under Kyua so cleanup, timeouts, isolation, and result databases are enforced. Standalone ATF execution is useful for quick diagnosis but does not provide the same harness guarantees.

## 17. Source tree, object tree, and live system

FreeBSD development involves three different realities:

```text
/usr/src/...       source files you edit
/usr/obj/...       binaries and generated files you build
/etc, /usr/sbin    files the running system actually executes
```

Changing:

```text
/usr/src/libexec/rc/rc.d/authorityd
```

does not immediately change:

```text
/etc/rc.d/authorityd
```

Likewise, building a new `authorityd` under `/usr/obj` does not replace `/usr/sbin/authorityd`.

Always establish which copy a test is exercising:

```sh
service -v authorityd status
command -v authorityd
ls -l /etc/rc.d/authorityd /usr/sbin/authorityd
```

For development suites, explicitly put object directories first in `PATH` and set required library paths. For live validation, install the intended world or individual artifacts using the project's supported procedure.

Kernel changes introduce a fourth distinction: new source and modules do not change code already resident in the running kernel. A core kernel change normally requires building, installing, and booting the new kernel before its test can pass.

## 18. Debugging tools and techniques

### Ask the script what it supports

```sh
service authorityd extracommands
service authorityd rcvar
service authorityd describe
```

### Enable rc tracing

```sh
service -d authorityd status
sysrc rc_debug=YES
```

Use persistent global debug settings carefully because boot output becomes noisy.

### Run the script directly

For controlled diagnosis:

```sh
sh -x /etc/rc.d/authorityd status
```

Remember that `service(8)` supplies a restricted boot-like environment with `HOME=/` and a system `PATH`. A script that works only in an interactive shell probably has an undeclared environment dependency.

### Inspect configuration

```sh
sysrc authorityd_enable
sysrc -a | grep '^authorityd_'
service authorityd rcvar
```

### Inspect ordering

```sh
service -r | grep -n authorityd
rcorder /etc/rc.d/* | grep -n authorityd
```

### Inspect runtime artifacts

```sh
ls -l /var/run/authorityd.pid /var/run/authorityd.sock
authorityctl status
sockstat -u -l
ps -axww
```

For intentionally hidden or signal-protected processes, control-plane diagnostics are more authoritative than `ps` or `kill -0`.

### Read the implementation

The most authoritative local references in this tree are:

- `libexec/rc/rc.subr`
- `share/man/man8/rc.8`
- `share/man/man8/rc.subr.8`
- `usr.sbin/service/service.8`
- `sbin/rcorder/rcorder.8`
- `share/man/man5/rc.conf.5`

The dispatch comments inside `run_rc_command` are particularly valuable.

## 19. Reusable templates

### Conventional signal-managed daemon

```sh
#!/bin/sh
# PROVIDE: exampled
# REQUIRE: FILESYSTEMS syslogd
# KEYWORD: shutdown

. /etc/rc.subr

name="exampled"
desc="Example daemon"
rcvar="exampled_enable"
command="/usr/sbin/exampled"
pidfile="/var/run/exampled.pid"
command_args="-p ${pidfile}"

load_rc_config "$name"
: ${exampled_enable:="NO"}
: ${exampled_flags:=""}

run_rc_command "$1"
```

This accepts default TERM stop and process-based status.

### Control-socket-managed daemon

```sh
#!/bin/sh
# PROVIDE: exampled
# REQUIRE: FILESYSTEMS syslogd
# KEYWORD: shutdown

. /etc/rc.subr

name="exampled"
desc="Example capability-protected daemon"
rcvar="exampled_enable"
command="/usr/sbin/exampled"
pidfile="/var/run/exampled.pid"
extra_commands="reload"

stop_cmd="exampled_stop"
reload_cmd="exampled_reload"
status_cmd="exampled_status"

exampled_stop()
{
    /usr/sbin/examplectl shutdown || return 1
    local i=0
    while [ -e "$pidfile" ] && [ "$i" -lt 100 ]; do
        i=$((i + 1))
        sleep 0.1
    done
    [ ! -e "$pidfile" ]
}

exampled_reload()
{
    /usr/sbin/examplectl reload
}

exampled_status()
{
    /usr/sbin/examplectl status
}

load_rc_config "$name"
: ${exampled_enable:="NO"}
: ${exampled_flags:=""}

run_rc_command "$1"
```

For strict portability with historical `/bin/sh` styles, declare locals separately instead of assigning in the `local` command.

### Daemon requiring device preparation

```sh
required_modules="driver_module protocol_module"
start_precmd="exampled_precmd"

exampled_precmd()
{
    install -d -o example -g example -m 0700 /var/db/exampled || return 1
    test -c /dev/example0 || {
        warn "example device unavailable"
        return 1
    }
}
```

Module presence is a framework requirement. Device readiness is a daemon-specific precondition.

## 20. Common mistakes

### Assuming `service` always sends signals

It asks the rc.d script to perform an operation. The default stop method sends TERM; a custom `stop_cmd` can do something entirely different.

### Defining `reload_cmd` without `extra_commands=reload`

The function exists, but reload is rejected as an unknown operation.

### Treating `REQUIRE` as readiness

It establishes order only. Check actual readiness separately.

### Deleting a pidfile after an uncertain stop

This destroys evidence and may permit a second instance while the first is alive. Only the owning daemon or a process that proved exact death should remove it.

### Falling back to SIGKILL after a secure control failure

That silently widens authority during failure. If forced termination is required, design an explicit supervisor or capability for it.

### Using `kill -0` against a signal-protected daemon

Signal zero is still a signal-permission query. Use a control health operation or exact process descriptor.

### Testing the source while running installed files

Know whether `/usr/src`, `/usr/obj`, or the live root filesystem supplied each component.

### Depending on an interactive environment

`service(8)` uses a restricted boot-like environment. Use absolute paths and explicit configuration.

### Hiding errors with `|| true`

Suppress only errors whose failure is intentionally irrelevant. Stop, reload, readiness, and cleanup failures are usually important.

## 21. Design checklist

Before merging a daemon integration, answer these questions.

### Ordering

- What does the script provide?
- Which providers must precede it?
- Which services must start after it?
- Should it participate in ordered shutdown?
- Can it run in a jail or service jail?

### Configuration

- What is the enable default?
- Which administrator flags are supported?
- Are paths and shell values quoted safely?
- Are per-service `rc.conf.d` overrides supported?

### Process contract

- Does the daemon remain foreground or daemonize?
- Who writes and removes the pidfile?
- How is duplicate startup prevented?
- What proves readiness?
- What proves complete exit?

### Lifecycle authority

- Does default TERM stop match the security model?
- Does generic HUP reload match it?
- Is process-based status meaningful?
- Are custom methods required?
- What happens when the control plane is unavailable?
- Who, if anyone, owns forced-termination authority?

### Teardown

- Are children drained before the parent exits?
- Are deadlines hierarchical and logged?
- Are descriptors, sockets, pidfiles, jails, and other resources released?
- Does shutdown remain correct after partial initialization?

### Testing

- Does the script pass `sh -n`?
- Is rcorder behavior tested?
- Are custom dispatch and failure propagation tested?
- Are start, reload, status, stop, restart, and faststop covered?
- Are security allow and deny paths both covered?
- Are tests run under Kyua with cleanup and timeouts?
- Is the test using the intended source, object, and installed artifacts?

## 22. Working mental model

When reading any rc.d script, ask three questions in order:

1. **When does it run?** Read `PROVIDE`, `REQUIRE`, `BEFORE`, and `KEYWORD`.
2. **What policy configures it?** Read `name`, `rcvar`, `load_rc_config`, defaults, and standard per-service variables.
3. **What actually performs each operation?** Look for `<operation>_cmd`; only absent custom methods fall through to `rc.subr` defaults.

For Authorityd, that produces a precise answer:

- rc ordering places Authorityd early enough to establish its authority world;
- rc configuration determines whether and how it starts;
- custom status, reload, and stop methods use `authorityctl`;
- generic signal operations are never selected for those commands;
- Authorityd remains free to deny ambient signals without breaking normal `service authorityd stop`.

That is the larger lesson. Integrating a daemon with rc is not about making the daemon conform to a universal signal convention. It is about expressing an honest lifecycle contract through rc's standard administrative vocabulary.

## 23. Incremental migration from rc to `serviced`

Making Authorityd PID 1 does not imply that every daemon must move out of rc at
the same time. During the transition Authorityd runs `/etc/rc`, and `/etc/rc`
continues running every enabled service that has not been explicitly migrated.
This mixed arrangement may remain deployed for a long time and therefore must
be designed as a stable operating mode.

Authorityd should execute `/etc/rc` as the one init-compatible child; it should not
walk `/etc/rc.d` itself.  Stock rc performs an early base-system pass, discovers
local scripts after filesystems are available, recalculates the graph, and
runs the remaining entries.  This preserves diskless, firstboot, jail,
keyword, local-startup, and configuration-reload behavior that a simplified
loop would miss.

Every long-running service needs one authoritative owner:

```text
RC_LEGACY  -> rc.d starts and stops the daemon
SERVICED   -> serviced starts and stops the daemon
DISABLED   -> neither launcher may start it
```

No discovery heuristic is strong enough to replace this record.  Process
names and pidfiles can be stale, ambiguous, or reused. Authorityd should reject
a configuration that assigns both launchers rather than trying to clean up a
duplicate after it starts.  This check is mandatory during autoboot because
rc's `faststart` mode intentionally skips ordinary already-running checks.

For an rc-owned service, its existing script and configuration continue to
work normally.  For a migrated service, retain its rc.d script as an adapter:

- keep `PROVIDE`, `REQUIRE`, `BEFORE`, and relevant `KEYWORD` metadata;
- retain any boot-time preparation that must occur in that position;
- delegate start, stop, restart, reload, and status to the authorized
  Authorityd/`serviced` control protocol;
- wait for actual service readiness when downstream scripts need a live
  provider; and
- make shutdown idempotent when Authorityd has already quiesced the managed world.

This matters because `rcorder` establishes invocation order, not readiness.
A replaced script that immediately returns success can allow a dependent
legacy script to run before the managed daemon is usable.  The adapter must
bridge that semantic gap or the preparation and readiness milestones must be
represented separately.

Stock `run_rc_scripts()` also continues after an individual script fails, and
stock `/etc/rc` normally exits zero.  The adapter must report failure to
Authorityd, dependent managed adapters must refuse to start without their required
provider, and Authorityd must validate its required multi-user target after rc
returns.  Checking only `/etc/rc`'s exit code is not a boot-health test.

Migrate one service at a time.  Inventory its dependencies, one-shot setup,
resources, credentials, readiness, operator commands, and shutdown behavior;
then add its capability contract and `serviced` definition.  Prove one-instance
boot, cross-world readiness, `service(8)` operations, orderly shutdown, and
rollback before changing its default owner.

During whole-system shutdown Authorityd first freezes new work but keeps both
worlds alive.  `/etc/rc.shutdown` selects `shutdown` scripts, reverses rcorder,
and invokes `faststop`; migrated adapters use that call to stop their units
through the still-running `serviced` control plane.  This preserves reverse
ordering across ownership boundaries. After rc shutdown, Authorityd drains any
managed unit omitted by the keyword selection or left by an adapter failure,
then terminates `serviced`, escalating through its retained procdesc if
necessary.  PID 1's final global process sweep remains the safety net for
unmanaged or incorrectly classified processes.

The stock firstboot path ends by signaling PID 1 with `SIGINT`. Before Authorityd
enables mandatory signal shielding, that request and equivalent rc.d uses must
be converted to the authorized Authorityd lifecycle operation.
