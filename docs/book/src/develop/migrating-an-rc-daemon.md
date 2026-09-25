# Migrating an rc Daemon

An rc daemon does not have to become a capability provider in one move, and
it does not have to become one at all. 5BSD keeps `/etc/rc` running beside
the plane so that a daemon can be adopted untouched, then given a manifest,
then moved onto channels, then sealed, then given a system gate if it needs
privilege, with the machine working at every step. This chapter walks those
steps in order, says what each one buys and what it breaks, and uses BSDTime
as the worked example for the last step, because its history in
`usr.sbin/BSDTime` shows the move from an ambient root daemon to a sealed one
in a single commit.

## The steps at a glance

| Step | What changes | What the daemon gains | What it still is |
|---|---|---|---|
| 0. Adoption | one line in `rc_adopt.conf` | supervision, restart, a label in `switchboardctl` | an rc.d script and a uid |
| 1. Manifest | a `.cap` with `ambient = true` (base bundles only) | a bootstrap channel, limits, `protect`, watchdog | an unsealed process on a socket |
| 2. Channels | `service_provider_expose()`, no socket, no `getpeereid` | reach by name, kernel-stamped client labels, per-client workers | unsealed |
| 3. Born in capability mode | `service_provider_enter_capability_mode()`, delivered descriptors, `open_paths` | the sandbox from the first instruction | unprivileged |
| 4. Gates | `capabilities { system = [...] }`, `service_system_*()` | one privileged operation, in kernel context, through a held token | a base provider |

Each step is a shippable state. Steps 0 and 1 change no daemon code.

## Step 0: adoption

switchboard runs `/etc/rc` concurrently with its native units, and it
natively supervises a curated list of rc.d services. The list is a file, not
code, at `/Capabilities/Config/switchboard/rc_adopt.conf`:

```text
# one rc.d service name per line; '#' begins a comment
cron
exampled
```

At boot switchboard probes each name with `service <name> onestatus`; a live
instance that `/etc/rc` already started is adopted as it is, and an absent one
is started with `onestart` regardless of its `rcvar`. The unit is registered
as an rc-kind unit with the script's name as its label, `control = "system"`
and `restart = "on-failure"`, and stopped with `onestop` under a 30-second
backstop. It appears in the service list with no change to the script or the
binary:

```sh
$ switchboardctl services
...
  cron                 running  pid 655 restart=on-failure mgmt=system by=system
  exampled             running  pid 701 restart=on-failure mgmt=system by=system
```

What breaks: nothing. The daemon still binds its socket, still checks uids,
still logs to syslog. What it gains is restart on crash and an operator
surface (`switchboardctl stop exampled`, which needs the
`system.switchboard.admin` anointment). A name absent from `/etc/rc.d` is not
an error; the list is fail-soft. Details in
[rc and service(8)](../compat/rc-and-service.md).

## Step 1: a manifest, still ambient

The next state is a bundle whose manifest launches the unchanged binary:

```ucl
# Exampled.cap/Units/exampled.unit/Unit.ucl
activation { boot = true; }
program = "exampled";
arguments = ["-f"];             # foreground
user = "root";
restart = "on-failure";
control = "system";
ambient = true;
limits { nofile = 256; nproc = 32; core = 0; }
protect = ["ptrace", "signal", "wait", "sigkill", "sigcont", "sched",
    "core", "ktrace"];
```

`ambient = true` means switchboard `execve(2)`s the program by path with no
`cap_enter(2)` and takes its ready message, not the kernel's capmode event,
as readiness. Only a base-system bundle under `/Capabilities/System` may say
this; for an Apps bundle switchboard logs "'ambient' ignored" and seals the
unit anyway. So step 1 is available to a daemon you are moving into base; a
third-party daemon goes from step 0 straight to step 2 and 3 together.

What this buys with no code change: `limits`, `umask`, `protect`, a
`watchdog` if the daemon can be taught one call, and, once it links
`libservice`, the bootstrap channel that step 2 uses. The daemon must run in
the foreground; switchboard supervises by process descriptor, and a program
that forks and exits looks like a crash. It must also stop leaning on its
environment: a unit gets `PATH`, `USER`, `HOME`, `CAPABILITY_UNIT_DIR` and
what the manifest's `environment` adds, nothing else, with stdio on
`/dev/null` (the diagnostic log comes with step 3).

What breaks: `rc.conf` knobs. The manifest is the configuration now
(`arguments`, `environment`), and the script's `precmd` and `pidfile` logic
is gone. Keep the rc.d script installed and disabled during the transition so
`service(8)` users are not surprised.

## Step 2: channels instead of a socket

This is the first code change and the one that removes the uid check. The
classic shape:

```c
lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
bind(lfd, (struct sockaddr *)&sun, sizeof(sun));
listen(lfd, 16);
for (;;) {
        fd = accept(lfd, NULL, NULL);
        if (getpeereid(fd, &uid, &gid) == -1 || uid != 0) {
                syslog(LOG_WARNING, "refusing uid %u", (unsigned)uid);
                close(fd);
                continue;
        }
        serve(fd);
}
```

becomes:

```c
if (service_provider_create(&provider) == -1 ||
    service_provider_authorize_capabilities(provider) == -1 ||
    service_provider_expose(provider, "org.example.exampled", &listener) == -1 ||
    service_provider_enter_ambient(provider) == -1 ||       /* step 2: still ambient */
    service_provider_ready(provider) == -1)
        ...
for (;;) {
        id.size = sizeof(id);
        if (service_listener_accept(listener, &id, &fd) == -1) {
                if (service_provider_quiescing(provider) == 1)
                        return (service_provider_quiesce_complete(provider, 0) == 0 ? 0 : 1);
                continue;
        }
        serve(fd, id.client_label);
}
```

and `serve()` becomes a channel loop whose policy keys on the label:

```c
static void
handle_request(struct channel *channel, struct channel_message *message, void *argument)
{
        const char *label = argument;

        if (channel_message_fd_count(message) != 0 ||
            strcmp(label, "org.example.app/worker") != 0) {
                int status = -EPERM;
                (void)channel_send_reply(message, &(struct channel_outgoing)
                    CHANNEL_OUTGOING_INITIALIZER(&status, sizeof(status)));
        } else {
                (void)channel_send_reply(message, &(struct channel_outgoing)
                    CHANNEL_OUTGOING_INITIALIZER(channel_message_data(message),
                    channel_message_length(message)));
        }
        channel_message_free(message);
}
```

The manifest gains `activation { boot = true; ipc = ["org.example.exampled"]; }`
and, if user sessions should reach it, `visible = ["user"]`. Clients replace
`connect()` on the socket path with `service_open("org.example.exampled", &fd)`
and `service_session_create()`; a client that resolves the name is launched
against if the unit is stopped, so `boot = true` becomes optional. Per-client
`pdfork(2)` workers, as in [A Capability Provider](provider.md), can come
now or with step 3; what matters here is that the daemon's authorization
question changed from "who is calling" to "what does the caller hold".

What breaks: every client that spoke the socket, at once. If some cannot be
rebuilt, keep the socket listener beside the channel listener for one
release, and drop it when the last client moves. The uid check has no
equivalent and should not be reproduced: a caller that could reach the name
holds a session switchboard was willing to mint, and `id.rights` carries
`SERVICE_RIGHTS_ADMIN` for an admin session if the daemon wants an
administrative bypass. Logging still goes to syslog at this step, and the
daemon still reads `/etc` by path, both of which the next step removes.

## Step 3: born in capability mode

Replace `service_provider_enter_ambient()` with
`service_provider_enter_capability_mode()`, drop `ambient = true` from the
manifest, change `user` to `capability`, and the process is sealed before its
first instruction. Now everything the daemon opened by path must come from
somewhere else. There are four sources, in order of preference:

| The daemon needs | It now uses | Delivered how |
|---|---|---|
| its own configuration | `service_config_open("exampled.conf", &fd)` | bundle `Config/` as `CAPABILITY_CONFIG_FD` |
| nodes under a known directory | `directories = ["/dev"]` then `service_resource_dir("/dev", &dirfd)` and `openat(2)` | `CAPABILITY_DIR_FDS`, opened by switchboard pre-seal |
| a shared file outside the bundle | `service_open_isolated(ctx, "/etc/resolv.conf", SERVICE_OPEN_READ, 0, &fd)` | BSDFilesystem opens it if `tzfs.conf(5)` `open_paths` grants the label |
| mutable state | `service_storage_open(ctx, "state", &dirfd)` | a container the label owns |

The isolated-open grant is written by the operator, keyed on the exact
label, default-deny:

```ucl
# /Capabilities/Config/bsdfilesystem.ucl
open_paths = [
    { label = "org.example.exampled/exampled"; path = "/etc/resolv.conf";
      rights = ["read"]; },
];
```

And the code that gathers descriptors does the path-shaped work before the
seal and the brokered work after it:

```c
tzset();                                 /* /etc/localtime, once, pre-seal */
cfg = open_config();                     /* service_config_open() */
dev = open_device();                     /* service_resource_dir() + openat() */
if (service_provider_create(&provider) == -1 ||
    ...
    service_provider_enter_capability_mode(provider) == -1 ||
    service_provider_ready(provider) == -1)
        ...
if (service_acquire(&ctx) == 0) {
        shared = open_shared(ctx);       /* service_open_isolated() */
        service_release(ctx);
}
```

Note that the born-in-capmode launch means the process is already sealed
when `main()` runs: `service_config_open()` and `service_resource_dir()` work
because they `openat(2)` under delivered descriptors, not because they run
early. The `tzset()` line is for the ambient path a test harness might use;
`service_worker_enter_capability_mode()` does the same warm-up for workers.

What breaks, and the fix for each:

| Breaks | Why | Fix |
|---|---|---|
| `syslog(3)` | `/var/run/log` is a path; the send fails silently | `logcmp_log(3)`; stderr goes to `/var/log/capability.log` |
| `open("/etc/...")`, `fopen()` | no path lookups after the seal | the four sources above |
| `getpwnam(3)`, `getgrnam(3)` | NSS reads `/etc/passwd` by path | resolve before the seal, or as BSDAuth does, read the files through an isolated open and parse them |
| `localtime(3)` first use | opens `/etc/localtime` | `tzset()` before the seal (the worker helper does it) |
| `res_query(3)`, `getaddrinfo(3)` | `/etc/resolv.conf` and sockets with addresses | `libnetworkcmp`: the broker resolves and connects |
| `socket()` + `bind()` on a UNIX path | a path | a channel; or a `socket` activation entry and `service_activation_socket(3)` for a listener switchboard binds |
| `bind()`/`connect()` INET | legal in capability mode on 5BSD | nothing; the kernel allows them (`sobindat`/`soconnectat`) |
| `dlopen(3)` by path | a path | bundle `lib/`; rtld consults `LD_LIBRARY_PATH_FDS` |
| Casper (`cap_init(3)`) | a zygote must fork before `cap_enter(2)`, and the unit is born sealed | do not start one; check `service_in_capability_mode(3)` and take the capmode-native path, as the base providers did when they retired Casper |
| `daemon(3)`, pidfiles | supervision is by process descriptor | run in the foreground; delete the pidfile code |
| `clock_settime(2)`, `kldload(2)`, `jail_set(2)`, privileged `sysctl(3)` | not capability-enabled system calls | step 4 |

The last row is the reason step 4 exists. Everything else on the list is a
matter of asking a broker instead of the filesystem, and the daemon is no
less capable for it.

## Step 4: a gate, with BSDTime as the worked example

Some daemons exist to perform a privileged kernel operation for their
clients. BSDTime steps and slews `CLOCK_REALTIME`, which needs
`PRIV_SETTIMEOFDAY`, and `clock_settime(2)` is refused at the system-call
boundary in capability mode, so no amount of uid can help a sealed process.
Its history shows the move.

**Before** (`575d421e461c`, "new system.Time capability provider"): an
ambient provider. The manifest said `user = "root"` and `ambient = true`;
`main()` ended with `service_provider_enter_ambient()`; each client was
served in a `pdfork(2)` worker that called
`service_worker_drop_inherited_authority()`; and `TIMECMP_OP_SET` called
`clock_settime(CLOCK_REALTIME, &ts)` directly. The per-label policy in
`time.conf` was the security boundary, and the daemon ran as root outside the
sandbox to reach the syscall.

**After** (`94d1d1c4408d`, "born-in-capmode BSDTime via a SYS_GATE_SETTIME
system gate"): the manifest reads

```ucl
user = "capability";
capabilities { system = ["settime"]; }
```

and the daemon reads

```c
static int g_time_token = -1;

/* in main(), after expose and before the seal: */
if (service_system_token_dup(&g_time_token) == -1) {
        logcmp_log(LOG_WARNING, "no settime capability; SET/ADJUST disabled: %m");
        g_time_token = -1;
}
if (service_provider_enter_capability_mode(provider) == -1 ||
    service_provider_ready(provider) == -1)
        goto fail;

/* in the SET handler, replacing clock_settime(): */
if (service_system_settime(g_time_token, &ts) == -1) {
        status = errno;
        ...
}
```

At launch switchboard asks capsule to mint a system-gate token carrying
exactly the declared gate and delivers it as a bootstrap capability;
`service_provider_authorize_capabilities()` activates it. The kernel
performs the operation in its own context after checking the held claim; the
raw `clock_settime(2)` stays refused, so the sandbox is not loosened. The
daemon runs as `capability`, not root: the token, not the uid, is the
authority. `service_system_adjtime()`, `service_system_sysctl()`,
`service_system_kldload()`, `service_system_kldunload()`,
`service_system_jail_set()` and `service_system_jail_get()` are the other
gate calls, each with a matching gate name in the manifest; the full list is
in [System Gates](../capability/system-gates.md).

Two things changed shape with the gate, and both are lessons for any daemon
taking this step. First, the token is delivered close-on-fork, so the
per-client `pdfork` workers went away and BSDTime serves each client inline,
sequentially, with an idle deadline so one silent client cannot wedge the
loop; a gate daemon whose requests are not trivial keeps workers and dups the
token into a plain descriptor for them, which is what
`service_system_token_dup()` is for. Second, the missing-token case is
fail-soft: `GET` still works, and `SET` returns the gate's error to the
client. The commit also fixed two kernel-side plumbing bugs in multi-gate
delegation, which is the kind of thing a first gate daemon should expect to
find.

The gate step is for base providers: the declaration is minted as the
verified manifest states it, it is stripped from per-user agents, and
`switchboard(5)` reserves it for the base brokers. A site daemon that needs a
privileged operation asks the base broker that already holds the gate
(`libtimecmp`, `libsysctlcmp`, `service_ensure_extension()`,
`service_enter_namespace()`), which is usually the better design anyway.

## Testing each step

Step 0 is tested by `usr.sbin/switchboard/tests/rc_adopt_test.c` and by
watching `switchboardctl services`. From step 2 on, the provider_test
pattern applies: compile the daemon with a `-D<NAME>_TESTING` flag that
exposes the session worker, connect a channel pair with
`mac_capability_channel_create()`, and drive the real handler; BSDTime's
`tests/provider_test.c` adds one case that mints a real settime token on an
unclaimed plane and performs a no-op round trip (set the clock to its current
value, slew by zero) so the whole gate path is covered without moving the
clock. The step-3 breakage table is best checked in a VM boot, where
`/var/log/capability.log` shows what a sealed daemon tried to open by path.
See [Testing](testing.md).

## Limits

Adoption today covers the rc.d services named in `rc_adopt.conf`; the full
migration of `/etc/rc` into native units is not done, and the rc-kind unit
never signals the daemon directly (it runs the script's `onestop`). A daemon
that needs a privileged operation with no gate in the list of twelve stays
ambient, and only in base. And there is no library for the per-label policy
file every provider ends up with; each base daemon parses its own with
`libucl`, from its delivered `Config/`.
