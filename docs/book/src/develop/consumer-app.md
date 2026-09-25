# A Consumer Application

A consumer application publishes no name of its own. It needs things the
system provides, the network, a log, a place to keep state, and it gets each
one by asking a provider for it at the moment it needs it. 5BSD arranges this
so that the same binary can run sealed in capability mode as a switchboard
unit and unsealed from a shell, and so that a provider being down is a delay,
not a crash. This chapter writes `netlog`, a program that fetches a URL,
records the reply in its own storage, and logs what it did, and runs it both
ways. The complete source compiles against the tree; the fragments below are
taken from it.

## What the program links

| Need | Library | Header | The call that acquires it |
|---|---|---|---|
| Sockets and name resolution | `libnetworkcmp` | `networkcmp.h` | `networkcmp_client_open(3)` |
| A log sink usable after the seal | `liblogcmp` | `logcmp.h` | `logcmp_log(3)` (lazy, internal) |
| Mutable storage of its own | `libservice` | `libservice.h` | `service_storage_open(3)` |
| The bootstrap or ambient context | `libservice` | `libservice.h` | `service_acquire(3)`, `service_open(3)` |

None of these needs a manifest declaration. `switchboard(5)` says it in one
line: a unit links the matching library and reaches the service lazily at
first use.

## Acquiring the network lazily

`networkcmp_client_open()` opens `system.Network` by name (it calls
`service_open()` underneath) and returns a process-wide client. Wrap it so
that a failure is recorded and retried rather than fatal:

```c
static struct networkcmp_client *net;

static struct networkcmp_client *
network(void)
{
        if (net == NULL && networkcmp_client_open(&net) == -1) {
                logcmp_log(LOG_WARNING, "system.Network unavailable, will retry: %m");
                net = NULL;
        }
        return (net);
}

static void
network_lost(void)
{
        if (net != NULL) {
                networkcmp_client_close(net);
                net = NULL;
        }
}
```

With a client in hand, resolution and connection are ordinary calls. The
broker resolves the name in its own process, applies the label's policy from
`bsdnetwork.conf`, and hands back a real, rights-limited, connected socket
over the channel; from then on the application reads and writes it itself.
The descriptor cannot bind, listen, accept, reconnect or be re-sent:

```c
memset(&hints, 0, sizeof(hints));
hints.ai_socktype = SOCK_STREAM;
error = networkcmp_getaddrinfo(n, host, port, &hints, &res);
if (error != 0) {
        logcmp_log(LOG_WARNING, "resolve %s: %s", host, gai_strerror(error));
        if (error == EAI_SYSTEM)
                network_lost();
        return (-1);
}
for (ai = res; ai != NULL; ai = ai->ai_next)
        if (networkcmp_connect_ex(n, ai->ai_addr, ai->ai_addrlen, 5000, &fd) == 0)
                break;
networkcmp_freeaddrinfo(res);
if (fd == -1) {
        logcmp_log(LOG_WARNING, "connect %s:%s: %m", host, port);
        if (errno == ECONNRESET || errno == EPIPE)
                network_lost();
        return (-1);
}
write(fd, request, sizeof(request) - 1);
got = read(fd, buf, bufsz - 1);
close(fd);
```

`networkcmp_connect_ex()` bounds the handshake; the plain
`networkcmp_connect()` blocks with the kernel default. A `EPERM` from either
means the label's policy does not grant `connect` (or `resolve`, or the
address family); that is an operator decision recorded in
[system.Network](../providers/network.md), not something to retry.

## Logging

`logcmp_log()` is the one sink to use. It opens a logger to `system.Log` on
first use, names the component after `getprogname()`, and if `system.Log` is
unreachable (before the plane is up, or when BSDLog is down) falls back to
`syslog(3)`; a sealed process's syslog attempt goes nowhere silently, which is
the right fail-soft behaviour for a diagnostic. It preserves `errno`, so
`%m` works. Anything written to standard error by a unit ends up in
`/var/log/capability.log`, which switchboard opened for the child before the
seal. Queries and retention are in [system.Log](../providers/log.md).

## Storage of its own

A unit's mutable state lives in a container that `system.Filesystem` derives
from the unit's channel label: `Data/<bundle>/<unit>/persistent/<name>`. The
program claims it by name and receives a mounted directory descriptor, the
only handle it will ever hold on that dataset:

```c
static int
spool_open(void)
{
        struct service_context *ctx;
        int dirfd;

        if (service_acquire(&ctx) == -1) {
                logcmp_log(LOG_INFO, "no switchboard context; spool disabled: %m");
                return (-1);
        }
        if (service_storage_open(ctx, "spool", &dirfd) == -1) {
                logcmp_log(LOG_WARNING, "system.Filesystem storage unavailable, will retry: %m");
                dirfd = -1;
        }
        service_release(ctx);
        return (dirfd);
}

fd = openat(dirfd, "last-reply", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
```

Everything under the descriptor is ordinary `openat(2)` work, legal in
capability mode. The claim persists across restarts, is quota-bounded, can
be snapshotted and rolled back, and is reaped when the bundle is removed:
`service_storage_open_cache()` for regenerable data,
`service_storage_open_shared()` for a store every unit of the bundle shares,
`service_storage_snapshot()` and `service_storage_rollback()` for versions,
`service_storage_txn_begin()` for an atomic multi-file update. Note the
`service_acquire()` in the middle: storage needs the bootstrap context that
only a switchboard launch provides. See
[Containers and Storage](../plane/containers-and-storage.md).

## The fail-soft path

The main loop treats every acquisition failure as "not yet":

```c
for (attempts = 0; attempts < 10; attempts++) {
        if (spool == -1)
                spool = spool_open();
        if (fetch(host, port, reply, sizeof(reply)) == 0) {
                logcmp_log(LOG_INFO, "fetched %s: %.40s", host, reply);
                if (spool != -1)
                        spool_write(spool, reply);
                return (0);
        }
        sleep(delay);                   /* 1, 2, 4, ... 30 s */
        if (delay < 30)
                delay *= 2;
}
logcmp_log(LOG_ERR, "giving up on %s after %d attempts", host, attempts);
```

What this buys, concretely. If `netlog` is boot-activated and comes up before
BSDNetwork has checked in, its first `service_open()` is parked by switchboard
until the provider is ready and then times out after
`SERVICE_LOOKUP_TIMEOUT_MS` if it is not; the program logs and sleeps instead
of dying with a "no such service". If BSDNetwork is restarted by its watchdog
mid-run, the next call on the old session fails with a reset; `network_lost()`
drops it and the next attempt opens a fresh one. If BSDFilesystem is slow, the
fetch still happens and only the spool is skipped this round. A provider being
down never turns into `netlog` being down.

## Running it as a bundle

Packaged as `Netlog.cap`, the program runs born in capability mode with no
code to say so. switchboard `cap_enter(2)`s in the child and `fexecve(2)`s
the program from the bundle; the dynamic linker finds `libc`, `libservice`
and the rest through directory descriptors in `LD_LIBRARY_PATH_FDS`, the
bundled `Config/` arrives as `CAPABILITY_CONFIG_FD`, stdio goes to the
diagnostic log, and the process reaches RUNNING when the kernel reports it in
capability mode. `service_in_capability_mode(3)` tells the program which world
it is in, if it ever needs to know.

```ucl
# Netlog.cap/Units/netlog.unit/Unit.ucl
activation { schedule = "hourly"; }
arguments = ["example.org", "80"];
restart = "never";
domain = "system";
limits { nofile = 64; nproc = 4; core = 0; }
```

Two lines deserve attention. `schedule = "hourly"` is the plane's cron: the
unit is launched on demand at each matching wall-clock time and stays stopped
in between; `restart = "never"` suits a one-shot. `domain = "system"` is
needed because `system.Network` publishes no `visible = ["user"]`: an
application bundle resolves only user-visible names by default, and the
network broker is SYSTEM-only. An Apps bundle may declare the system domain;
a per-user agent may not.

Every open path in the program is gone. There is no `open("/etc/resolv.conf")`;
the broker reads it. There is no `open("/var/spool/netlog")`; the container
descriptor replaces it. If the program did need a file it does not ship, it
would ask `system.Filesystem` for it by path through
`service_open_isolated(3)`, and receive it only if `tzfs.conf(5)` grants that
label that path.

## Running it from a shell

The same binary, run by hand:

```sh
$ netlog example.org 80
HTTP/1.0 200 OK
...
```

Nothing was sealed: the process holds the ambient authority of the login,
as any BSD program does. What changed is discovery. A login session inherits
a lookup channel that `login(1)`, `su(1)` or `sshd(8)` had `system.Auth` mint
for the principal, advertised as `SERVICE_LOOKUP_FD`; `service_open()` finds
no bootstrap descriptor, so it resolves over that channel through
`service_connect_ambient(3)`, and the first ambient lookup registers a private
per-process channel so replies never race a sibling's. The two paths differ in
one respect the program must accept: `service_acquire()` fails with `EBADF`
from a shell, so `spool_open()` logs "no switchboard context" and the spool is
skipped; storage is a per-unit container, and a shell process is not a unit.

Whether the lookup succeeds depends on the session's domain. An admin login
(a principal with `admin_rights` in `principal-policy.ucl`) holds a SYSTEM
channel and resolves `system.Network`; an ordinary user's session holds a
USER channel and gets `ENOENT`, indistinguishable from an unregistered name,
so `netlog` logs "system.Network unavailable" and retries until it gives up.
That is not a bug in the program; it is the policy in
[Discovery and the Lookup Channel](../plane/discovery-and-lookup.md) doing its
job. A program that wants to know which path it is on can call
`service_connect_ambient()` directly and treat the answer as a probe.

## Checklist

| Item | Do | Do not |
|---|---|---|
| Acquire | on first use, through the typed library | at startup, then `err(1)` |
| Provider down | log, back off, retry; drop a reset session | exit, or loop hot |
| Files | bundle `Config/`, `service_storage_open()`, `service_open_isolated()` | `open(2)` by global path |
| Logging | `logcmp_log()` | `syslog(3)` alone |
| Identity | let the label carry it | `getuid()`, `geteuid() == 0` |
| Reach | declare `domain = "system"` when a needed name is SYSTEM-only | assume every session sees every name |

## Limits

Storage self-service is available only to switchboard-launched units.
`system.Network` has no per-call timeout op beyond the connect deadline, and
its policy has no per-destination grants finer than family and dimension.
The `schedule` activation launches on the minute, in local time, with
`persistent = true` for catch-up after downtime; it is not a replacement for
`cron(8)` jobs that need a user's environment, which keep running through the
adopted `cron` unit.
