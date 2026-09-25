# A Capability Provider

A capability provider is a program that offers a facility to other programs
under a name. It is reached over a kernel channel that stamps the caller's
identity, launched by switchboard the first time someone looks the name up,
sealed in capability mode before its first instruction, and served to each
client in an isolated worker. 5BSD has providers so that a facility can be
handed out as a held capability instead of a socket path plus a uid check.
This chapter builds one end to end: `org.example.Echo`, a provider that sends
back what it is given. Every call below is declared in
`lib/libservice/libservice.h` and `lib/libchannel/channel.h`; the complete
sources compile against the tree and are the basis of every fragment shown.

## Two ways to write a service

| | The BSD way (still supported) | The 5BSD way |
|---|---|---|
| Reached by | a socket path or port | a name (`org.example.Echo`) |
| Started by | rc.d, always running | switchboard, on first lookup |
| Client identity | `getpeereid(3)`, a uid | the channel label the kernel stamped |
| Sandbox | opt-in | capability mode from the first instruction |
| Isolation | you fork or thread it | one `pdfork(2)` worker per client |
| Replaceable | rebuild clients | swap the binary; the name is the contract |

The `system.` prefix belongs to the base providers; a third-party provider
uses a reverse-domain name.

## 1. The wire protocol

A capability is a typed request/reply protocol over a channel. Put it in one
header both sides include, and give every message a fixed header with a magic,
an ABI version, an opcode and a status, so a provider can refuse a frame
without guessing at it:

```c
#define ECHO_SERVICE_NAME  "org.example.Echo"
#define ECHO_MAGIC         0x4543484fU
#define ECHO_ABI_VERSION   1
#define ECHO_MAX_DATA      240

enum echo_opcode { ECHO_OP_HELLO = 1, ECHO_OP_ECHO = 2 };

struct echo_msg {
        uint32_t magic;
        uint16_t version;
        uint16_t opcode;
        uint32_t flags;
        int32_t  status;        /* reply: 0 or -errno */
};
struct echo_hello_reply { uint32_t version; uint32_t max_data; };
struct echo_event       { uint32_t type;    uint32_t served;   };
```

`HELLO` exists so a client can learn the provider's ABI before it depends on
it; every base provider has one (`TIMECMP_OP_HELLO`, `AUDITCMP_OP_HELLO`).
A shared `echo_validate()` checks magic, version, opcode and length, and
both the provider and the test call it. Replies carry `-errno` in `status`,
which is how a client distinguishes "the provider said EPERM" from "the
transport failed".

## 2. The provider's main

The bootstrap is a fixed sequence. Create the provider object, authorize the
capabilities switchboard delivered, shield the process, publish the name,
seal, and report ready:

```c
service_set_proctitle();
kq = kqueuex(KQUEUE_CLOEXEC);
if (kq == -1 ||
    service_provider_create(&provider) == -1 ||
    service_provider_authorize_capabilities(provider) == -1 ||
    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
        SERVICE_PROTECT_NOEXEC) == -1 ||
    service_provider_expose(provider, ECHO_SERVICE_NAME, &listener) == -1) {
        logcmp_log(LOG_ERR, "echo: bootstrap: %m");
        return (1);
}
EV_SET(&change, service_listener_fd(listener), EVFILT_READ,
    EV_ADD | EV_ENABLE, 0, 0, listener);
if (kevent(kq, &change, 1, NULL, 0, NULL) == -1 ||
    service_provider_enter_capability_mode(provider) == -1 ||
    service_provider_ready(provider) == -1) {
        logcmp_log(LOG_ERR, "echo: ready: %m");
        return (1);
}
```

Nothing here opens `/dev/mac_capability`, binds a socket, or reads a uid.
switchboard launched the program with a sealed bootstrap descriptor at fd 5;
`service_provider_expose()` publishes the name on it. Note the order:
`service_provider_ready()` never enters capability mode itself, so the seal
comes first, and switchboard treats the kernel's `NOTE_CAPMODE` event, not
the ready message, as the moment the unit is RUNNING.

`SERVICE_PROTECT_EXTERNAL` is the capprotect shield against outside
interference (ptrace, signals, visibility); `NOEXEC` is a restriction on the
process itself. Where the flags come from, and what `protect = [...]` in the
manifest adds pre-exec, is in
[Descriptor and Process Protections](../capability/descriptor-protections.md).

The accept loop waits on the listener and on the process descriptors of live
workers, and it sends a heartbeat every pass:

```c
for (;;) {
        n = kevent(kq, NULL, 0, &event, 1, &tick);   /* tick = 10 s */
        if (n == -1 && errno == EINTR)
                continue;
        (void)service_provider_heartbeat(provider);
        if (n == 0)
                continue;
        if (event.filter == EVFILT_PROCDESC) {
                (void)pdwait((int)event.ident, &status, WEXITED | WNOHANG, NULL, NULL);
                close((int)event.ident);
                nworkers--;
                continue;
        }
        identity.size = sizeof(identity);
        if (service_listener_accept(listener, &identity, &fd) == -1) {
                if (service_provider_quiescing(provider) == 1)
                        break;
                continue;
        }
        if (start_session(fd, identity.client_label, &pd) == -1) {
                logcmp_log(LOG_WARNING, "echo: session for %s: %m",
                    identity.client_label);
                close(fd);
                continue;
        }
        close(fd);
        EV_SET(&change, pd, EVFILT_PROCDESC, EV_ADD | EV_ENABLE, NOTE_EXIT, 0, NULL);
        ...
}
status = service_provider_quiesce_complete(provider, 0);
```

`identity.client_label` is the caller's bundle label, stamped by the kernel;
`identity.rights` is the rights mask its session carries. Scope every piece
of per-caller state by the label. When switchboard asks the provider to stop,
`service_listener_accept()` fails and `service_provider_quiescing()` returns 1;
the provider finishes what it must and reports through
`service_provider_quiesce_complete()`.

The heartbeat is a no-op unless the manifest declares `watchdog { interval =
N }`; with it declared, a provider that stops calling
`service_provider_heartbeat()` for `N` seconds is killed and relaunched under
its `restart` policy. The deadline is armed when the unit reaches RUNNING, so
a provider that wedges during start-up is caught too.

## 3. Worker isolation

Each client is served in its own `pdfork(2)` child, so one client can neither
see nor stall another, and the parent's authority does not leak in. The
session descriptor is hardened to cross exactly one fork, and a small barrier
lets the parent learn whether the worker hardened itself before it starts
serving:

```c
static int
worker(int fd, int barrier, const char *label)
{
        int error;

        error = service_worker_enter_capability_mode(SERVICE_PROTECT_EXTERNAL |
            SERVICE_PROTECT_NOFORK | SERVICE_PROTECT_NOIPC |
            SERVICE_PROTECT_NOFDRECV | SERVICE_PROTECT_NOEXEC |
            SERVICE_PROTECT_NOSOCK) == -1 ? errno : 0;
        if (write(barrier, &error, sizeof(error)) != sizeof(error) || error != 0)
                return (1);
        if (read(barrier, &byte, 1) != 1)
                return (1);
        close(barrier);
        return (serve_session(fd, label));
}

/* in the parent, before pdfork(): */
service_harden_fd(fd, SERVICE_HARDEN_CLOFORK_ONCE);
socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, syncfd);
service_harden_fd(syncfd[0], 0);
service_harden_fd(syncfd[1], SERVICE_HARDEN_CLOFORK_ONCE);
pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
```

`service_worker_enter_capability_mode()` is the worker-side mirror of the
provider bootstrap: it shields the worker, drops every descriptor authority
libservice retained in the parent, warms the timezone and message catalogs
that would otherwise need a path lookup, and calls `cap_enter(2)`. The
in-tree providers use exactly this shape; `usr.sbin/BSDAudit/auditcmp.c` is
the smallest complete reference. A provider that must hold a close-on-fork
token in the serving process (BSDTime with its settime gate) serves inline
instead; see [Migrating an rc Daemon](migrating-an-rc-daemon.md).

## 4. Requests, replies and notifications

The worker drives one channel from a wait loop and answers requests from a
handler. Channels are kqueue-only; `channel_wait()` wraps that. The loop
bounds idle time so a client that connects and then goes silent cannot pin a
worker forever:

```c
if (channel_create(fd, &options, &channel) == -1 ||        /* consumes fd */
    channel_set_request_handler(channel, handle_request, &session) == -1)
        ...
for (;;) {
        wants_write = channel_wants_write(channel);
        ready = channel_wait(channel, wants_write, remaining_ms);
        if (ready <= 0)
                break;                  /* error, peer gone, or idle */
        if ((ready & CHANNEL_WAIT_WRITE) && channel_flush(channel) == -1)
                break;
        if ((ready & CHANNEL_WAIT_READ) && channel_dispatch(channel) == -1)
                break;
        if (session.error != 0)
                break;
}
channel_destroy(channel);
```

The handler validates first and fails closed: a frame that carries a
descriptor, or that does not pass `echo_validate()`, gets an `EPROTO` reply
and ends the session. Then it dispatches:

```c
static void
handle_request(struct channel *channel, struct channel_message *message, void *argument)
{
        struct session *session = argument;
        const struct echo_msg *rq = channel_message_data(message);
        size_t length = channel_message_length(message);

        if (channel_message_fd_count(message) != 0 || echo_validate(rq, length) == -1) {
                session->error = EPROTO;
                (void)send_reply(message, NULL, EPROTO, NULL, 0);
                goto out;
        }
        switch (rq->opcode) {
        case ECHO_OP_HELLO:
                hello.version = ECHO_ABI_VERSION;
                hello.max_data = ECHO_MAX_DATA;
                result = send_reply(message, rq, 0, &hello, sizeof(hello));
                break;
        case ECHO_OP_ECHO:
                result = send_reply(message, rq, 0, rq + 1, length - sizeof(*rq));
                if (result == 0 && ++session->served % 100 == 0) {
                        struct echo_event ev = { ECHO_EVENT_SERVED, session->served };
                        (void)channel_send_event(channel, &(struct channel_outgoing)
                            CHANNEL_OUTGOING_INITIALIZER(&ev, sizeof(ev)));
                }
                break;
        default:
                result = send_reply(message, rq, EOPNOTSUPP, NULL, 0);
        }
out:
        channel_message_free(message);
}
```

`send_reply()` builds a header plus payload in a stack buffer and hands it to
`channel_send_reply()`; an error reply carries no payload. The
`channel_send_event()` call is a notification: an unsolicited message from
provider to client that the client reads with
`service_session_receive_event(3)`. Use events for state changes a client
would otherwise poll for; keep them small and idempotent, because a slow
client's queue is bounded by the channel options.

## 5. Logging

A sealed provider cannot reach `syslogd`'s socket, so it logs through the Log
capability: `logcmp_log(3)` emits to `system.Log` through a logger opened
lazily on first use, and falls back to `syslog(3)` whenever `system.Log` is
unreachable. It never blocks and never fails the caller, and it preserves
`errno` so a trailing `%m` still works. Anything the provider writes to
standard output or error before or after the seal lands in
`/var/log/capability.log`, which switchboard opened as the child's stdio.
The whole story is in [Logging, Audit and Trace](../plane/logging-audit-trace.md).

## 6. The bundle

Ship the program as a `.cap` directory. The manifest says how to launch it
and nothing about what it may touch:

```text
Echo.cap/
  Bundle.ucl
  Units/echo.unit/
    Unit.ucl
    bin/echo
```

```ucl
# Echo.cap/Bundle.ucl
schema = "org.5bsd.capability-bundle";
schema_version = 1;
bundle_id = "org.example.echo";
version = "1.0.0";
sequence = 1;
publisher = "org.example";
units = ["echo"];
```

```ucl
# Echo.cap/Units/echo.unit/Unit.ucl
activation { ipc = ["org.example.Echo"]; }
restart = "on-failure";
control = "system";
visible = ["user"];
protect = ["ptrace", "signal", "wait", "sigkill", "sigcont", "sched",
    "core", "ktrace"];
watchdog { interval = 30; }
limits { nofile = 512; nproc = 300; core = 0; }
umask = "0077";
```

Unit names are lowercase, digits and hyphens; the default program is
`bin/<unit>`. `activation { ipc = [...] }` reserves the name and launches the
unit on first lookup; add `boot = true` to start it at boot instead or as
well. `visible = ["user"]` lets a login session resolve the name; without it,
only SYSTEM-domain callers can. `user` and `group` default to `capability`.
The unit runs born in capability mode; an application bundle cannot opt out.
The complete key set is in [Bundles and Manifests](../plane/bundles-and-manifests.md).

## 7. Install and observe

Check the bundle offline, then put it where switchboard looks. Site bundles go
under `/Capabilities/Apps`, root-owned and not group- or other-writable;
switchboard verifies the tree and watches the directory, so a bundle copied
into place is picked up, and `switchboardctl reload` forces a transactional
rescan (it needs the `system.switchboard.admin` anointment on the caller's
session, not root):

```sh
$ switchboardctl verify Echo.cap
Effective configuration:

Bundle: Echo.cap
  ID:      org.example.echo
  ...
  [0] org.example.echo/echo
      program:   .../Echo.cap/Units/echo.unit/bin/echo
      activation: ipc
      restart:   on-failure
      management: system
      user: capability
      provides: org.example.Echo
      protect: 0x1fb
# cp -R Echo.cap /Capabilities/Apps/
$ anoint system.switchboard.admin switchboardctl reload
```

(`switchboardctl install Echo.cap` copies a bundle into
`/Capabilities/System` instead; that is for base-style bundles.) Once loaded,
the unit shows in the service list by its label, `bundle_id/unit`:

```sh
$ switchboardctl services
switchboard: running
services: 18 loaded (17 running, 1 stopped, 0 starting, 0 stopping, 0 done)
fd-budget: soft=... hard=... reserve=... denied=0 control-shed=0

  system.Time/bsdtime    running  pid 412 restart=on-failure mgmt=core by=system
  org.example.echo/echo  stopped  restart=on-failure mgmt=system
```

`stopped` is the correct state for an `ipc`-activated provider nobody has
looked up yet. After the first client, it reads `running` with a pid and
`by=activation`.

## 8. The consumer

A client resolves the name and makes typed calls. It does not know or care
which binary answers, and it does not know whether it triggered a launch:

```c
if (service_open(ECHO_SERVICE_NAME, &fd) == -1)
        err(1, "open %s", ECHO_SERVICE_NAME);
if (service_session_create(fd, &session) == -1)
        err(1, "session");

rq->magic = ECHO_MAGIC; rq->version = ECHO_ABI_VERSION; rq->opcode = ECHO_OP_ECHO;
memcpy(rq + 1, text, strlen(text));
request.size = sizeof(request); request.data = out; request.length = sizeof(*rq) + strlen(text);
reply.size = sizeof(reply);     reply.data = in;    reply.capacity = ECHO_MAX_MESSAGE;
options.timeout_ms = 5000;
if (service_session_call(session, &request, &reply, &options) == -1)
        err(1, "call");
if (echo_validate(rp, reply.length) == -1 || rp->status != 0)
        ...
```

`service_open(3)` resolves over the bootstrap channel when switchboard
launched the caller and over the session's ambient lookup channel otherwise,
so the same client works as a unit and from a shell. A provider with a richer
surface wraps this in a small client library of typed calls, as the base
ships `libtimecmp`, `liblogcmp` and the rest. (The `err(1)` calls belong in a
throwaway client; a real consumer retries, as the
[next chapter](consumer-app.md) shows.)

## 9. Testing it

The in-tree pattern is a `provider_test` that compiles the provider with a
`-D<NAME>_TESTING` flag, which guards out `main()` and exposes the session
worker, then drives the real handler over a real kernel channel:

```c
/* in echo_provider.c */
#ifdef ECHO_TESTING
int echo_test_serve_session(int fd, const char *label) { return (serve_session(fd, label)); }
#else
int main(void) { ... }
#endif

/* in echo_test.c (ATF) */
static void
fixture_create(struct fixture *f)
{
        int fds[2];

        if (mac_capability_channel_create(fds) == -1)
                atf_tc_skip("mac_capability channels unavailable: %s", strerror(errno));
        f->child = fork();
        if (f->child == 0) {
                close(fds[0]);
                _exit(echo_test_serve_session(fds[1], "org.test.echo.client"));
        }
        close(fds[1]);
        ATF_REQUIRE_EQ(0, service_session_create(fds[0], &f->session));
}
```

`mac_capability_channel_create()` makes a self-owned pair of connected
channel endpoints with no switchboard involved, so the test needs no plane
and no root. The cases then cover the protocol the way `usr.sbin/BSDTime/tests/provider_test.c`
does: `HELLO` reports the ABI; an echo round-trips; an unknown opcode, a
short frame and an attached descriptor are each refused with `EPROTO` or a
torn-down session, either being a correct rejection. Wire it into the build
with `ATF_TESTS_C`, `CFLAGS.provider_test+= -DECHO_TESTING`, and
`LIBADD= channel service`, as `usr.sbin/BSDTime/tests/Makefile` does. More in
[Testing](testing.md).

## Limits

A provider's per-label policy is its own to define; libservice hands it the
label and the rights mask, and nothing more. There is no library helper for
policy files; the base providers each parse a small UCL file from their
delivered `Config/` directory with `service_config_open(3)`. Events are
delivered only while a client holds the session and are dropped, counted,
when its queue is full. And a provider that must perform a privileged kernel
operation is a base provider: the `capabilities { system = [...] }` gate
declaration is stripped from per-user agents and is minted for everything else
exactly as the verified manifest declares it, which under `mac_veriexec` means
only a bundle in the signed set can hold one. Such a facility ships in
`/Capabilities/System` or it does not exist.
