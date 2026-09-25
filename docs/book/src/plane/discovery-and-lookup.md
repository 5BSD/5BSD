# Discovery and the Lookup Channel

Every program on a 5BSD system that wants a service finds it the same way: it
sends a reverse-domain name over a channel it inherited, and
[switchboard](switchboard.md) answers with a fresh channel to the provider or
with `ENOENT`. There is no socket path to guess, no `/var/run` to search and
no uid check on the far end; the channel a request arrives on already says who
sent it. 5BSD has this because it makes discovery a scoped grant instead of a
global namespace, and because every session channel is unforgeable, so
"who may reach what" is decided once at mint time and never re-derived from
a pathname.

The model is recorded in `docs/service-discovery-model.md` and
`docs/capability-ambient-lookup-per-process.md`; the code is
`usr.sbin/switchboard/naming.c`, `domain.c`, `on_demand.c` and
`lib/libservice/service_client.c`, `service_ambient.c`.

## Two orthogonal axes

Discovery and management are separate questions, and the plane keeps them
separate on purpose. Discovery is which names a principal may resolve and
connect to. Management is which units a principal may start, stop, load or
unload. Both ride the same inherited channel, but the first is a property of
the channel's domain and anointment set, and the second is a property of the
unit's `control` class matched against the caller's rights. A monitoring tool
can hold full discovery with no management; an operator session can manage
`system` units it cannot see. This chapter is about the first axis; the
second is in [The Management Model](management-model.md).

## Principals and domains

A lookup channel carries a domain: a scope over the naming registry that only
ever narrows (`enum svc_domain_kind` in `switchboard.h`).

| Principal | Channel | Resolves |
|---|---|---|
| a unit launched from `/Capabilities/System` | its bootstrap channel, `domain = system` | every registered name |
| a unit from `/Capabilities/Apps` or a per-user agent | its bootstrap channel, `domain = user` | only names whose provider declares `visible = ["user"]` |
| an admin login session (wheel by default, per principal policy) | a SYSTEM session channel minted by BSDAuth | every name, and carries every anointment plus the admin rights bit |
| an ordinary login session | a USER session channel bound to the uid | user-visible names plus any gated endpoint its anointments cover |
| rc and its descendants | the SYSTEM ambient channel switchboard installs before `/etc/rc` | every name |

`visible` is the provider's decision, read from the bundle registry whether or
not the provider is running, so it answers identically on the resolve path and
the on-demand path. A name a domain may not see is reported as `ENOENT`,
indistinguishable from an unregistered name; the true reason (`EACCES`) is
visible only in the `domain-lookup-deny` DTrace probe. A gated endpoint (one
with `requires`) is reachable by any channel whose anointment set covers it
regardless of `visible`, because the provider said who may reach it. A unit
whose own domain is USER cannot mint session domains, so an application can
never widen itself (`svc_domain_may_mint()`).

Sessions get their channel from the mint boundary. `login(1)`, `su(1)` and
`sshd(8)` capture the SYSTEM lookup channel they inherited and call
`service_mint_session_via_agent()` (or `service_mint_session_authenticated()`
for a non-admin `su`, which proves the target's password instead); BSDAuth,
the one unit with `mint_authority = true`, decides from
`/Capabilities/Config/principal-policy.ucl` what the session holds and asks
switchboard to mint a channel bound to `(uid, domain, anointments, rights)`.
`login` pins the inherited channel at fd 3 (`SERVICE_LOOKUP_FIXED_FD`) before
its `closefrom(3)`, which is how a console session gets one at all: Capsule
`dup2`s the channel to fd 3 in each getty it spawns. See
[Anointments and Principal Policy](anointments.md) for the policy file and
[Sessions](../compat/sessions.md) for the per-program details.

## The per-process private lookup channel

The ambient channel rc inherits is one shared endpoint with one kernel receive
queue. Lookups are token-correlated request and reply, and libchannel drops a
reply whose token matches no pending request in the receiving process, so two
siblings looking up at once could discard each other's replies. The fix is the
Darwin shape: a caller-owned reply mailbox.

On its first ambient lookup a process calls
`mac_capability_channel_create(fds[2])`, an ungated, `SYF_CAPENABLED` syscall
that returns a connected pair it owns and that carries no authority. It sends
one end to switchboard in a one-way `SVC_OP_REGISTER_LOOKUP` over the shared
channel, never awaiting a reply there. switchboard validates that the
descriptor is a channel, derives the domain from the sender's kernel-attested
nonce (never from the wire), and adopts the endpoint into its kqueue as this
process's private lookup channel. Every later lookup goes over the private
end, whose queue only this process holds. The state is memoized per process
(`AMBIENT_PENDING`, `AMBIENT_PRIVATE`, `AMBIENT_FALLBACK` in
`service_ambient.c`), an `atfork` handler drops the private end in a child so
it registers its own, and every failure (no syscall, send failure, no ACK
within 2 s) falls back to the shared channel, resolved live on each call.
Staggered clients register cleanly; a microsecond-simultaneous burst of eight
or more first lookups can push some onto the fallback, which degrades soft.

## How a name resolves end to end

Take BSDNotify calling `logcmp_log(3)` for the first time.

```text
client                          switchboard                        provider
------                          -----------                        --------
service_open("system.Log")
  service_acquire() ok, so
  service_connect() over the
  bootstrap channel (fd 3)  -->  handle_lookup(): stamp says
                                 requester = system.Notify/notifyd
                                 naming_lookup():
                                   self-served control name?  no
                                   registered and RUNNING?    yes
                                   svc_domain_permits()?      yes
                                   requires covered by holds? open endpoint
                                   mac_cap_create_channel()
                                   cap_xfer_limit(client_end, ONCE)
                                   SVC_OP_NEW_CLIENT + provider_end -->  listener for
                                                                        "system.Log"
                                                                        queues the session
  <-- reply status 0 + client_end
*session_fdp = client_end
service_session_create(fd)   -----------------------------------------> direct channel
```

`service_open()` tries the bootstrap context first because it is the richer
one, and returns its result verbatim: a genuine `ENOENT` there is not retried
on the ambient channel. A program with no bootstrap (a CLI in a shell) goes
straight to `service_connect_ambient()`, which sends the same `SVC_OP_LOOKUP`
over the private lookup channel with a 2 s bound (`SERVICE_LOOKUP_TIMEOUT_MS`)
so a wedged switchboard cannot stall a tool forever.

When the name is reserved but no listener is published, `naming_lookup()`
returns `ENOENT` internally and `on_demand.c` takes over: it launches the
bundle if it is not already `STARTING`, coalesces every concurrent lookup for
that runtime onto the one launch, and holds each request. The provider checks
in a listener for every declared name (`SVC_OP_NAME_CLAIM`), enters capability
mode (observed by the kernel, not claimed), and sends `SVC_OP_READY`;
switchboard then sends `SVC_OP_ACTIVATE_NAME` for the requested name only, and
the provider's `SVC_OP_NAME_RESULT` releases that name's queued lookups, each
with its own fresh channel. A name that is out of scope for the channel is
refused before any launch, so a plain channel cannot force-start a provider it
could never reach.

## Descriptor delivery: single transfer, sender closes

The client end of a session channel is limited to `CAP_XFER_ONCE` before
switchboard sends it (`naming.c`). The one delivery send consumes that budget,
so the descriptor arrives at the consumer as `CAP_XFER_NONE`: it cannot be
forwarded again. The provider's end stays unlimited because it is the
provider's own; a provider that hands sessions to worker processes attenuates
to `ONCE` itself immediately before the `SCM_RIGHTS` send, so the worker lands
at `NONE`. A provider that exposed the name with `service_provider_expose_sendable()`
leaves the client end unlimited so the consumer may re-send it, attenuating
per hop as it chooses. There is no multi-hop budget minted at the source; the
lattice is `UNLIMITED > ONCE > NONE` with per-hop attenuation, and the rule for
every relay is the same: send it onward, then close your copy. Fork
inheritance is a separate axis (`CAP_CLOFORK`), which is how a session's shell
descendants share the session channel without any transfer.

Closing or crashing either peer revokes the other endpoint. A successful send
means the kernel accepted the message, not that the provider processed it;
typed protocols use non-zero reply tokens for acknowledgement, and only
operations a protocol defines as idempotent may be retried across a provider
restart.

## Fail-soft on a missing provider

A consumer sees one of a small set of errors and must treat all of them as
"not now":

| Condition | errno |
|---|---|
| name unregistered, out of the channel's domain, or an anointment miss | `ENOENT` |
| no ambient channel in this process at all | `ENOENT` |
| reserved name whose provider never published within 10 s | `ETIMEDOUT` |
| provider died between claim and publish | its exit fails the waiters immediately |
| switchboard itself unreachable | `ETIMEDOUT` from the bounded call |
| more than 64 lookups pending at once | `EAGAIN` |
| requester tried to look itself up | `ELOOP` |

None of these is fatal by contract. A unit must not `err(3)` because a
provider is down; it degrades, retries lazily, and keeps serving what it can
(the rule is recorded in the inventory as "no hard dependencies"). libservice
exposes `service_supervisor_fd()` and `service_supervisor_status()` so a library can
tell manager death from an unknown name when it matters, but the default
posture is to treat both the same.

## The client library pattern

Every typed client library does the same three things: acquire lazily on
first use, cache one session per process, and fall back when the provider is
absent. `lib/liblogcmp/logcmp.c` is the smallest example, because logging
must work before and during a BSDLog restart:

```c
static int
logcmp_open_channel(void)
{
	int fd, error;

	fd = -1;
	error = service_open(LOGCMP_INTERFACE, &fd) == -1 ? errno : 0;
	if (error != 0)
		fd = -1;
	LOGCMP_PROBE_OPEN(__DECONST(char *, LOGCMP_INTERFACE), error);
	errno = error;
	return (fd);
}

static void
logcmp_default_ensure(void)
{
	pid_t pid;

	pid = getpid();
	if (logcmp_default_pid != pid) {
		/* First use, or a forked child: abandon any inherited handle. */
		logcmp_default_client = NULL;
		logcmp_default_logger = NULL;
		logcmp_default_pid = pid;
	}
	if (logcmp_default_logger != NULL)
		return;			/* already connected this process */
	/* Retry the open on every call until it succeeds. */
	if (logcmp_client_open(&logcmp_default_client) == -1) {
		logcmp_default_client = NULL;
		return;
	}
	if (logcmp_logger_create(logcmp_default_client, getprogname(), "log",
	    &logcmp_default_logger) == -1) {
		logcmp_client_close(logcmp_default_client);
		logcmp_default_client = NULL;
		logcmp_default_logger = NULL;
	}
}
```

`logcmp_vlog()` calls `logcmp_default_ensure()`, emits over the cached logger
if there is one, and otherwise falls through to `vsyslog(3)`. The cost of a
failed connect while BSDLog is down is accepted because logging is not hot.
`lib/libnetworkcmp/networkcmp.c` uses the same shape with a mutex and a
condition variable so that concurrent first callers wait for one
`service_open(NETWORKCMP_INTERFACE, &fd)` rather than racing to open several,
then records `client->owner = getpid()` so a forked child does not reuse the
parent's session. Neither library takes a manifest declaration: linking it and
calling it is the whole integration.

A provider's side is the mirror image (`service_provider_create()`,
`service_provider_expose()` once per declared name, `service_provider_ready()`
after `cap_enter`, `service_heartbeat()` if it declares a watchdog), covered in
[A Capability Provider](../develop/provider.md).

## Status and limits

The private lookup channel, uid-derived domains, the anointment match and
session minting for console, `su` and `ssh` are shipped and VM-verified
(`lib/libservice/tests`, `usr.sbin/switchboard/tests/ambient_lookup_test`,
`register_lookup_gate_test`, `domain_test`). Two limits remain. Per-uid
discovery policy finer than `visible` plus anointments is not built; a
provider cannot yet say "user 1001 only" except by gating an endpoint on an
anointment that principal policy grants to that user. And switchboard-side
absorption of a simultaneous registration burst is future work, so a
synthetic herd of first lookups falls back to the shared channel rather than
failing, as described above. The `SVC_DOMAIN_CONTROL` kind and a
`SVC_MINT_DOMAIN_CONTROL` request survive in `domain.c` as a residual of an
earlier design; the shipped control path does not depend on them.
`switchboardctl` and `capsulectl` resolve `system.switchboard` and
`system.lifecycle` from an ordinary session, and `naming_lookup()` gates those
two names on the `system.switchboard.admin` anointment before any domain
check.

Reference: switchboard(8) NAMING REGISTRY, switchboard(5) IPC ANOINTMENTS,
libservice(3), `docs/service-discovery-model.md`,
`docs/capability-ambient-lookup-per-process.md`.
