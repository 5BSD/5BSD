# Discovery and the Lookup Channel

Programs request service names through an inherited, kernel-held discovery
channel. SwitchBoard returns a provider channel when admission succeeds.
The discovery route does not identify an authenticated user and does not grant
its holder the parent's software attributes.

## Route, software identity, and endpoint admission

These are separate responsibilities:

| Piece | Responsibility |
|---|---|
| Process-held discovery reference | Locate SwitchBoard without environment variables or a preserved FD number |
| Kernel software-authority context | Identify registered executable software and its authority generation |
| Kernel-stamped request metadata | Identify the actual sender without trusting a client-supplied bundle name |
| SwitchBoard | Resolve the sender's authority and enforce visibility and endpoint attributes |
| Provider | Implement the operations exposed by the returned capability |

Client bundles declare `attributes`; provider endpoints declare `requires`.
SwitchBoard checks the actual sender's attributes against those requirements.
The remaining SYSTEM, USER, and CONTROL domain scopes describe namespace
visibility; they are not login-account grants. See [Software attributes](attributes.md)
and [Management policy](management-policy.md).

UNIX login, SSH, and `su` authenticate and change UNIX credentials normally.
They do not mint capability privileges or replace discovery channels to match
an account. Anyone who may execute an approved program may use the operations
that program exposes. Changing UID neither grants another program's attributes
nor revokes the current program's attributes merely because its UID changed.
Prison boundaries and executable transitions have separate validity checks.

Fork inherits the discovery route and the permitted software context. Exec
preserves the route but re-evaluates executable authority: an unrelated image
cannot keep the previous program's privileges. Registered approved images can
acquire their own context on ordinary exec. Responsible-process attribution
and coalitions do not grant authority.

## Managed services and ordinary clients

A managed service has a typed bootstrap channel for checking in and publishing
endpoints, and a kernel-held discovery route available to its descendants.
An ordinary client uses that route through libservice without implementing
special login or FD-preservation logic. Both are authorized as software.

Discovery and management remain separate. An endpoint attribute permits
connection to that endpoint; management additionally follows the operation's
rights and the target's management class. Attributed clients can inspect
SwitchBoard status without the management attribute. Mutating control
operations require `system.switchboard.admin` and a held management right;
CORE services remain protected against runtime stop/restart.

The catalogue is controlled by an issuer capability and uses pinned executable
identity. A copied binary is not the registered executable. This mechanism is
not a substitute for the complete code-integrity boundary: manifests, loader,
libraries, configuration, and future signature enforcement also matter.

## Private lookup handles and lifetime

Libservice registers private reply channels so unrelated processes and library
sessions do not consume each other's replies. Requests are authorized using
kernel sender metadata, not a privilege snapshot inherited with the route.
Registration is bounded and may fail; it does not fall back to consuming replies
from an inherited shared queue.

Callers close returned handles. Closing ordinary descriptors or replacing the
environment does not clear the kernel-held discovery reference. A child may
select an already possessed route for itself and its future descendants;
this does not replace unrelated processes' routes. Process exit releases its
held reference. Explicitly clearing a route does not by itself revoke other
processes' references or already returned capabilities.

Authority-bound handles are a separate mechanism. Revoking an executable
registration invalidates its contexts and bound handles. Registry reload must
therefore retire changed authority, rather than let cached connections retain
removed privileges. Deliberately transferable provider capabilities need their
own documented lifetime semantics.

Keeping a route alive does not reconstruct SwitchBoard's server-side state
after its death. Recovery must re-establish valid routes and authority; route
inheritance alone is not a service-recovery guarantee.

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
                                   requires covered by attributes? open endpoint
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
| name unregistered, out of the channel's domain, or a missing required attribute | `ENOENT` |
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

## Verification and limits

The development VM exercises stock login, `su`, SSH authentication with and
without PAM, registered-image access, copied-image denial, and service control.
Additional tests cover cached-handle revocation and executable registration
changes. These are development checks, not a claim that the fresh installer
and every release artifact have passed acceptance.

There is no per-user capability grant policy or consent layer in this model.
A future operation-specific authorization layer would be additional policy,
not a reinterpretation of the inherited discovery route. See
[Software attributes](attributes.md) for the intended boundary and
[Authority model](../capability/authority-model.md) for kernel enforcement.

Reference: `usr.sbin/switchboard/naming.c`, `authority.c`, `domain.c`,
`on_demand.c`, and `lib/libservice/service_client.c`, `service_ambient.c`.
