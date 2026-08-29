# Using Process Protections

Beyond isolation claims, a component author routinely touches three more
capability services — capprotect, coalition, and channel — plus the Capsicum
descriptor-narrowing extensions.  This chapter shows the working patterns for
each, verified against the wire-protocol headers under
`sys/dev/mac_capability/` and the ATF tests under
`tests/sys/mac_capability/`.

## capprotect: shielding a process

The `capprotect` service protects a program (per nonce, so `fork()` children
are covered and `exec()` sheds the shield) against outside interference and
optionally restricts what it can do to itself.

Managed components use the `libservice` wrappers, which keep the kernel
protocol private.  A provider shields itself during bootstrap and a forked
session worker shields itself before `cap_enter()`:

```c
service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC);
/* ... in the pdfork'd worker: */
service_worker_protect(SERVICE_PROTECT_EXTERNAL | SERVICE_PROTECT_NOPRIVS |
    SERVICE_PROTECT_NOFORK | SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOEXEC);
service_worker_drop_inherited_authority();
cap_enter();
```

(`usr.sbin/localnetwork/networkcmp.c` does exactly this;
`usr.sbin/logd/logcmp.c` follows the same pattern with a stricter flag
set — its worker and provider both add `SERVICE_PROTECT_NOSOCK`, and its
provider also adds `SERVICE_PROTECT_NOFORK`.)  A supervisor-level program mints a shield directly with
`CP_OP_SHIELD` from `mac_capability_capprotect_proto.h` on a `"capprotect"`
instance:

```c
#include <dev/mac_capability/mac_capability_capprotect_proto.h>

struct cp_request req = { .op = CP_OP_SHIELD,
    .flags = CP_SF_PROTECT | CP_SF_NOPRIVS };	/* 0 means CP_SF_ALL */
size_t rlen = 0, rnfds = 0;
capability_kernel_call(shield_fd, &req, sizeof(req), NULL, 0,
    NULL, &rlen, NULL, &rnfds);
/* keep shield_fd open: closing it removes the flags it contributed */
```

Pick flags from two groups.  `CP_SF_PROTECT` blocks external interference:
with `CP_SF_VISIBLE` the process disappears from `ps`/`top`/procfs, with
`CP_SF_PTRACE` a foreign-nonce `ptrace(PT_ATTACH)` fails, with
`CP_SF_SIGNAL`/`CP_SF_SIGKILL`/`CP_SF_SIGCONT` foreign `kill(2)` — including
root's SIGKILL — is denied.  `CP_SF_RESTRICT` limits the process itself
(`CP_SF_NOFORK`, `CP_SF_NOEXEC`, `CP_SF_NOSOCK`, `CP_SF_NOFDRECV`,
`CP_SF_NOIPC`, `CP_SF_NOPRIVS`).  Flags are one-shot per fd and refcounted
per nonce: extra shield fds add flags, and each close removes only that fd's
contribution.  Undefined bits are rejected with `EINVAL`.  A held process
descriptor bypasses the signal shields — `pdkill(2)` is capability authority
in its own right.

To let a *different* program interact with a shielded one, the shield owner
mints a token (`CP_OP_MINT` on the shield fd, token returned as a reply fd,
`EINVAL` unless a shield is active) and hands it over; the peer activates it
with `CP_OP_AUTHORIZE` **on the token fd**, joining the authorized set for as
long as it holds the token.  `CP_OP_AUTHORIZE` on a shield fd and
`CP_OP_SHIELD` on a token fd both fail with `EINVAL` — the two fd flavors are
distinct.  The service also offers `CP_OP_CAPMODE` (enter capability mode)
and `CP_OP_CHROOT` (attached directory fd becomes the root).

## coalition: lifecycle containment

Connecting to `"coalition"` creates a new, empty coalition whose lifetime is
the instance fd.  Members are enlisted by attaching their descriptors —
process descriptors, sockets, other capability instance fds, jail
descriptors, even other coalitions (up to `COALITION_MAX_NESTING`):

```c
#include <sys/procdesc.h>
#include <dev/mac_capability/mac_capability_coalition_proto.h>

/* Connect with the MAC_CAPABILITY_CONNECT ioctl exactly as
 * isolation_connect() does in Writing a Component, with the service
 * name "coalition" — there is no library wrapper for connect. */
int cfd = coalition_connect();
int pd;
pid_t pid = pdfork(&pd, PD_CLOEXEC);
/* child runs the workload */

struct coalition_req_hdr hdr = { .op = COALITION_OP_ENLIST };
struct coalition_reply rpl;	/* rpl.status is a raw errno, 0 = ok */
size_t rlen = sizeof(rpl), rnfds = 0;
capability_kernel_call(cfd, &hdr, sizeof(hdr), &pd, 1,
    &rpl, &rlen, NULL, &rnfds);

int sv[2];
socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
hdr.op = COALITION_OP_ENLIST_SET;	/* batch: stops on first error */
struct coalition_enlist_set_reply esr;
rlen = sizeof(esr);
capability_kernel_call(cfd, &hdr, sizeof(hdr), sv, 2,
    &esr, &rlen, NULL, &rnfds);
```

A deadline gives the whole coalition a time budget, and a watchdog demands
periodic heartbeats:

```c
struct coalition_set_deadline_req dr = { .op = COALITION_OP_SET_DEADLINE,
    .timeout_ms = 30000, .signal = SIGTERM, .grace_ms = 2000 };
/* signal = 0 means immediate SIGKILL; timeout_ms = 0 cancels */

struct coalition_set_watchdog_req wr = { .op = COALITION_OP_SET_WATCHDOG,
    .timeout_ms = 5000 };	/* then COALITION_OP_HEARTBEAT periodically */
```

When a deadline or watchdog fires — or on `COALITION_OP_TERMINATE`, or when
the last coalition fd closes — enlisted processes receive the configured
signal (SIGKILL by default, settable with `COALITION_OP_SET_SIGNAL`) and
enlisted capability instances are revoked, so a wedged worker cannot keep
kernel services alive.  State changes arrive as `MAC_CAPABILITY_RECVMSG`
payloads (`struct coalition_event_msg`, `COALITION_NOTE_*`) with kqueue
`EVFILT_READ` readiness.  There is no userland wrapper library for coalition;
managed components instead return their worker to `serviced` with
`service_component_complete(bootstrap, SERVICE_COMPONENT_MEMBER_PROCDESC,
pd)` (or `SERVICE_COMPONENT_MEMBER_COALITION`) and let the framework own
containment.  `tests/sys/mac_capability/mac_capability_coalition_test.c` is
the exhaustive reference.

## channel: message passing between processes

`libchannel` (`channel.h`, `-lchannel`) is the high-level API over the
`"channel"` kernel service.  Pair creation itself is the one step libchannel
does not wrap: connect to `"channel"` and send `CHANNEL_OP_CREATE` with
`MAC_CAPABILITY_SENDMSG`; the `MAC_CAPABILITY_RECVMSG` reply carries the peer
fd (this raw two-ioctl sequence appears verbatim in
`lib/libchannel/tests/channel_test.c` and
`usr.sbin/serviced/mac_capability_direct.c`).  Each endpoint then wraps its
fd:

```c
#include <channel.h>

struct channel_options opts = CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
struct channel *ch;
channel_create(fd, &opts, &ch);		/* consumes fd on success */
```

Roles are directional: a client originates requests, a provider answers
them, and either side may send events.  Sending a message with an attached
descriptor puts the fd array in the outgoing struct — payload and fds remain
caller-owned:

```c
struct channel_outgoing out = CHANNEL_OUTGOING_INITIALIZER(buf, len);
out.fds = &fd_to_pass;
out.nfds = 1;
channel_send_request(ch, &out, reply_handler, ctx, NULL);
```

The provider installs a request handler with
`channel_set_request_handler()`, drives it from a kqueue loop (channels are
kqueue-only; register `channel_fd(ch)` for `EVFILT_READ`, toggle
`EVFILT_WRITE` while `channel_wants_write()` says so, then
`channel_dispatch()`/`channel_flush()` — see `serve_session()` in
`usr.sbin/localnetwork/networkcmp.c`), takes ownership of received
descriptors with `channel_message_take_fd()`, answers with
`channel_send_reply()`, and frees every message with
`channel_message_free()`.  Peer death is not an edge case: every outstanding
request completes with an error, a dead channel reports readable so the next
`channel_dispatch()` observes the failure, and `channel_error()` returns the
stable terminal errno thereafter.  After `fork()`, the child calls
`channel_abandon()` — channel fds are locked close-on-fork, so the child owns
bookkeeping but no live transport.

## Narrowing descriptors before handing them over

5BSD extends Capsicum with transfer and inheritance limits
(`sys/capsicum.h`): `cap_xfer_limit()` bounds how many times a descriptor may
be passed (`CAP_XFER_NONE`, `CAP_XFER_ONCE`), and
`cap_cloexec_limit()`/`cap_clofork_limit()` monotonically lock close-on-exec
and close-on-fork (`*_LOCKED` forces the flag forever; `*_ONCE` survives one
exec or fork, then locks).  Combined with classic `cap_rights_limit()` and
`cap_ioctls_limit()`, they produce descriptors whose authority cannot grow
back.  To hand a child a send-only, single-generation handle:

```c
#include <sys/capsicum.h>

cap_rights_t rights;
cap_rights_init(&rights, CAP_WRITE);		/* send-only */
cap_rights_limit(fd, &rights);
cap_ioctls_limit(fd, NULL, 0);			/* no ioctls at all */
cap_xfer_limit(fd, CAP_XFER_NONE);		/* never SCM_RIGHTS-passable */
cap_clofork_limit(fd, CAP_CLOFORK_ONCE);	/* one child inherits, then locked */
cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED);	/* never survives exec */
```

This is the production pattern: `localnetwork`'s `harden_worker_fd()` applies
`CAP_XFER_NONE` + `CAP_CLOFORK_ONCE` + `CAP_CLOEXEC_LOCKED` to every
descriptor destined for its `pdfork()`ed worker, and
`service_provider_worker_channel()` in `lib/libservice/libservice.c` locks
one endpoint of the pair into the parent (`CAP_CLOFORK_LOCKED`) and lets the
other cross into exactly one child (`CAP_CLOFORK_ONCE`).  For transferable
descriptors, `cap_xfer_rights_limit()`, `cap_xfer_ioctls_limit()`, and
`cap_xfer_fcntls_limit()` cap the authority the *receiver* obtains without
weakening the sender.  All limits are monotonic — apply them just before the
`fork()`/send, and the recipient can narrow further but never widen.
