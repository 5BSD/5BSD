# The MAC Capability Framework

`mac_capability` is the kernel substrate of the 5BSD capability plane: a
message-passing framework in which every kernel service, and every
process-to-process channel, is reached through a file descriptor of type
`DTYPE_MAC_CAPABILITY`. Holding the descriptor is holding the authority;
every attenuation is a one-way operation on the descriptor itself. 5BSD has
it because Capsicum confines a process but gives it no capability-shaped
way to obtain, delegate or revoke authority, and because every new
Capsicum-aware kernel service in FreeBSD otherwise costs new `CAP_*` bits, a
new `DTYPE_*`, a new syscall and hand-written queue code. This chapter
covers the framework itself. The descriptor-level controls it relies on are
in [Descriptor and Process Protections](descriptor-protections.md); why
authority is a held descriptor at all is in
[The Authority Model](authority-model.md).

## What is in the kernel

The framework and all of its service modules are compiled into every 5BSD
kernel: `sys/conf/files` lists the thirteen `sys/dev/mac_capability/*.c`
sources as `standard`. There is no `mac_capability_load` knob and no
module to load; only the two test fixtures (`test_kernelstore`,
`test_keystore`) are loadable. The core is four files: `mac_capability_core.c`
(service registry, instance lifecycle, sysctls, DTrace), `mac_capability_dev.c`
(the ioctl surface, kqueue, close), `mac_capability_kern.c` (the kernel API
used by service modules) and `mac_capability_label.c` (the process nonce).
Nine named services sit on top of it.

| Service name | Model | MAC policy? | What it is | Man page |
|---|---|---|---|---|
| `identity` | CALL | no | nonce queries: self, or a process named by an attached procdesc | mac_capability_identity(4) |
| `capprotect` | CALL | yes | per-process integrity shields, launcher-applied protection, access tokens | mac_capability_capprotect(4) |
| `isolation` | CALL | yes | file, network, vsock and jail claims and tokens keyed by nonce | mac_capability_isolation(4) |
| `system` | CALL | yes | the twelve privileged-operation gates and their perform ops | mac_capability_system(4) |
| `coalition` | CALL and SENDMSG, notifies | no | resource groups torn down together | mac_capability_coalition(4) |
| `node` | CALL | no | per-process inspection and control through an attached procdesc | mac_capability_node(4) |
| `accounting` | CALL | no | racct charge/release/set and rctl rules; connect needs `PRIV_ACCT` | mac_capability_accounting(4) |
| `channel` | SENDMSG/RECVMSG, mintable | no | connected endpoint pairs for process-to-process messaging | mac_capability_channel(4) |
| `mount` | CALL | no | mount and unmount through `kernel_mount(9)`, scoped to the caller's jail | mac_capability_mount(4) |

"MAC policy" means the module also registers with `MAC_POLICY_SET` and
enforces through MAC framework hooks, not only through its own messages.
Four policies register: the nonce label policy in `mac_capability_label.c`,
`capprotect`, `isolation` and `system`. The other services are pure message
services; their authority is the instance descriptor alone. Isolation and
the system gates each have their own chapters
([Policy Points](policy-points.md), [System Gates](system-gates.md));
coalitions and accounting are in
[Coalitions and Accounting](coalitions-and-accounting.md).

## Who can open the device

`/dev/mac_capability` is created mode 0600. At boot capsule claims the
device node itself through the isolation service (`FI_OP_CLAIM` in
`usr.sbin/capsule/mac_capability_claims.c`), so after that only capsule's
program identity can open it; every other opener gets `EACCES`, root
included. Nothing else in the system connects to a kernel service by name.
A process gets its capability descriptors in one of three ways: delivered
at launch by [switchboard](../plane/switchboard.md), received over a channel
it already holds, or created for itself with the ungated
`mac_capability_channel_create(2)` syscall, which returns a self-owned
endpoint pair with no service behind it and no authority attached. That
syscall is `CAPENABLED` and is how a process obtains the private lookup
channel described in [Discovery and the Lookup
Channel](../plane/discovery-and-lookup.md).

## Identity: the process nonce

Every credential carries a 64-bit nonce, generated with `arc4random_buf()`
and stored in a MAC label slot on `struct ucred`. It is inherited on
`fork()` (the child is the same program) and rotated on `execve()` (a new
image is a new principal) through the `mpo_vnode_execve_relabel` hook that
5BSD added to the MAC framework. Zero is never a valid nonce and userspace
cannot set one. The nonce is the subject of every capability policy:
isolation claims, system gates and shields are keyed to it. A process
learns its own nonce from the `identity` service (`IDENTITY_OP_SELF`) or a
child's with `IDENTITY_OP_QUERY` and an attached process descriptor; a
receiver learns its peer's from the credential trailer on every message.

Fork and exec are treated differently on purpose. A provider's workers
share their program's identity and therefore its claims; a program that
execs foreign code does not carry that authority into it. Descriptor
propagation composes with this: a descriptor locked close-on-fork never
reaches a child, one locked close-on-exec never reaches a new image, so a
supervisor can let exactly one bootstrap channel cross exactly one exec
into a program that then runs under a fresh identity.

## Descriptors, instances and badges

`MAC_CAPABILITY_CONNECT` on the device returns an instance descriptor. An
instance is one connection to one service; `dup(2)` shares it, `fork(2)`
inherits it, a message or `SCM_RIGHTS` can pass it unless the transfer
state forbids. Last close is a full teardown: queues drain, the service's
`co_revoke` fires once, and any peer sees `ECONNRESET`.

When a service accepts a connection its `co_connect` callback may assign a
badge, a 64-bit value stamped on every inbound message from that instance.
The badge is how a kernel service, or a userspace provider on the far end of
a channel, tells its clients apart without trusting anything they send.
`MAC_CAPABILITY_GETINFO` reports it, and procstat(1) shows a descriptor as
`mac_capability:service[badge]` with state suffixes such as `:no-send`,
`:no-call` or `:revoked`.

Every message received, and every synchronous call, carries a kernel-stamped
credential trailer (`struct mac_capability_cred_trailer`, 24 bytes):

| Field | Meaning |
|---|---|
| `uid`, `gid` | sender's effective credentials at send time |
| `prison_id` | sender's jail |
| `abi` | sender's syscall ABI: 9 native, 3 Linux, 0 kernel-originated or unknown; informational only |
| `nonce` | sender's program nonce |

A receiver never trusts wire data for who is speaking; it reads the trailer.

## The ioctl surface

All traffic is structured ioctls; `read(2)` and `write(2)` are refused. The
commands are in `sys/dev/mac_capability/mac_capability_ioctl.h` (group `'Y'`).

| Command | Direction | Effect |
|---|---|---|
| `MAC_CAPABILITY_CONNECT` | device fd | connect to a named service, return an instance fd |
| `MAC_CAPABILITY_SENDMSG` | instance | enqueue an async message with up to 32 fds and a reply token; `EAGAIN` when the queue is full |
| `MAC_CAPABILITY_RECVMSG` | instance | dequeue a reply or notification with its fds, badge, token and trailer; blocks unless `O_NONBLOCK` |
| `MAC_CAPABILITY_CALL` | instance | synchronous request and reply in the caller's thread; `EMSGSIZE` with the needed size if the reply buffer is short |
| `MAC_CAPABILITY_GETINFO` | instance | service name, badge, message limit, queue depth, TX limit, max fds, feature flags |
| `MAC_CAPABILITY_REVOKE_SEND` / `_RECV` / `_CALL` / `_MINT` | instance | one-way latches; a stripped operation later fails with `EACCES` |
| `MAC_CAPABILITY_TERMINATE` | instance | kill the instance for every holder; later operations return `ECONNRESET` |
| `MAC_CAPABILITY_MINT_INSTANCE` | instance | new instance of the same service, only for services registered `MAC_CAPABILITY_SVC_MINTABLE`; the service's `co_connect` authorizes it |

Fixed limits: 64-byte service names, 32 attached descriptors per message,
14336 bytes of payload (messages are 16384 bytes with a 2048-byte framework
header), 256 messages per async queue by default and 4096 at most, 1024
instances per service by default. Sync-only services allocate no queues.
`MAC_CAPABILITY_GETINFO` feature bits tell a client which of `SENDMSG`,
`RECVMSG`, `CALL` and kqueue readiness a service offers; libchannel refuses
a descriptor without all three async bits.

Capsicum applies to all of it. `CAP_IOCTL` permits ioctl use, and
`cap_ioctls_limit(2)` narrows an instance to an allowlist of commands, so a
send-only capability is `CAP_IOCTL` plus `{MAC_CAPABILITY_SENDMSG}`. The
introspection and narrowing commands are not exempt: `GETINFO`, the
`REVOKE_*` latches and `TERMINATE` must be in the allowlist if one is
installed.

## Two messaging models

A service implements `co_call`, `co_handler`, or both. `MAC_CAPABILITY_CALL`
runs `co_call` in the calling thread: the handler is the calling process,
so it can attach to a jail, change credentials or install descriptors in
the caller's table, and reply descriptors come back in the same ioctl. The
identity, capprotect, isolation, system, node, accounting and mount
services are call-only. `MAC_CAPABILITY_SENDMSG` enqueues a message on the
instance's RX queue; a per-service taskqueue runs `co_handler` one message at
a time per instance; the handler answers with `mac_capability_reply()`,
which lands on the TX queue for `MAC_CAPABILITY_RECVMSG`. kqueue maps onto
those queues: `EVFILT_READ` means `RECVMSG` will make progress, `EVFILT_WRITE`
means `SENDMSG` has space, `EV_EOF` means the instance was revoked.

A service registered with `MAC_CAPABILITY_SVC_NOTIFY` may also push
unsolicited messages with `mac_capability_notify()`; they arrive through
`RECVMSG` with a zero reply token, and kqueue reports readiness, not the
payload. The coalition service uses this for member-added, terminated,
leader-died and watchdog-fired events.

## Channels

The `channel` service turns the framework into process-to-process IPC. A
holder connects to `channel` (endpoint A), sends `CHANNEL_OP_CREATE`, and
receives endpoint B as an attached descriptor in the reply. From then on a
message sent on either end is forwarded to the other by
`mac_capability_forward()`, which preserves the payload, attached
descriptors, badge, reply token and credential trailer of the original
sender; forwarding is fire-and-forget at the kernel level. Closing or
revoking one end delivers `ECONNRESET` to the other. Because the service is
mintable, a holder can mint further unconnected instances from one it
holds. `mac_capability_channel_create(2)` produces the same kind of pair
without touching the service by name.

Two properties make a channel a security substrate and not a pipe. Every
message carries the kernel-stamped trailer and badge, so a provider keys
policy on who is speaking without parsing a claim. And descriptors ride
inside messages under the same rights and transfer discipline as anywhere
else: the receiver gets the sender's rights intersected with any
`cap_xfer_rights_limit(2)` ceiling, and a `CAP_XFER_ONCE` descriptor is
exhausted by the send. Every typed service protocol in
[Part IV](../providers/overview.md) runs over a channel obtained through the
lookup channel.

## Narrowing, transfer and propagation

Rights only shrink. Five mechanisms compose, and every one starts
unrestricted so unmodified software behaves as before:

| Mechanism | What it bounds |
|---|---|
| `cap_rights_limit(2)`, `cap_ioctls_limit(2)` | which operations the holder may perform (standard Capsicum) |
| `MAC_CAPABILITY_REVOKE_*` | which messaging operations the instance still accepts |
| `cap_xfer_limit(2)`: `UNLIMITED`, `ONCE`, `NONE` | whether, and how many more times, the descriptor may leave this process |
| `cap_xfer_rights_limit(2)`, `_ioctls_`, `_fcntls_` | the authority the receiver gets after a permitted transfer; the sender keeps its own |
| `cap_cloexec_limit(2)`, `cap_clofork_limit(2)`: `UNLOCKED`, `ONCE`, `LOCKED` | whether the descriptor survives exec or fork, enforced regardless of `FD_CLOEXEC`/`FD_CLOFORK` |

A one-hop send is consumed by the transfer: after it both copies are
`CAP_XFER_NONE`, so a multi-hop delegation exists only if each hop
deliberately re-grants it. This is how the minted login session channel
arrives non-transferable, and how switchboard hands a unit a bootstrap
channel that survives exactly one exec. The full semantics, error codes and
call sites are in [Descriptor and Process
Protections](descriptor-protections.md).

## A synchronous call, and a channel round trip

The synchronous path is wrapped by libcapability(3). Given an `identity`
instance the process holds, asking for its own nonce is one call:

```c
#include <capability.h>
#include <dev/mac_capability/mac_capability_identity_proto.h>

struct identity_request req = { .op = IDENTITY_OP_SELF };
struct identity_reply rep;

if (capability_service_call(idfd, &req, sizeof(req), &rep, sizeof(rep)) == -1)
	err(1, "identity");
if (rep.status != IDENTITY_STATUS_OK)
	errx(1, "identity: status %u", rep.status);
printf("nonce %#jx\n", (uintmax_t)rep.nonce);
```

`capability_service_call()` issues `MAC_CAPABILITY_CALL` and insists the
reply is exactly the size asked for; the `_fds` variant passes and receives
descriptors, and `capability_kernel_call()` is the loose form. The kernel
fills the trailer on the way back, so the reply is attributable.

libchannel(3) deliberately does not expose `CALL`. It is the nonblocking,
event-loop form of the same request and reply idea over `SENDMSG` and
`RECVMSG`, used by every provider and client in the plane. A client sends a
request with a fresh correlation token and a completion handler; the
provider receives it, reads the kernel-stamped sender, and answers with
`channel_send_reply()`, which reuses the request's token:

```c
/* client side: fd is a channel endpoint delivered to this process */
struct channel_options opts = CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
struct channel *ch;
struct channel_outgoing out = CHANNEL_OUTGOING_INITIALIZER(&req, sizeof(req));
struct channel_request *pending;

if (channel_create(fd, &opts, &ch) == -1)		/* consumes fd */
	err(1, "channel_create");
if (channel_send_request(ch, &out, on_reply, ctx, &pending) == -1)
	err(1, "send_request");
/* event loop: EVFILT_READ on channel_fd(ch); EVFILT_WRITE while
 * channel_wants_write(ch); then channel_dispatch(ch) and channel_flush(ch). */

static void
on_reply(struct channel_request *r, struct channel_message *reply, int error, void *ctx)
{
	if (reply == NULL) {			/* peer died, cancelled, or error */
		warnc(error, "request failed");
		return;
	}
	const struct channel_sender *who = channel_message_sender(reply);
	/* who->nonce, who->badge, who->uid: stamped by the kernel */
	handle(channel_message_data(reply), channel_message_length(reply));
	channel_message_free(reply);
}

/* provider side */
static void
on_request(struct channel *ch, struct channel_message *request, void *ctx)
{
	const struct channel_sender *who = channel_message_sender(request);
	struct channel_outgoing rep = CHANNEL_OUTGOING_INITIALIZER(&answer, sizeof(answer));

	if (!policy_allows(who->badge, who->nonce))
		answer.status = EPERM;
	channel_send_reply(request, &rep);		/* reuses request's token */
	channel_message_free(request);
}
```

The roles are directional: a `CHANNEL_ROLE_CLIENT` originates requests and
discards unmatched replies as stale; a `CHANNEL_ROLE_PROVIDER` answers
nonzero-token requests and may not originate them. Either side may send
token-zero events. Peer death completes every outstanding request with an
error, and a handler that wants a blocking wait instead of an event loop
can call `channel_wait()`, which is kqueue-based because channels do not
support poll(2) or select(2). Attached descriptors arrive owned by the
message; `channel_message_take_fd()` moves one to the caller and the rest
are closed on free.

## The kernel API for service authors

A service is a `struct mac_capability_ops` (`co_connect`, `co_init`,
`co_handler`, `co_call`, `co_revoke`, `co_fdclose`, `co_txdrain`) registered
with `mac_capability_service_create()` and torn down with
`mac_capability_service_destroy()`. The framework owns the descriptor:
services never touch `falloc`, `finit` or `fileops`. From a handler the
service uses `mac_capability_reply()`, `mac_capability_notify()`,
`mac_capability_forward()`, `mac_capability_mint_fp()` (mint a new instance
and return it as a reply descriptor), the message accessors
`mac_capability_msg_{data,datalen,fds,fcaps,nfds,badge,token,cred}()`, the
instance helpers `mac_capability_instance_{revoke,hold,rele,kick,set_priv,get_priv,get_badge}()`,
and `mac_capability_proc_nonce(cred)`. A handler may return
`MAC_CAPABILITY_HANDLER_RETRY` to leave a message at the head of its queue
and kick it later, which is how bounded bearer services apply backpressure.
`mac_capability_instance_revoke()` must not be called from inside
`co_call`. The full contract is in `sys/dev/mac_capability/mac_capability.h`
and the design guide `docs/mac_capability-architecture.md`; a kernel
extension that adds a service is walked through in
[A Kernel Extension](../develop/kernel-extension.md).

## Observing it

Sysctls: `kern.mac_capability.services`, `.instances`, `.service_names` and
`.service_details` (flags, queue depth, TX limit, instance limit, live count
per service). Each policy service adds its own node
(`kern.mac_capability_capprotect.max_auth`, `kern.mac_capability_system.max_auth`,
`kern.mac_capability_isolation.{enforce,max_auth}`,
`kern.mac_capability_coalition.{max,max_members,count,members}`); see
[Policy Points](policy-points.md) for what each decides.

DTrace providers, one per module:

| Provider | Probes |
|---|---|
| `mac_capability` | connect, send, recv, dispatch, reply, notify, call, forward, revoke (each with `-done`), close, fd-install/close/receive/mint, control, ioctl-deny, rights-change, state, error, instance-create/finalize/lastclose, service-create/destroy, queue-pressure |
| `mac_capability_nonce` | assign, copy, exec-rotate, backfill |
| `mac_capability_isolation`, `_capprotect`, `_system` | deny, allow, state (plus per-class deny/allow and token-narrow for isolation) |
| `mac_capability_coalition` | create, enlist, join, terminate, close, member-exit, leader-exit, fork-inherit, deadline and watchdog events, call-done, deny |
| `mac_capability_channel` | create, forward, handler-done, state |
| `mac_capability_node`, `mac_capability_acct`, `mac_capability_mount` | call-done or state, deny |

The descriptor layer has its own providers in `sys/kern`: `capsicum`
(rights, ioctl and fcntl limits, checks, denials), `fd` (install, dup,
close, fork inheritance, `SCM_RIGHTS` send and receive, pass-deny) and
`envfd`. Ready-made scripts live in `/usr/share/dtrace`:
`mac_capability-{audit,calls,coalitions,delegation,denials,errors,fds,holders,messages,nonces,services,shield,summary,who}`,
`capsicum-{changes,denials,xfer}`, `capflow`, `capwatch`, `fdpass`,
`envfd-events` and `procdesc-lifecycle`. See
[Observability](../operations/observability.md).

## Tests and status

`tests/sys/mac_capability/` holds one ATF program per service plus the core
`mac_capability_test.c`; `run_tests.sh` runs them on a plane-free boot
(`capability_plane="NO"`, see [Boot Knobs](../operations/boot-knobs.md)),
because a live plane has already claimed the device. The channel syscall,
transfer states and confinement flags are tested under `tests/sys/kern/`.

Status: shipped and mandatory-static since 1cfe04dcaf39. The framework
provides no kernel-to-kernel capability communication and no naming
registrar of its own; naming is switchboard's job. The SYNOPSIS of several
per-service man pages still shows a `_load="YES"` loader.conf line from
before the modules were made static; the line is inert.
