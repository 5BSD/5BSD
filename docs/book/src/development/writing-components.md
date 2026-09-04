# Writing a Service Provider

[The Hybrid Model](hybrid-model.md) built a capability end to end; this
chapter is the deep dive underneath it — the raw kernel services a provider
sits on, the ISOLATION claim model, access tokens, and process hardening. The
kernel services are loadable modules reached through file descriptors: a
process opens `/dev/mac_capability`,
connects to a service by name, and receives an *instance fd* that carries
every subsequent operation.

## Obtaining a mac_capability connection

There are two paths, and which one a program uses is a design decision, not a
convenience choice.

**Managed providers never open `/dev/mac_capability`.**  `authorityd(8)` claims
the device node itself at boot, so a foreign-nonce open is denied by the
MACF hooks.  A provider managed by `serviced(8)` never opens the device either. It is
launched with an unforgeable service channel and acquires any capability it
needs on demand, by name, scoped to its channel label — `serviced` mints and
delivers nothing at launch. Its startup sequence through `libservice` is:

```c
#include <libservice.h>

struct service_provider *provider;
struct service_listener *listener;

if (service_provider_create(&provider) == -1 ||
    service_provider_authorize_capabilities(provider) == -1 ||
    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
    service_provider_expose(provider, LOCALNETWORK_NAME, &listener) == -1 ||
    service_provider_enter_capability_mode(provider) == -1 ||
    service_provider_ready(provider) == -1)
	err(1, "bootstrap");
```

This is the exact startup sequence of the in-tree managed providers, each
reached lazily by its consumers through `service_connect()`.
`service_provider_authorize_capabilities()` completes the provider's own
capability-mode hardening; it does not walk a bundle-minted token set, because
a unit declares no capabilities in its manifest and `serviced` delivers none at
launch.  Whatever the provider needs — a filesystem path or device, mutable
storage, a namespace, a kernel module, a vsock endpoint — it acquires at
runtime, by name, over its own unforgeable channel through the
`service_*(3)` acquisition calls in `libservice(3)`, each grant scoped to
the channel label rather than handed over in a launch bootstrap.

**Supervisors connect directly.**  `authorityd(8)` and `serviced(8)` run as root
before any claims exist, open the device, and connect by service name.  This
is the pattern to copy for a new supervisor-level provider:

```c
#include <sys/ioctl.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

static int
isolation_connect(void)
{
	struct mac_capability_connect_args ca;
	int ctl;

	ctl = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (ctl == -1)
		return (-1);
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "isolation", sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) == -1) {
		close(ctl);
		return (-1);
	}
	close(ctl);
	return (ca.fd);		/* the instance fd */
}
```

There is no library wrapper for `MAC_CAPABILITY_CONNECT`; every in-tree
consumer issues this ioctl directly.  Calls on the instance fd, however,
should go through `libcapability`'s `capability_kernel_call()` rather than a
hand-rolled `MAC_CAPABILITY_CALL` ioctl — this is what `authorityd` does
(`mac_capability_do_call()` in `mac_capability_setup.c` is a thin
length-checking shim over it).  The request structures come from the shared
wire-protocol header `dev/mac_capability/mac_capability_isolation_proto.h`;
there is no higher-level claim API.

## Claiming resources

The ISOLATION service lets a supervisor claim network endpoints, vsock
endpoints, and jails as *exclusive* isolations (one owner system-wide), and
files and paths as *non-exclusive*, reference-counted access grants.  Every
claim is keyed to the caller's *nonce* — the kernel-stamped program identity
that is inherited across `fork()` and rotates on `exec()` — and is owned by
the instance fd.  Closing the instance releases every claim it owns.

A vnode claim passes the target as an attached fd; the actions mask is
ignored for `FI_OP_CLAIM` and required for `FI_OP_QUERY`:

```c
#include <dev/mac_capability/mac_capability_isolation_proto.h>

struct fi_request req = { .op = FI_OP_CLAIM };
struct fi_reply reply;
size_t rlen = sizeof(reply), rnfds = 0;
int target = open("/var/db/component/secrets", O_RDONLY | O_CLOEXEC);

if (capability_kernel_call(svc, &req, sizeof(req), &target, 1,
    &reply, &rlen, NULL, &rnfds) == -1)
	err(1, "claim");
close(target);		/* the claim holds its own vnode reference */
```

Claiming a directory gates lookups *into* it, so one claim protects an entire
subtree from foreign eyes.  The other claim types — Unix sockets, network
endpoints, vsock endpoints, and jails — follow the same call shape with
their own request structs and action masks; the wire-protocol header is the
authoritative list.

## Minting and activating access tokens

A claim owner grants selective access to another program by minting a *token
fd* narrowed to an `FI_FS_*` / `FI_NET_*` / `FI_JAIL_*` action mask, passing
it to the peer, and letting the peer activate it.  Vnode tokens
(`FI_OP_MINT`) attach the target fd; `FI_OP_MINT_NET`, `FI_OP_MINT_VSOCK`,
and `FI_OP_MINT_JAIL` describe the endpoint in the payload.  The token comes
back as a reply fd, and the receiver — typically after `exec`, so under a
different nonce — activates it by calling `FI_OP_AUTHORIZE` **on the token fd
itself**:

```c
/* Owner mints: */
struct fi_request req = { .op = FI_OP_MINT,
    .actions = FI_FS_READ | FI_FS_LOOKUP | FI_FS_STAT };
int token = -1;
size_t rlen = sizeof(reply), rnfds = 1;
capability_kernel_call(svc, &req, sizeof(req), &target, 1,
    &reply, &rlen, &token, &rnfds);

/* Receiver activates, on the token fd: */
struct fi_request auth = { .op = FI_OP_AUTHORIZE };
rnfds = 0;
capability_kernel_call(token, &auth, sizeof(auth), NULL, 0,
    &reply, &rlen, NULL, &rnfds);
```

Authorization is a descriptor lease: it adds the caller's nonce to the
claim's authorized set for exactly as long as the token fd stays open.
Closing the token revokes it.  Managed providers rarely do this by hand — when
a provider acquires a capability at runtime by name, `libservice` activates the
returned token and retains private close-on-exec references so a later program
image cannot reactivate it under a rotated nonce.

## What enforcement looks like

The isolation service registers MACF hooks for every gated operation.  Each
hook consults the claim table: no entry allows (default-open), a nonce match
allows, an authorized token-holder nonce allows, and everything else fails
with `EACCES`.  For a claimed file, a foreign-nonce process cannot open,
exec, stat, unlink, rename, chmod, or otherwise touch it; network and vsock
claims gate `bind()`/`connect()` per the direction mask, and jail claims gate
the `jail_set`/`jail_get`/`jail_attach`/`jail_remove` family per the actions
mask.

Two lifecycle rules matter in practice.  First, `exec()` rotates the nonce:
a supervisor that claims and then re-executes loses same-nonce access, though
an instance fd kept open across exec still holds the claim.  Second, closing
the claiming instance fd releases all of its claims, so orphaned supervisors
cannot leave resources permanently wedged.

`authorityd`'s claim path, configured by the `claims` section of
`authorityd.conf(5)`, is the production reference for a claiming supervisor.

## Hardening the process

Beyond isolation claims, a provider hardens itself with three more capability
services and the Capsicum descriptor-narrowing extensions.

**capprotect** shields a program (per nonce, so `fork()` children are covered
and `exec()` sheds the shield) against outside interference and optionally
restricts what it can do to itself.  Managed components use the `libservice`
wrappers — a provider shields itself during bootstrap and a forked worker
shields itself before `cap_enter()`:

```c
service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC);
/* ... in the pdfork'd worker: */
service_worker_protect(SERVICE_PROTECT_EXTERNAL | SERVICE_PROTECT_NOPRIVS |
    SERVICE_PROTECT_NOFORK | SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOEXEC);
service_worker_drop_inherited_authority();
cap_enter();
```

(The in-tree providers do exactly this, some with stricter flag sets.)
A supervisor-level program drives the `"capprotect"` service directly with
`CP_OP_SHIELD`: protect-class flags block external interference —
invisibility to `ps`, foreign-nonce `ptrace` denial, signal immunity
including root's SIGKILL — and restrict-class flags limit the process
itself; the full flag set is in the capprotect wire-protocol header.  Flags
are refcounted per shield fd; each close removes only that fd's
contribution.  A shield owner can mint and hand out tokens exactly as
ISOLATION does.  A held process descriptor bypasses the signal shields —
`pdkill(2)` is capability authority in its own right.

**coalition** provides lifecycle containment: connecting to `"coalition"`
creates a resource group whose lifetime is the instance fd.  Process
descriptors, sockets, other instance fds, jail descriptors, and nested
coalitions are enlisted by attaching them (`COALITION_OP_ENLIST`); deadlines,
watchdogs, and `COALITION_OP_TERMINATE` deliver a configured signal to every
member and revoke enlisted capability instances, so a wedged worker cannot
keep kernel services alive.  Managed components rarely drive it directly —
they return their worker to `serviced` with
`service_component_complete(bootstrap, SERVICE_COMPONENT_MEMBER_PROCDESC, pd)`
and let the framework own containment.

**channel** is the message-passing transport under every `libservice`
session; `libchannel` (`channel.h`, `-lchannel`) is the high-level API.  A
provider drives its channels from a kqueue loop (channels are kqueue-only),
takes ownership of received descriptors with `channel_message_take_fd()`,
answers with `channel_send_reply()`, and treats peer death as a normal
completion path — every outstanding request fails, and `channel_error()`
returns the stable terminal errno.  After `fork()`, the child calls
`channel_abandon()`: channel fds are locked close-on-fork, so the child owns
bookkeeping but no live transport.

**Descriptor narrowing.**  5BSD extends Capsicum with transfer and
inheritance limits (`sys/capsicum.h`): `cap_xfer_limit()` bounds how many
times a descriptor may be passed (`CAP_XFER_NONE`, `CAP_XFER_ONCE`), and
`cap_cloexec_limit()`/`cap_clofork_limit()` monotonically lock close-on-exec
and close-on-fork.  Combined with classic `cap_rights_limit()` and
`cap_ioctls_limit()`, they produce descriptors whose authority cannot grow
back:

```c
cap_rights_t rights;
cap_rights_init(&rights, CAP_WRITE);		/* send-only */
cap_rights_limit(fd, &rights);
cap_ioctls_limit(fd, NULL, 0);			/* no ioctls at all */
cap_xfer_limit(fd, CAP_XFER_NONE);		/* never SCM_RIGHTS-passable */
cap_clofork_limit(fd, CAP_CLOFORK_ONCE);	/* one child inherits, then locked */
cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED);	/* never survives exec */
```

This is the production pattern: the in-tree providers apply it to every
descriptor destined for a `pdfork()`ed worker, and
`service_provider_worker_channel()` locks one endpoint of the pair into the
parent and lets the other cross into exactly one child.  For transferable
descriptors, `cap_xfer_rights_limit()`,
`cap_xfer_ioctls_limit()`, and `cap_xfer_fcntls_limit()` cap the authority
the *receiver* obtains without weakening the sender.  All limits are
monotonic — apply them just before the `fork()`/send, and the recipient can
narrow further but never widen.
