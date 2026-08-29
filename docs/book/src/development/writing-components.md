# Writing a Service Provider

A 5BSD service provider is a userland program built around one or more kernel
capability services.  The services live under `sys/dev/mac_capability/` as
loadable modules and are reached through file descriptors: a process opens
`/dev/mac_capability`, connects to a service by name, and receives an
*instance fd* that carries every subsequent operation.  This chapter walks
through the ISOLATION service, which lets a supervisor claim exclusive
ownership of files, sockets, network endpoints, vsock endpoints, and jails.

## Obtaining a mac_capability connection

There are two paths, and which one a program uses is a design decision, not a
convenience choice.

**Managed providers never open `/dev/mac_capability`.**  `authorityd(8)` claims
the device node itself at boot (`usr.sbin/authorityd/mac_capability_claims.c`
always claims `/dev/mac_capability`), so a foreign-nonce open is denied by the
MACF hooks.  A provider managed by `serviced(8)` instead receives its
capability descriptors by *session injection*: `serviced` delivers narrowed
access tokens and capability descriptors in the bootstrap that accompanies the
inherited pair fd, and the provider activates them through `libservice`:

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

This is the exact startup sequence of the `networkcmp` peer provider daemon
(`usr.sbin/localnetwork/networkcmp.c`), a managed service reached lazily by its
consumers through `service_connect()`.
`service_provider_authorize_capabilities()` walks every bootstrap token,
verifies with `capability_get_info()` (from `libcapability`) that it names the
`isolation` or `system` service, and activates each one — issuing
`FI_OP_AUTHORIZE` on isolation tokens on the provider's behalf.  Descriptors
for manifest-declared capability services (`"mount"`, `"node"`,
`"accounting"`, `"identity"`) are opened with
`service_capability_open(ctx, name, expected_type, &fd)`.

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
length-checking shim over it):

```c
#include <capability.h>	/* libcapability, -lcapability */

size_t rlen = sizeof(reply), rnfds = 0;
if (capability_kernel_call(svc, &req, sizeof(req), NULL, 0,
    &reply, &rlen, NULL, &rnfds) == -1)
	err(1, "isolation call");
```

The request structures come from the shared wire-protocol header
`dev/mac_capability/mac_capability_isolation_proto.h`; there is no
higher-level claim API, so the examples below build the protocol structs
directly and pass them through `capability_kernel_call()`.

## Claiming resources

Every claim is keyed to the caller's *nonce* — the kernel-stamped program
identity that is inherited across `fork()` and rotates on `exec()` — and is
owned by the instance fd.  Closing the instance releases every claim it owns.

### File or directory

Vnode claims pass the target as an attached fd (`req_fds[0]`); the actions
mask is ignored for `FI_OP_CLAIM` and required for `FI_OP_QUERY`:

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

req.op = FI_OP_QUERY;
req.actions = FI_FS_ALL;	/* QUERY requires a valid mask */
/* ... same call shape; reply.flags == FI_QF_CLAIMED | FI_QF_MINE */
```

Claiming a directory gates lookups *into* it, so one claim protects an entire
subtree from foreign eyes.  Claiming an fd with no vnode (a pipe) fails with
`EINVAL`.

### Unix domain socket

A bound Unix socket is a vnode, so the same `FI_OP_CLAIM` applies; open the
socket path with `O_PATH` to get a claimable fd.  The gated operation is
`connect(2)` (`bind` creates a new vnode and cannot be gated):

```c
int target = open("/var/run/component.sock", O_PATH);
struct fi_request req = { .op = FI_OP_CLAIM };
/* attach target as req_fds[0], as above */
```

### Network endpoint

Network claims carry the endpoint in the payload — no fd.  Ports are network
byte order; a `0..65535` range, domain/protocol `0`, and an all-zero address
are wildcards.  IPv4 addresses go in `addr[]` v4-mapped:

```c
struct fi_net_request nr = {
	.op = FI_OP_CLAIM_NET,
	.domain = AF_INET,
	.protocol = IPPROTO_TCP,
	.port_min = htons(8443),
	.port_max = htons(8443),
	.direction = FI_NET_BIND,	/* or FI_NET_CONNECT, FI_NET_ANY */
};
```

AF_BLUETOOTH endpoints use the same struct with `BLUETOOTH_PROTO_*` protocols,
the BD_ADDR in `addr[0..5]`, and prefix `0` (any) or `48` (exact).

### vsock endpoint

vsock claims use their own request: 32-bit ports in **host** byte order and a
CID (`VSOCK_CID_ANY` or specific).  A claim covers both `SOCK_STREAM` and
`SOCK_SEQPACKET`:

```c
struct fi_vsock_request vr = {
	.op = FI_OP_CLAIM_VSOCK,
	.cid = 3,
	.port_min = 18000,
	.port_max = 18010,
	.direction = FI_NET_CONNECT,
};
```

`FI_VSOCK_PROVIDER` in `direction` additionally authorizes a `/dev/vsock`
transport provider; it is only valid for a claim covering every port of one
concrete CID.

### Jail

Jail claims are keyed by JID, name, or both (a claim naming both protects
either identifier for the same jail), and carry an `FI_JAIL_*` actions mask:

```c
struct fi_jail_request jr = {
	.op = FI_OP_CLAIM_JAIL,
	.jid = 0,			/* 0 = no JID key */
	.actions = FI_JAIL_ALL,		/* CREATE|GET|SET|REMOVE|ATTACH */
};
strlcpy(jr.name, "component-cell", sizeof(jr.name));
```

## Minting and activating access tokens

A claim owner grants selective access to another program by minting a *token
fd* narrowed to an `FI_FS_*` / `FI_NET_*` / `FI_JAIL_*` action mask, passing
it to the peer, and letting the peer activate it.  Vnode tokens
(`FI_OP_MINT`) attach the target fd; network, vsock, and jail tokens
(`FI_OP_MINT_NET`, `FI_OP_MINT_VSOCK`, `FI_OP_MINT_JAIL`) describe the
endpoint in the payload.  The token comes back as a reply fd:

```c
struct fi_request req = { .op = FI_OP_MINT,
    .actions = FI_FS_READ | FI_FS_LOOKUP | FI_FS_STAT };
int token = -1;
size_t rlen = sizeof(reply), rnfds = 1;
capability_kernel_call(svc, &req, sizeof(req), &target, 1,
    &reply, &rlen, &token, &rnfds);
```

The receiver — typically after `exec`, so under a different nonce — activates
the token by calling `FI_OP_AUTHORIZE` **on the token fd itself**:

```c
struct fi_request req = { .op = FI_OP_AUTHORIZE };
size_t rlen = sizeof(reply), rnfds = 0;
capability_kernel_call(token, &req, sizeof(req), NULL, 0,
    &reply, &rlen, NULL, &rnfds);
```

Authorization is a descriptor lease: it adds the caller's nonce to the
claim's authorized set for exactly as long as the token fd stays open.
Closing the token revokes it.  Managed providers never do this by hand —
`service_authorize_capabilities()` activates every injected token, and
`libservice` retains private close-on-exec references so a later program
image cannot reactivate them under a rotated nonce.

## What enforcement looks like

The isolation service registers MACF hooks for every gated vnode operation.
Each hook consults the claim table: no entry allows (default-open), a nonce
match allows, an authorized token-holder nonce allows, and everything else
fails with `EACCES`.  For a claimed file, a foreign-nonce process cannot
`open`, `exec`, `stat`, `access`, or `readlink` it; cannot `unlink`, `link`,
or `rename` it; cannot `chmod`, `chown`, `chflags`, `utimes`, or `truncate`
it; and cannot `connect(2)` to it if it is a Unix socket.  Network and vsock
claims gate `bind()` and `connect()` per the claim's direction mask, and jail
claims gate the `jail_set`/`jail_get`/`jail_attach`/`jail_remove` family per
the actions mask.

Two lifecycle rules matter in practice.  First, `exec()` rotates the nonce:
a supervisor that claims and then re-executes loses same-nonce access, though
an instance fd kept open across exec still holds the claim.  Second, closing
the claiming instance fd releases all of its claims, so orphaned supervisors
cannot leave resources permanently wedged.  Re-claiming the same resource
from the same nonce transfers ownership to the newest instance.

The canonical, exhaustively-tested call sequences for every operation above
are in `tests/sys/mac_capability/mac_capability_isolation_test.c`, and
`authorityd`'s claim path (`usr.sbin/authorityd/mac_capability_claims.c` with the
`claims` section of `authorityd.conf(5)`) is the production reference for a
claiming supervisor.
