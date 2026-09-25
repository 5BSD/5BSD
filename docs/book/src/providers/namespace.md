# system.Namespace (BSDNamespace)

## What it brokers

BSDNamespace is the jail broker. It creates jails through the kernel's
`jail` system gate on behalf of programs that want to confine themselves, and
it hands back a jail descriptor whose stored credential lets a non-root
process attach. 5BSD has it because jail construction used to live in PID 1
and in root-only tooling; on the plane a jail is consumer self-service,
scoped by the caller's unforgeable channel label, and neither switchboard
nor a manifest ever declares one. jail(8) and the rc-driven jail world keep
working unchanged; that side is covered in [Jails](../compat/jails.md).

A program that decides to confine itself calls
`service_enter_namespace(3)`. libservice opens `system.Namespace` over the
process's private lookup channel (pulling BSDNamespace up on demand), sends
the jail's shape (root path, optional hostname, IPv4 and IPv6 addresses, and
flags), receives one SCM descriptor, calls jail_attach_jd(2) on it, and
closes it. The descriptor is a non-owning jail descriptor (jail(2)
`JAIL_GET_DESC`, implemented in `sys/kern/kern_jaildesc.c`); the credential
stored inside it is BSDNamespace's, which is what authorizes the attach.
Closing it never removes the jail. See jail(2) for `jail_attach_jd` and the
`JAIL_USE_DESC`, `JAIL_GET_DESC` and `JAIL_OWN_DESC` flags.

BSDNamespace never takes a jail name or id from the wire. It derives one
jail name per client label, `wj_` followed by the hex SHA-256 of the label
(`jail_name_from_label()` in `usr.sbin/BSDNamespace/bsdnamespace.c`), so a
label owns at most one jail, a consumer can only ever name its own, and a
relaunched consumer reattaches to the same jail deterministically. Because
self-jailing only narrows the caller, no per-caller token is needed; the
label is the authority.
The daemon is born in capability mode as the `capability` user. jail_set(2)
needs `PRIV_JAIL_SET` and resolves the root path in the global namespace,
both forbidden in the sandbox, so every create, get and remove goes through
the held `SYS_GATE_JAIL` token: `service_system_jail_set(3)` and
`service_system_jail_get(3)` enter `kern_jail_set_gated()` and
`kern_jail_get()` in `sys/kern/kern_jail.c`, where the held claim replaces
the privilege and the root-path namei runs in kernel context. See
[System Gates](../capability/system-gates.md). Clients are served on threads
rather than pdfork workers so the single close-on-fork gate token is shared.

Two lifetimes exist. A persistent jail (flags 0) is created `persist=1`,
reused by label across restarts, and outlives any one consumer; it is
reclaimed with its bundle through the container model, using an owner map
in BSDNamespace's own storage container and the delivered `/Capabilities`
directories, on the timer set by `BSDNAMESPACE_RECLAIM_INTERVAL`. An
ephemeral jail (`BSDNAMESPACE_F_EPHEMERAL`) is anchored by a separate owning
descriptor (`JAIL_OWN_DESC`) that the per-client worker retains; when the
consumer disconnects the anchor drops and the jail is torn down. If the
owning descriptor cannot be acquired, the request fails and the newly
created jail is removed rather than leaked.

## Unit

Source: `usr.sbin/BSDNamespace/capbundle/Bundle.ucl` and
`capbundle/bsdnamespace.ucl` (installed as `Unit.ucl`).

| Field | Value |
|---|---|
| Wire name | `system.Namespace` |
| Bundle | `/Capabilities/System/Namespace.cap` (bundle_id `system.Namespace`) |
| Unit | `Units/bsdnamespace.unit` |
| Program | `Units/bsdnamespace.unit/bin/BSDNamespace` |
| Activation | `ipc = ["system.Namespace"]` (on demand; no boot activation) |
| User | `capability` |
| Launch mode | born in capability mode (`ambient` absent) |
| Declared gates | `capabilities { system = ["jail"] }` |
| Delivered directories | `/Capabilities/System`, `/Capabilities/Apps`, `/Capabilities/Run/live` |
| Control | `system` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 1024`, `nproc = 128`, `core = 0`; `umask = "0022"` |
| Environment | `BSDNAMESPACE_RECLAIM_INTERVAL` (10 to 86400 s, default 300) |

No `visible` key: the name resolves for SYSTEM-domain clients only.

## Wire operations

Protocol header: `lib/libcapsulert/bsdnamespace_proto.h`. No HELLO and no
version field; the request struct and the reply length carry the framing.
Every string field must be NUL-terminated and `path` must be absolute.

| Op | Request | Reply | Errors |
|---|---|---|---|
| `BSDNAMESPACE_OP_ENTER_JAIL` (1) | `bsdnamespace_request { op, flags, path[PATH_MAX], hostname[64], ip4_addr[64], ip6_addr[64] }` | `bsdnamespace_reply { status }` plus one SCM fd: the non-owning jail descriptor | `EINVAL` relative path, unknown flag bits, short message, attached descriptor; `EEXIST` a jail for this label exists with a different path, hostname, address or vnet setting; `EALREADY` second ephemeral enter on one connection; `E2BIG` parameter vector overflow; jail_set(2) errors (a vnet request on a kernel without VIMAGE fails here) |
| `BSDNAMESPACE_OP_DESTROY_JAIL` (2) | `bsdnamespace_control_request { op }` | `bsdnamespace_reply { status }` | `ENOENT` no jail for this label; jail_remove(2) errors |
| `BSDNAMESPACE_OP_LIST_JAILS` (3) | `bsdnamespace_control_request { op }` | `bsdnamespace_list_reply { status, present, jid, flags, path, hostname, ip4_addr, ip6_addr }` | `present == 0` is a success; errno only on a lookup failure |

Flags: `BSDNAMESPACE_F_EPHEMERAL` (0x1) binds the jail to the connection;
`BSDNAMESPACE_F_VNET` (0x2) creates it `vnet=new` with its own network
stack. Both are part of the immutable definition: a reuse whose vnet
setting differs is `EEXIST`. Without VNET, `ip4_addr` and `ip6_addr` are
the jail's addresses on the host stack (empty means none of that family);
with VNET they seed the jail's own stack. LIST reports
`BSDNAMESPACE_F_EPHEMERAL` only when this same connection's worker anchors
the jail; a persistent jail reused across a restart reports it clear.

## Client library

Header `<libservice.h>`, link `-lservice`. Documented in libservice(3).

| Group | Functions |
|---|---|
| Enter | `service_enter_namespace(ctx, path, hostname, ip4_addr, flags)`, `service_enter_namespace_ex(ctx, path, hostname, ip4_addr, ip6_addr, flags)` |
| Lifecycle | `service_destroy_namespace(ctx)`, `service_namespace_info(ctx, &info)` |
| Types and flags | `struct service_namespace_info { present, jid, flags, path, hostname, ip4_addr, ip6_addr }`, `SERVICE_NS_EPHEMERAL`, `SERVICE_NS_VNET` |
| Provider side (used by BSDNamespace) | `service_system_jail_set(token_fd, iov, niov, flags, &jid, &descfd)`, `service_system_jail_get(...)` |

`service_enter_namespace` is `_ex` with an empty `ip6_addr`. The attach
happens inside the library; after a successful return the calling process
is already inside the jail, so do it before exec and after every descriptor
the program needs has been obtained.

```c
#include <err.h>
#include <libservice.h>

/* Confine this process to /var/empty for the rest of its life. */
void
confine(struct service_context *ctx)
{
	struct service_namespace_info info;

	if (service_enter_namespace(ctx, "/var/empty", NULL, NULL,
	    SERVICE_NS_EPHEMERAL) == -1)
		err(1, "service_enter_namespace");
	if (service_namespace_info(ctx, &info) == 0 && info.present)
		warnx("now in jail %d rooted at %s", info.jid, info.path);
}
```

A consumer that lists after a restart can pass `info.flags`, `info.path`,
`info.hostname` and the addresses straight back to
`service_enter_namespace_ex` to reconstruct a matching request and reattach.

## Command-line tool

There is no ctl tool for BSDNamespace; the operation set is self-service by
design, and there is nothing an operator can do to another label's jail
through the broker. Broker-created jails are ordinary jails and appear in
jls(8) under their derived `wj_...` names:

```
# jls name path
wj_3f9a2c...   /var/empty
```

Removing one by hand with jail(8) is possible but is undone on the next
ENTER from its owner (persistent) or already pointless (ephemeral).

## Policy

BSDNamespace has no policy file. Its policy is structural:

| Rule | Effect |
|---|---|
| SYSTEM-domain only | `system.Namespace` does not resolve for USER-domain units |
| One jail per label | the jail name is derived from the caller's label; no wire argument names a jail |
| Immutable definition | path, hostname, ip4, ip6 and vnet must all match on reuse, else `EEXIST` |
| Self-confinement only | the returned descriptor authorizes attaching the caller; it confers nothing on anyone else |
| Reclaim | a persistent jail is removed when its bundle is neither installed nor running, at boot immediately and on the timer after two consecutive misses; pre-map jails are left alone and logged |

There is no admin bypass and no `SERVICE_RIGHTS_ADMIN` path: an ADMIN
session gets exactly the same one-jail-per-label view.

## Tests

`usr.sbin/BSDNamespace/tests` (package group `bsdnamespace-tests`,
installed under `/usr/tests/usr.sbin/BSDNamespace`):

| Program | Kind | Proves |
|---|---|---|
| `jailname_test` | pure unit | distinct labels get distinct names, no collisions over generated labels, determinism, name length and charset, empty label and small buffer refused, request shape validation |
| `provider_test` | plane (real channel, root, jail-capable kernel) | unexpected descriptor, short message, unknown opcode, unknown flag bits and relative path rejected; reuse mismatch is `EEXIST`; second ephemeral enter is `EALREADY`; list-then-destroy lifecycle; ip4 and ip6 round trip through LIST; ip6 mismatch is `EEXIST`; vnet enter creates a vnet jail; control-op framing checks |
| `reclaim_test` | pure unit | owner-map note idempotence, unsafe names rejected, malformed lines dropped, destroy removes only the bundle's entries, bundle-of-container mapping |

Run with `kyua test -k /usr/tests/usr.sbin/BSDNamespace/Kyuafile`; the
provider cases need the real-plane VM runner (see
[Testing](../develop/testing.md)).

## Status and gaps

Shipped and VM-verified with ENTER, DESTROY and LIST, vnet and ip6 (the
inventory's API-completeness pass added DESTROY/LIST/ip6/vnet). Gaps: one
jail per label, so a unit that needs several confinement shapes cannot get
them from the broker; the jail parameter set is fixed (path, hostname,
ip4.addr, ip6.addr, persist, vnet), with no devfs ruleset, mount or
`allow.*` knobs; no ctl tool; reclaim depends on BSDNamespace's storage
container being available (soft without it). Documentation drift to be aware
of: the "Operation" section of BSDNamespace.8 and the header comment in
`bsdnamespace_proto.h` still say the daemon runs as root outside capability
mode; the manifest (`user = "capability"`, `system = ["jail"]`) and
`service_provider_enter_capability_mode()` in `bsdnamespace.c` are the
truth.
