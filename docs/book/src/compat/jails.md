# Jails

jail(8), jail.conf(5), jexec(8) and the `jail_*` system calls work on 5BSD as they do on FreeBSD. 5BSD adds a second way to be jailed: a program confines itself at run time by asking the BSDNamespace provider (system.Namespace) for a jail over its capability channel, and attaches itself with a jail descriptor. That route exists so a sandboxed unit, born in capability mode as the unprivileged `capability` user, can be jailed without any process outside it holding jail privilege on its behalf. This chapter covers both routes, the kernel pieces they share, and how the plane's coalitions interact with jail teardown.

## The classic route

`usr.sbin/jail` is FreeBSD's, with three changes. Configuration strings are allocated with `calloc(3)` and `recallocarray(3)` instead of `malloc` and `realloc` (a HardenedBSD-derived fix), a DTrace USDT provider `jail` reports parameter sets, and the jail.8 example extracts a base from `/usr/5bsd-dist`. `usr.sbin/jail/tests/jail_config_test.sh` covers jail.conf variable expansion and string growth across allocation size classes; it runs from the `jail` test package under kyua.

The installer can populate a jail from pkgbase (`bsdinstall jail`, which drives `bsdinstall pkgbase --jail`), and `5BSD-set-base-jail` is the metapackage set for a jail root, produced by `release/packages/create-sets.sh` alongside `set-base`. Base packages in a jail come from the same local repository as the host (see [Packages and Ports](packages.md)). A jailed rc(8) runs `/etc/rc` the ordinary way, because switchboard inside a jail is not part of the model: the plane belongs to the host.

Jail descriptors are the FreeBSD 15 feature (jail(2): `JAIL_GET_DESC`, `JAIL_OWN_DESC`, `JAIL_USE_DESC`, `jail_attach_jd(2)`, `jail_remove_jd(2)`). 5BSD gives them Capsicum rights, listed in rights(4):

| Right | Permits |
|---|---|
| `CAP_JAIL_ATTACH` | `jail_attach_jd(2)` on the descriptor |
| `CAP_JAIL_REMOVE` | `jail_remove_jd(2)` on the descriptor |
| `CAP_JAIL_SET` | `jail_set(2)` with `JAIL_USE_DESC` on the descriptor |

A jail descriptor passed to a process in capability mode is therefore usable exactly to the extent of its rights, and a sandbox that held one before needs the right added. `jail_attach_jd(2)` and `jail_remove_jd(2)` are marked `CAPENABLED` in `sys/kern/syscalls.master`; `jail_set(2)` and `jail_get(2)` are not, whatever flags they carry, and `jail_set` keeps its `PRIV_JAIL_SET` check.

## The capability route

A unit does not declare a jail in its manifest; switchboard never brokers one on a unit's behalf. Instead the unit calls libservice(3):

```c
#include <libservice.h>

if (service_enter_namespace(ctx, "/var/jails/worker", "worker",
    "10.0.0.7", SERVICE_NS_EPHEMERAL) == -1)
        warn("enter_namespace");	/* soft: run unjailed, retry later */
```

`service_enter_namespace()` resolves `system.Namespace` over the caller's channel (pulling BSDNamespace up on demand if it is not running), asks for a jail rooted at `path` with the given hostname and IPv4 address, receives a jail descriptor as the reply's single `SCM_RIGHTS` fd, and calls `jail_attach_jd(2)` on it before returning. The credential stored in that descriptor is root's, from BSDNamespace, and that is what authorizes a non-root caller's own attach; the process never holds jail privilege itself. `service_enter_namespace_ex()` adds an IPv6 address and `SERVICE_NS_VNET` for a jail with its own network stack (requires `VIMAGE`). Flags:

| Flag | Meaning |
|---|---|
| 0 | persistent: the jail is reused by label across restarts of the unit |
| `SERVICE_NS_EPHEMERAL` | the jail's lifetime is bound to the calling process and torn down when it exits |
| `SERVICE_NS_VNET` | the jail gets its own virtual network stack |

`service_destroy_namespace()` removes the caller's own jail (`ENOENT` if none). `service_namespace_info()` reports it into a `struct service_namespace_info` with `present`, `jid`, `flags`, `path`, `hostname`, `ip4_addr` and `ip6_addr`, so a consumer that restarts can pass the same definition back.

The scoping rule is what makes self-service safe: BSDNamespace keys every jail by the caller's unforgeable channel label, and a label owns at most one jail. No operation takes a jail name or jid on the wire, so one consumer can never name, reuse or destroy another's. Reuse of a persistent jail is allowed only when the entire requested definition matches the existing jail: path, hostname, IPv4, IPv6 and vnet. A jail's definition is immutable, so any mismatch is a hard `EEXIST` rather than a silent reattach into a differently shaped jail. The descriptor BSDNamespace returns is non-owning; closing it never removes the jail. BSDNamespace also reconciles the persistent jails it created against the installed and running bundles it sees through delivered directories (`/Capabilities/System`, `/Capabilities/Apps`, `/Capabilities/Run/live`), so a jail whose bundle was removed is reaped on the next pass. The wire operations `ENTER_JAIL`, `DESTROY_JAIL` and `LIST_JAILS` are documented in [system.Namespace](../providers/namespace.md).

## The jail gate

BSDNamespace is itself born in capability mode as user `capability`, and `jail_set(2)` is neither capability-enabled nor unprivileged. It works through a mac_capability system gate. Its manifest (`usr.sbin/BSDNamespace/capbundle/bsdnamespace.ucl`) declares

```
capabilities {
    system = ["jail"];
}
```

and capsule mints the `SYS_GATE_JAIL` claim from that block, which switchboard delivers at launch. Instead of calling `jail_set(2)`, the daemon issues `SYS_OP_JAIL_SET` (10) and `SYS_OP_JAIL_GET` on the gate through `service_system_jail_set()` and `service_system_jail_get()`; the kernel side is `kern_jail_set_gated()` in `sys/kern/kern_jail.c`, where the held gate replaces `PRIV_JAIL_SET` and `PRIV_JAIL_ATTACH` while every other check (hierarchy limits, parameter validation, prison rules) is unchanged. The jail root's namei runs in kernel context (`UIO_SYSSPACE`), which is what exempts it from the capability-mode restriction on userspace paths. The gate is perform-only, with no MACF hook: the ambient `jail_set(2)` keeps its ordinary privilege check and remains refused in capability mode.

mac_capability_system(4) bounds the request: at most `SYS_JAIL_MAXPARAMS` (16) parameters and `SYS_JAIL_MAXBUF` (4096) bytes; `jail_flags` may contain only `JAIL_CREATE`, `JAIL_UPDATE`, `JAIL_GET_DESC`, `JAIL_OWN_DESC` and `JAIL_DYING`, and `JAIL_ATTACH` and the descriptor-input forms are refused, so the gate can create and query jails but a gate holder cannot attach anything to one through it. capsule.conf(5) accepts the same `jail` name in `claims.system`, and switchboard(5) lists it among the twelve gate names a manifest may declare. [System Gates](../capability/system-gates.md) explains the gate model.

## Coalitions and jail teardown

A coalition (mac_capability_coalition, see [Coalitions and Accounting](../capability/coalitions-and-accounting.md)) groups processes, channels, sockets and jails so that terminating the group revokes everything in it. A jail joins a coalition by enlisting its jail descriptor (`COALITION_OP_ENLIST`); the descriptor must carry `CAP_JAIL_REMOVE`, and a dead or invalid prison is refused with `ENOENT`. Termination of the coalition then calls `prison_remove()` on each enlisted jail, alongside `SIGKILL` for processes, `soshutdown(SHUT_RDWR)` for sockets and revocation for channels.

The other direction is handled too. The coalition attaches jail OSD to the prison when it enlists it; if the jail dies first, through `jail -r` or `jail_remove_jd`, the OSD destructor queues a cleanup task that removes the member from the coalition, drops the prison reference, and emits `COALITION_NOTE_MEMBER_REMOVED`. If that jail was the coalition's designated leader, its death terminates the coalition (`COALITION_OP_SET_LEADER`). Jail membership is inherited across fork through the same OSD, so a process forked inside an enlisted jail is accounted to the coalition. Limits are soft and best-effort: `kern.mac_capability_coalition.max` (1024 coalitions) and `max_members` (8192 total members) bound the tables, and `kern.mac_capability_coalition.count` and `members` report use. The exhaustion, jail-death race and churn cases are exercised by the coalition tests under `INVARIANTS` and `WITNESS`.

## Choosing a route

| Need | Route |
|---|---|
| Run a full system or service tree in a jail managed by an operator | jail(8) and jail.conf(5), as on FreeBSD |
| A daemon that wants its own root and address but runs as a switchboard unit | `service_enter_namespace()` from the unit itself |
| Hand a jail to a sandboxed helper | pass a jail descriptor with only the rights the helper needs |
| Tear down a worker's jail with its processes and sockets in one operation | enlist the jail descriptor in the worker's coalition |

The two routes do not mix on one jail: BSDNamespace owns the jails it creates, by label, and a jail created by jail(8) is not visible to `service_namespace_info()`.

## Status

Both routes are shipped and VM-tested; BSDNamespace's `provider_test` exercises create, reuse, mismatch (`EEXIST`), destroy and list, including vnet and IPv6, and the gate's bounds are covered in the mac_capability system tests. Nested jails through the capability route are not exercised. There is no jail-aware switchboard: a jail runs stock init and rc, and the units it contains cannot reach the host plane.
