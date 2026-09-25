# The Management Model

Who may stop a service, who may see it, and what it may see are three
separate questions on 5BSD, answered by three separate manifest keys and
enforced by switchboard before any privilege is consulted. Root is not the
answer to any of them: a bare uid 0 login carries no management authority,
an operator is a session holding the `system.switchboard.admin` anointment,
and a CORE unit cannot be managed at runtime by anyone at all. 5BSD has this
so that the base plane cannot be taken down by a compromised administrator
account, and so that an ordinary user can run and manage agents of their own
without operator help.

## The three axes

| Key | Question | Values | Default |
|---|---|---|---|
| `control` | who may stop, restart, unload or disable the unit at runtime | `core`, `system`, `user` | `system` |
| `visible` | which domain kinds may resolve the unit's `ipc` names | `["user"]`, `["system"]` | SYSTEM only |
| `domain` | which names the unit itself resolves over its bootstrap channel | `system`, `user` | by bundle class |

`control` is management. `visible` is being seen. `domain` is seeing. They
compose but never imply one another: BSDLog is `control = "core"` and
`visible = ["user"]`, so every login session can emit to it and nobody can
stop it; BSDDevice is `control = "system"` and `visible = ["system"]`, so an
operator can restart it and no user session can even resolve it. Manage and
see are decoupled at the principal end too: the principal policy's `*` grant
means see everything, and its separate `admin_rights` means manage (see
[Anointments and Principal Policy](anointments.md)). A site can give an
account one without the other.

`protect` is a fourth, orthogonal thing: it shields the unit's process from
signals, ptrace and the like (see [Descriptor and Process
Protections](../capability/descriptor-protections.md)). `control` governs
management through switchboard; `protect` governs what other processes can
do to the process directly.

## Management classes

`usr.sbin/switchboard/management.c` decides every runtime management
operation with `svc_management_check_class`, given the class, the caller's
uid, whether the caller is an operator, and, for user agents, the owning uid:

| Class | Who may manage at runtime | Shipped examples |
|---|---|---|
| `core` | nobody. Not an operator, not uid 0, not any held right or anointment. Only switchboard's own boot and shutdown lifecycle, and an in-place restart when the manifest changes, touch it | BSDFilesystem, BSDLog, BSDAuth, BSDAudit, BSDExtension, BSDSysctl, BSDTime, BSDPower |
| `system` | an operator only | BSDDevice, BSDCrypto, BSDNamespace, BSDNotify, BSDNetwork, BSDTrace, BSDVM, adopted rc.d services |
| `user` | the owning uid itself, or an operator | every per-user agent |

The class is checked first and absolutely. A CORE refusal is `EPERM` with a
warning in the log and an `AUE_SWITCHBOARD_CTL` audit record; no argument
about who the caller is gets past it. That is the property the rest of the
plane is built on: switchboard, the storage broker, the log authority and the
mint boundary stay up for as long as the machine does, whatever happens to
the accounts on it.

The class is the manifest's `control` key, and a bundle loaded from a
per-user agent directory is forced to `user` whatever it declares.

## What an operator is

The control plane, `system.switchboard`, is reachable by any authenticated
login session; what a session may do is decided per operation, not at the
door (`usr.sbin/switchboard/naming.c`, `naming_lookup_self_control`). A
session is an operator when its anointment set holds
`system.switchboard.admin`, or `*`. The boot channel installed ahead of rc
holds `*`, so getty, login and rc keep full control; a shipped `wheel` login
holds `*` too. An operator's control channel carries `SVC_RIGHTS_ADMIN` and
may manage SYSTEM units and run the global operations (`reload`, `enable`,
`disable`). A plain user's control channel carries no admin bit; the
management gate, keyed on the channel's minted uid, confines it to starting
and stopping its own agents. Anyone may query `status` and `services`; that
inventory is not secret. A service, as opposed to a session, may not open
the control plane at all.

## What root can and cannot do

Root is a principal like any other, so the honest list is:

| Root can | Root cannot |
|---|---|
| edit `/Capabilities/Config/principal-policy.ucl`, install and remove bundles, edit any file, reboot | stop, restart, unload or disable a CORE unit, with or without the admin anointment |
| hold `*` and the admin bypass under the shipped policy, and so manage every SYSTEM unit | manage anything if the policy no longer lists uid 0 or `wheel` (it falls under `default`, holding nothing) |
| `capsulectl reboot`, which drives a service-ordered shutdown through switchboard's lifecycle | signal a unit whose `protect` list shields it, or ptrace one |

The boundary is capability-plane least privilege, not a system seal.
Conventional root can still alter installed files and policy, then reboot;
5BSD claims neither macOS System Integrity Protection nor a signed system
volume. The shipped default is deliberately compatible and permissive: uid 0
and `wheel` hold `*` with admin rights. The stricter profile keeps the
bypass and turns every gated reach into an audited per-command ask:

```ucl
admin { groups = ["wheel"]; uids = [0]; anointments = [];
        may_elevate = ["*"]; admin_rights = true; }
```

With that in place `switchboardctl restart system.Network` from a wheel
shell fails, and `anoint system.switchboard.admin switchboardctl restart
system.Network` succeeds and leaves a record.

## Per-user agents

A user's own bundles live under `/Capabilities/Users/<uid>/Agents`
(`SWITCHBOARD_USERS_DIR_DEFAULT` in `usr.sbin/switchboard/switchboard.h`).
Switchboard creates `/Capabilities/Users/<uid>/Agents` (mode 0700, owned by
that uid) the first time the user's session reaches the control plane, so `switchboardctl
status` from a fresh login is enough to get a place to install into.

**Load.** At startup and on every rescan switchboard enumerates each
`<uid>` directory that its numeric uid owns and scans the `Agents` root
below it. Trust for a user root is by ownership, not by root: a `System/`
or `Apps/` root must be entirely root-owned, a per-user root must be
entirely owned by its uid, and neither may contain a symlink, a non-regular
object or a group- or world-writable path. A tree that fails is quarantined
with the reason and never blocks the plane; scanning user roots is best
effort and never fatal.

**Confine.** Every unit loaded from a user root is confined in
`usr.sbin/switchboard/startup.c` whatever its manifest declared:

| Field | Forced to | Effect |
|---|---|---|
| `control` | `user` | only its owner or an operator may manage it |
| `domain` | `user` | it resolves only user-visible names; no system reach |
| `visible` | cleared | its `ipc` names resolve only in the SYSTEM domain |
| `mint_authority` | false | it can never mint session channels |
| `ambient` | false | it is launched born in capability mode |
| `capabilities` | stripped | no system gates are delegated |
| `level = "interactive"` | clamped to `standard` | no scheduling boost |

A user's own, unverified code therefore gains no system authority by being
installed, and there is nothing the manifest can say to change that.

**Self-service control.** With the confinement in place the control plane
can be opened to the user. `switchboardctl start <label>` and `stop <label>`
from the owner's session succeed for the owner's agents, are refused `EPERM`
for anyone else's, are refused for SYSTEM units, and are refused for CORE
units for everyone. `reload`, `enable` and `disable` remain operator-only.

## Service level and the boost

`level` is `background`, `standard` (the default) or `interactive`, applied
as a nice(3) priority in the child after pdfork(2) and before the program
image runs. Throttling down needs no privilege and is honoured for any unit.
The interactive boost is a privilege: `svc_effective_band` honours it only
for a unit of a base-system bundle under `/Capabilities/System`, whose
verified manifest is the declaration, exactly as `ambient` and
`mint_authority` are. An application under `/Capabilities/Apps` or a
per-user agent that asks for `interactive` is clamped to `standard`.

## switchboardctl in practice

```sh
# anyone in a session: inventory
$ switchboardctl status
$ switchboardctl services

# an operator (a session holding system.switchboard.admin, or *)
$ switchboardctl restart system.Network
$ switchboardctl disable Notify           # persistent, applied by reload
$ switchboardctl enable Notify
$ switchboardctl reload

# an operator under the stricter policy: elevate per command
$ anoint system.switchboard.admin switchboardctl restart system.Network
Password:

# a CORE unit refuses everyone
$ switchboardctl stop system.Log
switchboardctl: stop: "system.Log" is management class core and cannot be stopped at runtime

# a plain user managing its own agent
$ switchboardctl start org.example.agent/agent
```

`install path.cap` copies a bundle into `/Capabilities/System` as a
root-owned tree and needs root because it writes there; `verify`, `deps`,
`bundles` and `graph` read the registry on disk and need nothing. The
anointment gate on the operator verbs is switchboardctl(8)'s "requires the
`system.switchboard.admin` anointment on the caller's session, not root".

## Observing decisions

Every control operation, allowed or refused, is an `AUE_SWITCHBOARD_CTL`
(43321) audit record with the caller's uid, or `(uid_t)-1` for a
capability caller whose authority is a held right. Refusals also fire
`switchboard:::sctl-deny` and log `management class core: <label> cannot be
stopped at runtime`, `management class system: <label>: stopped requires
operator authority (uid N)` or `management class user: <label>: stopped
denied for uid N (owner M)`. The management matrix is unit-tested in
`usr.sbin/switchboard/tests` (`management_enforce_test`, `sctl_gate_test`,
and the rootless agent tests that load a user agent tagged with its owner
and quarantine a world-writable one).

## Limits

The model governs management through switchboard. It does not stop root
from `kill`ing an unprotected process directly, editing the policy, or
replacing a bundle on disk and reloading; those are closed by `protect`,
by mac_veriexec once enforcing, and by keeping the install roots read-only,
not by `control`. Adopted rc.d services are SYSTEM units and inherit the
operator rule, but everything `/etc/rc` starts outside adoption is not
managed by switchboard at all; see [rc and
service(8)](../compat/rc-and-service.md).

Reference: switchboard(5) (`control`, `visible`, `domain`, `level`),
switchboard(8), switchboardctl(8), BSDAuth(8). Design:
`docs/service-discovery-model.md` sections 5 and 6. Related:
[Switchboard](switchboard.md), [Bundles and
Manifests](bundles-and-manifests.md), [Discovery and the Lookup
Channel](discovery-and-lookup.md), [A Per-User
Agent](../develop/per-user-agent.md).
