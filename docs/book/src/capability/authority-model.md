# The Authority Model

In 5BSD, authority is a held capability, never an identity. To perform an
operation on an object a process must hold a descriptor that names that
object and grants that operation; its uid, its pathname, its PID and any
signal it can send grant nothing. 5BSD has this rule because a traditional
Unix answers "may you?" by asking "who are you?", which is why one
compromised root process can do anything and why least privilege is so hard
to express. This chapter states the model, shows where identity is turned
into capability, lists the uid gates that remain during the migration, and
records how far the migration has come. The kernel substrate is in
[The MAC Capability Framework](mac-capability.md); the specification is
`docs/capability-authority-model.md`.

## The rule

A service performs an operation if and only if the endpoint the request
arrived on carries a capability whose rights permit that operation. It
never reads the caller's uid, gid, pathname, PID or a signal to decide.
Three consequences follow. A caller without the capability does not get
"permission denied"; the operation is unreachable, and a refused lookup
returns `ENOENT` exactly as an unregistered name would, which is the right
information posture. "Read-only versus privileged" is expressed as rights on
the capability, not as root versus non-root. And delegation gives least
privilege without root: an operator can hold an administrative capability
for one service while running as an ordinary uid.

## What a capability is

A capability is a channel endpoint bound to an `(object, rights)` pair. The
descriptor is the credential; holding it is holding the authority; using it
is presenting the capability. The kernel makes endpoints unforgeable and
stamps every message with the sender's identity; the granting service
records what each endpoint it handed out is bound to. Four operations
define the model:

| Operation | Meaning | Mechanism |
|---|---|---|
| present | send a request on the endpoint | the service resolves endpoint to `(object, rights)` and honours the request if the rights permit |
| delegate | hand the endpoint to another holder | descriptor passing over a channel, bounded by `cap_xfer_limit(2)` |
| attenuate | mint a strictly weaker capability from one held | `cap_xfer_rights_limit(2)` at the descriptor level; `service_rights_attenuate()` at the service level |
| revoke | invalidate a capability and everything minted from it | an epoch on the object (`service_epoch_t`, `service_epoch_live()`); selective revocation by dropping a caretaker endpoint |

Rights are small per-service bit sets, Capsicum-shaped: `service_rights_t`
in libservice(3), with `SERVICE_RIGHTS_ALL`, `SERVICE_RIGHTS_NONE` and
`SERVICE_RIGHTS_ADMIN` (bit 63), tested with `service_rights_allow()` and
narrowed with `service_rights_attenuate()`, which can only clear bits.
`admin` is shorthand for all of a service's bits; there is no "root can do
anything", only admin on a specific capability, held by whoever was given
it.

## The mint boundary

Pure capability systems do not have authority nowhere; they have one small,
explicit place where it is created, and derive everything else by
delegation. 5BSD's boundary has three parts.

The kernel `mac_capability` device creates endpoints that cannot be
fabricated, only received. [Capsule](../plane/capsule.md), PID 1, claims
the device and the system gates at boot and delegates the initial
capabilities: switchboard's registry and each unit's launch descriptors.
The authentication boundary is the single place a proven identity becomes
a set of capabilities. When login(1), su(1) or sshd(8) has authenticated a
principal, it asks BSDAuth (`system.Auth`, [the provider
chapter](../providers/auth.md)) to mint the session's lookup channel.
BSDAuth is a switchboard-managed, capability-mode unit that switchboard
recognises as the mint authority by the manifest role `mint_authority =
true`, honoured only for a base-system bundle, so no application bundle can
claim the role by naming itself. The agent resolves the principal itself
from `passwd` and `group` descriptors it obtained from BSDFilesystem before
entering capability mode (a compromised login program cannot claim a group
it is not in), applies `/Capabilities/Config/principal-policy.ucl`, mints the
scoped channel over its own bootstrap channel to switchboard, attenuates the
delivered descriptor to `CAP_XFER_ONCE`, and returns it. The login program
installs it as the session leader's inherited lookup channel.

Two gates keep the boundary exclusive. switchboard refuses direct minting
on any ambient lookup channel, so login programs hold no mint authority at
all; if the agent is unreachable they carry no lookup channel, never a
wider one. And BSDAuth accepts a session-mint request only from a caller
whose connection carries `SERVICE_RIGHTS_ADMIN`, a bit switchboard's naming
code stamps only on an ambient login-session lookup over a full-discovery
channel (`usr.sbin/switchboard/naming.c`); a managed unit that connects to
`system.Auth` and asks for a `{uid=0}` mint is refused `EPERM`. The same
agent serves elevation: anoint(1) asks for one more anointment for one
command after re-authentication ([Anointments and Principal
Policy](../plane/anointments.md)). The trusted base for the session-mint
decision is switchboard and BSDAuth, not login, su and sshd; sshd's
privilege-separated monitor forwards the minted descriptor one hop to its
session child, for the authenticated principal only
([Sessions](../compat/sessions.md)).

## Discovery capabilities

The lookup channel a session or unit holds is itself a capability whose
breadth decides what it can discover. switchboard scopes every channel by
the anointment set it carries: a unit's set comes from its manifest
`holds`, a session's from the principal policy at mint. An endpoint a
provider published without `requires` is open to anyone the domain rules
let see the name; a gated endpoint resolves only for a holder of every name
it requires. Two session kinds still exist beside the set during the
transition. A SYSTEM channel, minted for a principal whose grant holds `*`
or `admin_rights`, discovers every open name; under the shipped policy that
is root and `wheel`. A USER channel, per uid, sees open names only where
the provider opted in with `visible`, and gated names wherever its set
covers them. Neither kind makes a CORE unit manageable
([The Management Model](../plane/management-model.md)). Control planes are
ordinary gated names: `system.switchboard` and `system.lifecycle` require
the administrative right on the presenting channel, and switchboardctl(8)
and capsulectl(8) have no socket fallback.

## Where uid still lives

uids do not disappear; 5BSD is a POSIX system. Files have owners, processes
have credentials, the kernel enforces both, and units run under the
unprivileged `capability` user as defence in depth. What changes is that
the plane never derives its authority from a uid above the mint boundary:
a uid names a principal there, and naming is not authority. Some uid
checks nevertheless remain, and the model calls them transitional. They
are listed here so a reader knows what to expect and what will change.

| Remaining gate | Where | Status |
|---|---|---|
| capsule's control socket for status, reload and graceful shutdown is root-only by `getpeereid(3)`, and its command handlers check `euid == 0` | `usr.sbin/capsule/control.c`, `commands.c`; `capsule.conf(5)` `control_socket` | deliberate; lifecycle verbs (reboot, halt, single, reroot) already go through the `system.lifecycle` capability |
| the `accounting` kernel service refuses to connect without `PRIV_ACCT` | `sys/dev/mac_capability/mac_capability_accounting.c` | kernel priv gate, no plane user yet |
| an unclaimed system gate, presented from outside capability mode, falls back to the kernel's priv(9) checks | mac_capability_system(4) | compatibility for un-sandboxed callers; capability-mode callers fail closed |
| the SYSTEM and USER channel kinds are still chosen at mint | BSDAuth, `usr.sbin/switchboard/domain.c` | the choice now comes from the principal policy, not from an inline root/wheel test |
| the `SVC_DOMAIN_CONTROL` kind and the `.Control` name rule are still compiled in | `usr.sbin/switchboard/domain.c` | residual; no shipped control plane uses it, and the model retires it |
| the principal policy file is protected by file permissions | `/Capabilities/Config/principal-policy.ucl` | the specified end state is a `policy-admin` capability; the tight-permission file is the migration shim |
| BSDBluetooth's control socket privileges peer uid 0 | `usr.sbin/bluetooth/BSDBluetooth/ctl.c` | uid-gated, not yet held-capability |

Kernel-side, the `*_gated()` entry points (`kern_settime_gated`,
`kern_adjtime_gated`, `kern_kldload_gated`, `kern_kldunload_gated`,
`kern_jail_set_gated`, and the gated sysctl path) are the opposite of a gate:
they are where a held claim already replaces `priv_check(9)` so a
born-in-capability-mode daemon can do privileged work. The rootless
hardening notes in [The Management Model](../plane/management-model.md)
describe the present boundary for operators: the shipped default keeps
root as a powerful compatibility administrator, and 5BSD does not claim
an unmodifiable system volume.

## The migration and where it stands

The specification lays out a bootable-at-every-step migration in seven
phases. Status is taken from the tree and the divergence inventory
(`docs/5bsd-inventory.md`, sections 1 and 3).

| Phase | What it is | Where it stands |
|---|---|---|
| P0 primitive | rights, attenuation and epoch primitives in libservice | done; `service_rights_*` and `service_epoch_*` exist in `lib/libservice/libservice.h`; no component yet calls `service_rights_attenuate()` or `service_epoch_live()` |
| P1 auth boundary | one admin decision (P1a), an explicit UCL principal policy (P1b), an isolated agent (P1c) | done; BSDAuth is the agent, `mint_authority` its role, `capbundle_principal_*` in libcapbundle its policy reader |
| P-rights | grants carry a rights word | done; switchboard stamps `svc_new_client_msg.rights`, libservice delivers `identity.rights` |
| P2 one service converts | BSDNotify authorizes by `SERVICE_RIGHTS_ADMIN`, not uid | done and VM-validated ([BSDNotify](../providers/notify.md)) |
| P3 control planes | `system.switchboard` gated on the admin right; control sockets deleted | done for switchboard; BSDFilesystem is a socket-free provider under switchboard |
| P4 lifecycle and PID 1 minimisation | BSDFilesystem as a switchboard unit (P4a); a `system.lifecycle` capability served by capsule, reboot(8) and shutdown(8) delegating to capsulectl(8) (P4b) | done; capsule supervises exactly one child |
| P5 retire uid-derived domains | discovery minted purely by policy; remove the domain kinds and the `.Control` convention; convert remaining services | in progress: the decision is policy-driven, but the SYSTEM/USER kinds and `SVC_DOMAIN_CONTROL` remain in code |
| P6 revocation and attenuation in anger | delegation to non-root operators, attenuated capabilities, revocation | partly: anoint(1) elevation, per-endpoint `requires`/`holds`, non-admin su via authenticated mint are live; service-level attenuation and epoch revocation have no callers |
| P7 cleanup | remove superseded gates and shims, split grown files, final documentation sweep | not started |

Status: as of the divergence inventory of 2026-09-25, phases P0 through
P4 are complete and VM-verified, P5 and P6 are partial, P7 is pending.

## Future: a capability-sufficient process flag

Today a born-in-capability-mode daemon reaches each privileged primitive
through a matching `*_gated()` kernel entry point or a `system` perform op,
one per operation. The design direction, not yet built and without a
design document in `docs/`, is a per-process flag that can be set only by
presenting a held `mac_capability` claim, and that makes the kernel's own
`priv_check(9)` accept held capabilities as authority in place of uid and
gid. With it the per-gate variants and credential swaps would collapse into
one rule. An earlier attempt at the same idea as a per-descriptor flag
(`UF_CAP_SUFFICIENT`) was built and then removed from the fork, because a
flag that travels with a descriptor through `SCM_RIGHTS` widened authority
in ways the holder could not see. The process-scoped form is the design
that remains; until it exists, the per-gate entry points stay.

## See also

[Descriptor and Process Protections](descriptor-protections.md) for the
descriptor-level attenuation the model relies on;
[Discovery and the Lookup Channel](../plane/discovery-and-lookup.md) for
how names resolve; [Anointments and Principal Policy](../plane/anointments.md)
for `requires`, `holds`, the policy file and anoint(1);
[System Gates](system-gates.md) for the kernel gates and perform ops.
