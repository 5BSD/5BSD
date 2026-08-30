# The Authority Model

In 5BSD, **authority is a held capability, never an identity.** To perform an
operation on an object you must hold a capability that names that object and
grants that operation. Your uid, your pathname, your PID, and any signal you can
send grant you *nothing*. This chapter describes that model and how it differs
from the ambient authority a traditional Unix carries.

> **Status.** This is the target architecture and the rule new code is written
> to. The substrate it rests on — the [MAC Capability
> Framework](mac-capability.md), [Capability Transfer](capability-transfer.md),
> and [Capability Bundles](capability-bundles.md) — is in place. The
> authorization *decisions* are migrating onto it in phases; during that
> migration some services still fall back to a uid check behind the capability
> path. The authoritative, code-level specification is
> `docs/capability-authority-model.md` in the source tree.

## Ambient authority is the thing we removed

A traditional Unix answers "may you do this?" by looking at *who you are*: are
you root, are you in this group, do you own this file, can you connect this
socket. That is **ambient authority** — power that attaches to your identity and
is available without your having been handed anything. It is why a single
compromised root process can do anything, and why "least privilege" is so hard
to express.

5BSD answers a different question: "*do you hold a capability for this?*" Power
comes only from capabilities you were explicitly given, and it is exactly the
power those capabilities name — no more.

## What a capability is

A capability is a **channel endpoint bound to an `(object, rights)` pair**. The
file descriptor is the credential: holding the endpoint *is* holding the
authority, and using it *is* presenting the capability. The service on the other
end acts on a request because of *which endpoint it arrived on* and the rights
that endpoint carries — it never inspects the caller's identity.

Four operations define the model:

- **Present** — send a request on the endpoint. The service honors it if the
  endpoint's rights permit that operation.
- **Delegate** — hand the endpoint to another holder by passing the descriptor.
  Whether it may be re-delegated is itself an attenuable property of the fd (see
  [Capability Transfer](capability-transfer.md)).
- **Attenuate** — mint a strictly weaker capability from one you hold: fewer
  rights, or a narrower object. Attenuation is one-way.
- **Revoke** — invalidate a capability, and transitively everything minted from
  it, so authority can be withdrawn.

Rights are a small, per-service set of **operation bits** (Capsicum-shaped):
attenuation clears bits, and `admin` is shorthand for all of them. There is no
"root can do anything" — `admin` on a *specific* capability is as far as power
goes, and only its holder has it.

## The one place identity becomes capability

Pure capability systems do not have authority nowhere — they have a single,
explicit **mint boundary** where it is created, and derive everything else by
delegation. 5BSD's boundary has three parts:

1. The **kernel** `mac_capability` device, which makes endpoints unforgeable.
2. **Authority Init** (PID 1), which holds the root capability at boot and
   delegates the initial grants.
3. The **authentication boundary** — the *only* place an identity is exchanged
   for capabilities. When you prove a credential, a small, sandboxed **auth
   agent** consults an explicit **principal → bundle policy** and delegates that
   principal's capability bundle to your session. Your shell and its children
   inherit those capabilities the way they inherit standard I/O.

This is the honest analogue of what every capability system must do somewhere:
*"this principal may hold these capabilities."* It is stated once, as policy, in
the trusted base — not scattered as `uid == 0` tests across services. A
principal is still *named* by a uid, but naming is not authority: the mapping
from that name to capabilities is policy, and no service ever re-derives power
from the name.

## Discovery, control, and lifecycle are all just capabilities

- **Service discovery** — the lookup channel a session holds is a *discovery
  capability*; how broad it is (all services, or a narrow set) is set by the
  auth policy for that principal, not by whether the principal is root.
- **Control** (starting/stopping services, storage administration) is a
  *control capability* an admin principal holds — delegatable to an unprivileged
  operator without making it root. This is the payoff of the model: least
  privilege without a superuser.
- **Lifecycle** (reboot, halt) is a *lifecycle capability* served by the spine so
  it survives even the service manager's shutdown; `reboot` presents it. The
  kernel `reboot(2)` remains only as a last-resort escape hatch, not an
  authorization path.

## Where uid still lives

Unix uids do not disappear — 5BSD is still a POSIX system. Files have owners,
processes have credentials, and the kernel enforces them. What changes is that
**the capability plane never derives *its* authority from a uid.** uids name
principals at the authentication boundary and protect the POSIX substrate;
services run under an unprivileged, non-root uid as defense in depth. Authority
above that boundary is capabilities, and only capabilities.

## See also

- [The MAC Capability Framework](mac-capability.md) — the kernel substrate.
- [Capability Transfer](capability-transfer.md) — delegation and attenuation of
  the descriptor.
- [Capability Bundles](capability-bundles.md) — how a service's grants are
  declared and delivered.
