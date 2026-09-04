# The Authority Model

In 5BSD, **authority is a held capability, never an identity.** To perform an
operation on an object you must hold a capability that names that object and
grants that operation. Your uid, your pathname, your PID, and any signal you can
send grant you *nothing*. This chapter describes that model, the authority
domains a session can hold, and the one boundary where a proven identity is
exchanged for capabilities.

The substrate — the [MAC Capability Framework](mac-capability.md) and
[Capability Bundles](capability-bundles.md) — enforces this model, and the
authentication boundary is live: `login`, `su`, and `sshd` provision their
sessions through the auth-agent (see below). A few control paths deliberately
gate on a uid beside the capability path (the `authorityd` system-lifecycle
control socket keeps `getpeereid(3)` by design — reboot/halt keep their
classic path).

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
  the transfer controls in the [MAC Capability
  Framework](mac-capability.md)).
- **Attenuate** — mint a strictly weaker capability from one you hold: fewer
  rights, or a narrower object. Attenuation is one-way.
- **Revoke** — invalidate a capability, and transitively everything minted from
  it, so authority can be withdrawn.

Rights are a small, per-service set of **operation bits** (Capsicum-shaped):
attenuation clears bits, and `admin` is shorthand for all of them. There is no
"root can do anything" — `admin` on a *specific* capability is as far as power
goes, and only its holder has it.

## Authority domains

The lookup channel a session holds determines what it can even *discover*.
`serviced` scopes every channel to a domain:

- **SYSTEM** — full-discovery administrative reach. Held by the plane's own
  units and by administrator sessions.
- **USER** — a per-uid channel resolving an allow-listed subset of system
  names, plus that user's own services. Held by ordinary sessions.
- **CONTROL** — a sibling of SYSTEM, not a widening of it: control-plane names
  (starting/stopping services, storage administration) are invisible to SYSTEM
  and USER lookups and resolve only through a held CONTROL channel. This is the
  payoff of the model — a control capability is delegatable to an unprivileged
  operator without making it root.

Lifecycle (reboot, halt) is likewise a capability served by the plane's spine
so it survives even the service manager's shutdown; the kernel `reboot(2)`
remains only as a last-resort escape hatch, not an authorization path.

## The one place identity becomes capability

Pure capability systems do not have authority nowhere — they have a single,
explicit **mint boundary** where it is created, and derive everything else by
delegation. 5BSD's boundary has three parts: the kernel `mac_capability`
device, which makes endpoints unforgeable; **Capsule** (PID 1, the init
personality of `authorityd`), which holds the root capability at boot and
delegates the initial grants; and the **authentication boundary** — the only
place a proven identity is exchanged for capabilities, described next.

This is the honest analogue of what every capability system must do somewhere:
*"this principal may hold these capabilities."* It is stated once, as policy, in
the trusted base — not scattered as `uid == 0` tests across services. A
principal is still *named* by a uid, but naming is not authority: the mapping
from that name to capabilities is policy, and no service ever re-derives power
from the name.

## The authentication boundary

A login program (`login`, `su`, `sshd`) authenticates a principal and must then
hand the session a lookup channel scoped to that principal — SYSTEM for an
administrator, per-uid USER for everyone else. If each login program
classified the principal and minted the channel itself, mint authority — the
ability to conjure an admin capability for any uid — would live in three
separate, privileged, network-facing programs.

Instead that authority lives in one place: the **auth-agent** (`system.authagent`,
the `authagentd` daemon), a small, `serviced`-managed, capsicum-sandboxed
service. A login program, having authenticated a principal, asks the agent to
mint the session channel for a uid. The agent:

1. **Resolves the principal itself, via Casper** (`cap_pwd`/`cap_grp`). It
   never trusts attributes sent by the caller — a compromised login program
   must not be able to claim `wheel` membership it does not have.
2. **Applies the principal→domain policy.**
   `/Capabilities/Config/principal-policy.ucl` is the single config that
   decides which domain a principal's session receives: an explicit `admin`
   list of uids and groups gets SYSTEM; everyone else gets USER. An absent or
   unparseable policy fails safe to the historical default — root, or a member
   of `wheel`, is admin — so a typo can never lock out root.
3. **Mints the scoped channel** over its own unit bootstrap channel to
   `serviced`, re-attenuates the delivered descriptor to `CAP_XFER_ONCE` (the
   single reply send consumes it), and returns it. The login program installs
   it as the session leader's inherited lookup channel; the shell and its
   descendants resolve services through it at exactly their privilege level.

Two gates make the boundary exclusive:

- **`serviced` refuses direct minting on any ambient lookup channel** — even
  the SYSTEM ambient carry handed to `getty` is lookup-only for the mint
  operation. `login`/`su`/`sshd` hold no mint authority at all; if the agent is
  unreachable they simply carry no lookup channel (best-effort, never fatal).
- **The agent gates its callers on `SERVICE_RIGHTS_ADMIN`** — a right
  `serviced` stamps only on an ambient login-session lookup over a
  full-discovery channel, i.e. exactly the login family. An ordinary SYSTEM
  unit that connects to `system.authagent` and asks for a `{uid=0}` mint is
  refused `EPERM`; without this gate any managed unit could proxy itself an
  admin channel.

The trusted base for the session-mint decision is `{serviced, authagentd}` —
two components — instead of `{login, su, sshd}`. `sshd`'s
privilege-separated monitor forwards the minted descriptor one `SCM_RIGHTS`
hop to its session child, and only for the *authenticated* principal, never a
uid the untrusted child chose. Single-user mode is unaffected: `init` spawns
the recovery shell directly and the capability plane is not running, so a
`boot -s` root shell always works.

## Where uid still lives

Unix uids do not disappear — 5BSD is still a POSIX system. Files have owners,
processes have credentials, and the kernel enforces them. What changes is that
**the capability plane never derives *its* authority from a uid.** uids name
principals at the authentication boundary and protect the POSIX substrate;
services run under an unprivileged, non-root uid as defense in depth. Authority
above that boundary is capabilities, and only capabilities.

## See also

- [The MAC Capability Framework](mac-capability.md) — the kernel substrate,
  transfer controls, and descriptor types.
- [Capability Bundles](capability-bundles.md) — the bundle security model.
