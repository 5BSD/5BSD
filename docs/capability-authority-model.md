# Capability-authority model

Status: architecture spec / course-correction. Written before code. Supersedes
the authorization framing in [`service-discovery-model.md`](service-discovery-model.md),
[`lifecycle-capability-port-design.md`](lifecycle-capability-port-design.md), and
[`authority-control-abi-design.md`](authority-control-abi-design.md) wherever they
authorize by uid, socket path, PID, or signal.

## 0. What this is (and is not)

This is **not a rewrite of the system.** The capability *substrate* already
exists and is correct: the `mac_capability` kernel device, channel endpoints as
fd-capabilities, `cap_xfer`/`cap_clofork` attenuation of transfer, on-demand
capability acquisition by channel label, TrustedZFS capability-fds, capsicum
sandboxing, serviced, the
service plane, and the login→session delivery plumbing all stay.

This changes exactly **one layer: authorization** — *where authority comes
from.* Today authority is derived, in many places, from **ambient identity**: a
uid (`root may do X`), a socket pathname + `getpeereid`, a `getpid()==1` check,
or a signal. The thesis of this system is the opposite:

> **Authority is a held, unforgeable capability. To perform operation O on
> object X you must hold a capability that names (X, O). Nothing about your uid,
> your pathname, your PID, or a signal grants anything.**

The work is to move every authorization decision onto that rule, and to move the
*one* legitimate identity→capability translation into an explicit boundary.

## 1. The mint boundary (the seL4 acknowledgment)

Pure capability systems do not have "no authority anywhere" — they have a
**minimal, explicit place where authority is created**, and everything else is
derivation by delegation. Even seL4/KeyKOS say, at exactly one seam, *"this
principal may hold these capabilities."* We make that seam explicit and small:

1. **The kernel (`mac_capability` device)** — the ultimate TCB. It creates
   unforgeable endpoints and enforces that they cannot be fabricated, only
   received. All capabilities descend from the primordial endpoint.
2. **`capsule` (PID 1)** — holds the root capability at boot and
   delegates the initial caps: serviced's registry cap, each launched service's
   grant set (from its manifest), and the *session-mint* cap.
3. **The authentication boundary** — the single identity→capability translation.
   When a principal proves a credential (password, key, token), an
   **auth agent** holding the session-mint cap consults an explicit
   **principal→bundle policy** and delegates that principal's **capability
   bundle** to the new session. This is the seam. It is data-driven and lives in
   the TCB, not scattered as `uid==0` checks in services.

Everything above this boundary is pure: no service ever re-derives authority
from identity.

## 2. What a capability *is* here

A capability is a **channel endpoint bound at creation to `(object, rights)`.**
Holding the endpoint *is* the authority; using it *is* presenting the
capability. The peer (the service) maps the endpoint it received a request on to
its `(object, rights)` binding and acts — with **no ambient check.**

This is a thin addition to what `mac_capability` already provides. Four
operations, three of which largely exist:

- **Present** — send a request on the endpoint. The service resolves
  endpoint → `(object, rights)`; if `rights` permit the request's operation, it
  proceeds. *New:* the endpoint must carry an explicit `(object, rights)`
  binding the service can read (today the service instead reads `sender_uid`).
- **Delegate** — pass the endpoint to another holder (fd-passing / `SCM_RIGHTS`
  over a channel). *Exists:* governed by `cap_xfer` (`ONCE`/`NONE`/`UNLIMITED`).
- **Attenuate** — mint a weaker endpoint from a held one: fewer rights, or a
  narrower object. *Partly exists* for transfer/close (`cap_xfer`,
  `cap_clofork`); *new:* rights/object attenuation, so a holder can hand out a
  strictly lesser capability without the grantor's involvement.
- **Revoke** — invalidate an endpoint and, transitively, everything minted from
  it. *New:* a revocation primitive (generation/epoch on the object, or a
  revoker capability the grantor retains), so authority can be withdrawn.

The endpoint's binding and rights are enforced by the kernel + the granting
service, never inferred from the caller's identity.

## 3. Authentication → bundle

`login`, `su`, and `sshd` stop deciding authority themselves. They:

1. Authenticate the credential (unchanged — PAM/keys).
2. Ask the **auth agent** (holding the session-mint cap) for the authenticated
   **principal's bundle**. The agent applies the **principal→bundle policy**:
   which service capabilities, at which rights, this principal may hold.
3. Install the returned capabilities as inherited endpoints for the session
   leader; the shell and its descendants inherit them exactly as they inherit
   the ambient channel today.

The policy is where *"this user may have these capabilities"* is stated —
explicitly, once, in the TCB. A principal is still *named* by a POSIX identity
(a uid is a fine name), but the **mapping name → capabilities is policy, not a
hardcoded `uid==0` privilege.** Services never see the identity.

`principal_is_admin()` (root/wheel → SYSTEM) in `login.c` is the archetype of
what moves: it becomes a lookup in the auth policy ("what discovery + control
caps does principal P get"), not an inline uid test.

## 4. The authorization rule (the whole of it)

> A service performs an operation **iff** the endpoint the request arrived on
> carries a capability whose rights permit that operation. It never reads the
> caller's uid, gid, pathname, PID, or a signal to decide.

Consequences:
- A caller that lacks the capability doesn't get "permission denied" — the
  operation is **unreachable** (it holds no endpoint that offers it). Denial and
  non-existence look identical, which is the correct information posture.
- "Read-only vs privileged" is expressed as **rights on the capability**
  (`read` vs `admin`), not as "root vs non-root".
- Delegation gives **least privilege without root**: an unprivileged operator
  can hold a `serviced:admin` capability and start/stop services while being uid
  `nobody`. This is the entire point of the model.

## 5. The domain model, reinterpreted

The SYSTEM / USER / CONTROL "domains" are not discarded — they are recognized
for what they already are: **discovery capabilities of differing breadth.** A
lookup channel *is* a capability; today its breadth is chosen by uid at mint
time. Under this model:

- The auth bundle includes a **discovery capability** whose scope is set by the
  principal→bundle policy (broad for an admin principal, a narrow allow-list for
  an ordinary one) — **not** by `uid==0 || wheel` hardcoded in `login`.
- "CONTROL" stops being a reserved name-suffix trick. Control access is simply
  *holding a control capability* for the target service; the service's control
  operations live behind an endpoint whose rights include `admin`. No hidden
  names, no separate domain enum needed for it.

So the domain code already written is not wasted — it becomes "discovery caps,"
minted at the auth boundary by policy. The `SVC_DOMAIN_CONTROL` machinery and
the `.Control` convention are **retired** in favor of held control capabilities.

## 6. Control planes under the model

- **serviced control** — serviced hands out a `serviced:admin` capability
  (endpoint with `admin` rights) as part of an admin principal's bundle.
  `servicectl` presents it; serviced honors the op because the endpoint carries
  `admin`, with **no uid check and no socket.** Read-only status is a separate,
  broadly-granted capability (or a lesser right on the same endpoint).
- **tzfsd control** — identical shape: a `tzfsd:admin` capability.
- **lifecycle** — a `lifecycle` capability, held by admin bundles and served by
  the **spine** (`capsule`) so it survives serviced's death. `reboot`
  presents it; there is no `getpid()==1` authority check (the capability *is*
  the authority) and **no signal path** for authority. `reboot(2)` remains only
  as the kernel-level escape hatch, not an authorization mechanism.
- **session provisioning** — the sshd monitor holds a **session-mint
  capability** (delegated at sshd launch) and presents it to mint a session for
  the authenticated principal. "root speaks for uid X" becomes "the holder of
  the session-mint cap mints for principal X" — the same auth agent seam as §3.

All three getpeereid sockets are then deletable, because nothing authenticates a
peer by pathname or uid any longer.

> **Status (2026-08-30): all three getpeereid control sockets are now deleted.**
> The authorityd admin socket and serviced's general control socket were retired
> earlier; the last one — serviced's control socket, whose only remaining job was
> ssh session provisioning — is gone as of this milestone. Session provisioning
> no longer dials a socket: the sshd listener mints a **private per-connection
> SYSTEM lookup channel** over the ambient channel it inherits from rc, threads
> it through its re-exec into `sshd-session`, and the privileged monitor mints
> the session's uid-scoped channel over it with `service_mint_session_domain()` —
> exactly as `login(1)`/`su(1)` do over their getty-inherited SYSTEM channel.
> Holding a SYSTEM channel *is* the authority, replacing the `getpeereid(2)` uid
> attestation. serviced binds no control socket at all; `servicectl` and
> `authorityctl` reach the control/lifecycle planes only over minted capability
> channels (`system.serviced` / `system.lifecycle`).

## 7. Inventory: current ambient authority → its capability replacement

| # | Current (ambient authority) | Replacement (held capability) |
|---|---|---|
| 1 | `bsdnotify` root bypass (`sender_uid==0`) | present a topic capability with `publish`/`subscribe` rights |
| 2 | `traced` root bypass for the DTrace fd | present a `trace:raw` capability |
| 3 | serviced `sctl` `euid` checks | present `serviced:admin` (mutations) / `serviced:read` |
| 4 | authorityd control `euid` checks | present `lifecycle` capability |
| 5 | getpeereid on 3 control sockets | endpoints presented over channels; sockets deleted |
| 6 | login mints SYSTEM by `uid==0 \|\| wheel` | auth policy delegates a discovery capability by principal |
| 7 | USER domain keyed by uid | discovery capability scoped by policy, not indexed by uid |
| 8 | `provision-session` gated by root | present the session-mint capability |
| 9 | lifecycle gated by `getpid()==1` | present the `lifecycle` capability |
| 10 | shielded-signal reboot authority | removed; capability presentation only (`reboot(2)` = kernel escape) |
| 11 | services' authority entangled with their run-uid | authority = held caps; run-uid is defense-in-depth only |
| 12 | `.Control` reserved-name domain | held control capability; convention retired |

The bsdnotify and traced "root-bypass" fixes committed earlier are correct for
the *old* model and on the *wrong side* of this one; items 1–2 revert to
capability presentation in the migration.

## 8. Where uid / POSIX legitimately survives

Not everything uid is a violation — only uid *as authority above the mint
boundary*. These remain:

- **The kernel POSIX substrate** — file ownership, `cred`, syscalls. The
  capability plane simply never derives *its* authority from it.
- **Principal naming at the auth boundary** — a principal may be named by a uid;
  the policy maps that name to capabilities. Naming ≠ authority.
- **`reboot(2)` and other kernel syscalls** — the kernel is the TCB; syscall
  gating is the mint, not ambient service authority.
- **Compatibility shims during migration** — explicitly temporary, removed as
  each service converts.

## 9. Migration (bootable at every step)

Each phase leaves the machine bootable and rebootable. Early phases make the
policy *reproduce today's behavior* so nothing breaks while the mechanism moves.

- **P0 — primitive.** Add the `(object, rights)` binding, attenuation, and the
  revocation epoch to **libservice** — no kernel change is needed, because
  decision 1 keeps rights service-side and the kernel already provides
  unforgeable, `cap_xfer`-attenuated endpoints. Concretely: `service_rights_t`
  (a per-service bitmask) with `service_rights_allow`/`service_rights_attenuate`
  (monotone), a `rights` field on `struct service_identity` (the object is its
  `service_name`), and `service_epoch_t` + `service_epoch_live` for revocation.
  Behavior-neutral: a resolved name grants `SERVICE_RIGHTS_ALL`, so a service
  that ignores rights, or checks them, behaves exactly as before. No caller
  scopes rights yet. *(Done: rights delivered per-grant over the wire arrives in
  P3; caretaker-based selective revocation composes on the epoch primitive.)*
- **P1 — auth boundary.** Two sub-steps.
  - **P1a — the seam (done).** Collapse the triplicated inline admin test into a
    single `service_principal_is_admin()` in libservice that `login`/`su` call;
    the body is still the historical rule (root or wheel), so behavior is
    identical, but the principal→bundle decision now lives in one place ready
    for policy to plug in. VM-verified no-op: root→SYSTEM, a non-wheel user via
    `su`→USER. (`sshd`'s decision is now sshd-side too: the monitor calls the
    same `capbundle_principal_is_admin()` and mints the matching scope over its
    inherited SYSTEM channel — the `domain_provision_session` socket backend was
    removed with the control socket.)
  - **P1b — explicit policy (done).** The decision now reads an explicit UCL
    principal→bundle policy at `/Capabilities/Config/principal-policy.ucl`
    (`capbundle_principal_is_admin` in libcapbundle, which owns UCL); login/su
    call it (the libservice P1a seam is retired). `admin { uids=[…] groups=[…] }`
    names the admin principals; an absent or invalid policy falls back to the
    historical root/wheel rule, so it is behavior-neutral by default. Login is
    not PID 1, so decision-4's hard "not in PID 1" constraint holds; moving the
    read (and the session-mint cap) into an isolated auth-agent daemon is P1c.
    VM-verified: no policy → root=SYSTEM, testu=USER; a policy granting testu
    admin flips testu to SYSTEM (it resolves system.Network, which USER denies).
  - **P1c — isolated agent (todo).** Move the policy read and the session-mint
    capability into a small capsicum-sandboxed auth-agent daemon that
    `capsule` delegates to; login/su ask it over a channel. The call
    sites do not change.
- **P-rights (done, prerequisite for P2).** The grant now carries a rights word:
  serviced stamps `svc_new_client_msg.rights` at the broker (`SVC_RIGHTS_ALL`
  until a policy scopes it) and libservice delivers it as `identity.rights`.
  This is the mechanism P2 reads; landed early because a service cannot check
  granted rights until grants carry them. VM-verified behavior-neutral (every
  `system.*` still brokers). The *source* of scoped (non-ALL) rights is the
  auth policy (P1b) and, ultimately, a presented capability.
- **P2 — one service converts (done).** `bsdnotify` first (it is the model):
  the per-operation `sender->uid != 0` gate is gone. serviced stamps
  `SVC_RIGHTS_ADMIN` (bit 63) onto a grant **only** for an ambient login-session
  lookup (`requester == NULL`) on a `SVC_DOMAIN_SYSTEM` channel; bsdnotify
  carries that right onto the session (through the internal `router_control`
  handshake into `router_session.rights`) and authorizes each administrative
  operation with `service_rights_allow(session->rights, SERVICE_RIGHTS_ADMIN)`
  instead of the caller's uid. Every non-administrative publish/subscribe still
  runs through the per-client topic policy, unchanged. Behavior for the common
  paths is neutral (a root shell's `notifyctl` still bypasses topic policy via
  the ADMIN right; a non-root session and a resolving *service* are both bound by
  policy). The one deliberate tightening: a root-running **daemon** can no longer
  perform an unpolicied administrative notify operation on the strength of its
  uid — administrative authority now rides the login-minted capability, which is
  exactly the property P2 exists to establish. Rights are minted by serviced and
  ride the trusted service↔serviced control channel, never a client message, so
  a client cannot forge the ADMIN right.  VM-validated on a fresh image
  (2026-08-30): a root session (SYSTEM + ambient, holding ADMIN) publishes to an
  unpolicied topic (RC 0, bypass); a `nobody` session (USER domain, no ADMIN)
  resolves `system.Notify` but is denied that same publish (EACCES) — the held
  right, not the uid, decides. Boot is clean (capsule PID 1 + serviced +
  ambient lookup channel all come up).
- **P3 — control planes (serviced: done, VM-validated).** serviced and tzfsd
  control become presented `:admin` capabilities (rights on the grant); the
  getpeereid sockets are now retired entirely — serviced's last one, along with
  the `PROVISION_SESSION` op it carried, is gone as of this milestone.

  *Implemented + validated (serviced), 2026-08-30.* serviced self-serves
  `system.serviced`; `servicectl` resolves it over the ambient plane and uses it
  as its **only** transport — there is no socket fallback, so a caller with no
  ambient channel simply errors. Fresh-image proof: with **no control socket at
  all**, a root `servicectl status`/`reload` still succeed (capability path
  only); a `nobody` session cannot resolve `system.serviced` (USER domain →
  ENOENT) and is denied. The socket — admin ops and `PROVISION_SESSION` alike —
  is deleted; its getpeereid uid attestation is fully replaced by the
  SYSTEM-channel grant.

  *Settled design (serviced).* serviced self-serves a plain SYSTEM name
  `system.serviced` — **not** a `.Control` name (the `.Control` convention is a
  uid-derived-domain relic retired in P5; routing new control code through it
  would only be deleted again, twice-editing the spine). This reuses P2's mint
  verbatim: `naming_lookup` already grants `SVC_RIGHTS_ADMIN` only to an ambient
  (`requester == NULL`) lookup on a `SVC_DOMAIN_SYSTEM` channel — i.e. an admin
  login session — so a root shell's `servicectl` receives an ADMIN-bearing
  channel while a USER session and any service-to-service lookup do not. The
  lookup path **forks** for this one name: after minting the channel pair and
  computing rights, serviced keeps the provider end and adopts it into its own
  kqueue as an in-process control connection carrying those rights (rather than
  `SVC_OP_NEW_CLIENT`-notifying an external provider), and returns the client end
  to the caller as usual. The in-process handler runs the existing sctl dispatch
  but gates `RELOAD`/`START`/`STOP` on
  `service_rights_allow(rights, SERVICE_RIGHTS_ADMIN)` instead of the
  `getpeereid` euid; `STATUS`/`SERVICES` need no admin right. There is no more
  fd-passing control op: `PROVISION_SESSION` (the old kernel-attested login/sshd
  bridge) is gone, session provisioning having moved to a minted per-connection
  SYSTEM channel, so the capability path is a clean fd-less request→reply message
  exchange (no SCM_RIGHTS). The rollout is **complete, not dual-path**:
  `servicectl` resolves `system.serviced` over the ambient plane and has no
  socket fallback, and serviced binds no control socket at all. tzfsd's socket is
  the separate filesystem-socket→discovery concern, tracked independently.
- **P4 — lifecycle + PID-1 minimization.**

  *Principle: serviced is the sole process manager.* Every long-lived daemon is
  spawned and supervised by serviced. PID 1 (`capsule`) supervises exactly
  one child — serviced — and otherwise does only the irreducible init(8) duties
  (getty on the login ttys with the ambient-channel carry, single-user shell,
  reroot, `/etc/rc.shutdown`+`/etc/rc.final` ordering, the plane-free fallback to
  stock init). No daemon is special-cased under PID 1.

  *P4a — tzfsd under serviced (done first; subsumes the old "tzfsd socket" item).*
  Today authorityd (PID 1) `posix_spawn`s tzfsd lazily on the first storage mint —
  the lone exception to the principle. There is no real bootstrap-ordering reason
  for it: serviced reads its static bundle catalog + config from a ZFS-auto-mounted
  `/Capabilities` with no tzfsd involvement (proven at boot — serviced loads all
  bundles and runs `/etc/rc` before tzfsd ever starts; `bundle_registry.c` calls
  this out explicitly as "pre-storage bootstrap state"). tzfsd is needed only for
  *runtime* storage mints. So tzfsd becomes an ordinary serviced-supervised unit:
  a `Storage.cap` bundle (`program = /usr/sbin/tzfsd`, `user = root`, `boot`, no
  `ipc`) that serviced launches in the foreground; readiness is the NOTE_CAPMODE
  boundary serviced already observes (tzfsd `cap_enter`s), so no service-protocol
  rewrite is required — tzfsd only learns to stay foreground when serviced-launched
  (detects `SERVICE_UNIT_DIR_ENV`). authorityd drops the `posix_spawn` and just
  connects (with its existing retry) to the now serviced-managed tzfsd. The
  `/Capabilities` design does **not** change — the static catalog was already
  tzfsd-independent, so no pull-back is needed. Retiring tzfsd's *filesystem
  socket* in favour of a discovery-brokered channel is a later, separable step
  (it is a request/reply + fd-passing protocol migration); P4a first moves the
  *ownership* of the process to serviced.

  *P4b — lifecycle capability.* A `lifecycle` capability served by the spine;
  `reboot`/`halt`/`shutdown` present it; delete the authorityd socket and the
  signal-authority path; `reboot(2)` stays as the kernel escape. The serviced
  `PROVISION_SESSION` login/sshd bridge has already been re-homed onto a minted
  per-connection SYSTEM channel and the serviced socket retired whole (done this
  milestone); the authorityd control socket is likewise gone.
- **P5 — retire uid-derived domains.** Discovery becomes an auth-minted
  capability; remove `principal_is_admin`-style uid tests and the `.Control`
  convention. `traced` and the remaining services convert to presented caps.
- **P6 — revocation + attenuation in anger.** Exercise delegation to non-root
  operators, attenuated caps, and revocation, closing the "least privilege
  without root" story.
- **P7 — cleanup.** After the mechanism is complete: remove the dead code left
  behind in every file the migration touched (superseded uid gates, transitional
  shims, retired symbols, stale comments/markers); split any file that grew too
  large into smaller, single-purpose files where it improves clarity; and do a
  final documentation sweep — the spec, the design docs, the book, the man
  pages, and code comments — so the docs describe the finished capability model,
  not the migration.

### Testing discipline

Each phase is validated on a **fresh** VM image built by a clean
`installworld` + `distribution` + `installkernel` of the current tree (not by
hand-staging individual binaries onto a mutated guest root, which drifts and can
mask a stale or mismatched component). After a major change, rebuild the image
from scratch and **re-run the earlier phases' checks as regression** — SYSTEM
resolves all `system.*`, a USER session narrows to its allow-list, the default
principal policy reproduces root/wheel — before moving on.

## 10. Keep / change ledger (from recent work)

**Keep:** mac_capability channels; fd-cap inheritance at a fixed fd; on-demand
activation; ambient-channel *delivery*; on-demand capability acquisition by
channel label; TrustedZFS cap-fds; capsicum. **Removed:** the manifest
`capabilities {}` block (caps are now acquired on demand, by name, never
declared or minted at launch). **Change:** every
`sender_uid`/`euid`/`getpeereid`/`getpid()==1`/
signal authorization → capability presentation; uid-derived domain minting →
policy-minted discovery caps; `.Control` convention → held control caps.
**Add:** the `(object, rights)` binding, attenuation, revocation, the auth agent
+ principal→bundle policy.

## 11. Decisions (locked)

These are decided; they drive P0 onward. Each records the choice, the reason,
and the trade-off accepted.

1. **Representation — endpoint-bound `(object, rights)`.** A capability *is* a
   channel endpoint; the granting service records `endpoint → (object, rights)`
   in its per-connection state. The kernel already makes endpoints unforgeable,
   fd-passed, and `cap_xfer`-attenuated — no new crypto, keys, expiry, or replay
   window. Rejected: sealed/bearer tokens, which reintroduce copyable data,
   revocation lists, and a validator; pure-cap systems use kernel-enforced caps,
   and tokens are for when a kernel mechanism is absent. *Trade-off:* no offline
   delegation — irrelevant, since fd-passing over channels **is** delegation.

2. **Rights — per-operation bits, small and per-service** (Capsicum-shaped). Each
   service defines a tiny set of operation right bits; attenuation is a subset
   (clear a bit → strictly, monotonically weaker); `admin` is sugar for all
   bits. Rejected: a `read<write<admin` lattice — too coarse for real least
   privilege (bsdnotify's publish/subscribe/state-set/timer are not a line).
   This mirrors the in-kernel `cap_rights_t` model. *Trade-off:* each service
   states its rights explicitly — which is the intent.

3. **Revocation — object-epoch bump; caretakers for selective.** Each object
   carries a generation the service checks on present; bumping it invalidates
   all endpoints of that epoch at once (cheap, universal, coarse). For selective
   ("revoke Alice, not Bob") use a **caretaker**: hand out a cap to a forwarder
   the grantor controls and drop the forwarder to revoke — composed from the
   primitives, no kernel mechanism. Rejected: a general per-delegation
   revocation tree (the classic over-engineering trap). *Trade-off:* epoch is
   coarse and caretakers cost a hop; together they cover real needs.

4. **Auth agent — its own minimal, capsicum-sandboxed daemon, not
   `capsule`.** It parses untrusted input (login credentials) and the
   policy, which must never live in PID 1 — a credential-parsing bug must not
   wedge the spine. `capsule` holds the root cap and *delegates* only the
   session-mint cap to the auth agent. Login runs while the system is up, so the
   agent may be serviced/spine-launched (unlike lifecycle, it needs no
   serviced-death survival). Precedent: KeyKOS/EROS keep the account manager out
   of the kernel. *Trade-off:* one more component — worth it to keep PID 1 tiny.

5. **Policy — UCL, symmetric with manifests, edited only via a `policy-admin`
   capability.** The principal→bundle policy is UCL (the existing manifest/config
   language); a principal entry is a manifest grant-list inverted ("what a
   *principal* is granted" vs a manifest's "what a *service* is granted"). It
   lives in the capability config tree on TrustedZFS cap-fd storage. Editing it
   is itself a capability (`policy-admin`, in the bootstrap bundle) — never "root
   with an editor," which would be the ambient authority we are removing. A
   tight-perm file is the migration shim; capability-gated edits are the end
   state. *Trade-off:* the meta-object must be protected — a small, deliberate
   surface.

6. **POSIX-compat — uid is a name and a substrate mechanism; it authorizes
   nothing above the auth agent.** The *only* uid→capability translation is the
   auth agent (§1). Everywhere else the capability plane MUST NOT read
   `getuid`/`geteuid`/`getpeereid`/`cred` to authorize — enforced as a review
   invariant and a lint over the authorization paths. POSIX file ownership stays
   for the substrate; capability objects are reached by held caps (storage
   already does this via TrustedZFS cap-fds). Services run under an
   unprivileged, **non-zero** uid + capsicum, so uid is defense-in-depth, never
   authority, and a stray uid check cannot be coerced into ambient root.
   *Trade-off:* a belt-and-suspenders period during migration; the end state
   reads zero uids in authorization.

### Coherence

The six compose on the existing substrate: kernel-enforced endpoint
capabilities + Capsicum-style per-op rights + epoch revocation (caretakers for
selective) + a small sandboxed auth agent holding the session-mint cap + a UCL
principal-policy symmetric with manifests and capability-gated + uid demoted to
a pure name with a single translation point. No new trust-management subsystem
is required — which is why this is an evolution of the authorization layer, not
a rewrite.

## 12. Non-goals

- Not removing uids from the POSIX substrate (file ownership, `cred`).
- Not eliminating the kernel/syscall TCB (that is the mint, not ambient
  authority).
- Not a rewrite of serviced, the daemons, or the channel machinery — only their
  authorization decisions and the auth boundary.
- Not a flag day: every phase boots and reboots.
