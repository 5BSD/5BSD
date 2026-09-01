# Lifecycle control: from a getpeereid socket to a capability port

Status: design note / proposal. Extends the "move to an explicit minted
lifecycle capability token" TODO in
[`authority-control-abi-design.md`](authority-control-abi-design.md).

> **Superseded by [`capability-authority-model.md`](capability-authority-model.md).**
> The end state is not a separate CONTROL *domain* / `.Control` name reached by
> a domain-scoped channel, but a **`lifecycle` capability** — an endpoint with
> lifecycle rights, held by an admin principal's bundle and served by the spine
> (`authority-init`) so it survives serviced's death. `reboot` presents the
> capability; there is no `getpid()==1` authority check and no signal-authority
> path (`reboot(2)` remains only as the kernel escape). The socket-inventory and
> serviced-death constraints below are still correct; the *replacement
> mechanism* is a held capability, not a control domain.

## The gap

The lifecycle control ABI (reboot/halt/poweroff/single-user/reroot/rescan/
catatonia) is implemented and correct, but its transport is a **UNIX-domain
socket authenticated by `getpeereid()`**:

- `authorityd`: `/var/run/authorityd.sock`, `socket(PF_LOCAL)` +
  `getpeereid()` (control.c).
- `serviced`: the same pattern for `servicectl` (sctl.c).

This is the one place the plane still authenticates a peer by **uid + pathname**
rather than by a **held capability**. It contradicts the capability model
("authenticate the peer's capability, never its pathname") and it is a literal
`PF_LOCAL` socket in a system that otherwise moved IPC to mac_capability
channels. The design doc already names it a placeholder; this note makes the
replacement concrete.

### Full inventory of 5BSD control sockets

Named, listening `PF_LOCAL` control sockets — the ones to replace:

| Daemon | Socket | Control clients | Serviced-independent? |
|--------|--------|-----------------|-----------------------|
| `authorityd` | `/var/run/authorityd.sock` (control.c) | `reboot(8)`/`halt`/`shutdown`/`authorityctl` | **Yes — required** (survives shutdown) |
| `serviced` | `/var/run/serviced.sock` (sctl.c) | `servicectl` | No |
| `tzfsd` | root-only `listen()` (tzfsd.c) | `tzfsctl`, authorityd/serviced peers | No |

**Not control sockets (leave as-is):** `serviced/activation.c` is socket
*activation* — serviced binds listeners *for* socket-activated services (an
inetd-style feature), not its own control plane. `logd/{logcmp,storage}.c`,
`lib/liblogcmp/logcmp_wakeup.c`, and `auditbrokerd/auditcmp.c` use
`socketpair()` for private internal fd-pairs / self-pipes — not exposed
endpoints. `localnetwork/networkcmp.c` and `traced/tracecmp.c` socket code is
the provider handling *client data* sockets (their actual function).

## The model: control is a name in a separate CONTROL domain — no sockets

The goal is **no control sockets at all.** A daemon's control/admin interface
becomes an ordinary capability service **name**, registered in a dedicated
**CONTROL domain**, resolvable only by a caller that holds a CONTROL-domain
lookup channel. Nothing binds a `PF_LOCAL` path; nothing calls `getpeereid`.

Two enabling facts already exist, plus one new domain:

- **Multiple names per program.** A program may advertise up to
  `SERVICED_MAX_PROVIDES` (8) names; `service_provider_expose(p, name,
  &listener)` returns a **distinct `service_listener` per name**, so accepting
  on the control listener *is* the demux — a control connection is
  self-identifying, no per-message tagging.
- **Provider's choice of shape.** The control service can be a **second name on
  the same program** (multi-service), or a **separate control program**
  entirely — whichever the author wants. The plane does not care; it only sees
  a name and a domain.
- **New: a CONTROL (admin) domain.** Today `domain.c` has `SVC_DOMAIN_SYSTEM`
  (resolves everything) and `SVC_DOMAIN_USER` (an allow-list). Add
  `SVC_DOMAIN_CONTROL`: a caller resolves a control name **only** through a
  CONTROL-domain lookup channel. That channel is the capability — held by
  admin tools (`servicectl`/`authorityctl`/`tzfsctl`) and privileged admin
  sessions, minted for them the way the §21 ambient lookup channel is minted,
  and delivered the same way (getty→login/su/sshd). Authorization is "you hold
  a CONTROL-domain channel," never a uid or a socket path.

So the socket inventory collapses to name registrations:

- `serviced` registers `system.Service` (SYSTEM/USER as today) **and**
  `service.Control` (CONTROL domain); `servicectl` resolves `service.Control`
  over its CONTROL channel. `/var/run/serviced.sock` is deleted.
- `tzfsd` registers `system.Filesystem` **and** `storage.Control` (CONTROL);
  `tzfsctl` uses it. The `listen()` socket is deleted.
- Either daemon may instead ship a *separate* small control program that
  registers the CONTROL name and relays to the main daemon over a private
  channel — provider's call.

`serviced` and `tzfsd` control names are brokered by serviced's naming, which is
fine — those tools only run while the system is up.

`authorityd`'s **lifecycle** control is the one name that must resolve **after
serviced is gone** (shutdown tears serviced down). So the CONTROL domain is
served by the **spine**: `authority-init` owns the CONTROL-domain registry for
lifecycle (`lifecycle.Control`) and serves it from its own event loop, and the
CONTROL-domain lookup channel an admin session holds is spine-minted — so
`reboot(8)` resolves `lifecycle.Control` with zero serviced dependency. Live-
system control names (serviced/tzfsd) can be delegated into the same CONTROL
domain by serviced; lifecycle stays spine-served. One domain, two servers, no
sockets.

## The hard constraint: serviced-independence

Lifecycle control **must survive `serviced`'s death** — during shutdown
serviced is torn down, so the reboot path cannot be brokered by serviced's
naming/lookup. This is why the current endpoint is a *direct* authorityd
socket and not a serviced-registered service, and it is the property any
replacement must preserve:

> The reboot capability must be reachable from a privileged session using only
> state owned by the spine (authority-init), never by serviced.

This rules out "just expose `system.Lifecycle` as a normal capability service"
— that goes through serviced naming, which is gone at shutdown.

## Proposed design

### 1. Add `SVC_DOMAIN_CONTROL` to the naming scope

`domain.c` gains a third domain kind. `svc_domain_resolves()`:

- `SVC_DOMAIN_SYSTEM` — resolves SYSTEM/USER names (as today); does **not**
  resolve CONTROL names.
- `SVC_DOMAIN_USER` — allow-list only (as today).
- `SVC_DOMAIN_CONTROL` — resolves **only** names registered as CONTROL.

A name's domain is a property the provider declares at registration
(`service_provider_expose(..., SVC_DOMAIN_CONTROL)` / a `domain = control`
manifest attribute on the provides entry). Control names are thus invisible to
every ordinary (SYSTEM/USER) lookup — the separation is structural, not a flag
on a shared namespace.

### 2. The CONTROL-domain lookup channel *is* the capability

A caller reaches CONTROL names only through a **CONTROL-domain lookup channel**,
minted and delivered exactly like the §21 ambient lookup channel
(getty→login/su/sshd), but scoped to `SVC_DOMAIN_CONTROL` and handed only to
privileged admin sessions. Holding that channel is the authorization — there is
no `getpeereid`, no uid check, no path. Optionally backstopped by a
`SYS_GATE_LIFECYCLE`/`SYS_GATE_ADMIN` system gate for defence in depth.

`reboot(8)` then does the ordinary two-step plane dance — resolve
`lifecycle.Control` over its CONTROL channel, connect, send the existing
`CTL_OP_*` — with **no** `/var/run/authorityd.sock`.

### 3. Who serves the CONTROL domain

- **Live-system control** (`service.Control`, `storage.Control`): registered by
  `serviced`/`tzfsd` and brokered by serviced's naming, like any service. Fine
  — those tools only run while up.
- **Lifecycle** (`lifecycle.Control`): served by the **spine**. `authority-init`
  keeps a tiny CONTROL registry for its own lifecycle name and answers lookups
  on the spine-minted CONTROL channel from its own event loop, so `reboot(8)`
  resolves it with zero serviced dependency and it survives shutdown.

One CONTROL domain, two servers (serviced for live-system names, the spine for
lifecycle), zero sockets.

### 4. Migration (no flag day)

1. Add `SVC_DOMAIN_CONTROL` + the provider/manifest way to register a name in
   it; mint+deliver the CONTROL lookup channel to admin sessions; have
   `authority-init` serve `lifecycle.Control`.
2. Teach `reboot(8)`/`halt`/`shutdown`/`authorityctl`/`servicectl`/`tzfsctl` to
   prefer the CONTROL channel, falling back to the existing `getpeereid` socket,
   then (lifecycle only) the signal ABI. Non-fatal on each miss, as today.
3. Once proven, delete the `PF_LOCAL`+`getpeereid` sockets from `authorityd`,
   `serviced`, and `tzfsd`. The `reboot -q` → `reboot(2)` emergency hatch stays.

## Files touched

- `usr.sbin/serviced/domain.c` (+ `serviced.h`): `SVC_DOMAIN_CONTROL`, scope
  rules, CONTROL-channel minting.
- `lib/libservice`, `lib/libcapbundle`: provider/manifest way to declare a
  provides name's domain as CONTROL.
- `usr.sbin/authorityd/{control.c,authority_init.c}`: serve `lifecycle.Control`
  on a spine-minted CONTROL channel; retire the socket.
- `usr.bin/login`, `usr.bin/su`, `crypto/openssh/monitor*`: carry the CONTROL
  lookup channel to admin sessions (parallel to the §21 lookup fd).
- `sbin/reboot/reboot.c`, `sbin/shutdown`, `usr.sbin/{authorityctl,tzfsd}`,
  `usr.sbin/serviced/sctl.c`: resolve the CONTROL name; drop the sockets.

## Non-goals

- Not changing `CTL_OP_*` semantics or shutdown orchestration — only how the
  endpoint is named, scoped, and reached.
- Not making lifecycle serviced-brokered (would break shutdown).
- Not removing the `reboot(2)` emergency hatch.

## Open questions for review

1. CONTROL channel per session (matches §21) vs. acquired on demand from a
   well-known spine endpoint (no permanently-held fd).
2. Does the spine delegate live-system CONTROL names to serviced, or does each
   daemon register directly into the CONTROL domain with serviced only routing?
3. One CONTROL domain for everything, or distinguish `lifecycle` (spine) from
   `admin` (serviced) as sub-scopes? A single domain with two servers is
   simplest; sub-scopes buy finer least-privilege for admin tools.
