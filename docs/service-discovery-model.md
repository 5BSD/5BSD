# Service discovery and management model

Status: design, in implementation. Foundation (§21 ambient carry, §21.3 session
narrowing) committed (b56ab8808af). This document is the source of truth for the
service-discovery and domain *mechanism*.

> **Authorization superseded.** Wherever this document authorizes by uid, by a
> domain chosen from a uid (root/wheel → SYSTEM), or by a socket peer, that
> framing is replaced by [`capability-authority-model.md`](capability-authority-model.md):
> authority is a **held capability**, not a uid. The SYSTEM/USER/CONTROL domains
> are reinterpreted there as *discovery capabilities* minted by an explicit
> auth-boundary policy rather than by uid, and the `.Control` convention is
> retired in favor of held control capabilities. The channel/discovery
> *plumbing* below stands; the *authorization* does not.

## 1. Goals and truths

- **Every process must be able to discover other programs** — but not *all* of
  them: only what its principal is allowed to reach.
- Principals on the system: the **capability user**, **root**, and **regular
  users**. Users arriving via **login** and **ssh** need discovery access.
- **rc compatibility is required for now.** We provide alternatives to the rc
  management tools and ensure whatever rc does (scripts, services) stays
  controllable — covering `service(8)`'s functionality.
- The model may resemble **launchd** or diverge from it, but it must be
  **defensible and work today**.
- Some **system services must be unmanageable** by users (and even root) at
  runtime — you cannot unload core services. This must be *expressible*.
- Other services can be **loaded/unloaded** by cap bundle or rc, when authorized
  (root, or the owning user).
- **Get off filesystem sockets** — login and the shell pass the channel forward
  by inheritance, eliminating the control-socket exposure. This works for **all
  shells** because it is kernel fd inheritance, not a shell feature (identical to
  macOS's bootstrap port).

## 2. The core idea: two orthogonal axes

We previously conflated these; launchd keeps them separate and so must we.

1. **Discovery** — which services a principal can *find and connect to*. Scoped
   by principal (per-uid ACL, default-deny for users).
2. **Management** — which services a principal can *load / unload / start /
   stop*. Gated by the service's **management class** × the caller's principal.

Independent. The inherited channel is the authenticated carrier for both.

## 3. Principals and per-principal discovery

Discovery is a per-uid decision — "everything the user has access to", not one
global list:

| Principal | Discovery scope |
|---|---|
| system (plane, declared system bundles) | all services |
| root session | all services (root has access to everything) |
| regular user (login/ssh) | that user's accessible set (default-deny; services opt in per uid/group/policy) |
| capability user | per the launched bundle's declared domain |

A session channel carries `(uid, domain)`. Resolution asks "may uid U reach
service X?" — not "is X on the one allow-list." (Today: a 2-name global
allow-list; this must become a per-uid policy — see §10.1.)

## 4. Channels: the channel IS the authenticated principal

A serviced-minted channel is **unforgeable and non-transferable** (mac_capability).
serviced mints each session's channel bound to a recorded
`(uid, domain, rights)`. When any request arrives on a channel, serviced already
knows the principal — because it minted that exact channel for it. No
`SO_PEERCRED`, no file permissions, no uid re-check.

- Discovery and management **both ride the one inherited channel**.
- Authorization = "does the channel this arrived on carry the right to do X?"
- This is *stronger* than launchd (which re-checks uid): authority rides an
  unspoofable channel.

**Channel rights are distinct bits**: `discover` and `manage` are separate, so a
monitoring tool can hold a full-discovery / no-management channel.

## 5. Service management classes

A manifest declares a management class:

| Class | Who may load/unload/start/stop at runtime |
|---|---|
| **core** | **nobody** — only the boot/shutdown lifecycle. serviced, logd, the plane essentials. Root cannot unload these either. |
| **system** | **root only.** Base daemons + adopted rc.d services. |
| **user** | the **owning uid** (and root). Per-user agents. |

This is the field that expresses "users can't unload core services" (what Apple
does in practice). Composes with, but is distinct from, the launcher-`protect`
process-shield (which shields the *process*; this governs *management*).

Default class: **system** for base bundles is explicit (not inferred); a bundle
with no class declared and installed in a user scope defaults to **user**.

## 6. Uid-aware mint

The mint policy is keyed to the requesting principal:

- **root / wheel session → admin channel**: full discovery + system management.
  **core stays protected even from root.**
- **regular user → scoped channel**: their accessible discovery + management of
  their own (user-class) services only.

This fixes the wrinkle where root got a useless narrow channel. `discover` and
`manage` rights are set per the principal at mint time.

## 7. Session provisioning (login / sshd / su / sudo unified)

**A uid transition must re-provision, not re-narrow.** A process holding an
already-narrowed USER channel cannot mint (correctly — domains only narrow), so
su/sudo/setuid transitions must obtain a *fresh* channel for the target principal
via a privileged, authenticated path — exactly as login does from the getty
hop. Treat **login, sshd, su, sudo** as one **session-provisioning interface**,
not four ad-hoc carries. (This is how macOS re-associates a process with the
right per-uid bootstrap subset across a transition.)

Live breakage that motivates this: `su` currently EPERMs on the re-narrow and the
target session loses the channel (fails safe). See §11 test matrix and the
breakage-hunt findings.

**Modified-software inventory (the takeover surface).** Injecting the channel
required patching a specific set of base/third-party programs — PID 1 plus every
login/session/batch entry point (`capsule`, `login`, `su`, `sshd`/OpenSSH,
`cron`, `atrun`; `getty` inherits only). This set is exactly what a downstream
merge or FreeBSD rebase must carry forward, or the plane silently stops reaching
sessions. The per-program table (files touched, what each injects, why it's core)
lives in [`service-plane-review-brief.md` §2a](service-plane-review-brief.md).

## 8. rc compatibility and covering service(8)

- serviced **adopts rc.d services as `SVC_KIND_RC` units** (supervised;
  class=system). Scaffolding already exists (`rc_ingest_test`). An importer reads
  a curated rc.d set, creates units, and de-dups with `/etc/rc` so nothing
  double-starts.
- **`servicectl` reaches `service(8)` parity**: start/stop/restart/status/enable/
  disable, driving serviced. `service` becomes a thin shim.
- Un-adopted rc services keep running via the shrinking `/etc/rc`.

## 9. Eliminating the filesystem control socket

Move all management ops onto the inherited channel, authorized by the minting
principal (§4). The `SERVICED_CTL_SOCK` macro is now deleted. `servicectl` uses
the ambient channel login/ssh passed forward. **Sequenced last** — only after
§5/§6 prove the channel authz, so admin control is never lost mid-migration.

## 10. What must be built

1. **Per-uid discovery policy** (replace the 2-name global allow-list); domain
   carries uid; resolver consults policy. (§3)
2. **Management-class manifest field** `core|system|user` + parse/verify/enforce.
   (§5)
3. **Uid-aware mint** + `discover`/`manage` as distinct channel rights. (§6)
4. **Unified session provisioning** for login/sshd/su/sudo. (§7)
5. **rc adoption** + `servicectl` = `service(8)`. (§8)
6. **Delete the control socket**; management over the authenticated channel. (§9)

Ordering: 2 → 3 → 4 → 5 → 6 (1 folded into 3).

**Landed (clean-VM validated):** item 2 (management class, 5e03d10b112); the D1
identity handshake + cron/atrun/su fd-hygiene (51957a0d918); item 3 uid-aware
mint — root/wheel get admin (SYSTEM) discovery, escalation-guarded (3015486f3f5),
which also fixed su re-provision *from an admin session*. Foundation §21 carry
(b56ab8808af). **Remaining:** item 4 for the network path (sshd) and the
non-admin transition (a regular user's su/sudo still cannot re-provision — needs a
privileged provisioning path); item 6 (delete the control socket). **Item 5 rc
adoption landed** as the curated `cron` proof (832152c015d): serviced adopts cron
as a supervised SVC_KIND_RC unit, de-duped from /etc/rc (cron_enable=NO +
onestart), `servicectl restart` added; acceptance-validated (8/8 plane, single
cron, stop/start/restart, console + ssh login, services usable). The RC stop path
was fixed to use `service <label> onestop` (an rc daemon detaches, so pdkill of
the start-wrapper never stopped it). Follow-ups: widen the allow-list beyond cron,
and a service->servicectl shim.

**Item 4 (session provisioning) landed** (1dc6aaa329e): sshd now provisions a
per-uid ambient channel over serviced's getpeereid-authenticated control socket
(root-only, scope-by-target-uid, CAP_XFER_ONCE). Validated: over ssh
`SERVICE_LOOKUP_FD` is populated (was empty); console/su/cron/8-8-plane
unregressed. Non-root provisioning refused (EPERM), unit-tested. login/su keep
the getty-inheritance path (unified backend available for later migration).

**Item 6 resolved as KEEP, not delete.** The security analysis found the control
socket already authenticates with getpeereid(3) — the correct unforgeable
userspace peer-credential primitive (mac_capability peer-cred is kernel-only). It
is root-only, 0770, on a private tmpfs. Deleting it would remove the one userspace
attested-peer-cred primitive and require a more complex kernel service for NO
security gain, and it is now MORE central (the provisioning anchor). So the socket
is kept and hardened rather than removed. Physical removal is a surface-vs-
complexity call for later, not a security improvement.

## Descriptor delivery model: single transfer, sender closes

The rule for handing a channel descriptor across processes is: **do not
pre-lock it; each program that sends it onward closes (or locks) its own copy
once the send completes, and the final holder simply keeps it.** No multi-hop
transfer budget is minted at the source — that was a wrong turn. The old
two-hop `TWICE` transfer budget has since been removed entirely; the transfer
lattice is now `UNLIMITED > ONCE > NONE` with per-hop attenuation, and an
`ONCE` send is a single hop that leaves both ends at `NONE`.

Concretely for ssh session provisioning (serviced → sshd's privileged monitor →
the user's session child, `mm_send_fd` like the pty):
- **serviced** mints the channel with full (default) transfer authority and,
  after the SCM_RIGHTS send, closes its own copy (`sctl.c`: `fd_passed`,
  `close(pass_fd)`).
- **the monitor** (an in-between relay) receives it, sends it to the child, then
  closes its own copy — it is done.
- **the session child** (the leaf) installs it and holds it; it does not send it
  onward, so it does not lock it.
Fork inheritance by the session's descendants is `CAP_CLOFORK_UNLOCKED`, a
separate axis from SCM_RIGHTS transfer. (The console/su mint path already
delivers a channel that is exhausted after its single hop; same end, sender
side.)

## Roadmap — next steps (captured 2026-08-28)

Everything discussed this session, so we don't lose context. Ordered.

### 0. Quality pass (in progress) — before anything else
- Synthesize the four adversarial reviews (auth/provisioning, domain/mint/
  escalation/D1, fd-hygiene/non-fatal, Phase-4-launch/rc/mgmt); fix the real,
  verified bugs; re-validate in a clean VM; commit.
- (Done.) The `domain_provision_session` backend and `sctl.c` provisioning path
  have since been removed entirely along with the control socket, so the stale
  `CAP_XFER_ONCE` comments they carried are gone with them.
- Trim verbose comments across this session's code to concise KNF density.
- The former `naming.c` two-hop `TWICE` worker handoff has been
  removed; the model is per-hop attenuation (`ONCE` is a single hop), already in
  line with the single-transfer / sender-closes rule.
- Review design notes to weigh: over-channel mint trusts login/su to pass the
  correct domain (socket path derives it from the target uid — asymmetry);
  `SVC_DOMAIN_SYSTEM == 0` is fail-open on zero-init (latent).

### 0a. Deferred low-severity review findings (tracked, not yet fixed)
- **E** `principal_is_admin`→`getgrouplist` can block on a slow NSS backend in the
  post-auth login/su child (no watchdog). Fine for local `files`; bound or note.
- **F** cron's mailer runs in the never-dropped middle process, keeping the SYSTEM
  channel + `SERVICE_LOOKUP_FD` — system→system (not a uid-transition leak), but a
  defense-in-depth gap vs atrun (which unset+closefrom before its mailer).
- **G** a `core`-class unit that requests provider idle-stop is not class-gated on
  the idle path (theoretical — core units don't request idle).
- **H** stopping an RC unit while STARTING SIGKILLs the onestart wrapper mid-start
  (narrow race).
- **I** over-channel SYSTEM mint trusts login/su to pass the right domain (the
  socket path derives it from the target uid — asymmetry; make login-side the
  single source or add a symmetric check).
- **J** `SVC_DOMAIN_SYSTEM == 0` is fail-open on zero-init (latent; all current
  paths set it explicitly).
FIXED this pass: monitor wire-uid escalation (keyed on authctxt->pw), idle-stop
listener clobber (state preserved), unbounded mint RPC (2s bound), and the stale
CAP_XFER_ONCE comments (now describe the single-transfer/sender-closes model).

### 1. Descriptor-based isolation — the main architectural next piece
- **DONE (first slice):** descriptor-based file/dir isolation — a service calls
  `service_open_isolated(3)` and the filesystem daemon (`tzfsd`) opens the path
  under its own per-label policy, attenuates the fd to the requested rights
  (`cap_rights_limit` + `CAP_XFER_NONE`), and returns it. The service never opens
  a path, and nothing is declared in the manifest. This is a *non-exclusive* hold
  (unlike the exclusive `network`/`jail`/`vsock` isolations). Remaining below
  extends the same idea to vnode-pinned claims.
- `claim_fd` primitive: isolate the exact vnode behind a held descriptor (the
  policy already keys on vnodes) — no path TOCTOU.
- Shift confinement from global path-claims → per-process capability delivery +
  `cap_enter` (already partly true); retire blunt boot-time path-claims.
- Identity service for credentials: put `master.passwd` behind a service that
  hands out narrowed file tokens (`MINT_FILE`), not a global claim that hides the
  file — the right answer to the isolation bug we fixed this session.
- Migrate remaining boot-time path-claims into per-process capability delivery
  (minted at launch, released on stop).

### 2. Finish the service plane
- **User agents** — per-user serviced-managed services (launchd LaunchAgents
  shape); the payoff of the USER domain + per-uid session provisioning. Highest-
  value follow-on.
- **Retire /etc/rc progressively** — widen rc adoption service by service until
  the shim is empty, then delete it; `servicectl` becomes the full `service(8)`
  replacement plus a compatibility shim.
- **Management-over-channel, done right** (deferred #30) — keep the socket as the
  bootstrap/provisioning anchor (getpeereid is the correct primitive), but add an
  explicit *management capability* so control can also ride the authenticated
  channel. Non-admin su/sudo re-provisioning uses the same monitor pattern built
  for sshd.

### 3. Harden the substrate
- **Stand up the kyua VM test harness** (repeatable MK_TESTS=yes image) so the
  hundreds of tests written this session run for real, not just unit-local + hand
  VM checks. Worth doing early.
- **mac_capability driver hardening** — the WITNESS malloc-under-mutex lock-order
  warning at boot (`mac_capability_dev.c:324`, `filecaps_copy` under the instance
  mutex) + an audit for similar; unify the `cap_xfer` model across all users.

### 4. Wider platform (parked; each is its own effort, pick deliberately)
- Other capability planes: `tzfsd` (storage daemon), completing the network
  authority model.
- `SCHED_MIC` heterogeneous-core scheduler (in dev — DO NOT ENABLE yet).
- Deferred platform cleanup: delete the disabled 32-bit compat, prune ancient
  version shims, pkgbase-only base install, Authority→Caspian rename.

## Model status: the design is complete.
Landed + clean-VM validated: discovery/management split, management class (§5),
uid-aware mint (§6), session provisioning for console (getty) and ssh (socket),
the D1 identity handshake + fd-hygiene hardening, and rc adoption (cron) with the
launchd-style shim. Remaining refinements (not blockers): widen rc adoption beyond
cron; non-admin su/sudo re-provisioning via the socket path; migrate login/su onto
the unified socket backend; the mac_capability WITNESS malloc-under-mutex fix.

## 11. Test matrix (do NOT skimp)

### Discovery
- Per-uid resolution: user sees only their accessible set; system/root sees all;
  default-deny for an un-listed service.
- Inheritance across fork/exec through **every shell** (sh, bash, zsh, csh,
  tcsh): the channel survives to a grandchild process.
- login (console), ssh (network), su, sudo: each session gets the right channel.
- Fixed-fd (3) survival across the getty→login hop; env re-advertisement to the
  shell.
- No filesystem socket present after §9.

### Management authorization matrix
`{core, system, user}` × `{root, owning-user, other-user, unauthenticated}`:
- core: unload denied to **all**, including root.
- system: root may manage; user/other-user denied.
- user: owning uid and root may manage; other-user denied.
- start/stop/restart/reload/enable/disable each enforced.

### Session provisioning / transitions (breakage tests)
- su -l / su -m to another uid and back: target gets the target's channel.
- sudo (and doas if present): same.
- setuid program launched from a user shell: channel matches policy, not leaked.
- sshd network login: per-uid narrow with no getty hop.
- cron / atrun jobs: defined behavior (channel or none, by design).
- daemon(3) daemonization: channel not silently destroyed (or defined as
  intentionally dropped).
- newgrp, script(1), nohup, setsid, jexec/jail: channel behavior defined+tested.
- fixed fd 3 collision: no base program that assumes fd 3 is free misbehaves.

### Channel security
- Unforgeable: a forged/duplicated fd is rejected.
- Non-transferable: passing the channel to an unrelated process fails.
- USER channel cannot re-broaden via mint (EPERM), and cannot mint at all.
- Principal cannot be spoofed on a management op.

### rc
- Adopted service behaves like legacy: start/stop/status/reload parity.
- No double-start (adopted service removed from the /etc/rc path).
- Every `servicectl`/`service` verb + error paths (unknown service, already
  running/stopped, permission denied).

## 11a. Breakage-hunt findings (2026-08-27) — must fix

A tree-wide audit of the §21 carry found real breakages, several fail-dangerous.
These are requirements, not hypotheticals.

**D1 — fd-3 collision + non-discriminating validator (CRITICAL, security).**
`SVC_CHANNEL_FD = 3` (a service's unit control channel) is the same number as
`SERVICE_LOOKUP_FIXED_FD = 3`, and `ambient_fd_is_channel()` accepts ANY
mac_capability channel (it ignores `info.name`/`badge`). A bootstrap-launched
service — or a login/su spawned from one — probing fd 3 grabs its **unit control
channel** believing it is the ambient lookup channel, then narrows/hands it out.
Root cause is structural (S5): the two launch paths disagree on what fd 3 means.
*Fix:* lookup channels must carry a **distinct identity** the validator requires
(`GETINFO name == "serviced.lookup"` or a badge), because created channels
currently share a generic identity — `mac_cap_create_channel` associates every
pair with the same `csvc_name`, so neither name nor per-instance badge
discriminates today. This likely needs minimal mac_capability support to *name* a
created channel. Moving the fixed fd off 3 is a mitigation, not a fix, because the
service reserved range (3..tokens..caps) is variable.

**D2/D3 — cron/atrun leak the SYSTEM channel into user jobs (dangerous).**
serviced-launched cron/atrun inherit the SYSTEM ambient channel as an open,
non-cloexec, CLOFORK-unlocked fd and run the user's job after `setuid` WITHOUT
`closefrom` (`cron/do_command.c:339-410`, `atrun.c:310-373`). System-domain
discovery leaks to arbitrary user jobs. *Fix:* on any uid transition to a user,
close-or-narrow the ambient channel (fd hygiene).

**D4 — su leaks fds ≥3 into the target shell** (`su.c` child never `closefrom`s);
dangerous in the bootstrap/`-m` combination. *Fix:* su `closefrom(3)` after
install/failure and unset a stale `SERVICE_LOOKUP_FD`.

**S1 — sshd network logins get no channel** (`closefrom(3)` before shell exec, no
narrow). Fail-safe; it is the session-provisioning gap for the network path (§7).

**S3/S4 — `daemon(3)`/`jexec`/`newgrp`** don't scrub inherited channels; contribute
to the leaks; `jexec` could carry a host channel into a jail.

**The unifying principle:** *any code that changes principal (uid transition) or
crosses a trust boundary (jail, daemonize, network session) must re-provision or
drop the ambient channel — never silently inherit it.* This is the fd-hygiene
half of the session-provisioning interface (§7).

## 11b. Expanded test cases (from the hunt)

- Probe REJECTS a non-lookup mac_capability channel at fd 3 (feed a unit channel;
  require `service_ambient_lookup_fd()` → -1).
- Bootstrap-launched service: a login/su spawned from it must not narrow/hand out
  the unit channel.
- cron job / at job containment: a job fd-scans via `MAC_CAPABILITY_GETINFO`;
  require no channel (or only a correctly-narrowed one); `SERVICE_LOOKUP_FD` absent.
- `su -m`/`su -l` from a holder of a fd-3 channel: child shell has no unnarrowed
  channel; no stale env var.
- sshd parity: no channel today; a correct per-uid channel once provisioned;
  `closefrom(3)` doesn't strip a properly re-provisioned one.
- `daemon(0,0)` fd-3 survival documented; `jexec`/`newgrp` boundary: in-jail /
  newgrp'd process sees no host channel.
- getty carry positive-path regression (guards against a future `closefrom`
  creeping into getty).

## 12. Open questions

- **Per-uid discovery policy source**: declared per-service (who may reach me),
  a central policy file, or group-based? (Lean: per-service declaration +
  group.)
- **rc.d enumeration**: curated allow-list first (sshd, cron, syslogd-equiv),
  then widen — not all-of-rc.d at once.
- **User agents** (per-user services, launchd LaunchAgents): out of scope for
  this pass; the USER domain makes them possible later.
- **cron/at and other login-less contexts**: what principal/channel, if any.
- **Management transport for §9**: exact op set moved onto the channel and how
  `servicectl` authenticates without the socket.
