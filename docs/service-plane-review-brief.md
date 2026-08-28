# Service plane rework — review brief

Entry point for a reviewing agent. It states what this body of work set out to do,
what each commit changed and why, the invariants that must hold, how it was
validated, and the known/deferred findings. The **design source of truth** is
[`service-discovery-model.md`](service-discovery-model.md); read it first for the
model, then use this brief to navigate the commits.

Branch: `dev`. Range: `06f14a8b88e..HEAD` — 16 commits, ~113 files,
~11k insertions. Language: C (base system + a patched crypto/openssh).

## 1. What we set out to accomplish

Two intertwined goals:

1. **Execute the service-architecture plan** (`service-architecture-plan.md`)
   Phases 1–6: move serviced from a dependency-graph service manager to a
   **demand-driven capability service plane** — no startup ordering; services
   activate on demand (IPC lookup, timers, path events, inbound sockets); idle
   services stop and relaunch on demand.
2. **Build a defensible service-discovery + management model** on top of that:
   every process inherits an unforgeable **ambient lookup channel** to serviced;
   what it can **discover** is scoped by principal (SYSTEM vs per-uid USER
   domain); what it can **manage** is gated by a per-unit **management class**;
   and login/ssh/su hand each session its correctly-scoped channel.

The through-line: **the channel a process holds IS its authenticated authority**
(serviced mints it and records the principal), and confinement is capability-
descriptor-based rather than ambient.

## 2. Key concepts (see the model doc for detail)

- **Ambient lookup channel** — a mac_capability channel to serviced, inherited
  like stdio (`SERVICE_LOOKUP_FD` / fixed fd `SERVICE_LOOKUP_FIXED_FD=3`), used to
  resolve/connect to services. Bootstrap-port shaped (cf. macOS launchd).
- **Domains (§22)** — narrow *which* names a channel resolves. `SYSTEM` resolves
  all; `USER` resolves an allow-list (`org.5bsd.Log`, `org.5bsd.Notify`). Domains
  only ever narrow. `svc_mint_domain_kind` is the escalation guard.
- **Session provisioning (§21)** — login (getty fixed-fd carry), su (per-uid
  narrow), and sshd (privileged-monitor provision, fd-passed like the pty) each
  install the session's channel. All strictly non-fatal.
- **Management class** — manifest `management = core|system|user`; `core` is
  unstoppable at runtime by anyone including root.
- **rc adoption** — serviced adopts curated rc.d services as supervised
  `SVC_KIND_RC` units (launchd-style shim), started/stopped via
  `service <name> onestart|onestop`; the rest keep running under the `/etc/rc`
  shim.

## 3. Commit-by-commit (oldest → newest)

| Commit | What / why |
|---|---|
| `e9670b9a0ed` | **Phase 1+2**: delete dependency-graph/ordering; demand activation with coalescing/cancellation/recursion detection; provider-driven idle shutdown API (`service_idle_shutdown`), no persisted circuit breaker. |
| `88ada82e30f` | **Phase 3**: replace NetworkCmp inline socket proxying with a connection broker (v1 hello/resolve/connect/udp); session-derived immutable policy. |
| `2ec63489b6e` | **Phases 5 & 6**: timer + path activation sources (`activation.c`); user domains (`domain.c`, §22); the §21 ambient-carry scaffolding. |
| `8cf313844b6` | **Phase 4**: manager-owned listeners / socket activation — serviced binds+holds listeners, connection = demand, delivered by logical name via the bootstrap `capabilities[]` array (`type="socket"`); backlog survives restart. **Touches the launch path for every service** (execute.c). |
| `b56ab8808af` | **§21** ambient channel reaches interactive logins: fixed-fd carry across oracle-init→getty→login; `ORACLE_OP_SET_AMBIENT_LOOKUP`; fixed a real bug — `SVC_OP_MINT_DOMAIN` was only served on unit control channels, now on the ambient channel too. |
| `5e03d10b112` | **Management class** `core|system|user` — manifest field + serviced enforcement (`management.c`); core unstoppable. |
| `51957a0d918` | **Hardening**: D1 identity handshake (`SVC_OP_AMBIENT_HELLO`) so the fixed-fd probe rejects a non-lookup channel at fd 3; cron/atrun/su **fd-hygiene** (closefrom + unset on uid transition, so the SYSTEM channel can't leak into a user context). |
| `3015486f3f5` | **uid-aware mint**: root/wheel sessions get a SYSTEM (admin) channel, others USER; escalation guard (`svc_mint_domain_kind`) — a USER channel can never obtain SYSTEM. Fixes su-from-root. |
| `832152c015d` | **rc adoption of cron** as a supervised `SVC_KIND_RC` unit + de-dup (`cron_enable=NO` + `onestart`); `servicectl restart`. Also fixed the RC **stop** path (rc daemons detach → must `service <name> onestop`, not pdkill the wrapper). |
| `1dc6aaa329e` | **socket-authenticated session provisioning** (`SCTL_OP_PROVISION_SESSION`): sshd asks serviced over its `getpeereid`-authenticated control socket to mint a session channel. #30 rescoped: keep the socket (getpeereid is the correct userspace peer-cred primitive), don't delete it. |
| `f3875e4d124` | **oracled**: stop claiming `/etc/master.passwd` (and the demo path stubs) — a global isolation claim hid it from root too, breaking `pw`/`passwd`/`vipw`/`adduser`. |
| `71f36eacb61` | **sshd monitor provisioning**: modern OpenSSH runs `do_child` already dropped to the user, so provisioning from there failed for non-root ssh. Now the **root monitor** provisions and fd-passes the channel to the child (`mm_answer_provision`, pty pattern). Corrected the transfer model to **single-transfer, sender-closes** (no `CAP_XFER_TWICE`). |
| `d0a1d4aa691` | **Quality-review fixes** (3 HIGH): monitor now keys on `authctxt->pw->pw_uid` not a child-supplied wire uid; idle-stop preserves activation-source fds (was leaking + spinning); the mint RPC is bounded (was unbounded → could hang login); stale `CAP_XFER_ONCE` comments reconciled. |
| docs | `dea585c…`, `de721a8…`, `1b9a6746…` are doc-only. |

## 4. Invariants a reviewer MUST verify

1. **Escalation guard** — a `USER`-domain channel can NEVER obtain a `SYSTEM`
   channel. Both mint paths (`domain.c lookup_channel_request`,
   `svc_proto.c handle_mint_domain`) must check the requester's own domain via
   `svc_domain_may_mint` then `svc_mint_domain_kind`.
2. **Provisioning authority** — only root may provision a session channel for an
   arbitrary uid (`sctl.c` getpeereid `c->euid==0`; `domain.c requester_euid==0`).
   The sshd monitor must provision for the **authenticated** `pw->pw_uid`, never a
   child-supplied uid.
3. **Scope by target uid** — `domain_uid_is_admin`: uid 0 or wheel → SYSTEM, else
   USER; every lookup failure must fail SAFE to USER (never default to admin).
4. **fd-hygiene** — the SYSTEM ambient channel (and any capability fd ≥3) must
   NEVER survive a uid transition into a user process (cron/atrun/su: closefrom
   after setuid, on every branch; unset `SERVICE_LOOKUP_FD`).
5. **Non-fatal §21** — no session-provisioning code may block or fail
   getty/login/su/sshd/boot. All RPCs bounded; all failures degrade to "no
   channel."
6. **D1 identity** — the fixed-fd (3) probe must require the HELLO magic, not just
   `GETINFO`, so a unit control channel at fd 3 is rejected.
7. **Management class** — `core` unstoppable at every runtime chokepoint (sctl
   stop, reload teardown), but boot/shutdown/reload-in-place still work.
8. **Descriptor delivery** — single transfer, each sender closes its own copy
   after the SCM_RIGHTS send; no over-broad `cap_xfer` budgets.
9. **Launch path (Phase 4)** — the listener packing in `execute.c` must not break
   or leak on any service launch; a unit with no listeners launches identically.

## 5. Threat model

Capability-plane OS; the post-auth sshd session child and any confined service are
**untrusted**. Attacks to consider: privsep/uid-timing (a compromised child asking
for more authority), capsicum/`cap_xfer` misuse, fd leaks/double-closes across the
delivery chain, a wedged serviced hanging a login, a non-lookup channel spoofing
the ambient probe, and bounds/validation gaps in the wire protocols
(`serviced_svc_proto.h`, `serviced_ctl.h`, the monitor RPC).

## 6. Validation status — READ THIS

- **Clean-VM validated**: every code commit was booted in an oracle-init VM image
  (`build-image-oracle.sh` from an `installworld` tree) — plane 8/8, console+ssh
  login, cron adoption, escalation/non-root scope checks. Details in the model doc.
- **Unit tests**: extensive (management, activation, domain/escalation, rc_adopt,
  service_ambient, etc.), built `-Werror`. **Many device-gated cases (needing
  `/dev/mac_capability`) have never actually RUN** — no kyua harness stood up; they
  pass device-free or skip.
- **NOT yet representative of a real install** (in progress, task #35): the VM is
  built via `installworld` + custom oracle-init staging + test conveniences
  (autologin root, empty root password, `SSH_TEST` hacks), NOT via **pkgbase**
  (`pkg -r <root> install`, the real mechanism). A fresh-install harness is being
  built to prove a genuine install boots the plane and passes kyua. **Finding
  already surfaced**: the capability plane is NOT a dependency of `base`/`runtime`
  — it is an opt-in set of `5BSD-*` packages, so a *default* install boots plain
  `/sbin/init`, not the plane.

So: a reviewer should trust the *runtime behavior* but treat *install-path* and
*device-gated test* claims as not-yet-proven.

## 7. Known / deferred findings (from the adversarial review)

Fixed in `d0a1d4aa691`: monitor wire-uid escalation; idle-stop listener clobber;
unbounded mint hang; stale transfer comments.

Still open (low/latent — see model doc §0a):
- **E** `getgrouplist` in `principal_is_admin` can block on a slow NSS backend in
  the post-auth child (fine for local `files`).
- **F** cron's mailer runs in the never-dropped middle process, keeping the SYSTEM
  channel + env — system→system DiD gap vs atrun.
- **G** a `core` unit requesting provider idle-stop isn't class-gated on the idle
  path (theoretical).
- **H** stopping an RC unit while STARTING SIGKILLs the onestart wrapper (narrow
  race).
- **I** over-channel SYSTEM mint trusts login/su to pass the right domain (the
  socket path derives it from the target uid — asymmetry).
- **J** `SVC_DOMAIN_SYSTEM == 0` is fail-open on zero-init (latent; all paths set
  it explicitly today).

Verified-safe under adversarial attack (do not re-litigate without new evidence):
the escalation guard, D1 handshake, all fd-hygiene/leak-prevention paths, Phase-4
launch packing/barrier/cleanup, RC-stop disambiguation, bootstrap socket-type
validation, and the getpeereid auth (no TOCTOU on a local stream socket).

## 8. Suggested review approach

Read `service-discovery-model.md`, then review by subsystem against §4's
invariants: (a) auth/provisioning — `crypto/openssh/{monitor.c,monitor_wrap.c,
session.c}`, `serviced/sctl.c`, `libservice/service_client.c`, `serviced/domain.c`;
(b) domain/mint/D1 — `serviced/domain.c`, `serviced/svc_proto.c`,
`libservice/service_ambient.c`; (c) fd-hygiene — `cron/do_command.c`,
`atrun/atrun.c`, `su.c`, `login.c`, `oracle_init.c`, `serviced/startup.c`;
(d) launch/rc/mgmt — `serviced/{execute.c,activation.c,serviced.c,rc_adopt.c,
supervisor.c,management.c,reload.c}`, `libservice/libservice.c`. Prefer
adversarial verification (construct a concrete trigger) over pattern-matching.
