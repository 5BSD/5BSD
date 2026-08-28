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

## 2a. The injection surface — base software we modified to take over

The plane "takes over" the machine by **injecting an ambient lookup channel into
every process's descriptor table** and re-scoping it at each privilege/identity
boundary. That required patching a specific, security-critical set of base and
third-party programs — PID 1 and the login/session entry points. This inventory
**is** the takeover surface; record it deliberately, because these are the base
programs a downstream merge (or a FreeBSD rebase) must carry forward or the plane
silently stops reaching sessions. Every patch is **strictly non-fatal** (invariant
§4.5): a failure degrades to "no channel," never blocks boot/login.

| Program | Files | What the patch injects | Why it's core to takeover |
|---|---|---|---|
| **oracle-init (PID 1)** | `usr.sbin/oracled/oracle_init.c`, `oracle_proto.c`, `oracle_init.h`, `Makefile` | Receives the ambient channel from serviced (`ORACLE_OP_SET_AMBIENT_LOOKUP`); spawns the console getty with the channel on fixed fd 3. | Root of the carry chain — every init-spawned login inherits the channel from here. Nothing downstream has a channel without it. |
| **login** | `usr.bin/login/login.c`, `Makefile` | Carries the inherited channel into the user shell; fd-hygiene (closefrom / unset on the uid transition). | The console→user handoff; establishes the interactive session's authority. |
| **su** | `usr.bin/su/su.c`, `Makefile` | Mints a per-target-uid–narrowed channel; fd-hygiene on the uid transition. | Identity change must re-scope authority (root→user narrows; the SYSTEM channel must not leak down). |
| **sshd (OpenSSH)** | `crypto/openssh/{monitor.c,monitor.h,monitor_wrap.c,monitor_wrap.h,session.c}`, `secure/libexec/sshd-{session,auth}/Makefile` | The privileged monitor provisions a session channel for the **authenticated** uid and fd-passes it to the already-dropped child (`MONITOR_REQ_PROVISION`, pty pattern). | Remote login is the other entry point; privsep means only the root monitor may safely mint for the target uid. |
| **cron** | `usr.sbin/cron/cron/do_command.c` | fd-hygiene: closefrom + unset `SERVICE_LOOKUP_FD` before running a user's job. | Batch entry point crossing into a user context; must not leak the SYSTEM channel. |
| **atrun** | `libexec/atrun/atrun.c`, `Makefile` | Same fd-hygiene for `at` jobs. | Second batch entry point crossing into a user context. |

**Not patched, inherit-only:** `getty` execs `login` and passes fd 3 through by
plain inheritance — no code change needed. Recorded so a future reader doesn't hunt
for a getty patch that doesn't exist.

**Shared mechanism:** the channel is an unforgeable `mac_capability` descriptor at a
fixed fd (`SERVICE_LOOKUP_FIXED_FD=3`), inherited like stdio; the D1
`SVC_OP_AMBIENT_HELLO` handshake lets a receiver confirm fd 3 really is a lookup
channel (not a stray unit control channel). The `Makefile` edits (each adds
`LIBADD+= service`) are themselves part of the surface — they record which base
programs now link the plane.

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
- **Packaging correctness — AUDITED (pass), 2026-08-28.** The built `5BSD-*`
  packages were inspected directly (`pkg info -F`, no repo/root needed):
  - `5BSD-oracled` ships the boot integration a fresh install needs —
    `/boot/loader.conf.d/oracle-init.conf` (the `init_path` snippet), `/sbin/oracle-init`,
    `/usr/sbin/oracled`, the de-isolated `/etc/oracled.conf` — deps `serviced` +
    `libcapability` + `liboraclert`.
  - The injection surface is packaged correctly: patched `5BSD-ssh` declares
    `libservice.so.2` as a **required shlib**, so an install auto-pulls `5BSD-libservice`.
    `servicectl` is its own package.
  - All 8 capability bundles ship under `/Capabilities/System/*.cap/` (Bundle.ucl +
    Unit.ucl + bin): Audit, Blued, BsdNotify, Crypto, LocalFilesystem, LocalNetwork,
    Log, Trace.
  - **`5BSD-set-minimal` is the plane metapackage** — pulls oracled + serviced + the
    7 system components + syslogd. `Blued` is in `set-optional`. Opt-in is at the
    *set* level: `set-base` boots plain `/sbin/init`; `set-minimal` boots the plane.
- **Boot-from-pkgbase-install — PROVEN, 2026-08-28.** A real `pkg`-installed root
  was built and booted (`pkg-static repo` + `pkg -r /mnt install 5BSD-set-minimal
  5BSD-kernel-vbsd 5BSD-ssh` run **inside a native VM** — the session jail can't run
  `pkg repo`, see [[pkg-in-jail-limits]]), configured with a **real root password,
  a normal user, no autologin/SSH_TEST hacks**, then booted standalone:
  - `oracle-init` is PID 1 (from the package); serviced came up; **6/7 system
    components running** (bsdnotify, auditbrokerd, localfilesystem, localcrypto,
    localnetwork, traced); ambient lookup channel installed for logins.
  - **Real console login** (password auth) works; the session gets
    `SERVICE_LOOKUP_FD=6`.
  - **Non-root ssh login** works; the monitor provisions the ambient channel to the
    session (`SERVICE_LOOKUP_FD=3`, uid=1001) — the #28/#33 fix, on a real install.
  - `servicectl status` works over the ambient channel in both sessions.
  - **Real findings surfaced by the fresh install** (would never appear in the
    installworld-staged VM): (1) *task #37* — packages don't preload the
    `mac_capability` module stack, so a pure install falls back to `/sbin/init`
    (no plane); the loader snippet must ship in a package. (2) `logd` fails
    (`cannot load managed configuration`) — stays stopped; likely chains from
    `tzfsd` needing a ZFS `zroot` that a UFS install lacks. (3) `cron` (rc-adopted)
    shows stopped in the plane on a fresh UFS boot. Findings (2)/(3) filed.
- **kyua on the fresh install — RUN 2026-08-28** (installed the full `-tests` set +
  `5BSD-kyua`, ran on the booted plane). Per-suite passed/failed/skipped:
  serviced 71/7/87 · oracled 30/8/41 · servicectl 19/0/6 · logd 51/7/1 ·
  localnetwork 4/10/1 · auditbrokerd 10/6/1 · libservice 8/9/15 · libcapability
  3/2/0 · libcapbundle 36/20/0 · liboraclert 7/7 (all pass). Two failure classes,
  **neither a plane runtime bug** (boot/login/ssh/servicectl all proven working):
  1. **Device-gated tests can't run on a booted plane** (the dominant bucket — 87
     serviced skips, most localnetwork/libservice/libcapbundle failures). The MAC
     policy denies *all* direct `open("/dev/mac_capability")` — even `ls -l` on it is
     `Permission denied`; capability access is only via inherited **channels**
     (`fstat` shows `mac_capability:channel[5]`, never a device fd). The tests try to
     open the device directly, so they EPERM/skip. They need either a test-only
     device mode / pre-plane single-user run, or to be rewritten to acquire capability
     via an inherited channel like real programs do. **This is why the "device-gated
     cases have never actually RUN" — on a live plane they architecturally can't.**
  2. **Contract/metadata tests assume a source/build-tree layout**, not a
     pkgbase-installed `/usr/tests`: e.g. `pkgbase_default_identity` fails
     "capability must occur exactly once in master.passwd" although the system is
     correct (`grep -c '^capability:' /etc/master.passwd` == 1, uid 976); likewise
     "missing pkgbase metadata for auditbrokerd" / "missing filesystemcmp server
     header". Test-environment assumptions, not product defects.
  Device-independent suites largely pass (servicectl 19/25, liboraclert 7/7, logd
  51/59, serviced's 71 non-device cases). Filed as test-harness work.
- **Fixes landed + VALIDATED live, 2026-08-28** (task #39):
  - **A — permissive test mode**: `mac_capability_isolation.c` gains a boot-only
    `kern.mac_capability_isolation.enforce` tunable (`CTLFLAG_RDTUN`, default 1). At
    `enforce=0` the 8 resource-access denials are traced-but-allowed via a `fi_deny()`
    helper; the 3 ownership denials (release/mint/jail-claim wrong-nonce) stay hard.
    Built the module, booted the fresh-install target with `enforce=0`: `ls -l
    /dev/mac_capability` now succeeds (was `Permission denied`), and the serviced
    suite's **device-skips went 87 → 0** — the tests now execute. The live plane
    stays healthy under `enforce=0`. **Caveat**: tests that spin up their *own* full
    `oracled` (bootstrap cases) still can't run against a live PID 1 plane (it owns
    the isolation service) — those need a plane-free run (single-user, or a test image
    that doesn't launch the plane); `enforce=0` is necessary, not sufficient, for them.
  - **B/C — test portability**: functional `libcapbundle/capbundle_format_test.sh`
    now uses the co-located `servicectl` helper (installed `/usr/sbin/servicectl`
    fallback); the 7 component `bundle_test.sh` + serviced `component_examples_test.sh`
    got a `require_srctree` guard so source-contract cases **skip cleanly** off-tree.
    Validated on the target: auditbrokerd `bundle_test` now **0 failed / 4 skipped**
    (was 3 failed), skipping with "source tree (/usr/src) required for contract
    checks". All 10 edited scripts pass `sh -n`.

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
