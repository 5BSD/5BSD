# IPC anointments (v1)

Status: design, before code. 2026-09-14.

## Problem

Switchboard authorizes a lookup by the *name*, never by *who is asking*
(`naming_lookup()`, `usr.sbin/switchboard/naming.c`). Inside a domain, every
unit can reach every visible name. Providers that want to limit who reaches
them improvise it in their own config files with their own defaults. Nothing
on the system can say which program may talk to which.

## The feature

1. A bundle's policy file (today called the manifest; rename it) declares its
   endpoints, as it does now.
2. Each endpoint may **optionally** say which anointments a connecting
   program must hold. This lets one daemon publish a privileged and an
   unprivileged endpoint.
3. A program declares which anointments it holds.
4. Switchboard matches at lookup. A miss is reported as ENOENT and audited.
5. A tool draws the graph.

That is v1. Code signing and filesystem integrity gate it later; they change
nothing here.

## Policy file

```
# provider: two endpoints, one gated
activation {
    ipc = [
        "system.Notify",                                 # open
        { name = "system.Notify.System";
          requires = ["system.notify.system"]; }         # gated
    ];
}

# consumer
anointments = ["system.notify.system"];
```

- An anointment is a dotted name like a bundle id, lower-case by convention.
  `requires` with several names means all of them.
- A bare-string `ipc` entry, or an object without `requires`, is open:
  anyone the existing domain rules let see the name may connect. Nothing
  changes for any endpoint that does not add `requires`.
- `anointments` without a matching `requires` anywhere is harmless; the graph
  tool flags it.

## Switchboard

- At launch, read the unit's `anointments` into its runtime record.
- In `naming_lookup()`, after the existing domain check: if the endpoint has
  `requires` and the requester's set does not cover it, refuse with the
  internal EACCES that the wire already masks to ENOENT. Apply the same check
  before on-demand activation, so a program that cannot reach a provider
  cannot start it.
- Visibility: a gated endpoint (non-empty `requires`) is visible to any
  session or unit whose set covers it, regardless of the provider's
  `resolvable_by`. The provider gated it, so it said who may reach it. Open
  endpoints keep today's `resolvable_by` rule. This is what lets an operator
  reach a system-only name it was granted.
- Sessions: see "Domains and sessions" below. A session's set comes from the
  auth agent's principal policy at mint; it is empty unless the policy says
  otherwise.
- Audit: every refusal emits a record through `system.Audit` with the
  requester label, the endpoint, and the missing names, next to the existing
  DTrace deny probe.
- Identity in the NEW_CLIENT grant: the requester's label (already sent),
  its nonce, and its ABI.
  - Units carry their policy-file label. Programs on an ambient session
    channel (a login shell, sshd, anything not launched by switchboard) carry
    the reserved `org.5bsd.user-session`, which no bundle can use, so a
    provider can tell it is not talking to capability-world software. That
    string is the registered platform principal; it stays as is.
  - `client_nonce`: the kernel's per-exec program nonce, taken from the
    stamp on the lookup request. Label is the persistent identity, nonce the
    running instance.
  - `client_abi`: native or Linux, stamped by the kernel from the sender's
    sysentvec next to the uid, gid, prison and nonce it already stamps, and
    also exposed per message by libservice. ABI is information for the
    provider. It never gates reach; only anointments do.

`resolvable_by`, rights, helper names, on-demand: unchanged in v1.
Anointments are an additional check, not a replacement.

## Domains and sessions

A unit gets its anointment set from its policy file. A login session has no
policy file, so the **auth agent** decides what it holds, at mint, and the
session channel carries the result. That carried set plus the uid *is* the
domain. Today's two kinds are two hard-coded sets: SYSTEM holds everything,
USER holds nothing. Domains are therefore **repurposed, not removed**: the
kind is replaced by the set it stood for, and the principal policy fills it
in.

**What a user holds at login or ssh** is decided by
`/Capabilities/Config/principal-policy.ucl`, the file the auth agent already
consults for the admin decision:

```
principals {
    admin     { groups = ["wheel"]; anointments = ["*"]; admin_rights = true; }
    default   { anointments = []; }
    operators {
        groups      = ["operators"];
        anointments = ["system.trace.client"];        # held from login
        may_elevate = ["system.notify.system"];       # on request, per command
    }
}
```

Each entry has three knobs:

- `anointments`: what the session holds from login, silently, for every
  process under it.
- `may_elevate`: what the principal does not hold but is permitted to ask
  for, one command at a time, after authenticating again (see "Elevation").
  Absent or empty means the principal can never escalate. This replaces
  sudo and doas.
- `admin_rights`: whether connections from this session carry the ADMIN
  rights bit that providers use as an in-endpoint bypass. Today every
  SYSTEM session gets it; under this file it is a separate knob from reach,
  so a site can narrow root's reach and keep its bypass, or the reverse.

`*` is legal in `anointments` and `may_elevate` here, never in a bundle's
policy file.

**"Holds nothing" does not mean "connects to nothing."** An empty set means no
*gated* endpoint. Every endpoint without `requires` is open, and that is
expected to be the whole ordinary-user surface: system.Log, the open tier of
system.Notify, and whatever else a provider publishes without a requirement.
A default user connects to exactly what they connect to today, plus a
working bsdnotify. Only privileged tiers, the ones a provider chose to gate,
need an anointment.

**The capability user is not a principal here.** `user = "capability"` is
the unprivileged uid switchboard runs units as. Units never consult the
principal policy: their set comes from their own policy file, and their uid
plays no part in the match. So the capability user needs no entry in this
file, and a unit reaches open endpoints and whatever it declares, regardless
of uid. If anything ever logged in as that uid it would fall under `default`
and hold nothing, which is the right answer.

**Root is just a principal.** Switchboard never looks at the uid; the auth
agent is the only place a uid becomes a set. So a system may give root some
anointments and not all:

```
root { users = ["root"]; anointments = ["system.switchboard.admin"];
       may_elevate = ["*"]; admin_rights = false; }
```

A root shell then reaches one gated endpoint, asks per command for anything
else, and every ask is audited. Root's POSIX powers over the filesystem are
untouched; the capability daemons and TrustedZFS cap-fd storage are what sit
behind anointments.

**Shipped default**: `admin` (wheel) holds `*` with `admin_rights = true`,
so nothing changes on day one; `default` holds nothing and may elevate
nothing. The stricter profile, wheel holding a short list with
`may_elevate = ["*"]`, is a policy edit.

The set is fixed when `login`, `su` or `sshd` asks the auth agent for the
session channel, and every process under that session shares it. `su` to
another principal re-mints and gets that principal's set. A bundle launched
from the shell does **not** inherit it: switchboard starts it with its own
label and its own policy-file set. Authority follows the program, not the
terminal it was typed into.

**login, sshd and getty themselves** run before there is a session, on the
boot channel switchboard installs ahead of rc. In v1 that channel is SYSTEM
and reaches everything. When the kind becomes a set, that channel gets a
small explicit one in switchboard's own config, essentially the right to
reach the auth agent and mint. That is the only place stock binaries need an
anointment, and it is declared where they are launched, not in a policy file
they do not have.

**Sequencing.** v1 keeps the kind enum and adds the set beside it on the
channel record, so nothing breaks. The auth agent fills the set from the
principal policy once that file grows an `anointments` list.
`resolvable_by` retires endpoint by endpoint as providers add `requires`: a
user-visible name is simply an endpoint with no requirements. The enum goes
when the graph tool shows no endpoint still depends on domain visibility.

### Elevation: the sudo and doas replacement

Elevation is an operation, not a tool: a process on a session channel asks
the auth agent for one anointment in its principal's `may_elevate` list,
authenticates, and receives a channel holding just that name. The channel
lives as long as the process that asked and is never cached. Each elevation
is audited with uid, label and name. It is exposed as a libservice call, so a
program that hits ENOENT can ask for what it needs itself; the `anoint`
command wraps the same call for shell use and replaces sudo and doas:

```
anoint system.notify.system notifyctl -s publish system.maint "reboot at 02:00"
anoint system.switchboard.admin switchboardctl restart system.Network
```

This is sudo shaped as least privilege: one named anointment, never root,
scoped to a command rather than a clock. `may_elevate = ["*"]` on an admin
entry gives the sudo experience with an audit trail per name; `may_elevate`
absent means a principal can never escalate, whatever they type.

**How it works.**

1. `anoint NAME CMD...` resolves `system.auth` over the session's
   lookup channel (the agent's endpoint is open) and sends an ELEVATE request
   carrying NAME and the password. Switchboard is not in the loop. The agent
   takes the caller's uid from the kernel-stamped sender credential on the
   request, never from the payload, and refuses a caller whose label is a
   unit's rather than the session principal (units declare, they do not
   elevate).
2. The agent resolves the uid in the principal policy. NAME must be in that
   entry's `may_elevate` (or `*`), else EPERM before any password check,
   audited.
3. The agent authenticates the caller **itself**. v1 verifies the password
   against a read-only `master.passwd` descriptor the agent retained before
   entering capability mode (the same path it uses for `passwd` and `group`,
   granted by the filesystem daemon's open policy), using `crypt(3)`. PAM
   module stacks cannot run inside the agent's sandbox, so PAM is not used
   here; `login`, `su` and `sshd` keep their own PAM. The request buffer is
   zeroed after use on both sides. Repeated failures for a uid are
   rate-limited in the agent.
4. On success the agent mints a lookup channel whose set is the principal's
   policy set plus NAME (the session's own set is exactly that policy set,
   so the result is "session plus one"), bound to the same uid, and returns
   it. `anoint` installs it as the ambient channel and execs CMD. When CMD
   exits the channel is gone. Nothing is cached; a second `anoint`
   authenticates again.

**What it does not do.** It does not change uid. A command elevated to
`system.switchboard.admin` still runs as the user; it can reach the admin
endpoint because it holds the anointment, not because it is root. Programs
that genuinely need uid 0 for POSIX reasons keep using `su`, which re-mints
the whole principal as today.

## bsdnotify

Today `system.Notify` is open to every session, the shipped policy is an
empty `clients{}`, and undeclared labels are denied, so non-root connections
succeed and every operation fails. With v1:

- `system.Notify` (open): subscribe to anything, publish under `user.*`.
- `system.Notify.System` (requires `system.notify.system`): publish under
  `system.*`, timers, state. The existing `clients{}` table can still narrow
  a specific label on this tier.
- bsdnotify picks the tier from `identity.service_name` at accept and gains a
  `default {}` block per tier in its conf. Session setup, the relay
  authorization, and the admin bypass are otherwise unchanged.

## Observability

Every decision the feature makes is visible twice: as a DTrace USDT probe
(free, arguments never carry a password, a hash, or capability material) and,
where it is a security decision, as a BSM audit record. One refused request
yields exactly one record.

Probes (provider:name(args)):

- `switchboard:anoint-allow(name, requester, nrequires)` — gated match
  succeeded at resolve (open endpoints do not fire; control names fire with 1).
- `switchboard:anoint-deny(name, requester, missing)` — gated match failed:
  resolve path, on-demand pre-check, or the `system.switchboard.admin` gate.
- `switchboard:anoint-set(label, count, all, admin)` — a set was decided: a
  unit's at exec (label = unit, never all/admin) or a session's at mint
  (label = `org.5bsd.user-session`).
- `switchboard:mint-anoint(uid, count, all, admin, status)` — set detail of
  each `SVC_OP_MINT_DOMAIN`, beside `mint-domain(label, kind, uid, status)`.
- `switchboard:anoint-visibility(name, uid)` — a USER-kind channel saw a
  gated, non-user-visible name through the visibility rule.
- `authagent:elevate-start(client)` / `elevate-done(client, uid, name,
  status, transport_errno, stage)` with stage in `caller`, `shape`, `policy`,
  `ratelimit`, `password`, `mint`, `ok`; `authagent:ratelimit-block(uid,
  failures)`; `authagent:policy-resolve(uid, count, all, admin, from_default)`
  (both MINT and ELEVATE).
- `service_ambient:elevate-start(name)` / `elevate-done(name, errno)` — the
  client side of `service_elevate(3)` in every process that calls it.
- `bsdnotify:session-admit(label, tier, rights, abi)` at accept and
  `bsdnotify:tier-policy(label, tier, source)` when the router picks
  `default` / `system_default` / `clients`.

Scripts: `/usr/share/dtrace/switchboard-anoint` prints allow/deny/set/mint/
visibility events live; the `bsdinstruments watch capability-services`
profile summarises elevation outcomes by stage, rate-limit hits, policy
grants, anointment matches, and notify admissions.

Audit records:

- `AUE_SWITCHBOARD_ANOINT` (43328): every anointment refusal — resolve,
  on-demand pre-check, control-plane gate — with requester label, endpoint and
  missing names. `AUE_SWITCHBOARD_COMPONENT` (43327): every mint, with the
  set's count/all/admin.
- `AUE_AUTHAGENT_ELEVATE` (43335) and `AUE_AUTHAGENT_MINT` (43336): every
  ELEVATE and MINT outcome, committed by the agent through `system.Audit`
  right after the reply is sent (the agent is on every login's critical
  path, so a slow broker delays the next request, never the channel of the
  one it describes; the audit session is likewise opened lazily on the first
  record, not before the agent checks in); subject `<label>/uid<N>`, operation
  `elevate/<stage>/<name>` or `mint/<kind>/n<count>[/all][/admin][/default]`,
  result = reply status. auditbrokerd maps the first operation component to
  the event class. If `system.Audit` is down the record is dropped with a
  syslog warning and the session is re-opened lazily (no hard dependency).
  Event classes: the mints are `lo` (they establish a session's lookup
  channel); elevation is `lo,ad` (a session mint that is also an
  administrative privilege grant), so `praudit`-class filters on either
  `lo` or `ad` see it.
- `AUE_BSDNOTIFY_POLICY` (43333): the existing per-operation refusals, plus
  `admit-tier-mismatch-{open,system}` (EPROTO) when a connection's resolved
  endpoint disagrees with the listener it arrived on.

## Graph tool

`switchboardctl graph [--dot|--json]` reads the bundle registry, no running
plane needed. Nodes are units plus the two session classes. An edge exists
where the consumer's set covers the endpoint's `requires`, or the endpoint is
open. Warnings: an endpoint requiring a name nobody declares; a declared name
nothing requires.

## Scenarios (acceptance matrix)

Walked through the rules above with the shipped default policy unless a row
says otherwise. Fixture: bsdnotify as in the section above; a unit
`com.example.pub` with `anointments = ["system.notify.system"]`; a unit
`com.example.app` with no `anointments`; a gated endpoint
`system.Storage.Admin` with `requires = ["system.storage.admin"]`; an
endpoint `system.X.Both` with `requires = ["a.one", "a.two"]`. Every row is
a test.

**Sessions with the shipped default**

| # | Who | Does | Expect |
|---|---|---|---|
| S1 | root shell (wheel) | lookup `system.Notify.System` | connects; identity label `org.5bsd.user-session`, rights include ADMIN |
| S2 | root shell | lookup `system.Storage.Admin` | connects (`*`) |
| S3 | default user shell | lookup `system.Notify` | connects (open); publish `user.x` ok; publish `system.x` EACCES from bsdnotify |
| S4 | default user shell | lookup `system.Notify.System` | ENOENT; audit record (label, endpoint, missing `system.notify.system`) |
| S5 | default user shell | lookup `system.Storage.Admin` while provider stopped | ENOENT; provider **not** launched |
| S6 | default user | `anoint system.notify.system ...` | EPERM before any password prompt; audited |
| S7 | default user | `su` to root, then S1 | connects: su re-minted the root set |
| S8 | root | `su` to default user, then S4 | ENOENT: su re-minted the smaller set |
| S9 | default user shell | starts `com.example.pub` (a bundle) which looks up `system.Notify.System` | connects: the bundle's own set, not the session's |
| S10 | Linux binary in a default user shell | S3 and S4 | same results; identity `client_abi = linux`, reach unchanged |

**Units**

| # | Who | Does | Expect |
|---|---|---|---|
| U1 | `com.example.pub` | lookup `system.Notify.System` | connects; label `com.example.pub`, nonce set, rights without ADMIN |
| U2 | `com.example.app` | lookup `system.Notify.System` | ENOENT; audited |
| U3 | `com.example.app` | lookup `system.Notify` | connects (open) |
| U4 | `com.example.app` | lookup `system.Notify.System` while bsdnotify stopped | ENOENT; not launched |
| U5 | `com.example.pub` | same as U4 | bsdnotify launched on demand, then connects |
| U6 | unit with `anointments = ["a.one"]` | lookup `system.X.Both` | ENOENT (needs both) |
| U7 | unit with `["a.one","a.two"]` | lookup `system.X.Both` | connects |
| U8 | any unit | lookup `helper.foo` | EACCES as today; unchanged |
| U9 | a base unit under `/Capabilities/System` with no `anointments` | lookup `system.Notify.System` | ENOENT. Base bundles get no free pass; switchboard itself declares what it needs |
| U10 | `com.example.pub` restarted | reconnect | same label, **different** nonce in identity |
| U11 | policy file declares `anointments = ["*"]` | install / load | rejected by libcapbundle validation |

**Custom principal policy**

| # | Policy | Who | Does | Expect |
|---|---|---|---|---|
| P1 | `operators { anointments = ["system.trace.client"] }` | operator shell | lookup `system.Trace` (requires that) | connects, no prompt |
| P2 | same | operator shell | lookup `system.Notify.System` | ENOENT |
| P3 | `operators { may_elevate = ["system.notify.system"] }` | operator | `anoint system.notify.system notifyctl -s publish system.x` | prompt; correct password; publish ok; audited elevation; shell afterwards still gets ENOENT (P2) |
| P4 | same | operator | wrong password | fails closed; no channel; audited |
| P5 | same | operator | `anoint system.storage.admin ...` | EPERM, no prompt; audited |
| P6 | `root { anointments = ["system.switchboard.admin"]; may_elevate = ["*"]; admin_rights = false }` | root shell | lookup `system.Storage.Admin` | ENOENT: root has some, not all |
| P7 | same | root shell | `anoint system.storage.admin ...` | prompt; connects for that command only |
| P8 | same | root shell | connect `system.Notify` (open), publish `system.x` | EACCES from bsdnotify: no ADMIN bypass because `admin_rights = false` |
| P9 | `admin { anointments = []; may_elevate = ["*"] }` | wheel user | every gated lookup | ENOENT until anointed per command: the strict-admin profile |
| P10 | policy file missing or malformed | any login | falls back to today's rule: root/wheel `*` + ADMIN, others nothing; logged |

**Elevation mechanics**

| # | Does | Expect |
|---|---|---|
| E1 | `anoint NAME CMD` succeeds | CMD's ambient channel set = session set + NAME; uid unchanged |
| E2 | CMD exits | channel closed; a child CMD left running keeps it until it exits (it is fd inheritance) |
| E3 | second `anoint` | prompts again; nothing cached |
| E4 | ELEVATE request crafted with a forged uid/label in the payload | ignored: switchboard attaches the channel's uid/label, payload identity is not read |
| E5 | ELEVATE over a unit's bootstrap channel (not a session) | EPERM: units do not elevate; they declare |
| E6 | `anoint` while auth agent down | fails soft with a clear error, no hang |

**bsdnotify tiers**

| # | Who | Does | Expect |
|---|---|---|---|
| B1 | default user on `system.Notify` | subscribe `system.shutdown.x` | ok |
| B2 | default user on `system.Notify` | publish `user.me.x` | ok |
| B3 | default user on `system.Notify` | publish `system.x` / set timer | EACCES |
| B4 | `com.example.pub` on `system.Notify.System` | publish `system.x`, timer, state | ok |
| B5 | `clients { "com.example.pub" { publish = ["system.shutdown.*"] } }` | `com.example.pub` on system tier | publish `system.shutdown.now` ok, `system.other` EACCES: narrowing works |
| B6 | root on `system.Notify` (open tier) with ADMIN | publish `system.x` | ok: admin bypass unchanged |

**Graph tool**

| # | Input | Expect |
|---|---|---|
| G1 | fixture tree | edges: session-default → `system.Notify`; session-admin → all; `com.example.pub` → both bsdnotify endpoints; `com.example.app` → `system.Notify` only |
| G2 | endpoint requiring `nobody.declares` | warning: unreachable |
| G3 | unit declaring `nothing.requires` | warning: dead declaration |
| G4 | base tree | matches golden file |

## Work

- libcapbundle: parse object-form `ipc` and `anointments`; validate names;
  registry exposes per-endpoint `requires` and per-unit set. Rename
  `manifest` to `policy` in identifiers and docs.
- switchboard: runtime set, the check in `naming_lookup()` and both on-demand
  paths, audit record, nonce and ABI in the grant, anointment set on the
  channel record beside the domain kind.
- authagentd + libcapbundle principal policy: `anointments`, `may_elevate`,
  `admin_rights` per principal entry; mint carries the set. ELEVATE handler:
  policy check, in-agent password verification against a retained
  `master.passwd` descriptor, rate limit, mint of policy-set-plus-one.
  `login`, `su`, `sshd` unchanged.
- libservice: `service_elevate(name, password, &fd)`; the agent's endpoint
  becomes user-visible so a session can reach it (its MINT op stays gated on
  ADMIN rights as today; only ELEVATE is open to sessions).
- `anoint(1)`: `anoint NAME CMD...`; installs the returned channel as the
  ambient lookup channel and execs CMD.
- kernel: one ABI byte in the channel message credential trailer.
- libchannel/libservice: `client_nonce` and `client_abi` in
  `service_identity`, `sender_abi` in message metadata; `SHLIB_MAJOR` bump.
- bsdnotify: two endpoints, tier by name, per-tier defaults.
- switchboardctl: `graph`.
- Tests: libcapbundle parse/validate; switchboard positive reach, negative
  reach masked as ENOENT, on-demand not launched on a miss, audit record
  present; bsdnotify tiers; elevation: name not in `may_elevate` is EPERM
  and audited, wrong password fails closed, success mints exactly
  session-plus-one, channel gone after CMD exits, `*` honoured, a second
  call re-authenticates; VM: plain ssh session uses the open tier and gets
  ENOENT on the gated one, a declaring unit reaches it, an operator
  `anoint`s a system notification, a default user cannot; golden graph of
  the base tree.

## Gated providers

Two base providers gate an endpoint on an anointment:

- **bsdnotify** publishes `system.Notify` (open) and `system.Notify.System`
  (requires `system.notify.system`) -- the original worked example, two tiers
  of one service.
- **traced** gates its single endpoint `system.Trace` on `system.trace.client`:
  tracing reads arbitrary kernel and process state, so it is a privileged
  surface. The shipped principal policy grants it to the admin principal (via
  `*`); an operator can be granted just `system.trace.client` to trace without
  being an administrator, or `may_elevate` it per command. A session holding
  neither gets `ENOENT`. No base unit consumes `system.Trace` (only the
  tracing tools do), so gating it changes only who may trace, not any daemon.

The reach lint counts a gated endpoint reachable when a unit declares its
name, an admin session holds it, or -- the maturity fix -- any principal-policy
entry grants it or may elevate to it (so an operator grant satisfies the
gate). It still advises "unreachable" for a gate that only a wildcard-`*`
admin can reach, which is a valid but noteworthy secure default. "dead
declaration" and "duplicate endpoint" remain hard errors; the base tree is
gated against both.

## Later, separately

Code signing of bundles and filesystem integrity decide whether a policy
file's declarations are trusted. Until then, installing a bundle is the
trust decision, as it is for everything else in a policy file today.

The intended path is `mac_veriexec` with signed fingerprint manifests
covering each bundle's policy files and programs, verified against enrolled
keys (libsecureboot). Trusting an enrolled key means trusting every anointment
it declares; a per-key allow-list can be added later if that distinction is
ever wanted.

**Step 1, done: the plane reads every trust-bearing file with `O_VERIFY`.**
`libcapbundle` parses `Bundle.ucl`/`Unit.ucl` through a descriptor opened
`O_VERIFY` (feeding libucl a fd, since libucl's own open cannot carry the
flag); the principal policy read is `O_VERIFY`; and `switchboard` opens each
unit's program and the rtld `O_VERIFY`. The program open is the one that
matters: a non-privileged unit launches as `ld-elf.so.1 -f <fd>`, so rtld
mmaps the image and the kernel's exec-time veriexec check never sees it --
only the open-time `O_VERIFY` verifies it. `O_VERIFY` is a silent no-op when
veriexec is absent, not loaded, or not enforcing (the `VVERIFY` accmode
reaches `mac_vnode_check_open` only under `options MAC`, and mac_veriexec's
hook returns 0 unless `VERIEXEC_STATE_ENFORCE`), so this landed ahead of the
signing work and changes nothing on an unhardened system -- VM-proven: the
plane boots and the full scenario matrix passes with veriexec unloaded.

Remaining: a build-time base fingerprint manifest covering the base bundle
programs and policy files, a staged one-knob enable (off -> log-only ->
enforce, defaulted off so a self-building admin is not locked out on first
boot), and -- for authenticity rather than just integrity -- signing that
manifest with an enrolled key. The kernel already refuses to exec a modified
program directly; `O_VERIFY` closes the rtld-loaded-by-fd gap.


## Edge-case and negative test sweep (2026-09-15)

After the first commits, a second sweep added edge, boundary, adversarial
and negative cases across every layer (libcapbundle manifest 67 cases,
principal policy 46, switchboard match/mint 42 + manifest compare 5,
auth agent 84 pure + 25 provider, `anoint(1)` CLI 15, libservice wire 11,
bsdnotify policy 27 + dispatcher 21, libnotify 13, notifyctl 10, graph 26).
Fixed as a result:

- **Repeated keys in policy files.** Both the principal-policy parser and
  bsdnotify's conf parser created their libucl parser without
  `UCL_PARSER_NO_IMPLICIT_ARRAYS`, so a repeated block or list key folded
  into an implicit array and the first copy silently won (`default {} default
  {}`, a client label listed twice, `uids` given twice). Both now use the
  same flags as the unit-file parser (`NO_IMPLICIT_ARRAYS | DISABLE_MACRO |
  NO_FILEVARS`): a repeated array, object or boolean key is a parse error,
  the file is malformed and falls back (historical rule for sessions,
  refusal for bsdnotify). A repeated scalar *string* key is the one shape
  libucl still folds into a list; pinned by test. `.include` macros are
  refused in both files.
- bsdnotify: a non-object `clients{}` entry now reports EINVAL, not E2BIG.
- switchboard: `svc_anoint_holds()` refuses an empty name outright
  (defence in depth; every producer already drops or rejects it), and
  `svc_anoint_missing()` mirrors `svc_anoint_covers()` for `all`.
- `switchboardctl graph`: warns when two bundles publish one endpoint name
  (switchboard's registry refuses the second at load, so the graph would
  otherwise draw both); prints a stderr note for a present-but-malformed
  policy (only an absent one did before), and the summary reads "absent or
  malformed"; an empty file or a directory stays quiet as "no policy".

Pinned, not changed (see the tests): `authagent_verify_password` accepts a
3-field master.passwd line; a real `crypt("")` hash authenticates an empty
password while an empty hash field is refused; bcrypt 72-byte / DES 8-char
truncation; unsupported hash prefixes fail closed; `service_elevate` checks
only name length client-side (syntax is the agent's and `anoint`'s job);
the rate-limit window anchors on the first failure; `helper.*` refusals go
out as EACCES rather than the masked ENOENT (pre-existing, public prefix);
an embedded `\u0000` in a policy-file name truncates at parse.

## VM validation log (2026-09-15)

Live plane, qemu/TCG, `~/vm/bsd-guest.img` built from this tree (kernel
#35), scenario accounts `operator1` (group operators), `plainuser`,
`wheeluser` (wheel), policy per §"Domains and sessions".

Passed on the live plane: S1 (root reaches both bsdnotify tiers), S3 (plain
user reaches the open tier, publishes `user.*`, is refused `system.*` and
timers with EACCES), S4 (plain user gets ENOENT on the gated tier and an
audit record `anointment refused: org.5bsd.user-session ->
system.Notify.System missing system.notify.system` is committed), P2, P5
(`anoint -n` for a name outside `may_elevate` → "not permitted", no
password prompt), S6 (default user cannot elevate), P3/E1 (operator
`anoint system.notify.system` with the correct password reaches the gated
tier), P4 (wrong password → "authentication failed", fails closed), E3
(operator shell still ENOENT afterwards), P1 after gating `system.Trace`
in the guest's traced manifest and `switchboardctl reload` (operator
holder connects), B4/B6 (root publishes `system.*` on both tiers),
`switchboardctl graph --lint` on the real base tree (14 units, 15
endpoints, 1 gated, one honest warning).

Also passed: U1/U2 (a test bundle declaring `system.notify.system`, launched
by switchboard, connects to `system.Notify.System` over a confined endpoint;
a sibling bundle declaring nothing gets ENOENT), S7/S8 (`su` to a wheel user
reaches the gated tier, `su` to a plain user does not), B3 timers refused on
the open tier. Unit-side note: a unit's `arguments` list excludes argv[0]
(switchboard supplies the program name), and a client-type test unit uses
`activation { boot = true; }` since it exposes no name.


Final kyua tally on the plane-off image (device-level suites need it; every
skip is an environment skip such as no source tree or no plane session):

| Suite | Result |
|---|---|
| lib/libchannel | 13/13 |
| lib/libcapbundle | 165/165 |
| lib/libnotify | 18/18 |
| lib/libservice | 59/60, 1 skipped |
| usr.sbin/switchboardctl | 35/53, 18 skipped |
| usr.sbin/notifyctl | 8/8 |
| usr.sbin/bsdnotify | 39/47, 8 skipped |
| usr.sbin/authagentd | 65/72, 7 skipped |
| usr.sbin/switchboard | 240/276, 36 skipped |

Zero failures, zero broken.


Also exercised live: the rate limiter (six wrong passwords at a fast cadence,
the sixth answered "too many failures", and a seventh attempt with the
correct password still refused inside the window), a 64-character name
refused at the CLI, and a nested `su`.

**Second live pass (2026-09-15, after the boot fix).** Re-run on the rebuilt
image with scenario accounts and passwords seeded before boot: the scenario
rows S1/S1b/S3/S4/S3p/S3d/P2/P1n pass; the elevation refusals S6 and P5 return
"not permitted" before any password, and P4 (wrong password) returns
"authentication failed"; `switchboardctl` live-admin suite 21/21; the agent's
`system.Auth` mint/anoint audit records are present in the trail. End to
end, `anoint system.notify.system` as `operator1` with the correct password
reaches the gated `system.Notify.System` (proven with a pty driver -- see
next), and `elevate_integration_test` as `operator1` is 6/7 (p9 self-skips
unless the strict-admin profile is deployed).

**pty driver for the elevation test.** `anoint` reads its password with
`readpassphrase(3)`/`RPP_REQUIRE_TTY` (the tty-only rule `sudo`/`doas` use),
which calls `tcsetattr(TCSAFLUSH)` and discards input typed before the prompt.
So the integration test's `printf pw | script cmd` raced and lost -- the byte
was flushed, and the case hung in ttyin or read an empty line and failed
authentication. This was invisible until the suite ran on a live plane for the
first time. Fixed by a small helper, `pty_askpass`, that drives a real pty and
sends the password only after the prompt appears; the CLI itself was correct.

Plane-off validation (2026-09-15): the full `authagentd` provider suite runs
green as root on the plane-off image (139/149, 0 failed; the skips need a live
plane or the source tree), including the five MINT_AUTH cases. It caught one
regression: the proto 2->3 bump for MINT_AUTH had made the agent require the
exact version, refusing a v2 login/su/sshd whose MINT_SESSION and ELEVATE
requests are byte-identical to v3. Fixed by accepting
`[AUTHAGENTD_PROTO_VERSION_MIN, AUTHAGENTD_PROTO_VERSION]` for the two stable
ops (MINT_AUTH still requires the exact current version), so a rolling upgrade
keeps working.

Non-admin `su` (found by the nested-`su` row, now **resolved**): an ordinary
session's `su` to another user used to get **no lookup channel** ("su: no
lookup channel for uid …: Operation not permitted"), because the agent's
MINT_SESSION is gated on the caller's ADMIN rights and a su from an operator
session lacks them. The fix is a new authenticated mint,
`AUTHAGENT_OP_MINT_AUTH` (proto v3): the caller supplies the TARGET's password
(the one `su` collected through PAM) and the agent authenticates it against
`master.passwd` itself, rate-limited, exactly as ELEVATE does, then mints the
target's own session set. `su` captures the password through a PAM
conversation wrapper and falls back to `service_mint_session_authenticated(3)`
only when the admin mint returns EPERM. VM-proven: operator1 (a non-admin
session) `su` to plainuser now installs a USER lookup channel, reaches the
open `system.Notify` tier and is refused the gated one; the admin `su` path
(a wheel session to root) is unchanged.

Found and fixed on the VM:

- **Boot-time login lost its lookup channel.** On the rebuilt image the
  console autologin logged `login: no lookup channel for uid 0: Operation
  timed out` and the root shell had no ambient channel, while every unit was
  in fact running. Timeline from syslog: switchboard ready at :25, `login`
  at :25, its two-second mint budget gone at :27, `tzfsd` up at :28. The
  auth agent cannot check in before `tzfsd` serves its `passwd`, `group`
  and `master.passwd` opens, and the observability work had added a
  pre-capability-mode open of the `system.Audit` session (a further bounded
  lookup plus hello) and audit-before-reply, so the agent was several
  seconds behind the first login. Three changes, all on the "no hard
  dependency, fail soft" side: the agent no longer opens its audit session
  at start-up (it opens lazily on the first record, in capability mode,
  over its lookup channel) and logs `ready (elevation enabled|disabled)` at
  check-in; it sends the reply before committing the record, so a slow
  broker delays the next request and never the channel of the one it
  describes; and `service_mint_session_via_agent()` treats its timeout as a
  whole-exchange budget, retrying a parked lookup (switchboard holds a
  lookup for a launched-but-not-ready unit) until the deadline, with
  `login`, `su` and `sshd` passing `SERVICE_MINT_SESSION_TIMEOUT_MS`
  (10 s) instead of 2 s. After the change the console autologin on the
  same image had its channel on the first boot. The authagentd
  observability contract test pins audit-after-reply and the absence of a
  start-up prepare.
- **Stale runtime manifest beat the registry.** After a provider's policy
  file gained `requires` and `switchboardctl reload` ran, a plain user could
  still connect: the match consulted the running provider's manifest copy
  first, reload's comparator ignored the new fields so the unit was not
  refreshed, and the stale copy said "open". Fixed both: the registry (the
  on-disk policy, refreshed by reload) is consulted first and the runtime
  copy is only the fallback for a name the registry does not know; and
  `switchboard_manifest_equal()` now compares `requires`, `nrequires` and
  `anointments`. Test `registry_wins_over_stale_unit_manifest`.

Environment notes for whoever runs this next:

- A fresh NO_ROOT image boots switchboard directly, with no seeding.
- Device-level suites (libchannel, switchboard root cases, authagentd
  provider tests) need a `CAPLANE_OFF=1` image; under a live plane the
  channel device is not openable by root and those cases fail with
  "Permission denied", which is the isolation gate working.
- Driving `anoint` from a script: `-n` for rows that must refuse before a
  prompt; for password rows type on the console (command line, then the
  password), since piping through `script(1)` under `su` stalls.
- `notifyctl` exits 69 (EX_UNAVAILABLE) on a refused operation, not 1.
- Test harness fixes that fell out of the run:
  source-tree contract tests now probe a real file, because `/usr/src`
  exists but is empty on an installed guest; the auth-agent integration
  test no longer calls `atf_skip` from inside `$(...)`; the packaged-policy
  test falls back to the installed policy file; the libcapbundle
  `protect_policy` case now expects unknown protect flags to be rejected,
  matching the parser since 2026-08-26.
