# Anointments and Principal Policy

An anointment is a dotted name for the privilege to reach an endpoint. A
provider gates an endpoint by listing the anointments a connecting program
must hold; a unit declares the anointments it holds in its manifest; a login
session gets its set from the principal policy at mint; and anoint(1) extends
a session's set by one name for one command. Switchboard compares the two at
lookup and reports a miss as `ENOENT`, audited. 5BSD has this so that "which
program may talk to which service" is stated once, at the naming boundary,
and never as a uid test inside a provider. The idea is borrowed from macOS
entitlements.

## Gating an endpoint

An `activation.ipc` entry in `Unit.ucl` is either a bare name (an open
endpoint) or an object with `name` and `requires`:

```ucl
activation {
    ipc = [
        "system.Notify",                                 # open
        { name = "system.Notify.System";
          requires = ["system.notify.system"]; }         # gated
    ];
}
```

`requires` is one name or an array of at most eight unique names; with
several, a requester must hold all of them. A bare string, an object without
`requires`, and an object whose `requires` is empty all publish an open
endpoint. One daemon may publish an open and a gated endpoint side by side;
that is the intended way to separate a privileged surface from an
unprivileged one. Switchboard's own control endpoints, `system.switchboard`
and `system.lifecycle`, are keyed on `system.switchboard.admin`.

## Declaring what a unit holds

```ucl
holds = ["system.notify.system"];
```

One name or an array of at most 32 unique names; absent means the empty set.
A unit holding nothing still reaches every open endpoint. Base bundles under
`/Capabilities/System` get no free pass: a base unit with no `holds` is
refused a gated endpoint like any other.

Names are reverse-domain, validated by the endpoint-name rule: letters,
digits, `-`, `_` and `.`; at least one dot; no leading, trailing or doubled
dots; shorter than 64 characters; lower-case by convention so
`system.notify.system` reads differently from the endpoint `system.Notify.System`
it guards. `*` is never a valid name in `requires` or `holds`; libcapbundle
rejects such a bundle at verify, install and load. The `system.` prefix
belongs to the base system.

There is no separate grant step. A bundle that declares a name holds it as
soon as it is installed and loaded, so the trust decision is installation:
whoever runs `switchboardctl install`, or the package that does, accepts
every anointment in the manifest exactly as they accept its program and
limits. The later gate is mac_veriexec: libcapbundle already opens
`Bundle.ucl`, `Unit.ucl` and the principal policy with `O_VERIFY`, and
switchboard opens each program the same way, so once fingerprints are
enforced a declaration is only honoured from a verified file. See
[Verified Execution](../capability/veriexec.md).

## What switchboard does at lookup

A unit's set is read from its manifest at every exec. A session's set was
decided at mint and rides on the session channel. When a lookup arrives,
switchboard applies the domain rules, then, if the endpoint has `requires`,
checks that the requester's set covers it. A miss is refused: internally
`EACCES`, on the wire `ENOENT`, indistinguishable from an unregistered name,
so a program cannot enumerate what it may not reach. Every refusal commits an
audit record (`AUE_SWITCHBOARD_ANOINT`, 43328) with the requester's label,
the endpoint and the missing names, and fires `switchboard:::anoint-deny`.
The same check runs before on-demand activation: a program that cannot reach
a provider cannot start it.

Two consequences:

- **Visibility.** A gated endpoint is visible to any unit or session whose
  set covers it, regardless of the provider's `visible`. Open endpoints keep
  the `visible` rule of switchboard(5), which is how BSDLog opts its open
  endpoint into resolution from login sessions.
- **Identity.** The grant a provider receives on a new connection carries the
  requester's label, its per-exec kernel nonce and its ABI. Units carry their
  manifest label; anything on an ambient session channel carries the reserved
  `org.5bsd.user-session`, which no bundle may claim. ABI never gates reach.
  Only anointments do.

`switchboardctl reload` picks up manifest changes; adding `requires` to a
provider's endpoint takes effect at the next reload without restarting the
provider.

## The worked examples in the base system

| Endpoint | Gate | Provider |
|---|---|---|
| `system.Notify` | open | BSDNotify: subscribe to anything, publish only under `user.*`, no timers |
| `system.Notify.System` | `requires = ["system.notify.system"]` | BSDNotify: publish anywhere, state, timers |
| `system.Trace` | `requires = ["system.trace.client"]` | BSDTrace: a DTrace consumer descriptor |
| `system.switchboard`, `system.lifecycle` | `system.switchboard.admin` decides operator authority | switchboard, capsule lifecycle |

BSDNotify's tier is decided by the endpoint a session was accepted on,
cross-checked against the name switchboard resolved, never by anything the
client sends; `notifyctl -s` selects the gated tier and fails `ENOENT`
without the anointment. BSDTrace has one endpoint: tracing reads arbitrary
kernel and process state, so an operator is granted `system.trace.client`
(or may elevate to it) to trace without being an administrator. The rule for
other providers is the same: publish an endpoint per privilege tier, gate the
privileged one, keep the provider's own configuration for narrowing within a
tier.

## Who gets what at login: the principal policy

A login session has no manifest, so BSDAuth (`system.Auth`) decides what it
holds at mint, from `/Capabilities/Config/principal-policy.ucl`. The parser
is `lib/libcapbundle/principal_policy.c`; the shipped file is
`usr.sbin/BSDAuth/principal-policy.ucl`:

```ucl
principals {
    admin {
        groups = [ "wheel" ];
        uids = [ 0 ];
        anointments = [ "*" ];
        admin_rights = true;
    }
    operators {
        groups      = [ "operators" ];
        anointments = [ "system.trace.client" ];    # held from login
        may_elevate = [ "system.notify.system" ];   # per command, via anoint(1)
    }
    default {
        anointments = [];
    }
}
```

Entries are matched in file order against the authenticated principal's uid
and full group membership, which BSDAuth resolves itself from `passwd` and
`group` descriptors it obtains before entering capability mode; nothing the
login program claims is trusted. The first entry whose `uids` or `groups`
matches wins. An entry with neither list is the fallback, conventionally
named `default`. Entry names are for the operator; only the lists match.

| Key | Meaning |
|---|---|
| `uids` | numeric uids; renaming an account never transfers authority |
| `groups` | group names, matched against the full resolved membership |
| `anointments` | what the session holds from login, silently, for every process under it |
| `may_elevate` | what the principal may ask for one command at a time through anoint(1); absent or empty means it can never escalate |
| `admin_rights` | whether the session's connections carry `SERVICE_RIGHTS_ADMIN`, the in-endpoint bypass providers honour; defaults to true only when `anointments` is `["*"]` |

`*` is legal in `anointments` and `may_elevate` here and nowhere else. The
legacy top-level `admin { uids; groups; }` form is accepted and means the
same as the `admin` entry.

The session kind is SYSTEM (full discovery) when the grant holds `*` or
carries admin rights, and a per-uid USER channel carrying the listed set
otherwise. "Holds nothing" is not "connects to nothing": an empty set means
no gated endpoint, and every endpoint published without `requires` stays
reachable, which is expected to be the whole ordinary-user surface.

Root is a principal like any other. Switchboard never looks at the uid; the
auth agent is the only place a uid becomes a set. A stricter site profile
keeps the bypass but makes every gated reach an audited, per-command ask:

```ucl
admin { groups = ["wheel"]; uids = [0]; anointments = [];
        may_elevate = ["*"]; admin_rights = true; }
```

The `capability` uid is not a principal. It is the unprivileged uid
switchboard runs units as; units never consult this file, and BSDAuth logs a
warning at startup if an entry grants it anything. A missing or malformed
file falls back to the historical rule (uid 0 or a member of `wheel` holds
everything with admin rights, everyone else nothing) and logs the fallback,
so a damaged file cannot lock out root. The parser is the strict one used for
manifests: a repeated array, object or boolean key is a parse error and
`.include` is refused.

Authority follows the program. The set is fixed when login(1), su(1) or
sshd(8) asks the agent for the session channel, and every process under the
session shares it. A bundle launched from a shell does not inherit the
shell's set; switchboard starts it with its own label and its own manifest
set. `login`, `sshd` and `getty` run before there is a session, on the boot
channel switchboard installs ahead of rc; that channel holds every
anointment and the bypass.

The library API, for programs that need the same answers: 
`capbundle_principal_resolve(policy_fd, uid, gids, n, name2gid, ctx, &grant)`
fills a `struct capbundle_principal_grant`; `capbundle_principal_holds` and
`capbundle_principal_may_elevate` test one name against it;
`capbundle_principal_is_admin` (and the `_at`, `_fd`, `_resolved` variants)
answer whether a passwd entry carries admin rights; and
`capbundle_principal_declared_names` lists every non-wildcard name the file
mentions, which is what `switchboardctl graph --lint` uses. See
libcapbundle(3).

## The mint authority and who may mint

Only one unit may mint session lookup channels, and it is recognised by a
manifest role, not a hard-coded label:

```ucl
# usr.sbin/BSDAuth/capbundle/bsdauth.ucl
activation { boot = true; ipc = ["system.Auth"]; }
mint_authority = true;
visible = ["user"];
control = "core";
```

`mint_authority` is honoured only for a base-system bundle under
`/Capabilities/System`; a per-user agent that declares it has it stripped.
Within BSDAuth, minting is then gated on a held right, not on a name: only a
caller whose channel carries `SERVICE_RIGHTS_ADMIN` may request a session
mint, and switchboard stamps that right on a brokered session only for an
ambient login-session lookup over a SYSTEM channel, which is exactly the
channel the login family reaches BSDAuth over. Every ordinary unit, and every
login session reaching BSDAuth for elevation, is stamped without the bit and
is refused a mint with `EPERM` before the request is parsed. That closes the
proxy escalation in which a service or a user would ask the agent to mint an
admin session on its behalf.

`visible = ["user"]` opens only elevation to user sessions; a user session
that connects and sends a mint request is refused exactly as before.

Non-admin su is the other mint path. `su` changes uid and re-mints the whole
session; for an admin session that mint rides the caller's admin bit. An
ordinary session holds no such bit, so `su` there authenticates the target to
the agent directly (`service_mint_session_authenticated`, wire op
`MINT_AUTH`): the agent verifies the target's password against
`master.passwd`, rate-limited, and mints that principal's session set. An
operator can therefore `su` to another user and keep a working lookup
channel, scoped to that user's anointments. A unit, as opposed to a session,
cannot mint-auth at all.

## anoint(1): elevation in place of sudo and doas

Elevation is an operation, not a tool. A process on a session channel asks
the auth agent for one anointment in its principal's `may_elevate` list,
authenticates, and receives a channel holding the session's set plus that one
name. It is exposed to programs as `service_elevate(name, password,
timeout_ms, &fd)` in libservice(3), so a program that hits `ENOENT` can ask
for what it needs itself, and to the shell as anoint(1):

```sh
$ anoint system.notify.system notifyctl -s publish system.maint "reboot at 02:00"
Password:
$ anoint system.switchboard.admin switchboardctl restart system.Network
```

`anoint [-n] NAME CMD [ARG ...]` runs `CMD` as the caller, with the caller's
environment and working directory, over an ambient lookup channel whose set
is the session's set plus `NAME`. `-n` sends an empty password without
prompting, for an account whose stored password is empty; an account with an
empty or locked hash is refused regardless. There is no set-user-id binary
and no `sudoers`-style file; anoint needs a login, ssh or su session that
carries an ambient lookup channel.

Inside BSDAuth, each refusal audited:

1. **Policy before password.** The caller must be on a session channel; a
   unit's channel is refused `EPERM`. The uid is the kernel-stamped sender
   of the message, never the payload. `NAME` must be in that principal's
   `may_elevate`, or the entry must list `*`, else `EPERM` before any
   password is examined.
2. **Password checked in the agent.** The agent verifies the password with
   crypt(3), constant-time, against the hash in `/etc/master.passwd`, read
   through a read-only descriptor granted by BSDFilesystem's open policy.
   PAM is not used: module stacks cannot run in the sandbox. If the
   descriptor was not granted, elevation is disabled (`ENXIO`); minting is
   unaffected.
3. **Rate limit.** Five failures within sixty seconds for a uid refuse
   further requests with `EAGAIN` until the window has elapsed.
4. **Mint of set-plus-one.** A channel of the same kind and uid is minted,
   attenuated to transfer once, and returned. anoint installs it as the
   ambient channel and execs `CMD`.

The uid never changes. A command elevated to `system.switchboard.admin`
still runs as the user; it reaches the admin endpoint because it holds the
anointment. When `CMD` exits the channel is gone. Nothing is cached and
there is no timeout window. Work that genuinely needs uid 0 for POSIX
reasons, editing root-owned files or running `installworld`, keeps using
su(1).

| anoint message | Meaning |
|---|---|
| `not permitted` | `NAME` is not in this principal's `may_elevate`; no password was asked for |
| `authentication failed` | wrong password |
| `too many failures` | five failures within a minute |
| `no session channel` | not running inside a session |
| `elevation is not enabled on this system` | the agent was not granted `master.passwd` |

anoint exits 1 on a refusal, 126 when `CMD` could not be executed, 127 when
it could not be found, and otherwise with `CMD`'s status.

## Audit and observability

Where a decision is a security decision it is also a BSM record, committed
through `system.Audit`. One refused request yields exactly one record.

| Event | Number | When |
|---|---|---|
| `AUE_SWITCHBOARD_ANOINT` | 43328 | every anointment refusal (resolve, on-demand pre-check, control-plane gate) |
| `AUE_SWITCHBOARD_COMPONENT` | 43327 | every session mint, with the set's count and `all`/`admin` flags |
| `AUE_AUTHAGENT_ELEVATE` | 43335 | every ELEVATE outcome; operation `elevate/<stage>/<name>` |
| `AUE_AUTHAGENT_MINT` | 43336 | every MINT outcome; operation `mint/<kind>/n<count>[/all][/admin][/default]` |
| `AUE_BSDNOTIFY_POLICY` | 43333 | BSDNotify's per-operation refusals and tier mismatches |

BSDAuth commits its record right after sending the reply and opens its
`system.Audit` session lazily on the first record, so a slow audit broker
never delays a login. Passwords and hashes never appear in a record, a log
line or a probe. The probes are `switchboard:::anoint-allow`, `anoint-deny`,
`anoint-set`, `mint-anoint` and `anoint-visibility`; `authagent:::elevate-start`,
`elevate-done` (with a `stage` of `caller`, `shape`, `policy`, `ratelimit`,
`password`, `mint` or `ok`), `ratelimit-block` and `policy-resolve`; and
`service_ambient:::elevate-start`/`elevate-done` on the client side.
`/usr/share/dtrace/switchboard-anoint` prints the switchboard events live;
`bsdinstruments watch capability-services` summarises elevation outcomes by
stage.

## The reach graph

`switchboardctl graph [--text | --dot | --json] [--lint]` draws the reach
graph from the bundle registry on disk: every unit, every endpoint, and the
two session classes `session.default` (uid 65534, no groups) and
`session.admin` (uid 0). `--lint` exits 2 on an **unreachable** endpoint (a
name no unit declares and no principal is granted or may elevate to), a
**dead declaration** (a name nothing requires) or a **duplicate endpoint**.
`switchboardctl graph --dot | dot -Tsvg > anointments.svg` draws it.

## The live driver

The acceptance matrix runs against a real plane from
`tools/tools/anointments/live-scenarios.sh`. It is deliberately not a kyua
test: it needs a booted plane, real local accounts and passwords set before
the auth agent starts (BSDAuth reads `master.passwd` through a descriptor it
obtains at start-up). The one-time setup is in the script header: create
group `operators` and users `operator1` and `plainuser`, set their passwords,
install `scenario-policy.ucl` as `/Capabilities/Config/principal-policy.ucl`,
reboot, then run the script as root. It checks session reach for each tier,
anoint(1) through a real pty (anoint reads the password with
readpassphrase(3) and requires a tty), the non-admin su authenticated mint,
and `graph --lint` on the base tree. Its exit status is the number of failed
rows.

## Limits

The check is at the naming boundary only; what a client may do once
connected is the provider's own per-label policy. Declaration is the grant
until mac_veriexec fingerprints are enforced, so a bundle's `holds` is worth
exactly as much as the trust placed in installing it. Password automation
through anoint needs a pty. The `capability` uid must never appear in the
policy.

Reference: switchboard(5) (IPC ANOINTMENTS), BSDAuth(8), anoint(1),
switchboardctl(8), libcapbundle(3), libservice(3). Design:
`docs/ipc-anointments-design.md`. Related: [The Authority
Model](../capability/authority-model.md), [The Management
Model](management-model.md), [system.Notify](../providers/notify.md),
[system.Auth](../providers/auth.md).
