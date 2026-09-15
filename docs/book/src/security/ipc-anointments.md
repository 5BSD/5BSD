# IPC Anointments

`switchboard` resolves a name for whoever asks. Before anointments the only
question it asked was *which* name: inside a domain every unit could reach
every visible name, and a provider that wanted to limit who reached it
improvised the limit in its own configuration, with its own defaults. Nothing
on the system could say which program may talk to which.

An **anointment** is a dotted name for the privilege to reach an endpoint. A
provider gates an endpoint by listing the anointments a connecting program
must hold; a program declares the anointments it holds; `switchboard` compares
the two at lookup and reports a miss as `ENOENT`, audited. A login session has
no policy file, so the auth agent decides its set at mint from the principal
policy, and `anoint(1)` extends that set by one name for one command. The idea
is inspired by macOS entitlements; the check happens once, at the naming
boundary, and never as a uid test inside a provider.

That is the whole model. The rest of this chapter is the details.

## Gating an endpoint

An `activation.ipc` entry is either a bare name (an open endpoint) or an
object with `name` and `requires`:

```ucl
activation {
    ipc = [
        "system.Notify",                                 # open
        { name = "system.Notify.System";
          requires = ["system.notify.system"]; }         # gated
    ];
}
```

- `requires` is one name or an array of at most eight unique names. With
  several names a requester must hold **all** of them.
- A bare string, an object without `requires`, and an object whose `requires`
  is empty all publish an open endpoint. Nothing changes for any endpoint that
  does not add `requires`.
- One daemon may publish an open and a gated endpoint side by side. That is
  the intended way to separate a privileged surface from an unprivileged one
  (see [Split endpoints](#split-endpoints-dont-grow-policy-files)).

`switchboard`'s own control endpoints, `system.switchboard` and
`system.lifecycle`, are gated on `system.switchboard.admin`.

## Declaring what a program holds

A unit declares its set with one top-level key in `Unit.ucl`:

```ucl
anointments = ["system.notify.system"];
```

One name or an array of at most 32 unique names; absent means the empty set.
A unit holding nothing still reaches every open endpoint. A declared name that
no endpoint requires is harmless (`switchboardctl graph --lint` flags it as a
dead declaration). Base bundles under `/Capabilities/System` get no free pass:
a base unit with no `anointments` is refused a gated endpoint like any other,
and `switchboard` itself declares what it needs.

## Naming rules

An anointment name is a reverse-domain name, validated by the same rule as an
endpoint name:

- letters, digits, `-`, `_`, and `.`; at least one dot; no leading, trailing,
  or doubled dots; shorter than 64 characters;
- lower-case by convention (`system.notify.system`,
  `org.example.mail.admin`), so it reads differently from the endpoint it
  guards (`system.Notify.System`);
- `*` is never a valid name in a bundle's policy file, in `requires` or in
  `anointments`. `libcapbundle` rejects such a bundle at verify, install, and
  load. The wildcard is legal only in the
  [principal policy](#who-gets-what-at-login-the-principal-policy).

The `system.` prefix belongs to the base system. Third-party bundles name
their anointments in their own reverse-DNS namespace, as they name their
endpoints.

## What switchboard does at lookup

A unit's set is read from its policy file at every exec. A session's set was
decided at mint and rides on the session channel. When a lookup arrives,
`switchboard`:

1. applies the existing domain rules;
2. if the endpoint has `requires`, checks that the requester's set covers it.
   A miss is refused: internally `EACCES`, on the wire `ENOENT`,
   indistinguishable from an unregistered name, so a program cannot enumerate
   what it may not reach;
3. commits an audit record for every refusal (`AUE_SWITCHBOARD_ANOINT`,
   43328) with the requester's label, the endpoint, and the missing names,
   and fires the `switchboard:anoint-deny` probe;
4. applies the same check *before* on-demand activation. A program that cannot
   reach a provider cannot start it.

Two consequences of that order:

- **Visibility.** A gated endpoint is visible to any unit or session whose
  set covers it, regardless of the provider's `resolvable_by`. The provider
  gated it, so it said who may reach it. Open endpoints keep the
  `resolvable_by` rule of `switchboard(5)`, which is how a provider such as
  `logd` opts its open endpoint into resolution from login sessions. A
  user-visible name is simply an open endpoint whose provider opted in.
- **Identity.** The grant a provider receives on a new connection carries the
  requester's label, its per-exec kernel nonce, and its ABI (native or
  Linux). Units carry their policy-file label; anything on an ambient session
  channel (a shell, `sshd`, whatever `switchboard` did not launch) carries the
  reserved `org.5bsd.user-session`, which no bundle may claim, so a provider
  can tell it is not talking to capability-world software. The label is the
  persistent identity, the nonce the running instance. ABI is information
  for the provider; it never gates reach. Only anointments do.

`switchboardctl reload` picks up changes. The on-disk registry, refreshed by
reload, is consulted first, and a running provider's own copy of its policy
only for a name the registry does not know, so adding `requires` to a
provider's endpoint takes effect at the next reload without restarting the
provider.

`resolvable_by`, rights bits, helper names, and on-demand activation are
otherwise unchanged. Anointments are an additional check, not a replacement.

## Declaration is the grant

There is no separate grant step. A bundle that declares
`anointments = ["system.notify.system"]` holds it as soon as the bundle is
installed and loaded. The trust decision is therefore **installation**: whoever
runs `switchboardctl install`, or the package that does, accepts every
anointment in the bundle's policy file, exactly as they accept its program,
its activation, and its limits today.

The later gate is code signing and filesystem integrity: `mac_veriexec` with
signed fingerprint manifests covering each bundle's policy files and
programs, verified against enrolled keys. `switchboard` will open each unit's
policy file with `O_VERIFY` before honouring its anointments, and the kernel
will refuse to exec a modified program, so the nonce names a verified image.
Trusting an enrolled key then means trusting every anointment it declares.
Nothing in this chapter changes when that lands.

## Split endpoints, don't grow policy files

The pattern anointments make possible: a provider that wants a privileged and
an unprivileged surface publishes two endpoints and lets `switchboard` decide
who reaches which, instead of accumulating per-client tables in its own
configuration.

`bsdnotify` is the worked example. It publishes two tiers of one service:

| Endpoint | Gate | Default policy |
|---|---|---|
| `system.Notify` | open | subscribe to anything, publish only under `user.*`, no timers |
| `system.Notify.System` | `requires = ["system.notify.system"]` | publish anywhere, state, timers |

The tier is decided by the endpoint a session was accepted on, cross-checked
against the name `switchboard` resolved, never by anything the client sends.
`bsdnotify.conf` states one default block per tier, `default {}` for the open
tier and `system_default {}` for the gated one, and `clients {}` narrows a
specific label on the gated tier only:

```ucl
default        { subscribe = ["*"]; publish = ["user.*"]; timers = false; }
system_default { publish = ["*"]; subscribe = ["*"]; timers = true; }
clients {
    "com.example/publisher" {
        publish = ["system.shutdown.*"]; subscribe = ["*"]; timers = true;
    }
}
```

Topic lists take an exact topic, a `prefix.*` pattern (`user.*` matches
`user.x` and `user.x.y`, not `user`), or a bare `*` as the only entry. A
missing list denies, so an empty block denies everything.

Before anointments the shipped `clients {}` was empty and undeclared labels
were denied, so an ordinary user's connection succeeded and every operation
failed. Now a default user connects to the open tier and publishes under
`user.*`; a unit declaring `system.notify.system` reaches the gated tier; a
session that holds nothing gets `ENOENT` on `system.Notify.System` before the
daemon is involved. `notifyctl -s` selects the gated tier; without the
anointment the open fails with `ENOENT`. The admin bypass is unchanged: a
session carrying `SERVICE_RIGHTS_ADMIN` bypasses policy on either tier.

The rule for other providers is the same: publish an endpoint per privilege
tier, gate the privileged one, keep the provider's own configuration for
narrowing within a tier.

## Who gets what at login: the principal policy

A unit gets its set from its policy file. A login session has no policy file,
so the **auth agent** (`authagentd`, `system.authagent`) decides what it
holds, at mint, from `/Capabilities/Config/principal-policy.ucl`. That
carried set plus the uid *is* the session's domain. What used to be two
hard-coded kinds (SYSTEM held everything, USER held nothing) is now a set the
policy fills in; the kind enum stays beside the set during the transition,
SYSTEM when the grant holds `*` or carries admin rights, a per-uid USER kind
otherwise.

```ucl
principals {
    admin     { groups = ["wheel"]; uids = [0]; anointments = ["*"];
                admin_rights = true; }
    operators {
        groups      = ["operators"];
        anointments = ["system.trace.client"];      # held from login
        may_elevate = ["system.notify.system"];     # on request, per command
    }
    default   { anointments = []; }
}
```

**Matching.** Entries are matched in file order against the authenticated
principal's uid and full group membership (its primary group plus every group
whose member list names it), which the agent resolves itself from `passwd`
and `group` descriptors it retained before entering capability mode; nothing
the login program claims is trusted. The first entry whose `uids` or `groups`
matches wins. An entry with neither list is the fallback for everyone else,
conventionally named `default`. Entry names are for the operator; only the
lists match.

**Three knobs per entry.**

- `anointments` — what the session holds from login, silently, for every
  process under it.
- `may_elevate` — what the principal does not hold but may ask for, one
  command at a time, after re-entering its password (see
  [anoint](#anoint-elevation-in-place-of-sudo-and-doas)). Absent or empty
  means the principal can never escalate, whatever it types.
- `admin_rights` — whether connections from the session carry the
  `SERVICE_RIGHTS_ADMIN` bit providers honour as an in-endpoint bypass. It is
  separate from reach: a site can narrow root's anointments and keep its
  bypass, or the reverse. It defaults to true only for an entry whose
  `anointments` are `["*"]`. A unit never carries it.

`*` is legal in `anointments` and `may_elevate` here and nowhere else.

**The shipped default** is the `admin` and `default` entries above: `wheel`
and uid 0 hold `*` with admin rights; everyone else holds nothing and may
elevate nothing. Nothing changes on day one. The file is configuration, so
local edits survive package upgrades. The legacy top-level
`admin { uids; groups; }` form is still accepted and means the same as the
`admin` entry.

**"Holds nothing" is not "connects to nothing."** An empty set means no
*gated* endpoint. Every endpoint published without `requires` stays
reachable, and that is expected to be the whole ordinary-user surface:
`system.Log`, the open tier of `system.Notify`, and whatever else a provider
publishes without a requirement. Only privileged tiers need an anointment.

**Root is just a principal.** `switchboard` never looks at the uid; the auth
agent is the only place a uid becomes a set. So a site may give root some
anointments and not all:

```ucl
root { uids = [0]; anointments = ["system.switchboard.admin"];
       may_elevate = ["*"]; admin_rights = false; }
```

That root shell reaches one gated endpoint, asks per command for anything
else, and every ask is audited. Root's POSIX powers over the filesystem are
untouched; what sits behind anointments is the capability daemons and
TrustedZFS cap-fd storage. The stricter profile for administrators, `wheel`
holding a short list (or nothing) with `may_elevate = ["*"]` and
`admin_rights = true`, is a policy edit: the in-endpoint bypass survives while
every gated reach becomes an audited ask.

**The `capability` uid is not a principal.** It is the unprivileged uid
`switchboard` runs units as. Units never consult this file; their set comes
from their own policy file and their uid plays no part in the match. Do not
list it: the agent logs a warning at startup if an entry grants it anything.
If anything ever logged in as that uid it would fall under `default` and hold
nothing, which is the right answer.

**A malformed file falls back.** If the policy is missing or does not parse,
the agent applies the historical rule (uid 0 or a member of `wheel` holds
everything with admin rights; everyone else nothing) and logs the fallback so
it is observable. A damaged file cannot lock out root. The parser is the
strict one used for unit files: a repeated array, object, or boolean key
(`default {} default {}`, `uids` given twice) is a parse error, and
`.include` is refused. A repeated scalar string key is the one shape libucl
still folds into a list.

**Authority follows the program.** The set is fixed when `login`, `su`, or
`sshd` asks the agent for the session channel, and every process under the
session shares it. `su` to another principal re-mints and gets that
principal's set, larger or smaller. A bundle launched from a shell does
**not** inherit the shell's set: `switchboard` starts it with its own label
and its own policy-file set. The terminal a program was typed into grants it
nothing.

`login`, `sshd`, and `getty` run before there is a session, on the boot
channel `switchboard` installs ahead of `rc`. That channel holds every
anointment and the bypass, so the login family and `rc` behave as before.

## anoint: elevation in place of sudo and doas

Elevation is an operation, not a tool: a process on a session channel asks
the auth agent for one anointment in its principal's `may_elevate` list,
authenticates, and receives a channel holding the session's set plus that one
name. It is exposed to programs as `service_elevate(3)` in `libservice`, so a
program that hits `ENOENT` can ask for what it needs itself, and to the shell
as `anoint(1)`, which replaces `sudo` and `doas`:

```sh
anoint system.notify.system notifyctl -s publish system.maint "reboot at 02:00"
anoint system.switchboard.admin switchboardctl restart system.Network
```

`anoint [-n] NAME CMD [ARG ...]` runs `CMD` as the caller, with the caller's
environment and working directory, over an ambient lookup channel whose set
is the session's set plus `NAME`. `-n` sends an empty password without
prompting, for scripts and accounts whose stored password is empty; an
account with an empty or locked hash is refused regardless. `anoint` needs a
session: a login, `ssh`, or `su` shell that carries an ambient lookup
channel. There is no set-user-id binary and no `sudoers`-style file.

**The four steps**, inside `authagentd`, each refusal audited:

1. **Policy before password.** The caller must be on a session channel; a
   unit's channel is refused `EPERM` (units declare, they do not elevate).
   The uid is the kernel-stamped sender of the message, never the payload,
   which carries only the name and the password. `NAME` must be in that
   principal's `may_elevate`, or the entry must list `*`, else `EPERM` before
   any password is examined.
2. **Password checked in the agent.** The agent verifies the password with
   `crypt(3)`, constant-time, against the hash in `/etc/master.passwd`, read
   through a read-only descriptor it retained before entering capability mode
   and zeroed after each check. PAM is not used: module stacks cannot run in
   the sandbox. `login`, `su`, and `sshd` keep their own PAM. If the
   filesystem daemon did not grant `master.passwd`, elevation is disabled
   (`ENXIO`); minting is unaffected.
3. **Rate limit.** Five failures within sixty seconds for a uid refuse
   further requests with `EAGAIN`, without a password check, until the window
   (anchored on the first failure) has elapsed. A success clears the counter.
4. **Mint of policy-set-plus-one.** A channel of the same kind and uid is
   minted whose set is the principal's policy set plus `NAME`, attenuated to
   `CAP_XFER_ONCE`, and returned. `anoint` installs it as the ambient channel
   and execs `CMD`.

The uid never changes. A command elevated to `system.switchboard.admin` still
runs as the user; it reaches the admin endpoint because it holds the
anointment, not because it is root. When `CMD` exits the channel is gone (it
is descriptor inheritance, so a child `CMD` left running keeps it until that
child exits). Nothing is cached and there is no timeout window; a second
`anoint` authenticates again. The request buffer holding the password is
zeroed on both sides.

**Exit status.** `anoint` exits 1 when it refuses to run `CMD`, 126 when
`CMD` was found but could not be executed, 127 when it could not be found,
and otherwise with `CMD`'s status. The refusals:

| Message | Meaning |
|---|---|
| `not permitted` | `NAME` is not in this principal's `may_elevate`. No password was asked for. |
| `authentication failed` | wrong password |
| `too many failures` | five failures within a minute; wait |
| `session already holds the maximum number of anointments` | the policy set is full (`E2BIG`) |
| `no session channel` | not running inside a session |
| `auth agent unavailable` / `auth agent did not answer` | the agent is not registered, or did not reply within five seconds |
| `elevation is not enabled on this system` | the agent was not granted `master.passwd` |
| `auth agent rejected the request` / `malformed reply from auth agent` | a library/agent version mismatch |

**When you still use `su`.** `anoint` grants a named capability, never a
uid. Work that genuinely needs uid 0 for POSIX reasons, editing root-owned
files, `installworld`, anything outside the capability plane, keeps using
`su`, which authenticates through PAM and re-mints the whole principal's
session as before.

**Open item.** A non-admin session's `su` to another user currently gets no
lookup channel (`su: no lookup channel for uid …: Operation not permitted`):
the agent's MINT is gated on the caller's `SERVICE_RIGHTS_ADMIN`, and `su`
from an operator session lacks it. That is correct against escalation, since
a non-admin caller must not mint an arbitrary uid's session, but it means a
non-root `su` loses the plane entirely. The intended fix is for the agent to
authenticate the target principal itself on a non-admin mint, the way ELEVATE
already verifies a password.

## Operator tooling

### The reach graph

`switchboardctl graph [--text | --dot | --json] [--lint] [--root dir]` draws
the anointment reach graph from the bundle registry on disk; no running
`switchboard` is consulted. Nodes are every unit, every endpoint, and two
session classes: `session.default`, the set the principal policy grants uid
65534 with no groups, and `session.admin`, the set it grants uid 0. An edge
runs from a consumer to an endpoint when the endpoint is open or the
consumer's set covers its `requires`; for open endpoints `session.default`
also follows `resolvable_by`. `--text` (the default) prints one edge per
line, `--dot` a Graphviz digraph
(`switchboardctl graph --dot | dot -Tsvg > anointments.svg`), and `--json` a
stable object with `units`, `sessions`, `endpoints`, `edges`, and `warnings`.

`--lint` exits 2 if it reports any of:

- **unreachable** — an endpoint requires a name that no unit declares and no
  principal is granted. Nothing on the system can ever connect to it.
- **dead declaration** — a unit declares, or a principal is granted, a name
  that no endpoint requires. Usually a typo on one side. A session's `*` is
  not a declaration.
- **duplicate endpoint** — two bundles publish one endpoint name.
  `switchboard` refuses the second at load; the graph warns so you see it
  first.

An absent or malformed principal policy is noted on standard error and the
historical rule applied. `SWITCHBOARD_BUNDLE_DIR_SYSTEM`,
`SWITCHBOARD_BUNDLE_DIR_USER`, and `SWITCHBOARD_PRINCIPAL_POLICY` override the
inputs.

### DTrace

Every decision is a USDT probe. Arguments are labels, names, uids, and small
integers; never a password, a hash, or capability material.

- `switchboard:anoint-allow(name, requester, nrequires)`,
  `anoint-deny(name, requester, missing)`,
  `anoint-set(label, count, all, admin)` (a set decided: a unit's at exec, a
  session's at mint), `mint-anoint(uid, count, all, admin, status)`, and
  `anoint-visibility(name, uid)` (a USER-kind channel saw a gated name
  through the visibility rule).
- `authagent:elevate-start(client)`,
  `elevate-done(client, uid, name, status, transport_errno, stage)` with
  `stage` one of `caller`, `shape`, `policy`, `ratelimit`, `password`,
  `mint`, `ok`; `ratelimit-block(uid, failures)`;
  `policy-resolve(uid, count, all, admin, from_default)` for both MINT and
  ELEVATE; `request-start`/`request-done` for MINT.
- `service_ambient:elevate-start(name)` / `elevate-done(name, errno)`, the
  client side in every process that calls `service_elevate(3)`.
- `bsdnotify:session-admit(label, tier, rights, abi)` at accept and
  `tier-policy(label, tier, source)` when the router picks `default`,
  `system_default`, or `clients`.

`/usr/share/dtrace/switchboard-anoint` prints allow, deny, set, mint, and
visibility events live with a summary on exit.
`bsdinstruments watch capability-services` summarises elevation outcomes by
stage, rate-limit hits, policy grants, anointment matches, and notify
admissions.

### Audit

Where a decision is a security decision it is also a BSM record, committed
through `system.Audit` ([auditbrokerd](auditbrokerd.md)). One refused request
yields exactly one record.

| Event | Number | When |
|---|---|---|
| `AUE_SWITCHBOARD_ANOINT` | 43328 | every anointment refusal (resolve, on-demand pre-check, control-plane gate) with requester label, endpoint, missing names |
| `AUE_SWITCHBOARD_COMPONENT` | 43327 | every session mint, with the set's count and `all`/`admin` flags |
| `AUE_AUTHAGENT_ELEVATE` | 43335 | every ELEVATE outcome; operation `elevate/<stage>/<name>` |
| `AUE_AUTHAGENT_MINT` | 43336 | every MINT outcome; operation `mint/<kind>/n<count>[/all][/admin][/default]` |
| `AUE_BSDNOTIFY_POLICY` | 43333 | `bsdnotify`'s per-operation refusals, plus `admit-tier-mismatch-{open,system}` when a connection's resolved endpoint disagrees with the listener it arrived on |

The agent commits its record right after sending the reply, and opens its
`system.Audit` session lazily on the first record rather than before it
checks in: the agent is on every login's critical path, so a slow or absent
broker may delay the next request but never the channel of the one it
describes, and never the agent's own start-up. If `system.Audit` is
unreachable the record is dropped with a syslog warning and the session
re-opened lazily; there is no hard dependency. Passwords and hashes never
appear in a record, a log line, or a probe.

Reference: `switchboard(5)` (IPC ANOINTMENTS), `authagentd(8)`, `anoint(1)`,
`switchboardctl(8)`, `bsdnotify(8)`, `notifyctl(8)`, `libservice(3)`.
Design: `docs/ipc-anointments-design.md`.

## See also

- [The Authority Model](authority-model.md) — the mint boundary the auth
  agent guards, and where a uid still matters.
- [Rootless Hardening](rootless-hardening.md) — the shipped policy as a
  security boundary.
- [Service Manifests](../system/manifests.md) — the rest of the unit policy
  file.
- [Notifications (bsdnotify)](../system/bsdnotify.md) — the two-tier
  provider.
