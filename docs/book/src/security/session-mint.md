# The Authentication Boundary

Authentication answers *who is this principal?* Authorization on 5BSD answers
*what capability does this session hold?* — and those are two different
questions handled in two different places. This chapter documents the single
component that turns the first answer into the second: the **auth-agent**
(`system.authagent`, the `authagentd` daemon), the one place a proven identity
becomes a held capability.

Design source: `docs/auth-agent-design.md`; the model it serves is
`docs/capability-authority-model.md` (see [The Authority
Model](authority-model.md)).

Status: implemented and clean-VM verified. `login`, `su`, and `sshd` all
provision their sessions through the agent; direct minting is retired.

## The problem it solves

A login program (`login`, `su`, `sshd`) authenticates a principal — a password,
a key, a PAM stack — and must then hand the session a **capability lookup
channel** scoped to that principal: a SYSTEM (admin, full-discovery) channel for
an administrator, a per-uid USER channel for everyone else (see
[The Authority Model](authority-model.md) for the domains).

Before the auth-agent, each of `login`, `su`, and `sshd` did this itself: it
classified the principal (root or `wheel` → admin), held a mintable SYSTEM
channel inherited from boot, and minted the session channel directly. That put
**mint authority — the ability to conjure an admin capability for any uid — in
three separate, privileged, network-facing programs.** A bug in any one of them
forged administrative authority. The trusted base for the decision was
`{login, su, sshd}`.

## The auth-agent

`authagentd` is a small, `serviced`-managed, capsicum-sandboxed capability
service that exposes the name `system.authagent`. It is **not** a PID-1 peer; it
is an ordinary managed service that happens to hold the session-mint capability.
A login program, having authenticated a principal, connects to `system.authagent`
over its inherited ambient lookup channel and asks it to mint the session
channel for a uid. The agent does three things:

1. **Resolves the principal authoritatively — via Casper.** The agent runs
   inside a capsicum sandbox, so it cannot `open()` `/etc/master.passwd` or
   `/etc/group` by path. It uses **Casper** (`cap_pwd` / `cap_grp`, brought up
   before `cap_enter`) to resolve the uid to its passwd entry and group
   membership. This is not a convenience: the agent must resolve identity
   *itself* and must **never trust attributes sent by the caller** — the login
   program is exactly what we are removing from the trusted base, so a
   compromised one must not be able to claim `wheel` membership it does not
   have.

2. **Applies the principal→domain policy.** This is the critical piece:
   **`/Capabilities/Config/principal-policy.ucl` is the single config that
   decides which authority domain a principal's session receives.** It is an
   explicit list:

   ```ucl
   admin {
       uids   = [ 0 ]        # principals granted the SYSTEM (admin) domain by uid
       groups = [ "wheel" ]  # ...and by group membership
   }
   ```

   A principal named here — by uid or by membership in a named group — gets a
   **SYSTEM** (full-discovery admin) session; every other principal gets a
   per-uid **USER** session (see [The Authority Model](authority-model.md) for
   what each domain can reach). The file is delivered to the sandboxed agent as
   an optional [`capabilities.open`](capability-bundles.md) descriptor, so the
   agent reads it without ever opening a path. It is the one authoritative place
   the domain assignment is stated; an absent or unparseable policy fails safe to
   the historical default — **root, or a member of `wheel`, is admin** — so a
   system with no policy behaves exactly as before and a typo can never lock out
   root.

3. **Mints the scoped channel and returns it.** The agent mints a SYSTEM or
   USER session lookup channel over **its own unit bootstrap channel** to
   `serviced`, re-attenuates the descriptor's transfer state, and returns it.
   The login program installs it as the session leader's inherited lookup
   channel; the shell and its descendants resolve services through it at exactly
   their privilege level.

The trusted base for the session-mint decision is now `{serviced, authagentd}` —
two components — instead of `{login, su, sshd}`.

## Direct minting is retired

Moving the decision into the agent is only half the guarantee; the other half is
that the login programs can no longer make it themselves. `serviced` **refuses
`SVC_OP_MINT_DOMAIN` on any ambient lookup channel**: a session leader can still
*look up* `system.authagent` over its inherited channel, but it can no longer
mint its own session channel. The agent mints over its unit bootstrap channel (a
different path, unaffected). So even the SYSTEM ambient carry that `getty` hands
`login` is now **lookup-only** for the mint operation, and `login`/`su`/`sshd`
hold no mint authority at all — they call the agent and, if it is unreachable,
simply carry no lookup channel (best-effort, never fatal). The §21 ambient carry
is correspondingly narrowed toward `{system.authagent}` reachability rather than
general mint power.

`sshd`'s privilege-separated monitor is the one caller that must forward the
minted descriptor over one more `SCM_RIGHTS` hop to its session child; it
requests a **forwardable** channel and re-attenuates it to single-transfer
before the hand-off. The monitor provisions only for the *authenticated*
principal (`authctxt->pw`), never a uid the untrusted child chose.

## What this does and does not touch

- **Single-user mode is unaffected.** `init` spawns the recovery shell
  directly — no `getty`, no `login`, no ambient carry, and the capability plane
  is not running — so none of this is in that path. A `boot -s` root shell
  always works.
- The agent decides *scope* (SYSTEM vs USER); `serviced` enforces *reach* at
  every lookup (see [The Authority Model](authority-model.md)). The policy file
  is coarse — administrator or not — and picks the domain, not per-service
  permissions.
- Passwd/group *content* still lives in the usual files; the agent reads them
  through Casper. There is no new identity database.

## Verified

On a clean-built image: console `login` as root, and `su`/`ssh` for a non-`wheel`
user (→ USER), a `wheel` user (→ SYSTEM), and root (→ SYSTEM) all provision
their session channel through the agent — every mint appears in the agent log,
no direct mint succeeds, and a `wheel` user is classified administrator because
the agent's Casper lookup discovered the membership, not because the login
client claimed it.
