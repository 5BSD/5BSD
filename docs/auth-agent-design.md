# Auth-agent design (P1c): the identity→capability mint boundary

Status: design, written before code. Implements the "auth agent" seam of
[`capability-authority-model.md`](capability-authority-model.md) §1/§3. This is
the last structural piece of the capability-authority migration: it moves the
`principal → capability bundle` decision out of `login`/`su`/`sshd` and into one
small, capsicum-sandboxed daemon.

## 1. The problem it solves

Authority in this OS is a **held capability**, never a uid. But *somewhere* a
proven identity (password, key, token) must be translated into "which
capabilities this principal holds." Today that translation lives in three large,
network-facing programs:

- `login(1)`, `su(1)`, `sshd` each call `capbundle_principal_is_admin()` (reading
  `/Capabilities/Config/principal-policy.ucl`) and then mint a session lookup
  channel over the **SYSTEM channel they hold**.

That means each of those programs holds mint-capable authority. A compromise in
any of them can mint a SYSTEM (admin) session for an arbitrary principal.

The auth-agent collapses the decision **and** the mint-capable channel into one
tiny sandboxed service. `login`/`su`/`sshd` stop holding minting power — they
authenticate and *ask*.

## 2. No new kernel type

A "user handle" or "gid handle" as a kernel object is explicitly **rejected**: it
would re-inject identity into the kernel authorization path, which is exactly
what this model removes. The kernel already provides everything needed —
capability channels and `cap_xfer` attenuation.

- The **principal** (e.g. `alice`, uid 1001) is a **name** — a policy lookup key,
  passed as request data. The kernel never learns about users.
- The **trust** that a caller may request a mint is a **held capability** (reach
  the auth-agent), delegated at boot. A process without it cannot ask.
- Passing the principal as untrusted data is safe: the auth-agent trusts its
  caller (a login program) to have authenticated the named principal, and a
  compromised authenticator can already `setuid` to anyone — a kernel-bound
  principal would add no protection.

For **audit/accounting**, the existing `mac_capability_identity` per-process
nonce suffices (an opaque token audit maps back to the login event) — an opaque
nonce, never a uid, so it cannot be repurposed for authorization.

## 3. Placement: a serviced-managed service, not a PID-1 peer

```
authority-init (PID 1)
   └── serviced
         ├── system.authagent      (the auth-agent — this design)
         ├── system.Network, system.Filesystem, system.Audit, ...
         └── (all other capability services)
```

The auth-agent is a normal capability bundle: serviced launches it from its
manifest (capsicum-sandboxed), supervises/restarts it, orders it before getty,
and it **registers `system.authagent`** in the naming plane. It is a **client**
of serviced (it brokers the actual channel creation to serviced's
`SVC_OP_MINT_DOMAIN`), not a peer.

Rationale: reuse serviced's process model instead of growing PID 1; the bundle
manifest is the explicit, auditable grant of the mint-capable channel; and
serviced is already trusted (it is the mint mechanism), so peering buys no trust
and costs complexity. Net TCB = `{serviced, auth-agent}`, down from
`{login, su, sshd}` each holding the SYSTEM channel.

## 4. The three parties and the trust flow

1. **`authority-init` (PID 1)** — unchanged role. Starts serviced. Continues to
   carry an ambient channel into getty (§21), but a **narrowed** one (see §6).

2. **serviced** — starts `system.authagent` from its manifest, which grants the
   auth-agent a mint-capable SYSTEM lookup channel. serviced keeps doing the
   actual minting (`SVC_OP_MINT_DOMAIN`); the auth-agent decides *what* to mint.

3. **auth-agent (`system.authagent`)** — capsicum-sandboxed, holds:
   - the `principal → bundle` policy (`principal-policy.ucl`), and
   - a mint-capable SYSTEM channel to serviced.
   It serves one operation (see §5): given an authenticated principal, apply
   policy, mint the scoped bundle via serviced, and return it.

4. **`login` / `su` / `sshd`** — authenticate exactly as today (PAM/keys —
   unchanged BSD). They hold **only** a capability to reach `system.authagent`,
   never a mint-capable channel. After authentication they call the auth-agent
   and install the returned bundle as the session leader's inherited channel.

## 5. The protocol (one operation)

`AUTHAGENT_OP_MINT_SESSION`:

- **request** (over the `system.authagent` channel): `{ uid, gid, /* the
  authenticated principal, by name */ }`. No credential is sent — authentication
  already happened; holding the reach-capability *is* the assertion "I am a
  trusted authenticator and I have authenticated this principal."
- **reply**: `{ status }` plus, on success, the minted session lookup channel
  attached via SCM_RIGHTS, scoped per policy (SYSTEM for an admin principal, a
  per-uid USER channel otherwise). Delivered with the same `cap_xfer` discipline
  as the current sshd provisioning (transferable for the one install hop, then
  `CAP_XFER_NONE` at the leaf so a session cannot re-delegate its channel).

The auth-agent computes the scope with the existing
`capbundle_principal_is_admin()` policy logic (moved into the daemon), then
issues `SVC_OP_MINT_DOMAIN` to serviced with that scope and forwards the result.

## 6. Boot / login carry (§21 revised)

Today getty inherits the full SYSTEM lookup channel. In this design it inherits a
channel **scoped to only `{system.authagent}`** — enough to reach the auth-agent,
not to mint or to discover other names. Mechanics:

- serviced mints a `{system.authagent}`-scoped lookup channel and forwards it to
  authority-init, which installs it at `SERVICE_LOOKUP_FIXED_FD` in each getty
  child (the existing §21 carry, just a narrower channel).
- `sshd` obtains the same narrow reach-channel the way it obtains the ambient
  channel today (inherited from rc), and its monitor calls the auth-agent instead
  of minting directly — the sshd fd-plumbing and per-session install are already
  in place; only the "who mints" endpoint changes.
- **`su`**: an admin session's bundle *includes* the reach-`system.authagent`
  capability, so `su` can re-authenticate and request a fresh bundle for the
  target principal. A non-admin session's bundle omits it — a regular user cannot
  re-mint.

## 7. Failure / degradation

Every step stays best-effort and non-fatal, exactly like the current mint path:
if the auth-agent is unreachable or refuses, the session simply carries **no**
ambient channel and login proceeds. serviced supervises and restarts the
auth-agent; a momentary outage never blocks a login or the boot.

## 8. What does NOT change

- Kernel: nothing. No new type, no new syscall.
- serviced: keeps `SVC_OP_MINT_DOMAIN` and the naming plane; it gains one more
  service to launch and one manifest grant (the mint-capable channel to the
  auth-agent).
- `login`/`su`/`sshd`: keep their authentication (PAM/keys) verbatim; only the
  post-auth step changes from "decide + mint locally" to "ask `system.authagent`."
- The policy file and `capbundle_principal_is_admin()` logic are reused — the
  logic moves into the daemon, the file format is unchanged.

## 9. Migration order

1. Build the auth-agent daemon (`system.authagent` bundle) that serves
   `AUTHAGENT_OP_MINT_SESSION` by applying policy + brokering `SVC_OP_MINT_DOMAIN`.
2. Add the client call in `login`/`su`/`sshd` behind the presence of a
   reach-channel; keep the direct-mint path as a fallback during rollout.
3. Narrow the §21 getty carry to `{system.authagent}` and flip the login programs
   to the auth-agent path.
4. Remove the direct-mint fallback and the SYSTEM-channel carry once the
   auth-agent path is VM-verified (login/su/ssh, admin + non-admin, concurrent).
