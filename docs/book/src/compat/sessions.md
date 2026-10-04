# Sessions: login, su, ssh and cron

A 5BSD process can hold a discovery channel in kernel process state, independently
of its open descriptors and environment. Ordinary fork, exec, `closefrom()` and
`env -i` preserve that reference. Programs use libservice to obtain an owned,
close-on-exec working descriptor; each working handle has a private reply queue.
Neither fd 3 nor `SERVICE_LOOKUP_FD` selects discovery.

## Authentication boundaries

The boot launch paths give authorized login providers access to BSDAuth.
Capsule installs that context before the configured window-system fork and getty
exec. SwitchBoard installs boot discovery for the existing authorized rc launch
paths. Managed capability units receive their own manifest-scoped discovery,
separate from provider control and from login principal policy.

An authentication boundary replaces inherited provider authority with a channel
minted for the authenticated target UID. Changing UID alone never selects another
user's grants. The kernel denies an old context after an unprovisioned change of
real UID or prison; temporary effective-UID changes do not select new policy.

| Boundary | Handoff |
|---|---|
| Console login | The required `pam_capability` session module asks BSDAuth for the authenticated user's scope, installs it for that UID, and closes working descriptors. |
| `su` | Captures an owned provider handle after authentication and before PAM credential/session modules; the child clears inherited scope, changes identity and mints the target's policy. An ordinary caller proves the target password to BSDAuth. |
| SSH | Each connection's privileged monitor obtains a private lookup endpoint. It mints only for `authctxt->pw`, ignoring a UID supplied by the unprivileged child. The child installs that context before starting the user program. No discovery FD is reserved across listener re-exec. |
| Cron | Opens a PAM session for every job, including system-crontab jobs. System tasks retain their historical account-availability exemption, but receive unprivileged discovery bound to the job owner. |
| `at` | The per-job runner opens a PAM session before dropping identity. The default stack requests unprivileged discovery for the job and mailer; closing the PAM session does not revoke other processes' references. |

The `unprivileged` PAM option requests public USER discovery with no endpoint
anointments or administrative rights, even for a root-owned job. This avoids treating
permission to edit a crontab as authentication for the owner’s interactive grants.
A system builder may explicitly choose a different trusted session configuration.

Cron and atrun also discard an unchanged inherited context when a customized PAM
stack omits provisioning. This matters for root-owned jobs: their UID matches the
scheduler, so UID isolation alone would not discard its boot authority.

Base also supplies `/etc/pam.d/sddm-greeter`. It retains the greeter's UNIX/XDG
setup and requests unprivileged discovery. Normal and autologin SDDM user
sessions include the base login session stack. No SDDM source patch or ports-tree
override is needed for the process context transport.

Other PAM login providers can use `pam_capability` at their session boundary.
Ordinary child programs need no descriptor-preservation patch. Providers that
perform authentication themselves, such as SSH's privileged monitor, still need
a deliberate authenticated handoff. A program without such a handoff must not
recover privileged discovery merely because it changed to UID 0.

## Principal policy and minting

BSDAuth resolves the authenticated principal against
`/Capabilities/Config/principal-policy.ucl`. The system builder chooses UID/group
matches, endpoint anointments, management rights and optional elevation grants.
UID 0 has no implicit capability-world bypass. The shipped policy explicitly
grants root and wheel `*`; a system image may replace that policy.

Provider management (`ADMIN`) and authentication (`AUTHENTICATE`) are separate.
Only an eligible session holding `system.auth.mint` or `*` receives the latter
right when connecting to system.Auth. Ordinary managed-unit endpoint lookup does
not grant it. BSDAuth is the manifest-authorized mint boundary; it decides the
new scope rather than accepting grants from the requesting client.

A wildcard principal gets SYSTEM visibility; other principals get USER visibility
with their listed anointments. Management is a separate decision. Missing or
invalid policy grants nothing. Policy is an immutable startup snapshot; changing
it does not silently update existing bearer channels. Password and account
snapshots are reopened through the filesystem provider, so atomic password-file
replacement does not leave BSDAuth using an old password inode.

## What a shell holds

A shell can have only descriptors 0, 1 and 2 and still have discovery. An empty
`SERVICE_LOOKUP_FD` is expected and is not a diagnostic for lost access.
`service_process_info()` inspects the caller's kernel context, while
`service_ambient_lookup_fd()` obtains an owned working channel. Callers close
that descriptor after use. Authentication adapters close their provider and
minted working descriptors after installing the kernel-held reference.

Access to a gated name depends on the channel's recorded scope. An out-of-scope
lookup returns `ENOENT`, avoiding disclosure of otherwise invisible services.
A UNIX program without discovery can still run and use ordinary UNIX interfaces;
a capability client must report inability to reach a service it needs.

## anoint versus sudo

sudo(8) and doas(1) change the uid. anoint(1) does not: `anoint NAME COMMAND` runs `COMMAND` as the caller, in the caller's environment and directory, holding the caller's session anointments plus exactly one more, after the caller retypes their own password. The elevated channel exists for that one command and is gone when it exits; nothing is cached and there is no timeout window. Whether a principal may elevate to a name at all is the `may_elevate` list of its policy entry, checked before any password prompt; `*` is legal there. BSDAuth authenticates against `/etc/master.passwd` inside its own sandbox, not through PAM, rate-limits failures per uid, and audits every request as `AUE_AUTHAGENT_ELEVATE`.

| | sudo(8) / doas(1) | anoint(1) |
|---|---|---|
| What changes | effective uid | the anointment set on the session channel |
| Scope | the whole command as another user | one named capability, one command |
| Policy file | `sudoers(5)` / `doas.conf` | `/Capabilities/Config/principal-policy.ucl`, `may_elevate` |
| Mechanism | set-user-id binary | request to system.Auth over the session's own channel; no set-user-id |
| Caching | timestamp window | none |
| Requires | a password or NOPASSWD rule | a session with a lookup channel and the caller's password |

A stricter site profile keeps root's bypass but turns every gated reach into an audited, per-command ask:

```
admin { groups = ["wheel"]; uids = [0]; anointments = [];
        may_elevate = ["*"]; admin_rights = true; }
```

The line `anoint: no session channel` means the calling process is not part of a session: it was run from a context with no ambient channel, such as an unprovisioned job. [Anointments and Principal Policy](../plane/anointments.md) covers the policy language; [system.Auth](../providers/auth.md) covers the daemon.

## Failure and trust boundaries

If provisioning fails, no provider authority should reach the user command.
The PAM module permits the UNIX session to proceed without discovery after a
failed mint; failure to clear existing authority fails the PAM session itself.

Keeping a kernel reference does not reconnect to a dead SwitchBoard instance.
Existing sessions need a newly authenticated scope after broker state is lost;
new Capsule getty children receive the replacement boot channel. Existing login
providers, such as a long-running SSH listener, retain their old context and must
be restarted from a fresh authorized session before they can provision new
capability sessions. Automatic restoration of prior scopes is not provided.

Principal policy governs capability grants, not every UNIX privilege. The
credential store and trusted authentication programs/configuration are part of
the authentication trust boundary. A system claiming protection against a
hostile UNIX administrator must protect those inputs as well as the policy file;
removing UID 0 bypasses in capability checks alone does not provide that guarantee.

See [Discovery and the Lookup Channel](../plane/discovery-and-lookup.md) and
[Anointments and Principal Policy](../plane/anointments.md).
