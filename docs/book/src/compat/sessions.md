# Sessions: login, su, ssh and cron

On FreeBSD a login session is a uid, a tty and an environment. On 5BSD it is also a held descriptor: a lookup channel to switchboard's naming registry that decides which capability services the session can name at all. login(1), su(1) and sshd(8) were modified to obtain that channel for each session from BSDAuth (system.Auth), scoped to the authenticated principal, and cron(8) and atrun(8) were modified to make sure a user's job never inherits the system-wide one. This chapter explains where the channel comes from, what a shell holds after login, and why `anoint` replaces `sudo`.

## The inherited SYSTEM lookup channel

switchboard mints one SYSTEM-domain lookup channel at boot, before it runs `/etc/rc`, and installs it as an ambient descriptor: `FD_CLOEXEC` cleared, `CAP_CLOFORK_UNLOCKED` so it survives every fork, and its number advertised in the environment variable `SERVICE_LOOKUP_FD`. This is the boot carry. It holds every anointment (the principal policy's `*`) and admin rights, and it is the channel over which the login programs reach BSDAuth. It reaches processes by two routes (`lib/libservice/service_bootstrap.h`):

| Route | Carrier | How the fd is found |
|---|---|---|
| `/etc/rc` and every rc.d daemon, including sshd | environment variable `SERVICE_LOOKUP_FD` | `service_ambient_lookup_fd()` reads the variable and validates the fd with `MAC_CAPABILITY_GETINFO` |
| getty and console login | bare descriptor pinned at `SERVICE_LOOKUP_FIXED_FD`, which is fd 3 | capsule (PID 1) builds getty's environment from scratch (`{TERM, NULL}`), so the variable cannot cross that hop; switchboard hands capsule a duplicate of the channel and capsule `dup2()`s it to fd 3 with `FD_CLOEXEC` cleared before exec'ing each getty; `service_ambient_lookup_fd()` probes fd 3 under the same validation when the variable is absent |

The helper is discovery, never authority. A stale or unrelated descriptor at fd 3 fails validation, and the caller falls back to "no ambient channel" and proceeds as FreeBSD would.

## Session minting

Holding a SYSTEM channel is the authority to ask for a session channel; deciding what the session gets is BSDAuth's job. BSDAuth is the unit whose manifest declares `mint_authority = true` (`usr.sbin/BSDAuth/capbundle/bsdauth.ucl`); switchboard stamps `SERVICE_RIGHTS_ADMIN` on a connection to it only when the lookup came over a SYSTEM channel, which is exactly what login, su and sshd hold. Any other caller, including an ordinary unit or a user session, is refused a mint with `EPERM` before the request is parsed.

The decision is read from `/Capabilities/Config/principal-policy.ucl`. Entries match the authenticated uid and group membership in file order; the first match wins; an entry with neither list is the fallback. The shipped default:

```
principals {
    admin {
        groups = [ "wheel" ];
        uids = [ 0 ];
        anointments = [ "*" ];
        admin_rights = true;
    }
    default {
        anointments = [];
    }
}
```

A principal whose grant holds `*` or carries admin rights gets a SYSTEM channel with full discovery; everyone else gets a per-uid USER channel that resolves only names published with `visible = ["user"]` and carries the listed anointments. An empty list is not "no services": every endpoint a provider publishes without `requires` is still reachable (system.Log, the open tier of system.Notify), so an ordinary user loses nothing they had on FreeBSD. The `capability` uid is not a principal and BSDAuth warns at startup if the policy grants it anything. When the file is missing or malformed BSDAuth falls back to the historical rule (uid 0 or wheel holds everything) and logs the fallback.

The library call all three programs use is `service_mint_session_via_agent(syschan, uid, flags, SERVICE_MINT_SESSION_TIMEOUT_MS, &fd)` from libservice(3). The timeout is 10 seconds, long enough for a console autologin to outlast BSDAuth's own start-up on a slow boot and short enough that a broken agent costs one bounded wait per login. The minted descriptor arrives attenuated to `CAP_XFER_ONCE`, and the reply's own descriptor pass consumes it to `CAP_XFER_NONE`: the session leaf cannot re-delegate its lookup channel. Every mint is audited (`AUE_AUTHAGENT_MINT`) and logged at `LOG_INFO` with the kind and shape of the grant.

Each program does this at a different point.

**login(1)** (`usr.bin/login/login.c`) captures the channel before its `closefrom(3)`, since on the getty path the channel sits at fd 3, precisely where `closefrom` would start. It relocates the channel to fd 3 if it arrived elsewhere, closes from 4, authenticates through PAM, and after the uid switch asks BSDAuth to mint for `pwd->pw_uid`. On success it calls `service_install_ambient_lookup(fd)` so the shell and its descendants inherit the session channel, then closes the SYSTEM channel. On any failure it logs `login: no lookup channel for uid N` at `LOG_NOTICE` and the session proceeds with no channel. The unnarrowed SYSTEM channel is never handed to a user shell.

**su(1)** (`usr.bin/su/su.c`) captures the channel before the child may replace its environment, and after `setusercontext` has switched to the target uid relocates it to fd 3, closes everything above it, and unsets a stale `SERVICE_LOOKUP_FD` that `su -m` would otherwise preserve. A uid transition re-provisions rather than re-narrows: an su from a wheel session holds a mintable SYSTEM channel, so `su user` mints the target's USER channel and `su root` mints SYSTEM. When the caller's channel carries no admin bit (an ordinary user running `su`), the agent refuses the assertion mint with `EPERM`, and su falls back to `service_mint_session_authenticated()` with the password PAM verified. BSDAuth checks that password itself against `/etc/master.passwd`, in the same constant-time, rate-limited path as elevation (five failures within sixty seconds refuse with `EAGAIN`), and on success mints the target uid's own policy set. So `su root` from a non-admin login obtains root's admin channel by proving root's password, and `su alice` from bob's session obtains alice's set, never bob's plus something. Both password copies are zeroed after the mint.

**sshd(8)** (`crypto/openssh/sshd.c`, `sshd-session.c`, `monitor.c`, `session.c`) inherits the boot carry from `/etc/rc` through `SERVICE_LOOKUP_FD`. The listener pins it at the reserved re-exec slot `STDERR_FILENO + 3` so it survives sshd's descriptor cull, the `SIGHUP` re-exec and the per-connection re-exec into `sshd-session`, which adopts it into a high close-on-exec descriptor before the privsep descriptors reuse the slot. The privileged monitor answers a new request, `MONITOR_REQ_PROVISION` (54), from the post-authentication child. It ignores the uid the child sends and mints for `authctxt->pw`, the authenticated principal, so a compromised child cannot ask for uid 0. Because every monitor shares the one boot-carry endpoint, the mint runs under an exclusive flock(2) on `/var/run/sshd.mint.lock` (mode 0600, root-only); if the lock cannot be taken the monitor does not mint. The monitor requests a forwardable descriptor, re-attenuates it to `CAP_XFER_ONCE`, and sends it to the child with `mm_send_fd`, where the transfer consumes it to `CAP_XFER_NONE`. The child installs it at fd 3 in `do_child` and advertises `SERVICE_LOOKUP_FD=3` in the session environment.

## What a shell holds after login

After any of the three paths, a user's shell has fd 3 open on a mac_capability channel and `SERVICE_LOOKUP_FD=3` in its environment. procstat(1) shows the channel with type letter `M`:

```
$ procstat -f $$
  PID COMM                FD T V FLAGS    REF  OFFSET PRO NAME
 1204 sh                 text v r r-------   -       - -   /bin/sh
 1204 sh                 cwd v d r-------   -       - -   /home/alice
 1204 sh                 root v d r-------   -       - -   /
 1204 sh                   0 v c rw------   3       0 -   /dev/pts/0
 1204 sh                   1 v c rw------   3       0 -   /dev/pts/0
 1204 sh                   2 v c rw------   3       0 -   /dev/pts/0
 1204 sh                   3 M - rw------   1       0 -   -
$ echo $SERVICE_LOOKUP_FD
3
```

That descriptor is what every client library's `service_open()` uses when the caller was not launched by switchboard: `logctl`, `notifyctl`, `networkcmpctl`, `switchboardctl` and any program linked against a `lib*cmp` library resolve names through it (`service_connect_ambient`). Which names resolve depends on the channel's domain and anointments, and a refused name is `ENOENT`, indistinguishable from a name that does not exist. A program that finds no channel (`service_ambient_lookup_fd()` returns -1) runs with no plane access and should degrade, never fail. See [Discovery and the Lookup Channel](../plane/discovery-and-lookup.md).

## Descriptor hygiene across uid changes

The boot carry must never leak from a root context into a user's process. Each entry point that changes uid closes what it inherited:

| Program | Change | Effect |
|---|---|---|
| login(1) | relocates the channel to fd 3, then `closefrom(4)`; on no channel `closefrom(3)` | only the session channel survives into the shell |
| su(1) | same relocation and `closefrom` after the uid switch; `unsetenv("SERVICE_LOOKUP_FD")` | a stale fd number never survives `su -m` |
| sshd(8) | `child_close_fds` and `do_child` install the session channel at fd 3 and `closefrom(4)`; the monitor's copy is close-on-exec | the shell inherits its own channel and nothing of the monitor's |
| cron(8) | `closefrom(3)` in `child_process` after setuid, before the job runs; `environ` was already cleared | a crontab job never inherits cron's SYSTEM channel |
| atrun(8) | `unsetenv` and `closefrom(3)` before the job and again before the mailer runs as the job owner | same for at(1) jobs |
| inetd(8) | DTrace probes only; no descriptor hygiene was added | a service spawned by inetd inherits inetd's descriptors as it does on FreeBSD, including the boot carry if inetd was started by rc |

cron matters more than it looks: it is the one rc.d service switchboard adopts, and it is started with switchboard's own environment, so it holds the channel with the same authority as the boot carry.

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

The line `anoint: no session channel` means the calling process is not part of a session: it was run from a context with no ambient channel, such as a cron job. [Anointments and Principal Policy](../plane/anointments.md) covers the policy language; [system.Auth](../providers/auth.md) covers the daemon.

## Limits

Provisioning is best-effort at every step; a system with BSDAuth stopped still lets everyone log in, with no plane access. The sshd mint is serialized through one lock across all connections because the monitors share one channel endpoint, so a burst of simultaneous logins mints one at a time. inetd(8) has no hygiene change. The admin decision in login and su is the single seam `capbundle_principal_is_admin()` from libcapbundle(3), which reads the same policy file; a site that edits the file changes both the mint and the historical root-or-wheel classification. The set of modified programs (capsule, login, su, sshd, cron, atrun; getty inherits only) is exactly what a FreeBSD rebase must carry forward, or the plane silently stops reaching sessions.
