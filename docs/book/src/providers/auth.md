# system.Auth (BSDAuth)

BSDAuth is the mint boundary of the capability plane: the one daemon that
turns "an authenticator verified a login for uid U" into a lookup channel
scoped to that session and carrying that principal's anointments. It also
serves elevation, the sudo(8) and doas(1) replacement, extending a
session's set by one name for one command. 5BSD has it so that login(1),
su(1) and sshd(8) never hold mint authority themselves: they hold a
channel to `system.Auth`, and the trusted computing base for session
provisioning shrinks to switchboard and this daemon.

## What it brokers

The resource is the session lookup channel described in [Discovery and the
Lookup Channel](../plane/discovery-and-lookup.md). Switchboard performs the
actual mint (`SVC_OP_MINT_DOMAIN`); BSDAuth is the unit whose manifest says
`mint_authority = true`, which is the only way a unit obtains a
mint-capable bootstrap channel. Given a uid, BSDAuth decides what to mint:
a SYSTEM channel (full discovery, with `SERVICE_RIGHTS_ADMIN`) for an admin
principal, or a per-uid USER channel carrying the listed anointment set
otherwise. The decision comes from `/Capabilities/Config/principal-policy.ucl`
and from identity BSDAuth resolves itself. Before entering capability mode
it obtains read-only descriptors for `/etc/passwd`, `/etc/group` and
`/etc/master.passwd` from [system.Filesystem](filesystem.md) through
`open_paths`, and for each request it resolves the uid's passwd entry and
full group membership in-process. A compromised login program cannot claim
a group it is not in.

Three things arrive over the channel and nothing else. MINT_SESSION is
gated on a held right, not a name: only a caller whose channel carries
`SERVICE_RIGHTS_ADMIN` may ask, and switchboard stamps that bit only on an
ambient login-session lookup over a SYSTEM channel, which is exactly the
channel the login family reaches BSDAuth over. Every unit, and every
session reaching BSDAuth for elevation, is refused a mint with `EPERM`
before the request is parsed. MINT_AUTH exists for su(1) from an ordinary
session, whose channel has no admin bit: the caller proves the target's
password and BSDAuth verifies it against `/etc/master.passwd` with
crypt(3) inside the sandbox, then mints the target's own set. ELEVATE takes
the caller's uid from the kernel-stamped sender, checks the requested name
against the principal's `may_elevate`, verifies the caller's own password
the same way, and mints the caller's set plus one. PAM is not involved in
the daemon: module stacks cannot run in capability mode, and the login
programs keep their own PAM.

The minted leaf channel is attenuated to `CAP_XFER_ONCE` before it is
sent, so the reply's descriptor pass consumes it to `CAP_XFER_NONE` at the
login program and a session cannot re-delegate its channel. A forwarding
authenticator (sshd's monitor) passes `AUTHAGENT_FLAG_FORWARDABLE` to
receive a still-transferable channel and re-attenuates it before its one
forward. Every outcome, granted or refused, is committed to the BSM trail
through [system.Audit](audit.md) and logged to `LOG_AUTHPRIV`.

## Unit

| Field | Value |
|---|---|
| Wire name | `system.Auth` |
| Bundle | `/Capabilities/System/Auth.cap` (`bundle_id = "system.Auth"`) |
| Program | `Units/bsdauth.unit/bin/BSDAuth` |
| Unit name | `bsdauth` |
| Activation | `boot = true`, `ipc = ["system.Auth"]` |
| User | `root` |
| Launch mode | born in capability mode; no `directories` (identity files arrive through `open_paths`) |
| Declared gates | none; `mint_authority = true` (the only unit with it) |
| Visible | `["user"]` (every session must reach it for elevation) |
| Control | `core` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 256`, `nproc = 8`, `core = 0`; `umask = "0077"` |

## Wire operations

The protocol is `lib/libservice/authagent_proto.h`. There is no HELLO;
every request begins with `version` (`AUTHAGENTD_PROTO_VERSION` 3) and
`op`. The daemon accepts `AUTHAGENTD_PROTO_VERSION_MIN` 2 for MINT_SESSION
and ELEVATE, which are wire-identical from v2, so a v2 login program keeps
working across a rolling upgrade; MINT_AUTH requires v3. Every reply is a
`authagent_mint_reply` (`status`, `flags`) with the minted channel attached
as one SCM_RIGHTS fd on success and none on failure.

| Op | Request | Reply | Errors, in check order |
|---|---|---|---|
| 1 MINT_SESSION | `authagent_mint_req` (uid, flags: 0 or `FORWARDABLE`) | reply + session channel fd | `EPERM` (caller lacks `SERVICE_RIGHTS_ADMIN`), `EINVAL` (shape), `ENOENT` (uid has no passwd entry), mint transport errors |
| 2 ELEVATE | `authagent_elevate_req` (336 bytes: name[64], password[256]) | reply + channel fd holding the session set plus `name` | `EPERM` (caller is a unit, not a session), `EINVAL` (size, version, flags, unterminated field, attached fd, name not reverse-domain), `EPERM` (name not in `may_elevate`), `EAGAIN` (five failures within sixty seconds for this uid), `ENXIO` (no `/etc/master.passwd` grant), `EACCES` (wrong password), `EPERM` (empty or locked hash), `ENOENT` (no record), `E2BIG` (set full) |
| 3 MINT_AUTH | `authagent_mint_auth_req` (272 bytes: target uid, flags, password[256]) | reply + the target's session channel fd | `EPERM` (caller is a unit), `EINVAL`, `EAGAIN` (separate per-uid limiter), `EACCES`, `ENOENT` |

Both sides `explicit_bzero(3)` the request after use; nothing is cached
and every elevation authenticates again. The uid for ELEVATE is never in
the payload.

## Client library

The API lives in libservice(3) (`<libservice.h>`, `-lservice`), because
the callers are the login programs and anoint(1), not typed consumers:

| Function | Caller | Purpose |
|---|---|---|
| `service_mint_session_via_agent(lookup_chan, uid, flags, timeout_ms, &fd)` | login, su, sshd monitor | MINT_SESSION over the inherited SYSTEM channel; `SERVICE_MINT_AGENT_FORWARDABLE` for sshd; `SERVICE_MINT_SESSION_TIMEOUT_MS` (10 s) bounds the exchange |
| `service_mint_session_authenticated(lookup_chan, uid, password, flags, timeout_ms, &fd)` | su from a non-admin session | MINT_AUTH; su tries this only after the admin mint returns `EPERM` |
| `service_elevate(name, password, timeout_ms, &fd)` | anoint(1), any session program | ELEVATE over the caller's ambient lookup channel; errors `EINVAL`, `ENOENT` (no channel or no agent), `EPERM`, `EACCES`, `EBADMSG`, `ETIMEDOUT` |
| `service_install_ambient_lookup(fd)` (`<service_bootstrap.h>`) | all of the above | install the minted channel at `SERVICE_LOOKUP_FIXED_FD` before exec |
| `service_context_mint_domain`, `service_context_mint_domain_anointed` | BSDAuth itself | the mint over the provider's own bootstrap channel |

How a session program runs one command with an extra anointment:

```c
#include <err.h>
#include <unistd.h>
#include <libservice.h>
#include <service_bootstrap.h>

static void
run_elevated(const char *name, const char *password, char *const argv[])
{
        int fd;

        if (service_elevate(name, password, 10000, &fd) != 0)
                err(1, "elevate %s", name);
        if (service_install_ambient_lookup(fd) != 0)
                err(1, "install lookup channel");
        execvp(argv[0], argv);
        err(1, "%s", argv[0]);
}
```

The login programs' side is in [Sessions: login, su, ssh and
cron](../compat/sessions.md); a login proceeds without an ambient channel
if BSDAuth is unreachable.

## Command-line tool

anoint(1) is the user-facing client. It never changes uid: the command
runs as the caller with the caller's environment, and only the anointment
set on the inherited lookup channel changes.

```
$ anoint system.trace.client dtrace -n 'syscall:::entry { @[execname] = count(); }'
Password:
```

`anoint [-n] name command [argument ...]`; `-n` sends an empty password
without prompting. It exits 1 when it refuses to run the command (the name
is not in the caller's `may_elevate`, the password is wrong, the caller is
rate-limited, there is no session channel, or the agent is unreachable),
126 when the command was found but could not be executed, 127 when it was
not found, and otherwise with the command's own status. There is no
set-user-id binary, no sudoers(5)-style file, and no timeout window. Whether a mint happened for a login is visible in the
audit trail (`praudit` records of event 43336) and in the `LOG_INFO`
line BSDAuth writes for every mint.

## Policy

`/Capabilities/Config/principal-policy.ucl` (installed from
`usr.sbin/BSDAuth/principal-policy.ucl` as a `CONFS` file, so local edits
survive upgrades) decides what a session holds. It is a `principals` block
matched in file order; the first entry whose `uids` or `groups` matches
wins, and an entry with neither list is the fallback.

```ucl
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

| Key | Meaning |
|---|---|
| `anointments` | names the session holds from login; `[]` still reaches every endpoint published without `requires`; `"*"` is legal here and nowhere else |
| `may_elevate` | names the principal may ask for one command at a time through anoint(1); absent means never |
| `admin_rights` | whether connections from the session carry `SERVICE_RIGHTS_ADMIN`, the in-endpoint bypass some providers honour; defaults to true only when `anointments` is `"*"` |

Session kind is SYSTEM when the grant holds `"*"` or carries admin rights,
USER otherwise. Default-deny is the `default` entry: an unlisted principal
holds nothing and may elevate to nothing. The `capability` uid is not a
principal and BSDAuth warns if the policy grants it anything. A missing or
malformed policy falls back to the historical rule (uid 0 or group
`wheel` holds everything with admin rights) and logs the fallback. Admin
sessions do not bypass BSDAuth's own gates: an admin session still cannot
elevate to a name outside its `may_elevate` (though `"*"` covers all), and
MINT_SESSION still requires the admin bit on the channel, which a unit
never has. The full model is in [Anointments and Principal
Policy](../plane/anointments.md).

## Tests

| Suite | Location | Installed under | What it proves |
|---|---|---|---|
| `elevate_test` (86), `gate_test` (4), `identity_test` (3), `mint_decision_test` (11), `provider_test` (37) | `usr.sbin/BSDAuth/tests` | `/usr/tests/usr.sbin/BSDAuth` | every ELEVATE stage and refusal in order, the rate limiter, the admin-bit mint gate, in-sandbox passwd and group resolution, first-match policy semantics against the shipped file, and the provider under `BSDAUTH_TESTING` |
| `elevate_integration_test.sh` (7), `observability_test.sh` (3) | same | same | anoint(1) end to end through `pty_askpass` (a tty helper, since readpassphrase(3) needs one), and the `bsdauth` DTrace probes |
| `anoint_cli_test.sh` | `usr.bin/anoint/tests` | `/usr/tests/usr.bin/anoint` | argument handling and exit status |

Run with `kyua test -k /usr/tests/usr.sbin/BSDAuth/Kyuafile`; the package
is `5BSD-bsdauth-tests`. The integration tests need a booted plane. The
`bsdauth` provider exports `request-start`, `request-done`,
`elevate-start`, `elevate-done` (with the decision stage), `policy-resolve`
and `ratelimit-block`; the client side is traced by libservice's
`service_ambient` provider. Passwords and hashes never appear in a probe,
log line or audit record.

## Status and gaps

Shipped and VM-proven: session minting for login, su and sshd; MINT_AUTH
for non-admin su; elevation through anoint(1); audit of every outcome;
the first-match principal policy and the management model's split between
seeing (`"*"`) and managing (`admin_rights`). The BSDAuth(8) manual page
writes the wire name as `system.auth` in lowercase in several places; the
manifest and `AUTHAGENTD_NAME` say `system.Auth`, and lookups are exact.
The design document `docs/book/src/providers/auth.md` still describes the
protocol as one operation and getty's channel as scoped to `{system.auth}`;
the shipped protocol has three ops and the visibility mechanism is the
unit's `visible = ["user"]`. The legacy top-level `admin { uids; groups; }`
form of the policy file is still accepted and slated for removal. BSDAuth
runs as root and is one of the providers not yet moved to a gate-based
launch as user `capability`.
