# Capability-world fork inventory: modified base & contrib programs

This is the authoritative list of **upstream / imported** programs (OpenSSH and
FreeBSD base userland) that the 5BSD fork has modified to live in the
object-capability world — where authority is a **held lookup capability**
(a serviced-minted channel) rather than ambient uid / `getpeereid` sockets /
`getpid()==1` / signals. These are *our* forks; we carry them.

It deliberately **excludes** our own from-scratch daemons and libraries
(`serviced`, `authorityd`, `tzfsd`, `blued`, `traced`, `bsdnotify`,
`servicectl`, `authorityctl`, and libraries `libservice`, `libcapbundle`,
`libauthorityrt`, `libchannel`) — those are origin points, not forks. Where a
base program *consumes* one of those libraries it is noted.

See `docs/capability-authority-model.md` for the model these changes implement.

---

## The shared mechanism

serviced holds the SYSTEM ambient **lookup channel** and hands it down through
rc as an inherited, non-close-on-exec fd named by `SERVICE_LOOKUP_FD`
(`service_bootstrap.h`). A login path mints the *session's* uid-scoped channel
from it with `service_mint_session_domain(syschan, kind, uid, &fd)` — `kind`
chosen by `capbundle_principal_is_admin(pw)` (SYSTEM for root/wheel, else USER) —
and installs it with `service_install_ambient_lookup()` so the session leader's
shell and descendants inherit a live discovery channel. Holding the SYSTEM
channel *is* the authority, replacing `getpeereid(2)` uid attestation.

Programs that cannot inherit the channel the getty→login way (network daemons,
setuid transitions) either re-mint it or scrub it, as noted below.

---

## OpenSSH (`crypto/openssh/` — vendored OpenSSH portable)

The most heavily forked program: a network daemon cannot inherit an ambient
channel the getty→login way, so the listener carries one explicitly and mints a
**private per-connection** channel so concurrent sessions never share a channel
descriptor.

| File | Change |
|---|---|
| `sshd.c` (listener) | `capture_ambient_master()` pins the inherited `SERVICE_LOOKUP_FD` at the reserved slot `REEXEC_AMBIENT_LOOKUP_FD` before the fd cull, surviving `daemon()` and the `SIGHUP` self-re-exec (rewrites the env to name the pinned slot). Per accepted connection, `mint_connection_lookup()` mints a **private** SYSTEM channel (`service_mint_session_domain`, serial in the single-threaded accept loop) and passes it to the child on the reserved slot; the parent drops its copy. |
| `sshd-session.c` (per-connection monitor image) | Adopts the private channel off the reserved slot into a high CLOEXEC descriptor (`ambient_session_lookup_fd`) early in `main()`, before `PRIVSEP_LOG_FD` reuses that numeric slot. |
| `monitor.c` / `monitor.h` | Post-auth privileged-monitor RPC `mm_answer_provision` / `MONITOR_REQ_PROVISION`: the monitor mints the session's uid-scoped channel over `ambient_session_lookup_fd` with `service_mint_session_domain`, `kind` = `capbundle_principal_is_admin(authctxt->pw)`, keyed to the **authenticated** principal (never a uid the untrusted child chose). Replaces the retired `getpeereid(2)` serviced control socket. |
| `monitor_wrap.c` / `monitor_wrap.h` | Client half `mm_provision_session(uid, int *)` — the unprivileged session asks the monitor to provision. |
| `session.c` | Calls `mm_provision_session` while still privileged; installs the provisioned channel at `SERVICE_LOOKUP_FIXED_FD` and advertises `SERVICE_LOOKUP_FD` in the child env so the login shell inherits a live channel. `DISABLE_FD_PASSING` fallback re-mints directly from `ambient_session_lookup_fd`. |
| `secure/usr.sbin/sshd/Makefile` | `LIBADD+= service channel capability`, `-I lib/libservice`. |
| `secure/libexec/sshd-session/Makefile` | `LIBADD+= service channel capability capbundle`, `-I lib/libservice -I lib/libcapbundle`. |

**Non-fatal contract:** every step degrades to "this session carries no ambient
channel" on any failure — never blocking a login or the boot. A build with no
capability plane (`SERVICE_LOOKUP_FD` unset) behaves exactly as stock sshd.

---

## FreeBSD base userland

### `login(1)` — `usr.bin/login/login.c`
Captures the inherited SYSTEM channel (`syschan`) before rebuilding the
environment, mints the session's uid-scoped channel with
`service_mint_session_domain` + `service_install_ambient_lookup`, admin-vs-user
by `capbundle_principal_is_admin(pwd)`. Consumes `libservice`, `libcapbundle`,
`service_bootstrap.h`.

### `su(1)` — `usr.bin/su/su.c`
Same pattern across the uid transition — a `su` from an admin session re-mints
the *target* principal's channel (`su user` → USER, `su root` → SYSTEM) rather
than leaking the caller's. Notes `su -m` preserving the caller's `environ`.

### `cron(8)` — `usr.sbin/cron/cron/do_command.c`
Runs supervised by serviced holding the SYSTEM channel as an inherited fd.
Across the setuid to the crontab owner it does fd hygiene (§11a D2): NULLs
`environ` (dropping the `SERVICE_LOOKUP_FD` advertisement) and `closefrom(3)` so
system-domain discovery cannot leak into arbitrary user jobs. Pure fd/env
hygiene, no library linkage.

### `atrun(8)` — `libexec/atrun/atrun.c`
Same hygiene (§11a D3) across the setuid to each job owner and before running
the mailer: `unsetenv(SERVICE_LOOKUP_ENV)` + `closefrom(3)`. Consumes
`service_bootstrap.h` for the env-var name only.

### `reboot(8)` / `halt` — `sbin/reboot/reboot.c`
Delegates a clean, service-ordered shutdown to the capability plane by
fork+exec of `authorityctl(8)` (`_PATH_AUTHORITYCTL`, verb from the `RB_*`
howto), falling back to the `reboot(2)` kernel escape if authorityctl is
unavailable. Carries **no** capability/protocol code and no /usr runtime
dependency — the capability world sits *beside* the stock kernel escape.

### `shutdown(8)` — `sbin/shutdown/shutdown.c`
Same lifecycle delegation via `authorityctl(8)` (verb per target state,
including single-user), with the historical fast path as fallback.

---

## What is deliberately NOT modified

- `sbin/init`, `libexec/getty`, PAM modules, and everything under `contrib/`
  carry no capability code — the plane sits beside them.
- `sshd-auth` (the pre-auth cracker) touches no ambient channel; unchanged.
- Reboot/halt/shutdown keep the stock `reboot(2)` path as a fallback; the
  capability delegation is additive.

_Last updated: 2026-08-30 (the milestone that retired the last `getpeereid`
control socket; sshd session provisioning moved onto the inherited SYSTEM
channel)._
