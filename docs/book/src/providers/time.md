# system.Time (BSDTime)

## What it brokers

BSDTime is the `system.Time` provider: the trusted broker for the wall clock. A unit holding a `system.Time` channel reads `CLOCK_REALTIME`, and, when the per-label policy grants it, steps the clock with `clock_settime(2)` or slews it with `adjtime(2)`, without ever holding `PRIV_SETTIMEOFDAY` itself. Reading is unprivileged and allowed to every holder; stepping and slewing are default-deny.

The daemon is born in capability mode. Moving the clock is refused at the syscall boundary inside the sandbox, so BSDTime holds a `SYS_GATE_SETTIME` "system" gate token, minted by [Capsule](../plane/capsule.md) from the manifest declaration `capabilities { system = ["settime"]; }`, delegated by switchboard and authorized with `service_provider_authorize_capabilities(3)`. A SET or ADJUST goes through `service_system_settime(3)` or `service_system_adjtime(3)`, which the kernel executes in kernel context after verifying the held claim (the gated paths in `sys/kern/kern_time.c`). The raw `settimeofday(2)` stays refused, so the sandbox is never loosened; the gate claim replaces the privilege, and the daemon runs as the unprivileged `capability` user. See [System Gates](../capability/system-gates.md).

Because the token is close-on-fork, BSDTime serves each client inline in the single token-holding process rather than from a `pdfork(2)` worker. The three operations are trivial and stateless, so sequential serving is sufficient; a session that connects and then goes idle is dropped after `BSDTIME_SESSION_IDLE_SEC` (30 seconds) so it cannot hold the loop. Every step and slew is logged with the caller's label and fires the `BSDTime` DTrace provider's `clock-set` or `clock-adjust` probe.

## Unit

Source: `usr.sbin/BSDTime/capbundle/BSDTime.ucl` and `Bundle.ucl`.

| Field | Value |
|---|---|
| Wire name | `system.Time` (interface version `1.0.0`, ABI 1) |
| Bundle | `/Capabilities/System/Time.cap` (`bundle_id = "system.Time"`) |
| Program | `/Capabilities/System/Time.cap/Units/bsdtime.unit/bin/BSDTime` |
| Unit | `bsdtime` |
| User | `capability` |
| Launch | born in capability mode; `activation { boot = true; ipc = ["system.Time"]; }` |
| Control | `core` |
| Gates | `capabilities { system = ["settime"]; }` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 256; nproc = 64; core = 0`; `umask = "0077"` |
| Config | `Units/bsdtime.unit/Config/time.conf` |

## Wire operations

Defined in `lib/libtimecmp/timecmp_protocol.h`. Messages are fixed size: `struct timecmp_msg` (magic `TIME`, `version`, `opcode`, `flags`, `status`) optionally followed by exactly one `struct timecmp_time { sec, nsec, present }`. `timecmp_validate_message()` is shared by client and daemon and rejects anything that is not the bare header or header plus one time body. HELLO is a bare liveness exchange. A request with an attached descriptor, a bad magic, a wrong ABI version, an unknown opcode or a short or oversized body is `EPROTO` and ends the session.

| Op | Request | Reply | Errors |
|---|---|---|---|
| `HELLO` (1) | header | header, status 0 | `EPROTO` |
| `GET` (2) | header | `timecmp_time` (`present = 1`) with `CLOCK_REALTIME` | `clock_gettime(2)` errors |
| `SET` (3) | `timecmp_time` absolute, `nsec` in `[0, 999999999]` | header | `EPROTO` body missing; `EPERM` label not granted `set`; `EINVAL` nsec out of range; gate errors |
| `ADJUST` (4) | `timecmp_time` signed delta (sign in `sec`, `nsec` magnitude) | `timecmp_time` = correction still pending (`present = 0` if none) | `EPROTO`; `EPERM`; `EINVAL`; gate errors |

The policy check precedes the range check, so a denied label learns nothing about argument validity. ADJUST scales the sub-second part to microseconds for `adjtime(2)` and returns the previously pending correction in the same shape.

## Client library

Header `<timecmp.h>` (installs `timecmp.h` and `timecmp_protocol.h`); link with `-ltimecmp` (`SHLIB_MAJOR 1`, depends on libservice). Manual: libtimecmp(3).

| Group | Functions |
|---|---|
| Session | `timecmp_client_open`, `timecmp_client_close` |
| Read | `timecmp_get(client, struct timespec *)` |
| Write | `timecmp_set(client, const struct timespec *)`, `timecmp_adjust(client, const struct timeval *delta, struct timeval *old)` |

`timecmp_set()` and `timecmp_adjust()` fail with `EPERM` when the caller's label is not granted `set`. `old` may be `NULL`.

```c
#include <timecmp.h>
#include <err.h>
#include <stdio.h>

void
nudge_clock(long usec)
{
	struct timecmp_client *tc;
	struct timespec now;
	struct timeval delta = { .tv_sec = 0, .tv_usec = usec }, old;

	if (timecmp_client_open(&tc) == -1)
		err(1, "system.Time");
	if (timecmp_get(tc, &now) == -1)
		err(1, "get");
	printf("now %jd.%09ld\n", (intmax_t)now.tv_sec, now.tv_nsec);
	if (timecmp_adjust(tc, &delta, &old) == -1)
		warn("adjust (EPERM unless time.conf grants set)");
	timecmp_client_close(tc);
}
```

## Command-line tool

BSDTimectl(8) is the operator front end. Like every client it is bound by the invoking label's policy, so from an ordinary shell only `get` succeeds.

| Verb | Example | Output shape |
|---|---|---|
| `get` | `BSDTimectl get` | `1790000000.123456789` (seconds.nanoseconds) |
| `set epoch[.nsec]` | `BSDTimectl set 1790000000` | exit status; `EPERM` without `set` authority |
| `adjust [-]sec[.usec]` | `BSDTimectl adjust -0.250000` | `previous correction: 0.000000` |

The synopsis in BSDTimectl(8) prints `adjust file ...` for the slew verb; the tool takes one signed delta, as the DESCRIPTION says.

## Policy

`/Capabilities/System/Time.cap/Units/bsdtime.unit/Config/time.conf` (UCL), delivered as a directory descriptor and read once at startup. Reading is never gated. `set` grants a label authority to both step and slew; there is no separate slew-only grant. Labels match by exact string; an unlisted label falls back to `default`.

```ucl
default { set = false; }
clients {
	"org.5bsd.ntp" { set = true; }
}
```

The shipped file is exactly the `default` block plus a commented example. A missing or malformed file is fail-soft: the compiled-in default-deny stands. There is no `SERVICE_RIGHTS_ADMIN` bypass; an ambient root shell cannot step the clock through the broker unless its label is listed. A backward step invalidates TLS certificate validity windows, audit ordering and Kerberos tickets, so grant `set` only to a trusted time source.

## Tests

| Where | Programs | What they prove |
|---|---|---|
| `usr.sbin/BSDTime/tests` (package `runtime-tests`, `/usr/tests/usr.sbin/BSDTime`) | `provider_test` (10 cases), `config_test` (8) | provider_test compiles `BSDTime.c` with `-DBSDTIME_TESTING` and drives the real session handler over a mac_capability channel: HELLO answers, GET reads the clock, SET and ADJUST are denied by the default policy, an allowed label reaches the gate, unknown opcode, short message and missing body are rejected (`EPROTO`), an attached fd is rejected, and a gate round trip with a no-op delta succeeds. config_test covers `default`/`clients` parsing, exact-label matching and fail-soft loading. |
| `lib/libtimecmp/tests` (`libtimecmp-tests`) | `protocol_test` (6) | `timecmp_validate_message()` accepts the two legal shapes and rejects everything else for both roles |

Run with `kyua test -k /usr/tests/usr.sbin/BSDTime/Kyuafile`. `set_allowed_reaches_gate` and `gate_roundtrip_noop` need a held settime token, so they are meaningful only on a booted plane in the VM rig ([Testing](../develop/testing.md)); elsewhere they skip. BSDTime is the reference pattern the BSDPower suite was copied from.

## Status and gaps

Status: shipped; capmode; user `capability`; gate `settime`; ops HELLO, GET, SET, ADJUST (inventory section 4).

Known gaps and drift:

- No operator ctl test suite: `usr.sbin/BSDTimectl` has no `tests` directory.
- BSDTimectl(8)'s synopsis line for `adjust` is mangled (`file ...`); the description is correct.
- BSDTime(8) FILES names `Units/BSDTime.unit`; the Makefile installs `bsdtime.unit`.
- The chapter this one replaces described BSDTime as an ambient provider with pdfork workers; both statements predate the gate framework and are wrong.
- There is no clock-drift, NTP-style leap handling or `CLOCK_MONOTONIC` op; GET returns `CLOCK_REALTIME` only. A unit that needs monotonic time calls `clock_gettime(2)` itself, which is legal in capability mode.
- Inline serving means a single misbehaving client holds the process until the 30 second idle deadline.
