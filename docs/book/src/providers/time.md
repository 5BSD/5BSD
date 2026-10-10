# system.Time (BSDTime)

## What it brokers

BSDTime is the `system.Time` provider: the trusted broker for the wall clock. A unit holding a `system.Time` channel reads `CLOCK_REALTIME`, and, when the per-label policy grants it, steps the clock with `clock_settime(2)` or slews it with `adjtime(2)`, without ever holding `PRIV_SETTIMEOFDAY` itself. Reading is unprivileged and allowed to every holder; stepping and slewing are default-deny.

The daemon is born in capability mode. Moving the clock is refused at the syscall boundary inside the sandbox, so BSDTime holds a `SYS_GATE_SETTIME` "system" gate token, minted by [Capsule](../plane/capsule.md) from the manifest declaration `capabilities { system = ["settime"]; }`, delegated by switchboard and authorized with `service_provider_authorize_capabilities(3)`. A SET or ADJUST goes through `service_system_settime(3)` or `service_system_adjtime(3)`, which the kernel executes in kernel context after verifying the held claim (the gated paths in `sys/kern/kern_time.c`). The raw `settimeofday(2)` stays refused, so the sandbox is never loosened; the gate claim replaces the privilege, and the daemon runs as the unprivileged `capability` user. See [System Gates](../capability/system-gates.md).

Because the token is close-on-fork, BSDTime keeps clock operations in one
process and multiplexes client channels with kqueue. It admits at most 32 live
sessions, with a maximum of eight for one trusted client label. Each ready peer
gets one bounded libchannel dispatch batch (at most 64 messages), with the
starting peer rotating between iterations. An idle or nonreading client cannot
hold up healthy peers. The accepted label is copied into each session so later
accepts cannot change its policy identity.

Idle sessions expire after 30 seconds. Each session may queue at most 16 replies
and 4096 bytes, with no attached descriptors. A full session table or label quota
closes the newly accepted channel; a full reply queue closes that peer. Clients
must treat write failures as potentially ambiguous and must not replay writes
automatically. Quiescing closes all sessions before completing the provider's
quiesce handshake. Every step and slew is logged with the caller's label and
fires the `BSDTime` DTrace provider's `clock-set` or `clock-adjust` probe.

## Unit

Source: `usr.sbin/BSDTime/capbundle/BSDTime.ucl` and `Bundle.ucl`.

| Field | Value |
|---|---|
| Wire name | `system.Time` |
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

The source implementation uses `lib/libtimecmp/timecmp.fidl`, library
`bsd.time.v1`, with generated C bindings over native capability channels.
The schema installs as `/usr/share/fidl/timecmp.fidl`. No payload supplies
an identity or a grant: the existing accepted-session label and held gate token
remain the authorization inputs.

| Method | Request | Reply |
|---|---|---|
| `GetProtocolInfo` | empty | wire version 1 |
| `Get` | empty | seconds and nanoseconds, or an application errno |
| `Set` | seconds and nanoseconds | empty success, or an application errno |
| `Adjust` | signed seconds and signed microseconds | previous signed correction, or an application errno |

A session must negotiate before performing operations. Unknown strict methods,
legacy messages, malformed messages, and unexpected descriptors close it.
Set nanoseconds must be in `[0, 999999999]`; Adjust microseconds must be in
`[-999999, 999999]`. The provider checks policy before these application ranges
and before invoking a gate. Negative fractions now survive the C API and wire
round trip; the legacy client accepted them but the old provider rejected them.

The `bsd.time.v1` method ordinals and existing request/reply layouts are a
compatibility contract. Incompatible changes require a new wire major and a
coordinated peer migration; changing only the version reply does not make an
incompatible message decodable. The client never guesses a legacy layout.

## Client library

Header `<timecmp.h>` (installs `timecmp.h` and `timecmp_protocol.h`); link with `-ltimecmp` (`SHLIB_MAJOR 1`, depends on libservice and the FIDL runtime). Manual: libtimecmp(3).

| Group | Functions |
|---|---|
| Session | `timecmp_client_open`, `timecmp_client_create`, `timecmp_client_close` |
| Read | `timecmp_get(client, struct timespec *)` |
| Write | `timecmp_set(client, const struct timespec *)`, `timecmp_adjust(client, const struct timeval *delta, struct timeval *old)` |

`timecmp_set()` and `timecmp_adjust()` fail with `EPERM` when the caller's label is not granted `set`. `old` may be `NULL`. `timecmp_client_create(fd, &client)` adopts a held
native channel only on success. Sessions remain non-transferable and locked
against exec/fork inheritance; using an inherited client object returns `ECHILD`.
The first call checks the wire version. Negotiation and the operation share a
five-second monotonic deadline. Malformed replies and timeouts close the client;
write operations are never automatically replayed.

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

The `adjust` verb takes one signed `[-]sec[.usec]` delta; the suffix is an integer microsecond count, not a decimal fraction to be scaled.

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
| `usr.sbin/BSDTime/tests` (`bsdtime-tests`) | `provider_test` (24), `config_test` (8) | Actual C client/provider over native channels, child provider in capability mode; simulated gate calls verify exact values without changing host time. Covers policy, signed deltas, malformed input/replies, legacy/future peers, descriptor cleanup, deadlines, fork ownership, concurrent peers, per-label quotas, idle expiry and 512 session-reuse cycles without descriptor growth. |
| `usr.sbin/BSDTime/tests` (`bsdtime-tests`) | `gate_test` (1) | Real held settime token and guest clock operations; requires a disposable VM and explicit `vm_clock_test=true`. |
| `lib/libtimecmp/tests` (`libtimecmp-tests`) | `protocol_test` (6) | Retained legacy validator ABI; it is no longer the active provider parser. |

`python3.12 tools/build/fuchsia/test-provider.py` builds the library and daemon,
then runs host-safe provider/configuration tests and the legacy ABI checks.
It also builds BSDTimectl and checks staged C11/C++20 public-header consumers
with shared/static library links and native-channel client construction.
Add `--sanitize` to instrument the C client, provider/config parser, generated
bindings, FIDL runtime and native transport with ASan/UBSan: all 38 cases pass.
Installed service/support dependencies are not instrumented, and LeakSanitizer
is unavailable. These host tests simulate clock gates.
It deliberately does not run the real clock gate. In the disposable VM, run
Kyua with `test_suites.FreeBSD.vm_clock_test=true` and select `gate_test` as well
as the normal provider cases. A skipped gate case is not validation.

Add `--packages` to the ordinary provider check to create and extract pkgbase
archives, including development files, manuals/aliases and split debug symbols.
The check verifies complete METALOG-tagged file ownership, library dependencies, DWARF
and debug-link CRCs, then runs the extracted tests and C11/C++20 consumers.
`bsdtime-tests` and `bsdtime-tests-dbg` own the provider tests and their symbols;
`libtimecmp-tests` and its debug package own the legacy ABI tests. Provider and
CLI binaries remain in `runtime`. The validation runtime archive contains only
this provider subset and must not be treated as a complete world package.

The same test package installs `resource_soak N` for explicit-duration resource
checks. Eight concurrent C clients and four idle peers repeatedly reconnect;
clock writes and logging are simulated. The program checks descriptor recovery,
policy results and live allocation after every epoch. See the
[FIDL testing instructions](../develop/fidl.md#installed-tests-and-native-ci)
for duration controls, memory limits and the maintained `check-soak` target.

## Migration and rollback contract

The bundle advances to version 2.0.0, sequence 2; the FIDL wire major is 1.
The existing public C API and shared-library major remain compatible, with the
additive held-channel constructor. The old validator symbol/header remain for
ABI compatibility, but current services do not use or accept their old framing.

Deploy the provider and matching libtimecmp in the same release transaction,
quiescing the service and restarting both provider and consumers. Old processes
may retain the previous library in memory even after packages change. Mixed
wire versions fail; the new client probes before sending a clock operation,
and there is no legacy fallback or automatic replay of writes.

A recovery release must likewise pair the matching provider and client library.
It must satisfy the registry's increasing-sequence policy, for example by
publishing the previous matching implementation as a new higher-sequence recovery
bundle. Do not lower the bundle sequence or replace just one peer. Reconnect
clients and verify reads and authorized gate operations after activation.
Release-transaction upgrade and rollback across boot environments still need
the integrated software-authority VM run; runtime restart of this core unit
is refused by design.

## Status and gaps

**Status (October 10, 2026):** FIDL migration built into the complete world and published packages. In a plane-on VM the provider activates as a core unit, the real held-gate `gate_test` passes with the other 40 provider, policy, legacy and runtime cases, and BSDTimectl reaches the live provider: reads succeed, the shipped policy refuses unauthorized `set`/`adjust` with `EPERM`, and 200 consecutive sessions succeed. As for every core provider, `switchboardctl restart system.Time/bsdtime` is refused at runtime; provider replacement is a release transaction. Release upgrade and rollback across boot environments remain to be validated with the integrated software-authority run. Capmode, user `capability`, and gate `settime` are unchanged.

Login shells look names up through a USER-domain channel. The `bsdtime` unit declares `visible = ["user"]`, as do the `BSDPower` and `BSDSysctl` units, so operators reach `BSDTimectl`, `BSDPowerctl` and `sysctlcmpctl` from a shell. Visibility only makes the name resolvable: every adjustment is still decided by `time.conf`, default-deny.

Known gaps and drift:

- No operator ctl test suite: `usr.sbin/BSDTimectl` has no `tests` directory.
- The chapter this one replaces described BSDTime as an ambient provider with pdfork workers; both statements predate the gate framework and are wrong.
- There is no clock-drift, NTP-style leap handling or `CLOCK_MONOTONIC` op; GET returns `CLOCK_REALTIME` only. A unit that needs monotonic time calls `clock_gettime(2)` itself, which is legal in capability mode.
- The bounded multiplexer passed a ten-minute native resource soak and a five-minute ASan/UBSan soak with simulated gates and logging. Multi-day operation, kernel memory profiling and live-plane quiesce/restart remain unverified.
