# system.Power (BSDPower)

## What it brokers

BSDPower is the `system.Power` provider: the trusted broker for ACPI sleep. A unit holding a `system.Power` channel queries which sleep states the machine supports and, when the per-label policy grants it, asks the machine to enter one, without driving `/dev/acpi` itself. Reboot and halt stay with [Capsule](../plane/capsule.md); BSDPower owns sleep only.

Unlike [system.Time](time.md) and [system.Sysctl](sysctl.md), BSDPower needs no system gate. `ACPIIO_REQSLPSTATE` is gated only by device-node access, not by an in-kernel `priv_check`, so authority rides on a descriptor. Switchboard delivers `/dev` as a directory descriptor (manifest `directories = ["/dev"]`); at startup BSDPower opens the leaf `acpi` beneath it with `openat(2)`, narrows the result to `CAP_IOCTL` limited by `cap_ioctls_limit(2)` to exactly `ACPIIO_REQSLPSTATE`, and only then enters capability mode. The sandbox therefore exposes one privileged operation and nothing else. The supported-state mask is read once, also before capability mode, from the `CTLFLAG_CAPRD` sysctl `hw.acpi.supported_sleep_state` and cached.

If `/dev/acpi` is absent (a VM without ACPI, or a non-ACPI board) the daemon fails soft: it still starts, `States` reports the cached mask (zero when the sysctl is missing too), and `Suspend` returns `ENODEV`. One shared kqueue loop (`fidl_bsd_connections_wait()`) serves at most 64 sessions, with at most four per exact client label. Non-inhibiting sessions expire after 30 seconds without requests. Active inhibitors remain until release or disconnect and decline idle quiesce; explicit supervisor stop still revokes them. Inhibitor acquisition and suspend checks are serialized.

## Unit

Source: `usr.sbin/BSDPower/capbundle/BSDPower.ucl` and `Bundle.ucl`.

| Field | Value |
|---|---|
| Wire name | `system.Power` |
| Bundle | `/Capabilities/System/Power.cap` (`bundle_id = "system.Power"`) |
| Program | `/Capabilities/System/Power.cap/Units/bsdpower.unit/bin/BSDPower` |
| Unit | `bsdpower` |
| User | `capability` |
| Launch | born in capability mode; `activation { boot = true; ipc = ["system.Power"]; }` |
| Control | `core` |
| Directories | `/dev` (delivered as a directory descriptor; only `acpi` is opened) |
| Gates | none |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 256; nproc = 64; core = 0`; `umask = "0077"` |
| Config | `Units/bsdpower.unit/Config/power.conf` |

## Wire operations

The provider and client use `lib/libpowercmp/powercmp.fidl`, library
`bsd.power.v1`, with generated C bindings over native capability channels
(the same runtime as [system.Time](time.md); see
[FIDL and Capability IPC](../develop/fidl.md)). The schema installs as
`/usr/share/fidl/powercmp.fidl`. No payload carries an identity or a grant:
the accepted session's label and the per-label policy remain the only
authorization inputs.

| Method | Request | Reply | Errors |
|---|---|---|---|
| `GetProtocolInfo` | empty | wire version 1 | none |
| `States` | empty | `supported`: bit N set means SN is supported, e.g. `(1<<3)|(1<<4)|(1<<5)` for "S3 S4 S5" | none |
| `Suspend` | `state` | empty | `EPERM` label not granted `suspend`; `EINVAL` state outside 1..5; `EBUSY` an inhibitor is held; `ENODEV` no `/dev/acpi`; ioctl errors |
| `Inhibit` | empty | empty | `EPERM` label not granted `inhibit`; `EALREADY`; `ENOTSUP` |
| `Uninhibit` | empty | empty | `ENOENT` no inhibitor held by this session |
| `Inhibitors` | empty | global inhibitor `count` | none |

A session must negotiate (`GetProtocolInfo`) before any other method. An
unknown method, a method before negotiation, a malformed, truncated or
oversized frame, a pre-FIDL record, or an attached descriptor closes the
session without a reply (the provider closes any received descriptor).
Application errors are errno values in the result union and keep the session.

The `Suspend` checks run in that order: policy first, then range, inhibitor
count, then device presence, so a denied label learns nothing about arguments
or hardware. A granted suspend is logged with the caller's label and fires the
`bsdpower` provider's `suspend` probe before the reply; the machine may sleep
before the reply is read. The `request` probe reports every method with the
historical operation codes (0 negotiation, 1 States, 2 Suspend, 3 Inhibit,
4 Uninhibit, 5 Inhibitors) and the errno result.

The `bsd.power.v1` ordinals and layouts are a compatibility contract.
`usr.sbin/BSDPower/tests/evolution/powercmp_next.fidl` is the same schema at
`bsd:1` (checked by `tools/build/fuchsia/test-bindings.py`) and adds a method
at `bsd:2`; `evolution_test` pairs a peer built from it with the real client
and provider in both directions. An incompatible change needs a new wire
major; the client never falls back to the pre-FIDL records.

## Client library

Header `<powercmp.h>` (installs `powercmp.h` and the legacy
`powercmp_protocol.h`); link with `-lpowercmp` (`SHLIB_MAJOR 1`, depends on
libservice and the FIDL runtime). Manual: libpowercmp(3).

| Group | Functions |
|---|---|
| Session | `powercmp_client_open`, `powercmp_client_create`, `powercmp_client_close` |
| Read | `powercmp_states(client, uint32_t *supported)`, `powercmp_inhibitors(client, uint32_t *count)` |
| Act | `powercmp_suspend(client, uint32_t state)`, `powercmp_inhibit`, `powercmp_uninhibit` |

`powercmp_suspend()` fails with `EPERM` when the caller's label is not granted
`suspend`. `powercmp_client_create(fd, &client)` adopts a held native channel
only on success. Sessions are locked against transfer and fork inheritance;
an inherited client object returns `ECHILD`. The first call checks the wire
version; negotiation and the operation share a five-second monotonic deadline,
shortened by an active `service_budget_begin()`. Timeouts, transport failures
and malformed replies close the session and leave the handle terminal; policy
errors keep it. Requests are never replayed.

```c
#include <powercmp.h>
#include <err.h>

void
sleep_if_supported(void)
{
	struct powercmp_client *pc;
	uint32_t supported;

	if (powercmp_client_open(&pc) == -1)
		err(1, "system.Power");
	if (powercmp_states(pc, &supported) == -1)
		err(1, "states");
	if ((supported & (1U << 3)) != 0 &&
	    powercmp_suspend(pc, 3) == -1)
		warn("suspend S3 (EPERM unless power.conf grants suspend)");
	powercmp_client_close(pc);
}
```

## Command-line tool

BSDPowerctl(8) is the operator front end, bound by the invoking label's policy like any other client.

| Verb | Example | Output shape |
|---|---|---|
| `states` | `BSDPowerctl states` | `S3 S4 S5`, or `(none)` when the mask is zero |
| `suspend state` | `BSDPowerctl suspend 3` | exit status; `EPERM` without `suspend` authority, `ENODEV` without ACPI |

`BSDPowerctl inhibitors` reports the active inhibitor count. `BSDPowerctl inhibit seconds` holds one for 1–86400 seconds using a monotonic deadline, checks the connection approximately once per second, and releases on SIGINT/SIGTERM. Health-check RPC time counts toward that deadline; release has a separate one-second RPC budget. Scheduling delays can extend observed wall time. Provider loss is an error; it does not reacquire. The CLI lifecycle is a VM acceptance gate.

## Policy

`/Capabilities/System/Power.cap/Units/bsdpower.unit/Config/power.conf` (UCL), delivered as a directory descriptor and read once at startup. Querying states is never gated. `suspend` grants a label authority to put the machine to sleep. Labels match by exact string; an unlisted label falls back to `default`.

```ucl
default { suspend = false; }
clients {
	"org.5bsd.powerd" { suspend = true; }
}
```

The shipped file is exactly the `default` block plus a commented example. A missing or malformed file is fail-soft: the compiled-in default-deny stands. There is no `SERVICE_RIGHTS_ADMIN` bypass; an ambient root session with no entry gets `EPERM` from `Suspend` like any other label (acpiconf(8) from a root shell still drives `/dev/acpi` directly and is not interposed). An unexpected suspend is a denial of service, so grant `suspend` only to a trusted power manager.

## Tests

| Where | Programs | What they prove |
|---|---|---|
| `usr.sbin/BSDPower/tests` (package `runtime-tests`, `/usr/tests/usr.sbin/BSDPower`) | `provider_test` (17), `lease_test` (3), `reactor_test` (3), `evolution_test` (2), `config_test` (9) | provider_test compiles `BSDPower.c` with `-DBSDPOWER_TESTING`, which exposes the per-session FIDL server and the two startup-cached globals (state mask, narrowed ACPI descriptor), and drives it over a mac_capability channel with the real libpowercmp client, never holding a real `/dev/acpi`. Cases: bad serve arguments, the mask matches the sysctl, `States` with and without ACPI, default-deny `Suspend`/`Inhibit` that keep the session, an allowed label reaches the device (`ENODEV`), per-label policy, provider-side range check (`EINVAL`) and denial before it (raw frames, since the client refuses bad states itself), and rejection of a method before negotiation, an unknown method, short and oversized frames, a missing body, a pre-FIDL record and an attached descriptor (whose received copy is closed). lease_test calls the method handlers directly. reactor_test runs the production reactor with real clients: leases across sessions, idle expiry exempting lease holders, refused idle quiesce, explicit stop, and per-label and total admission with slot reuse. evolution_test is the `bsd:1`/`bsd:2` schema pairing. |
| `lib/libpowercmp/tests` (`libpowercmp-tests`) | `client_test` (8), `constructor_test` (2), `protocol_test` (7) | The client against a scripted server: policy errors keep the session; a lost or malformed reply, a future wire version and a pre-FIDL provider are terminal before any operation; a caller's RPC budget bounds the call; fork ownership; descriptor ownership. protocol_test keeps the retained legacy validator ABI. |
| `usr.sbin/BSDPowerctl/tests` | `duration_test` | The `inhibit` deadline and release budget. |

Run with `kyua test -k /usr/tests/usr.sbin/BSDPower/Kyuafile` on a booted plane
([Testing](../develop/testing.md)); the FIDL VM harness is
`tools/build/fuchsia/vm-provider.sh`. The worker never touches real hardware
under test, so `suspend_allowed_reaches_device` proves the request passes
policy and reaches the injected-descriptor step, not that the machine sleeps.

## Migration and rollback contract

The FIDL wire major is 1. The public C API and shared-library major are
unchanged, with the additive held-channel constructor; `powercmp_validate_message()`
and `powercmp_protocol.h` remain only for ABI compatibility. `system.Power` is
a core unit: deploy the provider and the matching libpowercmp in the same
release transaction and restart both; mixed peers fail at negotiation, before
any operation, and there is no legacy fallback. A recovery release must pair
the matching provider and client library too.

## Status and gaps

Status: shipped; capmode; user `capability`; `/dev/acpi` via delivered `/dev` with `cap_ioctls_limit`; FIDL `bsd.power.v1` (October 2026). Unit attributes, visibility and policy are unchanged by the migration.

Known gaps and drift:

- The chapter this one replaces described BSDPower as an ambient provider whose workers stay outside the sandbox; that predates the delivered-descriptor design and is wrong. The daemon and its workers run in capability mode.
- The op set is deliberately minimal: no wake scheduling, no battery or AC state, no lid or button events, and no notification on entering or leaving sleep. A unit that wants to observe sleep transitions has nothing to subscribe to through [system.Notify](notify.md) yet.
- `States` is cached at startup; a machine whose ACPI state set changes at run time (unusual) would report the boot-time mask until restart.

## Session-owned suspend inhibitors

`powercmp_inhibit(client)` requires the separate, default-deny `inhibit = true` permission. It grants one inhibitor per live client session; duplicate acquisition returns `EALREADY`. `powercmp_uninhibit(client)` releases it (`ENOENT` if absent). `powercmp_inhibitors(client, &count)` reports the global count. A held inhibitor makes every BSDPower suspend request return `EBUSY`, including requests from the owning session.

The provider uses libservice's bounded lease set. Disconnect cleanup reclaims all leases owned by that session. Provider restart loses every lease; client libraries never transparently reopen or reacquire. Transport or protocol failure closes the underlying session and leaves the client handle terminal; free it with `powercmp_client_close()`. The provider reclaims its leases when it observes disconnect. A failed call may already have reached the server, and disconnect cannot undo an operation already performed. Policy errors preserve the session. Leases do not govern direct kernel suspend, reboot, or halt. The narrow device descriptor and exact-label authorization still govern requests.

Lease handler tests cover separate authorization, duplicate acquisition, foreign-session release, EBUSY before device access, owner cleanup and failed-reply cleanup without touching ACPI. Shared reactor regressions cover idle isolation, admission/reuse and writable-event idle expiry. Native multi-client disconnect, restart and real suspend remain VM tests.
