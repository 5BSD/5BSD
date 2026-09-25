# system.Power (BSDPower)

## What it brokers

BSDPower is the `system.Power` provider: the trusted broker for ACPI sleep. A unit holding a `system.Power` channel queries which sleep states the machine supports and, when the per-label policy grants it, asks the machine to enter one, without driving `/dev/acpi` itself. Reboot and halt stay with [Capsule](../plane/capsule.md); BSDPower owns sleep only.

Unlike [system.Time](time.md) and [system.Sysctl](sysctl.md), BSDPower needs no system gate. `ACPIIO_REQSLPSTATE` is gated only by device-node access, not by an in-kernel `priv_check`, so authority rides on a descriptor. Switchboard delivers `/dev` as a directory descriptor (manifest `directories = ["/dev"]`); at startup BSDPower opens the leaf `acpi` beneath it with `openat(2)`, narrows the result to `CAP_IOCTL` limited by `cap_ioctls_limit(2)` to exactly `ACPIIO_REQSLPSTATE`, and only then enters capability mode. The sandbox therefore exposes one privileged operation and nothing else. The supported-state mask is read once, also before capability mode, from the `CTLFLAG_CAPRD` sysctl `hw.acpi.supported_sleep_state` and cached.

If `/dev/acpi` is absent (a VM without ACPI, or a non-ACPI board) the daemon fails soft: it still starts, STATES reports the cached mask (zero when the sysctl is missing too), and SUSPEND returns `ENODEV`. Each accepted client is served from a `pdfork(2)` worker that inherits the narrowed descriptor, the loaded policy and the cached mask; the parent remains an accept loop.

## Unit

Source: `usr.sbin/BSDPower/capbundle/BSDPower.ucl` and `Bundle.ucl`.

| Field | Value |
|---|---|
| Wire name | `system.Power` (interface version `1.0.0`, ABI 1) |
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

Defined in `lib/libpowercmp/powercmp_protocol.h`. Fixed-size messages: `struct powercmp_msg` (magic `PWR\0`, `version`, `opcode`, `flags`, `status`) optionally followed by one `struct powercmp_body { state, supported, reserved[2] }`. `powercmp_validate_message()` is shared by client and daemon. HELLO is a bare liveness exchange. A request with an attached descriptor, wrong magic, wrong ABI version, zero or unknown opcode, or a short, oversized or partial body is `EPROTO` and ends the session.

| Op | Request | Reply | Errors |
|---|---|---|---|
| `HELLO` (1) | header | header, status 0 | `EPROTO` |
| `STATES` (2) | header | `powercmp_body.supported`: bit N set means SN is supported, e.g. `(1<<3)|(1<<4)|(1<<5)` for "S3 S4 S5" | none beyond transport |
| `SUSPEND` (3) | `powercmp_body.state` in 1..5 | header | `EPROTO` body missing; `EPERM` label not granted `suspend`; `EINVAL` state outside 1..5; `ENODEV` no `/dev/acpi`; ioctl errors |

The checks run in that order: policy first, then range, then device presence, so a denied label learns nothing about arguments or hardware. A granted SUSPEND is logged with the caller's label and fires the `BSDPower` provider's `suspend` probe before the reply; the machine may sleep before the reply is read.

## Client library

Header `<powercmp.h>` (installs `powercmp.h` and `powercmp_protocol.h`); link with `-lpowercmp` (`SHLIB_MAJOR 1`, depends on libservice). Manual: libpowercmp(3).

| Group | Functions |
|---|---|
| Session | `powercmp_client_open`, `powercmp_client_close` |
| Read | `powercmp_states(client, uint32_t *supported)` |
| Act | `powercmp_suspend(client, uint32_t state)` |

`powercmp_suspend()` fails with `EPERM` when the caller's label is not granted `suspend`.

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

There is no ctl test suite; the tool is thin enough that the daemon's provider test covers every path it exercises.

## Policy

`/Capabilities/System/Power.cap/Units/bsdpower.unit/Config/power.conf` (UCL), delivered as a directory descriptor and read once at startup. Querying states is never gated. `suspend` grants a label authority to put the machine to sleep. Labels match by exact string; an unlisted label falls back to `default`.

```ucl
default { suspend = false; }
clients {
	"org.5bsd.powerd" { suspend = true; }
}
```

The shipped file is exactly the `default` block plus a commented example. A missing or malformed file is fail-soft: the compiled-in default-deny stands. There is no `SERVICE_RIGHTS_ADMIN` bypass; an ambient root session with no entry gets `EPERM` from SUSPEND like any other label (acpiconf(8) from a root shell still drives `/dev/acpi` directly and is not interposed). An unexpected suspend is a denial of service, so grant `suspend` only to a trusted power manager.

## Tests

| Where | Programs | What they prove |
|---|---|---|
| `usr.sbin/BSDPower/tests` (package `runtime-tests`, `/usr/tests/usr.sbin/BSDPower`) | `provider_test` (19 cases), `config_test` (8) | provider_test compiles `BSDPower.c` with `-DBSDPOWER_TESTING`, which exposes the per-session worker and the two startup-cached globals (the state mask and the narrowed ACPI descriptor) so a test can drive the real request handler over a mac_capability channel without the switchboard launch path and without holding a real `/dev/acpi`. Cases: bad serve arguments, the supported mask matches the sysctl, HELLO answers, STATES reports the cached mask and zero without ACPI, SUSPEND is denied by default policy, an allowed label reaches the device, policy is per label, a bad state is `EINVAL`, denial precedes the state check, wrong ABI version and wrong magic, unknown and zero opcode, short, oversized and partial bodies, missing SUSPEND body is `EPROTO`, and an attached fd is rejected. Two of the cases are plane-free and run anywhere. config_test covers the parser and fail-soft loading. |
| `lib/libpowercmp/tests` (`libpowercmp-tests`) | `protocol_test` (6) | `powercmp_validate_message()` for both roles |

Run with `kyua test -k /usr/tests/usr.sbin/BSDPower/Kyuafile` on a booted plane ([Testing](../develop/testing.md)). The suite was added on the BSDTime pattern in commit 5692d3ef2c5e; the worker never touches real hardware under test, so `suspend_allowed_reaches_device` proves the ioctl is issued on the injected descriptor, not that the machine sleeps.

## Status and gaps

Status: shipped; capmode; user `capability`; `/dev/acpi` via delivered `/dev` with `cap_ioctls_limit`; ops HELLO, STATES, SUSPEND; provider_test present since 5692d3ef2c5e (inventory section 4).

Known gaps and drift:

- The chapter this one replaces described BSDPower as an ambient provider whose workers stay outside the sandbox; that predates the delivered-descriptor design and is wrong. The daemon and its workers run in capability mode.
- `lib/libpowercmp/tests` contains a stray `protocol_test.c-e` editor backup alongside `protocol_test.c`; it is not built.
- No ctl test suite for BSDPowerctl(8).
- The op set is deliberately minimal: no wake scheduling, no battery or AC state, no lid or button events, and no notification on entering or leaving sleep. A unit that wants to observe sleep transitions has nothing to subscribe to through [system.Notify](notify.md) yet.
- STATES is cached at startup; a machine whose ACPI state set changes at run time (unusual) would report the boot-time mask until restart.
