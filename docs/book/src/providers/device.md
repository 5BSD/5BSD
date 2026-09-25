# system.Device (BSDDevice)

## What it brokers

BSDDevice is the `system.Device` provider: it opens a single `/dev` leaf on behalf of a capability-mode component and delivers a rights-limited, non-forwardable descriptor for it. A sandboxed unit cannot `open("/dev/xyz")` itself; instead it names the leaf and the rights it wants, and the broker returns exactly the intersection of that request and the per-label policy maximum. It sits one layer below [system.Filesystem](filesystem.md): BSDFilesystem brokers persistent storage, BSDDevice brokers the raw device nodes of the driver model.

The broker never names a global path. Switchboard delivers `/dev` as an inherited directory descriptor (manifest `directories = ["/dev"]`), and every requested leaf is opened beneath it with `openat(2)`. Names are validated before anything else: empty names, names containing `/`, names beginning with `.` and `..` are rejected with `EINVAL`, so a request can never escape `/dev` or reach a nested path. BSDDevice enters capability mode before serving any client and serves each connection from a `pdfork(2)` worker that holds only its channel and the retained `/dev` descriptor; the worker enters capability mode with `NOPRIVS`, `NOFORK`, `NOIPC`, `NOFDRECV`, `NOEXEC` and `NOSOCK` protections.

A delivered descriptor is capped with `cap_rights_limit(2)` to the granted rights (always including `CAP_FSTAT`), optionally narrowed by `cap_ioctls_limit(2)` to a per-device command whitelist when the policy entry carries one, and hardened so it can be transferred exactly once (this delivery) and no further. Open flags are derived from the granted read and write rights; an ioctl-, mmap-, seek- or event-only grant opens `O_RDONLY` as the least-authority base.

Only the `system` lookup domain resolves `system.Device`. Device brokering is not a user-session facility, so a login shell cannot reach it at all.

## Unit

Source: `usr.sbin/BSDDevice/capbundle/device.ucl` and `Bundle.ucl`.

| Field | Value |
|---|---|
| Wire name | `system.Device` (interface version `1.0.0`, ABI 1) |
| Bundle | `/Capabilities/System/Device.cap` (`bundle_id = "system.Device"`) |
| Program | `/Capabilities/System/Device.cap/Units/bsddevice.unit/bin/BSDDevice` |
| Unit | `bsddevice` |
| User | `capability` |
| Launch | born in capability mode; `activation { boot = true; ipc = ["system.Device"]; }` |
| Control | `system` |
| Directories | `/dev` (delivered as a directory descriptor) |
| Visible | `["system"]` |
| Gates | none |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 1024; nproc = 128; core = 0`; `umask = "0077"` |
| Config | `Units/bsddevice.unit/Config/device.conf` |

## Wire operations

Defined in `lib/libdevicecmp/devicecmp_protocol.h`. The header is `struct devicecmp_msg` (magic `DEVC`, `version`, `opcode`, `flags`, `status` = 0 or negative errno). HELLO is a liveness probe answered by `devicecmp_hello_reply { version }`; there is no feature negotiation because the op set is fixed.

| Op | Request | Reply | Errors |
|---|---|---|---|
| `HELLO` (1) | header | `devicecmp_hello_reply` | `EPROTO` malformed |
| `OPEN` (2) | `devicecmp_open_body { rights, name_length }` + NUL-terminated leaf name | same body with `rights` = granted mask, plus one delivered fd | `EINVAL` bad name; `EACCES` no policy entry or empty intersection; `openat(2)` errors such as `ENOENT` |
| `LIST` (3) | `devicecmp_list_request { cursor, flags = 0, reserved = 0 }` | `devicecmp_list_reply { count, next_cursor, entries[] }`, at most `DEVICECMP_LIST_MAX` (32) per page, no fd | `EINVAL` nonzero additive fields |

Rights bits are `DEVICECMP_RIGHT_READ`, `WRITE`, `IOCTL`, `MMAP`, `SEEK` and `EVENT` (kqueue/poll). Each `devicecmp_list_entry` carries the leaf name, the policy-maximum rights for this label and device, and `DEVICECMP_LIST_FLAG_IOCTL_WHITELIST` when an ioctl whitelist would further narrow a delivered `IOCTL` descriptor. The list walk is filtered on the connecting channel's unforgeable label, never on a wire argument, and a label with no policy lists empty (count 0) rather than failing.

## Client library

Header `<devicecmp.h>` (installs `devicecmp.h` and `devicecmp_protocol.h`); link with `-ldevicecmp` (`SHLIB_MAJOR 1`, depends on libservice and pthread). Manual: libdevicecmp(3).

| Group | Functions |
|---|---|
| Open | `devicecmp_open(ctx, name, want_rights, &granted, &fd)` |
| Discovery | `devicecmp_list(ctx, cursor, entries, max, &count, &next_cursor)` |
| Liveness | `devicecmp_hello(ctx)` |

`ctx` is the process libservice context and may be `NULL` for a standalone caller; the `system.Device` session is opened by name once and cached for the process. All three fail closed, returning -1 with `errno` set and leaving `*fdp` at -1. If `max` is smaller than the page the provider returned, `devicecmp_list()` fails with `ENOMEM`, stores the required count in `*countp` and does not advance the cursor.

```c
#include <devicecmp.h>
#include <err.h>
#include <sys/ioctl.h>

int
open_console_ro(void)
{
	uint32_t granted;
	int fd;

	if (devicecmp_open(NULL, "console",
	    DEVICECMP_RIGHT_READ | DEVICECMP_RIGHT_EVENT, &granted, &fd) == -1)
		err(1, "system.Device: console");
	if ((granted & DEVICECMP_RIGHT_EVENT) == 0)
		warnx("policy did not grant EVENT; poll will fail");
	return (fd);	/* CAP_READ (+CAP_EVENT) + CAP_FSTAT, one-hop only */
}
```

A discovery loop pages with `cursor = 0` first and re-issues each reply's `next_cursor` until it is 0.

## Command-line tool

There is no ctl tool for `system.Device`. The inventory lists none, and because the name is visible only to the `system` domain a shell-run tool could not resolve it. Operators inspect the policy file directly and verify a bundle's expectations with the provider's tests; a unit that needs to check its own permitted set calls `devicecmp_list()`.

## Policy

Access is default-deny. The compiled-in policy grants nothing, so with no file at all every OPEN fails with `EACCES` and every LIST is empty. The optional `/Capabilities/System/Device.cap/Units/bsddevice.unit/Config/device.conf` is loaded once, before capability mode, through the delivered Config descriptor; a malformed file logs a warning and leaves default-deny standing rather than widening access.

Each `devices` entry grants one client label access to one `/dev` leaf:

| Key | Meaning |
|---|---|
| `label` | the connecting component's unforgeable channel label |
| `device` | one `/dev` leaf (no `/`, no leading `.`, never `..`) |
| `rights` | any of `read`, `write`, `ioctl`, `mmap`, `seek`, `event` |
| `ioctls` | optional array of ioctl command numbers; with `ioctl` in `rights`, caps the delivered fd with `cap_ioctls_limit(2)` to exactly those |

```ucl
devices = [
    { label = "system.Example"; device = "null"; rights = ["read", "write"]; },
    { label = "system.Example"; device = "zero"; rights = ["read"]; },
]
```

The shipped file contains only these two sample entries for a label that no real unit carries; replace them with the fleet's device policy. The granted mask is `want_rights & policy_max & DEVICECMP_RIGHT_ALL`; an empty intersection is `EACCES` even when the entry exists. There is no admin bypass in BSDDevice: unlike system.Network and system.Notify it does not consult `SERVICE_RIGHTS_ADMIN`, so a root login session with no entry is denied like any other label.

## Tests

| Where | Programs | What they prove |
|---|---|---|
| `usr.sbin/BSDDevice/tests` (package `bsddevice-tests`, `/usr/tests/usr.sbin/BSDDevice`) | `provider_test` (10 cases), `policy_test` (5) | provider_test drives the real session worker over a channel with the daemon compiled `-DBSDDEVICE_TESTING`: a granted open reads and writes, rights are narrowed to the policy maximum, an ungranted label or device is denied, unsafe names are rejected, malformed OPEN and LIST requests are rejected, LIST is label-scoped and empty for an unpolicied label, HELLO answers. policy_test covers the UCL parser and lookup. |
| `lib/libdevicecmp/tests` (`libdevicecmp-tests`) | `devicecmp_api_test` (3), `client_protocol_test` (6) | argument validation, message encoding, fail-closed behaviour without a provider |

Run with `kyua test -k /usr/tests/usr.sbin/BSDDevice/Kyuafile`. provider_test needs mac_capability channels, so it runs on a booted plane in the VM rig ([Testing](../develop/testing.md)); the inventory records it as VM-verified. The daemon exports the `BSDDevice` DTrace provider with `open` (label, leaf, granted rights, errno) and `list` (label, cursor, count, errno) probes; device contents are never probe arguments.

## Status and gaps

Status: shipped; capmode; user `capability`; `visible = ["system"]`; ops HELLO, OPEN, LIST; default-deny `device.conf` (inventory section 4).

Known gaps and drift:

- No ctl tool and no operator-facing enumeration of the effective policy beyond reading `device.conf`.
- BSDDevice(8) FILES names the unit directory `BSDDevice.unit`; the Makefile installs `bsddevice.unit`. Use the lowercase path.
- The shipped policy grants only sample entries for `system.Example`; a fresh install brokers no real device until an operator writes entries.
- The protocol is deliberately a thin v1 (a narrowed fd, optionally ioctl-whitelisted). Richer driver semantics behind the same name are reserved, not built.
- Test coverage is at the fleet minimum (10 provider cases); there is no stress or concurrency case for the worker cap (`DEVICECMP_MAX_WORKERS` 4096).
