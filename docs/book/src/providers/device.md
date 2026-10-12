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
| Wire name | `system.Device` |
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

The provider and client use `lib/libdevicecmp/devicecmp.fidl`, library
`bsd.device.v1`, with generated C bindings over native capability channels
(see [FIDL and Capability IPC](../develop/fidl.md)). The schema installs as
`/usr/share/fidl/devicecmp.fidl` and imports `/usr/share/fidl/zx.fidl` for the
descriptor type. No payload carries an identity: the accepted session's label
and `device.conf` decide every request.

| Method | Request | Reply | Errors |
|---|---|---|---|
| `GetProtocolInfo` | empty | wire version 1 | none |
| `Open` | `name` (one /dev leaf, at most 255 bytes) and wanted `rights` | the delivered descriptor and the granted `rights` | `EINVAL` bad name; `EACCES` no policy entry or empty intersection; `openat(2)` errors such as `ENOENT` |
| `List` | `cursor` | `entries` (at most 32: leaf name, policy-maximum rights, flags) and `next_cursor` | none |

Rights bits are `DEVICECMP_RIGHT_READ`, `WRITE`, `IOCTL`, `MMAP`, `SEEK` and `EVENT` (kqueue/poll). Each list entry carries the leaf name, the policy-maximum rights for this label and device, and `DEVICECMP_LIST_FLAG_IOCTL_WHITELIST` when an ioctl whitelist would further narrow a delivered `IOCTL` descriptor. The list walk is filtered on the connecting channel's unforgeable label, never on a wire argument, and a label with no policy lists empty (count 0) rather than failing.

The delivered descriptor is Capsicum-limited to the granted rights (and the
ioctl whitelist), may be transferred no further, survives exactly one more
fork, and is close-on-exec locked; the FIDL transport keeps that state
(`fidl_bsd_connection_preserve_sent_inheritance()`). A session must negotiate
before any other method. A method before negotiation, an unknown method, a
malformed, truncated or oversized frame, a pre-FIDL record or an attached
descriptor closes the session without a reply; a name with a separator, a
leading dot or an embedded NUL is `EINVAL` and keeps the session. The
`bsd.device.v1` ordinals and layouts are a compatibility contract;
`usr.sbin/BSDDevice/tests/evolution/devicecmp_next.fidl` is the same schema at
`bsd:1` and adds a method at `bsd:2` for the pairing test.

## Client library

Header `<devicecmp.h>` (installs `devicecmp.h` and the legacy `devicecmp_protocol.h`, which still defines the rights bits, list entry and limits); link with `-ldevicecmp` (`SHLIB_MAJOR 1`, depends on libservice, the FIDL runtime and pthread). Manual: libdevicecmp(3).

| Group | Functions |
|---|---|
| Open | `devicecmp_open(ctx, name, want_rights, &granted, &fd)` |
| Discovery | `devicecmp_list(ctx, cursor, entries, max, &count, &next_cursor)` |

`ctx` is the process libservice context and may be `NULL` for a standalone caller; the `system.Device` session is opened by name once, negotiated, and cached for the process (a forked child opens its own). A timeout (30 seconds, shortened by an active `service_budget_begin()`), transport failure or malformed reply drops the cached session; application errors keep it. Both fail closed, returning -1 with `errno` set and leaving `*fdp` at -1. If `max` is smaller than the page the provider returned, `devicecmp_list()` fails with `ENOMEM`, stores the required count in `*countp` and does not advance the cursor.

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

Access is default-deny. The compiled-in policy grants nothing, so with no file at all every Open fails with `EACCES` and every List is empty. The optional `/Capabilities/System/Device.cap/Units/bsddevice.unit/Config/device.conf` is loaded once, before capability mode, through the delivered Config descriptor; a malformed file logs a warning and leaves default-deny standing rather than widening access.

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

## Client admission

Admission is limited to 4096 workers globally and 64 per authenticated client
label. `quota_test` covers the per-client boundary and returned capacity;
`lifecycle_test` covers child teardown. These are focused implementation tests,
not full endpoint saturation stress.

## Tests

| Where | Programs | What they prove |
|---|---|---|
| `usr.sbin/BSDDevice/tests` (package `bsddevice-tests`, `/usr/tests/usr.sbin/BSDDevice`) | `provider_test` (9 cases), `evolution_test` (2), `policy_test` (5), `lifecycle_test` (2), `quota_test` (1) | provider_test drives the real session worker (the daemon compiled `-DBSDDEVICE_TESTING`) over a channel with the generated client bindings: a granted open reads and writes and its descriptor survives one fork, rights are narrowed to the policy maximum, an ungranted label or device is denied, unsafe names are rejected, malformed Open and List frames (before negotiation, unknown method, truncated, missing body, over-long or mis-sized name, pre-FIDL record, attached descriptor) close the session, an embedded NUL is `EINVAL`, and List is label-scoped and empty for an unpolicied label. evolution_test is the `bsd:1`/`bsd:2` schema pairing in both directions. policy_test covers the UCL parser and lookup. |
| `lib/libdevicecmp/tests` (`libdevicecmp-tests`) | `devicecmp_api_test` (3), `client_protocol_test` (7) | argument validation; the client against a scripted server: session reuse, reconnection after transport failure, application errors that keep the session, malformed Open and List replies (with no descriptor leak), a future wire version, and a fresh session after fork |

Run with `kyua test -k /usr/tests/usr.sbin/BSDDevice/Kyuafile`. provider_test needs mac_capability channels, so it runs on a booted plane in the VM rig ([Testing](../develop/testing.md)); the inventory records it as VM-verified. The daemon exports the `BSDDevice` DTrace provider with `open` (label, leaf, granted rights, errno) and `list` (label, cursor, count, errno) probes; device contents are never probe arguments.

## Status and gaps

Status: shipped; capmode; user `capability`; `visible = ["system"]`; FIDL `bsd.device.v1` (October 2026) with Open and List; default-deny `device.conf`. Unit attributes, visibility and policy are unchanged by the migration; the provider and libdevicecmp ship together (mixed peers fail at negotiation).

Known gaps and drift:

- No ctl tool and no operator-facing enumeration of the effective policy beyond reading `device.conf`.
- The shipped policy grants only sample entries for `system.Example`; a fresh install brokers no real device until an operator writes entries.
- The protocol is deliberately thin (a narrowed fd, optionally ioctl-whitelisted). Richer driver semantics behind the same name are reserved, not built.
