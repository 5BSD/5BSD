# system.SystemExtension (BSDExtension)

## What it brokers

BSDExtension is the kernel-module broker. It is the only process on a 5BSD
system that loads kernel code on another program's behalf, and it does so
without holding root: it is born in capability mode as the `capability`
user and performs each load through a Capsule-minted `kldload` system gate.
5BSD has it because module loading used to be an ambient privilege of PID 1
and of anything running as root; moving it behind a named, allow-listed,
SYSTEM-domain-only service means a compromised user service can never pull
code into the kernel, and an operator can see in one file which modules the
platform is willing to load at all.

A consumer that needs a driver or a filesystem module (BSDCrypto for
`cryptodev`, BSDBluetooth for `vhid`, BSDFilesystem for `zfs`, the Linux
runtime for `linux64`) does not call kldload(2). It calls
`service_ensure_extension(3)`, which opens `system.SystemExtension` over the
process's private lookup channel and asks BSDExtension to make the named
module resident. An already-loaded module is success; a module that is not
on the allow-list is `EPERM` regardless of who asks.
There is deliberately no UNLOAD operation on the wire. Safe removal needs
per-consumer ownership that a request/reply broker does not have; an unload
requested by one client could pull kernel code out from under another. The
only unloads BSDExtension performs are its own reclaim decisions.

The name `system.SystemExtension` resolves only for SYSTEM-domain clients.
That is the first gate: a USER-domain unit gets `ENOENT` from the lookup, the
same answer as for an unknown name, so it cannot even reach the broker. The
second gate is the allow-list. The third is the kernel: BSDExtension itself
cannot call kldload(2) successfully, because the capability user fails
`PRIV_KLD_LOAD`. Instead it holds the `SYS_GATE_KLDLOAD` and
`SYS_GATE_KLDUNLOAD` system tokens declared in its manifest and calls
`service_system_kldload(3)`, which enters `kern_kldload_gated()` in
`sys/kern/kern_linker.c`. The kernel checks the held claim, resolves the
module path with a kernel-context namei (exempt from the capability-mode
path restriction) and loads it. The raw syscall stays privilege-checked; the
sandbox is never loosened. See [System Gates](../capability/system-gates.md).

BSDExtension is also a reconcile client of the container model. Every module
it loads is attributed to the requesting unit's bundle, read from the
kernel-stamped container identity rather than from the wire, in a per-boot
owner map (`modules.meta` in its own storage container). A forked reconcile
child compares that map against the bundles present under the delivered
`/Capabilities/System`, `/Capabilities/Apps` and `/Capabilities/Run/live`
directories and unloads a module whose owning bundle has been gone for two
consecutive passes, only if BSDExtension loaded it, only if no other bundle
still claims it, and retrying a busy module on the next pass. Reclaim is
soft: without the map or the directories, loads are served exactly as before.
See [Containers and Storage](../plane/containers-and-storage.md).

## Unit

Source: `usr.sbin/BSDExtension/capbundle/Bundle.ucl` and
`capbundle/bsdextension.ucl` (installed as `Unit.ucl`).

| Field | Value |
|---|---|
| Wire name | `system.SystemExtension` |
| Bundle | `/Capabilities/System/SystemExtension.cap` (bundle_id `system.SystemExtension`) |
| Unit | `Units/bsdextension.unit` |
| Program | `Units/bsdextension.unit/bin/BSDExtension` |
| Activation | `boot = true`, `ipc = ["system.SystemExtension"]` |
| User | `capability` |
| Launch mode | born in capability mode (`ambient` absent) |
| Declared gates | `capabilities { system = ["kldload", "kldunload"] }` |
| Delivered directories | `/Capabilities/System`, `/Capabilities/Apps`, `/Capabilities/Run/live` |
| Control | `core` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 1024`, `nproc = 128`, `core = 0`; `umask = "0022"` |
| Environment | `BSDEXTENSION_RECLAIM_INTERVAL` (10 to 86400 s, default 300) |

`boot = true` because early consumers (storage, networking) may need a
module before the general service population is up. No `visible` key is
set, so the name stays SYSTEM-only. Each client is served on its own thread
rather than a pdfork worker so that the single held gate token, which is
close-on-fork, is shared by every session.

## Wire operations

Protocol header: `lib/libcapsulert/sysext_proto.h`. There is no HELLO and no
version field; the request is a fixed `struct sysext_request` (`op`,
reserved, `name[64]`) and the reply length selects the reply type. Every
name must be a single filename component: no `/`, not `.` or `..`.

| Op | Request | Reply | Errors |
|---|---|---|---|
| `SYSEXT_OP_ENSURE` (1) | `name` | `sysext_reply { status }` | `EPERM` not allow-listed; `EINVAL` bad name or framing; kldload(2) errors such as `ENOENT` (module not found in the module path) |
| `SYSEXT_OP_STAT` (2) | `name` | `sysext_stat_reply { status, loaded }` | `EPERM` not allow-listed (so a denied name leaks no loaded state); `EINVAL` |
| `SYSEXT_OP_LIST` (3) | none (`name` unused) | `sysext_list_reply { status, count, names[32][64] }` | `EINVAL` framing |
| `SYSEXT_OP_RELOAD` (4) | none | `sysext_reply { status }` | requires `SERVICE_RIGHTS_ADMIN` on the session; `EINVAL` when the replacement file is missing, unsafe or malformed (last good policy stays) |

`SYSEXT_LIST_MAX` (32) is statically asserted to be at least the daemon's
allow-list capacity, so LIST is always one bounded, unpaged reply. A request
that arrives with an attached descriptor is rejected.

## Client library

Header `<libservice.h>`, link `-lservice`. The extension calls live in
libservice(3) rather than a separate `*cmp` library.

| Group | Functions |
|---|---|
| Context-based (lazy open of `system.SystemExtension`) | `service_ensure_extension(ctx, module)`, `service_extension_stat(ctx, module, &loaded)`, `service_extension_list(ctx, names, max, &count)` |
| Session-based (caller owns a `struct service_session`) | `service_session_extension_load`, `service_session_extension_stat`, `service_session_extension_list`, `service_session_extension_reload` |
| Constants | `SERVICE_EXTENSION_NAME_MAX` (64), `SERVICE_EXTENSION_LIST_MAX` (32) |
| Provider side (used by BSDExtension itself) | `service_system_kldload(token_fd, name, &fileid)`, `service_system_kldunload(token_fd, fileid, flags)`, `service_system_token_dup` |

Client-side validation fails with `EINVAL` or `ENAMETOOLONG` before anything
is sent; a malformed reply poisons the session with `EPROTO`; a
`service_extension_list` buffer too small for the whole list fails
`EMSGSIZE` with the required count stored, never a silent truncation.
Session calls have a 30 second timeout.

```c
#include <errno.h>
#include <stdio.h>
#include <libservice.h>

/* Make sure the zfs module is resident; fail soft if the broker is down. */
int
need_zfs(struct service_context *ctx)
{
	int loaded;

	if (service_extension_stat(ctx, "zfs", &loaded) == 0 && loaded)
		return (0);
	if (service_ensure_extension(ctx, "zfs") == -1) {
		if (errno == EPERM)
			fprintf(stderr, "zfs is not on the allow-list\n");
		return (-1);
	}
	return (0);
}
```

A consumer must not treat `-1` from a lookup failure as fatal: the broker is
pulled up on demand and may be restarting. Retry later, as described in
[Discovery and the Lookup Channel](../plane/discovery-and-lookup.md).

## Command-line tool

sysextctl(8) is a thin session client. It uses the caller's own discovery
authority, never calls kldload(2), and does not manage the unit.

```
# sysextctl list
cryptodev
vhid
zfs
linux64
# sysextctl status vhid
vhid: not loaded
# sysextctl load vhid
vhid: loaded
# sysextctl reload
SystemExtension policy reloaded
```

`status` exits 1 when the module is not loaded; `EINVAL`/`ENAMETOOLONG` map
to `EX_USAGE`, an unreachable broker to `EX_UNAVAILABLE`, a protocol fault to
`EX_PROTOCOL`. `reload` needs ADMIN rights on the service channel, which a
plain uid 0 shell does not automatically carry; see
[The Management Model](../plane/management-model.md).

## Policy

The allow-list is default-deny and global (not per label). It is read from
`bsdextension.ucl` through the switchboard-delivered Config descriptor with
`service_config_open(3)`, so the effective file for the base unit is
`/Capabilities/System/SystemExtension.cap/Units/bsdextension.unit/Config/bsdextension.ucl`
(installed from `usr.sbin/BSDExtension/bsdextension.ucl`). When the file is
absent the compiled-in set stands: `cryptodev`, `vhid`, `zfs`, `linux64`.
When present, `allowed_extensions` replaces that set entirely.

```ucl
allowed_extensions = [
    "cryptodev",   # BSDCrypto: /dev/crypto
    "vhid",        # BSDBluetooth: virtual HID transport
    "zfs",         # BSDFilesystem
    "linux64",     # Linux application runtime
]
```

Rules the parser enforces: each entry is a single safe component; a file
that is not an object, has a non-array `allowed_extensions`, or contains an
invalid entry is rejected wholesale and the previous policy (or the
built-in set) stays; the first array element must directly follow `[`
because the bundled libucl mis-parses a leading comment inside an array. A
reload replacement must be a regular file owned by the daemon's effective
uid and not group- or world-writable; an empty array denies everything.
Updates are published atomically to all workers; requests already admitted
finish. There is no admin bypass of the allow-list itself. ADMIN rights only
unlock RELOAD.

BSDExtension.8 lists `/Capabilities/Config/bsdextension.ucl` as the policy
path; that is the daemon's compiled default for the explicit `-c` test path,
not what a born-in-capmode unit opens.

## Tests

`usr.sbin/BSDExtension/tests` (package group `bsdextension-tests`,
installed under `/usr/tests/usr.sbin/BSDExtension`):

| Program | Kind | Proves |
|---|---|---|
| `allowlist_test` | pure unit | allow and deny decisions, name validation (paths rejected, dotted names accepted, NUL termination), malformed/non-object/missing config falls back to defaults, config replaces defaults, STAT shares the ENSURE gate, reload authorization and last-good retention |
| `provider_test` | plane (needs `/dev/mac_capability`, root) | real handler over a real channel: denied module, unknown op, unterminated name, wrong length, attached descriptor, STAT loaded/unloaded/denied, LIST full and empty, RELOAD requires ADMIN |
| `reclaim_test` | pure unit | owner-map round trip, dedup, unsafe names, unload only unshared own modules, busy module retried, unknown bundle no-op, epoch recorded |

`usr.sbin/sysextctl/tests/sysextctl_test.sh` drives the real `sysextctl.c`
against a fake service (`commands`, `usage`, `protocol` cases). Run with
`kyua test -k /usr/tests/usr.sbin/BSDExtension/Kyuafile`; the plane cases
need the real-plane VM runner described in [Testing](../develop/testing.md).

## Status and gaps

Shipped; born in capability mode; renamed from `sysextd`. The inventory
records the op set ENSURE, LIST, STAT, RELOAD and the gates `kldload`,
`kldunload` as VM-verified. Gaps: no per-label policy (every SYSTEM caller
sees and may load the same set); no wire UNLOAD by design; the module path
is the kernel's, so a rebuilt module must be installed there before a load
request; the man page's `/Capabilities/Config` path is stale relative to the
delivered-Config mechanism the daemon uses in production.
