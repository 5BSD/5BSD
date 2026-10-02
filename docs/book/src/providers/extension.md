# system.SystemExtension (BSDExtension)

## What it brokers

BSDExtension is the kernel-module broker. It is the only process on a 5BSD
system that loads kernel code on another program's behalf, and it does so
without holding root: it is born in capability mode as the `capability`
user and performs each load through a Capsule-minted `kldload` system gate.
5BSD has it because module loading used to be an ambient privilege of PID 1
and of anything running as root; moving it behind a named, allow-listed,
SYSTEM-domain-only service means a compromised user service can never pull
code into the kernel. Operators inspect the effective permissions and persistent
boot activations with `sysextctl config`.

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
Loads requested by sessions without a bundle, including boot restoration, carry
a boot-long ownership claim and are not reclaimed when a bundle disappears.
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
| Delivered directories | `/etc/bsdextension`, `/Capabilities/System`, `/Capabilities/Apps`, `/Capabilities/Run/live` |
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

Protocol header: `lib/libcapsulert/sysext_proto.h`. There is no HELLO or
wire-version field. Every request is a fixed `struct sysext_request`
(`op`, zero reserved field, `name[64]`). Module names are nonempty,
NUL-terminated single filename components, excluding `.` and `..`.
Persistent edits additionally restrict names to ASCII letters, digits, `_`,
`.` and `-`. Requests carrying descriptors are rejected.

All replies begin with an errno-style `status` (zero on success). Errors
can use the short `sysext_reply`; successful replies have the operation's
specified size. Clients validate framing, reserved fields and returned data.

| Op | Request name | Successful reply | Behavior |
|---|---|---|---|
| `ENSURE` (1) | module | `sysext_reply` | Load a permitted module; an existing load succeeds; denied names return `EPERM` |
| `STAT` (2) | module | `sysext_stat_reply { status, loaded }` | Query a permitted module; denied names return `EPERM` without loaded-state disclosure |
| `LIST` (3) | zero-filled | `sysext_list_reply { status, count, names[32][64] }` | Legacy permitted-name listing; `EOVERFLOW` if more than 32 names are allowed |
| `RELOAD` (4) | zero-filled | `sysext_reply` | ADMIN: reload shipped defaults, preserving administrator overrides; invalid replacement retains the previous policy |
| `ALLOW` (5) | module | `sysext_reply` | ADMIN: persist permission; does not install or load code |
| `DENY` (6) | module | `sysext_reply` | ADMIN: deny future loads and restoration, retaining desired activation |
| `RESET` (7) | module | `sysext_reply` | ADMIN: remove the entire override, including activation; inherit shipped permission |
| `ENABLE` (8) | module | `sysext_reply` | ADMIN: persist desired boot activation; `EPERM` unless already permitted |
| `DISABLE` (9) | module | `sysext_reply` | ADMIN: remove desired activation, retaining permission |
| `RESTORE` (10) | zero-filled | `sysext_reply` | ADMIN: load permitted entries with desired activation |
| `INFO` (11) | module | `sysext_info_reply { status, flags, name[64] }` | Query effective policy and permitted loaded state |
| `NEXT` (12) | exclusive lexical cursor; empty starts | `sysext_info_reply` | Return the next known policy entry; `ENOENT` ends enumeration |

The constants have the prefix `SYSEXT_OP_`. INFO/NEXT flags are
`SYSEXT_STATE_ALLOWED`, `ENABLED`, `LOADED`, `OVERRIDE` and `READY`.
Denied entries never disclose loaded state. READY means administrator storage
has been attached. Persistent edits and restoration return `EAGAIN` before
attachment; production attaches it before serving requests.

NEXT discovers both shipped entries and administrator overrides without the
legacy LIST limit. Each entry is coherent, but enumeration across concurrent
edits is not a snapshot. It is a policy view, not an installed-package catalogue.

## Client library

Header `<libservice.h>`, link `-lservice`. The extension calls live in
libservice(3) rather than a separate `*cmp` library.

| Group | Functions |
|---|---|
| Context-based (lazy open of `system.SystemExtension`) | `service_ensure_extension(ctx, module)`, `service_extension_stat(ctx, module, &loaded)`, `service_extension_list(ctx, names, max, &count)` |
| Session-based (caller owns a `struct service_session`) | `service_session_extension_load`, `service_session_extension_stat`, `service_session_extension_list`, `service_session_extension_reload` |
| Policy and discovery (session-based) | `service_session_extension_manage(session, action, name)`, `service_session_extension_info(session, name, next, &info)` |
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

For interactive module loading on 5BSD, use `sysextctl load MODULE`, not
`kldload MODULE`. Once the capability plane claims the loading gate, direct
loads from callers without gate authority fail with `Operation not permitted`,
even as root. The `kldload` permission diagnostic points callers to `sysextctl`;
ordinary privilege or securelevel checks can also deny a load.
Early startup before the gate is claimed retains its direct loading path.

```sh
sysextctl list                 # permitted modules: loaded or not loaded
sysextctl config               # permission, boot activation, loaded state, override
sysextctl status i915kms
sysextctl allow i915kms        # persist permission
sysextctl enable i915kms       # activate on subsequent boots
sysextctl load i915kms         # load now
sysextctl deny i915kms         # block future loads and restoration
sysextctl disable i915kms      # remove desired activation
sysextctl reset i915kms        # remove the entire administrator override
sysextctl reload               # reread shipped defaults
sysextctl restore              # apply all permitted boot activations now
```

`list` shows each permitted module as `NAME: loaded` or `NAME: not loaded`.
It reports the kernel's loaded state, not whether the module package is
installed. Denied entries stay omitted; `config` includes their policy but
keeps their loaded state undisclosed.

`status` exits 1 for a denied or unloaded module. `EINVAL`/`ENAMETOOLONG`
map to `EX_USAGE`, an unreachable broker to `EX_UNAVAILABLE`, a protocol
fault to `EX_PROTOCOL`, and unattached administrator storage to `EX_TEMPFAIL`.
The management commands (allow, deny, reset, enable, disable, reload, restore)
require ADMIN rights on the service channel; UID 0 alone does not grant them.
See [The Management Model](../plane/management-model.md).

With the capability plane enabled, the late `/etc/rc.d/kld` service invokes
`sysextctl restore` after local filesystems mount, even when `kld_list` is
empty. It then submits `kld_list` entries through the broker. `devmatch` also
uses the broker for autoload requests. A denial is not retried with direct
`kldload`. Early `load_kld` callers retain their direct path; explicitly
disabling the capability plane retains direct loading in these startup services.
Neither disabling activation nor denying permission forcibly unloads shared
kernel code; existing loads remain until reboot or normal ownership reclamation.

## Policy

The allow-list is default-deny and global (not per label). It is read from
`bsdextension.ucl` through the switchboard-delivered Config descriptor with
`service_config_open(3)`, so the effective file for the base unit is
`/Capabilities/System/SystemExtension.cap/Units/bsdextension.unit/Config/bsdextension.ucl`
(installed from `usr.sbin/BSDExtension/bsdextension.ucl`). When the file is
absent the compiled-in set stands: `cryptodev`, `vhid`, `zfs`, `linux64`,
`pty`, `fdescfs`, `linprocfs`, `linsysfs`, `drm`, `i915kms`, `amdgpu`,
`radeonkms`. When present, `allowed_extensions`
replaces those defaults. Administrator overrides are then applied.

```ucl
allowed_extensions = [
    "cryptodev",   # BSDCrypto: /dev/crypto
    "vhid",        # BSDBluetooth: virtual HID transport
    "zfs",         # BSDFilesystem
    "linux64",     # Linux application runtime
    "pty",         # Linux /dev/ptmx and legacy BSD PTYs
    "fdescfs",     # Linux /dev/fd (linrdlnk)
    "linprocfs",   # Linux /proc
    "linsysfs",    # Linux /sys
    "drm",
    "i915kms",
    "amdgpu",
    "radeonkms",
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
finish. ADMIN permits changing the policy, but ENSURE still checks the effective
permission for every caller.

Administrator overrides are versioned state in `/etc/bsdextension/overrides.ucl`,
inside a private directory owned by `capability` and delivered by descriptor.
This directory is on the root filesystem, so bootstrap policy does not depend
on the ZFS storage service whose startup may itself require an extension.
It works with UFS and read-only installer media; edits on read-only media fail
without publishing a replacement policy. An absent override file means no
overrides; a missing directory or corrupt registry fails startup closed.

Use `sysextctl` to edit this state. The broker serializes updates, writes and
syncs a replacement, renames it and syncs the directory before publishing it.
A directory-sync failure after rename fails closed because durability is
uncertain. Robust shared locking recovers a durable commit if a writer dies
before publication. Overrides survive shipped-default reloads and package
updates. An explicit deny overrides a shipped allow; enabling a denied entry
fails, while denying an enabled entry retains its desired activation as blocked.

## Tests

`usr.sbin/BSDExtension/tests` (package group `bsdextension-tests`,
installed under `/usr/tests/usr.sbin/BSDExtension`):

| Program | Kind | Proves |
|---|---|---|
| `allowlist_test` | pure unit | allow and deny decisions, name validation (paths rejected, dotted names accepted, NUL termination), malformed/non-object/missing config falls back to defaults, config replaces defaults, STAT shares the ENSURE gate, reload authorization and last-good retention |
| `provider_test` | real public capability-channel syscall; no privilege | real handler over a real channel: denied module, unknown op, unterminated name, wrong length, attached descriptor, STAT loaded/unloaded/denied, LIST full and empty, management requires ADMIN, discovery beyond the legacy limit |
| `reclaim_test` | pure unit | owner-map round trip, dedup, unsafe names, unload only unshared own modules, busy module retried, unknown bundle no-op, epoch recorded, boot ownership retained |
| `policy_test` | persistent policy | ADMIN enforcement, attachment, persistence and precedence, failed-write retention, corrupt-state rejection, concurrent updates and lexical discovery, writer-death recovery, real capability-mode persistence |

`usr.sbin/sysextctl/tests/sysextctl_test.sh` drives the real CLI and client
protocol implementation against a fake service (`commands`, `usage`, `protocol`
cases). Build the current broker, library, CLI and tests before running Kyua;
installed binaries can lag source changes. Run each suite's generated Kyuafile.
Provider cases skip if the capability-channel syscall is unavailable; a skip is
not a pass. These tests do not establish successful gated module loading or
boot restoration on a release image; those require boot integration tests.

`libexec/rc/tests/sysext_startup_test.sh` exercises the current startup scripts
with command seams: restoration with an empty `kld_list`, multiple requested
modules, ownership claims for already-loaded modules, denial without a direct
loader retry, devmatch freeze/thaw, and the explicit plane-disabled path.

## Status and gaps

The broker implements persistent administrator permissions and activation,
lexical discovery, and boot restoration alongside the original load/status API.
Policy remains global rather than per label, and there is no wire UNLOAD by
design. Permission does not install or authenticate module code: it must already
be available through the kernel's module path. Hardware-package compatibility
and release qualification are covered in
[Release hardware packages](../develop/packaging.md#release-hardware-packages).
