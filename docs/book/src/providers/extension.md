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
boot activations with `sysextctl config`, and see what is built in, loaded
and recently refused with `sysextctl status`, which works from a root login
shell through the read-only view `system.SystemExtension.Status`. Root can
also load a module that a 5BSD base package installed with `sysextctl load`,
through `system.SystemExtension.RootLoad`, which checks the file against the
package database (see [Root loads](#root-loads-from-a-login-shell)).

A consumer that needs a driver or a filesystem module (BSDCrypto for
`cryptodev`, BSDBluetooth for `vhid`, BSDFilesystem for `zfs`, the Linux
runtime for `linux64`) does not call kldload(2). It calls
`service_ensure_extension(3)`, which opens `system.SystemExtension` over the
process's private lookup channel and asks BSDExtension to make the named
module resident. An already-loaded module is success; a module that is not
permitted (see [Policy](#policy)) is `EPERM` regardless of who asks.
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
| Wire names | `system.SystemExtension`; `system.SystemExtension.Status` (read-only view) |
| Bundle | `/Capabilities/System/SystemExtension.cap` (bundle_id `system.SystemExtension`) |
| Unit | `Units/bsdextension.unit` |
| Program | `Units/bsdextension.unit/bin/BSDExtension` |
| Activation | `boot = true`, `ipc = ["system.SystemExtension", "system.SystemExtension.Status"]` |
| User | `capability` |
| Launch mode | born in capability mode (`ambient` absent) |
| Declared gates | `capabilities { system = ["kldload", "kldunload"] }` |
| Delivered directories | `/etc/bsdextension`, `/Capabilities/System`, `/Capabilities/Apps`, `/Capabilities/Run/live`, `/boot` (the running kernel's module directory beneath it: `linker.hints` for the hardware-driver class, module files for root loads), `/var/db/pkg` (root loads) |
| Control | `core` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 1024`, `nproc = 128`, `core = 0`; `umask = "0022"` |
| Environment | `BSDEXTENSION_RECLAIM_INTERVAL` (10 to 86400 s, default 300) |

`boot = true` because early consumers (storage, networking) may need a
module before the general service population is up. No `visible` key is
set, so both names stay SYSTEM-only; switchboard additionally resolves the
read-only `system.SystemExtension.Status` for UID 0 sessions without a grant
(see [Read-only status](#read-only-status)). Each client is served on its own thread
rather than a pdfork worker so that the single held gate token, which is
close-on-fork, is shared by every session.

## Wire operations

The provider and client use `lib/libextensioncmp/extensioncmp.fidl`, library
`bsd.extension.v1`, with generated C bindings over native capability channels
(see [FIDL and Capability IPC](../develop/fidl.md)). The schema installs as
`/usr/share/fidl/extensioncmp.fidl`. No payload carries an identity: the
accepted session's rights (ADMIN for policy edits) and the bundle its label
belongs to decide every request. Module names (`string:63`) are nonempty
single filename components without NUL, excluding `.` and `..`. Persistent
edits additionally restrict names to ASCII letters, digits, `_`, `.` and `-`.
Application errors are errno values.

| Method | Request | Successful reply | Behavior |
|---|---|---|---|
| `GetProtocolInfo` | empty | wire version 1 | Negotiation; required before any other method |
| `Ensure` | module | empty | Load a permitted module; an existing load succeeds; denied names return `EPERM` |
| `Stat` | module | `loaded` | Query a permitted module; denied names return `EPERM` without loaded-state disclosure |
| `List` | empty | `modules` (at most 32) | Permitted-name listing; `EOVERFLOW` if more than 32 names are allowed |
| `Reload` | empty | empty | ADMIN: reload shipped defaults, preserving administrator overrides; invalid replacement retains the previous policy |
| `Allow` | module | empty | ADMIN: persist permission; does not install or load code |
| `Deny` | module | empty | ADMIN: deny future loads and restoration, retaining desired activation |
| `Reset` | module | empty | ADMIN: remove the entire override, including activation; inherit shipped permission |
| `Enable` | module | empty | ADMIN: persist desired boot activation; `EPERM` unless already permitted |
| `Disable` | module | empty | ADMIN: remove desired activation, retaining permission |
| `Restore` | empty | empty | ADMIN: load permitted entries with desired activation |
| `Info` | module | `{ name, flags }` | Query effective policy and permitted loaded state |
| `Next` | exclusive lexical cursor; empty starts | `{ name, flags }` | Return the next known policy entry; `ENOENT` ends enumeration |

The read-only view `system.SystemExtension.Status` speaks a second protocol of
the same library, `SystemExtensionStatus`:

| Method | Request | Successful reply | Behavior |
|---|---|---|---|
| `GetProtocolInfo` | empty | wire version 1 | Negotiation |
| `Info` | module | `{ name, flags }` | As on `SystemExtension` |
| `Next` | cursor | `{ name, flags }` | As on `SystemExtension` |
| `NextDecision` | `{ after }` (0 starts) | `{ sequence, time, module, client, operation, result, error }` | The oldest retained load decision after the cursor; `ENOENT` at the end |

It has no `Ensure`, `Stat`, `List`, `Reload` or policy method: such a frame is
an unknown ordinal and closes the session. The worker also marks a session
that arrived on this name read-only and decides only `Info` and `Next` for it,
whatever rights switchboard attached. `result` is `SYSEXT_DECISION_*` from
`sysext_proto.h`: 1 loaded, 2 already present, 3 not permitted (not on the
allow-list and not a class driver), 4 client limited to hardware drivers
(`driver_clients`), 5 administrator deny override, 6 permitted but the load
failed (`error` holds the errno). `operation` is 1 (Ensure) or 10 (Restore).
BSDExtension keeps the 64 most recent decisions in memory; they are lost when
it restarts.

A method before negotiation, an unknown method, a malformed, truncated or
oversized frame, a pre-FIDL record or an attached descriptor closes the
session without a reply; an embedded NUL in a name is `EINVAL` and keeps it.
The `bsd.extension.v1` ordinals and layouts are a compatibility contract;
`usr.sbin/BSDExtension/tests/evolution/extensioncmp_next.fidl` is the same
schema at `bsd:1` and adds a method at `bsd:2` for the pairing test.
`lib/libcapsulert/sysext_proto.h` keeps the state bits, limits and the legacy
records; the `SYSEXT_OP_*` numbers remain the DTrace request probe's codes.

Info/Next flags are
`SYSEXT_STATE_ALLOWED`, `ENABLED`, `LOADED`, `OVERRIDE` and `READY`.
Denied entries never disclose loaded state. READY means administrator storage
has been attached. Persistent edits and restoration return `EAGAIN` before
attachment; production attaches it before serving requests.

Next discovers both shipped entries and administrator overrides without the
List limit. Each entry is coherent, but enumeration across concurrent
edits is not a snapshot. It is a policy view, not an installed-package catalogue.

## Client library

Header `<extensioncmp.h>`, link `-lextensioncmp` (`SHLIB_MAJOR 1`, depends on
libservice, the FIDL runtime and pthread). The context calls moved out of
libservice in October 2026 with the same names; the session calls replaced
`service_session_extension_*` on a borrowed `struct service_session`.
Manual: libextensioncmp(3).

| Group | Functions |
|---|---|
| Context-based (lazy open of `system.SystemExtension`) | `service_ensure_extension(ctx, module)`, `service_extension_stat(ctx, module, &loaded)`, `service_extension_list(ctx, names, max, &count)` |
| Explicit session | `extensioncmp_session_open(&session)`, `extensioncmp_session_create(fd, &session)`, `extensioncmp_session_close(session)` |
| Session operations | `extensioncmp_load`, `extensioncmp_stat`, `extensioncmp_list`, `extensioncmp_reload` |
| Policy and discovery (session) | `extensioncmp_manage(session, action, name)`, `extensioncmp_info(session, name, next, &info)` |
| Read-only view | `extensioncmp_session_open_status(&session)`, `extensioncmp_session_create_status(fd, &session)`, `extensioncmp_session_read_only(session)`, `extensioncmp_decision(session, after, &decision)`; on a status session every other operation is `EPERM` without a request |
| Constants | `SERVICE_EXTENSION_NAME_MAX` (64), `SERVICE_EXTENSION_LIST_MAX` (32) |
| Provider side (libservice, used by BSDExtension itself) | `service_system_kldload(token_fd, name, &fileid)`, `service_system_kldunload(token_fd, fileid, flags)`, `service_system_token_dup` |

Client-side validation fails with `EINVAL` or `ENAMETOOLONG` before anything
is sent. A transport failure, timeout or malformed reply (`EPROTO`) ends the
session: the process-wide one is reopened on the next call, an explicit one
fails every later call. A `List` buffer too small for the whole list fails
`EMSGSIZE` with the required count stored, never a silent truncation. Calls
have a 30 second timeout, shortened by an active `service_budget_begin()`.

```c
#include <errno.h>
#include <stdio.h>
#include <extensioncmp.h>

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

### Read-only status

From a root login shell:

```sh
sysextctl status               # built-in modules, loaded files, recent load decisions
sysextctl status if_axge       # one module's policy and its recent decisions
sysextctl config               # every policy entry
sysextctl list
```

`status` without a module lists the modules compiled into the kernel and
the module files loaded since boot (kldstat(2) and modstat(2)), then the
broker's recent load decisions, oldest first, for example:

```
recent load decisions (oldest first):
  2026-11-01 05:12:07 load accf_http (client devd): refused: client may load hardware drivers only
  2026-11-01 05:12:09 load if_axge (client devd): loaded
```

A root login shell, a root cron job and a command run after `/etc/rc` exits
hold no software grant, so the SYSTEM-only `system.SystemExtension` is
invisible to them. Switchboard resolves the read-only
`system.SystemExtension.Status` for such a caller when the kernel-stamped
sender of the lookup has effective UID 0 and is not jailed
(`/Capabilities/Config/switchboard/root-query.ucl`); the session carries no
administrative rights. `list`, `config` and `status MODULE` use the full
endpoint when the caller reaches it (rc, devd) and the read-only view
otherwise. `load` and the policy commands never use the read-only view: from a
login shell the policy commands still fail with `EX_UNAVAILABLE`, `load` goes
to the root-load endpoint below, and kldload(8) is still refused by the gate.
Other users reach none of these endpoints and get nothing.
Only decisions the broker made are listed: a direct kldload(8) refused by the
gate, or a `sysextctl load` that could not reach the broker, leaves no entry.

### Root loads from a login shell

A root login shell may load a kernel module that the base system installed,
and nothing else:

```sh
sysextctl load ext2fs          # /boot/kernel/ext2fs.ko from a 5BSD base package
sysextctl status               # the decision: root load ext2fs (client root (uid 0)): loaded
sysextctl unload ext2fs        # only what a root load loaded
```

Switchboard resolves `system.SystemExtension.RootLoad` for the same callers as
the read-only view (effective UID 0 in the kernel stamp, not jailed, no
software grant, not a unit), listed in its own file,
`/Capabilities/Config/switchboard/root-load.ucl`, so the read-only list stays
read-only and the load endpoint can be withdrawn alone. Its protocol,
`SystemExtensionRootLoad`, has `Load` and `Unload` and nothing else: no
Ensure, Stat, List, policy, Reload or Restore method, and the session carries
no ADMIN right. kldload(8) from the shell stays refused by the gate.

BSDExtension never root-loads a protected module: `mac_*` security policies
(several grant privileges), the DTrace/HyperTrace/kinst/fbt/sdt/systrace/
fasttrap/profile tracing providers, ZFS and opensolaris, pf/ipfw and vmm. It
is the same list `sysextctl unload` refuses, kept in one function, and the
refusal reads `protected module`; load these through loader.conf(5) or
rc.conf(5). Otherwise it loads `NAME.ko` from the running kernel's module
directory (normally `/boot/kernel`; see [the kernel
directory](#the-kernel-directory)) only when the policy sets
`root_load_repository` (shipped: `5BSD-base`), no administrator `sysextctl
deny` names the module (the allow-list is not consulted), and the module and
every file its load would bring in pass the checks below.

Dependencies are resolved before anything is loaded. A forked child reads
each file's module metadata (`MODULE_VERSION`, `MODULE_DEPEND`) with
libkldelf, as kldxref(8) does; a dependency no loaded module provides is
found as the kernel linker would find it, through the kernel directory's
`linker.hints` (the preferred version, else the highest in range) or as
`NAME`/`NAME.ko` there, and the kernel's own interfaces need nothing. A
dependency found nowhere in the kernel directory is refused:
`kern.module_path` and `/boot/modules` are never searched. For every file:

- it is a regular file in the kernel directory, examined without following
  symbolic links and refused before it is opened when it is anything else (a
  device node or FIFO is never opened);
- the local package database (`/var/db/pkg/local.sqlite`) records that path
  in a package whose origin starts with `base/` and whose `repository`
  annotation (written by pkg at install time) is the configured repository;
- its current checksum equals the one pkg recorded. pkg 2 records `2$` and
  its own base32 of a BLAKE2b-512 digest, not SHA-256, so the broker computes
  exactly that (sys/contrib/libb2);
- no administrator deny names it and it is not protected;
- a dependency provides the version range the file that needs it declares.

The files are then loaded dependencies first, each by its absolute path, so
the kernel resolves nothing itself. After every load the broker compares the
loaded files with those before: a file it did not ask for, or a new file id
kldstat(2) cannot report, is a hard failure (logged at `LOG_ERR`), and
everything the request loaded is unloaded again, as when a file (device,
inode, size, modification or change time) or the kernel directory changed
between the check and the end of the load. Dependencies the load brought in
are root loads too: `sysextctl unload` removes them, the module that needs
them first.

libpkg is not part of base and the broker never runs pkg(8). The database is
read with base's private sqlite (`libprivatesqlite3`), and module metadata
with libkldelf, in pdfork(2)ed children that hold neither the kldload token
(close-on-fork) nor any descriptor but the one they read and a reply pipe. The
database child maps `local.sqlite` privately, opens it read-only with
`sqlite3_deserialize` (views, triggers and untrusted schema functions off);
each child returns one fixed-size record that the broker validates again. A
malformed database or module therefore reaches a process that can load
nothing. The broker is threaded; the child runs only the forking thread, and
libc's allocator and stdio carry fork handlers, so it may allocate.

`sysextctl unload NAME` removes only a module that a root load loaded since
the broker started, while its file id still names that file, and only if no
other client has asked for it since; it never unloads a protected module,
and the kernel still refuses a busy module or one another module depends on.

Every request is in the decision list with the client `root (uid 0)` and
logged by the broker (`ROOT LOAD x (uid 0 session, client ..., program nonce
...) -> DENIED (...); reason`). The kernel stamp carries no login session, so
sysextctl also logs each request to the `auth` facility with the login name,
terminal, and the audit user and session ids when the kernel has audit.
Refusals print their reason and exit `EX_NOPERM`:

| Message | Meaning |
|---|---|
| `not a file of an installed 5BSD base package` | no package records the file or a dependency, or it belongs to a ports package or to another repository |
| `the file does not match the checksum its package recorded` | modified or replaced after installation; reinstall the package |
| `no regular module file of that name in the running kernel's directory ...` | absent, a symbolic link, only in another directory, a dependency outside the kernel directory, or the directory no longer holds the running kernel (reboot after a kernel upgrade) |
| `denied by an administrator override` | the module or a dependency; `sysextctl reset NAME` removes the deny |
| `root loads are not configured` | `root_load_repository` is absent from `bsdextension.ucl` |
| `the package database could not be read` | `/var/db/pkg/local.sqlite` missing or unreadable |
| `a module file changed, or the kernel loaded a file that was not checked` | the load was undone |
| `protected module` | a security policy, tracing provider, ZFS, packet filter or vmm, or a module that needs one |

Who counts as root here is switchboard's decision from the kernel stamp's
effective UID. The stamp has no real UID, so a set-user-ID-root program run
by another user is root for this endpoint (and for the read-only view). Any
root process without a software grant qualifies, not only a login shell: a
cron job, or devd(8) restarted from a root shell (which then runs without its
lasting grant), can root-load any base module that passes these checks, so
the hardware-driver limit on devd's own grant does not bound what root can
load.

What this protects against: a root login shell (or a script run as root)
loading an arbitrary file, a module copied into the kernel directory by hand,
a dependency planted in `/boot/modules`, a module modified after installation
or a third-party module, by mistake; and every attempt is recorded. What it
does not protect against: a compromised root. The package database and
`/boot` are root-writable, so root can edit the database, swap a file between
the check and the load, replace or mount over `/boot`, install a package, or
add the module to loader.conf(5) and reboot. A dependency that is already
loaded is accepted by module name; its version is not visible to userland,
and if it does not satisfy the module the kernel searches `kern.module_path`
itself; the file it loads is caught and unloaded, but its initialisation has
run. The plane isolates `kern.module_path` (BSDSysctl, `bsdsysctl.ucl`), so
that search stays within the loader's directories. mac_veriexec(4) is the
defence against a compromised root.

### The kernel directory

BSDExtension receives `/boot` by descriptor and uses the directory the loader
booted the running kernel from: the pathname kldstat(2) reports for file id 1
(`/boot/kernel/kernel`, or `/boot/kernel.old/kernel` after booting the old
kernel). Nothing changes that after boot (`kern.bootfile` is a writable
string and is not used). The directory must be one component beneath
`/boot`, not a symbolic link, and its kernel file must carry the running
kernel's GNU build-id (`kern.build_id`). Booted from `kernel.old`, the
hardware-driver class reads `kernel.old/linker.hints`; root loads find no
package records there and are refused.

Before each hardware-driver decision and before and after every root load
the broker opens the directory again by name and compares it with the one it
holds. The same directory with the running kernel is used. A different
directory under the name (installkernel renames `kernel` to `kernel.old`; a
mount over it) is adopted, and logged, only when it holds the running kernel.
Otherwise, and when the kernel file was replaced in place by a kernel package
upgrade, driver and root loads are refused until the reboot: those modules
belong to another kernel. `linker.hints` is kept in memory while its device,
inode, size and times are unchanged.

### Loading with a grant

For interactive module loading on 5BSD, use `sysextctl load MODULE`, not
`kldload MODULE`. Once the capability plane claims the loading gate, direct
loads from callers without gate authority fail with `Operation not permitted`,
even as root. The `kldload` permission diagnostic points callers to `sysextctl`;
ordinary privilege or securelevel checks can also deny a load.
Early startup before the gate is claimed retains its direct loading path.

```sh
sysextctl list                 # permitted modules: loaded or allowed, installed file presence
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

`list` shows each permitted module as `NAME: loaded, installed=yes` or
`NAME: allowed, installed=no` (the two fields are independent).
A module compiled into the kernel (most of the base subsystems on amd64
GENERIC) reports `loaded` although it has no file: the broker checks
kldfind(2) and then modfind(2).
`allowed` means permitted but not currently loaded. `installed` checks for a
regular file named `NAME` or `NAME.ko` in `kern.module_path`, as visible to the
caller. It is `unknown` when a search path cannot be checked and no file is
found. This checks file presence, not package registration, dependencies or
compatibility, and does not resolve aliases through `linker.hints`.
`config` and `status` include the same installed field. Denied entries stay
omitted from `list`; `config` includes their policy but keeps their loaded
state undisclosed.

`status` exits 1 for a denied or unloaded module. `EINVAL`/`ENAMETOOLONG`
map to `EX_USAGE`, an unreachable broker to `EX_UNAVAILABLE`, a protocol
fault to `EX_PROTOCOL`, and unattached administrator storage to `EX_TEMPFAIL`.
The management commands (allow, deny, reset, enable, disable, reload, restore)
require ADMIN rights on the service channel; UID 0 alone does not grant them.
The only shipped holder of those rights is `/etc/rc` with its descendants while
it runs (`boot-authority.ucl`); a login shell has none.
See [The Management Model](../plane/management-model.md).

## Boot, services and hotplug

With the capability plane enabled, the late `/etc/rc.d/kld` service invokes
`sysextctl restore` after local filesystems mount, even when `kld_list` is
empty, which starts the broker and with it the `kldload` gate claim. It then
submits `kld_list` entries through the broker. From then on a direct
kldload(2) by root fails (kldload(8) reports `Exec format error`), so:

- `devmatch` submits every hardware driver it matches at boot through the
  broker. The hardware-driver class below permits these drivers without a
  list entry.
- rc reaches the broker through a temporary authority
  (`/Capabilities/Config/switchboard/boot-authority.ucl`) that ends when
  `/etc/rc` exits.
- After boot, devd(8) loads the driver of a device attached later. devd is
  an adopted rc.d service (`rc_adopt.conf`); once `/etc/rc` exits,
  switchboard restarts it (`service devd onerestart`) under a lasting grant
  from `/Capabilities/Config/switchboard/service-authority.ucl`. Its
  `nomatch` action runs `service devmatch quietstart`, and devmatch asks the
  broker through `sysextctl load`. The broker sees the client label `devd`,
  which `driver_clients` limits to the hardware-driver class below. The
  drivers most devices need are compiled into GENERIC (USB audio, video,
  Ethernet, HID, mass storage, keyboards), so they attach without a load.
- Nothing else can load an allow-listed module or a driver after boot. A
  root login shell holds no grant; it can inspect with `sysextctl status`
  and load a verified base-package module through the root-load endpoint
  above (devmatch run from such a shell takes the same path), and its
  kldload(8) is refused by the gate. Other users and jailed root get
  nothing; devmatch run by them reports `Cannot autoload NAME: only rc at
  boot and devd(8) may load drivers`.
- rc.subr(8) `load_kld`, used by rc.d scripts (`mac_ntpd` for ntpd, `if_vlan`,
  NFS, `geom_uzip`, the Bluetooth HID modules) and by `required_modules`,
  tries the direct load first, which works before the broker starts, and
  retries a failed direct load through the broker. `load_kld -b` uses only
  the broker. Third-party rc scripts that use `load_kld` or
  `required_modules` get the same behavior.

A broker denial is final; it is never retried with a direct `kldload`.
Explicitly disabling the capability plane (or running in a jail) keeps only
the direct path in all of these.
Neither disabling activation nor denying permission forcibly unloads shared
kernel code; existing loads remain until reboot or normal ownership reclamation.

A driver denied by an administrator (`sysextctl deny`) is not loaded by
devmatch either. For a USB mouse detected by `usbhid` but lacking an active
input driver, see
[USB mouse troubleshooting](../operations/troubleshooting.md#usb-mouse-is-detected-but-does-not-work-in-the-desktop)
for the `hms` permission, immediate load, and persistent boot activation steps.

### devd's grant

The grant is a switchboard software authority, not a UNIX privilege, and it
is narrower than rc's boot authority:

| | rc (boot) | devd (after boot) |
|---|---|---|
| Policy file | `boot-authority.ucl` | `service-authority.ucl` |
| Holder | `/etc/rc` and its descendants | the `devd` unit's start command and the daemon it starts |
| Lifetime | until `/etc/rc` exits | until the unit is stopped, restarted or removed |
| Executables | any | only `/bin/sh`, `/usr/bin/env`, `/usr/bin/limits`, `/sbin/devd`, `/usr/sbin/sysextctl`; exec of any other image drops it in that process |
| Endpoints | `system.SystemExtension` | `system.SystemExtension` |
| Administrative rights | yes | no |
| Broker class | allow-list and hardware drivers | hardware drivers only (`driver_clients`) |

Every request is logged by the broker with its client label, for example
`ENSURE if_urndis (client devd, hardware driver): loaded`, and refusals as
`ENSURE NAME (client devd) -> DENIED (client may load hardware drivers
only)`. The broker's gated load is also an ordinary kernel module load for
audit(4) and the OTel audit exporter when auditing is enabled. The
`kldload` gate itself is unchanged: only the broker loads modules.

This is not protection against a compromised root. Root can edit
`/etc/devd.conf` or devd's rc.conf flags, so devd's actions can request any
module in the class; and root can add a module with plug-and-play data to
`/boot/kernel`, which the class then admits (the boot path admits it at the
next boot as well). Signed-module enforcement (veriexec) is what stops the
second case. `sysextctl deny NAME` removes a driver from the class for devd
too.

## Policy

The allow-list is default-deny and global, except that a client named in
`driver_clients` never uses it. A module may load when it is permitted by the
allow-list and administrator overrides, or when it belongs to the
hardware-driver class.

The policy key `device_drivers = true` (shipped) enables the class: a module
whose file the running kernel's `linker.hints` records with plug-and-play match data
(`MDT_PNP_INFO`, written by kldxref(8) from the driver's PNP tables) is
permitted without a list entry. These are exactly the drivers devmatch(8)
can select for a device, as installed by the kernel package. Service modules
such as `mac_ntpd`, filesystems and protocol modules carry no such data and
still need an entry; modules under `/boot/modules` are not in the class. An
administrator `sysextctl deny NAME` override excludes a driver from the
class, and `device_drivers = false` turns the class off. `Info` reports a
class driver as allowed; `Enable` (boot activation) still needs an explicit
`sysextctl allow`. The broker reads `linker.hints` beneath the running
kernel's directory ([the kernel directory](#the-kernel-directory)) and keeps it
in memory while the file is unchanged; without that directory, or while it no
longer holds the running kernel, the class permits nothing. devd's lasting
grant follows it into `/bin/sh`, so every shell script a devd.conf(5) rule
runs holds it; `driver_clients`, which limits the label `devd` to this class,
is what bounds those actions.

The policy is read from `bsdextension.ucl` through the switchboard-delivered Config descriptor with
`service_config_open(3)`, so the effective file for the base unit is
`/Capabilities/System/SystemExtension.cap/Units/bsdextension.unit/Config/bsdextension.ucl`
(installed from `usr.sbin/BSDExtension/bsdextension.ucl`). The executable
grants nothing itself: a missing or invalid file stops startup, and
`allowed_extensions` is the complete base list. Administrator overrides are
then applied. An excerpt of the shipped file:

```ucl
device_drivers = true;
driver_clients = ["devd"];
allowed_extensions = [
    "cryptodev",   # bsdcrypto: /dev/crypto (OCF) for the crypto provider
    "zfs",         # bsdfilesystem: ZFS backing /Capabilities storage
    "linux64",     # sysextctl: Linux application runtime
    "drm",         # graphics core
    "pf",          # rc.d/pf, pflog, pfsync: packet filter when not preloaded
    # Modules the base rc.d scripts load after the broker has started.
    "mac_ntpd",    # rc.d/ntpd: run ntpd unprivileged
    "nfscl",       # rc.d/nfsclient, mountcritremote
    "cuse",        # rc.d/virtual_oss; webcamd and other cuse(3) daemons
]
```

Rules the parser enforces: the file is an object with exactly
`allowed_extensions`, optionally a boolean `device_drivers`, and optionally a
`driver_clients` array of up to eight unique switchboard client labels
(`[A-Za-z0-9._-]`); each `allowed_extensions` entry is a single safe
component; any other key, a non-array `allowed_extensions`, a non-boolean
`device_drivers`, a malformed `driver_clients` or an invalid entry rejects
the file wholesale
and the previous policy stays; the first array element must directly follow `[`
because the bundled libucl mis-parses a leading comment inside an array. A
reload replacement must be a regular file owned by the daemon's effective
uid and not group- or world-writable; an empty array with `device_drivers`
absent or false denies everything.
Updates are published atomically to all workers; requests already admitted
finish. ADMIN permits changing the policy, but Ensure still checks the effective
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
| `provider_test` | real public capability-channel syscall; no privilege | the real server over a real channel with libextensioncmp: denied module, a `driver_clients` label refused an allow-listed module, Stat loaded/unloaded/denied, List full, empty and too small, reload and management require ADMIN, discovery beyond the List limit; hand-built frames (before negotiation, unknown method, missing, truncated or oversized body, trailing bytes, pre-FIDL record, attached descriptor) close the session and an embedded NUL is `EINVAL` |
| `evolution_test` | real channel | the `bsd:1` libextensioncmp client against a `bsd:2` peer, and a `bsd:2` client against the real `bsd:1` worker (the added strict method closes only that session) |
| `reclaim_test` | pure unit | owner-map round trip, dedup, unsafe names, unload only unshared own modules, busy module retried, unknown bundle no-op, epoch recorded, boot ownership retained |
| `policy_test` | persistent policy | ADMIN enforcement, attachment, persistence and precedence, failed-write retention, corrupt-state rejection, concurrent updates and lexical discovery, writer-death recovery, real capability-mode persistence |
| `drivers_test` | pure unit | `device_drivers` class: linker.hints PNP classification over synthetic and truncated images, the policy key, the `driver_clients` key, an override deny beating the class, the installed kernel's hints and the packaged policy (devd is a driver client) |
| `rootload_test` | real channel and sqlite fixtures, module fixtures with real module metadata, a fake kernel that resolves `MODULE_DEPEND` through its module path like the real linker; no privilege | root loads: pkg's BLAKE2b checksum against a value pkg recorded, the database lookup in a child and hostile databases (WAL header, a view or trigger schema, truncated, garbage, an oversized row, a FIFO); a package module loads by absolute path and unloads once; refusals for a file no package records, a ports or other-repository package, a modified file, a file outside the kernel directory, a symlink or FIFO, a protected module or one that needs one, a dependency only in the module path (never initialised), an unpackaged or modified or denied dependency, a version mismatch; dependencies load first by path; an unexpected file, an unreadable new file id or a file rewritten with its mtime restored undoes the load; the kernel directory replaced (adopted only with the running kernel), the kernel replaced in place, a `kernel.old` boot; devd's Ensure through the real worker for the driver class (cached hints, stale kernel); a missing database, an administrator deny, an unset `root_load_repository`; the RootLoad endpoint closes Ensure, Stat, List, Reload, Allow, Restore and status frames, the library refuses them, and the status view reports every root decision |

`provider_test` also proves the read-only view: Info and Next work over it,
Ensure, Reload, Allow, Restore, Stat and List frames close the session even with
ADMIN rights on it, the full-protocol client cannot negotiate on it, refusals made
on the full endpoint are reported with their reasons and client labels, and the
decision ring keeps the most recent 64 in order.

`usr.sbin/sysextctl/tests/sysextctl_test.sh` drives the real CLI and client
protocol implementation against a fake service (`commands`, `usage`, `protocol`,
`root_status`, `root_mutation_refused`, `nonroot_refused` and `root_load` cases;
the fake aborts if a load or policy call reaches the read-only view, or a policy
call the root-load endpoint). Its `live` case runs the installed sysextctl as
root on a running capability plane: `status` and `config` work, a name with no
file in `/boot/kernel` is refused through the root-load endpoint and shows in
`status`, `allow` is refused, and `nobody` is refused. Build the current broker, library, CLI and tests before running Kyua;
installed binaries can lag source changes. Run each suite's generated Kyuafile.
Provider cases skip if the capability-channel syscall is unavailable; a skip is
not a pass. These tests do not establish successful gated module loading or
boot restoration on a release image; those require boot integration tests.

`libexec/rc/tests/sysext_startup_test.sh` exercises the current startup scripts
with command seams: restoration with an empty `kld_list`, multiple requested
modules, ownership claims for already-loaded modules, denial without a direct
loader retry, devmatch freeze/thaw, the explicit plane-disabled path, and
`load_kld`'s broker retry after a refused direct load (also through
`required_modules`), which a jail or a disabled plane never attempts.

## Status and gaps

The broker implements persistent administrator permissions and activation,
lexical discovery, and boot restoration alongside the original load/status API.
FIDL `bsd.extension.v1` (October 2026); unit attributes, visibility and policy
are unchanged by the migration, and the provider, libextensioncmp and
sysextctl ship together (mixed peers fail at negotiation). `latency_bench`
(installed with the tests) times Stat round trips for
`tools/build/fuchsia/vm-daemons.sh`.
Policy remains global rather than per label, and the full protocol has
no UNLOAD by design (the root-load endpoint's `Unload` is limited to what a
root load loaded). Permission does not install or authenticate module code: it must already
be available through the kernel's module path. Hardware-package compatibility
and release qualification are covered in
[Release hardware packages](../develop/packaging.md#release-hardware-packages).
