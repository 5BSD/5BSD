# A Device Driver Bundle

A device driver bundle is a switchboard unit that talks to hardware from
userland without ever holding the authority to open `/dev` for itself. On
FreeBSD a userland driver runs as root, or as a user with a devfs rule, and
calls `open("/dev/foo")`. On 5BSD the unit is born in capability mode, so a
global path is unreachable; it asks a broker for one descriptor to one leaf,
receives it with narrowed Capsicum rights and a fixed ioctl whitelist, and
works with that descriptor for the rest of its life. Two brokers can hand out
such a descriptor: BSDDevice (`system.Device`), whose whole job is `/dev`
leaves, and BSDFilesystem (`system.Filesystem`), whose isolated-open policy
covers any absolute path including device units. This chapter shows both
routes, with BSDBluetooth as the worked example, and ends with what a userland
driver cannot yet do.

The mechanism comes from Part II: authority is a held descriptor, not a uid
(see [The Authority Model](../capability/authority-model.md)), and the unit
never leaves the sandbox it was launched into (see
[Capability Mode and the Born-Sandboxed Launch](../capability/capability-mode-and-launch.md)).

## How BSDDevice reaches /dev

BSDDevice itself is born in capability mode. Its manifest declares
`directories = ["/dev"]`, so switchboard opens `/dev` with
`O_DIRECTORY | O_RDONLY` before the exec, leaves the descriptor open across
it, and advertises the mapping in the environment as
`CAPABILITY_DIR_FDS=/dev=N`. The provider fetches it once with
`service_resource_dir("/dev", &devdir)` (libservice(3)); the descriptor is
borrowed and never closed. Every client request then becomes
`openat(devdir, name, flags)` in `usr.sbin/BSDDevice/bsddevice.c`. No code
path in the provider names a global path.

The `directories` key is validated in `lib/libcapbundle/libcapbundle_parse.c`:
an array of at most eight absolute paths, none containing `/../`. A missing
directory is skipped rather than failing the launch, so the provider must
handle `ENOENT` from `service_resource_dir` itself. The key is implemented and
used by BSDDevice, BSDCrypto, BSDPower and BSDFilesystem, but switchboard(5)
does not yet describe it; the parser and `switchboard_manifest.h` are the
reference.

Each connection is served by a `pdfork(2)` worker that enters capability mode
with `NOFORK | NOIPC | NOFDRECV | NOEXEC | NOSOCK` on top of the external
protections. The worker holds nothing but its channel and the `/dev`
directory descriptor.

## The OPEN path

The wire protocol lives in `lib/libdevicecmp/devicecmp_protocol.h` and has
three operations.

| Op | Request | Reply |
|---|---|---|
| `DEVICECMP_OP_HELLO` | header only | ABI version (`DEVICECMP_ABI_VERSION` is 1) |
| `DEVICECMP_OP_OPEN` | leaf name, wanted-rights mask | granted-rights mask plus one delivered descriptor |
| `DEVICECMP_OP_LIST` | cursor (0 for the first page) | up to 32 entries of leaf, policy-maximum rights, flags; next cursor |

For `OPEN` the provider does four things in order, all in `grant_open()`.

1. The name must be one component: no `/`, no leading `.`, never `..`.
   Nested device hierarchies such as `usb/0.1.0` are therefore unreachable.
2. The caller's label is looked up in the policy table. The label is the
   unforgeable channel identity switchboard stamped at launch, of the form
   `<bundle_id>/<unit>` (for example `system.Device/bsddevice`); it is never a
   wire argument. No entry means `EACCES`.
3. The delivered descriptor is limited with `cap_rights_limit(2)` to the
   intersection of the wanted mask and the policy maximum, always including
   `CAP_FSTAT`. If `ioctl` is granted, `cap_ioctls_limit(2)` is applied with
   the entry's command list; an `ioctl` grant with an empty list denies every
   ioctl and logs a warning, so a forgotten whitelist fails closed.
4. `service_harden_fd(fd, SERVICE_HARDEN_XFER_ONCE | SERVICE_HARDEN_CLOFORK_ONCE)`
   marks the descriptor so it crosses exactly one channel hop and cannot be
   forwarded again (see [Descriptor and Process Protections](../capability/descriptor-protections.md)).

The rights vocabulary maps one to one onto Capsicum.

| Policy word | `DEVICECMP_RIGHT_*` | Capsicum right |
|---|---|---|
| `read` | `READ` | `CAP_READ` |
| `write` | `WRITE` | `CAP_WRITE` |
| `ioctl` | `IOCTL` | `CAP_IOCTL`, then `cap_ioctls_limit` |
| `mmap` | `MMAP` | `CAP_MMAP` |
| `seek` | `SEEK` | `CAP_SEEK` |
| `event` | `EVENT` | `CAP_EVENT` (kqueue and poll) |

Open flags are derived from the granted read and write bits; a descriptor
granted only `ioctl` or `event` is opened `O_RDONLY`. `O_CLOEXEC`,
`O_NONBLOCK` and `O_NOCTTY` are always added.

## Policy: device.conf

BSDDevice grants nothing by default. Its policy is the UCL file
`/Capabilities/System/Device.cap/Units/bsddevice.unit/Config/device.conf`,
opened through the delivered `Config/` descriptor with
`service_config_open(3)`. The file must be a regular file, at most 1 MiB, and
not group- or world-writable, or it is rejected with `EPERM` and the
compiled-in deny-all stays in force. A parse error restores the previous
table atomically. The parser is `usr.sbin/BSDDevice/policy.c`.

The grammar is one array, `devices`, of entries with `label`, `device`,
`rights` and an optional `ioctls` list of at most 16 command numbers. The
shipped file grants two pseudo-devices to a placeholder label and is meant to
be replaced:

```
devices = [
    { label = "system.Example"; device = "null"; rights = ["read", "write"]; },
    { label = "system.Example"; device = "zero"; rights = ["read"]; },
]
```

A real entry for a driver unit `org.example.hid/hidd` that needs the vhid
control node would read:

```
devices = [
    { label = "org.example.hid/hidd"; device = "vhid";
      rights = ["read", "write", "ioctl"];
      ioctls = [ 1074025994, 2147767819 ]; },
]
```

Two things to notice. Matching is exact on both label and leaf; there are no
globs or prefixes, so a driver that creates numbered units (`vhid0`,
`vhid1`) needs one entry per unit or the Filesystem route below. And ioctl
commands are decimal integers, not names: 1074025994 is `VHID_CREATE`,
`_IOR('V', 10, int)` in `sys/dev/hid/vhid.h`, and the author has to compute
it. BSDCrypto,
which narrows its own `/dev/crypto` descriptor in C, spells the same kind of
whitelist as symbolic `CIOC*` names in `usr.sbin/BSDCrypto/bsdcrypto.c`; the
config-file form loses that readability.

## The client side

`libdevicecmp(3)` has three functions and no explicit session object; the
provider session is opened by name on first use and cached per process, and
reopened after a fork.

```c
int devicecmp_open(struct service_context *ctx, const char *name,
        uint32_t want_rights, uint32_t *granted_rights, int *fdp);
int devicecmp_list(struct service_context *ctx, uint32_t cursor,
        struct devicecmp_list_entry *entries, uint32_t max,
        uint32_t *countp, uint32_t *next_cursor);
int devicecmp_hello(struct service_context *ctx);
```

A driver unit that wants one leaf looks like this. It compiles and links
against the installed libraries (`cc -o devopen devopen.c -lservice -ldevicecmp`).

```c
#include <sys/ioctl.h>
#include <err.h>
#include <stdio.h>
#include <unistd.h>

#include <libservice.h>
#include <devicecmp.h>

int
main(void)
{
	struct service_context *ctx;
	struct devicecmp_list_entry entries[DEVICECMP_LIST_MAX];
	uint32_t count, next, granted;
	int fd;

	/* Process-wide switchboard context; idempotent, shared by all *cmp libs. */
	if (service_acquire(&ctx) == -1)
		err(1, "service_acquire");

	/* Discover what this unit's label may open (owner-scoped, default-deny). */
	if (devicecmp_list(ctx, 0, entries, DEVICECMP_LIST_MAX, &count, &next) == -1)
		err(1, "devicecmp_list");
	for (uint32_t i = 0; i < count; i++)
		printf("%s rights=%#x%s\n", entries[i].name, entries[i].rights,
		    (entries[i].flags & DEVICECMP_LIST_FLAG_IOCTL_WHITELIST) ?
		    " (ioctl whitelist)" : "");

	/* Ask for READ|WRITE|IOCTL; policy may grant less. Fails closed. */
	if (devicecmp_open(ctx, "vhci", DEVICECMP_RIGHT_READ |
	    DEVICECMP_RIGHT_WRITE | DEVICECMP_RIGHT_IOCTL, &granted, &fd) == -1)
		err(1, "devicecmp_open vhci");
	printf("granted=%#x fd=%d\n", granted, fd);

	/* Anything outside the whitelist fails with ENOTCAPABLE. */
	if (ioctl(fd, FIONREAD, &count) == -1)
		warn("ioctl FIONREAD");

	close(fd);
	service_release(ctx);
	return (0);
}
```

`LIST` exists so a unit can discover its openable set instead of probing
names; a label with no policy lists zero entries, which is not an error. The
`err(1, ...)` calls are for the example only: a real unit follows the
fail-soft rule from [A Consumer Application](consumer-app.md) and retries
later if `system.Device` is down.

## The driver unit's manifest

The unit declares nothing about devices. Its `Unit.ucl` is an ordinary
on-demand or boot unit; the device policy lives with the provider, keyed by
the label switchboard derives from `bundle_id` and the unit name. Only
SYSTEM-domain lookups resolve `system.Device` (its manifest says
`visible = ["system"]`), so the bundle must be installed under
`/Capabilities/System`, where a unit's own lookups run in the SYSTEM domain by
default (switchboard(5), `domain`).

```
# /Capabilities/System/Hid.cap/Bundle.ucl
schema = "org.5bsd.capability-bundle";
schema_version = 1;
bundle_id = "org.example.hid";
version = "1.0.0";
sequence = 1;
units = ["hidd"];

# /Capabilities/System/Hid.cap/Units/hidd.unit/Unit.ucl
activation { ipc = ["org.example.hid"]; }
program = "hidd";
restart = "on-failure";
protect = ["ptrace", "signal", "wait", "sigkill", "sigcont", "sched",
    "core", "ktrace"];
limits { nofile = 256; nproc = 16; core = 0; }
umask = "0077";
```

`user` and `group` default to `capability` (uid and gid 976, from
`etc/master.passwd`), `control` defaults to `system`, and the unit is born in
capability mode because `ambient` defaults to false. `activation { ipc = [...] }`
without `boot = true` makes it on-demand: it starts when something resolves
`org.example.hid`. A manifest key `kmod_requires` is rejected by the parser;
if the driver needs a kernel module it self-serves it through
`service_ensure_extension(3)` as described in
[A Kernel Extension](kernel-extension.md). The full key list is in
[Bundles and Manifests](../plane/bundles-and-manifests.md).

## The other route: an isolated open through BSDFilesystem

When the device hierarchy is dynamic, the Filesystem broker's isolated-open
policy fits better than `device.conf`. `service_open_isolated(3)` takes an
absolute path and a `SERVICE_OPEN_*` mask (`READ`, `WRITE`, `EXEC`, `LOOKUP`,
`IOCTL`, where `IOCTL` also carries `CAP_EVENT`) and returns a rights-limited,
close-on-exec descriptor, or `EACCES` if the caller's label has no grant. The
policy is the `open_paths` array in `/Capabilities/Config/bsdfilesystem.ucl`
(tzfs.conf(5)); an entry with `prefix = true` matches the path itself or the
path plus one trailing component, so `/dev/vhid` covers `/dev/vhid0`,
`/dev/vhid1` and so on, but never a deeper subdirectory.

The difference between the two routes is what an `ioctl` grant means. In
BSDFilesystem the whitelist is compiled in: an `IOCTL` open is capped to
exactly `VHID_CREATE`, `VHID_ATTACH` and `VHID_DESTROY`, because, as the
comment in `usr.sbin/BSDFilesystem/request.c` says, the only ioctl consumer of
an isolated device open is BSDBluetooth. A driver that needs any other
command on any other node has one route, `device.conf`, where the whitelist
is per entry. The Device route also marks the descriptor non-forwardable.

## Worked example: BSDBluetooth

BSDBluetooth is the largest userland driver in the tree and reaches three
kinds of kernel object, each by a different path. None of them is a global
`open(2)` when it runs under switchboard.

The radio is not a `/dev` node. HCI, L2CAP and ISO traffic go through
`AF_BLUETOOTH` sockets to the netgraph Bluetooth stack: `hci_open()` in
`usr.sbin/bluetooth/BSDBluetooth/hci_util.c` calls `bt_devopen()` on an
adapter name such as `ubt0`. Those sockets are not IP endpoints, so the unit
needs no `system.Network` grant either. The virtual controller behind the
test suite, ng_hci_virt(4), exposes `/dev/vhci` and `/dev/vhciN` for the
controller emulator side; that side is vhcitool(8) and the tests, which open
the node directly, not the daemon.

HID output devices are `/dev/vhid` units created by the vhid module. The
daemon first ensures the module through BSDExtension, then asks
BSDFilesystem for the control node, and narrows it itself
(`usr.sbin/bluetooth/BSDBluetooth/blued.c`, `blued_central.c`):

```c
if (blued_switchboard &&
    service_ensure_extension(blued_g.svc_ctx, "vhid") == -1)
	syslog(LOG_WARNING, "vhid module not loaded at startup "
	    "(ensured on demand): %m");

if (service_open_isolated(blued_g.svc_ctx, "/dev/vhid",
    SERVICE_OPEN_READ | SERVICE_OPEN_WRITE | SERVICE_OPEN_IOCTL,
    0, &blued_g.vhid_ctl_fd) == -1) {
	syslog(LOG_WARNING, "vhid control not available at "
	    "startup (acquired on demand): %m");
	blued_g.vhid_ctl_fd = -1;
}
...
unsigned long vhid_ioctls[] = { VHID_CREATE, VHID_DESTROY };
cap_rights_init(&rights, CAP_IOCTL, CAP_READ, CAP_WRITE);
(void)cap_rights_limit(blued_g.vhid_ctl_fd, &rights);
(void)cap_ioctls_limit(blued_g.vhid_ctl_fd, vhid_ioctls, nitems(vhid_ioctls));
```

The grant that makes the second call succeed is one line in the shipped
`bsdfilesystem.ucl`: label `org.5bsd.Blued/blued`, path `/dev/vhid`,
`prefix = true`, rights read, write and ioctl. Per-device units are then
opened the same way with the path `/dev/vhid%d`. Both opens are fail-soft:
a missing provider leaves the descriptor at -1 and the HID path acquires it
later when the first HID device appears.

Its manifest (`usr.sbin/bluetooth/BSDBluetooth/blued.ucl`) uses `directories`,
but for the bundle trees it reconciles against, not for `/dev`:

```
activation { ipc = ["system.Bluetooth"]; }
directories = ["/Capabilities/System", "/Capabilities/Apps", "/Capabilities/Run/live"];
control = "system";
protect = ["ptrace", "signal", "wait", "sigkill", "sigcont", "sched", "core", "ktrace"];
program = "BSDBluetooth";
restart = "on-failure";
stop_timeout = 10;
max_failures = 10;
```

So the worked example is honest in an uncomfortable way: the one big driver
in the base system does not use `libdevicecmp` at all. Nothing in the tree
links it except its own tests. BSDPower is the tightest in-tree use of the
delivered-`/dev` pattern (one node, `/dev/acpi`, one ioctl,
`ACPIIO_REQSLPSTATE`, fail-soft) and BSDCrypto the richest (`/dev/crypto`
with nine `CIOC*` commands); read `usr.sbin/BSDPower/BSDPower.c` for the
shape a new driver should copy.

## Testing a driver unit

BSDDevice ships two ATF programs in `usr.sbin/BSDDevice/tests`. `policy_test`
covers name validation, default deny, parsing and label-scoped paging.
`provider_test` compiles the real `bsddevice.c` with `-DBSDDEVICE_TESTING`,
drives `serve_session()` over a real plane session, and proves the properties
a driver author depends on: a policied open reads and writes, rights are
narrowed to policy, wrong label or unlisted leaf gives `EACCES`, unsafe names
are rejected, malformed requests get `EPROTO` or `EINVAL`, and `LIST` is
scoped to the connecting label. Those cases need a plane, so they run on the
VM runner described in [Testing](testing.md). A driver bundle's own tests
should follow the same pattern with a fake provider on the other end of a
session, and a plane-on integration case that opens the real leaf.

## Limits

State these plainly to anyone planning a driver.

| Limit | Detail |
|---|---|
| No interrupts to userland | There is no interrupt delivery mechanism for a unit; the tree has no code or design for it. A userland driver polls, blocks in `read(2)`, or uses `kevent(2)` on a descriptor the kernel driver already supports. |
| No DMA from userland | Nothing maps device memory or sets up bus_dma on a unit's behalf. `CAP_MMAP` can be granted on a delivered descriptor, but the mapping is whatever the kernel driver's `d_mmap` offers; BSDDevice never calls `mmap(2)` itself and grants bare `CAP_MMAP` without the `CAP_MMAP_R/W/X` sub-rights. |
| One leaf per entry, no nesting | Only single components under `/dev`; no globbing in `device.conf`. Use the Filesystem route with `prefix = true` for numbered units. |
| Ioctl whitelist is numeric | `device.conf` takes command numbers, not `_IOW` names. |
| Descriptor is the whole authority | The kernel driver's own checks still apply. `cryptodev`, for example, snapshots `PRIV_DRIVER` at open, which is why BSDCrypto opens its control node as root before dropping privileges. |
| Provider down | `devicecmp_open` fails with the session error. The driver must treat that as transient. |

The kernel side of a device, when userland is not enough, is the subject of
the next chapter, [A Kernel Extension](kernel-extension.md); the packaging of
the bundle is in [Packaging and Shipping](packaging.md).
