# system.Filesystem (BSDFilesystem)

BSDFilesystem is the storage broker of the capability plane. It holds the
ZFS pool behind `/Capabilities`, mints a rights-limited TrustedZFS dataset
handle for each claim a unit makes at runtime, mounts stores that sandboxed
consumers cannot mount themselves, and reaps the storage of bundles that are
gone. 5BSD has it because a unit born in capability mode cannot name a path,
and because the alternative, declaring storage in a manifest and letting
the service manager hand it out, put a resource-granting role into
switchboard that belongs in a daemon with exactly one job.

## What it brokers

The kernel side is TrustedZFS: a new descriptor type, `DTYPE_ZFSHANDLE`
(19 in `sys/sys/file.h`), minted on `/dev/zfs` with `ZFS_IOC_DATASET_OPEN`
or `ZFS_IOC_POOL_OPEN`. A handle pins a dataset or pool by guid, so it
follows a rename and fails visibly after a destroy; it carries a rights mask
fixed at mint (nineteen `ZH_*` bits in `sys/sys/zfshandle.h`, with
`ZH_PROPS_READ` and `ZH_EVENT` implicit) and flags (`ZHF_SUBTREE`,
`ZHF_SEND_ONCE`, `ZHF_SEND_CONSUME`); and it only narrows, through
`ZFD_DERIVE` and `ZFD_OPENAT`. Its verbs (`ZFD_*` 0x01 to 0x25, `ZPD_*` for
pools) drive the existing DSL paths. The verb that matters here is
`ZFD_MOUNT`: it mounts the dataset with no covered vnode and returns a
directory descriptor. The filesystem is fully functional through that
descriptor and unreachable by path; `vn_fullpath` reports nothing. Every
handle and every root dirfd is an anchor, and the last anchor unmounts.
libtrustedzfs (trustedzfs(3), `-ltrustedzfs`) wraps the ioctls as
`tzfs_open`, `tzfs_derive`, `tzfs_mount`, `tzfs_snapshot`, `tzfs_send`,
`tzfs_pool_open_fd` and about forty others, plus `tzfs_limit_*_ioctls`
profiles for `cap_ioctls_limit(2)`.

BSDFilesystem is the only program that mints from the pool root. At startup
it reads `/Capabilities/Config/bsdfilesystem.ucl` (tzfs.conf(5)), opens the
pool handle through the delivered `/dev` and `/`, provisions
`<pool>/Capabilities/Data` and `<pool>/Capabilities/ephemeral`, and enters
capability mode. Every request is then served from retained handles, and
the caller's dataset subtree is derived from the channel label switchboard
stamped: a caller can only ever create, open, stat, version or destroy
storage under its own bundle. The label is the address and it is never a
wire argument.

Durable storage lands in the container layout that [Containers and
Storage](../plane/containers-and-storage.md) describes:
`Data/<bundle>/<unit>/{persistent,cache}`, `Data/<bundle>/shared` for the
bundle's units, and `Data/Shared/<group>` for a cross-bundle group the
bundle declares membership in. A reconcile pass at boot and every
`reclaim_interval` seconds compares those containers against the installed
bundles and the `/Capabilities/Run/live` markers and destroys the container
of a bundle that is neither installed nor running, snapshots included. A
container whose snapshot is pinned by a clone outside it fails that pass
with `EEXIST`, is logged, and is retried on every later pass. The same
timer reaps abandoned transaction staging clones older than
`staging_idle_grace`.

## Unit

| Field | Value |
|---|---|
| Wire name | `system.Filesystem` |
| Bundle | `/Capabilities/System/Filesystem.cap` (`bundle_id = "system.Filesystem"`) |
| Program | `Units/bsdfilesystem.unit/bin/BSDFilesystem` |
| Unit name | `bsdfilesystem` |
| Activation | `boot = true`, `ipc = ["system.Filesystem"]` |
| User | `root` (pool-root mint only; no other provider runs as root for storage) |
| Launch mode | born in capability mode; `directories = ["/dev", "/"]` |
| Declared gates | none |
| Visible | `["user"]` (login sessions may resolve it) |
| Control | `core` |
| Restart | `on-failure` |
| Protect | `ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`, `ktrace` |
| Limits | `nofile = 4096`, `nproc = 128`, `core = 0`; `umask = "0022"` |

The daemon takes `-c config` to read a different configuration file; a
missing file is not an error. It writes `/var/run/BSDFilesystem.ready` once
serving begins.

## Wire operations

The protocol is `lib/libcapsulert/bsdfilesystem_proto.h`, version
`BSDFILESYSTEM_PROTO_VERSION` 6 (0.5.0). There is no HELLO: the first four
bytes of every request are the `op`. Opcode 3 is unassigned. A successful
REQUEST, OPEN, OPEN_VERSION or TXN_BEGIN delivers its descriptor as the
reply's single SCM_RIGHTS fd. Every claim-addressed op resolves the claim
under the caller's own container.

| Op | Request | Reply | Errors |
|---|---|---|---|
| 1 REQUEST | `bsdfilesystem_request` (dataset key, `ZH_*` rights, `ZHF_*` flags, lifetime, deliver shape, scope, group, quota, owner uid/gid, session) | `bsdfilesystem_reply` + fd: dataset handle, or a mounted dirfd for `DELIVER_MOUNTED`, read-only for `DELIVER_MOUNTED_RO` | `EINVAL` (quota below 1 MiB, bad name), `EPERM` (group not a declared membership), `ENXIO` (no pool) |
| 2 RELEASE | `bsdfilesystem_request` (dataset) | `bsdfilesystem_reply` | idempotent; a missing lease claim is success |
| 4 PING | header | `bsdfilesystem_reply` | none |
| 5 BEGIN_SESSION | `bsdfilesystem_request` (session id) | `bsdfilesystem_reply` | none |
| 6 OPEN | `bsdfilesystem_open_request` (absolute path, `BSDFILESYSTEM_OPEN_*` rights, `is_dir`) | `bsdfilesystem_reply` + rights-limited fd | `EACCES` (label not granted the path), `ENOENT` |
| 7 DESTROY | `bsdfilesystem_request` (dataset, lifetime PERSISTENT or CACHE, scope, group) | `bsdfilesystem_reply` | `ENOENT` (absent; not idempotent) |
| 8 LIST | `bsdfilesystem_list_request` (scope, group, cursor) | `bsdfilesystem_list_reply`: up to 32 `bsdfilesystem_claim_entry` (name, used, refquota, lifetime), `next_cursor` | none; an empty namespace lists empty |
| 9 STAT_CLAIM | `bsdfilesystem_request` (dataset, lifetime, scope, group) | `bsdfilesystem_stat_reply` (used, refquota, available) | `ENOENT` |
| 10 SET_QUOTA | `bsdfilesystem_request` (quota bytes; 0 clears) | `bsdfilesystem_reply` | `EINVAL` (below floor), `ENOENT` |
| 11 SNAPSHOT | `bsdfilesystem_version_request` (dataset, lifetime, scope, group) | `bsdfilesystem_version_reply` (assigned version id) | `ENOENT`; at most 256 snapshots per claim |
| 12 LIST_VERSIONS | `bsdfilesystem_version_request` (cursor) | `bsdfilesystem_versions_reply`: up to 32 version ids, `next_cursor` | `ENOENT` |
| 13 ROLLBACK | `bsdfilesystem_version_request` (version) | `bsdfilesystem_reply` | `EBUSY` (claim still mounted or held), `EINVAL` (reserved version shape), `ENOENT` |
| 14 OPEN_VERSION | `bsdfilesystem_version_request` (version) | `bsdfilesystem_reply` + read-only mounted dirfd of a clone | `ENXIO` (no BEGIN_SESSION), `ENOENT` |
| 15 TXN_BEGIN | `bsdfilesystem_version_request` | `bsdfilesystem_version_reply` (txn id in `version`) + writable dirfd of a staging clone | `ENOENT` |
| 16 TXN_COMMIT | `bsdfilesystem_version_request` (txn id in `version`) | `bsdfilesystem_reply` | `EBUSY` (claim mounted elsewhere), `EINVAL`, `ENOENT` |
| 17 TXN_ABORT | `bsdfilesystem_version_request` (txn id) | `bsdfilesystem_reply` | `ENOENT` |
| 18 UNMOUNT | `bsdfilesystem_request` (dataset, lifetime, scope) | `bsdfilesystem_reply` | idempotent |

Lifetimes are `BSDFILESYSTEM_PERSISTENT` (0), `CACHE` (1), `BOOT` (2) and
`LEASE` (3); scopes are `UNIT`, `SHARED` and `GROUP`. ROLLBACK discards
every snapshot newer than the target, as `zfs rollback -r` does. A
transaction snapshots the claim, clones it read-write as a sibling, and on
COMMIT promotes the clone and renames it over the claim, whole subtree, all
or nothing; the caller must UNMOUNT its own claim first or the swap is
`EBUSY`. Version ids of the shape `v<hex>` and names of the shape
`del-<version>` are reserved for the broker's transients and rejected as
caller input.

## Client library

There are three layers. Consumers use the libservice storage API, which is
the only one that applies the container model:

| Group | Functions (`<libservice.h>`, `-lservice`) |
|---|---|
| Claims | `service_storage_open`, `_open_quota`, `_open_cache`, `_open_shared`, `_open_shared_readonly`, `_open_env`, `_open_group` |
| Reclaim | `service_storage_destroy`, `_destroy_cache`, `_destroy_shared`, `_destroy_group` |
| Enumeration and usage | `service_storage_list`, `_list_shared`, `_list_group`, `service_storage_stat`, `service_storage_set_quota` |
| Versions | `service_storage_snapshot`, `_list_versions`, `_rollback`, `_open_version` |
| Transactions | `service_storage_txn_begin`, `_txn_commit`, `_txn_abort`, and `service_storage_release` (+ `_cache`, `_shared`, `_group`) to drop the mount anchor first |
| Isolated opens | `service_open_config`, `service_open_isolated`, `service_resource_dir` |

libbsdfilesystem (`<bsdfilesystem.h>`, `-lbsdfilesystem`, libbsdfilesystem(3))
is the thin owner of a channel for tool authors who want the raw REQUEST
shape: `bsdfilesystem_connect`, `_adopt`, `_close`, `_request`,
`_request_quota`, `_release`, `_destroy`, `_ping`, `_begin_session`, and
`bsdfilesystem_mount_dir` to turn a handle into a dirfd. libtrustedzfs
(`<trustedzfs.h>`) drives a handle once you hold one.

A unit that keeps a database in its persistent container and takes a
snapshot before an upgrade:

```c
#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <libservice.h>

static void
upgrade_store(struct service_context *ctx)
{
        char version[SERVICE_STORAGE_VERSION_MAX];
        int dirfd, fd;

        if (service_storage_open(ctx, "db", &dirfd) != 0)
                err(1, "system.Filesystem: db");
        if (service_storage_snapshot(ctx, "db", version,
            sizeof(version)) != 0)
                err(1, "snapshot");
        fd = openat(dirfd, "schema", O_RDWR | O_CREAT, 0600);
        if (fd < 0)
                err(1, "schema");
        /* ... migrate ... */
        close(fd);
        close(dirfd);
}
```

Link with `-lservice`. The `dirfd` is a mounted anonymous directory: it
works with `openat(2)`, `fstatat(2)` and `mmap(2)` and has no path.

## Command-line tool

tzfsctl(8) is a probe, not an administration tool. It resolves
`system.Filesystem` over the caller's ambient lookup channel, issues one
request and exits, closing (and so unmounting) anything it obtained.

```
# tzfsctl ping
ok
# tzfsctl request -l lease -r mount,props_read -m scratch
granted zroot/Capabilities/ephemeral/... (lifetime=3)
mounted (dirfd 4)
# tzfsctl release scratch
released scratch
```

`-l` is `persistent`, `cache`, `boot` or `lease` (default `lease`); `-r`
is a comma-separated `ZH_*` list without the prefix (`mount,snapshot`, or
`all`); `-m` mounts the handle and prints the descriptor number. There is
no list, stat, version or transaction verb.

## Policy

Authority is the channel label, so most of the policy is structural: a
caller cannot name another label's storage and there is no wire field that
would let it try. Group scope is the exception, and it is enforced twice:
switchboard stamps the bundle's declared `groups` on the connection and the
daemon refuses an undeclared group with `EPERM`.

The configuration file `/Capabilities/Config/bsdfilesystem.ucl`
(tzfs.conf(5)) is the operator surface:

| Key | Meaning | Default |
|---|---|---|
| `pool` | pool backing `/Capabilities`; the installer's `tzfspool` writes it | `zroot` |
| `roots.base`, `.persistent`, `.ephemeral`, `.mountpoint` | dataset roots | `<pool>/Capabilities`, `<base>/Data`, `<base>/ephemeral`, `/Capabilities` |
| `ephemeral.sync` | `sync` property of ephemeral datasets | `disabled` |
| `default_refquota` | per-claim ceiling when a request passes 0 | `1gb` |
| `reclaim_interval` | seconds between reconcile passes (10 to 86400) | 300 |
| `staging_idle_grace` | age before an abandoned transaction clone is reaped (1 to 86400) | 300 |
| `open_paths` | isolated-open grants | empty (deny all) |

`open_paths` is the default-deny policy behind OPEN and
`service_open_isolated(3)`. Each entry names an exact `label`, one absolute
`path`, a `rights` array from `read`, `write`, `exec`, `lookup`, `ioctl`,
and an optional `prefix` that matches one trailing device-unit component
(`/dev/vhid` covers `/dev/vhid3`, never a subdirectory). The shipped policy
in `usr.sbin/BSDFilesystem/bsdfilesystem.ucl` grants BSDAuth read access to
`/etc/passwd`, `/etc/group`, `/etc/master.passwd` and the principal policy;
BSDNetwork `/etc/resolv.conf`, `/etc/hosts` and `/etc/services`; and
BSDBluetooth the `/dev/vhid` family. There is no admin bypass: an admin
session's `SERVICE_RIGHTS_ADMIN` bit does not widen storage or open_paths.
Compiled bounds cap the damage a client can do: 32 claims per connection,
64 per namespace, 256 snapshots per claim, 32 `open_paths` entries, 4096
workers, and a destroy depth of 64.

## Tests

| Suite | Location | Installed under | What it proves |
|---|---|---|---|
| `namespace_test` (60 cases), `provider_test` (11) | `usr.sbin/BSDFilesystem/tests` | `/usr/tests/usr.sbin/BSDFilesystem` | label-to-dataset derivation, name validation, reserved version shapes, group scoping, the request handlers against a fake service |
| `bsdfilesystem_test` (18) | `lib/libbsdfilesystem/tests` | `/usr/tests/lib/libbsdfilesystem` | the client's wire encoding and fd handling |
| `trustedzfs_capsicum_test` (27) | `lib/libtrustedzfs/tests` | `/usr/tests/lib/libtrustedzfs` | `tzfs_*` verbs and ioctl-limit profiles under `cap_enter(2)` |
| ten `zfshandle_*_test` programs | `tests/sys/zfshandle` | `/usr/tests/sys/zfshandle` | kernel rights, derive, pinning, anonymous mounts, pool handles, negative and hardening cases |
| `tzfsctl_test.sh` | `usr.sbin/tzfsctl/tests` | `/usr/tests/usr.sbin/tzfsctl` | the tool against `fake_bsdfilesystem` |

The kernel and provider suites need a live pool and a real plane; run them
in the VM runner described in [Testing](../develop/testing.md), for example
`kyua test -k /usr/tests/usr.sbin/BSDFilesystem/Kyuafile`. Two programs
under `tests/sys/tzfs` are present but disabled pending a fake service
harness. Packages: `5BSD-tzfs-tests`, `5BSD-libtrustedzfs-tests`.

## Status and gaps

Shipped: the handle model, anonymous and shared anonymous mounts, the
broker with all eighteen ops, the container model and reconcile, quotas,
versions and transactions, and the installer path that writes the pool into
`bsdfilesystem.ucl`. The inventory's scorecard records BSDFilesystem as the
least-tested TCB component by test-to-code ratio. tzfsctl(8) exposes only
`ping`, `request` and `release`, and its manual page still says the tool
"connects the daemon socket", which stopped being true with the socket-free
rewrite. The ZFS MAC hooks (`mpo_zfs_check_*`) are enforcement points with
no production policy behind them. Two DoS-hardening findings from the
storage review (uncapped staging clones and snapshot counts outside the
per-claim bound) remain open. The retired "flavors" and installation-ledger
features must not be read back into this design.
