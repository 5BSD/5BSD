# Linux64 quota control on ZFS

Status: implemented on amd64 Linux64; named Linux-reference cases, focused BSD
VM checks and the full amd64 ZFS-root regression gate pass. No host installation has
been performed. Other ABI tables retain their existing behavior.

## Supported contract

`quotactl_fd` (443) accepts an open file or directory descriptor, including
`O_PATH`, and selects that descriptor's filesystem. On ZFS datasets with user
and object accounting available and no default quota for the requested type:

| Command | Supported behavior |
|---|---|
| `Q_GETQUOTA`, user/group | Byte hard limit, byte usage, object hard limit and object usage; soft limits and grace times are zero. |
| `Q_SETQUOTA`, user/group | `dqb_valid == QIF_BLIMITS` with a zero soft limit changes the byte hard limit. Zero removes that explicit limit. An empty valid mask leaves state unchanged. |
| `Q_SYNC`, user/group | Waits for the pool transaction group to commit quota accounting. |

Linux limit fields use 1024-byte units; usage is reported in bytes. Native
512-byte limits round upward when presented in the Linux limit field.
The 72-byte Linux64 result, including padding, is initialized before copyout.
User and group limits are separate; ZFS supplies their actual enforcement.
ZFS usage accounting is transaction-group based, so this does not promise
ext4-style immediate accounting or a byte-exact write cutoff. The tests force
quota sync between writes and require eventual `EDQUOT` for both quota types.
Object usage is ZFS's charged object count.

Unprivileged callers may query their effective UID or a group they belong to.
Other queries and limit changes require native quota privileges. Native jail
quota policy also applies. Both syscalls remain forbidden in capability mode.
Queries and updates through `quotactl_fd` reject read-only mounts with EROFS;
quota sync remains allowed, including pools imported read-only. Bad descriptors precede type validation. Invalid
UID/GID UINT32_MAX is rejected instead of becoming the native “current ID”.

Soft limits, grace-period updates, object-limit updates, usage mutation,
quota enable/disable, quota enumeration, project quotas and other commands
remain unsupported. Requests containing unsupported update fields fail
before changing a limit. An overflowing byte-limit conversion returns
EOVERFLOW. Unsupported filesystems and unsupported ZFS accounting/default-
quota configurations return ENOSYS; unsupported update fields return
EOPNOTSUPP. This is a defined subset, not complete quota-tool compatibility.

The older `quotactl` (179) supports `Q_SYNC` with a null device selector.
User/group requests synchronize supported filesystems; a project request
has no supported filesystem to synchronize. Non-null selectors retain Linux's
block-device meaning: ordinary paths return ENOTBLK, and native disk-device
selectors return EOPNOTSUPP. A ZFS dataset cannot be selected uniquely by a
pool member device. This implementation does not reinterpret the selector as
a mountpoint; applications needing dataset quota operations must use the fd
variant. Legacy per-device quota queries and updates remain pending.

## Ownership and native changes

Linux structures, numbers, flags, unit conversion and errno translation live
in `sys/amd64/linux/linux_quota.c`. The amd64 fd handler has a distinct internal
name (`linux_quotactl_fd64`) so the shared ENOSYS stub remains available to
unchanged ABI tables. No Linux32 functionality is added.

The native VFS gains a small kernel-buffer quota interface in one reserved
`vfsops` slot, preserving the structure's size and existing member offsets.
It checks quota privileges/jail policy, brackets updates with filesystem write
suspension protection, and dispatches through the filesystem's signal-deferral
wrapper where required. Callers hold a busy mount. Unknown backends return
EOPNOTSUPP; no user pointer is passed as a kernel quota buffer.

The FreeBSD ZFS backend reads existing `zfs_userspace_one()` accounting and
sets a single byte limit through `zfs_set_userquota()`. Its sync operation waits
for a transaction-group commit: ordinary per-filesystem ZFS sync only commits
the intent log and was insufficient for this accounting contract. Sync skips the transaction-group wait for read-only pools and allows signal
interruption or suspended-pool failure to unwind cleanly. The native quota wire format is unchanged. The existing native ZFS quota
entry now uses the same privilege check, closing the native bypass of the
new interface’s query/set policy. No quota database
or enforcement mechanism is duplicated in Linuxulator.

## Reference and validation

Pinned source references are Linux v6.18
[`fs/quota/quota.c`](https://github.com/torvalds/linux/blob/v6.18/fs/quota/quota.c)
and [`include/uapi/linux/quota.h`](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/quota.h).
The runtime oracle is Alpine Linux 6.18.35-0-virt on amd64 with an ext4 volume
created with embedded user/group quotas. The comparison covers the generic
Linux ABI subset, not a claim that Linux OpenZFS implements this syscall API.

`tests/sys/kern/linux_quota.c` names ten shared reference cases:

- `hard_limit_roundtrip`, `invalid_arguments`, `device_path_validation`;
- `quota_sync`, `permissions`, `ignored_fields`;
- `descriptor_lifetime`, `fork_exec_lifetime`;
- `enforcement_and_usage`, `group_enforcement_and_usage`.

The BSD build adds `unsupported_updates_are_atomic`. Three rounds give 33
executions on a dedicated ZFS dataset. Native probes verify updates in both
directions, including 512-to-1024-byte rounding, plus unprivileged own queries
and rejection of foreign queries and limit changes. Additional checks cover
remount persistence, read-only mounts and pools, default-quota rejection and
tmpfs rejection. Native tracers verify capability-mode rejection for both syscalls
in three rounds. The resulting focused matrix contains 47 checks, with
healthy ZFS, no recognized kernel diagnostics and clean shutdown.

Artifacts live under `/tmp/linuxulator-quota-20260921/`; `focus9.console.log`
is the passing focused BSD run. The final Linux oracle is
`oracle5.console.log`. `manifest.json` records source/build/artifact provenance.
The initial enforcement test failed because it assumed intent-log sync also
committed accounting. The corrected backend and explicit cleanup sync passed
both user and group enforcement. Earlier setup/build logs are retained and
are not acceptance evidence.

The full gate stages `guest-quota.sh`, the Linux binary, the native quota
probe, the native capability tracer and two Linux capability probes. The
runner checks exact case sets and multiplicities. The existing unshare and
io_uring workstreams remain part of that regression gate. No complete
external quota-management application is qualified by these ABI probes;
quota enumeration and legacy device-path tooling remain follow-up work.

## Full-gate result

The full amd64 ZFS-root gate passed with 47 quota checks, 1092 native/Linux shared-ring option executions and 432 main io_uring cases, plus the existing syscall and lifecycle matrices. The runner reported no recognized kernel diagnostics or leaked tracked ring resources, healthy ZFS and clean shutdown.

Evidence: `/tmp/linuxulator-quota-20260921/full4-run/results.json` and the
adjacent console log. `full4-run/manifest.json` records the exact source and artifact
hashes. The frozen runner uses all 432 cases compiled into the io_uring
binary; earlier setup/inventory failures and superseded builds are retained
separately and are not acceptance evidence. Later concurrent worktree edits
are not qualified by this recorded build.
