# Linux64 compatibility: IPC, notifications, discovery and FUSE

User-authorized scope (2026-09-23): implement and qualify all four batches.
Runtime tests run only in disposable amd64 VMs. No Linux32 or targeted io_uring
work. Existing changes from other owners must be preserved.

| Batch | Delivered and qualified | Remaining scope |
| --- | --- | --- |
| Abstract Unix sockets | Binary names, full Linux address length, stream/datagram/seqpacket, autobind, credentials/FD passing, lifetime and jail/VNET/Capsicum boundaries | Linux64 only |
| Notifications/descriptors | Queue/watch locking, disappearing-entry races, nonzero rename cookies, truncated socket-address queries | Post-unlink watch semantics and independent proc-fd pipe reopening |
| Device/netlink discovery | Per-interface route-netlink names, loopback type, carrier flags, allocation checks and sysfs `uevent` | Socket diagnostics and live device-event transport |
| FUSE | High-level libfuse hard links, lookup references, xattr listing; writable and daemon-failure tests | Full opcode/hostile-daemon qualification and remote lock-owner protocols |

Artifacts: `/tmp/linuxulator-compat-next-20260923`. Do not treat a batch as
complete before its named Linux-reference and BSD VM tests pass. Broader
kernel/module regressions must use matching final binaries.

## Implemented changes

* Abstract AF_UNIX names for amd64 Linux64 sockets: binary names through 108
  bytes, length-sensitive lookup, stream/datagram/seqpacket support, explicit
  and SO_PASSCRED automatic binding, close/rebind behavior and proc display.
  Names are isolated by VNET and prison. Capsicum cannot acquire a global name.
  The native sockaddr ABI stays unchanged; the internal unpcb layout changes,
  so kernel and dependent modules must be built together.
* Notification queue counters and watch masks are now read/updated under their
  protecting locks. Directory scans tolerate entries disappearing during watch
  registration. Rename cookies skip zero, including counter wraparound.
* Route-netlink dumps translate each interface's own name, hardware type and
  carrier flag. Header-copy allocation failures are checked before use.
  `/sys/class/net/IFACE/uevent` reports the visible interface name and index.
* FUSE accepts distinct protocol node IDs in high-level libfuse hard-link
  replies, without aliasing the original vnode, and releases the new lookup
  reference. Linux xattr listing keeps permitted user names when the system
  namespace is denied, handles size queries and short buffers, and validates
  length-prefixed native records before conversion.

The FUSE behavior is exercised using an unmodified libfuse library and the
private-directory daemon in `tests/sys/kern/linux_fuse_passthrough.c`. This is
an integration fixture, not a production passthrough filesystem. Linux's
[hard-link implementation](https://raw.githubusercontent.com/torvalds/linux/master/fs/fuse/dir.c)
and [libfuse's high-level link callback](https://raw.githubusercontent.com/libfuse/libfuse/master/lib/fuse.c)
allow a new protocol node for the new name.

## Reproduction

`tools/test/linuxulator/build-compat-next.sh MUSL_SYSROOT OUTPUT` cross-builds
Linux probes and builds the native fixtures without executing them. The
qualification sysroot contains musl 1.2.6 and libfuse 3.18.3. Stage Linux programs
with the Linux ELF brand in the BSD guest; use unbranded copies on Linux.

`guest-compat-next.sh` expects the resulting fixtures under `/root`, plus the
native `tests/sys/fs/fusefs/link` test as `/root/fuse-link-native`. It tests
root/unprivileged notification, discovery, abstract credential/descriptor
passing, concurrent binds, jail/VNET/Capsicum isolation, writable FUSE,
xattrs, shared mmap, locks, large readdir, and daemon death/recovery.

For the complete gate, run that phase and then the existing proc/filesystem
stress guest after unloading its mounts/modules. The artifact directory keeps
`stage-final.py` and `guest-final.sh` with the exact image construction.
`qemu-compat-next.py` wraps the proc/filesystem validator and requires the
additional 62 cases (30 abstract variants, 26 integration cases and six native
FUSE tests). All execution must take place in disposable guests.

## Explicit remaining gaps

This batch does not implement namespaces/containers, NETLINK_SOCK_DIAG,
NETLINK_KOBJECT_UEVENT hotplug sockets or a full Linux device model. The network
`uevent` file is readable discovery data, not a live event transport.

`IN_EXCL_UNLINK` and complete post-unlink directory notification lifetime still
need an open-file/name association beyond the current name-cache model.
Reopening anonymous pipes through proc-fd with independent file-description
flags also remains separate work; returning a dup would not match Linux.
The FUSE gate does not qualify every opcode, remote lock-owner protocol or
hostile daemon reply. No Electron application qualification is claimed.

## Final qualification (2026-09-23)

All final gates passed against the recorded kernel/module set:

* 858 checks in a single-CPU BSD guest and 858 in a four-vCPU guest: the existing
  803-case proc/filesystem/security/lifetime gate plus 55 new cases per guest.
* 1,184 broad Linux64/native regression checks.
* Eight real Linux Python/GDB client checks.
* 27 Linux-reference cases (ten abstract socket variants and 17 notification,
  discovery, credential-passing and writable FUSE cases).

That is 2,908 BSD VM cases plus 27 Linux-reference cases. The new FUSE cases
cover ordinary, default-permissions and requested-writeback mounts, with root
and unprivileged clients, followed by daemon death and clean unmount/remount.
All BSD final gates shut down cleanly with healthy ZFS pools and no panic,
lock-order or non-sleepable-lock diagnostics. No runtime probe ran on the host.
No Linux32 expansion or targeted io_uring work was included.

`manifest.json`, `source-hashes.json`, `binary-hashes.json`, `task.patch`, the
`source/` snapshot and final console logs live in the artifact directory.
Intermediate image files were removed; final images and diagnostic logs remain.
The source tree is uncommitted.

## Hardening follow-up (2026-09-23)

Artifacts: `/tmp/linuxulator-compat-mature-20260923`. This follow-up retains
all four batches and adds the following boundary checks and regressions:

* Linux xattr names may occupy the full 255-byte limit. Listing accepts the
  resulting 256-byte name-plus-terminator and returns EFAULT for invalid output
  pointers with a nonzero buffer size. Empty lists and size-only queries retain
  their normal behavior. Tests check exact sizing, short buffers and a canary
  beyond the returned data, both on ZFS and through Linux libfuse.
* FUSE releases the lookup reference from a LINK reply even when its attributes
  fail validation, provided its node ID is neither zero nor the root ID. A mock
  daemon returns an invalid file type and checks the asynchronous FORGET with a
  bounded wait. This extends hostile-reply coverage for LINK only.
* Outbound netlink translation rejects short, zero-length, oversized and
  misaligned message framing before dispatching the body translator. Normal
  discovery remains covered by Linux and BSD integration probes; malformed
  internal-buffer handling is defensive validation, not a fuzz qualification.
* Abstract socket tests keep 192 maximum-length binary names live together,
  route a datagram to each, and verify that an accepted stream survives listener
  close and name reuse while retaining its original local address.
* The FUSE gate waits for a backing-file marker through the mounted filesystem
  and fails if the daemon dies or the mount never becomes ready. Requested
  writeback must be advertised and explicitly negotiated, preventing a silent
  fallback from being counted as writeback coverage.

The limitations listed above remain. These changes do not establish complete
Linux compatibility or Electron readiness.

Follow-up qualification passed: **863 checks on one CPU, 863 on four vCPUs,
1,184 broad regression checks, and eight real Linux Python/GDB checks** —
2,918 BSD VM cases. The expanded 21-case Linux-reference integration run also
passed. The ten basic abstract-socket Linux-reference cases from the initial
qualification use a byte-identical probe and were not rerun.

The previous published modules fail the new maximum-length xattr and invalid
FUSE-reply tests; the final modules pass both. All final BSD guests shut down
cleanly with healthy ZFS pools and no panic or lock diagnostics. Final images,
console logs, source/binary hashes and a patch relative to the pre-hardening
snapshot are retained in the follow-up artifact directory. No host runtime
probe, Linux32 expansion or targeted io_uring work was performed.

## Expanded protocol and workload hardening (2026-09-23)

Artifacts: `/tmp/linuxulator-compat-full-20260923`. This run expands qualification
of the implemented features; it does not implement every remaining Linux
interface in the gap list above.

The full active native FUSE protocol inventory exposed a WITNESS lock-order
reversal in `AsyncReadNoAttrCache.read_sizechange`. Server-side file growth
invalidated buffers while holding the attribute-cache mutex. The implementation
now drops that mutex around buffer invalidation and reacquires it before further
attribute changes, retaining the vnode lock throughout. The rejected baseline
console log records the reversal.

FUSE xattr size-query replies now require their fixed protocol structure before
any caller reads it. List sizes above 64 KiB return E2BIG before integer
conversion or allocation. The converter bounds namespace comparisons, rejects
empty entries/names, and accepts the native maximum-length name. Six new mock
cases exercise truncated replies for GETXATTR/LISTXATTR, UINT32_MAX list sizes,
empty entries, empty user names and short foreign names. Linux also validates
nonempty, terminated lists and bounds the list representation; see the
[Linux FUSE xattr implementation](https://raw.githubusercontent.com/torvalds/linux/master/fs/fuse/xattr.c).
The native conversion rejects oversized advertised lists rather than allocating
an unbounded amount of memory.

Inotify now removes a watch on last-link deletion even when IN_DELETE_SELF was
not requested, delivering IN_IGNORED without the unrequested event. The new
root/unprivileged regression agrees with Linux. This does not fix the separate
open-but-unlinked file/directory notification lifetime limitation.

Abstract socket lookup uses SipHash with a boot-generated key over the binary
name, socket type, VNET and prison, with 4,096 buckets. This replaces the
predictable 256-bucket hash and reduces exposure to deliberately colliding names.
SipHash is now a standard kernel build dependency because AF_UNIX does not
require INET or INET6. No public socket ABI changes were needed.

The pre-init FUSE fixture now starts its daemon after installing expectations,
removing a race where INIT could be processed before its test was ready.
`build-fuse-protocol.sh` builds the native fixtures; `guest-fuse-protocol.sh`
runs all 47 gtest executables with the required privilege level, and
`qemu-fuse-protocol.py` rejects missing cases, failures, skips, timeouts and
kernel lock/panic diagnostics. Run these fixtures only in disposable guests.
The separate CTL integration shell test is outside this protocol inventory.

Twelve upstream-disabled variants remain excluded: remote flock (two), whiteout
(one), FUSE_NOTIFY_STORE (four), original OPEN flags (three), RELEASE flags (one)
and AIO writer PID (one). They are not counted as passes. Ordinary remote POSIX
locking, cancellation and teardown are exercised by the active lock tests.

`compat-workloads.py` exercises concurrent SQLite WAL transactions, rollback,
integrity checking and checkpointing, plus at least 1,000 socket/epoll/SCM_RIGHTS/
inotify creation and teardown cycles over at least 120 seconds. Process FD
counts are checked periodically; the guest also compares kernel socket and
inotify-watch counts before and after the workload. This finite soak is not a
substitute for an application's days-long operational qualification.

Release boundaries remain explicit: independent anonymous-pipe proc-fd opens,
post-unlink notification semantics, live device events/socket diagnostics,
upstream-disabled FUSE behaviors, and sandboxed Linux Electron are not delivered
by this hardening run. Full Electron readiness also requires sandbox, GUI and
application recovery testing; no such claim follows from these component tests.

Final expanded qualification passed against the recorded binaries:

* 865 compatibility/proc/filesystem/stress checks on one CPU and 865 on four.
* 758 active native FUSE protocol cases on each topology (1,516 total).
* 1,184 broad Linux64/native regression checks.
* Eight existing Linux Python/GDB checks, SQLite WAL and IPC/watch workloads,
  and one kernel resource-accounting check.
* 23 Linux-reference integration cases.

This is **4,441 BSD VM checks plus 23 Linux-reference cases**. The final workload
completed 18672 IPC/watch cycles in 120.0 seconds. Kernel Unix socket counts
were 0 before/0 after, and inotify watches were 0 before/0 after;
process FD counts also returned to baseline. Final guests shut down cleanly
with healthy ZFS pools and no panic or lock-order diagnostics. Protocol tests
intentionally elicit warnings for malformed daemon replies; these are distinct
from kernel locking failures. Final images, logs, source snapshots, isolated
patches and hashes are retained. Changes are uncommitted.
