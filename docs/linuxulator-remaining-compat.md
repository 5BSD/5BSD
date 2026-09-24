# Linux64 compatibility completion work

Requested 2026-09-24: implement and VM-test the four remaining groups from the
compatibility review. amd64 Linux64 only; no targeted io_uring work or host
kernel/probe execution. Preserve unrelated working-tree changes.

| Group | Required contracts | Status |
| --- | --- | --- |
| Notifications | Open-but-unlinked file events, watched-directory lifetime, IN_EXCL_UNLINK, rename/hard-link identity, final-close cleanup | Linux64 mapping, direct-watch and retained parent-path contracts qualified in batches 3, 11 and 13 |
| Proc descriptors | Independent pipe opens, access-mode/flag/lifetime semantics, missing fdinfo, deleted-path stability | Independent anonymous-pipe opens and retained/deleted path contracts qualified in batches 12 and 13 |
| FUSE | Remote flock owners and final-close unlock, notify-store cache coherence, OPEN/RELEASE flags, AIO process identity | Per-open descriptions, flags, locks, AIO, mappings, STORE and direct stream behavior qualified |
| Discovery | KOBJECT_UEVENT transport and actual events, SOCK_DIAG request/dump ABI, permissions and VNET/prison isolation | INET/UNIX diagnostics qualified; network kobject-event candidate passes focused tests, final regressions running |

Each group requires Linux-reference behavior, negative/security tests, native
regressions for shared mechanisms, resource cleanup, and matching single-CPU/SMP
VM images. Existing qualification is in linuxulator-compat-next.md. New evidence
belongs under /tmp/linuxulator-remaining-20260924. No group is complete merely
because a syscall or socket protocol accepts a request.

Seccomp was requested as an explanation, not part of these four implementations.
It uses classic BPF over syscall metadata; a validated interpreter is sufficient.
It does not require the general eBPF subsystem. Enforcement, thread-group filter
synchronization, fork/exec inheritance, action precedence, signals and ptrace are
separate essential integration work.
Source: https://docs.kernel.org/userspace-api/seccomp_filter.html

## First implementation batch

The first batch changes FUSE and the native AIO worker's protocol identity:

- Negotiate remote flock independently of POSIX record locks, starting with
  protocol 7.17. Use a keyed opaque owner derived from the open file description,
  so dup/fork retain the owner and independent opens have different owners.
  The existing final-close path retains the vnode until ADVLOCK unlock has run;
  it does not require a new fileops close wrapper. This corrects the initial
  ownership audit's concern about premature handle release.
- Drop the vnode lock before waiting for the daemon's lock reply. A blocked
  SETLKW must permit another owner's close/unlock to proceed.
- Consume GETLK replies before dropping their ticket. Reject invalid lock types,
  reversed or unrepresentable ranges, and unrepresentable PIDs. Normalize
  backwards request ranges and release the vnode lock on invalid whence.
- Translate Linux-daemon lock types in both directions. Native FreeBSD daemon
  lock types remain native. The existing linux_errnos mount option identifies
  the daemon ABI.
- Preserve positive asynchronous notification opcodes on Linux-daemon mounts;
  only negative ordinary replies undergo errno translation.
- Give an AIO worker a current submitter PID in existing thread OSD storage.
  FUSE uses it for protocol metadata. This neither changes authorization nor
  replaces the worker's process, and adds no field to struct thread.

Regression additions cover malformed GETLK replies, backwards ranges, remote
flock contention, distinct/shared owners, final close with a blocked waiter,
Linux wire lock types, asynchronous notification decoding, and AIO write PID.
The suite now contains 774 active cases in 47 executables. Disabled tests remain
excluded from the pass count. Final qualification results are recorded in
/tmp/linuxulator-remaining-20260924/final-{up,smp}/results.json.

This is **not completion of all four groups**. In particular, the existing FUSE
handle cache still shares handles among opens with matching access/credentials.
Remote lock RPCs now carry per-open owners and explicitly unlock on final close;
this does not establish per-open OPEN/RELEASE handle and flag fidelity for every
Linux daemon. That separate handle-lifetime work remains required.

## Original audit boundaries (addressed by later batches)

1. **Notifications:** vfs_cache.c currently reconstructs parent notifications
   from cached names. Unlink removes that identity, and multiple hard links may
   generate notifications for paths other than the path used by the open file.
   Direct watches now survive unlink while a live vnode reference remains.
   Retain the relevant open path identity across rename/unlink and test
   IN_EXCL_UNLINK against Linux. Complete mapping/file-description lifetime,
   beyond the Linux64 vnode mapping support in the third batch below.
   A vnode reference count alone is not sufficient for open-description
   lifetime. The second batch records the original failure and its limits.
2. **Proc descriptors:** linprocfs_fdlookup_impl follows real vnodes and returns
   ENXIO for anonymous pipes. kern_pipe supplies bidirectional endpoints that the
   Linux adapter restricts to one direction. A dup-like fallback cannot implement
   independent flags, reverse-direction opens, O_RDWR, and peer lifetime. Add an
   actual shared unidirectional pipe channel with a vnode/open bridge, or a
   coherent anonymous FIFO vnode implementation, with native pipe regressions.
3. **Remaining FUSE:** NOTIFY_STORE is implemented in the fourth batch below.
   Preserve original OPEN/RELEASE flags
   using per-open handle identity. Simply forwarding O_APPEND through the
   current shared handle cache can change another open's writes. STORE must not
   turn uninitialized bytes into valid cache data or unexpectedly write injected
   server data back to the daemon.
4. **Discovery:** native generic-netlink devctl events are not Linux kobject
   uevents. Add the raw NUL-separated kernel-origin transport and real event
   producers with truthful sysfs paths. Basic TCP/UDP SOCK_DIAG now provides request parsing and
   socket snapshots with credentials, stable identity, and prison/VNET scoping
   (fifth batch below). Extended diagnostic families and attributes remain.
   Registering protocols that return empty successful dumps would not provide
   the requested compatibility.

No io_uring implementation or test changes are part of this batch. No host
kernel module loads or runtime probes are part of its qualification.

## Second implementation and review batch

Evidence: `/tmp/linuxulator-lifetime-20260924`. This is partial qualification,
not a production-readiness declaration for all four groups.

Direct inotify watches now exchange their vnode use reference for a storage
hold after final unlink. This lets open descriptors continue generating events
without the watch itself preventing final inactivation. Final inactivation
queues DELETE_SELF and IGNORED. Rename-overwrite holds a temporary use reference
while converting watches. Adding a watch through `/proc/self/fd` to an already
unlinked vnode uses the same ownership rules. Watch removal, instance close and
deferred destruction release the corresponding reference or hold.

Linux instances omit IN_ISDIR on terminal DELETE_SELF; native instances retain
the native convention. Internal directory scans used to install watches no
longer generate spurious access events for existing watchers. The inactive hook
checks for a real pollinfo object: nullfs can mirror the lower vnode's inotify
flag without owning a watch list. The first native regression run exposed a
panic here; the correction passed both final native runs. Failed logs remain
in `lifetime-smp` and are not qualification evidence.

The FUSE review also found that correcting the AIO request header alone did not
correct cached handle selection. A common `fuse_thread_pid` helper now supplies
both identities, including related getattr/setattr and handle creation paths.
It leaves credentials and worker process identity intact. Cache writeback's
explicit PID-zero handle selection remains unchanged. The new
`AioWrite.submitter_handle` test keeps distinct parent/child handles open, then
checks that the parent's AIO uses the parent's handle even though the child's
handle is newer. It fails against the prior module (`aio-baseline`) and passes
with the correction.

Qualification on the INVARIANTS/WITNESS kernel:

| Configuration | Result |
| --- | --- |
| Linux 6.18.35 reference, root and unprivileged | 22 lifetime probes passed |
| FreeBSD ZFS, one CPU | 220 Linux/native lifetime probes + 18 native inotify cases passed |
| FreeBSD ZFS, four CPUs | 220 Linux/native lifetime probes + 18 native inotify cases passed |
| FUSE protocol suite, one CPU | 775 active cases passed |
| FUSE protocol suite, four CPUs | 775 active cases passed |
| FreeBSD tmpfs, four CPUs | Private-mapping lifetime fails; not qualified |

The successful inotify runs return watch counts from zero to zero and include
nullfs remove/rename, unmount, overflow, Capsicum, fork/exit, duplicate versus
independent opens, hard links, rename replacement and explicit watch removal.
The FUSE suite runs all 47 executables; disabled tests are excluded. Test runners
check complete case inventories, exit status, clean poweroff and kernel
panic/WITNESS diagnostics. All runtime work took place inside disposable VMs.

### Remaining notification failures

- A private tmpfs mapping does not keep the vnode active after the file closes.
  DELETE_SELF arrives before munmap. The complete tmpfs run retains this as a
  failing case; it is not skipped or counted as a pass. Tmpfs swap-backed object
  references differ from vnode-pager references. Its writable-mapping vnode
  reference does not cover private mappings. Fixing this needs file/mapping
  lifetime tracking, including fork, splits, partial unmap and shadow collapse.
- Even on ZFS, mapping tests currently assert deletion timing only. Linux holds
  the open file description through the mapping and delays CLOSE_WRITE until
  final unmap; the current implementation reports close at descriptor close.
- Parent-directory events after unlink and rename, IN_EXCL_UNLINK, and choosing
  the actual open path among multiple hard links remain unresolved. Passing a
  direct-watch hard-link test does not establish parent-path correctness.

Build the lifetime fixtures using
`sh tools/test/linuxulator/build-inotify-lifetime.sh MUSL_SYSROOT OUT`.
Stage its two probes, native ATF executable and generated `inotify-cases` list,
plus `guest-inotify-lifetime.sh`, into a disposable guest. Set INOTIFY_TMPFS=1
in that guest script's environment for the failing tmpfs qualification. Run
`qemu-inotify-lifetime.py --image IMAGE --output OUT --cpus 1` and `--cpus 4`.
The runner currently uses this workspace's pinned QEMU executor/firmware paths.
Do not execute these probes or load the modified modules on the host.

## Third batch: mapping lifetime review loop

Evidence: `/tmp/linuxulator-mapping-20260924`. This closes the Linux64 vnode
mapping failures found in the second batch; it does not complete the unrelated
parent-path, pipe, FUSE STORE/per-open handle, or discovery groups.

Linux64 vnode-backed mmap now retains the open file description until the last
mapping reference disappears. VM entries carry an optional shared owner, with
one checked file reference per original mapping. Splitting or inheriting an
entry retains that owner. Merging entries compares the underlying open file
description, not the owner allocation. Entries from independent opens remain
distinct. Ordinary native mappings and Linux32 do not opt into this behavior.

The file reference is installed under the map lock with the new entry, so
another thread cannot unmap or replace the range between installation and
ownership attachment. Final close runs through the existing deferred entry
cleanup after map locks are released. Fork, exec, partial unmap, fixed-address
replacement and remap_file_pages retain or release the owner consistently.
The anonymous-only mremap growth path now rejects entries retaining a file,
even after COW has produced an anonymous shadow object. File-backed mremap
growth/movement remains unsupported; this batch does not claim to add it.

This adds one pointer to vm_map_entry and a small owner allocation per Linux64
vnode mmap. The test kernel and every staged module were rebuilt together
because the embedded VM map layout changes. Kernel/module ABI compatibility
with earlier builds must not be assumed.

The review loop found and corrected three test/integration issues and an actual
mapping bug:

- The first guest script omitted the native case-list input redirection. Its
  interrupted run is retained as failed, not qualified.
- The broad regression image carried an old RWF binary whose expectations
  predated the current NOSIGNAL implementation. The fixture was rebuilt from
  the current source; no RWF implementation was changed by this batch.
- The fallocate binary was also stale and did not implement the harness's
  ZFS unsupported-reservation check. It was rebuilt from the existing source;
  the ZFS negative check and tmpfs positive checks remain required.
- Comparing owner allocations prevented compatible mappings of the same open
  file from merging and caused remap_file_pages to reject an adjacent range.
  Both review and the existing broad regression exposed this. Comparing file
  descriptions fixes the issue; the new remap-merge reference probe passes on
  Linux, and the qualified runs require it.

The final focused inventory has 18 mapping modes: private/shared mappings,
read-only opens, splits, merges, shrink, fork/unmap, fork/exit, fork/exec,
wired fork, anonymous MAP_FIXED replacement, failed fixed replacement,
MAP_FIXED_NOREPLACE, two mappings of one open, two independent opens,
remap_file_pages, adjacent remap, and MADV_DONTNEED. It runs as root and an
unprivileged user on ZFS and tmpfs for five rounds, together with the 11
existing Linux direct-watch modes. The 18 native inotify regressions run after
those probes. Close timing is asserted, rather than filtered out as it was in
the second batch's mapping probes. Linux reference results contain 36 cases.

Qualification results are in `qualified-{up,smp}/results.json`, with broader
results recorded separately in the batch manifest. A full pass requires 580
Linux probes plus 18 native cases, watch counts returning to zero, clean
poweroff, and no panic or WITNESS diagnostic. Native tmpfs private-map close
semantics are intentionally not changed to Linux semantics.

Build with `build-mapping-lifetime.sh MUSL_SYSROOT OUT`; the guest also needs
fixtures from `build-inotify-lifetime.sh`. Stage `guest-mapping-lifetime.sh`
and run `qemu-mapping-lifetime.py --image IMAGE --output OUT --cpus 1` and
`--cpus 4`. The scripts execute only inside disposable guests.

Still required for the original four-group request: parent inotify path
identity and IN_EXCL_UNLINK; independent proc pipe reopening; FUSE per-open
OPEN/RELEASE identity; actual kobject event delivery and scoped
SOCK_DIAG dumps. These are implementation gaps, not checks that can be closed
by repeating the passing mapping suite.

Final mapping qualification: both 1-vCPU and 4-vCPU runs passed 598 focused
cases, 775 FUSE cases, and 865 broader compatibility checks each. The broad
regression completed 1,094 non-ABI checks; its overall validator remains failed
because the staged ABI binary had an old inventory. A rebuilt current ABI
fixture separately passed all 96 checks on ZFS/tmpfs. The manifest preserves
this distinction instead of relabeling the original run. Linux reference:
36 mapping cases passed. Source, binary and image hashes are archived alongside
`manifest.json` in the evidence directory.

## Fourth batch: FUSE STORE review loop

Evidence: `/tmp/linuxulator-store-20260924`. FUSE_NOTIFY_STORE now populates
cached regular-file pages and extends cached/pager size when necessary. It
validates the payload length and signed offset range, finds open inodes even
when their pathname cache has expired, and returns ENOENT for unknown nodes.
NOTIFY_RETRIEVE remains unsupported.

STORE copies one page of daemon input into a temporary buffer before acquiring
the vnode/page locks: the source address can itself fault in a filesystem.
It preserves dirty state and does not issue READ or WRITE requests. Invalid
pages become completely valid only when the supplied prefix covers the whole
page or all bytes through EOF; the latter case zeros the unused tail. Partial
interior data does not make uninitialized bytes readable. Each page rechecks
vnode/object state and size, so a concurrent truncate limits subsequent copies.

The review added native tests for blank/clean/dirty caches, complete pages,
partial invalid pages, EOF extension and zero-fill, mmap coherence, expired
pathname entries, malformed payloads, offset overflow and unknown nodes.
Both asynchronous-read negotiation settings are tested. The full native suite
has 797 active cases across 47 executables, including 42 notification cases.
Disabled cases are excluded. No broader shared VM changes are needed for STORE;
the VM images use the already-qualified mapping kernel and a rebuilt fusefs.

The first dirty-growth test incorrectly assumed that writing six bytes made
the whole cache block valid. A later read legitimately flushed those original
six dirty bytes before fetching the missing data. Separate regressions now
cover fully valid dirty pages (no READ/WRITE during STORE or subsequent reads)
and partially valid dirty blocks (a later read may flush only the old dirt,
then fetch the complete server data). Both retain data-integrity assertions.
The failed original runs remain in `full-{up,smp}`.

`linux_fuse_store.c` is a real Linux64 libfuse daemon/client integration probe.
It uses an expired pathname entry, extends an empty file with multiple pages,
checks normal reads and mmap, verifies the zeroed EOF tail, updates an already
cached range, and rejects any READ RPC. The same probe runs in Linux and in the
Linuxulator. Linux reference review also caught the fixture returning its old
file size from GETATTR after STORE; it now updates authoritative server metadata
before notifying the kernel, as a real daemon must. The earlier failed reference
runs are retained. Native malformed-offset tests deliberately enforce stricter
bounds than Linux's zero-length malformed STORE handling; they are not claimed
as exact Linux behavior.

The first Linuxulator integration run passed data checks but failed cleanup:
libfuse's lazy unmount left mounts behind. The fixture now requires a successful
normal `umount2(..., 0)` before teardown, and the guest requires module unload.
This does not implement general Linux MNT_DETACH support. Failed evidence stays
in `linux-up`; successful data checks alone do not qualify that run.

Build the protocol fixtures with `build-fuse-protocol.sh OUT`. Build the real
Linux daemon with `build-fuse-store.sh LIBFUSE_MUSL_SYSROOT OUT` (the sysroot from
`build-fuse-client.sh` is suitable), and brand its ELF as Linux for FreeBSD
staging. Stage `guest-fuse-protocol.sh` or `guest-fuse-store.sh`, respectively,
and run their matching `qemu-fuse-protocol.py` / `qemu-fuse-store.py` runners on
1-vCPU and 4-vCPU disposable guests. Final inventories, diagnostic checks,
clean poweroff, module unload and source/binary hashes are recorded in the
batch manifest. Runtime probes must not run on the host.

The STORE behavior was reviewed against
[Linux v6.18 fuse_notify_store](https://raw.githubusercontent.com/torvalds/linux/v6.18/fs/fuse/dev.c).
The remaining parent-path notification, independent proc pipe, per-open FUSE
handle, kobject event and SOCK_DIAG work is still open; these passing STORE
checks do not establish completion of those contracts.

Final fourth-batch qualification passed:

| Gate | 1 vCPU | 4 vCPUs |
| --- | --- | --- |
| Complete native FUSE protocol suite | 797 active cases | 797 active cases |
| Real Linux64 libfuse STORE, including unmount/module unload | 5 rounds | 5 rounds |

The identical daemon binary also passed five Linux 6.18.35 reference rounds.
All final FreeBSD guests powered off cleanly with healthy pools and no panic,
lock-order reversal or non-sleepable-lock diagnostic. Exact results are in
`qualified-{up,smp}/results.json`,
`linux-qualified-final-{up,smp}/results.json`, `oracle-results.json`, and
`manifest.json`. Failed intermediate runs remain separate.


## Fifth implementation and review batch: Internet socket diagnostics

Evidence: `/tmp/linuxulator-diag-20260924`. This implements basic Linux wire
`NETLINK_SOCK_DIAG` / `SOCK_DIAG_BY_FAMILY` requests for TCP and UDP over IPv4
and IPv6. It is not completion of all discovery or all four compatibility groups.

`sys/netlink/netlink_sock_diag.c` supplies multipart dumps, exact tuple lookups,
state and port filtering, stable generation cookies, socket IDs, UIDs, endpoint
addresses, basic queues and TCP timers. TIME_WAIT records use Linux's zero
inode/UID/queues and timer type. Exact UDP requests preserve Linux's historical
reversed endpoint tuple and stale-cookie ESTALE behavior; TCP returns ENOENT
for a stale cookie. These details were checked against Linux reference runs.

Snapshots use the requesting netlink socket's credentials and current VNET,
with native PCB visibility checks for UID and prison isolation. A bounded array
is allocated before taking PCB locks; replies are allocated and emitted only
after those locks are released. Overflow retries are bounded, and allocation or
capacity errors are reported instead of silently truncating a successful dump.
The implementation lives in netlink core, avoiding a separately unloadable
Linux module callback with outstanding netlink work.

Scope still missing: UNIX/other diagnostic families, optional TCP_INFO/memory
attributes, bytecode filters and interface filters, SYN_RECV syncache entries,
and complete Linux wildcard lookup selection. Request attributes and nonzero
interface selectors explicitly return EOPNOTSUPP. Extension bits do not produce
optional attributes. UDP queues currently report native socket-buffer byte
counts, not Linux's memory-accounting values. Scoped/link-local IPv6 and bound
inactive TCP exact lookup behavior are not qualified. This is a useful base
implementation, not a claim that every `ss` mode works.

The private diagnostic kernel and all staged modules were rebuilt together,
retaining the previously qualified INVARIANTS/WITNESS configuration. Build
objects are isolated from the mutable shared build cache. Review/testing caught
and fixed IPv6 listener address selection and TIME_WAIT inode/queue semantics.
Earlier failing probe and harness runs remain separate from final evidence.

Qualification uses the independent Linux64 wire probe in
`tests/sys/kern/linux_sock_diag.c`. Build with
`tools/test/linuxulator/build-sock-diag.sh MUSL_SYSROOT OUT`, brand the resulting
ELF as Linux, stage `guest-sock-diag.sh`, and run `qemu-sock-diag.py --image IMAGE
--output OUT --cpus 1` and `--cpus 4` in disposable guests. The probe checks
multipart framing, exact requests, stale cookies, empty state masks, malformed
lengths, receive queues, closed sockets and TIME_WAIT. Host cases include 128
held endpoints and 1,000 concurrent create/close iterations per invocation.
Both root and an unprivileged UID run in the guest host, a VNET jail, and a
shared-network jail; a separate UID-visibility check hides a host listener.

The remaining parent-path notification, independent proc pipe, per-open FUSE
handle, and kobject event work stays open. The FUSE audit confirms that changing
OPEN alone is insufficient: CREATE flag propagation, buffered writeback,
mapping lifetime, FLUSH/RELEASE ordering, final lock release and forced reclaim
must preserve the same open-description identity.

Final fifth-batch qualification passed:

| Gate | Result |
| --- | --- |
| SOCK_DIAG, 1 vCPU | 54 inventory cases plus UID visibility check |
| SOCK_DIAG, 4 vCPUs | 54 inventory cases plus UID visibility check |
| Identical probe on Linux 6.18.35 | 18 bulk/churn reference cases |
| Native FUSE suite on rebuilt 4-vCPU kernel | 797 active cases |
| Mapping/inotify suite on rebuilt 4-vCPU kernel | 598 cases |
| Broader compatibility/proc/filesystem stress on rebuilt 4-vCPU kernel | Both validators passed |

All final FreeBSD guests shut down cleanly with healthy pools and without
panic, lock-order reversal or non-sleepable-lock diagnostics. Results live in
`final-{up,smp}/results.json`, `oracle-results.json`,
`fuse-regress-smp/results.json`, `mapping-regress-smp/results.json`, and both
`compat-regress-smp/{results,compat-results}.json`. The batch manifest records
source, binary and image hashes. Final standalone netlink module compilation
also passed; VM coverage uses the built-in provider.

Linux ABI references:
[inet_diag](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/ipv4/inet_diag.c),
[TCP diagnostics](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/ipv4/tcp_diag.c),
[UDP diagnostics](https://raw.githubusercontent.com/torvalds/linux/v6.18/net/ipv4/udp_diag.c).


## Sixth implementation batch: daemon open-flag ABI

Evidence: `/tmp/linuxulator-fuse-flags-20260924`.

FUSE_CREATE now encodes O_CREAT for the daemon ABI. Previously the native
FreeBSD bit (0x200) was sent unchanged to Linux daemons, where it means O_TRUNC;
Linux O_CREAT is 0x40. CREATE also preserves VA_EXCLUSIVE as the daemon's O_EXCL
bit. Both are one-time create flags and do not require changing cached handle
selection. Native-daemon CREATE retains native flag encoding.

Access flags for OPEN, RELEASE and direct READ/WRITE now use a common daemon-ABI
conversion. A native O_EXEC handle becomes O_RDONLY for a Linux daemon, which
has no O_EXEC wire value; local access mode and permission checks stay native.
Native-daemon O_EXEC remains unchanged.

Twenty protocol regressions cover native/Linux daemon CREATE flags with and
without exclusive creation at protocol 7.11, 7.12 and the current version, plus
OPEN/RELEASE for all four native access modes. The full suite inventory is 817
active cases. `linux_fuse_create_flags.c` adds an actual Linux64 libfuse daemon
and client: non-truncating ordinary/exclusive creation, direct write/read,
matching handle/access flags, RELEASE and normal unmount. The guest runs five
rounds of each mode and requires successful fusefs module unload.

Build the native fixtures with `build-fuse-protocol.sh OUT` and the Linux probe
with `build-fuse-create-flags.sh LIBFUSE_MUSL_SYSROOT OUT`. Brand the Linux ELF,
stage `guest-fuse-create-flags.sh`, then use `qemu-fuse-create-flags.py` on
single-CPU and four-CPU disposable images. The native suite uses its existing
guest and runner. Only fusefs needs rebuilding against the fifth-batch kernel;
there are no shared VFS or kernel ABI changes in this batch.

This does not fix per-open FUSE handle identity. CREATE still guesses O_RDWR
because VOP_CREATE does not carry the complete original open flags. O_APPEND,
O_DIRECT and other per-open flags must not simply be forwarded through the
shared handle cache. The wider handle/lifetime work remains open.

Linux flag values are defined in
[the Linux UAPI fcntl header](https://raw.githubusercontent.com/torvalds/linux/v6.18/include/uapi/asm-generic/fcntl.h).


Final sixth-batch qualification passed:

| Gate | 1 vCPU | 4 vCPUs |
| --- | --- | --- |
| Native FUSE protocol suite | 817 active cases | 817 active cases |
| Real Linux64 libfuse CREATE, ordinary/exclusive | 10 executions | 10 executions |

The identical Linux probe also passed ten Linux 6.18.35 reference executions.
The first expanded reference run exposed a fixture teardown race: Linux may
send RELEASE asynchronously after close returns. The corrected fixture waits
with a five-second bound for the callback before unmounting and destroying the
daemon session. Failed reference evidence remains in `oracle-qualified.*`;
final matching evidence is `oracle-qualified-release.*`. No kernel change was
needed for that fixture correction.

All final FreeBSD guests powered off cleanly with healthy pools and no panic,
lock-order reversal or non-sleepable-lock diagnostic. Real-daemon guests also
unloaded fusefs successfully. Results are in `native-final-{up,smp}/results.json`,
`linux-qualified-{up,smp}/results.json` and `oracle-results.json`. The manifest
records the source, rebuilt fusefs module, native fixtures, Linux probe and VM
image hashes. This batch does not qualify the remaining per-open handle work.

## Seventh batch: per-open FUSE descriptions

Evidence directory: `/tmp/linuxulator-openfiles-20260924`. Linux-daemon mounts
now bind handles to open file descriptions. Independent opens each reach the
daemon for authorization, while dup, fork, AIO and mappings retain their actual
handle. OPEN, CREATE, I/O and RELEASE carry the corresponding access/status
flags, including subsequent F_SETFL changes. Directory operations and both ends
of copy_file_range carry descriptor identity. Native-daemon handle caching is
unchanged.

Core-owned vnode fileops and a default no-op VOP_FILECLOSE provide descriptor
FLUSH and final RELEASE without leaving module function pointers in open files.
The thread context and VOP use existing spare slots; structure layout is
preserved. Final RELEASE follows flock/OFD unlock, is queued asynchronously, and
cannot block waiting for a daemon dropping its own last reference. Forced
unmount followed by module unload and descriptor close has a VM regression.
FUSE now declares its OFD-lock capability; remote owners use opaque
per-description identities and GETLK accepts the Linux OFD owner sentinel.

Direct-I/O handles reject shared mappings with ENODEV without negotiating
DIRECT_IO_ALLOW_MMAP, and allow private mappings. Cached and writeback mappings
retain handles through the final unmap and flush dirty data before RELEASE.
Ordinary non-writeback writes preserve their byte ranges. Pager writes retain
the VM-backed path because UIO_NOCOPY cannot supply bytes to the ordinary
uiomove path. Nonseekability is per description rather than per inode.

Qualified focused results so far:

- `native-final-{up,smp}/results.json`: **834 native FUSE cases per VM**, including
  17 new per-open cases. No new skips. The five pre-existing disabled native
  cases remain listed in the exact inventory.
- `linux-async-{up,smp}/results.json`: **nine real Linux64 libfuse executions per
  VM**, covering direct, cached and writeback modes, each repeated three times.
  Includes access after changing credentials, duplicate/fork ownership,
  write-only partial writes, CREATE flags, fsync, truncate and mapped writes.
- `oracle-reviewed.console.log`: the same Linux64 probe passed all three modes
  on Linux 6.18.35.
- `mapping-smp/results.json`: **580 Linux64 mapping/lifetime executions and 18
  native inotify cases**, with watch counts returning from zero to zero. This
  tests the same core kernel; later changes were confined to the FUSE module
  and test fixtures.
- Broader final-module compatibility regression failed in procfs stress:
  `compat-final-smp` exited 4 during round 2. Missing root fdscale output
  points to a failed epoll fdinfo read; the original fixture did not print
  the syscall errno. Diagnostic instrumentation and bounded snapshot-growth
  hardening are in progress under `/tmp/linuxulator-epoll-snapshot-20260924`.
  This failure is retained and the batch is not closed.

Failures remain preserved: the initial thread-field insertion violated a KBI
assertion (replaced with a spare slot); an overbroad edit changed legacy buffered
writes (restored); forcing pager writes through uiomove sent zero bytes (fixed);
OFD support lacked its filesystem capability flag (fixed). Asynchronous RELEASE
also exposed a fixture teardown race: completion now signals after writing the
reply, not before it. The copy-range fixture now acknowledges timestamp updates.

This establishes the tested per-open contracts, not complete Linux FUSE parity.
Pager operations without a file context still select a compatible inode handle;
FOPEN_STREAM has not received a full offset/concurrent-I/O qualification.
Parent-path inotify identity, independent proc pipe reopening, real kobject
events and extended socket diagnostics remain active work. UNIX SOCK_DIAG is
being implemented separately under `/tmp/linuxulator-unixdiag-20260924` and is
not included in this batch's kernel qualification.

## Eighth batch: UNIX socket diagnostics and epoll snapshot hardening

`/tmp/linuxulator-unixdiag-20260924` adds UNIX SOCK_DIAG dumps and exact inode /
cookie queries for stream, datagram and seqpacket sockets. Replies include
binary abstract or pathname names, filesystem inode/device identity, peer
identity, pending connections, queue lengths, memory accounting, shutdown bits
and UID. Filesystem device IDs use the Linux diagnostic 12:20 encoding, which
is different from Linux stat's device encoding. Unaccepted server sockets have
no Linux file inode: they are omitted from dumps and appear as peer inode zero
until accept. Pending-connection records identify their client sockets.

Native UNIX PCBs are global, so the bounded snapshot explicitly applies both
requesting-credential and VNET visibility. It exports generation identities,
not kernel addresses. Socket/PCB locks protect the copy; reply allocation and
filesystem metadata reads happen after those locks are released. Filesystem
vnodes are referenced while collecting their immutable identity. Pending
connections are resolved from captured identities without acquiring child PCB
locks under the listener socket lock.

Qualification:

- `pending-{up,smp}/results.json`: **90 inventory executions and two visibility
  checks per VM**, across host, shared-network jails and VNET jails. Eighteen
  executions additionally race 1,000 socketpair create/close cycles against
  repeated dumps. This includes all seven UNIX_DIAG optional attribute groups.
- `oracle-pending.console.log`: **18 matching Linux-reference executions**, also
  including churn and queued/accepted peer transitions.
- `fuse-smp/results.json`: **834 native FUSE cases** on the updated kernel.
- `inet-smp/results.json`: **54 TCP/UDP diagnostic inventory executions plus the
  UID-visibility check**, preserving the preceding diagnostic contracts.

The first VM found that native UNIX streams store the effective send shutdown
state and outgoing queue in the peer's receive buffer. The snapshot now follows
that native ownership. The failed `first-smp` result remains preserved. Memory
accounting reflects the host socket buffers; allocation categories the host does
not track remain zero, so byte totals are not promised to equal Linux skb costs.

The broader FUSE-checkpoint regression exposed a separate epoll fdinfo stress
failure (exit 4, syscall errno not originally printed). Evidence and the fix are
under `/tmp/linuxulator-epoll-snapshot-20260924`. The native knote snapshot used
an exact-sized allocation between two locked passes and could repeatedly lose a
concurrent delete/add race. It now reserves bounded growth room and grows
successive retries geometrically, within the existing 128 MiB ceiling. This
makes a fixed 128-interest table fit despite its transient filter removal.

Both the original and patched kernels passed 80 focused executions; that focused
run did not reproduce the earlier intermittent failure. The probe now prints
failed read/open results, and the stress runner records nonzero case exits.
`compat-fixed-smp/{results,compat-results}.json` passes the full instrumented
compatibility/proc/filesystem stress inventory with the hardened kernel. The
UNIX diagnostic checkpoint also includes this kernel change. The exact errno of
the original failure remains unknown; the preserved failed result is not
reclassified as a pass.

Still active: TCP/UDP extended attributes and filters, kobject uevents,
parent-path inotify identity, independent proc pipe reopening, and the remaining
FUSE stream-semantics review. No io_uring or Linux32 work is included.

### Ninth batch: inet_diag attributes and predicates (2026-09-24)

TCP/UDP diagnostics now return requested MEMINFO, SKMEMINFO, IPv4 TOS,
IPv6 traffic class, TCP congestion names, and the 104-byte stable TCP_INFO
prefix. Full sockets always report shutdown state. Memory fields describe
native socket-buffer accounting; Linux-only accounting categories and TCP
counters without a native counterpart remain zero. TIME_WAIT retains its
minimal record. Congestion-specific Vegas/BBR/DCTCP extensions are not supplied.

Dump bytecode supports forward branches, source/destination port comparisons,
address/prefix/port predicates (including mapped IPv4), automatically assigned
ports, and device predicates. Validation checks operands, instruction boundaries,
forward progress, branch targets and prefix lengths before taking PCB locks.
The protocol request attribute overrides the header protocol. Mark, cgroup and
BPF-storage requests remain explicitly unsupported. The dump-header interface
index is ignored, matching Linux; device filtering uses its bytecode predicate.

Native fixes found during qualification: expose the existing locked TCP_INFO
snapshot helper; retain separate IPv4 TOS on IPv6 sockets; mark automatically
assigned IPv6 connect ports; and retry the first PCB itself after a failed
iterator lock, instead of accidentally skipping its successor. An earlier SMP
inventory failed before the iterator correction; its log is retained. That
failure did not print the missing port/count, so its precise trigger is not
proven. The probe now prints those details on any future failure.

Artifacts: `/tmp/linuxulator-inetdiag-20260924`. The corrected kernel passed
54 inventory runs plus the UID-visibility case on each of one and four CPUs,
with per-extension/exact/dump checks, socket-option cross-checks, valid and
malformed predicates, bulk inventory and socket churn. Twelve Linux 6.18.35
reference runs passed (both UIDs, both families, TCP listener/connected and UDP).
The same kernel passed 90 UNIX inventories plus two visibility cases, all 834
native FUSE protocol cases, and the full instrumented compatibility/proc/filesystem
stress gate. Earlier failing fixtures and images remain separate.

Still outside this inet_diag batch: syncache/SYN_RECV enumeration,
congestion-specific telemetry, Linux marks/cgroups, and bound-device socket
support. Native memory accounting is not Linux skb accounting. FUSE stream
work is a subsequent batch and is not covered by these results.

### Tenth batch: FUSE stream semantics (2026-09-24)

Work directory: `/tmp/linuxulator-stream-20260924`. The final candidate passed
the qualification below. The core stream fileops keep per-call offsets, retain the mount while
filesystem code executes, and avoid sharing offset/sequential-read state.
Direct stream reads release the vnode lock while waiting for the daemon;
writes downgrade to a shared lock so reads can proceed while exclusive
writers/fsync/truncate remain ordered. Direct stream opens enable shared vnode
locks, including daemons without ASYNC_READ negotiation. Re-upgrade must retain
the shared hold until metadata completion; stream readers use deadlock treatment
to pass queued exclusive waiters. Stream writes flush/invalidate cached buffers,
handle short replies without advancing unsent UIO bytes, and preserve file-size
limits and append handling.

Qualification found that ending a FUSE session did not wake pending answer
waiters until the device descriptor closed or the 60-second timeout elapsed.
Session death now wakes those waiters; forced unmount calls the filesystem purge
hook before draining vnodes. Interrupt capability checks use retained session
state rather than a potentially detached mount, and interrupt callbacks retain
the original ticket across dropping the answer-queue lock.

Completed intermediate checks: Linux 6.18.35 runs in direct/cached/writeback
modes, Linux64 FreeBSD daemon runs with duplex traffic, short reads/writes,
errors, and fsync queued behind a pending write. One intermediate native suite
passed 840 cases with pending-read unmount completing in 17 ms. Earlier logs
include a duplicate mock expectation, stale test binary, a 60-second teardown
that passed an insufficient assertion, and a shared-lock setup panic. These
are retained as intermediate results. The final suite has 843 cases, adding
buffered-stream offsets, module unload with a live stream file, and time-bounded
forced unmount during both read and write. Its final results are below.


Final stream qualification: all 843 native cases passed on both one and four
CPUs, including both forced-unmount cases completing well below five seconds.
All nine Linux64 daemon runs passed on each CPU configuration. The final kernel
and module also passed the full instrumented compatibility/proc/filesystem
stress gate on both configurations. The malformed-reply regression was updated:
session termination now wakes the original lookup with ENOTCONN, without a
second daemon reply. Pager I/O is explicitly excluded from the stream helper.
Sources, binaries, hashes and results are frozen under the work directory;
these results do not qualify subsequent parent-path notification edits.

### Eleventh batch in progress: retained parent-path notifications

Work directory: `/tmp/linuxulator-parentpath-20260924`. Sixteen Linux 6.18.35
reference runs passed: eight parent-path cases under root and unprivileged UIDs.
The FreeBSD baseline passed only the two rename cases per UID; hard-link,
unlink/exclusion, replacement, overwrite and duplicate-description cases failed.
The baseline returned its watch count to zero. A retained per-file path registry
is being implemented; it is not yet VM-qualified. Rename/unlink concurrency,
failed-open cleanup, parent lifetime, mappings, nullfs and forced unmount require
review and regression coverage before this batch can be called complete.


Eleventh-batch qualification: retained paths now follow Linux64 regular-file and
directory descriptions through dup/fork, mappings, rename, unlink, replacement,
and proc-fd reopening. IN_EXCL_UNLINK tests the opened path's unlink status.
Layered notifications translate both vnodes through VOP_INOTIFY; direct inode
notifications remain independent. A generic rename post-hook owns storage holds,
not necessarily active references. Old parent references are released outside
the registry lock. Tmpfs permits reopening a retained unlinked regular file.

Final evidence in `/tmp/linuxulator-parentpath-20260924/manifest.json`:
126 parent-path cases per VM (ZFS/tmpfs/nullfs, root/unprivileged), 580 mapping
and lifetime probes plus 18 native inotify cases per VM, 843 native FUSE cases
per VM, nine Linux FUSE daemon runs per VM, and the full compatibility/proc/
filesystem stress gate on both one and four CPUs. All passed. Forty-two Linux
6.18.35 reference cases passed. Parent-path and watch counters returned to zero.

Retained failed artifacts include the original 12/16 baseline failures, a
nullfs reference assertion, tmpfs last-link reopen failures, direct-watch event
suppression found by mapping regressions, a race assertion stricter than Linux,
and an unbranded probe image. None is counted as qualification. Final sources
and binaries were frozen before beginning anonymous-pipe changes.

Boundaries still requiring the later maturity pass: O_PATH and final dot/dotdot
opens, path-based metadata operations without an open-description context, and
proc readlink formatting for deleted names/ancestors. This batch does not claim
that every Linux notification or descriptor-path behavior is complete.

### Twelfth batch in progress: anonymous-pipe reopening

Work directory: `/tmp/linuxulator-pipereopen-20260924`. Twenty-four Linux reference
cases pass, covering identity, all access-mode/end combinations, independent
flags, dup sharing, reader/writer lifetime, O_RDWR, reopening without a peer,
O_PATH, CLOEXEC, directory rejection and shared queues. The FreeBSD baseline
fails identity/reopening. The first candidate adds an explicitly one-way native
pipe channel with per-description reader/writer/reference counts and a proc-fd
open bridge. Native duplex pipes retain their existing constructor behavior.
This candidate is not yet VM-qualified. No io_uring implementation is changed.


Twelfth-batch qualification: Linux64 anonymous pipes now use a shared one-way
channel with independent open descriptions. Proc-fd reopening supports reversed
access, O_RDWR, O_PATH lifetime, independent nonblocking/close-on-exec state,
shared inode identity and mutable permissions/ownership. SIGIO ownership and
async enablement are per description; dup/fork retain shared descriptions.
The last I/O description discards queued data even if O_PATH keeps the inode.
FIONREAD works on either end; fstat reports zero FIFO size. Poll/epoll distinguish
empty EOF from readable bytes, and full broken writers from available space.
Native duplex pipes and named FIFO constructors retain their existing behavior.

Evidence: `/tmp/linuxulator-pipereopen-20260924/manifest.json`. Forty-four Linux
6.18.35 reference cases passed. Both one-CPU and four-CPU FreeBSD VMs passed all
44 Linux pipe cases, 22 native pipe/FIFO cases, and the full compatibility/proc/
filesystem stress gate. Tests include splice/tee, independent/reconnected epoll
interests, descriptor exhaustion, privilege changes, and concurrent reopen/close
loops. Failed candidates and harness failures are retained and excluded from
qualification. Source, binaries, hashes and per-batch diff are frozen.

This does not add packet-mode pipes, anonymous-pipe inotify, or fix every general
epoll semantic. Deleted descriptor names are the next batch. No io_uring changes.

### Thirteenth batch qualified: proc descriptor path identity

Evidence: `/tmp/linuxulator-procpath-20260924/manifest.json`. Opened hard-link
names, rename/unlink/recreation, proc-fd reopening, O_PATH, dot/dotdot, and
removed ancestor chains now retain the opened path identity. A reference-counted
parent graph retains only ancestry needed by live file descriptions. Generation
checks retry readlink across concurrent rename and parent removal. Nullfs rename
hooks retain upper-layer parent paths instead of leaking backing paths.

The final candidate passes 132 cases on each of one- and four-CPU disposable
BSD VMs, 264 cache-enabled/disabled cases with the debug kernel, and 44 Linux
reference cases. Paths and retained-parent counts return to zero. Final gates
also pass, per topology: 126 parent-notification cases, 598 mapping/native cases,
843 native FUSE cases, nine Linux FUSE daemon runs, 44 pipe cases, and the full
compatibility/proc/filesystem stress gate. Exact inventories and frozen binary,
source and image hashes are in the manifest; failed candidates remain retained.

Two test defects were corrected. Native FUSE auto-unmount now retries transient
statfs ENOENT within its existing bound; the same failure reproduced on the
prior frozen kernel. The fdinfo concurrency test now waits for the worker to
start before collecting snapshots. Deliberately delaying that worker reproduced
eight zero-update failures in the old fixture; all eight pass after the fix.
The original uninstrumented return-7 failure cannot be attributed conclusively,
but the final instrumented full gates pass on both topologies.

Boundaries: retained VREG/VDIR paths are covered; O_PATH symlink identity,
mutations exclusively through lower-layer aliases across all upper mounts,
metadata notifications without file context, and general mount-namespace
semantics are not claimed complete. These are component qualification results,
not a claim that every Linux filesystem behavior or Electron sandbox works.

### Fourteenth batch in progress: real network device events

Work directory: `/tmp/linuxulator-uevent-20260924`. The Linux reference and first
BSD candidate pass actual interface add/move/remove events as root and an
unprivileged user, on raw and datagram protocol-15 sockets. The baseline rejects
the protocol. The candidate provides kernel-origin NUL-separated datagrams,
credentials, subscription filtering, queue-overflow errors and network sysfs
paths under `/sys/devices/virtual/net`, with class and subsystem links.

The first VM found missing Linux recvmsg output-flag translation; the corrected
candidate passes short-peek truncation checks. Expanded transport, isolation,
lifecycle and broad regression gates are still pending. PCI/DRM device hotplug,
privileged user event injection and libudev's userspace group-2 relay are outside
this network-event increment. No io_uring implementation work is included.
