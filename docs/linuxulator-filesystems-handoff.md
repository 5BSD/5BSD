# Linux compatibility filesystems

Scope: amd64 Linux64. No Linux32 work. Do not work on or run io_uring/squeue
suites; those have a separate owner. Preserve the shared working tree.

User authorized this backlog on 2026-09-22. This is a staged implementation
plan, not a claim that listed interfaces are already implemented or tested.

## Batch 1: existing mount and system information interfaces

- [x] Map Linux `sysfs` mounts to `linsysfs` (amd64 Linux64).
- [ ] Translate supported tmpfs mount options (size, mode, uid, gid,
  nr_inodes); validate syntax, overflow, defaults, duplicate options,
  unsupported options, bind/remount behavior, and allocation cleanup.
- [x] Escape mount source/target fields in mounts/mtab/mountinfo using Linux
  octal escapes for space, tab, newline and backslash.
- [ ] Report actual CPU sets and enumerate actual CPU IDs, including sparse
  IDs. Distinguish supported online/present/possible semantics.
- [x] Add CPU package/core topology and sibling masks/lists using native data;
  do not invent topology when the host cannot supply it.
- [x] Add network statistics with native counters, plus carrier/operstate.
  Preserve VNET visibility and interface arrival/departure/rename behavior.
- [ ] Review hardcoded tx_queue_len and replace only with a semantically
  compatible native value; queue occupancy is not queue capacity.

## Batch 2: process and thread views

- [x] Extend pseudofs to enumerate and validate Linux thread identities.
  PFS_TIDNAME uses per-thread lifetime cookies; PFS_PIDNAME retains its original meaning.
- [x] Implement /proc/<pid>/task/<tid> and /proc/thread-self.
- [x] Add thread names and thread-specific stat/status; distinguish Tgid/Pid.
- [x] Correct SigPnd/ShdPnd/SigBlk; preserve signal-number translation.
- [x] Improve native-backed stat scheduling/signal fields and process-name
  escaping; unrelated flags/wchan/address placeholders remain.
- [x] Replace VmLck placeholder with user-wired mapping accounting; bound
  the existing VmLib estimate to prevent underflow.
- [ ] Check root/cwd/exe/maps/mem/auxv permissions and target visibility across
  credentials, exec, exit, jails and debugger restrictions.

## Batch 3: descriptors and mounts

- [x] Replace /proc/<pid>/fd shortcut with real descriptor directories,
  including cross-process access subject to native debugging permissions.
- [ ] Implement dynamic descriptor enumeration and Linux-compatible readlink
  and open behavior. Cover closed/reused descriptors, deleted files, pipes,
  sockets, permissions and process lifetime.
- [x] Add basic fdinfo (position, native-backed translated flags, inode/mount
  identity); vnode-less objects currently report mount ID zero.
- [ ] Add type-specific fdinfo for supported eventfd, epoll, inotify,
  signalfd and timerfd where native/emulator state supplies the information.
- [x] Replace dummy mountinfo parent/device values with consistent identities;
  ensure mount IDs agree with fdinfo/stat interfaces and survive enumeration.
- [ ] Correct mount visibility/path translation for chroot and jails.
- [x] Translate proc/sysfs names in /proc/filesystems and mark tmpfs nodev.
  Other native filesystem names retain their existing presentation.

## Further accounting and device work

- [ ] smaps and smaps_rollup: investigate native VM support for resident,
  private/shared, dirty and proportional accounting before implementing.
- [ ] /proc/<pid>/io and additional resource statistics where exact native
  counters exist; document differences instead of fabricating measurements.
- [ ] PCI sysfs: audit duplicate directory construction, PCI class encoding,
  configuration-space representation, device lifetime and relationships.
- [ ] Extend /sys device, block, DRM and NUMA views based on application needs
  and real host data; validate links and device numbers across /dev and /sys.
- [ ] Audit lindebugfs per-open state, seek/read/write behavior and removal
  races for interfaces actually supplied by compatible drivers.
- [x] Qualify existing Linux FUSE translation with the upstream libfuse 3.18.3
  Linux64 hello daemon; broader daemon/protocol coverage remains.
- [ ] Qualify devfs/fdescfs/tmpfs Linux views and filesystem behavior (locks,
  xattrs, notifications, permissions and filesystem identification).

## Larger projects, not path-only additions

- cgroupfs requires grouping, accounting and enforcement. The current
  /proc/<pid>/cgroup "0::/" response is not a cgroup implementation.
- Namespace-aware devpts and mount trees require corresponding lifetime and
  isolation semantics. Existing devfs pseudo-terminals are the baseline.
- New disk filesystem drivers such as ext4/overlayfs are separate VFS projects;
  ordinary Linux application files can reside on existing native filesystems.
- Keep unavailable capability/control interfaces distinguishable from working
  features. Do not add writable files that report success without effect.

## Validation and evidence

For every implemented batch: build affected modules with matching headers;
run static amd64 Linux probes in disposable BSD and Linux-reference QEMU VMs.
Never install/load the test kernel/modules or execute syscall probes on host.
Test short reads, seek/reopen, malformed inputs, root/unprivileged visibility,
concurrent object removal, mount/unmount cycles and applicable jail behavior.
Retain native regression tests for shared pseudofs/VFS changes. Add actual
application checks (e.g. procps/util-linux/runtime introspection) after ABI tests.
Do not count unsupported cases as passing or imply whole-backlog completion.

Initial source review: sys/compat/{linprocfs,linsysfs,lindebugfs},
sys/compat/linux/linux_file.c:linux_mount, sys/fs/pseudofs,
libexec/rc/rc.d/linux. Initial artifacts: /tmp/linuxulator-filesystems-20260922.

Linux contracts:
- https://docs.kernel.org/filesystems/proc.html
- https://www.kernel.org/doc/html/v6.16/admin-guide/cputopology.html
- https://docs.kernel.org/filesystems/tmpfs.html

## First implementation increment (2026-09-22)

Implemented in Linuxulator/linprocfs/linsysfs, without new host-kernel APIs:

- Linux64 sysfs mount alias.
- New Linux64 tmpfs mounts accept size (bytes or K/M/G/T/P/E suffix, either
  case), mode (octal), uid/gid (decimal), and nr_inodes. Duplicate options use
  the last value. Defaults: 01777, caller effective uid/gid, half physical RAM
  for size and min(half physical pages, INT_MAX) for inode count.
- Parse/validate before allocating mount arguments. Invalid numbers, trailing
  junk, unknown options and overflow fail; unreadable pointers return EFAULT.
  Native tmpfs enforces the translated size rather than merely reporting it.
- Mount-table source/target whitespace and backslashes receive octal escaping.
- CPU lists serialize the native configured set, and cpuN directories iterate
  actual IDs. This fixes the previous assumption that IDs are contiguous.
- /sys/class/net/<if>/statistics exports rx/tx packets, bytes, errors, queue
  drops, multicast receives and collisions using native interface counters.
  Added carrier and operstate, preserving VNET lookups and epoch protection.
- Fixed a pre-existing filesystem-type lookup reference leak in linux_mount;
  kernel_mount takes its own reference. The leak prevented module unload even
  after all Linux-created mounts had been removed.

These are subsets of batch 1. CPU topology/sibling files, tx_queue_len,
thread/descriptor directories, detailed memory accounting and further
filesystem projects remain unchecked above and are not implemented here.

Explicit limitations:

- tmpfs NUMA/hugepage policies and other unlisted options are not supported
  by this parser. Unknown options return EINVAL.
- Option-bearing tmpfs remounts return EOPNOTSUPP because native resizing is
  unavailable. nr_inodes values <=3 or >INT_MAX also return EOPNOTSUPP rather
  than silently applying native rounding/capping. size=0 uses native unlimited
  size semantics. Inode usage includes native metadata semantics.
- Native tmpfs reports its mount source as "tmpfs", not the caller's arbitrary
  source label. Escaping does not change this underlying VFS behavior.
- CPU online/present/possible report the configured native set; this does not
  implement Linux CPU hotplug. The VM tests exercise contiguous IDs; sparse-ID
  behavior has source review coverage only.
- Dropped counters reflect native queue-drop counters, as in the existing
  /proc/net/dev translation; no Linux-only driver counters are fabricated.
  Unknown native link state reports operstate "unknown" and carrier 1 while
  administratively up. A down interface's carrier read returns EINVAL.
- No new jail/VNET isolation implementation or full application qualification
  is claimed by the initial ABI probes.

Tests: tests/sys/kern/linux_filesystems.c;
tools/test/linuxulator/{guest-filesystems.sh,qemu-filesystems.py}.
The dedicated runner never invokes io_uring/squeue tests. Runtime evidence and
source/binary hashes are retained under /tmp/linuxulator-filesystems-20260922.
Initial Linux reference (oracle2.console.log): all 8 executions passed.
The first BSD run found the native tmpfs source-label difference; the test was
corrected to check path escaping without assuming source-label preservation.
The first unload run exposed the reference leak; its failed log is retained.
Final qualification: final-run/results.json reports passed=true, 24/24 ABI
executions and all three unload/reload cycles. Each cycle reran Linux sysfs
mounting, CPU enumeration and live network counters. No recognized kernel
panic/trap/locking diagnostics; healthy ZFS pool, synced buffers and clean
poweroff. linux64-build3.log, linprocfs-build.log and linsysfs-build.log record
successful affected-module builds. No host modules/kernel were installed.

The final guest uses stage5.py/focus5.img; the repository qemu-filesystems.py
runner validated it. source-inputs.json/source-snapshot pin this increment's
code and tests; task.patch isolates the code changes from the pre-existing
working tree. The guest kernel and linux_common binary are inherited from the
previous signal-modes qualification; module/test hashes are in manifest.json.
The new tests do not constitute complete Linux filesystem conformance.

## Expanded testing and fixes (2026-09-22)

Artifacts: `/tmp/linuxulator-fs-coverage-20260922/`.

Added independent behavioral tests for documented tmpfs number formats,
last-option precedence, exact inode exhaustion/reuse, byte limits, read-only
mount/remount enforcement, bind data handling, inaccessible first-byte and
partially accessible option buffers, privilege/ownership enforcement, one-byte
reads/seek/pread, every exposed network counter, 64 simultaneous mounts,
concurrent table reads during 64 mount/unmount cycles, dynamic interface
renaming/removal, and VNET visibility/teardown. Churn checks require successful
reads and ENOENT observations, rather than simply accepting an absent interface.

Linux-reference tests corrected two initial assumptions: bind mounts copy the
options buffer even though they ignore its contents, and a readable prefix
before a fault is parsed instead of unconditionally returning EFAULT. See
[Linux mount implementation](https://github.com/torvalds/linux/blob/v6.18/fs/namespace.c).

Fixed the failures exposed by the tests:

- Network sysfs fillers now let pseudofs handle sbuf exhaustion as a short
  read; they previously turned one-byte reads into ERANGE.
- Linux interface lookup accepts exact native interface names before parsing
  Linux aliases, with a bounded name check. Renaming lo1 to a name without a
  numeric suffix previously made its sysfs data inaccessible.
- Linux64 tmpfs parses readable option prefixes and terminates full-page
  option buffers, matching the Linux reference. An inaccessible first byte
  remains EFAULT. Linux64 bind mounts validate that first byte before ignoring
  the option contents.

A diagnostic boot rejected a newly built module with an undefined kernel
symbol; its old guest kernel was not a matching build. The guest kernel was
rebuilt, and the ZFS storage module refreshed. That failed boot is not counted
as coverage. Initial failed assertions and logs are retained.

The final runner expects 60 ABI records, 21 interface lifecycle records, three
VNET jail records and three module reload records. Final qualification results follow; the earlier 24-check result above remains
historical.

Limits still include sparse CPU IDs, topology, remount resizing, unsupported
mount options, complete per-open procfs snapshot semantics, and the unimplemented
thread/fdinfo/smaps backlog. VNET tests establish the named interface-visibility
and loopback properties, not complete jail or namespace conformance.

### Expanded qualification results

- `final3-run/results.json`: **87/87 named BSD results passed**: 60 ABI
  executions, 21 interface lifecycle results, three VNET jail results and
  three filesystem module reload results. Each churn round observed over
  1,000 successful reads and over 6,000 unavailable-interface observations.
- `oracle5.console.log`: **26/26 Linux-reference results passed**: 20 ABI
  executions and six interface lifecycle cases on Linux 6.18.35-0-virt.
  The same final unbranded probe was used. Linux churn observed 2,167 successful
  reads and 6,025 unavailable-interface observations.
- `network-results.json`: **237/237 existing regression executions passed**,
  covering root/unprivileged XSAVE, multicast and delivery, socket peer names,
  process tracing events, native multicast, Capsicum and native exit tracing.
  These specifically retain Ethernet/native-name callers of the shared Linux
  interface lookup. No io_uring/squeue tests ran.
- `client.console.log`: Linux GDB's embedded Python passed buffered/unbuffered
  filesystem reads and seeks, libc tmpfs mount/unmount with real file I/O,
  escaped mount-table parsing, and UDP/counter checks. This is a real-runtime
  smoke test, not qualification of a full Linux distribution.
- All final BSD guests reported healthy ZFS pools, synced buffers and clean
  poweroff, without recognized panic/trap/locking diagnostics. Kernel and
  affected-module builds completed, and probes compiled with warnings as errors.

The Linux removal race permits ENOENT, ENODEV and EINVAL only in the churn
case: Linux net-sysfs returned EINVAL during removal, while kernfs also permits
ENODEV when an opened node loses its active reference. Steady-state reads
still require valid numeric content. The earlier stricter assertion and its
failure are retained in oracle3/oracle4 logs; arbitrary errors are not accepted.
See [kernfs file operations](https://github.com/torvalds/linux/blob/v6.18/fs/kernfs/file.c).

`manifest.json` records final guest/probe/module hashes, results and source
provenance; `task.patch` isolates this increment from the shared dirty tree.
`source-inputs.json` and `source-snapshot` retain build/test inputs, and
`post-test-drift.json` identifies subsequent unrelated runner changes. No host
kernel or modules were installed or loaded. No commit was made.

## Additional tmpfs sizing (2026-09-22)

Linux64 tmpfs mounts now accept `size=N%` and `nr_blocks=N`, including
Linux memparse unit suffixes and base prefixes. Percentages use total physical
memory. `size` and `nr_blocks` set the same limit; the last occurrence wins.
The implementation is confined to the Linux64 mount parser and uses native
tmpfs limits. It does not change native tmpfs or add Linux32 support.
Values that overflow conversion or exceed the representable native byte limit
return EINVAL. Option-bearing remounts remain unsupported.

The existing `options` test now also checks ten exact statfs capacities:
block counts in decimal/hex/octal, a suffixed block count, both precedence
orders, sub-page byte rounding, and 1%, 50%, and 100% of guest physical RAM.
The invalid-option test adds malformed percentages and block counts.
Validation passed: the Linux64 module and freestanding probe build with
warnings treated as errors; all 26 Linux-reference filesystem/link checks;
and all 87 BSD VM checks (60 ABI, 21 interface lifecycle, 3 VNET, 3 module
reload). The BSD VM reported healthy ZFS, no diagnostic matches, and a clean
shutdown. This increment did not rerun the separate 237-execution regression
or Python client suites recorded above.
Artifacts: `/tmp/linuxulator-tmpfs-sizing-20260922/`.

## Process views and CPU topology (2026-09-22)

The next six requested items are implemented:

- `/proc/filesystems` translates linprocfs/linsysfs to proc/sysfs and correctly
  marks tmpfs as nodev.
- Status escapes newline and backslash in task names using Linux's text format.
  Stat retains the raw parenthesized name. Linux64 PR_SET_NAME/PR_GET_NAME now
  operate on the calling thread, with the full zero-padded 16-byte GET_NAME
  result; worker clones inherit the calling thread name.
- VmLib and the statm library estimate cannot underflow. They remain estimates,
  not shared-library mapping classification.
- VmLck sums user-wired VM mappings under the map lock with a held vmspace
  reference. It excludes wiring performed only by the kernel.
- CPU topology exports physical_package_id, core_id, thread_siblings,
  thread_siblings_list, core_siblings, and core_siblings_list. The amd64 native
  helper reads the immutable boot topology. Single-CPU startup bypasses that
  tree; that case uses Linux's documented generic defaults (package -1, core 0)
  and the actual singleton CPU set. No CPU hotplug is added.
- Pseudofs can enumerate Linux64 TIDs with an identity callback and immutable
  lifetime cookies. Lookup, attributes, reads, and directory enumeration validate
  the identity under the process lock; no thread pointer escapes that lock.
  Thread-dependent names bypass the name cache to handle TID reuse. Existing
  process-only pseudofs users retain their behavior. Pseudofs module ABI is now
  version 2, and consumers require version 2.
  The single-CPU VNET test exposed an existing directory-read lock inversion;
  readdir now acquires allproc before the vnode lock, holding and revalidating
  the vnode across the temporary unlock. WITNESS diagnostics remain failures.

`/proc/thread-self` resolves to the caller's `<pid>/task/<tid>` directory.
Thread directories provide mem/maps plus thread-specific stat/status. Stat
includes the thread ID, name, state, usage, last CPU, and worker creation time.
Status includes Tgid/Pid, thread count, blocked and thread-pending signal masks,
and the separately translated process-pending mask. This does not complete
all Linux procfs fields: existing stat flags/wchan and other placeholders,
additional task-directory files, fd/fdinfo, and detailed memory maps remain
separate backlog work.

Tests and artifacts:

- `tests/sys/kern/linux_proc_views.c` covers names, accounting, filesystem
  discovery, topology, live threads and 32 rounds of thread churn per invocation.
  It checks stale descriptors, post-exit lookup, thread masks and names, and
  delayed worker start times. Runs cover root and an unprivileged user.
- `tools/test/linuxulator/guest-proc-views.sh` runs the six groups three times and then exercises the existing filesystem/lifecycle suite.
  `qemu-proc-views.py` validates the full inventory and shutdown.
- `tools/test/linuxulator/proc-views-client.py` exercises real Linux Python
  threading and discovery; it can run in Linux GDB's embedded Python.
- `/tmp/linuxulator-proc-topology-20260922/` retains builds, images, logs and
  source provenance. Final validation passed:
  - 108 proc/topology checks plus 261 existing filesystem/lifecycle checks
    across single-CPU, two-package, and two-core/two-thread SMT guests.
  - Native procfs/fdescfs smoke checks and final module unloads on each layout.
  - 1,184 broad regression executions in one final BSD VM run: ptrace,
    pending signals, multicast and socket identity, quotas, unshare, swap
    priority/discard, rseq and unload refusal, legacy AIO, filesystem options,
    OFD locking, seals, and 144 path-resolution cases on ZFS and tmpfs.
  - 12 Linux-reference executions, root and unprivileged, using the same
    unbranded probe bytes as the final BSD probe before ELF branding.
  - Five real Linux Python smoke markers, including worker-thread discovery,
    alongside the existing filesystem and networking client checks.
  - Kernel/modules build with Werror; all 52 staged standalone regression
    payloads rebuilt successfully (the native ptrace fixture uses native cc).
  All final BSD runs required healthy ZFS, clean shutdown, and no kernel
  diagnostic matches. The focused controller validates exact records, and
  the broad controller requires all 1,184 unique named check records.

Final artifacts are `release-{single,smt,packages}/results.json`,
`regression4-results.json`, `oracle-final.log`, `client-final.console.log`,
`manifest.json`, and `task.patch` under that artifact directory. Kernel and
module hashes match across the focused, regression, and client staging roots.
Earlier failed attempts remain as diagnostic evidence; they are not counted
as passing runs. The final source audit found no implementation drift.

Three older probe build warnings were corrected without changing their
assertions: unsigned loop indices in linux_aio_counts/linux_swapon_discard,
and an unused local in linux_swapon_priority. No io_uring/squeue tests or
implementation changes are part of this increment.

## Process files, descriptor views and FUSE qualification (2026-09-22)

Artifacts: `/tmp/linuxulator-proc-descriptors-20260922`.

Implemented:

- Process and task `comm` files, including writes to sibling threads in the
  same process, 15-byte truncation, embedded NUL handling, literal newline
  reads, nonzero write offsets, and rejection of cross-process name writes.
- Task `cmdline`, `statm`, `limits`, `environ`, `auxv`, `mounts`, `mountinfo`,
  `fd`, and `fdinfo`, using existing thread identity/lifetime validation.
- Stat normal priority/nice, FIFO/RR policy and mapped realtime priority,
  thread pending/blocked masks, and ignored/caught masks. Legacy stat signal
  fields expose Linux's low 31 bits. Other stat placeholders are unchanged.
- Dynamic descriptor directories and basic fdinfo. Descriptor table and file
  references protect concurrent close/reuse; native debugging permissions
  are checked again while taking the descriptor snapshot. Permission and
  table lifetime are kept separate from the caller's own descriptor table.
- Vnode-backed descriptor links support independent open and directory
  traversal, including held unlinked regular files. Magic-link resolution
  constraints and native descriptor capability restrictions remain enforced.
  Pipes/sockets have descriptive readlink values. Descriptor inode numbers
  include process identity; directory snapshots use matching inode values.
- Basic fdinfo reports position, inode, mount ID and native-backed access,
  append, nonblock, async, direct, sync/dsync, path and close-on-exec flags.
- Mountinfo and Linux64 statx use the same positive signed-32-bit identity
  from a Linuxulator-owned registry, released on unmount. Parent IDs come from the covered vnode's mount. Device numbers
  use the same Linux translation as statx, including devfs normalization.
  Statx captures its ID from the same referenced vnode used for stat data.
- Real Linux64 libfuse hello qualification. Fixed Linux64 mount parsing so
  supported bare `allow_other`/`default_permissions` options actually mount;
  an unknown bare option returns EINVAL instead of false success.

Shared kernel changes: export existing `fdhold`/`fddrop` lifetime helpers;
add descriptor callbacks/identity to pseudofs; fix readdir's directory
visibility check to invoke callbacks without holding that node's mutex;
allow raw writers to handle their own input length without an sbuf limit.
**Pseudofs module ABI is now 3. Rebuild/use matching kernel and consumers.**
No host kernel/modules were installed or loaded. No Linux32 additions or
validation; no io_uring/squeue implementation or targeted tests.

Qualification covers root and normally launched unprivileged programs. The
unprivileged fixture drops credentials and execs before testing: native
P_SUGID debugging restrictions deliberately survive PR_SET_DUMPABLE(1), so
changing credentials and immediately inspecting another process is a
separate, more restricted case. Those host protections are preserved.

Remaining descriptor limitations are explicit: anonymous pipes cannot yet be
reopened through procfs; readlink of an unlinked file may fail after the native
name cache loses its pathname (reopening its held vnode works). Anonymous
filesystem mount identities and type-specific fdinfo are not implemented.
Remembered Linux-only open flags have no native backing in basic fdinfo.
Mount root/path presentation across different chroots/jails is still separate
work. FUSE hello qualification does not establish every protocol operation or
arbitrary daemon compatibility. Cgroups/namespaces and unrelated stat
placeholders remain outside this increment.

See `tools/test/linuxulator/build-fuse-client.sh` for pinned, checksum-checked
upstream source and Alpine build inputs. It only cross-compiles on the host.
The actual daemon is run exclusively in disposable guests.

Legacy mount IDs are allocated in `1..INT_MAX`, rather than exporting a hash
or a combined 64-bit fsid: util-linux/libmount stores both mountinfo IDs in
signed ints. The registry uses the native mount pointer and generation,
serializes insertion against unmount, and frees entries and IDs through the
existing `vfs_unmounted` event. Unloading linux_common cleans up entries for
still-mounted filesystems. No native mount structure changes are required.
Reference: https://github.com/util-linux/util-linux/blob/master/libmount/src/tab_parse.c

Final focused validation passed on a disposable amd64 BSD VM with the rebuilt
kernel and modules: **170 checks** (78 proc/task/descriptor/mount checks across
three rounds and root/unprivileged launches, 87 filesystem checks, three real
FUSE client modes, one malformed FUSE option check, and one complete
linux_common unload/reload check). Kernel WITNESS/INVARIANTS reported no
panic, lock-order reversal or non-sleepable-lock diagnostic. ZFS was healthy
and shutdown synchronized all buffers. The long-read fixture now uses 96
mounts to exceed a page with small mount IDs.

The Linux-reference VM passed **30 checks**: 26 proc-view cases, two real FUSE
modes, invalid-option rejection, and the 96-mount long-read fixture. The real
Linux Python/GDB client passed **six checks**, including naming a sibling
thread, task views, descriptor enumeration/fdinfo, and independent reopening
of an unlinked temporary file. Evidence: `registry2/results.json`,
`oracle-complete.console.log`, and `client-registry.console.log` in the
artifact directory. The pinned FUSE cross-build helper also rebuilt cleanly.

The broader regression VM passed **1,184 checks** with the final matching
kernel/modules (`regression-registry-results.json`), including 144 pathname
resolution cases and the native fixtures. All 52 staged standalone payloads
rebuilt without warnings/errors; the expanded filesystem probe was rebuilt
again after enlarging its long-read fixture. `guest-build-hashes.json` records
identical kernel, linux64/common, linprocfs/linsysfs, pseudofs/procfs and ZFS
binaries across focused, broad and Python guest images. `manifest.json`
records the exact evidence; `task.patch` isolates this increment from the
pre-existing shared working tree.

The final source drift audit found only documentation updates within this
work. Concurrent changes by the separate io_uring/squeue owner were preserved
and not investigated or incorporated into the already-built guest images.
The build-time source snapshot and those paths are recorded in the artifacts.

## Production hardening and Electron target (2026-09-22)

See `docs/linuxulator-production-readiness.md` for the findings, exact gates,
known compatibility limits and Electron/native-FreeBSD distinction.

Fixed mount-pointer lifetime during forced unmount, detached descriptor-table
snapshots across exec/exit, a near-OFF_MAX pseudofs read overflow that could
panic, and missing permission/thread-cookie revalidation on already-open
proc symlinks. These are incremental fixes to the ABI-3 implementation.
GENERIC embeds pseudofs, so the kernel itself was rebuilt and tested.

Final artifacts in `/tmp/linuxulator-production-20260922` passed 912 focused
and stress checks across single-CPU and SMT guests, 1,184 broad regressions,
36 Linux-reference checks and six real Linux Python/GDB checks. Matching
kernel/module hashes and source snapshots are recorded. No implementation
drift was found. No host installation, Linux32 work or targeted io_uring tests.

Electron is the requested production application family. Native FreeBSD ports
exist; Linux Electron binaries are a distinct, unqualified target. The local
seccomp filter installation remains unsupported. Do not infer production
Electron support from the procfs/syscall results or a --no-sandbox launch.

## Additional procfs views and hardening (2026-09-23)

See [task links, descriptor state and socket tables](linuxulator-proc-extra.md)
for the Linux64 implementation, lifecycle and VNET tests, snapshot limits, and
remaining compatibility gaps. Artifacts are retained under
`/tmp/linuxulator-proc-extra-20260922`; consult its qualification manifest rather
than treating earlier or intermediate VM runs as final qualification.

## IPC, notifications, network discovery and writable FUSE

See [the four-batch implementation and qualification record](linuxulator-compat-next.md) for the Linux64 additions, reproducible guest fixtures, and remaining gaps.
