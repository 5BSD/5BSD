# Linuxulator QEMU gate

The acceptance contract is
[linuxulator-implementation-gate.md](../../../docs/book/src/compat/linux/overview.md).
The current executable gate covers memfd validation, 64-bit syscall parity,
shared OFD locks on ZFS and tmpfs, future-write seals, and openat2 link,
mount-crossing and scoped-root restrictions, native squeue, Linux io_uring,
and the first shared ring-option batch. It does not certify the remaining
implementation backlog. Run all runtime tests inside disposable VMs; the host
is used only for building artifacts and running QEMU.

`qemu-gate.py` requires an amd64 FreeBSD guest image and a separate disposable
swap disk, and accepts an optional
arm64 image for architecture-specific changes. Every supplied image must boot
from ZFS. The guest verifies that `/` and the primary test directory are on
ZFS, records pool/dataset status, and requires a successful final pool sync and
healthy pool status. A UFS-root run fails the gate. QEMU TCG uses two vCPUs and
a private disk snapshot. The current amd64 inventory includes 1146 repeated
native/Linux option executions, 78 dedicated shared-RWF executions, three native
squeue runs, 477 Linux io_uring cases, 48 direct ABI executions, the syscall/filesystem matrices, and four
direct regression binaries. Missing/duplicate results, timeouts, unsuccessful QEMU
exit, incomplete console markers and recognized kernel fault diagnostics fail
the gate. Keep the full console logs for review of other warnings as well.

## Preparing the images

1. Build kernels with INVARIANTS and WITNESS and matching `linux64`,
   `linux_common`, `zfs`, and `mqueuefs` modules from the current source. Use isolated
   object directories. If reusing build output, verify every source symlink
   and dependency points at the current tree; regenerate dependencies and
   rebuild when it does not. Do not use the host's installed modules.
2. Stage each kernel and its modules under `/boot/kernel` in the corresponding
   architecture's guest root. Record their SHA256 hashes and the source commit,
   exact patch, configuration and build commands.  A direct `make -C
   sys/modules/linux_common` and the top-level tied-module build can produce
   different paths under `MAKEOBJDIRPREFIX`; stage the artifact from the build
   that actually compiled the changed source, then compare its hash with the
   guest's boot log.  A successful build of one path does not update the other.
   For an incremental `linux_common` or `linux64` rebuild against an existing
   guest kernel object directory, pass `KERNBUILDDIR=<kernel-obj>` and an
   isolated `MAKEOBJDIRPREFIX=<module-obj>` to the relevant `make -C
   sys/modules/<module> all`. Both modules must use the matching kernel option
   headers. A standalone module without them can fail to load with an undefined
   `sdt_provider_linuxulator` or omit RACCT accounting against a RACCT kernel,
   causing a thread-exit panic. Verify the module build command, kernel option
   header, staged SHA256 and boot-log hash before interpreting any test result.
3. Cross-compile `tests/sys/kern/linux_abi_gate.c` with:

   ```sh
   clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static \
       -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror \
       -o linux_abi_gate tests/sys/kern/linux_abi_gate.c
   brandelf -t Linux linux_abi_gate
   ```

   Use `--target=aarch64-linux-gnu` for arm64. Stage the matching binary as
   `/root/linux_abi_gate`. On amd64 also compile and brand `linux_fileflags.c`,
   `linux_fileattr.c`, `linux_fchroot.c`, `linux_machdep2.c`, and `linux_openat2.c` using the same flags, and stage the
   resulting binaries under `/root` with those names. Build and brand
   `linux_aio.c` eight times on amd64: with no extra define as
   `/root/linux_aio_full`, and with `-DAIO_CONTEXT_ONLY`,
   `-DAIO_RW_ONLY`, `-DAIO_CAPACITY_ONLY`, `-DAIO_FLAGS_ONLY`,
   `-DAIO_CANCEL_ONLY`, `-DAIO_POLL_ONLY`, and `-DAIO_NOSIGNAL_ONLY` as
   `/root/linux_aio_context`, `/root/linux_aio_rw`,
   `/root/linux_aio_capacity`, `/root/linux_aio_flags`,
   `/root/linux_aio_cancel`, `/root/linux_aio_poll`, and `/root/linux_aio_nosignal`, respectively.
   Compile `linux_aio_signal.c`, `linux_aio_timeout.c`, and
   `linux_aio_counts.c` with the same Linux amd64 flags, and stage them as
   `/root/linux_aio_signal`, `/root/linux_aio_timeout`, and
   `/root/linux_aio_counts`. They test
   signal-mask restoration, Linux's legacy-AIO timeout conversion and
   completion and submission-count boundaries. Add all eleven Linux AIO payloads to
   `METALOG.minimal`; the image builder verifies them. Also build
   `tests/sys/kern/aio_compat_native.c` as a static native FreeBSD binary at
   `/root/aio_compat_native`. The gate runs the AIO payloads three times on
   ZFS and, except the context-only variant, three times on tmpfs.
   Guest hashes cover all eleven AIO binaries before execution.
   On amd64, compile and brand `tests/sys/kern/linux_sysfs.c` as
   `/root/linux_sysfs64`. The x86 `sysfs(2)` gate checks all three
   operations, round-trip enumeration and negative cases three times on
   ZFS and tmpfs. The supported 5BSD kernel has no 32-bit ABI.
4. Stage `guest-gate.sh` as `/root/linuxulator-gate.sh`. Include its required
   tools (`sh`, `mount`, `ifconfig`, `mkdir`, `chmod`, `uname`, `sha256`,
   `kldstat`, `kldload`, `umount`, `wc`, `tr`, `timeout`, `dmesg`, `tail`, and `halt`)
   and their libraries, plus `df`, `zpool` and `zfs`. Supply ZFS root storage and
   tmpfs support. This batch
   uses 4 KiB guest pages; other page configurations require matching tests.
5. Configure the last loader override, typically `/boot/loader.conf.local`,
   with `init_path="/sbin/init"` and
   `init_rc="/root/linuxulator-gate.sh"`. A later Capsule loader configuration
   can otherwise replace init_path and bypass the test script. Use the serial
   console and the correct root partition. Disable unrelated module autoloads
   or stage matching modules. Do not weaken kernel security checks to pass tests.
6. Set `zfs_load="YES"` and `vfs.root.mountfrom="zfs:linuxgate"` in the final
   loader override. Remove UFS-root entries from the guest fstab. Build private
   images with `build-zfs-images.sh AMD64_ROOT ARM64_ROOT NEW_OUTPUT_DIRECTORY`.
   It uses `makefs -t zfs` without importing any pool on the host, amd64
   `gptzfsboot`, and an arm64 FAT32 EFI partition with one sector per cluster.
   The script also creates two 64 MiB disks, `amd64-swap.img` and
   `amd64-swap2.img`, for swap lifecycle and priority tests.
   Every image-build command must succeed.

## Running

```sh
python3 tools/test/linuxulator/qemu-gate.py \
    --amd64-image /tmp/gate/amd64.img \
    --amd64-swap-image /tmp/gate/amd64-swap.img \
    --amd64-swap-image2 /tmp/gate/amd64-swap2.img \
    --arm64-image /tmp/gate/arm64.img \
    --qemu-dir /path/to/qemu/bin \
    --firmware-dir /path/to/qemu/share/qemu \
    --output /tmp/gate/new-results-directory
```

The output directory must not exist. It contains per-architecture serial logs
and `results.json`, including commands, QEMU versions, case results and timing.
The script returns success only when every supplied guest passes. The full
amd64 suite takes over 15 minutes under TCG; the default guest timeout is
1,800 seconds and can be changed with `--timeout`. Runtime dependency
paths for a locally installed QEMU may need to be supplied in the environment.
When unrelated VM automation kills processes by executable name, use the
`--amd64-qemu` and `--arm64-qemu` overrides to select distinctly named private
copies of the QEMU binaries. Verify the copies' hashes against the originals.
Keep firmware and library paths explicit. Do not modify or terminate the other
VM; interrupted gate runs remain failed evidence.

Run portable cases against a Linux kernel too. `memfd_unknown` includes known
but currently unsupported EXEC/NOEXEC flags and `umount_invalid` includes
unsupported lazy-unmount/expiry modes; their Linuxulator rejection assertions
are intentionally not a Linux reference test. Do not execute that unmount case
on a Linux host: it tests flags against `/`. Use disposable VMs for this suite.

The ATF wrapper installs with `/usr/tests/sys/kern` on amd64 and aarch64 and
compiles the same raw Linux syscall test in the guest. The QEMU gate uses
precompiled copies to avoid compiling under TCG. Successful ATF compilation
or host execution alone does not replace either guest run.

## Shared OFD lock gate

The gate also requires `ofd_native` and `ofd_linux`, compiled from
`tests/sys/kern/ofd_lock.c`. Compile the native version for the guest's FreeBSD
architecture. Compile the Linux version with the same freestanding flags as
above, adding `-DLINUX_ABI`, and brand it Linux. Stage both under `/root`.
The native build may use the new source headers before installing them; the
test has fallback command constants for this purpose.

Each of 15 OFD groups runs three times through both APIs on both ZFS and tmpfs:
182 additional results per architecture. The harness checks the complete set
of filesystem/API/round/case tuples, so a skipped filesystem or ABI fails.
The suite covers invalid descriptors and pointers, guarded and read-only
memory, signed range boundaries, lock conversion/splitting, query reporting,
POSIX conflicts, flock independence, dup/fork/exec/SCM_RIGHTS lifetime, blocking
wakeups, signal interruption, killed waiters, owner cycles, and 512 iterations
of descriptor reuse. All OFD groups are safe to run in a disposable Linux
reference guest. The ATF wrapper mounts tmpfs for these tests explicitly.

OFD support is advertised by ZFS, UFS and tmpfs. Other filesystems
return EOPNOTSUPP; neither Linux32 nor those filesystems are certified by this
64-bit gate. Extending filesystem support requires auditing its ADVLOCK
implementation and adding that filesystem to this VM matrix.

Also build `tests/sys/kern/ofd_native_extra.c` with `-pthread` against the
**updated libthr**, and stage it as `/root/ofd_native_extra`. When using an
isolated static library build, ensure `libpthread.a` resolves to that build's
`libthr.a`, and retain a linker map proving which `thr_syscalls.o` was linked.
Simply supplying `-L` for a directory containing only `libthr.a` is insufficient
for `-pthread`. These six additional runs (two filesystems, three rounds)
check Capsicum denial, hidden internal flags, `kern.lockf` reporting, and
16 blocked-thread cancellation/cleanup cycles per run. An older library must
fail this test; a successful kernel-only test cannot certify libc integration.

## Future-write seal gate

Build `tests/sys/kern/memfd_future.c` as native FreeBSD and freestanding Linux
(`-DLINUX_ABI`) for each architecture, and stage `/root/seal_native` and
`/root/seal_linux`. Six common groups plus one native read-only-descriptor
group run three times, adding 39 checks per guest. Tests cover old and new
shared mappings, private copies, mprotect upgrades, write/pwrite/writev,
hole punching and preallocation, pread on memfds, signed range overflow, seal rollback on EBUSY, unknown bits, sealed-seal rejection,
dup/fork lifetime, shrink/grow composition, and 256 mapping/close cycles.
All six common groups also run on the Linux oracle.


## Link-resolution gate

Build `tests/sys/kern/linux_resolve.c` using the freestanding Linux flags above
for each architecture, and stage it as `/root/linux_resolve`. Build and stage
matching `linprocfs`, `fdescfs`, `pseudofs`, `nullfs`, and `autofs` modules (pseudofs/procfs may be
built into the kernel). The guest mounts linprocfs at `/proc` and fdescfs with
`linrdlnk` at `/dev/fd`, then runs 24 groups three times on each of ZFS and tmpfs. Missing mounts,
missing cases and skips fail the QEMU gate. The ATF wrapper requires those
mounts to be preconfigured instead of altering an existing host's mounts.
The nine portable groups also run in a disposable Linux reference VM.
The tenth checks native procfs and fdescfs default, rdlnk, and nodup mounts.
These extra mounts live under `/tmp/resolve-*` in the disposable guests.

Five further groups exercise NO_XDEV with nested tmpfs and nullfs mounts,
magic links, flag combinations, renamed directory descriptors, failed-create
rollback and synchronized concurrent mount/unmount replacement. The Linux
oracle uses bind mounts in place of nullfs. The full matrix therefore requires
144 resolution results per architecture. Guest setup also requires `ln`.

The native-filesystem group also checks legacy union-mount fallback and
uncached autofs lookups. No automount daemon runs in the guest: requesting an
automount instead of returning EXDEV must fail the case's timeout.

Eight IN_ROOT groups additionally check per-call roots, absolute symlinks,
clamped `..`, invalid descriptors/flags/pointers, object-link handling,
nested/bind mounts, renamed roots, fork lifetime, and concurrent ancestor
renames. All 22 portable resolution groups must pass the Linux reference too.
Two remaining groups exercise FreeBSD-specific filesystem variants and ZFS
dataset/clone behavior.

IN_ROOT coverage also includes unprivileged access through held directory
descriptors, denied create/truncate, and unchanged contents after denial.


## ZFS base-system gate

Only ZFS is supported for the base system. Earlier UFS-root logs are historical
supplemental evidence. The current gate requires ZFS root on both architectures
and runs the full OFD and pathname matrix on ZFS and tmpfs. ZFS uses the native
shared lock manager; its OFD capability is explicitly advertised by its module.
The module must be built against the same modified kernel headers.

The `zfs_datasets` group adds dataset-boundary NO_XDEV rejection, IN_ROOT clamping
at dataset roots, readonly-clone create/truncate rejection with no mutation,
and preservation of snapshot contents in clones after the origin is modified.
All fixtures and datasets exist only inside the private QEMU disk snapshots.
This group is FreeBSD/ZFS-specific; the 22 portable resolution groups continue
to use the Linux reference oracle.


## Shared squeue and Linux io_uring gate

Build `squeue_options.c` as native FreeBSD and freestanding Linux with
`-DLINUX_ABI` for each architecture; stage `/root/squeue_options_native` and
`/root/squeue_options_linux`. The current 191 groups run three times through each
API. `eventfd_async_shared` distinguishes inline from worker-origin completion
notification, exercises `IORING_CQ_EVENTFD_DISABLED`, and validates malformed
registration/unregistration plus retained-descriptor lifetime.
`files_v2_shared` validates sparse and tagged registered-file generations,
negative FILES2/UPDATE2 inputs, partial updates, tag CQEs, and delayed generation
release behind fixed-file worker I/O.
`buffers_v2_shared` validates sparse and tagged registered-buffer generations,
negative BUFFERS2/BUFFERS_UPDATE inputs, atomic and partial-update behavior, tag
CQEs, and pinned old-generation release behind fixed-buffer worker I/O.
`clone_buffers_shared` validates task-local registered ring fds and their
enter/register forms, clone metadata and range failures, shared backing with
independent tags, slice/self/replace behavior, closed-fd and task lifetime, and
concurrent cross-ring clone transactions.
`personality_shared` validates credential snapshot identifiers, malformed and
stale identifiers, unregister while worker I/O is pending, process-exit cleanup,
and privileged path access after the submitter drops privilege.
`iowq_controls_shared` validates per-ring bounded/unbounded worker limits,
Linux query/update and copyout ordering, strict queued-pipe serialization, CPU
affinity masks and restoration, invalid/faulting inputs, and idempotent reset.
The separate `kern.squeue.max_workers` boot/runtime tunable provides the hard
system-wide worker-pool ceiling. `register_msg_ring_shared` validates the blind
source-ring-free MSG_DATA registration path, its exact SQE contract, target
errors, CQE flags, faulting/read-only inputs and cleanup.
`enter_no_iowait_shared` verifies the NO_IOWAIT hint alone, with submission and
GETEVENTS, with ignored non-wait arguments, and beside an unknown rejected bit.
`sq_rewind_shared` validates prefix replay without SQ head/tail mutation, count
clamping and preparation-error policy. `extended_layout_shared` wraps SQE128/CQE32 independently, together and with
NO_SQARRAY while checking SQE-extension preservation and zero CQE extensions.
`cqe_mixed_shared` validates ordinary and two-slot completions, exact NOP_CQE32
extension payloads, F_32 selection, SKIP wrap padding, overflow recovery,
fixed-CQE32 behavior, invalid setup combinations and cleanup.
`sqe_mixed_shared` exercises ordinary/128/ordinary submission accounting,
plain-ring NOP128 rejection, fixed SQE128, incomplete pairs, last-slot wrap,
conflicting setup flags and one-entry overflow through both native and Linux
frontends. `sqe_mixed_cmd128` uses a socket command over a mixed ring.
`attach_wq_shared` checks valid non-SQPOLL attachment, source-ring closure,
worker-backed I/O, invalid and wrong-type descriptors through both frontends.
The ten `sqpoll_attach_*_shared` groups cover multi-ring submissions,
source-first and attached-first closure, nested attachment, idle wake and
SQ_WAIT, invalid/stale/wrong-type sources, fork and failed exec, owner exit,
shared worker controls, pending WAITID close/cancellation, and mixed
native/Linux frontend rejection. Each runs
on ZFS and tmpfs in both frontends for three rounds; Linux-relevant contracts
also have a Linux 7.1.5 oracle.
`sqpoll_nonfixed_shared` checks the advertised feature on ordinary and
SQPOLL rings, an ordinary pipe descriptor read, and closed-descriptor failure.
`feature_reg_ring_shared` checks registration through a registered ring fd,
invalid slots, removal and stale-slot errors in both frontends.
The setup matrix also validates COOP_TASKRUN, TASKRUN_FLAG and DEFER_TASKRUN
dependencies plus the observable SQ_TASKRUN transition around worker completion.
Nine portable groups exercise NO_SQARRAY layout and CQSIZE/CLAMP combinations,
wrap, legacy index indirection, invalid setup/mappings, real file I/O, invalid
SQE flags/personality before side effects, linked failure, descriptor churn
fork lifetime, and a separate producer racing slot reuse over 4096 submissions
in both layouts. Run those nine against Linux too. The tenth group requires
ZFS to reject reservation allocation without changing file size or contents.
Native raw mmap calls must use pointer-width returns (`__syscall`, not the
int-returning `syscall` wrapper).

Build and stage `squeue_native.c` as `/root/squeue_native` on both architectures,
using current `sys/io_uring.h` and syscall headers. Each guest runs it three
times. Build `linux_iouring.c` with the freestanding Linux flags and stage it
as `/root/linux_iouring` on each architecture. Its shared `linux_test.h` supplies
architecture-specific syscall entry, numbering, layouts, flags and startup;
the suite uses arm64-compatible *at/pipe2/clone calls and signal return.
The host-side `iouring-cases.json` is the authoritative 475-case inventory:
changing the executable's list requires explicit reconciliation.

The current architecture-neutral gate runs the complete matrix in the amd64
ZFS-root VM. The VM runner allows 180 seconds per squeue case so slow TCG hosts
do not truncate the 4096-submission concurrency stress.  The earlier platform phase qualified amd64 and arm64; rerun arm64
when a change affects its ABI, syscall table, or machine-dependent code.  The
QEMU tooling continues to support both architectures for that purpose.

The network-option portion includes `POLL_FIRST`, ACCEPT and RECV multishot,
RECVMSG multishot output layout, SEND/SEND_ZC vector and fixed-buffer modes,
SEND_ZC usage notifications, SEND/RECV provided-buffer bundles, and registered
provided-buffer rings (kernel-mapped and user-pinned), including incremental
consumption, `min_left`, and `IORING_CQE_F_BUF_MORE`. Bundle
coverage must include ordered buffer IDs, `IORING_CQE_F_MORE` termination,
byte limits, datagram truncation, EAGAIN/cancel/reuse, missing buffer groups,
and invalid opcode/flag combinations. The Linux front end alone advertises
`IORING_FEAT_RECVSEND_BUNDLE`; native squeue shares the buffer-pool machinery
but does not advertise that Linux policy bit. Every `squeue_options` setup
asserts the bit is present under the Linux ABI and absent under the native ABI;
`setup_features` independently checks the Linux io_uring response.
The [feature-flag audit](../../../docs/book/src/compat/linux/io-uring.md)
records the shared SQPOLL_NONFIXED, CQE_SKIP, LINKED_FILE and
REG_REG_RING contracts and their positive/negative VM tests.

The successful reservation-allocation case runs on tmpfs because ZFS explicitly
implements VOP_ALLOCATE as unsupported. This is paired with the required ZFS
negative case through both APIs; the gate does not claim ZFS preallocation.
Every other Linux io_uring case runs in the ZFS test directory. Preserve failed
runs, including test-harness failures, alongside final passing evidence.
These cases certify their assertions, not every option of each advertised
opcode. The next-phase option audit tracks remaining semantic gaps.


Seven additional PROBE groups check front-end-specific advertisement, output
bounds/canaries, every nonzero input byte, count limits and validation order,
invalid descriptors and descriptor types, guard pages, read-only output,
unmapped input, dup/fork/close lifetime, concurrent queries/submissions and
queries after dropping privilege (inside Capsicum for native rings). The
inventory group checks all 65 local opcodes, rejects every unavailable native
operation, and checks that native OPENAT cannot create a file while Linux
OPENAT can. That inventory is BSD-specific; the other six groups run on the
Linux reference, bringing the portable option total to 15. An advertised
opcode is evidence of dispatch availability, not complete option semantics.

## RWF synchronous-write crash gate

The 12 RWF groups run on ZFS and tmpfs for both APIs and architectures. The
portable Linux reference excludes `rwf_unsupported` (BSD's current unsupported
policies) and `rwf_fd_reuse` (the BSD worker's earlier file-reference capture).
These remain mandatory BSD tests.

After the normal gate passes, build separate ZFS images with the same kernel,
modules and option-test binaries, and `init_rc=/root/guest-rwf-durability.sh`
in both `loader.conf` and any overriding `loader.conf.local`.
Stage `guest-rwf-durability.sh` at that path. Run `qemu-rwf-durability.py` with
`--gate-results` naming the normal gate JSON, `--images` naming the separate
image directory, `--qemu-img` naming QEMU's image tool, and a new `--output`
directory. It verifies DSYNC/SYNC data after abruptly killing and rebooting each
private guest overlay. Both architectures must pass. Preserve the console logs,
JSON, overlays and backing-image/source/build hashes with the normal evidence.

## Registered-buffer gate

Fifteen named `buffers_*` groups in `squeue_options.c` are mandatory through
both native and Linux APIs, on ZFS and tmpfs, three times per architecture.
The complete inventory is 98 option groups and 1758 total case runs on each
ZFS-root guest (plus three amd64 regression binaries). `GATE_BUFFER_PAGES`
records the before/after `kern.squeue.wired_pages` values; they must match and
produce `GATE_BUFFER_PAGES_RELEASED`. Successful tmpfs unmount and final ZFS
pool sync/health checks remain mandatory.

The buffer groups cover sparse slots, invalid pointers/counts/lengths, overflow,
read-only and guard pages, partial-registration rollback, flat and vectored
range validation, page boundaries, inline/worker execution, remap and mprotect,
readiness retry across unregister/re-register, closing a descriptor alias during blocked I/O,
child registration and owner exit, private COW across fork (including PROT_NONE
and read-only mappings), overlapping registrations, shared file mappings and
msync, per-uid aggregate limits, linked failure without side effects and
concurrent registration churn and registration racing with mprotect/fork. Every fixed vector uses the selected registered
buffer; another registered slot does not authorize an out-of-range vector.

Use the same freestanding binary on Linux for portable contracts. The
`buffers_async` group asserts BSD's capture-before-submit-return invariant;
Linux can resolve a forced-async request's buffer later. Keep that BSD test
mandatory in both BSD guest APIs, and separate it from the Linux oracle.

Changes to `vm_map_entry` require rebuilding the kernels and all staged
modules, including ZFS; replacing just `linux64.ko` is insufficient. Any panic,
lock-order diagnostic, timeout, missing case, residual page charge or failed
unmount blocks qualification. Diagnostic runs do not replace the complete gate.

## Linked-deadline and cancellation gate

Twenty `links_*` groups run through both APIs on ZFS and tmpfs, three times
per architecture. They cover ordinary and expired absolute deadlines, each
clock selector, successful predecessors, hard links, deferred-chain preparation,
malformed fields and inaccessible timestamps, rollback without writes, target
cancellation, timeout-removal scope, duplicate keys, cancel-all counts, queued
and active workers, raw/fixed-file/fixed-buffer I/O, descriptor reuse and poll
fanout, completion/cancellation/expiry races, last-close cleanup, killed waiters
and exit with unread completions. Timestamp tests include guard-page crossings,
unmapped and protected memory, read-only input, and every unsupported flag bit.

`kern.squeue.live_requests` counts allocated requests, including unissued linked
successors. The gate requires `GATE_REQUESTS options 0 0` and
`GATE_REQUESTS final 0 0`, in addition to the registered-page check and
`GATE_FINAL_PAGES 0 0` after the older regression suites. This catches
chain and deadline leaks that a successful CQE or zero page count would miss.
All existing io_uring groups remain mandatory; cancel-all counts matches,
LINK_TIMEOUT receives a valid timestamp, and parked data I/O uses ASYNC_CANCEL.

Race assertions permit documented competing outcomes, while requiring exactly
one terminal completion for each request, no unauthorized I/O and continued
ring progress. Linux can accept two cancellation requests before delivering one
terminal target completion; success of a cancellation request is not permission
to free a still-owned worker request. Keep failed baselines and diagnostic logs,
and re-run both full gates and the matching crash/reboot gate before qualification.

The `links_queue_isolation` group specifically fills the eight-worker BSD pool
and requires cancellation of a queued ninth operation without waiting for
unrelated I/O. It is mandatory through both BSD APIs; Linux may start that
request in a larger pool, so it is excluded from the portable Linux comparison.


## Setup, issuer and restriction gate

The 22 `setup_*` groups run through both APIs, three rounds on ZFS and tmpfs.
They cover disabled rings, transactional restrictions, required/allowed SQE
flags, operation/register denial, fixed-file use, soft/hard linked rollback,
single-issuer fork/thread/exec/exit behavior, competing enable/install calls,
and submission stop/continue boundaries with and without SUBMIT_ALL.

Build native `squeue_options.c` with `-pthread` (and `-static` for the staged
standalone guest payload); the native ownership cases create real pthreads.
Linux payloads remain freestanding and use raw clone/exit with shared process
resources. The Linux parent waits for the thread tid to disappear before
releasing its stack. No runtime tests belong on the host.

`GATE_ISSUERS options 0 0 0 0` and `GATE_ISSUERS final 0 0 0 0` are mandatory.
They report before/after ring identity references followed by before/after
live identity tokens. The bounded 15-second cleanup allowance includes the
periodic thread reaper. Existing request/page checks remain mandatory.
Missing, duplicate or nonzero issuer markers fail the gate.

See the implementation gate for exact contract names and remaining boundaries:
passing SUBMIT_ALL cases does not certify every opcode-specific preparation,
reserved field or error-precedence combination.


## Registered-file gate

The twelve `files_*` groups cover ring-reference rejection, sparse/SKIP slots,
partial updates and rollback, copy faults, invalid fields and submission counts,
raw-fd lifetime, fixed lookup/update/unregister races, access rights and process
exit. They run both APIs on ZFS and tmpfs for three rounds. The native Capsicum
case includes an ioctl whitelist so capability copying exercises its allocating
path; the Linux variant checks descriptor access mode instead.

`GATE_FILES options 0 0` and `GATE_FILES final 0 0` require the registered-file
reference count to return to zero. Existing resource checks remain mandatory.
Non-sleepable-lock allocation diagnostics fail the controller even when every
case marker reports success. See the implementation gate for retained old-kernel
panic reproductions and exact partial-update semantics.

## Fallocate mode parity

Linux `IORING_OP_FALLOCATE` uses the same Linuxulator kernel helper as direct
`fallocate(2)`, after each ABI wrapper decodes its own arguments. Mode zero
and PUNCH_HOLE|KEEP_SIZE are supported; the remaining known modes return
EOPNOTSUPP. Run `fallocate`, `fallocate_mode`, and
`fallocate_modes_invalid` on tmpfs inside the ZFS-root guest because ZFS
intentionally rejects reservation allocation. On amd64, also stage and run the
freestanding `linux_fallocate` regression. The final qualified evidence is
`/tmp/linuxulator-gate-20260917/fallocate-full-run2/results.json`.

## Linux64 rseq gate

The freestanding `linux_rseq.c`, `linux_rseq_signal.c`,
`linux_rseq_threads.c`, `linux_rseq_lifecycle.c`, `linux_rseq_auxv.c`,
`linux_rseq_preempt.c`, and `linux_rseq_hold.c` probes run three times
each on ZFS and tmpfs in the disposable two-vCPU amd64 ZFS-root VM. The runner requires all 42 exit-zero markers, together
with the existing regression matrix and zero recognized diagnostics.
The registration test checks length, alignment, pointer, flag, duplicate and
unregister errors. The signal test exercises abort-IP redirection, forced
migration, alternate signal stacks, `SA_RESTART`, pending signals, bad
critical-section descriptors including length overflow and abort-IP bounds,
and unmapped registration memory. The thread and lifecycle probes cover concurrent `mm_cid`, fork, failed and successful
exec. The auxiliary-vector probe requires feature size 28 and alignment 32,
then registers with the advertised allocation contract. The preemption probe
runs a busy peer on the same CPU and requires at least one critical-section
abort across 128 yields, with no lost or duplicate completion. The hold
probe keeps a registered Linux process alive while the guest verifies that
`linux64.ko` refuses unload with EBUSY and remains loaded. Compile the
auxiliary-vector probe with
Build all seven probes with the freestanding Linux amd64 flags above and
`brandelf -t Linux`; add `-DEXPECT_RSEQ_FEATURE_SIZE=28` when building
`linux_rseq_auxv.c` for the BSD guest.

The registration, signal, thread, lifecycle, auxiliary-vector and same-CPU
preemption probes also passed the pinned Linux 6.18.35 reference VM.
The unload check is BSD guest specific.
`docs/book/src/compat/linux/syscalls.md` tracks the remaining descriptor
copyin and unregister-race stress qualification. Linux32 and arm64 rseq
remain ENOSYS; the ELF auxiliary vector advertises these fields only for
Linux64 amd64.

## Linux64 remap_file_pages gate

Stage the freestanding `linux_remap_file_pages.c` amd64 probe as
`/root/linux_remap_file_pages`, brand it Linux, and include it in the staged
root manifest. The amd64 guest gate runs it three times on ZFS and three
times on tmpfs; each run requires exit zero. The QEMU parser requires exactly
those six results alongside the existing regression matrix. Use the kernel
and `zfs.ko`, `linux64.ko`, and `linux_common.ko` built from the same current
source and kernel configuration. The passing run is recorded in
`docs/book/src/compat/linux/syscalls.md`.

## Linux64 ioperm gate

Stage the branded freestanding Linux amd64 `linux_ioperm.c` probe and the
static native amd64 `ioperm_native.c` probe in the manifest. The guest runs
each three times on ZFS and three times on tmpfs; the runner requires all
twelve results and the rest of the full regression matrix. See
`docs/book/src/compat/linux/syscalls.md` for the reference oracle, tested
cases and final QEMU result.

## Linux64 iopl option gate

Stage the branded freestanding `linux_iopl_options.c` amd64 probe in the
manifest. The guest runs it three times on ZFS and three times on tmpfs; the
runner requires all six results and the full regression matrix. The pinned
Linux reference result and final QEMU evidence are in
`docs/book/src/compat/linux/syscalls.md`.

## Linux64 modify_ldt gate

Stage the branded freestanding amd64 `linux_modify_ldt.c` probe in the
manifest. The guest runs it three times on ZFS and three times on tmpfs; the
runner requires all six results and the full regression matrix. It covers
read, default-table read, modern and legacy write, clear, high entry, fork
and negative ABI cases. The Linux reference and final VM results are in
`docs/book/src/compat/linux/syscalls.md`.

## Linux swapoff gate

Stage the freestanding `tests/sys/kern/linux_swapoff.c` probe as
`/root/linux_swapoff`, brand it Linux, and include it in the staged ZFS image
manifest. Attach a separate 64 MiB raw virtio disk using
`--amd64-swap-image`; the runner uses QEMU snapshot mode, so repeated VM
runs begin with an unchanged backing disk. The guest gate checks positive
activation/deactivation and negative errno/privilege behavior on each of six
runs. The pinned Linux oracle and supported subset are documented in
[linuxulator-swapoff-implementation.md](../../../docs/book/src/compat/linux/syscalls.md).

## Linux swapon flag gate

Stage and Linux-brand `tests/sys/kern/linux_swapon_flags.c` as
`/root/linux_swapon_flags`. The guest runs it three times each from ZFS and
tmpfs against the same disposable second virtio disk and requires a separate
`GATE_SWAPON_FLAGS` result row for each run. Its supported subset and flag-validation behavior are documented in
[linuxulator-swapon-flags.md](../../../docs/book/src/compat/linux/syscalls.md).

## Linux swap priority gate

Stage and Linux-brand both builds of `tests/sys/kern/linux_swapon_priority.c`:
`/root/linux_swapon_priority` and a `-DSWAP_CLEANUP` build as
`/root/linux_swapon_priority_cleanup`. Include `awk` and `swapinfo` in the
image manifest. The guest mounts linprocfs, activates two disposable swap
disks, checks reported priorities, and reserves 4 MiB through `mdconfig` to
verify allocation to the higher-priority disk. The strict gate requires three
ZFS and three tmpfs repetitions, followed by clean swap deactivation.

## Linux swap discard gate

Stage two Linux-branded freestanding builds of
`tests/sys/kern/linux_swapon_discard.c`: the default probe as
`/root/linux_swapon_discard` and a `-DDISCARD_PAGES_ONLY` build as
`/root/linux_swapon_discard_pages`. The third disposable virtio disk is
attached with `discard=unmap`. The guest checks five Linux flag combinations,
negative policy cases, per-swap discard counters, and page-free deletion using
a swap-backed `mdconfig` device. The runner requires six successful results
across ZFS and tmpfs; see
[the swap discard contract](../../../docs/book/src/compat/linux/syscalls.md).

## unshare path-state subset

On amd64 build `tests/sys/kern/linux_unshare.c` with the freestanding Linux
flags above and `-DUNSHARE_BSD_SUBSET`, brand it Linux, and stage it as
`/root/linux_unshare` with a `METALOG.minimal` entry. The full gate requires
66 executions: eleven supported-contract/rejection cases, three rounds each on
ZFS and tmpfs. Build without that define for the complete Linux reference
matrix. Some reference cases describe future functionality and intentionally
cannot pass on BSD yet. See [the contract](../../../docs/book/src/compat/linux/syscalls.md).

Also build `linux_unshare_capmode.c` as static native `unshare_capmode`, and
with the Linux freestanding flags plus `-DLINUX_PROBE` as
`unshare_capmode_probe`. Brand the probe Linux. Stage both in `/root` and
add both to `METALOG.minimal`. The gate runs the native tracer three times
to verify capability-mode rejection without requiring the Linux tracee to
make further syscalls after entering capability mode.

## amd64 quota subset

Build `tests/sys/kern/linux_quota.c` with the freestanding Linux flags and
`-DQUOTA_BSD_SUBSET` as `linux_quota`. Without that define it supplies the
Linux reference matrix. Build `linux_quota_native.c` and the native branch of
`linux_quota_capmode.c` with `clang -static -O2 -Wall -Wextra -Werror` as
`quota_native` and `quota_capmode`. Build the latter source with Linux flags
and `-DLINUX_PROBE` as `quota_capmode_probe`, and again with
`-DLINUX_PROBE -DQUOTA_SYSCALL=179` as `quota_capmode_path_probe`.
Brand the three Linux binaries with `brandelf -t Linux`.

Stage all five binaries plus `guest-quota.sh` in `/root`, with manifest
entries. Stage the matching kernel, `linux64.ko`, `linux_common.ko` and
`zfs.ko`; the new VFS operation consumes a reserved slot. The guest script
upgrades only its disposable pool, creates a separate ZFS dataset, and removes
it after 33 named quota executions, six capability checks, three native
interoperability/permission groups and five filesystem checks. This must
never be run against the host pool. The full runner requires all 47 results.
See [the quota contract](../../../docs/book/src/compat/linux/syscalls.md) for limitations.

## amd64 ptrace register options

The gate requires `linux_ptrace_registers`, `ptrace_native`, `ptrace_capmode`,
`ptrace_capmode_probe` and `guest-ptrace.sh` in `/root`. Build the Linux register
probe from `tests/sys/kern/linux_ptrace_registers.c` with the existing
freestanding amd64 flags. Build `linux_ptrace_native.c` and
`linux_ptrace_capmode.c` as static native binaries with warnings as errors.
Build the capmode source again with the Linux freestanding flags and
`-DLINUX_PROBE` for `ptrace_capmode_probe`. Brand both Linux executables Linux.

The guest script runs 21 Linux cases in three rounds, three native regressions
and three capmode checks (69 total). It copies the register probe to `/tmp`
so its unprivileged exec test can traverse the path. The amd64 runner uses
QEMU `-cpu max` to exercise XSAVE and AVX; the separate `no_xsave` case must
also run in a disposable guest without XSAVE. No Linux32 support is claimed.
The exact contracts, limitations and artifact paths are recorded in
[the ptrace register implementation](../../../docs/book/src/compat/linux/sandboxing.md).

### Linux64 debugger and socket-cookie follow-ups

The amd64 gate additionally requires `linux_ptrace_lifecycle`,
`linux_ptrace_user`, `linux_ptrace_metadata`, `linux_ptrace_sigmask`,
`linux_proc_task`, `linux_ptrace_kill_native`, `linux_socket_cookie`,
`cookie_caps`, `cookie_caps_probe`, and `guest-cookie.sh` in `/root`.
Build the freestanding Linux tests with the same Linux64 flags as
`linux_ptrace_registers` above. Build `linux_ptrace_kill_native.c` and
`linux_socket_cookie_caps.c` as static native binaries with warnings as errors;
build the latter again with the Linux64 flags and `-DLINUX_PROBE` for
`cookie_caps_probe`. Brand only the Linux ELF payloads as Linux.

Rebuild and stage matching `pseudofs.ko` and `linprocfs.ko`: debugger task paths
require the PID-named pseudofs node. `guest-ptrace.sh` temporarily mounts
linprocfs at `/proc`, tests it, and unmounts before the later lookup suite.
The parser requires 90 ptrace records and 24 socket-cookie records, including
native descriptor-right checks. The optional GDB 16.3 smoke test uses a
separate image with its Linux userland; do not add that userland to the full
gate, whose pathname tests assume the baseline filesystem.

Contracts and evidence: [debugger options](../../../docs/book/src/compat/linux/sandboxing.md)
and [socket cookie](../../../docs/book/src/compat/linux/syscalls.md).

### Linux64 XSAVE writes and multicast filters

Stage `linux_ptrace_xstate`, `linux_mcast_filter`, `mcast_native`, and
`guest-xstate-mcast.sh` in `/root`, with METALOG entries. Build the first two
from their namesake files in `tests/sys/kern` using the freestanding Linux64
flags above and brand them Linux. Build `linux_mcast_native.c` with native
`cc -static -O2 -Wall -Wextra -Werror -I/usr/src/sys`. Rebuild and stage the
kernel and linux64 module: the native multicast membership structures change.

The parser requires 42 XSAVE, 84 multicast and three native result records.
The amd64 runner supplies a restricted virtio Ethernet interface; the guest
uses 10.0.2.15 and fd00::1 on vtnet0 for deterministic local packet-filter tests.
It runs root/unprivileged matrices three times. The native tracer tests removed
GETSOCKOPT/SETSOCKOPT rights and capability-mode rejection across Linux exec.
Run `linux_ptrace_xstate no_xsave` separately with XSAVE/AVX disabled; the normal
matrix needs `-cpu max`. See [the contract and evidence](../../../docs/book/src/compat/linux/syscalls.md).

### Linux64 peer names and process ptrace events

Stage `linux_socket_peername`, `linux_ptrace_events`, `peer_caps`,
`peer_caps_probe`, `ptrace_exit_native`, and `guest-peer-events.sh` in `/root`.
Build the first two from their namesake sources with the freestanding Linux64
flags and build `linux_socket_peername_caps.c` both native and with
`-DLINUX_PROBE` as above. Build `ptrace_exit_native.c` native with `-I/usr/src/sys`.
Brand only the Linux binaries. Stage matching kernel, linux64 and linux_common
modules; native tracing gains the opt-in PTRACE_EXIT event.

The parser requires 42 peer-name cases, 60 process-event cases, three native
capability checks and three native exit-event checks. Multicast now includes
mixed full-state/delta updates, duplicate removal with packet delivery, and
shared-descriptor concurrent updates. Process ptrace events do not provide
complete Linux thread tracing. See [contracts and VM evidence](../../../docs/book/src/compat/linux/syscalls.md).

### Pending signals, tracing reattach and multicast mode transitions

Build `linux_ptrace_pending` from `tests/sys/kern/linux_ptrace_pending.c` with
freestanding Linux64 flags and brand it Linux. Rebuild `linux_mcast_filter` and
native `mcast_native`. Stage them and `guest-signal-modes.sh` in `/root`, adding
METALOG entries. Rebuild the kernel and linux64 module together: Linux option
cleanup uses the new native `process_ptrace` relationship event.

For this batch, use an isolated init script that sets up devfs, loopback and
Linux64, then invokes `guest-ptrace.sh`, `guest-cookie.sh`,
`guest-xstate-mcast.sh`, `guest-peer-events.sh`, and `guest-signal-modes.sh` in
that order, failing on any nonzero exit. The multicast script configures
vtnet0. Require `zpool status -x` to report `all pools are healthy`, emit
`SIGNAL_MODES_REGRESSION_DONE`, and power off with `/sbin/halt -p`.

`qemu-signal-modes.py --image IMAGE --qemu QEMU --firmware-dir DIRECTORY
--output RESULTS` runs that private image with two amd64 vCPUs, 1 GiB RAM,
TCG `-cpu max` and a snapshot disk. It requires exactly 405 named successful
records, suite completion markers, pool health, clean power-off and no
recognized kernel diagnostics. It does not run io_uring/squeue suites or need
swap test disks. See [the contract and evidence](../../../docs/book/src/compat/linux/sandboxing.md).

### Linux compatibility filesystem probes

`linux_filesystems.c` is a freestanding amd64 Linux64 guest probe. Compile with
`clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static
-fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror`. Compile the native
VNET fixture `linux_filesystems_jail.c` with `cc -static -O2 -Wall -Wextra
-Werror -I/usr/src/sys`. Install the Linux-branded probe as
`/root/linux_filesystems`, the native fixture as `/root/fsjail`, and
`guest-filesystems.sh` in a disposable BSD image. Use a matching guest kernel
and modules (`linux64`, `linux_common`, `linprocfs`, `linsysfs`, and the storage
modules used by that image). Never run the probes or load modules on the host.

The guest init script brings up loopback, makes `/tmp` writable, loads Linux64,
and mounts linprocfs at `/proc` and linsysfs at `/sys`, then runs
`guest-filesystems.sh`. It must stop on failure. The script emits exactly:

- 60 ABI execution records: three rounds of 16 root and four unprivileged
  cases, including inode/byte limits, parser boundaries, guarded-page faults,
  bind/remount behavior, permissions, short reads/seeks, large mount tables,
  concurrent mounts, CPU information and all exported network counters.
- 21 interface lifecycle records: down/up, rename, old-name disappearance,
  removal, concurrent reads/removal, and host visibility after jail teardown.
  Churn must observe both present and absent states.
- Three VNET jail records: host-only interface hidden, jail loopback usable,
  and root/unprivileged Linux network/counter access.
- Three filesystem module unload/reload records with Linux mount/CPU/network
  probes after each cycle.

After success, init unmounts `/sys` and `/proc`, performs `zpool sync` and
`zpool status -x`, prints `FILESYSTEMS_DONE`, then calls `halt -p`.
`qemu-filesystems.py --image IMAGE --qemu QEMU --firmware-dir DIR --output DIR`
validates the exact inventory, pool health and clean shutdown and rejects
kernel diagnostics or timeouts. `--cpus` selects the vCPU count (default 2).
Supply the QEMU runtime-library environment required by the local setup.

The Linux-reference run executes the same 16 root and four unprivileged cases
using the unbranded binary. Linux dummy interfaces provide the corresponding
up/down/rename/removal/churn fixture. VNET jail tests are BSD-specific.
No io_uring or squeue suites are invoked. See
`docs/book/src/compat/linux/procfs-sysfs.md` for evidence and remaining gaps.

`filesystems-client.py` supplies a real Linux Python smoke test through the
existing Linux GDB runtime: run GDB in batch mode with
`-ex 'python exec(open("/root/filesystems-client.py").read())'` in the guest
with Linux `/proc` and `/sys` mounted. Require all three `PYTHON_FS_*_PASS`
markers and a zero GDB exit status. It mounts only a disposable guest tmpfs.

## Linux64 procfs and CPU topology

Build `tests/sys/kern/linux_proc_views.c` with the freestanding amd64 Linux
flags above, brand the BSD guest copy, and stage it as `/root/proc_views`.
Keep an unbranded copy for the Linux-reference guest. Stage the existing
filesystem probe, native VNET fixture and `guest-filesystems.sh` as described
in the filesystem section. Use `guest-proc-views.sh` as the disposable guest's
init script. It includes native procfs/fdescfs checks and the filesystem suite.
The kernel and all pseudofs consumers must be rebuilt together: pseudofs now
requires module ABI version 3. Stage matching linux64, linux_common, linprocfs,
linsysfs, procfs, pseudofs and ZFS modules; built-in filesystems are supported.

Run each layout using the same image with QEMU snapshot mode:

```sh
python3 tools/test/linuxulator/qemu-proc-views.py --image guest.img \
    --output results-smt --topology 4,sockets=1,cores=2,threads=2
python3 tools/test/linuxulator/qemu-proc-views.py --image guest.img \
    --output results-packages --topology 2,sockets=2,cores=1,threads=1
python3 tools/test/linuxulator/qemu-proc-views.py --image guest.img \
    --output results-single --topology 1,sockets=1,cores=1,threads=1
```

The controller checks the exact 96 proc/topology and 87 filesystem records,
three FUSE client records plus its malformed-option check,
and unloading/reloading linux_common,
native/reload markers, kernel diagnostics, healthy ZFS and clean shutdown.
The default Intel CPU model exposes SMT topology to the native kernel; custom
QEMU and firmware paths can be supplied. The single-CPU startup path reports
the documented unknown/default topology IDs with singleton sibling masks.
`proc-views-client.py` adds a real Linux Python thread/discovery/descriptor smoke test and
can execute after `filesystems-client.py` in Linux GDB's embedded Python.

For broad regression staging, compile `linux_quota.c` with
`-DQUOTA_BSD_SUBSET` and `linux_unshare.c` with `-DUNSHARE_BSD_SUBSET` to include
the BSD rejection checks used by their guest scripts. The `linux_fallocate`
probe's `unsupported_reservation` case checks ZFS's deliberate EOPNOTSUPP;
run its positive preallocation tests on tmpfs.

The procfs probe now also covers writable process/thread names, task file
views, scheduling/signal fields, descriptor enumeration and reuse, fdinfo,
independent reopening of regular/deleted files, mount identity agreement with
statx, and nested/bind mount parents. Unprivileged runs drop credentials and
then exec the probe: FreeBSD deliberately prevents cross-process debugging
immediately after a credential change, even after PR_SET_DUMPABLE(1).

The guest init also requires `/root/guest-fuse.sh`, `/root/fuse-hello`, and a
matching `fusefs.ko`. Build the upstream libfuse 3.18.3 Linux64 hello daemon on
the BSD build host with pinned inputs:

```sh
sh tools/test/linuxulator/build-fuse-client.sh /tmp/linux-fuse-client
```

Brand only the BSD guest copy of `fuse-hello`, and stage it at the path above.
The helper cross-compiles; it never runs the daemon on the host. The guest
checks real mount/read/readdir/seek/ENOENT/unmount behavior with default
options, `default_permissions` and `allow_other`, plus rejection of an unknown
bare mount option. This qualifies the hello workload, not arbitrary FUSE
filesystems or every protocol operation.

Descriptor limitations: anonymous pipes cannot yet be reopened through
procfs; deleted-file readlink text can fail when the native name cache no
longer retains a pathname, although reopening the held regular-file vnode
works. Basic fdinfo uses mount ID zero for objects without a vnode; dedicated
anonymous-filesystem IDs and type-specific records remain separate work.

The long mountinfo-read fixture creates 96 mounts so that output exceeds one
page even with short legacy mount IDs. `guest-proc-views.sh` explicitly loads
linux_common before linux64 so that the final unload/reload sequence has an
owned module reference. The final check exercises registry destruction,
reinitialization and unmount cleanup; it requires `COMMON_RELOAD_PASS`.

### Procfs security and lifetime qualification

The focused inventory now has 96 proc-view executions. It also tests repeated
changes to dumpability, process exit with an open fdinfo file, exec while a
shared descriptor table is inspected, stale thread symlinks retained with
O_PATH, and openat2 restrictions on descriptor magic links.

For the extended BSD-only qualification, build and stage these additional
payloads (never execute them on the host):

```sh
clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -static \
    -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror \
    tests/sys/kern/linux_proc_lifetime.c -o /tmp/proc_lifetime
cc -static -O2 -Wall -Wextra -Werror \
    tests/sys/kern/linux_proc_native.c -o /tmp/proc_native
```

Brand only the BSD copy of proc_lifetime as Linux. Stage the payloads as
/root/proc_lifetime and /root/proc_native, and stage guest-proc-stress.sh as
/root/guest-proc-stress.sh. The guest init runs this extension when that
script is present. Pass `--stress --timeout 1800` to qemu-proc-views.py to
require all 256 concurrent test records, eight forced-unmount records and
four native security/boundary markers. The controller stops and fails early
on kernel diagnostic matches, including a panic stopped in DDB.

The extension checks jail isolation, access after credential changes and exec,
capability-limited descriptor reopening, near-OFF_MAX reads, and forced tmpfs
unmount during fdinfo/statx calls. Concurrent workers repeatedly exercise
thread exit, descriptor close/reuse, dumpability changes and file reopening.
Run both single-CPU and SMP images; keep kernel/module hashes with the logs.
GENERIC includes pseudofs in the kernel: replacing pseudofs.ko alone does
not apply a pseudofs fix to that configuration. Rebuild the kernel itself.

Passing these gates qualifies the listed behavior. It does not establish
compatibility with arbitrary production applications or complete Linux
procfs/FUSE semantics; see docs/book/src/compat/linux/overview.md.

The procfs extension suite now includes `tasklinks`, `fdextra`, `fdscale` and
`sockettables`. Build `tests/sys/kern/linux_proc_net_jail.c` as a native static
**guest** executable and stage it as `/root/proc_net_jail` for `--stress` runs.
The stress inventory requires three `PROC_NET_JAIL` passes and eight rounds of
eight cases, four iterations each, as both root and unprivileged users, plus
64 `PROC_EXEC_STRESS` passes.
See `docs/book/src/compat/linux/procfs-sysfs.md` for semantics and remaining limits.

## IPC, notifications, network discovery and writable FUSE

See [the four-batch implementation and qualification record](../../../docs/book/src/compat/linux/overview.md) for the Linux64 additions, reproducible guest fixtures, and remaining gaps.

## Linux64 UNIX socket diagnostics

Build `linux_unix_diag` with `build-unix-diag.sh <musl-sysroot> <output>` and brand
the FreeBSD guest copy as Linux. Stage it with native-exec, jail/jexec, the Linux64
modules, and `guest-unix-diag.sh`. Run `qemu-unix-diag.py --image <image> --output
<directory> --cpus 1` and again with `--cpus 4`, using disposable images only.
The validator requires the complete 90-case host/jail/VNET inventory, both UID
visibility checks, 18 socket-churn markers, clean shutdown and no kernel
invariant/WITNESS failures. The probe checks exact queries, stale cookies,
malformed requests, state filters, abstract binary names, pathname metadata,
queued and accepted peers, queue lengths, memory attributes and shutdown state.

## Linux64 kernel device events

Build the Linux probe with `build-kobject-uevent.sh <musl-sysroot> <output>`.
Build `tests/sys/kern/linux_uevent_jail.c` with the native C compiler and stage
it as `/root/uevent-jail`; stage the Linux probe as
`/root/kobject-uevent-linux`. Use `guest-kobject-uevent.sh` as the disposable
VM's init script. The guest needs matching kernel/Linux64 modules, ifconfig,
kldload/kldunload/kldstat, sysctl, mount, timeout and ZFS tools.

Run `qemu-kobject-uevent.py --image <image> --output <results> --cpus 1`, then
repeat with `--cpus 4`. Custom QEMU installations can use `--qemu` and
`--firmware-dir`; the controller inherits library settings from its environment.
It always uses snapshot disks and restricted guest networking.

The required inventory is 19 cases: four raw/datagram and root/unprivileged
combinations, ten host/jail/VNET isolation cases, two overflow/recovery cases,
two invalid-native-name cases, and one live-socket module reload case. It also
requires twelve add/move/remove packet records, unchanged socket counts,
healthy ZFS, clean shutdown and no invariant or WITNESS failure. The tests check
kernel credentials, truncated control buffers, whole datagram consumption,
subscription changes, sequence numbers across reload, class/subsystem symlinks,
and agreement between packet properties and the device's sysfs uevent file.

**Run only in disposable VMs.** The native fixture creates interfaces and jails
and unloads/reloads the compatibility modules. This batch supplies actual network
device events. PCI/DRM hotplug, user-injected events, and the userspace libudev
relay are separate contracts. See
[the qualification record](../../../docs/book/src/compat/linux/overview.md).
