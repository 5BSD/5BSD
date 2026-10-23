# FIDL / IPC work: what is left (2026-10-22 22:00 UTC)

Read `/home/koryheard/AGENTS.md` first (build in /usr/obj, all CPUs, never
install or reboot the host, publish only through the maintained /usr/src
package targets).  Then `HANDOFF.md`, `DAEMONS.md`, `BENCH.md`,
`VALIDATION.json` and `lib/libfidl/MATURITY` for history and evidence.

Branch: `dev` in `/usr/src`, shared with other agents whose work is
uncommitted in the same tree.  Stage paths explicitly, never a directory.
Never run `git reset` in the shared tree: a `git reset -q` racing another
agent's commit moved HEAD backwards once on 2026-10-22 (recovered with
`git update-ref`).  Verify a patch with `git apply --check`, or against a
throwaway index (`GIT_INDEX_FILE=/tmp/x git read-tree HEAD; GIT_INDEX_FILE=/tmp/x
git apply --cached --check PATCH`).

## State on 2026-10-22

Committed on dev:

- `330b8dd0dd2` libchannel: one allocation per queued message, bounded
  request freelist, `channel_outgoing_reserve/commit/abort` send buffers,
  `channel_get_stats`, `channel_call_request`/`channel_call` with fallback.
- `9cfc0f21749` libfidl: bounded per-connection slabs, encoding into the
  reserved send buffer, `fidl_bsd_fd_owned` (moved C descriptors),
  `fidl_bsd_connection_call`/`Connection::CallSync`, 53-scenario `ipc_bench`
  with JSON output and ktrace syscall counts, `check-bench-compare`.
- `2ee2c71c7a4` kernel: `MAC_CAPABILITY_CHANNEL_CALL` (send, sleep for the
  reply token, receive in one system call; late reply discarded after
  timeout; `MAC_CAPABILITY_INFO_F_CHANNEL_CALL` in GETINFO).
- `b5bf397ad30` schemas `@available(platform="bsd", added=1)` compiled at
  `FIDL_AVAILABLE` (default `bsd:1`); system.Network.PF served as
  `NetworkPf` with `networkcmp_pf_open(3)`; `pf_protocol.h` retired;
  records refreshed.

Measured (details and commands in `BENCH.md`; baseline
`/usr/obj/5bsd-fidl-bench/20261022T182557Z-baseline.json`):

| metric | before | after |
|---|---|---|
| client syscalls per synchronous call | 4.0 (Oct 7 host kernel), 2.0 (new kernel, split path) | 1.02 (VM run1, new kernel) |
| FIDL C heap allocations per call, client/server | 0 / 2 | 0 / 0 |
| FIDL C++ 8-byte round trip | 0 / 1 | 0 / 0 |
| client allocations per 1,000-event burst | 1,000 | 0.01 |
| C borrowed descriptor, client syscalls each | 6 | unchanged on kernels without SENDMSG_V2; one send with `fidl_bsd_fd_owned` on V2 kernels (VM proof pending) |

Latency columns are not comparable yet: every after-run was taken at host
load 25-49 or under TCG.  Evidence: `/usr/obj/5bsd-fidl-vm/run1` (kernel
call, libchannel, libfidl, switchboard, BSDTime) and `pf1` (PF and the
migrated daemons), both 4-vCPU plane-on VMs with the new kernel;
`PLANEON_GATE_PASS`, lifecycle checks and every libchannel, libfidl and
`pf_test` case passed.  Failures in those runs belong to other agents'
same-day uncommitted work: `bundle_test:*security_contract` in BSDCrypto,
BSDLog and BSDNetwork (audit client API renamed, source-grep tests not
updated), `BSDExtension/startup_test` timeouts, `switchboard/crypto_config_test`;
`lib/libchannel/ipc_soak_test "Invalid test program format"` was a staging
artifact (raw `.sh` copied over the atf-sh program), not a build defect.

## What is next, in priority order

1. **Prove the committed tree alone.**  A clean `buildworld buildkernel` of
   HEAD `b5bf397ad30` runs in the detached worktree
   `/usr/obj/5bsd-fidl-headcheck` (objects under
   `/usr/obj/5bsd-fidl-headcheck-obj`, log
   `/usr/obj/5bsd-fidl-headcheck-build.log`).  When it passes, restage from
   it into an empty directory and run `vm-provider.sh` with `vm-daemons.sh`
   (CPUS=4) for `lib/libchannel lib/libfidl usr.sbin/switchboard
   usr.sbin/BSDTime usr.sbin/BSDNetwork`; record the run in
   `VALIDATION.json`.  Until then the VM evidence above was built from a
   working tree that also carried other agents' changes.
2. **Latency on a quiet host and on a CHANNEL_CALL kernel.**  Run
   `make -C tools/build/fuchsia check-bench` with no other builds running
   and compare against the baseline; the host kernel (Oct 7) lacks the
   ioctl and SENDMSG_V2, so the one-syscall path and the descriptor-move
   savings only show after the host runs a current kernel.  Installing and
   rebooting is the user's decision.  Re-take the baseline on that kernel.
3. **Lease check in the call ioctl.**  Another agent's uncommitted
   cap_authority lease work adds `cap_authority_lease_valid()` checks to
   the receive loop; `mac_capability_instance_do_channel_call`'s wait loop
   needs the same check (it was in the working tree and deliberately left
   out of the HEAD-based patch).  Add it in the same commit as the lease
   work.
4. **PF consumers.**  Rebuild `sysutils/5bsd-instruments` against the new
   world (its distfiles were absent on the build host, GitHub assets 404);
   the port patch in `/usr/obj/5BSD-ports` is edited but not committed.  A
   pre-conversion Instruments speaks `PFS1`, which the provider now
   rejects.  Add a `system.Network.PF` case to
   `usr.sbin/switchboard/tests/service_reachability_test.sh`.
5. **Remaining FIDL C++ allocations.**  Natural types copy string and
   vector payloads (256-byte string: 2 client allocations; ceiling-size
   vector: 3 allocations, 43 KB per call).  Options: generate wire-domain
   views over the receive buffer for the C++ adapters, or an arena
   allocator for natural types; measure with `roundtrip-256` and
   `large-14304`.
6. **Typed descriptor schema library (needs the user's go-ahead).**  Only
   NONE, SOCKET and CHANNEL handle subtypes exist, because
   `mac_capability_fd_spec` knows those types.  Proposed: a `bsd` library
   with its own resource definition, an ObjType enum and Rights bits named
   after Capsicum rights, mapped FILE (VNODE), MEMORY (SHM), PIPE
   (PIPE/FIFO), SEMAPHORE (SEM), PROCESS (PROCDESC), DEVICE (DEV), EVENT
   (EVENTFD), TIMER (TIMERFD), CAPABILITY (non-channel MAC_CAPABILITY),
   JAIL, DATASET (ZFSHANDLE), ENVIRONMENT (ENVFD); kqueue stays unpassable
   (FreeBSD `DFLAG_PASSABLE`).  Touches the kernel type check,
   libchannel, `ValidateDescriptor`, the generators and tests.  MEMORY is
   the one with a consumer today (BSDLog's shared-memory ring).
7. **Build-time message size check.**  The generators read
   `type_shape_v2`; reject a protocol whose maximum message exceeds 14,336
   bytes or 32 descriptors at generation instead of at the first large
   reply.
8. **Schema ABI gate at publication.**  Wire `contrib/fuchsia/tools/fidl/
   fidl_api_summarize` and `fidl_api_diff` into `publish-packages` (and the
   `build-bsd` verification stage and manual) to compare each `bsd.*`
   schema with the one in the last published repository; an incompatible
   change fails publication.
9. **Persistent encoding.**  Standalone value encoding entry points in C
   and C++ so on-disk state uses the validated codec.
10. **Protocol documentation.**  Run the imported `fidldoc` into
    `docs/book` so protocol reference pages come from the schemas.
11. **BSDBluetooth.**  Isolate the plane/controller code its test matrix
    compiles directly, then convert ATTACH and Controller (last
    record-protocol provider).
12. **Rust runtime bindings.**  Deferred by the user; the generator builds.
13. **Latency records** for VM, Namespace, Extension and Filesystem
    (`latency_bench` exists; no record-protocol comparison was run).
14. **Package republication** stays a user-held release step: `latest`
    points at `16.snap20261012080606.complete` while newer complete
    snapshots exist (AGENTS.md targets, `PORTSDIR=/usr/obj/5BSD-ports`).

## Pitfalls

- Never `git reset` in the shared tree (see top).  Stage explicit paths;
  files such as `mac_capability_dev.c` and `networkcmp.c` carry several
  agents' hunks at once, so split them with a patch against HEAD.
- Restage into an empty directory every time (NO_ROOT METALOG appends).
  Do not copy raw `.sh` tests into a stage; `ATF_TESTS_SH` programs are
  rewritten with the `atf-sh` shebang by the build.
- `lib/libchannel/tests` links the in-tree libc (pthread): on an older host
  kernel it dies with SIGSYS on `cap_clofork_limit`; run it on a matching
  kernel (VM).
- Under ASan `cap_ioctls_get` reports an implausible count; both libchannel
  probes now treat counts above 256 as unrestricted.  Keep that when
  touching them.
- Incremental world can keep stale objects; if C tests SIGBUS, suspect
  stale objects.  Other agents build in the same /usr/obj world objdir.
- Run heavy builds and VMs one at a time (an earlier host hard reset).
- Plane-off VM runs: `PLANE_OFF=1`; build `mac_capability_test_kernelstore`
  from `tests/sys/mac_capability/fixtures`, ship it with `EXTRA_DIR` and
  set `MAC_CAPABILITY_FIXTURE_DIR`.
- Pre-existing, not FIDL: logctl_test `unavailable`/`severity_names` fail
  in any plane-on VM; BSDNetwork resolves `localhost` only if BSDFilesystem
  served /etc/hosts when it started.

## History

2026-10-09/10: import, native backend, BSDTime migration, maturity gates
(`cf97f876797`, `9ec24a62c93`, `58977d8dfd1`; HANDOFF.md, VALIDATION.json).
2026-10-11/12: nine daemons converted (`fidl/daemons`, DAEMONS.md), then
VM, Namespace, Extension and Filesystem.  2026-10-22: performance items,
versioning, PF (above).  Earlier versions of this file (git log) hold the
step-by-step instructions those phases used.
