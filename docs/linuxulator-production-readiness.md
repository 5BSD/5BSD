# Linux64 production qualification

Scope: the Linux64 procfs/sysfs, descriptor, mount identity and FUSE changes
tracked in linuxulator-filesystems-handoff.md, plus the existing broad
regression inventory. Linux32 and targeted io_uring/squeue work are excluded.

Status: the hardening qualification below passed. Production readiness is
still open, particularly Electron application and sandbox qualification.
Passing counts alone are not a claim that every Linux workload is supported.

## Hardening findings

1. Descriptor-based mount ID reads lacked vnode locking. A file reference
   keeps the vnode allocation alive but cannot prevent forced-unmount reclaim
   from changing its mount pointer. linux_vnode_mount_id now holds the vnode
   lock and rejects doomed vnodes. Path-based stat already holds its vnode
   locked; mountinfo holds its mount busy.
2. Descriptor snapshots could retain a table detached from the target during
   exec/exit. The snapshot now checks that the target still uses that table
   under the process lock. It also preserves permission errors instead of
   replacing them with ENOENT.
3. Pseudofs read-buffer sizing did not reserve room for its trailing byte in
   the overflow check. Near-OFF_MAX pread could panic the kernel. The guard
   now covers the addition of one, and a native regression requires EINVAL.
4. Reading an already-open proc symlink bypassed the common visibility and
   thread-cookie check. readlink now revalidates these before invoking its
   filler. Tests retain worker fd symlinks through worker exit and require
   subsequent readlinkat to fail.

The near-OFF_MAX test reproduced a panic in an intermediate VM whose GENERIC
kernel still contained the old built-in pseudofs implementation. That image
is rejected. A module-only rebuild is insufficient for this configuration.
All final qualification images must contain the rebuilt kernel itself.

## Qualification gates

- Exact root/unprivileged focused inventory, real libfuse hello modes,
  filesystem/network/jail lifecycle checks and complete module reload.
- Repeated dumpability changes with synchronized target/observer processes;
  fdinfo held through process exit; shared-table exec races.
- Descriptor openat2 traversal restrictions and stale O_PATH thread links.
- Native jail, credential/exec and capability-rights boundaries.
- Near-OFF_MAX pread regression with exact error assertions.
- Forced unmount during live fdinfo/statx, concurrent descriptor/thread churn.
- Linux-reference runs of the same unbranded probe.
- Existing 1,184-case broad regression inventory and real Linux Python client.
- WITNESS/INVARIANTS clean logs, healthy guest ZFS and synchronized poweroff.
- Matching kernel/module hashes and retained source snapshots.

Artifact directory: /tmp/linuxulator-production-20260922. Failed/intermediate
runs remain as evidence; only explicitly listed final runs qualify.

## Supported scope and remaining release work

Known compatibility limits remain: anonymous-pipe reopening through procfs,
deleted-file readlink text after name-cache eviction, anonymous filesystem
mount identities/type-specific fdinfo, and mount-root presentation for
arbitrary chroots/jails. Native SUGID debugging restrictions remain in effect.
Existing proc stat placeholders are not full Linux conformance. FUSE coverage
uses upstream hello, not every daemon or protocol operation.

A production release still needs an identified application/workload matrix,
longer workload-specific soak and resource-growth measurements, and independent
review of the shared pseudofs/VFS changes. These are unfulfilled qualification
gates, not automatic permission requirements. No host installation or release
publication is implied by the VM results. Deploy matching kernel/modules
(pseudofs ABI 3), with the previous matching build available for rollback.

## Electron target

The requested application family is now Electron. Keep two qualification
tracks distinct:

- Native FreeBSD Electron exists in FreeBSD Ports, including the Electron
  dependency used by editors/vscode and textproc/obsidian. This route does
  not test Linuxulator compatibility. Native Node addons also need native
  builds; the existence of the Electron port does not qualify every app.
- Existing Linux Electron binaries require separate Linux64 runtime and
  Chromium subprocess/sandbox validation. No Electron VM execution has been
  completed in this batch. The local linux_seccomp implementation rejects
  filter installation; this must be accounted for before claiming support
  for Linux Chromium's sandbox. A launch with --no-sandbox is not a production
  qualification: Electron documents that switch for testing only.

Suggested application matrix: libuv/Node.js first, then a minimal Electron
BrowserWindow with renderer IPC, then Obsidian and VS Code. Test native and
Linux binaries separately. Include file watching, subprocess/PTY behavior,
renderer crash/restart, shared memory, local storage and database recovery,
TLS/networking, display/input, audio/notifications, and shutdown/resource
cleanup. Signal is a further networking/media target. SQLite, OpenSSL,
GLib/GTK and Qt provide useful independent library coverage.

Sources checked 2026-09-22:

- https://www.electronjs.org/docs/latest/why-electron
- https://www.electronjs.org/docs/latest/tutorial/sandbox
- https://cgit.freebsd.org/ports/tree/editors/vscode/Makefile
- https://cgit.freebsd.org/ports/tree/textproc/obsidian/Makefile
- https://cgit.freebsd.org/ports/commit/?id=6e3c8010515063f2dc420b25910a0ef16fc81ed6
- https://docs.libuv.org/en/v1.x/guide/basics.html

## Final evidence (2026-09-22)

- candidate-smt/results.json and candidate-single/results.json: passed,
  456 checks each (96 proc views, 87 filesystem checks, four FUSE checks,
  one complete common-module reload, 256 concurrent runs, eight forced
  unmounts and four native security/boundary checks). Total: 912.
- regression-candidate-results.json: all 1,184 broad checks passed.
- oracle-candidate.console.log: 36 Linux-reference checks passed, including
  both credential levels, stale thread links and shared-table exec.
- client-candidate.console.log: all six real Linux Python/GDB checks passed.
- guest-build-hashes.json: identical final kernel and relevant modules in
  the focused, regression and application-client images.
- manifest.json, task.patch and source-snapshot/: result inventory,
  isolated changes and source provenance. No implementation drift was found.

All final BSD runs shut down cleanly with healthy ZFS and no matched kernel
diagnostics. Kernel and changed modules compiled with Werror; the three new
or expanded payloads also compiled with warnings treated as errors. Existing
broad-regression payloads were reused from their previous recorded build.
Only amd64 Linux64 and the necessary native security fixtures were exercised.
No host kernel/module installation, Linux32 tests, or targeted io_uring work.

Rejected intermediate runs are retained in logs: final/console.log records
an old built-in-pseudofs panic; release-final/console.log records an overly
strict exec-test scheduling assumption, corrected with explicit synchronization.
Neither contributes to the final passing counts. These checks strengthen the
implemented scope; they do not close the Electron or longer-soak release gates.

## Subsequent component qualification

The 2026-09-23 [IPC/notification/discovery/FUSE handoff](linuxulator-compat-next.md)
records the later kernel fixes, full active native FUSE protocol inventory and
Linux SQLite/IPC/watch workloads. It supersedes the earlier hello-only FUSE
coverage limitation above. Its explicit exclusions and Electron release gates
remain in force; historical test totals in this document describe their own
recorded binaries.
