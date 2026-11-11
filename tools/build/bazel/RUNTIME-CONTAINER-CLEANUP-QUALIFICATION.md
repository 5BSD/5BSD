# Runtime-container cleanup qualification

## Confirmed defect

The retained November 7 strict upgrade VM R2 fails with EROFS from unlink/rmdir:
Switchboard swept scratch directories before rc made root writable. A clone of a
running BE contains live scratch directories, so ignoring those errors left
existing entries that fresh-only container creation correctly rejected.

## Implementation (2026-11-11)

Switchboard now prepares runtime storage once, immediately before its first
native launch, including an on-demand provider requested during rc. Normal rc
has made storage writable before these requests. RC compatibility commands do
not trigger native scratch preparation. A request before storage is ready still
fails; there is no remount, temporary-filesystem or permission fallback.

Preparation sweeps old entries and recreates the live-marker directory before
any provider can receive its descriptor. It marks success only after both steps
succeed. Once native services may exist, it never repeats the global sweep.
Per-service stop cleanup remains scoped to that unit's leaf. Creation retains
its existing fresh-only semantics; stale directories are never adopted.

The separate descriptor-based cleanup module checks failures, avoids symlink
traversal and filesystem crossings, and uses an allocated traversal stack so
service-controlled nesting cannot overflow the manager's C stack. Allocation/fd
exhaustion returns an error. Callers must own the namespace against concurrent
mutation. This is runtime lifecycle handling, not BIP or protection from root.

Both maintained Make and native Bazel source/test declarations include the new
module and regressions. Existing format-5 frontend target/test inputs suffice;
no C frontend option/backend change is required. Make stays production/default.

## Evidence and limits

- `bazel-run-cleanup-make-tests-r2-20261111/receipt.json`: all three real host
  ATF cases pass: nested directories/symlink escape protection/fresh replacement,
  actual Capsicum denial followed by retry, and invalid leaf names/idempotence.
- Its `switchboard-build.log` records successful maintained Make compilation and
  linking of the actual traced Switchboard binary, including the cleanup module.
- R1 host tests retain a file-flag setup failure. The final denial test uses real
  Capsicum rights restrictions, requiring neither root nor file-flag changes;
  there is no test skip or fabricated syscall success.
- Native frontend attempt `build-runs/20261111T125603Z-34949` refuses the old SDK
  before compilation because its recorded `tmp/usr/bin/clang` origin is missing.
  No recorded origin, receipt or snapshot was edited to suppress verification.

All evidence paths are below /usr/obj/usr/src. These checks do not establish
native Bazel compilation or a successful upgraded boot. NEXT: recreate explicit
SDK inputs, run the native regressions and production build, then repeat the
complete signed-package VM upgrade with manifest-derived service-health coverage,
rollback, shared-data persistence and unused-BE deletion. Other closeout gates
remain in COMPLETION-PLAN.md. No host installation or reboot was performed.

## SDK prerequisite rebuild

The new source fix is committed as b2e1c8d7e3e. The Make-built executable/test
captures and source hashes are retained in the R2 host-test directory's
`build-review.json` and `captured/`.

SDK preparation also confirms that the current Make world selected a system
compiler wrapper, while the maintained qualification planner requires a genuine
staged Clang executable and resource tree. A proposed path-only input extension
was insufficient and was removed without landing; no planner check or old SDK
receipt was relaxed. Failed preparation logs remain in
`bazel-run-cleanup-sdk-r1-20261111` (the first attempt also correctly refused a
nonfresh output directory). Individually verified bootstrap-tool copies prepared
for that experiment are not used by the running rebuild.

`bazel-closeout-make-toolchain-r1-20261111` retains the command and live build log
for the maintained Make `toolchain` target, using 16 jobs, production malloc and
explicit WITHOUT_SYSTEM_COMPILER/WITHOUT_SYSTEM_LINKER. This rebuilds the staged
compiler, resources and SDK libraries under the standard object root. It does not
install the host or establish native Bazel bootstrap. Once it succeeds, regenerate
the SDK with the maintained planner/materializer, then rerun native tests and the
service-aware upgrade. The toolchain build is still in progress at this update.
