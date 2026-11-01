# bsdtrace deferred native migration checkpoint

2026-11-01. The user requested a clean committed stopping point for another
host upgrade. Make remains the production/default backend. No qualified
bsdtrace native conversion is claimed. The pending declarations are preserved
as an inert patch; they are not active BUILD files.

## Saved source work

`checkpoints/bsdtrace-20261101.patch` preserves exactly five owned files:

- usr.sbin/bsdtrace/BUILD.bazel: all fourteen maintained C units, original
  library link order, PIE, utility/header/manual/debug and test installation;
- usr.sbin/bsdtrace/tests/BUILD.bazel: unchanged original thirteen-case suite
  installation and eleven safe original ATF execution candidates;
- contrib/processor-trace/BUILD.bazel: original physical source-header context;
- sys/sys/BUILD.bazel and sys/vm/BUILD.bazel: explicit source-tree ABI headers
  discovered from actual fresh Make dependency files.

Patch SHA256: f68ff04ad69c130467501b68060d7afa3ddb881e0e24372763f38eff16068870.
`git apply --check` passed after restoring only these owned files. No C,
header, original test body, timeout or Make source was changed. The source
public intel-pt.h header currently retains version template tokens; Make uses
that original physical source header before the installed/generated header.
The native declaration deliberately preserves that precedence, which still
needs verification from actual native compile actions.

## Completed evidence and retained failures

All evidence paths below are under /usr/obj/usr/src:

- bazel-bsdtrace-make-r1-20261101 was built before the preceding upgrade. Its
  recorded /usr/bin/make hash changed. The explicit failed revalidation is
  bazel-bsdtrace-reference-revalidation-failed-20261101.json. Do not use r1 as
  a current independent reference.
- bazel-bsdtrace-make-r2-20261101/receipt.json passed the maintained
  install-reference.py build/install process with sixteen jobs after that
  upgrade. It contains nine component installation records, including both
  original test files and the public PTWRITE header. Its current-host bindings
  must be revalidated after the next upgrade too.
- bazel-bsdtrace-qualification-r1-20261101 failed before Bazel execution because
  the old SDK's /usr/bin/kyua input changed. Frontend logs remain in
  build-runs/20261101T195116Z-24281. The old immutable SDK was not edited.
- bazel-postupgrade-sdk-20261101 was newly prepared with unchanged maintained
  libmd-plan.py and libmd-stage-tools.py, using standard amd64 objtop/profile
  and the existing explicit bazel-bc-exec-sdk-20261029/tools.json selection.
  Its toolchain-inputs.json and workspace passed all 16,755 hash checks:
  8,382 inputs, 42 host dependencies and 8,331 snapshot files. Target is
  x86_64-unknown-freebsd16.0. Exact preparation commands and receipt hash are
  recorded in postupgrade-verification.json. This verifies a snapshot, not a
  successful Bazel build or a redistributable/hermetic toolchain.
- bazel-bsdtrace-inputs-20261101.json selects that fresh snapshot and thirteen
  explicit targets, including eleven tests.
- bazel-bsdtrace-qualification-r2-20261101 passed SDK preflight and began the
  fresh SDK-bound build closure. It was deliberately canceled with SIGINT to
  the owned Bazel client for the requested upgrade checkpoint. No passed
  qualification receipt, native test result or artifact parity is claimed.
  Full execution/events/stdout/stderr and the normal frontend log in
  build-runs/20261101T195539Z-57230 are retained. The exact owned Bazel server
  was then shut down successfully. No VM was started.

## Resume order

1. Revalidate the actual post-upgrade host/source/toolchain and every bound
   Make/SDK input before reuse. If any changed, create a fresh maintained Make
   reference and a fresh SDK snapshot under /usr/obj; never rewrite the old
   receipt or weaken current-host validation. The saved snapshot predates the
   next requested upgrade and therefore cannot be assumed current.
2. Apply the patch from /usr/src after reviewing current shared header files:
   `git apply --check tools/build/bazel/checkpoints/bsdtrace-20261101.patch`,
   then `git apply tools/build/bazel/checkpoints/bsdtrace-20261101.patch`.
   Resolve real intervening source ownership changes rather than force applying.
3. Select fresh explicit format-5 inputs and a new output directory, using the
   maintained build-bsd bazel-test workflow with all sixteen logical CPUs.
   Complete the program, install archive and all eleven safe original cases.
   Their CLI validation/offline decode paths do not authorize host tracing.
4. Compare immutable receipt/manifest-bound program and installation artifacts
   against the matching fresh Make reference. Check ELF contract and NEEDED
   order, all nine install records, literal manual/header/test payloads, both
   debug CRCs, all fourteen actual compile inputs and the source-header ABI
   precedence. No native parity audit has run at this checkpoint.
5. Keep ptwrite_header_compiles (/usr/include/bsdtrace_ptwrite.h plus cc) and
   meta_unparsable_warns (/boot/kernel/kernel) as explicit disposable-guest
   installed-path gates. Do not consume host installed files as substitutes.
   Hardware tracing, Intel PT/live HWT, cross-userland, package creation,
   publication and controlled CPU/disk/memory performance remain separate work.

The existing format-5 frontend/ATF/install APIs express this candidate without
frontend C or backend changes. This checkpoint updates the maintained README
and manual; it adds no active feature, new build input or policy setting.
