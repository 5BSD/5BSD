# Native repository discovery checkpoint (2026-11-03)

## Discovery policy and fixes

The first offline repository-wide query failed. Its partial output is retained
at `/usr/obj/usr/src/bazel-python-runtime-audit-r1-20261103`; it is not a
complete inventory. Failures were foreign upstream workspace definitions,
legacy generated-workspace templates, a missing native `cc_library` load in
the vsock device harness, and the tracked absolute `contrib/zsh/Doc/Doc`
symlink pointing back to its containing directory.

`REPO.bazel` now uses Bazel's standard `ignore_directories` API for foreign
workspace/template boundaries. The Fuchsia root license marker remains a
native package; FIDL continues to use the explicit `@fuchsia_runtime_src`
source view. libcbor's example workspace and Googletest's nested upstream
self-test packages assume their own workspace roots. The native libcbor and
Googletest library bindings remain. Legacy `targets/` files remain inputs to
the maintained probe workspace generators, rather than native packages.

This does **not** waive Make-selected Googletest self-tests:
`lib/googletest/tests/{gmock_main,gmock,gtest_main,gtest}` have Make definitions
and still need native Bazel conversion. Their upstream foreign BUILD files do
not establish equivalent 5BSD tests. Keep these in the reconciliation backlog.

The native harness imports `cc_library` explicitly, as required by current
Bazel. The recursive zsh symlink is removed; regular documentation and source
files remain. No executable implementation or test assertion changed.

## Evidence and limits

Both offline `query` commands exit zero in
`/usr/obj/usr/src/bazel-python-runtime-audit-r2-20261103`:

- `declared-graph.stdout`: 97,375 declared rule labels.
- `python-tests.stdout`: 103 Python/host-artifact rules, 67 distinct scripts.
- `source-before.json` / `source-after.json`: unchanged queried BUILD/Starlark,
  module/lock and repository policy inputs during those queries.
- `label-preservation.json`: all previously observed labels outside the
  intentional foreign/template boundaries remain. Fifteen foreign/template
  labels disappeared; the earlier query was partial, so this comparison does
  not establish complete Make coverage.

These are unconfigured graph discovery results. They do not prove dependency
analysis, compilation, runtime behavior, installation, architecture selection,
package completeness, sandboxing or performance. Rule counts include helper,
variant and test rules; do not describe them as unique converted programs.

## Python child-tool runtime review

`python-subprocess-review.json` binds all 67 source hashes and maps them to
actual query owners. A preliminary AST review finds 83 direct subprocess
calls in 44 scripts, with 39 calls lacking an explicit environment. These are
review leads, not 39 proven defects: aliases, helper functions, indirect keyword
arguments and each tool's declared loader requirements need manual review.

The SDK interpreter's `LD_LIBRARY_PATH` currently propagates to child tools.
The LLD regression already demonstrated that this can select an SDK DSO ahead
of a source-built tool's RUNPATH. Existing per-tool explicit environments must
be preserved. Complete the review before changing the common Python runner;
blindly clearing the environment could break tools needing declared SDK DSOs.

## Maintained frontend

The normal format-5 `build-bsd bazel-test` backend now binds `REPO.bazel` in
its input receipt, alongside MODULE and lock files. The maintained 16-job
frontend profile at
`/usr/obj/usr/src/bazel-native-repository-boundary-r1-20261103` passes and its
receipt binds the current repository policy hash. Both LLD tests are cached
passes (zero fresh executions), as confirmed by BEP and Bazel output; this is
frontend/cache integration evidence, not a new linker runtime qualification.
The disk guard retains initial/minimum/final filesystem free space; it is not
a comparative disk-I/O or aggregate-memory benchmark. The C frontend, command-line
interface, staging/signing/publication and manual require no new interface:
this change corrects native package discovery and backend provenance. No secure
boot, signing or compromised-root protection is tested here. Make remains
production/default. Full world/kernel/modules/pkgbase/runtime/performance
qualification remains open.

Reference: https://bazel.build/versions/9.2.0/rules/lib/globals/repo#ignore_directories
