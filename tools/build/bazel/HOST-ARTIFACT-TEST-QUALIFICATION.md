# Host artifact tests for kernel target profiles

## Contract and integration (2026-11-02)

bsd_host_artifact_test is an explicit source-reviewed test contract: its Python
script inspects target files and does not execute target programs, kernels or
modules. Its interpreter, Python home and runtime use config.exec("test"). Its
own test execution group selects the prepared FreeBSD execution SDK; kernel ABI
constraints remain on the ordinary data/artifact dependencies. Ordinary
bsd_python_test behavior is preserved. No global test-toolchain constraint or
legacy-test flag is disabled.

This follows Bazel's documented separation of test execution platforms and
execution groups: [test execution platform](https://bazel.build/versions/9.2.0/reference/test-encyclopedia#execution-platform),
[execution groups](https://bazel.build/extending/exec-groups). The local Bazel9.3.1
toolchain failure before the explicit group was added is retained as evidence;
registering a kernel target platform as an execution platform would wrongly imply
that kernel-target programs were runnable on the host.

The maintained build-bsd format-5 backend queries the configured test inventory
before executing tests. A kernel profile requires the explicit artifact-test
provider on every compatible test. A second configured query covers all selected
targets, so placing an unmarked test in targets while omitting it from tests cannot
bypass the guard. Selected compatible tests must equal the explicit requested
inventory. Disabled members remain recorded, and an empty compatible inventory
cannot pass. Receipts identify test_execution=host-artifacts and bind the complete
selected-test inventory capture. This is an execution/build contract for reviewed
source, not a security boundary against malicious build rules or test scripts.

No new CLI/config field is needed. The existing build-bsd binary invokes the
maintained backend; its C option parser and Make backend entry targets need no
change. The maintained manual documents the contract and its limits.

## Qualification evidence

All paths below are under /usr/obj/usr/src.

- bazel-broadcom-modules-ctf-debug-native-r6-20261102 and
  bazel-broadcom-modules-plain-native-r3-20261102 each pass the two registered
  provider tests on actual target artifacts. Both profiles use the kernel compiler
  platform and report host-artifacts execution. One test checks the real exported
  modules; the other proves the local-provider defect using an intentionally
  localized real BCMA artifact and its actual dependent consumer.
- bazel-host-artifact-frontend-tests-native-r2-20261102 runs the normal userland
  source_settings_test and source_test_inventory_test targets, covering 28 unit
  methods. They retain scalar/label/platform/log-format validation, configured
  compatibility, suite/result completeness, duplicate rejection and the new
  artifact-contract/selected-target checks.
- bazel-host-artifact-rejection-native-r1-20261102 rejects an ordinary unmarked
  kernel-profile Python test before execution. Its command receipt contains only
  cquery, not bazel test.
- bazel-host-artifact-unlisted-rejection-native-r1-20261102 rejects an unmarked
  test selected alongside a marked test but omitted from the requested test list.
  Both preflight queries ran; no bazel test command ran. The observer records this
  expected rejection separately from passing-build receipts.

Earlier Broadcom r2 rejects the old blanket artifacts-only guard, r3 exposes the
default test-toolchain mismatch, and r5 records an observer/backend local-variable
collision after actions completed. Those runs are rejected and retained. The
final r6/full plain/unit/negative profiles above establish the corrected result;
no historical receipt is relabeled.

## Limits

These are host-side static artifact tests. They establish no kernel boot, module
loading, target-program runtime, cross-target runtime, performance or complete
module dependency closure. The provider test reports external imports separately;
it only rejects a supplied provider whose required definition was localized.
Make remains production/default and BIP remains out of scope.
