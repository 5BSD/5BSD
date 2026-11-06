# Complete original AMD64 ATF C test construction (2026-11-06)

The source-owned native graph builds all eight original top-level C harnesses,
nine detail harnesses and process_helpers/version_helper. All nineteen programs,
two original C source fixtures and both Kyuafiles yield 42 installed records,
matching a fresh sixteen-job original Make control. Directory attributes,
fixture/Kyua bytes and required_programs="cc" metadata match. All nineteen
program dynamic ELF/import/export/NEEDED-order/hardening and split-debug
filename/CRC/DWARF contracts match. Raw executable/DWARF identity and actual
debugger source lookup remain separate gates.

Original WARNS=3, HAVE_CONFIG_H, ATF_BUILD_* and /usr/include metadata definitions
are retained. Private headers, config.h and h_build.h are declared with scoped
visibility. version_helper directly depends on the actual config.h version input;
Make's atf-version side file is a dependency marker, not installed payload or a
replacement source of a hardcoded version. Original bodies, headers, Makefiles,
implementation libraries and providers remain unchanged.

The common test_helpers source is compiled once as a native shared object group
for the two suites, using the original identical effective configuration. An
independent ELF comparison caught that normal lazy archive extraction could omit
the helper when a harness referenced none of its symbols. Original SRCS passes
the object directly even in that case. Native alwayslink preserves this required
object inclusion while retaining shared compilation and original ABI link order.
The comparison was not weakened to ignore the missing imports.

Actual installation-form native and original Make -l output, using explicitly
captured native ATF/libc/libsys DSOs, matches all 214 original registrations and
metadata across seventeen harnesses. The two plain helpers are not counted as
ATF programs. No original body executes in this batch: the single passing Bazel
source-settings helper is not 214 test passes. Compiler/preprocessor/header,
filesystem/process/user and death/exit/timeout tests still require proper declared
execution inputs, expected-result handling and suitable host/guest isolation.

Retained evidence under /usr/obj/usr/src:

- bazel-atf-c-tests-request-r1-20261106: existing format-5 construction request,
  with explicit 2 GiB action-cache idle target and unchanged 10 GiB free reserve.
  This resource choice is not a performance result or hard peak quota.
- bazel-atf-c-tests-native-r1-20261106: retained missing h_build.h sandbox error.
- bazel-atf-c-tests-native-r2-20261106: construction succeeds; independent review
  r1 catches the actual missing imports from lazy helper archive extraction.
- bazel-atf-c-tests-native-r3-20261106: final correct helper inclusion, complete
  installation/source/action and three runtime DSO captures, helper-test receipt.
- bazel-atf-c-tests-make-r1-20261106: independent original Make C/detail subtree,
  staging, recipes and source/environment bindings.
- bazel-atf-c-tests-review-r2-20261106: final 42-record/nineteen-ELF-debug
  comparisons and actual native/Make 214-case metadata inventories.

The existing build-bsd format-5 workflow expresses these targets; frontend C,
schema, signing, stage verification and publication policy do not change. The
manual/plan are updated in the same commit. This closes the initially missing C
declaration root including detail, leaving the ATF parent in that initial list.
Existing partial C++ declarations and nested test-programs still need complete
original traversal/installation qualification; file presence is not closure.

Whole tests-enabled world/pkgbase, normal-system services/VMs, ARM64/RISC-V,
bootstrap/cache/sandbox/reproducibility, CPU/RAM/disk-I/O/footprint and verified
combined publication remain open. No new live DTrace or audit-delivery evidence
is claimed. Make remains production/default, full-tests guards remain, BIP stays
excluded, and no host installation/upgrade/reboot or VM launch occurred.
