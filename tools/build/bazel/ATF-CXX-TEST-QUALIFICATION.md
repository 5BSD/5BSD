# Complete original AMD64 ATF C++ test construction (2026-11-06)

## Original construction and native dependencies

The source-owned graph now builds all six top-level and six detail harnesses,
version_helper, both original C++ source fixtures and both original Kyuafiles.
All thirty installed records, recorded directory attributes, exact fixture/Kyua
bytes and required_programs="c++" metadata match a fresh independent sixteen-job
Make control. All thirteen program dynamic ELF/import/export/NEEDED-order/
hardening and native/Make split-debug filename/CRC/DWARF contracts match.
Raw executable/DWARF equality, debugger source lookup and other profiles are not
claimed. All normal installed programs retain no private RPATH.

The graph preserves original GNU++20/WARNS=3 and directory-specific effective
HAVE_CONFIG_H, ATF_INCLUDEDIR, ATF_C_TESTS_BASE and top-level ATF_BUILD_CXX settings.
The shared warning-policy helper accepts GNU++20 explicitly. Actual version
configuration and private test headers are declared, including the original
atf-c/h_build.h fixture. Version_helper retains its plain C++ runtime dependency
set rather than acquiring unused ATF libraries. Native libgcc_s is an explicit
exception-unwinding ABI input; original libc++/libcxxrt/libm/unwinder order is
preserved. The first link failed without _Unwind_Resume; it is not bypassed with
host libraries or disabled exception handling.

Each directory compiles its original test_helpers.cpp once with its own settings.
Program-owned C++ source objects and original direct helper-object inclusion use
native cc_library/CcInfo/alwayslink, with native cc_binary owning final links.
The original source files, Makefiles, implementation libraries and providers are
unchanged. No production graph parses Make to produce sources or recipe actions.

## Three original suites execute

Actual native/Make normal-program listings match all 101 original registrations.
Sixteen original bodies execute and pass: environment four, exceptions three and
text nine. None skips or expects failure. The source-settings helper is one
separate cached pass: seventeen reported passes across four test targets.
Eighty-five original bodies remain unexecuted here, including compiler/header,
filesystem/process and other ATF integration cases.

The three existing qualification labels remain available. Their runtime-only
links reuse the same declared main/helper objects and native dependency sequence
as the normal installed programs. Six actual registered link-action records have
identical input sets, execution platform, configuration and environment. Expanded
arguments differ only in output filename and the private inherited $ORIGIN RPATH.
These are registered action comparisons, not six newly executed links or a cache
performance result. Runtime variants are qualification binaries, not a claim that
normal installed binaries acquire this RPATH or that their raw bytes are equal.

A stricter eight-library loader check initially caught host libsys resolution:
RUNPATH on the runtime executable did not supply a transitive libc dependency.
Only runtime links now use inherited private DT_RPATH. The check remains strict.
Final traces bind native ATF C/C++, libc++, libcxxrt, libm, libgcc_s, libc and
libsys to captured hashes and report no additional loader libraries. The loader
checker executes -l; actual Kyua body runs use the same staged runtime binaries.
Retained SQLite results identify every original case/result, with immutable final
Bazel log/XML bindings and original case inventories.

Runtime suites preserve the original implicit 300-second deadlines with an
adequate outer Bazel timeout. Body runs explicitly set DTRACE_DOF_INIT_DISABLE=1;
the separate loader metadata check retains its own documented PATH/LC environment.
No live provider-firing/audit-delivery evidence follows. The SDK Kyua engine,
host shell/env/loader utilities and host kernel remain execution inputs/limits.
Tests are external/no-remote rather than claimed hermetic bootstrap qualification.

## Evidence

Retained under /usr/obj/usr/src:

- bazel-atf-cxx-tests-request-r{1,2,3}-20261106: existing build-bsd format-5
  construction, explicit native unwinder and three-suite runtime requests.
- bazel-atf-cxx-tests-native-r1-20261106: retained first missing unwind-library
  link failure. After storage cleanup, this also rebuilds native dependencies and
  execution tools; it is not a controlled cold-cache/system performance benchmark.
- bazel-atf-cxx-tests-native-r2-20261106: successful complete construction,
  normal installed artifacts and eight native runtime library captures.
- bazel-atf-cxx-tests-make-r1-20261106: fresh original Make C++/detail control.
- bazel-atf-cxx-tests-review-r1-20261106: thirteen ELF/debug contracts, thirty
  installed records and all 101 actual native/Make registrations.
- bazel-atf-cxx-tests-native-r3-20261106: retained host-libsys loader failure,
  before any of the three original body suites executes in that phase.
- bazel-atf-cxx-tests-native-r4-20261106: corrected inherited runtime RPATH,
  all sixteen bodies pass with named native loader checks.
- bazel-atf-cxx-tests-native-r5-20261106: explicit body DOF environment and
  external/no-remote classification; sixteen original passes.
- bazel-atf-cxx-tests-native-r6-20261106: final original 300-second deadlines,
  all sixteen bodies pass; final captures and test reports.
- bazel-atf-cxx-tests-actions-r2-20261106: six configured normal/runtime link
  actions, identical input sets and exact argument-difference review. r1 used an
  unquoted C++ package name and its query was rejected, without product changes.
- bazel-atf-cxx-tests-final-review-r2-20261106: final artifacts byte-identical
  to the independently compared construction, retained loader receipts and results
  databases/logs, sixteen original case identities and final report bindings.
  Earlier final-review r1 tried writing a derived summary inside copied read-only
  test output; r2 preserves those modes and writes summaries alongside the copies.
- bazel-atf-parent-make-r1-20261106: complete independent tests-enabled original
  Make parent control, prepared for the next ATF parent/nested traversal batch.
  A Make control by itself does not qualify an unimplemented native parent.

## Remaining scope and maintained frontend

The existing format-5 frontend inputs cover these construction and runtime
targets. Frontend C/schema, stage/signing/verification/publication policy do not
change. The maintained manual and plan record actual scope in this commit.
Full ATF parent and nested test-programs declarations still need completion and
independent composition qualification. Full tests-enabled world/pkgbase, normal
service/VM acceptance, ARM64/RISC-V, bootstrap/cache/sandbox/reproducibility,
CPU/RAM/disk-I/O/footprint and verified combined publication remain open. Make
remains production/default; full-tests guards remain; BIP is excluded; no host
installation/upgrade/reboot or VM launch occurs in this batch.
