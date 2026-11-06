# Original AMD64 libc test parent and SSP (2026-11-06)

## Complete selected hierarchy construction

The original parent now composes all 22 unconditional Kyua children, conditional
ICONV/locale/SSP children, both TLS helper-library contributions and gen children.
All 31 installation archives build through the maintained frontend. The parent
Kyuafile preserves original Make traversal order; TLS helper libraries do not add
spurious Kyua includes. This is test installation construction, not execution of
every installed case or completion of all base-system tests.

A fresh original Make libc/tests parent builds and stages with 16 jobs and recipe
metadata. Aggregate audit verifies all 870 original non-directory records against
the native installation's 872 records, including permissions/owners/groups/tags,
links, every original directory attribute and collision-free archive composition.
All 106 non-ELF/non-archive payloads match byte for byte, including every Kyuafile,
shell script and fixture. The two extra records are h_raw and its separate debug
file: the native positive Clang profile builds its declared UBSan runtime, while
the original reference's unchanged SDK has no installed UBSan archive and the
original Makefile omits h_raw. This difference is explicit, not full positive-
profile Make parity. A complete original world/control with its sanitizer runtime
staged is still required to compare these two records independently.

Independent ELF review passes for all 375 common executables and five DSOs,
including the original static pututxline contract and installed TLS RPATHs. Every
native and original debug-link filename/CRC and presence of separate DWARF passes.
This does not prove raw ELF/DWARF equality, debugger source lookup or equality of
the two TLS static archives. The positive h_raw debug link is checked separately;
its complete Make ELF comparison remains open.

## SSP source ownership and runtime

All 19 original Clang SSP helper programs, the original shell script and Kyuafile
are constructed. Regular helpers retain global LIBADD=sys and MK_WERROR=no
warning policy. h_raw retains -fstack-protector-all, -Wstack-protector and
-fsanitize=bounds, with native whole-archive UBSan, explicit runtime library
providers and the original sanitizer installation RPATH. It does not search for
a sanitizer archive in the host SDK. The initial link exposed missing unwind
providers; declaring native gcc_s resolves them. No runtime shim or replacement
case is added. The unchanged source script exercises successful calls and actual
faulting children with original expected signal behavior.

All 19 original shell cases pass through Bazel. The source-settings helper also
passes (20 target results, 20 reported passes, no skips/expected failures). Seven
execute in final r2; twelve SSP cases reuse passing first-run results and the
source-settings helper reuses its earlier qualified result. The first build
failure is isolated to the missing h_raw unwinder. These are not twenty original
SSP cases or twenty newly executed tests. Earlier common-helper review independently
matches all eighteen runtime-independent helpers to the older original reference.

The all-disabled parent profile omits ICONV, locales and SSP. Actual original Make
queries with WITHOUT_ICONV/LOCALES/SSP confirm 22 remaining child includes and
matching order. Native parent Kyuafile bytes match that selection; the 28 archives
contain 772 non-directory records and no disabled-root payloads. This does not
qualify every feature combination. The new ssp setting controls test traversal;
whole-toolchain MK_SSP=no semantics remain a separate configuration gate.

## Retained evidence

Under /usr/obj/usr/src:

- bazel-libc-ssp-request-r1-20261106/inputs.json and
  bazel-libc-ssp-native-r{1,2}-20261106/: initial missing-unwinder failure and final
  passing build/case reports with immutable artifact capture.
- bazel-libc-ssp-review-r1-20261106/: eighteen common-helper ELF/debug contracts,
  38 common records and explicit two positive-profile additions.
- bazel-libc-test-parent-request-r{1,2}-20261106/inputs.json: full and all-disabled
  explicit format-5 input profiles.
- bazel-libc-test-parent-native-r{1,2}-20261106/receipt.json: completed aggregate
  captures. Only source-settings is selected as a test in these parent requests.
- bazel-libc-test-parent-make-r1-20261106/receipt.json: fresh original Make parent.
- bazel-libc-test-parent-review-r1-20261106/: retained failed audit rejecting the
  old reference because it predates the committed setjmp pthread Makefile fix.
- bazel-libc-test-parent-review-r2-20261106/review.json: current-source metadata,
  hierarchy and exact data/script/Kyua review.
- bazel-libc-test-parent-elf-review-r1-20261106/review.json: initial audit wrongly
  classifies three unversioned DSOs as executables; 377 other comparisons pass.
- bazel-libc-test-parent-elf-review-r2-20261106/review.json: corrected DSO
  classification, all 380 common ELF/debug contracts pass without verifier changes.
- bazel-libc-test-parent-options-review-r1-20261106/review.json: actual Make
  disabled-option queries and native optional-root absence/traversal review.

Each review retains its audit script and hash-bound inputs/captures. The original
source script and Makefiles are unchanged. An initial Make helper invocation with
a relative component path fails its absolute-path validation before construction;
the completed invocation uses the required absolute component path.

## Integration and remaining gates

Existing build-bsd format-5 targets/settings/tests carry both configurations. No
frontend C/schema, stage/signature or publication change is required; the manual
and roadmap are updated together. Other library/test families and full tests-
enabled world composition remain open, so production-only parent guards stay in
place. Full installed-system/pkgbase, positive sanitizer Make parity, other ABIs,
bootstrap/reproducibility/cache/sandbox, normal services and CPU/RAM/disk-I/O/
footprint/publication qualification remain required. Make remains default. No
host installation, upgrade, reboot, module loading, VM launch or BIP change occurs.
