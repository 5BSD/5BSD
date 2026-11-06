# Complete selected AMD64 libm tests (2026-11-06)

## Construction and independent Make control

All 47 original selected libm ATF programs (27 NetBSD and 20 local) now build
through native cc_binary rules with typed installation archives. A fresh original
Make test-component build/stage uses 16 jobs and the unchanged recorded SDK. All
95 installed non-directory records, original directory attributes and exact
Kyuafile bytes match. Every program passes independent ELF contracts including
DT_NEEDED order, imports/exports and symbol versions; native and Make separate
debug filenames/CRCs and DWARF presence verify. Raw ELF/DWARF equality and actual
debugger source lookup are not claimed. Commented-out/otherwise unselected Make
programs are not silently added to the selected inventory.

Native rules retain -fno-builtin, HAVE_FENV_H, __HAVE_LONG_DOUBLE, AMD64
_RENAME_FMA/_RENAME_FMAF and LDBL_PREC=64, with __HAVE_FENV only for fe_round_test.
Warning policy retains WARNS=6 and original unknown/ignored pragma handling.
ilogb2_test uses original local ilogb_test.c; the distinct imported ilogb_test
uses t_ilogb.c. ATF, libm, optional libutil and NetBSD compatibility dependencies
are declared and linked in original order. Local test-utils.h, imported t_libm.h
and fmod's isqemu.h have declared scoped header dependencies; shared test-header
visibility is extended only to this package. No source files or Makefiles change.

A configured-action review verifies all 94 registered regular/PIC compile actions:
source identities, original floating-point definitions, no fast-math/unsafe-math
flags and required private header inputs. Final output-pair review confirms each
source's distinct .o/.pic.o registrations. This is not 94 newly executed compiles,
source-mutation invalidation testing or a bootstrap/sandbox performance result.

## Full selected runtime

Actual native and original Make -l metadata matches for all 463 registered cases.
Each is represented by an explicit source-owned Bazel ATF target, using the native
libc/libsys/ATF/libm runtime and libutil for fenv_test, with the original implicit
300-second deadline. There are no required-user or cleanup cases in this profile.
All 463 original cases execute and pass in native r3 with no skipped or expected-
failure outcomes. The source-settings helper is a separate passing target (464
reported passes total); it is not counted as an original libm case. Final r4
passes all 464 targets as valid cached results after inventory formatting.

The final review binds archive/metadata/directory outputs and all five runtime
DSOs byte-for-byte to the independently compared r2 capture. It checks the final
case map against all original registrations and verifies every captured test
log/XML hash and passing result. No raw mutable bazel-bin output is used as proof.
This closes the selected AMD64 libm suite construction/runtime cohort, not full
system acceptance or every architecture/configuration.

## Failures retained and evidence

Under /usr/obj/usr/src:

- bazel-msun-tests-request-r{1,2}-20261106/inputs.json: explicit construction/full
  runtime format-5 requests; original-inventory.json records original Make queries.
- bazel-msun-tests-native-r1-20261106/: initial analysis rejects missing shared
  NetBSD header visibility. Scoped access corrects the declared dependency.
- bazel-msun-tests-native-r2-20261106/receipt.json: construction and DSOs capture.
- bazel-msun-tests-make-r1-20261106/receipt.json: independent original Make control.
- bazel-msun-tests-review-r1-20261106/review.json: all 47 ELF/debug contracts and
  95 installation records, exact Kyua bytes and directory comparisons.
- bazel-msun-tests-case-inventory-r1-20261106/: first inventory wrongly assumes
  ATF always prints its default timeout. It fails without changing test sources.
- bazel-msun-tests-case-inventory-r2-20261106/review.json: corrected implicit
  deadline handling and all 47/463 actual metadata comparisons.
- bazel-msun-tests-native-r3-20261106/receipt.json: actual 463 case executions,
  plus valid cached source-settings helper.
- bazel-msun-tests-native-r4-20261106/receipt.json: final cache reuse/capture.
- bazel-msun-tests-actions-review-r1-20261106/review.json: declared source/header/
  FP policy of both registered variants; final review verifies their distinct
  output identities in addition to initial action counts.
- bazel-msun-tests-final-review-r1-20261106/review.json: final unchanged artifact
  bindings, complete source-owned case map and all actual/cached case results.

Each review retains its audit script and hashes. Existing build-bsd format-5
inputs already carry the source-owned targets/settings/tests. No frontend C,
schema, stage/signing or publication change is required; the maintained manual,
roadmap and observability ledger are updated in the same commit.

## Architecture and system limits

This suite remains explicitly AMD64 compatible. ARM64/RISC-V have LDBL_PREC=113
and different architecture definitions in original Make; their libm/libc ABI
closure and execution must be qualified before enabling this test graph there.
Several original RISC-V math cases use atf_tc_expect_death. The current Bazel ATF
runner does not support that result form; it must be implemented and qualified
for those cases, not converted to a pass or omitted. No RISC-V runtime acceptance
is claimed by the all-passing AMD64 profile.

The remaining library test parents, full installed-test world, whole-world/kernel/
modules/pkgbase, archive order/debugger/bootstrap/reproducibility/cache/sandbox,
normal service boots, CPU/RAM/disk-I/O/footprint and verified hardware/combined
publication gates remain open. Make remains production/default; BIP excluded.
No VM is launched and no host installation, module load, upgrade or reboot occurs.
