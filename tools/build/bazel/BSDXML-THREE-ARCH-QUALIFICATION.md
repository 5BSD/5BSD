# BSD XML library, three-architecture qualification

Selected-default amd64, ARM64 and RISC-V library producers are qualified within the scope below. Make remains the production/default system build; BIP remains excluded.

## Selected production contract

The maintained world selection includes lib/libexpat. Original selected-default Make produces five normal and five small-PIC objects: random_arc4random_buf, xcs, xmlparse, xmlrole and xmltok. The library contributes to runtime, runtime development/debug and the configured manual component. It is not a standalone invented pkgbase family. libarchive and libgeom consume this prerequisite; their complete family and full-world qualification are separate gates.

Source owners are lib/libexpat/BUILD.bazel, installation.bzl and archive-contract-test.py. Runtime C, the existing real parser fixture, generated-header transformation rule, selected SDKs, target ABI definitions and Make production are unchanged. Existing normal build-bsd format5 rules handle all three architectures, artifact tests and installations; this cohort introduces no frontend profile bypass or foreign test execution.

## Measured completed checks

- Three untouched original default Make build/install references and three normal native profiles passed, with fully drained actual compiler/dependency/link captures. Actual production compiler policy and all 1,020 consumed-input pairs match across 30 normal/PIC contexts, including original source versus SDK API origins and explicit SSP flags.
- Both five-member archives per architecture preserve original order. Every native member is digest-bound to its actual compiler output. PIC names use the ordinary native .pic.o convention corresponding to original .pico; no archive-envelope byte-identity claim is implied.
- Nine actual link contracts bind DSO composition and real static/shared parser consumers. The default static CcInfo consumer uses the installable normal archive without whole-archive or garbage collection. The DSO consumes the real PIC archive and preserves SONAME4, ordered NEEDED/import/export/hardening and ARM64 Cortex-A53 link policy.
- Six generated public/external header bodies equal the original Make outputs and are digest-bound to actual parser compilation inputs. These intrinsic template outputs are captured; no spawned generator execution is invented.
- Five actual tests passed: three host artifact tests plus the two existing native static/shared parser tests. Foreign parser binaries are compiled and inspected as data, not executed. Real fixture coverage includes namespace processing, one-byte streaming, internal DTD entities and mismatched-tag errors.
- All 24 original install records match destination, owner/group, mode, flags, tags, type and symlink target. This includes the explicit /usr/lib/debug/lib directory. Public headers and compressed manual bodies equal originals. Native and original debuglink CRC pairs independently validate.

## Untouched-original rejection and independent filename-policy controls

Twenty-four objects match untouched original allocated sections and runtime relocations. The six xmlparse normal/PIC objects embed one different filename: /usr/src/contrib/expat/lib/xmlparse.c in Make and contrib/expat/lib/xmlparse.c natively. The original string section is exactly nine bytes longer; related runtime relocation offsets differ on amd64/ARM64. RISC-V runtime relocations already match. Raw differences remain retained and rejected. Three independent original Make controls append one explicit -fmacro-prefix-map=/usr/src/= flag to recursively expanded CFLAGS, preserving actual -MD/-MF/-MT. All 30 original compiler recipes differ only by that flag and preserve original consumed inputs before/after. All 30 native object allocated sections/runtime relocations and all three complete linked DSO allocated payloads equal those independent controls. The other 24 objects also match untouched originals. No artifact bytes are rewritten.

## Limits

Separate DWARF bytes/source lookup are not equal or qualified. Whole archives, whole packages, installation archive execution, full runtime package composition, foreign execution, alternate selected options/bootstrap, full libarchive/libgeom/world, installation/publication/boot and performance are not claimed. The library manifest has eight records per architecture; this is not a complete runtime or runtime-dev package inventory.

## Retained evidence

`/usr/obj/usr/src/bazel-bsdxml-three-abi-review-r1-20261103/qualification-summary.json` binds the three owner files, all architecture profile/capture receipts, raw rejections, original controls and strict review reports. The original untouched references remain under `bazel-bsdxml-three-abi-original-references-r1-20261103`; filename-policy controls are separately retained under `bazel-bsdxml-filename-original-controls-r1-20261103`. All 30 actual compiler executable digests equal their original before-bound selected compiler bytes.
