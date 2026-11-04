# Cross-platform regular and EFI libsa candidates (2026-11-04)

The original runs began on 2026-11-03. ARM64/RISC-V EFI runs began on
2026-11-04; retained evidence names preserve their actual dates.

## Native inventory and ABI

The regular standalone library now builds from one native inventory on all three
supported architectures. The common compiler option sequences match original
Make after accounting for target ABI options. Architecture selections retain the
x86 hypervisor helper only on AMD64, select the actual libc setjmp assembler on
ARM64/RISC-V, and add RISC-V's four compiler builtins. The exact selected member
order matches each independent Make archive. RISC-V uses rv64imac/lp64 soft-float;
ARM64 retains general-register-only code and reserved x18. Source-only physical
header contexts and machine aliases include the actual cross dependencies.

All three private EFI variants reuse the common source inventory and compile
independent objects, adding the same 69 BearSSL/verifier sources selected by Make.
Explicit platform selections retain short wchar on AMD64/ARM64, ordinary wchar on
RISC-V, and the corresponding EFI machine includes and freestanding CPU ABI.
Common and BearSSL tool-specific flags share one definition; their original
ordered option sequences are preserved. Each variant preserves its firmware,
PCR and verification options, and leaves its regular archive's bytes unchanged. The existing three Rijndael
NDEBUG selections remain per-source; no additional assertion was suppressed.

| Context | Selected objects | Raw allocated bytes/relocations equal Make | Filename-only original compiler controls |
| --- | ---: | ---: | ---: |
| AMD64 regular | 191 | 188 | 3/3 |
| ARM64 regular | 190 | 187 | 3/3 |
| RISC-V regular | 194 | 191 | 3/3 |
| AMD64 EFI | 260 | 257 | 3/3 |
| ARM64 EFI | 259 | 256 | 3/3 |
| RISC-V EFI | 263 | 260 | 3/3 |

All archive orders, external symbol contracts and inspected target ELF ABI
headers agree with the corresponding originals. The three retained differences
per context are lz4, zfs_zstd and md5c assertion filename strings and their
symbolic relocations. Separate original compiler controls explain these without
editing original/native objects or adding production mappings. Full object/debug
bytes and source lookup policy remain open. These are 1,357 object variants of one
standalone library matrix, not 835 newly converted programs or libraries.

## Explicit verifier generation

`//stand/efi/libsaefi:static_archive` aliases the private archive owned by
`stand/libsa`. It depends on the existing declared `secureboot_policy`, public
anchor and verification-certificate label inputs. The policy supplies build UTC,
hashes, signatures, self-test and trust-mode choices. Missing policy is rejected;
there is no implicit clock, certificate discovery, signer inheritance or default
test fixture. The normal format-5 frontend passes these existing source settings.

The shared native header generator now optionally emits `manifests.h` using
`//tools/build/bazel/config:loader_manifest_names`, a space-separated lookup order
defaulting to Make's `manifest ../manifest`. It preserves order and treats names
as data, without a shell. Existing non-standalone consumers keep their original
three outputs. The shared Python generator's multi-hash self-test blank-line
placement was corrected to reproduce the maintained Make recipe exactly.

All three generated Make headers (ta.h, vse.h, manifests.h) now match the closed
reference byte-for-byte. Every private compiler binds the generated configuration
header; vets, vesigned and verify_file bind the appropriate generated data-header
digests. AMD64 compiler/archive output chains cover all 260 objects; the corresponding
ARM64 and RISC-V checks cover all 259 and 263 objects, respectively. The
manifest-name override changes only verify_file.o and the private archive;
restoration reproduces the complete original private archive bytes. Shared
archive bytes remain unchanged. This is component dependency/invalidation
qualification, not complete-system cache or remote-cache qualification.

The qualification explicitly selects the existing development headers-policy
fixture (UTC 1546329600, hash self-tests and no compiled anchors) to exercise the
firmware-database mode. It is not selected as a production default. Framing and
header tests do not verify real firmware certificates, UEFI database behavior,
key rotation or a boot trust chain; those still require complete-loader runtime
and user-authorized VM qualification.

## Correcting the independent Make oracle

The initial isolated EFI reference consumed generated headers from the existing
world object directory before its own generated headers. That could mask a
changed BUILD_UTC or trust input. It was not used for the qualified private
comparison. The maintained install-reference helper now accepts a bounded
`--build-utc` and repeatable `--local-generated-header` basenames. Explicit local
requests place the actual selected component object directory first and require
compiler dependency records to consume those files. No arbitrary Make assignment
interface was added, and SDK/target/compiler identity checks remain intact.

An initial attempt used .OBJDIR expansion in the outer buildenv Make and still
selected old SDK headers. The new audit rejected that reference. The corrected
helper computes the actual isolated component path and the positive reference
passes for all three headers. Its exact helper sources are retained with hashes
matching its receipt, including the earlier implementation before refactoring.

A default post-build check also rejects different local generated-header bytes
shadowed by an SDK object-tree header, even without an explicit local request.
Equivalent SDK aliases are recorded. Explicit local requests require actual local
consumption even for identical bytes; missing/unconsumed requested headers fail.
This check covers top-level generated headers and Make dependency records. It is
not a claim that the Make oracle is a complete hermetic source/input closure.

## Tests and retained evidence

The new `//tools/build/bazel:secureboot_headers_test` runs the existing framing,
policy, deterministic-output and file2c-reference checks as a Bazel test using a
Bazel-built file2c and declared execution/runtime inputs. Its 35 checks include
explicit non-decodable framing fixtures; they do not claim cryptographic
certificate validation. The maintained `install_reference_options_test` passes
14 methods, including stale/default shadow rejection, equivalent alias recording,
strict local consumption and missing/unconsumed header failures. Its existing
metadata-directory checks use a declared native bmake. Bootstrap runtimes remain
SDK-provided and are not thereby qualified as a complete source-built bootstrap.

All evidence is under `/usr/obj/usr/src/`:

- `bazel-libsa-amd64-cross-refactor-r1-20261103`: unchanged shared AMD64 archive
  bytes after architecture refactoring; the pre-existing AMD64 proof remains.
- `bazel-libsa-aarch64-r2-20261103` and `bazel-libsa-riscv64-r1-20261103`:
  native cross archives, captured manual/install records and normal receipts.
- `bazel-libsa-<arch>-review-r1-20261103`,
  `bazel-libsa-<arch>-filename-controls-r1-20261103`, and
  `bazel-libsa-<arch>-action-review-r1-20261103`: actual cross comparison,
  compiler controls, ABI inspection and owned action bindings. Their original
  Make references have the corresponding `-make-r1-20261103` names.
- `bazel-libsa-efi-amd64-make-r3-20261103`: successful controlled Make reference,
  explicit UTC, actual generated-header consumption and retained helper sources.
  Its earlier r1/r2 records remain available as discovery/failed-audit evidence.
- `bazel-libsa-efi-amd64-r2-20261103`,
  `bazel-libsa-efi-amd64-review-r2-20261103`,
  `bazel-libsa-efi-amd64-filename-controls-r1-20261103`, and
  `bazel-libsa-efi-action-review-r1-20261103`: private archive/test results,
  comparison, controls and complete generated-header/compiler/archive bindings.
- `bazel-libsa-efi-amd64-{custom-manifests,restore}-r1-20261103` and
  `bazel-libsa-manifest-invalidation-review-r1-20261103`: one-object invalidation
  and byte restoration. `bazel-libsa-policy-rejection-r1-20261103` records missing
  policy rejection; its failed analysis output is retained separately.
- `bazel-libsa-reference-shadow-regression-r1-20261103`: both default and strict
  audits reject the real shadowed reference and accept the corrected reference.
- `bazel-libsa-helper-tests-{r1,r2}-20261103`: both maintained helper test
  outcomes; revision 2 covers the final reference helper source.

The first ARM64 analysis found a duplicate source-filegroup name for the two
libc assembler owners. Separate architecture names fixed it; the failed r1 and
successful r2 records are retained. No dependency or validation gate was removed.

## Foreign EFI evidence and current SDK refresh

All paths below are under `/usr/obj/usr/src`:

- `bazel-libsa-efi-aarch64-r1-20261104` and
  `bazel-libsa-efi-riscv64-r1-20261104`: successful maintained frontend builds.
- `bazel-libsa-efi-<arch>-review-r1-20261104` and
  `bazel-libsa-efi-<arch>-filename-controls-r1-20261104`: complete ordered member,
  symbol, code/relocation comparisons and the three original compiler controls.
- `bazel-libsa-efi-<arch>-action-review-r1-20261104`: every private compiler output,
  generated header digest/byte comparison, target ELF ABI and final archive input
  binding; each regular archive remains byte-identical to its prior capture.
- The controlled foreign references retain their original
  `bazel-libsa-efi-<arch>-make-r1-20261103` names and local-header audits.

The ARM64 repeat after common flag factoring was rejected before compilation:
`build-runs/20261104T002510Z-12791` records a changed SDK origin,
`amd64.amd64/tmp/usr/include/sys/hypertrace.h`. The concurrent reviewed HyperTrace
merge advanced dev to `a914137016e`; it changed no standalone/Bazel/frontend files.
The successful earlier captures remain evidence for their recorded inputs; this
failed repeat is not a cache-pass claim. Original receipts and SDKs were not
edited, and no SDK input/hash check was removed. Current SDK preparation uses
maintained `libmd-plan.py --sdk-only` and `libmd-stage-tools.py`, retained under
`bazel-libsa-sdk-refresh-r1-20261104`. All three refreshed
`bazel-libsa-efi-<arch>-current-r1-20261104` runs now pass and preserve both archive
byte hashes. The initial native SDK update nevertheless reran all 451 selected
compilers because their toolchain inputs contain both changed system headers.
See [SDK-VERIFICATION-QUALIFICATION.md](SDK-VERIFICATION-QUALIFICATION.md) for the
exact SDKs, preserved failure, bounded full-content verification and open
compiler-input/performance work.

## Frontend and completion gates

The normal maintained build-bsd format-5 path selects the library/generated
labels, all three supported regular/private EFI architectures, and explicit
policy/manifest settings.
No new C switch, publication destination, signing or stage-verification contract
changed. The manual, default/override setting and reference/test helpers are part
of the same source change. All compilation uses sixteen logical CPUs. Make stays
production/default, and BIP remains out of scope.

The selected regular manual remains owned by the common library; EFI has no
separate manual payload. Full directory/mtree/package installation, debug/source
lookup, alternate optional inventories, global-verifier/verification-off variants,
VECTX/pass-manifest selections and IA32 remain open. The selected foreign EFI
archives have actual native compiler/action comparisons, not merely prepared
Make references. Full entry/loader links, boot and filesystem/
crypto runtime, world/rescue/kernel/module completion, reproducible bootstrap,
sandboxing, pkgbase/hardware/combined repository publication and CPU/memory/disk
performance remain required. The broad SDK input/verification issue from Ficl
remains open. No VM, host installation, upgrade or reboot occurred.
