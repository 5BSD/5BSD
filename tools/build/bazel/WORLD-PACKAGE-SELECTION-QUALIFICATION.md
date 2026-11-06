# Selected world package metadata and coverage

## Qualified AMD64 default profile (2026-11-06)

The source-owned world_packages.bzl macro selects package families through typed
source options and target CPU constraints, preserving the maintained packages/
Makefile hierarchy for amd64, arm64 and riscv64. Checked-in native declarations
own all 105 traversal terms, including combined account/compiler/PF options,
optional test families, test-support selection and architecture additions.
Production does not parse or execute Makefiles, scan a staged filesystem or query
the running pkg database. The one-time migration helper/declaration map is retained
as evidence. Retired syscons is unselected because src.opts.mk forces it off and
rejects WITH_SYSCONS; its old family metadata remains directly inspectable.

//packages:world_family_manifests collects selected BsdPackageFamilyInfo providers.
It rejects duplicate family/package names and mixed prefix/version identities,
and declares a catalogue, all selected UCL outputs and family sidecars. The new
//:world_package_reconciliation action consumes that catalogue, every selected UCL
file and the complete world inventory as declared inputs. It rejects any payload
without selected metadata, any empty/directory-only ordinary selected package,
and any installation claim belonging to a metadata-only package. Only explicitly
source-declared metadata-only packages may lack payload. Generated construction
state stays outside ordinary package ownership. There is no basename/path filter,
unknown-file fallback or inferred empty transition package. The report hashes the
catalogue, inventory and every generated UCL manifest.

The final default profile reconciles 177 selected families, 445 manifests,
444 nonempty payload packages, one explicit pf-dev metadata-only transition and
32,517 file/link paths. All seven declared construction files remain accounted
for. Both maintained source_settings_test and the new five-method reconciliation
unit test pass through build-bsd bazel-test. Rejection cases cover unselected
payloads, missing and directory-only ordinary packages and metadata-only packages
claiming files or directories. This checks coverage, not a dependency solver or
complete independent Make world payload equivalence.

## Independent Make selection and metadata

Original Make buildenv controls query the actual packages SUBDIR set and all
relevant effective MK options. The selected family set must match exactly.
Sixteen independent one-job controls generate every explicit .pkgucl target;
full decoded UCL objects must match all native outputs, with no missing/extra
manifests. Source declarations, local/shared UCL, actual include closures,
SDK/tool/ABI files and explicit requests are hash bound and checked unchanged.

- Default: 177 families and all 445 manifests match original Make.
- Tests enabled, split manuals, debug metadata disabled and MAKE disabled:
  233 families and all 492 manifests match original Make.

The second profile qualifies traversal/metadata only; it does not claim a complete
tests-enabled world or global debug-off payload support. The final default gate's
445 manifest hashes equal the complete independently compared default capture.
The SDK interpreter remains a Make-built bootstrap input. Non-AMD64 branches and
additional option combinations still need qualification.

## ATF support/test selection correction

The previous complete world inventory contained /usr/tests/libexec/atf/Kyuafile
owned by tests with TESTS=no and TESTS_SUPPORT=yes. Original libexec/atf/Makefile
unconditionally traversed its tests discovery child, while packages/Makefile
correctly omitted the tests family. The maintained reconciliation function rejects
that entire prior immutable inventory with 'world payload lacks selected package
metadata: tests'. This real counterexample is retained and exercised by the audit.

The source parent now keeps atf-check, atf-pytest-wrapper and atf-sh available as
support tools and traverses the discovery child only when TESTS is enabled. Native
parent manifests and directory selection follow the same condition. Directory
ownership is explicit BsdInstallManifestInfo metadata for this component's actual
installation claims; global mtree remains physical policy. No file is retagged
and no final-inventory filtering is used. The selected default loses exactly the
unwanted Kyuafile, reducing 32,518 previous file/link paths to 32,517.

Fresh independent original Make parent build/install controls pass in both profiles:

- Tests disabled: 32 files/links, three directory claims, 26 exact non-ELF files
  and all 3 selected runtime ELF contracts match.
- Tests enabled: 44 files/links, six directory claims, 38 exact non-ELF files
  and all 3 selected runtime ELF contracts match.

Namespaces, ownership, modes, flags, package tags, actual original hardlink inode
relationships and directory claims agree. Native hardlinks are compared to actual
Make stage inode relationships (METALOG records them as files). Runtime executable
coverage is derived from the independent Make stage, not an assumed count. These
are construction/installation/ELF controls, not execution of every installed body,
raw DWARF equality, kernel/runtime/performance or whole-world Make payload proof.

Discovery retains failed attempts: default native r2 incorrectly selected every
matching global mtree directory, including unrelated test directories; r3 rejected
duplicate explicit directory policy. The final implementation declares each
component directory once through existing installation providers. The two earlier
ATF review attempts incorrectly treated METALOG hardlink encoding and assumed the
runtime executable count; the corrected audit verifies staged inodes and requires
coverage of every actual Make executable. No production fallback or verifier
weakening was introduced to bypass these checks.

## Evidence

Paths below are relative to /usr/obj/usr/src. Reviews retain audit.py, original
commands, decoded documents, inputs and immutable artifact bindings.

- bazel-world-package-reconciliation-default-native-r4-20261106/receipt.json
  SHA256 f6d21a6b35ddf03789e3f8d053636fe5f152aa3a3d772b1f05db760de4db756c
- bazel-world-family-make-review-r1-20261106/review.json
  SHA256 98bb19db39275e77d18e7042c860fef1daed18f59851d00da099cf4328871897
- bazel-world-family-tests-make-review-r1-20261106/review.json
  SHA256 f1cd196d32f5a39c1044c88338b320be3d716d44d1b69db47dbabd122fb41943
- bazel-atf-support-selection-review-r3-20261106/review.json
  SHA256 375e70b92ad586a0d9b3e80bb33651dc968cff7ef2cff973e28ce536f3b06b04
- bazel-atf-support-selection-tests-review-r1-20261106/review.json
  SHA256 3bfa034735d11e3b37584eb89fcab5699d7afcd1f95fa1d1c39f9872b09bccaf
- bazel-atf-support-selection-make-r1-20261106/receipt.json
  SHA256 bfe274c3ef78b686e3eb2e3f59bb72a7336ba58108c7af35849ee7b86c2c7144
- bazel-atf-support-selection-tests-make-r1-20261106/receipt.json
  SHA256 73c81667a4ddf32966fdc081a07e0b147e4ce8b05de16e5f5137b290916b626a
- bazel-atf-support-selection-tests-native-r1-20261106/receipt.json
  SHA256 b737e85a5992fef5c64f33a7f1a7bf5e03688f6787cdbf4f0607baad2caa06ae

Additional inputs/captures:

- bazel-world-package-selection-migration-r1-20261106/{migration.py,declarations.json}
- bazel-world-package-selection-default-{request,native}-r1-20261106
- bazel-world-package-selection-tests-{request,native}-r1-20261106
- bazel-world-package-reconciliation-default-request-r1-20261106/inputs.json
- bazel-world-package-reconciliation-default-native-r1/r2/r3-20261106 (discovery)
- bazel-atf-support-selection-tests-request-r1-20261106/inputs.json
- bazel-atf-support-selection-review-r1/r2-20261106 (incomplete audits)
- Prior rejected complete world: bazel-man-enabled-native-r3-20261106

## Frontend and remaining work

The maintained format-5 build-bsd target/build-setting interface selects both
catalogue and coverage targets and the new test. Its manual is updated; C CLI,
backend dispatch, stage/signing/verification and publication contracts are unchanged.
The normal system backend remains Make. No native package archives, signed bundles,
verified boot, root protection or repository publication were established here.

Next construct actual whole-world pkgbase archives from reconciled providers and
payloads, including pf-dev and the thirteen cross-package hardlinks. Qualify pkg
metadata/content, solver/install behavior, fresh system construction, preservation
of accounts/service data during updates and full base/hardware repository publication.
Keep independent world/kernel/module/debug/cross/runtime/bootstrap/cache/sandbox/
reproducibility/CPU/RAM/disk I/O/footprint gates open. Other components' directory
ownership still needs independent whole-world Make comparison; this ATF check does
not establish it globally. Keep Make production/default and BIP excluded.
No host installation, upgrade or reboot was performed.
