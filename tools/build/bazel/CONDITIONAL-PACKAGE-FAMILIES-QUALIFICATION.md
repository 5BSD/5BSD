# Conditional package-family metadata

## Coverage (2026-11-06)

All 239 existing packages/*/Makefile family owners now have explicit native
bsd_pkg_family declarations. The last seven are bhyve, bootloader, efi-tools,
flua, libcompat, libfidl and sendmail, available through the explicit
//packages:conditional_family_manifests aggregate. This closes declaration
coverage, not selected-world metadata coverage, package archives, installation,
boot, runtime, upgrades, bootstrap or performance qualification. The earlier
static/core/capability aggregates remain direct metadata cohorts. Actual
source-option/architecture package traversal still needs migration and exact
world inventory reconciliation. Some optional metadata can legitimately have
no payload in a different profile; no empty-package fallback is introduced.

Bhyve's ACPI dependency uses the target CPU. Bootloader's debug metadata is
AMD64-specific; flua and bootloader select man versus dev metadata from MAN and
MANSPLITPKG. Sendmail depends on bmake when MAKE is enabled. EFI compatibility
variants are absent because the source forbids LIB32 on supported profiles.
CPU branches beyond AMD64 still need cross-platform qualification.

## Real libcompat source fix

Independent original Make queries showed MANSPLITPKG=yes changed _ALLPACKAGES
from libcompat-dev to libcompat-man alone. The existing independently built Make
library installation METALOG records /usr/lib/libcompat.a with package=libcompat,dev.
Replacing dev therefore drops the static library's package metadata. The Makefile
now appends man to SUBPACKAGES; the native declaration likewise retains dev and
adds man when split. The default behavior is unchanged. The corrected original
Make and native split metadata both include dev and man. Discovery evidence
retains the original Makefile and independently hashed METALOG record. The first
incomplete probe had conflicting WITH/WITHOUT option inputs; the corrected probe
removes the conflicting profile choice and verifies effective MK_MANSPLITPKG.

## Optional FIDL SDK metadata

Typed fidl_sdk selects optional tools metadata and the matching template/license
additions. Typed fidl_python_version and fidl_re2_version have empty defaults and
must be explicitly supplied when SDK metadata is selected. The generic rule maps
declared BuildSettingInfo values to UCL variables, rejects duplicate, reserved,
empty/nonstring or control-character values, and preserves the maintained Lua
parser and scripts. SDK selection here controls metadata only; complete optional
SDK payload production/staging is not qualified by this target.

For the positive control, versions were queried from actual Python 3.12 and RE2
package archives and their FreeBSD:16:amd64 ABI checked against the selected target.
The exact archive paths, hashes and versions are retained in ports-inputs.json;
no installed-host version or invented package version was substituted. Both ports
dependencies retain their unprefixed names and original origins in the UCL.
This is metadata dependency input binding, not signature or repository trust proof.

Native analysis rejects an SDK request missing either Python or RE2 version.
Original Make independently rejects both requests too. The rejection audit checks
nonzero build-finished events and precise diagnostics; these intentionally failed
runs have no passed build receipts and no passed-test claim.

## Qualification

All three corrected AMD64 frontend builds and their maintained source-settings
tests pass with 16 jobs. Original Make controls query exact package coverage and
effective TESTS/MANSPLITPKG/DEBUG_FILES/LLVM_BINUTILS/MAKE/MAN/LIB32 values.
Explicit .pkgucl targets only are generated in isolated objects under /usr/obj;
complete decoded UCL objects match native captured artifacts in every case:

- Default, SDK off, manuals unsplit, debug on, MAKE on: 17 manifests.
- Alternate, SDK on with target versions, manuals split, debug off, MAKE off,
  custom package identity: 17 manifests.
- Minimal, SDK off, MAN/debug/MAKE off: 9 manifests.

All 43 match including scripts, deps, licenses, annotations and suffix semantics.
Local/shared UCL, source declarations, Make includes, selected ports archives,
tools, ABI and requests are hash bound and checked unchanged. Original baseline
environment verification passes before/after each comparison profile. This is
source-family metadata parity, not complete independently built world payload
or installed-system compatibility. The SDK interpreter is still Make-built.

## Evidence

Relative to /usr/obj/usr/src:

- bazel-conditional-package-families-default-native-r1-20261106/receipt.json
  SHA256 0dbfd8aef41d538962f49c08ad111cad716ec82d681b075cfd68e9922397c664
- bazel-conditional-package-families-alternate-native-r1-20261106/receipt.json
  SHA256 2472653f17457b217c5ba79fcbeb69502f87b17b3a73416035959b79b8cc0ab5
- bazel-conditional-package-families-minimal-native-r1-20261106/receipt.json
  SHA256 2ce43c8c785f3bcd327b8e7bf7705bb71515cb49fd9195ea641e94e42edcb8d8
- bazel-conditional-family-make-review-r1-20261106/review.json
  SHA256 95396947e40e45382dff8e4fae4a06a92bcc3075b031f2745a00838af6586031
- bazel-fidl-version-rejection-review-r1-20261106/review.json
  SHA256 adc085ee6bf00043811bae65f03e352b95c5d45c5042c61ca675592e97dfc5bf
- bazel-libcompat-split-discovery-r2-20261106/review.json
  SHA256 f6e38ad46878c1df1aff931ad043ed3c7be490da542344a65e04cfabd62e71a6

- bazel-conditional-package-families-{default,alternate,minimal}-request-r1-20261106/inputs.json
- bazel-conditional-package-families-inputs-r1-20261106/ports-inputs.json
- bazel-conditional-package-families-missing-{python,re2}-{request,native}-r1-20261106

Comparison/rejection audit.py scripts, decoded documents and original commands
are retained with their reviews. The original libcompat source copy is retained
with the corrected discovery. No host installation or publication was performed.

## Frontend and next

Existing format-5 targets/build-settings select the new aggregate and typed flags;
the maintained manual is updated. No C CLI, backend dispatch, stage/signing/
verification or publication interface change is needed. Existing component package
targets remain separate from these family declarations. Next migrate actual
package traversal, reconcile selected metadata with every world inventory bucket
and create actual whole-world pkgbase archives. Preserve all independent
world/kernel/module/debug/cross/runtime/upgrade/bootstrap/cache/sandbox/reproducibility,
CPU/RAM/disk I/O/footprint and combined base/hardware publication gates. Make stays
production/default. BIP remains excluded. No host install, upgrade or reboot.
