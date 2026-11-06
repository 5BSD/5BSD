# Static package-family declarations

## Scope (2026-11-06)

The explicit //packages:static_family_manifests aggregate adds all 208 remaining
families with static Make metadata. Together with the previously qualified 24,
232 of 239 package family directories now have native source-owned family rules.
Seven conditional owners remain: bhyve, bootloader, efi-tools, flua, libcompat,
libfidl and sendmail. These counts are family declarations, not created archives
or complete world metadata selection. Direct aggregate requests include families
regardless of optional world traversal; actual source-option/architecture traversal
must still be migrated and reconciled with complete world inventory.

The migration used a one-time, strict authoring helper that accepted only static
assignments from the original family Makefiles and rejected conditional owners.
The resulting BUILD declarations own all names, templates/overrides, subpackages,
sets, licenses/license logic, explicit dependencies and metadata-only properties.
No Makefile parser, Make query, generated BUILD or hidden Make build is used by
production metadata actions. The authoring script and original declaration map
are retained as migration evidence under /usr/obj. Existing component package
targets remain separate and are not requalified by the new family targets.

The pf-dev transition is explicitly marked metadata-only; this metadata marker
does not yet create that archive. libcompiler_rt has no base package and produces
its declared dev metadata. Includes remain declared Bazel action inputs.
Userland lib32 metadata is not emitted because the source opts forbid LIB32.

## Qualification

Both native aggregate builds and the maintained source-settings test pass through
build-bsd bazel-test with 16 jobs and the existing format-5 input contract.
Original Make buildenv controls evaluate every original family and effective
MK_TESTS/MK_MANSPLITPKG/MK_DEBUG_FILES/MK_LLVM_BINUTILS/MK_LIB32 values. The audit
uses 16 independent one-job Make controls, explicit .pkgucl targets only, and
isolated object directories under /usr/obj. No all, stagepackages or publication
target is invoked. Every native manifest is resolved in a hash-verified batch
from the immutable qualification capture. Every original target is accounted for,
with no extra native outputs accepted. Full decoded UCL objects compare equal:

- Default (tests off, split manuals off, debug on, LLVM binutils on): 489 manifests.
- Alternate (tests on, split manuals on, debug off, LLVM binutils off): 429 manifests,
  with explicit OrgBSD prefix and alternative maintainer/website settings.

All 918 match including scripts, deps, annotations, licenses and suffix semantics.
The audit binds local component inputs, all shared UCL templates, actual Make
include closures, native rule/configuration, selected ABI/tool files and requests;
inputs are checked unchanged after comparison. The buildenv baseline is verified
before and after each profile. Commands, decoded documents and the exact audit
script are retained. Raw UCL byte ordering is not asserted identical.

## Evidence

Paths are relative to /usr/obj/usr/src:

- bazel-static-package-families-default-native-r1-20261106/receipt.json
  SHA256 2b0eca2e3d1a05176159759f77b57efc4a6c7a936cc518ae6aace76833c9391e
- bazel-static-package-families-alternate-native-r1-20261106/receipt.json
  SHA256 26322b4bb69403204ad70ad6f9187712ee4d9b50bd2197e1ffff8d5b74b6dbe0
- bazel-static-family-make-review-r1-20261106/review.json
  SHA256 ab2ad600197e092db23fc0ba828b753b85d98fab127441539c01ff9e6817dfb2

- bazel-static-package-families-migration-r1-20261106/{migration.py,declarations.json}
- bazel-static-package-families-default-request-r1-20261106/inputs.json
- bazel-static-package-families-alternate-request-r1-20261106/inputs.json

## Frontend and remaining gates

Existing format-5 targets/build-settings select the aggregate; the maintained
manual describes it. No C frontend, backend dispatch, stage/signing/verification
or publication interface change is needed. Metadata inputs do not promise the
older component package targets honor new identity/debug settings.

Next finish the seven conditional owners, migrate actual package traversal and
require full selected family/inventory reconciliation before creating world
packages. Keep package-driven fresh construction, existing-system account/state
preservation, kernel/module/world binary/debug/runtime/cross-platform qualification,
bootstrap/cache/sandbox/reproducibility and CPU/RAM/disk I/O/footprint measurements,
and verified combined base/hardware repository publication gates. SDK flua remains
a Make-built bootstrap input; no global debug-off payload acceptance is implied.
Make remains production/default. BIP stays excluded. No host install or reboot.
