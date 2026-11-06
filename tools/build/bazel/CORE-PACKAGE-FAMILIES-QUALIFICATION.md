# Source-owned core package-family metadata

## Scope (2026-11-06)

`//packages:core_family_manifests` explicitly selects the first five native
package families: runtime, clibs, utilities, toolchain and bsdlog. This is not
the complete world package endpoint. There are 445 package buckets in the
qualified selected world inventory; these five families do not cover them all.

`bsd_pkg_family` models source-owned family/subpackage declarations, templates,
sets, vital properties and dependencies. It runs the maintained
`release/packages/generate-ucl.lua` through the existing manifest driver, with
PKGGENNAME enabled so family dependency and suffix semantics remain in Lua.
Production actions do not parse Makefiles or duplicate the UCL parser. Template
includes must be declared through template_inputs; runtime tools and templates
are action inputs. The provider exposes manifests and descriptive family metadata,
not payloads, package archives or a repository. Metadata-only declarations are
recorded but do not yet construct empty transition packages.

The maintained format-5 build-bsd bazel-test workflow builds the aggregate using
explicit targets/build-settings and SDK inputs. New typed package_name_prefix,
package_maintainer and package_www settings have the maintained Make defaults
and permit downstream overrides. Existing package_version remains mandatory.
The new debug_files flag currently selects family metadata only: world debug
payload producers have not been integrated with it. Do not advertise a complete
debug-off world. Existing split_manpages, tests and llvm_binutils flags select
family variants/dependencies. The C frontend, backend dispatch, stage, signing,
verification and publication contracts need no change for these additive targets;
the maintained manual describes the scope. No feature bypasses that frontend.

## Qualification

Two corrected native captures pass via build-bsd with 16 jobs. Original Make
buildenv commands generate only explicit .pkgucl targets under isolated /usr/obj
objects, using the actual SDK ABI and explicit version. The audit queries each
family's actual _ALLPACKAGES and effective MK settings, requires exact coverage,
decodes both UCL outputs with SDK flua/libucl and compares entire objects.
Input/include hashes and baseline build-environment verification bind the control.
Raw UCL ordering is not asserted byte-identical.

- Default: tests off, split manuals off, debug on, LLVM binutils on; 14 manifests.
- Alternate: tests on, split manuals on, debug off, LLVM binutils off; 15 manifests,
  with OrgBSD package prefix and distinct explicit maintainer/website inputs.
- All 29 decoded manifests match, including package scripts, annotations,
  dependencies, licenses, descriptions and vital properties. The maintained
  source_settings_test passes in both native captures.

The SDK flua used here is a Make-built static bootstrap tool. This does not prove
Bazel-native bootstrap construction, hermetic sandbox enforcement, cross-target
execution, world payload or archive parity, install/upgrade behavior or performance.

## Retained discovery

The first alternate capture included seven unsupported lib32 metadata variants.
The original Make comparison rejected that coverage. src.opts.mk declares LIB32
unconditionally broken, even when requested. The invented compatibility input
and all lib32 family variants were removed; the corrected audit verifies effective
Make options rather than assuming requested options took effect. BIOS/EFI 32-bit
boot artifacts are separate and are not disabled by this correction.

## Evidence

All paths below are under /usr/obj/usr/src; no package installation or publication
was performed. Qualification audit.py and decoded documents are retained with
the review. Failed r1 evidence is retained, not relabeled passing.

- bazel-core-package-families-native-r2-20261106/receipt.json
  SHA256 24776ab8a1b69cf5bdbba073efef54cd9bfe4231466c2200976df1c42aa759df
- bazel-core-package-families-alternate-native-r2-20261106/receipt.json
  SHA256 bf3877c66779f19f1f4ff03f45ab2ae2c353f8eda4ed88d90137e0cdbcee08d1
- bazel-core-family-make-review-r2-20261106/review.json
  SHA256 313d6c0e21364f71d823528153a90768334f0144c10e8bdc60589b04caac001b
- bazel-core-package-families-request-r1-20261106/inputs.json
- bazel-core-package-families-alternate-request-r2-20261106/inputs.json
- Failed discovery: bazel-core-family-make-review-r1-20261106 and
  bazel-core-package-families-alternate-native-r1-20261106.

## Next

Complete source-owned package families and reconcile the selected metadata with
the entire world inventory. Then connect actual native whole-world package
creation, including cross-package hardlinks, transition packages and generated
construction state, followed by package-driven fresh-system and upgrade tests.
Retain world/kernel/module/debug/cross/bootstrap/cache/sandbox/reproducibility,
CPU/RAM/disk I/O/footprint/runtime and combined base/hardware publication gates.
Make remains production/default. BIP stays out of scope.
