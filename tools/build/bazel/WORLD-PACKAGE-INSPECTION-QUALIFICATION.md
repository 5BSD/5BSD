# World package inspection dependencies (2026-11-06)

## Implementation and scope

The complete default AMD64 native package set now matches all 445 original Make
package manifests on the same native corpus, using the same qualified pkg tool
and an explicitly matched package epoch. This resolves the automatic metadata
failure recorded in WORLD-PACKAGES-CONSTRUCTION-QUALIFICATION.md. It does not prove
an independently Make-built world, installed-system behavior or performance.

bsd_world_pkg_create.bzl derives symlink referent Files from installation records,
including canonical sources behind hardlinks. It follows aliases by target-root
components, so an absolute link starts at the target / and link/.. follows the
link before processing its parent. Referents in generated trees select the
corresponding declared tree/additional Files using provider prefixes/destinations.
No runtime host scan, SONAME list, global staging tree or fixed library paths decide
which extra payload inputs are needed. Existing pkg library-provider configuration
remains the maintained Make configuration.

world_pkg_create.py expands the complete reconciled inventory, including generated
trees and construction records, into package-local inspection records/directories.
Only source-declared inputs may be copied. These inspection records are separate
from owned records: they never enter the package plist, ownership manifest or
package payload. Cross-package referents may therefore affect the package's automatic
ELF metadata and cache key without transferring their ownership. The final default
has 235 inspection records across 89 packages. Dangling aliases retain their literal
installation text; cycles/paths exceeding 40 symlinks fail explicitly. There is no
host lookup fallback. Directory policy and readonly scratch cleanup remain explicit.

The analysis and execution resolvers necessarily operate at different phases:
analysis declares Files/trees from static providers, while execution handles the
expanded inventory. Both use the same component-order semantics. Native Skylib
unit/analysis tests exercise the analysis resolver directly; real-pkg comparisons
exercise the expanded inventory and writer. The actual world build verifies that
required sources are available in each action's declared source/tree allowlist.

## Qualified package tool

The prior SDK contains pkg 2.8.4, which follows an absolute alias into the host
while inspecting ELF. A real ELF fixture with distinguishable host/stage dependency
names fails with that tool. The maintained /usr/obj/5BSD-ports pkg port already
contains rooted stage resolution and failure propagation patches. It was built
without installation, using BATCH=yes MAKE_JOBS_NUMBER=16; pkg 2.9.0 passes the same
control. No port source changes were needed in this turn. Its exact binary SHA256:
9551c824140f58f455f6406446fc27c733ff601a780d8033ff487d3547c0e816

A fresh SDK is prepared through maintained libmd-plan.py --sdk-only and
libmd-stage-tools.py, selecting that pkg binary through additional_execution_tools.
The receipt binds the tool bytes and inspected runtime dependencies. Earlier SDKs
remain unchanged. This is an explicit input selection, not host pkg replacement or
a version-string exemption. The tool must pass the real-pkg regression before an
SDK is considered qualified for this package path. Rooted inspection assumes a
quiescent private stage; it is not protection against concurrent malicious writers
or proof of full sandbox isolation. The old tool's failure remains retained.

## Epoch policy and complete Make comparison

Native package_epoch remains a uniform filesystem timestamp for package staging,
defaulting to explicit zero. It also applies to bootloader filesystem timestamps;
it does not rewrite PE timestamps or other bytes inside files. The earlier
unnormalized Make reference preserves loader archive timestamps and remains a
recorded failure, not a passing result with ignored mtime fields.

The new independent reference stage is extracted from all 1,280 immutable native
installation archives and applies the same package_epoch to its filesystem entries.
That normalization is an explicit reference input, recorded in stage.json with its
request hash. Original Make recipes, UCL generator and mtree-to-plist.awk then
construct all 445 packages using the same patched pkg. All complete +MANIFEST
objects match exactly, including automatic shared-library metadata, scripts,
dependencies, file/config/directory attributes and timestamps. No fields are ignored.
This qualifies matched-epoch behavior; it does not claim that the existing default
Make stage automatically normalizes every file timestamp identically.

## Verification

- The final maintained frontend run passes seven test targets: existing source
  settings/flags/directories/hardlinks wrappers and three native Skylib tests.
- The expanded real-pkg regression covers cross-package ELF referents; relative,
  absolute, chained and directory aliases; dangling aliases; cycle rejection;
  undeclared-source rejection; exact package file membership; and existing inode,
  readonly-directory and empty-directory ancestor cases. The absolute reference's
  real host target is non-ELF while its target-root counterpart is declared ELF;
  the alias package must retain dynamic requirements and its literal link text.
- Independent host libarchive inspection passes all 445 actual package archives,
  all 32,510 packaged paths and thirteen cross-package hardlink relationships against
  the captured native installation corpus. Inspection files do not leak into payloads.
- Adding the three analysis tests executes zero package actions and preserves all
  891 world package/plan/index outputs and all 3,840 installation outputs byte for
  byte. This is bounded test-only cache evidence, not general invalidation/CAS proof.

## Evidence

Paths are relative to /usr/obj/usr/src. Reviews retain scripts, exact bindings,
outputs, commands and failures. No publication, host installation, upgrade or reboot.

- bazel-world-packages-inspection-native-r2-20261106/receipt.json
  SHA256 b03a4b148bde9d23b092101c7d06d03967f5c2deb05bd6986de6a197239eafc8
- bazel-world-packages-make-reference-r2-20261106/review.json
  SHA256 946115bd96babd45d3e09d0b629d246d0561aee4c62df8fe69bdbcd6c1044306
- bazel-world-packages-inspection-payload-review-r1-20261106/review.json
  SHA256 9a4d683d54157873f9015460c5fa6ed33499234bbcf1701ff18a665d788102ca
- bazel-world-packages-inspection-final-review-r1-20261106/review.json
  SHA256 061370417d4856db2e0b3455ef8a93e9225a4d24697a86d2f68f3f92bd2de96c
- bazel-pkg-tool-build-r3-20261106/review.json
  SHA256 4f7f471de72a82cb4be204a5fca85001b33255f0323b519ac1c4a03250efd4b4

Additional evidence: bazel-world-packages-inspection-native-r1-20261106,
bazel-world-packages-inspection-request-r1/r2-20261106,
bazel-world-pkg-sdk-r1-20261106, bazel-world-pkg-rooted-control-r1/r2-20261106,
bazel-world-pkg-inspection-host-r1-20261106 and retained pkg build r1/r2 failures.

## Frontend and remaining gates

Existing format-5 targets/settings and explicit SDK inputs drive the maintained
build-bsd backend. The provider, package actions, tests and manual are updated;
C CLI dispatch, signing/verification helpers, packaging/publication contracts and
Make/ports defaults do not change. No one-off replacement frontend is introduced.

Next qualify solver/fresh installation, installed numeric ownership, generated
account state and update preservation, then real VM startup/services and native
kernel/module packaging. Retain every independent Make-world/debug/cross-platform/
bootstrap/cache/sandbox/reproducibility/CPU/RAM/disk I/O/disk footprint and separate
hardware/verified combined repository publication gate. Generated-tree cross-package
alias variations beyond the actual default world remain to extend. No performance
acceptance follows from the compile timings or resource estimates. Make remains
production/default and BIP remains excluded.
