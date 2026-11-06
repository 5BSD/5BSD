# Combined native world contributions and manual finalization

## Composition (2026-11-05)

The root `world_contributions` target composes the existing native production
roots: lib, libexec, bin, sbin, include, usr.bin, usr.sbin, share, etc and the
normal empty sys traversal, with the selected AMD64 stand parent under BOOT and
configured rescue, cddl, secure and MIT Kerberos roots. The lists and conditions live in
`tools/build/bazel/world_installation.bzl`, following maintained top-level world
traversal. Unsupported Heimdal aggregation fails explicitly rather than selecting
an empty replacement. Normal family installation rules retain their selections.

The etc contribution composes its normal termcap.small installation and separately
qualified distribution phase. It deliberately excludes afterinstall databases
until manuals from the other roots have joined the graph. The main and OpenSSL
database actions then consume the assembled records and declare only their manual
file payloads as inputs. A typed untagged root/wheel 0644 database archive follows
Make's afterinstall metadata. MAN/MAN_UTILS and OpenSSL control inclusion.

`finalized_world_contributions` adds those database outputs. The companion
`world_contribution_products` target also requests the maintained internal
library/program products that Make builds without installing; installation
archives alone are not substituted for that construction closure.

These names describe contributions: complete installed tests
and local extension roots are not yet part of this composition. Rescue now
participates under its source-owned enable setting. This is not the
complete world build target or a qualified replacement for buildworld/installworld.
As remaining roots become native, their manuals must enter finalization too.

## LLVM source ownership correction

The combined graph exposed stale LLVM parent labels after documentation introduced
a source package at llvm/lib/Support. Parent Support globs became empty and its
source labels crossed the existing package boundary. Support now exports its
C/C++/assembly source files and a bounded local header filegroup to the parent.
The parent uses those actual owning labels for both bootstrap and installed
Support variants. Glob checks remain strict; no source or option is omitted.

`bazel-llvm-support-ownership-review-r1-20261105/review.json` reverses only the
label rebinding and equivalent header grouping and requires exact equality with
the previous parent declaration. The combined build then compiles the LLVM
bootstrap/TableGen tools successfully. This is source declaration equivalence
and construction evidence, not a fresh independent LLVM object/runtime comparison.

## Accepted evidence

Evidence is under `/usr/obj/usr/src/`.

- `bazel-world-finalization-native-r3-20261105`: normal maintained build-bsd
  bazel-test, sixteen jobs. Combined installation construction and source-settings/
  manual-database tests pass. The build considers roughly 55600 actions, mostly
  cached; Bazel reports 233 total actions. This does not establish a fresh compile
  of every source or a performance benchmark.
- `bazel-world-finalization-review-r1-20261105/review.json`: all 1268 combined
  installation metadata captures are verified and their 32327 non-directory
  destinations have no duplicate claims. Explicit directory claims are retained
  and counted, not promoted to complete global directory-policy parity. Unlike
  earlier cross-capture namespace reports, these archives come from one combined
  native invocation.
- The main manual corpus has 11586 paths; OpenSSL has 6373. The review stages
  those native payloads with real hardlink identity and runs maintained Make
  makedb with the independently Make-built, previously hash-bound mandoc tool.
  Both databases match exact bytes, and Make's two untagged metadata records match
  the installed database ownership/modes. This is indexer parity on the SAME
  NATIVE CORPUS, not independently Make-staged whole-world payload parity.
- `bazel-world-finalization-native-r4-20261105`: normal frontend build also
  requests the noninstalled internal products; both tests pass.
  `bazel-world-finalization-products-review-r1-20261105/review.json` binds every
  final installation output and additional product, verifies all 3804 archive/
  metadata/directory outputs unchanged against r3, verifies 52 additional products and checks both databases unchanged.
  This connects the final product closure to the earlier combined review.

- `bazel-world-with-stand-native-r1-20261105`: maintained frontend combined
  construction with the normal empty sys contribution and selected AMD64 boot
  parent connected under BOOT. Source-settings and manual-database tests pass.
  `bazel-world-with-stand-review-r1-20261105/review.json` verifies 1295 archives
  and 32454 unique non-directory paths with no duplicate claims. Main/OpenSSL
  manual corpora contain 11622/6373 paths; both generated database bytes and
  metadata again match maintained Make makedb on this same assembled native
  corpus. Independent whole-world Make payload parity is still unproven.
  Native EFI help has one source-owned install contribution without losing
  complete standalone Lua/simple installs. Boot-enabled world aggregation is
  currently AMD64 only; the parent rejects other ABIs explicitly. Sixteen raw
  boot binary/debug differences remain against a fresh matching-mode original
  Make reference; see AMD64-BOOT-PARENT-CONSTRUCTION.md. This combined build
  does not close those differences or runtime/firmware/package acceptance.

The initial r1/r2 captures failed on stale LLVM Support header/source/assembly
ownership. They remain failed; fresh runs after the correction supply acceptance.
Existing original control tools are bound to retained earlier output digests;
current unverified bazel-bin files do not supply the reviewed artifact corpus.

## Frontend and remaining work

The maintained format-5 configured target/output interface already supports these
roots and product groups. The manual and completion plan document their limits.
No C dispatcher/schema, signing/staging/publication backend change is needed in
this checkpoint. Normal production/default system construction stays Make.

Next finish independent rescue/package/guest qualification, stand product/option/ABI gaps and installed test roots and incorporate them into
one complete world/kernel/module build. Reconcile source inventory and complete
Make installation/debug/metadata, directory and pkgbase behavior. Refresh current
kernel/module evidence after source changes, qualify bootstrap/toolchain and
configuration/cross-ABI coverage, then hardware integration, verified combined
publication, VM/runtime and CPU/memory/disk/cache/sandbox comparisons. These are
still required gates; this combined contribution build does not close them.
No host installation, publication, upgrade or reboot occurred. BIP remains excluded.

## Current integrated rescue/libc refresh (2026-11-05)

bazel-world-current-refresh-native-r1-20261105 completes one maintained
build-bsd bazel-test invocation with 16 jobs. It constructs the configured world
contributions, final manual indexes and noninstalled internal products together
with the actual rescue executable and its real unsigned pkgbase package.
All nine selected test targets pass as Bazel cache hits from qualified prior
executions. Inputs are recorded in
bazel-world-current-refresh-request-r1-20261105/inputs.json. The explicit
production-malloc and NIS-disabled selections match the current libc/rescue
comparison inputs; other explicit features remain as recorded in that file.
Counts must not be compared as coverage percentages with earlier NIS-enabled
captures. This does not silently broaden the independent Make parity claim.

bazel-world-current-refresh-review-r2-20261105/review.json verifies the immutable
capture, 1279 archive metadata outputs and 32515 unique nondirectory paths with
no duplicate claims. All 3552 archive directory records and fourteen separate
directory-policy claims are reconciled: 789 unique directory destinations have
consistent owner/group/mode/flags and no file/directory claim collisions.
Package tags remain attached to every repeated claim rather than being discarded
or treated as conflicting physical ownership. This proves consistency among the
emitted claims, not complete original Make global directory-policy parity or the
absence of missing installation roots. The narrower r1 review checked the
separate directory-policy outputs; r2 additionally checks every archive record.

Main and OpenSSL manual corpora have 11596 and 6373 paths. Both database bytes
and Make metadata agree with maintained Make makedb and its independently
Make-built mandoc tool on the same assembled native corpus. This is indexer
parity on native inputs, not independently Make-staged whole-world payload parity.
The original Make libc reference and per-member filename/DTrace controls remain
separate evidence in LIBC-SOURCE-ALIASES-QUALIFICATION.md.

Full installed tests remain intentionally rejected by production-only parents.
No acceptance claim covers them, other ABIs, complete installed Make parity,
archive ordering/debug, bootstrap, all pkgbase packages, hardware/repository
publication, guest services or resource/cache/sandbox performance. Existing
format-5 targets/tests fully express the refreshed request; no C frontend,
staging/signing or production backend change is required. Make stays default.
No host installation, upgrade, reboot or BIP change occurred.

## Fresh-account extension (2026-11-06)

See WORLD-ACCOUNT-FINALIZATION-QUALIFICATION.md. A separate fresh_world_contributions
aggregate adds the existing source-owned account archive; world_contribution_products
now requests that fresh closure. The finalized aggregate remains unchanged.
Fresh construction is not an account migration or an existing-system overlay.
