# Combined native world contributions and manual finalization

## Composition (2026-11-05)

The root `world_contributions` target composes the existing native production
roots: lib, libexec, bin, sbin, include, usr.bin, usr.sbin, share and etc, with
configured cddl, secure and MIT Kerberos roots. The lists and conditions live in
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

These names describe contributions: rescue, sys, stand, complete installed tests
and local extension roots are not yet part of this composition. This is not the
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

The initial r1/r2 captures failed on stale LLVM Support header/source/assembly
ownership. They remain failed; fresh runs after the correction supply acceptance.
Existing original control tools are bound to retained earlier output digests;
current unverified bazel-bin files do not supply the reviewed artifact corpus.

## Frontend and remaining work

The maintained format-5 configured target/output interface already supports these
roots and product groups. The manual and completion plan document their limits.
No C dispatcher/schema, signing/staging/publication backend change is needed in
this checkpoint. Normal production/default system construction stays Make.

Next finish rescue/sys/stand and installed test roots and incorporate them into
one complete world/kernel/module build. Reconcile source inventory and complete
Make installation/debug/metadata, directory and pkgbase behavior. Refresh current
kernel/module evidence after source changes, qualify bootstrap/toolchain and
configuration/cross-ABI coverage, then hardware integration, verified combined
publication, VM/runtime and CPU/memory/disk/cache/sandbox comparisons. These are
still required gates; this combined contribution build does not close them.
No host installation, publication, upgrade or reboot occurred. BIP remains excluded.
