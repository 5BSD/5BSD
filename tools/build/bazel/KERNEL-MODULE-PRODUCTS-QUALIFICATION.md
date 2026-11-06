# Typed kernel module installation products (2026-11-06)

## Architecture

The shared native module pipeline now exports a layout-independent module_product
provider containing actual runtime/debug Files, aliases, package owner and source
installation attributes. Its existing standalone manifest and the new base-kernel
composer use one maintained file/alias policy from kernel_module_artifacts.bzl.
The composer reads configured kernel_base_directory/kernel_debug_directory and
materializes normal typed installation entries. It preserves optional debug files,
package/debug tags, ownership, modes and aliases. The existing manifest writer
retains its payload materialization, hardlink and collision checks; source directory
validation is shared with kernel installation. There is no payload copying,
post-hoc manifest rewrite, Make query or filesystem scan in native actions.

The first source-owned parent, sys/modules/firewire:amd64_base_installation, selects
its six original SUBDIR members. Leaf owners retain compilation metadata. This is
a family composition checkpoint, not all-module traversal or a complete package.
Generic, cross and firmware factories using the shared pipeline gain typed product
targets; this AMD64 qualification does not establish other architecture builds.

## Rejected transition candidate

An earlier candidate passed eight tests and built real modules by changing the
module-directory setting on dependency edges. It produced distinct configured
NewReno output paths with identical runtime bytes for base and standalone layouts.
The final implementation consumes the exact same configured File objects in both
layouts, avoiding that extra product configuration. This is structural sharing
proof, not a measured general performance claim. Bazel documents configuration
transition graph/memory costs at https://bazel.build/extending/config.

Candidate source snapshots and bindings remain in
bazel-kernel-module-context-transition-review-r1-20261106. The attempted historical
compact-log decoder referenced a cleaned bootstrap binary; compiler duplication
was not measured or claimed. The final proof uses immutable output identities.
The first candidate test-inventory failed due to external-repository-relative
analysis-test setting labels; explicit resolved source Labels fixed it. An initial
typed-product test attempt failed a declaration syntax error before execution.
All failures remain recorded; no acceptance checks were weakened.

## Qualification

Paths below are relative to /usr/obj/usr/src:

- bazel-kernel-module-products-native-r4-20261106 passes ten test targets through
  the maintained format-5 frontend with sixteen jobs. Tests cover standalone/base
  paths, custom base/module/debug roots, inline debug placement, alias/package tags,
  collisions, invalid relative/traversal directories, prior archive behavior and
  world inventory behavior. Latest test executions are reused from valid cached
  results; configured analysis assertions are evaluated with the current providers.
  Metadata-only analysis tests use explicitly identified text fixtures, not ELF.
- Real debug-enabled NewReno and the complete six-member FireWire group build.
  bazel-kernel-module-products-review-r2-20261106/review.json requires identical
  configured runtime/debug output names and hashes across NewReno product/base/
  standalone views. Only installation destinations differ. It compares FireWire
  membership with the actual original Make SUBDIR query and verifies all seven
  real module ELF/debug-link/CRC pairs, including source policy metadata.
  SHA256 629ecd508d8e5d33e4bd132e5647a0188d30db5f98e024330a2627c4d72337cd
- The debug-disabled NewReno profile is captured separately under
  bazel-kernel-module-products-nodebug-native-r2-20261106. It builds the actual
  product and both layouts with tests=[]; independent inspection requires one
  shared runtime File and no debug installation/captured output. This is optional
  debug branch verification, not executed runtime cases.
  Review: bazel-kernel-module-products-nodebug-review-r2-20261106/review.json
  SHA256 2760d0608a9f428e06fabca11e47ee7231304a43405ceb640a5c5044ccccdae3

## Frontend and remaining work

Existing source settings and format-5 targets express these inputs. Backend rules,
shared factory, tests, source parent and manual change together; no new frontend C
option, signing/staging/publication contract or production Make default is needed.
No host module was loaded and no host install, upgrade or reboot occurred. BIP stays
excluded. Ordinary standalone module locations retain their current inputs.

Next expand source-owned conditional module traversal, compose all selected kernel,
module/GDB/alias/directory/linker.hints artifacts and kernel-flavored pkgbase output,
and join explicit non-kernel module owners to their actual world packages. Compare
original aggregate installation/package ownership and bytes independently. Full
normal startup/services, genuine version upgrades, cross-platform, debugger source
lookup, bootstrap, cache/sandbox/reproducibility and controlled CPU/RAM/disk I/O/
footprint/combined-publication acceptance remain required.
