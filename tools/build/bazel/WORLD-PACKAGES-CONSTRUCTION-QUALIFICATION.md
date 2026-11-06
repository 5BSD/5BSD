# Native whole-world pkgbase archive construction

## Qualified construction scope (2026-11-06)

The maintained //:world_packages candidate now constructs all 445 selected AMD64
pkgbase archives: 444 nonempty payload packages and the explicit pf-dev transition.
Independent host libarchive inspection checks every archive against the complete
1,280 captured native installation archives. All 32,510 packaged file/link paths
and all thirteen cross-package hardlink relationships are accounted for. Seven
source-declared generated construction files remain separate from package payloads.
This is a real pkg archive set, not only an inventory or UCL catalogue.

This establishes construction and same-native-corpus content/metadata inspection.
It does NOT establish independent Make-built world bytes, full Make package recipe
parity (particularly automatic shared-library metadata in a shared stage), solver/
installation/upgrade behavior, a bootable installed system, kernel/module packaging,
hardware integration, repository publication, signing or verified boot. Make remains
production/default and BIP remains excluded.

## Native action/dependency design

The existing reconciled family provider determines every declared .pkg output.
A declared planning action consumes the complete world inventory, selected family
catalogue and hash-bound reconciliation report. It verifies their identities and
writes a separate layout for each package. Each layout contains only that package's
records, source directory policy, manifest hash and cross-package inode metadata;
it does not copy a global world hash into every package layout.

Each BSDWorldPackageCreate action consumes its own layout, generated UCL, actual
payload Files and applicable generated-tree artifacts. Static records map to real
Bazel Files; hardlink sources resolve through the complete source graph. Generated
tree providers forward both uniform file/directory tags and explicitly supplied
additional Files. Missing source dependencies are rejected. There is no package/
program pathname whitelist, host filesystem scan or production Make invocation.
Changes to unrelated payloads need not change other package action inputs; actual
incremental/cache invalidation qualification remains a separate gate.

Each action copies only its package into private scratch storage. No whole-world
extraction is repeated per package and cached directory inode state is not relied
on. A linear hardlink root walk and explicit metadata reconstruct package-local
inode groups. If a group crosses package ownership, each owning package stores its
own canonical file and preserves links within that package, matching real pkg
behavior over a shared stage. Package flags remain plist metadata; they are not
applied to build scratch files. Scratch directory access is restored for cleanup
of readonly target directories. No staging tree is installed on the host.

The shared pkg_create.create_staged function retains the maintained pkg invocation,
file/config plist attributes, complete directory ancestor ownership and target ABI/
OS-version handling. The ABI is read from the actual native target uname ELF; no
fixed ABI string is passed by the production rule. Explicit metadata-only outputs
use pkg-create without a plist. Unmarked empty packages are rejected. Archive/index
hashing streams data rather than reading an entire package into Python memory.
A separate action collects deterministic per-package indexes into the declared
world index. These indexes are construction outputs, not independent verification.

## Frontend and resource inputs

Existing format-5 build-bsd targets/build-settings select //:world_packages.
source_graph.py now binds typed build_jobs to frontend --jobs and rejects a
contradictory explicit value. The normal --jobs path therefore reaches scheduling;
there is no host CPU count or home-directory repository constant in the rule.
Typed package_threads controls compression; zero chooses the frontend job budget.
package_epoch is explicit, defaults to zero and never falls back to wall-clock time.
The maintained manual describes these inputs in the same change.

The frontend enables Bazel action resource estimates and each package action
requests its configured compression CPU count and a source-declared memory estimate.
This uses the documented resource_set dictionary, accepted by the actual Bazel 9.3.1
qualification. These are scheduling estimates, not memory limits or performance
acceptance. The captured full run uses all 16 logical CPUs with one compression
thread per action; the largest final package can occupy one remaining CPU.
API reference: https://bazel.build/rules/lib/builtins/actions.html

C CLI/backend dispatch, stage/signing/verification helpers and publication contracts
do not change. The new backend inputs and tests are part of the maintained frontend,
not a replacement shell build. No repository latest or latest-built pointer moves.
Normal Make builds and ports/hardware workflows remain unchanged.

## Tests and independent inspection

All four requested maintained Bazel wrappers pass in the final full capture:

- source_settings_test includes CPU-budget binding/rejection alongside prior typed
  input/cache/runtime configuration tests.
- pkg_create_flags_test exercises six real-pkg positive/rejection cases, including
  system/user immutable file flags and immutable directory flags.
- pkg_create_directories_test retains six directory/layout controls and adds actual
  metadata-only archive inspection plus rejection of an unmarked empty package.
- world_pkg_hardlinks_test compares real pkg output over a shared stage against
  the package-local planner/writer. Complete decoded manifests, contents and inode
  groups match for two packages, including a cross-package link chain, an empty
  owned directory with otherwise unused ancestors, readonly directory cleanup and
  rejection of an undeclared source. Raw uid/gid/name/mode encoding is also compared
  against the actual SDK pkg reference, and its observed numeric encoding is logged
  in the hash-bound test report. These are bounded build/packaging checks,
  not execution of original installed-system tests or services.

The independent complete inspection resolves all inputs from hash-verified immutable
qualification captures and uses host libarchive, separate from the production
Python staging/pkg writer. It streams source and package payload hashes and checks:

- Exact archive and manifest file membership, declared package identity/ABI and
  configuration path membership.
- Every file's content (against captured native installation tar data), ownership,
  mode and flags; symlink text and per-package hardlink inode equivalence.
- Complete directory membership, owners/modes and persisted manifest flags, plus
  any actual tar directory headers and rejection of unowned headers.
- Explicit transition emptiness, index hashes, all thirteen cross-package inode
  relationships and exact exclusion of the seven declared construction files.

Pkg encodes percent/non-ASCII bytes in manifest paths; inspection decodes that
standard representation once and rejects duplicate decoded names. This preserves
all 442 percent-containing mapper filenames. Directory headers' conventional
trailing slash is normalized for ownership comparison. Production file names and
payloads are unchanged. Source reference:
https://github.com/freebsd/pkg/blob/main/libpkg/pkg_manifest.c

Pkg deliberately normalizes raw tar uid/gid fields for reproducibility; those
numbers are not the installed target account IDs. A stricter numeric-equality probe
(r6 inspection) correctly failed that incorrect assumption. The final audit instead
requires the actual encoding observed in the independent SDK-pkg reference test,
and still checks every owner/group name in the tar and manifest against source.
It does not rewrite tar ownership fields. Installed numeric ownership remains a
VM/install gate. Upstream writer and installer references:
https://github.com/freebsd/pkg/blob/main/libpkg/packing.c
https://github.com/freebsd/pkg/blob/main/libpkg/pkg_add.c

The final inspection is not a complete independently created Make package metadata
comparison: automatic shlibs, script execution, solver/install and upgrade behavior
still require the shared-stage Make control and actual installed-system tests.
It does not certify raw DWARF contents, bootstrap reproducibility, sandbox isolation,
remote/local cache correctness or controlled CPU/RAM/disk performance.

## Discovered fixes and retained failures

- First analysis lacked a narrow export for the new driver; it was declared.
- Native r2 stopped at zoneinfo after producing partial outputs because its three
  additional declared Files were not forwarded with the generated tree. The generic
  producer/consumer contract was fixed; no zoneinfo pathname exception was added.
- Native r3/r4 constructed all packages, but independent inspection found missing
  directory ancestors in clibs, mac-abac and utilities. Shared plist generation now
  applies ancestor closure to empty owned directories as well as files. The real
  hardlink regression includes this case. No expected inventory was reduced.
- An initial inspection treated encoded manifest file names as literal names;
  another tightened directory check treated a trailing slash as a different path.
  Both reader issues were corrected using the format's normal semantics. Full
  membership, content and flag checks remain enabled; no package was skipped.
- The bounded changes audit initially omitted the frontend manual's hardlink alias;
  its corrected control derives that alias from the declared package plan.

Across the corrected native captures, 441 complete .pkg files remain byte-identical.
The other three packages change only their directory metadata, adding source-owned
ancestors; bsd-build changes only its maintained manual and original hardlink alias.
This is bounded byte preservation, not independent-machine reproducibility proof.
A subsequent manual-only formatting edit executes exactly one package action and
changes only bsd-build, reusing 444 unchanged package outputs. A test-only encoding
observation then executes zero package actions and leaves all 445 package hashes
unchanged. Hash-bound BEP metrics and output indexes record both controls. This does
not close general C/library/header/toolchain invalidation, clean CAS restoration,
remote-cache, sandbox or controlled performance gates.

## Evidence

All paths below are relative to /usr/obj/usr/src. Reviews retain audit.py, exact
bindings and detailed results. No host install, upgrade, reboot or publication.

- bazel-world-packages-default-native-r7-20261106/receipt.json
  SHA256 509ce8bdb9e71279db87dbaa166d0f67d9c78ba8b2db8f9b1f5e565c81a2f351
- bazel-world-packages-inspection-r7-20261106/review.json
  SHA256 9fa229d488e4685767813c49ec53ba484c7a0a4a007efce9535cb6b6c577a3ef
- bazel-world-package-changes-review-r3-20261106/review.json
  SHA256 4dc8c70a053cc8f1cfef6d05c15435769b16dcf98acf76343e9833c49adab165
- bazel-world-pkg-driver-native-r1-20261106/receipt.json
  SHA256 7f66f60f8c87afa983433136d16f3c86d7e31df0b5bb20ed944639fcd57922ee
- bazel-world-package-incremental-review-r1-20261106/review.json
  SHA256 0d1ef74ab5e4d537054c41a764e6d5f0150650f2a1c06b37d175a70d63780f0d

Additional retained evidence:

- bazel-world-packages-default-request-r1/r2-20261106/inputs.json
- bazel-world-packages-default-native-r1/r2/r3/r4/r5/r6-20261106
- bazel-world-packages-inspection-r1/r2/r3/r4/r5/r6-20261106 (discovery and earlier scopes)
- bazel-world-package-changes-review-r1/r2-20261106 (discovery/earlier bindings)
- bazel-world-pkg-driver-request-r1-20261106/inputs.json
- bazel-world-pkg-hardlinks-host-r1-20261106 (initial host pkg control)

## Next required work

Run original maintained Make package recipes over a complete captured native stage
and compare every produced manifest/partition, including automatic shared-library
metadata. Then qualify solver/fresh install, generated-state construction and local
account/service-data preservation during upgrades. Integrate native kernel/modules,
separate hardware packaging and verified combined repository publication under the
standard /usr/obj/usr/src/repo, using /usr/obj/5BSD-ports.

Retain all independent world/kernel/module/debug/runtime/VM/cross-architecture/
bootstrap/cache/sandbox/reproducibility and controlled CPU/RAM/disk I/O/footprint
gates. Typed settings beyond the captured profile, global DEBUG_FILES payload
selection and complete tests-enabled world remain open. Current directory sidecars
still share serialization actions with installation tar outputs; measure that
package-only build cost before deciding whether to split the actions. Keep Make
production/default until the original full goal is actually qualified.
