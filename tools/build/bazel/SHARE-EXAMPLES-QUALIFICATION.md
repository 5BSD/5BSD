# Native production examples and source inventory fixes (2026-11-05)

## Source defects corrected

Before native conversion, original Make queries showed three apparently intended
package assignments resolving to examples. The group loop reads
SE_<normalized-directory>PACKAGE; SE_BOOTFORTH_PACKAGE, SE_JAILPACKAGE and
SE_MAC_ABAC_PACKAGE did not match that lookup. The maintained Makefile now uses
SE_BOOTFORTHPACKAGE, SE_JAILSPACKAGE and SE_MAC_ABACPACKAGE. Their sample files
and owned directories now belong to bootloader, jail and mac-abac respectively.
These are package ownership changes; installed paths and source contents stay
unchanged. Real package-upgrade qualification remains required.

The OES sample had a legacy cleanup-directory entry in the Bluetooth block but
no installed file group. It now has an unconditional SE_OES group for oeslogger.c
and an unconditional legacy directory-cleanup entry. Both builders install it
as examples data independently of Bluetooth. No example/application source is
rewritten, and no entitlement or runtime policy is changed.

## Native construction and selected scope

The source-owned share/examples BUILD.bazel declares all fifty selected example
groups and their actual files, packages and owned directories. The existing typed
script/data helper installs every example as data (0444), including shell samples,
following original Make rather than source executable bits. Hardware/service
choices use native bhyve/PF/LPR/EFI/NIS/HAST/USB/Bluetooth settings; bhyve samples
also require the original AMD64/AArch64 CPU selection. Supported target CPUs are
explicit; actual execution here uses AMD64.

The full installation_archives endpoint is available only with tests disabled.
The production_installation_archives endpoint explicitly excludes the installed
ATF/plain/TAP/Googletest examples. Those test subtrees are not yet converted.
A tests-enabled full request is rejected as an incompatible explicit target;
no sampled test hierarchy is substituted. Native artifacts model normal Make
installed payloads (MK_STAGING=no); the legacy Make staging mode is not qualified.
No Make inventory parser or metadata expansion runs during the native build.

## Complete independent original comparisons

| Profile | Records | Exact files | Owned directories |
| --- | ---: | ---: | ---: |
| Optional groups enabled | 235 | 185 | 50 |
| Optional groups disabled | 185 | 144 | 41 |

Both profiles pass complete maintained Make subtree inventory, owner/group,
numeric mode, package tag, exact payload-byte and archive-serialization checks.
Every explicit tar record and necessary ancestor is reconciled; extra entries
fail. The original reference runs the corrected maintained Makefile; the source
fixes are not mimicked only in Bazel.

A separate review requires the intended ownership of all bootforth (eight
records), jail (eight records) and MAC_ABAC (five records) contributions in both
native captures. It also requires oeslogger.c as 0444 examples data in each,
including the Bluetooth-disabled profile. Full independent comparisons check
all paths; the focused source-fix review does not replace them.

## Evidence under /usr/obj/usr/src

- bazel-share-examples-native-r1-20261105 and
  bazel-share-examples-make-r1-20261105: maintained build-bsd and independent
  Make build/stage with sixteen jobs, tests disabled, NIS/LPR selected explicitly.
- bazel-share-examples-original-review-r1-20261105/review.json: complete normal
  comparison with original source rechecks, immutable artifact bindings and audit.
- bazel-share-examples-options-native-r1-20261105 and
  bazel-share-examples-options-make-r1-20261105: bhyve/PF/LPR/EFI/NIS/HAST/USB/
  Bluetooth example groups disabled. Its complete comparison is retained at
  bazel-share-examples-options-original-review-r1-20261105/review.json.
- bazel-share-examples-native-r1-20261105/source-fixes-review.json binds the
  actual intended package ownership and unconditional OES sample in both captures.
- bazel-share-examples-tests-native-r1-20261105 remains a failed build with
  FAILED.json and no passing receipt. bazel.stderr names the explicitly requested
  incompatible installation_archives target. gate-review.json records this
  expected rejection without relabeling the failed build as passing qualification.
- bazel-share-examples-namespace-r1-20261105/review.json reconciles all example
  file claims with prior production/data/manual/documentation captures: 1145 unique
  archives, 28098 non-directory paths and zero conflicting file claims. It is
  cross-capture checking, not one complete native world build or directory/pkgbase
  acceptance.

Both positive profiles pass their selected source-settings test. This is source
installation qualification, not execution of sample programs or service behavior.

## Frontend and remaining gates

The maintained Make inventory changes feed normal make packages. The format-5
frontend accepts the native endpoints and existing settings; its manual describes
the changed sample ownership and test boundary. No dispatcher, schema, staging/
signing or publication-helper change is required. No tracked Python implementation
changes are part of this checkpoint. No host installation, upgrade, publication
or reboot occurred. Make remains production/default; BIP remains excluded.

Installed example tests and their runtime/Kyua fixtures remain required. Zoneinfo,
locale/encoding and remaining world composition, full installed tests/Make/pkgbase
parity, cross configurations/architectures, independent reproducible bootstrap/
output-query closure, kernel/module installation, hardware/publication, actual
package upgrades, system runtime/VM and comparative CPU/RAM/disk I/O/footprint/
cache/sandbox gates remain open.
