# Native shared manual sections (2026-11-05)

## Implementation

Sections 1, 3, 3lua, 5, 6, 7, 8 and 9 now have source-owned BUILD.bazel inventories.
The bsd_manual_installation.bzl helper declares each selected source, deterministic
gzip action, installed page and alias hardlink. Native builds execute no Make
inventory query or metadata translator. Optional groups use standard Bazel
condition groups combining man with the actual feature setting; nested select
expressions from the rejected initial attempt are not retained.

The helper preserves Make group-specific packages. Explicit group PACKAGE values
remain explicit; implicit group packages use their normal suffix or replace it
with -man for split_manpages. Section 3 defaults to clibs-dev and changes to
clibs-man when split. FIDL follows runtime/FIDLSUBPACKAGE. Compression selects
either the declared gzip result and .gz destination or the original raw source.
Aliases remain hardlinks, including aliases across manual groups. One final
component manifest resolves them together rather than requiring every group to
own a separate copy of its target. The source-owned ATF selection follows the
actual original inventory, including man7's overriding ATF assignment.

The native inet flag now represents MK_INET for networking manuals separately
from inet_support. Existing tests, USB, NIS, Bluetooth, LPR, toolchain, PF, SSH,
Hesiod and legacy-updater settings select their original groups. Disabling man
suppresses all groups and aliases. Section 4 and its architecture subdirectories
are still required; no complete share/man endpoint is declared here.

## Complete original component comparison

| Section | Installed records/payloads | Unique files | Hardlink aliases |
| --- | ---: | ---: | ---: |
| 1 | 90 | 2 | 88 |
| 3 | 534 | 103 | 431 |
| 3lua | 1 | 1 | 0 |
| 5 | 69 | 58 | 11 |
| 6 | 1 | 1 | 0 |
| 7 | 54 | 39 | 15 |
| 8 | 28 | 13 | 15 |
| 9 | 2519 | 470 | 2049 |
| Total | 3296 | 687 | 2609 |

All original records are compared, without a path whitelist. The audit requires
exact inventories, owner/group, numeric modes, package tags, raw or compressed
payload bytes, tar inventory/types/accounts/modes and epoch zero. It compares
complete original staged inode-equivalence classes with native archive hardlink
roots, detecting both missing hardlinks and unintended merging. Matching bytes
alone do not pass the alias check.

The alternate profile disables compression, enables split packages/test manuals,
and reverses the optional Bluetooth/toolchain/LPR/PF/SSH/updater/Hesiod/NIS/INET/USB
groups. All eight complete original components also pass: 3233 records/payloads,
679 unique files and 2554 hardlink aliases. A third native profile disables man
while test and other groups remain configured; all eight manifests are empty
and their archives contain only the root directory. This is a bounded native
selection check, not complete original disabled-world installation parity.

## Evidence under /usr/obj/usr/src

- bazel-share-manuals-native-r2-20261105: maintained build-bsd with sixteen jobs,
  eight installation archives and passing source-settings test. The r1 attempt
  failed before construction on invalid nested selects and remains rejected.
- bazel-share-man{1,3,3lua,5,6,7,8,9}-make-r2-20261105: independent original
  Make references with installed tests disabled and actual LPR/updater/NIS inputs
  selected where required. A prior man8 attempt was rejected by the original
  source-change guard while native declarations were being corrected. It is not
  reused as passing evidence; final stable references pass and source hashes
  are rechecked by the artifact review.
- bazel-share-manuals-original-review-r1-20261105/review.json: complete normal
  component metadata, payload, hardlink and serialization comparison.
- bazel-share-manuals-options-native-r1-20261105 and
  bazel-share-man{section}-options-make-r1-20261105: independent alternate profiles.
  bazel-share-manuals-options-original-review-r1-20261105/review.json records their
  complete comparison. Both audit sources and all artifact/reference bindings
  are retained.
- bazel-share-manuals-disabled-native-r1-20261105/disabled-review.json binds
  every empty selected manifest and root-only archive to the passed receipt.
- bazel-share-manuals-namespace-r1-20261105/review.json reconciles captures from
  the nine production families, ten shared-data components and eight manual
  components: 1132 unique archives and 26871 non-directory paths, with zero
  conflicting file claims. This is cross-capture checking, not one combined
  world build, complete directory reconciliation or pkgbase acceptance.

## Frontend and remaining gates

The maintained format-5 frontend already carries the targets and native flags.
Its manual documents compression/package/alias semantics and the inet input;
no C dispatcher, input-schema, signing or publication change is required. No
tracked Python implementation or original application/instrumentation sources
are changed in this checkpoint. Audit/probe behavior is unaffected by these
manual data declarations, and no runtime acceptance is implied.

Section 4, remaining documentation/examples/zoneinfo and complete locale/encoding
composition, other world roots and complete installed tests remain open. Full
Make/pkgbase parity, cross architectures/configurations, independent reproducible
bootstrap/output-query closure, kernel/module installation, hardware/publication,
real system boot/runtime and comparative CPU/RAM/disk I/O/footprint/cache/sandbox
gates remain required. Make stays production/default and BIP stays excluded.
No host installation, upgrade, publication or reboot occurred.
