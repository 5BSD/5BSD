# Complete configured shared-manual source parent (2026-11-05)

## Native implementation

The source-owned share/man parent now selects all nine original section
traversals and their eleven installation owners. Section 4 declares its actual
page/link inventories in readable architecture/feature condition groups, reusing
the existing manual installation helper. It uses target CPU constraints for
AMD64, AArch64 and RISC-V, and rejects unsupported target CPUs at the archive
endpoint. This checkpoint executes the AMD64 target; other target-ABI builds
remain unqualified. No Make parser or expanded inventory snapshot executes during
a native build, and no Python implementation change is part of this checkpoint.

Section 4 preserves original AUTOFS, Bluetooth, CDDL, EFI, iSCSI, OFED, MLX5TOOL,
PF, USB and AMD64 bhyve selections. In particular, its DTrace provider manuals
follow the original CDDL choice rather than inventing a new DTrace gate. The
base section uses kernel-man; mac_abac.4 uses mac-abac. The two architecture
children retain their original utilities package and architecture alias chains.

Make installs both current architecture children by default even when building
for AMD64. The native manual_architectures setting defaults to all and accepts
all, arm, aarch64 or none. These are the four distinct inventories of the two
current children; none leaves the target CPU's main section-4 pages enabled.
AArch64-only selection includes bcm283x_pwm.4 from the ARM source and its AArch64
alias, which Make normally lets the ARM child own when installing both children.
This setting selects documentation directories; it does not choose a target ABI.

## Complete installed source-manual comparisons

| Profile | Archives | Records/payloads | Unique files | Hardlink aliases |
| --- | ---: | ---: | ---: | ---: |
| Normal compressed | 11 | 4248 | 1426 | 2822 |
| Raw/split/opposite feature groups | 11 | 4075 | 1323 | 2752 |

Both profiles pass complete original share/man subtree staging comparisons, not
just sums of earlier component checks. Every path, owner/group, mode, package tag,
raw/compressed payload and tar serialization is checked. Complete original staged
inode-equivalence classes agree with native hardlink roots, including alias chains
in architecture directories. The normal section-4 contributions are:

| Owner | Records | Unique files | Aliases |
| --- | ---: | ---: | ---: |
| main section 4 | 914 | 722 | 192 |
| man4.arm | 22 | 9 | 13 |
| man4.aarch64 | 16 | 8 | 8 |

The full manual-disable native profile also passes: all eleven manifests are
empty and all archives contain only the root directory. That is a bounded native
selection check, not independent disabled-world installation parity.

## Architecture-directory selection evidence and limits

Native AMD64 requests separately build aarch64 (two archives/932 records), arm
(two archives/936 records) and none (one archive/914 records). Actual original
Make queries with explicit MAN_ARCH inputs agree on the selected children,
complete inventories, metadata and alias targets. Every payload agrees with the
complete normal original reference's corresponding source-page payload, including
the common BCM page. This does not claim independent alternate original installed
trees or native AArch64/RISC-V target execution. Those broader gates remain open.

## Evidence under /usr/obj/usr/src

- bazel-share-manual-parent-native-r1-20261105 and
  bazel-share-manual-parent-make-r1-20261105: normal maintained frontend build
  and independent original Make build/stage, using sixteen jobs and explicit
  actual option inputs. Both complete the entire configured share/man subtree.
- bazel-share-manual-parent-original-review-r1-20261105/review.json: complete
  normal metadata/payload/inode/archive comparison, with audit source and bindings.
- bazel-share-manual-parent-options-native-r1-20261105 and
  bazel-share-manual-parent-options-make-r1-20261105: raw, split, installed-test
  manuals and opposite optional feature groups, including all new section-4 flags.
  bazel-share-manual-parent-options-original-review-r1-20261105/review.json binds
  their complete comparison.
- bazel-man4-arch-{aarch64,arm,none}-native-r1-20261105: actual native directory
  selection requests through build-bsd. bazel-man4-architecture-review-r1-20261105/
  review.json binds the original queries, selected metadata/aliases and normal
  reference payload comparisons; audit source and original environment retained.
- bazel-share-manual-parent-disabled-native-r1-20261105/disabled-review.json:
  all eleven empty manifests/root-only archives are bound to the passed receipt.
- bazel-share-manual-parent-namespace-r1-20261105/review.json: cross-capture
  reconciliation with prior production families/shared data: 1135 unique archives,
  27823 non-directory paths and zero conflicting file claims. The prior eight
  manual archive/request identities remain identical. This is not one combined
  full-world build, complete directory ownership or pkgbase acceptance.

All native requests pass their selected source-settings test. These are build/
artifact checks; they do not establish runtime system behavior.

## Frontend and remaining gates

The existing format-5 frontend supports the parent targets and scalar settings.
The manual documents manual_architectures and the distinction from target CPU;
no C dispatcher, input-schema, stage/signing or publication change is required.
Application/instrumentation sources are unchanged. Make stays production/default;
BIP stays excluded. No host installation, upgrade, publication or reboot occurred.

This closes configured shared source-manual construction for the tested AMD64
profiles. It does not close mandoc database generation, every manual installed
elsewhere in world, full installed tests/Make/pkgbase parity, cross target-ABIs or
all configurations. Remaining share docs/examples/zoneinfo and locale/encoding
composition, other world roots, independent reproducible bootstrap/output-query
closure, kernel/module installation, hardware/publication, system runtime/VM and
comparative CPU/RAM/disk I/O/footprint/cache/sandbox gates remain required.
