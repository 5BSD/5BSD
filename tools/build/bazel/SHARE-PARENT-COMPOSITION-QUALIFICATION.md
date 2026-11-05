# Complete configured production share traversal qualification

## Native parent (2026-11-05)

`//share:production_installation_archives` now composes the maintained production
share/Makefile traversal. Its children cover locale categories, dictionaries,
documentation, DTrace scripts, examples, firmware, encoding data, repository keys,
manuals, miscellaneous data, Make support, sendmail configuration, skeletons,
SNMP MIBs, terminal tabs/database, console data and timezones. Existing settings
control each conditional subtree; new dict/sharedocs boolean settings preserve
their maintained default-enabled policy. Source-owned BUILD/.bzl declarations
remain the native build definitions. No Python implementation is added or changed.

The source Makefile excludes info and has no selected _me/_roffdocs subtree;
this parent does not invent such selections. Installed test hierarchies remain
unconverted. The ordinary `//share:installation_archives` endpoint explicitly
rejects tests-enabled requests; the production endpoint identifies its narrower
contract. This is the complete selected production share traversal for the
qualified AMD64 profiles, not a full world endpoint or universal option coverage.

## Defects exposed and corrected

Complete comparison found an omitted maintained DTrace script, mbufid-sidecar,
and missing /usr/share/dtrace and /usr/lib/dtrace directory claims. Native source
inventory and directory policy now include all three. No DTrace script, provider
or runtime instrumentation implementation was changed. Installing these scripts
does not prove that all their probes operate on a running target kernel.

Termcap previously installed a compressed manual unconditionally and changed
its explicit ncurses package under split-manual mode. It now uses the existing
manual-entry helper, honors manual-disable/compression settings and preserves
Make's explicit MANPACKAGE=ncurses override. Source Makefiles were not changed.
Only intended share-parent visibility was added to DTrace/tabset/termcap archives.

## Independent complete subtree evidence

Every evidence directory below is under `/usr/obj/usr/src/`. Native runs use the
maintained build-bsd bazel-test workflow with sixteen jobs. Each successful run
passes the selected source-settings Bazel test. Original runs independently build
and stage the entire maintained share subtree with sixteen jobs and the recorded
SDK/profile; native payloads never seed that stage.

| Profile | Native capture | Original Make capture | Complete audit |
| --- | --- | --- | --- |
| Default selected production | `bazel-share-parent-native-r3-20261105` | `bazel-share-parent-make-r3-20261105` | `bazel-share-parent-original-review-r3-20261105` |
| Raw manuals, split-manual packages | `bazel-share-parent-raw-native-r1-20261105` | `bazel-share-parent-raw-make-r1-20261105` | `bazel-share-parent-raw-review-r1-20261105` |
| Reduced shared data | `bazel-share-parent-minimal-native-r1-20261105` | `bazel-share-parent-minimal-make-r1-20261105` | `bazel-share-parent-minimal-review-r1-20261105` |

Audit directories retain review.json and the exact audit source, original receipt
and METALOG hashes, plus native receipt/manifest/archive/metadata bindings.
Original subtree source hashes are checked against current files. Full profiles
explicitly enable LPR, FREEBSD_UPDATE, NIS and SENDMAIL against the unchanged SDK;
tests are disabled. The raw profile also disables MANCOMPRESS and enables
MANSPLITPKG. The reduced profile disables LOCALES, DICT, SHAREDOCS, CDDL, EXAMPLES,
SOURCELESS_UCODE, ICONV, MAN, MAKE, SENDMAIL, BSNMP, VT and ZONEINFO. It preserves
the normal miscellaneous-data/editor/USB selections and other recorded settings.

| Compared result | Default / raw | Reduced |
| --- | ---: | ---: |
| Native installation archives | 47 | 7 |
| Original component record claims | 8813 | 62 |
| Original unique paths | 7834 | 61 |
| Native component record claims | 8834 | 62 |
| Native unique paths | 7855 | 61 |
| Regular-file/hardlink paths, exact bytes | 6875 | 54 |
| Unique file inode classes | 4053 | 54 |
| Hardlink aliases | 2822 | 0 |
| Symlinks | 641 | 0 |
| Explicit native mkdir-only timezone directories | 21 | 0 |

The audit checks every file/symlink inventory and all file bytes, METALOG size/hash,
ownership, modes, flags, package tags, tar member types/attributes and hardlink
inode-equivalence classes. Directory metadata is compared as a multiset of claims:
repetitions and different package tags are preserved, not flattened or ignored.
For example, /usr/share/misc has both its original miscellaneous-data package
claim and its ncurses-lib claim. Identical repeated legal/locale directory claims
also retain original multiplicity.

As in the standalone timezone qualification, Make creates twenty-one timezone
directories with plain mkdir rather than component METALOG records. Native
expanded metadata exposes those directories explicitly. Their exact inventory,
physical original-stage presence and attributes match the original global mtree
policy. This explains the twenty-one-record difference above; arbitrary extra
paths or directory differences are not accepted. The reduced profile selects no
timezone data and has no such difference. Its C.UTF-8 file remains present.

## Failed evidence and test boundary

The first native parent attempt failed due to an accidentally duplicated i18n
visibility keyword; it was corrected without changing i18n's existing public
interface. Native r2 built, but the first complete comparison correctly failed
on the three DTrace omissions. That failed audit remains at
`bazel-share-parent-original-review-r1-20261105/review.json`.
Original Make r1 rejected an in-flight source declaration change through its
existing source-change guard. Original r2 passed as pre-correction evidence;
r3 is the accepted final default reference. No source guard was bypassed. An
early audit directory without a completed Make receipt has no accepted result.

`bazel-share-parent-tests-native-r1-20261105` actually fails because the full
installation endpoint is incompatible when tests are enabled. FAILED.json and
stderr remain failed evidence; gate-review.json records observed rejection,
not a passing installation. Original share/tests registration, installed example
test hierarchies and timezone backward-link tests must still be converted and
qualified before removing that gate. Selected source-settings tests do not stand
in for those installed suites.

## Composition, frontend and outstanding system gates

`bazel-share-parent-namespace-r1-20261105/review.json` reconciles this complete
production parent with preceding component captures: 1161 unique production
archives, 30866 non-directory paths and zero conflicting file claims. Identical
repeated archive identities are checked. This is cross-capture namespace evidence,
not a single combined world build or whole-world directory/pkgbase reconciliation.

The normal format-5 target/setting interface and standard archive output groups
already support this parent. The maintained manual documents it and the remaining
test gate. No C dispatcher, input-schema, stage/signing/verification or publication
helper change is needed. These unsigned development runs neither publish packages
nor install, upgrade or reboot the host.

Next close remaining world roots (including include/etc/rescue/sys/stand and
installed tests), compose one complete world, and qualify complete installation/
debug/pkgbase metadata, other ABIs/configurations, reproducible bootstrap/package
inputs, hardware/combined repository publication, runtime/VM and comparative CPU,
memory, disk I/O and footprint. Existing AMD64-only locale and termcap selections
still reject unsupported target mappings; this work does not imply cross-platform
share qualification. Selected SDK/execution runtime reuse is not an independent
compiler bootstrap or complete OS sandbox qualification. Make remains the
production/default backend and remains available for ports. BIP stays excluded.
