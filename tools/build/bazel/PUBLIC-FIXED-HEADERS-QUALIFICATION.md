# Fixed public headers and corrected Make reference staging

## Native contribution (2026-11-05)

The source-owned fixed include contribution now covers arpa, protocols, ssp,
xlocale and the maintained i386/ARM companion header groups. Existing typed
installation/archive rules are shared through bsd_public_headers.bzl; source
lists remain BUILD/.bzl definitions. Files use root/wheel, 0444 and clibs/dev
tags. Source mtree inputs supply directory ancestors. No Python implementation
was added to native header construction.

The fixed parent selects i386 on AMD64 and ARM on AArch64; RISC-V has no companion
child in the maintained Make traversal. The qualified host request selects the
AMD64 parent and explicitly requests the ARM data archive separately. ARM source
files/metadata were independently staged on AMD64; this does not establish a
complete ARM64 target build. The direct ARM archive is excluded from AMD64
production namespace counts.

Companion Makefiles create their directory in beforeinstall, even with includes
disabled. Both native directory records preserve this behavior and the original
clibs package tag without dev. Initial r1 construction omitted that tag and is
not accepted for metadata parity; r2 corrects the declarations, not the comparison.

## Complete component comparisons

All evidence paths below are under `/usr/obj/usr/src/`.

`bazel-public-fixed-native-r2-20261105` uses maintained build-bsd bazel-test,
sixteen jobs and the selected source-settings test. Independent original stages
are `bazel-public-<owner>-make-r1-20261105`, using the unchanged selected SDK/profile
and sixteen jobs with tests disabled. Complete comparison is retained at
`bazel-public-fixed-original-review-r1-20261105/review.json`, with audit source,
original receipt/METALOG hashes and native artifact/metadata bindings.

| Owner | Exact regular header files | Directory records |
| --- | ---: | ---: |
| arpa | 6 | 0 |
| protocols | 5 | 0 |
| ssp | 12 | 0 |
| xlocale | 12 | 0 |
| i386 | 13 | 1 |
| ARM companion | 41 | 1 |
| Total | 89 | 2 |

All complete component inventories, file bytes, size/hash, owner/group, mode,
flags, package/dev tags and tar serialization match. The AMD64 parent contributes
five archives/48 files; the separate ARM archive contributes 41 files.

`bazel-public-fixed-disabled-native-r2-20261105` passes the source-settings test.
The disabled companion Make references and
`bazel-public-fixed-disabled-review-r1-20261105/review.json` confirm exactly one
directory record per companion and no installed files. The four ordinary native
groups have empty inventories, checked in ordinary-group-review.json. Independent
disabled Make staging in this checkpoint covers the companions, not those four
ordinary groups. Complete include option/relocation policy remains a later gate.

`bazel-public-fixed-guard-native-r1-20261105` adds the maintained reference-options
regression suite; both selected Bazel tests pass. Its artifact-regression review
binds all eighteen archive/metadata outputs byte for byte to the component capture
above. The new staged-object guard also independently validates all six existing
component stages; those original recipes are not claimed to have been rerun after
the harness correction.

## Full include reference exposed a harness defect

The initial complete Make include stage reported success, but inventory review
found header copies outside its test stage. Buildenv supplies SYSROOT for compiler
inputs; include/Makefile defaults SDESTDIR to that SYSROOT. The reference harness
set DESTDIR without SDESTDIR, so copy/compat recipes touched the object SDK.
Metalog entries misleadingly named usr/obj paths which did not exist in the test
stage. `bazel-complete-include-make-r1-20261105/inventory-review.json` rejects this
capture. Its Make success receipt is not installation/parity acceptance.

The maintained install-reference.py now explicitly passes SDESTDIR=stage together
with DESTDIR. A shared staged-metadata guard validates canonical paths, parent
containment, actual object types, recorded sizes/hashes and symlink values before
a reference can pass. It respects final claims for paths replaced during install;
NO_ROOT ownership remains logical. This is validation of recorded staged objects,
not a process/filesystem sandbox or proof against unlogged Make recipe writes.
The regression suite covers outside-stage installs, parent symlink escapes,
traversal and object/hash/size/link mismatches. No Makefile or SDK verification
bypass was introduced.

The bad reference removed eight recorded object-SDK header inputs. Recovery is
retained at `bazel-include-reference-sdk-recovery-r1-20261105`: the missing contents
were restored as regular files from the selected hash-verified snapshot, then all
8381 recorded input-content bindings were rechecked. Original symlink topology
was not reconstructed or claimed. This affected build objects under /usr/obj,
not the installed host system. The cached SDK snapshot remained unchanged.

`bazel-complete-include-make-r2-20261105` runs the corrected reference. Its
staged_metadata_audit and inventory-review.json verify 1434 claims/1433 unique
objects: 1417 regular files, all with matching SHA-256, fourteen symlinks and two
unique directory records. All selected 8381 SDK input-content bindings still match
afterward. This establishes a complete original baseline for the remaining native
include work; it does not establish complete native include parity.

## Frontend and remaining work

The maintained format-5 target/scalar settings and archive output groups already
support these contributions. The build-bsd manual describes the header selections
and reference destination/object checks. No C dispatcher/schema or production
signing/staging/publication helper change is required. The affected maintained
Make comparison helper and its Bazel tests were fixed in this change.

`bazel-public-fixed-namespace-r1-20261105/review.json` reconciles the actual
AMD64-selected parent with preceding production captures: 1168 unique archives
and 30991 non-directory paths, zero conflicts. The unselected ARM data archive is
excluded explicitly. This is cross-capture evidence, not one combined world build
or whole-world directory/pkgbase acceptance.

Continue the complete include parent: ordinary root headers, generated osreldate,
source kernel/architecture header groups, aliases and remaining feature policy.
Complete etc/rescue/sys/stand/world and installed tests, installation/debug/pkgbase,
other ABIs/configurations, reproducible bootstrap/package inputs, runtime/VM and
comparative CPU/memory/disk qualification remain open. Runs are unsigned development
work; no host installation, upgrade, reboot or package publication occurred.
Make stays production/default and available for ports. BIP stays excluded.
