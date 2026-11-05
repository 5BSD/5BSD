# Generated timezone installation qualification

## Scope and design (2026-11-05)

The source-owned `share/zoneinfo/BUILD.bazel` builds timezone data using the
execution-platform `//usr.sbin/zic:zic` and the two maintained vendor AWK passes.
Source order, version, leap-second input and runtime tools are declared Bazel
inputs. No Make invocation, host timezone dataset or captured zone-name inventory
supplies the native build.

`bsd_zoneinfo_compile` declares a directory artifact. The generic
`bsd_install_tree_archive` passes its files through Bazel's execution-time
`Args` directory expansion. A small serializer converts that explicit file list
and the declared installation policy into the existing archive/metadata format.
It neither walks the source tree nor invents build dependencies. The second small
Python action drives the two vendor AWK passes with a declared version file;
source selection and actions remain Starlark definitions. These are execution
tools, not a Python replacement for the Bazel graph.

The nineteen compatibility directory names mirror maintained Make layout policy;
they are not an enumeration of timezone files. Parent directories are derived
from generated destinations. Zic creates directories within its declared output,
so the native invocation omits Make's `-D` (skip mkdir after shell precreation).
Both use the maintained fat file format and mode 0444. Archive policy remains
root/wheel, directory mode 0755 and file package `zoneinfo`. No change was made to
the source Makefile or the existing static archive writer.

## Original-build comparison

All evidence directories below are under `/usr/obj/usr/src/`.

| Profile | Native capture | Independent original stage | Audited comparison |
| --- | --- | --- | --- |
| Default, tests disabled | `bazel-zoneinfo-native-r2-20261105` | `bazel-zoneinfo-make-r1-20261105` | `bazel-zoneinfo-original-review-r1-20261105/review.json` |
| Leap seconds, tests disabled | `bazel-zoneinfo-leaps-native-r1-20261105` | `bazel-zoneinfo-leaps-make-r1-20261105` | `bazel-zoneinfo-leaps-original-review-r1-20261105/review.json` |

Both comparisons pass complete inventories, installation attributes and exact
payload bytes for 601 files. Native metadata also exposes 21 directory records.
Original Make creates those directories using plain mkdir, outside its component
file METALOG. Their physical staged inventory and attributes match native output
and the original global mtree policy. This is not a claim of identical raw
component METALOGs: the native records explicitly include those directories.
Original installed aliases are independent regular files, as are native archive
entries; their bytes and inode behavior were checked.

`bazel-zoneinfo-source-bindings-r1-20261105/inputs.json` binds vendor data and zic
source inputs before qualification; the bindings were rechecked afterward.
The initial `bazel-zoneinfo-native-r1-20261105` failed analysis because execution
SDK aliases needed `allow_single_file`; that attribute was corrected. It is not
accepted as passing evidence. The r2 capture is the successful replacement.

## Tests, dependencies and reuse

Both successful profiles pass three selected Bazel test targets:

- `//tools/build/bazel:install_tree_test`: eight cases for dynamic destinations,
  duplicate/conflicting paths, escapes, compatibility directories and policy.
- `//tools/build/bazel/tests/zoneinfo:artifact_test`: real source-built zic creates
  three fixture zones; the produced archive and expanded metadata contain every
  zone, correct regular-file payloads/modes and an explicitly empty directory.
- The maintained source-settings test target.

`bazel-zoneinfo-dependency-review-r1-20261105/review.json` verifies actual action
logs using the bound upstream execution-log converter. Every one of the 598
compiled files appears as an archive input with the producer's digest. The AWK
version input is declared. Leap mode has `-L` and its declared data input;
changing that setting did not rerun the independent AWK generation. The unchanged
leap request (`bazel-zoneinfo-leaps-cached-native-r1-20261105`) preserves all
three installation outputs without uncached production generation.
The observed runner is `processwrapper-sandbox`; this does not establish complete
OS isolation, compiler bootstrap reproducibility or comparative performance.

`bazel-zoneinfo-disabled-leaps-native-r1-20261105/effective-option-review.json`
checks that disabling zoneinfo clears requested leap support, matching maintained
option policy. An explicitly requested component still builds; its outputs match
the Make-qualified no-leap profile. This is not separate complete Make staging
of that disabled-parent profile.

`bazel-zoneinfo-cold-cache-r2-20261105/receipt.json` and `binding-review.json`
verify fresh cold, restored shared-cache and independent empty-cache builds.
The archive action executes, restores, then executes respectively. Archive,
expanded metadata and directory metadata are byte-identical in all three runs
and match the Make-qualified default capture. Each archive passes external tar
extraction checks. The selected SDK/compiler and repository cache are reused;
this is not an independently bootstrapped toolchain.

The maintained `component-archive-cache-test.py` now selects an actual build/test
command rather than the preceding inventory query, removes conflicting recorded
execution-log flags, requests metadata output groups and compares all three
installation outputs. Its final source hash is bound in the cache review.
The previous static examples archive and both metadata outputs also remain
byte-identical (`bazel-zoneinfo-native-r2-20261105/static-archive-regression.json`).

## Frontend integration and remaining gates

The maintained format-5 frontend already carries scalar source settings and
standard installation archive output groups; no C dispatcher or schema change
is required. The normal `bazel-test` workflow produced these captures with
sixteen jobs. The build-bsd manual documents native generation and its limits.
Signing, verified boot and publication helpers require no change for this data
component. No signing/publication/installation/reboot was performed.

The tests-enabled full endpoint deliberately fails until the original installed
ATF backward-link hierarchy is converted. The actual failed capture is
`bazel-zoneinfo-tests-native-r1-20261105`; its gate review records rejection,
not a passing full installation. The installed tests must exercise candidate
zone files rather than their current host `/usr/share/zoneinfo` assumption.
The fixture/unit tests above do not replace that suite.

Fresh original staging has no selected `/var/db/zoneinfo`, so Make's local-time
activation branch was not exercised. Persistent timezone choice, `/etc/localtime`
and upgrades remain runtime/lifecycle gates. Arbitrary ZICFLAGS/slim format,
other target ABIs and complete parent selection are not qualified here.

`bazel-zoneinfo-namespace-r1-20261105/review.json` reconciles 1146 unique
production archives and 28699 non-directory paths with zero conflicts across
retained component captures. Fixture payloads are excluded. This is not a
combined world build, directory ownership reconciliation or pkgbase acceptance.
Remaining share locale/encoding/sendmail data, complete share/world parents,
include/etc/rescue/sys/stand and installed test coverage must be closed, followed
by complete installation/debug/pkgbase parity, cross-platform/bootstrap,
runtime/VM and comparative CPU/memory/disk qualification. Make remains the
production/default builder. BIP remains excluded.
