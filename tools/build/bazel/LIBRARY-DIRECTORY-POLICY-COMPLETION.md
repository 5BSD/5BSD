# Reconcile the 25 recorded library directory-policy overwrites

## Source changes

All 25 recorded cases now preserve separate original production/test package
claims for shared debug directory ancestors. The remaining 23 libraries use the
shared `bsd_library_installation_archives` macro in `bsd_test_installation.bzl`.
It declares ordinary native archives and a conditional archive set. Each owning
BUILD retains its explicit manifests, directories, feature selectors, account/
mtree/tool inputs and existing production archive output name/provider. The lib
root selects the complete parent. This adds no Make parser or runtime filesystem
inventory, and does not combine conflicting package tags into a single claim.

libfidl retains both tests and GoogleTest selectors, including conditional notices.
libsysdecode's original combined selector is separated into production/test claims.
The original libservice worker-contract installation also includes
`BSDExtension/rootload.c`; this missing declared source fixture and its directory
claim are now present. Its source export is restricted to the original extension
tests and libservice tests. The source-owned fixture inventory is reconciled
against actual original Make selection; no host source-tree fallback is used.

Building the full batch exposed incorrect source-including test boundaries.
cryptocmp's original tests compile the client directly; they now consume declared
generated bindings and explicit runtime providers, adding real libservice only
for the API test. networkcmp, notify and tracecmp source-including tests import
their actual native component archives with cc_import, preserving original lazy
member selection instead of inheriting the entire production CcInfo graph.
Their scripted fixtures exclude real service linkage where Make excludes it.
Trace keeps its existing explicit final static dependency sequence. No duplicate
symbol suppression, provider removal, source/body rewrite or SDK substitute was
used. The production library/provider rules remain unchanged.

## Independent installation evidence

All evidence paths below are under `/usr/obj/usr/src`. Maintained build-bsd
bazel-test uses explicit format-5 inputs, 16 CPUs and unsigned qualification.
There is no host installation, publication, verified boot or performance claim.

| Component | Make-matching file/link records, tests on/off | Distinct directory package claims, on/off |
| --- | ---: | ---: |
| libauditcmp | 24 / 17 | 12 / 5 |
| libbsnmp | 104 / 101 | 8 / 3 |
| libcache | 22 / 19 | 7 / 2 |
| libcapability | 18 / 15 | 7 / 2 |
| libcapbundle | 25 / 8 | 8 / 3 |
| libcapimage | 11 / 6 | 7 / 2 |
| libcapreclaim | 11 / 8 | 7 / 2 |
| libcapsulert | 34 / 29 | 7 / 2 |
| libchannel | 14 / 6 | 7 / 2 |
| libcryptocmp | 30 / 23 | 12 / 5 |
| libcryptodesc | 22 / 19 | 7 / 2 |
| libdevicecmp | 19 / 12 | 12 / 5 |
| libfidl | 123 / 109 | 30 / 22 |
| liblogcmp | 28 / 21 | 12 / 5 |
| libmp | 9 / 6 | 7 / 2 |
| libnetmap | 8 / 5 | 7 / 2 |
| libnetworkcmp | 38 / 29 | 12 / 5 |
| libnotify | 35 / 26 | 12 / 5 |
| libpowercmp | 27 / 18 | 12 / 5 |
| libservice | 91 / 60 | 19 / 2 |
| libshmring | 12 / 6 | 7 / 2 |
| libsysctlcmp | 27 / 20 | 12 / 5 |
| libsysdecode | 104 / 101 | 7 / 2 |
| libtimecmp | 19 / 16 | 10 / 5 |
| libtracecmp | 21 / 14 | 12 / 5 |
| Total | 876 / 694 | 260 / 102 |

The counts are summed component contributions, not unique whole-world paths.
All selected file/link sets, ownership/group/modes/flags/package tags, symbolic/
hardlink contracts and sets of explicit directory claims match independent Make
build/install controls. Exact non-ELF/non-archive data match, including controllers,
headers, licenses and fixtures. Debug separation/name/CRC are checked for 84/25
ELF files with tests on/off. This does **not** establish full ELF ABI/content,
static archive member equivalence, raw DWARF or debugger-source lookup.

- `bazel-directory-remaining-controls-r1-20261106` records all 46 original Make
  controls for the remaining 23 libraries. The prior two libraries retain their
  four original controls from LIBRARY-PACKAGE-DIRECTORY-QUALIFICATION.md.
- `bazel-directory-remaining-source-r1-20261106` binds the source composition
  edits to original controls and records the newly required fixture directory.
- `bazel-directory-remaining-native-r5-20261106` captures all 25 positive parents
  (50 archives); `bazel-directory-remaining-no-tests-native-r1-20261106` captures
  all 25 negative parents (25 archives). Only the source helper executes in each
  construction run; installed original test bodies are not counted as passes.
- `bazel-directory-remaining-review-r2-20261106` and
  `bazel-directory-remaining-no-tests-review-r1-20261106` compare the 23 libraries;
  `bazel-directory-two-final-{review,no-tests-review}-r1-20261106` compare the prior
  two against these same final captures.
- `bazel-directory-libfidl-no-gtest-make-r1-20261106`,
  `bazel-directory-fidl-no-gtest-native-r1-20261106` and
  `bazel-directory-fidl-no-gtest-review-r1-20261106` verify the actual alternative:
  tests on, GoogleTest off. All 120 records and 29 directory claims match Make;
  runtime_test, its debug file and the GoogleTest notice disappear as required.
- `bazel-directory-fixture-symbols-r1-20261106` retains five scripted fixtures'
  native/Make debug symbol inventories. Their defined service-symbol sets match;
  none pulls the real service_budget_begin/end lifecycle functions. These are
  symbol-boundary checks, not body execution or full ELF parity.
- `bazel-directory-remaining-final-review-r1-20261106` binds all reviews and
  report hashes. All 25 production archives are byte-identical across tests on/off.
- `bazel-library-directory-policy-audit-r3-20261106` finds zero remaining recorded
  same-named explicit directory-policy overwrites, down from 25. The configured
  negative library root still selects the exact same 231 archive output paths.
  This bounded audit does not cover every manifest/package interaction.

Failed analysis/build/audit records remain. Native r1 caught a missing helper
import; r2 caught cryptocmp's real/fake service duplicate; r3 exposed networkcmp's
forced duplicate client objects. r4 built but its comparison caught the omitted
libservice worker source; the corrected r5 capture passes all comparisons. Checks
were preserved while correcting the declared dependencies and installation data.

## Remaining completion gates

The global tests-enabled library guard remains. Next build and reconcile the
complete selected library/world installation against original Make, including
metadata contributed by manifests and all other package/feature combinations.
The zero count above is not proof of whole-library or whole-system completion.

Full ELF/static archive/debugger-source equivalence, original body execution,
current normal Capsule/service/login/PAM/SSH VM acceptance, cross-target runtime,
full world/kernel/modules/pkgbase, actual package construction and verified combined
base/hardware publication, CPU/RAM/disk-I/O/footprint comparisons, bootstrap output
queries/reproducibility and cache/sandbox qualification remain separate gates.
Make stays production/default. BIP is excluded. No C frontend/schema/signing or
backend action change is needed: maintained format-5 inputs select the real native
parents. The manual, completion plan and observability log are updated together.
