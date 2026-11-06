# Library package directory claims — first two corrections

## Original policy and source composition

Independent complete Make installs of libmp and libbsnmp each record two claims
for `/usr/lib/debug/usr`: one from the production package (utilities or bsnmp),
one from tests. The former Bazel dictionary union replaced the production tag
with the test tag when tests were enabled. This was a real package metadata loss.

Each component now keeps `install_archive` as its production archive and adds a
separate `tests_install_archive`. The source-owned `installation_archives` parent
selects production plus optional tests; the normal lib root selects that parent.
Both archives retain their own original package directory claims. Test directories
created by Make are explicitly recorded with their original tests package tag.
The unchanged archive policy still rejects duplicate explicit directory records
inside one archive. No package tags are merged, inferred from the running system,
or dropped to make construction pass.

A reference search found only the lib root consuming these two old aggregate
labels. Production archive output paths remain unchanged; callers needing the
complete optional installation should use the new parent. Existing single-archive
providers remain suitable for explicit individual package consumers. The source
shares existing mtree/account/tool policy between production/test rules; inputs
and tools remain explicitly declared. No production/test C source, compiler,
linker, runtime runner or code generator changes were needed.

## Evidence and boundaries

All named evidence is under `/usr/obj/usr/src`. Native construction uses the
maintained build-bsd bazel-test path, explicit format-5 SDK/offline input receipts,
16 CPUs, and unsigned qualification. Make controls use independent original
component builds/installs, not imported native output.

| Component | File/link records, tests on/off | Directory claims, tests on/off |
| --- | ---: | ---: |
| libmp | 9 / 6 | 7 / 2 |
| libbsnmp | 104 / 101 | 8 / 3 |

- `bazel-directory-{libmp,libbsnmp}-make-r1-20261106` and corresponding
  `bazel-directory-{libmp,libbsnmp}-no-tests-make-r1-20261106` are the four
  complete original Make installations.
- `bazel-directory-two-native-r3-20261106` and
  `bazel-directory-two-no-tests-native-r1-20261106` capture positive/negative
  installation parents, yielding two/one archives per component. Each run executes
  only the source helper, not original library test bodies.
- `bazel-directory-two-review-r2-20261106` and
  `bazel-directory-two-no-tests-review-r1-20261106` verify all file/link sets,
  owner/group/mode/flags/package tags, symlink/hardlink contracts, complete sets of
  explicit directory claims, exact non-ELF/non-archive data, and native/Make debug
  separation/name/CRC. There are two/one debug-bearing ELF files and one static
  archive per component. These checks do **not** compare ELF ABI/content, raw
  static archive members, DWARF or debugger-source lookup.
- Native r1 rejected an invalid BUILD-level kwargs expansion; attributes were
  made explicit. The first payload audit then caught the missing original test
  directory claims. Both failed records remain; the checks were not weakened.
- `bazel-library-selected-files-after-r3-20261106` still selects the same 231
  negative root archive output paths. `bazel-library-directory-policy-audit-r2-20261106`
  reports 23 remaining explicit policy changes, down from 25. The reduction is a
  bounded check, not a claim that all other package directory handling is correct.
  Metadata contributed by manifests and renamed/split archives still needs full
  Make and pkgbase reconciliation.

Complete remaining library/world payload, ELF/archive/debug and runtime gates,
all 23 remaining recorded policy changes, actual package construction and combined
base/hardware publication, kernel/modules, cross-target acceptance, normal-service
VM checks, CPU/RAM/disk-I/O/footprint, and bootstrap/cache/sandbox/reproducibility
remain open. Keep the full library tests-enabled guard and Make production default.
BIP is excluded. Existing frontend configuration/backend actions already select
this contribution, so no C frontend/schema/signing change is needed. The maintained
manual, completion plan and observability log are updated in the same change.
