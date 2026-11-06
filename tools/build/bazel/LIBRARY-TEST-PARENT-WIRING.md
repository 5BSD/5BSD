# Selected library test parent wiring — AMD64

## What changed and what the counts mean

The actual configured library composition selected production-only child labels
for fourteen libraries whose original Make traversal also selects test
contributions. Existing declarations alone did not connect those contributions
to the parent. Source-owned optional archive parents now connect them:

- csu and libxo use their existing complete conditional parents.
- libc, libarchive, libexecinfo, libkvm, libnv, libproc, libregex, librt, libsbuf
  and msun gain production-plus-optional-tests archive parents.
- libdiff remains an internal build-only library in the negative profile, with
  no installed production files; its optional contribution carries its tests.
- Googletest selects the existing full archive only under the original combined
  tests/Googletest condition, preserving the original production archive otherwise.
- The lib root also selects its original lib/tests Kyuafile when tests are enabled.

Actual configured reachability rises from 43 to 57 of the recorded 66 original
Make test entry roots. This is declaration reachability, not a completion
percentage or proof of complete installed files/bodies. Nine entry roots remain
unreachable, all under Casper: its library tests, service recursion tests and
cap_dns/cap_fileargs/cap_grp/cap_net/cap_netdb/cap_pwd/cap_sysctl tests. The wider
lib tests-enabled guard and the Casper full-tests guard remain in place.

The negative root still selects exactly the same 231 archive output paths.
The direct selected parent count changes from 162 to 163 because libdiff has an
empty negative contribution. Those are parent targets, not library/program
counts. Source build-only libraries remain selected separately, unchanged.

No production Make parser, new diagnostic-only build endpoint, case allowlist,
placeholder payload or alternate compiler shortcut was introduced. Existing
format-5 build-bsd inputs select real child targets for qualification. No C
frontend/schema/signing change is needed; the manual is updated in this change.
Make remains default, and BIP is excluded.

## Evidence

All evidence below is under `/usr/obj/usr/src`. Native construction uses the
maintained build-bsd bazel-test path with `--arch amd64 --jobs 16`, explicit
SDK/receipt/repository inputs and the recorded source settings. These are unsigned
qualification builds, not publication, verified boot or host installation.

- `bazel-library-test-edges-inventory-r1-20261106`: actual original Make traversal
  of SUBDIR and TESTS_SUBDIRS for the recorded profile, reaching 326/442 directories
  with tests off/on and adding 116 through 66 entry edges. The later
  `bazel-library-parent-wiring-r1-20261106/make-inventory-revalidation.json`
  rehashes all 597 recorded Make include inputs against the current source;
  none changed. This does not constitute completed filesystem inventory.
- `bazel-library-test-declarations-r1-20261106`: earlier unconfigured archive/
  manifest declarations at actual entry roots. This was not sufficient to prove
  configured reachability; for example it found already existing but disconnected
  test archives.
- `bazel-library-selected-archives-r{1,2}-20261106`: configured direct library
  archive selection before/after the source change. These queries use actual
  Bazel selection and the same explicit profile, not an estimated parent list.
- `bazel-library-selected-files-before-r1-20261106` and
  `bazel-library-selected-files-after-r1-20261106`: exact equality of the 231
  configured negative root DefaultInfo archive output paths. This checks output
  selection, not newly qualified payload bytes or Make parity for the whole root.
- `bazel-library-test-closure-r{1,2}-20261106`: configured positive installation
  declaration closures of actual selected children plus the original lib/tests
  root. They contain 794/1401 configured install archive/set/manifest rules and
  cover 43/57 original entry roots. They do not prove every file in a subtree.
- `bazel-library-parent-wiring-r1-20261106/graph-review.json` and changes.json:
  retained before/after comparison and exact fourteen source-owned parent changes.
- `bazel-library-make-test-programs-r1-20261106`: expanded original Make program,
  package and directory declarations at the 66 entry roots, using the exact
  traversal overrides and source hash checks.
- `bazel-library-make-test-programs-r2-20261106`: extends those original declaration
  queries to all 116 selected nested test/helper directories; 193 included Make
  files are hashed and revalidated. Recorded program/script/library variables are
  development audit inputs, not a replacement for complete METALOG/payload
  staging or evidence of native file coverage. Recompute after Make input changes.
- `bazel-library-parent-wiring-request-r1-20261106/inputs.json` and
  `bazel-library-parent-wiring-native-r1-20261106`: successful construction of
  all fourteen changed parent contributions and lib/tests, producing 59 distinct
  archive outputs. Existing helpers bring native compiler/LLVM tool dependencies
  into this build; they were built through the declared native graph. This is
  not ARM64/RISC-V system qualification merely because LLVM target sources build.
  Exactly one source-settings helper test executes in this construction run;
  no new original body passes are claimed from it.
- `bazel-library-parent-wiring-artifact-review-r1-20261106/review.json`: all
  captured output hashes verify. Forty-one test archives from ten components are
  byte-identical to their documented earlier captures: all 31 libc test archives,
  libarchive, libexecinfo, libkvm, librt, libsbuf, libnv, libproc, two libxo test
  archives and msun. Each prior comparison/runtime result retains its original
  limits, including the documented libc UBSan/Make control gap; equality does not
  promote partial earlier evidence into complete system qualification.
- `bazel-library-full-tests-guard-request-r1-20261106` and
  `bazel-library-full-tests-guard-native-r1-20261106`: actual maintained-frontend
  negative request for the full tests-enabled library parent. It fails explicitly
  at that parent's incompatible constraint; FAILED.json and logs are retained.
  The guard is not removed to make the broader build appear complete.

## Directory package claims still need reconciliation

`bazel-library-directory-policy-audit-r1-20261106/review.json` compares explicit
archive directory attributes between the original negative/positive profiles for
same-named archives. It records 25 policy changes, often replacing a production
package's debug ancestor tag with a test package's tag in a merged dictionary.
This diagnostic is not a complete directory inventory: manifest-owned claims,
renamed/split archives and actual Make install records need separate comparison.
The 25 changes require reconciliation and repair where original claims are lost;
they are not silently accepted by calling graph reachability complete.

Preserve both original production/test claims where Make creates both. Existing
separate archive composition is available; do not merge distinct package claims
into one misleading tag, omit the runtime claim, invent package membership from
path names, or weaken metadata comparisons. Reconcile completed original Make
staging, including data, directory ownership/mode/flags/tags, links and generated
files, before claiming full library/pkgbase installation parity.

## Remaining qualification

Finish Casper's nine missing selected test entry roots and the directory-policy
reconciliation, then compare complete library/world test payloads and runtime.
Presence or construction of an archive alone does not establish completeness.
Continue full world/kernel/module/pkgbase/debug, normal Capsule/service/SSH/PAM
VM acceptance, CPU/RAM/disk-I/O/footprint comparisons, bootstrap/cache/sandbox/
reproducibility and verified combined base/hardware publication. No new runtime
probe/audit, system boot, performance, host install/upgrade/reboot or BIP claim is
made by this wiring change.
