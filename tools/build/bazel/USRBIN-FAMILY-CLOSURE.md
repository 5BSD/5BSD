# usr.bin family composition prerequisites (2026-11-04)

The complete-world review queue's remaining production directories without local
BUILD files mostly have real parent-owned producers (iconv/OpenSSL modules,
Switchboard NSS and EFI Lua) or are Make recursion wrappers. This is not proof
that their installed contents or the whole world are complete. The larger next
gap is explicit family composition: usr.bin now has a production declaration
under qualification, while full installed tests and optional-program coverage
remain incomplete. Do not use recursive //... patterns or BUILD-file counts as
an installed-world definition.

A fresh maintained component-plan query records 243 selected usr.bin entries.
The LLVM subtree has 18 SUBDIR tokens: 17 directories and one .WAIT barrier.
An unconfigured offline Bazel query loads 337 archive declarations beneath
usr.bin, including optional and test declarations. These counts have different
scopes and are not programs, built products or completion percentages.

## Closed prerequisites

Six already native programs had installation manifests but no component archive:
bzip2recover, gzip, xz, xzdec, lzmainfo and zstd. Each now has install_archive using
its existing manifest and the maintained account/mtree/archive helpers. World
family composition can consume these contributions without pulling entire
compression packages and accidentally including their library payloads. Package
composition and pkgbase creation remain separate. Epoch zero follows the current
component archive convention; no publication version is silently supplied.

The six actual archive actions were audited against immutable requests and their
logged payload digests. All 56 file/link records, including 29 hardlinks, have
exact payload bytes, inventory, permissions and ownership. Existing package tags,
manuals, aliases and debug-directory records are preserved. This is serialization
of existing component policy, not a new per-program Make compiler/stage audit.
Both existing bzip2 package-contract and recovery tests executed and passed.
The package test requires an explicit version; 16.0.qual.20261104 is a declared
unsigned qualification input, not a production release or publication.

The broad query also found bc_tests/dc_tests rule names colliding with their
output file names. Their producer rules now have copy_ prefixes, with installed
script names and Kyuafile entries preserved. The actual archive is built and
checked against original script bytes, 0555 mode and test names. All six earlier
archive/request/directory outputs remain exact in that final passing run.

## Evidence under /usr/obj/usr/src

- bazel-usrbin-family-plan-r1-20261104
- bazel-usrbin-archive-query-r3-20261104
- bazel-usrbin-compression-archives-r2-20261104 (actual initial test executions)
- bazel-usrbin-compression-archives-r3-20261104 (final passing products)
- bazel-usrbin-compression-archives-review-r2-20261104

The first analysis rejected the missing version input; it was not defaulted in
production code. An initial audit misparsed absolute Bazel labels; only that
label parser was corrected. Failed attempts remain retained.

Next: finish native LLVM family qualification and construct the source-owned
usr.bin aggregate with explicit nested/test contributions and coverage checks.
The production parent is now declared and analyzed, but has not been built or
qualified as a full installation. Its metadata query and
unconfigured declaration query cannot establish installed-world coverage.
Other world/library/data/rescue/kernel/module/bootstrap/pkgbase/hardware and
runtime/VM/CPU/memory/disk gates remain open. The existing format-5 build-bsd path
already builds these archives and tests; no C dispatch change is needed and its
manual is updated. Make remains production/default; BIP remains excluded.

## LLVM family composition in progress

The new normal installed-family declaration separates MK_CLANG selection from
MK_CLANG_FULL feature selection. Analysis initially failed on a duplicate LLDB
visibility keyword; the corrected declaration preserves the existing lib/clang
consumer and admits the family owner. The initial native 17-archive graph is still compiling. Its analyzed source
is retained separately because the revised family closes overlap with seven
archive contributions. No passing native aggregate or runtime qualification is
claimed yet.

Review found the existing toolchain alias manifest already contains ten utility
manifests to close manual hardlinks. The revised family consumes that closed
contribution once, with strict combined-manifest validation. Repeating leaf
archives and that alias archive would duplicate installed payloads. Optional
CLANG_EXTRAS remains unfinished, not silently omitted. The compiler-disabled
binutils-only profile also needs its llvm-cov/manual-link ownership resolved.

The usr.bin test root now declares Make's existing regress.m4 and generic
source Kyuafile. Its directory discovery remains unchanged. A fresh maintained
Make reference supplies the two-file, 0444 root/wheel inventory and 0755 tests
directory; native archive comparison is pending. These are family prerequisites,
not evidence of complete world/pkgbase or installed test execution.

## Configured LLVM ownership checkpoint

bazel-llvm-family-analysis-r1-20261104 under /usr/obj/usr/src records a separate
configured query of both targets. The archive set has seven distinct immediate
owners; the toolchain contribution owns ten utility manifests. Their union
accounts for all 17 selected Make directories without repeating those utility
owners. All 50 bound inputs of the original metadata query still match. Strict
combined-manifest analysis succeeds and materializes no actions. That proves
configured ownership and link/destination validation, not compiled payloads,
archives, installation parity, runtime or complete-world acceptance. CLANG_EXTRAS
and compiler-disabled binutils-only installation are explicitly incompatible.
The normal format-5 frontend supports these targets and settings unchanged.

## Full test inventory gap found during family review

The retained selected-profile owner queue accounts for 243 immediate roots, but
that mapping is a review input, not completed build coverage. A conservative
source scan finds 84 selected roots mentioning HAS_TESTS or MK_TESTS recursion;
36 have a tests directory without a local native BUILD. Local native test rules
can also cover only samples: awk declares four upstream cases and comm three
legacy cases, while their Make test hierarchies have additional installation
responsibilities. cmp/tests has no local native BUILD. Reconcile the complete
configured recursion and original installed test inventory before accepting the
family with tests enabled. Neither a BUILD-file count nor successful sampled
execution closes that gate.

Review queues: bazel-usrbin-family-owner-queue-r1-20261104 and corrected r2 under
/usr/obj/usr/src. The second queue resolves tftp's distinct production/test
archives and records these source candidates and limitations. The text scan is
not an exhaustive configured test inventory. The LLVM build and small test-root
qualification are serialized by the maintained backend state lock; an isolated
Bazel output identifier does not bypass that lock.

## usr.bin production parent checkpoint

The source-owned production_installation_archives target now selects normal
AMD64 production contributions with native options. No Make discovery is used
by the production Bazel graph. Fifteen missing boolean options and the existing
mail option's selector are declared with maintained source defaults. Toolchain
disablement excludes the LLVM family and compiler-support utilities; LDNS utility
selection preserves its library/crypto prerequisites. Nested production owners
are used where the Make directory owns several children. Leaf production
archives keep test-suite contributions separate.

Configured analysis matches all 242 immediate production roots from the retained
Make profile (243 including its separate tests root). Its 267 flattened archives
are not a program count or an installed filesystem inventory. The first analysis
reported 184 private archive targets; each now grants only its usr.bin parent
access. Eight already native optional archives receive the same parent interface. A full
AST comparison against the recorded committed baseline proves all 192 leaf edits
change only archive visibility, with previous access preserved. Compiler, generator,
installation content and package policy definitions are unchanged by those edits.

The full installation_archives target explicitly rejects tests-enabled builds
until the complete original hierarchy is reconciled. The production-only target
remains separately selectable. Seven optional programs still need conversion:
hesinfo, compile_et, ypcat, ypmatch, ypwhich, vacation and telnet. Selecting their
profiles is explicitly incompatible. These are open requirements, not excluded
scope. ARM64/RISC-V parent qualification and alternate profile parity also remain
open. Native aggregate compilation, archive installation, full tests, pkgbase,
world/kernel/bootstrap/runtime and performance acceptance are still pending.

Evidence under /usr/obj/usr/src:

- bazel-usrbin-family-analysis-r1-20261104 (original visibility failures and edit bindings)
- bazel-usrbin-family-analysis-r3-20261104 (final configured graph)
- bazel-usrbin-family-review-r2-20261104 (selected ownership and all 192 visibility-only edits)
- bazel-usrbin-family-gates-r1-20261104 (configured tests/optional/toolchain gates)

The existing format-5 frontend selects these targets/settings unchanged. The
large initial LLVM build and the queued test-root archive qualification remain
live; no passing native production aggregate is claimed by this checkpoint.

Four configured gate checks pass: the full default tests-enabled target is
incompatible; disabling tests makes it compatible; requesting unconverted
Hesiod makes production incompatible; disabling the toolchain excludes the LLVM
family and compiler-support programs while retaining ordinary production tools.
These checks execute no compiler or runtime actions. The next maintained
frontend qualification is queued behind the live LLVM and test-root processes,
and starts only if both finish with passing receipts. It selects the complete
production parent plus the existing LLVM utility/profile/debugger tests.

## Native LLVM build and test-root export follow-up

The initial 17-archive LLVM qualification now passes in
bazel-llvm-family-r2-20261104. Its only test is source_settings_test; this is not
the revised seven-contribution production aggregate or LLVM runtime acceptance.
The first test-root run failed because the existing generic Kyuafile export
allowed bin/sbin/libexec but omitted usr.bin. Its source export now grants the
same narrow usr.bin subtree access; bytes, automatic discovery and installation
policy are unchanged. Fresh qualification r2 passes through the maintained frontend. Its actual
archive matches the original two 0444 root/wheel files and 0755 tests directory,
including package tags and exact file bytes. The initial queued broader build
stopped on that failed prerequisite. After the corrected qualification passed,
the maintained frontend started bazel-usrbin-production-runtime-r1-20261104
with all six expanded runtime/configuration tests. That aggregate remains live
and unqualified. Evidence: bazel-usrbin-test-root-review-r1-20261104.
Complete world, aggregate modules and cross-architecture/system qualification
remain unfinished. Make remains default; BIP remains excluded.

## Original TAP suite installation batch under qualification

Eleven existing suites now have complete declared installation/archive
contributions: apply, calendar, comm, file2c, join, jot, lastcomm, ncal, printf, tr
and units. The shared bsd_test_installation.bzl helper serializes unchanged TAP source payloads directly with their installed
names/modes, preserves explicit fixtures and metadata, and uses the existing
account/mtree/archive policy. Existing apply/lastcomm manifests and all original
scripts are preserved. The batch declares 259 fixtures, thirteen TAP programs
and eleven Kyuafiles. Configured archive analysis passes; it executes no actions.

Original Make installation references are being captured sequentially with the
maintained helper. Native archive qualification is queued behind the live
production build. Exact inventory/bytes/modes/tags and actual archive producer
bindings still need comparison before this batch is qualified. No full TAP
runtime execution or complete usr.bin test hierarchy is claimed. The full
installation target remains incompatible with tests enabled. Evidence paths:
bazel-usrbin-tap-analysis-r2-20261104, bazel-usrbin-tap-make-batch-r1-20261104
and the pending bazel-usrbin-tap-native-r1-20261104 under /usr/obj/usr/src.

## Native production and TAP archive results

The subsequent bazel-usrbin-production-runtime-r1-20261104 qualification passes
through normal build-bsd format-5. It materializes the 267 declared production
archives, seven-contribution LLVM collection, strict merged LLVM manifest and
usr.bin test-root archive. All six selected tests pass: source settings (cached),
LLVM utilities and profiles, LLDB safe CLI, LLDB API smoke and lldb-server safe
CLI (five executed). Native Clang/LLD also build in the execution configuration
for the real profile test. No Make compilation fallback is introduced.
This supersedes the earlier live-build status above. Independent full Make
installation parity and completed-world namespace reconciliation remain open;
the separate 267-archive producer/payload audit now passes.

The eleven TAP references in bazel-usrbin-tap-make-batch-r1-20261104 and native
build bazel-usrbin-tap-native-r1-20261104 pass. The independent review in
bazel-usrbin-tap-review-r1-20261104/review.json checks all 283 files and eleven
explicit directories: exact bytes, modes, ownership, flags, package tags,
configured inventory and actual archive producer bindings. The 13 programs,
259 fixtures and 11 Kyuafiles preserve original installation names. This closes
this batch's archive installation comparison, not execution of those TAP scripts
or the complete tests-enabled parent, which remains explicitly incompatible.

The capture reader now has resolve_many for nonempty batches. Receipt/manifest
metadata is parsed once and rehashed before returning; each selected payload
still requires unique target/output selection, contained regular files, exact
size and SHA-256. No global cache or mutable bazel-bin lookup is added. The
existing single-output resolve interface delegates to the same checks.
bazel-qualification-artifact-batch-r1-20261104 passes the maintained Bazel test;
16 unit checks include later-output corruption, empty selection and metadata
mutation rejection. This reduces repeated metadata parsing, not a measured
whole-build speed or memory claim. Generic build-bsd format-5 dispatch already
supports these inputs; no C dispatcher or packaging/publication change is needed.

## Aggregate module status reconciliation

The older kernel refresh next-step text was stale: the later recorded
bazel-all-amd64-modules-ctf-debug-native-r2-20261103 receipt passes all 2,191
requested kernel/module targets, and
bazel-all-amd64-modules-payload-review-r3-20261103/summary.json passes for all
729 selected modules. The module aggregate construction gate is complete;
independent complete installation/pkgbase parity and runtime remain open.
The authoritative bounded details are in AMD64-AGGREGATE-MODULES-QUALIFICATION.md.
This correction records existing evidence, not a new build or runtime result.

## Complete production archive serialization audit

bazel-usrbin-production-review-r3-20261104/review.json independently reads all
801 captured archive/request/directory outputs and reconciles all 267 archives
with the prior configured selection. All 1,482 file/link records have exact
request inventories, logged payload hashes, modes, account-policy ownership,
flags and link targets. No non-directory destination occurs in two archives.
The audit reads tar contents without installing or extracting them on the host.

There are 254 current logged archive producer actions. Thirteen cached outputs
have explicit prior witnesses from the compression and LLVM qualifications:
current/prior tar, request and directory-output hashes all match, their actual
prior actions pass, and current payload/account-policy inputs match the logged
digests. These are reused witnesses, not thirteen fresh actions. The retained
prior-witness input list and audit source are hash-bound in the review.

The first inspection failed on a caller's extra slash before a full output name;
the second correctly rejected thirteen missing current action witnesses. The
third supplies explicit prior qualifications with strict product/input binding.
Failed inspections remain retained. No missing action record is manufactured.
This proves serialization consistency and destination uniqueness for this
production collection. It does not establish independent full Make installation
parity, completed-world directory/package reconciliation, complete installed
TAP execution or whole-system acceptance.

## Optional Hesiod closure and file2c regression correction

AMD64 hesinfo now has a native program, source header dependency, configured
native libc/libsys link, standard debug/manual/archive contribution and safe CLI
test. The default production set remains 267 archives; WITH_HESIOD selects 268
in a passing configured parent query. Native build/test and archive serialization
pass. Independent Make parity needs a coherent original HESIOD-enabled SDK:
the retained leaf reference fails because the unchanged SDK lacks hesiod.h.
DNS runtime, alternate architectures and full installation/pkgbase are open.
Six optional programs remain unconverted: compile_et, ypcat, ypmatch, ypwhich,
vacation and telnet. See HESINFO-NATIVE-QUALIFICATION.md for bounded evidence.

The new query exposed a package-boundary error from the earlier TAP batch:
file2c's parent native cases referenced files inside the new tests package via
old relative labels. Explicit package labels and eleven narrowly exported
fixtures repair it. All nine original native cases plus source settings pass in
bazel-usrbin-file2c-boundary-native-r1-20261104. The independent capture review
proves all 801 production archive/request/directory outputs unchanged from the
previous passing production run. No test was deleted, fixture patched or failure
masked. This follow-up supersedes earlier aggregate status for the changed graph.
