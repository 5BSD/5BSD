# lib family composition and remaining owners

## Current evidence (2026-11-05)

The fresh maintained Make plan at
/usr/obj/usr/src/bazel-lib-family-plan-r1-20261104/components.json records 173
selected immediate SUBDIR entries after removing .WAIT barriers. These entries
include actual library producers, internal libraries with no installed archive,
header/manual-only owners, recursion wrappers and test hierarchies. This is
configuration evidence, not a count of completed libraries. There is currently
no accepted complete lib production parent or full installed lib test hierarchy.

Seven known manifest-to-production-archive gaps now build and pass bounded
qualification; see LIBRARY-PRODUCTION-ARCHIVES-QUALIFICATION.md. Their archive
rules are source-owned, and no Make evaluation supplies Bazel build metadata.
The selected Make plan remains an independent comparison inventory.

See PROCESS-LIBRARY-INSTALLATION-QUALIFICATION.md for the next three completed
production contributions and their explicit remaining scope.

See CAPSICUM-PROTOBUF-COMPOSITION-QUALIFICATION.md for Capsicum production/ATF
execution and the explicit normal protobuf parent.

## Internal library installation reconciliation (2026-11-05)

The selected libelftc implementation was native, but its original manuals had no
installation contribution. INTERNALLIB suppresses library/header installation;
it does not suppress MAN/MLINKS. The native source-owned inventory now installs
all nine manuals and eleven hardlinks, using the original toolchain-dev package
(or toolchain-man when split_manpages is enabled). No installed library/header
was invented for this internal owner.

`bazel-elftc-parent-native-r1-20261105` passes the existing API test and builds
regular/PIE archives plus the production manual archive through build-bsd.
`original-review/review.json` compares the fresh original
`bazel-elftc-parent-make-r2-20261105`: all twenty metadata records and compressed
payloads, all eleven actual hardlink relationships, and regular/PIE member order
and symbols agree. Other package profiles/ABIs and full-world parity remain open.
All paths are under /usr/obj/usr/src. Generic format-5 selection already supports
the labels; no C frontend, SDK, signing or publication interface changed.

## Combined selected production build

The fresh production-only Make recursion selects 172 immediate owners with
TESTS_SUPPORT explicitly enabled. The normal frontend's
`bazel-lib-family-composition-native-r1-20261105` completes 185 explicit
installation/build targets plus two cached passing tests. The r2 request also
explicitly builds the four internal regular/PIE archives for libotelexport and
libutil++, alongside their manual/data installation contributions. Its
`bazel-lib-family-composition-native-r2-20261105` result passes all 189 build/
installation targets plus two cached tests for all 172 selected owners, with
230 installation archives and no incompatible selected targets.
Requests r1/r2 and all bindings are retained in
`bazel-lib-family-composition-request-r{1,2}-20261105` under /usr/obj/usr/src.
Eleven internal-only owners build regular/PIE archives without inventing installed
files; libelftc's manuals remain a distinct installed contribution. This request
is a passing configured combined build, not yet a source-owned lib parent or
accepted complete original installation ownership. See COMPLETION-PLAN.md for the next usr.sbin batch and remaining
option-dependent parent integration.

## Concrete remaining review queue

| Owner | Source evidence and next work |
| --- | --- |
| lib/libproc | Default production installation now qualifies against fresh Make; original installed ATF/process-control tests, CTF-enabled compilation/production archive now builds in the OpenZFS header-closure batch; independent CTF-enabled original/runtime comparisons and other ABIs remain. |
| lib/libprocstat | Default production installation, all 30 manual hardlinks and native self-process/argv runtime qualify; alternate options/ABIs remain. |
| lib/librtld_db | Default production installation now qualifies; the header-only cycle break is retained. Loader/process operations and other profiles remain. |
| lib/libthread_db | Native AMD64 library/production installation now passes original regular/PIC and interface comparisons. Actual debugger runtime and other architectures remain; see THREAD-DB-NATIVE-QUALIFICATION.md. |
| lib/libcapsicum | Production header/manual/13 hardlinks now match original Make; all four original C/C++ stream ATF cases execute. Original installed-test metadata remains. |
| lib/csu | AMD64 parent now passes all 64 logical original records, ten allocated/symbolic-relocation startup contracts, six Kyuafiles, fifteen debug pairs, seventeen loader contracts and all 36 unchanged original runtime cases. Repeated note sections are retained with explicit occurrence identity. Other ABIs remain incompatible; full world remains open. |
| lib/libcasper | Native production parent now preserves all nine owners; 139 production and eight original connection-test records qualify. Both original connection cases execute; complete service-test/parent Kyuafile ownership remains gated. See CASPER-PARENT-COMPOSITION-QUALIFICATION.md. |
| lib/libxo | Production parent now preserves library + CSV encoder contributions; all 96 original metadata records and three actual runtime targets pass. Full installed functional/encoder test hierarchy remains explicitly gated; see LIBXO-PARENT-COMPOSITION-QUALIFICATION.md. |
| lib/protobuf | Explicit parent now builds all four children and preserves three install contributions, including upb licences and no libprotoc payload. Other profiles/ABIs and refreshed implementation parity remain. |
| lib/atf and lib/tests | ATF production parent candidate now declares both existing library owners; original ATF test recursion and general lib/tests parent remain open. |
| lib/clang | Shared-library parent and LLVM/Clang archive endpoint candidates now preserve original library/resource-header selection separately from tool executables; aggregate construction passes in the library/admin batch; selected Make ownership comparisons remain pending. |
| lib/googletest | Production/full-manifest archive endpoint candidates reuse existing four framework owners and optional selftest manifests. Aggregate construction passes in the library/admin batch; complete original ownership acceptance remains pending. |

This is a concrete next queue, not an exhaustive list of missing work or a claim
that every other selected entry is accepted. Reconcile every selected immediate
owner with its real products before declaring lib or full-world completion.
Internal libraries such as libder/libdiff are legitimate build dependencies even
when they produce no installed file; do not invent installed payloads for them.
All full world/pkgbase/bootstrap/runtime/cache/sandbox/performance and alternate
architecture gates remain. Make stays default; BIP remains excluded.
